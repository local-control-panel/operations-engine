//! The `ingress.unpark` operation: restoring a parked domain's
//! pre-maintenance configuration from its `.maintenance-backup` file, as one
//! preflight-locked, one-transaction-recorded operation — the inverse of
//! `ingress::park`.
//!
//! Like `park`, this is not just a caller driving `ingress::activateConfig`
//! itself: it runs under the same `mutation::preflight::run`/`PreCommit`/
//! audit cycle `execute::execute` and `park::execute` use, so it gets its
//! own idempotency key, its own lock hold, and exactly one transaction
//! record, while reusing `activate::activate` for the actual filesystem/
//! container work.
//!
//! `UnparkRequest` carries no content field at all — unlike
//! `ActivateConfigRequest` and even `ParkRequest` (which at least supplies
//! the maintenance page's content) — because the content this operation
//! writes to the live route always comes from the domain's own
//! `.maintenance-backup` file, never from the caller. A caller cannot ask
//! this operation to restore anything other than what `park` actually
//! saved.
//!
//! The one invariant this module exists to get right is the mirror image of
//! `park`'s: `park` had to decide when a backup it just wrote could safely
//! be deleted again after a failed live write. Here, the backup is the
//! *only* remaining copy of the pre-maintenance configuration once the live
//! route holds the maintenance page, so it must be deleted if and only if
//! the live write it is restoring genuinely, fully succeeded — never on any
//! `activate::Error`, no matter which variant, and no matter how much of
//! the live write that variant implies actually landed. See `execute`'s doc
//! comment for the deletion condition itself.

use std::io;

use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    ingress::{
        ConfigHash, HashGuard, RouteTarget, UNPARK_OPERATION, UnparkRequest, UnparkResult,
        activate,
        activate::read_optional,
        backup_route_path,
        execute::{
            ActivateContext, ProtocolError, audit_log_path, compose_failure_code, fail,
            open_ingress_state, state_path_for, timed_out,
        },
        route_path,
    },
    mutation::preflight,
    process::CancellationToken,
    transaction::{
        RequestId,
        audit::{self, AuditRecord},
        commit::PreCommit,
        state::{self, TransactionStatus},
    },
};

#[derive(Debug)]
pub enum UnparkError {
    Io(io::Error),
    Preflight(preflight::Error),
    /// The idempotency key was already claimed, but the original attempt
    /// is still `InProgress` — nothing to replay yet.
    ReplayInProgress,
    /// There is no `.maintenance-backup` file for this domain — nothing to
    /// restore. Either the domain was never parked, or an earlier
    /// successful `unpark` already deleted it.
    NotParked,
    /// The live write that restores the backup's content onto the live
    /// route failed. A caller does not need to know which `activate::Error`
    /// variant: either way, the backup was not deleted (see `execute`'s doc
    /// comment) and the domain should be treated as still parked.
    Activate(activate::Error),
    State(state::StateError),
    Cancelled,
    /// Unparking itself succeeded — the pre-maintenance configuration is
    /// live and the backup file has been removed — but the
    /// `TransactionState` could not be saved afterward. Carries the result
    /// so the caller never loses it.
    PostCommitRecordFailed {
        result: UnparkResult,
        cause: state::StateError,
    },
    /// A replayed request whose original attempt failed.
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl UnparkError {
    /// Mirrors `ParkError::protocol`'s mapping for the `activate::Error`
    /// variants both operations can produce, plus one new message for
    /// `NotParked`.
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Io(_) | Self::State(_) | Self::PostCommitRecordFailed { .. } => (
                ErrorCode::Internal,
                "internal ingress activation error".to_owned(),
            ),
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another ingress configuration activation is already in progress".to_owned(),
            ),
            Self::Preflight(_) => (ErrorCode::Internal, "preflight failed".to_owned()),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request for this idempotency key is still in progress".to_owned(),
            ),
            Self::NotParked => (
                ErrorCode::IngressNotParked,
                "this domain is not currently parked".to_owned(),
            ),
            Self::Activate(activate::Error::Io(_)) => (
                ErrorCode::Internal,
                "internal ingress activation error".to_owned(),
            ),
            Self::Activate(activate::Error::Path(_)) => (
                ErrorCode::InvalidInput,
                "the route file does not resolve inside the configured ingress root".to_owned(),
            ),
            Self::Activate(activate::Error::HashGuardMismatch) => (
                ErrorCode::ConfigHashMismatch,
                "the configuration changed since it was read - re-read it and retry".to_owned(),
            ),
            Self::Activate(activate::Error::ValidateFailed(failure)) => (
                compose_failure_code(failure, ErrorCode::ConfigValidationFailed),
                "the submitted configuration was rejected before it was activated".to_owned(),
            ),
            Self::Activate(activate::Error::ReloadFailedAndRestored(failure)) => (
                compose_failure_code(failure, ErrorCode::ConfigReloadFailed),
                if timed_out(failure) {
                    "the submitted configuration timed out while loading; the previous \
                     configuration was put back on disk, but whether the running server is on \
                     it could not be confirmed - verify the live ingress configuration"
                } else {
                    "the submitted configuration failed to load; the previous configuration was \
                     restored and is live"
                }
                .to_owned(),
            ),
            Self::Activate(activate::Error::ReloadFailedUnchanged(failure)) => (
                compose_failure_code(failure, ErrorCode::ConfigReloadFailed),
                "the configuration was already in place but failed to load; nothing was \
                 changed"
                    .to_owned(),
            ),
            Self::Activate(activate::Error::RecoveryFailed { .. }) => (
                ErrorCode::ConfigRecoveryFailed,
                "the configuration failed to load and could not be rolled back; the live \
                 ingress configuration needs manual inspection"
                    .to_owned(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before the commit point".to_owned(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
        }
    }
}

impl ProtocolError for UnparkError {
    fn protocol(&self) -> (ErrorCode, String) {
        UnparkError::protocol(self)
    }
}

/// Unparks `request.domain`: restores its `.maintenance-backup` file onto
/// the live route and, only on a genuinely successful restore, deletes the
/// backup — as one preflight-locked, one-transaction-recorded operation.
/// See this module's doc comment for why this does not just call
/// `ingress::execute::execute` itself.
///
/// 1. `preflight::run`, exactly as `execute::execute`/`park::execute`,
///    under `UNPARK_OPERATION` — including idempotency-key replay.
/// 2. A `PreCommit` cancellation check, exactly as the other two.
/// 3. Reads the domain's `.maintenance-backup` file. No such file at all is
///    `UnparkError::NotParked` — there is nothing to restore, and a client
///    needs to be able to tell that apart from every other failure mode.
/// 4. Reads the domain's current live route content (the maintenance page),
///    to build this call's own `HashGuard` — exactly the same
///    "read, then guard on what you read" pattern `park::execute` step 3
///    uses, so nothing else can change the live file between this
///    operation's own read and its own guarded write.
/// 5. Activates the backup's content onto the live route
///    (`RouteTarget::Live`), guarded by the hash of exactly the live
///    content step 4 read.
/// 6. On success: deletes the backup file, best-effort — matching
///    `set_maintenance`'s existing legacy behavior of
///    `sudo rm -f ... .ok()`, so a leftover backup after an otherwise
///    successful unpark is a known, already-accepted failure mode being
///    ported faithfully, not a new one.
///
///    On *any* failure from step 5's `activate::activate` call, the backup
///    is left exactly as it was — untouched, regardless of which
///    `activate::Error` variant came back. This is deliberately simpler
///    than (and the mirror image of) `park::execute`'s deletion condition,
///    which had to carve out one specific `RecoveryFailed` sub-case because
///    most of its failure variants still meant "the live write did not
///    happen" for a backup *it had just written and could safely discard*.
///    Here every `activate::Error` variant means something more dangerous
///    to get wrong: even where the live *file* may already hold the
///    restored content (e.g. `RecoveryFailed { restore: RestoreFailure::
///    File(_), .. }`, where the rollback-of-the-rollback's own rename
///    failed and so never overwrote it), this call never *confirmed* that
///    outcome — the reload that would have proven it never succeeded, and
///    in every other variant the live route may still hold the maintenance
///    page outright. A backup deleted on any of those readings would
///    permanently destroy the only remaining copy of the real
///    configuration for a domain that may still — or again — be parked.
///    So the condition is not "was the live file probably restored", it is
///    "did this call return `Ok`" — full stop.
/// 7. Commit/state/audit tail identical in shape to `park::execute`'s.
pub fn execute(
    context: &ActivateContext<'_>,
    request: &UnparkRequest,
    cancellation: &CancellationToken,
) -> Result<UnparkResult, UnparkError> {
    let ingress_state = open_ingress_state(context.engine_state).map_err(UnparkError::Io)?;

    let admitted = match preflight::run(
        &ingress_state,
        request.request_id,
        request.idempotency_key.as_ref(),
        UNPARK_OPERATION,
    )
    .map_err(UnparkError::Preflight)?
    {
        preflight::Outcome::Replay(original) => return replay(&ingress_state, original),
        preflight::Outcome::Proceed(admitted) => admitted,
    };
    let preflight::Admitted { lock, mut state } = admitted;

    let state_path = state_path_for(request.request_id);
    let audit_path = audit_log_path();
    let pre_commit = PreCommit::new(cancellation.clone());

    if pre_commit.check().is_err() {
        return Err(fail(
            &ingress_state,
            &state_path,
            &audit_path,
            state,
            UnparkError::Cancelled,
        ));
    }

    let root = match ManagedRoot::open(context.ingress_root) {
        Ok(root) => root,
        Err(error) => {
            return Err(fail(
                &ingress_state,
                &state_path,
                &audit_path,
                state,
                UnparkError::Io(error),
            ));
        }
    };

    // Step 3: the backup file. Missing means there is nothing to unpark.
    let backup_path = backup_route_path(&request.domain);
    let backup_bytes = match read_optional(&root, &backup_path) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            return Err(fail(
                &ingress_state,
                &state_path,
                &audit_path,
                state,
                UnparkError::NotParked,
            ));
        }
        Err(error) => {
            return Err(fail(
                &ingress_state,
                &state_path,
                &audit_path,
                state,
                UnparkError::Activate(error),
            ));
        }
    };
    // `activate::activate` takes `content: &str`; every route file this
    // engine has ever written came from a `String`, so a non-UTF-8 backup
    // file here means something outside this engine wrote it. Reported as
    // an internal error rather than added as a new `UnparkError` variant,
    // since it is not a state this operation's own writes can produce.
    let backup_content = match std::str::from_utf8(&backup_bytes) {
        Ok(text) => text.to_owned(),
        Err(_) => {
            return Err(fail(
                &ingress_state,
                &state_path,
                &audit_path,
                state,
                UnparkError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "backup route file is not valid UTF-8",
                )),
            ));
        }
    };

    // Step 4: the current live content, read once, for this call's own
    // hash guard.
    let live_bytes = match read_optional(&root, &route_path(&request.domain)) {
        Ok(bytes) => bytes,
        Err(error) => {
            return Err(fail(
                &ingress_state,
                &state_path,
                &audit_path,
                state,
                UnparkError::Activate(error),
            ));
        }
    };
    let guard = match &live_bytes {
        Some(bytes) => HashGuard::Sha256(ConfigHash::of(bytes)),
        None => HashGuard::Absent,
    };

    // Step 5: restore the backup's content onto the live route.
    let backup_suffix = request.request_id.to_string();
    if let Err(error) = activate::activate(
        context.ingress_root,
        &request.domain,
        &backup_content,
        &guard,
        RouteTarget::Live,
        &backup_suffix,
        context.compose,
    ) {
        // See `execute`'s doc comment: the backup must survive *any*
        // `activate::Error` here, unconditionally — it is the only
        // remaining copy of the pre-maintenance configuration for a domain
        // that may still be parked.
        return Err(fail(
            &ingress_state,
            &state_path,
            &audit_path,
            state,
            UnparkError::Activate(error),
        ));
    }

    // Step 6: the live write genuinely succeeded — delete the backup,
    // best-effort.
    let _ = root.remove_file(&backup_path);

    // Commit point: the live route file now holds the pre-maintenance
    // configuration and the ingress server has reloaded it.
    let _post_commit = pre_commit.commit();
    drop(lock);

    let result = UnparkResult {
        domain: request.domain.as_str().to_owned(),
        content_sha256: ConfigHash::of(&backup_bytes),
        activated_at_unix_secs: unix_now_secs(),
    };
    let result_value = serde_json::to_value(&result).expect("UnparkResult always serializes");
    state
        .mark_committed(result_value)
        .expect("state is always InProgress at this point");

    if let Err(cause) = state::save(&ingress_state, &state_path, &state) {
        return Err(UnparkError::PostCommitRecordFailed { result, cause });
    }
    let _ = audit::append(
        &ingress_state,
        &audit_path,
        &AuditRecord::result(request.request_id, true, None),
    );

    Ok(result)
}

fn replay(ingress_state: &ManagedRoot, original: RequestId) -> Result<UnparkResult, UnparkError> {
    let original_state =
        state::load(ingress_state, &state_path_for(original)).map_err(UnparkError::State)?;
    if original_state.operation != UNPARK_OPERATION {
        return Err(UnparkError::State(state::StateError::Corrupt));
    }
    match original_state.status {
        TransactionStatus::InProgress => Err(UnparkError::ReplayInProgress),
        TransactionStatus::Committed => {
            let outcome = original_state
                .outcome
                .expect("a committed transaction always has an outcome");
            let result_value = outcome
                .result
                .expect("a committed outcome always has a result");
            serde_json::from_value(result_value)
                .map_err(|_| UnparkError::State(state::StateError::Corrupt))
        }
        TransactionStatus::Failed => {
            let outcome = original_state
                .outcome
                .expect("a failed transaction always has an outcome");
            Err(UnparkError::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}

fn unix_now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;

    use super::{UnparkError, execute};
    use crate::{
        error::ErrorCode,
        filesystem::ManagedRoot,
        ingress::{
            ActivateConfigRequest, HashGuard, RouteTarget, UnparkRequest, UnparkResult,
            execute::{self as activate_execute, ActivateContext},
            fake_docker::FakeDocker,
        },
        process::CancellationToken,
        site::TrustedRoot,
    };

    const DOMAIN: &str = "example.com";
    const ROUTE: &str = "example.com.caddyfile";
    const BACKUP_ROUTE: &str = "example.com.maintenance-backup";
    const REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const RETRY_REQUEST_ID: &str = "9b2f1c34-5678-4abc-9def-0123456789ab";
    const PREVIOUS: &str = "example.com {\n  respond \"old\"\n}\n";
    const MAINTENANCE: &str = "example.com {\n  respond \"down for maintenance\"\n}\n";

    /// The engine-wide state root and the ingress root, as separate real
    /// directories - the same separation `park.rs`'s own `Host` uses.
    struct Host {
        state_dir: tempfile::TempDir,
        ingress_dir: tempfile::TempDir,
        ingress_root: TrustedRoot,
        engine_state: ManagedRoot,
    }

    fn host(live: Option<&str>, backup: Option<&str>) -> Host {
        let state_dir = tempfile::tempdir().expect("state root should be created");
        let ingress_dir = tempfile::tempdir().expect("ingress root should be created");
        if let Some(contents) = live {
            fs::write(ingress_dir.path().join(ROUTE), contents)
                .expect("existing live route should be written");
        }
        if let Some(contents) = backup {
            fs::write(ingress_dir.path().join(BACKUP_ROUTE), contents)
                .expect("existing backup route should be written");
        }
        let engine_state = ManagedRoot::open(
            &TrustedRoot::parse(state_dir.path()).expect("state root should be valid"),
        )
        .expect("state root should open");
        let ingress_root =
            TrustedRoot::parse(ingress_dir.path()).expect("ingress root should be valid");
        Host {
            state_dir,
            ingress_dir,
            ingress_root,
            engine_state,
        }
    }

    impl Host {
        fn live(&self) -> Option<String> {
            fs::read_to_string(self.ingress_dir.path().join(ROUTE)).ok()
        }

        fn backup(&self) -> Option<String> {
            fs::read_to_string(self.ingress_dir.path().join(BACKUP_ROUTE)).ok()
        }

        fn transaction(&self, request_id: &str) -> serde_json::Value {
            let path = self
                .state_dir
                .path()
                .join(format!("ingress/transactions/{request_id}.json"));
            serde_json::from_str(
                &fs::read_to_string(path).expect("the transaction record should exist"),
            )
            .expect("the transaction record should be JSON")
        }

        fn transaction_exists(&self, request_id: &str) -> bool {
            self.state_dir
                .path()
                .join(format!("ingress/transactions/{request_id}.json"))
                .exists()
        }
    }

    fn request(request_id: &str, key: Option<&str>) -> UnparkRequest {
        UnparkRequest::parse(DOMAIN, request_id, key).expect("request should parse")
    }

    fn run(
        host: &Host,
        docker: &FakeDocker,
        request: &UnparkRequest,
    ) -> Result<UnparkResult, UnparkError> {
        let access = docker.access();
        let context = ActivateContext {
            ingress_root: &host.ingress_root,
            engine_state: &host.engine_state,
            compose: &access,
        };
        execute(&context, request, &CancellationToken::default())
    }

    #[test]
    fn unparking_restores_the_backup_to_live_and_deletes_it() {
        let host = host(Some(MAINTENANCE), Some(PREVIOUS));
        let docker = FakeDocker::new();

        let result = run(&host, &docker, &request(REQUEST_ID, None))
            .expect("unparking a parked domain should succeed");

        assert_eq!(result.domain, DOMAIN);
        assert_eq!(
            result.content_sha256,
            crate::ingress::ConfigHash::of(PREVIOUS.as_bytes())
        );
        assert_eq!(host.live().as_deref(), Some(PREVIOUS));
        assert!(
            host.backup().is_none(),
            "a successful unpark must delete the backup file"
        );

        let record = host.transaction(REQUEST_ID);
        assert_eq!(record["operation"], "ingress.unpark");
        assert_eq!(record["status"], "COMMITTED");
    }

    #[test]
    fn unparking_a_domain_with_no_backup_fails_closed() {
        let host = host(Some(MAINTENANCE), None);
        let docker = FakeDocker::new();

        let error = run(&host, &docker, &request(REQUEST_ID, None))
            .expect_err("unparking a domain with no backup must fail");

        assert!(matches!(error, UnparkError::NotParked));
        assert_eq!(error.protocol().0, ErrorCode::IngressNotParked);
        assert_eq!(
            host.live().as_deref(),
            Some(MAINTENANCE),
            "a domain with no backup must not have its live route touched"
        );

        let record = host.transaction(REQUEST_ID);
        assert_eq!(record["status"], "FAILED");
        assert_eq!(record["outcome"]["errorCode"], "INGRESS_NOT_PARKED");
    }

    #[test]
    fn a_reload_failure_during_unpark_leaves_the_maintenance_page_live() {
        let host = host(Some(MAINTENANCE), Some(PREVIOUS));
        let docker = FakeDocker::new().failing("reload", "all");

        let error = run(&host, &docker, &request(REQUEST_ID, None))
            .expect_err("a config the server refuses to load must not unpark the domain");

        assert!(matches!(error, UnparkError::Activate(_)));
        assert_eq!(
            host.live().as_deref(),
            Some(MAINTENANCE),
            "activate::activate's own rollback restores the maintenance page"
        );
        assert_eq!(
            host.backup().as_deref(),
            Some(PREVIOUS),
            "the backup must still exist after a failed live write - it may be the only \
             remaining way to recover this parked site"
        );

        let record = host.transaction(REQUEST_ID);
        assert_eq!(record["status"], "FAILED");
    }

    #[test]
    fn a_retried_idempotency_key_replays_without_re_unparking() {
        let host = host(Some(MAINTENANCE), Some(PREVIOUS));
        let docker = FakeDocker::new();
        let key = Some("unpark-2026-09-05-01");

        let first = run(&host, &docker, &request(REQUEST_ID, key))
            .expect("the first attempt should unpark");
        let reloads_after_first = docker.calls("reload").len();

        let replayed = run(&host, &docker, &request(RETRY_REQUEST_ID, key))
            .expect("the retry should replay the original outcome");

        assert_eq!(replayed.domain, first.domain);
        assert_eq!(replayed.content_sha256, first.content_sha256);
        assert_eq!(
            host.live().as_deref(),
            Some(PREVIOUS),
            "a replay must not touch the live route again"
        );
        assert_eq!(
            docker.calls("reload").len(),
            reloads_after_first,
            "a replay must not touch the container again"
        );
        assert!(!host.transaction_exists(RETRY_REQUEST_ID));
    }

    /// Regression test for the cross-operation idempotency-replay hole
    /// confirmed empirically during the final review: `UnparkResult`
    /// (`domain`, `contentSha256`, `activatedAtUnixSecs`) is a *structural
    /// subset* of `ActivateConfigResult` (those same three fields plus
    /// `activated`), so before `replay` checked `original_state.operation`,
    /// calling `ingress activate-config --idempotency-key K` and then
    /// `ingress unpark --idempotency-key K` would deserialize the stored
    /// `ActivateConfigResult` straight into an `UnparkResult` and return a
    /// *fake* unpark success - without ever touching the backup or live
    /// files - because every field `UnparkResult` needs happens to already
    /// be present in `ActivateConfigResult`'s JSON. Every other
    /// cross-operation pairing (see `execute.rs`'s and this module's
    /// sibling `park.rs` regression tests) fails closed even without this
    /// fix, purely by accident of which fields do *not* line up; this is
    /// the one pairing that silently succeeded, so it is the one that
    /// actually proves the fix.
    #[test]
    fn an_activate_config_key_is_never_replayed_as_a_fake_unpark_success() {
        let host = host(Some(MAINTENANCE), None);
        let docker = FakeDocker::new();
        let key = Some("shared-key-across-operations");

        let activate_context = ActivateContext {
            ingress_root: &host.ingress_root,
            engine_state: &host.engine_state,
            compose: &docker.access(),
        };
        let activate_request = ActivateConfigRequest::parse(
            DOMAIN,
            MAINTENANCE,
            HashGuard::Sha256(crate::ingress::ConfigHash::of(MAINTENANCE.as_bytes())),
            RouteTarget::Live,
            REQUEST_ID,
            key,
        )
        .expect("activate-config request should parse");
        activate_execute::execute(
            &activate_context,
            &activate_request,
            &CancellationToken::default(),
        )
        .expect("the activate-config call under this key should succeed");

        let error = run(&host, &docker, &request(RETRY_REQUEST_ID, key)).expect_err(
            "an unpark call reusing an activate-config idempotency key must not silently \
             succeed",
        );

        assert!(
            matches!(error, UnparkError::State(_)),
            "expected the cross-operation mismatch to be reported as a state error, got {error:?}"
        );
        // The fix rejects before ever deserializing the stored
        // `ActivateConfigResult` as an `UnparkResult` - proven by the live
        // route still holding exactly what activate-config left it as, and
        // no backup having been fabricated or consumed.
        assert_eq!(host.live().as_deref(), Some(MAINTENANCE));
        assert!(host.backup().is_none());
    }
}
