//! The `ingress.park` operation: putting a domain's maintenance page live
//! while preserving its pre-maintenance configuration, as one
//! preflight-locked, one-transaction-recorded operation.
//!
//! This is *not* two `ingress.activateConfig` calls wired together by a
//! caller. A caller could, in principle, snapshot the live route to
//! `RouteTarget::Backup` itself and then activate the maintenance page to
//! `RouteTarget::Live` — but that would record two separate
//! `ingress.activateConfig` transactions for what is, from the operator's
//! point of view, a single action ("park this domain"), and it would leave
//! a window between the two calls where a second concurrent request could
//! observe (or itself attempt) a half-parked domain. This module runs both
//! writes inside the *same* `mutation::preflight::run`/`PreCommit`/audit
//! cycle `execute::execute` uses for `activateConfig`, so `ingress.park`
//! gets its own idempotency key, its own lock hold, and exactly one
//! transaction record — while still reusing `activate::activate` itself
//! (including its `RouteTarget::Backup` branch from Task 2) for the actual
//! filesystem/container work, rather than duplicating it.

use std::io;

use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    ingress::{
        ConfigHash, HashGuard, PARK_OPERATION, ParkRequest, ParkResult, RouteTarget, activate,
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
pub enum ParkError {
    Io(io::Error),
    Preflight(preflight::Error),
    /// The idempotency key was already claimed, but the original attempt
    /// is still `InProgress` — nothing to replay yet.
    ReplayInProgress,
    /// There is no live route file for this domain to park. Parking is
    /// defined in terms of preserving *something* that is currently live;
    /// a caller that reaches this either read something a moment ago (and
    /// the domain is not actually live any more) or should have.
    NothingLive,
    /// Either the backup snapshot write or the maintenance-page live write
    /// failed. A caller does not need to know which: either way, parking
    /// did not complete.
    Activate(activate::Error),
    State(state::StateError),
    Cancelled,
    /// Parking itself succeeded — the maintenance page is live and (on a
    /// first park) the backup was written — but the `TransactionState`
    /// could not be saved afterward. Carries the result so the caller never
    /// loses it.
    PostCommitRecordFailed {
        result: ParkResult,
        cause: state::StateError,
    },
    /// A replayed request whose original attempt failed.
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl ParkError {
    /// Mirrors `ActivateConfigError::protocol`'s mapping for the
    /// `activate::Error` variants both operations can produce, plus one new
    /// message for `NothingLive`.
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
            Self::NothingLive => (
                ErrorCode::InvalidInput,
                "no live configuration exists for this domain to park".to_owned(),
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

impl ProtocolError for ParkError {
    fn protocol(&self) -> (ErrorCode, String) {
        ParkError::protocol(self)
    }
}

/// Parks `request.domain`: snapshots its current live route to
/// `.maintenance-backup` (only if no such snapshot already exists) and
/// activates `request.maintenance_content` in its place, as one
/// preflight-locked, one-transaction-recorded operation. See this module's
/// doc comment for why this does not just call `ingress::execute::execute`
/// twice.
///
/// 1. `preflight::run`, exactly as `execute::execute`, under
///    `PARK_OPERATION` — including idempotency-key replay.
/// 2. A `PreCommit` cancellation check, exactly as `execute::execute`.
/// 3. Reads the domain's current live route file. No file at all is
///    `ParkError::NothingLive`.
/// 4. If no `.maintenance-backup` exists yet for this domain, snapshots the
///    live content just read into one (`RouteTarget::Backup`,
///    `HashGuard::Absent`) — a first park. If one already exists, it is left
///    exactly as is — a second `park` call (e.g. to update the maintenance
///    reason while already parked) must never overwrite the real
///    pre-maintenance config with whatever happens to be live right now
///    (the maintenance page itself).
/// 5. Activates `request.maintenance_content` onto the live route
///    (`RouteTarget::Live`), guarded by the hash of exactly the content
///    step 3 read — not anything the caller supplied, which is what makes
///    `ParkRequest` need no guard field of its own: this operation owns
///    the "read, then guard on what you read" invariant end to end.
/// 6. On success: commit, drop the lock, build the result, mark the
///    transaction committed, save it, append the audit record — the same
///    tail `execute::execute` has.
/// 7. On failure: the same `fail` helper, which records one `FAILED`
///    transaction (never two).
pub fn execute(
    context: &ActivateContext<'_>,
    request: &ParkRequest,
    cancellation: &CancellationToken,
) -> Result<ParkResult, ParkError> {
    let ingress_state = open_ingress_state(context.engine_state).map_err(ParkError::Io)?;

    let admitted = match preflight::run(
        &ingress_state,
        request.request_id,
        request.idempotency_key.as_ref(),
        PARK_OPERATION,
    )
    .map_err(ParkError::Preflight)?
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
            ParkError::Cancelled,
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
                ParkError::Io(error),
            ));
        }
    };

    // Step 3: the current live content, read once. Every guard below is
    // derived from exactly these bytes.
    let live_bytes = match read_optional(&root, &route_path(&request.domain)) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            return Err(fail(
                &ingress_state,
                &state_path,
                &audit_path,
                state,
                ParkError::NothingLive,
            ));
        }
        Err(error) => {
            return Err(fail(
                &ingress_state,
                &state_path,
                &audit_path,
                state,
                ParkError::Activate(error),
            ));
        }
    };
    // `activate::activate` takes `content: &str`; every route file this
    // engine has ever written came from a `String` (`ActivateConfigRequest`
    // / `ParkRequest`), so a non-UTF-8 live file here means something
    // outside this engine wrote it. Reported as an internal error rather
    // than added as a new `ParkError` variant, since it is not a state this
    // operation's own writes can produce.
    let live_content = match std::str::from_utf8(&live_bytes) {
        Ok(text) => text.to_owned(),
        Err(_) => {
            return Err(fail(
                &ingress_state,
                &state_path,
                &audit_path,
                state,
                ParkError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "live route file is not valid UTF-8",
                )),
            ));
        }
    };

    let backup_path = backup_route_path(&request.domain);
    let existing_backup = match read_optional(&root, &backup_path) {
        Ok(existing) => existing,
        Err(error) => {
            return Err(fail(
                &ingress_state,
                &state_path,
                &audit_path,
                state,
                ParkError::Activate(error),
            ));
        }
    };
    let already_parked = existing_backup.is_some();
    let backup_suffix = request.request_id.to_string();

    // Step 4/5: snapshot only on a first park. `backup_sha256` reports
    // whatever the backup now holds either way — the pre-maintenance
    // config, whether this call just wrote it or it already existed.
    let backup_sha256 = match existing_backup {
        Some(bytes) => ConfigHash::of(&bytes),
        None => {
            if let Err(error) = activate::activate(
                context.ingress_root,
                &request.domain,
                &live_content,
                &HashGuard::Absent,
                RouteTarget::Backup,
                &backup_suffix,
                context.compose,
            ) {
                return Err(fail(
                    &ingress_state,
                    &state_path,
                    &audit_path,
                    state,
                    ParkError::Activate(error),
                ));
            }
            ConfigHash::of(&live_bytes)
        }
    };

    // Step 6: the maintenance page, live, guarded on exactly what step 3
    // read.
    if let Err(error) = activate::activate(
        context.ingress_root,
        &request.domain,
        &request.maintenance_content,
        &HashGuard::Sha256(ConfigHash::of(&live_bytes)),
        RouteTarget::Live,
        &backup_suffix,
        context.compose,
    ) {
        // Judgment call: a backup this call just wrote (a first-time park,
        // `already_parked == false`) must not survive a failed live write,
        // on *any* failure branch of that write - not just the reload
        // failure this module's tests exercise. Left behind, its mere
        // existence would make a later retry's "does a backup already
        // exist" check (above) answer "yes" and report
        // `already_parked: true` for a domain whose live route was never
        // actually replaced, silently skipping the snapshot it still
        // needs. `activate::activate`'s own rollback already restores the
        // live *file* on this path (`ReloadFailedAndRestored`); this
        // removes the one piece of state that rollback does not know
        // about. A backup that already existed before this call
        // (`already_parked == true`) is never touched here, on any path -
        // it is not this call's to discard.
        //
        // Best-effort, like every other `discard` in this codebase's
        // rollback paths: the error being returned is the actionable one,
        // and a leftover `.maintenance-backup` matching the still-live
        // content is (if this removal itself fails) a false "already
        // parked" on the next attempt, not data loss - the next successful
        // park attempt would just skip re-snapshotting a live config that
        // was never replaced. That is a real, if narrow, follow-on risk;
        // see this task's report for why it is accepted here rather than
        // folded into `activate::activate`'s own atomic rollback.
        if !already_parked {
            let _ = root.remove_file(&backup_path);
        }
        return Err(fail(
            &ingress_state,
            &state_path,
            &audit_path,
            state,
            ParkError::Activate(error),
        ));
    }

    // Commit point: the live route file now holds the maintenance page and
    // the ingress server has reloaded it.
    let _post_commit = pre_commit.commit();
    drop(lock);

    let result = ParkResult {
        domain: request.domain.as_str().to_owned(),
        already_parked,
        backup_sha256,
        activated_at_unix_secs: unix_now_secs(),
    };
    let result_value = serde_json::to_value(&result).expect("ParkResult always serializes");
    state
        .mark_committed(result_value)
        .expect("state is always InProgress at this point");

    if let Err(cause) = state::save(&ingress_state, &state_path, &state) {
        return Err(ParkError::PostCommitRecordFailed { result, cause });
    }
    let _ = audit::append(
        &ingress_state,
        &audit_path,
        &AuditRecord::result(request.request_id, true, None),
    );

    Ok(result)
}

fn replay(ingress_state: &ManagedRoot, original: RequestId) -> Result<ParkResult, ParkError> {
    let original_state =
        state::load(ingress_state, &state_path_for(original)).map_err(ParkError::State)?;
    match original_state.status {
        TransactionStatus::InProgress => Err(ParkError::ReplayInProgress),
        TransactionStatus::Committed => {
            let outcome = original_state
                .outcome
                .expect("a committed transaction always has an outcome");
            let result_value = outcome
                .result
                .expect("a committed outcome always has a result");
            serde_json::from_value(result_value)
                .map_err(|_| ParkError::State(state::StateError::Corrupt))
        }
        TransactionStatus::Failed => {
            let outcome = original_state
                .outcome
                .expect("a failed transaction always has an outcome");
            Err(ParkError::Replayed {
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

    use super::{ParkError, execute};
    use crate::{
        error::ErrorCode,
        filesystem::ManagedRoot,
        ingress::{ParkRequest, ParkResult, execute::ActivateContext, fake_docker::FakeDocker},
        process::CancellationToken,
        site::TrustedRoot,
    };

    const DOMAIN: &str = "example.com";
    const ROUTE: &str = "example.com.caddyfile";
    const BACKUP_ROUTE: &str = "example.com.maintenance-backup";
    const REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const RETRY_REQUEST_ID: &str = "9b2f1c34-5678-4abc-9def-0123456789ab";
    const PREVIOUS: &str = "example.com {\n  respond \"old\"\n}\n";
    const MAINTENANCE_A: &str = "example.com {\n  respond \"down for maintenance A\"\n}\n";
    const MAINTENANCE_B: &str = "example.com {\n  respond \"down for maintenance B\"\n}\n";

    /// The engine-wide state root and the ingress root, as separate real
    /// directories - the same separation `execute.rs`'s own `Host` uses.
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

    fn request(maintenance_content: &str, request_id: &str, key: Option<&str>) -> ParkRequest {
        ParkRequest::parse(DOMAIN, maintenance_content, request_id, key)
            .expect("request should parse")
    }

    fn run(
        host: &Host,
        docker: &FakeDocker,
        request: &ParkRequest,
    ) -> Result<ParkResult, ParkError> {
        let access = docker.access();
        let context = ActivateContext {
            ingress_root: &host.ingress_root,
            engine_state: &host.engine_state,
            compose: &access,
        };
        execute(&context, request, &CancellationToken::default())
    }

    #[test]
    fn a_first_park_snapshots_live_and_activates_the_maintenance_page() {
        let host = host(Some(PREVIOUS), None);
        let docker = FakeDocker::new();

        let result = run(&host, &docker, &request(MAINTENANCE_A, REQUEST_ID, None))
            .expect("a first park should succeed");

        assert_eq!(result.domain, DOMAIN);
        assert!(!result.already_parked);
        assert_eq!(host.live().as_deref(), Some(MAINTENANCE_A));
        assert_eq!(host.backup().as_deref(), Some(PREVIOUS));

        let record = host.transaction(REQUEST_ID);
        assert_eq!(record["operation"], "ingress.park");
        assert_eq!(record["status"], "COMMITTED");
        assert_eq!(record["outcome"]["result"]["alreadyParked"], false);
    }

    #[test]
    fn parking_an_already_parked_domain_reactivates_the_maintenance_page_without_touching_the_backup()
     {
        let host = host(Some(MAINTENANCE_A), Some(PREVIOUS));
        let docker = FakeDocker::new();

        let result = run(&host, &docker, &request(MAINTENANCE_B, REQUEST_ID, None))
            .expect("re-parking an already-parked domain should succeed");

        assert!(result.already_parked);
        assert_eq!(host.live().as_deref(), Some(MAINTENANCE_B));
        assert_eq!(
            host.backup().as_deref(),
            Some(PREVIOUS),
            "the real pre-maintenance config must not be overwritten by the maintenance page"
        );
    }

    #[test]
    fn parking_a_domain_with_no_live_config_fails_closed() {
        let host = host(None, None);
        let docker = FakeDocker::new();

        let error = run(&host, &docker, &request(MAINTENANCE_A, REQUEST_ID, None))
            .expect_err("parking a domain with no live route must fail");

        assert!(matches!(error, ParkError::NothingLive));
        assert_eq!(error.protocol().0, ErrorCode::InvalidInput);
        assert!(host.live().is_none());
        assert!(host.backup().is_none());

        // A failed transaction record is expected, not absent: preflight
        // already admitted and recorded this attempt before step 3's read
        // failed.
        let record = host.transaction(REQUEST_ID);
        assert_eq!(record["status"], "FAILED");
    }

    #[test]
    fn a_retried_idempotency_key_replays_without_re_parking() {
        let host = host(Some(PREVIOUS), None);
        let docker = FakeDocker::new();
        let key = Some("park-2026-09-05-01");

        let first = run(&host, &docker, &request(MAINTENANCE_A, REQUEST_ID, key))
            .expect("the first attempt should park");
        let reloads_after_first = docker.calls("reload").len();

        let replayed = run(
            &host,
            &docker,
            &request(MAINTENANCE_B, RETRY_REQUEST_ID, key),
        )
        .expect("the retry should replay the original outcome");

        assert_eq!(replayed.domain, first.domain);
        assert_eq!(replayed.already_parked, first.already_parked);
        assert_eq!(replayed.backup_sha256, first.backup_sha256);
        assert_eq!(
            host.live().as_deref(),
            Some(MAINTENANCE_A),
            "a replay must not reactivate with the retry's own content"
        );
        assert_eq!(
            docker.calls("reload").len(),
            reloads_after_first,
            "a replay must not touch the container again"
        );
        assert!(!host.transaction_exists(RETRY_REQUEST_ID));
    }

    #[test]
    fn a_reload_failure_during_the_live_write_leaves_no_backup_orphaned() {
        let host = host(Some(PREVIOUS), None);
        let docker = FakeDocker::new().failing("reload", "1");

        let error = run(&host, &docker, &request(MAINTENANCE_A, REQUEST_ID, None))
            .expect_err("a config the server refuses to load must not park the domain");

        assert!(matches!(error, ParkError::Activate(_)));
        assert_eq!(
            host.live().as_deref(),
            Some(PREVIOUS),
            "activate::activate's own rollback restores the live file"
        );
        assert!(
            host.backup().is_none(),
            "a backup written for this failed first-time park must not survive it - \
             otherwise a later retry's \"does a backup already exist\" check would wrongly \
             report already_parked: true for a domain that was never actually parked"
        );

        let record = host.transaction(REQUEST_ID);
        assert_eq!(record["status"], "FAILED");
    }
}
