//! The assembled `ingress.activateConfig` pipeline: preflight, the
//! activation sequence, and result/audit persistence. Same shape as
//! `deploy::execute::execute` and `engine::install::execute` — see
//! `deploy::execute`'s doc comments for the reasoning behind the shared
//! preflight/commit/audit pattern; this module only orders the steps this
//! operation needs and records what happened.

use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    compose,
    error::ErrorCode,
    filesystem::ManagedRoot,
    ingress::{
        ActivateConfigRequest, ActivateConfigResult, ConfigHash, OPERATION, activate,
        activate::{ComposeFailure, RestoreFailure},
    },
    mutation::preflight,
    process::{self, CancellationToken},
    site::{SiteRelativePath, TrustedRoot},
    transaction::{
        RequestId,
        audit::{self, AuditRecord},
        commit::PreCommit,
        state::{self, TransactionState, TransactionStatus},
    },
};

/// The single subdirectory of the engine-wide state root every ingress
/// activation's lock, transaction, and audit records live under. Parallel
/// to `engine/` (`engine::state`) and `sites/<siteId>/`
/// (`mutation::preflight::open_site_state`).
const INGRESS_SUBTREE: &str = "ingress";

/// The roots and already-opened state directory an activation needs.
/// Bundled for the same reason `DeployContext` is: they are
/// request-independent, resolved once from `EngineConfig`.
pub struct ActivateContext<'a> {
    /// The one directory outside a site's own content root this operation
    /// may write into — `EngineConfig::ingress_root`.
    pub ingress_root: &'a TrustedRoot,
    /// The engine-wide state root, opened once. `execute` scopes it down
    /// to the `ingress/` subtree via `open_ingress_state`.
    pub engine_state: &'a ManagedRoot,
    /// How to reach the Compose stack that runs the ingress container.
    /// `compose::Access::default()` in production.
    pub compose: &'a compose::Access,
}

#[derive(Debug)]
pub enum ActivateConfigError {
    Io(io::Error),
    Preflight(preflight::Error),
    /// The idempotency key was already claimed, but the original attempt
    /// is still `InProgress` — nothing to replay yet.
    ReplayInProgress,
    Activate(activate::Error),
    State(state::StateError),
    Cancelled,
    /// The activation itself succeeded — the live route file was replaced
    /// and reloaded — but its `TransactionState` could not be saved
    /// afterward. Carries the result so the caller never loses it.
    PostCommitRecordFailed {
        result: ActivateConfigResult,
        cause: state::StateError,
    },
    /// A replayed request whose original attempt failed.
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl ActivateConfigError {
    /// The stable code and a safe, generic message for this failure. As
    /// everywhere else in this engine, the message is fixed text chosen
    /// here — never subprocess output, a path, or a config fragment (see
    /// `docs/protocol.md`'s `details` allowlist).
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
            // The message here is branched on whether the *first* reload
            // timed out, because that is exactly the case where the
            // restore's guarantee stops being one. `process::run` kills
            // the local `docker` client on timeout; it does not kill the
            // `caddy reload` that client already started inside the
            // container. So a timed-out reload may still land — and if it
            // lands after the restore reload, the live server ends up on
            // the *new* config while the file on disk is the old one.
            // Asserting "the previous configuration was restored and is
            // live" in that case would be claiming a property this engine
            // did not verify, in precisely the scenario the restore path
            // exists to cover. A non-timeout failure has a real exit
            // status, so the ordering is known and the assertion holds.
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
            // Deliberately one code regardless of which half of the
            // recovery failed: every variant here means the same thing to
            // a client - do not retry, the live configuration needs an
            // operator. Which half it was is in `restore`, for the caller
            // that logs the error value itself.
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

    /// Both halves of a `RecoveryFailed`, for a caller that wants to log
    /// or surface them separately. `None` for every other variant.
    pub fn recovery_failure(&self) -> Option<(&ComposeFailure, &RestoreFailure)> {
        match self {
            Self::Activate(activate::Error::RecoveryFailed { reload, restore }) => {
                Some((reload, restore))
            }
            _ => None,
        }
    }
}

/// A Compose call that could not be *run* — or that was never allowed to
/// finish — is a host/dependency problem, not a verdict on the submitted
/// configuration. Report it as such rather than telling the caller its
/// config is invalid.
///
/// `timed_out` is checked before `cancelled` because a timeout is the more
/// specific claim: the deadline is what ended the call, and the
/// cancellation flag on the same diagnostics only says the token was also
/// observed. `rejected` is reached only when the command really did run to
/// completion and return a failing status — the one case where the
/// container's verdict on the config is what the caller should hear.
fn compose_failure_code(failure: &ComposeFailure, rejected: ErrorCode) -> ErrorCode {
    match failure {
        ComposeFailure::Run(compose::Error::NoHomeDirectory) => ErrorCode::Internal,
        ComposeFailure::Run(compose::Error::Run(error)) => process::spawn_error_code(error),
        ComposeFailure::Rejected(diagnostics) => {
            if diagnostics.timed_out {
                ErrorCode::Timeout
            } else if diagnostics.cancelled {
                ErrorCode::Cancelled
            } else {
                rejected
            }
        }
    }
}

/// Whether this failure was a timeout — the one failure mode where the
/// command may still be running inside the container after this engine has
/// stopped waiting for it, so nothing observed afterward can be reported
/// as settled. See the `ReloadFailedAndRestored` arm above.
fn timed_out(failure: &ComposeFailure) -> bool {
    matches!(failure, ComposeFailure::Rejected(diagnostics) if diagnostics.timed_out)
}

pub fn execute(
    context: &ActivateContext<'_>,
    request: &ActivateConfigRequest,
    cancellation: &CancellationToken,
) -> Result<ActivateConfigResult, ActivateConfigError> {
    let ingress_state =
        open_ingress_state(context.engine_state).map_err(ActivateConfigError::Io)?;

    let admitted = match preflight::run(
        &ingress_state,
        request.request_id,
        request.idempotency_key.as_ref(),
        OPERATION,
    )
    .map_err(ActivateConfigError::Preflight)?
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
            ActivateConfigError::Cancelled,
        ));
    }

    // The backup file's suffix is this request's own `RequestId` rather
    // than fresh randomness. `website-control-panel` has no request
    // identity to reach for at this point, so it mints a
    // `random_hex_suffix()`; here every mutation already carries a
    // caller-minted canonical UUID (`ReleaseId` reuses it for exactly this
    // kind of reason, `deploy::mod`), which is unique for the same
    // purpose, needs no new randomness source, and ties any backup file
    // left behind by an interrupted run to the transaction record that
    // explains it.
    let outcome = activate::activate(
        context.ingress_root,
        &request.domain,
        &request.content,
        &request.guard,
        &request.request_id.to_string(),
        context.compose,
    );
    let activation = match outcome {
        Ok(activation) => activation,
        Err(error) => {
            return Err(fail(
                &ingress_state,
                &state_path,
                &audit_path,
                state,
                ActivateConfigError::Activate(error),
            ));
        }
    };

    // Commit point: the live route file now holds the submitted content
    // and the ingress server has reloaded it. (On the no-op path nothing
    // changed at all, but the operation is equally past the point where
    // cancelling it would mean anything.)
    let _post_commit = pre_commit.commit();
    drop(lock);

    let result = ActivateConfigResult {
        domain: request.domain.as_str().to_owned(),
        activated: activation.activated,
        content_sha256: ConfigHash::of(request.content.as_bytes()),
        activated_at_unix_secs: unix_now_secs(),
    };
    let result_value =
        serde_json::to_value(&result).expect("ActivateConfigResult always serializes");
    state
        .mark_committed(result_value)
        .expect("state is always InProgress at this point");

    if let Err(cause) = state::save(&ingress_state, &state_path, &state) {
        return Err(ActivateConfigError::PostCommitRecordFailed { result, cause });
    }
    let _ = audit::append(
        &ingress_state,
        &audit_path,
        &AuditRecord::result(request.request_id, true, None),
    );

    Ok(result)
}

/// Opens (creating if necessary) the host-wide ingress state beneath
/// `engine_state`'s `ingress/` subtree, with the
/// `locks`/`transactions`/`audit` subdirectories `mutation::preflight::run`
/// expects. Mirrors `engine::state::open_engine_state`, and for the same
/// reason: there is exactly one of these per host, so there is exactly one
/// lock.
///
/// That is a deliberate choice of granularity, not an oversight.
/// `website-control-panel` locks per domain
/// (`with_domain_lock!(server_id, &domain, ...)`), which is finer than the
/// resource actually being mutated: the reload step reloads the *whole*
/// imported config set, so two domains activating concurrently can each
/// see the other's half-applied file, and a reload failure caused by
/// domain B can send domain A's activation down its rollback path. One
/// host-wide lock makes the serialization match what is really shared.
/// Ingress config changes are operator-paced, so the throughput this costs
/// is not worth the race it removes.
pub fn open_ingress_state(engine_state: &ManagedRoot) -> io::Result<ManagedRoot> {
    let relative = SiteRelativePath::parse(INGRESS_SUBTREE).expect("literal path is valid");
    engine_state.create_dir_all(&relative)?;
    let scoped = engine_state.open_managed_dir(&relative)?;
    for sub in ["locks", "transactions", "audit"] {
        scoped.create_dir_all(&SiteRelativePath::parse(sub).expect("literal path is valid"))?;
    }
    Ok(scoped)
}

fn replay(
    ingress_state: &ManagedRoot,
    original: RequestId,
) -> Result<ActivateConfigResult, ActivateConfigError> {
    let original_state = state::load(ingress_state, &state_path_for(original))
        .map_err(ActivateConfigError::State)?;
    match original_state.status {
        TransactionStatus::InProgress => Err(ActivateConfigError::ReplayInProgress),
        TransactionStatus::Committed => {
            let outcome = original_state
                .outcome
                .expect("a committed transaction always has an outcome");
            let result_value = outcome
                .result
                .expect("a committed outcome always has a result");
            serde_json::from_value(result_value)
                .map_err(|_| ActivateConfigError::State(state::StateError::Corrupt))
        }
        TransactionStatus::Failed => {
            let outcome = original_state
                .outcome
                .expect("a failed transaction always has an outcome");
            Err(ActivateConfigError::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}

/// Records a pre-commit failure and returns `error` unchanged, exactly as
/// `deploy::execute::fail` does — persistence failures here are swallowed
/// because the original error is the actionable one and nothing was
/// activated.
fn fail(
    ingress_state: &ManagedRoot,
    state_path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut state: TransactionState,
    error: ActivateConfigError,
) -> ActivateConfigError {
    let (code, message) = error.protocol();
    let _ = state.mark_failed(code, message);
    let _ = state::save(ingress_state, state_path, &state);
    let _ = audit::append(
        ingress_state,
        audit_path,
        &AuditRecord::result(state.request_id, false, Some(code)),
    );
    error
}

fn state_path_for(request_id: RequestId) -> SiteRelativePath {
    SiteRelativePath::parse(format!("transactions/{request_id}.json"))
        .expect("a canonical RequestId always yields a valid relative path")
}

fn audit_log_path() -> SiteRelativePath {
    SiteRelativePath::parse("audit/events.jsonl").expect("literal path is valid")
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;

    use super::{ActivateConfigError, ActivateContext, execute, open_ingress_state};
    use crate::{
        error::ErrorCode,
        filesystem::ManagedRoot,
        ingress::{ActivateConfigRequest, ConfigHash, HashGuard, fake_docker::FakeDocker},
        process::CancellationToken,
        site::TrustedRoot,
        transaction::{
            RequestId,
            lock::{self, DEFAULT_STALE_AFTER},
        },
    };

    const DOMAIN: &str = "example.com";
    const ROUTE: &str = "example.com.caddyfile";
    const REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const RETRY_REQUEST_ID: &str = "9b2f1c34-5678-4abc-9def-0123456789ab";
    const PREVIOUS: &str = "example.com {\n  basicauth {\n  }\n}\n";
    const UPDATED: &str = "example.com {\n}\n";

    /// The engine-wide state root and the ingress root, as separate real
    /// directories — the same separation `EngineConfig` enforces.
    struct Host {
        state_dir: tempfile::TempDir,
        ingress_dir: tempfile::TempDir,
        ingress_root: TrustedRoot,
        engine_state: ManagedRoot,
    }

    fn host(existing: Option<&str>) -> Host {
        let state_dir = tempfile::tempdir().expect("state root should be created");
        let ingress_dir = tempfile::tempdir().expect("ingress root should be created");
        if let Some(contents) = existing {
            fs::write(ingress_dir.path().join(ROUTE), contents)
                .expect("existing route should be written");
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

        fn audit(&self) -> Vec<serde_json::Value> {
            fs::read_to_string(self.state_dir.path().join("ingress/audit/events.jsonl"))
                .expect("the audit log should exist")
                .lines()
                .map(|line| serde_json::from_str(line).expect("each audit line should be JSON"))
                .collect()
        }
    }

    fn request(guard: HashGuard, request_id: &str, key: Option<&str>) -> ActivateConfigRequest {
        ActivateConfigRequest::parse(DOMAIN, UPDATED, guard, request_id, key)
            .expect("request should parse")
    }

    fn run(
        host: &Host,
        docker: &FakeDocker,
        request: &ActivateConfigRequest,
    ) -> Result<crate::ingress::ActivateConfigResult, ActivateConfigError> {
        let access = docker.access();
        let context = ActivateContext {
            ingress_root: &host.ingress_root,
            engine_state: &host.engine_state,
            compose: &access,
        };
        execute(&context, request, &CancellationToken::default())
    }

    #[test]
    fn a_successful_activation_is_recorded_as_a_committed_transaction() {
        let host = host(None);
        let docker = FakeDocker::new();

        let result = run(
            &host,
            &docker,
            &request(HashGuard::Absent, REQUEST_ID, None),
        )
        .expect("a fresh activation should succeed");

        assert_eq!(result.domain, DOMAIN);
        assert!(result.activated);
        assert_eq!(result.content_sha256, ConfigHash::of(UPDATED.as_bytes()));
        assert_eq!(host.live().as_deref(), Some(UPDATED));

        let record = host.transaction(REQUEST_ID);
        assert_eq!(record["status"], "COMMITTED");
        assert_eq!(record["operation"], "ingress.activateConfig");
        assert_eq!(record["outcome"]["result"]["activated"], true);

        let audit = host.audit();
        assert_eq!(audit[0]["event"], "MUTATION_START");
        assert_eq!(audit[0]["operation"], "ingress.activateConfig");
        assert_eq!(audit[1]["event"], "RESULT");
        assert_eq!(audit[1]["ok"], true);
    }

    #[test]
    fn a_retried_idempotency_key_replays_the_original_result_without_reactivating() {
        let host = host(None);
        let docker = FakeDocker::new();
        let key = Some("basic-auth-off-1");

        let first = run(&host, &docker, &request(HashGuard::Absent, REQUEST_ID, key))
            .expect("the first attempt should activate");
        let reloads_after_first = docker.calls("reload").len();

        // The retry's guard would now be *wrong* (the file exists), which
        // is exactly the point: a replay must return the original outcome
        // without evaluating any of it again.
        let replayed = run(
            &host,
            &docker,
            &request(HashGuard::Absent, RETRY_REQUEST_ID, key),
        )
        .expect("the retry should replay the original outcome");

        assert!(replayed.activated);
        assert_eq!(replayed.content_sha256, first.content_sha256);
        assert_eq!(
            docker.calls("reload").len(),
            reloads_after_first,
            "a replay must not touch the container again"
        );
        // No second transaction record: the retry never started work.
        assert!(
            !host
                .state_dir
                .path()
                .join(format!("ingress/transactions/{RETRY_REQUEST_ID}.json"))
                .exists()
        );
    }

    #[test]
    fn a_stale_hash_guard_fails_closed_and_is_replayed_as_the_same_error() {
        let host = host(Some(PREVIOUS));
        let docker = FakeDocker::new();
        let key = Some("basic-auth-off-2");
        let stale = HashGuard::Sha256(ConfigHash::of(b"read before someone else wrote"));

        let error = run(&host, &docker, &request(stale.clone(), REQUEST_ID, key))
            .expect_err("a stale guard must fail");

        assert_eq!(error.protocol().0, ErrorCode::ConfigHashMismatch);
        assert_eq!(host.live().as_deref(), Some(PREVIOUS));
        assert!(docker.calls("validate").is_empty());

        let record = host.transaction(REQUEST_ID);
        assert_eq!(record["status"], "FAILED");
        assert_eq!(record["outcome"]["errorCode"], "CONFIG_HASH_MISMATCH");
        assert_eq!(host.audit()[1]["errorCode"], "CONFIG_HASH_MISMATCH");

        // A retry under the same key reports the original failure rather
        // than quietly re-running it.
        let replayed = run(&host, &docker, &request(stale, RETRY_REQUEST_ID, key))
            .expect_err("the retry should replay the original failure");
        let ActivateConfigError::Replayed { code, message } = &replayed else {
            panic!("expected a replayed failure, got {replayed:?}")
        };
        assert_eq!(*code, ErrorCode::ConfigHashMismatch);
        assert!(!message.is_empty());
    }

    #[test]
    fn a_reload_failure_is_recorded_as_a_failed_transaction_with_the_previous_file_live() {
        let host = host(Some(PREVIOUS));
        let docker = FakeDocker::new().failing("reload", "1");

        let error = run(
            &host,
            &docker,
            &request(
                HashGuard::Sha256(ConfigHash::of(PREVIOUS.as_bytes())),
                REQUEST_ID,
                None,
            ),
        )
        .expect_err("a config the server refuses to load must not stay live");

        assert_eq!(error.protocol().0, ErrorCode::ConfigReloadFailed);
        assert_eq!(host.live().as_deref(), Some(PREVIOUS));
        assert_eq!(
            host.transaction(REQUEST_ID)["outcome"]["errorCode"],
            "CONFIG_RELOAD_FAILED"
        );
    }

    #[test]
    fn a_failed_rollback_is_reported_with_both_failures_and_its_own_code() {
        let host = host(Some(PREVIOUS));
        let docker = FakeDocker::new().failing("reload", "all");

        let error = run(
            &host,
            &docker,
            &request(
                HashGuard::Sha256(ConfigHash::of(PREVIOUS.as_bytes())),
                REQUEST_ID,
                None,
            ),
        )
        .expect_err("an unrecoverable reload failure must be reported");

        assert_eq!(error.protocol().0, ErrorCode::ConfigRecoveryFailed);
        let (reload, restore) = error
            .recovery_failure()
            .expect("a recovery failure must expose both halves");
        assert!(matches!(
            reload,
            crate::ingress::activate::ComposeFailure::Rejected(_)
        ));
        assert!(matches!(
            restore,
            crate::ingress::activate::RestoreFailure::Reload(_)
        ));
    }

    #[test]
    fn re_submitting_the_current_contents_succeeds_without_activating() {
        let host = host(Some(UPDATED));
        let docker = FakeDocker::new();

        let result = run(
            &host,
            &docker,
            &request(
                HashGuard::Sha256(ConfigHash::of(UPDATED.as_bytes())),
                REQUEST_ID,
                None,
            ),
        )
        .expect("re-submitting the current contents should succeed");

        assert!(!result.activated);
        assert_eq!(host.transaction(REQUEST_ID)["status"], "COMMITTED");
        assert_eq!(
            docker.calls("reload").len(),
            1,
            "a no-op still converges the running server onto the file"
        );
    }

    #[test]
    fn a_held_ingress_lock_is_reported_as_a_conflict() {
        let host = host(None);
        let docker = FakeDocker::new();
        let ingress_state =
            open_ingress_state(&host.engine_state).expect("ingress state should open");
        let _held = lock::acquire(
            &ingress_state,
            &crate::site::SiteRelativePath::parse("locks/mutation.lock")
                .expect("literal path is valid"),
            RequestId::parse(RETRY_REQUEST_ID).expect("test UUID should be canonical"),
            DEFAULT_STALE_AFTER,
        )
        .expect("the contending lock should be acquired");

        let error = run(
            &host,
            &docker,
            &request(HashGuard::Absent, REQUEST_ID, None),
        )
        .expect_err("a held lock must block a second activation");

        assert_eq!(error.protocol().0, ErrorCode::Conflict);
        assert!(host.live().is_none());
    }

    #[test]
    fn cancellation_before_the_commit_point_activates_nothing() {
        let host = host(None);
        let docker = FakeDocker::new();
        let cancellation = CancellationToken::default();
        cancellation.cancel();

        let access = docker.access();
        let context = ActivateContext {
            ingress_root: &host.ingress_root,
            engine_state: &host.engine_state,
            compose: &access,
        };
        let error = execute(
            &context,
            &request(HashGuard::Absent, REQUEST_ID, None),
            &cancellation,
        )
        .expect_err("a cancelled request must not activate");

        assert_eq!(error.protocol().0, ErrorCode::Cancelled);
        assert!(host.live().is_none());
        assert!(docker.calls("validate").is_empty());
    }

    #[test]
    fn open_ingress_state_creates_every_expected_subdirectory_and_is_idempotent() {
        let host = host(None);
        open_ingress_state(&host.engine_state).expect("first open should succeed");
        open_ingress_state(&host.engine_state).expect("second open should also succeed");
        for sub in ["locks", "transactions", "audit"] {
            assert!(
                host.state_dir.path().join("ingress").join(sub).is_dir(),
                "ingress/{sub} should exist"
            );
        }
    }

    /// Every failure a client has to tell apart maps to its own stable
    /// code, and none of the messages leaks a path or subprocess output.
    #[test]
    fn each_failure_maps_to_its_own_protocol_code() {
        use crate::ingress::activate;

        let cases = [
            (
                ActivateConfigError::Activate(activate::Error::HashGuardMismatch),
                ErrorCode::ConfigHashMismatch,
            ),
            (
                ActivateConfigError::Activate(activate::Error::ValidateFailed(
                    activate::ComposeFailure::Rejected(diagnostics(false)),
                )),
                ErrorCode::ConfigValidationFailed,
            ),
            (
                ActivateConfigError::Activate(activate::Error::ReloadFailedAndRestored(
                    activate::ComposeFailure::Rejected(diagnostics(false)),
                )),
                ErrorCode::ConfigReloadFailed,
            ),
            (
                ActivateConfigError::Activate(activate::Error::ReloadFailedUnchanged(
                    activate::ComposeFailure::Rejected(diagnostics(false)),
                )),
                ErrorCode::ConfigReloadFailed,
            ),
            (
                ActivateConfigError::Activate(activate::Error::RecoveryFailed {
                    reload: activate::ComposeFailure::Rejected(diagnostics(false)),
                    restore: activate::RestoreFailure::File(std::io::Error::other("nope")),
                }),
                ErrorCode::ConfigRecoveryFailed,
            ),
            // A timeout is a host problem, not a verdict on the config.
            (
                ActivateConfigError::Activate(activate::Error::ValidateFailed(
                    activate::ComposeFailure::Rejected(diagnostics(true)),
                )),
                ErrorCode::Timeout,
            ),
            (ActivateConfigError::ReplayInProgress, ErrorCode::Conflict),
            (ActivateConfigError::Cancelled, ErrorCode::Cancelled),
        ];
        for (error, expected) in cases {
            let (code, message) = error.protocol();
            assert_eq!(code, expected, "wrong code for {error:?}");
            assert!(!message.is_empty());
            assert!(
                !message.contains('/'),
                "a protocol message must not carry a path: {message}"
            );
        }
    }

    /// A cancelled Compose call is not a verdict on the submitted config
    /// either: the command was stopped, not answered. Reporting it as
    /// `CONFIG_VALIDATION_FAILED`/`CONFIG_RELOAD_FAILED` would tell a
    /// client to fix a configuration that was never actually judged.
    #[test]
    fn a_cancelled_compose_call_reports_cancellation_not_a_rejected_config() {
        use crate::ingress::activate;

        let cancelled = || {
            activate::ComposeFailure::Rejected(crate::process::SubprocessDiagnostics {
                cancelled: true,
                ..diagnostics(false)
            })
        };
        for error in [
            ActivateConfigError::Activate(activate::Error::ValidateFailed(cancelled())),
            ActivateConfigError::Activate(activate::Error::ReloadFailedAndRestored(cancelled())),
        ] {
            assert_eq!(error.protocol().0, ErrorCode::Cancelled, "for {error:?}");
        }
    }

    /// The safety claim this operation's restore path exists to make -
    /// "the previous configuration was restored and is live" - is only
    /// made when this engine actually saw the failing reload finish. On a
    /// timeout it did not: `process::run` kills the local `docker` client,
    /// not the `caddy reload` already running in the container, so that
    /// reload can still land *after* the restore reload and leave the
    /// server on the new config. The message must say so rather than
    /// assert a guarantee nothing verified.
    #[test]
    fn a_timed_out_reload_does_not_claim_the_previous_config_is_live() {
        use crate::ingress::activate;

        let (settled_code, settled) =
            ActivateConfigError::Activate(activate::Error::ReloadFailedAndRestored(
                activate::ComposeFailure::Rejected(diagnostics(false)),
            ))
            .protocol();
        assert_eq!(settled_code, ErrorCode::ConfigReloadFailed);
        assert!(
            settled.contains("restored and is live"),
            "a reload that really failed still restores and reloads: {settled}"
        );

        let (timeout_code, timed_out) =
            ActivateConfigError::Activate(activate::Error::ReloadFailedAndRestored(
                activate::ComposeFailure::Rejected(diagnostics(true)),
            ))
            .protocol();
        assert_eq!(timeout_code, ErrorCode::Timeout);
        assert!(
            !timed_out.contains("is live"),
            "a timed-out reload must not assert what is live: {timed_out}"
        );
        assert!(
            timed_out.contains("could not be confirmed"),
            "a timed-out reload must say the outcome is unconfirmed: {timed_out}"
        );
        assert!(
            !timed_out.contains('/'),
            "a protocol message must not carry a path: {timed_out}"
        );
    }

    fn diagnostics(timed_out: bool) -> crate::process::SubprocessDiagnostics {
        crate::process::SubprocessDiagnostics {
            program: "caddy validate".to_owned(),
            exit_code: if timed_out { None } else { Some(1) },
            timed_out,
            cancelled: false,
            stdout_truncated: false,
            stderr_truncated: false,
        }
    }
}
