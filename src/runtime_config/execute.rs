//! The assembled `runtime.activateConfig` pipeline: preflight, the
//! activation sequence, and result/audit persistence. Same shape as
//! `ingress::execute::execute` — see that module's doc comments for the
//! reasoning behind the shared preflight/commit/audit pattern; this module
//! only orders the steps this operation needs and records what happened.

use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    compose,
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{self, CancellationToken},
    runtime_config::{
        ConfigHash, OPERATION, RuntimeActivateConfigRequest, RuntimeActivateConfigResult, activate,
        activate::{ComposeFailure, RestoreFailure},
    },
    site::{RuntimeId, SiteRelativePath, TrustedRoot},
    transaction::{
        RequestId,
        audit::{self, AuditRecord},
        commit::PreCommit,
        state::{self, TransactionState, TransactionStatus},
    },
};

/// The roots and already-opened state directory an activation needs.
/// Bundled for the same reason `ingress::execute::ActivateContext` is: they
/// are request-independent, resolved once from `EngineConfig`.
pub struct RuntimeActivateContext<'a> {
    /// The one directory outside a site's own content root this operation
    /// may write into — `EngineConfig::runtime_root`.
    pub runtime_root: &'a TrustedRoot,
    /// The engine-wide state root, opened once. `execute` scopes it down to
    /// the per-`runtime_id` subtree via `open_runtime_config_state`.
    pub engine_state: &'a ManagedRoot,
    /// How to reach the Compose stack that runs the runtime-service
    /// containers. `compose::Access::default()` in production.
    pub compose: &'a compose::Access,
}

#[derive(Debug)]
pub enum RuntimeActivateConfigError {
    Io(io::Error),
    Preflight(preflight::Error),
    /// The idempotency key was already claimed, but the original attempt is
    /// still `InProgress` — nothing to replay yet.
    ReplayInProgress,
    Activate(activate::Error),
    State(state::StateError),
    Cancelled,
    /// The activation itself succeeded — the fragment was replaced and
    /// reloaded — but its `TransactionState` could not be saved afterward.
    /// Carries the result so the caller never loses it.
    PostCommitRecordFailed {
        result: RuntimeActivateConfigResult,
        cause: state::StateError,
    },
    /// A replayed request whose original attempt failed.
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl RuntimeActivateConfigError {
    /// The stable code and a safe, generic message for this failure —
    /// mirrors `ingress::execute::ActivateConfigError::protocol` variant for
    /// variant; every code here is already generic (not ingress-named), so
    /// nothing new is introduced. See `src/error.rs`'s `ErrorCode` doc
    /// comments for what each one promises.
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Io(_) | Self::State(_) | Self::PostCommitRecordFailed { .. } => (
                ErrorCode::Internal,
                "internal runtime config activation error".to_owned(),
            ),
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another activation for this runtime pool is already in progress".to_owned(),
            ),
            Self::Preflight(_) => (ErrorCode::Internal, "preflight failed".to_owned()),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request for this idempotency key is still in progress".to_owned(),
            ),
            Self::Activate(activate::Error::Io(_)) => (
                ErrorCode::Internal,
                "internal runtime config activation error".to_owned(),
            ),
            Self::Activate(activate::Error::Path(_)) => (
                ErrorCode::InvalidInput,
                "the fragment does not resolve inside the configured runtime root".to_owned(),
            ),
            Self::Activate(activate::Error::HashGuardMismatch) => (
                ErrorCode::ConfigHashMismatch,
                "the configuration changed since it was read - re-read it and retry".to_owned(),
            ),
            Self::Activate(activate::Error::ValidateFailed(failure)) => (
                compose_failure_code(failure, ErrorCode::ConfigValidationFailed),
                "the submitted configuration was rejected before it was activated".to_owned(),
            ),
            // Same timeout-vs-settled distinction as
            // `ingress::execute::ActivateConfigError::protocol` — see its
            // doc comment for why a timed-out reload cannot claim the
            // restore is confirmed live.
            Self::Activate(activate::Error::ReloadFailedAndRestored(failure)) => (
                compose_failure_code(failure, ErrorCode::ConfigReloadFailed),
                if timed_out(failure) {
                    "the submitted configuration timed out while loading; the previous \
                     configuration was put back on disk, but whether the running server is on \
                     it could not be confirmed - verify the live runtime configuration"
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
                 runtime configuration needs manual inspection"
                    .to_owned(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before the commit point".to_owned(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
        }
    }

    /// Both halves of a `RecoveryFailed`, for a caller that wants to log or
    /// surface them separately. `None` for every other variant.
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
/// configuration. See `ingress::execute::compose_failure_code`'s doc
/// comment; identical reasoning.
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

/// See `ingress::execute::timed_out`'s doc comment; identical reasoning.
fn timed_out(failure: &ComposeFailure) -> bool {
    matches!(failure, ComposeFailure::Rejected(diagnostics) if diagnostics.timed_out)
}

pub fn execute(
    context: &RuntimeActivateContext<'_>,
    request: &RuntimeActivateConfigRequest,
    cancellation: &CancellationToken,
) -> Result<RuntimeActivateConfigResult, RuntimeActivateConfigError> {
    let runtime_state = open_runtime_config_state(context.engine_state, &request.runtime_id)
        .map_err(RuntimeActivateConfigError::Io)?;

    let admitted = match preflight::run(
        &runtime_state,
        request.request_id,
        request.idempotency_key.as_ref(),
        OPERATION,
    )
    .map_err(RuntimeActivateConfigError::Preflight)?
    {
        preflight::Outcome::Replay(original) => return replay(&runtime_state, original),
        preflight::Outcome::Proceed(admitted) => admitted,
    };
    let preflight::Admitted { lock, mut state } = admitted;

    let state_path = state_path_for(request.request_id);
    let audit_path = audit_log_path();
    let pre_commit = PreCommit::new(cancellation.clone());

    if pre_commit.check().is_err() {
        return Err(fail(
            &runtime_state,
            &state_path,
            &audit_path,
            state,
            RuntimeActivateConfigError::Cancelled,
        ));
    }

    // The backup file's suffix is this request's own `RequestId`, same
    // reasoning as `ingress::execute::execute`'s identical choice.
    let outcome = activate::activate(
        context.runtime_root,
        &request.runtime_id,
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
                &runtime_state,
                &state_path,
                &audit_path,
                state,
                RuntimeActivateConfigError::Activate(error),
            ));
        }
    };

    // Commit point: the runtime-service container now holds the submitted
    // content and has reloaded it.
    let _post_commit = pre_commit.commit();
    drop(lock);

    let result = RuntimeActivateConfigResult {
        runtime_id: request.runtime_id.as_str().to_owned(),
        domain: request.domain.as_str().to_owned(),
        activated: activation.activated,
        content_sha256: ConfigHash::of(request.content.as_bytes()),
        activated_at_unix_secs: unix_now_secs(),
    };
    let result_value =
        serde_json::to_value(&result).expect("RuntimeActivateConfigResult always serializes");
    state
        .mark_committed(result_value)
        .expect("state is always InProgress at this point");

    if let Err(cause) = state::save(&runtime_state, &state_path, &state) {
        return Err(RuntimeActivateConfigError::PostCommitRecordFailed { result, cause });
    }
    let _ = audit::append(
        &runtime_state,
        &audit_path,
        &AuditRecord::result(request.request_id, true, None),
    );

    Ok(result)
}

/// Opens (creating if necessary) this `runtime_id`'s own state subtree
/// beneath `engine_state`'s `runtime-config/<runtime_id>/` — one lock per
/// runtime pool, deliberately **not** one host-wide lock like
/// `ingress::execute::open_ingress_state`, and **not** one per domain
/// either.
///
/// The resource a reload actually shares is everything imported by *that
/// one runtime-service container's* Caddyfile — every domain currently
/// assigned to that same runtime pool — exactly the same "the lock has to
/// match what a reload really touches" reasoning `ingress`'s host-wide lock
/// documents (its own 2026-09-04 decision log entry). But unlike ingress,
/// where there is only one shared container, two different runtime pools
/// (`fp1-php83` vs `fp1-php84`) share nothing: reloading one's Caddy never
/// observes or is observed by the other's imported config set, so serializing
/// activations across different runtime pools would cost throughput for a
/// race that cannot occur. Per-`runtime_id` is therefore the correct
/// granularity — coarser than per-domain (matches what a reload actually
/// touches), finer than host-wide (matches what it does not).
pub fn open_runtime_config_state(
    engine_state: &ManagedRoot,
    runtime_id: &RuntimeId,
) -> io::Result<ManagedRoot> {
    let relative = SiteRelativePath::parse(format!("runtime-config/{runtime_id}"))
        .expect("a validated RuntimeId always yields a valid relative path");
    engine_state.create_dir_all(&relative)?;
    let scoped = engine_state.open_managed_dir(&relative)?;
    for sub in ["locks", "transactions", "audit"] {
        scoped.create_dir_all(&SiteRelativePath::parse(sub).expect("literal path is valid"))?;
    }
    Ok(scoped)
}

fn replay(
    runtime_state: &ManagedRoot,
    original: RequestId,
) -> Result<RuntimeActivateConfigResult, RuntimeActivateConfigError> {
    let original_state = state::load(runtime_state, &state_path_for(original))
        .map_err(RuntimeActivateConfigError::State)?;
    if original_state.operation != OPERATION {
        return Err(RuntimeActivateConfigError::State(
            state::StateError::Corrupt,
        ));
    }
    match original_state.status {
        TransactionStatus::InProgress => Err(RuntimeActivateConfigError::ReplayInProgress),
        TransactionStatus::Committed => {
            let outcome = original_state
                .outcome
                .expect("a committed transaction always has an outcome");
            let result_value = outcome
                .result
                .expect("a committed outcome always has a result");
            serde_json::from_value(result_value)
                .map_err(|_| RuntimeActivateConfigError::State(state::StateError::Corrupt))
        }
        TransactionStatus::Failed => {
            let outcome = original_state
                .outcome
                .expect("a failed transaction always has an outcome");
            Err(RuntimeActivateConfigError::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}

/// Records a pre-commit failure and returns `error` unchanged — see
/// `ingress::execute::fail`'s doc comment. Not reused directly because it
/// is generic over `ingress::execute::ProtocolError`, a `pub(crate)` trait
/// private to that module; duplicating this ~10-line function is cheaper
/// than widening that trait's visibility for one more implementor outside
/// its own module tree.
fn fail(
    runtime_state: &ManagedRoot,
    state_path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut state: TransactionState,
    error: RuntimeActivateConfigError,
) -> RuntimeActivateConfigError {
    let (code, message) = error.protocol();
    let _ = state.mark_failed(code, message);
    let _ = state::save(runtime_state, state_path, &state);
    let _ = audit::append(
        runtime_state,
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

    use super::{
        RuntimeActivateConfigError, RuntimeActivateContext, execute, open_runtime_config_state,
    };
    use crate::{
        error::ErrorCode,
        filesystem::ManagedRoot,
        ingress::{ConfigHash, HashGuard, fake_docker::FakeDocker},
        process::CancellationToken,
        runtime_config::RuntimeActivateConfigRequest,
        site::{RuntimeId, TrustedRoot},
        transaction::{
            RequestId,
            lock::{self, DEFAULT_STALE_AFTER},
        },
    };

    const RUNTIME_ID: &str = "fp1-php83";
    const OTHER_RUNTIME_ID: &str = "fp1-php84";
    const DOMAIN: &str = "example.com";
    const REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const RETRY_REQUEST_ID: &str = "9b2f1c34-5678-4abc-9def-0123456789ab";
    const PREVIOUS: &str = "example.com {\n  respond \"old\"\n}\n";
    const UPDATED: &str = "example.com {\n}\n";

    /// The engine-wide state root and the runtime root, as separate real
    /// directories — the same separation `EngineConfig` enforces.
    struct Host {
        state_dir: tempfile::TempDir,
        runtime_dir: tempfile::TempDir,
        runtime_root: TrustedRoot,
        engine_state: ManagedRoot,
    }

    fn host(existing: Option<&str>) -> Host {
        let state_dir = tempfile::tempdir().expect("state root should be created");
        let runtime_dir = tempfile::tempdir().expect("runtime root should be created");
        if let Some(contents) = existing {
            let subdir = runtime_dir.path().join(RUNTIME_ID);
            fs::create_dir_all(&subdir).expect("runtime-id subdirectory should be created");
            fs::write(subdir.join(format!("{DOMAIN}.caddyfile")), contents)
                .expect("existing fragment should be written");
        }
        let engine_state = ManagedRoot::open(
            &TrustedRoot::parse(state_dir.path()).expect("state root should be valid"),
        )
        .expect("state root should open");
        let runtime_root =
            TrustedRoot::parse(runtime_dir.path()).expect("runtime root should be valid");
        Host {
            state_dir,
            runtime_dir,
            runtime_root,
            engine_state,
        }
    }

    impl Host {
        fn live(&self) -> Option<String> {
            fs::read_to_string(
                self.runtime_dir
                    .path()
                    .join(RUNTIME_ID)
                    .join(format!("{DOMAIN}.caddyfile")),
            )
            .ok()
        }

        fn transaction(&self, runtime_id: &str, request_id: &str) -> serde_json::Value {
            let path = self.state_dir.path().join(format!(
                "runtime-config/{runtime_id}/transactions/{request_id}.json"
            ));
            serde_json::from_str(
                &fs::read_to_string(path).expect("the transaction record should exist"),
            )
            .expect("the transaction record should be JSON")
        }

        fn audit(&self, runtime_id: &str) -> Vec<serde_json::Value> {
            fs::read_to_string(
                self.state_dir
                    .path()
                    .join(format!("runtime-config/{runtime_id}/audit/events.jsonl")),
            )
            .expect("the audit log should exist")
            .lines()
            .map(|line| serde_json::from_str(line).expect("each audit line should be JSON"))
            .collect()
        }
    }

    fn request(
        runtime_id: &str,
        guard: HashGuard,
        request_id: &str,
        key: Option<&str>,
    ) -> RuntimeActivateConfigRequest {
        RuntimeActivateConfigRequest::parse(runtime_id, DOMAIN, UPDATED, guard, request_id, key)
            .expect("request should parse")
    }

    fn run(
        host: &Host,
        docker: &FakeDocker,
        request: &RuntimeActivateConfigRequest,
    ) -> Result<crate::runtime_config::RuntimeActivateConfigResult, RuntimeActivateConfigError>
    {
        let access = docker.access();
        let context = RuntimeActivateContext {
            runtime_root: &host.runtime_root,
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
            &request(RUNTIME_ID, HashGuard::Absent, REQUEST_ID, None),
        )
        .expect("a fresh activation should succeed");

        assert_eq!(result.runtime_id, RUNTIME_ID);
        assert_eq!(result.domain, DOMAIN);
        assert!(result.activated);
        assert_eq!(result.content_sha256, ConfigHash::of(UPDATED.as_bytes()));
        assert_eq!(host.live().as_deref(), Some(UPDATED));

        let record = host.transaction(RUNTIME_ID, REQUEST_ID);
        assert_eq!(record["status"], "COMMITTED");
        assert_eq!(record["operation"], "runtime.activateConfig");
        assert_eq!(record["outcome"]["result"]["activated"], true);

        let audit = host.audit(RUNTIME_ID);
        assert_eq!(audit[0]["event"], "MUTATION_START");
        assert_eq!(audit[0]["operation"], "runtime.activateConfig");
        assert_eq!(audit[1]["event"], "RESULT");
        assert_eq!(audit[1]["ok"], true);
    }

    #[test]
    fn a_retried_idempotency_key_replays_the_original_result_without_reactivating() {
        let host = host(None);
        let docker = FakeDocker::new();
        let key = Some("runtime-cutover-1");

        let first = run(
            &host,
            &docker,
            &request(RUNTIME_ID, HashGuard::Absent, REQUEST_ID, key),
        )
        .expect("the first attempt should activate");
        let reloads_after_first = docker.calls("reload").len();

        let replayed = run(
            &host,
            &docker,
            &request(RUNTIME_ID, HashGuard::Absent, RETRY_REQUEST_ID, key),
        )
        .expect("the retry should replay the original outcome");

        assert!(replayed.activated);
        assert_eq!(replayed.content_sha256, first.content_sha256);
        assert_eq!(
            docker.calls("reload").len(),
            reloads_after_first,
            "a replay must not touch the container again"
        );
        assert!(
            !host
                .state_dir
                .path()
                .join(format!(
                    "runtime-config/{RUNTIME_ID}/transactions/{RETRY_REQUEST_ID}.json"
                ))
                .exists()
        );
    }

    #[test]
    fn a_stale_hash_guard_fails_closed_and_is_replayed_as_the_same_error() {
        let host = host(Some(PREVIOUS));
        let docker = FakeDocker::new();
        let key = Some("runtime-cutover-2");
        let stale = HashGuard::Sha256(ConfigHash::of(b"read before someone else wrote"));

        let error = run(
            &host,
            &docker,
            &request(RUNTIME_ID, stale.clone(), REQUEST_ID, key),
        )
        .expect_err("a stale guard must fail");

        assert_eq!(error.protocol().0, ErrorCode::ConfigHashMismatch);
        assert_eq!(host.live().as_deref(), Some(PREVIOUS));
        assert!(docker.calls("validate").is_empty());

        let record = host.transaction(RUNTIME_ID, REQUEST_ID);
        assert_eq!(record["status"], "FAILED");
        assert_eq!(record["outcome"]["errorCode"], "CONFIG_HASH_MISMATCH");
        assert_eq!(
            host.audit(RUNTIME_ID)[1]["errorCode"],
            "CONFIG_HASH_MISMATCH"
        );

        let replayed = run(
            &host,
            &docker,
            &request(RUNTIME_ID, stale, RETRY_REQUEST_ID, key),
        )
        .expect_err("the retry should replay the original failure");
        let RuntimeActivateConfigError::Replayed { code, message } = &replayed else {
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
                RUNTIME_ID,
                HashGuard::Sha256(ConfigHash::of(PREVIOUS.as_bytes())),
                REQUEST_ID,
                None,
            ),
        )
        .expect_err("a config the server refuses to load must not stay live");

        assert_eq!(error.protocol().0, ErrorCode::ConfigReloadFailed);
        assert_eq!(host.live().as_deref(), Some(PREVIOUS));
        assert_eq!(
            host.transaction(RUNTIME_ID, REQUEST_ID)["outcome"]["errorCode"],
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
                RUNTIME_ID,
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
            crate::runtime_config::activate::ComposeFailure::Rejected(_)
        ));
        assert!(matches!(
            restore,
            crate::runtime_config::activate::RestoreFailure::Reload(_)
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
                RUNTIME_ID,
                HashGuard::Sha256(ConfigHash::of(UPDATED.as_bytes())),
                REQUEST_ID,
                None,
            ),
        )
        .expect("re-submitting the current contents should succeed");

        assert!(!result.activated);
        assert_eq!(
            host.transaction(RUNTIME_ID, REQUEST_ID)["status"],
            "COMMITTED"
        );
        assert_eq!(
            docker.calls("reload").len(),
            1,
            "a no-op still converges the running server onto the file"
        );
    }

    #[test]
    fn a_held_lock_for_the_same_runtime_id_is_reported_as_a_conflict() {
        let host = host(None);
        let docker = FakeDocker::new();
        let runtime_state = open_runtime_config_state(
            &host.engine_state,
            &RuntimeId::parse(RUNTIME_ID).expect("test runtime id should be valid"),
        )
        .expect("runtime state should open");
        let _held = lock::acquire(
            &runtime_state,
            &crate::site::SiteRelativePath::parse("locks/mutation.lock")
                .expect("literal path is valid"),
            RequestId::parse(RETRY_REQUEST_ID).expect("test UUID should be canonical"),
            DEFAULT_STALE_AFTER,
        )
        .expect("the contending lock should be acquired");

        let error = run(
            &host,
            &docker,
            &request(RUNTIME_ID, HashGuard::Absent, REQUEST_ID, None),
        )
        .expect_err("a held lock must block a second activation for the same runtime id");

        assert_eq!(error.protocol().0, ErrorCode::Conflict);
        assert!(host.live().is_none());
    }

    /// The lock-granularity proof this module exists to make: two different
    /// runtime pools never serialize against each other, unlike
    /// `ingress.activateConfig`'s single host-wide lock.
    #[test]
    fn a_held_lock_for_a_different_runtime_id_does_not_block_this_one() {
        let host = host(None);
        let docker = FakeDocker::new();
        let other_state = open_runtime_config_state(
            &host.engine_state,
            &RuntimeId::parse(OTHER_RUNTIME_ID).expect("test runtime id should be valid"),
        )
        .expect("runtime state should open");
        let _held = lock::acquire(
            &other_state,
            &crate::site::SiteRelativePath::parse("locks/mutation.lock")
                .expect("literal path is valid"),
            RequestId::parse(RETRY_REQUEST_ID).expect("test UUID should be canonical"),
            DEFAULT_STALE_AFTER,
        )
        .expect("the other runtime id's lock should be acquired");

        let result = run(
            &host,
            &docker,
            &request(RUNTIME_ID, HashGuard::Absent, REQUEST_ID, None),
        )
        .expect("a lock held for a different runtime id must not block this activation");

        assert!(result.activated);
    }

    #[test]
    fn cancellation_before_the_commit_point_activates_nothing() {
        let host = host(None);
        let docker = FakeDocker::new();
        let cancellation = CancellationToken::default();
        cancellation.cancel();

        let access = docker.access();
        let context = RuntimeActivateContext {
            runtime_root: &host.runtime_root,
            engine_state: &host.engine_state,
            compose: &access,
        };
        let error = execute(
            &context,
            &request(RUNTIME_ID, HashGuard::Absent, REQUEST_ID, None),
            &cancellation,
        )
        .expect_err("a cancelled request must not activate");

        assert_eq!(error.protocol().0, ErrorCode::Cancelled);
        assert!(host.live().is_none());
        assert!(docker.calls("validate").is_empty());
    }

    #[test]
    fn open_runtime_config_state_creates_every_expected_subdirectory_and_is_idempotent() {
        let host = host(None);
        let runtime_id = RuntimeId::parse(RUNTIME_ID).expect("test runtime id should be valid");
        open_runtime_config_state(&host.engine_state, &runtime_id)
            .expect("first open should succeed");
        open_runtime_config_state(&host.engine_state, &runtime_id)
            .expect("second open should also succeed");
        for sub in ["locks", "transactions", "audit"] {
            assert!(
                host.state_dir
                    .path()
                    .join(format!("runtime-config/{RUNTIME_ID}"))
                    .join(sub)
                    .is_dir(),
                "runtime-config/{RUNTIME_ID}/{sub} should exist"
            );
        }
    }

    #[test]
    fn each_failure_maps_to_its_own_protocol_code() {
        use crate::runtime_config::activate;

        let cases = [
            (
                RuntimeActivateConfigError::Activate(activate::Error::HashGuardMismatch),
                ErrorCode::ConfigHashMismatch,
            ),
            (
                RuntimeActivateConfigError::Activate(activate::Error::ValidateFailed(
                    activate::ComposeFailure::Rejected(diagnostics(false)),
                )),
                ErrorCode::ConfigValidationFailed,
            ),
            (
                RuntimeActivateConfigError::Activate(activate::Error::ReloadFailedAndRestored(
                    activate::ComposeFailure::Rejected(diagnostics(false)),
                )),
                ErrorCode::ConfigReloadFailed,
            ),
            (
                RuntimeActivateConfigError::Activate(activate::Error::ReloadFailedUnchanged(
                    activate::ComposeFailure::Rejected(diagnostics(false)),
                )),
                ErrorCode::ConfigReloadFailed,
            ),
            (
                RuntimeActivateConfigError::Activate(activate::Error::RecoveryFailed {
                    reload: activate::ComposeFailure::Rejected(diagnostics(false)),
                    restore: activate::RestoreFailure::File(std::io::Error::other("nope")),
                }),
                ErrorCode::ConfigRecoveryFailed,
            ),
            (
                RuntimeActivateConfigError::Activate(activate::Error::ValidateFailed(
                    activate::ComposeFailure::Rejected(diagnostics(true)),
                )),
                ErrorCode::Timeout,
            ),
            (
                RuntimeActivateConfigError::ReplayInProgress,
                ErrorCode::Conflict,
            ),
            (RuntimeActivateConfigError::Cancelled, ErrorCode::Cancelled),
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

    #[test]
    fn a_cancelled_compose_call_reports_cancellation_not_a_rejected_config() {
        use crate::runtime_config::activate;

        let cancelled = || {
            activate::ComposeFailure::Rejected(crate::process::SubprocessDiagnostics {
                cancelled: true,
                ..diagnostics(false)
            })
        };
        for error in [
            RuntimeActivateConfigError::Activate(activate::Error::ValidateFailed(cancelled())),
            RuntimeActivateConfigError::Activate(activate::Error::ReloadFailedAndRestored(
                cancelled(),
            )),
        ] {
            assert_eq!(error.protocol().0, ErrorCode::Cancelled, "for {error:?}");
        }
    }

    #[test]
    fn a_timed_out_reload_does_not_claim_the_previous_config_is_live() {
        use crate::runtime_config::activate;

        let (settled_code, settled) =
            RuntimeActivateConfigError::Activate(activate::Error::ReloadFailedAndRestored(
                activate::ComposeFailure::Rejected(diagnostics(false)),
            ))
            .protocol();
        assert_eq!(settled_code, ErrorCode::ConfigReloadFailed);
        assert!(
            settled.contains("restored and is live"),
            "a reload that really failed still restores and reloads: {settled}"
        );

        let (timeout_code, timed_out) =
            RuntimeActivateConfigError::Activate(activate::Error::ReloadFailedAndRestored(
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
