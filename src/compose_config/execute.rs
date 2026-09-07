//! The assembled `compose.activateConfig` pipeline: preflight, the
//! activation sequence, and result/audit persistence. Same shape as
//! `runtime_config::execute::execute` - see `ingress::execute`'s doc
//! comments for the reasoning behind the shared preflight/commit/audit
//! pattern; this module only orders the steps this operation needs.

use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    compose_config::{
        ComposeActivateConfigRequest, ComposeActivateConfigResult, ConfigHash, OPERATION, activate,
        activate::{ComposeFailure, RestoreFailure},
    },
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{self, CancellationToken},
    site::{SiteRelativePath, StackName, TrustedRoot},
    transaction::{
        RequestId,
        audit::{self, AuditRecord},
        commit::PreCommit,
        state::{self, TransactionState, TransactionStatus},
    },
};

/// The roots and already-opened state directory an activation needs.
/// `compose_root` is resolved by the caller (`commands::compose_config`) via
/// `crate::compose::compose_root_dir` before this context is built - see
/// `compose_config::mod`'s doc comment for why that resolution does not
/// live in `EngineConfig` the way every other root here does.
pub struct ComposeActivateContext<'a> {
    pub compose_root: &'a TrustedRoot,
    /// The engine-wide state root, opened once. `execute` scopes it down to
    /// the per-`stack_name` subtree via `open_compose_state`.
    pub engine_state: &'a ManagedRoot,
    /// `PATH` override for the spawned `docker compose` children. `None` in
    /// production (resolves against this process's real `PATH`); tests
    /// point it at a fake `docker` fixture.
    pub docker_path: Option<&'a std::ffi::OsStr>,
}

#[derive(Debug)]
pub enum ComposeActivateConfigError {
    Io(io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Activate(activate::Error),
    State(state::StateError),
    Cancelled,
    PostCommitRecordFailed {
        result: ComposeActivateConfigResult,
        cause: state::StateError,
    },
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl ComposeActivateConfigError {
    /// See `runtime_config::execute::RuntimeActivateConfigError::protocol`'s
    /// doc comment; identical structure, "runtime"/"fragment" wording
    /// swapped for "compose"/"stack".
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Io(_) | Self::State(_) | Self::PostCommitRecordFailed { .. } => (
                ErrorCode::Internal,
                "internal compose activation error".to_owned(),
            ),
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another activation for this compose stack is already in progress".to_owned(),
            ),
            Self::Preflight(_) => (ErrorCode::Internal, "preflight failed".to_owned()),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request for this idempotency key is still in progress".to_owned(),
            ),
            Self::Activate(activate::Error::Io(_)) => (
                ErrorCode::Internal,
                "internal compose activation error".to_owned(),
            ),
            Self::Activate(activate::Error::Path(_)) => (
                ErrorCode::InvalidInput,
                "the compose file does not resolve inside the configured compose root".to_owned(),
            ),
            Self::Activate(activate::Error::HashGuardMismatch) => (
                ErrorCode::ConfigHashMismatch,
                "the configuration changed since it was read - re-read it and retry".to_owned(),
            ),
            Self::Activate(activate::Error::ValidateFailed(failure)) => (
                compose_failure_code(failure, ErrorCode::ConfigValidationFailed),
                "the submitted compose file was rejected before it was activated".to_owned(),
            ),
            Self::Activate(activate::Error::ReloadFailedAndRestored(failure)) => (
                compose_failure_code(failure, ErrorCode::ConfigReloadFailed),
                if timed_out(failure) {
                    "the submitted compose file timed out while coming up; the previous \
                     file was put back on disk, but whether the stack is actually on it \
                     could not be confirmed - verify the live stack"
                } else {
                    "the submitted compose file failed to come up; the previous file was \
                     restored and is live"
                }
                .to_owned(),
            ),
            Self::Activate(activate::Error::ReloadFailedUnchanged(failure)) => (
                compose_failure_code(failure, ErrorCode::ConfigReloadFailed),
                "the compose file was already in place but the stack failed to come up; \
                 nothing was changed"
                    .to_owned(),
            ),
            Self::Activate(activate::Error::RecoveryFailed { .. }) => (
                ErrorCode::ConfigRecoveryFailed,
                "the compose file failed to come up and could not be rolled back; the live \
                 stack needs manual inspection"
                    .to_owned(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before the commit point".to_owned(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
        }
    }

    pub fn recovery_failure(&self) -> Option<(&ComposeFailure, &RestoreFailure)> {
        match self {
            Self::Activate(activate::Error::RecoveryFailed { reload, restore }) => {
                Some((reload, restore))
            }
            _ => None,
        }
    }
}

/// A `docker compose` call that could not be *run*, or was rejected. See
/// `runtime_config::execute::compose_failure_code`'s doc comment; this
/// module's `ComposeFailure::Run` already carries a `ProcessRunError`
/// directly (no `compose::Error`/`NoHomeDirectory` wrapper - this
/// operation's root is resolved once, before this context is built, not
/// re-resolved per subprocess call), so the mapping is one layer flatter.
fn compose_failure_code(failure: &ComposeFailure, rejected: ErrorCode) -> ErrorCode {
    match failure {
        ComposeFailure::Run(error) => process::spawn_error_code(error),
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

fn timed_out(failure: &ComposeFailure) -> bool {
    matches!(failure, ComposeFailure::Rejected(diagnostics) if diagnostics.timed_out)
}

pub fn execute(
    context: &ComposeActivateContext<'_>,
    request: &ComposeActivateConfigRequest,
    cancellation: &CancellationToken,
) -> Result<ComposeActivateConfigResult, ComposeActivateConfigError> {
    let compose_state = open_compose_state(context.engine_state, &request.stack_name)
        .map_err(ComposeActivateConfigError::Io)?;

    let admitted = match preflight::run(
        &compose_state,
        request.request_id,
        request.idempotency_key.as_ref(),
        OPERATION,
    )
    .map_err(ComposeActivateConfigError::Preflight)?
    {
        preflight::Outcome::Replay(original) => return replay(&compose_state, original),
        preflight::Outcome::Proceed(admitted) => admitted,
    };
    let preflight::Admitted { lock, mut state } = admitted;

    let state_path = state_path_for(request.request_id);
    let audit_path = audit_log_path();
    let pre_commit = PreCommit::new(cancellation.clone());

    if pre_commit.check().is_err() {
        return Err(fail(
            &compose_state,
            &state_path,
            &audit_path,
            state,
            ComposeActivateConfigError::Cancelled,
        ));
    }

    let outcome = activate::activate(
        context.compose_root,
        &request.stack_name,
        &request.content,
        &request.guard,
        &request.request_id.to_string(),
        context.docker_path,
    );
    let activation = match outcome {
        Ok(activation) => activation,
        Err(error) => {
            return Err(fail(
                &compose_state,
                &state_path,
                &audit_path,
                state,
                ComposeActivateConfigError::Activate(error),
            ));
        }
    };

    // Commit point: the stack's compose file now holds the submitted
    // content and the stack has been brought up against it.
    let _post_commit = pre_commit.commit();
    drop(lock);

    let result = ComposeActivateConfigResult {
        stack_name: request.stack_name.as_str().to_owned(),
        activated: activation.activated,
        content_sha256: ConfigHash::of(request.content.as_bytes()),
        activated_at_unix_secs: unix_now_secs(),
    };
    let result_value =
        serde_json::to_value(&result).expect("ComposeActivateConfigResult always serializes");
    state
        .mark_committed(result_value)
        .expect("state is always InProgress at this point");

    if let Err(cause) = state::save(&compose_state, &state_path, &state) {
        return Err(ComposeActivateConfigError::PostCommitRecordFailed { result, cause });
    }
    let _ = audit::append(
        &compose_state,
        &audit_path,
        &AuditRecord::result(request.request_id, true, None),
    );

    Ok(result)
}

/// Opens (creating if necessary) this stack's own state subtree beneath
/// `engine_state`'s `compose/<stack_name>/` - one lock per stack, mirroring
/// `runtime_config::execute::open_runtime_config_state`'s per-`runtime_id`
/// reasoning exactly: two different stacks share nothing a reload could
/// race on, two edits to the *same* stack's file do.
pub fn open_compose_state(
    engine_state: &ManagedRoot,
    stack_name: &StackName,
) -> io::Result<ManagedRoot> {
    let relative = SiteRelativePath::parse(format!("compose/{stack_name}"))
        .expect("a validated StackName always yields a valid relative path");
    engine_state.create_dir_all(&relative)?;
    let scoped = engine_state.open_managed_dir(&relative)?;
    for sub in ["locks", "transactions", "audit"] {
        scoped.create_dir_all(&SiteRelativePath::parse(sub).expect("literal path is valid"))?;
    }
    Ok(scoped)
}

fn replay(
    compose_state: &ManagedRoot,
    original: RequestId,
) -> Result<ComposeActivateConfigResult, ComposeActivateConfigError> {
    let original_state = state::load(compose_state, &state_path_for(original))
        .map_err(ComposeActivateConfigError::State)?;
    if original_state.operation != OPERATION {
        return Err(ComposeActivateConfigError::State(
            state::StateError::Corrupt,
        ));
    }
    match original_state.status {
        TransactionStatus::InProgress => Err(ComposeActivateConfigError::ReplayInProgress),
        TransactionStatus::Committed => {
            let outcome = original_state
                .outcome
                .expect("a committed transaction always has an outcome");
            let result_value = outcome
                .result
                .expect("a committed outcome always has a result");
            serde_json::from_value(result_value)
                .map_err(|_| ComposeActivateConfigError::State(state::StateError::Corrupt))
        }
        TransactionStatus::Failed => {
            let outcome = original_state
                .outcome
                .expect("a failed transaction always has an outcome");
            Err(ComposeActivateConfigError::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}

fn fail(
    compose_state: &ManagedRoot,
    state_path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut state: TransactionState,
    error: ComposeActivateConfigError,
) -> ComposeActivateConfigError {
    let (code, message) = error.protocol();
    let _ = state.mark_failed(code, message);
    let _ = state::save(compose_state, state_path, &state);
    let _ = audit::append(
        compose_state,
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

    use super::{ComposeActivateConfigError, ComposeActivateContext, execute, open_compose_state};
    use crate::{
        compose_config::{ComposeActivateConfigRequest, ConfigHash},
        error::ErrorCode,
        filesystem::ManagedRoot,
        ingress::HashGuard,
        process::CancellationToken,
        site::TrustedRoot,
        transaction::{
            RequestId,
            lock::{self, DEFAULT_STALE_AFTER},
        },
    };

    const STACK: &str = "wp-stack";
    const REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const RETRY_REQUEST_ID: &str = "9b2f1c34-5678-4abc-9def-0123456789ab";
    const UPDATED: &str = "services:\n  app:\n    image: new\n";

    struct Host {
        state_dir: tempfile::TempDir,
        compose_dir: tempfile::TempDir,
        bin_dir: tempfile::TempDir,
        compose_root: TrustedRoot,
        engine_state: ManagedRoot,
    }

    fn host() -> Host {
        let state_dir = tempfile::tempdir().expect("state root should be created");
        let compose_dir = tempfile::tempdir().expect("compose root should be created");
        let bin_dir = tempfile::tempdir().expect("bin dir should be created");
        let engine_state = ManagedRoot::open(
            &TrustedRoot::parse(state_dir.path()).expect("state root should be valid"),
        )
        .expect("state root should open");
        let compose_root =
            TrustedRoot::parse(compose_dir.path()).expect("compose root should be valid");
        write_fake_docker(bin_dir.path(), "exit 0");
        Host {
            state_dir,
            compose_dir,
            bin_dir,
            compose_root,
            engine_state,
        }
    }

    fn write_fake_docker(directory: &std::path::Path, script: &str) {
        use std::os::unix::fs::PermissionsExt;

        let path = directory.join("docker");
        fs::write(&path, format!("#!/bin/sh\n{script}\n")).expect("fake docker should be written");
        let mut perms = fs::metadata(&path)
            .expect("fake docker metadata")
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).expect("fake docker permissions");
    }

    impl Host {
        fn live(&self) -> Option<String> {
            fs::read_to_string(
                self.compose_dir
                    .path()
                    .join(STACK)
                    .join("docker-compose.yml"),
            )
            .ok()
        }

        fn transaction(&self, request_id: &str) -> serde_json::Value {
            let path = self
                .state_dir
                .path()
                .join(format!("compose/{STACK}/transactions/{request_id}.json"));
            serde_json::from_str(
                &fs::read_to_string(path).expect("the transaction record should exist"),
            )
            .expect("the transaction record should be JSON")
        }
    }

    fn request(
        guard: HashGuard,
        request_id: &str,
        key: Option<&str>,
    ) -> ComposeActivateConfigRequest {
        ComposeActivateConfigRequest::parse(STACK, UPDATED, guard, request_id, key)
            .expect("request should parse")
    }

    fn run(
        host: &Host,
        request: &ComposeActivateConfigRequest,
    ) -> Result<crate::compose_config::ComposeActivateConfigResult, ComposeActivateConfigError>
    {
        let docker_path = host.bin_dir.path().as_os_str();
        let context = ComposeActivateContext {
            compose_root: &host.compose_root,
            engine_state: &host.engine_state,
            docker_path: Some(docker_path),
        };
        execute(&context, request, &CancellationToken::default())
    }

    #[test]
    fn a_successful_activation_is_recorded_as_a_committed_transaction() {
        let host = host();

        let result = run(&host, &request(HashGuard::Absent, REQUEST_ID, None))
            .expect("a fresh activation should succeed");

        assert!(result.activated);
        assert_eq!(result.content_sha256, ConfigHash::of(UPDATED.as_bytes()));
        assert_eq!(host.live().as_deref(), Some(UPDATED));

        let record = host.transaction(REQUEST_ID);
        assert_eq!(record["status"], "COMMITTED");
        assert_eq!(record["operation"], "compose.activateConfig");
    }

    #[test]
    fn a_retried_idempotency_key_replays_the_original_result_without_reactivating() {
        let host = host();
        let key = Some("compose-edit-1");

        let first = run(&host, &request(HashGuard::Absent, REQUEST_ID, key))
            .expect("the first attempt should activate");

        let replayed = run(&host, &request(HashGuard::Absent, RETRY_REQUEST_ID, key))
            .expect("the retry should replay the original outcome");

        assert!(replayed.activated);
        assert_eq!(replayed.content_sha256, first.content_sha256);
        assert!(
            !host
                .state_dir
                .path()
                .join(format!(
                    "compose/{STACK}/transactions/{RETRY_REQUEST_ID}.json"
                ))
                .exists()
        );
    }

    #[test]
    fn a_stale_hash_guard_fails_closed_and_is_replayed_as_the_same_error() {
        let host = host();
        let key = Some("compose-edit-2");
        let stale = HashGuard::Sha256(ConfigHash::of(b"read before someone else wrote"));

        let error = run(&host, &request(stale.clone(), REQUEST_ID, key))
            .expect_err("a stale guard must fail");

        assert_eq!(error.protocol().0, ErrorCode::ConfigHashMismatch);

        let replayed = run(&host, &request(stale, RETRY_REQUEST_ID, key))
            .expect_err("the retry should replay the original failure");
        let ComposeActivateConfigError::Replayed { code, .. } = &replayed else {
            panic!("expected a replayed failure, got {replayed:?}")
        };
        assert_eq!(*code, ErrorCode::ConfigHashMismatch);
    }

    #[test]
    fn a_held_compose_lock_is_reported_as_a_conflict() {
        let host = host();
        let compose_state = open_compose_state(
            &host.engine_state,
            &crate::site::StackName::parse(STACK).unwrap(),
        )
        .expect("compose state should open");
        let _held = lock::acquire(
            &compose_state,
            &crate::site::SiteRelativePath::parse("locks/mutation.lock")
                .expect("literal path is valid"),
            RequestId::parse(RETRY_REQUEST_ID).expect("test UUID should be canonical"),
            DEFAULT_STALE_AFTER,
        )
        .expect("the contending lock should be acquired");

        let error = run(&host, &request(HashGuard::Absent, REQUEST_ID, None))
            .expect_err("a held lock must block a second activation");

        assert_eq!(error.protocol().0, ErrorCode::Conflict);
        assert!(host.live().is_none());
    }

    #[test]
    fn open_compose_state_creates_every_expected_subdirectory_and_is_idempotent() {
        let host = host();
        let stack_name = crate::site::StackName::parse(STACK).unwrap();
        open_compose_state(&host.engine_state, &stack_name).expect("first open should succeed");
        open_compose_state(&host.engine_state, &stack_name)
            .expect("second open should also succeed");
        for sub in ["locks", "transactions", "audit"] {
            assert!(
                host.state_dir
                    .path()
                    .join(format!("compose/{STACK}/{sub}"))
                    .is_dir(),
                "compose/{STACK}/{sub} should exist"
            );
        }
    }
}
