//! The shared machinery behind the route-lifecycle operations
//! (`ingress.removeRoute`, `ingress.setEnabled`, `runtime.removeConfig`):
//! one transactional "rename files, reload, put everything back if the
//! reload refuses" step, and the stack-lock/preflight/commit/audit pipeline
//! wrapped around it.
//!
//! Every file here is moved with an atomic rename, never rewritten, so the
//! previous content is never only in memory. A removal renames the file to a
//! `<name>.rollback-<request-id>` sibling instead of deleting it; the
//! `.rollback-*` suffix is the exact convention `ingress.reconcile` and
//! `runtime.reconcile` already recover from, so an interrupted removal is
//! put back by the existing sweeps rather than lost.
//!
//! Replaces the panel's `sudo rm -f`/`sudo mv -f` plus its own snapshot and
//! restore (`delete_site`, `toggle_site`, `remove_runtime_config_checked`).

use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Serialize, de::DeserializeOwned};

use crate::{
    compose,
    error::ErrorCode,
    filesystem::ManagedRoot,
    ingress::{
        activate::{self, ComposeFailure, RestoreFailure},
        execute::{ProtocolError, audit_log_path, compose_failure_code, fail, state_path_for},
    },
    mutation::preflight,
    process::CancellationToken,
    site::SiteRelativePath,
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        commit::PreCommit,
        state::{self, TransactionStatus},
    },
};

/// Why a route-lifecycle operation did not complete. Generic over the
/// operation's result so `PostCommitRecordFailed` can carry it.
#[derive(Debug)]
pub enum LifecycleError<R> {
    /// Another operation is already working on the managed WCP stack.
    /// Nothing was changed.
    StackBusy,
    Io(io::Error),
    Preflight(preflight::Error),
    /// The idempotency key was already claimed, but the original attempt is
    /// still `InProgress` — nothing to replay yet.
    ReplayInProgress,
    /// The file the request names does not exist.
    NotFound,
    /// The files on disk are in a state this operation refuses to guess
    /// about (for example both the live and the disabled route exist).
    Conflict(&'static str),
    /// A file's current contents do not match the hash the caller read.
    /// Nothing was changed.
    HashGuardMismatch,
    /// The reload refused the change, or the change could not be undone.
    Transition(activate::Error),
    State(state::StateError),
    Cancelled,
    /// The change succeeded but its `TransactionState` could not be saved.
    /// Carries the result so the caller never loses it.
    PostCommitRecordFailed {
        result: R,
        cause: state::StateError,
    },
    /// A replayed request whose original attempt failed.
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl<R> LifecycleError<R> {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::StackBusy => (
                ErrorCode::Conflict,
                "another operation on the wcp stack is in progress".into(),
            ),
            Self::Io(_) | Self::State(_) | Self::PostCommitRecordFailed { .. } => (
                ErrorCode::Internal,
                "internal route lifecycle error".to_owned(),
            ),
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another configuration change is already in progress".to_owned(),
            ),
            Self::Preflight(_) => (ErrorCode::Internal, "preflight failed".to_owned()),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request for this idempotency key is still in progress".to_owned(),
            ),
            Self::NotFound => (
                ErrorCode::NotFound,
                "the configuration file does not exist".to_owned(),
            ),
            Self::Conflict(message) => (ErrorCode::Conflict, (*message).to_owned()),
            Self::HashGuardMismatch => (
                ErrorCode::ConfigHashMismatch,
                "the configuration changed since it was read - re-read it and retry".to_owned(),
            ),
            Self::Transition(error) => transition_protocol(error),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before the commit point".to_owned(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
        }
    }
}

impl<R> ProtocolError for LifecycleError<R> {
    fn protocol(&self) -> (ErrorCode, String) {
        LifecycleError::protocol(self)
    }
}

fn transition_protocol(error: &activate::Error) -> (ErrorCode, String) {
    match error {
        activate::Error::Io(_) => (
            ErrorCode::Internal,
            "internal route lifecycle error".to_owned(),
        ),
        activate::Error::Path(_) => (
            ErrorCode::InvalidInput,
            "the file does not resolve inside the configured root".to_owned(),
        ),
        activate::Error::HashGuardMismatch => (
            ErrorCode::ConfigHashMismatch,
            "the configuration changed since it was read - re-read it and retry".to_owned(),
        ),
        activate::Error::ValidateFailed(failure) => (
            compose_failure_code(failure, ErrorCode::ConfigValidationFailed),
            "the configuration was rejected before it was applied".to_owned(),
        ),
        activate::Error::ReloadFailedAndRestored(failure) => (
            compose_failure_code(failure, ErrorCode::ConfigReloadFailed),
            if crate::ingress::execute::timed_out(failure) {
                "the change timed out while loading; the previous files were put back, but \
                 whether the running server is on them could not be confirmed - verify the \
                 live configuration"
            } else {
                "the change failed to load; the previous files were restored and are live"
            }
            .to_owned(),
        ),
        activate::Error::ReloadFailedUnchanged(failure) => (
            compose_failure_code(failure, ErrorCode::ConfigReloadFailed),
            "the configuration was already in place but failed to load; nothing was changed"
                .to_owned(),
        ),
        activate::Error::RecoveryFailed { .. } => (
            ErrorCode::ConfigRecoveryFailed,
            "the change failed to load and could not be rolled back; the live configuration \
             needs manual inspection"
                .to_owned(),
        ),
    }
}

/// One rename a transition performs, `from` becoming `to`.
pub(crate) struct Rename {
    pub(crate) from: SiteRelativePath,
    pub(crate) to: SiteRelativePath,
}

/// `<path>.rollback-<suffix>`, the sibling a removed file waits in.
pub(crate) fn rollback_sibling(path: &SiteRelativePath, suffix: &str) -> SiteRelativePath {
    SiteRelativePath::parse(format!("{}.rollback-{suffix}", path.as_path().display()))
        .expect("appending a literal suffix to a valid name stays valid")
}

/// Applies `renames` in order, then (when `reload_service` is `Some`)
/// reloads that Compose service's Caddy. If a rename or the reload fails,
/// every rename already applied is reversed and the reload is run again, so
/// disk and the running server agree with the pre-call state.
///
/// On success, `cleanup` is deleted. A failed deletion is reported as an
/// error and not ignored: a leftover `.rollback-*` file of a deleted route
/// would be resurrected by the next reconcile sweep.
pub(crate) fn transition(
    root: &ManagedRoot,
    renames: &[Rename],
    reload_service: Option<&str>,
    cleanup: &[SiteRelativePath],
    compose: &compose::Access,
) -> Result<(), activate::Error> {
    let mut applied = 0;
    let mut rename_error = None;
    for step in renames {
        match root.rename(&step.from, &step.to) {
            Ok(()) => applied += 1,
            Err(error) => {
                rename_error = Some(error);
                break;
            }
        }
    }
    if let Some(error) = rename_error {
        // A failed undo leaves a `.rollback-*` sibling behind, which the
        // reconcile sweeps put back; the undo error is the one to report.
        return match undo(root, &renames[..applied]) {
            Ok(()) => Err(activate::Error::Io(error)),
            Err(restore) => Err(activate::Error::Io(restore)),
        };
    }

    if let Some(service) = reload_service {
        if let Err(reload_failure) = reload(compose, service) {
            if let Err(error) = undo(root, renames) {
                return Err(activate::Error::RecoveryFailed {
                    reload: reload_failure,
                    restore: RestoreFailure::File(error),
                });
            }
            if let Err(second) = reload(compose, service) {
                return Err(activate::Error::RecoveryFailed {
                    reload: reload_failure,
                    restore: RestoreFailure::Reload(second),
                });
            }
            return Err(activate::Error::ReloadFailedAndRestored(reload_failure));
        }
    }

    let mut cleanup_error = None;
    for path in cleanup {
        if let Err(error) = root.remove_file(path) {
            if error.kind() != io::ErrorKind::NotFound {
                cleanup_error = Some(error);
            }
        }
    }
    match cleanup_error {
        Some(error) => Err(activate::Error::Io(error)),
        None => Ok(()),
    }
}

fn undo(root: &ManagedRoot, applied: &[Rename]) -> io::Result<()> {
    let mut first_error = None;
    for step in applied.iter().rev() {
        if let Err(error) = root.rename(&step.to, &step.from) {
            first_error.get_or_insert(error);
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// `caddy reload` inside `service`'s container — the same call
/// `stack.reloadCaddy` makes, here under the lock this pipeline already
/// holds.
pub(crate) fn reload(compose: &compose::Access, service: &str) -> Result<(), ComposeFailure> {
    activate::check(
        "caddy reload",
        compose.exec(
            service,
            &[
                "caddy",
                "reload",
                "--config",
                crate::ingress::LIVE_CONFIG_PATH,
                "--adapter",
                "caddyfile",
            ],
        ),
    )
}

/// Reads a file that may not exist.
pub(crate) fn read_optional(
    root: &ManagedRoot,
    path: &SiteRelativePath,
) -> Result<Option<Vec<u8>>, io::Error> {
    match root.read_bytes(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub(crate) fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Runs `body` as one admitted, locked, idempotent, audited operation:
/// the shared stack lock first, then preflight (idempotency replay), a
/// cancellation check, `body`, and the commit/state/audit tail — the same
/// pipeline `ingress.park`/`ingress.unpark` assemble.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run<R, F>(
    engine_state: &ManagedRoot,
    op_state: &ManagedRoot,
    operation: &'static str,
    request_id: RequestId,
    idempotency_key: Option<&IdempotencyKey>,
    cancellation: &CancellationToken,
    body: F,
) -> Result<R, LifecycleError<R>>
where
    R: Serialize + DeserializeOwned,
    F: FnOnce() -> Result<R, LifecycleError<R>>,
{
    // The operations reload containers `stack.deploy` can be recreating, so
    // they take the shared stack lock first and hold it for the whole body.
    let stack_scope = crate::stack_deploy::open_scope(engine_state).map_err(LifecycleError::Io)?;
    let _stack_lock = crate::stack_deploy::acquire_stack_lock(&stack_scope, request_id)
        .map_err(|_| LifecycleError::StackBusy)?;

    let admitted = match preflight::run(op_state, request_id, idempotency_key, operation)
        .map_err(LifecycleError::Preflight)?
    {
        preflight::Outcome::Replay(original) => return replay(op_state, original, operation),
        preflight::Outcome::Proceed(admitted) => admitted,
    };
    let preflight::Admitted { lock, mut state } = admitted;

    let state_path = state_path_for(request_id);
    let audit_path = audit_log_path();
    let pre_commit = PreCommit::new(cancellation.clone());

    if pre_commit.check().is_err() {
        return Err(fail(
            op_state,
            &state_path,
            &audit_path,
            state,
            LifecycleError::Cancelled,
        ));
    }

    let result = match body() {
        Ok(result) => result,
        Err(error) => return Err(fail(op_state, &state_path, &audit_path, state, error)),
    };

    let _post_commit = pre_commit.commit();
    drop(lock);

    let result_value = serde_json::to_value(&result).expect("operation results always serialize");
    state
        .mark_committed(result_value)
        .expect("state is always InProgress at this point");
    if let Err(cause) = state::save(op_state, &state_path, &state) {
        return Err(LifecycleError::PostCommitRecordFailed { result, cause });
    }
    let _ = audit::append(
        op_state,
        &audit_path,
        &AuditRecord::result(request_id, true, None),
    );
    Ok(result)
}

fn replay<R: DeserializeOwned>(
    op_state: &ManagedRoot,
    original: RequestId,
    operation: &'static str,
) -> Result<R, LifecycleError<R>> {
    let original_state =
        state::load(op_state, &state_path_for(original)).map_err(LifecycleError::State)?;
    if original_state.operation != operation {
        return Err(LifecycleError::State(state::StateError::Corrupt));
    }
    match original_state.status {
        TransactionStatus::InProgress => Err(LifecycleError::ReplayInProgress),
        TransactionStatus::Committed => {
            let outcome = original_state
                .outcome
                .expect("a committed transaction always has an outcome");
            let result_value = outcome
                .result
                .expect("a committed outcome always has a result");
            serde_json::from_value(result_value)
                .map_err(|_| LifecycleError::State(state::StateError::Corrupt))
        }
        TransactionStatus::Failed => {
            let outcome = original_state
                .outcome
                .expect("a failed transaction always has an outcome");
            Err(LifecycleError::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}
