//! The assembled `engine.rollback` pipeline: preflight, then a purely
//! local swap back to the one retained previous binary — no network
//! call, so it works even when GitHub is unreachable. Mirrors
//! `install.rs`'s shape; see that file's doc comment for the shared
//! preflight/commit/audit pattern both borrow from `deploy::execute`.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    engine::{EngineRollbackRequest, EngineRollbackResult, ROLLBACK_OPERATION, state},
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    site::{SiteRelativePath, TrustedRoot},
    transaction::{
        RequestId,
        audit::{self, AuditRecord},
        commit::PreCommit,
        state::{self as tx_state, TransactionStatus},
    },
};

pub struct RollbackContext<'a> {
    pub bin_root: &'a TrustedRoot,
    pub engine_state: &'a ManagedRoot,
}

#[derive(Debug)]
pub enum RollbackError {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    NoPreviousVersion,
    State(tx_state::StateError),
    InstallState(state::Error),
    Cancelled,
    PostCommitRecordFailed {
        result: EngineRollbackResult,
        cause: tx_state::StateError,
    },
    /// The rollback itself succeeded, but `install.state` — the
    /// authoritative record of which version is active and which one a
    /// further `engine rollback` restores — could not be written
    /// afterward. See `install::InstallError::PostCommitInstallStateFailed`.
    PostCommitInstallStateFailed {
        result: EngineRollbackResult,
        cause: state::Error,
    },
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl RollbackError {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Io(_) | Self::State(_) | Self::InstallState(_) => (
                ErrorCode::Internal,
                "internal engine rollback error".to_owned(),
            ),
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another engine install or rollback is already in progress".to_owned(),
            ),
            Self::Preflight(_) => (ErrorCode::Internal, "preflight failed".to_owned()),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request for this idempotency key is still in progress".to_owned(),
            ),
            Self::NoPreviousVersion => (
                ErrorCode::InvalidInput,
                "there is no previous engine version retained to roll back to".to_owned(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before the commit point".to_owned(),
            ),
            Self::PostCommitRecordFailed { .. } | Self::PostCommitInstallStateFailed { .. } => (
                ErrorCode::Internal,
                "internal engine rollback error".to_owned(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
        }
    }
}

pub fn execute(
    context: &RollbackContext<'_>,
    request: &EngineRollbackRequest,
    cancellation: &crate::process::CancellationToken,
) -> Result<EngineRollbackResult, RollbackError> {
    let engine_state = state::open_engine_state(context.engine_state).map_err(RollbackError::Io)?;

    let admitted = match preflight::run(
        &engine_state,
        request.request_id,
        request.idempotency_key.as_ref(),
        ROLLBACK_OPERATION,
    )
    .map_err(RollbackError::Preflight)?
    {
        preflight::Outcome::Replay(original) => return replay(&engine_state, original),
        preflight::Outcome::Proceed(admitted) => admitted,
    };
    // See `install.rs`'s identical destructuring for why this renames
    // the `state` field to `tx`.
    let preflight::Admitted {
        lock,
        state: mut tx,
    } = admitted;

    let state_path = state_path_for(request.request_id);
    let audit_path = audit_log_path();
    let pre_commit = PreCommit::new(cancellation.clone());

    let current = match state::load(&engine_state) {
        Ok(Some(current)) => current,
        Ok(None) => {
            return Err(fail(
                &engine_state,
                &state_path,
                &audit_path,
                tx,
                RollbackError::NoPreviousVersion,
            ));
        }
        Err(error) => {
            return Err(fail(
                &engine_state,
                &state_path,
                &audit_path,
                tx,
                RollbackError::InstallState(error),
            ));
        }
    };
    let Some(previous) = current.previous_version.clone() else {
        return Err(fail(
            &engine_state,
            &state_path,
            &audit_path,
            tx,
            RollbackError::NoPreviousVersion,
        ));
    };

    let version_binary = SiteRelativePath::parse(format!("versions/{previous}/ops-engine"))
        .expect("a previously-installed version string always yields a valid relative path");
    let bytes = match engine_state.read_bytes(&version_binary) {
        Ok(bytes) => bytes,
        Err(error) => {
            return Err(fail(
                &engine_state,
                &state_path,
                &audit_path,
                tx,
                RollbackError::Io(error),
            ));
        }
    };

    if pre_commit.check().is_err() {
        return Err(fail(
            &engine_state,
            &state_path,
            &audit_path,
            tx,
            RollbackError::Cancelled,
        ));
    }

    let bin_root = match ManagedRoot::open(context.bin_root) {
        Ok(root) => root,
        Err(error) => {
            return Err(fail(
                &engine_state,
                &state_path,
                &audit_path,
                tx,
                RollbackError::Io(error),
            ));
        }
    };
    // Commit point: `/usr/local/bin/ops-engine` now contains the
    // previously-retained binary.
    if let Err(error) = bin_root.write_new_executable(&binary_path(), &bytes) {
        return Err(fail(
            &engine_state,
            &state_path,
            &audit_path,
            tx,
            RollbackError::Io(error),
        ));
    }
    let _post_commit = pre_commit.commit();

    // Symmetric swap: a second `engine rollback` right after this one
    // would roll forward again, exactly like `site.rollback`'s
    // roll-forward property — the source version is never invalidated.
    let new_state = state::InstallState {
        active_version: previous.clone(),
        previous_version: Some(current.active_version.clone()),
    };
    // Still holding the lock, and the failure is surfaced rather than
    // swallowed — see the matching comment in `install::execute` for why
    // `install.state` is not the same kind of post-commit bookkeeping as
    // the transaction record.
    let install_state_saved = state::save(&engine_state, &new_state);
    drop(lock);

    let result = EngineRollbackResult {
        version: previous,
        previous_version: current.active_version,
        activated_at_unix_secs: unix_now_secs(),
    };
    let result_value =
        serde_json::to_value(&result).expect("EngineRollbackResult always serializes");
    tx.mark_committed(result_value)
        .expect("state is always InProgress at this point");

    if let Err(cause) = tx_state::save(&engine_state, &state_path, &tx) {
        return Err(RollbackError::PostCommitRecordFailed { result, cause });
    }
    let _ = audit::append(
        &engine_state,
        &audit_path,
        &AuditRecord::result(request.request_id, true, None),
    );
    if let Err(cause) = install_state_saved {
        return Err(RollbackError::PostCommitInstallStateFailed { result, cause });
    }

    Ok(result)
}

fn replay(
    engine_state: &ManagedRoot,
    original: RequestId,
) -> Result<EngineRollbackResult, RollbackError> {
    let original_state =
        tx_state::load(engine_state, &state_path_for(original)).map_err(RollbackError::State)?;
    match original_state.status {
        TransactionStatus::InProgress => Err(RollbackError::ReplayInProgress),
        TransactionStatus::Committed => {
            let outcome = original_state
                .outcome
                .expect("a committed transaction always has an outcome");
            let result_value = outcome
                .result
                .expect("a committed outcome always has a result");
            serde_json::from_value(result_value)
                .map_err(|_| RollbackError::State(tx_state::StateError::Corrupt))
        }
        TransactionStatus::Failed => {
            let outcome = original_state
                .outcome
                .expect("a failed transaction always has an outcome");
            Err(RollbackError::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}

fn fail(
    engine_state: &ManagedRoot,
    state_path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut tx: tx_state::TransactionState,
    error: RollbackError,
) -> RollbackError {
    let (code, message) = error.protocol();
    let _ = tx.mark_failed(code, message);
    let _ = tx_state::save(engine_state, state_path, &tx);
    let _ = audit::append(
        engine_state,
        audit_path,
        &AuditRecord::result(tx.request_id, false, Some(code)),
    );
    error
}

fn binary_path() -> SiteRelativePath {
    SiteRelativePath::parse("ops-engine").expect("literal path is valid")
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
