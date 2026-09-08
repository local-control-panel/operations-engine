//! The `runtime.reconcile` operation (Milestone 003,
//! `docs/milestones/003-runtime-reconcile.md`): sweeps one runtime pool's
//! `<runtime_id>/` subdirectory of `runtimeRoot` for orphaned `.tmp`/
//! `.tmp-*` staging siblings and orphaned `.rollback-*` backup siblings left
//! behind by a `runtime.activateConfig` attempt that never reached its own
//! commit point.
//!
//! A direct structural port of `ingress::reconcile` (see that module's doc
//! comment), narrowed to one pool's subdirectory instead of a flat root -
//! see the milestone doc's "Two differences" section for why this takes
//! `--runtime-id` rather than sweeping every pool in one call, and why it
//! reuses `runtime_config::execute::open_runtime_config_state` verbatim for
//! identical per-`runtime_id` lock/state scoping to `activateConfig`.

use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    ingress::execute::ProtocolError,
    ingress::reconcile::{RestoredBackup, is_temp_file, rollback_backup_live_sibling},
    mutation::preflight,
    process::CancellationToken,
    runtime_config::execute::open_runtime_config_state,
    site::{RuntimeId, SiteRelativePath, TrustedRoot},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        commit::PreCommit,
        state::{self, StateError, TransactionStatus},
    },
};

pub const RECONCILE_OPERATION: &str = "runtime.reconcile";

#[derive(Debug, Eq, PartialEq)]
pub struct RuntimeReconcileRequest {
    pub runtime_id: RuntimeId,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeReconcileRequestError {
    InvalidRuntimeId,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl RuntimeReconcileRequest {
    pub fn parse(
        runtime_id: &str,
        request_id: &str,
        idempotency_key: Option<&str>,
    ) -> Result<Self, RuntimeReconcileRequestError> {
        Ok(Self {
            runtime_id: RuntimeId::parse(runtime_id)
                .map_err(|_| RuntimeReconcileRequestError::InvalidRuntimeId)?,
            request_id: RequestId::parse(request_id)
                .map_err(|_| RuntimeReconcileRequestError::InvalidRequestId)?,
            idempotency_key: idempotency_key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RuntimeReconcileRequestError::InvalidIdempotencyKey)?,
        })
    }
}

/// The `result` payload of a successful `runtime.reconcile` response. Every
/// path is a bare filename relative to `runtime_root/<runtime_id>/`, never
/// prefixed with the runtime id again (already its own field) and never an
/// absolute host path - see the milestone doc's "Result shape" section.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeReconcileResult {
    pub runtime_id: String,
    pub removed_temp_files: Vec<String>,
    pub removed_redundant_backups: Vec<String>,
    pub restored_recoverable_backups: Vec<RestoredBackup>,
    pub reconciled_at_unix_secs: u64,
}

#[derive(Debug)]
pub enum RuntimeReconcileError {
    Io(io::Error),
    Preflight(preflight::Error),
    /// The idempotency key was already claimed, but the original attempt
    /// is still `InProgress` — nothing to replay yet.
    ReplayInProgress,
    State(StateError),
    Cancelled,
    /// The sweep itself succeeded, but its `TransactionState` could not be
    /// saved afterward. Carries the result so the caller never loses it.
    PostCommitRecordFailed {
        result: RuntimeReconcileResult,
        cause: StateError,
    },
    /// A replayed request whose original attempt failed.
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl RuntimeReconcileError {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Io(_) | Self::State(_) | Self::PostCommitRecordFailed { .. } => (
                ErrorCode::Internal,
                "internal runtime reconciliation error".to_owned(),
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
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before the commit point".to_owned(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
        }
    }
}

impl ProtocolError for RuntimeReconcileError {
    fn protocol(&self) -> (ErrorCode, String) {
        RuntimeReconcileError::protocol(self)
    }
}

pub struct RuntimeReconcileContext<'a> {
    pub runtime_root: &'a TrustedRoot,
    pub engine_state: &'a ManagedRoot,
}

pub fn execute(
    context: &RuntimeReconcileContext<'_>,
    request: &RuntimeReconcileRequest,
    cancellation: &CancellationToken,
) -> Result<RuntimeReconcileResult, RuntimeReconcileError> {
    let runtime_state = open_runtime_config_state(context.engine_state, &request.runtime_id)
        .map_err(RuntimeReconcileError::Io)?;

    let admitted = match preflight::run(
        &runtime_state,
        request.request_id,
        request.idempotency_key.as_ref(),
        RECONCILE_OPERATION,
    )
    .map_err(RuntimeReconcileError::Preflight)?
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
            RuntimeReconcileError::Cancelled,
        ));
    }

    // A pool that has never had a fragment activated on this host has no
    // `<runtime_id>/` subdirectory yet (`activate::activate`'s
    // `create_dir_all` only ever runs on a real activation) — that is a
    // clean, empty no-op, not an error. See the milestone doc's "Failure
    // and recovery cases" section.
    let names = match open_runtime_id_dir(context.runtime_root, &request.runtime_id) {
        Ok(Some(root)) => match root.file_names() {
            Ok(names) => names,
            Err(error) => {
                return Err(fail(
                    &runtime_state,
                    &state_path,
                    &audit_path,
                    state,
                    RuntimeReconcileError::Io(error),
                ));
            }
        },
        Ok(None) => Vec::new(),
        Err(error) => {
            return Err(fail(
                &runtime_state,
                &state_path,
                &audit_path,
                state,
                RuntimeReconcileError::Io(error),
            ));
        }
    };

    // Commit point: same reasoning as `ingress::reconcile::execute` - every
    // removal/restore below is independently atomic, so there is no single
    // "the sweep committed" moment to gate cancellation on.
    let _post_commit = pre_commit.commit();
    drop(lock);

    let mut removed_temp_files = Vec::new();
    let mut removed_redundant_backups = Vec::new();
    let mut restored_recoverable_backups = Vec::new();

    if let Ok(Some(root)) = open_runtime_id_dir(context.runtime_root, &request.runtime_id) {
        for name in names {
            let Ok(path) = SiteRelativePath::parse(&name) else {
                continue;
            };
            if is_temp_file(&name) {
                if root.remove_file(&path).is_ok() {
                    removed_temp_files.push(name);
                }
                continue;
            }
            if let Some(live_name) = rollback_backup_live_sibling(&name) {
                let Ok(live_path) = SiteRelativePath::parse(&live_name) else {
                    continue;
                };
                if root.exists(&live_path) {
                    if root.remove_file(&path).is_ok() {
                        removed_redundant_backups.push(name);
                    }
                } else if root.rename(&path, &live_path).is_ok() {
                    restored_recoverable_backups.push(RestoredBackup {
                        backup_path: name,
                        restored_to: live_name,
                    });
                }
            }
        }
    }

    let result = RuntimeReconcileResult {
        runtime_id: request.runtime_id.as_str().to_owned(),
        removed_temp_files,
        removed_redundant_backups,
        restored_recoverable_backups,
        reconciled_at_unix_secs: unix_now_secs(),
    };
    let result_value =
        serde_json::to_value(&result).expect("RuntimeReconcileResult always serializes");
    state
        .mark_committed(result_value)
        .expect("state is always InProgress at this point");

    if let Err(cause) = state::save(&runtime_state, &state_path, &state) {
        return Err(RuntimeReconcileError::PostCommitRecordFailed { result, cause });
    }
    let _ = audit::append(
        &runtime_state,
        &audit_path,
        &AuditRecord::result(request.request_id, true, None),
    );

    Ok(result)
}

/// Opens `runtime_root/<runtime_id>/` as its own `ManagedRoot`, or `Ok(None)`
/// if that subdirectory does not exist yet — see the milestone doc's
/// "Failure and recovery cases" for why that is a no-op, not an error.
fn open_runtime_id_dir(
    runtime_root: &TrustedRoot,
    runtime_id: &RuntimeId,
) -> io::Result<Option<ManagedRoot>> {
    let root = ManagedRoot::open(runtime_root)?;
    let relative = SiteRelativePath::parse(runtime_id.to_string())
        .expect("a validated RuntimeId always yields a valid relative path");
    match root.open_managed_dir(&relative) {
        Ok(scoped) => Ok(Some(scoped)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn replay(
    runtime_state: &ManagedRoot,
    original: RequestId,
) -> Result<RuntimeReconcileResult, RuntimeReconcileError> {
    let original_state = state::load(runtime_state, &state_path_for(original))
        .map_err(RuntimeReconcileError::State)?;
    match original_state.status {
        TransactionStatus::InProgress => Err(RuntimeReconcileError::ReplayInProgress),
        TransactionStatus::Committed => {
            let outcome = original_state
                .outcome
                .expect("a committed transaction always has an outcome");
            let result_value = outcome
                .result
                .expect("a committed outcome always has a result");
            serde_json::from_value(result_value)
                .map_err(|_| RuntimeReconcileError::State(StateError::Corrupt))
        }
        TransactionStatus::Failed => {
            let outcome = original_state
                .outcome
                .expect("a failed transaction always has an outcome");
            Err(RuntimeReconcileError::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Records a pre-commit failure and returns `error` unchanged — see
/// `ingress::execute::fail`'s doc comment. Not reused directly for the same
/// reason `runtime_config::execute::fail` isn't: it is generic over a
/// `pub(crate)` trait private to `ingress::execute`'s own module tree.
fn fail(
    runtime_state: &ManagedRoot,
    state_path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut state: state::TransactionState,
    error: RuntimeReconcileError,
) -> RuntimeReconcileError {
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

#[cfg(all(test, unix))]
mod tests {
    use std::fs;

    use super::{
        RuntimeReconcileContext, RuntimeReconcileRequest, execute, open_runtime_config_state,
    };
    use crate::{
        filesystem::ManagedRoot,
        process::CancellationToken,
        site::{RuntimeId, TrustedRoot},
        transaction::{
            RequestId,
            lock::{self, DEFAULT_STALE_AFTER},
        },
    };

    const RUNTIME_ID: &str = "fp1-php83";
    const OTHER_RUNTIME_ID: &str = "fp1-php84";
    const REQUEST_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

    struct Host {
        // Held only to keep the temporary directory alive for `engine_state`
        // (an already-open `ManagedRoot`) - never read directly.
        _state_dir: tempfile::TempDir,
        runtime_dir: tempfile::TempDir,
        runtime_root: TrustedRoot,
        engine_state: ManagedRoot,
    }

    fn host() -> Host {
        let state_dir = tempfile::tempdir().expect("state root should be created");
        let runtime_dir = tempfile::tempdir().expect("runtime root should be created");
        let engine_state = ManagedRoot::open(
            &TrustedRoot::parse(state_dir.path()).expect("state root should be valid"),
        )
        .expect("state root should open");
        let runtime_root =
            TrustedRoot::parse(runtime_dir.path()).expect("runtime root should be valid");
        Host {
            _state_dir: state_dir,
            runtime_dir,
            runtime_root,
            engine_state,
        }
    }

    fn write(directory: &std::path::Path, runtime_id: &str, name: &str, content: &str) {
        let subdir = directory.join(runtime_id);
        fs::create_dir_all(&subdir).expect("runtime-id subdirectory should be created");
        fs::write(subdir.join(name), content).expect("fixture file should be written");
    }

    fn request(runtime_id: &str, request_id: &str, key: Option<&str>) -> RuntimeReconcileRequest {
        RuntimeReconcileRequest::parse(runtime_id, request_id, key)
            .expect("test request should parse")
    }

    fn run(
        host: &Host,
        request: &RuntimeReconcileRequest,
    ) -> Result<super::RuntimeReconcileResult, super::RuntimeReconcileError> {
        let context = RuntimeReconcileContext {
            runtime_root: &host.runtime_root,
            engine_state: &host.engine_state,
        };
        execute(&context, request, &CancellationToken::default())
    }

    #[test]
    fn a_sweep_removes_orphaned_temp_files_and_resolves_both_backup_cases() {
        let host = host();
        write(
            host.runtime_dir.path(),
            RUNTIME_ID,
            "a.test.caddyfile.tmp",
            "stale staged content",
        );
        write(
            host.runtime_dir.path(),
            RUNTIME_ID,
            "b.test.caddyfile",
            "live content for b",
        );
        write(
            host.runtime_dir.path(),
            RUNTIME_ID,
            "b.test.caddyfile.rollback-111111",
            "old content for b",
        );
        write(
            host.runtime_dir.path(),
            RUNTIME_ID,
            "c.test.caddyfile.rollback-222222",
            "the only surviving copy of c",
        );

        let result =
            run(&host, &request(RUNTIME_ID, REQUEST_ID, None)).expect("reconcile should succeed");

        assert_eq!(result.runtime_id, RUNTIME_ID);
        assert_eq!(result.removed_temp_files, vec!["a.test.caddyfile.tmp"]);
        assert_eq!(
            result.removed_redundant_backups,
            vec!["b.test.caddyfile.rollback-111111"]
        );
        assert_eq!(result.restored_recoverable_backups.len(), 1);
        assert_eq!(
            result.restored_recoverable_backups[0].restored_to,
            "c.test.caddyfile"
        );

        let subdir = host.runtime_dir.path().join(RUNTIME_ID);
        assert!(!subdir.join("a.test.caddyfile.tmp").exists());
        assert!(!subdir.join("b.test.caddyfile.rollback-111111").exists());
        assert_eq!(
            fs::read_to_string(subdir.join("b.test.caddyfile")).unwrap(),
            "live content for b"
        );
        assert_eq!(
            fs::read_to_string(subdir.join("c.test.caddyfile")).unwrap(),
            "the only surviving copy of c"
        );
    }

    #[test]
    fn a_runtime_id_with_no_subdirectory_yet_is_a_successful_no_op() {
        let host = host();

        let result = run(&host, &request(RUNTIME_ID, REQUEST_ID, None))
            .expect("a pool never activated on this host should reconcile as a clean no-op");

        assert!(result.removed_temp_files.is_empty());
        assert!(result.removed_redundant_backups.is_empty());
        assert!(result.restored_recoverable_backups.is_empty());
    }

    #[test]
    fn retrying_with_the_same_idempotency_key_replays_the_original_result_without_resweeping() {
        let host = host();
        write(
            host.runtime_dir.path(),
            RUNTIME_ID,
            "a.test.caddyfile.tmp",
            "stale",
        );
        let key = Some("runtime-reconcile-2026-09-08-01");

        let first =
            run(&host, &request(RUNTIME_ID, REQUEST_ID, key)).expect("first sweep should succeed");

        write(
            host.runtime_dir.path(),
            RUNTIME_ID,
            "e.test.caddyfile.tmp",
            "new orphan",
        );

        let replayed = run(
            &host,
            &request(RUNTIME_ID, "9b2f1c34-5678-4abc-9def-0123456789ab", key),
        )
        .expect("replay should succeed");

        assert_eq!(
            first.reconciled_at_unix_secs,
            replayed.reconciled_at_unix_secs
        );
        assert_eq!(replayed.removed_temp_files, vec!["a.test.caddyfile.tmp"]);
        assert!(
            host.runtime_dir
                .path()
                .join(RUNTIME_ID)
                .join("e.test.caddyfile.tmp")
                .exists(),
            "a replay must not touch anything created after the original sweep"
        );
    }

    /// The lock-granularity proof this module exists to make, mirroring
    /// `runtime_config::execute`'s own equivalent test: a lock held for one
    /// runtime id never blocks a reconcile for a different one.
    #[test]
    fn a_held_lock_for_a_different_runtime_id_does_not_block_this_one() {
        let host = host();
        write(
            host.runtime_dir.path(),
            RUNTIME_ID,
            "a.test.caddyfile.tmp",
            "stale",
        );
        let other_state = open_runtime_config_state(
            &host.engine_state,
            &RuntimeId::parse(OTHER_RUNTIME_ID).expect("test runtime id should be valid"),
        )
        .expect("runtime state should open");
        let _held = lock::acquire(
            &other_state,
            &crate::site::SiteRelativePath::parse("locks/mutation.lock")
                .expect("literal path is valid"),
            RequestId::parse("9b2f1c34-5678-4abc-9def-0123456789ab")
                .expect("test UUID should be canonical"),
            DEFAULT_STALE_AFTER,
        )
        .expect("the other runtime id's lock should be acquired");

        let result = run(&host, &request(RUNTIME_ID, REQUEST_ID, None))
            .expect("a lock held for a different runtime id must not block this sweep");

        assert_eq!(result.removed_temp_files, vec!["a.test.caddyfile.tmp"]);
    }

    #[test]
    fn a_held_lock_for_the_same_runtime_id_is_reported_as_a_conflict() {
        let host = host();
        let runtime_state = open_runtime_config_state(
            &host.engine_state,
            &RuntimeId::parse(RUNTIME_ID).expect("test runtime id should be valid"),
        )
        .expect("runtime state should open");
        let _held = lock::acquire(
            &runtime_state,
            &crate::site::SiteRelativePath::parse("locks/mutation.lock")
                .expect("literal path is valid"),
            RequestId::parse("9b2f1c34-5678-4abc-9def-0123456789ab")
                .expect("test UUID should be canonical"),
            DEFAULT_STALE_AFTER,
        )
        .expect("the contending lock should be acquired");

        let error = run(&host, &request(RUNTIME_ID, REQUEST_ID, None))
            .expect_err("a held lock must block a second sweep for the same runtime id");

        assert_eq!(error.protocol().0, crate::error::ErrorCode::Conflict);
    }
}
