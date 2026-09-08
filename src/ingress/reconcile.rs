//! The `ingress.reconcile` operation (Milestone 002,
//! `docs/milestones/002-ingress-reconcile.md`): a whole-`ingressRoot` sweep
//! that removes orphaned `.tmp`/`.tmp-*` staging siblings and resolves
//! orphaned `.rollback-*` backup siblings left behind by an
//! `ingress.activateConfig`/`ingress.park`/`ingress.unpark` attempt that
//! never reached its own commit point (a crash, a killed connection) and
//! whose domain was never activated again to naturally overwrite them.
//!
//! A direct behavioral port of `website-control-panel`'s
//! `reconciliation.rs::sweep`, narrowed to the two orphan classes that need
//! only `ingressRoot` itself (see the milestone doc's "Scope" section for
//! what is deliberately deferred and why). Unlike that raw-SSH `find`/`rm`/
//! `mv` sequence, every step here is a `ManagedRoot` filesystem call - no
//! shell string is built anywhere in this path.

use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    ingress::execute::{ProtocolError, audit_log_path, fail, open_ingress_state, state_path_for},
    mutation::preflight,
    process::CancellationToken,
    site::{SiteRelativePath, TrustedRoot},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        commit::PreCommit,
        state::{self, StateError, TransactionStatus},
    },
};

pub const RECONCILE_OPERATION: &str = "ingress.reconcile";

#[derive(Debug, Eq, PartialEq)]
pub struct ReconcileRequest {
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconcileRequestError {
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl ReconcileRequest {
    pub fn parse(
        request_id: &str,
        idempotency_key: Option<&str>,
    ) -> Result<Self, ReconcileRequestError> {
        Ok(Self {
            request_id: RequestId::parse(request_id)
                .map_err(|_| ReconcileRequestError::InvalidRequestId)?,
            idempotency_key: idempotency_key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| ReconcileRequestError::InvalidIdempotencyKey)?,
        })
    }
}

/// One backup sibling this sweep found no longer redundant, and so moved
/// back into place as the live file.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoredBackup {
    pub backup_path: String,
    pub restored_to: String,
}

/// The `result` payload of a successful `ingress.reconcile` response.
/// Every path is a bare filename relative to `ingressRoot`, never an
/// absolute host path - see the milestone doc's "Result shape" section.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReconcileResult {
    pub removed_temp_files: Vec<String>,
    pub removed_redundant_backups: Vec<String>,
    pub restored_recoverable_backups: Vec<RestoredBackup>,
    pub reconciled_at_unix_secs: u64,
}

#[derive(Debug)]
pub enum ReconcileError {
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
        result: ReconcileResult,
        cause: StateError,
    },
    /// A replayed request whose original attempt failed.
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl ReconcileError {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Io(_) | Self::State(_) | Self::PostCommitRecordFailed { .. } => (
                ErrorCode::Internal,
                "internal ingress reconciliation error".to_owned(),
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
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before the commit point".to_owned(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
        }
    }
}

impl ProtocolError for ReconcileError {
    fn protocol(&self) -> (ErrorCode, String) {
        ReconcileError::protocol(self)
    }
}

pub struct ReconcileContext<'a> {
    pub ingress_root: &'a TrustedRoot,
    pub engine_state: &'a ManagedRoot,
}

pub fn execute(
    context: &ReconcileContext<'_>,
    request: &ReconcileRequest,
    cancellation: &CancellationToken,
) -> Result<ReconcileResult, ReconcileError> {
    let ingress_state = open_ingress_state(context.engine_state).map_err(ReconcileError::Io)?;

    let admitted = match preflight::run(
        &ingress_state,
        request.request_id,
        request.idempotency_key.as_ref(),
        RECONCILE_OPERATION,
    )
    .map_err(ReconcileError::Preflight)?
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
            ReconcileError::Cancelled,
        ));
    }

    let ingress_root = match ManagedRoot::open(context.ingress_root) {
        Ok(root) => root,
        Err(error) => {
            return Err(fail(
                &ingress_state,
                &state_path,
                &audit_path,
                state,
                ReconcileError::Io(error),
            ));
        }
    };
    let names = match ingress_root.file_names() {
        Ok(names) => names,
        Err(error) => {
            return Err(fail(
                &ingress_state,
                &state_path,
                &audit_path,
                state,
                ReconcileError::Io(error),
            ));
        }
    };

    // Commit point: every removal/restore below is independently atomic
    // (a single `remove_file`/`rename`), so there is no single "the sweep
    // committed" moment to gate cancellation on - once the scan above
    // succeeded, letting the sweep finish is strictly better than
    // stopping halfway for no benefit (see the milestone doc's "Failure
    // and recovery cases").
    let _post_commit = pre_commit.commit();
    drop(lock);

    let mut removed_temp_files = Vec::new();
    let mut removed_redundant_backups = Vec::new();
    let mut restored_recoverable_backups = Vec::new();

    for name in names {
        let Ok(path) = SiteRelativePath::parse(&name) else {
            continue;
        };
        if is_temp_file(&name) {
            if ingress_root.remove_file(&path).is_ok() {
                removed_temp_files.push(name);
            }
            continue;
        }
        if let Some(live_name) = rollback_backup_live_sibling(&name) {
            let Ok(live_path) = SiteRelativePath::parse(&live_name) else {
                continue;
            };
            if ingress_root.exists(&live_path) {
                if ingress_root.remove_file(&path).is_ok() {
                    removed_redundant_backups.push(name);
                }
            } else if ingress_root.rename(&path, &live_path).is_ok() {
                restored_recoverable_backups.push(RestoredBackup {
                    backup_path: name,
                    restored_to: live_name,
                });
            }
        }
    }

    let result = ReconcileResult {
        removed_temp_files,
        removed_redundant_backups,
        restored_recoverable_backups,
        reconciled_at_unix_secs: unix_now_secs(),
    };
    let result_value = serde_json::to_value(&result).expect("ReconcileResult always serializes");
    state
        .mark_committed(result_value)
        .expect("state is always InProgress at this point");

    if let Err(cause) = state::save(&ingress_state, &state_path, &state) {
        return Err(ReconcileError::PostCommitRecordFailed { result, cause });
    }
    let _ = audit::append(
        &ingress_state,
        &audit_path,
        &AuditRecord::result(request.request_id, true, None),
    );

    Ok(result)
}

/// `*.tmp` or `*.tmp-*`, matching `website-control-panel`'s
/// `reconciliation.rs::classify_staging_files`'s scope exactly (this
/// engine's own `activate::activate` only ever produces the bare `.tmp`
/// form; the `-suffix` form is a legacy client-side naming this sweep
/// still has to account for on a not-yet-fully-migrated server).
///
/// `pub(crate)`: also reused verbatim by `runtime_config::reconcile`, which
/// shares this exact `.tmp`/`.rollback-<suffix>` naming convention (see
/// `runtime_config::activate::RoutePaths`) - see
/// `docs/milestones/003-runtime-reconcile.md`'s "Scope" section for why
/// duplicating this classification logic there would be wrong, not just
/// redundant.
pub(crate) fn is_temp_file(name: &str) -> bool {
    name.ends_with(".tmp") || name.contains(".tmp-")
}

/// `Some(live_sibling_name)` if `name` is a `*.rollback-*` backup,
/// `None` otherwise. Mirrors `reconciliation.rs`'s
/// `backup_path.rsplit_once(".rollback-")` exactly - the live sibling is
/// always everything before the first `.rollback-`.
///
/// `pub(crate)` for the same reason as `is_temp_file`.
pub(crate) fn rollback_backup_live_sibling(name: &str) -> Option<String> {
    name.split_once(".rollback-")
        .map(|(live, _suffix)| live.to_owned())
}

fn replay(
    ingress_state: &ManagedRoot,
    original: RequestId,
) -> Result<ReconcileResult, ReconcileError> {
    let original_state =
        state::load(ingress_state, &state_path_for(original)).map_err(ReconcileError::State)?;
    match original_state.status {
        TransactionStatus::InProgress => Err(ReconcileError::ReplayInProgress),
        TransactionStatus::Committed => {
            let outcome = original_state
                .outcome
                .expect("a committed transaction always has an outcome");
            let result_value = outcome
                .result
                .expect("a committed outcome always has a result");
            serde_json::from_value(result_value)
                .map_err(|_| ReconcileError::State(StateError::Corrupt))
        }
        TransactionStatus::Failed => {
            let outcome = original_state
                .outcome
                .expect("a failed transaction always has an outcome");
            Err(ReconcileError::Replayed {
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

#[cfg(test)]
mod tests {
    use super::{
        ReconcileContext, ReconcileRequest, execute, is_temp_file, rollback_backup_live_sibling,
    };
    use crate::{filesystem::ManagedRoot, process::CancellationToken, site::TrustedRoot};

    #[test]
    fn temp_files_are_recognized_in_both_naming_forms() {
        assert!(is_temp_file("a.test.caddyfile.tmp"));
        assert!(is_temp_file("a.test.caddyfile.tmp-abc123"));
        assert!(!is_temp_file("a.test.caddyfile"));
        assert!(!is_temp_file("a.test.caddyfile.rollback-abc123"));
    }

    #[test]
    fn rollback_backup_live_sibling_splits_at_the_first_rollback_marker() {
        assert_eq!(
            rollback_backup_live_sibling("a.test.caddyfile.rollback-abc123"),
            Some("a.test.caddyfile".to_owned())
        );
        assert_eq!(rollback_backup_live_sibling("a.test.caddyfile"), None);
    }

    fn managed_root() -> (tempfile::TempDir, TrustedRoot, ManagedRoot) {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let root = TrustedRoot::parse(directory.path()).expect("root should be valid");
        let managed = ManagedRoot::open(&root).expect("root should open");
        (directory, root, managed)
    }

    fn write(directory: &std::path::Path, name: &str, content: &str) {
        std::fs::write(directory.join(name), content).expect("fixture file should be written");
    }

    fn request(id: &str) -> ReconcileRequest {
        ReconcileRequest::parse(id, None).expect("test request should parse")
    }

    #[test]
    fn a_sweep_removes_orphaned_temp_files_and_resolves_both_backup_cases() {
        let (ingress_dir, ingress_root, _ingress_managed) = managed_root();
        let (_state_dir, _state_root, engine_state) = managed_root();

        // Orphaned staging file - always removable.
        write(
            ingress_dir.path(),
            "a.test.caddyfile.tmp",
            "stale staged content",
        );
        // A live route with a redundant backup (the live activation that
        // created this backup already succeeded and reloaded).
        write(ingress_dir.path(), "b.test.caddyfile", "live content for b");
        write(
            ingress_dir.path(),
            "b.test.caddyfile.rollback-111111",
            "old content for b",
        );
        // A recoverable backup - no live sibling, meaning the restore this
        // backup exists for never completed.
        write(
            ingress_dir.path(),
            "c.test.caddyfile.rollback-222222",
            "the only surviving copy of c",
        );
        // Untouched by this sweep - neither a temp file nor a backup.
        write(ingress_dir.path(), "d.test.caddyfile", "live content for d");

        let context = ReconcileContext {
            ingress_root: &ingress_root,
            engine_state: &engine_state,
        };
        let result = execute(
            &context,
            &request("550e8400-e29b-41d4-a716-446655440000"),
            &CancellationToken::default(),
        )
        .expect("reconcile should succeed");

        assert_eq!(result.removed_temp_files, vec!["a.test.caddyfile.tmp"]);
        assert_eq!(
            result.removed_redundant_backups,
            vec!["b.test.caddyfile.rollback-111111"]
        );
        assert_eq!(result.restored_recoverable_backups.len(), 1);
        assert_eq!(
            result.restored_recoverable_backups[0].backup_path,
            "c.test.caddyfile.rollback-222222"
        );
        assert_eq!(
            result.restored_recoverable_backups[0].restored_to,
            "c.test.caddyfile"
        );

        assert!(!ingress_dir.path().join("a.test.caddyfile.tmp").exists());
        assert!(
            !ingress_dir
                .path()
                .join("b.test.caddyfile.rollback-111111")
                .exists()
        );
        assert_eq!(
            std::fs::read_to_string(ingress_dir.path().join("b.test.caddyfile")).unwrap(),
            "live content for b",
            "a redundant backup's live sibling must be left exactly as it was"
        );
        assert!(
            !ingress_dir
                .path()
                .join("c.test.caddyfile.rollback-222222")
                .exists()
        );
        assert_eq!(
            std::fs::read_to_string(ingress_dir.path().join("c.test.caddyfile")).unwrap(),
            "the only surviving copy of c",
            "a recoverable backup must be restored to its live path"
        );
        assert_eq!(
            std::fs::read_to_string(ingress_dir.path().join("d.test.caddyfile")).unwrap(),
            "live content for d",
            "a file that is neither a temp file nor a backup must be untouched"
        );
    }

    #[test]
    fn an_empty_root_is_a_successful_no_op() {
        let (_ingress_dir, ingress_root, _ingress_managed) = managed_root();
        let (_state_dir, _state_root, engine_state) = managed_root();
        let context = ReconcileContext {
            ingress_root: &ingress_root,
            engine_state: &engine_state,
        };

        let result = execute(
            &context,
            &request("9b2f1c34-5678-4abc-9def-0123456789ab"),
            &CancellationToken::default(),
        )
        .expect("an empty root should reconcile as a clean no-op");

        assert!(result.removed_temp_files.is_empty());
        assert!(result.removed_redundant_backups.is_empty());
        assert!(result.restored_recoverable_backups.is_empty());
    }

    #[test]
    fn retrying_with_the_same_idempotency_key_replays_the_original_result_without_resweeping() {
        let (ingress_dir, ingress_root, _ingress_managed) = managed_root();
        let (_state_dir, _state_root, engine_state) = managed_root();
        write(ingress_dir.path(), "a.test.caddyfile.tmp", "stale");
        let context = ReconcileContext {
            ingress_root: &ingress_root,
            engine_state: &engine_state,
        };
        let keyed_request = ReconcileRequest::parse(
            "3f0d5a71-2c48-4f6b-8b21-7d5e9c1a4b60",
            Some("reconcile-2026-09-08-01"),
        )
        .expect("request should parse");

        let first = execute(&context, &keyed_request, &CancellationToken::default())
            .expect("first sweep should succeed");
        assert_eq!(first.removed_temp_files, vec!["a.test.caddyfile.tmp"]);

        // A file created *after* the first sweep - if the retry actually
        // re-scanned instead of replaying, this would show up in its
        // result too.
        write(ingress_dir.path(), "e.test.caddyfile.tmp", "new orphan");

        let replayed_request = ReconcileRequest::parse(
            "9b2f1c34-5678-4abc-9def-0123456789ab", // a different RequestId, same idempotency key
            Some("reconcile-2026-09-08-01"),
        )
        .expect("request should parse");
        let replayed = execute(&context, &replayed_request, &CancellationToken::default())
            .expect("replay should succeed");

        assert_eq!(
            first.reconciled_at_unix_secs, replayed.reconciled_at_unix_secs,
            "a replay must return the original outcome, not a fresh sweep's"
        );
        assert_eq!(replayed.removed_temp_files, vec!["a.test.caddyfile.tmp"]);
        assert!(
            ingress_dir.path().join("e.test.caddyfile.tmp").exists(),
            "a replay must not touch anything created after the original sweep"
        );
    }
}
