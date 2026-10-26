//! Durable evidence around the atomic release switch. Recovery only records
//! the observed outcome; it never switches current, fetches, or runs site code.
use crate::{
    deploy::{ReleaseId, activate},
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    operation_status::OperationStatus,
    site::{GitCommitSha, SiteId, SiteRelativePath, TrustedRoot},
    transaction::{
        RequestId,
        audit::{self, AuditRecord},
        lock,
        state::{self, TransactionStatus},
    },
};
use serde::{Deserialize, Serialize};
pub const OPERATION: &str = "site.recoverDeployment";

#[derive(Debug)]
pub enum Error {
    Unavailable,
    Conflict,
    Unsupported,
    NotFound,
}
impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Conflict => (
                ErrorCode::Conflict,
                "deployment is active or its current release cannot be safely reconciled".into(),
            ),
            Self::Unsupported => (
                ErrorCode::InvalidInput,
                "this request has no supported deployment recovery checkpoint".into(),
            ),
            Self::NotFound => (
                ErrorCode::NotFound,
                "deployment transaction was not found".into(),
            ),
            Self::Unavailable => (
                ErrorCode::Internal,
                "deployment recovery evidence is unavailable".into(),
            ),
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Checkpoint {
    site_id: SiteId,
    request_id: RequestId,
    operation: String,
    target: ReleaseId,
    previous: Option<ReleaseId>,
    revision: Option<GitCommitSha>,
}
fn path(id: RequestId) -> SiteRelativePath {
    SiteRelativePath::parse(format!("deployment-recovery/{id}.json")).unwrap()
}
fn state_path(id: RequestId) -> SiteRelativePath {
    SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap()
}
fn load(root: &ManagedRoot, id: RequestId) -> Result<Checkpoint, Error> {
    serde_json::from_str(
        &root
            .read_to_string(&path(id))
            .map_err(|_| Error::Unsupported)?,
    )
    .map_err(|_| Error::Unavailable)
}
/// Called under the mutation lock before staging or activation. A previous
/// interrupted request must be reconciled before another release can switch.
pub fn prepare(
    content: &TrustedRoot,
    scope: &ManagedRoot,
    site_id: SiteId,
    request_id: RequestId,
    operation: &str,
    target: ReleaseId,
    revision: Option<GitCommitSha>,
) -> Result<(), Error> {
    let dir = SiteRelativePath::parse("deployment-recovery").unwrap();
    scope.create_dir_all(&dir).map_err(|_| Error::Unavailable)?;
    let markers = scope
        .open_managed_dir(&dir)
        .map_err(|_| Error::Unavailable)?;
    for name in markers.file_names().map_err(|_| Error::Unavailable)? {
        let Some(id) = name
            .strip_suffix(".json")
            .and_then(|s| RequestId::parse(s).ok())
        else {
            return Err(Error::Unavailable);
        };
        let record = state::load(scope, &state_path(id)).map_err(|_| Error::Unavailable)?;
        if record.status == TransactionStatus::InProgress {
            return Err(Error::Conflict);
        }
        // Completed markers are no longer needed. This also keeps checkpoint
        // retention bounded by the transaction retention policy.
        scope
            .remove_file(&path(id))
            .map_err(|_| Error::Unavailable)?;
    }
    if activate::current_release(content, site_id).map_err(|_| Error::Unavailable)? == Some(target)
    {
        return Err(Error::Conflict);
    }
    let checkpoint = Checkpoint {
        site_id,
        request_id,
        operation: operation.into(),
        target,
        previous: activate::current_release(content, site_id).map_err(|_| Error::Unavailable)?,
        revision,
    };
    scope
        .write_atomic(
            &path(request_id),
            &serde_json::to_vec(&checkpoint).map_err(|_| Error::Unavailable)?,
        )
        .map_err(|_| Error::Unavailable)
}

pub fn available(scope: &ManagedRoot, record: &state::TransactionState) -> bool {
    record.status == TransactionStatus::InProgress
        && matches!(record.operation.as_str(), "site.deploy" | "site.rollback")
        && load(scope, record.request_id)
            .is_ok_and(|c| c.request_id == record.request_id && c.operation == record.operation)
}

pub fn execute(
    content: &TrustedRoot,
    engine_state: &ManagedRoot,
    site_id: SiteId,
    request_id: RequestId,
) -> Result<OperationStatus, Error> {
    let relative = SiteRelativePath::parse(format!("sites/{site_id}")).unwrap();
    let scope = engine_state
        .open_managed_dir(&relative)
        .map_err(|_| Error::NotFound)?;
    // Acquire rather than trusting a status read: the original process may
    // still own the lock, or another request may have acquired it meanwhile.
    let _lock =
        lock::acquire(&scope, &preflight::lock_path(), request_id).map_err(|_| Error::Conflict)?;
    let mut record = state::load(&scope, &state_path(request_id)).map_err(|e| match e {
        state::StateError::NotFound => Error::NotFound,
        _ => Error::Unavailable,
    })?;
    if !matches!(record.operation.as_str(), "site.deploy" | "site.rollback") {
        return Err(Error::Unsupported);
    }
    if record.status != TransactionStatus::InProgress {
        return Ok(OperationStatus {
            transaction: record,
            active: false,
            recovery_action: None,
        });
    }
    let c = load(&scope, request_id)?;
    if c.site_id != site_id
        || c.request_id != request_id
        || c.operation != record.operation
        || (record.operation == "site.deploy"
            && (c.revision.is_none() || c.target != ReleaseId::from(request_id)))
        || (record.operation == "site.rollback" && c.revision.is_some())
    {
        return Err(Error::Unavailable);
    }
    let current = activate::current_release(content, site_id).map_err(|_| Error::Conflict)?;
    if current == Some(c.target) && c.previous != Some(c.target) {
        // A prepared checkpoint plus the target current link proves that the
        // switch happened. The timestamp is when recovery verified activation.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut result = serde_json::json!({"releaseId": c.target, "previousReleaseId": c.previous,
            "activatedAtUnixSecs": now, "recovered": true});
        if let Some(revision) = c.revision {
            result["commit"] = serde_json::to_value(revision).map_err(|_| Error::Unavailable)?;
        }
        record
            .mark_committed(result)
            .map_err(|_| Error::Unavailable)?;
    } else if current == c.previous && c.previous != Some(c.target) {
        record
            .mark_failed(
                ErrorCode::Cancelled,
                "interrupted before release activation; the previous release is unchanged",
            )
            .map_err(|_| Error::Unavailable)?;
    } else {
        return Err(Error::Conflict);
    }
    // Audit before saving: an audit failure keeps the request recoverable.
    audit::append(
        &scope,
        &SiteRelativePath::parse("audit/events.jsonl").unwrap(),
        &AuditRecord::mutation_start(request_id, None, OPERATION),
    )
    .map_err(|_| Error::Unavailable)?;
    state::save(&scope, &state_path(request_id), &record).map_err(|_| Error::Unavailable)?;
    let _ = audit::append(
        &scope,
        &SiteRelativePath::parse("audit/events.jsonl").unwrap(),
        &AuditRecord::result(
            request_id,
            record.status == TransactionStatus::Committed,
            record.outcome.as_ref().and_then(|o| o.error_code),
        ),
    );
    Ok(OperationStatus {
        transaction: record,
        active: false,
        recovery_action: None,
    })
}

pub fn command(
    site_id: &str,
    request_id: &str,
) -> Result<crate::protocol::Response, crate::protocol::ResponseBuildError> {
    use crate::{
        config::{EngineConfig, SiteManifest},
        protocol::Response,
    };
    let (Ok(site_id), Ok(request_id)) = (SiteId::parse(site_id), RequestId::parse(request_id))
    else {
        return Ok(Response::failure(
            OPERATION,
            ErrorCode::InvalidInput,
            "invalid deployment identity",
        ));
    };
    let run = || -> Result<OperationStatus, Error> {
        let config = EngineConfig::load_root_owned(std::path::Path::new(
            "/etc/operations-engine/config.json",
        ))
        .map_err(|_| Error::Unavailable)?;
        let manifest = SiteManifest::load_root_owned(
            &std::path::Path::new("/etc/operations-engine/sites").join(format!("{site_id}.json")),
            site_id,
        )
        .map_err(|_| Error::Unavailable)?;
        let expected = SiteRelativePath::parse(format!("sites/{site_id}/current")).unwrap();
        if manifest.content_root != expected {
            return Err(Error::Unsupported);
        }
        let [content] = config.content_roots.as_slice() else {
            return Err(Error::Unavailable);
        };
        let state = ManagedRoot::open(&config.state_root).map_err(|_| Error::Unavailable)?;
        execute(content, &state, site_id, request_id)
    };
    match run() {
        Ok(result) => Response::success(OPERATION, result),
        Err(e) => {
            let (code, message) = e.protocol();
            Ok(Response::failure(OPERATION, code, &message))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const SITE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const REQUEST: &str = "123e4567-e89b-12d3-a456-426614174000";
    const OTHER: &str = "9b2f1c34-5678-4abc-9def-0123456789ab";
    fn fixture(
        operation: &'static str,
    ) -> (
        tempfile::TempDir,
        tempfile::TempDir,
        TrustedRoot,
        ManagedRoot,
        SiteId,
        RequestId,
    ) {
        let c = tempfile::tempdir().unwrap();
        let s = tempfile::tempdir().unwrap();
        let content = TrustedRoot::parse(c.path()).unwrap();
        let state = ManagedRoot::open(&TrustedRoot::parse(s.path()).unwrap()).unwrap();
        let site = SiteId::parse(SITE).unwrap();
        let id = RequestId::parse(REQUEST).unwrap();
        let scope = preflight::open_site_state(&state, site).unwrap();
        let admitted = preflight::run(&scope, id, None, operation).unwrap();
        let revision = (operation == "site.deploy")
            .then(|| GitCommitSha::parse("abcdef0123456789abcdef0123456789abcdef01").unwrap());
        prepare(
            &content,
            &scope,
            site,
            id,
            operation,
            ReleaseId::from(id),
            revision,
        )
        .unwrap();
        drop(admitted);
        (c, s, content, state, site, id)
    }
    #[test]
    fn interrupted_before_switch_is_failed_without_changing_current() {
        let (_c, _s, content, state, site, id) = fixture("site.deploy");
        let result = execute(&content, &state, site, id).unwrap();
        assert_eq!(result.transaction.status, TransactionStatus::Failed);
        assert_eq!(activate::current_release(&content, site).unwrap(), None);
        assert_eq!(
            execute(&content, &state, site, id).unwrap().transaction,
            result.transaction
        );
    }
    #[test]
    fn interrupted_after_switch_commits_and_preserves_replay_result() {
        for operation in ["site.deploy", "site.rollback"] {
            let (_c, _s, content, state, site, id) = fixture(operation);
            activate::activate(&content, site, ReleaseId::from(id)).unwrap();
            let result = execute(&content, &state, site, id).unwrap();
            assert_eq!(result.transaction.status, TransactionStatus::Committed);
            assert_eq!(
                result
                    .transaction
                    .outcome
                    .as_ref()
                    .unwrap()
                    .result
                    .as_ref()
                    .unwrap()["recovered"],
                true
            );
            assert_eq!(
                execute(&content, &state, site, id).unwrap().transaction,
                result.transaction
            );
        }
    }
    #[test]
    fn live_lock_refuses_recovery_even_when_the_owner_id_matches() {
        let (_c, _s, content, state, site, id) = fixture("site.deploy");
        let scope = preflight::open_site_state(&state, site).unwrap();
        let _guard = lock::acquire(&scope, &preflight::lock_path(), id).unwrap();
        assert!(matches!(
            execute(&content, &state, site, id),
            Err(Error::Conflict)
        ));
    }
    #[test]
    fn unexpected_current_and_corrupt_checkpoint_keep_transaction_interrupted() {
        let (_c, s, content, state, site, id) = fixture("site.deploy");
        activate::activate(&content, site, ReleaseId::parse(OTHER).unwrap()).unwrap();
        assert!(matches!(
            execute(&content, &state, site, id),
            Err(Error::Conflict)
        ));
        std::fs::write(
            s.path()
                .join(format!("sites/{SITE}/deployment-recovery/{REQUEST}.json")),
            b"{}",
        )
        .unwrap();
        assert!(matches!(
            execute(&content, &state, site, id),
            Err(Error::Unavailable)
        ));
        assert_eq!(
            crate::operation_status::load_site(&state, SITE, REQUEST)
                .unwrap()
                .transaction
                .status,
            TransactionStatus::InProgress
        );
    }
    #[test]
    fn missing_and_cross_site_requests_never_create_a_transaction() {
        let (_c, _s, content, state, site, id) = fixture("site.deploy");
        assert!(matches!(
            execute(&content, &state, site, RequestId::parse(OTHER).unwrap()),
            Err(Error::NotFound)
        ));
        assert!(matches!(
            execute(&content, &state, SiteId::parse(OTHER).unwrap(), id),
            Err(Error::NotFound)
        ));
    }
    #[test]
    fn pending_checkpoint_blocks_a_second_release_switch() {
        let (_c, _s, content, state, site, _id) = fixture("site.deploy");
        let scope = preflight::open_site_state(&state, site).unwrap();
        let other = RequestId::parse(OTHER).unwrap();
        let _lock = lock::acquire(&scope, &preflight::lock_path(), other).unwrap();
        assert!(matches!(
            prepare(
                &content,
                &scope,
                site,
                other,
                "site.rollback",
                ReleaseId::from(other),
                None
            ),
            Err(Error::Conflict)
        ));
    }
    #[test]
    fn advertised_recovery_requires_a_valid_checkpoint_and_incomplete_transaction() {
        let (_c, _s, content, state, site, id) = fixture("site.deploy");
        let status = crate::operation_status::load_site(&state, SITE, REQUEST).unwrap();
        assert_eq!(status.recovery_action, Some(OPERATION));
        let list =
            crate::operation_status::list(&state, Some(SITE), None, None, None, None).unwrap();
        assert_eq!(list.operations[0].recovery_action, Some(OPERATION));
        execute(&content, &state, site, id).unwrap();
        assert_eq!(
            crate::operation_status::load_site(&state, SITE, REQUEST)
                .unwrap()
                .recovery_action,
            None
        );
    }
}
