//! The `site.rollback` operation (Phase 5). Nothing here is wired into
//! `cli`/`capabilities` until every item in `PLAN.md`'s Phase 5 passes.
//!
//! Rollback reuses the same transaction, locking, audit, and recovery
//! machinery Phase 4 deploy already built (`mutation::preflight`,
//! `transaction::commit`, `transaction::state`), and reuses two of deploy's
//! own operation-agnostic steps directly rather than duplicating them:
//! `deploy::validate::validate_staged_release` (integrity checks that don't
//! care how a release directory came to exist) and
//! `deploy::activate::activate` (the atomic switch, which only ever needed
//! a `SiteId` and `ReleaseId` — never anything staging-specific). See
//! `PLAN.md`'s decision log for why those two were reused verbatim instead
//! of being forked into rollback-owned copies.

pub mod eligibility;
pub mod execute;

use serde::{Deserialize, Serialize};

use crate::{
    deploy::ReleaseId,
    site::SiteId,
    transaction::{IdempotencyKey, RequestId},
};

/// The stable protocol operation name, and the value recorded as
/// `TransactionState::operation` for every rollback attempt.
pub const OPERATION: &str = "site.rollback";

/// A validated `site.rollback` request. Field types already enforce their
/// own rules; `parse` only composes them and reports which one failed —
/// mirrors `deploy::DeployRequest::parse`.
#[derive(Debug, Eq, PartialEq)]
pub struct RollbackRequest {
    pub site_id: SiteId,
    /// The retained release to switch back to. Eligibility (does this
    /// release actually still exist as engine-owned state?) is not decided
    /// here — a syntactically valid `ReleaseId` is not itself authorization,
    /// exactly as a syntactically valid `GitCommitSha` is not for deploy.
    /// See `rollback::eligibility`.
    pub release_id: ReleaseId,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackRequestError {
    InvalidSiteId,
    InvalidReleaseId,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl RollbackRequest {
    pub fn parse(
        site_id: &str,
        release_id: &str,
        request_id: &str,
        idempotency_key: Option<&str>,
    ) -> Result<Self, RollbackRequestError> {
        Ok(Self {
            site_id: SiteId::parse(site_id).map_err(|_| RollbackRequestError::InvalidSiteId)?,
            release_id: ReleaseId::parse(release_id)
                .map_err(|_| RollbackRequestError::InvalidReleaseId)?,
            request_id: RequestId::parse(request_id)
                .map_err(|_| RollbackRequestError::InvalidRequestId)?,
            idempotency_key: idempotency_key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RollbackRequestError::InvalidIdempotencyKey)?,
        })
    }
}

/// The `result` payload of a successful `site.rollback` response.
///
/// Deliberately has no `commit` field, unlike `DeployResult`: deploy's
/// `commit` is an echo of an already-validated request input
/// (`DeployRequest::revision`), not a derived value. Rollback's request
/// carries a `ReleaseId`, not a commit, and there is no equivalent input to
/// echo — inventing one would mean an extra subprocess call
/// (`git rev-parse HEAD` against the target release) that no exit criterion
/// requires. `release_id` and `previous_release_id` alone already satisfy
/// "identify both source and target releases safely".
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RollbackResult {
    /// The release that is now active (the rollback target).
    pub release_id: ReleaseId,
    /// The release that was active immediately before this rollback (the
    /// rollback source), or `None` only if the site had no prior activation
    /// at all — which would itself mean there was nothing eligible to roll
    /// back from, so this is expected to always be `Some` in practice.
    pub previous_release_id: Option<ReleaseId>,
    pub activated_at_unix_secs: u64,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{RollbackRequest, RollbackRequestError, RollbackResult};
    use crate::{deploy::ReleaseId, transaction::RequestId};

    const SITE_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
    const REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const RELEASE_ID: &str = "9b2f1c34-5678-4abc-9def-0123456789ab";

    #[test]
    fn rollback_request_parses_all_valid_fields() {
        let request =
            RollbackRequest::parse(SITE_ID, RELEASE_ID, REQUEST_ID, Some("rollback-key-1"))
                .expect("request should parse");
        assert_eq!(request.site_id.to_string(), SITE_ID);
        assert_eq!(request.release_id.to_string(), RELEASE_ID);
        assert_eq!(request.request_id.to_string(), REQUEST_ID);
        assert_eq!(
            request.idempotency_key.map(|key| key.as_str().to_owned()),
            Some("rollback-key-1".to_owned())
        );
    }

    #[test]
    fn rollback_request_allows_a_missing_idempotency_key() {
        let request = RollbackRequest::parse(SITE_ID, RELEASE_ID, REQUEST_ID, None)
            .expect("request without an idempotency key should parse");
        assert_eq!(request.idempotency_key, None);
    }

    #[test]
    fn rollback_request_reports_which_field_failed() {
        assert_eq!(
            RollbackRequest::parse("not-a-uuid", RELEASE_ID, REQUEST_ID, None).unwrap_err(),
            RollbackRequestError::InvalidSiteId
        );
        assert_eq!(
            RollbackRequest::parse(SITE_ID, "not-a-uuid", REQUEST_ID, None).unwrap_err(),
            RollbackRequestError::InvalidReleaseId
        );
        assert_eq!(
            RollbackRequest::parse(SITE_ID, RELEASE_ID, "not-a-uuid", None).unwrap_err(),
            RollbackRequestError::InvalidRequestId
        );
        assert_eq!(
            RollbackRequest::parse(SITE_ID, RELEASE_ID, REQUEST_ID, Some("has space")).unwrap_err(),
            RollbackRequestError::InvalidIdempotencyKey
        );
    }

    #[test]
    fn rollback_result_serializes_with_safe_camel_case_fields() {
        let release_id =
            ReleaseId::from(RequestId::parse(RELEASE_ID).expect("test UUID should be canonical"));
        let previous_release_id =
            ReleaseId::from(RequestId::parse(REQUEST_ID).expect("test UUID should be canonical"));
        let result = RollbackResult {
            release_id,
            previous_release_id: Some(previous_release_id),
            activated_at_unix_secs: 1_700_000_000,
        };

        let value = serde_json::to_value(&result).expect("result should serialize");
        assert_eq!(
            value,
            json!({
                "releaseId": RELEASE_ID,
                "previousReleaseId": REQUEST_ID,
                "activatedAtUnixSecs": 1_700_000_000_u64,
            })
        );
    }
}
