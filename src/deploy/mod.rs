//! The `site.deploy` operation (Phase 4). Nothing here is wired into
//! `cli`/`capabilities` until every item in `PLAN.md`'s Phase 4 passes.

pub mod preflight;
pub mod resolve;

use std::fmt;

use serde::Serialize;

use crate::{
    site::{GitCommitSha, SiteId},
    transaction::{IdempotencyKey, IdentifierError, RequestId},
};

/// Identifies one prepared release directory (`releases/<releaseId>/`).
/// Always equal to the `RequestId` of the deploy attempt that created it:
/// deploy produces at most one release per transaction, so reusing that
/// identifier keeps a release, its transaction state, and its audit trail
/// joinable without a second ID scheme to keep in sync.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ReleaseId(RequestId);

impl ReleaseId {
    pub fn parse(value: &str) -> Result<Self, IdentifierError> {
        RequestId::parse(value).map(Self)
    }
}

impl From<RequestId> for ReleaseId {
    fn from(request_id: RequestId) -> Self {
        Self(request_id)
    }
}

impl fmt::Display for ReleaseId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// The stable protocol operation name, and the value recorded as
/// `TransactionState::operation` for every deploy attempt.
pub const OPERATION: &str = "site.deploy";

/// A validated `site.deploy` request. Field types (`SiteId`, `GitCommitSha`,
/// `RequestId`, `IdempotencyKey`) already enforce their own rules; `parse`
/// only composes them and reports which one failed.
#[derive(Debug, Eq, PartialEq)]
pub struct DeployRequest {
    pub site_id: SiteId,
    /// A resolved full Git object ID. Per `docs/site-model.md`, branch names
    /// and short SHAs are not accepted here — resolving an allowed ref to
    /// this form is a preflight concern (item 3), not a parsing one.
    pub revision: GitCommitSha,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeployRequestError {
    InvalidSiteId,
    InvalidRevision,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl DeployRequest {
    pub fn parse(
        site_id: &str,
        revision: &str,
        request_id: &str,
        idempotency_key: Option<&str>,
    ) -> Result<Self, DeployRequestError> {
        Ok(Self {
            site_id: SiteId::parse(site_id).map_err(|_| DeployRequestError::InvalidSiteId)?,
            revision: GitCommitSha::parse(revision)
                .map_err(|_| DeployRequestError::InvalidRevision)?,
            request_id: RequestId::parse(request_id)
                .map_err(|_| DeployRequestError::InvalidRequestId)?,
            idempotency_key: idempotency_key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| DeployRequestError::InvalidIdempotencyKey)?,
        })
    }
}

/// The `result` payload of a successful `site.deploy` response. Every field
/// is either an opaque stable identifier or a value the request already
/// supplied — nothing here can carry secrets or subprocess output.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployResult {
    pub release_id: ReleaseId,
    pub previous_release_id: Option<ReleaseId>,
    pub commit: GitCommitSha,
    pub activated_at_unix_secs: u64,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{DeployRequest, DeployRequestError, DeployResult, ReleaseId};
    use crate::transaction::RequestId;

    const SITE_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
    const REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const REVISION: &str = "abcdef0123456789abcdef0123456789abcdef01";

    #[test]
    fn release_id_shares_request_ids_canonical_uuid_rule() {
        assert!(ReleaseId::parse(REQUEST_ID).is_ok());
        assert!(ReleaseId::parse("not-a-uuid").is_err());
        assert!(ReleaseId::parse("00000000-0000-0000-0000-000000000000").is_err());
    }

    #[test]
    fn release_id_from_request_id_round_trips_through_display() {
        let request_id = RequestId::parse(REQUEST_ID).expect("test UUID should be canonical");
        assert_eq!(ReleaseId::from(request_id).to_string(), REQUEST_ID);
    }

    #[test]
    fn deploy_request_parses_all_valid_fields() {
        let request = DeployRequest::parse(SITE_ID, REVISION, REQUEST_ID, Some("deploy-key-1"))
            .expect("request should parse");
        assert_eq!(request.site_id.to_string(), SITE_ID);
        assert_eq!(request.revision.as_str(), REVISION);
        assert_eq!(request.request_id.to_string(), REQUEST_ID);
        assert_eq!(
            request.idempotency_key.map(|key| key.as_str().to_owned()),
            Some("deploy-key-1".to_owned())
        );
    }

    #[test]
    fn deploy_request_allows_a_missing_idempotency_key() {
        let request = DeployRequest::parse(SITE_ID, REVISION, REQUEST_ID, None)
            .expect("request without an idempotency key should parse");
        assert_eq!(request.idempotency_key, None);
    }

    #[test]
    fn deploy_request_reports_which_field_failed() {
        assert_eq!(
            DeployRequest::parse("not-a-uuid", REVISION, REQUEST_ID, None).unwrap_err(),
            DeployRequestError::InvalidSiteId
        );
        assert_eq!(
            DeployRequest::parse(SITE_ID, "main", REQUEST_ID, None).unwrap_err(),
            DeployRequestError::InvalidRevision
        );
        assert_eq!(
            DeployRequest::parse(SITE_ID, REVISION, "not-a-uuid", None).unwrap_err(),
            DeployRequestError::InvalidRequestId
        );
        assert_eq!(
            DeployRequest::parse(SITE_ID, REVISION, REQUEST_ID, Some("has space")).unwrap_err(),
            DeployRequestError::InvalidIdempotencyKey
        );
    }

    #[test]
    fn deploy_result_serializes_with_safe_camel_case_fields() {
        let release_id =
            ReleaseId::from(RequestId::parse(REQUEST_ID).expect("test UUID should be canonical"));
        let result = DeployResult {
            release_id,
            previous_release_id: None,
            commit: crate::site::GitCommitSha::parse(REVISION).expect("test SHA should be valid"),
            activated_at_unix_secs: 1_700_000_000,
        };

        let value = serde_json::to_value(&result).expect("result should serialize");
        assert_eq!(
            value,
            json!({
                "releaseId": REQUEST_ID,
                "previousReleaseId": null,
                "commit": REVISION,
                "activatedAtUnixSecs": 1_700_000_000_u64,
            })
        );
    }
}
