//! The `engine.install` and `engine.rollback` operations (Phase 7):
//! fetching, verifying, and atomically activating a new `ops-engine`
//! binary, and reverting to the one retained previous binary without a
//! network call. See
//! `docs/superpowers/specs/2026-09-03-release-pipeline-design.md`.

pub mod fetch;
pub mod install;
pub mod release;
pub mod rollback;
pub mod state;
pub mod verify;

use serde::{Deserialize, Serialize};

use crate::transaction::{IdempotencyKey, RequestId};

pub const INSTALL_OPERATION: &str = "engine.install";
pub const ROLLBACK_OPERATION: &str = "engine.rollback";

#[derive(Debug, Eq, PartialEq)]
pub struct EngineInstallRequest {
    pub version: release::EngineVersion,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineInstallRequestError {
    InvalidVersion,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl EngineInstallRequest {
    pub fn parse(
        version: &str,
        request_id: &str,
        idempotency_key: Option<&str>,
    ) -> Result<Self, EngineInstallRequestError> {
        Ok(Self {
            version: release::EngineVersion::parse(version)
                .map_err(|_| EngineInstallRequestError::InvalidVersion)?,
            request_id: RequestId::parse(request_id)
                .map_err(|_| EngineInstallRequestError::InvalidRequestId)?,
            idempotency_key: idempotency_key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| EngineInstallRequestError::InvalidIdempotencyKey)?,
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct EngineRollbackRequest {
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineRollbackRequestError {
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl EngineRollbackRequest {
    pub fn parse(
        request_id: &str,
        idempotency_key: Option<&str>,
    ) -> Result<Self, EngineRollbackRequestError> {
        Ok(Self {
            request_id: RequestId::parse(request_id)
                .map_err(|_| EngineRollbackRequestError::InvalidRequestId)?,
            idempotency_key: idempotency_key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| EngineRollbackRequestError::InvalidIdempotencyKey)?,
        })
    }
}

/// The `result` payload of a successful `engine.install` response.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineInstallResult {
    pub version: String,
    pub previous_version: Option<String>,
    pub activated_at_unix_secs: u64,
}

/// The `result` payload of a successful `engine.rollback` response.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineRollbackResult {
    pub version: String,
    pub previous_version: String,
    pub activated_at_unix_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::{
        EngineInstallRequest, EngineInstallRequestError, EngineRollbackRequest,
        EngineRollbackRequestError,
    };

    const REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    #[test]
    fn install_request_parses_all_valid_fields() {
        let request = EngineInstallRequest::parse("0.5.0", REQUEST_ID, Some("install-1"))
            .expect("request should parse");
        assert_eq!(request.version.as_str(), "0.5.0");
        assert_eq!(request.request_id.to_string(), REQUEST_ID);
        assert_eq!(
            request.idempotency_key.map(|key| key.as_str().to_owned()),
            Some("install-1".to_owned())
        );
    }

    #[test]
    fn install_request_allows_a_missing_idempotency_key() {
        let request = EngineInstallRequest::parse("0.5.0", REQUEST_ID, None)
            .expect("request without an idempotency key should parse");
        assert_eq!(request.idempotency_key, None);
    }

    #[test]
    fn install_request_reports_which_field_failed() {
        assert_eq!(
            EngineInstallRequest::parse("not-a-version", REQUEST_ID, None).unwrap_err(),
            EngineInstallRequestError::InvalidVersion
        );
        assert_eq!(
            EngineInstallRequest::parse("0.5.0", "not-a-uuid", None).unwrap_err(),
            EngineInstallRequestError::InvalidRequestId
        );
        assert_eq!(
            EngineInstallRequest::parse("0.5.0", REQUEST_ID, Some("has space")).unwrap_err(),
            EngineInstallRequestError::InvalidIdempotencyKey
        );
    }

    #[test]
    fn rollback_request_parses_all_valid_fields() {
        let request = EngineRollbackRequest::parse(REQUEST_ID, None).expect("request should parse");
        assert_eq!(request.request_id.to_string(), REQUEST_ID);
    }

    #[test]
    fn rollback_request_reports_which_field_failed() {
        assert_eq!(
            EngineRollbackRequest::parse("not-a-uuid", None).unwrap_err(),
            EngineRollbackRequestError::InvalidRequestId
        );
        assert_eq!(
            EngineRollbackRequest::parse(REQUEST_ID, Some("has space")).unwrap_err(),
            EngineRollbackRequestError::InvalidIdempotencyKey
        );
    }
}
