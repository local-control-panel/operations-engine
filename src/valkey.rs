pub mod delete;
pub mod flush;
pub mod flush_all;

use crate::{
    db_restore::ContainerName,
    transaction::{IdempotencyKey, RequestId},
};
use serde::Deserialize;

pub const DELETE_OPERATION: &str = "db.deleteValkeyKey";
pub const FLUSH_DB_OPERATION: &str = "db.flushValkeyDb";
pub const FLUSH_ALL_OPERATION: &str = "db.flushAllValkey";
pub const MAX_KEY_BYTES: usize = 4096;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeletePlan {
    container: String,
    key: String,
}

#[derive(Debug)]
pub struct DeleteRequest {
    pub container: ContainerName,
    pub key: String,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    InvalidContainer,
    InvalidKey,
    InvalidFlushDbConfirmation,
    InvalidFlushAllConfirmation,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl DeleteRequest {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: DeletePlan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        if plan.key.is_empty() || plan.key.len() > MAX_KEY_BYTES {
            return Err(RequestError::InvalidKey);
        }
        Ok(Self {
            container: ContainerName::parse(&plan.container)
                .map_err(|_| RequestError::InvalidContainer)?,
            key: plan.key,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteResult {
    pub deleted: bool,
    pub completed_at_unix_secs: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FlushDbPlan {
    container: String,
    confirmation: String,
}

#[derive(Debug)]
pub struct FlushDbRequest {
    pub container: ContainerName,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl FlushDbRequest {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: FlushDbPlan =
            serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        if plan.confirmation != "FLUSHDB" {
            return Err(RequestError::InvalidFlushDbConfirmation);
        }
        Ok(Self {
            container: ContainerName::parse(&plan.container)
                .map_err(|_| RequestError::InvalidContainer)?,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlushResult {
    pub accepted: bool,
    pub completed_at_unix_secs: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FlushAllPlan {
    container: String,
    confirmation: String,
}

#[derive(Debug)]
pub struct FlushAllRequest {
    pub container: ContainerName,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl FlushAllRequest {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: FlushAllPlan =
            serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        if plan.confirmation != "FLUSHALL" {
            return Err(RequestError::InvalidFlushAllConfirmation);
        }
        Ok(Self {
            container: ContainerName::parse(&plan.container)
                .map_err(|_| RequestError::InvalidContainer)?,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    #[test]
    fn accepts_utf8_and_control_bytes_but_bounds_the_key() {
        for key in ["", &"x".repeat(MAX_KEY_BYTES + 1)] {
            let json = serde_json::json!({"container":"valkey-8","key":key}).to_string();
            assert_eq!(
                DeleteRequest::parse(&json, ID, None).unwrap_err(),
                RequestError::InvalidKey
            );
        }
        let json = serde_json::json!({"container":"valkey-8","key":"ключ\n\0*"}).to_string();
        assert!(DeleteRequest::parse(&json, ID, None).is_ok());
    }

    #[test]
    fn flush_db_requires_the_exact_confirmation_token() {
        for confirmation in ["", "flushdb", "FLUSHALL", " FLUSHDB"] {
            let json =
                serde_json::json!({"container":"valkey-8","confirmation":confirmation}).to_string();
            assert_eq!(
                FlushDbRequest::parse(&json, ID, None).unwrap_err(),
                RequestError::InvalidFlushDbConfirmation
            );
        }
        let json = serde_json::json!({"container":"valkey-8","confirmation":"FLUSHDB"}).to_string();
        assert!(FlushDbRequest::parse(&json, ID, None).is_ok());
    }

    #[test]
    fn flush_all_requires_its_own_exact_confirmation_token() {
        for confirmation in ["", "flushall", "FLUSHDB", " FLUSHALL"] {
            let json =
                serde_json::json!({"container":"valkey-8","confirmation":confirmation}).to_string();
            assert_eq!(
                FlushAllRequest::parse(&json, ID, None).unwrap_err(),
                RequestError::InvalidFlushAllConfirmation
            );
        }
        let json =
            serde_json::json!({"container":"valkey-8","confirmation":"FLUSHALL"}).to_string();
        assert!(FlushAllRequest::parse(&json, ID, None).is_ok());
    }
}
