pub mod execute;

use crate::{
    db_restore::ContainerName,
    transaction::{IdempotencyKey, RequestId},
};
use serde::Deserialize;

pub const OPERATION: &str = "db.clearMariaSlowLog";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    container: String,
    root_password: String,
}

pub struct Request {
    pub container: ContainerName,
    pub root_password: String,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    InvalidContainer,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl Request {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        Ok(Self {
            container: ContainerName::parse(&plan.container)
                .map_err(|_| RequestError::InvalidContainer)?,
            root_password: plan.root_password,
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
pub struct ClearResult {
    pub restored_enabled_state: bool,
    pub completed_at_unix_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_the_container_and_request_identity() {
        let id = "123e4567-e89b-12d3-a456-426614174000";
        assert!(
            Request::parse(
                r#"{"container":"mariadb-11","rootPassword":"secret"}"#,
                id,
                None
            )
            .is_ok()
        );
        assert!(
            Request::parse(
                r#"{"container":"../bad","rootPassword":"secret"}"#,
                id,
                None
            )
            .is_err()
        );
    }
}
