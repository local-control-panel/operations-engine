pub mod execute;

use crate::{
    db_restore::{ContainerName, DatabaseName},
    transaction::{IdempotencyKey, RequestId},
};
use serde::Deserialize;

pub const OPERATION: &str = "db.provisionPostgres";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    container: String,
    root_password: String,
    database: String,
}

#[derive(Debug)]
pub struct Request {
    pub container: ContainerName,
    pub root_password: String,
    pub database: DatabaseName,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    InvalidContainer,
    InvalidDatabase,
    InvalidSecret,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl Request {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let p: Plan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        if p.root_password.len() > 4096 || p.root_password.contains(['\n', '\r', '\0']) {
            return Err(RequestError::InvalidSecret);
        }
        Ok(Self {
            container: ContainerName::parse(&p.container)
                .map_err(|_| RequestError::InvalidContainer)?,
            root_password: p.root_password,
            database: DatabaseName::parse(&p.database)
                .map_err(|_| RequestError::InvalidDatabase)?,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisionResult {
    pub database: String,
    pub completed_at_unix_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    #[test]
    fn validates_request() {
        assert!(
            Request::parse(
                r#"{"container":"postgres-17","rootPassword":"secret","database":"site_db"}"#,
                ID,
                None
            )
            .is_ok()
        );
        assert!(
            Request::parse(
                r#"{"container":"postgres-17","rootPassword":"secret","database":"bad-db"}"#,
                ID,
                None
            )
            .is_err()
        );
    }
}
