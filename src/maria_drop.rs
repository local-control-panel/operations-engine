pub mod execute;

use crate::{
    db_restore::{ContainerName, DatabaseName},
    transaction::{IdempotencyKey, RequestId},
};
use serde::Deserialize;

pub const OPERATION: &str = "db.dropMariaDb";

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
    ProtectedDatabase,
    InvalidSecret,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl Request {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        if plan.root_password.len() > 4096 || plan.root_password.contains(['\n', '\r', '\0']) {
            return Err(RequestError::InvalidSecret);
        }
        if matches!(
            plan.database.to_ascii_lowercase().as_str(),
            "mysql" | "information_schema" | "performance_schema" | "sys"
        ) {
            return Err(RequestError::ProtectedDatabase);
        }
        Ok(Self {
            container: ContainerName::parse(&plan.container)
                .map_err(|_| RequestError::InvalidContainer)?,
            root_password: plan.root_password,
            database: DatabaseName::parse(&plan.database)
                .map_err(|_| RequestError::InvalidDatabase)?,
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
pub struct DropResult {
    pub database: String,
    pub completed_at_unix_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    #[test]
    fn rejects_system_databases_case_insensitively_and_invalid_identifiers() {
        for database in [
            "mysql",
            "MYSQL",
            "information_schema",
            "performance_schema",
            "sys",
            "bad-db",
        ] {
            let json = format!(
                r#"{{"container":"mariadb-11","rootPassword":"secret","database":"{database}"}}"#
            );
            assert!(Request::parse(&json, ID, None).is_err());
        }
        assert!(
            Request::parse(
                r#"{"container":"mariadb-11","rootPassword":"secret","database":"site_db"}"#,
                ID,
                None,
            )
            .is_ok()
        );
    }
}
