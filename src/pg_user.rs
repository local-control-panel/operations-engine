pub mod execute;

use crate::{
    db_restore::{ContainerName, DatabaseName},
    transaction::{IdempotencyKey, RequestId},
};
use serde::Deserialize;

pub const OPERATION: &str = "db.provisionPostgresUser";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    container: String,
    root_password: String,
    user: String,
    password: String,
    database: Option<String>,
}

#[derive(Debug)]
pub struct Request {
    pub container: ContainerName,
    pub root_password: String,
    pub user: String,
    pub password: String,
    pub database: Option<DatabaseName>,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    InvalidContainer,
    InvalidUser,
    ProtectedUser,
    InvalidDatabase,
    InvalidSecret,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl Request {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        if [&plan.root_password, &plan.password].iter().any(|secret| {
            secret.is_empty() || secret.len() > 4096 || secret.contains(['\n', '\r', '\0'])
        }) {
            return Err(RequestError::InvalidSecret);
        }
        if !valid_user(&plan.user) {
            return Err(RequestError::InvalidUser);
        }
        if plan.user == "postgres" || plan.user.starts_with("pg_") {
            return Err(RequestError::ProtectedUser);
        }
        Ok(Self {
            container: ContainerName::parse(&plan.container)
                .map_err(|_| RequestError::InvalidContainer)?,
            root_password: plan.root_password,
            user: plan.user,
            password: plan.password,
            database: plan
                .database
                .map(|value| DatabaseName::parse(&value).map_err(|_| RequestError::InvalidDatabase))
                .transpose()?,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }
}

fn valid_user(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}
pub(crate) fn quote_literal(value: &str) -> String {
    value.replace('\'', "''")
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisionResult {
    pub user: String,
    pub database: Option<String>,
    pub completed_at_unix_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    #[test]
    fn validates_role_and_secrets() {
        assert!(Request::parse(r#"{"container":"postgres-17","rootPassword":"root","user":"app_user","password":"p'ass","database":"site_db"}"#, ID, None).is_ok());
        for user in ["postgres", "pg_monitor", "bad-user", ""] {
            let json = format!(
                r#"{{"container":"postgres-17","rootPassword":"root","user":"{user}","password":"secret"}}"#
            );
            assert!(Request::parse(&json, ID, None).is_err());
        }
        assert_eq!(quote_literal("p'ass"), "p''ass");
    }
}
