pub mod drop;

use crate::{
    db_restore::ContainerName,
    transaction::{IdempotencyKey, RequestId},
};
use serde::Deserialize;

pub const DROP_OPERATION: &str = "db.dropMariaDbUser";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DropPlan {
    container: String,
    root_password: String,
    user: String,
    host: String,
}

#[derive(Debug)]
pub struct DropRequest {
    pub container: ContainerName,
    pub root_password: String,
    pub user: String,
    pub host: String,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    InvalidContainer,
    InvalidUser,
    ProtectedUser,
    InvalidHost,
    InvalidSecret,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl DropRequest {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: DropPlan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        if plan.user.is_empty()
            || plan.user.len() > 80
            || !plan
                .user
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '@' | '%'))
        {
            return Err(RequestError::InvalidUser);
        }
        if matches!(
            plan.user.to_ascii_lowercase().as_str(),
            "root" | "mysql" | "mariadb.sys" | "healthcheck"
        ) {
            return Err(RequestError::ProtectedUser);
        }
        if plan.host.is_empty()
            || plan.host.len() > 255
            || !plan
                .host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '%' | '_' | '-'))
        {
            return Err(RequestError::InvalidHost);
        }
        if plan.root_password.len() > 4096 || plan.root_password.contains(['\n', '\r', '\0']) {
            return Err(RequestError::InvalidSecret);
        }
        Ok(Self {
            container: ContainerName::parse(&plan.container)
                .map_err(|_| RequestError::InvalidContainer)?,
            root_password: plan.root_password,
            user: plan.user,
            host: plan.host,
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
    pub user: String,
    pub host: String,
    pub completed_at_unix_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    #[test]
    fn validates_account_and_protects_system_users() {
        for user in ["root", "ROOT", "mysql", "mariadb.sys", "healthcheck"] {
            let json = format!(
                r#"{{"container":"mariadb-11","rootPassword":"secret","user":"{user}","host":"localhost"}}"#
            );
            assert_eq!(
                DropRequest::parse(&json, ID, None).unwrap_err(),
                RequestError::ProtectedUser
            );
        }
        for json in [
            r#"{"container":"mariadb-11","rootPassword":"secret","user":"bad'user","host":"localhost"}"#,
            r#"{"container":"mariadb-11","rootPassword":"secret","user":"site_user","host":"bad'host"}"#,
        ] {
            assert!(DropRequest::parse(json, ID, None).is_err());
        }
        assert!(DropRequest::parse(
            r#"{"container":"mariadb-11","rootPassword":"secret","user":"site_user","host":"%"}"#,
            ID,
            None,
        ).is_ok());
    }
}
