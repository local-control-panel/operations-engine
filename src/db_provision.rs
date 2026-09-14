pub mod execute;

use serde::Deserialize;

use crate::{
    db_restore::{ContainerName, DatabaseName},
    transaction::{IdempotencyKey, RequestId},
};

pub const OPERATION: &str = "db.provisionMariaDb";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum CreateMode {
    Create,
    Ensure,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    container: String,
    root_password: String,
    database: Option<DatabasePlan>,
    user: Option<UserPlan>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DatabasePlan {
    name: String,
    mode: CreateMode,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UserPlan {
    name: String,
    host: String,
    password: String,
    mode: CreateMode,
    grant_database: Option<String>,
}

#[derive(Debug)]
pub struct DatabaseRequest {
    pub name: DatabaseName,
    pub mode: CreateMode,
}

#[derive(Debug)]
pub struct UserRequest {
    pub name: String,
    pub host: String,
    pub password: String,
    pub mode: CreateMode,
    pub grant_database: Option<DatabaseName>,
}

#[derive(Debug)]
pub struct ProvisionRequest {
    pub container: ContainerName,
    pub root_password: String,
    pub database: Option<DatabaseRequest>,
    pub user: Option<UserRequest>,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    InvalidContainer,
    InvalidDatabase,
    InvalidUser,
    InvalidHost,
    InvalidSecret,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl ProvisionRequest {
    pub fn parse(
        json: &str,
        request_id: &str,
        idempotency_key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        let container =
            ContainerName::parse(&plan.container).map_err(|_| RequestError::InvalidContainer)?;
        if plan.database.is_none() && plan.user.is_none() {
            return Err(RequestError::InvalidDatabase);
        }
        let database = plan
            .database
            .map(|database| {
                Ok(DatabaseRequest {
                    name: DatabaseName::parse(&database.name)
                        .map_err(|_| RequestError::InvalidDatabase)?,
                    mode: database.mode,
                })
            })
            .transpose()?;
        validate_secret(&plan.root_password)?;
        let user =
            plan.user
                .map(|user| {
                    if user.name.is_empty()
                        || user.name.len() > 80
                        || !user
                            .name
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
                    {
                        return Err(RequestError::InvalidUser);
                    }
                    if user.host.is_empty()
                        || user.host.len() > 255
                        || !user.host.chars().all(|c| {
                            c.is_ascii_alphanumeric() || matches!(c, '.' | '%' | '_' | '-')
                        })
                    {
                        return Err(RequestError::InvalidHost);
                    }
                    validate_secret(&user.password)?;
                    Ok(UserRequest {
                        name: user.name,
                        host: user.host,
                        password: user.password,
                        mode: user.mode,
                        grant_database: user
                            .grant_database
                            .as_deref()
                            .map(DatabaseName::parse)
                            .transpose()
                            .map_err(|_| RequestError::InvalidDatabase)?,
                    })
                })
                .transpose()?;
        Ok(Self {
            container,
            root_password: plan.root_password,
            database,
            user,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: idempotency_key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }
}

fn validate_secret(secret: &str) -> Result<(), RequestError> {
    if secret.len() > 4096 || secret.contains(['\n', '\r', '\0']) {
        Err(RequestError::InvalidSecret)
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisionResult {
    pub database: Option<String>,
    pub user_provisioned: bool,
    pub completed_at_unix_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    #[test]
    fn parses_typed_ensure_plan() {
        let request = ProvisionRequest::parse(
            r#"{"container":"wcp-mariadb-1","rootPassword":"root-secret","database":{"name":"site_db","mode":"ensure"},"user":{"name":"site_user","host":"%","password":"user-secret","mode":"ensure","grantDatabase":"site_db"}}"#,
            ID,
            Some("provision-1"),
        ).unwrap();
        assert_eq!(request.database.unwrap().name.as_str(), "site_db");
        assert_eq!(request.user.unwrap().host, "%");
    }

    #[test]
    fn rejects_shell_syntax_and_multiline_secrets() {
        for json in [
            r#"{"container":"c","rootPassword":"x","database":{"name":"bad-db","mode":"create"},"user":null}"#,
            "{\"container\":\"c\",\"rootPassword\":\"a\\nb\",\"database\":{\"name\":\"db\",\"mode\":\"create\"},\"user\":null}",
        ] {
            assert!(ProvisionRequest::parse(json, ID, None).is_err());
        }
    }
}
