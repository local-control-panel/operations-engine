pub mod execute;
pub mod remove;

use crate::{
    site::Domain,
    transaction::{IdempotencyKey, RequestId},
};
use serde::Deserialize;

pub const OPERATION: &str = "dbTool.converge";
pub const REMOVE_OPERATION: &str = "dbTool.remove";
pub const PMA_IMAGE: &str =
    "phpmyadmin:5.2.3@sha256:3a8a8d6b5289091f959ba0293f21163b3a2fc5741991a53de70b3497fe8d31db";
pub const ADMINER_IMAGE: &str = "adminer:6.0.1-standalone@sha256:f742dcf1b6ca95733b54c4e020488ce78f3e774d73543a6ded9b4eaea8974f3d";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum Tool {
    PhpMyAdmin,
    Adminer,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum Action {
    Install,
    Start,
    Stop,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum DatabaseType {
    Mariadb,
    Postgresql,
}

/// Database services a tool may point at: the closed set of Compose services
/// the stack catalog can run, per database type.
pub const MARIADB_SERVICES: &[&str] = &["mariadb-11", "mariadb-13"];
pub const POSTGRES_SERVICES: &[&str] = &["postgres-17"];
pub const DEFAULT_MARIADB_SERVICE: &str = "mariadb-11";
pub const DEFAULT_POSTGRES_SERVICE: &str = "postgres-17";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    tool: Tool,
    action: Action,
    domain: Option<String>,
    database_type: Option<DatabaseType>,
    database_service: Option<String>,
}

#[derive(Debug)]
pub struct Request {
    pub tool: Tool,
    pub action: Action,
    pub domain: Option<Domain>,
    pub database_type: Option<DatabaseType>,
    /// Compose service the tool connects to; `None` means the default of the
    /// database type (`mariadb-11`, `postgres-17`).
    pub database_service: Option<&'static str>,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    InvalidDomain,
    InvalidShape,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl Request {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        if plan.action == Action::Install && plan.domain.is_none() {
            return Err(RequestError::InvalidShape);
        }
        if plan.action != Action::Install
            && (plan.domain.is_some()
                || plan.database_type.is_some()
                || plan.database_service.is_some())
        {
            return Err(RequestError::InvalidShape);
        }
        if plan.tool == Tool::PhpMyAdmin
            && plan
                .database_type
                .is_some_and(|v| v != DatabaseType::Mariadb)
        {
            return Err(RequestError::InvalidShape);
        }
        let allowed = match plan.database_type {
            Some(DatabaseType::Postgresql) => POSTGRES_SERVICES,
            _ => MARIADB_SERVICES,
        };
        let database_service = plan
            .database_service
            .as_deref()
            .map(|v| allowed.iter().copied().find(|s| *s == v))
            .map(|v| v.ok_or(RequestError::InvalidShape))
            .transpose()?;
        let domain = plan
            .domain
            .as_deref()
            .map(Domain::parse)
            .transpose()
            .map_err(|_| RequestError::InvalidDomain)?;
        Ok(Self {
            tool: plan.tool,
            action: plan.action,
            domain,
            database_type: plan.database_type,
            database_service,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }
    pub fn name(&self) -> &'static str {
        match self.tool {
            Tool::PhpMyAdmin => "wcp-phpmyadmin",
            Tool::Adminer => "wcp-adminer",
        }
    }
    /// The database service the tool is wired to.
    pub fn service(&self) -> &'static str {
        self.database_service.unwrap_or(match self.database_type {
            Some(DatabaseType::Postgresql) => DEFAULT_POSTGRES_SERVICE,
            _ => DEFAULT_MARIADB_SERVICE,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RemovePlan {
    tool: Tool,
    domain: Option<String>,
}

#[derive(Debug)]
pub struct RemoveRequest {
    pub tool: Tool,
    pub domain: Option<Domain>,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}
impl RemoveRequest {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: RemovePlan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        Ok(Self {
            tool: plan.tool,
            domain: plan
                .domain
                .as_deref()
                .map(Domain::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidDomain)?,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }
    pub fn name(&self) -> &'static str {
        match self.tool {
            Tool::PhpMyAdmin => "wcp-phpmyadmin",
            Tool::Adminer => "wcp-adminer",
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveResult {
    pub tool: String,
    pub removed: bool,
    pub completed_at_unix_secs: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolResult {
    pub tool: String,
    pub action: String,
    pub running: bool,
    pub completed_at_unix_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    #[test]
    fn validates_action_shapes() {
        assert!(Request::parse(r#"{"tool":"adminer","action":"install","domain":"db.example.com","databaseType":"postgresql"}"#,ID,None).is_ok());
        assert!(Request::parse(r#"{"tool":"phpMyAdmin","action":"start","domain":"db.example.com","databaseType":null}"#,ID,None).is_err());
    }
}
