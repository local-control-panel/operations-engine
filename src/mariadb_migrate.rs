//! Validated request contract for `db.migrateMariadbLine`: moving the managed
//! stack's databases and accounts from one MariaDB line's service to another
//! line's service (their data volumes are separate and never shared), then
//! pointing the old service name at the new server with a network alias so
//! no site configuration changes.

pub mod docker;
pub mod execute;

use serde::Deserialize;

use crate::{
    site::StackName,
    transaction::{IdempotencyKey, RequestId},
};

pub const OPERATION: &str = "db.migrateMariadbLine";
/// The Compose services of the lines the catalog can run.
pub const SERVICES: [&str; 2] = ["mariadb-11", "mariadb-13"];
const MAX_SECRET_BYTES: usize = 4096;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    stack_name: String,
    source_service: String,
    target_service: String,
    root_password: String,
}

#[derive(Debug)]
pub struct MigrateRequest {
    pub stack_name: StackName,
    pub source_service: &'static str,
    pub target_service: &'static str,
    /// Execution-only secret: never serialized into transaction or audit
    /// state, so the request deliberately does not implement `Serialize`.
    pub root_password: String,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrateResult {
    pub source_service: String,
    pub target_service: String,
    pub source_version: String,
    pub target_version: String,
    pub backup_id: String,
    pub retained_source_volume: String,
    pub target_volume: String,
    pub databases: u64,
    pub tables: u64,
    pub completed_at_unix_secs: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    InvalidStackName,
    InvalidService,
    SameService,
    InvalidSecret,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl MigrateRequest {
    pub fn parse(
        json: &str,
        request_id: &str,
        idempotency_key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        if plan.stack_name != "wp-stack" {
            return Err(RequestError::InvalidStackName);
        }
        let service = |value: &str| {
            SERVICES
                .iter()
                .copied()
                .find(|known| *known == value)
                .ok_or(RequestError::InvalidService)
        };
        let source_service = service(&plan.source_service)?;
        let target_service = service(&plan.target_service)?;
        if source_service == target_service {
            return Err(RequestError::SameService);
        }
        if plan.root_password.is_empty()
            || plan.root_password.len() > MAX_SECRET_BYTES
            || plan.root_password.contains(['\n', '\r', '\0'])
        {
            return Err(RequestError::InvalidSecret);
        }
        Ok(Self {
            stack_name: StackName::parse(&plan.stack_name)
                .map_err(|_| RequestError::InvalidStackName)?,
            source_service,
            target_service,
            root_password: plan.root_password,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: idempotency_key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }
}

/// `13` for `mariadb-13`: names the Compose profile (`db-13`) and the alias
/// variable (`WCP_MARIADB_13_ALIAS`) of a service.
pub fn major_of(service: &str) -> &str {
    service.rsplit('-').next().unwrap_or(service)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    fn plan(source: &str, target: &str, password: &str) -> String {
        format!(
            r#"{{"stackName":"wp-stack","sourceService":"{source}","targetService":"{target}","rootPassword":"{password}"}}"#
        )
    }

    #[test]
    fn a_catalog_line_pair_is_admitted() {
        let request =
            MigrateRequest::parse(&plan("mariadb-11", "mariadb-13", "s3cret"), ID, None).unwrap();
        assert_eq!(request.source_service, "mariadb-11");
        assert_eq!(request.target_service, "mariadb-13");
        assert_eq!(major_of(request.target_service), "13");
    }

    #[test]
    fn anything_else_is_refused() {
        for (json, expected) in [
            (plan("mariadb-11", "mariadb-12", "x"), RequestError::InvalidService),
            (plan("mariadb-11 --privileged", "mariadb-13", "x"), RequestError::InvalidService),
            (plan("mariadb-13", "mariadb-13", "x"), RequestError::SameService),
            (plan("mariadb-11", "mariadb-13", ""), RequestError::InvalidSecret),
            (plan("mariadb-11", "mariadb-13", "a\\nb"), RequestError::InvalidSecret),
            (
                r#"{"stackName":"other","sourceService":"mariadb-11","targetService":"mariadb-13","rootPassword":"x"}"#.into(),
                RequestError::InvalidStackName,
            ),
            ("{}".into(), RequestError::InvalidJson),
        ] {
            assert_eq!(MigrateRequest::parse(&json, ID, None).unwrap_err(), expected, "{json}");
        }
        assert_eq!(
            MigrateRequest::parse(&plan("mariadb-11", "mariadb-13", "x"), "nope", None)
                .unwrap_err(),
            RequestError::InvalidRequestId
        );
    }
}
