pub mod execute;
pub mod set;

use crate::{
    db_restore::ContainerName,
    transaction::{IdempotencyKey, RequestId},
};
use serde::Deserialize;

pub const OPERATION: &str = "db.clearMariaSlowLog";
pub const SET_OPERATION: &str = "db.configureMariaSlowLog";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    container: String,
    root_password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SetPlan {
    container: String,
    root_password: String,
    enabled: bool,
    long_query_time: Option<f64>,
}

pub struct Request {
    pub container: ContainerName,
    pub root_password: String,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

pub struct SetRequest {
    pub container: ContainerName,
    pub root_password: String,
    pub enabled: bool,
    pub long_query_time: Option<f64>,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    InvalidContainer,
    InvalidRequestId,
    InvalidIdempotencyKey,
    InvalidLongQueryTime,
}

impl SetRequest {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: SetPlan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        if plan
            .long_query_time
            .is_some_and(|value| !value.is_finite() || !(0.0..=3600.0).contains(&value))
        {
            return Err(RequestError::InvalidLongQueryTime);
        }
        Ok(Self {
            container: ContainerName::parse(&plan.container)
                .map_err(|_| RequestError::InvalidContainer)?,
            root_password: plan.root_password,
            enabled: plan.enabled,
            long_query_time: plan.long_query_time,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }
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

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetResult {
    pub enabled: bool,
    pub long_query_time: Option<f64>,
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

    #[test]
    fn set_request_rejects_out_of_range_thresholds() {
        let id = "123e4567-e89b-12d3-a456-426614174000";
        for value in [-0.1, 3600.1] {
            let json = serde_json::json!({
                "container":"mariadb-11",
                "rootPassword":"secret",
                "enabled":true,
                "longQueryTime":value,
            });
            assert_eq!(
                SetRequest::parse(&json.to_string(), id, None).err(),
                Some(RequestError::InvalidLongQueryTime)
            );
        }
    }
}
