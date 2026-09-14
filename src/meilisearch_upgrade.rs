//! Validated request contract for the controlled Meilisearch upgrade.
//!
//! Execution is intentionally added separately: admitting an upgrade request
//! must be strict before any code is allowed to stop a live search service or
//! touch its data store.

use serde::Deserialize;

use crate::{
    db_restore::ContainerName,
    site::StackName,
    transaction::{IdempotencyKey, RequestId},
};

pub const OPERATION: &str = "meilisearch.upgrade";
pub const TARGET_VERSION: &str = "1.53.2";
pub const TARGET_IMAGE: &str = "ghcr.io/local-control-panel/meilisearch:1.53.2@sha256:c94e58ca09662dd6e65e8f1b0fd145767be3da7d5422a863a27b8d2b68e090c9";
const MAX_SECRET_BYTES: usize = 4096;
const MAX_PROBES: usize = 32;
const MAX_QUERY_BYTES: usize = 4096;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    stack_name: String,
    service: String,
    target_image: String,
    master_key: String,
    #[serde(default)]
    search_probes: Vec<SearchProbePlan>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SearchProbePlan {
    index_uid: String,
    query: String,
}

#[derive(Debug, Eq, PartialEq)]
pub struct SearchProbe {
    pub index_uid: String,
    pub query: String,
}

#[derive(Debug)]
pub struct UpgradeRequest {
    pub stack_name: StackName,
    pub service: ContainerName,
    pub target_image: &'static str,
    /// Execution-only secret. It must never be serialized into transaction or
    /// audit state; the request deliberately does not implement `Serialize`.
    pub master_key: String,
    pub search_probes: Vec<SearchProbe>,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    InvalidStackName,
    InvalidService,
    UnsupportedTargetImage,
    InvalidSecret,
    InvalidProbe,
    TooManyProbes,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl UpgradeRequest {
    pub fn parse(
        json: &str,
        request_id: &str,
        idempotency_key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        if plan.target_image != TARGET_IMAGE {
            return Err(RequestError::UnsupportedTargetImage);
        }
        if plan.master_key.is_empty()
            || plan.master_key.len() > MAX_SECRET_BYTES
            || plan.master_key.contains(['\n', '\r', '\0'])
        {
            return Err(RequestError::InvalidSecret);
        }
        if plan.search_probes.len() > MAX_PROBES {
            return Err(RequestError::TooManyProbes);
        }
        let search_probes = plan
            .search_probes
            .into_iter()
            .map(|probe| {
                if !valid_index_uid(&probe.index_uid)
                    || probe.query.len() > MAX_QUERY_BYTES
                    || probe.query.contains(['\0', '\r', '\n'])
                {
                    return Err(RequestError::InvalidProbe);
                }
                Ok(SearchProbe {
                    index_uid: probe.index_uid,
                    query: probe.query,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            stack_name: StackName::parse(&plan.stack_name)
                .map_err(|_| RequestError::InvalidStackName)?,
            service: ContainerName::parse(&plan.service)
                .map_err(|_| RequestError::InvalidService)?,
            target_image: TARGET_IMAGE,
            master_key: plan.master_key,
            search_probes,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: idempotency_key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }
}

fn valid_index_uid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 400
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    fn plan(target: &str, key: &str) -> String {
        format!(
            r#"{{"stackName":"wp-stack","service":"meili-1","targetImage":"{target}","masterKey":"{key}","searchProbes":[{{"indexUid":"products_en","query":"червена рокля"}}]}}"#
        )
    }

    #[test]
    fn accepts_only_the_selected_digest_pinned_target() {
        let request = UpgradeRequest::parse(&plan(TARGET_IMAGE, "secret"), ID, Some("meili-1"))
            .expect("selected target should be admitted");
        assert_eq!(request.target_image, TARGET_IMAGE);
        assert_eq!(request.stack_name.as_str(), "wp-stack");
        assert_eq!(request.service.as_str(), "meili-1");
        assert_eq!(request.search_probes[0].query, "червена рокля");

        for target in [
            "getmeili/meilisearch:v1.53.2",
            "ghcr.io/local-control-panel/meilisearch:latest",
            "ghcr.io/local-control-panel/meilisearch:1.53.2",
        ] {
            assert_eq!(
                UpgradeRequest::parse(&plan(target, "secret"), ID, None).unwrap_err(),
                RequestError::UnsupportedTargetImage
            );
        }
    }

    #[test]
    fn rejects_secrets_or_probes_that_are_unsafe_to_execute() {
        assert_eq!(
            UpgradeRequest::parse(&plan(TARGET_IMAGE, "line\nbreak"), ID, None).unwrap_err(),
            RequestError::InvalidJson
        );
        let invalid_probe = plan(TARGET_IMAGE, "secret").replace("products_en", "../index");
        assert_eq!(
            UpgradeRequest::parse(&invalid_probe, ID, None).unwrap_err(),
            RequestError::InvalidProbe
        );
    }

    #[test]
    fn unknown_fields_and_unpinned_targets_fail_closed() {
        let unknown = plan(TARGET_IMAGE, "secret").replace(
            "\"masterKey\":\"secret\"",
            "\"masterKey\":\"secret\",\"ignoreFailure\":true",
        );
        assert_eq!(
            UpgradeRequest::parse(&unknown, ID, None).unwrap_err(),
            RequestError::InvalidJson
        );
    }
}
