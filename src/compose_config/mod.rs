//! The `compose.activateConfig` operation: replacing one Docker Compose
//! stack's `docker-compose.yml` atomically, with the new content validated
//! (`docker compose config`) before it can reach the live path and the
//! previous content restored (and the stack reloaded via `docker compose up
//! -d`) if the post-write reload rejects it.
//!
//! Sibling to `crate::runtime_config` in shape (a per-identifier
//! subdirectory of one trusted root, service/target varies per request) but
//! for `website-control-panel`'s `docker.rs::compose_write` instead of a
//! Caddyfile fragment: `<compose_root>/<stackName>/docker-compose.yml` on
//! the host, where `compose_root` (unlike every other trusted root in this
//! engine) is resolved dynamically via `crate::compose::compose_root_dir`
//! rather than sourced from `EngineConfig` - it is inherently relative to
//! whichever account this process runs as (`website-control-panel`'s
//! `COMPOSE_DIR = "~/compose"`), not a fixed absolute path an operator
//! configures, so no `EngineConfig` schema change was needed for this
//! operation. No park/unpark, no `Backup`-style inert-file target - every
//! activation is the one validate/write/rename/reload/restore-on-failure
//! sequence, mirroring `runtime_config::activate`'s shape with the
//! validate/reload subprocess swapped for `docker compose config`/`docker
//! compose up -d` against the stack's own file instead of a `docker compose
//! exec` into an already-running sibling container.

pub mod activate;
pub mod execute;

use serde::{Deserialize, Serialize};

use crate::{
    ingress::{ConfigHash, HashGuard, MAX_CONTENT_BYTES},
    site::{SiteRelativePath, StackName},
    transaction::{IdempotencyKey, RequestId},
};

/// The stable protocol operation name, and the value recorded as
/// `TransactionState::operation` for every activation attempt.
pub const OPERATION: &str = "compose.activateConfig";

/// A validated `compose.activateConfig` request.
#[derive(Debug, Eq, PartialEq)]
pub struct ComposeActivateConfigRequest {
    /// Which stack's `docker-compose.yml` is being replaced. Selects both
    /// the file `docker compose -f <path> ...` operates on and the
    /// `<stackName>/` subdirectory of `compose_root` it lives under.
    pub stack_name: StackName,
    /// The complete new contents of the compose file. Whole-file
    /// replacement, not a patch.
    pub content: String,
    pub guard: HashGuard,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComposeActivateConfigRequestError {
    InvalidStackName,
    /// The submitted content exceeds `MAX_CONTENT_BYTES`.
    ContentTooLarge,
    InvalidExpectedHash,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl ComposeActivateConfigRequest {
    pub fn parse(
        stack_name: &str,
        content: impl Into<String>,
        guard: HashGuard,
        request_id: &str,
        idempotency_key: Option<&str>,
    ) -> Result<Self, ComposeActivateConfigRequestError> {
        let content = content.into();
        if content.len() > MAX_CONTENT_BYTES {
            return Err(ComposeActivateConfigRequestError::ContentTooLarge);
        }
        Ok(Self {
            stack_name: StackName::parse(stack_name)
                .map_err(|_| ComposeActivateConfigRequestError::InvalidStackName)?,
            content,
            guard,
            request_id: RequestId::parse(request_id)
                .map_err(|_| ComposeActivateConfigRequestError::InvalidRequestId)?,
            idempotency_key: idempotency_key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| ComposeActivateConfigRequestError::InvalidIdempotencyKey)?,
        })
    }

    /// Parses the wire form of `guard`: identical semantics to
    /// `ingress::ActivateConfigRequest::guard_from_expected_hash` - omitting
    /// the hash asserts absence, not "skip the check".
    pub fn guard_from_expected_hash(
        expected: Option<&str>,
    ) -> Result<HashGuard, ComposeActivateConfigRequestError> {
        match expected {
            None => Ok(HashGuard::Absent),
            Some(value) => ConfigHash::parse(value)
                .map(HashGuard::Sha256)
                .map_err(|_| ComposeActivateConfigRequestError::InvalidExpectedHash),
        }
    }
}

/// The `result` payload of a successful `compose.activateConfig` response.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComposeActivateConfigResult {
    pub stack_name: String,
    /// `false` when the file already contained exactly the submitted
    /// content, so nothing was written - the reload still runs regardless,
    /// same reasoning as `ingress::activate::activate`'s doc comment.
    pub activated: bool,
    pub content_sha256: ConfigHash,
    pub activated_at_unix_secs: u64,
}

/// The path one stack's compose file lives at, relative to `compose_root`:
/// `<stack_name>/docker-compose.yml`.
pub fn route_path(stack_name: &StackName) -> SiteRelativePath {
    SiteRelativePath::parse(format!("{stack_name}/docker-compose.yml"))
        .expect("a validated StackName always yields a valid relative path")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        ComposeActivateConfigRequest, ComposeActivateConfigRequestError,
        ComposeActivateConfigResult, route_path,
    };
    use crate::ingress::{ConfigHash, HashGuard, MAX_CONTENT_BYTES};
    use crate::site::StackName;

    const REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    #[test]
    fn request_parses_all_valid_fields() {
        let guard = ComposeActivateConfigRequest::guard_from_expected_hash(Some(
            ConfigHash::of(b"prior").as_str(),
        ))
        .expect("a well-formed digest should parse");
        let request = ComposeActivateConfigRequest::parse(
            "wp-stack",
            "services:\n  app:\n    image: nginx\n",
            guard,
            REQUEST_ID,
            Some("compose-edit-1"),
        )
        .expect("request should parse");

        assert_eq!(request.stack_name.as_str(), "wp-stack");
        assert_eq!(request.content, "services:\n  app:\n    image: nginx\n");
        assert_eq!(request.guard, HashGuard::Sha256(ConfigHash::of(b"prior")));
        assert_eq!(request.request_id.to_string(), REQUEST_ID);
        assert_eq!(
            request.idempotency_key.map(|key| key.as_str().to_owned()),
            Some("compose-edit-1".to_owned())
        );
    }

    #[test]
    fn request_reports_which_field_failed() {
        let cases = [
            (
                ComposeActivateConfigRequest::parse("", "", HashGuard::Absent, REQUEST_ID, None),
                ComposeActivateConfigRequestError::InvalidStackName,
            ),
            (
                ComposeActivateConfigRequest::parse(
                    "wp-stack",
                    "x".repeat(MAX_CONTENT_BYTES + 1),
                    HashGuard::Absent,
                    REQUEST_ID,
                    None,
                ),
                ComposeActivateConfigRequestError::ContentTooLarge,
            ),
            (
                ComposeActivateConfigRequest::parse(
                    "wp-stack",
                    "",
                    HashGuard::Absent,
                    "not-a-uuid",
                    None,
                ),
                ComposeActivateConfigRequestError::InvalidRequestId,
            ),
            (
                ComposeActivateConfigRequest::parse(
                    "wp-stack",
                    "",
                    HashGuard::Absent,
                    REQUEST_ID,
                    Some("has space"),
                ),
                ComposeActivateConfigRequestError::InvalidIdempotencyKey,
            ),
        ];
        for (outcome, expected) in cases {
            assert_eq!(outcome.unwrap_err(), expected);
        }

        assert_eq!(
            ComposeActivateConfigRequest::guard_from_expected_hash(Some("nope")).unwrap_err(),
            ComposeActivateConfigRequestError::InvalidExpectedHash
        );
        assert_eq!(
            ComposeActivateConfigRequest::guard_from_expected_hash(None)
                .expect("an omitted hash is a claim, not an opt-out"),
            HashGuard::Absent
        );
    }

    #[test]
    fn content_exactly_at_the_bound_is_accepted() {
        let request = ComposeActivateConfigRequest::parse(
            "wp-stack",
            "x".repeat(MAX_CONTENT_BYTES),
            HashGuard::Absent,
            REQUEST_ID,
            None,
        )
        .expect("content at exactly the bound should be accepted");
        assert_eq!(request.content.len(), MAX_CONTENT_BYTES);
    }

    #[test]
    fn route_path_nests_the_compose_file_under_the_stack_name() {
        let stack_name = StackName::parse("wp-stack").expect("stack name should parse");
        assert_eq!(
            route_path(&stack_name).as_path().to_str(),
            Some("wp-stack/docker-compose.yml")
        );
    }

    #[test]
    fn result_serializes_with_safe_camel_case_fields() {
        let result = ComposeActivateConfigResult {
            stack_name: "wp-stack".to_owned(),
            activated: true,
            content_sha256: ConfigHash::of(b""),
            activated_at_unix_secs: 1_700_000_000,
        };

        let value = serde_json::to_value(&result).expect("result should serialize");
        assert_eq!(
            value,
            json!({
                "stackName": "wp-stack",
                "activated": true,
                "contentSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "activatedAtUnixSecs": 1_700_000_000_u64,
            })
        );
    }
}
