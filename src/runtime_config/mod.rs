//! The `runtime.activateConfig` operation: replacing one site's
//! runtime-service Caddyfile fragment atomically, with the new content
//! validated before it can reach the live path and the previous content
//! restored if the live reload rejects it.
//!
//! Sibling to `crate::ingress` (`ingress.activateConfig`'s operation for the
//! shared ingress route), but for the *other* directory `activate_caddyfile`
//! writes: `website-control-panel`'s `RUNTIME_CONTAINER_CONFIG_DIR`
//! (`/etc/wcp/runtime.d` inside a `runtime-<id>` container, backed by
//! `/etc/wcp/runtimes/<id>` on the host) — a per-site exec-config fragment
//! for whichever runtime pool a site is currently assigned to, not the
//! shared ingress Caddy. Structurally out of scope for `ingress`'s
//! `EngineConfig::ingress_root`, which only ever covers the ingress route
//! directory, hence a second trusted root (`EngineConfig::runtime_root`)
//! and a second operation rather than a `target` variant on the existing
//! one: unlike `ingress.activateConfig`'s `RouteTarget::Live`/`Backup`
//! split (two different files under the *same* root), a runtime config
//! write's target container genuinely varies per request (whichever
//! `runtime_id` the caller names), not a fixed choice between two known
//! files.
//!
//! No park/unpark equivalent, and no `Backup`-style inert-file target:
//! every activation here is `ingress::activate::activate_live`'s shape —
//! validate inside the container, atomic rename, reload, restore-and-
//! reload-again on failure — since a runtime-service Caddyfile fragment has
//! no maintenance-mode concept of its own (that lives entirely at the
//! ingress layer).

pub mod activate;
pub mod execute;

use serde::{Deserialize, Serialize};

use crate::{
    ingress::{ConfigHash, HashGuard},
    site::{Domain, RuntimeId, SiteRelativePath},
    transaction::{IdempotencyKey, RequestId},
};

/// The stable protocol operation name, and the value recorded as
/// `TransactionState::operation` for every activation attempt.
pub const OPERATION: &str = "runtime.activateConfig";

/// Upper bound on a submitted config fragment. Reuses `ingress`'s bound
/// rather than defining a fresh one: a runtime-service Caddyfile fragment
/// (one site's `reverse_proxy`/worker block) is the same order of size as
/// an ingress route file, and a second number here would just be a second
/// thing to keep in sync with no behavioral difference.
pub use crate::ingress::MAX_CONTENT_BYTES;

/// A validated `runtime.activateConfig` request.
#[derive(Debug, Eq, PartialEq)]
pub struct RuntimeActivateConfigRequest {
    /// Which runtime pool's Caddyfile fragment is being replaced. Selects
    /// both the `runtime-<id>` Compose service the write validates/reloads
    /// against and the `<id>/` subdirectory of `runtime_root` it lives
    /// under.
    pub runtime_id: RuntimeId,
    /// The site whose fragment this is. The engine derives the file name
    /// from it (`<domain>.caddyfile`) rather than accepting a path, exactly
    /// as `ingress::ActivateConfigRequest` does for the ingress route.
    pub domain: Domain,
    /// The complete new contents of that fragment. Whole-file replacement,
    /// not a patch — the caller reads the current file, transforms it, and
    /// submits the result.
    pub content: String,
    pub guard: HashGuard,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeActivateConfigRequestError {
    InvalidRuntimeId,
    InvalidDomain,
    /// The submitted content exceeds `MAX_CONTENT_BYTES`.
    ContentTooLarge,
    InvalidExpectedHash,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl RuntimeActivateConfigRequest {
    pub fn parse(
        runtime_id: &str,
        domain: &str,
        content: impl Into<String>,
        guard: HashGuard,
        request_id: &str,
        idempotency_key: Option<&str>,
    ) -> Result<Self, RuntimeActivateConfigRequestError> {
        let content = content.into();
        if content.len() > MAX_CONTENT_BYTES {
            return Err(RuntimeActivateConfigRequestError::ContentTooLarge);
        }
        Ok(Self {
            runtime_id: RuntimeId::parse(runtime_id)
                .map_err(|_| RuntimeActivateConfigRequestError::InvalidRuntimeId)?,
            domain: Domain::parse(domain)
                .map_err(|_| RuntimeActivateConfigRequestError::InvalidDomain)?,
            content,
            guard,
            request_id: RequestId::parse(request_id)
                .map_err(|_| RuntimeActivateConfigRequestError::InvalidRequestId)?,
            idempotency_key: idempotency_key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RuntimeActivateConfigRequestError::InvalidIdempotencyKey)?,
        })
    }

    /// Parses the wire form of `guard`: a caller supplies either the hash
    /// it read or nothing. Identical semantics to
    /// `ingress::ActivateConfigRequest::guard_from_expected_hash` — see its
    /// doc comment; omitting the hash asserts absence, not "skip the
    /// check".
    pub fn guard_from_expected_hash(
        expected: Option<&str>,
    ) -> Result<HashGuard, RuntimeActivateConfigRequestError> {
        match expected {
            None => Ok(HashGuard::Absent),
            Some(value) => ConfigHash::parse(value)
                .map(HashGuard::Sha256)
                .map_err(|_| RuntimeActivateConfigRequestError::InvalidExpectedHash),
        }
    }
}

/// The `result` payload of a successful `runtime.activateConfig` response.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeActivateConfigResult {
    pub runtime_id: String,
    pub domain: String,
    /// `false` when the fragment already contained exactly the submitted
    /// content, so nothing was written and no reload was needed — see
    /// `ingress::activate::activate`'s doc comment for why the reload still
    /// runs in that case (the same reasoning applies verbatim here).
    pub activated: bool,
    pub content_sha256: ConfigHash,
    pub activated_at_unix_secs: u64,
}

/// The path one site's runtime-service Caddyfile fragment lives at,
/// relative to `runtime_root`: `<runtime_id>/<domain>.caddyfile`.
pub fn route_path(runtime_id: &RuntimeId, domain: &Domain) -> SiteRelativePath {
    SiteRelativePath::parse(format!("{runtime_id}/{domain}.caddyfile"))
        .expect("a validated RuntimeId and Domain always yield a valid relative path")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        MAX_CONTENT_BYTES, RuntimeActivateConfigRequest, RuntimeActivateConfigRequestError,
        RuntimeActivateConfigResult, route_path,
    };
    use crate::ingress::{ConfigHash, HashGuard};
    use crate::site::{Domain, RuntimeId};

    const REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    #[test]
    fn request_parses_all_valid_fields() {
        let guard = RuntimeActivateConfigRequest::guard_from_expected_hash(Some(
            ConfigHash::of(b"prior").as_str(),
        ))
        .expect("a well-formed digest should parse");
        let request = RuntimeActivateConfigRequest::parse(
            "fp1-php83",
            "example.com",
            "example.com {\n}\n",
            guard,
            REQUEST_ID,
            Some("runtime-cutover-1"),
        )
        .expect("request should parse");

        assert_eq!(request.runtime_id.as_str(), "fp1-php83");
        assert_eq!(request.domain.as_str(), "example.com");
        assert_eq!(request.content, "example.com {\n}\n");
        assert_eq!(request.guard, HashGuard::Sha256(ConfigHash::of(b"prior")));
        assert_eq!(request.request_id.to_string(), REQUEST_ID);
        assert_eq!(
            request.idempotency_key.map(|key| key.as_str().to_owned()),
            Some("runtime-cutover-1".to_owned())
        );
    }

    #[test]
    fn request_reports_which_field_failed() {
        let cases = [
            (
                RuntimeActivateConfigRequest::parse(
                    "NOT A RUNTIME ID",
                    "example.com",
                    "",
                    HashGuard::Absent,
                    REQUEST_ID,
                    None,
                ),
                RuntimeActivateConfigRequestError::InvalidRuntimeId,
            ),
            (
                RuntimeActivateConfigRequest::parse(
                    "fp1-php83",
                    "NOT A DOMAIN",
                    "",
                    HashGuard::Absent,
                    REQUEST_ID,
                    None,
                ),
                RuntimeActivateConfigRequestError::InvalidDomain,
            ),
            (
                RuntimeActivateConfigRequest::parse(
                    "fp1-php83",
                    "example.com",
                    "x".repeat(MAX_CONTENT_BYTES + 1),
                    HashGuard::Absent,
                    REQUEST_ID,
                    None,
                ),
                RuntimeActivateConfigRequestError::ContentTooLarge,
            ),
            (
                RuntimeActivateConfigRequest::parse(
                    "fp1-php83",
                    "example.com",
                    "",
                    HashGuard::Absent,
                    "not-a-uuid",
                    None,
                ),
                RuntimeActivateConfigRequestError::InvalidRequestId,
            ),
            (
                RuntimeActivateConfigRequest::parse(
                    "fp1-php83",
                    "example.com",
                    "",
                    HashGuard::Absent,
                    REQUEST_ID,
                    Some("has space"),
                ),
                RuntimeActivateConfigRequestError::InvalidIdempotencyKey,
            ),
        ];
        for (outcome, expected) in cases {
            assert_eq!(outcome.unwrap_err(), expected);
        }

        assert_eq!(
            RuntimeActivateConfigRequest::guard_from_expected_hash(Some("nope")).unwrap_err(),
            RuntimeActivateConfigRequestError::InvalidExpectedHash
        );
        assert_eq!(
            RuntimeActivateConfigRequest::guard_from_expected_hash(None)
                .expect("an omitted hash is a claim, not an opt-out"),
            HashGuard::Absent
        );
    }

    #[test]
    fn content_exactly_at_the_bound_is_accepted() {
        let request = RuntimeActivateConfigRequest::parse(
            "fp1-php83",
            "example.com",
            "x".repeat(MAX_CONTENT_BYTES),
            HashGuard::Absent,
            REQUEST_ID,
            None,
        )
        .expect("content at exactly the bound should be accepted");
        assert_eq!(request.content.len(), MAX_CONTENT_BYTES);
    }

    #[test]
    fn route_path_nests_the_domain_fragment_under_the_runtime_id() {
        let runtime_id = RuntimeId::parse("fp1-php83").expect("runtime id should parse");
        let domain = Domain::parse("sub.example.com").expect("domain should parse");
        assert_eq!(
            route_path(&runtime_id, &domain).as_path().to_str(),
            Some("fp1-php83/sub.example.com.caddyfile")
        );
    }

    #[test]
    fn result_serializes_with_safe_camel_case_fields() {
        let result = RuntimeActivateConfigResult {
            runtime_id: "fp1-php83".to_owned(),
            domain: "example.com".to_owned(),
            activated: true,
            content_sha256: ConfigHash::of(b""),
            activated_at_unix_secs: 1_700_000_000,
        };

        let value = serde_json::to_value(&result).expect("result should serialize");
        assert_eq!(
            value,
            json!({
                "runtimeId": "fp1-php83",
                "domain": "example.com",
                "activated": true,
                "contentSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "activatedAtUnixSecs": 1_700_000_000_u64,
            })
        );
    }
}
