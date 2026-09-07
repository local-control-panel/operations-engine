//! The `cron.installTab` operation: atomically replaces the engine's own
//! host user's crontab, hash-guarded against a caller-supplied prior
//! digest. Host-wide, not site-scoped - unlike every other mutation this
//! engine runs, there is no `SiteId`/`Domain` to key this to, since a
//! crontab is one resource per host user, not one per site.
//!
//! Simpler than `ingress`/`runtime_config`: no `TrustedRoot`-managed file
//! the engine itself serves to a container, no validate/reload cycle -
//! `crontab` parses and installs the whole submission atomically itself,
//! so there is no partial-apply state to roll back.

pub mod execute;

use crate::{
    ingress::{ConfigHash, HashGuard},
    transaction::{IdempotencyKey, RequestId},
};

pub const OPERATION: &str = "cron.installTab";

/// Same bound `ingress`/`runtime_config` use for a config fragment - a
/// crontab is a handful of lines, comfortably under this.
pub const MAX_CONTENT_BYTES: usize = 256 * 1024;

#[derive(Debug, Eq, PartialEq)]
pub struct InstallTabRequest {
    pub content: String,
    pub guard: HashGuard,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallTabRequestError {
    ContentTooLarge,
    InvalidExpectedHash,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl InstallTabRequest {
    pub fn parse(
        content: impl Into<String>,
        guard: HashGuard,
        request_id: &str,
        idempotency_key: Option<&str>,
    ) -> Result<Self, InstallTabRequestError> {
        let content = content.into();
        if content.len() > MAX_CONTENT_BYTES {
            return Err(InstallTabRequestError::ContentTooLarge);
        }
        Ok(Self {
            content,
            guard,
            request_id: RequestId::parse(request_id)
                .map_err(|_| InstallTabRequestError::InvalidRequestId)?,
            idempotency_key: idempotency_key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| InstallTabRequestError::InvalidIdempotencyKey)?,
        })
    }

    /// See `ingress::ActivateConfigRequest::guard_from_expected_hash` - the
    /// identical rule applies here: omitting the hash asserts "no crontab
    /// exists yet" (`Absent`), not "skip the check".
    pub fn guard_from_expected_hash(
        expected: Option<&str>,
    ) -> Result<HashGuard, InstallTabRequestError> {
        match expected {
            None => Ok(HashGuard::Absent),
            Some(value) => ConfigHash::parse(value)
                .map(HashGuard::Sha256)
                .map_err(|_| InstallTabRequestError::InvalidExpectedHash),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallTabResult {
    pub activated: bool,
    pub content_sha256: ConfigHash,
    pub activated_at_unix_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::{InstallTabRequest, InstallTabRequestError, MAX_CONTENT_BYTES};
    use crate::ingress::{ConfigHash, HashGuard};

    const REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    #[test]
    fn request_parses_all_valid_fields() {
        let guard =
            InstallTabRequest::guard_from_expected_hash(Some(ConfigHash::of(b"prior").as_str()))
                .expect("a well-formed digest should parse");
        let request = InstallTabRequest::parse("* * * * * true\n", guard, REQUEST_ID, Some("k1"))
            .expect("request should parse");
        assert_eq!(request.content, "* * * * * true\n");
        assert_eq!(request.guard, HashGuard::Sha256(ConfigHash::of(b"prior")));
    }

    #[test]
    fn omitting_the_expected_hash_asserts_absence() {
        let guard = InstallTabRequest::guard_from_expected_hash(None)
            .expect("an omitted hash should parse");
        assert_eq!(guard, HashGuard::Absent);
    }

    #[test]
    fn oversized_content_is_rejected() {
        let err = InstallTabRequest::parse(
            "x".repeat(MAX_CONTENT_BYTES + 1),
            HashGuard::Absent,
            REQUEST_ID,
            None,
        )
        .unwrap_err();
        assert_eq!(err, InstallTabRequestError::ContentTooLarge);
    }

    #[test]
    fn invalid_hash_is_rejected() {
        assert_eq!(
            InstallTabRequest::guard_from_expected_hash(Some("nope")).unwrap_err(),
            InstallTabRequestError::InvalidExpectedHash
        );
    }
}
