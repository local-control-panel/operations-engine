pub mod audit;
pub mod commit;
pub mod idempotency;
pub mod lock;
pub mod state;

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Identifies one mutation attempt. Used as the transaction state filename
/// component (`transactions/<requestId>.json`), so it must be a canonical
/// UUID and nothing else.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestId(Uuid);

impl RequestId {
    pub fn parse(value: &str) -> Result<Self, IdentifierError> {
        let uuid = Uuid::parse_str(value).map_err(|_| IdentifierError::InvalidRequestId)?;
        if uuid.is_nil() || value != uuid.hyphenated().to_string() {
            return Err(IdentifierError::InvalidRequestId);
        }
        Ok(Self(uuid))
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.hyphenated().fmt(formatter)
    }
}

impl FromStr for RequestId {
    type Err = IdentifierError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Opaque, caller-supplied token that lets a retried request return the
/// original outcome instead of starting duplicate work. Bounded and
/// restricted to printable ASCII so it is always safe to log and store.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    pub const MAX_LEN: usize = 128;

    pub fn parse(value: &str) -> Result<Self, IdentifierError> {
        if value.is_empty()
            || value.len() > Self::MAX_LEN
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(IdentifierError::InvalidIdempotencyKey);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for IdempotencyKey {
    type Err = IdentifierError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentifierError {
    InvalidRequestId,
    InvalidIdempotencyKey,
}

#[cfg(test)]
mod tests {
    use super::{IdempotencyKey, IdentifierError, RequestId};

    #[test]
    fn request_id_requires_canonical_lowercase_nonnil_uuid() {
        let id = RequestId::parse("550e8400-e29b-41d4-a716-446655440000")
            .expect("canonical UUID should be accepted");
        assert_eq!(id.to_string(), "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(
            RequestId::parse("550E8400-E29B-41D4-A716-446655440000").unwrap_err(),
            IdentifierError::InvalidRequestId
        );
        assert_eq!(
            RequestId::parse("550e8400e29b41d4a716446655440000").unwrap_err(),
            IdentifierError::InvalidRequestId
        );
        assert_eq!(
            RequestId::parse("00000000-0000-0000-0000-000000000000").unwrap_err(),
            IdentifierError::InvalidRequestId
        );
        assert_eq!(
            RequestId::parse("not-a-uuid").unwrap_err(),
            IdentifierError::InvalidRequestId
        );
    }

    #[test]
    fn idempotency_key_accepts_bounded_printable_ascii() {
        let key = IdempotencyKey::parse("deploy-2026-09-02-01").expect("token should be valid");
        assert_eq!(key.as_str(), "deploy-2026-09-02-01");
        assert!(IdempotencyKey::parse(&"a".repeat(IdempotencyKey::MAX_LEN)).is_ok());
    }

    #[test]
    fn idempotency_key_rejects_empty_oversized_and_unsafe_bytes() {
        assert_eq!(
            IdempotencyKey::parse("").unwrap_err(),
            IdentifierError::InvalidIdempotencyKey
        );
        assert_eq!(
            IdempotencyKey::parse(&"a".repeat(IdempotencyKey::MAX_LEN + 1)).unwrap_err(),
            IdentifierError::InvalidIdempotencyKey
        );
        assert_eq!(
            IdempotencyKey::parse("has space").unwrap_err(),
            IdentifierError::InvalidIdempotencyKey
        );
        assert_eq!(
            IdempotencyKey::parse("line\nbreak").unwrap_err(),
            IdentifierError::InvalidIdempotencyKey
        );
        assert_eq!(
            IdempotencyKey::parse("null\0byte").unwrap_err(),
            IdentifierError::InvalidIdempotencyKey
        );
        assert_eq!(
            IdempotencyKey::parse("caf\u{e9}").unwrap_err(),
            IdentifierError::InvalidIdempotencyKey
        );
    }
}
