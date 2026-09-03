//! The `ingress.activateConfig` operation (Phase 8 pilot): replacing one
//! domain's ingress route file atomically, with the new content validated
//! before it can reach the live path and the previous content restored if
//! the live reload rejects it.
//!
//! This is a port of `website-control-panel`'s
//! `activate_caddyfile`/`activate_caddyfile_checked`
//! (`src-tauri/src/commands/runtime_pool.rs:834-1038`) — the write path
//! behind ~28 of that codebase's site-config mutations. The *behavior* is
//! ported; the mechanism is not. Every step there is one `sudo`/`docker`
//! shell string sent over SSH; here the filesystem steps go through
//! `ManagedRoot` (capability-scoped under `EngineConfig::ingress_root`) and
//! the container steps go through `compose::exec`'s argv-only
//! `docker compose exec`.
//!
//! Module shape follows `src/deploy/` rather than `src/engine/`: this is a
//! request-driven mutation over managed content, not engine self-update.
//! `activate.rs` is the activation sequence itself (the analogue of
//! `deploy::activate`), `execute.rs` the same preflight/commit/audit
//! pipeline `deploy::execute` assembles around it.

pub mod activate;
pub mod execute;

#[cfg(all(test, unix))]
mod fake_docker;

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    site::{Domain, SiteRelativePath},
    transaction::{IdempotencyKey, RequestId},
};

/// The stable protocol operation name, and the value recorded as
/// `TransactionState::operation` for every activation attempt.
pub const OPERATION: &str = "ingress.activateConfig";

/// The Compose service running the shared ingress Caddy. Mirrors
/// `website-control-panel`'s `INGRESS_CONTAINER`
/// (`src-tauri/src/commands/runtime_pool.rs:39`) verbatim — a compiled-in
/// constant there and here, never configurable at runtime.
pub const INGRESS_SERVICE: &str = "ingress";

/// The ingress container's own top-level Caddyfile, which `import`s
/// `/etc/wcp/ingress.d/*.caddyfile`. This is what a reload reloads —
/// mirrors `runtime_pool.rs`'s `reload` verbatim.
pub const LIVE_CONFIG_PATH: &str = "/etc/caddy/Caddyfile";

/// The extension every live ingress route file carries. Load-bearing, not
/// cosmetic: the container's Caddyfile imports exactly
/// `/etc/wcp/ingress.d/*.caddyfile` (`images/frankenphp/Caddyfile.ingress`),
/// so this suffix is what makes a file live — and its absence is what keeps
/// the `.tmp` and `.rollback-*` siblings this operation creates invisible to
/// the running server.
pub const ROUTE_EXTENSION: &str = "caddyfile";

/// Upper bound on a submitted route file, so a single request cannot ask
/// this root-privileged process to write an unbounded amount into
/// `ingress_root`. Real route files are a few hundred bytes; the largest
/// thing `website-control-panel` ever generates (every policy block
/// enabled at once) is comfortably under a kilobyte.
pub const MAX_CONTENT_BYTES: usize = 256 * 1024;

/// A SHA-256 digest of a route file's exact bytes, in lowercase hex — the
/// same value `website-control-panel`'s `hash_of`
/// (`runtime_pool.rs:817`) computes and passes as `expected_prior_hash`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConfigHash(String);

/// A caller-supplied expected-prior-hash that is not 64 hex digits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidConfigHash;

impl ConfigHash {
    /// The digest of `bytes`, as this engine will report it.
    pub fn of(bytes: &[u8]) -> Self {
        use std::fmt::Write as _;

        Self(
            Sha256::digest(bytes)
                .iter()
                .fold(String::with_capacity(64), |mut hex, byte| {
                    let _ = write!(hex, "{byte:02x}");
                    hex
                }),
        )
    }

    /// A caller-supplied digest. Accepts either case on input and
    /// normalizes to lowercase, so a client that renders its hashes in
    /// uppercase is not silently told its file changed.
    pub fn parse(value: &str) -> Result<Self, InvalidConfigHash> {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(InvalidConfigHash);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ConfigHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// The optimistic-concurrency precondition an activation is allowed to
/// proceed under.
///
/// Every activation carries one. There is deliberately no "skip the
/// check" variant: the plan makes the hash guard part of this operation's
/// contract, not an option, so the two variants below are the only two
/// states a request can be in — either the caller believes there is no
/// live file yet, or it read one and is telling us what it read.
///
/// `website-control-panel` reaches the same two states through two
/// different functions plus one overloaded `Option<&str>`:
/// `activate_caddyfile_checked(.., None)` means "must not currently
/// exist" (its own doc comment), while the ~27 call sites on unchecked
/// `activate_caddyfile` mean "no precondition at all" by calling
/// something else entirely. Naming the states removes that ambiguity, and
/// dropping the unchecked one removes the silent-overwrite default with
/// it — nothing this pilot's caller does needs it (`disable_basic_auth`
/// always has a prior file it just read, so it always has a real hash to
/// send). A future caller that genuinely wants "overwrite regardless"
/// should have to add that path back deliberately.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HashGuard {
    /// The route file must not currently exist — a first activation for
    /// this domain, refusing to silently overwrite one that appeared in
    /// the meantime.
    Absent,
    /// The route file must currently exist and hash to exactly this
    /// value: what the caller read moments ago, unchanged since.
    Sha256(ConfigHash),
}

impl HashGuard {
    /// Checks this precondition against the route file's current contents
    /// (`None` when it does not exist).
    pub fn is_satisfied_by(&self, current: Option<&[u8]>) -> bool {
        match (self, current) {
            (Self::Absent, current) => current.is_none(),
            (Self::Sha256(expected), Some(bytes)) => &ConfigHash::of(bytes) == expected,
            (Self::Sha256(_), None) => false,
        }
    }
}

/// A validated `ingress.activateConfig` request.
#[derive(Debug, Eq, PartialEq)]
pub struct ActivateConfigRequest {
    /// The domain whose route file is being replaced. The engine derives
    /// the file name from it (`<domain>.caddyfile`) rather than accepting
    /// a path, so no request can name a file under `ingress_root` that
    /// isn't a live route for a domain it also named.
    pub domain: Domain,
    /// The complete new contents of that file. Whole-file replacement,
    /// not a patch: the caller reads the current file, transforms it, and
    /// submits the result, exactly as every `activate_caddyfile` call site
    /// does today.
    pub content: String,
    pub guard: HashGuard,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivateConfigRequestError {
    InvalidDomain,
    /// The submitted content exceeds `MAX_CONTENT_BYTES`.
    ContentTooLarge,
    InvalidExpectedHash,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl ActivateConfigRequest {
    pub fn parse(
        domain: &str,
        content: impl Into<String>,
        guard: HashGuard,
        request_id: &str,
        idempotency_key: Option<&str>,
    ) -> Result<Self, ActivateConfigRequestError> {
        let content = content.into();
        if content.len() > MAX_CONTENT_BYTES {
            return Err(ActivateConfigRequestError::ContentTooLarge);
        }
        Ok(Self {
            domain: Domain::parse(domain).map_err(|_| ActivateConfigRequestError::InvalidDomain)?,
            content,
            guard,
            request_id: RequestId::parse(request_id)
                .map_err(|_| ActivateConfigRequestError::InvalidRequestId)?,
            idempotency_key: idempotency_key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| ActivateConfigRequestError::InvalidIdempotencyKey)?,
        })
    }

    /// Parses the wire form of `guard`: a caller supplies either the hash
    /// it read or nothing.
    ///
    /// Omitting the hash means `Absent` — "there is no live file for this
    /// domain yet" — and *not* "activate regardless of what is there". A
    /// caller that omits it while a live file does exist gets a hash
    /// mismatch, which is the point: the omission is a claim about the
    /// current state, and a wrong claim has to fail closed. Nothing a
    /// client can send reaches an unguarded activation, because no such
    /// state exists (see `HashGuard`).
    ///
    /// Separate from `parse` so a caller that already holds a `HashGuard`
    /// is not forced through a string round-trip.
    pub fn guard_from_expected_hash(
        expected: Option<&str>,
    ) -> Result<HashGuard, ActivateConfigRequestError> {
        match expected {
            None => Ok(HashGuard::Absent),
            Some(value) => ConfigHash::parse(value)
                .map(HashGuard::Sha256)
                .map_err(|_| ActivateConfigRequestError::InvalidExpectedHash),
        }
    }
}

/// The `result` payload of a successful `ingress.activateConfig` response.
/// Every field is either an identifier the request already supplied or a
/// digest of content the request itself carried — nothing here can hold
/// subprocess output, a path, or a secret.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivateConfigResult {
    pub domain: String,
    /// `false` when the route file already contained exactly the submitted
    /// content, so nothing was written and no reload was needed. See
    /// `activate::activate`'s doc comment for why that case short-circuits.
    pub activated: bool,
    /// The digest of what the route file now contains — the value to pass
    /// back as the next request's expected prior hash.
    pub content_sha256: ConfigHash,
    pub activated_at_unix_secs: u64,
}

/// The route file one domain's live configuration lives in, relative to
/// `ingress_root`.
pub fn route_path(domain: &Domain) -> SiteRelativePath {
    SiteRelativePath::parse(format!("{domain}.{ROUTE_EXTENSION}"))
        .expect("a validated Domain always yields a single valid path component")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        ActivateConfigRequest, ActivateConfigRequestError, ActivateConfigResult, ConfigHash,
        HashGuard, MAX_CONTENT_BYTES, route_path,
    };
    use crate::site::Domain;

    const REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    #[test]
    fn config_hash_matches_the_known_sha256_of_its_input() {
        // The same value `sha256sum` (and `website-control-panel`'s
        // `hash_of`) produces for the empty input, so this pins the
        // interoperable encoding, not just self-consistency.
        assert_eq!(
            ConfigHash::of(b"").as_str(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_ne!(ConfigHash::of(b"a"), ConfigHash::of(b"b"));
    }

    #[test]
    fn config_hash_parses_either_case_and_rejects_non_digests() {
        let upper = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
        assert_eq!(
            ConfigHash::parse(upper).expect("uppercase hex should parse"),
            ConfigHash::of(b"")
        );
        assert!(ConfigHash::parse("abc123").is_err());
        assert!(ConfigHash::parse(&"g".repeat(64)).is_err());
    }

    #[test]
    fn absent_guard_accepts_only_a_missing_file() {
        assert!(HashGuard::Absent.is_satisfied_by(None));
        assert!(!HashGuard::Absent.is_satisfied_by(Some(b"")));
        assert!(!HashGuard::Absent.is_satisfied_by(Some(b"existing")));
    }

    #[test]
    fn sha256_guard_accepts_only_the_exact_current_contents() {
        let guard = HashGuard::Sha256(ConfigHash::of(b"current"));
        assert!(guard.is_satisfied_by(Some(b"current")));
        assert!(!guard.is_satisfied_by(Some(b"changed")));
        // A hash guard is never satisfied by a missing file: that is the
        // `Absent` precondition, and the two must not be interchangeable.
        assert!(!guard.is_satisfied_by(None));
    }

    #[test]
    fn request_parses_all_valid_fields() {
        let guard = ActivateConfigRequest::guard_from_expected_hash(Some(
            ConfigHash::of(b"prior").as_str(),
        ))
        .expect("a well-formed digest should parse");
        let request = ActivateConfigRequest::parse(
            "example.com",
            "example.com {\n}\n",
            guard,
            REQUEST_ID,
            Some("basic-auth-off-1"),
        )
        .expect("request should parse");

        assert_eq!(request.domain.as_str(), "example.com");
        assert_eq!(request.content, "example.com {\n}\n");
        assert_eq!(request.guard, HashGuard::Sha256(ConfigHash::of(b"prior")));
        assert_eq!(request.request_id.to_string(), REQUEST_ID);
        assert_eq!(
            request.idempotency_key.map(|key| key.as_str().to_owned()),
            Some("basic-auth-off-1".to_owned())
        );
    }

    #[test]
    fn request_reports_which_field_failed() {
        let cases = [
            (
                ActivateConfigRequest::parse(
                    "NOT A DOMAIN",
                    "",
                    HashGuard::Absent,
                    REQUEST_ID,
                    None,
                ),
                ActivateConfigRequestError::InvalidDomain,
            ),
            (
                ActivateConfigRequest::parse(
                    "example.com",
                    "x".repeat(MAX_CONTENT_BYTES + 1),
                    HashGuard::Absent,
                    REQUEST_ID,
                    None,
                ),
                ActivateConfigRequestError::ContentTooLarge,
            ),
            (
                ActivateConfigRequest::parse(
                    "example.com",
                    "",
                    HashGuard::Absent,
                    "not-a-uuid",
                    None,
                ),
                ActivateConfigRequestError::InvalidRequestId,
            ),
            (
                ActivateConfigRequest::parse(
                    "example.com",
                    "",
                    HashGuard::Absent,
                    REQUEST_ID,
                    Some("has space"),
                ),
                ActivateConfigRequestError::InvalidIdempotencyKey,
            ),
        ];
        for (outcome, expected) in cases {
            assert_eq!(outcome.unwrap_err(), expected);
        }

        assert_eq!(
            ActivateConfigRequest::guard_from_expected_hash(Some("nope")).unwrap_err(),
            ActivateConfigRequestError::InvalidExpectedHash
        );
        assert_eq!(
            ActivateConfigRequest::guard_from_expected_hash(None)
                .expect("an omitted hash is a claim, not an opt-out"),
            HashGuard::Absent
        );
    }

    /// The wire form has exactly two reachable states, and neither of
    /// them is "activate regardless of what is there". Omitting the hash
    /// is a claim that no live file exists, which `HashGuard::Absent`
    /// makes the engine verify rather than assume.
    #[test]
    fn omitting_the_expected_hash_asserts_absence_rather_than_skipping_the_check() {
        let guard = ActivateConfigRequest::guard_from_expected_hash(None)
            .expect("an omitted hash should parse");

        assert_eq!(guard, HashGuard::Absent);
        assert!(guard.is_satisfied_by(None));
        assert!(
            !guard.is_satisfied_by(Some(b"a live route file")),
            "omitting the hash must not authorize overwriting an existing file"
        );
    }

    #[test]
    fn content_exactly_at_the_bound_is_accepted() {
        let request = ActivateConfigRequest::parse(
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
    fn route_path_is_the_domains_live_caddyfile() {
        let domain = Domain::parse("sub.example.com").expect("domain should parse");
        assert_eq!(
            route_path(&domain).as_path().to_str(),
            Some("sub.example.com.caddyfile")
        );
    }

    #[test]
    fn result_serializes_with_safe_camel_case_fields() {
        let result = ActivateConfigResult {
            domain: "example.com".to_owned(),
            activated: true,
            content_sha256: ConfigHash::of(b""),
            activated_at_unix_secs: 1_700_000_000,
        };

        let value = serde_json::to_value(&result).expect("result should serialize");
        assert_eq!(
            value,
            json!({
                "domain": "example.com",
                "activated": true,
                "contentSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "activatedAtUnixSecs": 1_700_000_000_u64,
            })
        );
    }
}
