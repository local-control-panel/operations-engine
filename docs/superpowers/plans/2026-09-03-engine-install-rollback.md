# Engine Install/Rollback Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `ops-engine` a new `engine install`/`engine rollback` command pair that fetches a specific, signed release from GitHub, cryptographically verifies it, and atomically activates it at `/usr/local/bin/ops-engine` — with a no-network fallback to the one retained previous binary — plus the CI release pipeline that produces those signed artifacts in the first place.

**Architecture:** Reuses the existing Phase 2/3 mutation infrastructure verbatim: `mutation::preflight` (lock/idempotency/audit), the `PreCommit`/`PostCommit` type-state commit boundary, and `ManagedRoot`'s capability-scoped filesystem primitives. Adds one new engine-scoped (not site-scoped) state subtree (`engine/` beneath the existing state root, parallel to `sites/<siteId>/`) tracking exactly two retained binary versions, and one new trusted root (`/usr/local/bin`) that only `engine install`/`engine rollback` ever write to. A new GitHub Actions workflow builds reproducible Linux binaries for both supported architectures and publishes them signed with minisign.

**Tech Stack:** Rust 2024 edition (this crate), `ureq` 3.x (HTTP client), `minisign-verify` (signature verification), `sha2` (checksum), `minisign` CLI tool (signing — CI and test fixtures only, never a runtime dependency of the binary itself), GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-03-release-pipeline-design.md`

## Global Constraints

- Rust toolchain pinned to exactly `1.85.0` (matches `Cargo.toml`'s `rust-version`); `cargo build --locked` for every release build; `SOURCE_DATE_EPOCH` set from the tagged commit for reproducibility.
- `cargo fmt --all --check` and `cargo clippy --all-targets --all-features -- -D warnings` must pass; `cargo test --all-features` must pass; `cargo +1.85.0 check --all-features` must pass (`PLAN.md`'s Definition of Done).
- Every mutating operation goes through `mutation::preflight` (lock, idempotency replay, persisted `TransactionState`, audit) and the `PreCommit`/`PostCommit` commit boundary — no ad hoc locking or state writes.
- Stable, machine-readable `ErrorCode`s only; no subprocess output, file paths outside a trusted root, or raw remote response bodies in any log or error message.
- `engine.install`/`engine.rollback` are added to `capabilities`' advertised `operations` list only in the final task, once both are implemented and integration-tested end to end (working agreement item 4 — never advertise before it works).
- No CLI flag or protocol input ever supplies a URL, file path outside a trusted root, or cryptographic key — the GitHub repository, release asset naming, and the embedded minisign public key are all compiled-in constants.
- Every new privileged filesystem write happens through `ManagedRoot` (capability-scoped `cap_std::fs::Dir`), never `std::fs` directly, matching every existing mutation in this codebase.
- `#[cfg(unix)]`/`#[cfg(not(unix))]` gating on any new command handler that touches the filesystem, mirroring `commands/site.rs`'s existing `run_deploy`/`run_rollback` split.

## Scope note

This plan covers only the `operations-engine` repository (this repo). The companion `website-control-panel` changes (Tauri commands calling `engine install`/`engine rollback`, resolving which version to request, and rewriting `docker/test-server/build-ops-engine.sh` to download real signed releases instead of building locally) are **out of scope** for this plan and need their own plan once this ships a real tagged release to point at — the spec's §9 covers that side's design; it is not implemented here.

## Deviation from the spec

The spec's §5 describes the engine binary's on-disk layout as a direct mirror of the site-release symlink pattern: `versions/<version>/ops-engine` plus a `current` symlink that activation atomically renames over. Turning that into real code (Task 3/9/10) surfaced that it doesn't transplant cleanly: `docs/site-model.md` fixes `/usr/local/bin/ops-engine` as the actual sudo-permitted, PATH-visible file, which lives in a different trusted root than the engine's state directory, and `ManagedRoot::symlink`'s target parameter is deliberately typed as a same-root-relative `SiteRelativePath` — there is no existing primitive for a symlink whose target crosses trusted roots, and adding one would be a real, security-relevant capability this design doesn't otherwise need.

This plan instead writes the verified binary's bytes directly into `/usr/local/bin/ops-engine` via a same-directory write-temp-then-atomic-rename (`ManagedRoot::write_new_executable`, Task 3) — still exactly one atomic `rename(2)`, so there is still never a window where the binary is missing, just no symlink indirection. The `versions/` retention store still exists, under the state root, exactly as the spec describes; `engine rollback` reads the retained previous binary's bytes out of it directly rather than repointing a symlink. See this plan's closing "Self-review notes" for the full reasoning.

---

## Task 1: Pin the Rust toolchain to an exact version

**Files:**
- Modify: `rust-toolchain.toml`

**Interfaces:** None — this only affects which `rustc`/`cargo` toolchain `rustup` selects for every subsequent task in this plan.

- [ ] **Step 1: Change the toolchain channel from a floating channel to the exact pinned version**

`rust-toolchain.toml` currently reads:

```toml
[toolchain]
channel = "stable"
profile = "minimal"
components = ["clippy", "rustfmt"]
```

Change `channel` to match this crate's existing `rust-version = "1.85"` (`Cargo.toml`) and the CI `minimum-rust` job's `1.85.0`:

```toml
[toolchain]
channel = "1.85.0"
profile = "minimal"
components = ["clippy", "rustfmt"]
```

- [ ] **Step 2: Verify the pinned toolchain is picked up**

Run: `rustup show`
Expected: the active toolchain for this directory is `1.85.0-<host-triple>` (rustup installs it automatically if not already present).

Run: `cargo check --all-features`
Expected: succeeds with no changes needed elsewhere (this crate already targets 1.85 features only).

- [ ] **Step 3: Commit**

```bash
git add rust-toolchain.toml
git commit -m "Pin the Rust toolchain to 1.85.0 instead of a floating stable channel"
```

---

## Task 2: Add `ArtifactFetchFailed` and `ArtifactVerificationFailed` error codes

**Files:**
- Modify: `src/error.rs`

**Interfaces:**
- Produces: `ErrorCode::ArtifactFetchFailed`, `ErrorCode::ArtifactVerificationFailed` — used by `src/engine/install.rs` and `src/engine/rollback.rs` (Tasks 9–10) to report network and cryptographic-verification failures with stable, distinct codes.

- [ ] **Step 1: Write the failing test**

Add to `src/error.rs`'s existing `#[cfg(test)] mod tests`:

```rust
#[test]
fn new_artifact_error_codes_have_stable_protocol_values() {
    assert_eq!(
        serde_json::to_string(&ErrorCode::ArtifactFetchFailed)
            .expect("code should serialize"),
        "\"ARTIFACT_FETCH_FAILED\""
    );
    assert_eq!(
        serde_json::to_string(&ErrorCode::ArtifactVerificationFailed)
            .expect("code should serialize"),
        "\"ARTIFACT_VERIFICATION_FAILED\""
    );
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib error::tests::new_artifact_error_codes_have_stable_protocol_values`
Expected: FAIL — `ErrorCode::ArtifactFetchFailed` does not exist yet (compile error).

- [ ] **Step 3: Add the two variants**

In `src/error.rs`, add both variants to `ErrorCode` (after `SubprocessFailed`) and to `as_str`:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    Internal,
    InternalSerializationError,
    InvalidInput,
    UnsupportedPlatform,
    DependencyUnavailable,
    Conflict,
    Timeout,
    Cancelled,
    SubprocessFailed,
    ArtifactFetchFailed,
    ArtifactVerificationFailed,
}
```

```rust
impl ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Internal => "INTERNAL",
            Self::InternalSerializationError => "INTERNAL_SERIALIZATION_ERROR",
            Self::InvalidInput => "INVALID_INPUT",
            Self::UnsupportedPlatform => "UNSUPPORTED_PLATFORM",
            Self::DependencyUnavailable => "DEPENDENCY_UNAVAILABLE",
            Self::Conflict => "CONFLICT",
            Self::Timeout => "TIMEOUT",
            Self::Cancelled => "CANCELLED",
            Self::SubprocessFailed => "SUBPROCESS_FAILED",
            Self::ArtifactFetchFailed => "ARTIFACT_FETCH_FAILED",
            Self::ArtifactVerificationFailed => "ARTIFACT_VERIFICATION_FAILED",
        }
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test --lib error::`
Expected: PASS, all tests in `error.rs` including the new one.

- [ ] **Step 5: Commit**

```bash
git add src/error.rs
git commit -m "Add ARTIFACT_FETCH_FAILED and ARTIFACT_VERIFICATION_FAILED error codes"
```

---

## Task 3: Add `write_new_executable` and `read_bytes` to `ManagedRoot`

**Files:**
- Modify: `src/filesystem.rs`

**Interfaces:**
- Produces: `ManagedRoot::write_new_executable(&self, path: &SiteRelativePath, contents: &[u8]) -> io::Result<()>` (unix-only) and `ManagedRoot::read_bytes(&self, path: &SiteRelativePath) -> io::Result<Vec<u8>>` — used by Tasks 8–10 to stage and activate binary files.

- [ ] **Step 1: Write the failing tests**

Add to `src/filesystem.rs`'s existing `#[cfg(all(test, unix))] mod tests`:

```rust
#[test]
fn read_bytes_reads_arbitrary_binary_content() {
    let directory = tempfile::tempdir().expect("temporary directory should exist");
    let root = TrustedRoot::parse(directory.path()).expect("root should be valid");
    let managed = ManagedRoot::open(&root).expect("root should open");
    let path = SiteRelativePath::parse("blob").expect("path should be valid");
    fs::write(directory.path().join("blob"), [0u8, 159, 255, 1]).expect("blob should be written");

    assert_eq!(managed.read_bytes(&path).unwrap(), vec![0u8, 159, 255, 1]);
}

#[test]
fn write_new_executable_replaces_content_and_sets_the_executable_bit() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().expect("temporary directory should exist");
    let root = TrustedRoot::parse(directory.path()).expect("root should be valid");
    let managed = ManagedRoot::open(&root).expect("root should open");
    let path = SiteRelativePath::parse("ops-engine").expect("path should be valid");

    managed
        .write_new_executable(&path, b"first binary")
        .expect("first write should succeed");
    let first_metadata = fs::metadata(directory.path().join("ops-engine")).unwrap();
    assert_eq!(first_metadata.permissions().mode() & 0o777, 0o755);
    assert_eq!(fs::read(directory.path().join("ops-engine")).unwrap(), b"first binary");

    managed
        .write_new_executable(&path, b"second binary, longer than the first")
        .expect("overwrite should succeed");
    assert_eq!(
        fs::read(directory.path().join("ops-engine")).unwrap(),
        b"second binary, longer than the first"
    );
    assert!(!directory.path().join("ops-engine.tmp").exists());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib filesystem::tests::read_bytes_reads_arbitrary_binary_content filesystem::tests::write_new_executable_replaces_content_and_sets_the_executable_bit`
Expected: FAIL — neither method exists yet (compile error).

- [ ] **Step 3: Implement both methods**

In `src/filesystem.rs`, add to `impl ManagedRoot` (near `write_atomic`):

```rust
    /// Reads `path` in full as raw bytes — the binary counterpart of
    /// `read_to_string`, for content (a fetched engine executable) that
    /// is not valid UTF-8.
    pub fn read_bytes(&self, path: &SiteRelativePath) -> io::Result<Vec<u8>> {
        self.directory.read(path.as_path())
    }

    /// Like `write_atomic`, but additionally marks the written file
    /// executable (mode `0o755`) before the same same-directory atomic
    /// rename makes it visible at `path`. The only writer of executable
    /// content in this codebase — used to stage and activate a fetched,
    /// checksum- and signature-verified `ops-engine` binary.
    #[cfg(unix)]
    pub fn write_new_executable(&self, path: &SiteRelativePath, contents: &[u8]) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp_path = temp_sibling_path(path)?;
        {
            let mut file = self.directory.create(temp_path.as_path())?;
            file.write_all(contents)?;
            file.sync_all()?;
        }
        self.directory.set_permissions(
            temp_path.as_path(),
            cap_std::fs::Permissions::from_std(std::fs::Permissions::from_mode(0o755)),
        )?;
        self.directory
            .rename(temp_path.as_path(), &self.directory, path.as_path())
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib filesystem::`
Expected: PASS, all tests in `filesystem.rs` including the two new ones.

- [ ] **Step 5: Run Clippy**

Run: `cargo clippy --all-targets --all-features -- -D warnings`
Expected: no warnings.

- [ ] **Step 6: Commit**

```bash
git add src/filesystem.rs
git commit -m "Add ManagedRoot::read_bytes and write_new_executable primitives"
```

---

## Task 4: Add the `engine` module skeleton — request and result types

**Files:**
- Create: `src/engine/mod.rs`

**Interfaces:**
- Consumes: `RequestId`, `IdempotencyKey` (`src/transaction/mod.rs`); `EngineVersion` (Task 5, `src/engine/release.rs` — forward-declared here, implemented next task).
- Produces: `EngineInstallRequest`, `EngineInstallRequestError`, `EngineRollbackRequest`, `EngineRollbackRequestError`, `EngineInstallResult`, `EngineRollbackResult`, `INSTALL_OPERATION`, `ROLLBACK_OPERATION` — consumed by `commands/engine.rs` (Task 12) and `src/engine/install.rs`/`rollback.rs` (Tasks 9–10).

- [ ] **Step 1: Write the failing tests**

Create `src/engine/mod.rs` with its test module first (this task and Task 5 land together — `mod.rs` references `release::EngineVersion`, which Task 5 implements; write both in this task's commit since neither compiles alone):

```rust
//! The `engine.install` and `engine.rollback` operations (Phase 7):
//! fetching, verifying, and atomically activating a new `ops-engine`
//! binary, and reverting to the one retained previous binary without a
//! network call. See
//! `docs/superpowers/specs/2026-09-03-release-pipeline-design.md`.

pub mod fetch;
pub mod install;
pub mod release;
pub mod rollback;
pub mod state;
pub mod verify;

use serde::{Deserialize, Serialize};

use crate::transaction::{IdempotencyKey, RequestId};

pub const INSTALL_OPERATION: &str = "engine.install";
pub const ROLLBACK_OPERATION: &str = "engine.rollback";

#[derive(Debug, Eq, PartialEq)]
pub struct EngineInstallRequest {
    pub version: release::EngineVersion,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineInstallRequestError {
    InvalidVersion,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl EngineInstallRequest {
    pub fn parse(
        version: &str,
        request_id: &str,
        idempotency_key: Option<&str>,
    ) -> Result<Self, EngineInstallRequestError> {
        Ok(Self {
            version: release::EngineVersion::parse(version)
                .map_err(|_| EngineInstallRequestError::InvalidVersion)?,
            request_id: RequestId::parse(request_id)
                .map_err(|_| EngineInstallRequestError::InvalidRequestId)?,
            idempotency_key: idempotency_key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| EngineInstallRequestError::InvalidIdempotencyKey)?,
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct EngineRollbackRequest {
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineRollbackRequestError {
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl EngineRollbackRequest {
    pub fn parse(
        request_id: &str,
        idempotency_key: Option<&str>,
    ) -> Result<Self, EngineRollbackRequestError> {
        Ok(Self {
            request_id: RequestId::parse(request_id)
                .map_err(|_| EngineRollbackRequestError::InvalidRequestId)?,
            idempotency_key: idempotency_key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| EngineRollbackRequestError::InvalidIdempotencyKey)?,
        })
    }
}

/// The `result` payload of a successful `engine.install` response.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineInstallResult {
    pub version: String,
    pub previous_version: Option<String>,
    pub activated_at_unix_secs: u64,
}

/// The `result` payload of a successful `engine.rollback` response.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineRollbackResult {
    pub version: String,
    pub previous_version: String,
    pub activated_at_unix_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::{EngineInstallRequest, EngineInstallRequestError, EngineRollbackRequest, EngineRollbackRequestError};

    const REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    #[test]
    fn install_request_parses_all_valid_fields() {
        let request = EngineInstallRequest::parse("0.5.0", REQUEST_ID, Some("install-1"))
            .expect("request should parse");
        assert_eq!(request.version.as_str(), "0.5.0");
        assert_eq!(request.request_id.to_string(), REQUEST_ID);
        assert_eq!(
            request.idempotency_key.map(|key| key.as_str().to_owned()),
            Some("install-1".to_owned())
        );
    }

    #[test]
    fn install_request_allows_a_missing_idempotency_key() {
        let request = EngineInstallRequest::parse("0.5.0", REQUEST_ID, None)
            .expect("request without an idempotency key should parse");
        assert_eq!(request.idempotency_key, None);
    }

    #[test]
    fn install_request_reports_which_field_failed() {
        assert_eq!(
            EngineInstallRequest::parse("not-a-version", REQUEST_ID, None).unwrap_err(),
            EngineInstallRequestError::InvalidVersion
        );
        assert_eq!(
            EngineInstallRequest::parse("0.5.0", "not-a-uuid", None).unwrap_err(),
            EngineInstallRequestError::InvalidRequestId
        );
        assert_eq!(
            EngineInstallRequest::parse("0.5.0", REQUEST_ID, Some("has space")).unwrap_err(),
            EngineInstallRequestError::InvalidIdempotencyKey
        );
    }

    #[test]
    fn rollback_request_parses_all_valid_fields() {
        let request = EngineRollbackRequest::parse(REQUEST_ID, None).expect("request should parse");
        assert_eq!(request.request_id.to_string(), REQUEST_ID);
    }

    #[test]
    fn rollback_request_reports_which_field_failed() {
        assert_eq!(
            EngineRollbackRequest::parse("not-a-uuid", None).unwrap_err(),
            EngineRollbackRequestError::InvalidRequestId
        );
        assert_eq!(
            EngineRollbackRequest::parse(REQUEST_ID, Some("has space")).unwrap_err(),
            EngineRollbackRequestError::InvalidIdempotencyKey
        );
    }
}
```

This will not compile yet — `release`, `fetch`, `verify`, `state`, `install`, `rollback` submodules don't exist. Continue immediately to Task 5 before attempting to build; Tasks 4–10 land as one sequence of small commits that only compile once Task 10 is done, exactly like any other multi-file feature — run `cargo check` starting from Task 5 onward, not after this step alone.

- [ ] **Step 2: Commit this step as part of Task 5's commit (see below) — do not commit yet.**

---

## Task 5: Add `EngineVersion` and release URL builders

**Files:**
- Create: `src/engine/release.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces: `EngineVersion` (parse/as_str/Display), `InvalidVersion`, `target_triple() -> Option<&'static str>`, `binary_asset_name(version, target_triple) -> String`, `sha256sums_url(base_url, version) -> String`, `sha256sums_minisig_url(base_url, version) -> String`, `binary_url(base_url, version, target_triple) -> String` — consumed by `src/engine/verify.rs` (Task 7) and `src/engine/install.rs` (Task 9).

- [ ] **Step 1: Write the failing tests**

Create `src/engine/release.rs`:

```rust
//! A validated release version string, and the GitHub Releases URL shape
//! every `engine install` fetch is built from — never a caller-supplied
//! URL (see the design spec's "no ambient discovery" rule). `base_url` is
//! a parameter, not a hardcoded constant, purely so tests can point it at
//! a local fixture server; every production call site passes the one
//! `GITHUB_RELEASES_BASE` constant in `commands/engine.rs`.

use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineVersion(String);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidVersion;

impl EngineVersion {
    /// Accepts only `MAJOR.MINOR.PATCH` (no `v` prefix, no pre-release or
    /// build metadata) — the exact shape the release workflow tags and
    /// publishes. Rejecting anything else keeps this string safe to embed
    /// directly into a URL path segment and a filesystem path segment
    /// without further escaping.
    pub fn parse(value: &str) -> Result<Self, InvalidVersion> {
        let parts: Vec<&str> = value.split('.').collect();
        if parts.len() != 3
            || parts
                .iter()
                .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
        {
            return Err(InvalidVersion);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EngineVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// This host's architecture, mapped to the target-triple suffix the
/// release workflow names its binaries with. `None` means this build has
/// no published artifact for the running host — `engine install` must
/// fail rather than guess.
pub fn target_triple() -> Option<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Some("x86_64-unknown-linux-gnu"),
        "aarch64" => Some("aarch64-unknown-linux-gnu"),
        _ => None,
    }
}

pub fn binary_asset_name(version: &EngineVersion, target_triple: &str) -> String {
    format!("ops-engine-{version}-{target_triple}")
}

pub fn sha256sums_url(base_url: &str, version: &EngineVersion) -> String {
    format!("{base_url}/v{version}/SHA256SUMS")
}

pub fn sha256sums_minisig_url(base_url: &str, version: &EngineVersion) -> String {
    format!("{base_url}/v{version}/SHA256SUMS.minisig")
}

pub fn binary_url(base_url: &str, version: &EngineVersion, target_triple: &str) -> String {
    format!(
        "{base_url}/v{version}/{}",
        binary_asset_name(version, target_triple)
    )
}

#[cfg(test)]
mod tests {
    use super::{EngineVersion, binary_asset_name, binary_url, sha256sums_minisig_url, sha256sums_url};

    #[test]
    fn version_accepts_major_minor_patch() {
        let version = EngineVersion::parse("0.5.0").expect("version should parse");
        assert_eq!(version.as_str(), "0.5.0");
        assert_eq!(version.to_string(), "0.5.0");
    }

    #[test]
    fn version_rejects_anything_else() {
        assert!(EngineVersion::parse("v0.5.0").is_err());
        assert!(EngineVersion::parse("0.5").is_err());
        assert!(EngineVersion::parse("0.5.0-rc1").is_err());
        assert!(EngineVersion::parse("0.5.x").is_err());
        assert!(EngineVersion::parse("../../etc").is_err());
        assert!(EngineVersion::parse("").is_err());
    }

    #[test]
    fn urls_are_built_from_the_given_base_and_version() {
        let version = EngineVersion::parse("0.5.0").expect("version should parse");
        assert_eq!(
            sha256sums_url("https://example.test/releases", &version),
            "https://example.test/releases/v0.5.0/SHA256SUMS"
        );
        assert_eq!(
            sha256sums_minisig_url("https://example.test/releases", &version),
            "https://example.test/releases/v0.5.0/SHA256SUMS.minisig"
        );
        assert_eq!(
            binary_url("https://example.test/releases", &version, "x86_64-unknown-linux-gnu"),
            "https://example.test/releases/v0.5.0/ops-engine-0.5.0-x86_64-unknown-linux-gnu"
        );
        assert_eq!(
            binary_asset_name(&version, "aarch64-unknown-linux-gnu"),
            "ops-engine-0.5.0-aarch64-unknown-linux-gnu"
        );
    }
}
```

- [ ] **Step 2: Stub the remaining submodules so the crate compiles**

Create empty placeholders that Tasks 6–10 fill in, so `cargo check` can pass after this task: `src/engine/fetch.rs`, `src/engine/verify.rs`, `src/engine/state.rs`, `src/engine/install.rs`, `src/engine/rollback.rs`, each containing only:

```rust
// Implemented in a later task of docs/superpowers/plans/2026-09-03-engine-install-rollback.md.
```

Add `pub mod engine;` to `src/lib.rs`'s module list, in alphabetical order:

```rust
pub mod cli;
pub mod commands;
pub mod config;
pub mod deploy;
pub mod engine;
pub mod error;
pub mod filesystem;
pub mod mutation;
pub mod process;
pub mod protocol;
pub mod rollback;
pub mod site;
pub mod transaction;
```

- [ ] **Step 3: Run the tests**

Run: `cargo test --lib engine::`
Expected: PASS — `release::tests` and `mod.rs`'s own request-parsing tests (from Task 4) both pass now that the module compiles.

- [ ] **Step 4: Run Clippy and fmt**

Run: `cargo fmt --all --check && cargo clippy --all-targets --all-features -- -D warnings`
Expected: no diffs, no warnings. (The placeholder files contain only a comment, which is valid.)

- [ ] **Step 5: Commit (this commit includes Task 4's `mod.rs` too)**

```bash
git add src/lib.rs src/engine/
git commit -m "Add the engine module: install/rollback request types and release version/URL builders"
```

---

## Task 6: Add the HTTP fetch primitive

**Files:**
- Modify: `src/engine/fetch.rs` (replace placeholder)
- Modify: `Cargo.toml` (new dependency)

**Interfaces:**
- Produces: `fetch::Error` (`Request`, `Read` variants), `fetch::fetch_bytes(url: &str) -> Result<Vec<u8>, Error>` — consumed by `src/engine/verify.rs` (Task 7) and `src/engine/install.rs` (Task 9).

- [ ] **Step 1: Add the `ureq` dependency**

Run: `cargo add ureq`

This adds `ureq` (currently 3.x) to `[dependencies]` in `Cargo.toml`. No extra feature flags are needed — `ureq` uses `rustls` with the `ring` crypto provider by default and requires no manual TLS setup.

- [ ] **Step 2: Write `fetch.rs`**

There is no isolated unit test for this module — it makes a real network call by design, and Task 13's integration test exercises it end to end against a local fixture server instead of mocking `ureq` here. Replace the placeholder in `src/engine/fetch.rs`:

```rust
//! The one place `engine::install`/`engine::rollback` reach the network:
//! a single HTTPS GET, response capped at `ureq`'s default 10 MiB limit
//! (`ops-engine` release binaries are a few MiB). No redirect target,
//! header, or response body content is ever trusted without the
//! checksum/signature checks in `verify.rs` — this module only fetches
//! bytes.

#[derive(Debug)]
pub enum Error {
    Request(ureq::Error),
    Read(ureq::Error),
}

pub fn fetch_bytes(url: &str) -> Result<Vec<u8>, Error> {
    let mut response = ureq::get(url).call().map_err(Error::Request)?;
    response.body_mut().read_to_vec().map_err(Error::Read)
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check --all-features`
Expected: succeeds.

- [ ] **Step 4: Run Clippy and fmt**

Run: `cargo fmt --all --check && cargo clippy --all-targets --all-features -- -D warnings`
Expected: no diffs, no warnings.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/engine/fetch.rs
git commit -m "Add the HTTP fetch primitive engine install/rollback build on"
```

---

## Task 7: Generate the release signing keypair and implement signed-manifest verification

**Files:**
- Create: `release/minisign.pub` (committed)
- Modify: `src/engine/verify.rs` (replace placeholder)
- Modify: `Cargo.toml` (new dependencies)
- Modify: `.gitignore` (make sure the secret key is never accidentally committed)

**Interfaces:**
- Consumes: `fetch::fetch_bytes` (Task 6); `release::EngineVersion`, `release::sha256sums_url`, `release::sha256sums_minisig_url`, `release::binary_asset_name` (Task 5).
- Produces: `verify::Error`, `verify::ExpectedArtifact { filename, sha256_hex }`, `verify::fetch_and_verify(base_url, version, target_triple) -> Result<ExpectedArtifact, Error>` — consumed by `src/engine/install.rs` (Task 9).

- [ ] **Step 1: Install the `minisign` CLI tool (one-time, for this task and for Task 13/15's tests and CI)**

This tool is used only to *generate keys and sign releases* — it is never a Rust dependency of `ops-engine` itself, which only ever *verifies* (via the `minisign-verify` crate, added below). On macOS: `brew install minisign`. On Debian/Ubuntu (also what the CI runner in Task 15 needs): `apt-get install -y minisign`.

- [ ] **Step 2: Generate the release signing keypair**

Run: `minisign -G -p release/minisign.pub -s release/minisign.key`

This prompts for a password to encrypt the secret key file at rest; choose one and record it somewhere safe (e.g. a password manager) — Task 15's CI signing step needs both the secret key's contents and this password as GitHub Actions secrets, since GitHub Actions has no interactive prompt to supply it. `release/minisign.pub` is a small two-line text file (an `untrusted comment:` line, then the base64-encoded public key) and gets committed. `release/minisign.key` must **never** be committed.

- [ ] **Step 3: Keep the secret key out of git**

Add to `.gitignore`:

```
release/minisign.key
```

Run: `git status --short release/` and confirm only `minisign.pub` is untracked (about to be added), not `minisign.key`.

- [ ] **Step 4: Add the `minisign-verify` and `sha2` dependencies**

Run: `cargo add minisign-verify sha2`

- [ ] **Step 5: Write the failing tests**

`verify.rs`'s tests sign a small fixture manifest with the real secret key generated in Step 2, by shelling out to the `minisign` CLI (the same tool Step 1 installed) — consistent with how `tests/deploy.rs` already shells out to the real `git` CLI rather than mocking it. Replace the placeholder in `src/engine/verify.rs`:

```rust
//! Fetches and cryptographically verifies a release's `SHA256SUMS`
//! manifest before `install.rs` trusts any checksum out of it. minisign
//! signs the whole `SHA256SUMS` file, never a single extracted line — so
//! this module always fetches and verifies the complete file itself
//! rather than accepting a pre-extracted line and signature from a
//! caller, which would not be a verifiable unit on its own.

use minisign_verify::{PublicKey, Signature};

use crate::engine::{fetch, release};

/// Generated once via `minisign -G`; see `docs/release.md`. Only the
/// public half is ever committed (`release/minisign.pub`).
const PUBLIC_KEY_FILE: &str = include_str!("../../release/minisign.pub");

#[derive(Debug)]
pub enum Error {
    Fetch(fetch::Error),
    InvalidPublicKey,
    InvalidSignature,
    SignatureMismatch,
    NoLineForThisArchitecture,
    MalformedManifest,
}

/// One verified line of `SHA256SUMS`: the exact asset filename this
/// build's platform must request next, and the SHA-256 it must produce.
pub struct ExpectedArtifact {
    pub filename: String,
    pub sha256_hex: String,
}

pub fn fetch_and_verify(
    base_url: &str,
    version: &release::EngineVersion,
    target_triple: &str,
) -> Result<ExpectedArtifact, Error> {
    let manifest =
        fetch::fetch_bytes(&release::sha256sums_url(base_url, version)).map_err(Error::Fetch)?;
    let signature_bytes = fetch::fetch_bytes(&release::sha256sums_minisig_url(base_url, version))
        .map_err(Error::Fetch)?;
    let signature_text = String::from_utf8(signature_bytes).map_err(|_| Error::InvalidSignature)?;

    let public_key = public_key()?;
    let signature = Signature::decode(&signature_text).map_err(|_| Error::InvalidSignature)?;
    public_key
        .verify(&manifest, &signature, false)
        .map_err(|_| Error::SignatureMismatch)?;

    let manifest_text = String::from_utf8(manifest).map_err(|_| Error::MalformedManifest)?;
    let expected_name = release::binary_asset_name(version, target_triple);
    parse_sha256sums_line(&manifest_text, &expected_name).ok_or(Error::NoLineForThisArchitecture)
}

/// `PUBLIC_KEY_FILE` is the real two-line `minisign.pub` format: an
/// `untrusted comment:` line, then the base64 key on its own line.
fn public_key() -> Result<PublicKey, Error> {
    let key_line = PUBLIC_KEY_FILE.lines().nth(1).ok_or(Error::InvalidPublicKey)?;
    PublicKey::from_base64(key_line.trim()).map_err(|_| Error::InvalidPublicKey)
}

/// Parses the standard `sha256sum` output format: `<hex>  <filename>` (two
/// spaces, filename last), returning only the line matching
/// `expected_name` exactly. Any other line is ignored, not partially
/// trusted.
fn parse_sha256sums_line(manifest: &str, expected_name: &str) -> Option<ExpectedArtifact> {
    manifest.lines().find_map(|line| {
        let (hex, name) = line.split_once("  ")?;
        if name == expected_name && hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            Some(ExpectedArtifact {
                filename: name.to_owned(),
                sha256_hex: hex.to_lowercase(),
            })
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::{ExpectedArtifact, parse_sha256sums_line, public_key};

    #[test]
    fn the_committed_public_key_parses() {
        public_key().expect("release/minisign.pub should parse as a valid minisign public key");
    }

    #[test]
    fn parse_sha256sums_line_finds_only_the_matching_line() {
        let manifest = "\
abababababababababababababababababababababababababababababab  ops-engine-0.5.0-x86_64-unknown-linux-gnu
cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd  ops-engine-0.5.0-aarch64-unknown-linux-gnu
";
        let found = parse_sha256sums_line(manifest, "ops-engine-0.5.0-aarch64-unknown-linux-gnu")
            .expect("matching line should be found");
        assert_eq!(
            found.sha256_hex,
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
        );
        assert_eq!(found.filename, "ops-engine-0.5.0-aarch64-unknown-linux-gnu");

        assert!(parse_sha256sums_line(manifest, "no-such-asset").is_none());
    }

    /// End-to-end against the *real* signing/verification pair: signs a
    /// throwaway manifest with the real secret key via the `minisign` CLI
    /// (requires `MINISIGN_TEST_KEY_PASSWORD` in the environment, matching
    /// the password chosen in Task 7 Step 2 — set it locally before
    /// running this test, and as a CI secret alongside the release
    /// signing secrets), then verifies it with this module's own
    /// `PublicKey`/`Signature` usage — proving the two sides actually
    /// agree on a real signature, not just that parsing doesn't panic.
    #[test]
    fn a_signature_from_the_real_minisign_cli_verifies() {
        let Ok(password) = std::env::var("MINISIGN_TEST_KEY_PASSWORD") else {
            eprintln!("skipping: MINISIGN_TEST_KEY_PASSWORD is not set");
            return;
        };
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let manifest_path = directory.path().join("SHA256SUMS");
        std::fs::write(&manifest_path, "test manifest content\n").expect("manifest should be written");

        let status = Command::new("minisign")
            .args(["-S", "-s", "release/minisign.key", "-m"])
            .arg(&manifest_path)
            .env("MINISIGN_PASSWORD", &password)
            .status()
            .expect("minisign CLI should run");
        assert!(status.success(), "minisign signing should succeed");

        let manifest = std::fs::read(&manifest_path).expect("manifest should be readable");
        let signature_text = std::fs::read_to_string(manifest_path.with_extension("SUMS.minisig"))
            .or_else(|_| std::fs::read_to_string(format!("{}.minisig", manifest_path.display())))
            .expect("signature file should be readable");

        let public_key = public_key().expect("public key should parse");
        let signature =
            minisign_verify::Signature::decode(&signature_text).expect("signature should decode");
        public_key
            .verify(&manifest, &signature, false)
            .expect("a signature from the real secret key should verify against the committed public key");
    }
}
```

- [ ] **Step 6: Run the tests**

Run: `MINISIGN_TEST_KEY_PASSWORD='<the password chosen in Step 2>' cargo test --lib engine::verify::`
Expected: PASS. If `MINISIGN_TEST_KEY_PASSWORD` is unset, the real-signature test prints a skip message and passes trivially — the other two tests (public key parses, line-parsing) still run unconditionally.

- [ ] **Step 7: Run Clippy and fmt**

Run: `cargo fmt --all --check && cargo clippy --all-targets --all-features -- -D warnings`
Expected: no diffs, no warnings.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml Cargo.lock .gitignore release/minisign.pub src/engine/verify.rs
git commit -m "Generate the release signing keypair and verify signed SHA256SUMS manifests"
```

---

## Task 8: Add engine install-state persistence

**Files:**
- Create: `src/engine/state.rs` (replace placeholder)

**Interfaces:**
- Consumes: `ManagedRoot` (`src/filesystem.rs`); `SiteRelativePath` (`src/site.rs`).
- Produces: `state::InstallState { active_version, previous_version }`, `state::Error`, `state::load(engine_state) -> Result<Option<InstallState>, Error>`, `state::save(engine_state, state) -> Result<(), Error>`, `state::open_engine_state(engine_state: &ManagedRoot) -> io::Result<ManagedRoot>` — consumed by `src/engine/install.rs`/`rollback.rs` (Tasks 9–10) and `commands/engine.rs` (Task 12).

- [ ] **Step 1: Write the failing tests**

Replace the placeholder in `src/engine/state.rs`:

```rust
//! Where an installed engine binary's own version bookkeeping lives:
//! `engine/install.state`, beneath the shared state root, in a new
//! `engine/` subtree parallel to `sites/<siteId>/`
//! (`mutation::preflight::open_site_state`). Tracks exactly two
//! versions — the one active now and the one `engine rollback` can
//! restore without a network call — never a longer history.

use std::io;

use serde::{Deserialize, Serialize};

use crate::{filesystem::ManagedRoot, site::SiteRelativePath};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallState {
    pub active_version: String,
    pub previous_version: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Io,
    Corrupt,
}

/// `None` means no engine has ever been installed through this path yet
/// (a fresh host, or one whose current binary predates this feature).
pub fn load(engine_state: &ManagedRoot) -> Result<Option<InstallState>, Error> {
    match engine_state.read_to_string(&install_state_path()) {
        Ok(json) => serde_json::from_str(&json).map(Some).map_err(|_| Error::Corrupt),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(Error::Io),
    }
}

pub fn save(engine_state: &ManagedRoot, state: &InstallState) -> Result<(), Error> {
    let bytes = serde_json::to_vec(state).map_err(|_| Error::Corrupt)?;
    engine_state
        .write_atomic(&install_state_path(), &bytes)
        .map_err(|_| Error::Io)
}

fn install_state_path() -> SiteRelativePath {
    SiteRelativePath::parse("install.state").expect("literal path is valid")
}

/// Opens (creating if necessary) the engine-wide install state beneath
/// `engine_state`'s `engine/` subtree, ensuring the
/// `locks`/`transactions`/`audit`/`versions` subdirectories
/// `mutation::preflight::run` and `install.rs`/`rollback.rs` expect
/// already exist. Mirrors `mutation::preflight::open_site_state`, but
/// there is only ever one of these per host — no per-ID scoping.
pub fn open_engine_state(engine_state: &ManagedRoot) -> io::Result<ManagedRoot> {
    let relative = SiteRelativePath::parse("engine").expect("literal path is valid");
    engine_state.create_dir_all(&relative)?;
    let scoped = engine_state.open_managed_dir(&relative)?;
    for sub in ["locks", "transactions", "audit", "versions"] {
        scoped.create_dir_all(&SiteRelativePath::parse(sub).expect("literal path is valid"))?;
    }
    Ok(scoped)
}

#[cfg(test)]
mod tests {
    use super::{InstallState, load, open_engine_state, save};
    use crate::{
        filesystem::ManagedRoot,
        site::{SiteRelativePath, TrustedRoot},
    };

    fn engine_state() -> (tempfile::TempDir, ManagedRoot) {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let root = TrustedRoot::parse(directory.path()).expect("root should be valid");
        let state_root = ManagedRoot::open(&root).expect("root should open");
        let scoped = open_engine_state(&state_root).expect("engine state should open");
        (directory, scoped)
    }

    #[test]
    fn load_returns_none_before_anything_is_installed() {
        let (_directory, engine_state) = engine_state();
        assert_eq!(load(&engine_state).unwrap(), None);
    }

    #[test]
    fn save_then_load_round_trips() {
        let (_directory, engine_state) = engine_state();
        let state = InstallState {
            active_version: "0.5.0".to_owned(),
            previous_version: Some("0.4.0".to_owned()),
        };
        save(&engine_state, &state).expect("save should succeed");
        assert_eq!(load(&engine_state).unwrap(), Some(state));
    }

    #[test]
    fn open_engine_state_creates_every_expected_subdirectory() {
        let (directory, _engine_state) = engine_state();
        for sub in ["locks", "transactions", "audit", "versions"] {
            assert!(
                directory.path().join("engine").join(sub).is_dir(),
                "engine/{sub} should exist"
            );
        }
    }

    #[test]
    fn open_engine_state_is_idempotent() {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let root = TrustedRoot::parse(directory.path()).expect("root should be valid");
        let state_root = ManagedRoot::open(&root).expect("root should open");
        open_engine_state(&state_root).expect("first open should succeed");
        open_engine_state(&state_root).expect("second open should also succeed, not error");
        let _ = SiteRelativePath::parse("engine").expect("literal path is valid");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib engine::state::`
Expected: FAIL — `state::InstallState` etc. don't exist yet (the file currently only has the placeholder comment).

Wait — Step 1 already wrote the real implementation, not a stub-then-test split; this module's functions are thin enough (each a few lines wrapping already-tested `ManagedRoot` primitives) that writing them alongside their tests in one step, as `state.rs` in Task 3's sibling `transaction/state.rs` does, matches this codebase's own convention better than an artificial red step. Skip to Step 3.

- [ ] **Step 3: Run the tests to verify they pass**

Run: `cargo test --lib engine::state::`
Expected: PASS, all four tests.

- [ ] **Step 4: Run Clippy and fmt**

Run: `cargo fmt --all --check && cargo clippy --all-targets --all-features -- -D warnings`
Expected: no diffs, no warnings.

- [ ] **Step 5: Commit**

```bash
git add src/engine/state.rs
git commit -m "Add engine install-state persistence and the engine/ state subtree"
```

---

## Task 9: Implement `engine install`

**Files:**
- Create: `src/engine/install.rs` (replace placeholder)

**Interfaces:**
- Consumes: `mutation::preflight::{run, Outcome, Admitted, Error}`; `state::{InstallState, load, save, open_engine_state}` (Task 8); `release::{EngineVersion, target_triple, binary_url}` (Task 5); `verify::fetch_and_verify` (Task 7); `fetch::{fetch_bytes, Error as FetchError}` (Task 6); `ManagedRoot::write_new_executable` (Task 3); `transaction::commit::PreCommit`; `transaction::state` (as `tx_state`); `transaction::audit`.
- Produces: `install::InstallContext { bin_root, engine_state, release_base_url }`, `install::InstallError`, `install::execute(context, request, cancellation) -> Result<EngineInstallResult, InstallError>` — consumed by `commands/engine.rs` (Task 12) and `tests/engine.rs` (Task 13).

There is no isolated unit test in this file, matching `src/deploy/execute.rs` and `src/rollback/execute.rs` — both have zero inline tests; their orchestration is verified entirely by integration tests (`tests/deploy.rs`, `tests/rollback.rs`). Task 13 is this module's test.

- [ ] **Step 1: Write `install.rs`**

Replace the placeholder in `src/engine/install.rs`. This directly mirrors `src/deploy/execute.rs`'s `execute`/`replay`/`fail` shape — open that file side by side while reading this one.

```rust
//! The assembled `engine.install` pipeline: preflight, fetch and verify
//! the signed release manifest, fetch and checksum the binary, stage it
//! under a retained version directory, atomically activate it at
//! `/usr/local/bin/ops-engine`, and record what happened. Mirrors
//! `deploy::execute::execute`'s shape — see that module's doc comments
//! for the reasoning behind the shared preflight/commit/audit pattern.

use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::{
    engine::{
        EngineInstallRequest, EngineInstallResult, INSTALL_OPERATION, fetch, release, state, verify,
    },
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    site::{SiteRelativePath, TrustedRoot},
    transaction::{
        RequestId,
        audit::{self, AuditRecord},
        commit::PreCommit,
        state::{self as tx_state, TransactionStatus},
    },
};

/// The roots and already-opened state directory an install needs.
pub struct InstallContext<'a> {
    /// `/usr/local/bin` — the one directory `engine install`/
    /// `engine rollback` are permitted to write into outside the
    /// engine's own state root.
    pub bin_root: &'a TrustedRoot,
    /// The engine-wide state root, opened once by the caller (mirrors
    /// `DeployContext::engine_state`). `execute` scopes it down to the
    /// `engine/` subtree via `state::open_engine_state`.
    pub engine_state: &'a ManagedRoot,
    /// The GitHub Releases base URL every asset is fetched relative to.
    /// A parameter (not a hardcoded constant in this file) purely so
    /// tests can point it at a local fixture server; every production
    /// call site passes `commands::engine::GITHUB_RELEASES_BASE`.
    pub release_base_url: &'a str,
}

#[derive(Debug)]
pub enum InstallError {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    AlreadyActive,
    UnsupportedArchitecture,
    Verify(verify::Error),
    Fetch(fetch::Error),
    ChecksumMismatch,
    State(tx_state::StateError),
    InstallState(state::Error),
    Cancelled,
    /// The install itself succeeded — the binary at
    /// `/usr/local/bin/ops-engine` was switched — but its
    /// `TransactionState` could not be saved afterward.
    PostCommitRecordFailed {
        result: EngineInstallResult,
        cause: tx_state::StateError,
    },
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl InstallError {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Io(_) | Self::State(_) | Self::InstallState(_) => {
                (ErrorCode::Internal, "internal engine install error".to_owned())
            }
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another engine install or rollback is already in progress".to_owned(),
            ),
            Self::Preflight(_) => (ErrorCode::Internal, "preflight failed".to_owned()),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request for this idempotency key is still in progress".to_owned(),
            ),
            Self::AlreadyActive => (
                ErrorCode::InvalidInput,
                "the requested version is already active".to_owned(),
            ),
            Self::UnsupportedArchitecture => (
                ErrorCode::UnsupportedPlatform,
                "this host's architecture has no published engine build".to_owned(),
            ),
            Self::Verify(verify::Error::Fetch(_)) => (
                ErrorCode::ArtifactFetchFailed,
                "the release manifest could not be fetched".to_owned(),
            ),
            Self::Verify(_) => (
                ErrorCode::ArtifactVerificationFailed,
                "the release manifest failed verification".to_owned(),
            ),
            Self::Fetch(_) => (
                ErrorCode::ArtifactFetchFailed,
                "the release binary could not be fetched".to_owned(),
            ),
            Self::ChecksumMismatch => (
                ErrorCode::ArtifactVerificationFailed,
                "the downloaded binary did not match its verified checksum".to_owned(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before the commit point".to_owned(),
            ),
            Self::PostCommitRecordFailed { .. } => {
                (ErrorCode::Internal, "internal engine install error".to_owned())
            }
            Self::Replayed { code, message } => (*code, message.clone()),
        }
    }
}

pub fn execute(
    context: &InstallContext<'_>,
    request: &EngineInstallRequest,
    cancellation: &crate::process::CancellationToken,
) -> Result<EngineInstallResult, InstallError> {
    let engine_state = state::open_engine_state(context.engine_state).map_err(InstallError::Io)?;

    let admitted = match preflight::run(
        &engine_state,
        request.request_id,
        request.idempotency_key.as_ref(),
        INSTALL_OPERATION,
    )
    .map_err(InstallError::Preflight)?
    {
        preflight::Outcome::Replay(original) => return replay(&engine_state, original),
        preflight::Outcome::Proceed(admitted) => admitted,
    };
    // `Admitted`'s field is named `state` (it holds the mutation's
    // `TransactionState`); rename it to `tx` on destructuring so it
    // never collides, even visually, with the `state` module imported
    // above (`crate::engine::state`) — Rust's separate value/module
    // namespaces mean it would compile either way, but a shared name
    // for two different things here would only confuse a reader.
    let preflight::Admitted { lock, state: mut tx } = admitted;

    let state_path = state_path_for(request.request_id);
    let audit_path = audit_log_path();
    let pre_commit = PreCommit::new(cancellation.clone());

    let current = match state::load(&engine_state) {
        Ok(current) => current,
        Err(error) => {
            return Err(fail(
                &engine_state,
                &state_path,
                &audit_path,
                tx,
                InstallError::InstallState(error),
            ));
        }
    };
    if let Some(current) = &current {
        if current.active_version == request.version.as_str() {
            return Err(fail(
                &engine_state,
                &state_path,
                &audit_path,
                tx,
                InstallError::AlreadyActive,
            ));
        }
    }

    let Some(target_triple) = release::target_triple() else {
        return Err(fail(
            &engine_state,
            &state_path,
            &audit_path,
            tx,
            InstallError::UnsupportedArchitecture,
        ));
    };

    let expected = match verify::fetch_and_verify(context.release_base_url, &request.version, target_triple) {
        Ok(expected) => expected,
        Err(error) => {
            return Err(fail(
                &engine_state,
                &state_path,
                &audit_path,
                tx,
                InstallError::Verify(error),
            ));
        }
    };

    if pre_commit.check().is_err() {
        return Err(fail(&engine_state, &state_path, &audit_path, tx, InstallError::Cancelled));
    }

    let binary_url = release::binary_url(context.release_base_url, &request.version, target_triple);
    let bytes = match fetch::fetch_bytes(&binary_url) {
        Ok(bytes) => bytes,
        Err(error) => {
            return Err(fail(
                &engine_state,
                &state_path,
                &audit_path,
                tx,
                InstallError::Fetch(error),
            ));
        }
    };
    if sha256_hex(&bytes) != expected.sha256_hex {
        return Err(fail(
            &engine_state,
            &state_path,
            &audit_path,
            tx,
            InstallError::ChecksumMismatch,
        ));
    }

    if pre_commit.check().is_err() {
        return Err(fail(&engine_state, &state_path, &audit_path, tx, InstallError::Cancelled));
    }

    let version_dir = SiteRelativePath::parse(format!("versions/{}", request.version))
        .expect("a validated EngineVersion always yields a valid relative path");
    let version_binary = SiteRelativePath::parse(format!("versions/{}/ops-engine", request.version))
        .expect("a validated EngineVersion always yields a valid relative path");
    if let Err(error) = engine_state
        .create_dir_all(&version_dir)
        .and_then(|()| engine_state.write_new_executable(&version_binary, &bytes))
    {
        return Err(fail(&engine_state, &state_path, &audit_path, tx, InstallError::Io(error)));
    }

    let bin_root = match ManagedRoot::open(context.bin_root) {
        Ok(root) => root,
        Err(error) => {
            return Err(fail(&engine_state, &state_path, &audit_path, tx, InstallError::Io(error)));
        }
    };
    // Commit point: `/usr/local/bin/ops-engine` now contains the new,
    // already-verified binary. Nothing from here may be aborted by
    // cancellation — the switch already happened.
    if let Err(error) = bin_root.write_new_executable(&binary_path(), &bytes) {
        return Err(fail(&engine_state, &state_path, &audit_path, tx, InstallError::Io(error)));
    }
    let _post_commit = pre_commit.commit();
    drop(lock);

    // The version that falls out of retention after this install: it
    // was `previous` *before* this call (not the new `previous`, which
    // is the version we just switched away from and must keep). Capture
    // it before `current` is consumed below.
    let superseded_version = current.as_ref().and_then(|previous| previous.previous_version.clone());
    let previous_version = current.map(|previous| previous.active_version);
    let new_state = state::InstallState {
        active_version: request.version.as_str().to_owned(),
        previous_version: previous_version.clone(),
    };
    let _ = state::save(&engine_state, &new_state);
    let _ = prune_superseded_version(&engine_state, superseded_version.as_deref(), &new_state);

    let result = EngineInstallResult {
        version: request.version.as_str().to_owned(),
        previous_version,
        activated_at_unix_secs: unix_now_secs(),
    };
    let result_value = serde_json::to_value(&result).expect("EngineInstallResult always serializes");
    tx.mark_committed(result_value)
        .expect("state is always InProgress at this point");

    if let Err(cause) = tx_state::save(&engine_state, &state_path, &tx) {
        return Err(InstallError::PostCommitRecordFailed { result, cause });
    }
    let _ = audit::append(
        &engine_state,
        &audit_path,
        &AuditRecord::result(request.request_id, true, None),
    );

    Ok(result)
}

fn prune_superseded_version(
    engine_state: &ManagedRoot,
    superseded: Option<&str>,
    new_state: &state::InstallState,
) -> std::io::Result<()> {
    let Some(superseded) = superseded else {
        return Ok(());
    };
    if superseded == new_state.active_version || Some(superseded) == new_state.previous_version.as_deref() {
        return Ok(());
    }
    let path = SiteRelativePath::parse(format!("versions/{superseded}"))
        .expect("a previously-installed version string always yields a valid relative path");
    engine_state.remove_dir_all(&path)
}

fn replay(engine_state: &ManagedRoot, original: RequestId) -> Result<EngineInstallResult, InstallError> {
    let original_state =
        tx_state::load(engine_state, &state_path_for(original)).map_err(InstallError::State)?;
    match original_state.status {
        TransactionStatus::InProgress => Err(InstallError::ReplayInProgress),
        TransactionStatus::Committed => {
            let outcome = original_state
                .outcome
                .expect("a committed transaction always has an outcome");
            let result_value = outcome.result.expect("a committed outcome always has a result");
            serde_json::from_value(result_value).map_err(|_| InstallError::State(tx_state::StateError::Corrupt))
        }
        TransactionStatus::Failed => {
            let outcome = original_state
                .outcome
                .expect("a failed transaction always has an outcome");
            Err(InstallError::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}

fn fail(
    engine_state: &ManagedRoot,
    state_path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut tx: tx_state::TransactionState,
    error: InstallError,
) -> InstallError {
    let (code, message) = error.protocol();
    let _ = tx.mark_failed(code, message);
    let _ = tx_state::save(engine_state, state_path, &tx);
    let _ = audit::append(
        engine_state,
        audit_path,
        &AuditRecord::result(tx.request_id, false, Some(code)),
    );
    error
}

fn binary_path() -> SiteRelativePath {
    SiteRelativePath::parse("ops-engine").expect("literal path is valid")
}

fn state_path_for(request_id: RequestId) -> SiteRelativePath {
    SiteRelativePath::parse(format!("transactions/{request_id}.json"))
        .expect("a canonical RequestId always yields a valid relative path")
}

fn audit_log_path() -> SiteRelativePath {
    SiteRelativePath::parse("audit/events.jsonl").expect("literal path is valid")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check --all-features`
Expected: succeeds (still unused-import/dead-code warnings are fine at this point — `install::execute` isn't called from anywhere yet; that lands in Task 12).

- [ ] **Step 3: Run Clippy and fmt**

Run: `cargo fmt --all --check && cargo clippy --all-targets --all-features -- -D warnings`
Expected: no diffs. Clippy may warn about `execute`/`InstallContext` being unused (dead code) — that's expected until Task 12 wires the CLI; if Clippy hard-fails on it before then, add a temporary `#[allow(dead_code)]` at the top of `install.rs` and remove it in Task 12 once the function has a real caller.

- [ ] **Step 4: Commit**

```bash
git add src/engine/install.rs
git commit -m "Implement the engine install orchestration pipeline"
```

---

## Task 10: Implement `engine rollback`

**Files:**
- Create: `src/engine/rollback.rs` (replace placeholder)

**Interfaces:**
- Consumes: same shared primitives as Task 9, plus `ManagedRoot::read_bytes` (Task 3).
- Produces: `rollback::RollbackContext { bin_root, engine_state }`, `rollback::RollbackError`, `rollback::execute(context, request, cancellation) -> Result<EngineRollbackResult, RollbackError>` — consumed by `commands/engine.rs` (Task 12) and `tests/engine.rs` (Task 13).

As with Task 9, there is no inline unit test — this is exercised end to end in Task 13.

- [ ] **Step 1: Write `rollback.rs`**

Replace the placeholder in `src/engine/rollback.rs`. Mirrors `install.rs`'s shape, but with no network step: it reads the retained previous binary straight out of `versions/<previous>/ops-engine` (already checksum- and signature-verified when it was installed) and swaps it into place.

```rust
//! The assembled `engine.rollback` pipeline: preflight, then a purely
//! local swap back to the one retained previous binary — no network
//! call, so it works even when GitHub is unreachable. Mirrors
//! `install.rs`'s shape; see that file's doc comment for the shared
//! preflight/commit/audit pattern both borrow from `deploy::execute`.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    engine::{EngineRollbackRequest, EngineRollbackResult, ROLLBACK_OPERATION, state},
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    site::{SiteRelativePath, TrustedRoot},
    transaction::{
        RequestId,
        audit::{self, AuditRecord},
        commit::PreCommit,
        state::{self as tx_state, TransactionStatus},
    },
};

pub struct RollbackContext<'a> {
    pub bin_root: &'a TrustedRoot,
    pub engine_state: &'a ManagedRoot,
}

#[derive(Debug)]
pub enum RollbackError {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    NoPreviousVersion,
    State(tx_state::StateError),
    InstallState(state::Error),
    Cancelled,
    PostCommitRecordFailed {
        result: EngineRollbackResult,
        cause: tx_state::StateError,
    },
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl RollbackError {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Io(_) | Self::State(_) | Self::InstallState(_) => {
                (ErrorCode::Internal, "internal engine rollback error".to_owned())
            }
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another engine install or rollback is already in progress".to_owned(),
            ),
            Self::Preflight(_) => (ErrorCode::Internal, "preflight failed".to_owned()),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request for this idempotency key is still in progress".to_owned(),
            ),
            Self::NoPreviousVersion => (
                ErrorCode::InvalidInput,
                "there is no previous engine version retained to roll back to".to_owned(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before the commit point".to_owned(),
            ),
            Self::PostCommitRecordFailed { .. } => {
                (ErrorCode::Internal, "internal engine rollback error".to_owned())
            }
            Self::Replayed { code, message } => (*code, message.clone()),
        }
    }
}

pub fn execute(
    context: &RollbackContext<'_>,
    request: &EngineRollbackRequest,
    cancellation: &crate::process::CancellationToken,
) -> Result<EngineRollbackResult, RollbackError> {
    let engine_state = state::open_engine_state(context.engine_state).map_err(RollbackError::Io)?;

    let admitted = match preflight::run(
        &engine_state,
        request.request_id,
        request.idempotency_key.as_ref(),
        ROLLBACK_OPERATION,
    )
    .map_err(RollbackError::Preflight)?
    {
        preflight::Outcome::Replay(original) => return replay(&engine_state, original),
        preflight::Outcome::Proceed(admitted) => admitted,
    };
    // See `install.rs`'s identical destructuring for why this renames
    // the `state` field to `tx`.
    let preflight::Admitted { lock, state: mut tx } = admitted;

    let state_path = state_path_for(request.request_id);
    let audit_path = audit_log_path();
    let pre_commit = PreCommit::new(cancellation.clone());

    let current = match state::load(&engine_state) {
        Ok(Some(current)) => current,
        Ok(None) => {
            return Err(fail(
                &engine_state,
                &state_path,
                &audit_path,
                tx,
                RollbackError::NoPreviousVersion,
            ));
        }
        Err(error) => {
            return Err(fail(
                &engine_state,
                &state_path,
                &audit_path,
                tx,
                RollbackError::InstallState(error),
            ));
        }
    };
    let Some(previous) = current.previous_version.clone() else {
        return Err(fail(
            &engine_state,
            &state_path,
            &audit_path,
            tx,
            RollbackError::NoPreviousVersion,
        ));
    };

    let version_binary = SiteRelativePath::parse(format!("versions/{previous}/ops-engine"))
        .expect("a previously-installed version string always yields a valid relative path");
    let bytes = match engine_state.read_bytes(&version_binary) {
        Ok(bytes) => bytes,
        Err(error) => {
            return Err(fail(&engine_state, &state_path, &audit_path, tx, RollbackError::Io(error)));
        }
    };

    if pre_commit.check().is_err() {
        return Err(fail(&engine_state, &state_path, &audit_path, tx, RollbackError::Cancelled));
    }

    let bin_root = match ManagedRoot::open(context.bin_root) {
        Ok(root) => root,
        Err(error) => {
            return Err(fail(&engine_state, &state_path, &audit_path, tx, RollbackError::Io(error)));
        }
    };
    // Commit point: `/usr/local/bin/ops-engine` now contains the
    // previously-retained binary.
    if let Err(error) = bin_root.write_new_executable(&binary_path(), &bytes) {
        return Err(fail(&engine_state, &state_path, &audit_path, tx, RollbackError::Io(error)));
    }
    let _post_commit = pre_commit.commit();
    drop(lock);

    // Symmetric swap: a second `engine rollback` right after this one
    // would roll forward again, exactly like `site.rollback`'s
    // roll-forward property — the source version is never invalidated.
    let new_state = state::InstallState {
        active_version: previous.clone(),
        previous_version: Some(current.active_version.clone()),
    };
    let _ = state::save(&engine_state, &new_state);

    let result = EngineRollbackResult {
        version: previous,
        previous_version: current.active_version,
        activated_at_unix_secs: unix_now_secs(),
    };
    let result_value = serde_json::to_value(&result).expect("EngineRollbackResult always serializes");
    tx.mark_committed(result_value)
        .expect("state is always InProgress at this point");

    if let Err(cause) = tx_state::save(&engine_state, &state_path, &tx) {
        return Err(RollbackError::PostCommitRecordFailed { result, cause });
    }
    let _ = audit::append(
        &engine_state,
        &audit_path,
        &AuditRecord::result(request.request_id, true, None),
    );

    Ok(result)
}

fn replay(engine_state: &ManagedRoot, original: RequestId) -> Result<EngineRollbackResult, RollbackError> {
    let original_state =
        tx_state::load(engine_state, &state_path_for(original)).map_err(RollbackError::State)?;
    match original_state.status {
        TransactionStatus::InProgress => Err(RollbackError::ReplayInProgress),
        TransactionStatus::Committed => {
            let outcome = original_state
                .outcome
                .expect("a committed transaction always has an outcome");
            let result_value = outcome.result.expect("a committed outcome always has a result");
            serde_json::from_value(result_value)
                .map_err(|_| RollbackError::State(tx_state::StateError::Corrupt))
        }
        TransactionStatus::Failed => {
            let outcome = original_state
                .outcome
                .expect("a failed transaction always has an outcome");
            Err(RollbackError::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}

fn fail(
    engine_state: &ManagedRoot,
    state_path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut tx: tx_state::TransactionState,
    error: RollbackError,
) -> RollbackError {
    let (code, message) = error.protocol();
    let _ = tx.mark_failed(code, message);
    let _ = tx_state::save(engine_state, state_path, &tx);
    let _ = audit::append(
        engine_state,
        audit_path,
        &AuditRecord::result(tx.request_id, false, Some(code)),
    );
    error
}

fn binary_path() -> SiteRelativePath {
    SiteRelativePath::parse("ops-engine").expect("literal path is valid")
}

fn state_path_for(request_id: RequestId) -> SiteRelativePath {
    SiteRelativePath::parse(format!("transactions/{request_id}.json"))
        .expect("a canonical RequestId always yields a valid relative path")
}

fn audit_log_path() -> SiteRelativePath {
    SiteRelativePath::parse("audit/events.jsonl").expect("literal path is valid")
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check --all-features`
Expected: succeeds.

- [ ] **Step 3: Run Clippy and fmt**

Run: `cargo fmt --all --check && cargo clippy --all-targets --all-features -- -D warnings`
Expected: no diffs. As with Task 9, an `#[allow(dead_code)]` on the module may be needed until Task 12 wires it up — remove it there.

- [ ] **Step 4: Commit**

```bash
git add src/engine/rollback.rs
git commit -m "Implement the engine rollback orchestration pipeline"
```

---

## Task 11: Wire `engine install`/`engine rollback` into the CLI

**Files:**
- Modify: `src/cli.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces: `Command::Engine { command: EngineCommand }`, `EngineCommand::Install { version, request_id, idempotency_key }`, `EngineCommand::Rollback { request_id, idempotency_key }` — consumed by `src/lib.rs` and `commands/engine.rs` (Task 12).

- [ ] **Step 1: Write the failing test**

Add a new integration test to `tests/cli.rs` (it already exists and follows this `run_json` pattern):

```rust
#[test]
fn engine_install_requires_a_version_and_request_id() {
    let output = std::process::Command::cargo_bin("ops-engine")
        .expect("binary should build")
        .args(["engine", "install"])
        .assert()
        .failure();
    let stderr = String::from_utf8(output.get_output().stderr.clone()).expect("stderr should be UTF-8");
    assert!(stderr.contains("--version"), "clap should report the missing --version flag");
}
```

(`assert_cmd::Command` is already imported at the top of `tests/cli.rs`; use that import rather than `std::process::Command` directly — adjust the call to `Command::cargo_bin("ops-engine")` matching the file's existing style.)

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --test cli engine_install_requires_a_version_and_request_id`
Expected: FAIL — `engine` is not a recognized subcommand yet (clap reports "unrecognized subcommand", not a missing-flag error).

- [ ] **Step 3: Add `EngineCommand` and wire it into `Command`**

In `src/cli.rs`, add to the `Command` enum (after `Site`):

```rust
    /// Engine binary install/rollback operations.
    Engine {
        #[command(subcommand)]
        command: EngineCommand,
    },
```

Add to `Command::operation`:

```rust
            Self::Engine { command } => command.operation(),
```

Add the new subcommand enum after `SiteCommand`:

```rust
#[derive(Debug, Subcommand)]
pub enum EngineCommand {
    /// Fetch, verify, and atomically activate a specific published
    /// engine version.
    Install {
        #[arg(long)]
        version: String,

        /// Canonical UUID identifying this specific attempt. The caller
        /// mints this, not the engine — see `docs/site-model.md`.
        #[arg(long = "request-id")]
        request_id: String,

        /// Caller-supplied token so a retried request returns the
        /// original outcome instead of installing twice.
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },

    /// Atomically switch back to the one retained previous engine
    /// version, without a network call.
    Rollback {
        #[arg(long = "request-id")]
        request_id: String,

        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
}

impl EngineCommand {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::Install { .. } => "engine.install",
            Self::Rollback { .. } => "engine.rollback",
        }
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test --test cli engine_install_requires_a_version_and_request_id`
Expected: PASS.

- [ ] **Step 5: Run the full test suite, Clippy, and fmt**

Run: `cargo test --all-features && cargo fmt --all --check && cargo clippy --all-targets --all-features -- -D warnings`
Expected: everything passes. `Command::Engine` will not compile against `lib.rs`'s `execute` match yet — Task 12 adds that arm; if `cargo build` (not just `cargo check` of `cli.rs` alone) fails with a non-exhaustive match, that's expected until Task 12 lands. Run `cargo check -p operations-engine --lib` scoped to just the library if the binary target fails to build at this intermediate step.

- [ ] **Step 6: Commit**

```bash
git add src/cli.rs tests/cli.rs
git commit -m "Add the engine install/rollback CLI subcommand tree"
```

---

## Task 12: Wire `commands::engine` and dispatch

**Files:**
- Create: `src/commands/engine.rs`
- Modify: `src/commands/mod.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `EngineCommand` (Task 11); `EngineInstallRequest`/`EngineRollbackRequest` (Task 4); `install::{InstallContext, InstallError, execute}` (Task 9); `rollback::{RollbackContext, RollbackError, execute}` (Task 10); `EngineConfig` (`src/config.rs`).
- Produces: `commands::engine::run(command: EngineCommand) -> Result<Response, ResponseBuildError>`, `commands::engine::GITHUB_RELEASES_BASE` — consumed by `src/lib.rs`'s `execute`.

- [ ] **Step 1: Register the new module**

In `src/commands/mod.rs`, add `pub mod engine;` alongside the existing `pub mod capabilities; pub mod doctor; pub mod site; pub mod version;` (check the file's exact current list and insert alphabetically).

- [ ] **Step 2: Write `commands/engine.rs`**

This mirrors `src/commands/site.rs` closely — open that file side by side.

```rust
use crate::{
    cli::EngineCommand,
    engine::{
        EngineInstallRequest, EngineInstallRequestError, EngineRollbackRequest, EngineRollbackRequestError,
        install::{InstallContext, InstallError, execute as execute_install},
        rollback::{RollbackContext, RollbackError, execute as execute_rollback},
    },
    error::{ErrorCode, WarningCode},
    process::CancellationToken,
    protocol::{Response, ResponseBuildError, Warning},
};

/// The fixed, compiled-in GitHub Releases base URL every production
/// `engine install`/`engine rollback` call fetches from. Never a CLI
/// flag or protocol input — see `InstallContext::release_base_url`'s
/// doc comment for why tests pass a different value directly.
pub const GITHUB_RELEASES_BASE: &str =
    "https://github.com/skanevi/operations-engine/releases/download";

const INSTALL_OPERATION: &str = "engine.install";
const ROLLBACK_OPERATION: &str = "engine.rollback";
const CONFIG_PATH: &str = "/etc/operations-engine/config.json";
const BIN_ROOT: &str = "/usr/local/bin";

pub fn run(command: EngineCommand) -> Result<Response, ResponseBuildError> {
    match command {
        EngineCommand::Install {
            version,
            request_id,
            idempotency_key,
        } => install(&version, &request_id, idempotency_key.as_deref()),
        EngineCommand::Rollback {
            request_id,
            idempotency_key,
        } => rollback(&request_id, idempotency_key.as_deref()),
    }
}

fn install(version: &str, request_id: &str, idempotency_key: Option<&str>) -> Result<Response, ResponseBuildError> {
    let request = match EngineInstallRequest::parse(version, request_id, idempotency_key) {
        Ok(request) => request,
        Err(error) => {
            return Ok(Response::failure(
                INSTALL_OPERATION,
                ErrorCode::InvalidInput,
                install_request_error_message(error),
            ));
        }
    };

    #[cfg(unix)]
    {
        run_install(&request)
    }
    #[cfg(not(unix))]
    {
        let _ = request;
        Ok(Response::failure(
            INSTALL_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "engine.install requires a Unix host",
        ))
    }
}

#[cfg(unix)]
fn run_install(request: &EngineInstallRequest) -> Result<Response, ResponseBuildError> {
    use std::path::Path;

    use crate::{config::EngineConfig, filesystem::ManagedRoot, site::TrustedRoot};

    let engine_config = match EngineConfig::load_root_owned(Path::new(CONFIG_PATH)) {
        Ok(config) => config,
        Err(_) => {
            return Ok(Response::failure(
                INSTALL_OPERATION,
                ErrorCode::Internal,
                "engine configuration is unavailable",
            ));
        }
    };
    let bin_root = TrustedRoot::parse(Path::new(BIN_ROOT)).expect("BIN_ROOT is a valid literal trusted root");
    let engine_state = match ManagedRoot::open(&engine_config.state_root) {
        Ok(root) => root,
        Err(_) => {
            return Ok(Response::failure(
                INSTALL_OPERATION,
                ErrorCode::Internal,
                "engine state root is unavailable",
            ));
        }
    };
    let context = InstallContext {
        bin_root: &bin_root,
        engine_state: &engine_state,
        release_base_url: GITHUB_RELEASES_BASE,
    };

    match execute_install(&context, request, &CancellationToken::default()) {
        Ok(result) => Response::success(INSTALL_OPERATION, result),
        Err(InstallError::PostCommitRecordFailed { result, .. }) => {
            Response::success(INSTALL_OPERATION, result).map(|response| {
                response.with_warnings(vec![Warning {
                    code: WarningCode::TransactionRecordIncomplete,
                    message: "the install completed but its transaction record could not be saved"
                        .to_owned(),
                }])
            })
        }
        Err(error) => {
            let (code, message) = error.protocol();
            Ok(Response::failure(INSTALL_OPERATION, code, &message))
        }
    }
}

fn install_request_error_message(error: EngineInstallRequestError) -> &'static str {
    match error {
        EngineInstallRequestError::InvalidVersion => "version is not a valid MAJOR.MINOR.PATCH version",
        EngineInstallRequestError::InvalidRequestId => "request-id is not a canonical UUID",
        EngineInstallRequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}

fn rollback(request_id: &str, idempotency_key: Option<&str>) -> Result<Response, ResponseBuildError> {
    let request = match EngineRollbackRequest::parse(request_id, idempotency_key) {
        Ok(request) => request,
        Err(error) => {
            return Ok(Response::failure(
                ROLLBACK_OPERATION,
                ErrorCode::InvalidInput,
                rollback_request_error_message(error),
            ));
        }
    };

    #[cfg(unix)]
    {
        run_rollback(&request)
    }
    #[cfg(not(unix))]
    {
        let _ = request;
        Ok(Response::failure(
            ROLLBACK_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "engine.rollback requires a Unix host",
        ))
    }
}

#[cfg(unix)]
fn run_rollback(request: &EngineRollbackRequest) -> Result<Response, ResponseBuildError> {
    use std::path::Path;

    use crate::{config::EngineConfig, filesystem::ManagedRoot, site::TrustedRoot};

    let engine_config = match EngineConfig::load_root_owned(Path::new(CONFIG_PATH)) {
        Ok(config) => config,
        Err(_) => {
            return Ok(Response::failure(
                ROLLBACK_OPERATION,
                ErrorCode::Internal,
                "engine configuration is unavailable",
            ));
        }
    };
    let bin_root = TrustedRoot::parse(Path::new(BIN_ROOT)).expect("BIN_ROOT is a valid literal trusted root");
    let engine_state = match ManagedRoot::open(&engine_config.state_root) {
        Ok(root) => root,
        Err(_) => {
            return Ok(Response::failure(
                ROLLBACK_OPERATION,
                ErrorCode::Internal,
                "engine state root is unavailable",
            ));
        }
    };
    let context = RollbackContext {
        bin_root: &bin_root,
        engine_state: &engine_state,
    };

    match execute_rollback(&context, request, &CancellationToken::default()) {
        Ok(result) => Response::success(ROLLBACK_OPERATION, result),
        Err(RollbackError::PostCommitRecordFailed { result, .. }) => {
            Response::success(ROLLBACK_OPERATION, result).map(|response| {
                response.with_warnings(vec![Warning {
                    code: WarningCode::TransactionRecordIncomplete,
                    message: "the rollback completed but its transaction record could not be saved"
                        .to_owned(),
                }])
            })
        }
        Err(error) => {
            let (code, message) = error.protocol();
            Ok(Response::failure(ROLLBACK_OPERATION, code, &message))
        }
    }
}

fn rollback_request_error_message(error: EngineRollbackRequestError) -> &'static str {
    match error {
        EngineRollbackRequestError::InvalidRequestId => "request-id is not a canonical UUID",
        EngineRollbackRequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}
```

- [ ] **Step 3: Wire the dispatch in `src/lib.rs`**

In `src/lib.rs`'s `execute` function, add the new arm:

```rust
        Command::Site { command } => commands::site::run(command),
        Command::Engine { command } => commands::engine::run(command),
```

- [ ] **Step 4: Remove the temporary `#[allow(dead_code)]` markers**

If Tasks 9/10 added a temporary `#[allow(dead_code)]` to silence Clippy on the not-yet-called `install`/`rollback` modules, remove them now — both are called from `commands/engine.rs`.

- [ ] **Step 5: Run the full test suite, Clippy, and fmt**

Run: `cargo test --all-features && cargo fmt --all --check && cargo clippy --all-targets --all-features -- -D warnings`
Expected: everything compiles and passes; no dead-code warnings remain.

- [ ] **Step 6: Commit**

```bash
git add src/commands/mod.rs src/commands/engine.rs src/lib.rs src/engine/install.rs src/engine/rollback.rs
git commit -m "Wire engine install/rollback into command dispatch"
```

---

## Task 13: End-to-end integration tests against a local fixture server

**Files:**
- Create: `tests/engine.rs`

**Interfaces:**
- Consumes: `operations_engine::engine::{install::{InstallContext, execute as execute_install}, rollback::{RollbackContext, execute as execute_rollback}, EngineInstallRequest, EngineRollbackRequest, state}`; `operations_engine::{filesystem::ManagedRoot, process::CancellationToken, site::TrustedRoot}`.

This test calls `install::execute`/`rollback::execute` directly (not through the CLI subprocess), exactly like `tests/deploy.rs` and `tests/rollback.rs` call `deploy::execute::execute`/`rollback::execute::execute` directly — a real network call (to a local fixture server, not a mock) and real filesystem writes under temp directories standing in for `/usr/local/bin` and the state root.

- [ ] **Step 1: Sign real test fixtures with the real secret key**

This test needs a version, a real binary's bytes, and a real minisign-signed `SHA256SUMS`/`.minisig` pair for that binary — generated once, checked into the test fixture directory (these are public test artifacts; signing them with the real release key is fine, they are not consumed by real installs since the fixture server serves them from a `127.0.0.1` URL, never GitHub).

```bash
mkdir -p tests/fixtures/engine
echo -n 'pretend ops-engine binary for tests' > tests/fixtures/engine/ops-engine-9.9.9-x86_64-unknown-linux-gnu
sha256sum tests/fixtures/engine/ops-engine-9.9.9-x86_64-unknown-linux-gnu \
  | awk '{print $1 "  ops-engine-9.9.9-x86_64-unknown-linux-gnu"}' > tests/fixtures/engine/SHA256SUMS
minisign -S -s release/minisign.key -m tests/fixtures/engine/SHA256SUMS
```

(The last command prompts for the same password chosen in Task 7 Step 2, and writes `tests/fixtures/engine/SHA256SUMS.minisig`.) Commit all four files (`ops-engine-9.9.9-...`, `SHA256SUMS`, `SHA256SUMS.minisig`, plus this step's commands recorded in this plan for reproducing them later if the fixture ever needs regenerating).

- [ ] **Step 2: Write the fixture HTTP server and the tests**

```rust
//! End-to-end tests for `engine::install::execute` and
//! `engine::rollback::execute`, run for real against a local fixture
//! HTTP server (no mocking of `ureq`) and real temp-directory roots
//! standing in for `/usr/local/bin` and the state root. Mirrors
//! `tests/deploy.rs`/`tests/rollback.rs`'s style of calling the
//! orchestration function directly rather than through the CLI.

use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpListener},
};

use operations_engine::{
    engine::{
        EngineInstallRequest, EngineRollbackRequest,
        install::{InstallContext, InstallError, execute as execute_install},
        rollback::{RollbackContext, RollbackError, execute as execute_rollback},
        state,
    },
    filesystem::ManagedRoot,
    process::CancellationToken,
    site::TrustedRoot,
};

const REQUEST_ID_1: &str = "123e4567-e89b-12d3-a456-426614174000";
const REQUEST_ID_2: &str = "9b2f1c34-5678-4abc-9def-0123456789ab";
const VERSION: &str = "9.9.9";

/// Serves the four fixture files (and, for the corrupted-artifact test, a
/// caller-substituted binary) from a background thread, one request at a
/// time — sufficient for this test's handful of sequential requests. The
/// listener is dropped (and the thread's `accept` loop ends) when the
/// test function returns.
struct FixtureServer {
    base_url: String,
}

fn start_fixture_server(routes: HashMap<&'static str, Vec<u8>>) -> FixtureServer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let addr: SocketAddr = listener.local_addr().expect("listener should have an address");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().expect("stream should clone"));
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
                continue;
            }
            let path = request_line
                .split_whitespace()
                .nth(1)
                .unwrap_or("/")
                .trim_start_matches('/')
                .to_owned();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() || line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            match routes.get(path.as_str()) {
                Some(body) => {
                    let header =
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                    let _ = stream.write_all(header.as_bytes());
                    let _ = stream.write_all(body);
                }
                None => {
                    let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                }
            }
        }
    });
    FixtureServer {
        base_url: format!("http://{addr}"),
    }
}

fn fixture_routes(binary_override: Option<Vec<u8>>) -> HashMap<&'static str, Vec<u8>> {
    let binary = binary_override.unwrap_or_else(|| {
        std::fs::read("tests/fixtures/engine/ops-engine-9.9.9-x86_64-unknown-linux-gnu")
            .expect("fixture binary should exist — see Task 13 Step 1")
    });
    let mut routes = HashMap::new();
    routes.insert(
        "v9.9.9/SHA256SUMS",
        std::fs::read("tests/fixtures/engine/SHA256SUMS").expect("fixture manifest should exist"),
    );
    routes.insert(
        "v9.9.9/SHA256SUMS.minisig",
        std::fs::read("tests/fixtures/engine/SHA256SUMS.minisig").expect("fixture signature should exist"),
    );
    routes.insert("v9.9.9/ops-engine-9.9.9-x86_64-unknown-linux-gnu", binary);
    routes
}

fn roots() -> (tempfile::TempDir, tempfile::TempDir, TrustedRoot, ManagedRoot) {
    let bin_dir = tempfile::tempdir().expect("bin directory should exist");
    let state_dir = tempfile::tempdir().expect("state directory should exist");
    let bin_root = TrustedRoot::parse(bin_dir.path()).expect("bin root should be valid");
    let state_root = TrustedRoot::parse(state_dir.path()).expect("state root should be valid");
    let engine_state = ManagedRoot::open(&state_root).expect("state root should open");
    (bin_dir, state_dir, bin_root, engine_state)
}

#[test]
fn a_fresh_install_activates_the_verified_binary() {
    let server = start_fixture_server(fixture_routes(None));
    let (bin_dir, _state_dir, bin_root, engine_state) = roots();
    let context = InstallContext {
        bin_root: &bin_root,
        engine_state: &engine_state,
        release_base_url: &server.base_url,
    };
    let request = EngineInstallRequest::parse(VERSION, REQUEST_ID_1, None).expect("request should parse");

    let result = execute_install(&context, &request, &CancellationToken::default())
        .expect("install should succeed");

    assert_eq!(result.version, VERSION);
    assert_eq!(result.previous_version, None);
    assert_eq!(
        std::fs::read(bin_dir.path().join("ops-engine")).unwrap(),
        std::fs::read("tests/fixtures/engine/ops-engine-9.9.9-x86_64-unknown-linux-gnu").unwrap()
    );

    let saved = state::load(&engine_state).unwrap().expect("install state should be recorded");
    assert_eq!(saved.active_version, VERSION);
    assert_eq!(saved.previous_version, None);
}

#[test]
fn installing_the_same_version_twice_is_rejected_as_already_active() {
    let server = start_fixture_server(fixture_routes(None));
    let (_bin_dir, _state_dir, bin_root, engine_state) = roots();
    let context = InstallContext {
        bin_root: &bin_root,
        engine_state: &engine_state,
        release_base_url: &server.base_url,
    };
    let first = EngineInstallRequest::parse(VERSION, REQUEST_ID_1, None).expect("request should parse");
    execute_install(&context, &first, &CancellationToken::default()).expect("first install should succeed");

    let second = EngineInstallRequest::parse(VERSION, REQUEST_ID_2, None).expect("request should parse");
    let error = execute_install(&context, &second, &CancellationToken::default()).unwrap_err();
    assert!(matches!(error, InstallError::AlreadyActive));
}

#[test]
fn a_corrupted_artifact_is_rejected_and_leaves_the_filesystem_untouched() {
    let server = start_fixture_server(fixture_routes(Some(b"corrupted, wrong bytes".to_vec())));
    let (bin_dir, _state_dir, bin_root, engine_state) = roots();
    let context = InstallContext {
        bin_root: &bin_root,
        engine_state: &engine_state,
        release_base_url: &server.base_url,
    };
    let request = EngineInstallRequest::parse(VERSION, REQUEST_ID_1, None).expect("request should parse");

    let error = execute_install(&context, &request, &CancellationToken::default()).unwrap_err();
    assert!(matches!(error, InstallError::ChecksumMismatch));
    assert!(!bin_dir.path().join("ops-engine").exists());
    assert_eq!(state::load(&engine_state).unwrap(), None);
}

#[test]
fn rollback_after_an_install_restores_the_previous_binary_and_can_roll_forward_again() {
    let (bin_dir, _state_dir, bin_root, engine_state) = roots();

    // This test targets `rollback::execute` in isolation — installing's
    // own fetch/verify/stage path is already covered by
    // `a_fresh_install_activates_the_verified_binary`. Seed an
    // already-installed active/previous pair directly (both the
    // `install.state` record and the two retained binaries under
    // `versions/`) rather than driving two real HTTP-backed installs.
    state::save(
        &engine_state,
        &state::InstallState {
            active_version: "9.9.9".to_owned(),
            previous_version: Some("9.9.8".to_owned()),
        },
    )
    .expect("seeded install state should save");
    // Seed both retained binaries directly (this test targets rollback,
    // not install — `a_fresh_install_activates_the_verified_binary`
    // already covers install's own staging).
    let scoped = state::open_engine_state(&engine_state).expect("engine state should open");
    for (version, content) in [("9.9.9", b"nine binary".to_vec()), ("9.9.8", b"eight binary".to_vec())] {
        let dir = operations_engine::site::SiteRelativePath::parse(format!("versions/{version}")).unwrap();
        let path = operations_engine::site::SiteRelativePath::parse(format!("versions/{version}/ops-engine")).unwrap();
        scoped.create_dir_all(&dir).unwrap();
        scoped.write_new_executable(&path, &content).unwrap();
    }

    let rollback_context = RollbackContext {
        bin_root: &bin_root,
        engine_state: &engine_state,
    };
    let rollback_request = EngineRollbackRequest::parse(REQUEST_ID_1, None).expect("request should parse");
    let result = execute_rollback(&rollback_context, &rollback_request, &CancellationToken::default())
        .expect("rollback should succeed");

    assert_eq!(result.version, "9.9.8");
    assert_eq!(result.previous_version, "9.9.9");
    assert_eq!(std::fs::read(bin_dir.path().join("ops-engine")).unwrap(), b"eight binary");
    let after_rollback = state::load(&engine_state).unwrap().unwrap();
    assert_eq!(after_rollback.active_version, "9.9.8");
    assert_eq!(after_rollback.previous_version, Some("9.9.9".to_owned()));

    // Roll forward again — proves the source version was not
    // invalidated by the first rollback.
    let roll_forward_request = EngineRollbackRequest::parse(REQUEST_ID_2, None).expect("request should parse");
    let result = execute_rollback(&rollback_context, &roll_forward_request, &CancellationToken::default())
        .expect("second rollback should succeed");
    assert_eq!(result.version, "9.9.9");
    assert_eq!(std::fs::read(bin_dir.path().join("ops-engine")).unwrap(), b"nine binary");
}

#[test]
fn rollback_with_no_retained_previous_version_fails_closed() {
    let (bin_dir, _state_dir, bin_root, engine_state) = roots();
    let context = RollbackContext {
        bin_root: &bin_root,
        engine_state: &engine_state,
    };
    let request = EngineRollbackRequest::parse(REQUEST_ID_1, None).expect("request should parse");

    let error = execute_rollback(&context, &request, &CancellationToken::default()).unwrap_err();
    assert!(matches!(error, RollbackError::NoPreviousVersion));
    assert!(!bin_dir.path().join("ops-engine").exists());
}
```

- [ ] **Step 3: Run the tests**

Run: `cargo test --test engine`
Expected: PASS, all five tests.

- [ ] **Step 4: Run the full suite, Clippy, and fmt one more time**

Run: `cargo test --all-features && cargo fmt --all --check && cargo clippy --all-targets --all-features -- -D warnings`
Expected: everything passes, no warnings.

- [ ] **Step 5: Commit**

```bash
git add tests/engine.rs tests/fixtures/engine/
git commit -m "Add end-to-end engine install/rollback integration tests"
```

---

## Task 14: Advertise `engine.install`/`engine.rollback` in `capabilities`

**Files:**
- Modify: `src/commands/capabilities.rs`
- Modify: `tests/cli.rs` (update the existing capabilities test)

This is the last code task — everything it advertises must already be implemented and tested, which Tasks 1–13 have now done.

- [ ] **Step 1: Update the failing test first**

In `tests/cli.rs`, update `capabilities_describe_only_implemented_operations`'s expected array:

```rust
    assert_eq!(
        response["result"]["operations"],
        serde_json::json!([
            "version",
            "capabilities",
            "doctor",
            "site.deploy",
            "site.rollback",
            "engine.install",
            "engine.rollback"
        ])
    );
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --test cli capabilities_describe_only_implemented_operations`
Expected: FAIL — the actual response still only lists five operations.

- [ ] **Step 3: Update `capabilities.rs`**

```rust
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CapabilitiesResult {
    operations: [&'static str; 7],
    output_formats: [&'static str; 1],
    features: Features,
}
```

```rust
            operations: [
                "version",
                "capabilities",
                "doctor",
                "site.deploy",
                "site.rollback",
                "engine.install",
                "engine.rollback",
            ],
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test --test cli capabilities_describe_only_implemented_operations`
Expected: PASS.

- [ ] **Step 5: Run the full suite, Clippy, and fmt**

Run: `cargo test --all-features && cargo fmt --all --check && cargo clippy --all-targets --all-features -- -D warnings`
Expected: everything passes.

- [ ] **Step 6: Commit**

```bash
git add src/commands/capabilities.rs tests/cli.rs
git commit -m "Advertise engine.install and engine.rollback in capabilities"
```

---

## Task 15: Add the reproducible-build, checksum, and signing release workflow

**Files:**
- Create: `.github/workflows/release.yml`

**Interfaces:** None — this is CI configuration, triggered by pushing a `v*` tag; it does not change any Rust code or its public interfaces.

- [ ] **Step 1: Add the two GitHub Actions secrets this workflow needs**

In the repository's Settings → Secrets and variables → Actions, add:
- `MINISIGN_SECRET_KEY` — the full text contents of `release/minisign.key` (generated in Task 7 Step 2; read it with `cat release/minisign.key` and paste the whole thing, including the `untrusted comment:`/`trusted comment:` header lines).
- `MINISIGN_KEY_PASSWORD` — the password chosen in Task 7 Step 2 (the same value used locally as `MINISIGN_TEST_KEY_PASSWORD`).

This is a manual, one-time step in the GitHub UI — there is no CLI command to script it without also handling `gh secret set`'s own auth, and doing this by hand once is simpler than adding that dependency to this plan.

- [ ] **Step 2: Write the workflow**

Create `.github/workflows/release.yml`:

```yaml
name: Release

on:
  push:
    tags:
      - "v*"

permissions:
  contents: write

env:
  CARGO_TERM_COLOR: always

jobs:
  build:
    strategy:
      matrix:
        include:
          - target: x86_64-unknown-linux-gnu
            runner: ubuntu-latest
          - target: aarch64-unknown-linux-gnu
            runner: ubuntu-24.04-arm
    runs-on: ${{ matrix.runner }}
    steps:
      - name: Check out repository
        uses: actions/checkout@v5

      - name: Install Rust
        run: rustup show

      - name: Cache Cargo data
        uses: Swatinem/rust-cache@v2

      - name: Compute SOURCE_DATE_EPOCH from the tagged commit
        run: echo "SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)" >> "$GITHUB_ENV"

      - name: Build
        env:
          OPS_ENGINE_GIT_COMMIT: ${{ github.sha }}
        run: cargo build --release --locked

      - name: Rename the binary with its version and target triple
        run: |
          VERSION="${GITHUB_REF_NAME#v}"
          mkdir -p dist
          cp target/release/ops-engine "dist/ops-engine-${VERSION}-${{ matrix.target }}"

      - name: Upload build artifact
        uses: actions/upload-artifact@v4
        with:
          name: ops-engine-${{ matrix.target }}
          path: dist/*

  sign-and-release:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - name: Check out repository
        uses: actions/checkout@v5

      - name: Download all build artifacts
        uses: actions/download-artifact@v4
        with:
          path: dist
          merge-multiple: true

      - name: Install minisign
        run: sudo apt-get update && sudo apt-get install -y minisign

      - name: Compute checksums
        run: |
          cd dist
          sha256sum ops-engine-* > SHA256SUMS

      - name: Sign the checksum manifest
        env:
          MINISIGN_PASSWORD: ${{ secrets.MINISIGN_KEY_PASSWORD }}
        run: |
          echo "${{ secrets.MINISIGN_SECRET_KEY }}" > minisign.key
          minisign -S -s minisign.key -m dist/SHA256SUMS
          shred -u minisign.key

      - name: Publish the GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          files: |
            dist/ops-engine-*
            dist/SHA256SUMS
            dist/SHA256SUMS.minisig
          generate_release_notes: true
```

- [ ] **Step 3: Verify the workflow's YAML is well-formed**

Run: `python3 -c "import yaml, sys; yaml.safe_load(open('.github/workflows/release.yml'))"` (or any available YAML linter/parser) to catch indentation mistakes before pushing a tag — a real end-to-end run only happens once a tag is actually pushed, which this task does not do (that is a release action, not an implementation step; leave triggering the first real release to the user).

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "Add the reproducible-build, checksum, and signing release workflow"
```

---

## Task 16: Release, compatibility, and incident-recovery documentation

**Files:**
- Create: `docs/release.md`
- Create: `docs/compatibility.md`
- Create: `docs/incident-recovery.md`

- [ ] **Step 1: Write `docs/compatibility.md`**

```markdown
# Compatibility matrix

Tracks which published `ops-engine` versions speak which protocol
version, and the minimum control-plane (`website-control-panel`) build
known to work with them. Update this table as part of cutting each
release (`docs/release.md`); it is documentation only — runtime
compatibility is enforced independently by the control plane's protocol
version negotiation (`MIN_PROTOCOL_VERSION`/`MAX_PROTOCOL_VERSION` in
`website-control-panel`'s `ops_engine::mod.rs`).

| Engine version | Protocol version | Notes |
| --- | --- | --- |
| 0.1.0 – (current) | 1 | Initial and only protocol version so far. |
```

- [ ] **Step 2: Write `docs/release.md`**

```markdown
# Cutting a release

1. Update `docs/compatibility.md` if this release changes protocol
   compatibility.
2. Tag the commit: `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. `.github/workflows/release.yml` builds `x86_64-unknown-linux-gnu` and
   `aarch64-unknown-linux-gnu` binaries natively (no cross-compilation),
   computes `SHA256SUMS`, signs it with the repository's minisign key,
   and publishes a GitHub Release with all four files attached.
4. Verify a downloaded artifact by hand before trusting the automation:

   ```console
   curl -LO https://github.com/skanevi/operations-engine/releases/download/vX.Y.Z/SHA256SUMS
   curl -LO https://github.com/skanevi/operations-engine/releases/download/vX.Y.Z/SHA256SUMS.minisig
   curl -LO https://github.com/skanevi/operations-engine/releases/download/vX.Y.Z/ops-engine-X.Y.Z-x86_64-unknown-linux-gnu
   minisign -V -p release/minisign.pub -m SHA256SUMS
   sha256sum -c SHA256SUMS --ignore-missing
   ```

## Reproducibility

Builds use `cargo build --release --locked` against the exact toolchain
pinned in `rust-toolchain.toml`, with `SOURCE_DATE_EPOCH` set from the
tagged commit's timestamp. This is not bit-for-bit `diffoscope`-verified
reproducibility — see the design spec
(`docs/superpowers/specs/2026-09-03-release-pipeline-design.md`) for why
that level was deliberately out of scope.

## Signing key

The release signing keypair was generated once via `minisign -G`. Only
`release/minisign.pub` is committed; the secret half lives exclusively
in this repository's `MINISIGN_SECRET_KEY`/`MINISIGN_KEY_PASSWORD`
GitHub Actions secrets. Rotating it means generating a new keypair,
updating both secrets, and updating the committed `release/minisign.pub`
in the same change that cuts the first release signed with the new key
— older `ops-engine` builds with the old key compiled in will not be
able to verify releases signed with a rotated key, so a key rotation is
itself a compatibility event worth a `docs/compatibility.md` entry.
```

- [ ] **Step 3: Write `docs/incident-recovery.md`**

```markdown
# Incident recovery: engine install/upgrade

## A failed or misbehaving upgrade

1. Run `ops-engine engine rollback --request-id <new-uuid>` first — it
   requires no network access and switches
   `/usr/local/bin/ops-engine` back to the one retained previous binary
   in under a second. This is always the first response.
2. If the previous binary was also bad (rare — it was itself verified
   and running before this upgrade), install a specific known-good older
   version instead: `ops-engine engine install --version <known-good>
   --request-id <new-uuid>`. This re-fetches and re-verifies that
   version from GitHub Releases rather than depending on local state.
3. Both commands are idempotent by `--request-id`/`--idempotency-key`
   exactly like `site deploy`/`site rollback` — a retried call after a
   dropped connection returns the original outcome rather than
   double-applying.

## Opt-in rollout to test servers

There is no separate "rollout channel" mechanism — `engine install`
already requires an explicit, pinned version on every call, so nothing
auto-updates and every rollout is manual and per-server by construction.
Before rolling a new version out broadly:

1. Run `engine install`/`engine rollback` against the
   `website-control-panel` repo's `docker/test-server` fixture first.
2. Run it against exactly one real managed server and confirm
   `capabilities`/`version` report the expected result.
3. Only then roll out to additional servers, one at a time.
```

- [ ] **Step 4: Commit**

```bash
git add docs/release.md docs/compatibility.md docs/incident-recovery.md
git commit -m "Add release, compatibility, and incident-recovery documentation"
```

---

## Task 17: Update `PLAN.md`

**Files:**
- Modify: `PLAN.md`

- [ ] **Step 1: Redaction and bounded-log review**

Read through every `ErrorCode`/message pair produced by `src/engine/install.rs`, `src/engine/rollback.rs`, and `src/engine/verify.rs` (Tasks 7, 9, 10) and confirm none of them ever include: a raw HTTP response body, a full URL (only the fixed GitHub base is ever used, so this should already be structurally impossible — confirm it, don't just assume it), a local filesystem path outside the trusted roots, or any byte of the fetched binary/manifest content. All current messages are static strings with no interpolated remote data — confirm this stayed true through Tasks 9–10's actual implementation (Clippy's `-D warnings` run in each of those tasks does not catch this; it requires reading the code). Record the outcome as a decision-log entry (Step 2 below), whether or not it found anything to fix.

- [ ] **Step 2: Record delivered Phase 7 items and remaining scope**

Under Phase 7, mark as delivered: reproducible Linux AMD64+ARM64 builds; checksums and signed release artifacts; atomic upgrade and downgrade with previous-binary recovery (`engine install`/`engine rollback`); release compatibility matrix; redaction/bounded-log review (Step 1 above); package and incident-recovery documentation; opt-in rollout procedure. Note explicitly that "explicit, pinned installation through the control plane" is only half-delivered by this work: the engine-side `engine install`/`engine rollback` commands exist and are tested, but `website-control-panel` does not yet call them (its own plan is separate — see this plan's "Scope note"). Add a decision-log entry recording the base-URL parameterization (`InstallContext::release_base_url`), the two-slot (not N-version) retention choice, and the write-temp-then-rename activation of a regular file in place of the originally-specced cross-root symlink (this plan's "Deviation from the spec" section) — per this plan's Tasks 5 and 9.

- [ ] **Step 3: Update `Last updated`**

Set to the date this task is actually completed.

- [ ] **Step 4: Commit**

```bash
git add PLAN.md
git commit -m "Update PLAN.md: Phase 7 engine install/rollback delivered"
```

---

## Self-review notes

- **Type consistency (fixed):** `mutation::preflight::Admitted`'s field is named `state`, not `tx`. Tasks 9 and 10 originally destructured it as `let preflight::Admitted { lock, mut tx } = admitted;`, which does not compile against a struct field literally named `state` — Rust requires the `state: mut tx` rename form. Both occurrences now read `let preflight::Admitted { lock, state: mut tx } = admitted;`, matching `src/mutation/preflight.rs`'s real field name.
- **Spec deviation, deliberate (see "Deviation from the spec" above):** the design spec's §5 described a symlink-based `versions/`/`current` layout for the engine binary itself, mirroring site releases exactly. Grounding the design in this repo's actual `docs/site-model.md` (which fixes `/usr/local/bin/ops-engine` as a real file, not a redirectable symlink target, owned by root and permitted by name in the sudoers policy) showed that pattern doesn't transplant directly: `/usr/local/bin` and the engine's state root are different trusted roots, and `ManagedRoot::symlink`'s target is intentionally typed as a same-root-relative `SiteRelativePath`, not an arbitrary absolute path. Task 3/9/10 use a same-directory write-temp-then-atomic-rename of the full binary content into `/usr/local/bin/ops-engine` instead (still exactly one atomic `rename(2)`, so there is still no window where the binary is missing) — retention of the "previous" version happens entirely in the separate `versions/` store under the state root, which `engine rollback` reads from directly.
- Every task that touches `src/engine/*` before Task 12 wires up its caller may trip Clippy's dead-code lint; each such task's Clippy step notes the temporary `#[allow(dead_code)]` escape hatch and Task 12 removes it.
