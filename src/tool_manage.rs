//! `tool.install`, `tool.remove` and `tool.status`: host-managed tools that
//! are mounted read-only into the runtime containers instead of being baked
//! into the Docker images.
//!
//! The tool catalog is compiled into the engine: one pinned official release
//! URL, exact version and SHA-256 per tool, cross-checked against the
//! checksums the upstream project publishes when the pin was set. There is
//! no way for a request to name a URL, a version or a path.
//!
//! Nothing downloaded is trusted until it hashes to the pinned digest and has
//! the structure of the expected artifact (a PHP archive for WP-CLI). The
//! tool lands in `<tools>/<name>/<version>/<file>`; a relative `current`
//! symlink is switched with a same-directory atomic rename, so a container
//! reading `<tools>/<name>/current/<file>` sees the old or the new tool, never
//! a partial one. The selection is recorded in the engine state root.

use crate::{
    engine::fetch,
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::CancellationToken,
    site::SiteRelativePath,
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        commit::PreCommit,
        state::{self, TransactionStatus},
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const INSTALL: &str = "tool.install";
pub const REMOVE: &str = "tool.remove";
pub const STATUS: &str = "tool.status";
/// Host directory that is bind-mounted read-only into runtime containers.
pub const TOOLS_DIR: &str = "/var/lib/wcp/tools";
pub const WP_CLI_VERSION: &str = "2.12.0";
/// The WP-CLI phar is ~7 MiB.
pub const MAX_ARTIFACT_BYTES: u64 = 32 * 1024 * 1024;
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const SELECTION_FILE: &str = "selection.json";
const CURRENT: &str = "current";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Tool {
    WpCli,
}

impl Tool {
    pub const ALL: &'static [Tool] = &[Tool::WpCli];

    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|tool| tool.name() == name)
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::WpCli => "wp-cli",
        }
    }

    /// File name inside the version directory.
    pub const fn file(self) -> &'static str {
        match self {
            Self::WpCli => "wp.phar",
        }
    }

    pub fn pinned(self) -> Artifact {
        match self {
            Self::WpCli => Artifact {
                version: WP_CLI_VERSION.to_owned(),
                url: format!(
                    "https://github.com/wp-cli/wp-cli/releases/download/v{WP_CLI_VERSION}/wp-cli-{WP_CLI_VERSION}.phar"
                ),
                // Matches both wp-cli-2.12.0.phar.sha256 and .sha512 as
                // published with the release.
                sha256: "ce34ddd838f7351d6759068d09793f26755463b4a4610a5a5c0a97b68220d85c"
                    .to_owned(),
            },
        }
    }

    /// Structural check on top of the digest: the artifact must look like
    /// what the tool is supposed to be, so a mis-pinned URL cannot install an
    /// unrelated file.
    fn looks_valid(self, bytes: &[u8]) -> bool {
        match self {
            Self::WpCli => {
                bytes.starts_with(b"#!/usr/bin/env php")
                    && bytes
                        .windows(18)
                        .any(|window| window == b"__HALT_COMPILER();")
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Artifact {
    pub version: String,
    pub url: String,
    pub sha256: String,
}

pub struct Request {
    pub tool: Tool,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug)]
pub enum RequestError {
    UnknownTool,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl Request {
    pub fn parse(tool: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        Ok(Self {
            tool: Tool::parse(tool).ok_or(RequestError::UnknownTool)?,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolResult {
    pub tool: String,
    /// `false` when the request found the host already in the requested state.
    pub changed: bool,
    pub version: Option<String>,
    pub completed_at_unix_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ToolStatus {
    pub tool: String,
    pub pinned_version: String,
    pub installed_version: Option<String>,
    /// Recorded as wanted on this host.
    pub selected: bool,
    /// The installed file exists and still hashes to its pinned digest.
    pub intact: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StatusReport {
    pub tools_dir: String,
    pub tools: Vec<ToolStatus>,
}

pub type Fetcher<'a> = &'a dyn Fn(&str) -> Result<Vec<u8>, fetch::Error>;
pub type Catalog<'a> = &'a dyn Fn(Tool) -> Artifact;

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    /// Opened on [`TOOLS_DIR`] (or a test directory).
    pub tools_root: &'a ManagedRoot,
    /// [`Tool::pinned`] in production; tests substitute their own artifacts.
    pub catalog: Catalog<'a>,
    pub fetch: Fetcher<'a>,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Cancelled,
    Fetch(fetch::Error),
    DigestMismatch,
    NotTheExpectedArtifact,
    Write(io::Error),
    PostCommit { result: ToolResult },
    Replayed { code: ErrorCode, message: String },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another tool operation is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before the tool changed".into(),
            ),
            Self::Fetch(fetch::Error::Timeout) => (
                ErrorCode::Timeout,
                "timed out downloading the tool release".into(),
            ),
            Self::Fetch(_) => (
                ErrorCode::ArtifactFetchFailed,
                "could not download the tool release".into(),
            ),
            Self::DigestMismatch => (
                ErrorCode::ArtifactVerificationFailed,
                "the downloaded tool does not match its pinned SHA-256".into(),
            ),
            Self::NotTheExpectedArtifact => (
                ErrorCode::ArtifactVerificationFailed,
                "the downloaded file is not the expected kind of artifact".into(),
            ),
            Self::Write(_) => (ErrorCode::Internal, "could not write the tool".into()),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit { .. } => {
                (ErrorCode::Internal, "internal tool error".into())
            }
        }
    }
}

fn rel(value: impl AsRef<Path>) -> SiteRelativePath {
    SiteRelativePath::parse(value).expect("static tool paths are valid")
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 15) as usize] as char);
    }
    out
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn result(tool: Tool, changed: bool, version: Option<String>) -> ToolResult {
    ToolResult {
        tool: tool.name().to_owned(),
        changed,
        version,
        completed_at_unix_secs: now(),
    }
}

/// The version `current` points at, when it is a plain version directory.
fn current_version(tool_dir: &ManagedRoot) -> Option<String> {
    let target = tool_dir.read_link(&rel(CURRENT)).ok()?;
    let name = target.to_str()?;
    (!name.contains('/') && !name.is_empty() && name != "." && name != "..")
        .then(|| name.to_owned())
}

fn intact(tool: Tool, tool_dir: &ManagedRoot, version: &str, pinned: &Artifact) -> bool {
    if version != pinned.version {
        return false;
    }
    let Ok(version_dir) = tool_dir.open_managed_dir(&rel(version)) else {
        return false;
    };
    version_dir
        .read_bytes(&rel(tool.file()))
        .is_ok_and(|bytes| hex_digest(&Sha256::digest(bytes)) == pinned.sha256)
}

fn read_selection(ctx: &Context<'_>) -> BTreeMap<String, String> {
    let Ok(scope) = ctx.engine_state.open_managed_dir(&rel("tools")) else {
        return BTreeMap::new();
    };
    scope
        .read_to_string(&rel(SELECTION_FILE))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

fn write_selection(scope: &ManagedRoot, selection: &BTreeMap<String, String>) -> Result<(), Error> {
    let body = serde_json::to_vec_pretty(selection).map_err(|e| Error::Io(io::Error::other(e)))?;
    scope
        .write_atomic(&rel(SELECTION_FILE), &body)
        .map_err(Error::Write)
}

pub fn status(ctx: &Context<'_>, tools_dir: &str) -> StatusReport {
    let selection = read_selection(ctx);
    let tools = Tool::ALL
        .iter()
        .map(|&tool| {
            let pinned = (ctx.catalog)(tool);
            let tool_dir = ctx.tools_root.open_managed_dir(&rel(tool.name())).ok();
            let installed_version = tool_dir.as_ref().and_then(current_version);
            let intact = match (&tool_dir, &installed_version) {
                (Some(dir), Some(version)) => intact(tool, dir, version, &pinned),
                _ => false,
            };
            ToolStatus {
                tool: tool.name().to_owned(),
                pinned_version: pinned.version,
                installed_version,
                selected: selection.contains_key(tool.name()),
                intact,
            }
        })
        .collect();
    StatusReport {
        tools_dir: tools_dir.to_owned(),
        tools,
    }
}

fn install(
    ctx: &Context<'_>,
    tool: Tool,
    req_id: RequestId,
    pre_commit: PreCommit,
) -> Result<ToolResult, Error> {
    let artifact = (ctx.catalog)(tool);
    ctx.tools_root
        .create_dir_all(&rel(tool.name()))
        .map_err(Error::Write)?;
    let tool_dir = ctx
        .tools_root
        .open_managed_dir(&rel(tool.name()))
        .map_err(Error::Write)?;

    if let Some(version) = current_version(&tool_dir) {
        if intact(tool, &tool_dir, &version, &artifact) {
            return Ok(result(tool, false, Some(version)));
        }
    }

    let bytes = (ctx.fetch)(&artifact.url).map_err(Error::Fetch)?;
    if hex_digest(&Sha256::digest(&bytes)) != artifact.sha256 {
        return Err(Error::DigestMismatch);
    }
    if !tool.looks_valid(&bytes) {
        return Err(Error::NotTheExpectedArtifact);
    }

    pre_commit.check().map_err(|_| Error::Cancelled)?;
    let _post_commit = pre_commit.commit();

    let version = rel(&artifact.version);
    if tool_dir.exists(&version) {
        tool_dir.remove_dir_all(&version).map_err(Error::Write)?;
    }
    tool_dir.create_dir_all(&version).map_err(Error::Write)?;
    tool_dir
        .open_managed_dir(&version)
        .and_then(|dir| dir.write_new_executable(&rel(tool.file()), &bytes))
        .map_err(Error::Write)?;

    // Same-directory atomic switch of the relative `current` symlink.
    let staged = rel(format!("{CURRENT}.new-{req_id}"));
    let _ = tool_dir.remove_file(&staged);
    tool_dir
        .symlink_relative(&staged, Path::new(&artifact.version))
        .map_err(Error::Write)?;
    tool_dir
        .rename(&staged, &rel(CURRENT))
        .map_err(Error::Write)?;

    // Old versions are no longer referenced; best effort.
    if let Ok(entries) = tool_dir.child_entries() {
        for entry in entries {
            let Some(name) = entry.name.to_str() else {
                continue;
            };
            if entry.is_dir && name != artifact.version {
                let _ = tool_dir.remove_dir_all(&rel(name));
            }
        }
    }
    Ok(result(tool, true, Some(artifact.version)))
}

fn remove(ctx: &Context<'_>, tool: Tool, pre_commit: PreCommit) -> Result<ToolResult, Error> {
    pre_commit.check().map_err(|_| Error::Cancelled)?;
    let _post_commit = pre_commit.commit();
    let name = rel(tool.name());
    if !ctx.tools_root.exists(&name) {
        return Ok(result(tool, false, None));
    }
    let tool_dir = ctx
        .tools_root
        .open_managed_dir(&name)
        .map_err(Error::Write)?;
    let previous = current_version(&tool_dir);
    // Unlink `current` first so nothing is left half-referenced.
    let _ = tool_dir.remove_file(&rel(CURRENT));
    ctx.tools_root.remove_dir_all(&name).map_err(Error::Write)?;
    Ok(result(tool, true, previous))
}

#[derive(Clone, Copy)]
pub enum Action {
    Install,
    Remove,
}

impl Action {
    const fn operation(self) -> &'static str {
        match self {
            Self::Install => INSTALL,
            Self::Remove => REMOVE,
        }
    }
}

pub fn execute(
    ctx: &Context<'_>,
    action: Action,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<ToolResult, Error> {
    let operation = action.operation();
    let scope_path = rel("tools");
    ctx.engine_state
        .create_dir_all(&scope_path)
        .map_err(Error::Io)?;
    let scope = ctx
        .engine_state
        .open_managed_dir(&scope_path)
        .map_err(Error::Io)?;
    for child in ["locks", "transactions", "audit"] {
        scope.create_dir_all(&rel(child)).map_err(Error::Io)?;
    }
    let admitted = match preflight::run(
        &scope,
        req.request_id,
        req.idempotency_key.as_ref(),
        operation,
    )
    .map_err(Error::Preflight)?
    {
        preflight::Outcome::Replay(id) => return replay(&scope, id, operation),
        preflight::Outcome::Proceed(value) => value,
    };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path = rel(format!("transactions/{}.json", req.request_id));
    let audit_path = rel("audit/events.jsonl");

    let pre_commit = PreCommit::new(cancel.clone());
    let outcome = match action {
        Action::Install => install(ctx, req.tool, req.request_id, pre_commit),
        Action::Remove => remove(ctx, req.tool, pre_commit),
    };
    let done = match outcome {
        Ok(value) => value,
        Err(error) => return Err(fail(&scope, &state_path, &audit_path, state, error)),
    };

    // The selection follows the committed filesystem change.
    let mut selection = read_selection(ctx);
    match action {
        Action::Install => {
            if let Some(version) = &done.version {
                selection.insert(req.tool.name().to_owned(), version.clone());
            }
        }
        Action::Remove => {
            selection.remove(req.tool.name());
        }
    }
    let selection_saved = write_selection(&scope, &selection);

    state
        .mark_committed(serde_json::to_value(&done).unwrap())
        .unwrap();
    if selection_saved.is_err() || state::save(&scope, &state_path, &state).is_err() {
        drop(lock);
        return Err(Error::PostCommit { result: done });
    }
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(req.request_id, true, None),
    );
    drop(lock);
    Ok(done)
}

fn replay(scope: &ManagedRoot, id: RequestId, operation: &str) -> Result<ToolResult, Error> {
    let path = rel(format!("transactions/{id}.json"));
    let loaded = state::load(scope, &path)
        .map_err(|error| Error::Io(io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != operation {
        return Err(Error::Io(io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => {
            serde_json::from_value(loaded.outcome.unwrap().result.unwrap())
                .map_err(|error| Error::Io(io::Error::other(error)))
        }
        TransactionStatus::Failed => {
            let outcome = loaded.outcome.unwrap();
            Err(Error::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}

fn fail(
    scope: &ManagedRoot,
    state_path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut state: crate::transaction::state::TransactionState,
    error: Error,
) -> Error {
    let (code, message) = error.protocol();
    let _ = state.mark_failed(code, message);
    let _ = state::save(scope, state_path, &state);
    let _ = audit::append(
        scope,
        audit_path,
        &AuditRecord::result(state.request_id, false, Some(code)),
    );
    error
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{cell::Cell, fs, os::unix::fs::PermissionsExt, path::PathBuf};

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const ID_2: &str = "123e4567-e89b-12d3-a456-426614174001";
    const ID_3: &str = "123e4567-e89b-12d3-a456-426614174002";
    const VERSION: &str = "9.9.9";

    fn managed(directory: &Path) -> ManagedRoot {
        ManagedRoot::open(&crate::site::TrustedRoot::parse(directory).unwrap()).unwrap()
    }

    fn phar(body: &str) -> Vec<u8> {
        format!("#!/usr/bin/env php\n<?php {body} __HALT_COMPILER();").into_bytes()
    }

    struct Host {
        dir: tempfile::TempDir,
    }

    impl Host {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            for sub in ["state", "tools"] {
                fs::create_dir(dir.path().join(sub)).unwrap();
            }
            Self { dir }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.dir.path().join(name)
        }

        /// `pinned` is the artifact the catalog claims; `served` is what the
        /// fake download returns.
        fn run(
            &self,
            action: Action,
            pinned: &[u8],
            served: &[u8],
            id: &str,
            key: Option<&str>,
            fetches: &Cell<u32>,
        ) -> Result<ToolResult, Error> {
            let state = managed(&self.path("state"));
            let tools = managed(&self.path("tools"));
            let sha256 = hex_digest(&Sha256::digest(pinned));
            let catalog = |_: Tool| Artifact {
                version: VERSION.into(),
                url: "https://downloads.example.test/wp.phar".into(),
                sha256: sha256.clone(),
            };
            let fetch = |_: &str| {
                fetches.set(fetches.get() + 1);
                Ok(served.to_vec())
            };
            execute(
                &Context {
                    engine_state: &state,
                    tools_root: &tools,
                    catalog: &catalog,
                    fetch: &fetch,
                },
                action,
                &Request::parse("wp-cli", id, key).unwrap(),
                &CancellationToken::default(),
            )
        }

        fn status(&self, pinned: &[u8]) -> StatusReport {
            let state = managed(&self.path("state"));
            let tools = managed(&self.path("tools"));
            let sha256 = hex_digest(&Sha256::digest(pinned));
            let catalog = |_: Tool| Artifact {
                version: VERSION.into(),
                url: String::new(),
                sha256: sha256.clone(),
            };
            let fetch = |_: &str| unreachable!("status never downloads");
            status(
                &Context {
                    engine_state: &state,
                    tools_root: &tools,
                    catalog: &catalog,
                    fetch: &fetch,
                },
                "/t",
            )
        }
    }

    #[test]
    fn the_catalog_is_well_formed() {
        for tool in Tool::ALL {
            let artifact = tool.pinned();
            assert_eq!(artifact.sha256.len(), 64);
            assert!(artifact.sha256.bytes().all(|c| c.is_ascii_hexdigit()));
            assert!(
                artifact
                    .url
                    .starts_with("https://github.com/wp-cli/wp-cli/releases/")
            );
            assert!(artifact.url.contains(&artifact.version));
            assert_eq!(Tool::parse(tool.name()), Some(*tool));
        }
        assert_eq!(Tool::parse("../wp-cli"), None);
        assert_eq!(Tool::parse("drush"), None);
    }

    #[test]
    fn installs_the_verified_tool_then_replays() {
        let host = Host::new();
        let bytes = phar("echo 1;");
        let fetches = Cell::new(0);

        let first = host
            .run(Action::Install, &bytes, &bytes, ID, Some("k"), &fetches)
            .unwrap();
        let second = host
            .run(Action::Install, &bytes, &bytes, ID_2, Some("k"), &fetches)
            .unwrap();

        assert!(first.changed);
        assert_eq!(first.version.as_deref(), Some(VERSION));
        assert_eq!(first.completed_at_unix_secs, second.completed_at_unix_secs);
        assert_eq!(fetches.get(), 1);
        let installed = host.path("tools/wp-cli/current/wp.phar");
        assert_eq!(fs::read(&installed).unwrap(), bytes);
        assert_eq!(
            fs::metadata(&installed).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(
            fs::read_link(host.path("tools/wp-cli/current")).unwrap(),
            Path::new(VERSION)
        );

        let report = host.status(&bytes);
        assert_eq!(
            report.tools,
            vec![ToolStatus {
                tool: "wp-cli".into(),
                pinned_version: VERSION.into(),
                installed_version: Some(VERSION.into()),
                selected: true,
                intact: true,
            }]
        );
    }

    #[test]
    fn a_second_install_with_a_new_id_is_a_no_op_when_intact() {
        let host = Host::new();
        let bytes = phar("echo 1;");
        let fetches = Cell::new(0);
        host.run(Action::Install, &bytes, &bytes, ID, None, &fetches)
            .unwrap();
        let again = host
            .run(Action::Install, &bytes, &bytes, ID_2, None, &fetches)
            .unwrap();
        assert!(!again.changed);
        assert_eq!(fetches.get(), 1);
    }

    #[test]
    fn a_damaged_install_is_repaired_and_stale_versions_are_pruned() {
        let host = Host::new();
        let bytes = phar("echo 1;");
        let fetches = Cell::new(0);
        host.run(Action::Install, &bytes, &bytes, ID, None, &fetches)
            .unwrap();
        fs::create_dir(host.path("tools/wp-cli/1.0.0")).unwrap();
        fs::write(host.path("tools/wp-cli/current/wp.phar.tmp"), b"x").ok();
        fs::write(host.path("tools/wp-cli/9.9.9/wp.phar"), b"corrupt").unwrap();
        assert!(!host.status(&bytes).tools[0].intact);

        let repaired = host
            .run(Action::Install, &bytes, &bytes, ID_2, None, &fetches)
            .unwrap();

        assert!(repaired.changed);
        assert_eq!(fetches.get(), 2);
        assert!(host.status(&bytes).tools[0].intact);
        assert!(!host.path("tools/wp-cli/1.0.0").exists());
    }

    #[test]
    fn a_digest_mismatch_installs_nothing_and_replays_its_error() {
        let host = Host::new();
        let fetches = Cell::new(0);
        let pinned = phar("echo 1;");
        let served = phar("echo EVIL;");

        let first = host
            .run(Action::Install, &pinned, &served, ID, Some("k"), &fetches)
            .unwrap_err();
        assert!(matches!(first, Error::DigestMismatch));
        assert_eq!(first.protocol().0, ErrorCode::ArtifactVerificationFailed);
        assert!(!host.path("tools/wp-cli/current").exists());

        let replayed = host
            .run(Action::Install, &pinned, &served, ID_2, Some("k"), &fetches)
            .unwrap_err();
        assert!(matches!(
            replayed,
            Error::Replayed {
                code: ErrorCode::ArtifactVerificationFailed,
                ..
            }
        ));
        assert_eq!(fetches.get(), 1);
    }

    #[test]
    fn a_pinned_file_that_is_not_a_phar_is_refused() {
        let host = Host::new();
        let html = b"<html>not found</html>".to_vec();
        let error = host
            .run(Action::Install, &html, &html, ID, None, &Cell::new(0))
            .unwrap_err();
        assert!(matches!(error, Error::NotTheExpectedArtifact));
        assert!(!host.path("tools/wp-cli/current").exists());
    }

    #[test]
    fn a_failed_download_is_reported_without_touching_the_host() {
        let host = Host::new();
        let state = managed(&host.path("state"));
        let tools = managed(&host.path("tools"));
        let catalog = |tool: Tool| tool.pinned();
        let fetch = |_: &str| Err(fetch::Error::Timeout);
        let error = execute(
            &Context {
                engine_state: &state,
                tools_root: &tools,
                catalog: &catalog,
                fetch: &fetch,
            },
            Action::Install,
            &Request::parse("wp-cli", ID, None).unwrap(),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert_eq!(error.protocol().0, ErrorCode::Timeout);
        assert!(!host.path("tools/wp-cli/current").exists());
    }

    #[test]
    fn remove_deletes_the_tool_clears_the_selection_and_is_idempotent() {
        let host = Host::new();
        let bytes = phar("echo 1;");
        host.run(Action::Install, &bytes, &bytes, ID, None, &Cell::new(0))
            .unwrap();

        let removed = host
            .run(
                Action::Remove,
                &bytes,
                &bytes,
                ID_2,
                Some("rm"),
                &Cell::new(0),
            )
            .unwrap();
        assert!(removed.changed);
        assert_eq!(removed.version.as_deref(), Some(VERSION));
        assert!(!host.path("tools/wp-cli").exists());
        assert!(!host.status(&bytes).tools[0].selected);

        let again = host
            .run(Action::Remove, &bytes, &bytes, ID_3, None, &Cell::new(0))
            .unwrap();
        assert!(!again.changed);
    }

    #[test]
    fn structural_checks_refuse_look_alikes() {
        assert!(Tool::WpCli.looks_valid(&phar("echo 1;")));
        assert!(!Tool::WpCli.looks_valid(b"<html>not found</html>"));
        assert!(!Tool::WpCli.looks_valid(b"#!/usr/bin/env php\n<?php echo 1;"));
    }

    #[test]
    fn requests_reject_unknown_tools_and_bad_ids() {
        assert!(matches!(
            Request::parse("drush", ID, None),
            Err(RequestError::UnknownTool)
        ));
        assert!(matches!(
            Request::parse("wp-cli", "nope", None),
            Err(RequestError::InvalidRequestId)
        ));
        assert!(matches!(
            Request::parse("wp-cli", ID, Some("bad key")),
            Err(RequestError::InvalidIdempotencyKey)
        ));
    }
}
