//! `system.installDocker`: installs Docker Engine and Compose v2 from the
//! official Docker apt repository on an allowlisted Debian/Ubuntu host.
//! Replaces the panel's distro-specific raw-SSH `setup_install` script,
//! which fetched Docker's signing key at run time and trusted it unchecked,
//! treated an undetected OS as Debian, and mixed packages with any Docker
//! that was already there.
//!
//! - Only the releases in [`SUPPORTED`] on amd64/arm64 are accepted.
//!   Anything else is refused by name, never defaulted.
//! - Docker's signing key is compiled in ([`DOCKER_KEYRING`], fingerprint
//!   `9DC8 5822 9FC7 DD38 854A  E2D8 8D81 803C 0EBF CD88`) and must hash to
//!   [`DOCKER_KEYRING_SHA256`] before it is written. Nothing fetched at run
//!   time decides what apt trusts. Package versions are not pinned: apt
//!   installs the newest packages that key signs.
//! - A complete install from Docker's repository is a no-op, except that a
//!   stopped or disabled service is enabled and started. Any other Docker —
//!   `docker.io`, `podman-docker`, Compose v1, the distro `containerd`/
//!   `runc`, a snap or a stray binary — is refused and named. Nothing is
//!   replaced or removed.
//! - The repository file and key are removed again when apt fails before
//!   any Docker package is installed. After a partial install nothing is
//!   purged: a later request finishes it from the same engine-written
//!   repository, or refuses when that repository is not in place.

use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{
        self, CancellationToken, ProcessLimits, ProcessOutput, ProcessRequest, ProcessTermination,
        SubprocessDiagnostics,
    },
    site::SiteRelativePath,
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        commit::PreCommit,
        state::{self, TransactionStatus},
    },
};
use sha2::{Digest, Sha256};
use std::{
    io,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const OPERATION: &str = "system.installDocker";
pub const OS_RELEASE: &str = "/etc/os-release";
pub const KEYRINGS_DIR: &str = "/etc/apt/keyrings";
pub const SOURCES_DIR: &str = "/etc/apt/sources.list.d";
pub const SOURCES_LIST: &str = "/etc/apt/sources.list";
pub const KEYRING_NAME: &str = "docker.asc";
pub const SOURCE_NAME: &str = "docker.sources";

/// Docker's Debian/Ubuntu repository signing key, as published at
/// `https://download.docker.com/linux/{debian,ubuntu}/gpg`.
pub const DOCKER_KEYRING: &[u8] = include_bytes!("../assets/docker-archive-keyring.asc");
pub const DOCKER_KEYRING_SHA256: &str =
    "1500c1f56fa9e26b9b8f42452a553675796ade0807cdce11975eb98170b3a570";

/// Distribution `ID` → accepted `VERSION_CODENAME`s. A new release is
/// accepted only through a new engine release.
pub const SUPPORTED: &[(&str, &[&str])] = &[
    ("debian", &["bookworm", "trixie"]),
    ("ubuntu", &["jammy", "noble"]),
];
pub const ARCHITECTURES: &[&str] = &["amd64", "arm64"];

/// What a complete install from Docker's repository consists of.
pub const PACKAGES: &[&str] = &[
    "docker-ce",
    "docker-ce-cli",
    "containerd.io",
    "docker-buildx-plugin",
    "docker-compose-plugin",
];
/// Packages that conflict with [`PACKAGES`]: installing over them would
/// make apt remove or replace them.
pub const FOREIGN_PACKAGES: &[&str] = &[
    "docker.io",
    "docker-doc",
    "docker-compose",
    "docker-compose-v2",
    "podman-docker",
    "containerd",
    "runc",
];
/// A `docker` here is never one `docker-ce-cli` installed.
pub const UNOWNED_BINARIES: &[&str] = &["/usr/local/bin/docker", "/snap/bin/docker"];
/// Where `docker-ce-cli` puts `docker`; foreign only without that package.
pub const CLI_BINARIES: &[&str] = &["/usr/bin/docker", "/bin/docker"];

const PREREQUISITE: &str = "ca-certificates";
const REPOSITORY_HOST: &str = "download.docker.com";
const APT_LOCK_TIMEOUT: &str = "DPkg::Lock::Timeout=300";

pub struct Request {
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug)]
pub enum RequestError {
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl Request {
    pub fn parse(request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        Ok(Self {
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    Architecture,
    Inspect,
    Refresh,
    Prerequisites,
    Install,
    Enable,
    Verify,
}

impl Stage {
    fn message(self) -> &'static str {
        match self {
            Self::Architecture => "could not determine the host package architecture",
            Self::Inspect => "could not inspect the installed packages",
            Self::Refresh => "could not refresh the apt package index",
            Self::Prerequisites => "could not install ca-certificates",
            Self::Install => "could not install the Docker packages",
            Self::Enable => "could not enable and start the Docker service",
            Self::Verify => "Docker was installed but its daemon or Compose v2 did not respond",
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallResult {
    /// `installed || started`.
    pub changed: bool,
    /// This request installed (or finished installing) the packages.
    pub installed: bool,
    /// This request enabled and started the service.
    pub started: bool,
    pub distribution: String,
    pub codename: String,
    pub architecture: String,
    pub docker_version: String,
    pub compose_version: String,
    pub completed_at_unix_secs: u64,
}

pub struct Tools<'a> {
    pub apt_get: &'a str,
    pub dpkg: &'a str,
    pub dpkg_query: &'a str,
    pub systemctl: &'a str,
    pub docker: &'a str,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub os_release: &'a Path,
    /// Opened on [`KEYRINGS_DIR`]; only its [`KEYRING_NAME`] is written.
    pub keyrings_dir: &'a ManagedRoot,
    /// Opened on [`SOURCES_DIR`]; only its [`SOURCE_NAME`] is written.
    pub sources_dir: &'a ManagedRoot,
    pub sources_list: &'a Path,
    pub unowned_binaries: &'a [&'a Path],
    pub cli_binaries: &'a [&'a Path],
    pub keyring: &'a [u8],
    pub keyring_sha256: &'a str,
    pub tools: Tools<'a>,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Cancelled,
    UnsupportedHost(String),
    ForeignDocker(Vec<String>),
    ForeignRepository(Vec<String>),
    /// An engine-managed path holds content this engine did not write.
    UnmanagedFile(&'static str),
    PartialWithoutRepository,
    KeyringMismatch,
    Write(io::Error),
    Run(Stage, process::ProcessRunError),
    Rejected(Stage, SubprocessDiagnostics),
    /// apt failed after some Docker packages were installed. They were
    /// left in place; a new request finishes the install.
    PartialInstall(SubprocessDiagnostics),
    /// apt failed before any package was installed and the repository
    /// file or key this request wrote could not be removed again.
    RollbackFailed,
    PostCommit {
        result: Box<InstallResult>,
    },
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another Docker installation is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before Docker was installed".into(),
            ),
            Self::UnsupportedHost(detail) => (
                ErrorCode::UnsupportedPlatform,
                format!(
                    "Docker can only be installed on Debian 12/13 or Ubuntu 22.04/24.04 \
                     (amd64/arm64); this host is {detail}"
                ),
            ),
            Self::ForeignDocker(found) => (
                ErrorCode::Conflict,
                format!(
                    "Docker from another source is present ({}); remove it before installing \
                     Docker from the official repository",
                    found.join(", ")
                ),
            ),
            Self::ForeignRepository(files) => (
                ErrorCode::Conflict,
                format!(
                    "{REPOSITORY_HOST} is already configured in {}; remove it so the engine can \
                     manage the Docker repository",
                    files.join(", ")
                ),
            ),
            Self::UnmanagedFile(path) => (
                ErrorCode::Conflict,
                format!("{path} already exists with content the engine did not write"),
            ),
            Self::PartialWithoutRepository => (
                ErrorCode::Conflict,
                "Docker packages are partially installed, but not from the engine-managed \
                 repository; finish or remove them by hand"
                    .into(),
            ),
            Self::KeyringMismatch => (
                ErrorCode::ArtifactVerificationFailed,
                "the embedded Docker signing key does not match its pinned SHA-256".into(),
            ),
            Self::Write(_) => (
                ErrorCode::Internal,
                "could not write the Docker repository configuration".into(),
            ),
            Self::Run(stage, error) => (process::spawn_error_code(error), stage.message().into()),
            Self::Rejected(stage, diagnostics) => {
                (diagnostics_code(diagnostics), stage.message().into())
            }
            Self::PartialInstall(diagnostics) => (
                diagnostics_code(diagnostics),
                "the Docker packages were only partially installed and were left in place; \
                 run the installation again to finish it"
                    .into(),
            ),
            Self::RollbackFailed => (
                ErrorCode::Internal,
                "apt failed and the Docker repository configuration could not be removed again"
                    .into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit { .. } => (
                ErrorCode::Internal,
                "internal Docker installation error".into(),
            ),
        }
    }
}

fn diagnostics_code(diagnostics: &SubprocessDiagnostics) -> ErrorCode {
    if diagnostics.timed_out {
        ErrorCode::Timeout
    } else if diagnostics.cancelled {
        ErrorCode::Cancelled
    } else {
        ErrorCode::SubprocessFailed
    }
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

// ── subprocesses ─────────────────────────────────────────────────────────────

fn spawn(
    program: &str,
    args: &[&str],
    timeout: Duration,
    stage: Stage,
    cancel: &CancellationToken,
) -> Result<ProcessOutput, Error> {
    process::run(
        &ProcessRequest::new(program)
            .args(args)
            .env("DEBIAN_FRONTEND", "noninteractive"),
        &ProcessLimits {
            timeout,
            max_stdout_bytes: 64 * 1024,
            max_stderr_bytes: 64 * 1024,
        },
        cancel,
    )
    .map_err(|error| Error::Run(stage, error))
}

fn succeeded(output: &ProcessOutput) -> bool {
    matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    )
}

/// Runs `program` and returns its trimmed stdout, or `Rejected` on failure.
fn run_checked(
    program: &str,
    args: &[&str],
    timeout: Duration,
    stage: Stage,
    cancel: &CancellationToken,
) -> Result<String, Error> {
    let output = spawn(program, args, timeout, stage, cancel)?;
    if !succeeded(&output) {
        return Err(Error::Rejected(
            stage,
            SubprocessDiagnostics::from_output(program, &output),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout.bytes)
        .trim()
        .to_owned())
}

fn apt(
    ctx: &Context<'_>,
    stage: Stage,
    args: &[&str],
    cancel: &CancellationToken,
) -> Result<ProcessOutput, Error> {
    let mut argv = vec![
        "-o",
        APT_LOCK_TIMEOUT,
        "-o",
        "Dpkg::Options::=--force-confdef",
        "-o",
        "Dpkg::Options::=--force-confold",
    ];
    argv.extend_from_slice(args);
    spawn(
        ctx.tools.apt_get,
        &argv,
        Duration::from_secs(20 * 60),
        stage,
        cancel,
    )
}

fn apt_checked(
    ctx: &Context<'_>,
    stage: Stage,
    args: &[&str],
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let output = apt(ctx, stage, args, cancel)?;
    if !succeeded(&output) {
        return Err(Error::Rejected(
            stage,
            SubprocessDiagnostics::from_output(ctx.tools.apt_get, &output),
        ));
    }
    Ok(())
}

fn install_args() -> Vec<&'static str> {
    let mut args = vec!["install", "-y"];
    args.extend_from_slice(PACKAGES);
    args
}

// ── detection ────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Host {
    pub distribution: String,
    pub codename: String,
    pub architecture: String,
}

/// `KEY=value` lookup in `os-release(5)` syntax, unquoting the value.
fn os_release_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines().find_map(|line| {
        let value = line.trim().strip_prefix(key)?.strip_prefix('=')?;
        let value = value.trim();
        let unquoted = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(value);
        Some(unquoted)
    })
}

pub fn supported_release(os_release: &str) -> Result<(String, String), String> {
    let id = os_release_value(os_release, "ID").unwrap_or_default();
    let codename = os_release_value(os_release, "VERSION_CODENAME").unwrap_or_default();
    let describe = || {
        if id.is_empty() {
            "an unidentified distribution".to_owned()
        } else if codename.is_empty() {
            format!("{id} without a release codename")
        } else {
            format!("{id} {codename}")
        }
    };
    let codenames = SUPPORTED
        .iter()
        .find(|(supported, _)| *supported == id)
        .map(|(_, codenames)| *codenames)
        .ok_or_else(describe)?;
    if !codenames.contains(&codename) {
        return Err(describe());
    }
    Ok((id.to_owned(), codename.to_owned()))
}

fn detect(ctx: &Context<'_>, cancel: &CancellationToken) -> Result<Host, Error> {
    let os_release = std::fs::read_to_string(ctx.os_release).map_err(|_| {
        Error::UnsupportedHost(format!("missing a readable {}", ctx.os_release.display()))
    })?;
    let (distribution, codename) =
        supported_release(&os_release).map_err(Error::UnsupportedHost)?;
    let architecture = run_checked(
        ctx.tools.dpkg,
        &["--print-architecture"],
        Duration::from_secs(30),
        Stage::Architecture,
        cancel,
    )?;
    if !ARCHITECTURES.contains(&architecture.as_str()) {
        return Err(Error::UnsupportedHost(format!(
            "{distribution} {codename} on {architecture}"
        )));
    }
    Ok(Host {
        distribution,
        codename,
        architecture,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageState {
    Absent,
    /// Unpacked, half-configured, or otherwise not fully installed.
    Partial,
    Installed,
}

/// Parses `dpkg-query -W -f '${Package}\t${db:Status-Abbrev}\n'` output.
fn package_state(stdout: &str, package: &str) -> PackageState {
    stdout
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .find(|(name, _)| *name == package)
        .map_or(PackageState::Absent, |(_, abbrev)| {
            match abbrev.chars().nth(1) {
                Some('i') => PackageState::Installed,
                Some('n') | Some('c') | None => PackageState::Absent,
                Some(_) => PackageState::Partial,
            }
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Inventory {
    Absent,
    Partial,
    Complete,
}

fn inspect(ctx: &Context<'_>, cancel: &CancellationToken) -> Result<Inventory, Error> {
    let mut args = vec!["-W", "-f", "${Package}\\t${db:Status-Abbrev}\\n", "--"];
    args.extend_from_slice(PACKAGES);
    args.extend_from_slice(FOREIGN_PACKAGES);
    let output = spawn(
        ctx.tools.dpkg_query,
        &args,
        Duration::from_secs(60),
        Stage::Inspect,
        cancel,
    )?;
    // Exit status 1 only means some of the named packages are unknown.
    if !matches!(
        output.termination,
        ProcessTermination::Exited {
            code: Some(0 | 1),
            ..
        }
    ) {
        return Err(Error::Rejected(
            Stage::Inspect,
            SubprocessDiagnostics::from_output(ctx.tools.dpkg_query, &output),
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout.bytes);

    let cli_present = package_state(&stdout, "docker-ce-cli") != PackageState::Absent;
    let mut foreign: Vec<String> = FOREIGN_PACKAGES
        .iter()
        .filter(|package| package_state(&stdout, package) != PackageState::Absent)
        .map(|package| (*package).to_owned())
        .collect();
    let binaries = ctx.unowned_binaries.iter().chain(if cli_present {
        &[][..]
    } else {
        ctx.cli_binaries
    });
    for binary in binaries {
        if std::fs::symlink_metadata(binary).is_ok() {
            foreign.push(binary.display().to_string());
        }
    }
    if !foreign.is_empty() {
        return Err(Error::ForeignDocker(foreign));
    }

    let states: Vec<PackageState> = PACKAGES
        .iter()
        .map(|package| package_state(&stdout, package))
        .collect();
    Ok(if states.iter().all(|s| *s == PackageState::Installed) {
        Inventory::Complete
    } else if states.iter().all(|s| *s == PackageState::Absent) {
        Inventory::Absent
    } else {
        Inventory::Partial
    })
}

// ── repository ───────────────────────────────────────────────────────────────

pub fn source_contents(host: &Host) -> String {
    format!(
        "# Managed by operations-engine ({OPERATION}). Do not edit.\n\
         Types: deb\n\
         URIs: https://{REPOSITORY_HOST}/linux/{}\n\
         Suites: {}\n\
         Components: stable\n\
         Architectures: {}\n\
         Signed-By: {KEYRINGS_DIR}/{KEYRING_NAME}\n",
        host.distribution, host.codename, host.architecture
    )
}

fn mentions_repository(contents: &[u8]) -> bool {
    String::from_utf8_lossy(contents)
        .lines()
        .any(|line| !line.trim_start().starts_with('#') && line.contains(REPOSITORY_HOST))
}

/// Every active apt source, other than the engine's own, that already
/// points at Docker's repository.
fn foreign_repositories(ctx: &Context<'_>) -> Result<Vec<String>, Error> {
    let mut found = Vec::new();
    match std::fs::read(ctx.sources_list) {
        Ok(contents) if mentions_repository(&contents) => {
            found.push(ctx.sources_list.display().to_string());
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(Error::Io(error)),
    }
    let mut names = ctx.sources_dir.file_names().map_err(Error::Io)?;
    names.sort();
    for name in names {
        if name == SOURCE_NAME || !(name.ends_with(".list") || name.ends_with(".sources")) {
            continue;
        }
        let path = SiteRelativePath::parse(name.as_str())
            .map_err(|_| Error::Io(io::Error::other("unexpected apt source file name")))?;
        let contents = ctx.sources_dir.read_bytes(&path).map_err(Error::Io)?;
        if mentions_repository(&contents) {
            found.push(format!("{SOURCES_DIR}/{name}"));
        }
    }
    Ok(found)
}

enum Existing {
    Missing,
    Matches,
    Differs,
}

fn existing(root: &ManagedRoot, path: &SiteRelativePath, wanted: &[u8]) -> Result<Existing, Error> {
    match root.read_bytes(path) {
        Ok(contents) if contents == wanted => Ok(Existing::Matches),
        Ok(_) => Ok(Existing::Differs),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Existing::Missing),
        Err(error) => Err(Error::Io(error)),
    }
}

fn write_public(root: &ManagedRoot, path: &SiteRelativePath, contents: &[u8]) -> io::Result<()> {
    root.write_atomic(path, contents)?;
    root.set_mode(path, 0o644)
}

/// The repository files this request created, removed again on rollback.
#[derive(Default)]
struct Written {
    keyring: bool,
    source: bool,
}

fn remove_written(ctx: &Context<'_>, written: &Written) -> Result<(), Error> {
    let mut ok = true;
    if written.source {
        ok &= ctx
            .sources_dir
            .remove_file(&SiteRelativePath::parse(SOURCE_NAME).unwrap())
            .is_ok();
    }
    if written.keyring {
        ok &= ctx
            .keyrings_dir
            .remove_file(&SiteRelativePath::parse(KEYRING_NAME).unwrap())
            .is_ok();
    }
    if ok {
        Ok(())
    } else {
        Err(Error::RollbackFailed)
    }
}

// ── install ──────────────────────────────────────────────────────────────────

/// Enables and starts the service unless it already is both; `true` when
/// it had to.
fn ensure_running(ctx: &Context<'_>, cancel: &CancellationToken) -> Result<bool, Error> {
    let probe = |args: &[&str]| -> Result<bool, Error> {
        spawn(
            ctx.tools.systemctl,
            args,
            Duration::from_secs(30),
            Stage::Enable,
            cancel,
        )
        .map(|output| succeeded(&output))
    };
    if probe(&["is-enabled", "--quiet", "docker"])? && probe(&["is-active", "--quiet", "docker"])? {
        return Ok(false);
    }
    run_checked(
        ctx.tools.systemctl,
        &["enable", "--now", "docker"],
        Duration::from_secs(2 * 60),
        Stage::Enable,
        cancel,
    )?;
    Ok(true)
}

/// Both the daemon and Compose v2 must answer; returns their versions.
fn verify(ctx: &Context<'_>, cancel: &CancellationToken) -> Result<(String, String), Error> {
    let docker = run_checked(
        ctx.tools.docker,
        &["info", "--format", "{{.ServerVersion}}"],
        Duration::from_secs(60),
        Stage::Verify,
        cancel,
    )?;
    let compose = run_checked(
        ctx.tools.docker,
        &["compose", "version", "--short"],
        Duration::from_secs(60),
        Stage::Verify,
        cancel,
    )?;
    Ok((docker, compose))
}

/// Installs [`PACKAGES`] onto a host with none of them yet, from a
/// repository this request configures and removes again on failure.
fn install_fresh(
    ctx: &Context<'_>,
    host: &Host,
    pre_commit: PreCommit,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    if hex_digest(&Sha256::digest(ctx.keyring)) != ctx.keyring_sha256 {
        return Err(Error::KeyringMismatch);
    }
    let keyring_path = SiteRelativePath::parse(KEYRING_NAME).unwrap();
    let source_path = SiteRelativePath::parse(SOURCE_NAME).unwrap();
    let source = source_contents(host);
    let keyring_state = existing(ctx.keyrings_dir, &keyring_path, ctx.keyring)?;
    if matches!(keyring_state, Existing::Differs) {
        return Err(Error::UnmanagedFile("/etc/apt/keyrings/docker.asc"));
    }
    let source_state = existing(ctx.sources_dir, &source_path, source.as_bytes())?;
    if matches!(source_state, Existing::Differs) {
        return Err(Error::UnmanagedFile(
            "/etc/apt/sources.list.d/docker.sources",
        ));
    }
    let foreign = foreign_repositories(ctx)?;
    if !foreign.is_empty() {
        return Err(Error::ForeignRepository(foreign));
    }

    pre_commit.check().map_err(|_| Error::Cancelled)?;
    let _post_commit = pre_commit.commit();

    apt_checked(ctx, Stage::Refresh, &["update"], cancel)?;
    apt_checked(
        ctx,
        Stage::Prerequisites,
        &["install", "-y", PREREQUISITE],
        cancel,
    )?;

    let mut written = Written::default();
    if matches!(keyring_state, Existing::Missing) {
        written.keyring = true;
        if let Err(error) = write_public(ctx.keyrings_dir, &keyring_path, ctx.keyring) {
            remove_written(ctx, &written)?;
            return Err(Error::Write(error));
        }
    }
    if matches!(source_state, Existing::Missing) {
        written.source = true;
        if let Err(error) = write_public(ctx.sources_dir, &source_path, source.as_bytes()) {
            remove_written(ctx, &written)?;
            return Err(Error::Write(error));
        }
    }

    if let Err(error) = apt_checked(ctx, Stage::Refresh, &["update"], cancel) {
        remove_written(ctx, &written)?;
        return Err(error);
    }
    let output = apt(ctx, Stage::Install, &install_args(), cancel)?;
    if succeeded(&output) {
        return Ok(());
    }
    let diagnostics = SubprocessDiagnostics::from_output(ctx.tools.apt_get, &output);
    match inspect(ctx, cancel) {
        Ok(Inventory::Absent) => {
            remove_written(ctx, &written)?;
            Err(Error::Rejected(Stage::Install, diagnostics))
        }
        _ => Err(Error::PartialInstall(diagnostics)),
    }
}

/// Finishes an install a previous request left partial, only from the
/// repository and key that request wrote.
fn finish_partial(
    ctx: &Context<'_>,
    host: &Host,
    pre_commit: PreCommit,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let keyring = existing(
        ctx.keyrings_dir,
        &SiteRelativePath::parse(KEYRING_NAME).unwrap(),
        ctx.keyring,
    )?;
    let source = existing(
        ctx.sources_dir,
        &SiteRelativePath::parse(SOURCE_NAME).unwrap(),
        source_contents(host).as_bytes(),
    )?;
    if !matches!((keyring, source), (Existing::Matches, Existing::Matches)) {
        return Err(Error::PartialWithoutRepository);
    }

    pre_commit.check().map_err(|_| Error::Cancelled)?;
    let _post_commit = pre_commit.commit();

    apt_checked(ctx, Stage::Refresh, &["update"], cancel)?;
    let output = apt(ctx, Stage::Install, &install_args(), cancel)?;
    if !succeeded(&output) {
        return Err(Error::PartialInstall(SubprocessDiagnostics::from_output(
            ctx.tools.apt_get,
            &output,
        )));
    }
    Ok(())
}

fn install(
    ctx: &Context<'_>,
    pre_commit: PreCommit,
    cancel: &CancellationToken,
) -> Result<InstallResult, Error> {
    let host = detect(ctx, cancel)?;
    let installed = match inspect(ctx, cancel)? {
        Inventory::Complete => {
            pre_commit.check().map_err(|_| Error::Cancelled)?;
            let _post_commit = pre_commit.commit();
            false
        }
        Inventory::Absent => {
            install_fresh(ctx, &host, pre_commit, cancel)?;
            true
        }
        Inventory::Partial => {
            finish_partial(ctx, &host, pre_commit, cancel)?;
            true
        }
    };
    let started = ensure_running(ctx, cancel)?;
    let (docker_version, compose_version) = verify(ctx, cancel)?;
    Ok(InstallResult {
        changed: installed || started,
        installed,
        started,
        distribution: host.distribution,
        codename: host.codename,
        architecture: host.architecture,
        docker_version,
        compose_version,
        completed_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    })
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<InstallResult, Error> {
    let scope_path = SiteRelativePath::parse("system-install-docker").unwrap();
    ctx.engine_state
        .create_dir_all(&scope_path)
        .map_err(Error::Io)?;
    let scope = ctx
        .engine_state
        .open_managed_dir(&scope_path)
        .map_err(Error::Io)?;
    for child in ["locks", "transactions", "audit"] {
        scope
            .create_dir_all(&SiteRelativePath::parse(child).unwrap())
            .map_err(Error::Io)?;
    }
    let admitted = match preflight::run(
        &scope,
        req.request_id,
        req.idempotency_key.as_ref(),
        OPERATION,
    )
    .map_err(Error::Preflight)?
    {
        preflight::Outcome::Replay(id) => return replay(&scope, id),
        preflight::Outcome::Proceed(value) => value,
    };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path =
        SiteRelativePath::parse(format!("transactions/{}.json", req.request_id)).unwrap();
    let audit_path = SiteRelativePath::parse("audit/events.jsonl").unwrap();

    let result = match install(ctx, PreCommit::new(cancel.clone()), cancel) {
        Ok(value) => value,
        Err(error) => return Err(fail(&scope, &state_path, &audit_path, state, error)),
    };
    state
        .mark_committed(serde_json::to_value(&result).unwrap())
        .unwrap();
    if state::save(&scope, &state_path, &state).is_err() {
        drop(lock);
        return Err(Error::PostCommit {
            result: Box::new(result),
        });
    }
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(req.request_id, true, None),
    );
    drop(lock);
    Ok(result)
}

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<InstallResult, Error> {
    let path = SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap();
    let loaded = state::load(scope, &path)
        .map_err(|error| Error::Io(io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != OPERATION {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const ID_2: &str = "123e4567-e89b-12d3-a456-426614174001";
    const NOBLE: &str = "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nID=ubuntu\nID_LIKE=debian\n\
                         VERSION_CODENAME=noble\nUBUNTU_CODENAME=noble\n";

    fn managed(directory: &Path) -> ManagedRoot {
        ManagedRoot::open(&crate::site::TrustedRoot::parse(directory).unwrap()).unwrap()
    }

    /// A fake host: `pkgs/<name>` holds a package's dpkg status
    /// abbreviation, `active` marks the running service, and `fail-*`
    /// files make the matching fake tool fail.
    struct Fixture {
        dir: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            for child in ["state", "keyrings", "sources", "pkgs", "bin"] {
                fs::create_dir(root.join(child)).unwrap();
            }
            fs::write(root.join("os-release"), NOBLE).unwrap();
            fs::write(root.join("arch"), "arm64\n").unwrap();
            let docker_packages = PACKAGES.join(" ");
            let p = root.display();
            Self::tool(
                root,
                "apt-get",
                &format!(
                    r#"echo "apt-get $*" >> '{p}/calls.log'
case " $* " in
  *" update "*) [ -e '{p}/fail-update' ] && exit 100; exit 0 ;;
  *" docker-ce "*) ;;
  *) exit 0 ;;
esac
[ -e '{p}/fail-install' ] && exit 100
for pkg in "$@"; do
  for ours in {docker_packages}; do
    [ "$pkg" = "$ours" ] || continue
    if [ -e '{p}/partial-install' ] && [ "$pkg" != docker-ce-cli ]; then continue; fi
    printf 'ii ' > '{p}/pkgs/'"$pkg"
  done
done
if [ -e '{p}/partial-install' ]; then rm '{p}/partial-install'; exit 100; fi
exit 0
"#
                ),
            );
            Self::tool(root, "dpkg", &format!("cat '{p}/arch'\n"));
            Self::tool(
                root,
                "dpkg-query",
                &format!(
                    r#"shift 4
missing=0
for pkg in "$@"; do
  if [ -e '{p}/pkgs/'"$pkg" ]; then printf '%s\t%s\n' "$pkg" "$(cat '{p}/pkgs/'"$pkg")"
  else echo "dpkg-query: no packages found matching $pkg" >&2; missing=1; fi
done
exit $missing
"#
                ),
            );
            Self::tool(
                root,
                "systemctl",
                &format!(
                    r#"echo "systemctl $*" >> '{p}/calls.log'
case "$1" in
  is-enabled|is-active) [ -e '{p}/active' ] ;;
  enable) [ -e '{p}/fail-enable' ] && exit 1; touch '{p}/active' ;;
esac
"#
                ),
            );
            Self::tool(
                root,
                "docker",
                &format!(
                    r#"[ -e '{p}/active' ] || exit 1
case "$1" in info) echo 28.5.0 ;; compose) echo 2.39.4 ;; esac
"#
                ),
            );
            Self { dir }
        }

        fn tool(root: &Path, name: &str, body: &str) {
            let path = root.join("bin").join(name);
            fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }

        fn path(&self, relative: &str) -> PathBuf {
            self.dir.path().join(relative)
        }

        fn touch(&self, relative: &str) {
            fs::write(self.path(relative), "").unwrap();
        }

        fn install_all(&self) {
            for package in PACKAGES {
                fs::write(self.path(&format!("pkgs/{package}")), "ii ").unwrap();
            }
        }

        fn calls(&self) -> String {
            fs::read_to_string(self.path("calls.log")).unwrap_or_default()
        }

        fn run(&self, id: &str) -> Result<InstallResult, Error> {
            self.run_with(id, None, DOCKER_KEYRING)
        }

        fn run_with(
            &self,
            id: &str,
            idempotency_key: Option<&str>,
            keyring: &[u8],
        ) -> Result<InstallResult, Error> {
            let state = managed(&self.path("state"));
            let keyrings = managed(&self.path("keyrings"));
            let sources = managed(&self.path("sources"));
            let tool = |name: &str| self.path(&format!("bin/{name}")).display().to_string();
            let (apt_get, dpkg, dpkg_query, systemctl, docker) = (
                tool("apt-get"),
                tool("dpkg"),
                tool("dpkg-query"),
                tool("systemctl"),
                tool("docker"),
            );
            let snap = self.path("snap-docker");
            let usr_bin = self.path("usr-bin-docker");
            let os_release = self.path("os-release");
            let sources_list = self.path("sources.list");
            let ctx = Context {
                engine_state: &state,
                os_release: &os_release,
                keyrings_dir: &keyrings,
                sources_dir: &sources,
                sources_list: &sources_list,
                unowned_binaries: &[&snap],
                cli_binaries: &[&usr_bin],
                keyring,
                keyring_sha256: DOCKER_KEYRING_SHA256,
                tools: Tools {
                    apt_get: &apt_get,
                    dpkg: &dpkg,
                    dpkg_query: &dpkg_query,
                    systemctl: &systemctl,
                    docker: &docker,
                },
            };
            let req = Request::parse(id, idempotency_key).unwrap();
            execute(&ctx, &req, &CancellationToken::default())
        }

        fn repository_written(&self) -> (bool, bool) {
            (
                self.path("keyrings/docker.asc").exists(),
                self.path("sources/docker.sources").exists(),
            )
        }
    }

    #[test]
    fn embedded_keyring_matches_its_pin() {
        assert_eq!(
            hex_digest(&Sha256::digest(DOCKER_KEYRING)),
            DOCKER_KEYRING_SHA256
        );
    }

    #[test]
    fn release_allowlist_refuses_everything_else() {
        assert_eq!(
            supported_release(NOBLE).unwrap(),
            ("ubuntu".to_owned(), "noble".to_owned())
        );
        assert!(supported_release("ID=debian\nVERSION_CODENAME=\"bookworm\"\n").is_ok());
        assert_eq!(
            supported_release("ID=ubuntu\nVERSION_CODENAME=focal\n").unwrap_err(),
            "ubuntu focal"
        );
        assert_eq!(
            supported_release("ID=fedora\nVERSION_ID=40\n").unwrap_err(),
            "fedora without a release codename"
        );
        // ID_LIKE=debian is not Debian.
        assert!(
            supported_release("ID=linuxmint\nID_LIKE=debian\nVERSION_CODENAME=noble\n").is_err()
        );
        assert_eq!(
            supported_release("").unwrap_err(),
            "an unidentified distribution"
        );
    }

    #[test]
    fn package_states_follow_the_dpkg_status_column() {
        let out = "docker-ce\tii \ndocker-ce-cli\tiU \ndocker.io\trc \n";
        assert_eq!(package_state(out, "docker-ce"), PackageState::Installed);
        assert_eq!(package_state(out, "docker-ce-cli"), PackageState::Partial);
        assert_eq!(package_state(out, "docker.io"), PackageState::Absent);
        assert_eq!(package_state(out, "runc"), PackageState::Absent);
    }

    #[test]
    fn fresh_install_configures_the_repository_installs_and_starts() {
        let fx = Fixture::new();
        let result = fx.run(ID).unwrap();
        assert!(result.changed && result.installed && result.started);
        assert_eq!(
            (result.distribution.as_str(), result.codename.as_str()),
            ("ubuntu", "noble")
        );
        assert_eq!(result.docker_version, "28.5.0");
        assert_eq!(result.compose_version, "2.39.4");
        assert_eq!(
            fs::read(fx.path("keyrings/docker.asc")).unwrap(),
            DOCKER_KEYRING
        );
        let source = fs::read_to_string(fx.path("sources/docker.sources")).unwrap();
        assert!(source.contains("URIs: https://download.docker.com/linux/ubuntu\n"));
        assert!(source.contains("Suites: noble\n"));
        assert!(source.contains("Architectures: arm64\n"));
        assert_eq!(
            fs::metadata(fx.path("keyrings/docker.asc"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        let calls = fx.calls();
        assert!(calls.contains("install -y ca-certificates\n"));
        assert!(calls.contains(&format!("install -y {}\n", PACKAGES.join(" "))));
        assert!(calls.contains("systemctl enable --now docker\n"));
    }

    #[test]
    fn complete_running_install_is_a_no_op() {
        let fx = Fixture::new();
        fx.run(ID).unwrap();
        let before = fx.calls();
        let result = fx.run(ID_2).unwrap();
        assert!(!result.changed && !result.installed && !result.started);
        let after = fx.calls();
        assert!(!after[before.len()..].contains("apt-get"));
        assert!(!after[before.len()..].contains("enable --now"));
    }

    #[test]
    fn same_request_replays_without_running_anything() {
        let fx = Fixture::new();
        fx.run_with(ID, Some("install-docker"), DOCKER_KEYRING)
            .unwrap();
        let before = fx.calls();
        let replayed = fx
            .run_with(ID, Some("install-docker"), DOCKER_KEYRING)
            .unwrap();
        assert!(replayed.installed);
        assert_eq!(fx.calls(), before);
    }

    #[test]
    fn stopped_docker_from_the_repository_is_started() {
        let fx = Fixture::new();
        fx.install_all();
        let result = fx.run(ID).unwrap();
        assert!(result.changed && result.started && !result.installed);
        assert!(!fx.calls().contains("apt-get"));
        assert_eq!(fx.repository_written(), (false, false));
    }

    #[test]
    fn unsupported_hosts_are_refused_before_anything_runs() {
        for (os_release, arch) in [
            ("ID=ubuntu\nVERSION_CODENAME=focal\n", "amd64"),
            ("ID=fedora\nVERSION_ID=40\n", "amd64"),
            (NOBLE, "armhf"),
        ] {
            let fx = Fixture::new();
            fs::write(fx.path("os-release"), os_release).unwrap();
            fs::write(fx.path("arch"), arch).unwrap();
            let error = fx.run(ID).unwrap_err();
            assert!(matches!(error, Error::UnsupportedHost(_)), "{error:?}");
            assert_eq!(error.protocol().0, ErrorCode::UnsupportedPlatform);
            assert_eq!(fx.calls(), "");
            assert_eq!(fx.repository_written(), (false, false));
        }
        let fx = Fixture::new();
        fs::remove_file(fx.path("os-release")).unwrap();
        assert!(matches!(fx.run(ID), Err(Error::UnsupportedHost(_))));
    }

    #[test]
    fn foreign_docker_is_refused_and_named() {
        let fx = Fixture::new();
        fs::write(fx.path("pkgs/docker.io"), "ii ").unwrap();
        fs::write(fx.path("pkgs/docker-compose"), "ii ").unwrap();
        match fx.run(ID) {
            Err(Error::ForeignDocker(found)) => {
                assert_eq!(found, ["docker.io", "docker-compose"])
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(fx.calls(), "");
        assert_eq!(fx.repository_written(), (false, false));
    }

    #[test]
    fn foreign_binaries_are_refused() {
        let fx = Fixture::new();
        fx.touch("snap-docker");
        assert!(matches!(fx.run(ID), Err(Error::ForeignDocker(_))));

        // A /usr/bin/docker without docker-ce-cli is foreign; with it, it
        // is the package's own.
        let fx = Fixture::new();
        fx.touch("usr-bin-docker");
        assert!(matches!(fx.run(ID), Err(Error::ForeignDocker(_))));
        fx.install_all();
        fx.run(ID_2).unwrap();
    }

    #[test]
    fn removed_package_with_leftover_config_is_not_foreign() {
        let fx = Fixture::new();
        fs::write(fx.path("pkgs/docker.io"), "rc ").unwrap();
        assert!(fx.run(ID).unwrap().installed);
    }

    #[test]
    fn tampered_keyring_is_refused_before_anything_is_written() {
        let fx = Fixture::new();
        let mut tampered = DOCKER_KEYRING.to_vec();
        tampered[100] ^= 1;
        let error = fx.run_with(ID, None, &tampered).unwrap_err();
        assert!(matches!(error, Error::KeyringMismatch));
        assert_eq!(error.protocol().0, ErrorCode::ArtifactVerificationFailed);
        assert_eq!(fx.calls(), "");
        assert_eq!(fx.repository_written(), (false, false));
    }

    #[test]
    fn existing_docker_repository_elsewhere_is_refused() {
        let fx = Fixture::new();
        fs::write(
            fx.path("sources/docker.list"),
            "deb [signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu noble stable\n",
        )
        .unwrap();
        match fx.run(ID) {
            Err(Error::ForeignRepository(files)) => {
                assert_eq!(files, ["/etc/apt/sources.list.d/docker.list"])
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(fx.repository_written(), (false, false));
    }

    #[test]
    fn commented_out_docker_repository_is_ignored() {
        let fx = Fixture::new();
        fs::write(
            fx.path("sources.list"),
            "# deb https://download.docker.com/linux/ubuntu noble stable\n",
        )
        .unwrap();
        fx.run(ID).unwrap();
    }

    #[test]
    fn unmanaged_keyring_at_the_engine_path_is_refused() {
        let fx = Fixture::new();
        fs::write(fx.path("keyrings/docker.asc"), "someone else's key").unwrap();
        assert!(matches!(fx.run(ID), Err(Error::UnmanagedFile(_))));
        assert_eq!(
            fs::read_to_string(fx.path("keyrings/docker.asc")).unwrap(),
            "someone else's key"
        );
        assert!(!fx.path("sources/docker.sources").exists());
    }

    #[test]
    fn failed_refresh_removes_the_repository_again() {
        let fx = Fixture::new();
        // The first `apt-get update` (distro index) must pass, the one
        // after the repository is written must fail.
        let apt = fx.path("bin/apt-get");
        let script = fs::read_to_string(&apt).unwrap().replace(
            &format!(
                "[ -e '{}/fail-update' ] && exit 100",
                fx.dir.path().display()
            ),
            &format!(
                "[ -e '{0}/sources/docker.sources' ] && [ -e '{0}/fail-update' ] && exit 100",
                fx.dir.path().display()
            ),
        );
        fs::write(&apt, script).unwrap();
        fx.touch("fail-update");
        assert!(matches!(
            fx.run(ID),
            Err(Error::Rejected(Stage::Refresh, _))
        ));
        assert_eq!(fx.repository_written(), (false, false));
    }

    #[test]
    fn failed_install_with_nothing_installed_removes_the_repository() {
        let fx = Fixture::new();
        fx.touch("fail-install");
        assert!(matches!(
            fx.run(ID),
            Err(Error::Rejected(Stage::Install, _))
        ));
        assert_eq!(fx.repository_written(), (false, false));
    }

    #[test]
    fn partial_install_is_left_in_place_and_finished_by_the_next_request() {
        let fx = Fixture::new();
        fx.touch("partial-install");
        let error = fx.run(ID).unwrap_err();
        assert!(matches!(error, Error::PartialInstall(_)), "{error:?}");
        assert_eq!(fx.repository_written(), (true, true));
        assert!(fx.path("pkgs/docker-ce-cli").exists());

        let result = fx.run(ID_2).unwrap();
        assert!(result.installed && result.started);
        for package in PACKAGES {
            assert!(fx.path(&format!("pkgs/{package}")).exists(), "{package}");
        }
    }

    #[test]
    fn partial_install_from_elsewhere_is_refused() {
        let fx = Fixture::new();
        fs::write(fx.path("pkgs/docker-ce-cli"), "ii ").unwrap();
        assert!(matches!(fx.run(ID), Err(Error::PartialWithoutRepository)));
        assert!(!fx.calls().contains("apt-get"));
    }

    #[test]
    fn service_that_does_not_start_fails_without_removing_packages() {
        let fx = Fixture::new();
        fx.touch("fail-enable");
        assert!(matches!(fx.run(ID), Err(Error::Rejected(Stage::Enable, _))));
        assert!(fx.path("pkgs/docker-ce").exists());
        assert_eq!(fx.repository_written(), (true, true));
    }
}
