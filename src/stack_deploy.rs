//! `stack.deploy`: replaces the managed WCP Compose stack's eight files
//! (`stack/docker-compose.yml`, six support files and `.env`) and converges
//! the running containers onto them as one lock/idempotency/transaction/
//! audit-backed request.
//!
//! The caller owns the file contents (the image catalog lives with the
//! control panel), but the engine owns everything that runs as root: the
//! fixed path set, the image policy (every image must be a digest-pinned
//! `ghcr.io/local-control-panel/...` reference), validation and pull against
//! staged copies before anything live changes, activation with a durable
//! journal, the health gate, and the automatic rollback when the new stack
//! does not come up.
//!
//! Sequence:
//!
//! 1. finish an interrupted predecessor, if its journal is still present:
//!    restore its previous files, bring them up and mark it failed;
//! 2. stage every file as `<path>.new` (`.env` owner-only);
//! 3. `docker compose config --quiet`, the image policy over every profile
//!    (`--profile '*' config --images`) and `pull`, all on the staged files;
//! 4. write the journal, back up each previous file to
//!    `<path>.rollback-<request id>`, rename each staged file into place;
//! 5. `up -d`; ingress must publish `443/tcp` (one plain retry, then a
//!    forced ingress recreate, because Docker can drop a lost port-bind
//!    race silently); every deployed service must be `running` and, if it
//!    has a healthcheck, `healthy` within the health bound;
//! 6. any failure in 5 restores the previous files and brings them up
//!    again — or, on a first deploy, takes the new containers down (never
//!    their volumes) and removes the new files.

use std::{
    io,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{
        self, CancellationToken, ProcessLimits, ProcessOutput, ProcessRequest, ProcessRunError,
        ProcessTermination, SubprocessDiagnostics,
    },
    site::{SiteRelativePath, TrustedRoot},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        state::{self, TransactionState, TransactionStatus},
    },
};

pub const OPERATION: &str = "stack.deploy";

/// Engine-state scope shared by every operation on the WCP stack.
pub const SCOPE: &str = "stacks/wcp";

/// The managed stack's directory name under `~/compose`; the one
/// `compose.*` stack name that must take the shared stack lock.
pub const STACK_NAME: &str = "wp-stack";

/// Compose project name; mirrors `crate::compose::COMPOSE_PROJECT`.
pub const PROJECT: &str = crate::compose::COMPOSE_PROJECT;

pub const COMPOSE_FILE: &str = "stack/docker-compose.yml";
pub const ENV_FILE: &str = ".env";

/// Every file a deploy writes, relative to the stack directory. A request
/// must supply exactly these.
pub const FILES: [&str; 8] = [
    COMPOSE_FILE,
    "frankenphp/Caddyfile.ingress",
    "frankenphp/Caddyfile.runtime",
    "frankenphp/php.ini",
    "mariadb/conf.d/wp-performance.cnf",
    "valkey/valkey.conf",
    "postgres/postgresql.conf",
    ENV_FILE,
];

const DIRECTORIES: [&str; 5] = [
    "stack",
    "frankenphp",
    "mariadb/conf.d",
    "valkey",
    "postgres",
];

pub const INGRESS_SERVICE: &str = "ingress";
const IMAGE_PREFIX: &str = "ghcr.io/local-control-panel/";
pub const MAX_FILE_BYTES: usize = 128 * 1024;
const JOURNAL: &str = "journal.json";

/// `.env`'s position in `FILES`.
const ENV_INDEX: usize = FILES.len() - 1;
const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_INSPECT_BYTES: usize = 4 * 1024 * 1024;

// ── Request ────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct Request {
    /// Contents in `FILES` order.
    pub files: Vec<String>,
    /// `.env` keys the engine fills with a fresh random secret when the
    /// merged file does not already carry them. The value never leaves the
    /// server, so the caller cannot keep a stale copy of it.
    pub generate_env_keys: Vec<String>,
    /// `.env` keys that must hold a non-empty value once the incoming file
    /// has been merged over the existing one and the generated keys filled
    /// in. This is what makes a first deploy without passwords fail instead
    /// of silently installing a placeholder.
    pub require_env_keys: Vec<String>,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    Malformed,
    UnexpectedFile,
    MissingFile,
    FileTooLarge,
    InvalidContent,
    InvalidEnvFile,
    InvalidEnvKey,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl RequestError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::Malformed => "request-file is not a valid stack deploy request",
            Self::UnexpectedFile => "request names a file outside the managed stack file set",
            Self::MissingFile => "request does not supply every managed stack file",
            Self::FileTooLarge => "a stack file exceeds the maximum allowed size",
            Self::InvalidContent => "a stack file contains a NUL byte",
            Self::InvalidEnvFile => "the .env file must hold only comments and KEY=value lines",
            Self::InvalidEnvKey => "generate-env-keys and require-env-keys must name env variables",
            Self::InvalidRequestId => "request-id is not a canonical UUID",
            Self::InvalidIdempotencyKey => "idempotency-key is invalid",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WireRequest {
    files: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    generate_env_keys: Vec<String>,
    #[serde(default)]
    require_env_keys: Vec<String>,
}

impl Request {
    pub fn parse(
        request_json: &str,
        request_id: &str,
        idempotency_key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let request_id =
            RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?;
        let idempotency_key = idempotency_key
            .map(IdempotencyKey::parse)
            .transpose()
            .map_err(|_| RequestError::InvalidIdempotencyKey)?;
        let mut wire: WireRequest =
            serde_json::from_str(request_json).map_err(|_| RequestError::Malformed)?;
        if wire
            .files
            .keys()
            .any(|name| !FILES.contains(&name.as_str()))
        {
            return Err(RequestError::UnexpectedFile);
        }
        let mut files = Vec::with_capacity(FILES.len());
        for name in FILES {
            let content = wire.files.remove(name).ok_or(RequestError::MissingFile)?;
            if content.len() > MAX_FILE_BYTES {
                return Err(RequestError::FileTooLarge);
            }
            if content.contains('\0') {
                return Err(RequestError::InvalidContent);
            }
            if name == ENV_FILE && !env_file_is_valid(&content) {
                return Err(RequestError::InvalidEnvFile);
            }
            files.push(content);
        }
        if !wire
            .generate_env_keys
            .iter()
            .chain(&wire.require_env_keys)
            .all(|key| env_key_is_valid(key))
        {
            return Err(RequestError::InvalidEnvKey);
        }
        Ok(Self {
            files,
            generate_env_keys: wire.generate_env_keys,
            require_env_keys: wire.require_env_keys,
            request_id,
            idempotency_key,
        })
    }
}

/// Compose's env-file grammar has no line continuation, so one bad line
/// cannot smuggle a second variable in; this only rejects lines Compose
/// would misread (a `\r`, a missing `=`, a key that is not an identifier).
fn env_file_is_valid(content: &str) -> bool {
    if content.contains('\r') {
        return false;
    }
    content.lines().all(|line| {
        let line = line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            return true;
        }
        let Some((key, _)) = line.split_once('=') else {
            return false;
        };
        env_key_is_valid(key)
    })
}

fn env_key_is_valid(key: &str) -> bool {
    let mut bytes = key.bytes();
    matches!(bytes.next(), Some(b) if b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// The `KEY` a `.env` line assigns, or `None` for a comment or blank line.
fn env_line_key(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    trimmed.split_once('=').map(|(key, _)| key)
}

/// The last line of `content` assigning `key`, verbatim.
fn env_line<'a>(content: &'a str, key: &str) -> Option<&'a str> {
    content
        .lines()
        .filter(|line| env_line_key(line) == Some(key))
        .next_back()
}

/// A value Compose would read for `key`, with the surrounding quotes the
/// panel writes stripped. Later assignments win, matching Compose.
fn env_value<'a>(content: &'a str, key: &str) -> Option<&'a str> {
    env_line(content, key)
        .and_then(|line| line.trim_start().split_once('='))
        .map(|(_, value)| unquote_env_value(value))
}

/// Strips one matching pair of single or double quotes. Enough to tell an
/// empty value from a set one; this is not a full dotenv parser.
fn unquote_env_value(value: &str) -> &str {
    for quote in ['\'', '"'] {
        if let Some(inner) = value
            .strip_prefix(quote)
            .and_then(|rest| rest.strip_suffix(quote))
        {
            return inner;
        }
    }
    value
}

/// Merges `incoming` over `existing`, keeping `existing`'s line order,
/// comments and every key `incoming` does not mention.
///
/// This is what makes a redeploy non-destructive (milestone 047): the panel
/// leaves out the keys whose form fields were left blank, so their current
/// server-side values survive, and operator-added keys it knows nothing
/// about (`WCP_TLS_MODE`, `CADDY_TRUSTED_PROXIES`) are never dropped.
/// `incoming`'s own comments are discarded, because `existing` already
/// carries the generated header and duplicating it on every deploy would
/// make an unchanged redeploy look changed.
fn merge_env_file(existing: &str, incoming: &str) -> String {
    let mut merged = String::with_capacity(existing.len() + incoming.len());
    for line in existing.lines() {
        // `incoming` is already quoted by the caller, so its line is taken
        // verbatim rather than re-quoting a parsed-out value.
        merged.push_str(
            env_line_key(line)
                .and_then(|key| env_line(incoming, key))
                .unwrap_or(line),
        );
        merged.push('\n');
    }
    for line in incoming.lines() {
        let Some(key) = env_line_key(line) else {
            continue;
        };
        if env_value(existing, key).is_none() {
            merged.push_str(line);
            merged.push('\n');
        }
    }
    merged
}

/// Appends `KEY='<secret>'` for every requested key the file does not
/// already set, and reports which keys were filled in. Names only: the
/// secret itself stays on the server.
fn generate_missing_env_keys(env: &mut String, keys: &[String]) -> Vec<String> {
    let mut generated = Vec::new();
    for key in keys {
        if env_value(env, key).is_some_and(|value| !value.is_empty()) {
            continue;
        }
        if !env.is_empty() && !env.ends_with('\n') {
            env.push('\n');
        }
        // Two v4 UUIDs: 244 random bits as 64 hex characters, which needs no
        // quoting beyond the single quotes every generated value carries.
        env.push_str(&format!(
            "{key}='{}{}'\n",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        ));
        generated.push(key.clone());
    }
    generated
}

/// The requested keys the merged file leaves unset or empty.
fn missing_env_values(env: &str, keys: &[String]) -> Vec<String> {
    let mut missing: Vec<String> = keys
        .iter()
        .filter(|key| env_value(env, key).is_none_or(str::is_empty))
        .cloned()
        .collect();
    missing.sort();
    missing.dedup();
    missing
}

/// `ghcr.io/local-control-panel/<name>[:<tag>]@sha256:<64 lowercase hex>`.
pub fn image_allowed(reference: &str) -> bool {
    let Some(rest) = reference.strip_prefix(IMAGE_PREFIX) else {
        return false;
    };
    let Some((name_and_tag, digest)) = rest.split_once("@sha256:") else {
        return false;
    };
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return false;
    }
    let (name, tag) = match name_and_tag.split_once(':') {
        Some((name, tag)) => (name, Some(tag)),
        None => (name_and_tag, None),
    };
    let name_ok = !name.is_empty()
        && name.split('/').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
                && part
                    .bytes()
                    .next()
                    .is_some_and(|b| b.is_ascii_alphanumeric())
        });
    let tag_ok = tag.is_none_or(|tag| {
        !tag.is_empty()
            && tag.len() <= 128
            && tag
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    });
    name_ok && tag_ok
}

// ── Result ─────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageEvidence {
    pub service: String,
    pub declared_reference: String,
    pub resolved_image_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployResult {
    /// `false` when every file already held the submitted content.
    pub changed: bool,
    /// An interrupted earlier deploy was rolled back before this one ran.
    pub recovered_interrupted: bool,
    /// The services this deploy brought up and health-checked.
    pub services: Vec<String>,
    /// Every container of the project after the deploy, sorted by service.
    pub images: Vec<ImageEvidence>,
    /// `.env` keys this deploy filled with a freshly generated secret.
    /// Names only, so the record stays safe to log and replay.
    #[serde(default)]
    pub generated_env_keys: Vec<String>,
    pub completed_at_unix_secs: u64,
}

// ── Context ────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
pub struct Timing {
    pub validate: Duration,
    pub pull: Duration,
    pub up: Duration,
    pub health: Duration,
    pub poll_interval: Duration,
}

impl Timing {
    pub const PRODUCTION: Self = Self {
        validate: Duration::from_secs(60),
        pull: Duration::from_secs(20 * 60),
        up: Duration::from_secs(10 * 60),
        health: Duration::from_secs(4 * 60),
        poll_interval: Duration::from_secs(2),
    };
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    /// The stack directory (`~/compose/wp-stack`); must already exist.
    pub stack_root: &'a TrustedRoot,
    pub docker: &'a str,
    pub timing: Timing,
    /// Who owns the stack files and directories: the account whose home
    /// holds the stack, as when the control panel wrote them itself. `None`
    /// leaves them root-owned.
    pub owner: Option<(u32, u32)>,
}

// ── Errors ─────────────────────────────────────────────────────────────────

/// One `docker` call that did not succeed.
#[derive(Debug)]
pub enum DockerFailure {
    Run(ProcessRunError),
    Rejected(SubprocessDiagnostics),
    /// It succeeded but printed something this engine could not parse.
    Unreadable,
}

/// Why the activated stack was not accepted.
#[derive(Debug)]
pub enum NotUp {
    /// Swapping the files into place failed part-way.
    Activation(io::Error),
    Up(DockerFailure),
    /// Ingress never published `443/tcp`, even after a forced recreate.
    PortsNotPublished,
    /// These services were not running/healthy within the health bound.
    Unhealthy(Vec<String>),
    Inspect(DockerFailure),
}

/// What the rollback after `NotUp` could not finish.
#[derive(Debug)]
pub enum RestoreFailure {
    Files(io::Error),
    Up(DockerFailure),
    PortsNotPublished,
    Down(DockerFailure),
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Preflight(preflight::Error),
    /// Required `.env` keys that neither the request nor the existing file
    /// supplied - a first deploy with the password fields left blank.
    MissingEnvValues(Vec<String>),
    ReplayInProgress,
    Replayed {
        code: ErrorCode,
        message: String,
    },
    Cancelled,
    /// An interrupted earlier deploy could not be rolled back; nothing new
    /// was attempted.
    InterruptedRecoveryFailed(RestoreFailure),
    /// `docker compose config` rejected the staged files.
    ValidateFailed(DockerFailure),
    /// The staged files name an image outside the policy.
    ImageRejected(String),
    PullFailed(DockerFailure),
    /// The files were already current, and converging onto them failed.
    /// Nothing on disk was changed.
    UnchangedNotUp(NotUp),
    /// The new stack did not come up; the previous one is back.
    NotUpRestored(NotUp),
    /// The new stack did not come up and the rollback did not finish.
    RecoveryFailed {
        cause: NotUp,
        restore: RestoreFailure,
    },
    PostCommit {
        result: Box<DeployResult>,
    },
}

impl NotUp {
    fn describe(&self) -> String {
        match self {
            Self::Activation(_) => "activating the new files failed".to_owned(),
            Self::Up(_) => "docker compose up failed".to_owned(),
            Self::PortsNotPublished => "ingress did not publish its host ports".to_owned(),
            Self::Unhealthy(services) => {
                format!(
                    "services not running/healthy in time: {}",
                    services.join(", ")
                )
            }
            Self::Inspect(_) => "the stack's containers could not be inspected".to_owned(),
        }
    }

    fn timed_out(&self) -> bool {
        matches!(
            self,
            Self::Up(DockerFailure::Rejected(d)) | Self::Inspect(DockerFailure::Rejected(d))
                if d.timed_out
        )
    }
}

impl RestoreFailure {
    fn describe(&self) -> &'static str {
        match self {
            Self::Files(_) => "the previous files could not be restored",
            Self::Up(_) => "the previous stack could not be brought up again",
            Self::PortsNotPublished => "the previous ingress did not publish its host ports",
            Self::Down(_) => "the new containers could not be taken down",
        }
    }
}

fn docker_failure_code(failure: &DockerFailure) -> ErrorCode {
    match failure {
        DockerFailure::Run(error) => process::spawn_error_code(error),
        DockerFailure::Rejected(d) if d.timed_out => ErrorCode::Timeout,
        DockerFailure::Rejected(d) if d.cancelled => ErrorCode::Cancelled,
        DockerFailure::Rejected(_) | DockerFailure::Unreadable => ErrorCode::SubprocessFailed,
    }
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another stack operation is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Cancelled => (ErrorCode::Cancelled, "stack deploy was cancelled".into()),
            Self::InterruptedRecoveryFailed(restore) => (
                ErrorCode::ConfigRecoveryFailed,
                format!(
                    "an interrupted earlier deploy could not be rolled back ({}); nothing new \
                     was deployed",
                    restore.describe()
                ),
            ),
            Self::ValidateFailed(failure) => match failure {
                DockerFailure::Run(error) => (
                    process::spawn_error_code(error),
                    "docker compose could not be run".into(),
                ),
                _ => (
                    ErrorCode::ConfigValidationFailed,
                    "docker compose rejected the stack configuration; nothing was changed".into(),
                ),
            },
            Self::ImageRejected(image) => (
                ErrorCode::ConfigValidationFailed,
                format!(
                    "image {image} is not a digest-pinned {IMAGE_PREFIX} reference; nothing was \
                     changed"
                ),
            ),
            Self::PullFailed(failure) => (
                docker_failure_code(failure),
                "pulling the stack images failed; nothing was changed".into(),
            ),
            Self::UnchangedNotUp(cause) => (
                if cause.timed_out() {
                    ErrorCode::Timeout
                } else {
                    ErrorCode::ConfigReloadFailed
                },
                format!(
                    "the stack files were already current but the stack did not come up: {}",
                    cause.describe()
                ),
            ),
            Self::NotUpRestored(cause) => (
                ErrorCode::ConfigReloadFailed,
                format!(
                    "the new stack did not come up ({}); the previous configuration and \
                     containers were restored",
                    cause.describe()
                ),
            ),
            Self::RecoveryFailed { cause, restore } => (
                ErrorCode::ConfigRecoveryFailed,
                format!(
                    "the new stack did not come up ({}) and {}; check the server",
                    cause.describe(),
                    restore.describe()
                ),
            ),
            Self::MissingEnvValues(keys) => (
                ErrorCode::InvalidInput,
                format!(
                    "the stack needs a value for {} - a first deploy must supply every \
                     password, and a redeploy only keeps what the server already has",
                    keys.join(", ")
                ),
            ),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit { .. } => {
                (ErrorCode::Internal, "internal stack deploy error".into())
            }
        }
    }
}

// ── Paths ──────────────────────────────────────────────────────────────────

fn rel(path: impl AsRef<Path>) -> SiteRelativePath {
    SiteRelativePath::parse(path).expect("stack paths are literal and valid")
}

fn staged_name(name: &str) -> String {
    format!("{name}.new")
}

fn backup_path(name: &str, request_id: RequestId) -> SiteRelativePath {
    rel(format!("{name}.rollback-{request_id}"))
}

fn is_private(name: &str) -> bool {
    name == ENV_FILE
}

fn write(
    root: &ManagedRoot,
    owner: Option<(u32, u32)>,
    name: &str,
    path: &SiteRelativePath,
    bytes: &[u8],
) -> io::Result<()> {
    if is_private(name) {
        root.write_atomic_private(path, bytes)?;
    } else {
        root.write_atomic(path, bytes)?;
    }
    match owner {
        Some((uid, gid)) => root.chown(path, uid, gid),
        None => Ok(()),
    }
}

fn remove_if_present(root: &ManagedRoot, path: &SiteRelativePath) -> io::Result<()> {
    match root.remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

fn read_optional(root: &ManagedRoot, path: &SiteRelativePath) -> io::Result<Option<Vec<u8>>> {
    match root.read_bytes(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Which previous files existed, recorded before the first live change so
/// an interrupted deploy can be rolled back by the next one.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Journal {
    request_id: RequestId,
    existed: Vec<bool>,
}

// ── Docker ─────────────────────────────────────────────────────────────────

struct Docker<'a> {
    program: &'a str,
    cwd: &'a Path,
    cancel: &'a CancellationToken,
}

#[derive(Clone, Copy)]
enum Files {
    Staged,
    Live,
}

impl Docker<'_> {
    fn run(
        &self,
        args: &[&str],
        timeout: Duration,
        max_stdout: usize,
    ) -> Result<ProcessOutput, DockerFailure> {
        let output = process::run(
            &ProcessRequest::new(self.program)
                .args(args)
                .current_dir(self.cwd),
            &ProcessLimits {
                timeout,
                max_stdout_bytes: max_stdout,
                max_stderr_bytes: MAX_OUTPUT_BYTES,
            },
            self.cancel,
        )
        .map_err(DockerFailure::Run)?;
        if matches!(
            output.termination,
            ProcessTermination::Exited { success: true, .. }
        ) {
            Ok(output)
        } else {
            Err(DockerFailure::Rejected(SubprocessDiagnostics::from_output(
                self.program,
                &output,
            )))
        }
    }

    fn compose(
        &self,
        files: Files,
        args: &[&str],
        timeout: Duration,
    ) -> Result<ProcessOutput, DockerFailure> {
        let (env, compose) = match files {
            Files::Staged => (staged_name(ENV_FILE), staged_name(COMPOSE_FILE)),
            Files::Live => (ENV_FILE.to_owned(), COMPOSE_FILE.to_owned()),
        };
        let mut argv = vec!["compose", "-p", PROJECT, "--env-file", &env, "-f", &compose];
        argv.extend_from_slice(args);
        self.run(&argv, timeout, MAX_OUTPUT_BYTES)
    }

    fn lines(
        &self,
        files: Files,
        args: &[&str],
        timeout: Duration,
    ) -> Result<Vec<String>, DockerFailure> {
        let output = self.compose(files, args, timeout)?;
        if output.stdout.truncated {
            return Err(DockerFailure::Unreadable);
        }
        let text = String::from_utf8(output.stdout.bytes).map_err(|_| DockerFailure::Unreadable)?;
        Ok(text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect())
    }

    fn inspect(&self) -> Result<Vec<Container>, DockerFailure> {
        let label = format!("label=com.docker.compose.project={PROJECT}");
        let ids = self.run(
            &["ps", "-aq", "--filter", &label],
            Duration::from_secs(30),
            MAX_OUTPUT_BYTES,
        )?;
        let ids = String::from_utf8(ids.stdout.bytes).map_err(|_| DockerFailure::Unreadable)?;
        let ids: Vec<&str> = ids.split_whitespace().collect();
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut argv = vec!["inspect"];
        argv.extend(ids);
        let output = self.run(&argv, Duration::from_secs(30), MAX_INSPECT_BYTES)?;
        if output.stdout.truncated {
            return Err(DockerFailure::Unreadable);
        }
        parse_inspect(&output.stdout.bytes).ok_or(DockerFailure::Unreadable)
    }
}

#[derive(Debug, Eq, PartialEq)]
struct Container {
    service: String,
    declared_image: String,
    image_id: String,
    status: String,
    health: Option<String>,
    https_published: bool,
}

/// Reads the fields this operation needs out of `docker inspect` JSON —
/// parsed rather than templated, because a Go template that names
/// `.State.Health` fails outright on a container without a healthcheck.
fn parse_inspect(bytes: &[u8]) -> Option<Vec<Container>> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    value
        .as_array()?
        .iter()
        .map(|item| {
            let text = |pointer: &str| item.pointer(pointer).and_then(|v| v.as_str());
            Some(Container {
                service: text("/Config/Labels/com.docker.compose.service")?.to_owned(),
                declared_image: text("/Config/Image")?.to_owned(),
                image_id: text("/Image")?.to_owned(),
                status: text("/State/Status")?.to_owned(),
                health: text("/State/Health/Status").map(str::to_owned),
                https_published: item
                    .pointer("/NetworkSettings/Ports/443~1tcp")
                    .and_then(|v| v.as_array())
                    .is_some_and(|bindings| !bindings.is_empty()),
            })
        })
        .collect()
}

fn ingress_published(docker: &Docker<'_>) -> Result<bool, DockerFailure> {
    Ok(docker
        .inspect()?
        .iter()
        .any(|c| c.service == INGRESS_SERVICE && c.status == "running" && c.https_published))
}

/// `up -d` succeeded; make sure ingress really published its ports. A
/// container that lost a port-bind race can come back `running` with no
/// ports, and plain restarts of the same container object keep it that way,
/// so the last attempt forces a fresh ingress container.
fn ensure_ports(docker: &Docker<'_>, timing: &Timing) -> Result<bool, DockerFailure> {
    if ingress_published(docker)? {
        return Ok(true);
    }
    if docker
        .compose(Files::Live, &["up", "-d"], timing.up)
        .is_ok()
        && ingress_published(docker)?
    {
        return Ok(true);
    }
    docker.compose(
        Files::Live,
        &["up", "-d", "--force-recreate", INGRESS_SERVICE],
        timing.up,
    )?;
    ingress_published(docker)
}

/// Waits until every service is `running` and, where it has a healthcheck,
/// `healthy`. Returns the services that never got there.
fn wait_healthy(
    docker: &Docker<'_>,
    services: &[String],
    timing: &Timing,
) -> Result<Vec<String>, DockerFailure> {
    let deadline = Instant::now() + timing.health;
    loop {
        let containers = docker.inspect()?;
        let not_ready: Vec<String> = services
            .iter()
            .filter(|service| {
                let mine: Vec<&Container> = containers
                    .iter()
                    .filter(|c| &c.service == *service)
                    .collect();
                mine.is_empty()
                    || mine.iter().any(|c| {
                        c.status != "running" || c.health.as_deref().is_some_and(|h| h != "healthy")
                    })
            })
            .cloned()
            .collect();
        let dead = services.iter().any(|service| {
            containers
                .iter()
                .any(|c| &c.service == service && matches!(c.status.as_str(), "exited" | "dead"))
        });
        if not_ready.is_empty() || dead || Instant::now() >= deadline {
            return Ok(not_ready);
        }
        if docker.cancel.is_cancelled() {
            return Ok(not_ready);
        }
        std::thread::sleep(timing.poll_interval);
    }
}

// ── Execute ────────────────────────────────────────────────────────────────

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<DeployResult, Error> {
    let scope = open_scope(ctx.engine_state).map_err(Error::Io)?;
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
    let state_path = rel(format!("transactions/{}.json", req.request_id));
    let audit_path = rel("audit/events.jsonl");

    let result = match deploy(ctx, &scope, req, cancel) {
        Ok(result) => result,
        Err(error) => return Err(fail(&scope, &state_path, &audit_path, state, error)),
    };
    state
        .mark_committed(serde_json::to_value(&result).expect("result serializes"))
        .expect("an in-progress transaction can commit");
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

/// Acquires the one lock that serializes every operation able to recreate
/// or reload a container of the managed WCP stack (milestone 048).
///
/// `stack.deploy` already takes this as its own preflight lock, so the
/// operations that only *reload* the running stack - `ingress.*`,
/// `runtime.*` and the compose operations on `wp-stack` - take it here,
/// before their own scope lock, and hold it for their whole body. Without
/// it an `ingress.reconcile` can reload Caddy while a deploy's `up -d` is
/// recreating the ingress container, and the reload lands in a container
/// that is about to be replaced.
///
/// The ordering is fixed: this lock is always the outermost one, so a
/// deploy and a reload can never each hold half of the pair. Every lock
/// here is non-blocking, so the loser gets `Held` immediately.
pub fn acquire_stack_lock(
    scope: &ManagedRoot,
    holder: RequestId,
) -> Result<crate::transaction::lock::SiteLockGuard<'_>, crate::transaction::lock::LockError> {
    crate::transaction::lock::acquire(scope, &preflight::lock_path(), holder)
}

pub fn open_scope(engine_state: &ManagedRoot) -> io::Result<ManagedRoot> {
    let scope_path = rel(SCOPE);
    engine_state.create_dir_all(&scope_path)?;
    let scope = engine_state.open_managed_dir(&scope_path)?;
    for child in ["locks", "transactions", "audit"] {
        scope.create_dir_all(&rel(child))?;
    }
    Ok(scope)
}

fn deploy(
    ctx: &Context<'_>,
    scope: &ManagedRoot,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<DeployResult, Error> {
    let root = ManagedRoot::open(ctx.stack_root).map_err(Error::Io)?;
    for directory in DIRECTORIES {
        root.create_dir_all(&rel(directory)).map_err(Error::Io)?;
        if let Some((uid, gid)) = ctx.owner {
            for path in [directory.split('/').next().unwrap_or(directory), directory] {
                root.chown(&rel(path), uid, gid).map_err(Error::Io)?;
            }
        }
    }
    let docker = Docker {
        program: ctx.docker,
        cwd: ctx.stack_root.as_path(),
        cancel,
    };

    let recovered_interrupted = recover_interrupted(ctx, scope, &root, &docker)?;

    let mut previous = Vec::with_capacity(FILES.len());
    for name in FILES {
        previous.push(read_optional(&root, &rel(name)).map_err(Error::Io)?);
    }

    // Milestone 047: `.env` is merged over what the server already holds
    // rather than replaced, so blank form fields and operator-added keys
    // survive a redeploy, and the keys the caller asked the engine to own
    // are generated here once and never handed back.
    let mut files = req.files.clone();
    let env = &mut files[ENV_INDEX];
    if let Some(existing) = previous[ENV_INDEX]
        .as_deref()
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
    {
        *env = merge_env_file(&existing, env);
    }
    let generated_env_keys = generate_missing_env_keys(env, &req.generate_env_keys);
    let missing = missing_env_values(env, &req.require_env_keys);
    if !missing.is_empty() {
        return Err(Error::MissingEnvValues(missing));
    }

    let changed = FILES
        .iter()
        .enumerate()
        .any(|(i, _)| previous[i].as_deref() != Some(files[i].as_bytes()));

    // Stage, validate, enforce the image policy and pull — all before any
    // live file changes.
    let staged = || FILES.iter().map(|name| rel(staged_name(name)));
    let discard_staged = || {
        for path in staged() {
            let _ = remove_if_present(&root, &path);
        }
    };
    for (i, name) in FILES.iter().enumerate() {
        if let Err(error) = write(
            &root,
            ctx.owner,
            name,
            &rel(staged_name(name)),
            files[i].as_bytes(),
        ) {
            discard_staged();
            return Err(Error::Io(error));
        }
    }
    let services = match prepare(&docker, &ctx.timing) {
        Ok(services) => services,
        Err(error) => {
            discard_staged();
            return Err(error);
        }
    };
    if cancel.is_cancelled() {
        discard_staged();
        return Err(Error::Cancelled);
    }

    if !changed {
        discard_staged();
        if let Err(cause) = converge(&docker, &services, &ctx.timing) {
            return Err(Error::UnchangedNotUp(cause));
        }
    } else {
        let existed: Vec<bool> = previous.iter().map(Option::is_some).collect();
        let journal = Journal {
            request_id: req.request_id,
            existed: existed.clone(),
        };
        if let Err(error) = scope.write_atomic(
            &rel(JOURNAL),
            &serde_json::to_vec(&journal).expect("journal serializes"),
        ) {
            discard_staged();
            return Err(Error::Io(error));
        }
        let outcome = activate(&root, ctx.owner, req.request_id, &previous)
            .map_err(NotUp::Activation)
            .and_then(|()| converge(&docker, &services, &ctx.timing));
        if let Err(cause) = outcome {
            discard_staged();
            return match restore(&root, &docker, &ctx.timing, req.request_id, &existed) {
                Ok(()) => {
                    let _ = scope.remove_file(&rel(JOURNAL));
                    Err(Error::NotUpRestored(cause))
                }
                Err(restore) => Err(Error::RecoveryFailed { cause, restore }),
            };
        }
        for name in FILES {
            let _ = remove_if_present(&root, &backup_path(name, req.request_id));
        }
        let _ = scope.remove_file(&rel(JOURNAL));
    }

    // Evidence is best-effort after a successful deploy: the stack is up and
    // its record of what ran must not turn that into a failure.
    let mut images: Vec<ImageEvidence> = docker
        .inspect()
        .unwrap_or_default()
        .into_iter()
        .map(|c| ImageEvidence {
            service: c.service,
            declared_reference: c.declared_image,
            resolved_image_id: c.image_id,
        })
        .collect();
    images.sort_by(|a, b| a.service.cmp(&b.service));

    Ok(DeployResult {
        changed,
        recovered_interrupted,
        services,
        images,
        generated_env_keys,
        completed_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    })
}

/// Validates the staged files, applies the image policy to every service of
/// every profile, pulls, and returns the services a plain `up -d` starts.
fn prepare(docker: &Docker<'_>, timing: &Timing) -> Result<Vec<String>, Error> {
    docker
        .compose(Files::Staged, &["config", "--quiet"], timing.validate)
        .map_err(Error::ValidateFailed)?;
    let images = docker
        .lines(
            Files::Staged,
            &["--profile", "*", "config", "--images"],
            timing.validate,
        )
        .map_err(Error::ValidateFailed)?;
    if images.is_empty() {
        return Err(Error::ValidateFailed(DockerFailure::Unreadable));
    }
    if let Some(image) = images.iter().find(|image| !image_allowed(image)) {
        return Err(Error::ImageRejected(image.clone()));
    }
    let services = docker
        .lines(Files::Staged, &["config", "--services"], timing.validate)
        .map_err(Error::ValidateFailed)?;
    if !services.iter().any(|service| service == INGRESS_SERVICE) {
        return Err(Error::ValidateFailed(DockerFailure::Unreadable));
    }
    docker
        .compose(Files::Staged, &["pull", "--quiet"], timing.pull)
        .map_err(Error::PullFailed)?;
    let mut services = services;
    services.sort();
    Ok(services)
}

/// Backs every previous file up, then renames each staged file into place.
fn activate(
    root: &ManagedRoot,
    owner: Option<(u32, u32)>,
    request_id: RequestId,
    previous: &[Option<Vec<u8>>],
) -> io::Result<()> {
    for (i, name) in FILES.iter().enumerate() {
        if let Some(bytes) = &previous[i] {
            write(root, owner, name, &backup_path(name, request_id), bytes)?;
        }
        root.rename(&rel(staged_name(name)), &rel(name))?;
    }
    Ok(())
}

fn converge(docker: &Docker<'_>, services: &[String], timing: &Timing) -> Result<(), NotUp> {
    docker
        .compose(Files::Live, &["up", "-d"], timing.up)
        .map_err(NotUp::Up)?;
    if !ensure_ports(docker, timing).map_err(NotUp::Inspect)? {
        return Err(NotUp::PortsNotPublished);
    }
    let not_ready = wait_healthy(docker, services, timing).map_err(NotUp::Inspect)?;
    if not_ready.is_empty() {
        Ok(())
    } else {
        Err(NotUp::Unhealthy(not_ready))
    }
}

/// Puts the previous files back (a file whose backup exists is restored
/// from it; a file that did not exist before is removed) and brings the
/// previous stack up again. With no previous compose file there is no
/// previous stack: the new containers are taken down — volumes kept — while
/// the new files still describe them, and only then removed.
fn restore(
    root: &ManagedRoot,
    docker: &Docker<'_>,
    timing: &Timing,
    request_id: RequestId,
    existed: &[bool],
) -> Result<(), RestoreFailure> {
    let compose_existed = existed.first().copied().unwrap_or(false);
    // Containers can only exist if `up -d` ran, which needs the whole new
    // set live; an activation that stopped earlier started nothing.
    if !compose_existed && root.exists(&rel(COMPOSE_FILE)) && root.exists(&rel(ENV_FILE)) {
        docker
            .compose(Files::Live, &["down"], timing.up)
            .map_err(RestoreFailure::Down)?;
    }
    let mut first_error = None;
    for (i, name) in FILES.iter().enumerate() {
        let backup = backup_path(name, request_id);
        let outcome = if existed.get(i).copied().unwrap_or(false) {
            if root.exists(&backup) {
                root.rename(&backup, &rel(name))
            } else {
                Ok(())
            }
        } else {
            remove_if_present(root, &rel(name))
        };
        if let Err(error) = outcome {
            first_error.get_or_insert(error);
        }
    }
    if let Some(error) = first_error {
        return Err(RestoreFailure::Files(error));
    }
    if compose_existed {
        docker
            .compose(Files::Live, &["up", "-d"], timing.up)
            .map_err(RestoreFailure::Up)?;
        if !ensure_ports(docker, timing).map_err(RestoreFailure::Up)? {
            return Err(RestoreFailure::PortsNotPublished);
        }
    }
    Ok(())
}

/// A journal left behind means an earlier deploy stopped between activation
/// and its own commit or rollback (its process died; this one holds the
/// lock). Roll it back before anything new is staged, so the live files are
/// never a mix of two deploys.
fn recover_interrupted(
    ctx: &Context<'_>,
    scope: &ManagedRoot,
    root: &ManagedRoot,
    docker: &Docker<'_>,
) -> Result<bool, Error> {
    let bytes = match read_optional(scope, &rel(JOURNAL)).map_err(Error::Io)? {
        Some(bytes) => bytes,
        None => return Ok(false),
    };
    let journal: Journal = serde_json::from_slice(&bytes)
        .map_err(|error| Error::Io(io::Error::new(io::ErrorKind::InvalidData, error)))?;
    if journal.existed.len() != FILES.len() {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "stack deploy journal does not match the managed file set",
        )));
    }
    for name in FILES {
        remove_if_present(root, &rel(staged_name(name))).map_err(Error::Io)?;
    }
    restore(
        root,
        docker,
        &ctx.timing,
        journal.request_id,
        &journal.existed,
    )
    .map_err(Error::InterruptedRecoveryFailed)?;
    let path = rel(format!("transactions/{}.json", journal.request_id));
    if let Ok(mut interrupted) = state::load(scope, &path) {
        if interrupted.status == TransactionStatus::InProgress
            && interrupted
                .mark_failed(
                    ErrorCode::Cancelled,
                    "interrupted; rolled back by a later deploy".to_owned(),
                )
                .is_ok()
        {
            let _ = state::save(scope, &path, &interrupted);
        }
    }
    scope.remove_file(&rel(JOURNAL)).map_err(Error::Io)?;
    Ok(true)
}

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<DeployResult, Error> {
    let loaded = state::load(scope, &rel(format!("transactions/{id}.json")))
        .map_err(|error| Error::Io(io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != OPERATION {
        return Err(Error::Io(io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => loaded
            .outcome
            .and_then(|outcome| outcome.result)
            .ok_or_else(|| Error::Io(io::Error::other("committed transaction has no result")))
            .and_then(|value| {
                serde_json::from_value(value).map_err(|error| Error::Io(io::Error::other(error)))
            }),
        TransactionStatus::Failed => {
            let (code, message) = loaded
                .outcome
                .map(|outcome| (outcome.error_code, outcome.error_message))
                .unwrap_or((None, None));
            Err(Error::Replayed {
                code: code.unwrap_or(ErrorCode::Internal),
                message: message.unwrap_or_default(),
            })
        }
    }
}

fn fail(
    scope: &ManagedRoot,
    state_path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut state: TransactionState,
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
    const ID_3: &str = "123e4567-e89b-12d3-a456-426614174002";
    const DIGEST: &str = "33a577fe9547132caa9550eb013a18e16fd63bb31e75547cc37bf53c8ec4a746";

    /// Every test forks many fake `docker` processes; run in parallel they
    /// widen the fork-before-exec window that flakes unrelated tests.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A fake host. Flag files in `ctl/` steer the fake `docker`:
    /// `fail-config`, `fail-pull`, `bad-image`, `no-ports`,
    /// `fix-ports-on-recreate`, `unhealthy`, `fail-down`. A compose file
    /// containing `BROKEN` makes `up -d` fail.
    struct Fixture {
        dir: tempfile::TempDir,
        _serial: std::sync::MutexGuard<'static, ()>,
    }

    impl Fixture {
        fn new() -> Self {
            let serial = SERIAL
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let dir = tempfile::tempdir().unwrap();
            for child in ["state", "stack", "ctl"] {
                fs::create_dir(dir.path().join(child)).unwrap();
            }
            let ctl = dir.path().join("ctl");
            let c = ctl.display();
            let script = format!(
                r#"#!/bin/sh
C='{c}'
D='{DIGEST}'
if [ "$1" = ps ]; then [ -e "$C/running" ] && echo cid1 cid2; exit 0; fi
if [ "$1" = inspect ]; then
  ports='[{{"HostIp":"0.0.0.0","HostPort":"443"}}]'; [ -e "$C/no-ports" ] && ports='[]'
  health='"Health":{{"Status":"healthy"}},'; [ -e "$C/unhealthy" ] && health='"Health":{{"Status":"unhealthy"}},'
  printf '[{{"Config":{{"Image":"ghcr.io/local-control-panel/frankenphp:1@sha256:%s","Labels":{{"com.docker.compose.service":"ingress"}}}},"Image":"sha256:aa","State":{{"Status":"running"}},"NetworkSettings":{{"Ports":{{"443/tcp":%s}}}}}},{{"Config":{{"Image":"ghcr.io/local-control-panel/mariadb:11@sha256:%s","Labels":{{"com.docker.compose.service":"mariadb-11"}}}},"Image":"sha256:bb","State":{{%s"Status":"running"}},"NetworkSettings":{{"Ports":{{}}}}}}]' "$D" "$ports" "$D" "$health"
  exit 0
fi
shift 3
env=$2; file=$4; shift 4
echo "$* [$env] $(head -n1 "$file" 2>/dev/null)" >> "$C/calls.log"
case "$*" in
  "config --quiet") [ -e "$C/fail-config" ] && exit 1; exit 0 ;;
  "--profile * config --images")
    echo "ghcr.io/local-control-panel/frankenphp:1@sha256:$D"
    [ -e "$C/bad-image" ] && echo "docker.io/library/nginx:latest"
    exit 0 ;;
  "config --services") printf 'mariadb-11\ningress\n'; exit 0 ;;
  "pull --quiet") [ -e "$C/fail-pull" ] && exit 1; exit 0 ;;
  "up -d") grep -q BROKEN "$file" && exit 1; touch "$C/running"; exit 0 ;;
  "up -d --force-recreate ingress") [ -e "$C/fix-ports-on-recreate" ] && rm -f "$C/no-ports"; exit 0 ;;
  down) [ -e "$C/fail-down" ] && exit 1; rm -f "$C/running"; exit 0 ;;
esac
exit 2
"#
            );
            let docker = dir.path().join("docker");
            fs::write(&docker, script).unwrap();
            fs::set_permissions(&docker, fs::Permissions::from_mode(0o755)).unwrap();
            Self {
                dir,
                _serial: serial,
            }
        }

        fn path(&self, relative: &str) -> PathBuf {
            self.dir.path().join(relative)
        }

        fn flag(&self, name: &str) {
            fs::write(self.path(&format!("ctl/{name}")), "").unwrap();
        }

        fn calls(&self) -> String {
            fs::read_to_string(self.path("ctl/calls.log")).unwrap_or_default()
        }

        fn reset_calls(&self) {
            let _ = fs::remove_file(self.path("ctl/calls.log"));
        }

        fn live(&self, name: &str) -> Option<String> {
            fs::read_to_string(self.path(&format!("stack/{name}"))).ok()
        }

        fn stack_entries(&self) -> Vec<String> {
            let mut names = Vec::new();
            for directory in [
                "",
                "stack",
                "frankenphp",
                "mariadb/conf.d",
                "valkey",
                "postgres",
            ] {
                let Ok(entries) = fs::read_dir(self.path(&format!("stack/{directory}"))) else {
                    continue;
                };
                for entry in entries {
                    let entry = entry.unwrap();
                    if entry.file_type().unwrap().is_file() {
                        names.push(entry.file_name().to_string_lossy().into_owned());
                    }
                }
            }
            names.sort();
            names
        }

        fn run(&self, id: &str, key: Option<&str>, compose: &str) -> Result<DeployResult, Error> {
            self.run_json(id, key, &request_json(compose))
        }

        fn run_json(&self, id: &str, key: Option<&str>, json: &str) -> Result<DeployResult, Error> {
            let state =
                ManagedRoot::open(&TrustedRoot::parse(self.path("state")).unwrap()).unwrap();
            let stack = TrustedRoot::parse(self.path("stack")).unwrap();
            let docker = self.path("docker");
            let ctx = Context {
                engine_state: &state,
                stack_root: &stack,
                docker: docker.to_str().unwrap(),
                timing: Timing {
                    validate: Duration::from_secs(10),
                    pull: Duration::from_secs(10),
                    up: Duration::from_secs(10),
                    health: Duration::from_millis(300),
                    poll_interval: Duration::from_millis(20),
                },
                owner: Some(current_owner()),
            };
            let request = Request::parse(json, id, key).unwrap();
            execute(&ctx, &request, &CancellationToken::default())
        }

        fn run_env(
            &self,
            id: &str,
            key: Option<&str>,
            compose: &str,
            env: &str,
        ) -> Result<DeployResult, Error> {
            self.run_full(id, key, compose, env, &[], &[])
        }

        fn run_full(
            &self,
            id: &str,
            key: Option<&str>,
            compose: &str,
            env: &str,
            generate: &[&str],
            require: &[&str],
        ) -> Result<DeployResult, Error> {
            let mut value: serde_json::Value =
                serde_json::from_str(&request_json_with_env(compose, env)).unwrap();
            value["generateEnvKeys"] = generate.into();
            value["requireEnvKeys"] = require.into();
            self.run_json(id, key, &value.to_string())
        }
    }

    fn current_owner() -> (u32, u32) {
        // SAFETY: neither call takes arguments or can fail.
        unsafe { (libc::getuid(), libc::getgid()) }
    }

    fn request_json(compose: &str) -> String {
        request_json_with_env(compose, "# generated\nMARIADB_ROOT_PASSWORD='s3cret'\n")
    }

    fn request_json_with_env(compose: &str, env: &str) -> String {
        let mut files = serde_json::Map::new();
        for name in FILES {
            let content = match name {
                COMPOSE_FILE => compose.to_owned(),
                ENV_FILE => env.to_owned(),
                other => format!("# {other}\n"),
            };
            files.insert(name.to_owned(), content.into());
        }
        serde_json::json!({ "files": files }).to_string()
    }

    fn managed_files() -> Vec<String> {
        let mut names: Vec<String> = FILES
            .iter()
            .map(|name| name.rsplit('/').next().unwrap().to_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn first_deploy_writes_every_file_and_brings_the_stack_up() {
        let fx = Fixture::new();
        let result = fx.run(ID, None, "services: old\n").unwrap();

        assert!(result.changed);
        assert!(!result.recovered_interrupted);
        assert_eq!(result.services, ["ingress", "mariadb-11"]);
        assert_eq!(result.images.len(), 2);
        assert_eq!(result.images[0].service, "ingress");
        assert_eq!(fx.live(COMPOSE_FILE).as_deref(), Some("services: old\n"));
        let env_mode = fs::metadata(fx.path("stack/.env"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(env_mode & 0o777, 0o600);
        {
            use std::os::unix::fs::MetadataExt;
            let owner = current_owner();
            for path in [
                "stack/.env",
                "stack/stack/docker-compose.yml",
                "stack/mariadb",
                "stack/mariadb/conf.d",
            ] {
                let metadata = fs::metadata(fx.path(path)).unwrap();
                assert_eq!((metadata.uid(), metadata.gid()), owner, "{path}");
            }
        }
        assert_eq!(fx.stack_entries(), managed_files());
        assert!(!fx.path("state/stacks/wcp/journal.json").exists());
        let calls = fx.calls();
        let pull = calls.find("pull --quiet [.env.new]").unwrap();
        let up = calls.find("up -d [.env]").unwrap();
        assert!(
            pull < up,
            "pull must run on staged files before activation:\n{calls}"
        );
    }

    #[test]
    fn unchanged_redeploy_converges_without_writing_and_replays_by_key() {
        let fx = Fixture::new();
        fx.run(ID, None, "services: old\n").unwrap();
        let second = fx.run(ID_2, Some("deploy-2"), "services: old\n").unwrap();
        assert!(!second.changed);
        assert_eq!(fx.stack_entries(), managed_files());

        fx.reset_calls();
        let replayed = fx.run(ID_3, Some("deploy-2"), "services: old\n").unwrap();
        assert_eq!(
            replayed.completed_at_unix_secs,
            second.completed_at_unix_secs
        );
        assert!(fx.calls().is_empty(), "a replay must not run docker");
    }

    #[test]
    fn rejected_configuration_changes_nothing() {
        let fx = Fixture::new();
        fx.run(ID, None, "services: old\n").unwrap();
        fx.flag("fail-config");
        let error = fx.run(ID_2, None, "services: new\n").unwrap_err();
        assert_eq!(error.protocol().0, ErrorCode::ConfigValidationFailed);
        assert_eq!(fx.live(COMPOSE_FILE).as_deref(), Some("services: old\n"));
        assert_eq!(fx.stack_entries(), managed_files());
    }

    #[test]
    fn image_outside_the_policy_is_rejected_before_any_pull() {
        let fx = Fixture::new();
        fx.flag("bad-image");
        let error = fx.run(ID, None, "services: new\n").unwrap_err();
        assert!(matches!(&error, Error::ImageRejected(image) if image.contains("nginx")));
        assert_eq!(error.protocol().0, ErrorCode::ConfigValidationFailed);
        assert!(!fx.calls().contains("pull"));
        assert!(fx.stack_entries().is_empty());
    }

    #[test]
    fn failed_pull_changes_nothing() {
        let fx = Fixture::new();
        fx.run(ID, None, "services: old\n").unwrap();
        fx.flag("fail-pull");
        let error = fx.run(ID_2, None, "services: new\n").unwrap_err();
        assert!(matches!(error, Error::PullFailed(_)));
        assert_eq!(fx.live(COMPOSE_FILE).as_deref(), Some("services: old\n"));
        assert_eq!(fx.stack_entries(), managed_files());
    }

    #[test]
    fn failed_up_restores_the_previous_files_and_containers() {
        let fx = Fixture::new();
        fx.run(ID, None, "services: old\n").unwrap();
        fx.reset_calls();
        let error = fx.run(ID_2, None, "services: BROKEN\n").unwrap_err();
        assert!(
            matches!(error, Error::NotUpRestored(NotUp::Up(_))),
            "{error:?}"
        );
        assert_eq!(error.protocol().0, ErrorCode::ConfigReloadFailed);
        assert_eq!(fx.live(COMPOSE_FILE).as_deref(), Some("services: old\n"));
        assert_eq!(fx.stack_entries(), managed_files());
        assert!(fx.calls().contains("up -d [.env] services: old"));
        assert!(!fx.path("state/stacks/wcp/journal.json").exists());
    }

    #[test]
    fn unhealthy_service_rolls_the_deploy_back() {
        let fx = Fixture::new();
        fx.run(ID, None, "services: old\n").unwrap();
        fx.flag("unhealthy");
        let error = fx.run(ID_2, None, "services: new\n").unwrap_err();
        match &error {
            Error::NotUpRestored(NotUp::Unhealthy(services)) => {
                assert_eq!(services, &["mariadb-11"]);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(error.protocol().1.contains("mariadb-11"));
        assert_eq!(fx.live(COMPOSE_FILE).as_deref(), Some("services: old\n"));
    }

    #[test]
    fn lost_ingress_ports_are_recovered_by_a_forced_recreate() {
        let fx = Fixture::new();
        fx.flag("no-ports");
        fx.flag("fix-ports-on-recreate");
        fx.run(ID, None, "services: old\n").unwrap();
        assert!(fx.calls().contains("up -d --force-recreate ingress"));
    }

    #[test]
    fn ports_that_never_appear_roll_the_deploy_back() {
        let fx = Fixture::new();
        fx.run(ID, None, "services: old\n").unwrap();
        fx.flag("no-ports");
        let error = fx.run(ID_2, None, "services: new\n").unwrap_err();
        // The restored stack has the same port problem, so the rollback
        // cannot claim the previous containers are healthy again.
        assert!(
            matches!(
                error,
                Error::RecoveryFailed {
                    cause: NotUp::PortsNotPublished,
                    restore: RestoreFailure::PortsNotPublished,
                }
            ),
            "{error:?}"
        );
        assert_eq!(error.protocol().0, ErrorCode::ConfigRecoveryFailed);
        assert_eq!(fx.live(COMPOSE_FILE).as_deref(), Some("services: old\n"));
    }

    #[test]
    fn failed_first_deploy_takes_the_new_containers_down_and_removes_its_files() {
        let fx = Fixture::new();
        fx.flag("unhealthy");
        let error = fx.run(ID, None, "services: new\n").unwrap_err();
        assert!(
            matches!(error, Error::NotUpRestored(NotUp::Unhealthy(_))),
            "{error:?}"
        );
        assert!(fx.calls().contains("down [.env] services: new"));
        assert!(fx.stack_entries().is_empty());
        assert!(!fx.path("ctl/running").exists());
    }

    #[test]
    fn interrupted_deploy_is_rolled_back_before_the_next_one() {
        let fx = Fixture::new();
        fx.run(ID, None, "services: old\n").unwrap();

        // Simulate a deploy that died after swapping only the compose file.
        let interrupted = RequestId::parse(ID_2).unwrap();
        let state = ManagedRoot::open(&TrustedRoot::parse(fx.path("state")).unwrap()).unwrap();
        let scope = open_scope(&state).unwrap();
        state::create(
            &scope,
            &rel(format!("transactions/{interrupted}.json")),
            &TransactionState::start(interrupted, None, OPERATION),
        )
        .unwrap();
        scope
            .write_atomic(
                &rel(JOURNAL),
                &serde_json::to_vec(&Journal {
                    request_id: interrupted,
                    existed: vec![true; FILES.len()],
                })
                .unwrap(),
            )
            .unwrap();
        fs::copy(
            fx.path("stack/stack/docker-compose.yml"),
            fx.path(&format!(
                "stack/stack/docker-compose.yml.rollback-{interrupted}"
            )),
        )
        .unwrap();
        fs::write(
            fx.path("stack/stack/docker-compose.yml"),
            "services: half\n",
        )
        .unwrap();

        fx.reset_calls();
        let result = fx.run(ID_3, None, "services: new\n").unwrap();
        assert!(result.recovered_interrupted);
        assert_eq!(fx.live(COMPOSE_FILE).as_deref(), Some("services: new\n"));
        assert!(fx.calls().contains("up -d [.env] services: old"));
        assert_eq!(fx.stack_entries(), managed_files());
        let old = state::load(&scope, &rel(format!("transactions/{interrupted}.json"))).unwrap();
        assert_eq!(old.status, TransactionStatus::Failed);
        assert!(!fx.path("state/stacks/wcp/journal.json").exists());
    }

    #[test]
    fn a_held_stack_lock_is_a_conflict() {
        let fx = Fixture::new();
        let state = ManagedRoot::open(&TrustedRoot::parse(fx.path("state")).unwrap()).unwrap();
        let scope = open_scope(&state).unwrap();
        let _held = crate::transaction::lock::acquire(
            &scope,
            &rel("locks/mutation.lock"),
            RequestId::parse(ID_2).unwrap(),
        )
        .unwrap();
        let error = fx.run(ID, None, "services: new\n").unwrap_err();
        assert_eq!(error.protocol().0, ErrorCode::Conflict);
        assert!(fx.calls().is_empty());
    }

    #[test]
    fn request_must_supply_exactly_the_managed_files() {
        let valid = request_json("services: x\n");
        assert!(Request::parse(&valid, ID, None).is_ok());

        let mut value: serde_json::Value = serde_json::from_str(&valid).unwrap();
        value["files"]
            .as_object_mut()
            .unwrap()
            .remove("valkey/valkey.conf");
        assert_eq!(
            Request::parse(&value.to_string(), ID, None).unwrap_err(),
            RequestError::MissingFile
        );

        let mut value: serde_json::Value = serde_json::from_str(&valid).unwrap();
        value["files"]["../etc/passwd"] = "x".into();
        assert_eq!(
            Request::parse(&value.to_string(), ID, None).unwrap_err(),
            RequestError::UnexpectedFile
        );

        let mut value: serde_json::Value = serde_json::from_str(&valid).unwrap();
        value["files"][ENV_FILE] = "A=1\nnot a variable\n".into();
        assert_eq!(
            Request::parse(&value.to_string(), ID, None).unwrap_err(),
            RequestError::InvalidEnvFile
        );

        let mut value: serde_json::Value = serde_json::from_str(&valid).unwrap();
        value["files"][COMPOSE_FILE] = "x".repeat(MAX_FILE_BYTES + 1).into();
        assert_eq!(
            Request::parse(&value.to_string(), ID, None).unwrap_err(),
            RequestError::FileTooLarge
        );

        assert_eq!(
            Request::parse(r#"{"files":{},"extra":1}"#, ID, None).unwrap_err(),
            RequestError::Malformed
        );
        assert_eq!(
            Request::parse(&valid, "nope", None).unwrap_err(),
            RequestError::InvalidRequestId
        );
    }

    #[test]
    fn image_policy_accepts_only_digest_pinned_project_images() {
        let ok = |image: &str| image_allowed(image);
        assert!(ok(&format!(
            "ghcr.io/local-control-panel/frankenphp:1-php8.3@sha256:{DIGEST}"
        )));
        assert!(ok(&format!(
            "ghcr.io/local-control-panel/mariadb@sha256:{DIGEST}"
        )));
        assert!(!ok("ghcr.io/local-control-panel/frankenphp:1-php8.3"));
        assert!(!ok(&format!("docker.io/library/nginx@sha256:{DIGEST}")));
        assert!(!ok(&format!(
            "ghcr.io/local-control-panel-evil/x@sha256:{DIGEST}"
        )));
        assert!(!ok(&format!(
            "ghcr.io/local-control-panel/../x@sha256:{DIGEST}"
        )));
        assert!(!ok(&format!(
            "ghcr.io/local-control-panel/x@sha256:{}",
            &DIGEST[1..]
        )));
        assert!(!ok(&format!(
            "ghcr.io/local-control-panel/x@sha256:{}",
            DIGEST.to_uppercase()
        )));
    }

    // ── .env merge and secret ownership (milestone 047) ──────────────────

    #[test]
    fn merge_keeps_unmentioned_keys_comments_and_order() {
        let existing = "# Generated by Website Control Panel\n\
                        MARIADB_ROOT_PASSWORD='kept'\n\
                        SERVER_NAME=':80'\n\
                        WCP_TLS_MODE='internal'\n";
        let incoming = "# header the panel just wrote\nSERVER_NAME=':443'\nWORKER_PROCESSES='8'\n";
        assert_eq!(
            merge_env_file(existing, incoming),
            "# Generated by Website Control Panel\n\
             MARIADB_ROOT_PASSWORD='kept'\n\
             SERVER_NAME=':443'\n\
             WCP_TLS_MODE='internal'\n\
             WORKER_PROCESSES='8'\n"
        );
    }

    #[test]
    fn merging_the_same_file_twice_is_a_fixed_point() {
        let existing = "# head\nA='1'\nB='2'\n";
        let once = merge_env_file(existing, "A='1'\nC='3'\n");
        assert_eq!(once, merge_env_file(&once, "A='1'\nC='3'\n"));
    }

    #[test]
    fn generate_fills_only_absent_or_empty_keys() {
        let mut env = "A='set'\nB=''\n".to_owned();
        let generated =
            generate_missing_env_keys(&mut env, &["A".to_owned(), "B".to_owned(), "C".to_owned()]);
        assert_eq!(generated, ["B", "C"]);
        assert_eq!(env_value(&env, "A"), Some("set"));
        for key in ["B", "C"] {
            let value = env_value(&env, key).unwrap();
            assert_eq!(value.len(), 64, "{key}");
            assert!(value.bytes().all(|b| b.is_ascii_hexdigit()), "{key}");
        }
        assert_ne!(env_value(&env, "B"), env_value(&env, "C"));
    }

    #[test]
    fn required_keys_missing_from_both_sides_are_reported() {
        assert_eq!(
            missing_env_values(
                "A='set'\nB=''\n",
                &["A".to_owned(), "B".to_owned(), "C".to_owned()]
            ),
            ["B", "C"]
        );
    }

    #[test]
    fn a_blank_field_on_redeploy_keeps_the_servers_secret() {
        let fx = Fixture::new();
        fx.run_env(
            ID,
            None,
            "services: old\n",
            "MARIADB_ROOT_PASSWORD='original'\n",
        )
        .unwrap();
        // The panel leaves the key out entirely when its field is blank.
        let second = fx
            .run_env(ID_2, None, "services: old\n", "SERVER_NAME=':443'\n")
            .unwrap();
        assert!(second.changed);
        let env = fx.live(ENV_FILE).unwrap();
        assert_eq!(env_value(&env, "MARIADB_ROOT_PASSWORD"), Some("original"));
        assert_eq!(env_value(&env, "SERVER_NAME"), Some(":443"));
    }

    #[test]
    fn a_generated_key_survives_the_next_deploy_unchanged() {
        let fx = Fixture::new();
        let first = fx
            .run_full(ID, None, "services: old\n", "A='1'\n", &["MEILI_KEY"], &[])
            .unwrap();
        assert_eq!(first.generated_env_keys, ["MEILI_KEY"]);
        let key = env_value(&fx.live(ENV_FILE).unwrap(), "MEILI_KEY")
            .unwrap()
            .to_owned();

        let second = fx
            .run_full(
                ID_2,
                None,
                "services: old\n",
                "A='1'\n",
                &["MEILI_KEY"],
                &[],
            )
            .unwrap();
        assert!(second.generated_env_keys.is_empty());
        assert!(
            !second.changed,
            "a regenerated key would recreate containers"
        );
        assert_eq!(
            env_value(&fx.live(ENV_FILE).unwrap(), "MEILI_KEY"),
            Some(key.as_str())
        );
    }

    #[test]
    fn a_first_deploy_without_a_required_password_is_rejected_before_anything_runs() {
        let fx = Fixture::new();
        let error = fx
            .run_full(
                ID,
                None,
                "services: old\n",
                "SERVER_NAME=':80'\n",
                &[],
                &["MARIADB_ROOT_PASSWORD", "POSTGRES_PASSWORD"],
            )
            .unwrap_err();
        let (code, message) = error.protocol();
        assert_eq!(code, ErrorCode::InvalidInput);
        assert!(message.contains("MARIADB_ROOT_PASSWORD"), "{message}");
        assert!(message.contains("POSTGRES_PASSWORD"), "{message}");
        assert_eq!(fx.stack_entries(), Vec::<String>::new());
        assert_eq!(fx.calls(), "", "nothing may run before the check");
    }

    #[test]
    fn a_redeploy_satisfies_required_keys_from_the_existing_file() {
        let fx = Fixture::new();
        fx.run_full(
            ID,
            None,
            "services: old\n",
            "MARIADB_ROOT_PASSWORD='original'\n",
            &[],
            &["MARIADB_ROOT_PASSWORD"],
        )
        .unwrap();
        fx.run_full(
            ID_2,
            None,
            "services: old\n",
            "SERVER_NAME=':443'\n",
            &[],
            &["MARIADB_ROOT_PASSWORD"],
        )
        .expect("the server's own value satisfies the requirement");
    }

    #[test]
    fn env_key_lists_must_name_env_variables() {
        let mut value: serde_json::Value =
            serde_json::from_str(&request_json("services: a\n")).unwrap();
        value["requireEnvKeys"] = serde_json::json!(["not a key"]);
        assert_eq!(
            Request::parse(&value.to_string(), ID, None).unwrap_err(),
            RequestError::InvalidEnvKey
        );
    }

    #[test]
    fn inspect_json_without_a_healthcheck_parses() {
        let parsed = parse_inspect(
            br#"[{"Config":{"Image":"i","Labels":{"com.docker.compose.service":"valkey-8"}},
                 "Image":"sha256:1","State":{"Status":"running"},
                 "NetworkSettings":{"Ports":{"443/tcp":null}}}]"#,
        )
        .unwrap();
        assert_eq!(parsed[0].health, None);
        assert!(!parsed[0].https_published);
    }
}
