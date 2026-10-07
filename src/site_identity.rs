//! `site.allocateIdentity`, `site.releaseIdentity`, `site.updateIdentity` and
//! `site.renameIdentity`: the engine's one owner of a site's per-pool Unix
//! identity (milestone 064). The control panel used to run `groupadd`,
//! `useradd` and `userdel` over raw `sudo`, keep the host-wide UID counter in
//! a shell snippet, bump the per-pool port counter with `tee`, and write and
//! delete the `<domain>.identity` record the same way.
//!
//! Everything runs under the shared `stacks/wcp` lock (the outermost lock of
//! every site-service operation, milestones 048-052), then this scope's own
//! preflight (idempotency, transaction record, audit). That lock is what makes
//! the monotonic UID counter safe: two allocations, on different pools or the
//! same one, can never read the same counter value.
//!
//! The UID invariant the panel documented is enforced here, not trusted from
//! the caller:
//!
//! - ids come from a counter that only moves forward and is saved *before* the
//!   account is created, so a failed or rolled-back allocation burns its id
//!   instead of handing it to the next site;
//! - a candidate that any `passwd` or `group` entry already uses (as a uid or
//!   a gid) is skipped, so a counter that was reset can never collide with a
//!   live account;
//! - the counter starts at `max(10000, legacy counter, highest id in use + 1)`
//!   the first time it is read, which carries the panel's old
//!   `/etc/wcp/site-uid-counter` forward without a gap.
//!
//! Accounts are only ever created with an explicit `-u`/`-g` pair and only
//! under the derived name `wcp-site-<first 16 hex of sha256(domain)>`. An
//! existing account is reused (a runtime migration allocates a second record
//! for the same user), but only a managed one: a `wcp-site-` name with ids of
//! at least 1000. `site.releaseIdentity` deletes an account only when no other
//! identity record names it and the site's service directory is gone, so a
//! live process can never keep a freed uid.
//!
//! The record is the file the panel parses: `OS_USER=`, `UID=`, `GID=`,
//! `PORT=`, `ROOT=`, `WORKER_MODE=`, `WORKER_COUNT=`, one per line, in
//! `<runtime root>/<runtime id>/<domain>.identity`, mode `0644`.

use std::{
    fmt, fs, io,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    ingress::ConfigHash,
    mutation::preflight,
    process::{
        self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination,
        SubprocessDiagnostics,
    },
    site::{Domain, RuntimeId, SiteRelativePath, TrustedRoot},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        state::{self, TransactionState, TransactionStatus},
    },
};

pub const ALLOCATE_OPERATION: &str = "site.allocateIdentity";
pub const RELEASE_OPERATION: &str = "site.releaseIdentity";
pub const UPDATE_OPERATION: &str = "site.updateIdentity";
pub const RENAME_OPERATION: &str = "site.renameIdentity";

/// Engine-state scope: its own transactions and audit log, plus the UID
/// counter.
const SCOPE: &str = "site-identity";
const UID_COUNTER: &str = "uid-counter";
/// Per-pool counter file, unchanged from the panel's layout.
const PORT_COUNTER: &str = ".next-site-port";
const IDENTITY_EXTENSION: &str = "identity";

/// Well above Debian's `SYS_UID_MAX` (999) and `UID_MIN` (1000).
pub const UID_START: u32 = 10_000;
/// Ids at or above this are never handed out; far below `nobody` (65534).
pub const UID_MAX: u32 = 60_000;
/// Managed accounts are never below the human range.
pub const MIN_SITE_IDENTITY: u32 = 1000;
pub const PORT_START: u16 = 9000;
/// Below the Linux ephemeral range (32768+), so a site port never collides
/// with an outgoing connection's source port.
pub const PORT_MAX: u16 = 32_767;
pub const MAX_WORKER_COUNT: i64 = 64;
const USER_PREFIX: &str = "wcp-site-";
const MAX_ROOT_BYTES: usize = 4096;
const TOOL_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidRuntimeId,
    InvalidDomain,
    InvalidOsUser,
    InvalidRoot,
    InvalidWorkerCount,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl RequestError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidRuntimeId => "runtime-id is not a valid runtime pool identifier",
            Self::InvalidDomain => "domain is not a valid site domain",
            Self::InvalidOsUser => "os-user must be wcp-site- followed by 16 lowercase hex digits",
            Self::InvalidRoot => {
                "root must be a plain absolute path without spaces or dot segments"
            }
            Self::InvalidWorkerCount => "worker-count must be between 1 and 64",
            Self::InvalidRequestId => "request-id is not a canonical UUID",
            Self::InvalidIdempotencyKey => "idempotency-key is invalid",
        }
    }
}

/// The derived account name of a domain. The panel's `site_user_slug` is the
/// same function; the test below pins one value both sides must agree on.
pub fn derived_user(domain: &Domain) -> String {
    format!(
        "{USER_PREFIX}{}",
        &ConfigHash::of(domain.as_str().as_bytes()).as_str()[..16]
    )
}

fn valid_managed_user(name: &str) -> bool {
    name.strip_prefix(USER_PREFIX).is_some_and(|hash| {
        hash.len() == 16
            && hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// A document root: absolute, made of path-safe characters and no dot
/// segments, so it can sit in a Caddyfile and an identity record line, and it
/// lies under one of the engine's content roots.
pub(crate) fn validate_root(root: &str, content_roots: &[TrustedRoot]) -> Result<(), RequestError> {
    let path = Path::new(root);
    let plain = !root.is_empty()
        && root.len() <= MAX_ROOT_BYTES
        && root.starts_with('/')
        && !root.ends_with('/')
        && root.split('/').skip(1).all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        });
    if !plain
        || !content_roots
            .iter()
            .any(|content| path != content.as_path() && path.starts_with(content.as_path()))
    {
        return Err(RequestError::InvalidRoot);
    }
    Ok(())
}

fn validate_worker_count(count: i64) -> Result<(), RequestError> {
    if (1..=MAX_WORKER_COUNT).contains(&count) {
        Ok(())
    } else {
        Err(RequestError::InvalidWorkerCount)
    }
}

fn parse_ids(
    request_id: &str,
    key: Option<&str>,
) -> Result<(RequestId, Option<IdempotencyKey>), RequestError> {
    Ok((
        RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
        key.map(IdempotencyKey::parse)
            .transpose()
            .map_err(|_| RequestError::InvalidIdempotencyKey)?,
    ))
}

/// The settings a record carries besides the account and the port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SiteSettings {
    pub root: String,
    pub worker_mode: bool,
    pub worker_count: i64,
}

pub struct AllocateRequest {
    pub runtime_id: RuntimeId,
    pub domain: Domain,
    /// An existing managed account to reuse (a runtime migration keeps the
    /// site's user, which a rename may have left named after the old
    /// domain). `None` means the account derived from the domain.
    pub os_user: Option<String>,
    pub settings: SiteSettings,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl AllocateRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn parse(
        runtime_id: &str,
        domain: &str,
        os_user: Option<&str>,
        root: &str,
        worker_mode: bool,
        worker_count: i64,
        content_roots: &[TrustedRoot],
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        validate_root(root, content_roots)?;
        validate_worker_count(worker_count)?;
        let (request_id, idempotency_key) = parse_ids(request_id, key)?;
        let os_user = os_user
            .map(|name| {
                valid_managed_user(name)
                    .then(|| name.to_owned())
                    .ok_or(RequestError::InvalidOsUser)
            })
            .transpose()?;
        Ok(Self {
            runtime_id: RuntimeId::parse(runtime_id).map_err(|_| RequestError::InvalidRuntimeId)?,
            domain: Domain::parse(domain).map_err(|_| RequestError::InvalidDomain)?,
            os_user,
            settings: SiteSettings {
                root: root.to_owned(),
                worker_mode,
                worker_count,
            },
            request_id,
            idempotency_key,
        })
    }
}

pub struct ReleaseRequest {
    pub runtime_id: RuntimeId,
    pub domain: Domain,
    /// Also delete the account when this was its last record.
    pub remove_user: bool,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl ReleaseRequest {
    pub fn parse(
        runtime_id: &str,
        domain: &str,
        remove_user: bool,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let (request_id, idempotency_key) = parse_ids(request_id, key)?;
        Ok(Self {
            runtime_id: RuntimeId::parse(runtime_id).map_err(|_| RequestError::InvalidRuntimeId)?,
            domain: Domain::parse(domain).map_err(|_| RequestError::InvalidDomain)?,
            remove_user,
            request_id,
            idempotency_key,
        })
    }
}

pub struct UpdateRequest {
    pub runtime_id: RuntimeId,
    pub domain: Domain,
    pub root: String,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl UpdateRequest {
    pub fn parse(
        runtime_id: &str,
        domain: &str,
        root: &str,
        content_roots: &[TrustedRoot],
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        validate_root(root, content_roots)?;
        let (request_id, idempotency_key) = parse_ids(request_id, key)?;
        Ok(Self {
            runtime_id: RuntimeId::parse(runtime_id).map_err(|_| RequestError::InvalidRuntimeId)?,
            domain: Domain::parse(domain).map_err(|_| RequestError::InvalidDomain)?,
            root: root.to_owned(),
            request_id,
            idempotency_key,
        })
    }
}

pub struct RenameRequest {
    pub runtime_id: RuntimeId,
    pub from_domain: Domain,
    pub to_domain: Domain,
    pub root: String,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl RenameRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn parse(
        runtime_id: &str,
        from_domain: &str,
        to_domain: &str,
        root: &str,
        content_roots: &[TrustedRoot],
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        validate_root(root, content_roots)?;
        let (request_id, idempotency_key) = parse_ids(request_id, key)?;
        Ok(Self {
            runtime_id: RuntimeId::parse(runtime_id).map_err(|_| RequestError::InvalidRuntimeId)?,
            from_domain: Domain::parse(from_domain).map_err(|_| RequestError::InvalidDomain)?,
            to_domain: Domain::parse(to_domain).map_err(|_| RequestError::InvalidDomain)?,
            root: root.to_owned(),
            request_id,
            idempotency_key,
        })
    }
}

/// One site's record in one pool.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityRecord {
    pub os_user: String,
    pub uid: u32,
    pub gid: u32,
    pub port: u16,
    pub settings: SiteSettings,
}

impl IdentityRecord {
    fn render(&self) -> String {
        format!(
            "OS_USER={}\nUID={}\nGID={}\nPORT={}\nROOT={}\nWORKER_MODE={}\nWORKER_COUNT={}\n",
            self.os_user,
            self.uid,
            self.gid,
            self.port,
            self.settings.root,
            self.settings.worker_mode,
            self.settings.worker_count,
        )
    }

    /// Strict, like the panel's parser: a missing or malformed field is a
    /// corrupt record, never a default (a silent default uid would be a
    /// security regression).
    fn parse(content: &str) -> Option<Self> {
        let field = |key: &str| {
            content
                .lines()
                .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
        };
        Some(Self {
            os_user: field("OS_USER")?.to_owned(),
            uid: field("UID")?.parse().ok()?,
            gid: field("GID")?.parse().ok()?,
            port: field("PORT")?.parse().ok()?,
            settings: SiteSettings {
                root: field("ROOT")?.to_owned(),
                worker_mode: field("WORKER_MODE")? == "true",
                worker_count: field("WORKER_COUNT")?.parse().ok()?,
            },
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityResult {
    pub runtime_id: String,
    pub domain: String,
    pub os_user: String,
    pub uid: u32,
    pub gid: u32,
    pub port: u16,
    pub root: String,
    pub worker_mode: bool,
    pub worker_count: i64,
    /// This call created the account (a repeat, or a migration that reuses
    /// the site's user, reports `false`).
    pub user_created: bool,
    /// This call created or changed the record.
    pub changed: bool,
    pub completed_at_unix_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseResult {
    pub runtime_id: String,
    pub domain: String,
    /// `None` when there was no record to read the account from and none was
    /// asked to be deleted.
    pub os_user: Option<String>,
    pub record_removed: bool,
    pub user_removed: bool,
    /// The account was left because another pool's record still names it.
    pub user_retained: bool,
    pub completed_at_unix_secs: u64,
}

/// What the account tools are called. `useradd` and friends in production;
/// fixture scripts in tests.
pub struct UserTools<'a> {
    pub groupadd: &'a str,
    pub useradd: &'a str,
    pub userdel: &'a str,
    pub groupdel: &'a str,
}

impl UserTools<'static> {
    pub const PRODUCTION: Self = Self {
        groupadd: "groupadd",
        useradd: "useradd",
        userdel: "userdel",
        groupdel: "groupdel",
    };
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    /// `EngineConfig::runtime_root`: identity records and port counters live
    /// in `<runtime id>/`.
    pub runtime_root: &'a TrustedRoot,
    /// `EngineConfig::site_services_root`; a site's service directory must be
    /// gone before its account can be deleted.
    pub site_services_root: &'a TrustedRoot,
    /// `/etc/passwd` and `/etc/group` in production.
    pub passwd_file: &'a Path,
    pub group_file: &'a Path,
    /// The panel's old `/etc/wcp/site-uid-counter`, read once to seed the
    /// engine's counter.
    pub legacy_uid_counter: Option<&'a Path>,
    pub tools: UserTools<'a>,
}

#[derive(Debug)]
pub enum Error {
    /// Another operation holds the shared `stacks/wcp` lock. Nothing ran.
    StackBusy,
    Io(io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    /// Update or rename of a record that does not exist.
    RecordMissing,
    /// A record or account contradicts the request (rename target already
    /// recorded with other content, a record that names a missing account,
    /// an account that is not a managed one).
    Conflict(&'static str),
    /// The site's service directory still exists, so its account stays.
    ServiceStillPresent,
    /// The id or port counter is used up.
    Exhausted(&'static str),
    Tool(&'static str, ToolFailure),
    PostCommit(serde_json::Value),
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

#[derive(Debug)]
pub enum ToolFailure {
    Run(process::ProcessRunError),
    Rejected(SubprocessDiagnostics),
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::StackBusy => (
                ErrorCode::Conflict,
                "another operation on the wcp stack is in progress".into(),
            ),
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another site identity operation is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::RecordMissing => (
                ErrorCode::NotFound,
                "the site has no identity record".into(),
            ),
            Self::Conflict(message) | Self::Exhausted(message) => {
                (ErrorCode::Conflict, (*message).into())
            }
            Self::ServiceStillPresent => (
                ErrorCode::Conflict,
                "the site's service still exists; remove it before its account".into(),
            ),
            Self::Tool(tool, ToolFailure::Run(error)) => (
                process::spawn_error_code(error),
                format!("{tool} could not be run"),
            ),
            Self::Tool(tool, ToolFailure::Rejected(diagnostics)) => (
                if diagnostics.timed_out {
                    ErrorCode::Timeout
                } else if diagnostics.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::SubprocessFailed
                },
                format!("{tool} failed"),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit(_) => {
                (ErrorCode::Internal, "internal site identity error".into())
            }
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.protocol().1)
    }
}

// ------------------------------------------------------------------ files

fn record_rel(runtime_id: &RuntimeId, domain: &Domain) -> SiteRelativePath {
    rel(&format!("{runtime_id}/{domain}.{IDENTITY_EXTENSION}"))
}

fn read_record(
    runtime: &ManagedRoot,
    runtime_id: &RuntimeId,
    domain: &Domain,
) -> Result<Option<IdentityRecord>, Error> {
    match runtime.read_to_string(&record_rel(runtime_id, domain)) {
        Ok(content) => IdentityRecord::parse(&content)
            .map(Some)
            .ok_or(Error::Conflict("the site's identity record is corrupt")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Error::Io(error)),
    }
}

fn write_record(
    runtime: &ManagedRoot,
    runtime_id: &RuntimeId,
    domain: &Domain,
    record: &IdentityRecord,
) -> Result<(), Error> {
    let path = record_rel(runtime_id, domain);
    runtime
        .create_dir_all(&rel(runtime_id.as_str()))
        .map_err(Error::Io)?;
    runtime
        .write_atomic(&path, record.render().as_bytes())
        .map_err(Error::Io)?;
    // The panel reads the record as an unprivileged SSH user.
    runtime.set_mode(&path, 0o644).map_err(Error::Io)
}

fn remove_record(
    runtime: &ManagedRoot,
    runtime_id: &RuntimeId,
    domain: &Domain,
) -> Result<bool, Error> {
    match runtime.remove_file(&record_rel(runtime_id, domain)) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Error::Io(error)),
    }
}

/// Every record in every pool, as `(runtime id, domain, record)`.
fn all_records(runtime: &ManagedRoot) -> Result<Vec<(String, String, IdentityRecord)>, Error> {
    let mut records = Vec::new();
    for entry in runtime.child_entries().map_err(Error::Io)? {
        if !entry.is_dir {
            continue;
        }
        let Some(runtime_name) = entry.name.to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(pool) = rel_checked(&runtime_name).and_then(|path| {
            runtime
                .open_managed_dir(&path)
                .map_err(|_| io::Error::other("unreadable pool"))
        }) else {
            continue;
        };
        for name in pool.file_names().map_err(Error::Io)? {
            let Some(domain) = name.strip_suffix(&format!(".{IDENTITY_EXTENSION}")) else {
                continue;
            };
            let content = pool.read_to_string(&rel_checked(&name).map_err(Error::Io)?);
            if let Some(record) = content.ok().and_then(|text| IdentityRecord::parse(&text)) {
                records.push((runtime_name.clone(), domain.to_owned(), record));
            }
        }
    }
    Ok(records)
}

fn rel_checked(path: &str) -> io::Result<SiteRelativePath> {
    SiteRelativePath::parse(path).map_err(|_| io::Error::other("invalid path"))
}

/// One `passwd` or `group` entry: `(name, id, gid)`; groups have no gid
/// field of their own, so it repeats the id.
fn parse_accounts(content: &str, group: bool) -> Vec<(String, u32, u32)> {
    content
        .lines()
        .filter_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?;
            fields.next()?;
            let id: u32 = fields.next()?.parse().ok()?;
            let gid: u32 = if group {
                id
            } else {
                fields.next()?.parse().ok()?
            };
            Some((name.to_owned(), id, gid))
        })
        .collect()
}

fn passwd(ctx: &Context<'_>) -> Result<Vec<(String, u32, u32)>, Error> {
    Ok(parse_accounts(
        &fs::read_to_string(ctx.passwd_file).map_err(Error::Io)?,
        false,
    ))
}

fn groups(ctx: &Context<'_>) -> Result<Vec<(String, u32, u32)>, Error> {
    Ok(parse_accounts(
        &fs::read_to_string(ctx.group_file).map_err(Error::Io)?,
        true,
    ))
}

fn lookup_user(ctx: &Context<'_>, name: &str) -> Result<Option<(u32, u32)>, Error> {
    Ok(passwd(ctx)?
        .into_iter()
        .find(|(user, _, _)| user == name)
        .map(|(_, uid, gid)| (uid, gid)))
}

fn group_exists(ctx: &Context<'_>, name: &str) -> Result<bool, Error> {
    Ok(groups(ctx)?.iter().any(|(group, _, _)| group == name))
}

fn id_in_use(ctx: &Context<'_>, id: u32) -> Result<bool, Error> {
    Ok(passwd(ctx)?
        .iter()
        .any(|(_, uid, gid)| *uid == id || *gid == id)
        || groups(ctx)?.iter().any(|(_, gid, _)| *gid == id))
}

// -------------------------------------------------------------- counters

fn read_counter(scope: &ManagedRoot, path: &SiteRelativePath) -> Result<Option<u32>, Error> {
    match scope.read_to_string(path) {
        Ok(text) => text
            .trim()
            .parse()
            .map(Some)
            .map_err(|_| Error::Conflict("a counter file is corrupt")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Error::Io(error)),
    }
}

/// The counter value that has not been handed out yet. First use seeds it
/// from the panel's old counter and from the ids already in use, so it can
/// only start above everything that ever was.
fn next_uid(ctx: &Context<'_>, scope: &ManagedRoot) -> Result<u32, Error> {
    if let Some(next) = read_counter(scope, &rel(UID_COUNTER))? {
        return Ok(next);
    }
    let legacy = ctx
        .legacy_uid_counter
        .and_then(|path| fs::read_to_string(path).ok())
        .and_then(|text| text.trim().parse::<u32>().ok())
        .unwrap_or(0);
    let used = passwd(ctx)?
        .iter()
        .flat_map(|(_, uid, gid)| [*uid, *gid])
        .chain(groups(ctx)?.iter().map(|(_, gid, _)| *gid))
        .filter(|id| (UID_START..UID_MAX).contains(id))
        .max()
        .map_or(0, |id| id + 1);
    Ok(UID_START.max(legacy).max(used))
}

/// Takes the next free id and saves the counter past it *before* returning,
/// so whatever happens to the account afterwards the id is never offered
/// again.
fn allocate_uid(ctx: &Context<'_>, scope: &ManagedRoot) -> Result<u32, Error> {
    let mut candidate = next_uid(ctx, scope)?;
    while id_in_use(ctx, candidate)? {
        candidate += 1;
    }
    if candidate >= UID_MAX {
        return Err(Error::Exhausted("the site uid range is exhausted"));
    }
    scope
        .write_atomic(&rel(UID_COUNTER), format!("{}\n", candidate + 1).as_bytes())
        .map_err(Error::Io)?;
    Ok(candidate)
}

/// Per-pool and monotonic like the uid; the file holds the next port to hand
/// out, as before.
fn allocate_port(runtime: &ManagedRoot, runtime_id: &RuntimeId) -> Result<u16, Error> {
    let path = rel(&format!("{runtime_id}/{PORT_COUNTER}"));
    runtime
        .create_dir_all(&rel(runtime_id.as_str()))
        .map_err(Error::Io)?;
    let next = read_counter(runtime, &path)?.unwrap_or(u32::from(PORT_START));
    if next > u32::from(PORT_MAX) {
        return Err(Error::Exhausted(
            "the runtime pool's port range is exhausted",
        ));
    }
    runtime
        .write_atomic(&path, format!("{}\n", next + 1).as_bytes())
        .map_err(Error::Io)?;
    Ok(u16::try_from(next).expect("bounded by PORT_MAX"))
}

// ----------------------------------------------------------------- tools

fn run_tool(
    program: &str,
    label: &'static str,
    args: &[String],
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let limits = ProcessLimits {
        timeout: TOOL_TIMEOUT,
        ..ProcessLimits::default()
    };
    let output = process::run(&ProcessRequest::new(program).args(args), &limits, cancel)
        .map_err(|error| Error::Tool(label, ToolFailure::Run(error)))?;
    if matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        Ok(())
    } else {
        Err(Error::Tool(
            label,
            ToolFailure::Rejected(SubprocessDiagnostics::from_output(label, &output)),
        ))
    }
}

/// Creates the group and the user with the same explicit numeric id.
/// Never a bare `useradd --system`: Debian's own allocator recycles its small
/// range, which is how a deleted site's orphaned process ends up with access
/// to a new tenant's files.
fn create_account(
    ctx: &Context<'_>,
    name: &str,
    id: u32,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    // A group left behind by an earlier interrupted attempt carries our own
    // name and nothing else; clear it so the new id pair is consistent.
    if group_exists(ctx, name)? {
        run_tool(ctx.tools.groupdel, "groupdel", &[name.to_owned()], cancel)?;
    }
    let id_text = id.to_string();
    run_tool(
        ctx.tools.groupadd,
        "groupadd",
        &["--system".into(), "-g".into(), id_text.clone(), name.into()],
        cancel,
    )?;
    let created = run_tool(
        ctx.tools.useradd,
        "useradd",
        &[
            "--system".into(),
            "-u".into(),
            id_text.clone(),
            "-g".into(),
            id_text,
            "--no-create-home".into(),
            "--shell".into(),
            "/usr/sbin/nologin".into(),
            name.into(),
        ],
        cancel,
    );
    if let Err(error) = created {
        let _ = run_tool(ctx.tools.groupdel, "groupdel", &[name.to_owned()], cancel);
        return Err(error);
    }
    match lookup_user(ctx, name)? {
        Some((uid, gid)) if uid == id && gid == id => Ok(()),
        _ => {
            let _ = delete_account(ctx, name, cancel);
            Err(Error::Conflict(
                "the new account does not have the requested ids",
            ))
        }
    }
}

fn delete_account(ctx: &Context<'_>, name: &str, cancel: &CancellationToken) -> Result<(), Error> {
    if lookup_user(ctx, name)?.is_some() {
        run_tool(ctx.tools.userdel, "userdel", &[name.to_owned()], cancel)?;
    }
    // `userdel` removes the user's own group when nothing else uses it.
    if group_exists(ctx, name)? {
        run_tool(ctx.tools.groupdel, "groupdel", &[name.to_owned()], cancel)?;
    }
    Ok(())
}

// ------------------------------------------------------------ operations

fn result_of(
    runtime_id: &RuntimeId,
    domain: &Domain,
    record: &IdentityRecord,
    user_created: bool,
    changed: bool,
) -> IdentityResult {
    IdentityResult {
        runtime_id: runtime_id.as_str().to_owned(),
        domain: domain.as_str().to_owned(),
        os_user: record.os_user.clone(),
        uid: record.uid,
        gid: record.gid,
        port: record.port,
        root: record.settings.root.clone(),
        worker_mode: record.settings.worker_mode,
        worker_count: record.settings.worker_count,
        user_created,
        changed,
        completed_at_unix_secs: unix_now_secs(),
    }
}

/// Makes sure `domain` has an account, a port and a record in the pool.
/// Idempotent: an existing record keeps its uid and port and is only
/// rewritten when the settings differ.
pub fn allocate(
    ctx: &Context<'_>,
    req: &AllocateRequest,
    cancel: &CancellationToken,
) -> Result<IdentityResult, Error> {
    run_admitted(
        ctx,
        ALLOCATE_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        |scope| {
            let runtime = ManagedRoot::open(ctx.runtime_root).map_err(Error::Io)?;
            let derived = derived_user(&req.domain);
            let wanted = req.os_user.clone().unwrap_or_else(|| derived.clone());

            if let Some(mut record) = read_record(&runtime, &req.runtime_id, &req.domain)? {
                if record.os_user != wanted {
                    return Err(Error::Conflict(
                        "the site's record names a different account",
                    ));
                }
                match lookup_user(ctx, &record.os_user)? {
                    Some((uid, gid)) if uid == record.uid && gid == record.gid => {}
                    _ => return Err(Error::Conflict("the record names a missing account")),
                }
                let changed = record.settings != req.settings;
                if changed {
                    record.settings = req.settings.clone();
                    write_record(&runtime, &req.runtime_id, &req.domain, &record)?;
                }
                return Ok(result_of(
                    &req.runtime_id,
                    &req.domain,
                    &record,
                    false,
                    changed,
                ));
            }

            let (uid, gid, created) = match lookup_user(ctx, &wanted)? {
                Some((uid, gid)) => {
                    if uid < MIN_SITE_IDENTITY || gid < MIN_SITE_IDENTITY {
                        return Err(Error::Conflict("the account is not a site identity"));
                    }
                    (uid, gid, false)
                }
                None if wanted == derived => {
                    let id = allocate_uid(ctx, scope)?;
                    create_account(ctx, &wanted, id, cancel)?;
                    (id, id, true)
                }
                None => return Err(Error::Conflict("the requested account does not exist")),
            };

            let finished = (|| {
                let port = allocate_port(&runtime, &req.runtime_id)?;
                let record = IdentityRecord {
                    os_user: wanted.clone(),
                    uid,
                    gid,
                    port,
                    settings: req.settings.clone(),
                };
                write_record(&runtime, &req.runtime_id, &req.domain, &record)?;
                Ok(record)
            })();
            match finished {
                Ok(record) => Ok(result_of(
                    &req.runtime_id,
                    &req.domain,
                    &record,
                    created,
                    true,
                )),
                Err(error) => {
                    // Undo what this call made. The uid stays burned.
                    let _ = remove_record(&runtime, &req.runtime_id, &req.domain);
                    if created {
                        let _ = delete_account(ctx, &wanted, cancel);
                    }
                    Err(error)
                }
            }
        },
    )
}

/// Removes the pool's record and, on request, the account when no other
/// record uses it. A service directory that is still there keeps the
/// account: `userdel` on a uid with a live process would leave that process
/// running under a reusable id.
pub fn release(
    ctx: &Context<'_>,
    req: &ReleaseRequest,
    cancel: &CancellationToken,
) -> Result<ReleaseResult, Error> {
    run_admitted(
        ctx,
        RELEASE_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        |_| {
            let runtime = ManagedRoot::open(ctx.runtime_root).map_err(Error::Io)?;
            let record = read_record(&runtime, &req.runtime_id, &req.domain)?;
            let os_user = record
                .as_ref()
                .map(|record| record.os_user.clone())
                .or_else(|| req.remove_user.then(|| derived_user(&req.domain)));
            let mut user_removed = false;
            let mut user_retained = false;

            if req.remove_user {
                let services = ManagedRoot::open(ctx.site_services_root).map_err(Error::Io)?;
                let service = rel(&format!("{}/{}", req.runtime_id, req.domain));
                if services.exists(&service) {
                    return Err(Error::ServiceStillPresent);
                }
                let name = os_user.as_deref().expect("set when remove_user is true");
                let shared = all_records(&runtime)?.iter().any(|(pool, domain, other)| {
                    other.os_user == name
                        && !(pool == req.runtime_id.as_str() && domain == req.domain.as_str())
                });
                if shared {
                    user_retained = true;
                } else if let Some((uid, gid)) = lookup_user(ctx, name)? {
                    if !valid_managed_user(name)
                        || uid < MIN_SITE_IDENTITY
                        || gid < MIN_SITE_IDENTITY
                    {
                        return Err(Error::Conflict(
                            "the account is not a managed site identity",
                        ));
                    }
                    delete_account(ctx, name, cancel)?;
                    user_removed = true;
                }
            }

            // The record goes last: until the account is really gone a repeat
            // still knows which account to remove (a renamed site's account
            // is not named after its current domain).
            let record_removed = remove_record(&runtime, &req.runtime_id, &req.domain)?;
            Ok(ReleaseResult {
                runtime_id: req.runtime_id.as_str().to_owned(),
                domain: req.domain.as_str().to_owned(),
                os_user,
                record_removed,
                user_removed,
                user_retained,
                completed_at_unix_secs: unix_now_secs(),
            })
        },
    )
}

/// Changes only the document root of an existing record.
pub fn update(
    ctx: &Context<'_>,
    req: &UpdateRequest,
    _cancel: &CancellationToken,
) -> Result<IdentityResult, Error> {
    run_admitted(
        ctx,
        UPDATE_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        |_| {
            let runtime = ManagedRoot::open(ctx.runtime_root).map_err(Error::Io)?;
            let mut record =
                read_record(&runtime, &req.runtime_id, &req.domain)?.ok_or(Error::RecordMissing)?;
            let changed = record.settings.root != req.root;
            if changed {
                record.settings.root = req.root.clone();
                write_record(&runtime, &req.runtime_id, &req.domain, &record)?;
            }
            Ok(result_of(
                &req.runtime_id,
                &req.domain,
                &record,
                false,
                changed,
            ))
        },
    )
}

/// Moves a record to the site's new domain with its new root, keeping the
/// account, ids and port. The new record is written before the old one is
/// removed, so a failure never leaves the site without a record; a repeat
/// after the move finds only the new one and succeeds.
pub fn rename(
    ctx: &Context<'_>,
    req: &RenameRequest,
    _cancel: &CancellationToken,
) -> Result<IdentityResult, Error> {
    run_admitted(
        ctx,
        RENAME_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        |_| {
            let runtime = ManagedRoot::open(ctx.runtime_root).map_err(Error::Io)?;
            let existing = read_record(&runtime, &req.runtime_id, &req.to_domain)?;
            let record = match read_record(&runtime, &req.runtime_id, &req.from_domain)? {
                Some(mut moved) => {
                    moved.settings.root = req.root.clone();
                    if req.from_domain != req.to_domain
                        && existing.as_ref().is_some_and(|other| *other != moved)
                    {
                        return Err(Error::Conflict("the new domain already has a record"));
                    }
                    moved
                }
                None => match existing {
                    // Already moved by an earlier attempt.
                    Some(done) if done.settings.root == req.root => {
                        return Ok(result_of(
                            &req.runtime_id,
                            &req.to_domain,
                            &done,
                            false,
                            false,
                        ));
                    }
                    _ => return Err(Error::RecordMissing),
                },
            };
            write_record(&runtime, &req.runtime_id, &req.to_domain, &record)?;
            if req.from_domain != req.to_domain {
                remove_record(&runtime, &req.runtime_id, &req.from_domain)?;
            }
            Ok(result_of(
                &req.runtime_id,
                &req.to_domain,
                &record,
                false,
                true,
            ))
        },
    )
}

// ------------------------------------------------------------ transaction

/// Stack lock, then this scope's preflight, then `body`, then the
/// transaction record and audit entry.
fn run_admitted<T, F>(
    ctx: &Context<'_>,
    operation: &'static str,
    request_id: RequestId,
    key: Option<&IdempotencyKey>,
    body: F,
) -> Result<T, Error>
where
    T: Serialize + for<'de> Deserialize<'de>,
    F: FnOnce(&ManagedRoot) -> Result<T, Error>,
{
    let scope = open_scope(ctx.engine_state).map_err(Error::Io)?;
    let stack_scope = crate::stack_deploy::open_scope(ctx.engine_state).map_err(Error::Io)?;
    let _stack_lock = crate::stack_deploy::acquire_stack_lock(&stack_scope, request_id)
        .map_err(|_| Error::StackBusy)?;

    let admitted =
        match preflight::run(&scope, request_id, key, operation).map_err(Error::Preflight)? {
            preflight::Outcome::Replay(original) => return replay(&scope, operation, original),
            preflight::Outcome::Proceed(admitted) => admitted,
        };
    let preflight::Admitted { lock, state } = admitted;
    let state_path = transaction_path(request_id);
    let audit_path = rel("audit/events.jsonl");

    let value = match body(&scope) {
        Ok(value) => value,
        Err(error) => return Err(fail(&scope, &state_path, &audit_path, state, error)),
    };
    let mut state = state;
    let encoded = serde_json::to_value(&value).expect("operation results always serialize");
    state
        .mark_committed(encoded.clone())
        .expect("state is always InProgress at this point");
    if state::save(&scope, &state_path, &state).is_err() {
        drop(lock);
        return Err(Error::PostCommit(encoded));
    }
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(request_id, true, None),
    );
    drop(lock);
    Ok(value)
}

fn open_scope(engine_state: &ManagedRoot) -> io::Result<ManagedRoot> {
    engine_state.create_dir_all(&rel(SCOPE))?;
    let scope = engine_state.open_managed_dir(&rel(SCOPE))?;
    for child in ["locks", "transactions", "audit"] {
        scope.create_dir_all(&rel(child))?;
    }
    Ok(scope)
}

fn replay<T>(scope: &ManagedRoot, operation: &'static str, original: RequestId) -> Result<T, Error>
where
    T: for<'de> Deserialize<'de>,
{
    let loaded = state::load(scope, &transaction_path(original))
        .map_err(|error| Error::Io(io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != operation {
        return Err(Error::Io(io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => loaded
            .outcome
            .and_then(|outcome| outcome.result)
            .ok_or_else(|| Error::Io(io::Error::other("committed outcome has no result")))
            .and_then(|value| {
                serde_json::from_value(value).map_err(|error| Error::Io(io::Error::other(error)))
            }),
        TransactionStatus::Failed => {
            let outcome = loaded
                .outcome
                .expect("a failed transaction always has an outcome");
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

fn transaction_path(request_id: RequestId) -> SiteRelativePath {
    rel(&format!("transactions/{request_id}.json"))
}

fn rel(path: &str) -> SiteRelativePath {
    SiteRelativePath::parse(path).expect("literal path is valid")
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(all(test, unix))]
mod tests {
    use std::{os::unix::fs::PermissionsExt, path::PathBuf, sync::Mutex};

    use super::*;

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const ID2: &str = "123e4567-e89b-12d3-a456-426614174001";
    const ID3: &str = "123e4567-e89b-12d3-a456-426614174002";
    const ID4: &str = "123e4567-e89b-12d3-a456-426614174003";
    const ID5: &str = "123e4567-e89b-12d3-a456-426614174004";

    /// Fixture scripts fork; serialize like the other fork-heavy modules.
    static SERIAL: Mutex<()> = Mutex::new(());

    struct Fixture {
        _dir: tempfile::TempDir,
        state: ManagedRoot,
        runtime_root: TrustedRoot,
        site_services_root: TrustedRoot,
        content: TrustedRoot,
        passwd: PathBuf,
        group: PathBuf,
        legacy: PathBuf,
        bin: PathBuf,
        calls: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path().canonicalize().unwrap();
            for sub in ["state", "runtimes", "site-services", "www", "bin"] {
                fs::create_dir(base.join(sub)).unwrap();
            }
            let passwd = base.join("passwd");
            let group = base.join("group");
            fs::write(&passwd, "root:x:0:0:root:/root:/bin/bash\n").unwrap();
            fs::write(&group, "root:x:0:\n").unwrap();
            let calls = base.join("calls.log");
            let bin = base.join("bin");
            let script = |name: &str, body: String| {
                let path = bin.join(name);
                fs::write(
                    &path,
                    format!(
                        "#!/bin/sh\necho \"{name} $*\" >> '{}'\n{body}",
                        calls.display()
                    ),
                )
                .unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            };
            let (p, g) = (passwd.display(), group.display());
            script(
                "groupadd",
                format!("grep -q \"^$4:\" '{g}' && exit 9\necho \"$4:x:$3:\" >> '{g}'\n"),
            );
            script(
                "useradd",
                format!(
                    "[ -f '{b}/fail-useradd' ] && exit 9\n\
                     echo \"$9:x:$3:$5:site:/nonexistent:/usr/sbin/nologin\" >> '{p}'\n",
                    b = base.display()
                ),
            );
            script(
                "userdel",
                format!(
                    "grep -v \"^$1:\" '{p}' > '{p}.new'; mv '{p}.new' '{p}'; grep -v \"^$1:\" '{g}' > '{g}.new'; mv '{g}.new' '{g}'\n"
                ),
            );
            script(
                "groupdel",
                format!("grep -v \"^$1:\" '{g}' > '{g}.new'; mv '{g}.new' '{g}'\n"),
            );
            Self {
                state: ManagedRoot::open(&TrustedRoot::parse(base.join("state")).unwrap()).unwrap(),
                runtime_root: TrustedRoot::parse(base.join("runtimes")).unwrap(),
                site_services_root: TrustedRoot::parse(base.join("site-services")).unwrap(),
                content: TrustedRoot::parse(base.join("www")).unwrap(),
                legacy: base.join("legacy-counter"),
                passwd,
                group,
                bin,
                calls,
                _dir: dir,
            }
        }

        fn ctx(&self) -> Context<'_> {
            Context {
                engine_state: &self.state,
                runtime_root: &self.runtime_root,
                site_services_root: &self.site_services_root,
                passwd_file: &self.passwd,
                group_file: &self.group,
                legacy_uid_counter: Some(&self.legacy),
                tools: UserTools {
                    groupadd: Box::leak(
                        self.bin
                            .join("groupadd")
                            .to_string_lossy()
                            .into_owned()
                            .into_boxed_str(),
                    ),
                    useradd: Box::leak(
                        self.bin
                            .join("useradd")
                            .to_string_lossy()
                            .into_owned()
                            .into_boxed_str(),
                    ),
                    userdel: Box::leak(
                        self.bin
                            .join("userdel")
                            .to_string_lossy()
                            .into_owned()
                            .into_boxed_str(),
                    ),
                    groupdel: Box::leak(
                        self.bin
                            .join("groupdel")
                            .to_string_lossy()
                            .into_owned()
                            .into_boxed_str(),
                    ),
                },
            }
        }

        fn root(&self, domain: &str) -> String {
            format!("{}/{domain}/public", self.content.as_path().display())
        }

        fn alloc_req(
            &self,
            runtime: &str,
            domain: &str,
            id: &str,
            key: Option<&str>,
        ) -> AllocateRequest {
            AllocateRequest::parse(
                runtime,
                domain,
                None,
                &self.root(domain),
                false,
                4,
                std::slice::from_ref(&self.content),
                id,
                key,
            )
            .unwrap()
        }

        fn allocate(&self, runtime: &str, domain: &str, id: &str) -> Result<IdentityResult, Error> {
            allocate(
                &self.ctx(),
                &self.alloc_req(runtime, domain, id, None),
                &CancellationToken::default(),
            )
        }

        fn release(
            &self,
            runtime: &str,
            domain: &str,
            remove_user: bool,
            id: &str,
        ) -> Result<ReleaseResult, Error> {
            release(
                &self.ctx(),
                &ReleaseRequest::parse(runtime, domain, remove_user, id, None).unwrap(),
                &CancellationToken::default(),
            )
        }

        fn record_path(&self, runtime: &str, domain: &str) -> PathBuf {
            self.runtime_root
                .as_path()
                .join(runtime)
                .join(format!("{domain}.identity"))
        }

        fn passwd_text(&self) -> String {
            fs::read_to_string(&self.passwd).unwrap()
        }

        fn calls(&self) -> Vec<String> {
            fs::read_to_string(&self.calls)
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect()
        }
    }

    #[test]
    fn the_account_name_matches_the_panels_slug() {
        // `site_user_slug("example.test")` in website-control-panel.
        assert_eq!(
            derived_user(&Domain::parse("example.test").unwrap()),
            "wcp-site-9b263fbcb5898531"
        );
    }

    #[test]
    fn allocation_creates_the_account_port_and_record() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        let result = fixture.allocate("fp1-php83", "a.test", ID).unwrap();
        assert_eq!(
            (result.uid, result.gid, result.port),
            (10_000, 10_000, 9000)
        );
        assert!(result.user_created && result.changed);
        assert!(
            fixture
                .passwd_text()
                .contains(&format!("{}:x:10000:10000", result.os_user))
        );
        let record = fs::read_to_string(fixture.record_path("fp1-php83", "a.test")).unwrap();
        assert_eq!(
            record,
            format!(
                "OS_USER={}\nUID=10000\nGID=10000\nPORT=9000\nROOT={}\nWORKER_MODE=false\nWORKER_COUNT=4\n",
                result.os_user,
                fixture.root("a.test")
            )
        );
        let mode = fs::metadata(fixture.record_path("fp1-php83", "a.test"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o644);
        assert_eq!(
            fixture.calls(),
            vec![
                format!("groupadd --system -g 10000 {}", result.os_user),
                format!(
                    "useradd --system -u 10000 -g 10000 --no-create-home --shell /usr/sbin/nologin {}",
                    result.os_user
                ),
            ]
        );
    }

    #[test]
    fn uids_only_move_forward_and_are_never_reused_after_a_release() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        let a = fixture.allocate("fp1-php83", "a.test", ID).unwrap();
        let b = fixture.allocate("fp1-php84", "b.test", ID2).unwrap();
        assert_eq!((a.uid, b.uid), (10_000, 10_001));
        // Ports are per pool: each pool starts at 9000.
        assert_eq!((a.port, b.port), (9000, 9000));

        let released = fixture.release("fp1-php83", "a.test", true, ID3).unwrap();
        assert!(released.record_removed && released.user_removed);
        assert!(!fixture.passwd_text().contains(&a.os_user));

        // The freed 10000 is not offered again.
        let c = fixture.allocate("fp1-php83", "c.test", ID4).unwrap();
        assert_eq!(c.uid, 10_002);
        assert_eq!(c.port, 9001);
    }

    #[test]
    fn a_rolled_back_allocation_still_burns_its_uid() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        fs::write(fixture._dir.path().join("fail-useradd"), "").unwrap();
        let error = fixture.allocate("fp1-php83", "a.test", ID).unwrap_err();
        assert!(matches!(error, Error::Tool("useradd", _)));
        assert_eq!(error.protocol().0, ErrorCode::SubprocessFailed);
        // Nothing is left behind.
        assert!(!fixture.passwd_text().contains("wcp-site-"));
        assert!(
            !fs::read_to_string(&fixture.group)
                .unwrap()
                .contains("wcp-site-")
        );
        assert!(!fixture.record_path("fp1-php83", "a.test").exists());

        fs::remove_file(fixture._dir.path().join("fail-useradd")).unwrap();
        let next = fixture.allocate("fp1-php83", "a.test", ID2).unwrap();
        assert_eq!(next.uid, 10_001);
    }

    #[test]
    fn ids_in_use_by_any_account_or_group_are_skipped() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        // First read seeds above the highest id in use.
        fs::write(
            &fixture.passwd,
            "root:x:0:0::/root:/bin/sh\nold:x:10004:10004::/h:/bin/sh\n",
        )
        .unwrap();
        fs::write(&fixture.group, "root:x:0:\nold:x:10004:\nstray:x:10005:\n").unwrap();
        let first = fixture.allocate("fp1-php83", "a.test", ID).unwrap();
        assert_eq!(first.uid, 10_006);
        // Later, a group appears on the counter's next value: skipped.
        fs::write(
            &fixture.group,
            format!(
                "{}stray2:x:10007:\n",
                fs::read_to_string(&fixture.group).unwrap()
            ),
        )
        .unwrap();
        let second = fixture.allocate("fp1-php83", "b.test", ID2).unwrap();
        assert_eq!(second.uid, 10_008);
    }

    #[test]
    fn the_counter_continues_from_the_panels_legacy_file() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        fs::write(&fixture.legacy, "10250\n").unwrap();
        let result = fixture.allocate("fp1-php83", "a.test", ID).unwrap();
        assert_eq!(result.uid, 10_250);
        // The legacy file is read once; the engine's own counter leads.
        fs::write(&fixture.legacy, "10000\n").unwrap();
        assert_eq!(
            fixture.allocate("fp1-php83", "b.test", ID2).unwrap().uid,
            10_251
        );
    }

    #[test]
    fn allocation_is_idempotent_and_updates_only_changed_settings() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        let first = fixture.allocate("fp1-php83", "a.test", ID).unwrap();
        let again = fixture.allocate("fp1-php83", "a.test", ID2).unwrap();
        assert_eq!((again.uid, again.port), (first.uid, first.port));
        assert!(!again.user_created && !again.changed);

        let changed = allocate(
            &fixture.ctx(),
            &AllocateRequest::parse(
                "fp1-php83",
                "a.test",
                None,
                &fixture.root("a.test"),
                true,
                8,
                std::slice::from_ref(&fixture.content),
                ID3,
                None,
            )
            .unwrap(),
            &CancellationToken::default(),
        )
        .unwrap();
        assert!(changed.changed && !changed.user_created);
        assert_eq!(
            (changed.uid, changed.port, changed.worker_count),
            (first.uid, first.port, 8)
        );
    }

    #[test]
    fn a_replayed_request_returns_the_original_without_running_tools_again() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        let request = fixture.alloc_req("fp1-php83", "a.test", ID, Some("alloc-1"));
        let first = allocate(&fixture.ctx(), &request, &CancellationToken::default()).unwrap();
        let calls = fixture.calls().len();
        let repeat = fixture.alloc_req("fp1-php83", "a.test", ID2, Some("alloc-1"));
        let replayed = allocate(&fixture.ctx(), &repeat, &CancellationToken::default()).unwrap();
        assert_eq!(replayed.uid, first.uid);
        assert_eq!(fixture.calls().len(), calls);
    }

    #[test]
    fn a_migration_reuses_the_account_with_a_port_from_the_target_pool() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        let source = fixture.allocate("fp1-php83", "a.test", ID).unwrap();
        // Burn a port on the target pool first.
        fixture.allocate("fp1-php84", "b.test", ID2).unwrap();
        let moved = allocate(
            &fixture.ctx(),
            &AllocateRequest::parse(
                "fp1-php84",
                "a.test",
                Some(&source.os_user),
                &fixture.root("a.test"),
                false,
                4,
                std::slice::from_ref(&fixture.content),
                ID3,
                None,
            )
            .unwrap(),
            &CancellationToken::default(),
        )
        .unwrap();
        assert_eq!((moved.uid, moved.gid), (source.uid, source.gid));
        assert_eq!(moved.port, 9001);
        assert!(!moved.user_created);

        // Releasing the source record keeps the account: the target uses it.
        let released = fixture.release("fp1-php83", "a.test", true, ID4).unwrap();
        assert!(released.record_removed && released.user_retained && !released.user_removed);
        assert!(fixture.passwd_text().contains(&source.os_user));
        // Releasing the last record deletes it.
        let last = fixture.release("fp1-php84", "a.test", true, ID5).unwrap();
        assert!(last.user_removed);
        assert!(!fixture.passwd_text().contains(&source.os_user));
    }

    #[test]
    fn an_unknown_or_unmanaged_account_is_never_adopted() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        // A managed-looking name that does not exist is not created for
        // another domain's slug.
        let error = allocate(
            &fixture.ctx(),
            &AllocateRequest::parse(
                "fp1-php83",
                "a.test",
                Some("wcp-site-0123456789abcdef"),
                &fixture.root("a.test"),
                false,
                4,
                std::slice::from_ref(&fixture.content),
                ID,
                None,
            )
            .unwrap(),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::Conflict(_)));
        // Arbitrary names are refused at parse time.
        for name in [
            "root",
            "www-data",
            "wcp-site-XYZ",
            "wcp-site-0123456789abcdeg",
        ] {
            assert_eq!(
                AllocateRequest::parse(
                    "fp1-php83",
                    "a.test",
                    Some(name),
                    &fixture.root("a.test"),
                    false,
                    4,
                    std::slice::from_ref(&fixture.content),
                    ID,
                    None
                )
                .err(),
                Some(RequestError::InvalidOsUser)
            );
        }
        // A low-numbered account with the derived name is not a site identity.
        let derived = derived_user(&Domain::parse("a.test").unwrap());
        fs::write(
            &fixture.passwd,
            format!("{}{derived}:x:500:500::/h:/bin/sh\n", fixture.passwd_text()),
        )
        .unwrap();
        assert!(matches!(
            fixture.allocate("fp1-php83", "a.test", ID2).unwrap_err(),
            Error::Conflict(_)
        ));
    }

    #[test]
    fn release_refuses_to_delete_the_account_while_the_service_exists() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        let a = fixture.allocate("fp1-php83", "a.test", ID).unwrap();
        fs::create_dir_all(
            fixture
                .site_services_root
                .as_path()
                .join("fp1-php83/a.test"),
        )
        .unwrap();
        let error = fixture
            .release("fp1-php83", "a.test", true, ID2)
            .unwrap_err();
        assert!(matches!(error, Error::ServiceStillPresent));
        assert!(fixture.passwd_text().contains(&a.os_user));
        assert!(fixture.record_path("fp1-php83", "a.test").exists());
        // Record-only release does not look at the service.
        assert!(
            fixture
                .release("fp1-php83", "a.test", false, ID3)
                .unwrap()
                .record_removed
        );
        assert!(fixture.passwd_text().contains(&a.os_user));
    }

    #[test]
    fn release_of_a_missing_record_is_a_no_op_and_a_repeat_after_failure_finishes() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        let none = fixture
            .release("fp1-php83", "ghost.test", false, ID)
            .unwrap();
        assert!(!none.record_removed && !none.user_removed);

        // Account deleted but the record survives (interrupted release): the
        // repeat removes the record.
        let a = fixture.allocate("fp1-php83", "a.test", ID2).unwrap();
        fs::write(&fixture.passwd, "root:x:0:0:root:/root:/bin/bash\n").unwrap();
        fs::write(&fixture.group, "root:x:0:\n").unwrap();
        let repeat = fixture.release("fp1-php83", "a.test", true, ID3).unwrap();
        assert!(repeat.record_removed && !repeat.user_removed);
        assert_eq!(repeat.os_user.as_deref(), Some(a.os_user.as_str()));
    }

    #[test]
    fn rename_moves_the_record_keeping_account_and_port() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        let a = fixture.allocate("fp1-php83", "a.test", ID).unwrap();
        let request = |from: &str, to: &str, id: &str| {
            RenameRequest::parse(
                "fp1-php83",
                from,
                to,
                &fixture.root(to),
                std::slice::from_ref(&fixture.content),
                id,
                None,
            )
            .unwrap()
        };
        let moved = rename(
            &fixture.ctx(),
            &request("a.test", "b.test", ID2),
            &CancellationToken::default(),
        )
        .unwrap();
        assert_eq!(
            (moved.uid, moved.port, moved.os_user.clone()),
            (a.uid, a.port, a.os_user.clone())
        );
        assert_eq!(moved.root, fixture.root("b.test"));
        assert!(!fixture.record_path("fp1-php83", "a.test").exists());
        assert!(fixture.record_path("fp1-php83", "b.test").exists());

        // A repeat (new request id) after the move is a no-op success.
        let again = rename(
            &fixture.ctx(),
            &request("a.test", "b.test", ID3),
            &CancellationToken::default(),
        )
        .unwrap();
        assert!(!again.changed);

        // And back, the way a panel rollback does.
        rename(
            &fixture.ctx(),
            &request("b.test", "a.test", ID4),
            &CancellationToken::default(),
        )
        .unwrap();
        assert!(fixture.record_path("fp1-php83", "a.test").exists());

        // A missing source with no target is an error.
        assert!(matches!(
            rename(
                &fixture.ctx(),
                &request("x.test", "y.test", ID5),
                &CancellationToken::default()
            )
            .unwrap_err(),
            Error::RecordMissing
        ));
    }

    #[test]
    fn rename_refuses_to_overwrite_a_different_record() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        fixture.allocate("fp1-php83", "a.test", ID).unwrap();
        fixture.allocate("fp1-php83", "b.test", ID2).unwrap();
        let error = rename(
            &fixture.ctx(),
            &RenameRequest::parse(
                "fp1-php83",
                "a.test",
                "b.test",
                &fixture.root("b.test"),
                std::slice::from_ref(&fixture.content),
                ID3,
                None,
            )
            .unwrap(),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::Conflict(_)));
        assert!(fixture.record_path("fp1-php83", "a.test").exists());
    }

    #[test]
    fn update_changes_only_the_root() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        let a = fixture.allocate("fp1-php83", "a.test", ID).unwrap();
        let root = format!("{}/sites/abc/current", fixture.content.as_path().display());
        let updated = update(
            &fixture.ctx(),
            &UpdateRequest::parse(
                "fp1-php83",
                "a.test",
                &root,
                std::slice::from_ref(&fixture.content),
                ID2,
                None,
            )
            .unwrap(),
            &CancellationToken::default(),
        )
        .unwrap();
        assert!(updated.changed);
        assert_eq!(
            (updated.uid, updated.port, updated.root.as_str()),
            (a.uid, a.port, root.as_str())
        );
        let missing = update(
            &fixture.ctx(),
            &UpdateRequest::parse(
                "fp1-php83",
                "none.test",
                &root,
                std::slice::from_ref(&fixture.content),
                ID3,
                None,
            )
            .unwrap(),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert!(matches!(missing, Error::RecordMissing));
        assert_eq!(missing.protocol().0, ErrorCode::NotFound);
    }

    #[test]
    fn roots_must_be_plain_paths_under_a_content_root() {
        let content = [TrustedRoot::parse("/var/www").unwrap()];
        for good in [
            "/var/www/a.test",
            "/var/www/a.test/public",
            "/var/www/sites/x/current",
        ] {
            assert!(validate_root(good, &content).is_ok(), "{good}");
        }
        for bad in [
            "",
            "/",
            "/var/www",
            "/var/www/",
            "/etc",
            "/var/wwwx/a",
            "var/www/a",
            "/var/www/a b",
            "/var/www/a\nROOT=/",
            "/var/www/../etc",
            "/var/www/a/./b",
            "/var/www//a",
            "/var/www/a;rm",
            "/var/www/a{",
        ] {
            assert!(validate_root(bad, &content).is_err(), "{bad:?}");
        }
        assert!(validate_worker_count(1).is_ok() && validate_worker_count(64).is_ok());
        assert!(validate_worker_count(0).is_err() && validate_worker_count(65).is_err());
    }

    #[test]
    fn the_record_round_trips_and_a_corrupt_one_is_refused() {
        let record = IdentityRecord {
            os_user: "wcp-site-0123456789abcdef".into(),
            uid: 10_023,
            gid: 10_023,
            port: 9007,
            settings: SiteSettings {
                root: "/var/www/x/public".into(),
                worker_mode: true,
                worker_count: 6,
            },
        };
        assert_eq!(IdentityRecord::parse(&record.render()), Some(record));
        assert_eq!(IdentityRecord::parse("not a record"), None);
        assert_eq!(IdentityRecord::parse("OS_USER=x\nGID=1\nPORT=1\n"), None);
    }

    #[test]
    fn the_port_range_is_bounded() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        fs::create_dir_all(fixture.runtime_root.as_path().join("fp1-php83")).unwrap();
        fs::write(
            fixture
                .runtime_root
                .as_path()
                .join("fp1-php83/.next-site-port"),
            "32768\n",
        )
        .unwrap();
        let error = fixture.allocate("fp1-php83", "a.test", ID).unwrap_err();
        assert!(matches!(error, Error::Exhausted(_)));
        // The account made for it is rolled back; the uid is burned.
        assert!(!fixture.passwd_text().contains("wcp-site-"));
        assert_eq!(
            fixture.allocate("fp1-php84", "a.test", ID2).unwrap().uid,
            10_001
        );
    }
}
