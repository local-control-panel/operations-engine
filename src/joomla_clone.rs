//! Same-server Joomla clone. Files and the target database are snapshotted
//! before mutation; the copy gets its own database credentials, a fresh
//! `secret` and the staging safety defaults in `configuration.php`; a Joomla
//! CLI probe runs before commit. Handled failures restore the target;
//! interrupted or failed recovery leaves a durable marker and artifacts, the
//! same shape `wordpress.clone` leaves, so `site.reconcile` recovers both.
//!
//! Joomla has no CLI to change its configuration, so the engine edits the
//! copy's `configuration.php` itself: only the listed `public $name = value;`
//! lines, each required to exist exactly once, nothing evaluated. The source
//! site is never written.

pub use crate::wordpress_clone::{CloneResult, Context};
use crate::{
    db_restore::{
        ContainerName, DatabaseName, DbType, RestoreRequestError,
        execute::{RestoreContext, RestoreError, run_restore},
    },
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    permissions::execute::repair_tree,
    process::{self, CancellationToken, ProcessLimits, ProcessRequest, ProcessRunError},
    site::{SiteRelativePath, TrustedRoot},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        resource_lock,
        state::{self, TransactionStatus},
    },
};
use serde::Deserialize;
use std::{
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const OPERATION: &str = "joomla.clone";

const MAX_DB_PASSWORD_BYTES: usize = 256;
const COPY_TIMEOUT: Duration = Duration::from_secs(1800);
const MAX_STEP_OUTPUT_BYTES: usize = 64 * 1024;
/// A real `configuration.php` is a few KiB; anything bigger is not one.
const MAX_CONFIG_BYTES: u64 = 256 * 1024;
const SECRET_LEN: usize = 32;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    source_root: String,
    staging_root: String,
    staging_container: String,
    db_user: String,
    db_password: String,
    staging_uid: u32,
    staging_gid: u32,
    mariadb_container: String,
    db_name: String,
    db_root_password: String,
    #[serde(default)]
    recovery_evidence: bool,
    /// Safety defaults for the copy; empty for a plain clone. Closed set, see
    /// [`StagingDefaults`].
    #[serde(default)]
    staging_defaults: Vec<String>,
}

/// What the copy is made safe against, chosen by the caller from a closed set
/// (`noindex`, `blockMail`). A new `secret` is always generated: a copy that
/// shares the source's secret shares its session and token trust. Nothing
/// here changes the source site.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StagingDefaults {
    /// `robots = 'noindex, nofollow'`.
    pub noindex: bool,
    /// `mailonline = false`: Joomla sends no mail from the copy.
    pub block_mail: bool,
}

impl StagingDefaults {
    fn parse(values: &[String]) -> Result<Self, RequestError> {
        let mut out = Self::default();
        for value in values {
            let flag = match value.as_str() {
                "noindex" => &mut out.noindex,
                "blockMail" => &mut out.block_mail,
                _ => return Err(RequestError),
            };
            *flag = true;
        }
        Ok(out)
    }
}

#[derive(Clone)]
pub struct Request {
    source_root: PathBuf,
    staging_root: PathBuf,
    staging_container: ContainerName,
    db_user: DatabaseName,
    db_password: String,
    staging_uid: u32,
    staging_gid: u32,
    mariadb_container: ContainerName,
    db_name: DatabaseName,
    db_root_password: String,
    recovery_evidence: bool,
    original_database_container: Option<ContainerName>,
    staging_defaults: StagingDefaults,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug)]
pub struct RequestError;

fn parse_root(value: String) -> Result<PathBuf, RequestError> {
    let root = PathBuf::from(value);
    if !root.is_absolute()
        || root.as_os_str().len() > 4096
        || root
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(RequestError);
    }
    Ok(root)
}

/// No NUL, CR or LF (the value goes to a PHP string and to a one-line file).
fn validate_db_password(value: &str) -> Result<(), RequestError> {
    if value.is_empty()
        || value.len() > MAX_DB_PASSWORD_BYTES
        || value.bytes().any(|b| matches!(b, 0 | b'\n' | b'\r'))
    {
        return Err(RequestError);
    }
    Ok(())
}

impl Request {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError)?;
        let source_root = parse_root(plan.source_root)?;
        let staging_root = parse_root(plan.staging_root)?;
        if source_root == staging_root
            || source_root.starts_with(&staging_root)
            || staging_root.starts_with(&source_root)
        {
            return Err(RequestError);
        }
        validate_db_password(&plan.db_root_password)?;
        validate_db_password(&plan.db_password)?;
        if [plan.staging_uid, plan.staging_gid].contains(&0) {
            return Err(RequestError);
        }
        Ok(Self {
            source_root,
            staging_root,
            staging_container: ContainerName::parse(&plan.staging_container)
                .map_err(|_| RequestError)?,
            db_user: DatabaseName::parse(&plan.db_user).map_err(|_| RequestError)?,
            db_password: plan.db_password,
            staging_uid: plan.staging_uid,
            staging_gid: plan.staging_gid,
            mariadb_container: ContainerName::parse(&plan.mariadb_container)
                .map_err(|_: RestoreRequestError| RequestError)?,
            db_name: DatabaseName::parse(&plan.db_name)
                .map_err(|_: RestoreRequestError| RequestError)?,
            db_root_password: plan.db_root_password,
            recovery_evidence: plan.recovery_evidence,
            original_database_container: None,
            staging_defaults: StagingDefaults::parse(&plan.staging_defaults)?,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError)?,
        })
    }

    pub fn source_root(&self) -> &std::path::Path {
        &self.source_root
    }

    pub fn staging_root(&self) -> &std::path::Path {
        &self.staging_root
    }
}

// ── configuration.php ────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// A property that has to be rewritten is missing, duplicated or not in
    /// the plain `public $name = value;` shape Joomla writes.
    Property(&'static str),
    /// The source database is not one this operation can copy.
    Unsupported,
}

/// `public $name = raw;` on one line: (indent, name, raw value).
fn property(line: &str) -> Option<(&str, &str, &str)> {
    let body = line.trim_start();
    let indent = &line[..line.len() - body.len()];
    let rest = body.strip_prefix("public $")?;
    let (name, raw) = rest.split_once(" = ")?;
    let raw = raw.trim_end().strip_suffix(';')?;
    Some((indent, name, raw))
}

/// The text of a PHP single-quoted string literal (`\\` and `\'` unescaped).
fn php_string(raw: &str) -> Option<String> {
    let inner = raw.strip_prefix('\'')?.strip_suffix('\'')?;
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next()? {
                c @ ('\\' | '\'') => out.push(c),
                other => {
                    out.push('\\');
                    out.push(other);
                }
            },
            '\'' => return None, // an unescaped quote inside: not one literal
            c => out.push(c),
        }
    }
    Some(out)
}

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

/// One value of the configuration, read from the text.
fn read_string(text: &str, name: &'static str) -> Result<String, ConfigError> {
    let mut found = text.lines().filter_map(|line| {
        property(line)
            .filter(|(_, n, _)| *n == name)
            .map(|(_, _, raw)| raw)
    });
    let raw = found.next().ok_or(ConfigError::Property(name))?;
    if found.next().is_some() {
        return Err(ConfigError::Property(name));
    }
    php_string(raw).ok_or(ConfigError::Property(name))
}

/// What the copy's `configuration.php` has to say.
struct Rewrite<'a> {
    db_name: &'a str,
    db_user: &'a str,
    db_password: &'a str,
    db_host: &'a str,
    secret: &'a str,
    source_root: &'a std::path::Path,
    staging_root: &'a std::path::Path,
    defaults: StagingDefaults,
}

/// Replaces `path` when it lies under the source root (on a path boundary).
fn move_path(value: &str, from: &std::path::Path, to: &std::path::Path) -> Option<String> {
    let rest = std::path::Path::new(value).strip_prefix(from).ok()?;
    Some(to.join(rest).to_string_lossy().into_owned())
}

/// Returns the new text. Every property that has to change must be present
/// exactly once in the plain shape; anything else fails closed, so a
/// protection is never claimed for a file that was not changed.
fn rewrite_configuration(text: &str, rewrite: &Rewrite<'_>) -> Result<String, ConfigError> {
    // Name -> new raw value; each of these must exist exactly once.
    let mut required: Vec<(&'static str, String)> = vec![
        ("db", quote(rewrite.db_name)),
        ("user", quote(rewrite.db_user)),
        ("password", quote(rewrite.db_password)),
        ("host", quote(rewrite.db_host)),
        ("secret", quote(rewrite.secret)),
    ];
    if rewrite.defaults.noindex {
        required.push(("robots", quote("noindex, nofollow")));
    }
    if rewrite.defaults.block_mail {
        required.push(("mailonline", "false".to_owned()));
    }
    // Optional properties: changed only when present and pointing at the source;
    // `None` leaves the line as it is.
    let mut optional: Vec<(&'static str, Option<String>)> = Vec::new();
    for name in ["log_path", "tmp_path", "cache_path"] {
        let current = match read_string(text, name) {
            Ok(value) => Some(value),
            Err(ConfigError::Property(_)) if !text.contains(&format!("public ${name} ")) => None,
            Err(error) => return Err(error),
        };
        optional.push((
            name,
            current
                .and_then(|v| move_path(&v, rewrite.source_root, rewrite.staging_root))
                .map(|v| quote(&v)),
        ));
    }
    // A non-empty `live_site` names the source's address; the copy detects its own.
    let live = match read_string(text, "live_site") {
        Ok(value) if !value.is_empty() => Some(quote("")),
        Ok(_) => None,
        Err(ConfigError::Property(_)) if !text.contains("public $live_site ") => None,
        Err(error) => return Err(error),
    };
    optional.push(("live_site", live));

    let mut counts = std::collections::HashMap::<&str, usize>::new();
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let (body, newline) = match line.strip_suffix('\n') {
            Some(body) => (body, "\n"),
            None => (line, ""),
        };
        let replaced = property(body).and_then(|(indent, name, _)| {
            required
                .iter()
                .map(|(n, v)| (*n, Some(v)))
                .chain(optional.iter().map(|(n, v)| (*n, v.as_ref())))
                .find(|(n, _)| *n == name)
                .map(|(n, v)| (indent, n, v))
        });
        match replaced {
            Some((indent, name, value)) => {
                *counts.entry(name).or_default() += 1;
                match value {
                    Some(value) => out.push_str(&format!("{indent}public ${name} = {value};")),
                    None => out.push_str(body),
                }
            }
            None => out.push_str(body),
        }
        out.push_str(newline);
    }
    for (name, _) in &required {
        if counts.get(name) != Some(&1) {
            return Err(ConfigError::Property(name));
        }
    }
    for (name, _) in &optional {
        if counts.get(name).copied().unwrap_or(0) > 1 {
            return Err(ConfigError::Property(name));
        }
    }
    Ok(out)
}

/// What the source's configuration says about its database.
struct SourceDatabase {
    name: String,
    host: String,
}

fn source_database(text: &str) -> Result<SourceDatabase, ConfigError> {
    let dbtype = read_string(text, "dbtype")?.to_ascii_lowercase();
    if dbtype != "mysqli" && dbtype != "pdomysql" {
        return Err(ConfigError::Unsupported);
    }
    let name = read_string(text, "db")?;
    if DatabaseName::parse(&name).is_err() {
        return Err(ConfigError::Unsupported);
    }
    Ok(SourceDatabase {
        name,
        host: read_string(text, "host")?,
    })
}

/// A fresh secret from the kernel's random source (alphanumeric, like Joomla's own).
fn new_secret() -> std::io::Result<String> {
    use std::io::Read;
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut urandom = std::fs::File::open("/dev/urandom")?;
    let mut out = String::with_capacity(SECRET_LEN);
    let mut byte = [0u8; 1];
    while out.len() < SECRET_LEN {
        urandom.read_exact(&mut byte)?;
        // 248 = 62 * 4: rejecting the rest keeps every character equally likely.
        if byte[0] < 248 {
            out.push(ALPHABET[usize::from(byte[0]) % ALPHABET.len()] as char);
        }
    }
    Ok(out)
}

/// A regular file (never a symlink) of reasonable size, as text.
fn read_config(path: &std::path::Path) -> Result<String, Error> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| Error::UnsafeTarget)?;
    if !meta.is_file() || meta.len() > MAX_CONFIG_BYTES {
        return Err(Error::UnsafeTarget);
    }
    std::fs::read_to_string(path).map_err(|_| Error::UnsafeTarget)
}

/// Replaces `path` (a regular file, checked by [`read_config`]) with `text`,
/// keeping its mode. A temporary file and a rename: a crash never leaves half a
/// configuration, and the rename replaces the name, never a symlink target.
fn replace_config(path: &std::path::Path, text: &str) -> Result<(), Error> {
    use std::io::Write;
    let mode = std::fs::symlink_metadata(path)
        .map_err(Error::Io)?
        .permissions();
    let temp = path.with_file_name(".configuration.php.wcp-clone");
    let _ = std::fs::remove_file(&temp);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(Error::Io)?;
    file.write_all(text.as_bytes()).map_err(Error::Io)?;
    file.sync_all().map_err(Error::Io)?;
    std::fs::set_permissions(&temp, mode).map_err(Error::Io)?;
    std::fs::rename(&temp, path).map_err(Error::Io)
}

// ── execution ────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Run(ProcessRunError),
    Rejected(ErrorCode),
    SourceUnavailable,
    UnsafeTarget,
    /// The source is not a Joomla 4+ site this operation can copy.
    UnsupportedSource,
    ResourceBusy,
    RecoveryRequired,
    Import(RestoreError),
    PostCommit {
        result: CloneResult,
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
                "another Joomla clone into this staging site is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Run(error) => (
                process::spawn_error_code(error),
                "could not run a Joomla clone prerequisite".into(),
            ),
            Self::Rejected(code) => (*code, "Joomla clone step failed".into()),
            Self::SourceUnavailable => (
                ErrorCode::InvalidInput,
                "Joomla source root does not exist or is outside the configured content root"
                    .into(),
            ),
            Self::UnsafeTarget => (
                ErrorCode::InvalidInput,
                "clone target overlaps the source or has an unsafe configuration".into(),
            ),
            Self::UnsupportedSource => (
                ErrorCode::InvalidInput,
                "the source is not a Joomla 4 or later site on the given MariaDB server".into(),
            ),
            Self::ResourceBusy => (
                ErrorCode::Conflict,
                "another Joomla operation is already in progress for this site".into(),
            ),
            Self::RecoveryRequired => (
                ErrorCode::Conflict,
                "Joomla clone requires manual recovery; retained artifacts and pending.json identify the target".into(),
            ),
            Self::Import(error) => error.protocol(),
            Self::Replayed { code, message } => (*code, message.clone()),
            _ => (ErrorCode::Internal, "internal Joomla clone error".into()),
        }
    }
}

pub fn execute(
    ctx: &Context<'_>,
    source_content_root: &TrustedRoot,
    staging_content_root: &TrustedRoot,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<CloneResult, Error> {
    let pinned;
    if req.recovery_evidence
        && ["mysql", "sys", "information_schema", "performance_schema"]
            .iter()
            .any(|name| req.db_name.as_str().eq_ignore_ascii_case(name))
    {
        return Err(Error::UnsafeTarget);
    }
    let req = if req.recovery_evidence {
        let id = crate::recovery_evidence::container_id(
            ctx.docker_program,
            req.mariadb_container.as_str(),
        )
        .map_err(Error::Io)?;
        let mut copy = req.clone();
        copy.original_database_container = Some(req.mariadb_container.clone());
        copy.mariadb_container = ContainerName::parse(&id).map_err(|_| Error::UnsafeTarget)?;
        pinned = copy;
        &pinned
    } else {
        req
    };

    let hash = resource_lock::canonical_hash(&req.staging_root);
    let scope_path = SiteRelativePath::parse(format!("joomla-clone/{hash}")).unwrap();
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
    let _resource_locks = resource_lock::acquire_pair(
        ctx.engine_state,
        &req.source_root,
        &req.staging_root,
        req.request_id,
    )
    .map_err(|_| Error::ResourceBusy)?;

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

    macro_rules! fail_now {
        ($error:expr) => {
            return Err(fail(
                &scope,
                &state_path,
                &audit_path,
                state.clone(),
                $error,
            ))
        };
    }

    let staging_managed = match ManagedRoot::open(staging_content_root) {
        Ok(value) => value,
        Err(error) => fail_now!(Error::Io(error)),
    };

    let source_relative = match req
        .source_root
        .strip_prefix(source_content_root.as_path())
        .ok()
        .filter(|value| !value.as_os_str().is_empty())
        .and_then(|value| SiteRelativePath::parse(value).ok())
    {
        Some(value) => value,
        None => fail_now!(Error::SourceUnavailable),
    };
    let source_absolute = match source_content_root.resolve_existing(&source_relative) {
        Ok(value) => value,
        Err(_) => fail_now!(Error::SourceUnavailable),
    };
    let staging_relative = match req
        .staging_root
        .strip_prefix(staging_content_root.as_path())
        .ok()
        .filter(|value| !value.as_os_str().is_empty())
        .and_then(|value| SiteRelativePath::parse(value).ok())
    {
        Some(value) => value,
        None => fail_now!(Error::SourceUnavailable),
    };

    if let Err(error) = clone_with_recovery(
        ctx,
        req,
        &scope,
        &staging_managed,
        staging_content_root,
        &staging_relative,
        &source_absolute,
        cancel,
    ) {
        fail_now!(error);
    }

    let result = CloneResult {
        recovery_id: req.request_id.to_string(),
        completed_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    state
        .mark_committed(serde_json::to_value(&result).unwrap())
        .unwrap();
    if state::save(&scope, &state_path, &state).is_err() {
        drop(lock);
        return Err(Error::PostCommit { result });
    }
    // A crash before this point leaves pending.json and prevents a blind retry.
    let _ = scope.remove_file(&SiteRelativePath::parse("pending.json").unwrap());
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(req.request_id, true, None),
    );
    drop(lock);
    Ok(result)
}

fn step_limits() -> ProcessLimits {
    ProcessLimits {
        timeout: COPY_TIMEOUT,
        max_stdout_bytes: MAX_STEP_OUTPUT_BYTES,
        max_stderr_bytes: MAX_STEP_OUTPUT_BYTES,
    }
}

#[allow(clippy::too_many_arguments)]
fn clone_with_recovery(
    ctx: &Context<'_>,
    req: &Request,
    scope: &ManagedRoot,
    staging: &ManagedRoot,
    content_root: &TrustedRoot,
    relative: &SiteRelativePath,
    source: &std::path::Path,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    // Reject symlinked targets/parents and overlapping canonical paths before
    // snapshotting or executing anything against the destination.
    let parent = relative
        .as_path()
        .parent()
        .filter(|p| !p.as_os_str().is_empty());
    let parent_absolute = match parent {
        Some(p) => content_root
            .resolve_existing(&SiteRelativePath::parse(p).map_err(|_| Error::UnsafeTarget)?)
            .map_err(|_| Error::UnsafeTarget)?,
        None => content_root.as_path().canonicalize().map_err(Error::Io)?,
    };
    let target = parent_absolute.join(relative.as_path().file_name().ok_or(Error::UnsafeTarget)?);
    if target.starts_with(source) || source.starts_with(&target) {
        return Err(Error::UnsafeTarget);
    }
    match staging.open_dir(relative) {
        Ok(_) => {
            let resolved = content_root
                .resolve_existing(relative)
                .map_err(|_| Error::UnsafeTarget)?;
            if resolved != target {
                return Err(Error::UnsafeTarget);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(Error::UnsafeTarget),
    }

    // The source's own configuration says which database it uses. The dump
    // comes from the same MariaDB server the copy goes to.
    let source_config = read_config(&source.join("configuration.php"))?;
    let source_db = source_database(&source_config).map_err(|_| Error::UnsupportedSource)?;
    if source_db.host
        != req
            .original_database_container
            .as_ref()
            .unwrap_or(&req.mariadb_container)
            .as_str()
        || source_db.name == req.db_name.as_str()
    {
        return Err(Error::UnsupportedSource);
    }
    // The CLI probe at the end needs Joomla 4's console.
    if !std::fs::symlink_metadata(source.join("cli/joomla.php")).is_ok_and(|m| m.is_file()) {
        return Err(Error::UnsupportedSource);
    }
    let secret = new_secret().map_err(Error::Io)?;

    let pending = SiteRelativePath::parse("pending.json").unwrap();
    let recovery_dir = SiteRelativePath::parse(format!("joomla-clone/{}", req.request_id)).unwrap();
    let recovery_sql =
        SiteRelativePath::parse(format!("joomla-clone/{}/target.sql", req.request_id)).unwrap();
    let source_sql =
        SiteRelativePath::parse(format!("joomla-clone/{}/dump.sql", req.request_id)).unwrap();
    let saved_dir = SiteRelativePath::parse(format!(".wcp-jclone-{}", req.request_id)).unwrap();
    let saved_files =
        SiteRelativePath::parse(format!(".wcp-jclone-{}/site", req.request_id)).unwrap();
    let had_target = staging.symlink_metadata(relative).is_ok();
    let manifest = serde_json::to_vec(&serde_json::json!({
        "requestId": req.request_id, "stagingRoot": req.staging_root,
        "hadTarget": had_target,
        "database": req.db_name.as_str(), "databaseContainer": req.mariadb_container.as_str(),
        "databaseSnapshot": ctx.dump_root.join(&recovery_sql),
        "savedFiles": content_root.join(&saved_files),
    }))
    .map_err(|_| Error::UnsafeTarget)?;
    scope
        .create_new(&pending, &manifest)
        .map_err(|_| Error::RecoveryRequired)?;

    let mut moved_files = false;
    let mut created_target = false;
    let mut database_mutated = false;
    let work = (|| -> Result<(), Error> {
        ctx.dump_managed
            .create_dir_all(&recovery_dir)
            .map_err(Error::Io)?;
        ctx.dump_managed
            .set_mode(&recovery_dir, 0o700)
            .map_err(Error::Io)?;
        ctx.dump_managed
            .create_new(
                &SiteRelativePath::parse(format!("joomla-clone/{}/manifest.json", req.request_id))
                    .unwrap(),
                &manifest,
            )
            .map_err(Error::Io)?;
        let snapshot = ctx
            .dump_managed
            .create_new_file(&recovery_sql)
            .map_err(Error::Io)?;
        ctx.dump_managed
            .set_mode(&recovery_sql, 0o600)
            .map_err(Error::Io)?;
        // Include DROP/CREATE DATABASE so rollback also removes tables newly
        // introduced by the clone. The target database already exists.
        critical(process::run_with_stdout_file(
            &ProcessRequest::new(ctx.docker_program)
                .env("MYSQL_PWD", &req.db_root_password)
                .args([
                    "exec",
                    "-i",
                    "-e",
                    "MYSQL_PWD",
                    req.mariadb_container.as_str(),
                    "mariadb-dump",
                    "-uroot",
                    "--single-transaction",
                    "--routines",
                    "--triggers",
                    "--events",
                    "--add-drop-database",
                    "--databases",
                    req.db_name.as_str(),
                ]),
            snapshot,
            &step_limits(),
            cancel,
        ))?;
        if req.recovery_evidence {
            crate::recovery_evidence::record(
                scope,
                &pending,
                ctx.dump_managed,
                &recovery_sql,
                req.original_database_container
                    .as_ref()
                    .expect("pinned name")
                    .as_str(),
                req.mariadb_container.as_str(),
            )
            .map_err(Error::Io)?;
            crate::failpoint::hit("content.after-snapshot");
            crate::recovery_evidence::mutation_started(scope, &pending).map_err(Error::Io)?;
        }
        staging.create_dir(&saved_dir).map_err(Error::Io)?;
        staging.set_mode(&saved_dir, 0o700).map_err(Error::Io)?;
        match staging.rename(relative, &saved_files) {
            Ok(()) => moved_files = true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::Io(e)),
        }
        staging.create_dir(relative).map_err(Error::Io)?;
        created_target = true;
        let absolute = content_root
            .resolve_existing(relative)
            .map_err(|_| Error::UnsafeTarget)?;
        critical(process::run(
            &ProcessRequest::new(ctx.cp_program).args([
                "-a",
                "--",
                &format!("{}/.", source.display()),
                absolute.to_str().ok_or(Error::UnsafeTarget)?,
            ]),
            &step_limits(),
            cancel,
        ))?;

        // The copy's configuration: its own database, a fresh secret, the
        // safety defaults, its own paths. read_config refuses a symlink, so
        // the source's file can never be the one that gets edited.
        let config_path = absolute.join("configuration.php");
        let copied = read_config(&config_path)?;
        let rewritten = rewrite_configuration(
            &copied,
            &Rewrite {
                db_name: req.db_name.as_str(),
                db_user: req.db_user.as_str(),
                db_password: &req.db_password,
                db_host: req
                    .original_database_container
                    .as_ref()
                    .unwrap_or(&req.mariadb_container)
                    .as_str(),
                secret: &secret,
                source_root: &req.source_root,
                staging_root: &req.staging_root,
                defaults: req.staging_defaults,
            },
        )
        .map_err(|_| Error::UnsupportedSource)?;
        replace_config(&config_path, &rewritten)?;
        repair_tree(&absolute, req.staging_uid, req.staging_gid, &[]).map_err(Error::Io)?;

        let dump = ctx
            .dump_managed
            .create_new_file(&source_sql)
            .map_err(Error::Io)?;
        ctx.dump_managed
            .set_mode(&source_sql, 0o600)
            .map_err(Error::Io)?;
        critical(process::run_with_stdout_file(
            &ProcessRequest::new(ctx.docker_program)
                .env("MYSQL_PWD", &req.db_root_password)
                .args([
                    "exec",
                    "-i",
                    "-e",
                    "MYSQL_PWD",
                    req.mariadb_container.as_str(),
                    "mariadb-dump",
                    "-uroot",
                    "--single-transaction",
                    "--routines",
                    "--triggers",
                    "--events",
                    "--add-drop-table",
                    source_db.name.as_str(),
                ]),
            dump,
            &step_limits(),
            cancel,
        ))?;
        database_mutated = true; // Even a failed import may have changed tables.
        crate::failpoint::hit("joomla-clone.before-db");
        restore(ctx, req, &source_sql, cancel)?;
        crate::failpoint::hit("joomla-clone.after-db");
        verify_database_identity(ctx, req)?;

        // The copy must start with the new credentials: Joomla's own console
        // boots with the rewritten configuration and lists the extensions
        // from the copied database.
        critical(process::run(
            &ProcessRequest::new(ctx.docker_program).args([
                "exec".to_owned(),
                "--user".into(),
                format!("{}:{}", req.staging_uid, req.staging_gid),
                "--workdir".into(),
                req.staging_root.display().to_string(),
                req.staging_container.as_str().into(),
                "php".into(),
                "cli/joomla.php".into(),
                "extension:list".into(),
                "--no-ansi".into(),
                "--no-interaction".into(),
            ]),
            &step_limits(),
            cancel,
        ))?;
        verify_database_identity(ctx, req)?;
        Ok(())
    })();
    let _ = ctx.dump_managed.remove_file(&source_sql);
    if let Err(error) = work {
        if req.recovery_evidence {
            return Err(Error::RecoveryRequired);
        }
        // A cancelled forward operation must still be allowed to recover.
        let recovered_db = !database_mutated
            || restore(ctx, req, &recovery_sql, &CancellationToken::default()).is_ok();
        let removed = !created_target || staging.remove_dir_all(relative).is_ok();
        let recovered_files = if moved_files && recovered_db && removed {
            staging.rename(&saved_files, relative).is_ok()
        } else {
            !moved_files
        };
        if !recovered_db || !removed || !recovered_files {
            return Err(Error::RecoveryRequired);
        }
        scope.remove_file(&pending).map_err(Error::Io)?;
        return Err(error);
    }
    // Keep target.sql, manifest.json and old files for explicit recovery.
    // pending.json is cleared only after execute() durably records commit.
    Ok(())
}

fn restore(
    ctx: &Context<'_>,
    req: &Request,
    file: &SiteRelativePath,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let absolute = ctx
        .dump_root
        .resolve_existing(file)
        .map_err(|_| Error::UnsafeTarget)?;
    let request = crate::db_restore::RestoreRequest {
        db_type: DbType::Mariadb,
        database: req.db_name.clone(),
        container: req.mariadb_container.clone(),
        file_path: absolute.to_str().ok_or(Error::UnsafeTarget)?.into(),
        root_password: req.db_root_password.clone(),
        request_id: req.request_id,
        idempotency_key: req.idempotency_key.clone(),
    };
    run_restore(
        &RestoreContext {
            engine_state: ctx.engine_state,
            docker_program: ctx.docker_program,
            gunzip_program: "gunzip",
        },
        &request,
        cancel,
    )
    .map_err(Error::Import)
}

fn verify_database_identity(ctx: &Context<'_>, req: &Request) -> Result<(), Error> {
    if let Some(name) = req.original_database_container.as_ref() {
        if crate::recovery_evidence::container_id(ctx.docker_program, name.as_str())
            .ok()
            .as_deref()
            != Some(req.mariadb_container.as_str())
        {
            return Err(Error::RecoveryRequired);
        }
    }
    Ok(())
}

fn critical(output: Result<process::ProcessOutput, ProcessRunError>) -> Result<(), Error> {
    let output = output.map_err(Error::Run)?;
    if let Some(code) = process::error_code(&output.termination) {
        return Err(Error::Rejected(code));
    }
    Ok(())
}

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<CloneResult, Error> {
    let loaded = state::load(
        scope,
        &SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap(),
    )
    .map_err(|e| Error::Io(std::io::Error::other(format!("{e:?}"))))?;
    if loaded.operation != OPERATION {
        return Err(Error::Io(std::io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => {
            serde_json::from_value(loaded.outcome.unwrap().result.unwrap())
                .map_err(|e| Error::Io(std::io::Error::other(e)))
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
    path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut state: crate::transaction::state::TransactionState,
    error: Error,
) -> Error {
    let (code, message) = error.protocol();
    let _ = state.mark_failed(code, message);
    let _ = state::save(scope, path, &state);
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
    use std::{fs, os::unix::fs::PermissionsExt};

    const REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174001";

    const CONFIG: &str = r#"<?php
class JConfig {
	public $offline = false;
	public $sitename = 'Source site';
	public $dbtype = 'mysqli';
	public $host = 'mariadb-1';
	public $user = 'source_user';
	public $password = 'it\'s a "secret"';
	public $db = 'source_db';
	public $dbprefix = 'jos_';
	public $secret = 'OLDSECRETOLDSECRET';
	public $mailonline = true;
	public $robots = '';
	public $live_site = 'https://source.example.com';
	public $log_path = '@ROOT@/administrator/logs';
	public $tmp_path = '@ROOT@/tmp';
}
"#;

    fn config_for(root: &std::path::Path) -> String {
        CONFIG.replace("@ROOT@", &root.display().to_string())
    }

    fn rewrite_with<'a>(
        source: &'a std::path::Path,
        staging: &'a std::path::Path,
        defaults: StagingDefaults,
    ) -> Rewrite<'a> {
        Rewrite {
            db_name: "staging_db",
            db_user: "staging_user",
            db_password: "pa'ss\\word",
            db_host: "mariadb-1",
            secret: "NEWSECRETNEWSECRETNEWSECRETNEWS",
            source_root: source,
            staging_root: staging,
            defaults,
        }
    }

    fn value(text: &str, name: &'static str) -> String {
        read_string(text, name).unwrap()
    }

    #[test]
    fn the_copys_configuration_gets_its_own_database_secret_and_paths() {
        let source = std::path::Path::new("/var/www/source.example.com");
        let staging = std::path::Path::new("/var/www/staging.example.com");
        let out = rewrite_configuration(
            &config_for(source),
            &rewrite_with(source, staging, StagingDefaults::default()),
        )
        .unwrap();
        assert_eq!(value(&out, "db"), "staging_db");
        assert_eq!(value(&out, "user"), "staging_user");
        assert_eq!(value(&out, "password"), "pa'ss\\word");
        assert_eq!(value(&out, "secret"), "NEWSECRETNEWSECRETNEWSECRETNEWS");
        assert_eq!(value(&out, "tmp_path"), "/var/www/staging.example.com/tmp");
        assert_eq!(
            value(&out, "log_path"),
            "/var/www/staging.example.com/administrator/logs"
        );
        assert_eq!(value(&out, "live_site"), "");
        // Untouched: other settings, and the mail/robots defaults when not asked.
        assert!(out.contains("public $sitename = 'Source site';"));
        assert!(out.contains("public $dbprefix = 'jos_';"));
        assert!(out.contains("public $mailonline = true;"));
        assert!(out.contains("public $robots = '';"));
        assert!(!out.contains("source_db") && !out.contains("OLDSECRET"));
    }

    #[test]
    fn the_defaults_switch_mail_off_and_robots_to_noindex() {
        let source = std::path::Path::new("/var/www/source.example.com");
        let staging = std::path::Path::new("/var/www/staging.example.com");
        let out = rewrite_configuration(
            &config_for(source),
            &rewrite_with(
                source,
                staging,
                StagingDefaults {
                    noindex: true,
                    block_mail: true,
                },
            ),
        )
        .unwrap();
        assert!(out.contains("public $mailonline = false;"));
        assert_eq!(value(&out, "robots"), "noindex, nofollow");
    }

    #[test]
    fn a_missing_or_repeated_property_fails_closed() {
        let source = std::path::Path::new("/var/www/source.example.com");
        let staging = std::path::Path::new("/var/www/staging.example.com");
        let all = StagingDefaults {
            noindex: true,
            block_mail: true,
        };
        let text = config_for(source);
        for name in [
            "db",
            "user",
            "password",
            "host",
            "secret",
            "robots",
            "mailonline",
        ] {
            let kept: Vec<&str> = text
                .lines()
                .filter(|l| !l.contains(&format!("public ${name} ")))
                .collect();
            let removed = kept.join("\n");
            assert_eq!(
                rewrite_configuration(&removed, &rewrite_with(source, staging, all)).err(),
                Some(ConfigError::Property(name)),
                "{name} missing"
            );
        }
        let doubled = text.replace(
            "\tpublic $secret = 'OLDSECRETOLDSECRET';\n",
            "\tpublic $secret = 'a';\n\tpublic $secret = 'b';\n",
        );
        assert!(rewrite_configuration(&doubled, &rewrite_with(source, staging, all)).is_err());
    }

    #[test]
    fn a_source_path_is_moved_only_on_a_path_boundary() {
        let from = std::path::Path::new("/var/www/site");
        let to = std::path::Path::new("/var/www/copy");
        assert_eq!(
            move_path("/var/www/site/tmp", from, to).as_deref(),
            Some("/var/www/copy/tmp")
        );
        assert_eq!(move_path("/var/www/site-other/tmp", from, to), None);
        assert_eq!(move_path("/tmp/joomla", from, to), None);
    }

    #[test]
    fn only_mysql_family_sources_with_a_valid_database_name_are_accepted() {
        let source = std::path::Path::new("/var/www/source.example.com");
        let ok = source_database(&config_for(source)).unwrap();
        assert_eq!(
            (ok.name.as_str(), ok.host.as_str()),
            ("source_db", "mariadb-1")
        );
        let pg = config_for(source).replace("'mysqli'", "'pgsql'");
        assert_eq!(source_database(&pg).err(), Some(ConfigError::Unsupported));
        let bad = config_for(source).replace("'source_db'", "'x; drop'");
        assert_eq!(source_database(&bad).err(), Some(ConfigError::Unsupported));
    }

    #[test]
    fn a_secret_is_32_alphanumeric_characters_and_not_repeated() {
        let a = new_secret().unwrap();
        let b = new_secret().unwrap();
        assert_eq!(a.len(), SECRET_LEN);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_ne!(a, b);
    }

    // ── request parsing ───────────────────────────────────────────────────

    fn valid_json(source_root: &std::path::Path, staging_root: &std::path::Path) -> String {
        format!(
            r#"{{
                "sourceRoot": "{source}",
                "stagingRoot": "{staging}",
                "stagingContainer": "runtime-staging",
                "dbUser": "staging_user",
                "dbPassword": "staging-secret",
                "stagingUid": {uid},
                "stagingGid": {gid},
                "mariadbContainer": "mariadb-1",
                "dbName": "staging_db",
                "dbRootPassword": "rootpw"
            }}"#,
            source = source_root.display(),
            staging = staging_root.display(),
            uid = unsafe { libc::getuid().max(1) },
            gid = unsafe { libc::getgid().max(1) },
        )
    }

    #[test]
    fn parses_a_well_formed_plan_and_rejects_overlapping_roots() {
        let s = std::path::Path::new("/var/www/source.example.com");
        let t = std::path::Path::new("/var/www/staging.example.com");
        let request = Request::parse(&valid_json(s, t), REQUEST_ID, None).unwrap();
        assert_eq!((request.source_root(), request.staging_root()), (s, t));
        assert!(Request::parse(&valid_json(s, s), REQUEST_ID, None).is_err());
        assert!(
            Request::parse(
                &valid_json(s, std::path::Path::new("/var/www/source.example.com/x")),
                REQUEST_ID,
                None
            )
            .is_err()
        );
        let unknown = valid_json(s, t).replace("\"dbName\"", "\"extra\": 1, \"dbName\"");
        assert!(Request::parse(&unknown, REQUEST_ID, None).is_err());
    }

    #[test]
    fn staging_defaults_are_a_closed_set_and_optional() {
        assert_eq!(
            StagingDefaults::parse(&[]).unwrap(),
            StagingDefaults::default()
        );
        let all = StagingDefaults::parse(&["noindex".into(), "blockMail".into(), "noindex".into()])
            .unwrap();
        assert!(all.noindex && all.block_mail);
        for bad in ["disableCron", "blockPayments", "noindex; rm", ""] {
            assert!(StagingDefaults::parse(&[bad.into()]).is_err(), "{bad}");
        }
    }

    // ── execute (fake docker, real cp and files) ──────────────────────────

    fn write_script(directory: &std::path::Path, name: &str, body: &str) -> PathBuf {
        let path = directory.join(name);
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    const FAKE_CP: &str =
        "#!/bin/sh\necho \"$@\" >> \"$(dirname \"$0\")/cp-calls.log\"\nexec cp \"$@\"\n";

    /// Logs argv; `--databases` is the target snapshot, `--add-drop-table` the
    /// source dump; a `mariadb ` import is either the recovery (the snapshot
    /// text) or the clone. REJECT_PROBE makes the Joomla console fail.
    const FAKE_DOCKER: &str = r#"#!/bin/sh
base="$(dirname "$0")"
echo "$@" >> "$base/docker-calls.log"
case "$*" in
  *"--databases"*) echo '-- original target database --' ;;
  *"--add-drop-table"*) echo '-- source dump --' ;;
  *"extension:list"*) test ! -f "$base/REJECT_PROBE" ;;
  *"mariadb "*)
    cat > "$base/last-import.sql"
    if grep -q 'original target' "$base/last-import.sql"; then
      cp "$base/last-import.sql" "$base/recovered.sql"
    else
      cp "$base/last-import.sql" "$base/received.sql"
    fi ;;
  *) exit 2 ;;
esac
"#;

    struct Fixture {
        _directory: tempfile::TempDir,
        content_root: TrustedRoot,
        engine_state: ManagedRoot,
        dump_managed: ManagedRoot,
        dump_root: TrustedRoot,
        docker: PathBuf,
        cp: PathBuf,
        source_root: PathBuf,
        staging_root: PathBuf,
    }

    fn fixture(config: Option<&dyn Fn(&std::path::Path) -> String>) -> Fixture {
        let directory = tempfile::tempdir().unwrap();
        let content_dir = directory.path().join("content");
        let state_dir = directory.path().join("state");
        let dump_dir = directory.path().join("dumps");
        let source = content_dir.join("source.example.com");
        fs::create_dir_all(source.join("cli")).unwrap();
        fs::create_dir_all(source.join("administrator/logs")).unwrap();
        fs::write(source.join("cli/joomla.php"), "<?php // console\n").unwrap();
        fs::write(source.join("index.php"), "<?php // joomla\n").unwrap();
        let text = match config {
            Some(make) => make(&source),
            None => config_for(&source),
        };
        fs::write(source.join("configuration.php"), text).unwrap();
        fs::create_dir_all(&state_dir).unwrap();
        fs::create_dir_all(&dump_dir).unwrap();
        let content_root = TrustedRoot::parse(&content_dir).unwrap();
        let engine_state = ManagedRoot::open(&TrustedRoot::parse(&state_dir).unwrap()).unwrap();
        let dump_root = TrustedRoot::parse(&dump_dir).unwrap();
        let dump_managed = ManagedRoot::open(&dump_root).unwrap();
        let docker = write_script(directory.path(), "fake-docker", FAKE_DOCKER);
        let cp = write_script(directory.path(), "fake-cp", FAKE_CP);
        Fixture {
            source_root: source,
            staging_root: content_dir.join("staging.example.com"),
            _directory: directory,
            content_root,
            engine_state,
            dump_managed,
            dump_root,
            docker,
            cp,
        }
    }

    fn context(fx: &Fixture) -> Context<'_> {
        Context {
            engine_state: &fx.engine_state,
            dump_managed: &fx.dump_managed,
            dump_root: &fx.dump_root,
            docker_program: fx.docker.to_str().unwrap(),
            cp_program: fx.cp.to_str().unwrap(),
        }
    }

    fn request(fx: &Fixture, defaults: &str) -> Request {
        let json = valid_json(&fx.source_root, &fx.staging_root).replace(
            r#""dbRootPassword": "rootpw""#,
            &format!(r#""dbRootPassword": "rootpw", "stagingDefaults": {defaults}"#),
        );
        Request::parse(&json, REQUEST_ID, None).unwrap()
    }

    fn run(fx: &Fixture, req: &Request) -> Result<CloneResult, Error> {
        execute(
            &context(fx),
            &fx.content_root,
            &fx.content_root,
            req,
            &CancellationToken::default(),
        )
    }

    fn log(fx: &Fixture) -> String {
        fs::read_to_string(fx.docker.parent().unwrap().join("docker-calls.log")).unwrap()
    }

    #[test]
    fn a_clone_copies_files_and_database_and_rewrites_only_the_copys_configuration() {
        let fx = fixture(None);
        let req = request(&fx, r#"["noindex","blockMail"]"#);
        let before = fs::read_to_string(fx.source_root.join("configuration.php")).unwrap();
        run(&fx, &req).expect("clone should succeed");

        let copy = fs::read_to_string(fx.staging_root.join("configuration.php")).unwrap();
        assert_eq!(value(&copy, "db"), "staging_db");
        assert_ne!(value(&copy, "secret"), "OLDSECRETOLDSECRET");
        assert!(copy.contains("public $mailonline = false;"));
        assert_eq!(value(&copy, "robots"), "noindex, nofollow");
        assert_eq!(
            fs::read_to_string(fx.staging_root.join("index.php")).unwrap(),
            "<?php // joomla\n"
        );
        assert_eq!(
            fs::read_to_string(fx.source_root.join("configuration.php")).unwrap(),
            before,
            "the source site is never written"
        );
        assert_eq!(
            fs::read_to_string(fx.docker.parent().unwrap().join("received.sql")).unwrap(),
            "-- source dump --\n"
        );
        let calls = log(&fx);
        assert!(
            calls.find("--add-drop-table source_db").unwrap()
                < calls.find("extension:list").unwrap()
        );
        assert!(calls.contains("runtime-staging php cli/joomla.php extension:list"));
        assert!(
            !fx.dump_root
                .as_path()
                .join(format!("joomla-clone/{REQUEST_ID}/dump.sql"))
                .exists(),
            "the working dump does not survive"
        );
    }

    #[test]
    fn a_plain_clone_still_gets_a_new_secret_but_keeps_mail_and_robots() {
        let fx = fixture(None);
        run(&fx, &request(&fx, "[]")).unwrap();
        let copy = fs::read_to_string(fx.staging_root.join("configuration.php")).unwrap();
        assert_ne!(value(&copy, "secret"), "OLDSECRETOLDSECRET");
        assert!(copy.contains("public $mailonline = true;"));
        assert!(copy.contains("public $robots = '';"));
    }

    #[test]
    fn a_failed_probe_rolls_the_copy_back() {
        let fx = fixture(None);
        fs::write(fx.docker.parent().unwrap().join("REJECT_PROBE"), "").unwrap();
        assert!(run(&fx, &request(&fx, r#"["blockMail"]"#)).is_err());
        assert!(!fx.staging_root.exists(), "the half-built copy is removed");
        let recovered = fx.docker.parent().unwrap().join("recovered.sql");
        assert!(
            fs::read_to_string(recovered)
                .unwrap()
                .contains("original target"),
            "the target database is put back"
        );
        assert!(
            !fx.engine_state_has_pending(),
            "no recovery marker after a handled failure"
        );
    }

    #[test]
    fn a_failed_probe_restores_an_existing_staging_site() {
        let fx = fixture(None);
        fs::create_dir_all(&fx.staging_root).unwrap();
        fs::write(fx.staging_root.join("old.txt"), "old").unwrap();
        fs::write(fx.docker.parent().unwrap().join("REJECT_PROBE"), "").unwrap();
        assert!(run(&fx, &request(&fx, "[]")).is_err());
        assert_eq!(
            fs::read_to_string(fx.staging_root.join("old.txt")).unwrap(),
            "old"
        );
        assert!(!fx.staging_root.join("index.php").exists());
    }

    #[test]
    fn a_source_on_another_database_server_or_without_the_console_is_refused_untouched() {
        let other_host = fixture(Some(&|root| {
            config_for(root).replace("'mariadb-1'", "'other-db'")
        }));
        assert!(matches!(
            run(&other_host, &request(&other_host, "[]")),
            Err(Error::UnsupportedSource)
        ));
        assert!(!other_host.staging_root.exists());
        assert!(
            !other_host
                .docker
                .parent()
                .unwrap()
                .join("docker-calls.log")
                .exists()
        );

        let no_console = fixture(None);
        fs::remove_file(no_console.source_root.join("cli/joomla.php")).unwrap();
        assert!(matches!(
            run(&no_console, &request(&no_console, "[]")),
            Err(Error::UnsupportedSource)
        ));
    }

    #[test]
    fn a_symlinked_configuration_is_never_followed() {
        let fx = fixture(None);
        let outside = fx._directory.path().join("outside.php");
        fs::write(&outside, config_for(&fx.source_root)).unwrap();
        fs::remove_file(fx.source_root.join("configuration.php")).unwrap();
        std::os::unix::fs::symlink(&outside, fx.source_root.join("configuration.php")).unwrap();
        assert!(matches!(
            run(&fx, &request(&fx, "[]")),
            Err(Error::UnsafeTarget)
        ));
        assert_eq!(
            fs::read_to_string(&outside).unwrap(),
            config_for(&fx.source_root)
        );
    }

    #[test]
    fn the_same_request_id_replays_the_recorded_result() {
        let fx = fixture(None);
        let req = Request::parse(
            &valid_json(&fx.source_root, &fx.staging_root),
            REQUEST_ID,
            Some("key-1"),
        )
        .unwrap();
        let first = run(&fx, &req).unwrap();
        let again = run(&fx, &req).unwrap();
        assert_eq!(first.recovery_id, again.recovery_id);
        assert_eq!(
            log(&fx).matches("extension:list").count(),
            1,
            "the replay does not run the clone again"
        );
    }

    impl Fixture {
        fn engine_state_has_pending(&self) -> bool {
            let hash = resource_lock::canonical_hash(&self.staging_root);
            self.engine_state.exists(
                &SiteRelativePath::parse(format!("joomla-clone/{hash}/pending.json")).unwrap(),
            )
        }
    }
}
