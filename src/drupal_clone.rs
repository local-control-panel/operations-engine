//! Same-server Drupal clone. Files and the target database are snapshotted
//! before mutation; the copy gets its own database credentials, a fresh
//! `hash_salt` and the staging safety defaults; Drush runs against the copy
//! before commit. Handled failures restore the target; interrupted or failed
//! recovery leaves a durable marker and artifacts, the same shape
//! `wordpress.clone` and `joomla.clone` leave, so `site.reconcile` recovers
//! all three.
//!
//! Drupal's `settings.php` is arbitrary PHP, so the engine does not parse it:
//! it appends one generated override block at the end, after everything the
//! file (and any `settings.local.php` it includes) set. Only the listed
//! database keys, `hash_salt`, the optional `trusted_host_patterns` and the
//! optional mail block are assigned; nothing is evaluated by the engine. The
//! source site is never written.
//!
//! The copy's database is read from the source with Drush
//! (`drush status`, no password in its output), so the engine never guesses
//! it from PHP text. Before anything is sanitised, Drush on the copy must
//! report the copy's own database as connected: a rewrite that did not take
//! effect can never sanitise the source.

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

pub const OPERATION: &str = "drupal.clone";

const MAX_DB_PASSWORD_BYTES: usize = 256;
const COPY_TIMEOUT: Duration = Duration::from_secs(1800);
const DRUSH_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const MAX_STEP_OUTPUT_BYTES: usize = 64 * 1024;
/// A real `settings.php` is tens of KiB at most; anything bigger is not one.
const MAX_SETTINGS_BYTES: u64 = 1024 * 1024;
const SALT_LEN: usize = 64;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    source_root: String,
    staging_root: String,
    /// The public directory below the project root: empty for the classic
    /// layout, `web` (or similar) for a Composer project.
    #[serde(default)]
    document_root: String,
    source_container: String,
    source_uid: u32,
    source_gid: u32,
    staging_container: String,
    staging_uid: u32,
    staging_gid: u32,
    db_user: String,
    db_password: String,
    mariadb_container: String,
    db_name: String,
    db_root_password: String,
    #[serde(default)]
    recovery_evidence: bool,
    /// The copy's host name, for `trusted_host_patterns`; without it the
    /// source's patterns stay and may reject the copy's address.
    #[serde(default)]
    staging_domain: Option<String>,
    /// Safety defaults for the copy; empty for a plain clone. Closed set, see
    /// [`StagingDefaults`].
    #[serde(default)]
    staging_defaults: Vec<String>,
}

/// What the copy is made safe against, chosen by the caller from a closed set
/// (`sanitize`, `blockMail`). A new `hash_salt` is always generated: a copy
/// that shares the source's salt shares its one-time-link and session trust.
/// Nothing here changes the source site.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StagingDefaults {
    /// `drush sql:sanitize` on the copy's database: user emails and passwords.
    pub sanitize: bool,
    /// The copy's mail goes to Drupal's test collector and is never sent.
    pub block_mail: bool,
}

impl StagingDefaults {
    fn parse(values: &[String]) -> Result<Self, RequestError> {
        let mut out = Self::default();
        for value in values {
            let flag = match value.as_str() {
                "sanitize" => &mut out.sanitize,
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
    document_root: PathBuf,
    source_container: ContainerName,
    source_uid: u32,
    source_gid: u32,
    staging_container: ContainerName,
    staging_uid: u32,
    staging_gid: u32,
    db_user: DatabaseName,
    db_password: String,
    mariadb_container: ContainerName,
    db_name: DatabaseName,
    db_root_password: String,
    recovery_evidence: bool,
    original_database_container: Option<ContainerName>,
    staging_domain: Option<String>,
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

/// Empty, or a relative path of plain components.
fn parse_document_root(value: &str) -> Result<PathBuf, RequestError> {
    let path = PathBuf::from(value);
    if value.len() > 255
        || value.chars().any(char::is_control)
        || path
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err(RequestError);
    }
    Ok(path)
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

/// A lower-case DNS name: labels of `a-z0-9-`, no empty label, bounded.
fn validate_domain(value: &str) -> Result<(), RequestError> {
    let ok = !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        });
    if ok { Ok(()) } else { Err(RequestError) }
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
        if [
            plan.staging_uid,
            plan.staging_gid,
            plan.source_uid,
            plan.source_gid,
        ]
        .contains(&0)
        {
            return Err(RequestError);
        }
        if let Some(domain) = &plan.staging_domain {
            validate_domain(domain)?;
        }
        Ok(Self {
            source_root,
            staging_root,
            document_root: parse_document_root(&plan.document_root)?,
            source_container: ContainerName::parse(&plan.source_container)
                .map_err(|_| RequestError)?,
            source_uid: plan.source_uid,
            source_gid: plan.source_gid,
            staging_container: ContainerName::parse(&plan.staging_container)
                .map_err(|_| RequestError)?,
            staging_uid: plan.staging_uid,
            staging_gid: plan.staging_gid,
            db_user: DatabaseName::parse(&plan.db_user).map_err(|_| RequestError)?,
            db_password: plan.db_password,
            mariadb_container: ContainerName::parse(&plan.mariadb_container)
                .map_err(|_: RestoreRequestError| RequestError)?,
            db_name: DatabaseName::parse(&plan.db_name)
                .map_err(|_: RestoreRequestError| RequestError)?,
            db_root_password: plan.db_root_password,
            recovery_evidence: plan.recovery_evidence,
            original_database_container: None,
            staging_domain: plan.staging_domain,
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

// ── settings.php ─────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// The file cannot take an appended override block: it closes PHP with
    /// `?>`, so appended code would be printed as text.
    ClosedPhp,
    /// The file names the source site's own directory: the copy would keep
    /// using the source's files.
    NamesSource,
}

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

/// What the copy's `settings.php` has to say.
struct Overrides<'a> {
    db_name: &'a str,
    db_user: &'a str,
    db_password: &'a str,
    db_host: &'a str,
    salt: &'a str,
    domain: Option<&'a str>,
    source_root: &'a std::path::Path,
    defaults: StagingDefaults,
}

/// `^staging\.example\.com$`: a validated domain only needs its dots escaped.
fn host_pattern(domain: &str) -> String {
    format!("^{}$", domain.replace('.', "\\."))
}

/// The text with the override block appended. Fails closed on a file the block
/// cannot safely follow.
fn append_overrides(text: &str, o: &Overrides<'_>) -> Result<String, ConfigError> {
    if text.contains("?>") {
        return Err(ConfigError::ClosedPhp);
    }
    if text.contains(&o.source_root.display().to_string()) {
        return Err(ConfigError::NamesSource);
    }
    let mut out = String::with_capacity(text.len() + 1024);
    out.push_str(text);
    if !text.ends_with('\n') {
        out.push('\n');
    }
    out.push_str("\n// BEGIN wcp staging clone (generated by operations-engine)\n");
    out.push_str(&format!(
        "$databases['default']['default']['database'] = {};\n",
        quote(o.db_name)
    ));
    out.push_str(&format!(
        "$databases['default']['default']['username'] = {};\n",
        quote(o.db_user)
    ));
    out.push_str(&format!(
        "$databases['default']['default']['password'] = {};\n",
        quote(o.db_password)
    ));
    out.push_str(&format!(
        "$databases['default']['default']['host'] = {};\n",
        quote(o.db_host)
    ));
    out.push_str("$databases['default']['default']['port'] = '3306';\n");
    out.push_str("unset($databases['default']['default']['unix_socket']);\n");
    out.push_str(&format!("$settings['hash_salt'] = {};\n", quote(o.salt)));
    if let Some(domain) = o.domain {
        out.push_str(&format!(
            "$settings['trusted_host_patterns'] = [{}];\n",
            quote(&host_pattern(domain))
        ));
    }
    if o.defaults.block_mail {
        out.push_str("$config['system.mail']['interface']['default'] = 'test_mail_collector';\n");
    }
    out.push_str("// END wcp staging clone\n");
    Ok(out)
}

/// A fresh salt from the kernel's random source (alphanumeric).
fn new_salt() -> std::io::Result<String> {
    use std::io::Read;
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut urandom = std::fs::File::open("/dev/urandom")?;
    let mut out = String::with_capacity(SALT_LEN);
    let mut byte = [0u8; 1];
    while out.len() < SALT_LEN {
        urandom.read_exact(&mut byte)?;
        // 248 = 62 * 4: rejecting the rest keeps every character equally likely.
        if byte[0] < 248 {
            out.push(ALPHABET[usize::from(byte[0]) % ALPHABET.len()] as char);
        }
    }
    Ok(out)
}

/// `base/relative` with no symlink in any component below `base`: a symlinked
/// `sites/default` or docroot could point the copy's edit outside the copy
/// (or at the source) and is refused.
fn without_symlinks(base: &std::path::Path, relative: &std::path::Path) -> Result<(), Error> {
    let mut path = base.to_path_buf();
    for part in relative.components() {
        path.push(part);
        let meta = std::fs::symlink_metadata(&path).map_err(|_| Error::UnsafeTarget)?;
        if meta.file_type().is_symlink() {
            return Err(Error::UnsafeTarget);
        }
    }
    Ok(())
}

/// A regular file (never a symlink) of reasonable size, as text.
fn read_settings(path: &std::path::Path) -> Result<String, Error> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| Error::UnsafeTarget)?;
    if !meta.is_file() || meta.len() > MAX_SETTINGS_BYTES {
        return Err(Error::UnsafeTarget);
    }
    std::fs::read_to_string(path).map_err(|_| Error::UnsafeTarget)
}

/// Replaces `path` (a regular file, checked by [`read_settings`]) with `text`,
/// keeping its mode. Drupal makes `settings.php` read-only; the engine runs as
/// root and the mode is put back. A temporary file and a rename: a crash never
/// leaves half a file, and the rename replaces the name, never a symlink target.
fn replace_settings(path: &std::path::Path, text: &str) -> Result<(), Error> {
    use std::io::Write;
    let mode = std::fs::symlink_metadata(path)
        .map_err(Error::Io)?
        .permissions();
    let temp = path.with_file_name(".settings.php.wcp-clone");
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

// ── Drush ────────────────────────────────────────────────────────────────

/// What `drush status` reports about the database and the bootstrap.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
struct DrushStatus {
    #[serde(rename = "db-name")]
    db_name: Option<String>,
    #[serde(rename = "db-hostname")]
    db_hostname: Option<String>,
    #[serde(rename = "db-driver")]
    db_driver: Option<String>,
    #[serde(rename = "db-status")]
    db_status: Option<String>,
    bootstrap: Option<String>,
}

fn parse_status(bytes: &[u8]) -> Option<DrushStatus> {
    serde_json::from_slice(bytes).ok()
}

/// What the source's own Drush says about its database.
struct SourceDatabase {
    name: String,
}

fn source_database(status: &DrushStatus, mariadb: &str) -> Option<SourceDatabase> {
    let driver = status.db_driver.as_deref()?;
    if driver != "mysql" || status.db_hostname.as_deref()? != mariadb {
        return None;
    }
    let name = status.db_name.clone()?;
    DatabaseName::parse(&name).ok()?;
    Some(SourceDatabase { name })
}

/// The copy answers as the copy: its own database, connected, bootstrapped.
fn copy_is_healthy(status: &DrushStatus, db_name: &str) -> bool {
    status.db_name.as_deref() == Some(db_name)
        && status.db_status.as_deref() == Some("Connected")
        && status.bootstrap.as_deref() == Some("Successful")
}

struct Site<'a> {
    container: &'a ContainerName,
    uid: u32,
    gid: u32,
    root: &'a std::path::Path,
    document_root: std::path::PathBuf,
}

/// `drush --root=<docroot> <args>` as the site user from the project root,
/// preferring the project's own Drush. `sh` only selects the binary; every
/// value reaches it as a positional parameter, never as shell text.
fn drush(
    ctx: &Context<'_>,
    site: &Site<'_>,
    args: &[&str],
    cancel: &CancellationToken,
) -> Result<Vec<u8>, Error> {
    let mut argv: Vec<String> = vec![
        "exec".into(),
        "-i".into(),
        "--user".into(),
        format!("{}:{}", site.uid, site.gid),
        "-w".into(),
        site.root.display().to_string(),
        site.container.as_str().to_owned(),
        "sh".into(),
        "-c".into(),
        "if [ -x ./vendor/bin/drush ]; then exec ./vendor/bin/drush \"$@\"; else exec drush \"$@\"; fi"
            .into(),
        "drush".into(),
        format!("--root={}", site.document_root.display()),
        "--no-interaction".into(),
    ];
    argv.extend(args.iter().map(|arg| (*arg).to_owned()));
    let output = process::run(
        &ProcessRequest::new(ctx.docker_program).args(argv),
        &ProcessLimits {
            timeout: DRUSH_TIMEOUT,
            max_stdout_bytes: MAX_STEP_OUTPUT_BYTES,
            max_stderr_bytes: MAX_STEP_OUTPUT_BYTES,
        },
        cancel,
    )
    .map_err(Error::Run)?;
    if let Some(code) = process::error_code(&output.termination) {
        return Err(Error::Rejected(code));
    }
    Ok(output.stdout.bytes)
}

const STATUS_FIELDS: &str = "--fields=db-name,db-hostname,db-driver,db-status,bootstrap";

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
    /// The source is not a Drupal site this operation can copy.
    UnsupportedSource,
    /// The copy did not come up as itself; the target was put back.
    CopyUnhealthy,
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
                "another Drupal clone into this staging site is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Run(error) => (
                process::spawn_error_code(error),
                "could not run a Drupal clone prerequisite".into(),
            ),
            Self::Rejected(code) => (*code, "Drupal clone step failed".into()),
            Self::SourceUnavailable => (
                ErrorCode::InvalidInput,
                "Drupal source root does not exist or is outside the configured content root"
                    .into(),
            ),
            Self::UnsafeTarget => (
                ErrorCode::InvalidInput,
                "clone target overlaps the source or has an unsafe settings.php".into(),
            ),
            Self::UnsupportedSource => (
                ErrorCode::InvalidInput,
                "the source is not a Drupal site that Drush can read on the given MariaDB server, or its settings.php cannot take an override block".into(),
            ),
            Self::CopyUnhealthy => (
                ErrorCode::Internal,
                "the copy did not start with its own database; it was rolled back".into(),
            ),
            Self::ResourceBusy => (
                ErrorCode::Conflict,
                "another Drupal operation is already in progress for this site".into(),
            ),
            Self::RecoveryRequired => (
                ErrorCode::Conflict,
                "Drupal clone requires manual recovery; retained artifacts and pending.json identify the target".into(),
            ),
            Self::Import(error) => error.protocol(),
            Self::Replayed { code, message } => (*code, message.clone()),
            _ => (ErrorCode::Internal, "internal Drupal clone error".into()),
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
    let scope_path = SiteRelativePath::parse(format!("drupal-clone/{hash}")).unwrap();
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

    // The source's own Drush says which database it uses. The dump comes from
    // the same MariaDB server the copy goes to. Nothing has been touched yet.
    let settings_relative = req.document_root.join("sites/default/settings.php");
    without_symlinks(source, &settings_relative)?;
    read_settings(&source.join(&settings_relative))?;
    let source_site = Site {
        container: &req.source_container,
        uid: req.source_uid,
        gid: req.source_gid,
        root: &req.source_root,
        document_root: req.source_root.join(&req.document_root),
    };
    let source_status = drush(
        ctx,
        &source_site,
        &["status", STATUS_FIELDS, "--format=json"],
        cancel,
    )
    .ok()
    .and_then(|bytes| parse_status(&bytes))
    .ok_or(Error::UnsupportedSource)?;
    let source_db =
        source_database(&source_status, database_host(req)).ok_or(Error::UnsupportedSource)?;
    if source_db.name == req.db_name.as_str() {
        return Err(Error::UnsupportedSource);
    }
    let salt = new_salt().map_err(Error::Io)?;

    let pending = SiteRelativePath::parse("pending.json").unwrap();
    let recovery_dir = SiteRelativePath::parse(format!("drupal-clone/{}", req.request_id)).unwrap();
    let recovery_sql =
        SiteRelativePath::parse(format!("drupal-clone/{}/target.sql", req.request_id)).unwrap();
    let source_sql =
        SiteRelativePath::parse(format!("drupal-clone/{}/dump.sql", req.request_id)).unwrap();
    let saved_dir = SiteRelativePath::parse(format!(".wcp-dclone-{}", req.request_id)).unwrap();
    let saved_files =
        SiteRelativePath::parse(format!(".wcp-dclone-{}/site", req.request_id)).unwrap();
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
                &SiteRelativePath::parse(format!("drupal-clone/{}/manifest.json", req.request_id))
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

        // The copy's settings: its own database, a fresh salt, the safety
        // defaults. read_settings refuses a symlink, so the source's file can
        // never be the one that gets edited.
        let settings_path = absolute.join(&settings_relative);
        without_symlinks(&absolute, &settings_relative)?;
        let copied = read_settings(&settings_path)?;
        let rewritten = append_overrides(
            &copied,
            &Overrides {
                db_name: req.db_name.as_str(),
                db_user: req.db_user.as_str(),
                db_password: &req.db_password,
                db_host: database_host(req),
                salt: &salt,
                domain: req.staging_domain.as_deref(),
                source_root: &req.source_root,
                defaults: req.staging_defaults,
            },
        )
        .map_err(|_| Error::UnsupportedSource)?;
        replace_settings(&settings_path, &rewritten)?;
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
        crate::failpoint::hit("drupal-clone.before-db");
        restore(ctx, req, &source_sql, cancel)?;
        crate::failpoint::hit("drupal-clone.after-db");
        verify_database_identity(ctx, req)?;

        // The copy must start as itself: Drush boots with the rewritten
        // settings and reports the copy's own database as connected. Only then
        // is anything sanitised, so a rewrite that did not take effect can
        // never reach the source's data.
        let staging_site = Site {
            container: &req.staging_container,
            uid: req.staging_uid,
            gid: req.staging_gid,
            root: &req.staging_root,
            document_root: req.staging_root.join(&req.document_root),
        };
        let healthy = || -> Result<(), Error> {
            let bytes = drush(
                ctx,
                &staging_site,
                &["status", STATUS_FIELDS, "--format=json"],
                cancel,
            )?;
            match parse_status(&bytes) {
                Some(status) if copy_is_healthy(&status, req.db_name.as_str()) => Ok(()),
                _ => Err(Error::CopyUnhealthy),
            }
        };
        healthy()?;
        if req.staging_defaults.sanitize {
            drush(ctx, &staging_site, &["sql:sanitize", "--yes"], cancel)?;
            healthy()?;
        }
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

/// The MariaDB container name the sites' own settings use (the pinned
/// identity replaces `mariadb_container` when recovery evidence is on).
fn database_host(req: &Request) -> &str {
    req.original_database_container
        .as_ref()
        .unwrap_or(&req.mariadb_container)
        .as_str()
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

    const REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174002";

    const SETTINGS: &str = r#"<?php
$databases['default']['default'] = [
  'database' => 'source_db',
  'username' => 'source_user',
  'password' => 'it\'s a "secret"',
  'host' => 'mariadb-1',
  'driver' => 'mysql',
];
$settings['hash_salt'] = 'OLDSALTOLDSALT';
$settings['config_sync_directory'] = '../config/sync';
"#;

    fn overrides(source: &std::path::Path, defaults: StagingDefaults) -> Overrides<'_> {
        Overrides {
            db_name: "staging_db",
            db_user: "staging_user",
            db_password: "pa'ss\\word",
            db_host: "mariadb-1",
            salt: "NEWSALT",
            domain: Some("staging.example.com"),
            source_root: source,
            defaults,
        }
    }

    #[test]
    fn the_copys_settings_get_an_override_block_at_the_end() {
        let source = std::path::Path::new("/var/www/source.example.com");
        let out =
            append_overrides(SETTINGS, &overrides(source, StagingDefaults::default())).unwrap();
        assert!(out.starts_with(SETTINGS), "the original text is untouched");
        let block = &out[SETTINGS.len()..];
        assert!(block.contains("['database'] = 'staging_db';"));
        assert!(block.contains("['username'] = 'staging_user';"));
        assert!(block.contains(r"['password'] = 'pa\'ss\\word';"));
        assert!(block.contains("['host'] = 'mariadb-1';"));
        assert!(block.contains("$settings['hash_salt'] = 'NEWSALT';"));
        assert!(
            block.contains(r"$settings['trusted_host_patterns'] = ['^staging\\.example\\.com$'];")
        );
        assert!(
            !block.contains("test_mail_collector"),
            "mail only when asked"
        );
        assert!(block.trim_end().ends_with("// END wcp staging clone"));
    }

    #[test]
    fn block_mail_routes_the_copys_mail_to_the_test_collector() {
        let source = std::path::Path::new("/var/www/source.example.com");
        let out = append_overrides(
            SETTINGS,
            &overrides(
                source,
                StagingDefaults {
                    sanitize: false,
                    block_mail: true,
                },
            ),
        )
        .unwrap();
        assert!(
            out.contains("$config['system.mail']['interface']['default'] = 'test_mail_collector';")
        );
    }

    #[test]
    fn no_domain_leaves_the_trusted_hosts_alone() {
        let source = std::path::Path::new("/var/www/source.example.com");
        let mut o = overrides(source, StagingDefaults::default());
        o.domain = None;
        let out = append_overrides(SETTINGS, &o).unwrap();
        assert!(!out.contains("trusted_host_patterns"));
    }

    #[test]
    fn a_file_the_block_cannot_follow_fails_closed() {
        let source = std::path::Path::new("/var/www/source.example.com");
        let o = overrides(source, StagingDefaults::default());
        let closed = format!("{SETTINGS}?>\n");
        assert_eq!(
            append_overrides(&closed, &o).err(),
            Some(ConfigError::ClosedPhp)
        );
        let names_source = format!(
            "{SETTINGS}$settings['file_private_path'] = '/var/www/source.example.com/private';\n"
        );
        assert_eq!(
            append_overrides(&names_source, &o).err(),
            Some(ConfigError::NamesSource)
        );
    }

    #[test]
    fn a_file_without_a_final_newline_still_gets_a_clean_block() {
        let source = std::path::Path::new("/var/www/source.example.com");
        let out = append_overrides(
            "<?php\n$a = 1;",
            &overrides(source, StagingDefaults::default()),
        )
        .unwrap();
        assert!(out.starts_with("<?php\n$a = 1;\n\n// BEGIN"));
    }

    #[test]
    fn domains_are_lower_case_dns_names() {
        for ok in ["staging.example.com", "a-b.example.co.uk", "localhost"] {
            assert!(validate_domain(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "Staging.example.com",
            "a..b",
            "-a.example.com",
            "a.example.com-",
            "exa mple.com",
            "a.example.com/",
            "a'.example.com",
            "*.example.com",
        ] {
            assert!(validate_domain(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_salt_is_64_alphanumeric_characters_and_not_repeated() {
        let a = new_salt().unwrap();
        let b = new_salt().unwrap();
        assert_eq!(a.len(), SALT_LEN);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_ne!(a, b);
    }

    #[test]
    fn drush_status_is_read_and_only_a_mysql_source_on_the_given_server_is_accepted() {
        let ok = parse_status(
            br#"{"db-name":"source_db","db-hostname":"mariadb-1","db-driver":"mysql","db-status":"Connected","bootstrap":"Successful"}"#,
        )
        .unwrap();
        assert_eq!(source_database(&ok, "mariadb-1").unwrap().name, "source_db");
        assert!(source_database(&ok, "other-db").is_none());
        for patch in [("mysql", "pgsql"), ("source_db", "x; drop")] {
            let text = String::from_utf8(
                br#"{"db-name":"source_db","db-hostname":"mariadb-1","db-driver":"mysql"}"#
                    .to_vec(),
            )
            .unwrap()
            .replace(patch.0, patch.1);
            let status = parse_status(text.as_bytes()).unwrap();
            assert!(source_database(&status, "mariadb-1").is_none(), "{patch:?}");
        }
        assert!(parse_status(b"not json").is_none());
        assert!(source_database(&DrushStatus::default(), "mariadb-1").is_none());
    }

    #[test]
    fn a_copy_is_healthy_only_with_its_own_connected_bootstrapped_database() {
        let status = |db: &str, conn: &str, boot: &str| DrushStatus {
            db_name: Some(db.into()),
            db_status: Some(conn.into()),
            bootstrap: Some(boot.into()),
            ..DrushStatus::default()
        };
        assert!(copy_is_healthy(
            &status("staging_db", "Connected", "Successful"),
            "staging_db"
        ));
        assert!(!copy_is_healthy(
            &status("source_db", "Connected", "Successful"),
            "staging_db"
        ));
        assert!(!copy_is_healthy(
            &status("staging_db", "Not connected", "Successful"),
            "staging_db"
        ));
        assert!(!copy_is_healthy(
            &status("staging_db", "Connected", ""),
            "staging_db"
        ));
        assert!(!copy_is_healthy(&DrushStatus::default(), "staging_db"));
    }

    // ── request parsing ───────────────────────────────────────────────────

    fn valid_json(source_root: &std::path::Path, staging_root: &std::path::Path) -> String {
        format!(
            r#"{{
                "sourceRoot": "{source}",
                "stagingRoot": "{staging}",
                "documentRoot": "web",
                "sourceContainer": "runtime-source",
                "sourceUid": {uid},
                "sourceGid": {gid},
                "stagingContainer": "runtime-staging",
                "stagingUid": {uid},
                "stagingGid": {gid},
                "dbUser": "staging_user",
                "dbPassword": "staging-secret",
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
    fn the_document_root_is_a_plain_relative_path() {
        let s = std::path::Path::new("/var/www/source.example.com");
        let t = std::path::Path::new("/var/www/staging.example.com");
        for ok in ["", "web", "public/html"] {
            let json = valid_json(s, t).replace("\"web\"", &format!("\"{ok}\""));
            assert!(Request::parse(&json, REQUEST_ID, None).is_ok(), "{ok:?}");
        }
        for bad in ["/web", "../web", "web/../..", "./web/..", "w\\u0000eb"] {
            let json = valid_json(s, t).replace("\"web\"", &format!("\"{bad}\""));
            assert!(Request::parse(&json, REQUEST_ID, None).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn staging_defaults_are_a_closed_set_and_optional() {
        assert_eq!(
            StagingDefaults::parse(&[]).unwrap(),
            StagingDefaults::default()
        );
        let all =
            StagingDefaults::parse(&["sanitize".into(), "blockMail".into(), "sanitize".into()])
                .unwrap();
        assert!(all.sanitize && all.block_mail);
        for bad in ["noindex", "disableCron", "sanitize; rm", ""] {
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
    /// text) or the clone. Drush answers per container: the source reports
    /// `source_db`, the copy `staging_db` (or `source_db` when WRONG_DB is
    /// set, as if the rewrite had not taken effect). REJECT_PROBE makes the
    /// copy's Drush fail; REJECT_SANITIZE makes the sanitising fail.
    const FAKE_DOCKER: &str = r#"#!/bin/sh
base="$(dirname "$0")"
echo "$@" >> "$base/docker-calls.log"
case "$*" in
  "inspect "*) echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ;;
  *"--databases"*) echo '-- original target database --' ;;
  *"--add-drop-table"*) echo '-- source dump --' ;;
  *"runtime-source"*"status"*)
    echo '{"db-name":"source_db","db-hostname":"mariadb-1","db-driver":"mysql","db-status":"Connected","bootstrap":"Successful"}' ;;
  *"runtime-staging"*"sql:sanitize"*) test ! -f "$base/REJECT_SANITIZE" ;;
  *"runtime-staging"*"status"*)
    test ! -f "$base/REJECT_PROBE" || exit 1
    if [ -f "$base/WRONG_DB" ]; then db=source_db; else db=staging_db; fi
    echo "{\"db-name\":\"$db\",\"db-hostname\":\"mariadb-1\",\"db-driver\":\"mysql\",\"db-status\":\"Connected\",\"bootstrap\":\"Successful\"}" ;;
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

    fn fixture(settings: Option<&dyn Fn(&std::path::Path) -> String>) -> Fixture {
        let directory = tempfile::tempdir().unwrap();
        let content_dir = directory.path().join("content");
        let state_dir = directory.path().join("state");
        let dump_dir = directory.path().join("dumps");
        let source = content_dir.join("source.example.com");
        fs::create_dir_all(source.join("web/sites/default/files")).unwrap();
        fs::write(source.join("web/index.php"), "<?php // drupal\n").unwrap();
        fs::write(source.join("web/sites/default/files/a.txt"), "upload").unwrap();
        let text = match settings {
            Some(make) => make(&source),
            None => SETTINGS.to_owned(),
        };
        let settings_path = source.join("web/sites/default/settings.php");
        fs::write(&settings_path, text).unwrap();
        // Drupal leaves settings.php read-only.
        fs::set_permissions(&settings_path, fs::Permissions::from_mode(0o444)).unwrap();
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
            &format!(
                r#""dbRootPassword": "rootpw", "stagingDomain": "staging.example.com", "stagingDefaults": {defaults}"#
            ),
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

    fn flag(fx: &Fixture, name: &str) {
        fs::write(fx.docker.parent().unwrap().join(name), "").unwrap();
    }

    fn copy_settings(fx: &Fixture) -> String {
        fs::read_to_string(fx.staging_root.join("web/sites/default/settings.php")).unwrap()
    }

    #[test]
    fn a_clone_copies_files_and_database_and_overrides_only_the_copys_settings() {
        let fx = fixture(None);
        let req = request(&fx, r#"["sanitize","blockMail"]"#);
        run(&fx, &req).expect("clone should succeed");

        let copy = copy_settings(&fx);
        assert!(copy.starts_with(SETTINGS));
        assert!(copy.contains("['database'] = 'staging_db';"));
        assert_eq!(
            copy.matches("hash_salt").count(),
            2,
            "the source's salt line stays, a new one follows it"
        );
        assert!(copy.contains("test_mail_collector"));
        assert_eq!(
            fs::read_to_string(fx.staging_root.join("web/sites/default/files/a.txt")).unwrap(),
            "upload"
        );
        assert_eq!(
            fs::read_to_string(fx.source_root.join("web/sites/default/settings.php")).unwrap(),
            SETTINGS,
            "the source site is never written"
        );
        let mode = fs::metadata(fx.staging_root.join("web/sites/default/settings.php"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o444, "settings.php stays read-only");
        assert_eq!(
            fs::read_to_string(fx.docker.parent().unwrap().join("received.sql")).unwrap(),
            "-- source dump --\n"
        );
        let calls = log(&fx);
        let dump = calls.find("--add-drop-table source_db").unwrap();
        let first_probe = calls.find("runtime-staging").unwrap();
        let sanitize = calls.find("sql:sanitize --yes").unwrap();
        assert!(dump < first_probe && first_probe < sanitize);
        assert!(
            calls.contains("--root=") && calls.contains("/staging.example.com/web"),
            "Drush runs against the copy's own document root"
        );
        assert!(
            !fx.dump_root
                .as_path()
                .join(format!("drupal-clone/{REQUEST_ID}/dump.sql"))
                .exists(),
            "the working dump does not survive"
        );
    }

    #[test]
    fn a_plain_clone_still_gets_a_new_salt_but_does_not_sanitize_or_block_mail() {
        let fx = fixture(None);
        run(&fx, &request(&fx, "[]")).unwrap();
        let copy = copy_settings(&fx);
        assert!(copy.contains("$settings['hash_salt'] = '"));
        assert!(!copy.contains("test_mail_collector"));
        assert!(!log(&fx).contains("sql:sanitize"));
    }

    #[test]
    fn a_copy_that_still_answers_as_the_source_is_never_sanitized() {
        let fx = fixture(None);
        flag(&fx, "WRONG_DB");
        assert!(matches!(
            run(&fx, &request(&fx, r#"["sanitize"]"#)),
            Err(Error::CopyUnhealthy)
        ));
        assert!(
            !log(&fx).contains("sql:sanitize"),
            "nothing is sanitised before the copy proves it is itself"
        );
        assert!(!fx.staging_root.exists());
    }

    #[test]
    fn a_failed_probe_rolls_the_copy_back() {
        let fx = fixture(None);
        flag(&fx, "REJECT_PROBE");
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

    fn evidence_request(fx: &Fixture) -> Request {
        let json = valid_json(&fx.source_root, &fx.staging_root).replace(
            r#""dbRootPassword": "rootpw""#,
            r#""dbRootPassword": "rootpw", "recoveryEvidence": true"#,
        );
        Request::parse(&json, REQUEST_ID, None).unwrap()
    }

    fn pending_text(fx: &Fixture) -> String {
        let hash = resource_lock::canonical_hash(&fx.staging_root);
        let path = fx
            .engine_state
            .open_regular_read(
                &SiteRelativePath::parse(format!("drupal-clone/{hash}/pending.json")).unwrap(),
            )
            .map(|mut f| {
                let mut text = String::new();
                std::io::Read::read_to_string(&mut f, &mut text).unwrap();
                text
            });
        path.unwrap_or_default()
    }

    #[test]
    fn with_recovery_evidence_the_pinned_container_runs_every_database_step() {
        let fx = fixture(None);
        run(&fx, &evidence_request(&fx)).expect("clone should succeed");
        let calls = log(&fx);
        let id = "a".repeat(64);
        assert!(calls.contains(&format!("{id} mariadb-dump")));
        assert!(
            !calls.contains(" mariadb-1 mariadb"),
            "no database step uses the movable name"
        );
        assert!(
            copy_settings(&fx).contains("['host'] = 'mariadb-1';"),
            "the copy's settings keep the container name, not the pinned id"
        );
    }

    #[test]
    fn with_recovery_evidence_a_failure_keeps_the_checkpoint_and_does_not_guess() {
        let fx = fixture(None);
        flag(&fx, "REJECT_PROBE");
        assert!(matches!(
            run(&fx, &evidence_request(&fx)),
            Err(Error::RecoveryRequired)
        ));
        let pending = pending_text(&fx);
        assert!(pending.contains("databaseContainerId"));
        assert!(pending.contains(r#""mutationStarted":true"#));
        assert!(
            !fx.docker.parent().unwrap().join("recovered.sql").exists(),
            "no automatic database restore"
        );
        assert!(fx.staging_root.exists(), "the half-built copy is retained");
    }

    #[test]
    fn a_failed_sanitize_rolls_the_copy_back() {
        let fx = fixture(None);
        flag(&fx, "REJECT_SANITIZE");
        assert!(run(&fx, &request(&fx, r#"["sanitize"]"#)).is_err());
        assert!(!fx.staging_root.exists());
        assert!(
            fs::read_to_string(fx.docker.parent().unwrap().join("recovered.sql"))
                .unwrap()
                .contains("original target")
        );
    }

    #[test]
    fn a_failed_probe_restores_an_existing_staging_site() {
        let fx = fixture(None);
        fs::create_dir_all(&fx.staging_root).unwrap();
        fs::write(fx.staging_root.join("old.txt"), "old").unwrap();
        flag(&fx, "REJECT_PROBE");
        assert!(run(&fx, &request(&fx, "[]")).is_err());
        assert_eq!(
            fs::read_to_string(fx.staging_root.join("old.txt")).unwrap(),
            "old"
        );
        assert!(!fx.staging_root.join("web").exists());
    }

    #[test]
    fn a_source_that_drush_cannot_read_or_that_closes_php_is_refused_untouched() {
        let closed = fixture(Some(&|_| format!("{SETTINGS}?>\n")));
        assert!(matches!(
            run(&closed, &request(&closed, "[]")),
            Err(Error::UnsupportedSource)
        ));
        assert!(!closed.staging_root.exists());

        let no_settings = fixture(None);
        fs::remove_file(
            no_settings
                .source_root
                .join("web/sites/default/settings.php"),
        )
        .unwrap();
        assert!(matches!(
            run(&no_settings, &request(&no_settings, "[]")),
            Err(Error::UnsafeTarget)
        ));
        assert!(
            !no_settings
                .docker
                .parent()
                .unwrap()
                .join("docker-calls.log")
                .exists(),
            "nothing runs before the source is known"
        );
    }

    #[test]
    fn a_source_on_the_target_database_is_refused() {
        let fx = fixture(None);
        let json = valid_json(&fx.source_root, &fx.staging_root)
            .replace("\"staging_db\"", "\"source_db\"");
        let req = Request::parse(&json, REQUEST_ID, None).unwrap();
        assert!(matches!(run(&fx, &req), Err(Error::UnsupportedSource)));
        assert!(!fx.staging_root.exists());
    }

    #[test]
    fn a_symlinked_sites_directory_is_refused_before_anything_runs() {
        let fx = fixture(None);
        let real = fx.source_root.join("web/sites/real");
        fs::rename(fx.source_root.join("web/sites/default"), &real).unwrap();
        std::os::unix::fs::symlink(&real, fx.source_root.join("web/sites/default")).unwrap();
        assert!(matches!(
            run(&fx, &request(&fx, "[]")),
            Err(Error::UnsafeTarget)
        ));
        assert!(!fx.staging_root.exists());
        assert!(
            !fx.docker
                .parent()
                .unwrap()
                .join("docker-calls.log")
                .exists()
        );
    }

    #[test]
    fn a_symlinked_settings_file_is_never_followed() {
        let fx = fixture(None);
        let outside = fx._directory.path().join("outside.php");
        fs::write(&outside, SETTINGS).unwrap();
        let path = fx.source_root.join("web/sites/default/settings.php");
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&outside, &path).unwrap();
        assert!(matches!(
            run(&fx, &request(&fx, "[]")),
            Err(Error::UnsafeTarget)
        ));
        assert_eq!(fs::read_to_string(&outside).unwrap(), SETTINGS);
    }

    #[test]
    fn the_same_request_id_replays_the_recorded_result() {
        let fx = fixture(None);
        let json = valid_json(&fx.source_root, &fx.staging_root);
        let req = Request::parse(&json, REQUEST_ID, Some("key-1")).unwrap();
        let first = run(&fx, &req).unwrap();
        let again = run(&fx, &req).unwrap();
        assert_eq!(first.recovery_id, again.recovery_id);
        assert_eq!(
            log(&fx).matches("--add-drop-table").count(),
            1,
            "the replay does not run the clone again"
        );
    }

    impl Fixture {
        fn engine_state_has_pending(&self) -> bool {
            let hash = resource_lock::canonical_hash(&self.staging_root);
            self.engine_state.exists(
                &SiteRelativePath::parse(format!("drupal-clone/{hash}/pending.json")).unwrap(),
            )
        }
    }
}
