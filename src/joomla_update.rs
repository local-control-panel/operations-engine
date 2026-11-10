//! Recovery-first Joomla core updates: `joomla.updateCore` and
//! `joomla.restoreUpdate`, each one lock/idempotency/transaction/audit
//! backed request on a single-site Joomla 4+ project.
//!
//! Flow: preflight (no change) -> recovery bundle (files, database dump,
//! manifest under `joomla-updates/<request id>/` in the backup root) ->
//! site offline -> Joomla's own `php cli/joomla.php core:update` -> health
//! probe -> site back to its previous mode. The engine downloads and unpacks
//! nothing: the console does the whole update (verified on Joomla 5.2.3 ->
//! 5.4.10: it checks the table structure, fetches and extracts the package,
//! runs the schema migrations and finalises the database). A failing step
//! after the bundle is rolled back by the engine itself: files are replaced
//! from the bundle, the database is emptied and re-imported, then the probe
//! runs again. Only a probe that passes after the rollback reports
//! `rolledBack`; anything else is a `recovery required` failure, never a
//! success. `restoreUpdate` runs the same rollback from a kept bundle.
//!
//! The caller supplies only validated paths and UID/GID. Before anything is
//! changed the engine runs `core:update:check` and refuses a major-version
//! jump or an answer it does not recognise.
//!
//! This follows `drupal_update` (same bundle layout, journal and interrupted
//! update handling). The shared database steps live in `update_db`; the rest
//! is kept separate on purpose: it is tied to what Drupal and Joomla each use
//! to read the database connection, run the console and probe the site.
//! Recorded divergence: the bundle directory is `joomla-updates`, the journal
//! steps have no Composer step, and the database connection comes from
//! `configuration.php` instead of Drush.

use crate::{
    db_restore::{ContainerName, RestoreRequestError},
    drupal_action::{
        self, DbConnection, MAX_OUTPUT, READ_TIMEOUT, RUN_TIMEOUT, UPDATE_TIMEOUT, container_exec,
        exited_ok,
    },
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{self, CancellationToken, ProcessLimits, ProcessRequest},
    site::SiteRelativePath,
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        resource_lock,
        state::{self, TransactionStatus},
    },
    update_db,
    wordpress_migrate_export::sha256_file,
};
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub const CORE: &str = "joomla.updateCore";
pub const RESTORE: &str = "joomla.restoreUpdate";

/// Recovery bundles are kept this long.
const RETENTION_SECS: u64 = 7 * 24 * 60 * 60;
/// A real `configuration.php` is a few KiB; anything bigger is not one.
const MAX_CONFIG_BYTES: u64 = 256 * 1024;
const MAX_MANIFEST_XML_BYTES: u64 = 64 * 1024;
const BUNDLES_DIR: &str = "joomla-updates";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Core,
    Restore,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    container: String,
    project_root: String,
    uid: u32,
    gid: u32,
    /// `restoreUpdate` only: the request id of the update to undo.
    recovery_id: Option<String>,
}

pub struct Request {
    kind: Kind,
    recovery_id: Option<RequestId>,
    /// The shared container/root/user request shape of `drupal_action`; the
    /// Joomla project root is its document root too.
    base: drupal_action::Request,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    InvalidRecoveryId,
    InvalidShape,
    Base(drupal_action::RequestError),
}

impl Request {
    /// `kind` is `update-core` or `restore-update`, as named by the CLI.
    pub fn parse(
        kind: &str,
        json: &str,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        let (kind, recovery_id) = match (kind, plan.recovery_id) {
            ("update-core", None) => (Kind::Core, None),
            ("restore-update", Some(id)) => (
                Kind::Restore,
                Some(RequestId::parse(&id).map_err(|_| RequestError::InvalidRecoveryId)?),
            ),
            _ => return Err(RequestError::InvalidShape),
        };
        let base_json = serde_json::json!({
            "container": plan.container,
            "projectRoot": plan.project_root,
            "documentRoot": plan.project_root,
            "uid": plan.uid,
            "gid": plan.gid,
        })
        .to_string();
        let base = drupal_action::Request::parse("cache-rebuild", &base_json, request_id, key)
            .map_err(RequestError::Base)?;
        let _: ContainerName =
            ContainerName::parse(&plan.container).map_err(|_: RestoreRequestError| {
                RequestError::Base(drupal_action::RequestError::InvalidContainer)
            })?;
        Ok(Self {
            kind,
            recovery_id,
            base,
            request_id: RequestId::parse(request_id)
                .map_err(|_| RequestError::Base(drupal_action::RequestError::InvalidRequestId))?,
            idempotency_key: key.map(IdempotencyKey::parse).transpose().map_err(|_| {
                RequestError::Base(drupal_action::RequestError::InvalidIdempotencyKey)
            })?,
        })
    }

    pub fn root(&self) -> &Path {
        self.base.root()
    }

    pub const fn operation(&self) -> &'static str {
        match self.kind {
            Kind::Core => CORE,
            Kind::Restore => RESTORE,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateResult {
    /// `updated`, `rolledBack` or (restore) `restored`.
    pub outcome: String,
    /// Request id of the update whose bundle holds the recovery data.
    pub recovery_id: String,
    /// Why the update was rolled back (engine-written, no tool output).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub version_before: String,
    pub version_after: String,
    pub completed_at_unix_secs: u64,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub docker_program: &'a str,
    pub tar_program: &'a str,
    pub tools_dir: &'a Path,
    pub backup_root: &'a ManagedRoot,
    /// Host path of `backup_root`, for `tar` and checksums.
    pub backup_path: &'a Path,
}

impl<'a> Context<'a> {
    fn action(&self) -> drupal_action::Context<'a> {
        drupal_action::Context {
            engine_state: self.engine_state,
            docker_program: self.docker_program,
            tools_dir: self.tools_dir,
            backup_root: self.backup_root,
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    ResourceBusy,
    Cancelled,
    Action(drupal_action::Error),
    Run(process::ProcessRunError),
    /// No `cli/joomla.php` or `configuration.php` in the project root.
    NotJoomla,
    UnsupportedDatabase,
    VersionUnreadable,
    /// `core:update:check` says the site is current.
    NothingToUpdate,
    /// The offered version has another major number.
    MajorUpdate,
    /// `core:update:check` failed (update server unreachable).
    UpdateCheckFailed,
    /// `core:update:check` said something the engine does not recognise.
    UpdateCheckUnclear,
    /// The bundle could not be written; nothing was changed.
    BundleFailed,
    BundleMissing,
    BundleCorrupt,
    /// Rolling back did not work out: the site needs `restoreUpdate`, or hands.
    RecoveryRequired(String),
    PostCommit {
        result: Box<UpdateResult>,
    },
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        let invalid = |message: &str| (ErrorCode::InvalidInput, message.to_owned());
        match self {
            Self::Preflight(preflight::Error::Lock(_)) | Self::ResourceBusy => (
                ErrorCode::Conflict,
                "another operation is already in progress for this site".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Cancelled => (ErrorCode::Cancelled, "cancelled".into()),
            Self::Action(error) => error.protocol(),
            Self::Run(error) => (
                process::spawn_error_code(error),
                "could not run an update step".into(),
            ),
            Self::NotJoomla => invalid(
                "the project root has no cli/joomla.php and configuration.php; nothing was changed",
            ),
            Self::UnsupportedDatabase => invalid(
                "the site database is not a MySQL/MariaDB one reachable by container name, so a \
                 restorable backup cannot be taken; nothing was changed",
            ),
            Self::VersionUnreadable => {
                invalid("the installed Joomla version could not be read; nothing was changed")
            }
            Self::NothingToUpdate => invalid("Joomla is already up to date; nothing was changed"),
            Self::MajorUpdate => invalid(
                "the offered Joomla version has a different major number; major updates are not \
                 supported here, nothing was changed",
            ),
            Self::UpdateCheckFailed => (
                ErrorCode::DependencyUnavailable,
                "Joomla could not check for updates (the update server was not reachable); \
                 nothing was changed"
                    .into(),
            ),
            Self::UpdateCheckUnclear => invalid(
                "Joomla's update check gave an answer this engine does not recognise; nothing \
                 was changed",
            ),
            Self::BundleFailed => (
                ErrorCode::Internal,
                "the recovery bundle could not be written; nothing was changed".into(),
            ),
            Self::BundleMissing => (
                ErrorCode::NotFound,
                "no recovery bundle exists for this update (it may have expired)".into(),
            ),
            Self::BundleCorrupt => {
                invalid("the recovery bundle does not match its manifest; nothing was changed")
            }
            Self::RecoveryRequired(why) => (
                ErrorCode::SubprocessFailed,
                format!(
                    "recovery required: {why}. The recovery bundle is kept; run restoreUpdate \
                     with the recovery id of this update"
                ),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit { .. } => {
                (ErrorCode::Internal, "internal Joomla update error".into())
            }
        }
    }
}

impl From<drupal_action::Error> for Error {
    fn from(error: drupal_action::Error) -> Self {
        match error {
            drupal_action::Error::Cancelled => Self::Cancelled,
            other => Self::Action(other),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    version: u32,
    operation: String,
    request_id: String,
    project_root: String,
    created_at_unix_secs: u64,
    previous_offline: bool,
    version_before: String,
    files_sha256: String,
    database_sha256: String,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn rel(path: String) -> SiteRelativePath {
    SiteRelativePath::parse(path).unwrap()
}

// ── Reading the project ───────────────────────────────────────────────────

/// A regular file (never a symlink) of bounded size, as text.
fn read_text(path: &Path, max: u64) -> Option<String> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    (meta.is_file() && meta.len() <= max)
        .then(|| std::fs::read_to_string(path).ok())
        .flatten()
}

/// `<version>x.y.z</version>` of Joomla's own manifest.
fn installed_version(root: &Path) -> Result<String, Error> {
    let text = read_text(
        &root.join("administrator/manifests/files/joomla.xml"),
        MAX_MANIFEST_XML_BYTES,
    )
    .ok_or(Error::VersionUnreadable)?;
    let start = text.find("<version>").ok_or(Error::VersionUnreadable)? + "<version>".len();
    let end = text[start..]
        .find("</version>")
        .ok_or(Error::VersionUnreadable)?;
    let value = text[start..start + end].trim();
    plain_version(value)
        .then(|| value.to_owned())
        .ok_or(Error::VersionUnreadable)
}

/// `5.2.3`, `5.3.0-rc1`: digits, dots and a short alphanumeric suffix.
fn plain_version(value: &str) -> bool {
    let core = value.split('-').next().unwrap_or_default();
    let parts: Vec<&str> = core.split('.').collect();
    (2..=4).contains(&parts.len())
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()))
        && value.len() <= 24
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

fn major(version: &str) -> Option<u32> {
    version.split('.').next()?.parse().ok()
}

/// The MySQL/MariaDB connection `configuration.php` names. The host must be
/// the database container's name; a socket, an address or a port gives
/// nothing to `docker exec` into.
fn db_connection(root: &Path) -> Result<DbConnection, Error> {
    use crate::joomla_clone::read_string;
    let text =
        read_text(&root.join("configuration.php"), MAX_CONFIG_BYTES).ok_or(Error::NotJoomla)?;
    let driver = read_string(&text, "dbtype")
        .map_err(|_| Error::UnsupportedDatabase)?
        .to_ascii_lowercase();
    if driver != "mysqli" && driver != "pdomysql" {
        return Err(Error::UnsupportedDatabase);
    }
    let read =
        |name: &'static str| read_string(&text, name).map_err(|_| Error::UnsupportedDatabase);
    let (host, user, database) = (read("host")?, read("user")?, read("db")?);
    let password = read("password").unwrap_or_default();
    if ContainerName::parse(&host).is_err()
        || host == "localhost"
        || user.is_empty()
        || database.is_empty()
        || user.starts_with('-')
        || database.starts_with('-')
        || user.chars().chain(database.chars()).any(char::is_control)
    {
        return Err(Error::UnsupportedDatabase);
    }
    Ok(DbConnection {
        host,
        user,
        password,
        database,
    })
}

/// Whether `configuration.php` has the site offline. Unknown is an error,
/// never "online".
fn read_offline(root: &Path) -> Result<bool, Error> {
    let text =
        read_text(&root.join("configuration.php"), MAX_CONFIG_BYTES).ok_or(Error::NotJoomla)?;
    crate::cms_maintenance::joomla_offline(text.as_bytes()).ok_or(Error::NotJoomla)
}

fn console(
    ctx: &Context<'_>,
    req: &drupal_action::Request,
    args: &[&str],
    timeout: std::time::Duration,
    cancel: &CancellationToken,
) -> Result<process::ProcessOutput, Error> {
    let mut command = vec!["php", "cli/joomla.php"];
    command.extend_from_slice(args);
    command.push("--no-interaction");
    Ok(container_exec(
        &ctx.action(),
        req,
        &[],
        &command,
        timeout,
        cancel,
    )?)
}

/// What `core:update:check` offers.
#[derive(Debug, PartialEq, Eq)]
enum Offer {
    Version(String),
    Current,
}

/// `New Joomla Version 5.4.10 is available.` or `You already have the latest
/// Joomla version ...`; anything else is not recognised.
fn parse_offer(stdout: &str) -> Option<Offer> {
    if let Some(at) = stdout.find("New Joomla Version ") {
        let rest = &stdout[at + "New Joomla Version ".len()..];
        let version = rest.split_whitespace().next()?;
        return plain_version(version).then(|| Offer::Version(version.to_owned()));
    }
    stdout
        .contains("You already have the latest Joomla version")
        .then_some(Offer::Current)
}

fn target_version(
    ctx: &Context<'_>,
    req: &Request,
    installed: &str,
    cancel: &CancellationToken,
) -> Result<String, Error> {
    let output = console(ctx, &req.base, &["core:update:check"], RUN_TIMEOUT, cancel)?;
    if !exited_ok(&output) {
        return Err(Error::UpdateCheckFailed);
    }
    let text = String::from_utf8_lossy(&output.stdout.bytes).into_owned();
    match parse_offer(&text) {
        Some(Offer::Version(target)) => {
            if major(&target).is_none() || major(&target) != major(installed) {
                Err(Error::MajorUpdate)
            } else {
                Ok(target)
            }
        }
        Some(Offer::Current) => Err(Error::NothingToUpdate),
        None => Err(Error::UpdateCheckUnclear),
    }
}

// ── Journal ──────────────────────────────────────────────────────────────

mod steps {
    //! The journal of how far one update got (see `update_steps`). Step names
    //! only: no paths, tool output or secrets. Writing it is best effort; it
    //! is not the recovery data (the bundle is).
    //! `WCP_FAILPOINT=joomla-update-after-<step>` kills the process after a
    //! step is written (failpoints feature, tests only).

    use super::{Context, now, rel};
    use crate::transaction::RequestId;
    pub use crate::update_steps::{Journal, Step};

    fn path(id: RequestId) -> crate::site::SiteRelativePath {
        rel(format!("{}/{id}/steps.json", super::BUNDLES_DIR))
    }

    /// The journal of an update; an absent or unreadable one is `None`.
    pub(super) fn load(ctx: &Context<'_>, id: RequestId) -> Option<Journal> {
        Journal::parse(&ctx.backup_root.read_to_string(&path(id)).ok()?)
    }

    /// Appends `step` to the journal of update `id`, then hits the step's
    /// failpoint. Errors are ignored: the journal is diagnostic.
    pub fn record(ctx: &Context<'_>, id: RequestId, step: Step) {
        let journal = load(ctx, id).unwrap_or_default();
        if let Some(bytes) = journal.with_step(step, now()) {
            let _ = ctx.backup_root.write_atomic(&path(id), &bytes);
        }
        crate::failpoint::hit(&step.failpoint("joomla"));
    }
}
use steps::{Step, record};

// ── Bundle ───────────────────────────────────────────────────────────────

fn tar_bundle(
    ctx: &Context<'_>,
    req: &Request,
    dir: &str,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let file = ctx
        .backup_root
        .create_new_file(&rel(format!("{dir}/files.tar.gz")))
        .map_err(|_| Error::BundleFailed)?;
    let output = process::run_with_stdout_file(
        &ProcessRequest::new(ctx.tar_program).args([
            "-C".to_owned(),
            req.root().display().to_string(),
            "-czpf".into(),
            "-".into(),
            "--numeric-owner".into(),
            ".".into(),
        ]),
        file,
        &ProcessLimits {
            timeout: UPDATE_TIMEOUT,
            max_stdout_bytes: 0,
            max_stderr_bytes: MAX_OUTPUT,
        },
        cancel,
    )
    .map_err(Error::Run)?;
    if !exited_ok(&output) {
        return Err(Error::BundleFailed);
    }
    Ok(())
}

/// Dumps the site database through the database container's own client,
/// streamed to `database.sql`; the password travels only in the environment
/// of that one `docker exec`.
fn dump_database(
    ctx: &Context<'_>,
    connection: &DbConnection,
    dir: &str,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let file = ctx
        .backup_root
        .create_new_file(&rel(format!("{dir}/database.sql")))
        .map_err(|_| Error::BundleFailed)?;
    let output = process::run_with_stdout_file(
        &ProcessRequest::new(ctx.docker_program)
            .env("MYSQL_PWD", &connection.password)
            .args([
                "exec".to_owned(),
                "-i".into(),
                "-e".into(),
                "MYSQL_PWD".into(),
                connection.host.clone(),
                "mariadb-dump".into(),
                format!("-u{}", connection.user),
                "--single-transaction".into(),
                "--routines".into(),
                "--triggers".into(),
                connection.database.clone(),
            ]),
        file,
        &ProcessLimits {
            timeout: UPDATE_TIMEOUT,
            max_stdout_bytes: 0,
            max_stderr_bytes: MAX_OUTPUT,
        },
        cancel,
    )
    .map_err(Error::Run)?;
    if !exited_ok(&output) {
        return Err(Error::BundleFailed);
    }
    Ok(())
}

fn bundle(
    ctx: &Context<'_>,
    req: &Request,
    connection: &DbConnection,
    previous_offline: bool,
    version_before: &str,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let dir = format!("{BUNDLES_DIR}/{}", req.request_id);
    ctx.backup_root
        .create_dir_all(&rel(dir.clone()))
        .map_err(|_| Error::BundleFailed)?;
    tar_bundle(ctx, req, &dir, cancel)?;
    dump_database(ctx, connection, &dir, cancel)?;
    let bundle_dir = ctx.backup_path.join(&dir);
    let (_, files_sha256) = sha256_file(&bundle_dir.join("files.tar.gz")).map_err(Error::Io)?;
    let (_, database_sha256) = sha256_file(&bundle_dir.join("database.sql")).map_err(Error::Io)?;
    let manifest = Manifest {
        version: 1,
        operation: req.operation().into(),
        request_id: req.request_id.to_string(),
        project_root: req.root().display().to_string(),
        created_at_unix_secs: now(),
        previous_offline,
        version_before: version_before.to_owned(),
        files_sha256,
        database_sha256,
    };
    ctx.backup_root
        .create_new(
            &rel(format!("{dir}/manifest.json")),
            &serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .map_err(|_| Error::BundleFailed)?;
    record(ctx, req.request_id, Step::Bundled);
    Ok(())
}

/// Removes bundles older than the retention window. Best effort: a bundle
/// that cannot be removed stays for the next run, and the one belonging to
/// this request is never touched.
fn prune_bundles(ctx: &Context<'_>, keep: RequestId) {
    let Ok(parent) = ctx.backup_root.open_managed_dir(&rel(BUNDLES_DIR.into())) else {
        return;
    };
    let Ok(children) = parent.child_entries() else {
        return;
    };
    for child in children {
        let Some(name) = child.name.to_str().filter(|n| *n != keep.to_string()) else {
            continue;
        };
        let path = rel(name.to_owned());
        let old = child.is_dir
            && parent
                .modified(&path)
                .ok()
                .and_then(|time| time.elapsed().ok())
                .is_some_and(|age| age.as_secs() > RETENTION_SECS);
        if old {
            let _ = parent.remove_dir_all(&path);
        }
    }
}

// ── Update, probe, rollback ──────────────────────────────────────────────

/// The site must report the version `expected` and Joomla must boot and read
/// its database (`extension:list`).
fn probe(
    ctx: &Context<'_>,
    req: &drupal_action::Request,
    expected: &str,
    cancel: &CancellationToken,
) -> Result<(), String> {
    match installed_version(req.root()) {
        Ok(version) if version == expected => {}
        Ok(_) => return Err("the site reports another Joomla version".into()),
        Err(_) => return Err("the installed Joomla version could not be read".into()),
    }
    match console(ctx, req, &["extension:list"], READ_TIMEOUT, cancel) {
        Ok(output) if exited_ok(&output) => Ok(()),
        _ => Err("Joomla did not start or could not read its database".into()),
    }
}

fn set_offline(
    ctx: &Context<'_>,
    req: &drupal_action::Request,
    offline: bool,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let command = if offline { "site:down" } else { "site:up" };
    let ran = console(ctx, req, &[command], RUN_TIMEOUT, cancel)
        .map(|output| exited_ok(&output))
        .unwrap_or(false);
    match read_offline(req.root()) {
        Ok(now) if ran && now == offline => Ok(()),
        _ => Err("the offline mode could not be set".into()),
    }
}

fn apply(
    ctx: &Context<'_>,
    req: &Request,
    target: &str,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let output = console(ctx, &req.base, &["core:update"], UPDATE_TIMEOUT, cancel)
        .map_err(|error| format!("core update: {}", error.protocol().1))?;
    if !exited_ok(&output) {
        let timed_out = matches!(output.termination, process::ProcessTermination::TimedOut);
        return Err(if timed_out {
            "core update: Joomla took too long".into()
        } else {
            "core update: Joomla reported an error".into()
        });
    }
    record(ctx, req.request_id, Step::Updated);
    probe(ctx, &req.base, target, cancel)?;
    record(ctx, req.request_id, Step::Probed);
    Ok(())
}

/// Replaces the project's files and database with the bundle's. The bundle
/// is verified (checksums, readable archive) before anything is removed.
fn rollback(
    ctx: &Context<'_>,
    base: &drupal_action::Request,
    id: RequestId,
) -> Result<Manifest, Error> {
    let cancel = CancellationToken::default();
    let dir = format!("{BUNDLES_DIR}/{id}");
    let manifest: Manifest = serde_json::from_str(
        &ctx.backup_root
            .read_to_string(&rel(format!("{dir}/manifest.json")))
            .map_err(|_| Error::BundleMissing)?,
    )
    .map_err(|_| Error::BundleCorrupt)?;
    if manifest.project_root != base.root().display().to_string() {
        return Err(Error::BundleCorrupt);
    }
    let bundle_dir = ctx.backup_path.join(&dir);
    let files = bundle_dir.join("files.tar.gz");
    let database = bundle_dir.join("database.sql");
    for (path, expected) in [
        (&files, &manifest.files_sha256),
        (&database, &manifest.database_sha256),
    ] {
        match sha256_file(path) {
            Ok((_, sum)) if &sum == expected => {}
            _ => return Err(Error::BundleCorrupt),
        }
    }
    let limits = ProcessLimits {
        timeout: UPDATE_TIMEOUT,
        max_stdout_bytes: 0,
        max_stderr_bytes: MAX_OUTPUT,
    };
    let sink = || std::fs::File::create("/dev/null").map_err(Error::Io);
    let listing = process::run_with_stdout_file(
        &ProcessRequest::new(ctx.tar_program)
            .args(["-tzf".to_owned(), files.display().to_string()]),
        sink()?,
        &limits,
        &cancel,
    )
    .map_err(Error::Run)?;
    if !exited_ok(&listing) {
        return Err(Error::BundleCorrupt);
    }

    record(ctx, id, Step::RollbackStarted);
    // Files: empty the project root (links are removed, never followed),
    // then extract.
    for entry in std::fs::read_dir(base.root()).map_err(Error::Io)? {
        let entry = entry.map_err(Error::Io)?;
        let path = entry.path();
        if entry.file_type().map_err(Error::Io)?.is_dir() {
            std::fs::remove_dir_all(&path).map_err(Error::Io)?;
        } else {
            std::fs::remove_file(&path).map_err(Error::Io)?;
        }
    }
    let archive = ctx
        .backup_root
        .open_regular_read(&rel(format!("{dir}/files.tar.gz")))
        .map_err(Error::Io)?;
    let extracted = process::run_with_stdin_handle(
        &ProcessRequest::new(ctx.tar_program).args([
            "-C".to_owned(),
            base.root().display().to_string(),
            "-xzpf".into(),
            "-".into(),
            "--numeric-owner".into(),
        ]),
        archive,
        &limits,
        &cancel,
    )
    .map_err(Error::Run)?;
    if !exited_ok(&extracted) {
        return Err(Error::RecoveryRequired(
            "the files could not be extracted".into(),
        ));
    }

    record(ctx, id, Step::FilesRestored);
    // Database: the restored configuration.php names the connection.
    let connection = db_connection(base.root())?;
    update_db::empty_database(ctx.docker_program, &connection, &limits, &cancel).map_err(
        |error| match error {
            update_db::DbError::Run(error) => Error::Run(error),
            update_db::DbError::Failed(why) => Error::RecoveryRequired(why.into()),
        },
    )?;
    let dump = ctx
        .backup_root
        .open_regular_read(&rel(format!("{dir}/database.sql")))
        .map_err(Error::Io)?;
    let imported = process::run_with_stdin_handle(
        &update_db::db_client(ctx.docker_program, &connection),
        dump,
        &limits,
        &cancel,
    )
    .map_err(Error::Run)?;
    if !exited_ok(&imported) {
        return Err(Error::RecoveryRequired("the database import failed".into()));
    }
    record(ctx, id, Step::DatabaseRestored);
    probe(ctx, base, &manifest.version_before, &cancel)
        .map_err(|why| Error::RecoveryRequired(format!("after restoring: {why}")))?;
    record(ctx, id, Step::RolledBack);
    Ok(manifest)
}

// ── Interrupted updates ──────────────────────────────────────────────────

mod reconcile {
    //! Completing an update that was interrupted (the engine was killed, the
    //! host rebooted, the SSH session dropped). There is no daemon: the next
    //! Joomla update request for the same project does it, under the
    //! project's resource lock, so no live update can be mistaken for an
    //! interrupted one. Every bundle of this project whose journal did not
    //! end in `finished` or `rolledBack` is rolled back from its bundle,
    //! oldest first, whole (every part of the rollback is safe to repeat).
    //! A bundle that cannot be rolled back stops the new request with
    //! `recovery required` and stays for a manual `restoreUpdate`.

    use super::{BUNDLES_DIR, CORE, Context, Error, Manifest, RESTORE, rel, rollback, steps};
    use crate::{
        drupal_action,
        error::ErrorCode,
        filesystem::ManagedRoot,
        site::SiteRelativePath,
        transaction::{
            RequestId,
            audit::{self, AuditRecord},
            state::{self, TransactionStatus},
        },
    };

    /// More bundles than this in the directory are not scanned.
    const MAX_BUNDLES: usize = 512;

    pub(super) fn reconcile(
        ctx: &Context<'_>,
        base: &drupal_action::Request,
        scope: &ManagedRoot,
        current: RequestId,
        leave: Option<RequestId>,
    ) -> Result<(), Error> {
        for id in incomplete(ctx, base, scope, current, leave) {
            rollback(ctx, base, id).map_err(|error| {
                Error::RecoveryRequired(format!(
                    "an earlier update was interrupted and rolling it back failed ({}); its \
                     recovery bundle {id} is kept",
                    error.protocol().1
                ))
            })?;
        }
        close_interrupted(scope, current, leave);
        Ok(())
    }

    fn incomplete(
        ctx: &Context<'_>,
        base: &drupal_action::Request,
        scope: &ManagedRoot,
        current: RequestId,
        leave: Option<RequestId>,
    ) -> Vec<RequestId> {
        let Ok(entries) = std::fs::read_dir(ctx.backup_path.join(BUNDLES_DIR)) else {
            return Vec::new();
        };
        let mut found = Vec::new();
        for entry in entries.flatten().take(MAX_BUNDLES) {
            let Some(id) = entry
                .file_name()
                .to_str()
                .and_then(|name| RequestId::parse(name).ok())
            else {
                continue;
            };
            if id == current || Some(id) == leave {
                continue;
            }
            let Some(manifest) = ctx
                .backup_root
                .read_to_string(&rel(format!("{BUNDLES_DIR}/{id}/manifest.json")))
                .ok()
                .and_then(|text| serde_json::from_str::<Manifest>(&text).ok())
            else {
                continue;
            };
            if manifest.project_root != base.root().display().to_string() {
                continue;
            }
            let needs_rollback = match crate::update_steps::needs_rollback(
                steps::load(ctx, id).and_then(|journal| journal.last()),
            ) {
                Some(interrupted) => interrupted,
                None => transaction_in_progress(scope, id),
            };
            if needs_rollback {
                found.push((manifest.created_at_unix_secs, id));
            }
        }
        found.sort_by_key(|(created, _)| *created);
        found.into_iter().map(|(_, id)| id).collect()
    }

    fn transaction_path(id: RequestId) -> SiteRelativePath {
        SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap()
    }

    fn transaction_in_progress(scope: &ManagedRoot, id: RequestId) -> bool {
        state::load(scope, &transaction_path(id))
            .is_ok_and(|record| record.status == TransactionStatus::InProgress)
    }

    /// Finishes the records of requests that died, so they stop showing as
    /// running and a retry with their key gets a plain answer.
    fn close_interrupted(scope: &ManagedRoot, current: RequestId, leave: Option<RequestId>) {
        let Ok(dir) = scope.open_managed_dir(&SiteRelativePath::parse("transactions").unwrap())
        else {
            return;
        };
        let audit_path = SiteRelativePath::parse("audit/events.jsonl").unwrap();
        for name in dir.file_names().unwrap_or_default() {
            let Some(id) = name
                .strip_suffix(".json")
                .and_then(|stem| RequestId::parse(stem).ok())
            else {
                continue;
            };
            if id == current || Some(id) == leave {
                continue;
            }
            let Ok(mut record) = state::load(scope, &transaction_path(id)) else {
                continue;
            };
            let ours = [CORE, RESTORE].contains(&record.operation.as_str());
            if record.status != TransactionStatus::InProgress || !ours {
                continue;
            }
            let _ = record.mark_failed(
                ErrorCode::Internal,
                "the request was interrupted; a later request brought the site back to a \
                 consistent state",
            );
            let _ = state::save(scope, &transaction_path(id), &record);
            let _ = audit::append(
                scope,
                &audit_path,
                &AuditRecord::result(id, false, Some(ErrorCode::Internal)),
            );
        }
    }
}

// ── Run ──────────────────────────────────────────────────────────────────

fn run(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<UpdateResult, Error> {
    if req.kind == Kind::Restore {
        let id = req.recovery_id.unwrap();
        let manifest = rollback(ctx, &req.base, id)?;
        return Ok(UpdateResult {
            outcome: "restored".into(),
            recovery_id: id.to_string(),
            reason: None,
            version_after: manifest.version_before.clone(),
            version_before: manifest.version_before,
            completed_at_unix_secs: now(),
        });
    }

    // Preflight: nothing is changed until all of this holds.
    let root = req.root();
    let entry = root.join("cli/joomla.php");
    if !std::fs::symlink_metadata(&entry).is_ok_and(|meta| meta.is_file()) {
        return Err(Error::NotJoomla);
    }
    let connection = db_connection(root)?;
    let installed = installed_version(root)?;
    let previous_offline = read_offline(root)?;
    let target = target_version(ctx, req, &installed, cancel)?;

    prune_bundles(ctx, req.request_id);
    bundle(ctx, req, &connection, previous_offline, &installed, cancel)?;

    // From here a failure is rolled back by the engine.
    let attempt = (|| {
        if !previous_offline {
            set_offline(ctx, &req.base, true, cancel)?;
        }
        record(ctx, req.request_id, Step::OfflineOn);
        apply(ctx, req, &target, cancel)
    })();
    let restore_cancel = CancellationToken::default();
    match attempt {
        Ok(()) => {
            if !previous_offline {
                set_offline(ctx, &req.base, false, &restore_cancel).map_err(|_| {
                    Error::RecoveryRequired(
                        "the update succeeded but the site could not be put back online".into(),
                    )
                })?;
            }
            record(ctx, req.request_id, Step::Finished);
            Ok(UpdateResult {
                outcome: "updated".into(),
                recovery_id: req.request_id.to_string(),
                reason: None,
                version_before: installed,
                version_after: target,
                completed_at_unix_secs: now(),
            })
        }
        Err(reason) => {
            rollback(ctx, &req.base, req.request_id).map_err(|error| {
                Error::RecoveryRequired(format!(
                    "the update failed ({reason}) and rolling back failed ({})",
                    error.protocol().1
                ))
            })?;
            Ok(UpdateResult {
                outcome: "rolledBack".into(),
                recovery_id: req.request_id.to_string(),
                reason: Some(reason),
                version_before: installed.clone(),
                version_after: installed,
                completed_at_unix_secs: now(),
            })
        }
    }
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<UpdateResult, Error> {
    let hash = resource_lock::canonical_hash(req.root());
    let scope_path = SiteRelativePath::parse(format!("joomla-update/{hash}")).unwrap();
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
    // The project's resource lock: no other operation runs against a
    // half-updated site.
    let _resource_lock = resource_lock::acquire(ctx.engine_state, req.root(), req.request_id)
        .map_err(|_| Error::ResourceBusy)?;

    let operation = req.operation();
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
    let state_path =
        SiteRelativePath::parse(format!("transactions/{}.json", req.request_id)).unwrap();
    let audit_path = SiteRelativePath::parse("audit/events.jsonl").unwrap();

    if cancel.is_cancelled() {
        return Err(fail(
            &scope,
            &state_path,
            &audit_path,
            state,
            Error::Cancelled,
        ));
    }
    // An earlier update of this project that died half way is rolled back
    // first, so this request starts from a consistent site.
    if let Err(error) =
        reconcile::reconcile(ctx, &req.base, &scope, req.request_id, req.recovery_id)
    {
        return Err(fail(&scope, &state_path, &audit_path, state, error));
    }
    let result = match run(ctx, req, cancel) {
        Ok(value) => value,
        Err(Error::RecoveryRequired(why)) => {
            let id = req.recovery_id.unwrap_or(req.request_id);
            let error = Error::RecoveryRequired(format!("{why} (recovery id {id})"));
            return Err(fail(&scope, &state_path, &audit_path, state, error));
        }
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

fn replay(scope: &ManagedRoot, id: RequestId, operation: &str) -> Result<UpdateResult, Error> {
    let path = SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap();
    let loaded = state::load(scope, &path)
        .map_err(|error| Error::Io(std::io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != operation {
        return Err(Error::Io(std::io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => {
            serde_json::from_value(loaded.outcome.unwrap().result.unwrap())
                .map_err(|error| Error::Io(std::io::Error::other(error)))
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

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    fn plan(extra: &str) -> String {
        format!(
            r#"{{"container":"runtime-1","projectRoot":"/var/www/j","uid":1000,"gid":1000{extra}}}"#
        )
    }

    #[test]
    fn requests_have_exactly_one_shape_per_kind() {
        assert!(Request::parse("update-core", &plan(""), ID, None).is_ok());
        let restore = Request::parse(
            "restore-update",
            &plan(&format!(r#","recoveryId":"{ID}""#)),
            ID,
            None,
        )
        .unwrap();
        assert_eq!(restore.operation(), RESTORE);
        for (kind, extra) in [
            ("update-core", format!(r#","recoveryId":"{ID}""#)),
            ("restore-update", String::new()),
            ("restore-update", r#","recoveryId":"../x""#.to_owned()),
            ("update-extensions", String::new()),
        ] {
            assert!(
                Request::parse(kind, &plan(&extra), ID, None).is_err(),
                "{kind} {extra}"
            );
        }
        assert!(
            Request::parse("update-core", &plan(r#","packages":["a/b"]"#), ID, None).is_err(),
            "unknown fields are refused"
        );
        assert!(
            Request::parse(
                "update-core",
                &plan("").replace("/var/www/j", "/var/www/../etc"),
                ID,
                None
            )
            .is_err()
        );
    }

    #[test]
    fn the_offer_is_read_from_the_two_sentences_joomla_prints() {
        let new = " ! [NOTE] New Joomla Version 5.4.10 is available.      \n";
        assert_eq!(parse_offer(new), Some(Offer::Version("5.4.10".to_owned())));
        let current = " [OK] You already have the latest Joomla version 5.4.10   ";
        assert_eq!(parse_offer(current), Some(Offer::Current));
        for text in [
            "",
            "Something else",
            "New Joomla Version ; rm -rf / is available",
        ] {
            assert_eq!(parse_offer(text), None, "{text:?}");
        }
    }

    #[test]
    fn only_plain_versions_and_equal_majors_pass() {
        assert!(plain_version("5.2.3"));
        assert!(plain_version("5.3.0-rc1"));
        for bad in ["", "5", "5.x.1", "5.2.3; ls", "../5.2.3", "5.2.3.4.5"] {
            assert!(!plain_version(bad), "{bad:?}");
        }
        assert_eq!(major("5.4.10"), Some(5));
        assert_eq!(major("x"), None);
    }

    #[test]
    fn the_installed_version_and_the_database_come_from_the_project_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("administrator/manifests/files")).unwrap();
        std::fs::write(
            root.join("administrator/manifests/files/joomla.xml"),
            "<extension><version>5.2.3</version></extension>",
        )
        .unwrap();
        assert_eq!(installed_version(root).unwrap(), "5.2.3");

        std::fs::write(
            root.join("configuration.php"),
            "<?php\nclass JConfig {\n\tpublic $dbtype = 'mysqli';\n\tpublic $host = 'wcp-db';\n\
             \tpublic $user = 'cms';\n\tpublic $password = 'p\\'w';\n\tpublic $db = 'cms';\n\
             \tpublic $offline = false;\n}\n",
        )
        .unwrap();
        let db = db_connection(root).unwrap();
        assert_eq!(
            (db.host.as_str(), db.user.as_str(), db.password.as_str()),
            ("wcp-db", "cms", "p'w")
        );
        assert!(!read_offline(root).unwrap());

        for (from, to) in [
            ("'mysqli'", "'postgresql'"),
            ("'wcp-db'", "'localhost'"),
            ("'wcp-db'", "'db:3306'"),
            ("public $user = 'cms'", "public $user = '-x'"),
        ] {
            let text = std::fs::read_to_string(root.join("configuration.php"))
                .unwrap()
                .replace(from, to);
            std::fs::write(root.join("configuration.php"), text).unwrap();
            assert!(db_connection(root).is_err(), "{to}");
            std::fs::write(
                root.join("configuration.php"),
                "<?php\nclass JConfig {\n\tpublic $dbtype = 'mysqli';\n\tpublic $host = 'wcp-db';\n\
                 \tpublic $user = 'cms';\n\tpublic $password = 'p\\'w';\n\tpublic $db = 'cms';\n\
                 \tpublic $offline = false;\n}\n",
            )
            .unwrap();
        }
    }

    #[test]
    fn a_symlinked_configuration_is_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), "<?php public $offline = false;").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("configuration.php")).unwrap();
        assert!(matches!(read_offline(dir.path()), Err(Error::NotJoomla)));
    }
}
