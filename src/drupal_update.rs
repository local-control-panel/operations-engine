//! Recovery-first Drupal updates: `drupal.updateCore`, `drupal.updatePackages`
//! and `drupal.restoreUpdate`, each one lock/idempotency/transaction/audit
//! backed request on a single-site Composer project.
//!
//! Flow: preflight (no change) -> recovery bundle (files, database dump,
//! manifest under `drupal-updates/<request id>/` in the backup root) ->
//! maintenance on -> `composer update` (allowlisted package names only) ->
//! `drush updatedb` -> `drush cache:rebuild` -> health probe -> maintenance
//! back to its previous mode. A failing step after the bundle is rolled back
//! by the engine itself: files are replaced from the bundle, the database is
//! dropped and re-imported, then the probe runs again. Only a probe that
//! passes after the rollback reports `rolledBack`; anything else is a
//! `recovery required` failure, never a success. `restoreUpdate` runs the
//! same rollback from a kept bundle on explicit request.
//!
//! Nothing here takes a command: the caller supplies validated paths, UID/GID
//! and, for packages, `vendor/name` identifiers that must already be locked
//! in the project. Multisite projects and non-MySQL databases are refused
//! before anything is changed.

use crate::{
    db_restore::{ContainerName, RestoreRequestError},
    drupal_action::{
        self, COMPOSER_HOME, CONTAINER_COMPOSER, INSTALL_TIMEOUT, MAX_OUTPUT, READ_TIMEOUT,
        RUN_TIMEOUT, UPDATE_TIMEOUT, container_exec, drush, exited_ok,
    },
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{self, CancellationToken, ProcessLimits, ProcessRequest, SubprocessDiagnostics},
    site::SiteRelativePath,
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        resource_lock,
        state::{self, TransactionStatus},
    },
    wordpress_migrate_export::sha256_file,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub const CORE: &str = "drupal.updateCore";
pub const PACKAGES: &str = "drupal.updatePackages";
pub const RESTORE: &str = "drupal.restoreUpdate";

const MAX_PACKAGES: usize = 128;
/// Recovery bundles are kept this long.
const RETENTION_SECS: u64 = 7 * 24 * 60 * 60;
const MAX_LOCK_BYTES: u64 = 64 * 1024 * 1024;
/// Core packages `updateCore` may name, when the project requires them.
const CORE_PACKAGES: [&str; 6] = [
    "drupal/core",
    "drupal/core-recommended",
    "drupal/core-composer-scaffold",
    "drupal/core-project-message",
    "drupal/core-vendor-hardening",
    "drupal/core-dev",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Core,
    Packages,
    Restore,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    container: String,
    project_root: String,
    document_root: String,
    uid: u32,
    gid: u32,
    /// `updatePackages` only.
    packages: Option<Vec<String>>,
    /// `restoreUpdate` only: the request id of the update to undo.
    recovery_id: Option<String>,
}

pub struct Request {
    kind: Kind,
    packages: Vec<String>,
    recovery_id: Option<RequestId>,
    /// The shared Drush/Composer request shape of `drupal_action`.
    base: drupal_action::Request,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    InvalidPackage,
    InvalidRecoveryId,
    InvalidShape,
    Base(drupal_action::RequestError),
}

fn package_name(value: &str) -> bool {
    let part = |part: &str| {
        !part.is_empty()
            && part.len() <= 100
            && part.as_bytes()[0].is_ascii_alphanumeric()
            && part
                .bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
    };
    value.len() <= 200
        && value
            .split_once('/')
            .is_some_and(|(vendor, name)| part(vendor) && part(name))
}

impl Request {
    /// `kind` is `update-core`, `update-packages` or `restore-update`.
    pub fn parse(
        kind: &str,
        json: &str,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        let (kind, packages, recovery_id) = match (kind, plan.packages, plan.recovery_id) {
            ("update-core", None, None) => (Kind::Core, Vec::new(), None),
            ("update-packages", Some(packages), None) => {
                if packages.is_empty()
                    || packages.len() > MAX_PACKAGES
                    || packages.iter().any(|name| !package_name(name))
                {
                    return Err(RequestError::InvalidPackage);
                }
                // Core goes through `updateCore`, so the two stay separate
                // operations with their own checks.
                if packages.iter().any(|name| name.starts_with("drupal/core")) {
                    return Err(RequestError::InvalidPackage);
                }
                let mut sorted = packages;
                sorted.sort();
                sorted.dedup();
                (Kind::Packages, sorted, None)
            }
            ("restore-update", None, Some(id)) => (
                Kind::Restore,
                Vec::new(),
                Some(RequestId::parse(&id).map_err(|_| RequestError::InvalidRecoveryId)?),
            ),
            _ => return Err(RequestError::InvalidShape),
        };
        let base_json = serde_json::json!({
            "container": plan.container,
            "projectRoot": plan.project_root,
            "documentRoot": plan.document_root,
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
            packages,
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
            Kind::Packages => PACKAGES,
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
    #[serde(default)]
    pub versions_before: BTreeMap<String, String>,
    #[serde(default)]
    pub versions_after: BTreeMap<String, String>,
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
    Multisite,
    NotAComposerProject,
    ComposerMissing,
    UnsupportedDatabase,
    NoCorePackages,
    PackageNotInstalled(String),
    LockUnreadable,
    /// The bundle could not be written; nothing was changed.
    BundleFailed,
    BundleMissing,
    BundleCorrupt,
    ComposerFailed(SubprocessDiagnostics),
    /// Rolled back automatically did not work out: the site needs
    /// `restoreUpdate`, or hands.
    RecoveryRequired(String),
    PostCommit {
        result: UpdateResult,
    },
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
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
            Self::Multisite => (
                ErrorCode::InvalidInput,
                "this Drupal project is a multisite; recovery-first updates support single-site \
                 projects only, nothing was changed"
                    .into(),
            ),
            Self::NotAComposerProject => (
                ErrorCode::InvalidInput,
                "the site has no composer.json and composer.lock; nothing was changed".into(),
            ),
            Self::ComposerMissing => (
                ErrorCode::DependencyUnavailable,
                "the managed Composer tool is not installed".into(),
            ),
            Self::UnsupportedDatabase => (
                ErrorCode::InvalidInput,
                "the site database is not a MySQL/MariaDB one reachable by container name, so a \
                 restorable backup cannot be taken; nothing was changed"
                    .into(),
            ),
            Self::NoCorePackages => (
                ErrorCode::InvalidInput,
                "composer.json requires no drupal/core package; nothing was changed".into(),
            ),
            Self::PackageNotInstalled(name) => (
                ErrorCode::InvalidInput,
                format!("{name} is not installed in composer.lock; nothing was changed"),
            ),
            Self::LockUnreadable => (
                ErrorCode::InvalidInput,
                "composer.lock could not be read; nothing was changed".into(),
            ),
            Self::BundleFailed => (
                ErrorCode::Internal,
                "the recovery bundle could not be written; nothing was changed".into(),
            ),
            Self::BundleMissing => (
                ErrorCode::NotFound,
                "no recovery bundle exists for this update (it may have expired)".into(),
            ),
            Self::BundleCorrupt => (
                ErrorCode::InvalidInput,
                "the recovery bundle does not match its manifest; nothing was changed".into(),
            ),
            Self::ComposerFailed(diagnostics) => (
                drupal_action::subprocess_code(diagnostics),
                "Composer could not update the packages".into(),
            ),
            Self::RecoveryRequired(why) => (
                ErrorCode::SubprocessFailed,
                format!(
                    "recovery required: {why}. The recovery bundle is kept; run restoreUpdate \
                     with this update's id"
                ),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit { .. } => {
                (ErrorCode::Internal, "internal Drupal update error".into())
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
    document_root: String,
    created_at_unix_secs: u64,
    previous_maintenance_mode: bool,
    versions_before: BTreeMap<String, String>,
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

/// `name -> version` for every package in `composer.lock`.
fn locked_versions(root: &Path) -> Result<BTreeMap<String, String>, Error> {
    let path = root.join("composer.lock");
    let meta = std::fs::metadata(&path).map_err(|_| Error::LockUnreadable)?;
    if !meta.is_file() || meta.len() > MAX_LOCK_BYTES {
        return Err(Error::LockUnreadable);
    }
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).map_err(|_| Error::LockUnreadable)?)
            .map_err(|_| Error::LockUnreadable)?;
    let mut out = BTreeMap::new();
    for section in ["packages", "packages-dev"] {
        for item in value
            .get(section)
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            if let (Some(name), Some(version)) = (
                item.get("name").and_then(|v| v.as_str()),
                item.get("version").and_then(|v| v.as_str()),
            ) {
                out.insert(name.to_owned(), version.trim_start_matches('v').to_owned());
            }
        }
    }
    Ok(out)
}

/// The core packages composer.json requires (the only ones `updateCore`
/// names).
fn required_core_packages(root: &Path) -> Result<Vec<String>, Error> {
    let bytes =
        std::fs::read(root.join("composer.json")).map_err(|_| Error::NotAComposerProject)?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| Error::NotAComposerProject)?;
    let mut out = Vec::new();
    for section in ["require", "require-dev"] {
        if let Some(map) = value.get(section).and_then(|v| v.as_object()) {
            for name in CORE_PACKAGES {
                if map.contains_key(name) {
                    out.push(name.to_owned());
                }
            }
        }
    }
    out.sort();
    out.dedup();
    if out.is_empty() {
        return Err(Error::NoCorePackages);
    }
    Ok(out)
}

fn is_multisite(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<bool, Error> {
    // More than one `sites/*/settings.php`, or a `sites.php` map, means
    // several sites share this code.
    let script = r#"n=0; for f in "$1"/sites/*/settings.php; do [ -f "$f" ] && n=$((n+1)); done; if [ "$n" -gt 1 ] || [ -f "$1/sites/sites.php" ]; then exit 3; fi"#;
    let output = container_exec(
        &ctx.action(),
        &req.base,
        &[],
        &["sh", "-c", script, "sh", &req.base.document_root_str()],
        READ_TIMEOUT,
        cancel,
    )?;
    Ok(!exited_ok(&output))
}

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

fn bundle(
    ctx: &Context<'_>,
    req: &Request,
    previous_maintenance: bool,
    versions_before: &BTreeMap<String, String>,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let dir = format!("drupal-updates/{}", req.request_id);
    ctx.backup_root
        .create_dir_all(&rel(dir.clone()))
        .map_err(|_| Error::BundleFailed)?;
    tar_bundle(ctx, req, &dir, cancel)?;
    // `database.sql` is written by the shared dump helper into the same dir.
    drupal_action::backup_database(&ctx.action(), &req.base, cancel)?;
    let bundle_dir = ctx.backup_path.join(&dir);
    let (_, files_sha256) = sha256_file(&bundle_dir.join("files.tar.gz")).map_err(Error::Io)?;
    let (_, database_sha256) = sha256_file(&bundle_dir.join("database.sql")).map_err(Error::Io)?;
    let manifest = Manifest {
        version: 1,
        operation: req.operation().into(),
        request_id: req.request_id.to_string(),
        project_root: req.root().display().to_string(),
        document_root: req.base.document_root_str(),
        created_at_unix_secs: now(),
        previous_maintenance_mode: previous_maintenance,
        versions_before: versions_before.clone(),
        files_sha256,
        database_sha256,
    };
    ctx.backup_root
        .create_new(
            &rel(format!("{dir}/manifest.json")),
            &serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .map_err(|_| Error::BundleFailed)
}

/// Removes bundles older than the retention window. Best effort: a bundle
/// that cannot be removed stays for the next run, and the one belonging to
/// this request is never touched.
fn prune_bundles(ctx: &Context<'_>, keep: RequestId) {
    let Ok(parent) = ctx
        .backup_root
        .open_managed_dir(&rel("drupal-updates".into()))
    else {
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

fn composer_update(
    ctx: &Context<'_>,
    req: &Request,
    names: &[String],
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let home = format!("COMPOSER_HOME={COMPOSER_HOME}");
    let cache = format!("COMPOSER_CACHE_DIR={COMPOSER_HOME}/cache");
    let mut args: Vec<&str> = vec!["php", CONTAINER_COMPOSER, "update"];
    args.extend(names.iter().map(String::as_str));
    args.extend([
        "--with-dependencies",
        "--no-interaction",
        "--no-ansi",
        "--no-progress",
    ]);
    let output = container_exec(
        &ctx.action(),
        &req.base,
        &[&home, &cache, "COMPOSER_NO_INTERACTION=1"],
        &args,
        INSTALL_TIMEOUT,
        cancel,
    )?;
    if !exited_ok(&output) {
        return Err(Error::ComposerFailed(SubprocessDiagnostics::from_output(
            ctx.docker_program,
            &output,
        )));
    }
    Ok(())
}

/// Bootstrap must be `Successful`, nothing may be left pending in
/// `updatedb:status`, and for a core update Drupal must report the version
/// `composer.lock` now holds.
fn probe(
    ctx: &Context<'_>,
    req: &Request,
    expect_core: Option<&str>,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let action = ctx.action();
    let bytes = drush(
        &action,
        &req.base,
        &["status", "--format=json"],
        READ_TIMEOUT,
        cancel,
    )
    .map_err(|_| "drush status failed".to_owned())?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| "drush status was unreadable".to_owned())?;
    if value.get("bootstrap").and_then(|v| v.as_str()) != Some("Successful") {
        return Err("Drupal did not bootstrap".into());
    }
    if let Some(expected) = expect_core {
        let reported = value
            .get("drupal-version")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if reported != expected {
            return Err(format!(
                "Drupal reports {reported}, composer.lock holds {expected}"
            ));
        }
    }
    match drupal_action::update_status(&action, &req.base, cancel) {
        Ok(0) => Ok(()),
        Ok(count) => Err(format!("{count} database update(s) are still pending")),
        Err(_) => Err("pending database updates could not be read".into()),
    }
}

fn apply(
    ctx: &Context<'_>,
    req: &Request,
    names: &[String],
    cancel: &CancellationToken,
) -> Result<BTreeMap<String, String>, String> {
    let action = ctx.action();
    let step = |label: &str, result: Result<(), Error>| {
        result.map_err(|error| format!("{label}: {}", error.protocol().1))
    };
    step("composer update", composer_update(ctx, req, names, cancel))?;
    step(
        "database updates",
        drush(&action, &req.base, &["updatedb"], UPDATE_TIMEOUT, cancel)
            .map(|_| ())
            .map_err(Error::from),
    )?;
    step(
        "cache rebuild",
        drush(&action, &req.base, &["cache:rebuild"], RUN_TIMEOUT, cancel)
            .map(|_| ())
            .map_err(Error::from),
    )?;
    let after = locked_versions(req.root()).map_err(|_| "composer.lock unreadable".to_owned())?;
    let core = (req.kind == Kind::Core)
        .then(|| after.get("drupal/core").cloned())
        .flatten();
    probe(ctx, req, core.as_deref(), cancel)?;
    Ok(after)
}

/// Replaces the project's files and database with the bundle's. The bundle
/// is verified (checksums, readable archive) before anything is removed.
fn rollback(ctx: &Context<'_>, req: &Request, id: RequestId) -> Result<Manifest, Error> {
    let cancel = CancellationToken::default();
    let dir = format!("drupal-updates/{id}");
    let manifest: Manifest = serde_json::from_str(
        &ctx.backup_root
            .read_to_string(&rel(format!("{dir}/manifest.json")))
            .map_err(|_| Error::BundleMissing)?,
    )
    .map_err(|_| Error::BundleCorrupt)?;
    if manifest.project_root != req.root().display().to_string() {
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

    // Files: empty the project root (links are removed, never followed),
    // then extract.
    for entry in std::fs::read_dir(req.root()).map_err(Error::Io)? {
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
            req.root().display().to_string(),
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

    // Database: Drush (restored with the files) names the connection.
    let action = ctx.action();
    let connection = drupal_action::read_db_connection(&action, &req.base, &cancel)?
        .ok_or(Error::UnsupportedDatabase)?;
    drush(
        &action,
        &req.base,
        &["sql:drop", "--yes"],
        UPDATE_TIMEOUT,
        &cancel,
    )?;
    let dump = ctx
        .backup_root
        .open_regular_read(&rel(format!("{dir}/database.sql")))
        .map_err(Error::Io)?;
    let imported = process::run_with_stdin_handle(
        &ProcessRequest::new(ctx.docker_program)
            .env("MYSQL_PWD", &connection.password)
            .args([
                "exec".to_owned(),
                "-i".into(),
                "-e".into(),
                "MYSQL_PWD".into(),
                connection.host.clone(),
                "mariadb".into(),
                format!("-u{}", connection.user),
                connection.database.clone(),
            ]),
        dump,
        &limits,
        &cancel,
    )
    .map_err(Error::Run)?;
    if !exited_ok(&imported) {
        return Err(Error::RecoveryRequired("the database import failed".into()));
    }
    drush(&action, &req.base, &["cache:rebuild"], RUN_TIMEOUT, &cancel)?;
    let before = manifest.versions_before.get("drupal/core").cloned();
    probe(ctx, req, before.as_deref(), &cancel)
        .map_err(|why| Error::RecoveryRequired(format!("after restoring: {why}")))?;
    Ok(manifest)
}

fn run(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<UpdateResult, Error> {
    let action = ctx.action();
    if req.kind == Kind::Restore {
        let id = req.recovery_id.unwrap();
        let manifest = rollback(ctx, req, id)?;
        return Ok(UpdateResult {
            outcome: "restored".into(),
            recovery_id: id.to_string(),
            reason: None,
            versions_before: manifest.versions_before.clone(),
            versions_after: manifest.versions_before,
            completed_at_unix_secs: now(),
        });
    }

    // Preflight: nothing is changed until all of this holds.
    if !ctx
        .tools_dir
        .join("composer/current/composer.phar")
        .is_file()
    {
        return Err(Error::ComposerMissing);
    }
    let before = locked_versions(req.root())?;
    let names = match req.kind {
        Kind::Core => required_core_packages(req.root())?,
        _ => {
            for name in &req.packages {
                if !before.contains_key(name) {
                    return Err(Error::PackageNotInstalled(name.clone()));
                }
            }
            req.packages.clone()
        }
    };
    if is_multisite(ctx, req, cancel)? {
        return Err(Error::Multisite);
    }
    if drupal_action::read_db_connection(&action, &req.base, cancel)?.is_none() {
        return Err(Error::UnsupportedDatabase);
    }
    let previous = drupal_action::read_maintenance(&action, &req.base, cancel)?;
    let watched: BTreeMap<String, String> = before
        .iter()
        .filter(|(name, _)| names.contains(name) || name.starts_with("drupal/core"))
        .map(|(n, v)| (n.clone(), v.clone()))
        .collect();

    prune_bundles(ctx, req.request_id);
    bundle(ctx, req, previous, &watched, cancel)?;

    // From here a failure is rolled back by the engine.
    let attempt = (|| {
        if !previous {
            drupal_action::set_maintenance(&action, &req.base, true, cancel)
                .map_err(|e| format!("maintenance: {}", Error::from(e).protocol().1))?;
        }
        apply(ctx, req, &names, cancel)
    })();
    let restore_cancel = CancellationToken::default();
    match attempt {
        Ok(after) => {
            if !previous {
                drupal_action::set_maintenance(&action, &req.base, false, &restore_cancel)
                    .map_err(|_| {
                        Error::RecoveryRequired(
                            "the update succeeded but maintenance mode could not be turned off"
                                .into(),
                        )
                    })?;
            }
            let after = after
                .into_iter()
                .filter(|(name, _)| watched.contains_key(name))
                .collect();
            Ok(UpdateResult {
                outcome: "updated".into(),
                recovery_id: req.request_id.to_string(),
                reason: None,
                versions_before: watched,
                versions_after: after,
                completed_at_unix_secs: now(),
            })
        }
        Err(reason) => {
            rollback(ctx, req, req.request_id).map_err(|error| {
                Error::RecoveryRequired(format!(
                    "the update failed ({reason}) and rolling back failed ({})",
                    error.protocol().1
                ))
            })?;
            Ok(UpdateResult {
                outcome: "rolledBack".into(),
                recovery_id: req.request_id.to_string(),
                reason: Some(reason),
                versions_before: watched.clone(),
                versions_after: watched,
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
    let scope_path = SiteRelativePath::parse(format!("drupal-update/{hash}")).unwrap();
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
    // Same lock the other Drupal actions take: no cron or cache action runs
    // against a half-updated project.
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
    let result = match run(ctx, req, cancel) {
        Ok(value) => value,
        Err(error) => return Err(fail(&scope, &state_path, &audit_path, state, error)),
    };
    state
        .mark_committed(serde_json::to_value(&result).unwrap())
        .unwrap();
    if state::save(&scope, &state_path, &state).is_err() {
        drop(lock);
        return Err(Error::PostCommit { result });
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
mod tests;
