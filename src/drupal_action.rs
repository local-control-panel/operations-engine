//! Four small, typed Drupal mutations run through the site's Drush under one
//! lock/idempotency/transaction/audit-backed request:
//! `drupal.cacheRebuild` (`drush cache:rebuild`), `drupal.cronRun`
//! (`drush core:cron`), `drupal.maintenance` (maintenance mode on/off) and
//! `drupal.installDrush` (`composer require drush/drush` in the project with
//! the engine-managed Composer, so Drush lives in the project's
//! `vendor/bin/drush`, never globally).
//!
//! There is deliberately no way to pass a Drush command or argument: the
//! action selects a fixed argv, the only caller-controlled values are the
//! validated container/roots/UID/GID and, for maintenance, an explicit
//! `on`/`off`. Drush runs as the site user, never root, inside the site's
//! runtime container, from the project root (project-local
//! `vendor/bin/drush` first, `drush` on `PATH` as fallback) with the public
//! document root passed as `--root`. The result carries no Drush output: only
//! the action, whether it succeeded and, for maintenance, the state read back
//! after the change. A retried request with the same idempotency key replays
//! the recorded outcome instead of running Drush again.

use crate::{
    db_restore::{ContainerName, RestoreRequestError},
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{
        self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination,
        SubprocessDiagnostics,
    },
    site::SiteRelativePath,
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        resource_lock,
        state::{self, TransactionStatus},
    },
};
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const CACHE_REBUILD: &str = "drupal.cacheRebuild";
pub const CRON_RUN: &str = "drupal.cronRun";
pub const MAINTENANCE: &str = "drupal.maintenance";
pub const INSTALL_DRUSH: &str = "drupal.installDrush";
pub const UPDATE_DB: &str = "drupal.updateDb";
pub const AUTOMATED_CRON: &str = "drupal.automatedCron";

/// Upper bound for a restored interval (one year, in seconds); Drupal offers
/// 3 hours to 1 week, `0` turns the web-triggered cron off.
const MAX_CRON_INTERVAL: u32 = 31_536_000;

/// Path of the engine-managed Composer inside runtime containers (the tools
/// directory is mounted read-only at `/opt/wcp-tools`).
const CONTAINER_COMPOSER: &str = "/opt/wcp-tools/composer/current/composer.phar";
/// Writable by any site user; Composer's home and cache for one run.
const COMPOSER_HOME: &str = "/tmp/wcp-composer";
const INSTALL_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Drush's `cache:rebuild` and `core:cron` can legitimately take minutes on a
/// large site; anything longer is a hang.
const RUN_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Database updates (`hook_update_N`, post-updates) can legitimately run
/// long on a big site.
const UPDATE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const READ_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_OUTPUT: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    CacheRebuild,
    CronRun,
    Maintenance {
        enabled: bool,
    },
    InstallDrush,
    UpdateDb,
    /// Set `automated_cron.settings:interval` (seconds; `0` = off).
    AutomatedCron {
        interval: u32,
    },
}

impl Action {
    pub const fn operation(self) -> &'static str {
        match self {
            Self::CacheRebuild => CACHE_REBUILD,
            Self::CronRun => CRON_RUN,
            Self::Maintenance { .. } => MAINTENANCE,
            Self::InstallDrush => INSTALL_DRUSH,
            Self::UpdateDb => UPDATE_DB,
            Self::AutomatedCron { .. } => AUTOMATED_CRON,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::CacheRebuild => "cacheRebuild",
            Self::CronRun => "cronRun",
            Self::Maintenance { .. } => "maintenance",
            Self::InstallDrush => "installDrush",
            Self::UpdateDb => "updateDb",
            Self::AutomatedCron { .. } => "automatedCron",
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    container: String,
    project_root: String,
    document_root: String,
    uid: u32,
    gid: u32,
    /// `"on"` or `"off"`; required for maintenance, forbidden otherwise.
    state: Option<String>,
    /// Seconds for `automated-cron` (default `0` = off); forbidden otherwise.
    interval: Option<u32>,
}

#[derive(Debug)]
pub struct Request {
    pub action: Action,
    container: ContainerName,
    project_root: PathBuf,
    document_root: PathBuf,
    uid: u32,
    gid: u32,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    InvalidState,
    InvalidInterval,
    InvalidRoot,
    InvalidContainer,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

/// An absolute path made of plain components: no `..`, no control
/// characters, bounded length. It is passed as one argv element and never
/// through a shell, so this is defence in depth rather than quoting.
fn plain_absolute_path(value: &str) -> Option<PathBuf> {
    let path = PathBuf::from(value);
    (path.is_absolute()
        && value.len() <= 4096
        && !value.chars().any(char::is_control)
        && !path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir)))
    .then_some(path)
}

impl Request {
    /// `kind` is `cache-rebuild`, `cron-run` or `maintenance`, as named by
    /// the CLI subcommand.
    pub fn parse(
        kind: &str,
        json: &str,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        if plan.interval.is_some() && kind != "automated-cron" {
            return Err(RequestError::InvalidInterval);
        }
        let action = match (kind, plan.state.as_deref()) {
            ("automated-cron", None) => {
                let interval = plan.interval.unwrap_or(0);
                if interval > MAX_CRON_INTERVAL {
                    return Err(RequestError::InvalidInterval);
                }
                Action::AutomatedCron { interval }
            }
            ("cache-rebuild", None) => Action::CacheRebuild,
            ("cron-run", None) => Action::CronRun,
            ("install-drush", None) => Action::InstallDrush,
            ("update-db", None) => Action::UpdateDb,
            ("maintenance", Some("on")) => Action::Maintenance { enabled: true },
            ("maintenance", Some("off")) => Action::Maintenance { enabled: false },
            _ => return Err(RequestError::InvalidState),
        };
        let project_root =
            plain_absolute_path(&plan.project_root).ok_or(RequestError::InvalidRoot)?;
        let document_root =
            plain_absolute_path(&plan.document_root).ok_or(RequestError::InvalidRoot)?;
        // The public root is the project root itself (classic layout) or a
        // directory below it (Composer `web/` layout); never outside it.
        if !document_root.starts_with(&project_root) {
            return Err(RequestError::InvalidRoot);
        }
        Ok(Self {
            action,
            container: ContainerName::parse(&plan.container)
                .map_err(|_: RestoreRequestError| RequestError::InvalidContainer)?,
            project_root,
            document_root,
            uid: plan.uid,
            gid: plan.gid,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }

    pub fn root(&self) -> &std::path::Path {
        &self.project_root
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionResult {
    pub action: String,
    /// For `maintenance`: the mode read back from Drupal after the change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maintenance_mode: Option<bool>,
    /// For `installDrush`: `false` when the project already had Drush.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    /// For `automatedCron`: the interval (seconds) before the change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_interval: Option<u32>,
    /// For `automatedCron`: the interval (seconds) read back after the change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<u32>,
    /// For `updateDb`: how many database updates `updatedb:status` listed
    /// before the run (`0` means nothing was run).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updates_pending: Option<u32>,
    /// For `updateDb`: how many were still listed after the run (`0` on
    /// success; the request fails otherwise).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updates_remaining: Option<u32>,
    /// For `updateDb` that ran updates: the maintenance mode before the run
    /// (it is restored to this afterwards, also when the run failed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_maintenance_mode: Option<bool>,
    /// For `updateDb` that ran updates: the database dump taken first,
    /// relative to the backup root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_file: Option<String>,
    pub completed_at_unix_secs: u64,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub docker_program: &'a str,
    /// Host directory of the engine-managed tools ([`crate::tool_manage::TOOLS_DIR`]).
    pub tools_dir: &'a std::path::Path,
    /// Managed backup root; `updateDb` writes its pre-update database dump
    /// under `drupal-updates/<request id>/` there.
    pub backup_root: &'a ManagedRoot,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    ResourceBusy,
    Cancelled,
    Run(process::ProcessRunError),
    Rejected(SubprocessDiagnostics),
    /// The Composer step of `installDrush` failed. Kept apart from
    /// `Rejected` so the message names Composer, not Drush.
    ComposerFailed(SubprocessDiagnostics),
    /// Composer added Drush but `drush --version` does not run.
    DrushDoesNotRun(SubprocessDiagnostics),
    /// Drupal did not report the maintenance mode that was just set.
    StateMismatch,
    /// `updatedb:status` printed something that is not the JSON list of
    /// pending updates, so the engine does not run an update blind.
    UpdateStatusUnreadable,
    /// `config:get` printed something that is not a whole number of seconds.
    CronIntervalUnreadable,
    /// Updates were still listed after `updatedb` finished.
    UpdatesRemain(u32),
    /// The maintenance mode before `updateDb` could not be read, so it could
    /// not be restored; nothing was changed.
    MaintenanceUnreadable,
    /// The pre-update database dump failed; no update was run.
    BackupFailed(SubprocessDiagnostics),
    /// The backup root could not be written; no update was run.
    BackupUnavailable(std::io::Error),
    /// `updateDb` failed (or finished) and the previous maintenance mode
    /// could not be put back: the site may be left in maintenance mode.
    MaintenanceNotRestored,
    /// The engine-managed Composer is not installed on the host.
    ComposerMissing,
    /// The project root has no `composer.json`: Drush is installed per
    /// Composer project only.
    NotAComposerProject,
    PostCommit {
        result: ActionResult,
    },
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

fn subprocess_code(diagnostics: &SubprocessDiagnostics) -> ErrorCode {
    if diagnostics.timed_out {
        ErrorCode::Timeout
    } else if diagnostics.cancelled {
        ErrorCode::Cancelled
    } else {
        ErrorCode::SubprocessFailed
    }
}

/// How the child ended, from the runner's own bookkeeping only (never from
/// what it printed): " (timed out)", " (cancelled)" or " (exit code N)".
fn outcome_suffix(diagnostics: &SubprocessDiagnostics) -> String {
    if diagnostics.timed_out {
        " (timed out)".into()
    } else if diagnostics.cancelled {
        " (cancelled)".into()
    } else if let Some(code) = diagnostics.exit_code {
        format!(" (exit code {code})")
    } else {
        String::new()
    }
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
            Self::Run(error) => (
                process::spawn_error_code(error),
                "could not run Drush".into(),
            ),
            Self::Rejected(diagnostics) => (
                subprocess_code(diagnostics),
                format!("Drush reported an error{}", outcome_suffix(diagnostics)),
            ),
            Self::ComposerFailed(diagnostics) => (
                subprocess_code(diagnostics),
                format!(
                    "Composer could not add drush/drush to the project{}. Likely causes: the project is \
                     not writable by the site user, no network from the runtime \
                     container, or a PHP or package conflict in composer.json. Run `composer require drush/drush` in the project \
                     to see the exact reason",
                    outcome_suffix(diagnostics)
                ),
            ),
            Self::DrushDoesNotRun(diagnostics) => (
                subprocess_code(diagnostics),
                format!(
                    "Drush was added to the project but does not run{}",
                    outcome_suffix(diagnostics)
                ),
            ),
            Self::StateMismatch => (
                ErrorCode::SubprocessFailed,
                "Drupal did not report the requested maintenance mode".into(),
            ),
            Self::UpdateStatusUnreadable => (
                ErrorCode::SubprocessFailed,
                "Drush did not report the pending database updates in a readable form".into(),
            ),
            Self::CronIntervalUnreadable => (
                ErrorCode::SubprocessFailed,
                "Drush did not report the automated cron interval in a readable form".into(),
            ),
            Self::UpdatesRemain(count) => (
                ErrorCode::SubprocessFailed,
                format!("{count} database update(s) are still pending after the run"),
            ),
            Self::MaintenanceUnreadable => (
                ErrorCode::SubprocessFailed,
                "Drush did not report the maintenance mode in a readable form; no update was run"
                    .into(),
            ),
            Self::BackupFailed(diagnostics) => (
                subprocess_code(diagnostics),
                format!(
                    "the database backup before the update failed{}; no update was run",
                    outcome_suffix(diagnostics)
                ),
            ),
            Self::BackupUnavailable(_) => (
                ErrorCode::Internal,
                "the backup root could not be written; no update was run".into(),
            ),
            Self::MaintenanceNotRestored => (
                ErrorCode::SubprocessFailed,
                "the database update did not finish cleanly and the previous maintenance mode \
                 could not be restored; the site may still be in maintenance mode"
                    .into(),
            ),
            Self::ComposerMissing => (
                ErrorCode::DependencyUnavailable,
                "the managed Composer tool is not installed".into(),
            ),
            Self::NotAComposerProject => (
                ErrorCode::InvalidInput,
                "the site has no composer.json, so Drush cannot be installed for it".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit { .. } => {
                (ErrorCode::Internal, "internal Drupal action error".into())
            }
        }
    }
}

/// Runs `drush --root=<docroot> <args>` as the site user from the project
/// root, preferring the project's own Drush. `sh` only selects the binary;
/// every value reaches it as a positional parameter, never as shell text.
fn drush(
    ctx: &Context<'_>,
    req: &Request,
    drush_args: &[&str],
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<Vec<u8>, Error> {
    let mut args: Vec<String> = vec![
        "exec".into(),
        "-i".into(),
        "--user".into(),
        format!("{}:{}", req.uid, req.gid),
        "-w".into(),
        req.project_root.display().to_string(),
        req.container.as_str().to_owned(),
        "sh".into(),
        "-c".into(),
        "if [ -x ./vendor/bin/drush ]; then exec ./vendor/bin/drush \"$@\"; else exec drush \"$@\"; fi"
            .into(),
        "drush".into(),
        format!("--root={}", req.document_root.display()),
        "--no-interaction".into(),
    ];
    args.extend(drush_args.iter().map(|arg| (*arg).to_owned()));
    let output = process::run(
        &ProcessRequest::new(ctx.docker_program).args(args),
        &ProcessLimits {
            timeout,
            max_stdout_bytes: MAX_OUTPUT,
            max_stderr_bytes: MAX_OUTPUT,
        },
        cancel,
    )
    .map_err(Error::Run)?;
    if !matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        return Err(Error::Rejected(SubprocessDiagnostics::from_output(
            ctx.docker_program,
            &output,
        )));
    }
    Ok(output.stdout.bytes)
}

/// Runs a fixed `docker exec` as the site user in the project root. Used for
/// the Composer step of `installDrush`; `program_and_args` never contains
/// caller-controlled text.
fn container_exec(
    ctx: &Context<'_>,
    req: &Request,
    env: &[&str],
    program_and_args: &[&str],
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<process::ProcessOutput, Error> {
    let mut args: Vec<String> = vec![
        "exec".into(),
        "-i".into(),
        "--user".into(),
        format!("{}:{}", req.uid, req.gid),
        "-w".into(),
        req.project_root.display().to_string(),
    ];
    for value in env {
        args.push("-e".into());
        args.push((*value).to_owned());
    }
    args.push(req.container.as_str().to_owned());
    args.extend(program_and_args.iter().map(|arg| (*arg).to_owned()));
    process::run(
        &ProcessRequest::new(ctx.docker_program).args(args),
        &ProcessLimits {
            timeout,
            max_stdout_bytes: MAX_OUTPUT,
            max_stderr_bytes: MAX_OUTPUT,
        },
        cancel,
    )
    .map_err(Error::Run)
}

fn exited_ok(output: &process::ProcessOutput) -> bool {
    matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    )
}

/// Installs Drush into the project with the managed Composer. Returns
/// whether anything changed.
fn install_drush(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<bool, Error> {
    // Already there: a Composer project whose vendor/bin/drush is executable.
    if exited_ok(&container_exec(
        ctx,
        req,
        &[],
        &["test", "-x", "./vendor/bin/drush"],
        READ_TIMEOUT,
        cancel,
    )?) {
        return Ok(false);
    }
    if !exited_ok(&container_exec(
        ctx,
        req,
        &[],
        &["test", "-f", "./composer.json"],
        READ_TIMEOUT,
        cancel,
    )?) {
        return Err(Error::NotAComposerProject);
    }
    if !ctx
        .tools_dir
        .join("composer/current/composer.phar")
        .is_file()
    {
        return Err(Error::ComposerMissing);
    }
    let home = format!("COMPOSER_HOME={COMPOSER_HOME}");
    let cache = format!("COMPOSER_CACHE_DIR={COMPOSER_HOME}/cache");
    let output = container_exec(
        ctx,
        req,
        &[&home, &cache, "COMPOSER_NO_INTERACTION=1"],
        &[
            "php",
            CONTAINER_COMPOSER,
            "require",
            "drush/drush",
            "--no-interaction",
            "--no-ansi",
            "--no-progress",
            "--no-scripts",
            "--quiet",
        ],
        INSTALL_TIMEOUT,
        cancel,
    )?;
    if !exited_ok(&output) {
        return Err(Error::ComposerFailed(SubprocessDiagnostics::from_output(
            ctx.docker_program,
            &output,
        )));
    }
    // Prove the result works the way later operations will run it.
    drush(ctx, req, &["--version"], READ_TIMEOUT, cancel).map_err(|error| match error {
        Error::Rejected(diagnostics) => Error::DrushDoesNotRun(diagnostics),
        other => other,
    })?;
    Ok(true)
}

fn maintenance_flag(bytes: &[u8]) -> Option<bool> {
    match String::from_utf8_lossy(bytes).trim() {
        "1" | "true" | "TRUE" => Some(true),
        "0" | "false" | "FALSE" | "" => Some(false),
        _ => None,
    }
}

/// What one action reports besides its name.
#[derive(Default)]
struct Outcome {
    maintenance_mode: Option<bool>,
    changed: Option<bool>,
    previous_interval: Option<u32>,
    interval: Option<u32>,
    updates_pending: Option<u32>,
    updates_remaining: Option<u32>,
    previous_maintenance_mode: Option<bool>,
    backup_file: Option<String>,
}

/// Number of pending updates in `drush updatedb:status --format=json`
/// output: empty output and an empty list/object mean none, a JSON array or
/// object counts its entries, anything else is unreadable.
fn pending_updates(bytes: &[u8]) -> Option<u32> {
    let text = String::from_utf8_lossy(bytes);
    let text = text.trim();
    if text.is_empty() {
        return Some(0);
    }
    match serde_json::from_str::<serde_json::Value>(text).ok()? {
        serde_json::Value::Array(items) => u32::try_from(items.len()).ok(),
        serde_json::Value::Object(items) => u32::try_from(items.len()).ok(),
        serde_json::Value::Null => Some(0),
        _ => None,
    }
}

/// Drush versions report either a scalar or a single named config value.
/// Accept only the requested interval; unrelated or ambiguous output is unknown.
fn cron_interval(bytes: &[u8]) -> Option<u32> {
    let value: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(bytes).trim()).ok()?;
    let interval = match &value {
        serde_json::Value::Object(items) if items.len() == 1 => {
            items.get("automated_cron.settings:interval")?
        }
        _ => &value,
    };
    interval
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
}

fn read_cron_interval(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<u32, Error> {
    let bytes = drush(
        ctx,
        req,
        &[
            "config:get",
            "automated_cron.settings",
            "interval",
            "--format=json",
        ],
        READ_TIMEOUT,
        cancel,
    )?;
    cron_interval(&bytes).ok_or(Error::CronIntervalUnreadable)
}

/// Reads the interval (failing when Drupal or the module is not there), sets
/// it through Drupal's own config API only when it differs, and reads it back.
fn automated_cron(
    ctx: &Context<'_>,
    req: &Request,
    interval: u32,
    cancel: &CancellationToken,
) -> Result<Outcome, Error> {
    let previous = read_cron_interval(ctx, req, cancel)?;
    if previous == interval {
        return Ok(Outcome {
            changed: Some(false),
            previous_interval: Some(previous),
            interval: Some(previous),
            ..Outcome::default()
        });
    }
    drush(
        ctx,
        req,
        &[
            "config:set",
            "--no-interaction",
            "--input-format=yaml",
            "automated_cron.settings",
            "interval",
            &interval.to_string(),
        ],
        READ_TIMEOUT,
        cancel,
    )?;
    let now = read_cron_interval(ctx, req, cancel)?;
    if now != interval {
        return Err(Error::StateMismatch);
    }
    Ok(Outcome {
        changed: Some(true),
        previous_interval: Some(previous),
        interval: Some(now),
        ..Outcome::default()
    })
}

fn update_status(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<u32, Error> {
    let bytes = drush(
        ctx,
        req,
        &["updatedb:status", "--format=json"],
        READ_TIMEOUT,
        cancel,
    )?;
    pending_updates(&bytes).ok_or(Error::UpdateStatusUnreadable)
}

fn read_maintenance(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<bool, Error> {
    maintenance_flag(&drush(
        ctx,
        req,
        &["state:get", "system.maintenance_mode"],
        READ_TIMEOUT,
        cancel,
    )?)
    .ok_or(Error::StateMismatch)
}

/// Sets maintenance mode through Drupal's state API, rebuilds so cached pages
/// follow, and reads it back.
fn set_maintenance(
    ctx: &Context<'_>,
    req: &Request,
    enabled: bool,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let value = if enabled { "1" } else { "0" };
    drush(
        ctx,
        req,
        &[
            "state:set",
            "system.maintenance_mode",
            value,
            "--input-format=integer",
        ],
        READ_TIMEOUT,
        cancel,
    )?;
    // Drupal only honours the new mode for cached pages after a rebuild.
    drush(ctx, req, &["cache:rebuild"], RUN_TIMEOUT, cancel)?;
    if read_maintenance(ctx, req, cancel)? != enabled {
        return Err(Error::StateMismatch);
    }
    Ok(())
}

/// Dumps the database with the site's own Drush into the managed backup root
/// (`drupal-updates/<request id>/database.sql`) and returns that relative
/// path. The dump is streamed to the file, never held in memory or returned.
fn backup_database(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<String, Error> {
    let dir = format!("drupal-updates/{}", req.request_id);
    let dir_path = SiteRelativePath::parse(&dir).unwrap();
    ctx.backup_root
        .create_dir_all(&dir_path)
        .map_err(Error::BackupUnavailable)?;
    let relative = format!("{dir}/database.sql");
    let file = ctx
        .backup_root
        .create_new_file(&SiteRelativePath::parse(&relative).unwrap())
        .map_err(Error::BackupUnavailable)?;
    let args: Vec<String> = vec![
        "exec".into(),
        "-i".into(),
        "--user".into(),
        format!("{}:{}", req.uid, req.gid),
        "-w".into(),
        req.project_root.display().to_string(),
        req.container.as_str().to_owned(),
        "sh".into(),
        "-c".into(),
        "if [ -x ./vendor/bin/drush ]; then exec ./vendor/bin/drush \"$@\"; else exec drush \"$@\"; fi"
            .into(),
        "drush".into(),
        format!("--root={}", req.document_root.display()),
        "--no-interaction".into(),
        "sql:dump".into(),
    ];
    let output = process::run_with_stdout_file(
        &ProcessRequest::new(ctx.docker_program).args(args),
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
        // A partial dump is not a backup: do not leave it looking like one.
        let _ = ctx
            .backup_root
            .remove_file(&SiteRelativePath::parse(&relative).unwrap());
        return Err(Error::BackupFailed(SubprocessDiagnostics::from_output(
            ctx.docker_program,
            &output,
        )));
    }
    Ok(relative)
}

/// `updatedb:status` first; nothing is run when nothing is pending. When
/// updates are pending: read the maintenance mode, dump the database, turn
/// maintenance on, run `updatedb`, and put the PREVIOUS mode back whatever
/// happened (also on error and after a cancel). Afterwards the status is read
/// again and must be empty.
fn update_db(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<Outcome, Error> {
    let pending = update_status(ctx, req, cancel)?;
    if pending == 0 {
        return Ok(Outcome {
            changed: Some(false),
            updates_pending: Some(0),
            updates_remaining: Some(0),
            ..Outcome::default()
        });
    }
    let previous = read_maintenance(ctx, req, cancel).map_err(|_| Error::MaintenanceUnreadable)?;
    let backup_file = backup_database(ctx, req, cancel)?;

    // From here on maintenance may have been touched: always run the restore.
    let ran = (|| {
        if !previous {
            set_maintenance(ctx, req, true, cancel)?;
        }
        drush(ctx, req, &["updatedb"], UPDATE_TIMEOUT, cancel)?;
        let remaining = update_status(ctx, req, cancel)?;
        if remaining > 0 {
            return Err(Error::UpdatesRemain(remaining));
        }
        Ok(())
    })();
    // A cancelled request must still leave the site as it found it.
    let restore_cancel = CancellationToken::default();
    let restored = if previous {
        Ok(())
    } else {
        set_maintenance(ctx, req, false, &restore_cancel)
    };
    if restored.is_err() {
        return Err(Error::MaintenanceNotRestored);
    }
    ran?;
    Ok(Outcome {
        changed: Some(true),
        updates_pending: Some(pending),
        updates_remaining: Some(0),
        previous_maintenance_mode: Some(previous),
        backup_file: Some(backup_file),
        ..Outcome::default()
    })
}

fn run_action(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<Outcome, Error> {
    match req.action {
        Action::InstallDrush => install_drush(ctx, req, cancel).map(|changed| Outcome {
            changed: Some(changed),
            ..Outcome::default()
        }),
        Action::UpdateDb => update_db(ctx, req, cancel),
        Action::AutomatedCron { interval } => automated_cron(ctx, req, interval, cancel),
        _ => run_drush_action(ctx, req, cancel).map(|maintenance_mode| Outcome {
            maintenance_mode,
            ..Outcome::default()
        }),
    }
}

fn run_drush_action(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<Option<bool>, Error> {
    match req.action {
        Action::InstallDrush | Action::UpdateDb | Action::AutomatedCron { .. } => {
            unreachable!("handled by run_action")
        }
        Action::CacheRebuild => {
            drush(ctx, req, &["cache:rebuild"], RUN_TIMEOUT, cancel)?;
            Ok(None)
        }
        Action::CronRun => {
            drush(ctx, req, &["core:cron"], RUN_TIMEOUT, cancel)?;
            Ok(None)
        }
        Action::Maintenance { enabled } => {
            let value = if enabled { "1" } else { "0" };
            drush(
                ctx,
                req,
                &[
                    "state:set",
                    "system.maintenance_mode",
                    value,
                    "--input-format=integer",
                ],
                READ_TIMEOUT,
                cancel,
            )?;
            // Drupal only honours the new mode for cached pages after a
            // rebuild.
            drush(ctx, req, &["cache:rebuild"], RUN_TIMEOUT, cancel)?;
            let read_back = maintenance_flag(&drush(
                ctx,
                req,
                &["state:get", "system.maintenance_mode"],
                READ_TIMEOUT,
                cancel,
            )?)
            .ok_or(Error::StateMismatch)?;
            if read_back != enabled {
                return Err(Error::StateMismatch);
            }
            Ok(Some(read_back))
        }
    }
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<ActionResult, Error> {
    let hash = resource_lock::canonical_hash(&req.project_root);
    let scope_path = SiteRelativePath::parse(format!("drupal-action/{hash}")).unwrap();
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
    let _resource_lock =
        resource_lock::acquire(ctx.engine_state, &req.project_root, req.request_id)
            .map_err(|_| Error::ResourceBusy)?;

    let operation = req.action.operation();
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

    let outcome = match run_action(ctx, req, cancel) {
        Ok(value) => value,
        Err(error) => return Err(fail(&scope, &state_path, &audit_path, state, error)),
    };
    let result = ActionResult {
        action: req.action.name().into(),
        maintenance_mode: outcome.maintenance_mode,
        changed: outcome.changed,
        previous_interval: outcome.previous_interval,
        interval: outcome.interval,
        updates_pending: outcome.updates_pending,
        updates_remaining: outcome.updates_remaining,
        previous_maintenance_mode: outcome.previous_maintenance_mode,
        backup_file: outcome.backup_file,
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
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(req.request_id, true, None),
    );
    drop(lock);
    Ok(result)
}

fn replay(scope: &ManagedRoot, id: RequestId, operation: &str) -> Result<ActionResult, Error> {
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
    use std::{fs, os::unix::fs::PermissionsExt};

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const ID2: &str = "123e4567-e89b-12d3-a456-426614174001";

    fn managed(directory: &std::path::Path) -> ManagedRoot {
        ManagedRoot::open(&crate::site::TrustedRoot::parse(directory).unwrap()).unwrap()
    }

    fn request(kind: &str, state: Option<&str>, id: &str, key: Option<&str>) -> Request {
        let state = state.map_or(String::new(), |s| format!(r#","state":"{s}""#));
        Request::parse(
            kind,
            &format!(
                r#"{{"container":"runtime-1","projectRoot":"/var/www/site","documentRoot":"/var/www/site/web","uid":1000,"gid":1000{state}}}"#
            ),
            id,
            key,
        )
        .unwrap()
    }

    /// A stand-in for `docker exec ... drush ...`: records every invocation
    /// and keeps the maintenance flag in a file so a read-back works.
    fn fake_docker(directory: &std::path::Path, fail_all: bool) -> String {
        let log = directory.join("drush.log");
        let flag = directory.join("flag");
        let path = directory.join("fake-docker");
        fs::write(
            &path,
            format!(
                r#"#!/bin/sh
printf '%s\n' "$*" >> '{log}'
{fail}
case "$*" in
  *"state:set system.maintenance_mode 1"*) echo 1 > '{flag}' ;;
  *"state:set system.maintenance_mode 0"*) echo 0 > '{flag}' ;;
  *"state:get system.maintenance_mode"*) cat '{flag}' ;;
esac
exit 0
"#,
                log = log.display(),
                flag = flag.display(),
                fail = if fail_all { "exit 1" } else { "" },
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn log(directory: &std::path::Path) -> String {
        fs::read_to_string(directory.join("drush.log")).unwrap_or_default()
    }

    #[test]
    fn rejects_invalid_requests() {
        let base = |extra: &str| {
            format!(
                r#"{{"container":"runtime-1","projectRoot":"/var/www/site","documentRoot":"/var/www/site/web","uid":1,"gid":1{extra}}}"#
            )
        };
        // maintenance needs an explicit on/off; the others forbid a state
        assert_eq!(
            Request::parse("maintenance", &base(""), ID, None).unwrap_err(),
            RequestError::InvalidState
        );
        assert_eq!(
            Request::parse("maintenance", &base(r#","state":"maybe""#), ID, None).unwrap_err(),
            RequestError::InvalidState
        );
        assert_eq!(
            Request::parse("cache-rebuild", &base(r#","state":"on""#), ID, None).unwrap_err(),
            RequestError::InvalidState
        );
        assert_eq!(
            Request::parse("run-anything", &base(""), ID, None).unwrap_err(),
            RequestError::InvalidState
        );
        // unknown fields (a smuggled command) are refused
        assert_eq!(
            Request::parse("cron-run", &base(r#","command":"sql:cli""#), ID, None).unwrap_err(),
            RequestError::InvalidJson
        );
        // the document root must live inside the project root
        let outside = r#"{"container":"runtime-1","projectRoot":"/var/www/site","documentRoot":"/var/www/other","uid":1,"gid":1}"#;
        assert_eq!(
            Request::parse("cron-run", outside, ID, None).unwrap_err(),
            RequestError::InvalidRoot
        );
        let traversal = r#"{"container":"runtime-1","projectRoot":"/var/www/site","documentRoot":"/var/www/site/../etc","uid":1,"gid":1}"#;
        assert_eq!(
            Request::parse("cron-run", traversal, ID, None).unwrap_err(),
            RequestError::InvalidRoot
        );
        let relative = r#"{"container":"runtime-1","projectRoot":"site","documentRoot":"site/web","uid":1,"gid":1}"#;
        assert_eq!(
            Request::parse("cron-run", relative, ID, None).unwrap_err(),
            RequestError::InvalidRoot
        );
    }

    #[test]
    fn runs_fixed_argv_as_the_site_user_and_replays() {
        let dir = tempfile::tempdir().unwrap();
        let docker = fake_docker(dir.path(), false);
        let state = managed(dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
            tools_dir: dir.path(),
            backup_root: &state,
        };
        let req = request("cache-rebuild", None, ID, Some("cache-key"));
        let first = execute(&ctx, &req, &CancellationToken::default()).unwrap();
        assert_eq!(first.action, "cacheRebuild");
        let recorded = log(dir.path());
        assert_eq!(recorded.lines().count(), 1, "{recorded}");
        assert!(recorded.contains("exec -i --user 1000:1000 -w /var/www/site runtime-1 sh -c"));
        assert!(recorded.contains("--root=/var/www/site/web --no-interaction cache:rebuild"));

        let second = execute(&ctx, &req, &CancellationToken::default()).unwrap();
        assert_eq!(first.completed_at_unix_secs, second.completed_at_unix_secs);
        assert_eq!(log(dir.path()).lines().count(), 1, "replay must not re-run");
    }

    #[test]
    fn cron_run_uses_core_cron() {
        let dir = tempfile::tempdir().unwrap();
        let docker = fake_docker(dir.path(), false);
        let state = managed(dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
            tools_dir: dir.path(),
            backup_root: &state,
        };
        let req = request("cron-run", None, ID, None);
        let result = execute(&ctx, &req, &CancellationToken::default()).unwrap();
        assert_eq!(result.action, "cronRun");
        assert!(log(dir.path()).contains("core:cron"));
    }

    #[test]
    fn maintenance_sets_rebuilds_and_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let docker = fake_docker(dir.path(), false);
        let state = managed(dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
            tools_dir: dir.path(),
            backup_root: &state,
        };
        let on = request("maintenance", Some("on"), ID, None);
        let result = execute(&ctx, &on, &CancellationToken::default()).unwrap();
        assert_eq!(result.maintenance_mode, Some(true));
        let recorded = log(dir.path());
        assert!(recorded.contains("state:set system.maintenance_mode 1 --input-format=integer"));
        assert!(recorded.contains("cache:rebuild"));
        assert!(recorded.contains("state:get system.maintenance_mode"));

        let off = request("maintenance", Some("off"), ID2, None);
        let result = execute(&ctx, &off, &CancellationToken::default()).unwrap();
        assert_eq!(result.maintenance_mode, Some(false));
    }

    #[test]
    fn a_failing_drush_fails_the_request_and_is_replayed_as_failed() {
        let dir = tempfile::tempdir().unwrap();
        let docker = fake_docker(dir.path(), true);
        let state = managed(dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
            tools_dir: dir.path(),
            backup_root: &state,
        };
        let req = request("cache-rebuild", None, ID, Some("fail-key"));
        assert!(matches!(
            execute(&ctx, &req, &CancellationToken::default()),
            Err(Error::Rejected(_))
        ));
        let retry = request("cache-rebuild", None, ID2, Some("fail-key"));
        assert!(matches!(
            execute(&ctx, &retry, &CancellationToken::default()),
            Err(Error::Replayed { .. })
        ));
        assert_eq!(log(dir.path()).lines().count(), 1, "retry must not re-run");
    }

    /// `updatedb:status` lists `pending` entries until `updatedb` ran, then
    /// none (or, with `sticky`, still the same after it).
    fn fake_updatedb_docker(directory: &std::path::Path, pending: u32, sticky: bool) -> String {
        let log = directory.join("drush.log");
        let done = directory.join("updated");
        let path = directory.join("fake-docker");
        let list = (0..pending)
            .map(|n| format!(r#""hook_{n}":{{"module":"m"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        fs::write(
            &path,
            format!(
                r#"#!/bin/sh
printf '%s\n' "$*" >> '{log}'
case "$*" in
  *"updatedb:status"*)
    if [ -e '{done}' ] && [ "{sticky}" = false ]; then echo '[]'; else echo '{{{list}}}'; fi ;;
  *" updatedb"*) touch '{done}' ;;
  *"state:set system.maintenance_mode 1"*) echo 1 > '{flag}' ;;
  *"state:set system.maintenance_mode 0"*) echo 0 > '{flag}' ;;
  *"state:get system.maintenance_mode"*) cat '{flag}' 2>/dev/null ;;
esac
exit 0
"#,
                log = log.display(),
                done = done.display(),
                flag = directory.join("flag").display(),
                sticky = sticky,
                list = list,
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    /// Like `fake_updatedb_docker` but also keeps the maintenance flag in a
    /// file (starting at `start_flag`), dumps a marker for `sql:dump`, and
    /// with `fail_update` makes `updatedb` exit 1.
    fn fake_safe_docker(
        directory: &std::path::Path,
        start_flag: u8,
        fail_update: bool,
        fail_dump: bool,
    ) -> String {
        let log = directory.join("drush.log");
        let done = directory.join("updated");
        let flag = directory.join("flag");
        fs::write(&flag, start_flag.to_string()).unwrap();
        let path = directory.join("fake-docker");
        fs::write(
            &path,
            format!(
                r#"#!/bin/sh
printf '%s\n' "$*" >> '{log}'
case "$*" in
  *"updatedb:status"*)
    if [ -e '{done}' ]; then echo '[]'; else echo '{{"hook_1":{{}}}}'; fi ;;
  *" updatedb"*) if [ "{fail_update}" = true ]; then exit 1; fi; touch '{done}' ;;
  *"sql:dump"*) if [ "{fail_dump}" = true ]; then echo partial; exit 1; fi; echo 'DUMP' ;;
  *"state:set system.maintenance_mode 1"*) echo 1 > '{flag}' ;;
  *"state:set system.maintenance_mode 0"*) echo 0 > '{flag}' ;;
  *"state:get system.maintenance_mode"*) cat '{flag}' ;;
esac
exit 0
"#,
                log = log.display(),
                done = done.display(),
                flag = flag.display(),
                fail_update = fail_update,
                fail_dump = fail_dump,
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn flag(directory: &std::path::Path) -> String {
        fs::read_to_string(directory.join("flag"))
            .unwrap()
            .trim()
            .to_owned()
    }

    #[test]
    fn update_db_backs_up_then_wraps_the_run_in_maintenance_and_restores() {
        let dir = tempfile::tempdir().unwrap();
        let backups_dir = tempfile::tempdir().unwrap();
        let docker = fake_safe_docker(dir.path(), 0, false, false);
        let state = managed(dir.path());
        let backups = managed(backups_dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
            tools_dir: dir.path(),
            backup_root: &backups,
        };
        let result = execute(
            &ctx,
            &request("update-db", None, ID, None),
            &CancellationToken::default(),
        )
        .unwrap();
        assert_eq!(result.previous_maintenance_mode, Some(false));
        let file = result.backup_file.unwrap();
        assert_eq!(file, format!("drupal-updates/{ID}/database.sql"));
        assert_eq!(
            fs::read_to_string(backups_dir.path().join(&file)).unwrap(),
            "DUMP\n"
        );
        assert_eq!(flag(dir.path()), "0", "previous mode restored");
        let recorded = log(dir.path());
        let at = |needle: &str| {
            recorded
                .find(needle)
                .unwrap_or_else(|| panic!("{needle}: {recorded}"))
        };
        assert!(at("sql:dump") < at("maintenance_mode 1"));
        assert!(at("maintenance_mode 1") < at("--no-interaction updatedb\n"));
        assert!(at("--no-interaction updatedb\n") < at("maintenance_mode 0"));
    }

    #[test]
    fn update_db_leaves_maintenance_on_when_it_was_on_before() {
        let dir = tempfile::tempdir().unwrap();
        let docker = fake_safe_docker(dir.path(), 1, false, false);
        let state = managed(dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
            tools_dir: dir.path(),
            backup_root: &state,
        };
        let result = execute(
            &ctx,
            &request("update-db", None, ID, None),
            &CancellationToken::default(),
        )
        .unwrap();
        assert_eq!(result.previous_maintenance_mode, Some(true));
        assert_eq!(flag(dir.path()), "1");
        assert!(!log(dir.path()).contains("state:set"), "never toggled");
    }

    #[test]
    fn update_db_restores_maintenance_after_a_failed_update() {
        let dir = tempfile::tempdir().unwrap();
        let docker = fake_safe_docker(dir.path(), 0, true, false);
        let state = managed(dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
            tools_dir: dir.path(),
            backup_root: &state,
        };
        let error = execute(
            &ctx,
            &request("update-db", None, ID, None),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::Rejected(_)), "{error:?}");
        assert_eq!(flag(dir.path()), "0", "restored although updatedb failed");
        assert!(log(dir.path()).contains("maintenance_mode 1"));
    }

    #[test]
    fn update_db_runs_nothing_when_the_backup_fails() {
        let dir = tempfile::tempdir().unwrap();
        let docker = fake_safe_docker(dir.path(), 0, false, true);
        let state = managed(dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
            tools_dir: dir.path(),
            backup_root: &state,
        };
        let error = execute(
            &ctx,
            &request("update-db", None, ID, None),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::BackupFailed(_)), "{error:?}");
        let recorded = log(dir.path());
        assert!(!recorded.contains("state:set"), "{recorded}");
        assert!(
            !recorded.contains("--no-interaction updatedb\n"),
            "{recorded}"
        );
        assert!(
            !dir.path()
                .join(format!("drupal-updates/{ID}/database.sql"))
                .exists(),
            "a partial dump is removed"
        );
    }

    #[test]
    fn update_db_runs_updatedb_only_when_updates_are_pending() {
        let dir = tempfile::tempdir().unwrap();
        let docker = fake_updatedb_docker(dir.path(), 3, false);
        let state = managed(dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
            tools_dir: dir.path(),
            backup_root: &state,
        };
        let result = execute(
            &ctx,
            &request("update-db", None, ID, None),
            &CancellationToken::default(),
        )
        .unwrap();
        assert_eq!(result.action, "updateDb");
        assert_eq!(result.changed, Some(true));
        assert_eq!(result.updates_pending, Some(3));
        assert_eq!(result.updates_remaining, Some(0));
        let recorded = log(dir.path());
        assert!(recorded.contains("--no-interaction updatedb:status --format=json"));
        assert!(
            recorded.contains("--no-interaction updatedb\n"),
            "{recorded}"
        );
        assert!(
            recorded.contains("sql:dump") && recorded.contains("maintenance_mode 1"),
            "{recorded}"
        );

        // nothing pending now: status only, no mutation
        let again = execute(
            &ctx,
            &request("update-db", None, ID2, None),
            &CancellationToken::default(),
        )
        .unwrap();
        assert_eq!(again.changed, Some(false));
        assert_eq!(again.updates_pending, Some(0));
        let after = log(dir.path());
        assert_eq!(
            after.matches("sql:dump").count(),
            1,
            "no second dump: {after}"
        );
        assert_eq!(after.matches("--no-interaction updatedb\n").count(), 1);
    }

    #[test]
    fn update_db_fails_when_updates_remain() {
        let dir = tempfile::tempdir().unwrap();
        let docker = fake_updatedb_docker(dir.path(), 2, true);
        let state = managed(dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
            tools_dir: dir.path(),
            backup_root: &state,
        };
        let error = execute(
            &ctx,
            &request("update-db", None, ID, None),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::UpdatesRemain(2)));
        assert_eq!(error.protocol().0, ErrorCode::SubprocessFailed);
    }

    /// Keeps the interval in a file: `config:get` prints it, `config:set`
    /// stores it. `missing` makes `config:get` fail like a site without the
    /// automated_cron module.
    fn fake_cron_docker(directory: &std::path::Path, start: u32, missing: bool) -> String {
        let log = directory.join("drush.log");
        let value = directory.join("interval");
        fs::write(&value, start.to_string()).unwrap();
        let path = directory.join("fake-docker");
        fs::write(
            &path,
            format!(
                r#"#!/bin/sh
printf '%s\n' "$*" >> '{log}'
case "$*" in
  *"config:get automated_cron.settings interval --format=json"*)
    if [ "{missing}" = true ]; then exit 1; fi; printf '%s' '{{"automated_cron.settings:interval":'; cat '{value}'; printf '%s\n' '}}' ;;
  *"config:set"*"automated_cron.settings interval "*) printf '%s' "$(echo "$*" | sed 's/.*interval //')" > '{value}' ;;
esac
exit 0
"#,
                log = log.display(),
                value = value.display(),
                missing = missing,
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn cron_request(interval: Option<u32>, id: &str) -> Request {
        let extra = interval.map_or(String::new(), |n| format!(r#","interval":{n}"#));
        Request::parse(
            "automated-cron",
            &format!(
                r#"{{"container":"runtime-1","projectRoot":"/var/www/site","documentRoot":"/var/www/site/web","uid":1000,"gid":1000{extra}}}"#
            ),
            id,
            None,
        )
        .unwrap()
    }

    #[test]
    fn automated_cron_switches_off_is_idempotent_and_restores() {
        let dir = tempfile::tempdir().unwrap();
        let docker = fake_cron_docker(dir.path(), 10800, false);
        let state = managed(dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
            tools_dir: dir.path(),
            backup_root: &state,
        };
        let cancel = CancellationToken::default();
        let off = execute(&ctx, &cron_request(None, ID), &cancel).unwrap();
        assert_eq!(off.action, "automatedCron");
        assert_eq!(
            (off.changed, off.previous_interval, off.interval),
            (Some(true), Some(10800), Some(0))
        );
        let recorded = log(dir.path());
        assert!(recorded.contains(
            "config:set --no-interaction --input-format=yaml automated_cron.settings interval 0"
        ));
        assert_eq!(recorded.lines().count(), 3, "get, set, get");

        let again = execute(&ctx, &cron_request(Some(0), ID2), &cancel).unwrap();
        assert_eq!(
            (again.changed, again.previous_interval, again.interval),
            (Some(false), Some(0), Some(0))
        );
        assert_eq!(log(dir.path()).lines().count(), 4, "repeat only reads");

        let back = execute(
            &ctx,
            &cron_request(Some(10800), "123e4567-e89b-12d3-a456-426614174002"),
            &cancel,
        )
        .unwrap();
        assert_eq!(
            (back.changed, back.previous_interval, back.interval),
            (Some(true), Some(0), Some(10800))
        );
    }

    #[test]
    fn automated_cron_refuses_when_drupal_cannot_report_the_interval() {
        let dir = tempfile::tempdir().unwrap();
        let docker = fake_cron_docker(dir.path(), 10800, true);
        let state = managed(dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
            tools_dir: dir.path(),
            backup_root: &state,
        };
        assert!(matches!(
            execute(&ctx, &cron_request(None, ID), &CancellationToken::default()),
            Err(Error::Rejected(_))
        ));
        assert!(
            !log(dir.path()).contains("config:set"),
            "never writes blind"
        );
    }

    #[test]
    fn automated_cron_request_validation_and_interval_parsing() {
        let base = |extra: &str| {
            format!(
                r#"{{"container":"runtime-1","projectRoot":"/var/www/site","documentRoot":"/var/www/site/web","uid":1,"gid":1{extra}}}"#
            )
        };
        assert_eq!(
            Request::parse("automated-cron", &base(r#","interval":99999999"#), ID, None)
                .unwrap_err(),
            RequestError::InvalidInterval
        );
        assert_eq!(
            Request::parse("automated-cron", &base(r#","state":"on""#), ID, None).unwrap_err(),
            RequestError::InvalidState
        );
        assert_eq!(
            Request::parse("cron-run", &base(r#","interval":0"#), ID, None).unwrap_err(),
            RequestError::InvalidInterval
        );
        assert_eq!(cron_interval(b"10800\n"), Some(10800));
        assert_eq!(cron_interval(b"0"), Some(0));
        assert_eq!(cron_interval(b"null"), None);
        assert_eq!(cron_interval(b"\"abc\""), None);
        assert_eq!(cron_interval(b"-1"), None);
    }

    #[test]
    fn cron_interval_accepts_only_the_requested_nonnegative_integer() {
        for bytes in [
            br#"{"automated_cron.settings:interval":3600}"#.as_slice(),
            b"3600\n",
        ] {
            assert_eq!(cron_interval(bytes), Some(3600));
        }
        assert_eq!(
            cron_interval(br#"{"automated_cron.settings:interval":0}"#),
            Some(0)
        );
        for bytes in [
            br#"{"interval":0}"#.as_slice(),
            br#"{"automated_cron.settings:interval":0,"other":0}"#,
            br#"{"automated_cron.settings:interval":null}"#,
            br#"{"automated_cron.settings:interval":"0"}"#,
            br#"{"automated_cron.settings:interval":-1}"#,
            br#"{"automated_cron.settings:interval":1.5}"#,
            b"4294967296",
            b"[]",
            b"{}",
            b"warning\n0",
        ] {
            assert_eq!(cron_interval(bytes), None, "{bytes:?}");
        }
    }

    #[test]
    fn pending_updates_counts_entries_and_refuses_garbage() {
        assert_eq!(pending_updates(b""), Some(0));
        assert_eq!(pending_updates(b"  []\n"), Some(0));
        assert_eq!(pending_updates(b"{}"), Some(0));
        assert_eq!(pending_updates(br#"{"a":{},"b":{}}"#), Some(2));
        assert_eq!(pending_updates(br#"[{"a":1}]"#), Some(1));
        assert_eq!(pending_updates(b"No database updates required"), None);
        assert_eq!(pending_updates(b"7"), None);
    }

    /// A stand-in for the container: `test -x ./vendor/bin/drush` succeeds
    /// once a Composer run created the marker; `composer.json` presence is
    /// controlled by `has_composer_json`.
    fn fake_composer_docker(directory: &std::path::Path, has_composer_json: bool) -> String {
        let log = directory.join("drush.log");
        let marker = directory.join("drush-installed");
        let path = directory.join("fake-docker");
        fs::write(
            &path,
            format!(
                r#"#!/bin/sh
printf '%s\n' "$*" >> '{log}'
case "$*" in
  *"test -x ./vendor/bin/drush"*) [ -e '{marker}' ]; exit $? ;;
  *"test -f ./composer.json"*) exit {json} ;;
  *"composer.phar require drush/drush"*) touch '{marker}'; exit 0 ;;
esac
exit 0
"#,
                log = log.display(),
                marker = marker.display(),
                json = if has_composer_json { 0 } else { 1 },
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn with_composer(dir: &std::path::Path) {
        let current = dir.join("tools/composer/current");
        fs::create_dir_all(&current).unwrap();
        fs::write(current.join("composer.phar"), b"x").unwrap();
    }

    #[test]
    fn install_drush_requires_with_the_managed_composer_then_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        with_composer(dir.path());
        let docker = fake_composer_docker(dir.path(), true);
        let state = managed(dir.path());
        let tools = dir.path().join("tools");
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
            tools_dir: &tools,
            backup_root: &state,
        };
        let first = execute(
            &ctx,
            &request("install-drush", None, ID, None),
            &CancellationToken::default(),
        )
        .unwrap();
        assert_eq!(first.action, "installDrush");
        assert_eq!(first.changed, Some(true));
        let recorded = log(dir.path());
        assert!(recorded.contains(
            "-e COMPOSER_HOME=/tmp/wcp-composer -e COMPOSER_CACHE_DIR=/tmp/wcp-composer/cache"
        ));
        assert!(recorded.contains(
            "runtime-1 php /opt/wcp-tools/composer/current/composer.phar require drush/drush"
        ));
        assert!(recorded.contains("--no-scripts"));
        assert!(recorded.contains("--version"), "verifies Drush runs");

        let second = execute(
            &ctx,
            &request("install-drush", None, ID2, None),
            &CancellationToken::default(),
        )
        .unwrap();
        assert_eq!(second.changed, Some(false));
        assert_eq!(recorded.matches("require drush/drush").count(), 1);
        assert_eq!(log(dir.path()).matches("require drush/drush").count(), 1);
    }

    /// Like `fake_composer_docker`, but the Composer run exits with `code`.
    fn failing_composer_docker(directory: &std::path::Path, code: i32) -> String {
        let path = directory.join("fake-docker-failing");
        fs::write(
            &path,
            format!(
                r#"#!/bin/sh
case "$*" in
  *"test -x ./vendor/bin/drush"*) exit 1 ;;
  *"test -f ./composer.json"*) exit 0 ;;
  *"composer.phar require drush/drush"*) echo 'SECRET-TOKEN-IN-STDERR' >&2; exit {code} ;;
esac
exit 0
"#
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn a_failing_composer_step_is_reported_as_composer_with_its_exit_code_and_no_output() {
        let dir = tempfile::tempdir().unwrap();
        with_composer(dir.path());
        let docker = failing_composer_docker(dir.path(), 3);
        let state = managed(dir.path());
        let tools = dir.path().join("tools");
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
            tools_dir: &tools,
            backup_root: &state,
        };
        let error = execute(
            &ctx,
            &request("install-drush", None, ID, None),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::ComposerFailed(_)), "{error:?}");
        let (code, message) = error.protocol();
        assert_eq!(code, ErrorCode::SubprocessFailed);
        assert!(message.starts_with("Composer could not add drush/drush"));
        assert!(message.contains("(exit code 3)"), "{message}");
        assert!(
            !message.contains("SECRET"),
            "what the child printed never reaches the message"
        );
    }

    #[test]
    fn subprocess_outcomes_read_plainly() {
        let base = SubprocessDiagnostics {
            program: "docker".into(),
            exit_code: Some(2),
            timed_out: false,
            cancelled: false,
            stdout_truncated: false,
            stderr_truncated: false,
        };
        assert_eq!(outcome_suffix(&base), " (exit code 2)");
        let timed_out = SubprocessDiagnostics {
            exit_code: None,
            timed_out: true,
            ..base
        };
        assert_eq!(outcome_suffix(&timed_out), " (timed out)");
        assert_eq!(subprocess_code(&timed_out), ErrorCode::Timeout);
        let (_, message) = Error::DrushDoesNotRun(timed_out).protocol();
        assert_eq!(
            message,
            "Drush was added to the project but does not run (timed out)"
        );
    }

    #[test]
    fn install_drush_refuses_without_composer_or_a_composer_project() {
        let dir = tempfile::tempdir().unwrap();
        let state = managed(dir.path());
        let tools = dir.path().join("tools");
        let ctx = Context {
            engine_state: &state,
            docker_program: &fake_composer_docker(dir.path(), true),
            tools_dir: &tools,
            backup_root: &state,
        };
        assert!(matches!(
            execute(
                &ctx,
                &request("install-drush", None, ID, None),
                &CancellationToken::default()
            ),
            Err(Error::ComposerMissing)
        ));
        let dir = tempfile::tempdir().unwrap();
        with_composer(dir.path());
        let state = managed(dir.path());
        let tools = dir.path().join("tools");
        let ctx = Context {
            engine_state: &state,
            docker_program: &fake_composer_docker(dir.path(), false),
            tools_dir: &tools,
            backup_root: &state,
        };
        assert!(matches!(
            execute(
                &ctx,
                &request("install-drush", None, ID, None),
                &CancellationToken::default()
            ),
            Err(Error::NotAComposerProject)
        ));
    }

    /// Real-host check against a live Drupal container; run manually with
    /// `WCP_DRUPAL_E2E_CONTAINER=<name> WCP_DRUPAL_E2E_PROJECT=<project root>
    /// WCP_DRUPAL_E2E_DOCROOT=<public root> WCP_DRUPAL_E2E_UID=<uid>
    /// cargo test -- --ignored drupal_action_e2e`.
    #[test]
    #[ignore = "needs a live Drupal container"]
    fn drupal_action_e2e() {
        let (Ok(container), Ok(project), Ok(docroot), Ok(uid)) = (
            std::env::var("WCP_DRUPAL_E2E_CONTAINER"),
            std::env::var("WCP_DRUPAL_E2E_PROJECT"),
            std::env::var("WCP_DRUPAL_E2E_DOCROOT"),
            std::env::var("WCP_DRUPAL_E2E_UID"),
        ) else {
            return;
        };
        let docker = std::env::var("WCP_DRUPAL_E2E_DOCKER").unwrap_or("docker".into());
        let dir = tempfile::tempdir().unwrap();
        let state = managed(dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
            tools_dir: dir.path(),
            backup_root: &state,
        };
        let make = |kind: &str, st: Option<&str>, id: &str| {
            let st = st.map_or(String::new(), |s| format!(r#","state":"{s}""#));
            Request::parse(
                kind,
                &format!(
                    r#"{{"container":"{container}","projectRoot":"{project}","documentRoot":"{docroot}","uid":{uid},"gid":{uid}{st}}}"#
                ),
                id,
                None,
            )
            .unwrap()
        };
        let cancel = CancellationToken::default();
        println!(
            "{:?}",
            execute(&ctx, &make("cache-rebuild", None, ID), &cancel).unwrap()
        );
        println!(
            "{:?}",
            execute(&ctx, &make("cron-run", None, ID2), &cancel).unwrap()
        );
        let on = execute(
            &ctx,
            &make(
                "maintenance",
                Some("on"),
                "123e4567-e89b-12d3-a456-426614174002",
            ),
            &cancel,
        )
        .unwrap();
        assert_eq!(on.maintenance_mode, Some(true));
        let off = execute(
            &ctx,
            &make(
                "maintenance",
                Some("off"),
                "123e4567-e89b-12d3-a456-426614174003",
            ),
            &cancel,
        )
        .unwrap();
        assert_eq!(off.maintenance_mode, Some(false));
    }
}
