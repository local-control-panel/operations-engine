//! `cms.safeMode`: "disable all extensions" with a saved list and an exact
//! way back, for the CMSs whose extensions can be switched through their own
//! console.
//!
//! * `wordpress`: `wp plugin deactivate --all`. The active plugins are read
//!   first and written to a saved list in the engine's own state directory
//!   (never on the customer site) *before* anything is deactivated. `off`
//!   re-activates exactly that list and removes it only when every saved
//!   plugin reads back as active. A multisite install is refused (network
//!   activation is a different state that this list does not describe).
//! * `drupal`: maintenance mode on plus the list of enabled modules for the
//!   record. Nothing is uninstalled or disabled. `off` puts maintenance mode
//!   back to the value it had before (a site that was already in maintenance
//!   mode stays there).
//! * `joomla`: Joomla's console cannot enable or disable extensions, so the
//!   engine boots Joomla's own framework in the site's runtime container
//!   (inline `php -r`, as `site.adminUsers` does; nothing is written on the
//!   site) and uses Joomla's database API: the credentials and the table
//!   prefix never leave the site's own configuration and are never read by
//!   the engine. Fixed statements only, over `#__extensions` rows with
//!   `type = 'plugin'`, `protected = 0` and `locked = 0` that Joomla's
//!   `ExtensionHelper::checkIfCoreExtension` does not list as core (third-party
//!   plugins only; core and protected extensions are never touched). The enabled
//!   ones are read first and written, by id, to the saved list; `on` sets
//!   `enabled = 0` for exactly those ids in one transaction, `off` sets
//!   `enabled = 1` for exactly the saved ids that read back as disabled and
//!   removes the list only when every saved plugin reads back as enabled.
//!
//! `status` is a read of the saved list. The argv is fixed per kind; commands
//! run as the site user inside the site's runtime container. Names that come
//! back from the CMS are validated before they are passed on as arguments.
//! When a change fails half way, the engine puts back what it changed (and
//! keeps the saved list if that is not possible). Lock, idempotency,
//! transaction and audit as for the other CMS actions.

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
    collections::BTreeSet,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const OPERATION: &str = "cms.safeMode";

const READ_TIMEOUT: Duration = Duration::from_secs(60);
const RUN_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const MAX_OUTPUT: usize = 256 * 1024;
const MAX_EXTENSIONS: usize = 2000;
const SAVED: &str = "saved.json";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    WordPress,
    Drupal,
    Joomla,
}

impl Kind {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "wordpress" => Some(Self::WordPress),
            "drupal" => Some(Self::Drupal),
            "joomla" => Some(Self::Joomla),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::WordPress => "wordpress",
            Self::Drupal => "drupal",
            Self::Joomla => "joomla",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    On,
    Off,
    Status,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    kind: String,
    /// `"on"`, `"off"` or `"status"`.
    state: String,
    container: String,
    project_root: String,
    /// Drupal only: the directory Drush is given as `--root`.
    document_root: Option<String>,
    uid: u32,
    gid: u32,
}

#[derive(Debug)]
pub struct Request {
    pub kind: Kind,
    mode: Mode,
    container: ContainerName,
    project_root: PathBuf,
    document_root: Option<PathBuf>,
    uid: u32,
    gid: u32,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    InvalidKind,
    InvalidState,
    InvalidRoot,
    InvalidContainer,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

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
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        let kind = Kind::parse(&plan.kind).ok_or(RequestError::InvalidKind)?;
        let mode = match plan.state.as_str() {
            "on" => Mode::On,
            "off" => Mode::Off,
            "status" => Mode::Status,
            _ => return Err(RequestError::InvalidState),
        };
        let project_root =
            plain_absolute_path(&plan.project_root).ok_or(RequestError::InvalidRoot)?;
        let document_root = match (kind, plan.document_root.as_deref()) {
            (Kind::Drupal, Some(value)) => {
                let path = plain_absolute_path(value).ok_or(RequestError::InvalidRoot)?;
                if !path.starts_with(&project_root) {
                    return Err(RequestError::InvalidRoot);
                }
                Some(path)
            }
            (Kind::WordPress | Kind::Joomla, None) => None,
            _ => return Err(RequestError::InvalidRoot),
        };
        Ok(Self {
            kind,
            mode,
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

/// What the engine keeps between `on` and `off`, in its own state directory.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Saved {
    kind: String,
    /// WordPress: the active plugins (slug as WP-CLI names them). Drupal:
    /// the enabled modules, for the record only.
    extensions: Vec<String>,
    /// Joomla: the `extension_id` of each saved plugin (same order as
    /// `extensions`). The ids are what `off` restores.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    ids: Vec<u64>,
    /// Drupal: maintenance mode before safe mode was switched on.
    previous_maintenance: Option<bool>,
    saved_at_unix_secs: u64,
}

/// The part of the answer that may be stored and replayed.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SafeModeResult {
    pub kind: String,
    /// Whether the saved list exists, i.e. the site is in safe mode.
    pub safe_mode: bool,
    /// `false` when nothing had to be changed.
    pub changed: bool,
    /// The saved list (what `on` disabled / listed, what `off` restored).
    pub extensions: Vec<String>,
    /// Drupal: maintenance mode as read back from the site.
    pub maintenance_mode: Option<bool>,
    pub saved_at_unix_secs: Option<u64>,
    pub completed_at_unix_secs: u64,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub docker_program: &'a str,
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
    /// Multisite (or another layout) this list cannot describe.
    Unsupported,
    /// A list or flag the CMS printed could not be read.
    Unreadable,
    /// The site did not report the state that was just set.
    StateMismatch,
    /// Safe mode is on, but plugins were activated since.
    Diverged,
    /// `off` could not bring every saved extension back; the list is kept.
    Incomplete(usize),
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
            Self::Run(error) => (
                process::spawn_error_code(error),
                "could not run the safe mode command".into(),
            ),
            Self::Unsupported => (
                ErrorCode::InvalidInput,
                "safe mode is not supported for this installation (multisite)".into(),
            ),
            Self::Unreadable => (
                ErrorCode::SubprocessFailed,
                "the site did not report its extensions in a readable form".into(),
            ),
            Self::StateMismatch => (
                ErrorCode::SubprocessFailed,
                "the site did not report the requested state; the previous state was put back"
                    .into(),
            ),
            Self::Diverged => (
                ErrorCode::Conflict,
                "safe mode is on but extensions were activated since; restore first".into(),
            ),
            Self::Incomplete(count) => (
                ErrorCode::SubprocessFailed,
                format!(
                    "{count} saved extension(s) could not be re-activated; the saved list is kept, retry the restore"
                ),
            ),
            Self::Rejected(diagnostics) => {
                let code = if diagnostics.timed_out {
                    ErrorCode::Timeout
                } else if diagnostics.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::SubprocessFailed
                };
                let suffix = if diagnostics.timed_out {
                    " (timed out)".to_owned()
                } else if diagnostics.cancelled {
                    " (cancelled)".to_owned()
                } else if let Some(exit) = diagnostics.exit_code {
                    format!(" (exit code {exit})")
                } else {
                    String::new()
                };
                (
                    code,
                    format!("the safe mode command reported an error{suffix}"),
                )
            }
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) => {
                (ErrorCode::Internal, "internal safe mode error".into())
            }
        }
    }
}

fn exited_ok(output: &process::ProcessOutput) -> bool {
    matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    )
}

/// Runs one fixed command in the container as the site user. The output is
/// returned whatever the exit status; the caller decides.
fn exec(
    ctx: &Context<'_>,
    req: &Request,
    inner: &[String],
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
        req.container.as_str().to_owned(),
    ];
    args.extend(inner.iter().cloned());
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

fn checked(
    ctx: &Context<'_>,
    output: process::ProcessOutput,
) -> Result<process::ProcessOutput, Error> {
    if exited_ok(&output) {
        Ok(output)
    } else {
        Err(Error::Rejected(SubprocessDiagnostics::from_output(
            ctx.docker_program,
            &output,
        )))
    }
}

/// A plugin slug or module machine name; it becomes one argv element, so
/// anything that could be read as an option or a path escape is refused.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 200
        && !name.starts_with(['-', '.', '/'])
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---- WordPress ----------------------------------------------------------

fn wp(req: &Request, tail: &[&str]) -> Vec<String> {
    // `--skip-plugins/--skip-themes`: a plugin that is itself the problem
    // must not be able to stop the command that disables it.
    let mut args = vec![
        "wp".to_owned(),
        format!("--path={}", req.project_root.display()),
        "--allow-root".to_owned(),
        "--skip-plugins".to_owned(),
        "--skip-themes".to_owned(),
    ];
    args.extend(tail.iter().map(|arg| (*arg).to_owned()));
    args
}

fn wp_active(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<Vec<String>, Error> {
    let output = checked(
        ctx,
        exec(
            ctx,
            req,
            &wp(
                req,
                &[
                    "plugin",
                    "list",
                    "--status=active",
                    "--field=name",
                    "--format=json",
                ],
            ),
            READ_TIMEOUT,
            cancel,
        )?,
    )?;
    let mut names: Vec<String> =
        serde_json::from_slice(&output.stdout.bytes).map_err(|_| Error::Unreadable)?;
    if names.len() > MAX_EXTENSIONS || !names.iter().all(|name| valid_name(name)) {
        return Err(Error::Unreadable);
    }
    names.sort();
    names.dedup();
    Ok(names)
}

fn wp_activate(
    ctx: &Context<'_>,
    req: &Request,
    names: &[String],
    cancel: &CancellationToken,
) -> Result<(), Error> {
    if names.is_empty() {
        return Ok(());
    }
    let mut tail: Vec<&str> = vec!["plugin", "activate"];
    tail.extend(names.iter().map(String::as_str));
    // WP-CLI carries on past a plugin that fails to activate and exits
    // non-zero at the end; the read-back decides, not the exit status.
    exec(ctx, req, &wp(req, &tail), RUN_TIMEOUT, cancel)?;
    Ok(())
}

fn missing(saved: &[String], current: &[String]) -> Vec<String> {
    let have: BTreeSet<&String> = current.iter().collect();
    saved
        .iter()
        .filter(|name| !have.contains(name))
        .cloned()
        .collect()
}

// ---- Drupal -------------------------------------------------------------

fn drush(
    ctx: &Context<'_>,
    req: &Request,
    drush_args: &[&str],
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<Vec<u8>, Error> {
    let root = req.document_root.as_ref().ok_or(Error::Unreadable)?;
    let mut inner: Vec<String> = vec![
        "sh".into(),
        "-c".into(),
        "if [ -x ./vendor/bin/drush ]; then exec ./vendor/bin/drush \"$@\"; else exec drush \"$@\"; fi"
            .into(),
        "drush".into(),
        format!("--root={}", root.display()),
        "--no-interaction".into(),
    ];
    inner.extend(drush_args.iter().map(|arg| (*arg).to_owned()));
    Ok(checked(ctx, exec(ctx, req, &inner, timeout, cancel)?)?
        .stdout
        .bytes)
}

fn drupal_maintenance(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<bool, Error> {
    let bytes = drush(
        ctx,
        req,
        &["state:get", "system.maintenance_mode"],
        READ_TIMEOUT,
        cancel,
    )?;
    match String::from_utf8_lossy(&bytes).trim() {
        "1" | "true" | "TRUE" => Ok(true),
        "0" | "false" | "FALSE" | "" => Ok(false),
        _ => Err(Error::Unreadable),
    }
}

fn drupal_set_maintenance(
    ctx: &Context<'_>,
    req: &Request,
    enabled: bool,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    drush(
        ctx,
        req,
        &[
            "state:set",
            "system.maintenance_mode",
            if enabled { "1" } else { "0" },
            "--input-format=integer",
        ],
        READ_TIMEOUT,
        cancel,
    )?;
    drush(ctx, req, &["cache:rebuild"], RUN_TIMEOUT, cancel)?;
    if drupal_maintenance(ctx, req, cancel)? != enabled {
        return Err(Error::StateMismatch);
    }
    Ok(())
}

fn drupal_modules(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<Vec<String>, Error> {
    let bytes = drush(
        ctx,
        req,
        &[
            "pm:list",
            "--status=enabled",
            "--type=module",
            "--format=json",
        ],
        READ_TIMEOUT,
        cancel,
    )?;
    let map: std::collections::BTreeMap<String, serde_json::Value> =
        serde_json::from_slice(&bytes).map_err(|_| Error::Unreadable)?;
    let names: Vec<String> = map.into_keys().collect();
    if names.len() > MAX_EXTENSIONS || !names.iter().all(|name| valid_name(name)) {
        return Err(Error::Unreadable);
    }
    Ok(names)
}

// ---- Joomla -------------------------------------------------------------

/// Fixed PHP text, run with `php -r` as the site user. The plan arrives on
/// stdin as JSON (`root`, `op`, integer `ids`); nothing from it becomes SQL
/// except the validated integers. Joomla's own database layer supplies the
/// connection and the table prefix; no credential is read or printed. Only
/// non-core (`locked = 0`), non-protected plugin rows are ever selected or
/// updated. The last output line is `{"ok":true,...}` or `{"ok":false,"error":...}`;
/// exception messages are never printed.
const JOOMLA_PHP: &str = r#"$say = function ($v) { echo "\n" . json_encode($v) . "\n"; };
try {
$plan = json_decode(stream_get_contents(STDIN), true);
if (!is_array($plan) || !isset($plan['root'], $plan['op']) || !is_string($plan['root']) || !in_array($plan['op'], array('list', 'disable', 'enable'), true)) { $say(array('ok' => false, 'error' => 'badPlan')); return; }
$ids = array();
foreach ((array) (isset($plan['ids']) ? $plan['ids'] : array()) as $i) { if (!is_int($i) || $i < 1) { $say(array('ok' => false, 'error' => 'badPlan')); return; } $ids[] = $i; }
define('_JEXEC', 1); define('JPATH_BASE', $plan['root']);
$_SERVER['HTTP_HOST'] = 'localhost';
if (!is_file(JPATH_BASE . '/includes/framework.php') || !is_file(JPATH_BASE . '/configuration.php')) { $say(array('ok' => false, 'error' => 'notJoomla')); return; }
require_once JPATH_BASE . '/includes/defines.php';
require_once JPATH_BASE . '/includes/framework.php';
$db = \Joomla\CMS\Factory::getContainer()->get(\Joomla\Database\DatabaseInterface::class);
$t = $db->quoteName('#__extensions');
$guard = $db->quoteName('type') . ' = ' . $db->quote('plugin') . ' AND ' . $db->quoteName('protected') . ' = 0 AND ' . $db->quoteName('locked') . ' = 0';
// Joomla's own list of core extensions decides; without it nothing is touched.
if (!class_exists('\Joomla\CMS\Extension\ExtensionHelper') || !method_exists('\Joomla\CMS\Extension\ExtensionHelper', 'checkIfCoreExtension')) { $say(array('ok' => false, 'error' => 'noCoreList')); return; }
$rows = function ($extra) use ($db, $t, $guard) {
  $q = $db->getQuery(true)->select($db->quoteName(array('extension_id', 'folder', 'element', 'client_id')))->from($t)->where($guard)->where($extra)->order($db->quoteName('extension_id'))->setLimit(2001);
  $o = array();
  foreach ($db->setQuery($q)->loadAssocList() as $r) {
    if (\Joomla\CMS\Extension\ExtensionHelper::checkIfCoreExtension('plugin', (string) $r['element'], (int) $r['client_id'], (string) $r['folder'])) { continue; }
    $o[(int) $r['extension_id']] = $r['folder'] . '/' . $r['element'];
  }
  return $o;
};
if ($plan['op'] === 'list') {
  $o = array();
  foreach ($rows($db->quoteName('enabled') . ' = 1') as $id => $name) { $o[] = array('id' => $id, 'name' => $name); }
  $say(array('ok' => true, 'plugins' => $o));
  return;
}
if (!$ids) { $say(array('ok' => true, 'affected' => 0)); return; }
$to = $plan['op'] === 'enable' ? 1 : 0;
$eligible = array_keys($rows($db->quoteName('enabled') . ' = ' . (1 - $to) . ' AND ' . $db->quoteName('extension_id') . ' IN (' . implode(',', $ids) . ')'));
if (!$eligible) { $say(array('ok' => true, 'affected' => 0)); return; }
$q = $db->getQuery(true)->update($t)->set($db->quoteName('enabled') . ' = ' . $to)->where($guard)->where($db->quoteName('enabled') . ' = ' . (1 - $to))->where($db->quoteName('extension_id') . ' IN (' . implode(',', $eligible) . ')');
$db->setQuery($q)->execute();
$n = (int) $db->getAffectedRows();
try {
  foreach (array('site', 'administrator') as $app) {
    \Joomla\CMS\Factory::getContainer()->get(\Joomla\CMS\Cache\CacheControllerFactoryInterface::class)->createCacheController('callback', array('defaultgroup' => 'com_plugins', 'application' => $app))->clean();
  }
} catch (\Throwable $e) { }
$say(array('ok' => true, 'affected' => $n));
} catch (\Throwable $e) { $say(array('ok' => false, 'error' => 'failed')); }"#;

#[derive(Debug, Deserialize)]
struct JoomlaReply {
    ok: bool,
    #[serde(default)]
    plugins: Vec<JoomlaPlugin>,
}

#[derive(Debug, Deserialize)]
struct JoomlaPlugin {
    id: u64,
    name: String,
}

fn joomla_call(
    ctx: &Context<'_>,
    req: &Request,
    op: &str,
    ids: &[u64],
    cancel: &CancellationToken,
) -> Result<JoomlaReply, Error> {
    let plan = serde_json::json!({
        "root": req.project_root.display().to_string(),
        "op": op,
        "ids": ids,
    });
    let args: Vec<String> = vec![
        "exec".into(),
        "-i".into(),
        "--user".into(),
        format!("{}:{}", req.uid, req.gid),
        req.container.as_str().to_owned(),
        "php".into(),
        "-r".into(),
        JOOMLA_PHP.into(),
    ];
    let output = process::run_with_stdin_bytes(
        &ProcessRequest::new(ctx.docker_program).args(args),
        plan.to_string().as_bytes(),
        &ProcessLimits {
            timeout: if op == "list" {
                READ_TIMEOUT
            } else {
                RUN_TIMEOUT
            },
            max_stdout_bytes: MAX_OUTPUT,
            max_stderr_bytes: MAX_OUTPUT,
        },
        cancel,
    )
    .map_err(Error::Run)?;
    let output = checked(ctx, output)?;
    if output.stdout.truncated {
        return Err(Error::Unreadable);
    }
    let text = String::from_utf8_lossy(&output.stdout.bytes);
    let line = text
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .ok_or(Error::Unreadable)?;
    let reply: JoomlaReply = serde_json::from_str(line).map_err(|_| Error::Unreadable)?;
    if reply.ok {
        Ok(reply)
    } else {
        Err(Error::Unreadable)
    }
}

/// The enabled, non-core, non-protected plugins: (ids, names), sorted by id.
fn joomla_enabled(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<(Vec<u64>, Vec<String>), Error> {
    let mut plugins = joomla_call(ctx, req, "list", &[], cancel)?.plugins;
    plugins.sort_by_key(|plugin| plugin.id);
    plugins.dedup_by_key(|plugin| plugin.id);
    if plugins.len() > MAX_EXTENSIONS || !plugins.iter().all(|plugin| valid_name(&plugin.name)) {
        return Err(Error::Unreadable);
    }
    Ok(plugins
        .into_iter()
        .map(|plugin| (plugin.id, plugin.name))
        .unzip())
}

fn joomla_set(
    ctx: &Context<'_>,
    req: &Request,
    enable: bool,
    ids: &[u64],
    cancel: &CancellationToken,
) -> Result<(), Error> {
    joomla_call(
        ctx,
        req,
        if enable { "enable" } else { "disable" },
        ids,
        cancel,
    )
    .map(|_| ())
}

fn missing_ids(saved: &[u64], current: &[u64]) -> Vec<u64> {
    let have: BTreeSet<&u64> = current.iter().collect();
    saved
        .iter()
        .filter(|id| !have.contains(id))
        .copied()
        .collect()
}

fn run_joomla(
    ctx: &Context<'_>,
    scope: &ManagedRoot,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<Ran, Error> {
    let saved = load_saved(scope, req.kind)?;
    match (req.mode, saved) {
        (Mode::Status, Some(saved)) => Ok(ran_from(&saved, true, false, None)),
        (Mode::Status, None) | (Mode::Off, None) => Ok(Ran {
            safe_mode: false,
            changed: false,
            extensions: Vec::new(),
            maintenance_mode: None,
            saved_at: None,
        }),
        (Mode::On, Some(saved)) => {
            // Already on. Anything enabled since is reported, not folded in.
            if !joomla_enabled(ctx, req, cancel)?.0.is_empty() {
                return Err(Error::Diverged);
            }
            Ok(ran_from(&saved, true, false, None))
        }
        (Mode::On, None) => {
            let (ids, names) = joomla_enabled(ctx, req, cancel)?;
            let saved = Saved {
                kind: req.kind.name().into(),
                extensions: names,
                ids: ids.clone(),
                previous_maintenance: None,
                saved_at_unix_secs: unix_now(),
            };
            // The list is durable before the first plugin is touched.
            store_saved(scope, &saved)?;
            let disabled = (|| -> Result<(), Error> {
                joomla_set(ctx, req, false, &ids, cancel)?;
                if joomla_enabled(ctx, req, cancel)?.0.is_empty() {
                    Ok(())
                } else {
                    Err(Error::StateMismatch)
                }
            })();
            if let Err(error) = disabled {
                // Put the previous state back; keep the list if that fails.
                let restored = joomla_set(ctx, req, true, &ids, cancel)
                    .and_then(|()| joomla_enabled(ctx, req, cancel))
                    .is_ok_and(|(now, _)| missing_ids(&ids, &now).is_empty());
                if restored {
                    let _ = drop_saved(scope);
                }
                return Err(error);
            }
            Ok(ran_from(&saved, true, true, None))
        }
        (Mode::Off, Some(saved)) => {
            if saved.ids.len() != saved.extensions.len() {
                return Err(Error::Unreadable);
            }
            let (now, _) = joomla_enabled(ctx, req, cancel)?;
            joomla_set(ctx, req, true, &missing_ids(&saved.ids, &now), cancel)?;
            let (after, _) = joomla_enabled(ctx, req, cancel)?;
            let left = missing_ids(&saved.ids, &after);
            if !left.is_empty() {
                return Err(Error::Incomplete(left.len()));
            }
            drop_saved(scope)?;
            Ok(ran_from(&saved, false, true, None))
        }
    }
}

// ---- shared -------------------------------------------------------------

struct Ran {
    safe_mode: bool,
    changed: bool,
    extensions: Vec<String>,
    maintenance_mode: Option<bool>,
    saved_at: Option<u64>,
}

fn saved_path() -> SiteRelativePath {
    SiteRelativePath::parse(SAVED).unwrap()
}

fn load_saved(scope: &ManagedRoot, kind: Kind) -> Result<Option<Saved>, Error> {
    let path = saved_path();
    if !scope.exists(&path) {
        return Ok(None);
    }
    let text = scope.read_to_string(&path).map_err(Error::Io)?;
    let saved: Saved = serde_json::from_str(&text).map_err(|_| Error::Unreadable)?;
    if saved.kind != kind.name() {
        return Err(Error::Unreadable);
    }
    Ok(Some(saved))
}

fn store_saved(scope: &ManagedRoot, saved: &Saved) -> Result<(), Error> {
    let bytes = serde_json::to_vec(saved).map_err(|e| Error::Io(std::io::Error::other(e)))?;
    scope
        .write_atomic_private(&saved_path(), &bytes)
        .map_err(Error::Io)
}

fn drop_saved(scope: &ManagedRoot) -> Result<(), Error> {
    scope.remove_file(&saved_path()).map_err(Error::Io)
}

fn ran_from(saved: &Saved, safe_mode: bool, changed: bool, maintenance: Option<bool>) -> Ran {
    Ran {
        safe_mode,
        changed,
        extensions: saved.extensions.clone(),
        maintenance_mode: maintenance,
        saved_at: Some(saved.saved_at_unix_secs),
    }
}

fn run_wordpress(
    ctx: &Context<'_>,
    scope: &ManagedRoot,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<Ran, Error> {
    let saved = load_saved(scope, req.kind)?;
    match (req.mode, saved) {
        (Mode::Status, Some(saved)) => Ok(ran_from(&saved, true, false, None)),
        (Mode::Status, None) | (Mode::Off, None) => Ok(Ran {
            safe_mode: false,
            changed: false,
            extensions: Vec::new(),
            maintenance_mode: None,
            saved_at: None,
        }),
        (Mode::On, Some(saved)) => {
            // Already on. Anything activated since is not folded into the
            // list (that would lose the original), it is reported.
            if !wp_active(ctx, req, cancel)?.is_empty() {
                return Err(Error::Diverged);
            }
            Ok(ran_from(&saved, true, false, None))
        }
        (Mode::On, None) => {
            // Multisite has network-activated plugins this list would miss.
            if exited_ok(&exec(
                ctx,
                req,
                &wp(req, &["core", "is-installed", "--network"]),
                READ_TIMEOUT,
                cancel,
            )?) {
                return Err(Error::Unsupported);
            }
            let active = wp_active(ctx, req, cancel)?;
            let saved = Saved {
                kind: req.kind.name().into(),
                extensions: active.clone(),
                ids: Vec::new(),
                previous_maintenance: None,
                saved_at_unix_secs: unix_now(),
            };
            // The list is durable before the first plugin is touched.
            store_saved(scope, &saved)?;
            let disabled = (|| -> Result<(), Error> {
                if !active.is_empty() {
                    // A non-zero exit is judged by the read-back below.
                    exec(
                        ctx,
                        req,
                        &wp(req, &["plugin", "deactivate", "--all"]),
                        RUN_TIMEOUT,
                        cancel,
                    )?;
                }
                if wp_active(ctx, req, cancel)?.is_empty() {
                    Ok(())
                } else {
                    Err(Error::StateMismatch)
                }
            })();
            if let Err(error) = disabled {
                // Put the previous state back; keep the list if that fails.
                let restored = wp_activate(ctx, req, &active, cancel)
                    .and_then(|()| wp_active(ctx, req, cancel))
                    .is_ok_and(|now| missing(&active, &now).is_empty());
                if restored {
                    let _ = drop_saved(scope);
                }
                return Err(error);
            }
            Ok(ran_from(&saved, true, true, None))
        }
        (Mode::Off, Some(saved)) => {
            let now = wp_active(ctx, req, cancel)?;
            let todo = missing(&saved.extensions, &now);
            wp_activate(ctx, req, &todo, cancel)?;
            let after = wp_active(ctx, req, cancel)?;
            let left = missing(&saved.extensions, &after);
            if !left.is_empty() {
                return Err(Error::Incomplete(left.len()));
            }
            drop_saved(scope)?;
            Ok(ran_from(&saved, false, true, None))
        }
    }
}

fn run_drupal(
    ctx: &Context<'_>,
    scope: &ManagedRoot,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<Ran, Error> {
    let saved = load_saved(scope, req.kind)?;
    match (req.mode, saved) {
        (Mode::Status, Some(saved)) => Ok(ran_from(&saved, true, false, None)),
        (Mode::Status, None) | (Mode::Off, None) => Ok(Ran {
            safe_mode: false,
            changed: false,
            extensions: Vec::new(),
            maintenance_mode: None,
            saved_at: None,
        }),
        (Mode::On, Some(saved)) => {
            let mut changed = false;
            if !drupal_maintenance(ctx, req, cancel)? {
                drupal_set_maintenance(ctx, req, true, cancel)?;
                changed = true;
            }
            Ok(ran_from(&saved, true, changed, Some(true)))
        }
        (Mode::On, None) => {
            let previous = drupal_maintenance(ctx, req, cancel)?;
            let modules = drupal_modules(ctx, req, cancel)?;
            let saved = Saved {
                kind: req.kind.name().into(),
                extensions: modules,
                ids: Vec::new(),
                previous_maintenance: Some(previous),
                saved_at_unix_secs: unix_now(),
            };
            store_saved(scope, &saved)?;
            let set = if previous {
                Ok(())
            } else {
                drupal_set_maintenance(ctx, req, true, cancel)
            };
            if let Err(error) = set {
                if drupal_set_maintenance(ctx, req, previous, cancel).is_ok() {
                    let _ = drop_saved(scope);
                }
                return Err(error);
            }
            Ok(ran_from(&saved, true, true, Some(true)))
        }
        (Mode::Off, Some(saved)) => {
            let previous = saved.previous_maintenance.ok_or(Error::Unreadable)?;
            let mut changed = false;
            if drupal_maintenance(ctx, req, cancel)? != previous {
                drupal_set_maintenance(ctx, req, previous, cancel)?;
                changed = true;
            }
            drop_saved(scope)?;
            Ok(ran_from(&saved, false, changed, Some(previous)))
        }
    }
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<SafeModeResult, Error> {
    let hash = resource_lock::canonical_hash(&req.project_root);
    let scope_path = SiteRelativePath::parse(format!("cms-safe-mode/{hash}")).unwrap();
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

    let outcome = if cancel.is_cancelled() {
        Err(Error::Cancelled)
    } else {
        match req.kind {
            Kind::WordPress => run_wordpress(ctx, &scope, req, cancel),
            Kind::Drupal => run_drupal(ctx, &scope, req, cancel),
            Kind::Joomla => run_joomla(ctx, &scope, req, cancel),
        }
    };
    let ran = match outcome {
        Ok(ran) => ran,
        Err(error) => return Err(fail(&scope, &state_path, &audit_path, state, error)),
    };
    let public = SafeModeResult {
        kind: req.kind.name().into(),
        safe_mode: ran.safe_mode,
        changed: ran.changed,
        extensions: ran.extensions,
        maintenance_mode: ran.maintenance_mode,
        saved_at_unix_secs: ran.saved_at,
        completed_at_unix_secs: unix_now(),
    };
    state
        .mark_committed(serde_json::to_value(&public).unwrap())
        .unwrap();
    // The change is already made: a failed save must not turn it into an error.
    let _ = state::save(&scope, &state_path, &state);
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(req.request_id, true, None),
    );
    drop(lock);
    Ok(public)
}

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<SafeModeResult, Error> {
    let path = SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap();
    let loaded = state::load(scope, &path)
        .map_err(|error| Error::Io(std::io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != OPERATION {
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
    use std::{fs, os::unix::fs::PermissionsExt, path::Path};

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    fn id(n: u32) -> String {
        format!("123e4567-e89b-12d3-a456-4266141740{n:02}")
    }

    fn managed(directory: &Path) -> ManagedRoot {
        ManagedRoot::open(&crate::site::TrustedRoot::parse(directory).unwrap()).unwrap()
    }

    fn request(kind: &str, state: &str, id: &str, key: Option<&str>) -> Request {
        let doc = if kind == "drupal" {
            r#","documentRoot":"/var/www/site/web""#
        } else {
            ""
        };
        Request::parse(
            &format!(
                r#"{{"kind":"{kind}","state":"{state}","container":"runtime-1","projectRoot":"/var/www/site"{doc},"uid":1000,"gid":1000}}"#
            ),
            id,
            key,
        )
        .unwrap()
    }

    /// A fake site. `plugins` holds the active plugins one per line;
    /// `maint` holds the Drupal flag. Marker files steer failures:
    /// `MULTISITE`, `HALF_DEACTIVATE` (removes only the first plugin and
    /// exits 1), `BAD_ACTIVATE` (names listed in it never activate),
    /// `BROKEN_MAINT` (state:set does nothing).
    fn fake_docker(dir: &Path) -> String {
        let log = dir.join("calls.log");
        let path = dir.join("fake-docker");
        fs::write(
            &path,
            format!(
                r#"#!/bin/sh
D='{d}'
printf '%s\n' "$*" >> '{log}'
case "$*" in
  *" php -r "*)
    plan=$(cat)
    printf '%s\n' "$plan" >> '{d}/plans.log'
    case "$plan" in *'"op":"list"'*)
      printf '{{"ok":true,"plugins":['; sep=''
      while read -r id name en; do
        [ "$en" = 1 ] || continue
        printf '%s{{"id":%s,"name":"%s"}}' "$sep" "$id" "$name"; sep=','
      done < "$D/jplugins"
      printf ']}}\n'; exit 0 ;; esac
    ids=$(printf '%s' "$plan" | sed 's/.*"ids":\[\([0-9,]*\)\].*/\1/')
    case "$plan" in *'"op":"enable"'*) op=enable ;; *) op=disable ;; esac
    if [ "$op" = disable ] && [ -f "$D/J_HALF" ]; then ids=$(printf '%s' "$ids" | cut -d, -f1); fi
    awk -v ids=",$ids," -v op="$op" -v lock="$(cat "$D/J_LOCKED" 2>/dev/null)" '
      {{ if (index(ids, "," $1 ",") > 0 && index(" " lock " ", " " $1 " ") == 0) $3 = (op == "enable") ? 1 : 0; print }}' "$D/jplugins" > "$D/jplugins.new" && mv "$D/jplugins.new" "$D/jplugins"
    printf '{{"ok":true,"affected":1}}\n'; exit 0 ;;
  *"core is-installed --network"*) [ -f "$D/MULTISITE" ]; exit $? ;;
  *"plugin list --status=active"*)
    printf '['; sep=''
    for p in $(cat "$D/plugins" 2>/dev/null); do printf '%s"%s"' "$sep" "$p"; sep=','; done
    printf ']'; exit 0 ;;
  *"plugin deactivate --all"*)
    if [ -f "$D/HALF_DEACTIVATE" ]; then sed -i.bak 1d "$D/plugins"; exit 1; fi
    : > "$D/plugins"; exit 0 ;;
  *"plugin activate "*)
    rc=0; go=0
    for a in "$@"; do
      if [ "$go" = 1 ]; then
        if [ -f "$D/BAD_ACTIVATE" ] && grep -qx "$a" "$D/BAD_ACTIVATE"; then rc=1; continue; fi
        grep -qx "$a" "$D/plugins" || echo "$a" >> "$D/plugins"
      fi
      [ "$a" = activate ] && go=1
    done
    exit $rc ;;
  *"state:set system.maintenance_mode 1"*) [ -f "$D/BROKEN_MAINT" ] || echo 1 > "$D/maint"; exit 0 ;;
  *"state:set system.maintenance_mode 0"*) [ -f "$D/BROKEN_MAINT" ] || echo 0 > "$D/maint"; exit 0 ;;
  *"state:get system.maintenance_mode"*) cat "$D/maint"; exit 0 ;;
  *"pm:list"*) echo '{{"system":{{}},"node":{{}},"views":{{}}}}'; exit 0 ;;
esac
exit 0
"#,
                d = dir.display(),
                log = log.display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    /// Joomla plugins as `id name enabled`, one per line.
    fn set_joomla(dir: &Path, rows: &[(u32, &str, u8)]) {
        let mut text = String::new();
        for (id, name, en) in rows {
            text.push_str(&format!("{id} {name} {en}\n"));
        }
        fs::write(dir.join("jplugins"), text).unwrap();
    }

    fn joomla_enabled_names(dir: &Path) -> Vec<String> {
        fs::read_to_string(dir.join("jplugins"))
            .unwrap()
            .lines()
            .filter_map(|line| {
                let mut parts = line.split(' ');
                let (_, name, en) = (parts.next()?, parts.next()?, parts.next()?);
                (en == "1").then(|| name.to_owned())
            })
            .collect()
    }

    fn set_plugins(dir: &Path, list: &[&str]) {
        fs::write(dir.join("plugins"), list.join("\n") + "\n").unwrap();
    }

    fn plugins(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_to_string(dir.join("plugins"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect();
        v.sort();
        v
    }

    fn log(dir: &Path) -> String {
        fs::read_to_string(dir.join("calls.log")).unwrap_or_default()
    }

    fn run(dir: &Path, req: &Request) -> Result<SafeModeResult, Error> {
        let docker = fake_docker(dir);
        // The engine state lives in its own sub-directory of the temp dir.
        let state_dir = dir.join("engine-state");
        fs::create_dir_all(&state_dir).unwrap();
        let state = managed(&state_dir);
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };
        execute(&ctx, req, &CancellationToken::default())
    }

    #[test]
    fn rejects_invalid_requests() {
        let with = |kind: &str, state: &str, extra: &str| {
            format!(
                r#"{{"kind":"{kind}","state":"{state}","container":"c","projectRoot":"/var/www/site","uid":1,"gid":1{extra}}}"#
            )
        };
        assert_eq!(
            Request::parse(&with("typo3", "on", ""), ID, None).unwrap_err(),
            RequestError::InvalidKind
        );
        assert_eq!(
            Request::parse(&with("wordpress", "toggle", ""), ID, None).unwrap_err(),
            RequestError::InvalidState
        );
        // Drupal needs a document root below the project root; WordPress has none.
        assert_eq!(
            Request::parse(&with("drupal", "on", ""), ID, None).unwrap_err(),
            RequestError::InvalidRoot
        );
        assert_eq!(
            Request::parse(&with("drupal", "on", r#","documentRoot":"/etc""#), ID, None)
                .unwrap_err(),
            RequestError::InvalidRoot
        );
        assert_eq!(
            Request::parse(
                &with("wordpress", "on", r#","documentRoot":"/var/www/site""#),
                ID,
                None
            )
            .unwrap_err(),
            RequestError::InvalidRoot
        );
        assert_eq!(
            Request::parse(&with("wordpress", "on", r#","x":1"#), ID, None).unwrap_err(),
            RequestError::InvalidJson
        );
        assert!(Request::parse(&with("wordpress", "status", ""), ID, None).is_ok());
    }

    #[test]
    fn names_are_validated_before_they_become_arguments() {
        for good in ["akismet", "my-plugin_2", "dir/file.php", "views_ui"] {
            assert!(valid_name(good), "{good}");
        }
        for bad in ["", "--all", "../x", "a b", "a;b", "-x", "/abs", "a\nb"] {
            assert!(!valid_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn wordpress_disables_all_and_restores_exactly() {
        let dir = tempfile::tempdir().unwrap();
        set_plugins(dir.path(), &["woo", "akismet", "seo"]);
        let on = run(dir.path(), &request("wordpress", "on", ID, Some("k1"))).unwrap();
        assert!(on.safe_mode && on.changed);
        assert_eq!(on.extensions, ["akismet", "seo", "woo"]);
        assert!(plugins(dir.path()).is_empty());
        let recorded = log(dir.path());
        assert!(recorded.contains("--skip-plugins --skip-themes plugin deactivate --all"));
        // The saved list is written before the deactivation runs.
        let state = dir.path().join("engine-state/cms-safe-mode");
        assert!(fs::read_dir(&state).unwrap().count() == 1);

        // A replay with the same key re-runs nothing.
        let calls = log(dir.path()).lines().count();
        let again = run(dir.path(), &request("wordpress", "on", &id(1), Some("k1"))).unwrap();
        assert_eq!(again.extensions, on.extensions);
        assert_eq!(log(dir.path()).lines().count(), calls);

        // Already on: nothing changes and the saved list is untouched.
        let again = run(dir.path(), &request("wordpress", "on", &id(2), None)).unwrap();
        assert!(again.safe_mode && !again.changed);
        assert_eq!(again.extensions, ["akismet", "seo", "woo"]);

        let status = run(dir.path(), &request("wordpress", "status", &id(3), None)).unwrap();
        assert!(status.safe_mode && !status.changed);

        let off = run(dir.path(), &request("wordpress", "off", &id(4), None)).unwrap();
        assert!(!off.safe_mode && off.changed);
        assert_eq!(plugins(dir.path()), ["akismet", "seo", "woo"]);
        let status = run(dir.path(), &request("wordpress", "status", &id(5), None)).unwrap();
        assert!(!status.safe_mode);
        // Off again is a no-op.
        let off = run(dir.path(), &request("wordpress", "off", &id(6), None)).unwrap();
        assert!(!off.safe_mode && !off.changed);
    }

    #[test]
    fn wordpress_failed_disable_puts_the_plugins_back() {
        let dir = tempfile::tempdir().unwrap();
        set_plugins(dir.path(), &["a", "b", "c"]);
        fs::write(dir.path().join("HALF_DEACTIVATE"), "").unwrap();
        let error = run(dir.path(), &request("wordpress", "on", ID, None))
            .err()
            .unwrap();
        assert!(matches!(error, Error::StateMismatch));
        assert_eq!(plugins(dir.path()), ["a", "b", "c"]);
        // Nothing is left behind: the next status says safe mode is off.
        let status = run(dir.path(), &request("wordpress", "status", &id(1), None)).unwrap();
        assert!(!status.safe_mode);
    }

    #[test]
    fn wordpress_partial_restore_keeps_the_list_and_a_retry_finishes() {
        let dir = tempfile::tempdir().unwrap();
        set_plugins(dir.path(), &["good", "bad", "fine"]);
        run(dir.path(), &request("wordpress", "on", ID, None)).unwrap();
        fs::write(dir.path().join("BAD_ACTIVATE"), "bad\n").unwrap();
        let error = run(dir.path(), &request("wordpress", "off", &id(1), None))
            .err()
            .unwrap();
        assert!(matches!(error, Error::Incomplete(1)), "{error:?}");
        assert_eq!(plugins(dir.path()), ["fine", "good"]);
        let status = run(dir.path(), &request("wordpress", "status", &id(2), None)).unwrap();
        assert!(status.safe_mode, "the list survives a failed restore");
        // The cause is fixed; only the missing plugin is activated again.
        fs::remove_file(dir.path().join("BAD_ACTIVATE")).unwrap();
        let off = run(dir.path(), &request("wordpress", "off", &id(3), None)).unwrap();
        assert!(!off.safe_mode);
        assert_eq!(plugins(dir.path()), ["bad", "fine", "good"]);
    }

    #[test]
    fn wordpress_on_again_after_new_activations_is_a_conflict() {
        let dir = tempfile::tempdir().unwrap();
        set_plugins(dir.path(), &["a"]);
        run(dir.path(), &request("wordpress", "on", ID, None)).unwrap();
        set_plugins(dir.path(), &["late"]);
        let error = run(dir.path(), &request("wordpress", "on", &id(1), None))
            .err()
            .unwrap();
        assert!(matches!(error, Error::Diverged));
        assert_eq!(error.protocol().0, ErrorCode::Conflict);
        // The original list is intact.
        let status = run(dir.path(), &request("wordpress", "status", &id(2), None)).unwrap();
        assert_eq!(status.extensions, ["a"]);
    }

    #[test]
    fn wordpress_multisite_is_refused_before_anything_is_saved() {
        let dir = tempfile::tempdir().unwrap();
        set_plugins(dir.path(), &["a"]);
        fs::write(dir.path().join("MULTISITE"), "").unwrap();
        let error = run(dir.path(), &request("wordpress", "on", ID, None))
            .err()
            .unwrap();
        assert!(matches!(error, Error::Unsupported));
        assert_eq!(plugins(dir.path()), ["a"]);
        assert!(!log(dir.path()).contains("deactivate"));
    }

    #[test]
    fn drupal_sets_maintenance_and_restores_the_previous_value() {
        for previous in ["0", "1"] {
            let dir = tempfile::tempdir().unwrap();
            fs::write(dir.path().join("maint"), format!("{previous}\n")).unwrap();
            let on = run(dir.path(), &request("drupal", "on", ID, None)).unwrap();
            assert!(on.safe_mode && on.maintenance_mode == Some(true));
            assert!(on.changed, "safe mode itself is a change");
            assert_eq!(on.extensions, ["node", "system", "views"]);
            let recorded = log(dir.path());
            assert!(!recorded.contains("pm:uninstall") && !recorded.contains("pm-uninstall"));
            let off = run(dir.path(), &request("drupal", "off", &id(1), None)).unwrap();
            assert!(!off.safe_mode);
            assert_eq!(off.maintenance_mode, Some(previous == "1"));
            assert_eq!(
                fs::read_to_string(dir.path().join("maint")).unwrap().trim(),
                previous
            );
        }
    }

    #[test]
    fn drupal_unconfirmed_maintenance_is_never_reported_ok() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("maint"), "0\n").unwrap();
        fs::write(dir.path().join("BROKEN_MAINT"), "").unwrap();
        let error = run(dir.path(), &request("drupal", "on", ID, None))
            .err()
            .unwrap();
        assert!(matches!(error, Error::StateMismatch));
        // The record was dropped again because the previous value is in place.
        let status = run(dir.path(), &request("drupal", "status", &id(1), None)).unwrap();
        assert!(!status.safe_mode);
    }

    #[test]
    fn a_failed_request_is_replayed_as_failed() {
        let dir = tempfile::tempdir().unwrap();
        set_plugins(dir.path(), &["a"]);
        fs::write(dir.path().join("MULTISITE"), "").unwrap();
        assert!(run(dir.path(), &request("wordpress", "on", ID, Some("f"))).is_err());
        let calls = log(dir.path()).lines().count();
        let error = run(dir.path(), &request("wordpress", "on", &id(1), Some("f")))
            .err()
            .unwrap();
        assert!(matches!(error, Error::Replayed { .. }));
        assert_eq!(log(dir.path()).lines().count(), calls);
    }

    const JOOMLA: [(u32, &str, u8); 4] = [
        (10, "system/seo", 1),
        (11, "content/gallery", 1),
        (12, "system/off-already", 0),
        (13, "user/sso", 1),
    ];

    #[test]
    fn joomla_disables_the_enabled_plugins_and_restores_exactly_that_set() {
        let dir = tempfile::tempdir().unwrap();
        set_joomla(dir.path(), &JOOMLA);
        let on = run(dir.path(), &request("joomla", "on", ID, Some("j1"))).unwrap();
        assert!(on.safe_mode && on.changed);
        assert_eq!(on.extensions, ["system/seo", "content/gallery", "user/sso"]);
        assert!(joomla_enabled_names(dir.path()).is_empty());
        // Every call carried a fixed op and integer ids only.
        let plans = fs::read_to_string(dir.path().join("plans.log")).unwrap();
        assert!(plans.contains(r#""ids":[10,11,13]"#), "{plans}");
        assert!(!plans.contains("off-already"));

        // Replay with the same key re-runs nothing.
        let calls = plans.lines().count();
        run(dir.path(), &request("joomla", "on", &id(1), Some("j1"))).unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("plans.log"))
                .unwrap()
                .lines()
                .count(),
            calls
        );
        // Already on: unchanged.
        let again = run(dir.path(), &request("joomla", "on", &id(2), None)).unwrap();
        assert!(again.safe_mode && !again.changed);

        let off = run(dir.path(), &request("joomla", "off", &id(3), None)).unwrap();
        assert!(!off.safe_mode && off.changed);
        // The plugin that was already disabled stays disabled.
        assert_eq!(
            joomla_enabled_names(dir.path()),
            ["system/seo", "content/gallery", "user/sso"]
        );
        assert!(
            !run(dir.path(), &request("joomla", "status", &id(4), None))
                .unwrap()
                .safe_mode
        );
        let off = run(dir.path(), &request("joomla", "off", &id(5), None)).unwrap();
        assert!(!off.safe_mode && !off.changed);
    }

    #[test]
    fn joomla_failed_disable_puts_the_plugins_back() {
        let dir = tempfile::tempdir().unwrap();
        set_joomla(dir.path(), &JOOMLA);
        fs::write(dir.path().join("J_HALF"), "").unwrap();
        let error = run(dir.path(), &request("joomla", "on", ID, None))
            .err()
            .unwrap();
        assert!(matches!(error, Error::StateMismatch), "{error:?}");
        assert_eq!(
            joomla_enabled_names(dir.path()),
            ["system/seo", "content/gallery", "user/sso"]
        );
        assert!(
            !run(dir.path(), &request("joomla", "status", &id(1), None))
                .unwrap()
                .safe_mode
        );
    }

    #[test]
    fn joomla_partial_restore_keeps_the_list_and_a_retry_finishes() {
        let dir = tempfile::tempdir().unwrap();
        set_joomla(dir.path(), &JOOMLA);
        run(dir.path(), &request("joomla", "on", ID, None)).unwrap();
        fs::write(dir.path().join("J_LOCKED"), "11").unwrap();
        let error = run(dir.path(), &request("joomla", "off", &id(1), None))
            .err()
            .unwrap();
        assert!(matches!(error, Error::Incomplete(1)), "{error:?}");
        assert_eq!(joomla_enabled_names(dir.path()), ["system/seo", "user/sso"]);
        assert!(
            run(dir.path(), &request("joomla", "status", &id(2), None))
                .unwrap()
                .safe_mode
        );
        fs::remove_file(dir.path().join("J_LOCKED")).unwrap();
        let off = run(dir.path(), &request("joomla", "off", &id(3), None)).unwrap();
        assert!(!off.safe_mode);
        assert_eq!(
            joomla_enabled_names(dir.path()),
            ["system/seo", "content/gallery", "user/sso"]
        );
    }

    #[test]
    fn joomla_on_again_after_new_activations_is_a_conflict() {
        let dir = tempfile::tempdir().unwrap();
        set_joomla(dir.path(), &JOOMLA);
        run(dir.path(), &request("joomla", "on", ID, None)).unwrap();
        set_joomla(dir.path(), &[(12, "system/late", 1)]);
        let error = run(dir.path(), &request("joomla", "on", &id(1), None))
            .err()
            .unwrap();
        assert!(matches!(error, Error::Diverged));
    }

    #[test]
    fn joomla_takes_no_document_root() {
        let json = r#"{"kind":"joomla","state":"on","container":"c","projectRoot":"/var/www/j","documentRoot":"/var/www/j","uid":1,"gid":1}"#;
        assert_eq!(
            Request::parse(json, ID, None).unwrap_err(),
            RequestError::InvalidRoot
        );
    }

    #[test]
    fn the_joomla_script_touches_only_plugin_rows_that_are_neither_core_nor_protected() {
        assert!(JOOMLA_PHP.contains("'plugin'"));
        assert!(JOOMLA_PHP.contains("quoteName('protected') . ' = 0 AND '"));
        assert!(JOOMLA_PHP.contains("quoteName('locked') . ' = 0'"));
        assert!(JOOMLA_PHP.contains("checkIfCoreExtension"));
        // No credential is read or printed.
        for word in ["password", "getConfig", "->get('user')", "dbtype"] {
            assert!(!JOOMLA_PHP.contains(word), "{word}");
        }
    }
}
