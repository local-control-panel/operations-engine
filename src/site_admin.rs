//! `site.adminUsers` and `site.adminLogin`: list a site's administrators and
//! mint a short-lived, single-use login link for one of them.
//!
//! WordPress (`cms: "wordpress"`) and Joomla (`cms: "joomla"`). Drupal is
//! refused with a clear error: `drush uli` lives 24 h by default, cannot be
//! made single-use under parallel opens and needs Drush as an engine-managed
//! tool; see the ROADMAP.
//!
//! ## WordPress design (the "login broker")
//!
//! WP-CLI has no login URL. The engine therefore drops a tiny **mu-plugin**
//! into `wp-content/mu-plugins/`, written as the site user through
//! `docker exec ... wp eval`:
//!
//! - The engine generates a 244-bit random token, keeps it in memory only and
//!   sends the container just its SHA-256, the admin user id and the expiry.
//!   The token never reaches argv, stdin, the container or the disk.
//! - The file is named `wcp-otl-<expiresAt>-<random>.php` and contains the
//!   hash, the expiry and the user id. A request carrying `?wcp_otl=<token>`
//!   is checked with `hash_equals`; the file is then `unlink`ed (atomic, so of
//!   two concurrent requests exactly one wins), the user is logged in and
//!   redirected to the dashboard. Any other request does nothing, except that
//!   an expired file deletes itself.
//! - Each issue also deletes expired files; at most 10 can be outstanding.
//! ## Joomla design
//!
//! Joomla has no CLI login and no must-use plugin directory, so the engine
//! writes one minimal, self-deleting entry file `wcp-otl-<expiresAt>-<random>.php`
//! into the Joomla root (as the site user, 0600, tmp + rename), holding only
//! the token hash, the expiry, the user id and the absolute admin URL. A
//! request with `?wcp_otl=<token>` is compared with `hash_equals`, the file is
//! `unlink`ed (atomic: exactly one concurrent request wins; every other one
//! gets a plain 404), then Joomla's `AdministratorApplication` is booted and,
//! in `onAfterInitialise`, the official `onUserLogin` / `onUserAfterLogin`
//! events run for the target user (`core.login.admin`, blocked users refused,
//! the `joomla` user plugin forks the session and writes `#__session`).
//! **Joomla multi-factor authentication is not bypassed**: the user lands on
//! Joomla's own MFA captive page if they have a second factor. The target must
//! be an unblocked member of a group with `core.admin` (Super Users).
//! Issue time boots Joomla in CLI to check this and to list super users.
//! Because the Joomla root is not behind a CLI that knows the public URL, the
//! request carries `siteUrl` (public base URL, e.g. `https://example.com/`).
//!
//! - The link is returned through `secretResult` (`crate::secret_result`):
//!   only `{adminUserId, adminLogin, issuedAt, expiresAt}` is stored in the
//!   transaction state and returned by an idempotent replay.

use crate::{
    db_restore::{ContainerName, RestoreRequestError},
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{
        self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination,
        SubprocessDiagnostics,
    },
    secret_result::SecretResult,
    site::SiteRelativePath,
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        resource_lock,
        state::{self, TransactionStatus},
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const USERS_OPERATION: &str = "site.adminUsers";
pub const LOGIN_OPERATION: &str = "site.adminLogin";

pub const MIN_TTL_SECS: u64 = 60;
pub const MAX_TTL_SECS: u64 = 600;
pub const DEFAULT_TTL_SECS: u64 = 300;
/// `site.adminUsers` returns at most this many administrators.
pub const MAX_ADMIN_USERS: usize = 50;
const MAX_LOGIN_BYTES: usize = 60;
const MAX_HOME_BYTES: usize = 2048;
const TIMEOUT: Duration = Duration::from_secs(60);
const MAX_OUTPUT_BYTES: usize = 64 * 1024;
/// The query parameter the mu-plugin listens for.
pub const TOKEN_PARAMETER: &str = "wcp_otl";

/// Prints the administrators as one JSON line. Fixed text; no input.
const USERS_PHP: &str = r#"$u = get_users(array('role' => 'administrator', 'number' => 51, 'orderby' => 'ID', 'order' => 'ASC', 'fields' => array('ID', 'user_login')));
$o = array();
foreach ($u as $x) { $o[] = array('id' => (int) $x->ID, 'login' => (string) $x->user_login); }
echo "\n" . wp_json_encode(array('ok' => true, 'users' => $o)) . "\n";"#;

/// Validates the administrator, removes expired broker files, writes the new
/// one atomically and prints `{ok, home, login, file}` as one JSON line. The
/// plan (user id, token hash, expiry, file source) comes on stdin, never
/// argv. Fixed text; nothing is interpolated.
const LOGIN_PHP: &str = r#"$say = function ($v) { echo "\n" . wp_json_encode($v) . "\n"; };
$plan = json_decode(stream_get_contents(STDIN), true);
if (!is_array($plan) || !isset($plan['userId'], $plan['expires'], $plan['source'])) { $say(array('ok' => false, 'error' => 'badPlan')); return; }
$user = get_userdata((int) $plan['userId']);
if (!$user) { $say(array('ok' => false, 'error' => 'notFound')); return; }
if (!in_array('administrator', (array) $user->roles, true)) { $say(array('ok' => false, 'error' => 'notAdmin')); return; }
$dir = WPMU_PLUGIN_DIR;
if (!is_dir($dir) && !wp_mkdir_p($dir)) { $say(array('ok' => false, 'error' => 'cannotWrite')); return; }
$now = time(); $active = 0;
foreach ((array) glob($dir . '/wcp-otl-*.php') as $f) {
  if (preg_match('/^wcp-otl-(\d+)-[0-9a-f]{16}\.php$/', basename($f), $m)) { if ((int) $m[1] <= $now) { @unlink($f); } else { $active++; } }
}
if ($active >= 10) { $say(array('ok' => false, 'error' => 'busy')); return; }
$name = 'wcp-otl-' . (int) $plan['expires'] . '-' . bin2hex(random_bytes(8)) . '.php';
$tmp = $dir . '/.' . $name . '.tmp';
if (file_put_contents($tmp, (string) $plan['source']) === false) { $say(array('ok' => false, 'error' => 'cannotWrite')); return; }
@chmod($tmp, 0600);
if (!rename($tmp, $dir . '/' . $name)) { @unlink($tmp); $say(array('ok' => false, 'error' => 'cannotWrite')); return; }
$say(array('ok' => true, 'home' => home_url('/'), 'login' => (string) $user->user_login, 'file' => $name));"#;

/// Boots Joomla's administrator application in CLI (no HTTP, no session
/// output). The plan arrives on stdin as JSON; `root` is the Joomla root.
const JOOMLA_BOOT_PHP: &str = r#"$say = function ($v) { echo "\n" . json_encode($v) . "\n"; };
$plan = json_decode(stream_get_contents(STDIN), true);
if (!is_array($plan) || !isset($plan['root']) || !is_string($plan['root'])) { $say(array('ok' => false, 'error' => 'badPlan')); return; }
define('_JEXEC', 1); define('JPATH_BASE', $plan['root']);
$_SERVER['HTTP_HOST'] = 'localhost';
if (!is_file(JPATH_BASE . '/includes/framework.php') || !is_file(JPATH_BASE . '/configuration.php')) { $say(array('ok' => false, 'error' => 'notJoomla')); return; }
require_once JPATH_BASE . '/includes/defines.php';
require_once JPATH_BASE . '/includes/framework.php';
$container = \Joomla\CMS\Factory::getContainer();
$container->alias('session.web', 'session.web.administrator')->alias('session', 'session.web.administrator')->alias('JSession', 'session.web.administrator')->alias(\Joomla\CMS\Session\Session::class, 'session.web.administrator')->alias(\Joomla\Session\Session::class, 'session.web.administrator')->alias(\Joomla\Session\SessionInterface::class, 'session.web.administrator');
\Joomla\CMS\Factory::$application = $container->get(\Joomla\CMS\Application\AdministratorApplication::class);
$db = $container->get(\Joomla\Database\DatabaseInterface::class);
$groups = array();
foreach ($db->setQuery($db->getQuery(true)->select('id')->from('#__usergroups'))->loadColumn() as $g) { if (\Joomla\CMS\Access\Access::checkGroup((int) $g, 'core.admin')) { $groups[] = (int) $g; } }
"#;

/// Prints the unblocked super users (groups with `core.admin`).
const JOOMLA_USERS_PHP: &str = r#"$o = array();
if ($groups) {
  $q = $db->getQuery(true)->select('DISTINCT u.id, u.username')->from('#__users AS u')->join('INNER', '#__user_usergroup_map AS m ON m.user_id = u.id')->where('u.block = 0')->where('m.group_id IN (' . implode(',', $groups) . ')')->order('u.id')->setLimit(51);
  foreach ($db->setQuery($q)->loadAssocList() as $r) { $o[] = array('id' => (int) $r['id'], 'login' => (string) $r['username']); }
}
$say(array('ok' => true, 'users' => $o));"#;

/// Validates the super user, removes expired entry files, writes the new one
/// atomically and prints `{ok, login, file}`. Fixed text.
const JOOMLA_LOGIN_PHP: &str = r#"if (!isset($plan['userId'], $plan['name'], $plan['source']) || !preg_match('/^wcp-otl-\d+-[0-9a-f]{16}\.php$/', (string) $plan['name'])) { $say(array('ok' => false, 'error' => 'badPlan')); return; }
$q = $db->getQuery(true)->select('id, username, block')->from('#__users')->where('id = ' . (int) $plan['userId']);
$u = $db->setQuery($q)->loadAssoc();
if (!$u) { $say(array('ok' => false, 'error' => 'notFound')); return; }
if ((int) $u['block'] !== 0) { $say(array('ok' => false, 'error' => 'notAdmin')); return; }
$isAdmin = false;
foreach ($db->setQuery($db->getQuery(true)->select('group_id')->from('#__user_usergroup_map')->where('user_id = ' . (int) $u['id']))->loadColumn() as $g) { if (in_array((int) $g, $groups, true)) { $isAdmin = true; } }
if (!$isAdmin) { $say(array('ok' => false, 'error' => 'notAdmin')); return; }
$dir = JPATH_BASE; $now = time(); $active = 0;
foreach ((array) glob($dir . '/wcp-otl-*.php') as $f) {
  if (preg_match('/^wcp-otl-(\d+)-[0-9a-f]{16}\.php$/', basename($f), $m)) { if ((int) $m[1] <= $now) { @unlink($f); } else { $active++; } }
}
if ($active >= 10) { $say(array('ok' => false, 'error' => 'busy')); return; }
$tmp = $dir . '/.' . $plan['name'] . '.tmp';
if (file_put_contents($tmp, (string) $plan['source']) === false) { $say(array('ok' => false, 'error' => 'cannotWrite')); return; }
@chmod($tmp, 0600);
if (!rename($tmp, $dir . '/' . $plan['name'])) { @unlink($tmp); $say(array('ok' => false, 'error' => 'cannotWrite')); return; }
$say(array('ok' => true, 'login' => (string) $u['username'], 'file' => $plan['name']));"#;

/// Lists active administrators: uid 1 and every user with a role flagged
/// `is_admin`. Fixed text, run through `drush php:eval`.
const DRUPAL_USERS_PHP: &str = r#"$roles = array_keys(array_filter(\Drupal\user\Entity\Role::loadMultiple(), static function ($r) { return $r->isAdmin(); }));
$s = \Drupal::entityTypeManager()->getStorage('user');
$q = $s->getQuery()->accessCheck(FALSE)->condition('status', 1);
$g = $q->orConditionGroup()->condition('uid', 1);
if ($roles) { $g->condition('roles', $roles, 'IN'); }
$ids = $q->condition($g)->sort('uid')->range(0, 51)->execute();
$o = array();
foreach ($s->loadMultiple($ids) as $u) { $o[] = array('id' => (int) $u->id(), 'login' => (string) $u->getAccountName()); }
echo "\n" . json_encode(array('ok' => TRUE, 'users' => $o)) . "\n";"#;

/// Checks one user (the id is prepended as `$uid = <number>;`) and reports
/// the site's reset-link lifetime.
const DRUPAL_CHECK_PHP: &str = r#"$say = static function ($v) { echo "\n" . json_encode($v) . "\n"; };
$u = \Drupal\user\Entity\User::load($uid);
if (!$u || $u->isAnonymous()) { $say(array('ok' => FALSE, 'error' => 'notFound')); return; }
$admin = ((int) $u->id() === 1);
foreach ($u->getRoles() as $rid) { $r = \Drupal\user\Entity\Role::load($rid); if ($r && $r->isAdmin()) { $admin = TRUE; } }
if (!$u->isActive() || !$admin) { $say(array('ok' => FALSE, 'error' => 'notAdmin')); return; }
$say(array('ok' => TRUE, 'login' => (string) $u->getAccountName(), 'timeout' => (int) \Drupal::config('user.settings')->get('password_reset_timeout')));"#;

/// Exit status of the Drush selector when no Drush exists.
const DRUSH_ABSENT: i32 = 97;

/// Runs Drush as the site user from the project root: the project's own
/// `vendor/bin/drush` first, `drush` on `PATH` as fallback. `sh` only selects
/// the binary; every value reaches it as a positional parameter.
fn run_drush(
    ctx: &Context<'_>,
    target: &Target,
    drush_args: &[&str],
    cancel: &CancellationToken,
) -> Result<Vec<u8>, Error> {
    let project = target.project_root.as_ref().ok_or(Error::BadOutput)?;
    let mut args: Vec<String> = vec![
        "exec".into(),
        "--user".into(),
        format!("{}:{}", target.uid, target.gid),
        "-w".into(),
        project.display().to_string(),
        target.container.as_str().to_owned(),
        "sh".into(),
        "-c".into(),
        format!(
            "if [ -x ./vendor/bin/drush ]; then exec ./vendor/bin/drush \"$@\"; elif command -v drush >/dev/null 2>&1; then exec drush \"$@\"; else exit {DRUSH_ABSENT}; fi"
        ),
        "drush".into(),
        format!("--root={}", target.root.display()),
        "--no-interaction".into(),
    ];
    if let Some(url) = &target.site_url {
        args.push(format!("--uri={}", url.trim_end_matches('/')));
    }
    args.extend(drush_args.iter().map(|arg| (*arg).to_owned()));
    let output = process::run(
        &ProcessRequest::new(ctx.docker_program).args(args),
        &ProcessLimits {
            timeout: TIMEOUT,
            max_stdout_bytes: MAX_OUTPUT_BYTES,
            max_stderr_bytes: MAX_OUTPUT_BYTES,
        },
        cancel,
    )
    .map_err(Error::Run)?;
    match output.termination {
        ProcessTermination::Exited { success: true, .. } => {}
        ProcessTermination::Exited {
            code: Some(DRUSH_ABSENT),
            ..
        } => return Err(Error::DrushMissing),
        _ => {
            return Err(Error::Rejected(SubprocessDiagnostics::from_output(
                ctx.docker_program,
                &output,
            )));
        }
    }
    if output.stdout.truncated || output.stderr.truncated {
        return Err(Error::TooLarge);
    }
    Ok(output.stdout.bytes)
}

/// `{id}/{ts}/{hash}/login` out of a `drush uli` link whose base is `base`
/// (no trailing slash). The link is the secret; only the timestamp is read.
fn parse_uli(line: &str, base: &str, user_id: u64) -> Option<u64> {
    let rest = line.strip_prefix(base)?;
    let rest = rest.strip_prefix("/user/reset/")?;
    let mut parts = rest.split('/');
    let (id, ts, hash, tail) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    let clean = !hash.is_empty()
        && hash.len() <= 256
        && hash
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    (parts.next().is_none()
        && tail == "login"
        && clean
        && id.parse::<u64>().ok()? == user_id
        && line.len() <= MAX_HOME_BYTES)
        .then(|| ts.parse::<u64>().ok())
        .flatten()
}

/// Drupal: the native `drush uli`. The link lives as long as the site's own
/// `password_reset_timeout`; single use comes from Drupal's login timestamp,
/// which is *not* race-free (parallel opens can each start a session until
/// the first one finishes). Both are reported in `limits`.
fn mint_drupal(
    ctx: &Context<'_>,
    req: &LoginRequest,
    cancel: &CancellationToken,
) -> Result<Minted, Error> {
    let php = format!("$uid = {}; {DRUPAL_CHECK_PHP}", req.admin_user_id);
    let bytes = run_drush(ctx, &req.target, &["php:eval", &php], cancel)?;
    let answer = last_json(&bytes)?;
    if answer.get("ok").and_then(|value| value.as_bool()) != Some(true) {
        let code = answer
            .get("error")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        return Err(reject(code));
    }
    let login = answer
        .get("login")
        .and_then(|value| value.as_str())
        .filter(|value| valid_login(value))
        .ok_or(Error::BadOutput)?
        .to_owned();
    let timeout = answer
        .get("timeout")
        .and_then(|value| value.as_u64())
        .filter(|value| *value > 0)
        .ok_or(Error::BadOutput)?;
    let uid = req.admin_user_id.to_string();
    let bytes = run_drush(
        ctx,
        &req.target,
        &["user:login", "--no-browser", &format!("--uid={uid}")],
        cancel,
    )?;
    let text = std::str::from_utf8(&bytes).map_err(|_| Error::BadOutput)?;
    let line = text
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or(Error::BadOutput)?;
    let base = req
        .target
        .site_url
        .as_deref()
        .ok_or(Error::BadOutput)?
        .trim_end_matches('/');
    let timestamp = parse_uli(line, base, req.admin_user_id).ok_or(Error::BadOutput)?;
    Ok(Minted {
        url: line.to_owned(),
        login,
        expires_at: timestamp.saturating_add(timeout),
        limits: vec![
            "ttlFromSiteSettings".to_owned(),
            "singleUseNotRaceSafe".to_owned(),
        ],
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UsersPlan {
    cms: String,
    container: String,
    root: String,
    uid: u32,
    gid: u32,
    site_url: Option<String>,
    project_root: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LoginPlan {
    cms: String,
    container: String,
    root: String,
    uid: u32,
    gid: u32,
    site_url: Option<String>,
    project_root: Option<String>,
    admin_user_id: u64,
    ttl_seconds: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    UnsupportedCms,
    InvalidRoot,
    InvalidContainer,
    InvalidUserId,
    InvalidTtl,
    InvalidSiteUrl,
    /// Joomla needs the public base URL to build the link.
    SiteUrlRequired,
    /// Drupal links live as long as the site's own setting.
    TtlNotSupported,
    /// `projectRoot` is required for Drupal and refused otherwise.
    InvalidProjectRoot,
    InvalidRequestId,
    InvalidIdempotencyKey,
    /// `site.adminLogin` mutates and must be replay-safe.
    IdempotencyKeyRequired,
}

impl RequestError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::UnsupportedCms => {
                "one-time admin login is implemented for WordPress, Joomla and Drupal, not for this CMS"
            }
            Self::InvalidSiteUrl => {
                "siteUrl must be an http(s) base URL without query, fragment or credentials"
            }
            Self::SiteUrlRequired => "siteUrl is required for Joomla and Drupal login",
            Self::TtlNotSupported => {
                "ttlSeconds is not supported for Drupal: the link lives as long as the site's password_reset_timeout"
            }
            Self::InvalidProjectRoot => "projectRoot is required for Drupal (and only for Drupal)",
            Self::IdempotencyKeyRequired => "site.adminLogin requires an idempotency key",
            Self::InvalidTtl => "ttlSeconds must be between 60 and 600",
            _ => "request-file is not a valid site admin plan",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cms {
    WordPress,
    Joomla,
    Drupal,
}

struct Target {
    cms: Cms,
    project_root: Option<PathBuf>,
    site_url: Option<String>,
    container: ContainerName,
    root: PathBuf,
    uid: u32,
    gid: u32,
}

/// A public base URL: scheme, host, optional port and plain path. It is
/// embedded in a PHP string and in the returned link, so the charset is
/// closed. Always ends with `/`.
fn base_url(value: &str) -> Option<String> {
    let rest = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))?;
    let (authority, path) = rest.split_once('/').map_or((rest, ""), |(a, p)| (a, p));
    let host_ok = !authority.is_empty()
        && authority.len() <= 255
        && authority
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
        && authority.matches(':').count() <= 1;
    let path_ok = path.len() <= 1024
        && path.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'%' | b'/' | b'-')
        })
        && !path.split('/').any(|part| part == "..");
    if !host_ok || !path_ok || value.len() > MAX_HOME_BYTES {
        return None;
    }
    let scheme_len = value.len() - rest.len();
    let mut out = format!("{}{}/", &value[..scheme_len], authority);
    if !path.is_empty() {
        out.push_str(path);
        if !path.ends_with('/') {
            out.push('/');
        }
    }
    Some(out)
}

fn target(
    cms: &str,
    container: &str,
    root: String,
    uid: u32,
    gid: u32,
    site_url: Option<String>,
    project_root: Option<String>,
    need_url: bool,
) -> Result<Target, RequestError> {
    let cms = match cms {
        "wordpress" => Cms::WordPress,
        "joomla" => Cms::Joomla,
        "drupal" => Cms::Drupal,
        _ => return Err(RequestError::UnsupportedCms),
    };
    let site_url = match site_url {
        Some(value) => Some(base_url(&value).ok_or(RequestError::InvalidSiteUrl)?),
        None => None,
    };
    if cms != Cms::WordPress && need_url && site_url.is_none() {
        return Err(RequestError::SiteUrlRequired);
    }
    let plain = |value: &PathBuf| {
        value.is_absolute()
            && value.as_os_str().len() <= 4096
            && !value.to_string_lossy().chars().any(char::is_control)
            && !value
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
    };
    let project_root = match (cms, project_root) {
        (Cms::Drupal, Some(value)) => Some(PathBuf::from(value)),
        (Cms::Drupal, None) => return Err(RequestError::InvalidProjectRoot),
        (_, Some(_)) => return Err(RequestError::InvalidProjectRoot),
        (_, None) => None,
    };
    if project_root.as_ref().is_some_and(|value| !plain(value)) {
        return Err(RequestError::InvalidRoot);
    }
    let root = PathBuf::from(root);
    if !root.is_absolute()
        || root.as_os_str().len() > 4096
        || root
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(RequestError::InvalidRoot);
    }
    Ok(Target {
        cms,
        project_root,
        site_url,
        container: ContainerName::parse(container)
            .map_err(|_: RestoreRequestError| RequestError::InvalidContainer)?,
        root,
        uid,
        gid,
    })
}

impl Target {
    /// `docker exec` argv that runs `php` inside the site's container as the
    /// site user: `wp eval` for WordPress, `php -r` for Joomla.
    fn exec_php(&self, php: &str) -> Vec<String> {
        if self.cms == Cms::Joomla {
            return vec![
                "exec".to_owned(),
                "-i".to_owned(),
                "--user".to_owned(),
                format!("{}:{}", self.uid, self.gid),
                self.container.as_str().to_owned(),
                "php".to_owned(),
                "-r".to_owned(),
                php.to_owned(),
            ];
        }
        vec![
            "exec".to_owned(),
            "-i".to_owned(),
            "--user".to_owned(),
            format!("{}:{}", self.uid, self.gid),
            self.container.as_str().to_owned(),
            "wp".to_owned(),
            format!("--path={}", self.root.display()),
            "--allow-root".to_owned(),
            "eval".to_owned(),
            php.to_owned(),
        ]
    }
}

pub struct UsersRequest {
    target: Target,
}

impl UsersRequest {
    pub fn parse(json: &str) -> Result<Self, RequestError> {
        let plan: UsersPlan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        Ok(Self {
            target: target(
                &plan.cms,
                &plan.container,
                plan.root,
                plan.uid,
                plan.gid,
                plan.site_url,
                plan.project_root,
                false,
            )?,
        })
    }

    pub fn root(&self) -> &std::path::Path {
        &self.target.root
    }
}

pub struct LoginRequest {
    target: Target,
    admin_user_id: u64,
    ttl_seconds: u64,
    request_id: RequestId,
    idempotency_key: IdempotencyKey,
}

impl LoginRequest {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: LoginPlan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        let target = target(
            &plan.cms,
            &plan.container,
            plan.root,
            plan.uid,
            plan.gid,
            plan.site_url,
            plan.project_root,
            true,
        )?;
        if plan.admin_user_id == 0 || plan.admin_user_id > u64::from(u32::MAX) {
            return Err(RequestError::InvalidUserId);
        }
        if target.cms == Cms::Drupal && plan.ttl_seconds.is_some() {
            return Err(RequestError::TtlNotSupported);
        }
        let ttl_seconds = plan.ttl_seconds.unwrap_or(DEFAULT_TTL_SECS);
        if !(MIN_TTL_SECS..=MAX_TTL_SECS).contains(&ttl_seconds) {
            return Err(RequestError::InvalidTtl);
        }
        Ok(Self {
            target,
            admin_user_id: plan.admin_user_id,
            ttl_seconds,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: IdempotencyKey::parse(
                key.ok_or(RequestError::IdempotencyKeyRequired)?,
            )
            .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }

    pub fn root(&self) -> &std::path::Path {
        &self.target.root
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminUser {
    pub id: u64,
    pub login: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUsersResult {
    pub users: Vec<AdminUser>,
    /// More administrators exist than the 50 returned.
    pub truncated: bool,
}

/// The part of a login result that is stored and replayed. No link.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminLoginPublic {
    pub admin_user_id: u64,
    pub admin_login: String,
    pub issued_at_unix_secs: u64,
    pub expires_at_unix_secs: u64,
    /// Honest caveats of the CMS mechanism (empty for WordPress and Joomla).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limits: Vec<String>,
}

/// The one-time part. Only ever lives in the response.
#[derive(Serialize)]
pub struct AdminLoginSecret {
    pub url: String,
}

pub type AdminLoginResult = SecretResult<AdminLoginPublic, AdminLoginSecret>;

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
    TooLarge,
    BadOutput,
    UserNotFound,
    NotAnAdministrator,
    CannotWrite,
    TooManyLinks,
    /// Drush is not installed for this site (`drupal.installDrush`).
    DrushMissing,
    UnsupportedVersion,
    /// The link was issued but the transaction record could not be saved.
    PostCommit(AdminLoginResult),
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        let fixed = |code, message: &str| (code, message.to_owned());
        match self {
            Self::Preflight(preflight::Error::Lock(_)) | Self::ResourceBusy => fixed(
                ErrorCode::Conflict,
                "another operation is already in progress for this site",
            ),
            Self::ReplayInProgress => fixed(
                ErrorCode::Conflict,
                "the original request is still in progress",
            ),
            Self::Cancelled => fixed(ErrorCode::Cancelled, "cancelled before a link was issued"),
            Self::Run(error) => fixed(
                process::spawn_error_code(error),
                "could not run the CMS for the admin login",
            ),
            Self::Rejected(diagnostics) => fixed(
                if diagnostics.timed_out {
                    ErrorCode::Timeout
                } else if diagnostics.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::SubprocessFailed
                },
                "the CMS rejected the admin login request",
            ),
            Self::TooLarge | Self::BadOutput => {
                fixed(ErrorCode::Internal, "the CMS returned an unexpected answer")
            }
            Self::UserNotFound => fixed(ErrorCode::NotFound, "no such user on this site"),
            Self::NotAnAdministrator => fixed(
                ErrorCode::PermissionDenied,
                "the user is not an administrator",
            ),
            Self::CannotWrite => fixed(
                ErrorCode::SubprocessFailed,
                "the site directory for the login file is not writable",
            ),
            Self::TooManyLinks => fixed(
                ErrorCode::Conflict,
                "too many unexpired login links are outstanding; wait a few minutes",
            ),
            Self::DrushMissing => fixed(
                ErrorCode::DependencyUnavailable,
                "Drush is not installed for this site; run drupal.installDrush first",
            ),
            Self::UnsupportedVersion => fixed(
                ErrorCode::InvalidInput,
                "this Drupal version is not supported for one-time login",
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit(_) => {
                fixed(ErrorCode::Internal, "internal admin login error")
            }
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// 244 random bits as 64 lowercase hex characters (two v4 UUIDs).
fn new_token() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

fn token_hash(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

/// The mu-plugin that redeems one token. Only a hash, a timestamp and a user
/// id are interpolated, each from a closed charset.
pub fn mu_plugin_source(hash: &str, expires_at: u64, user_id: u64) -> String {
    assert!(hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()));
    format!(
        r#"<?php
// Generated by operations-engine (site.adminLogin). One-time admin login:
// valid until {expires_at}, deletes itself on use or expiry. Safe to delete.
defined('ABSPATH') || exit;
(static function () {{
    $hash = '{hash}'; $expires = {expires_at}; $user_id = {user_id};
    if (time() >= $expires) {{ @unlink(__FILE__); return; }}
    $token = isset($_GET['{TOKEN_PARAMETER}']) ? $_GET['{TOKEN_PARAMETER}'] : null;
    if (!is_string($token) || !preg_match('/^[0-9a-f]{{64}}$/', $token)) {{ return; }}
    if (!hash_equals($hash, hash('sha256', $token))) {{ return; }}
    if (!@unlink(__FILE__)) {{ return; }}
    add_action('init', static function () use ($user_id) {{
        nocache_headers();
        header('Referrer-Policy: no-referrer');
        $user = get_userdata($user_id);
        if (!$user || !in_array('administrator', (array) $user->roles, true)) {{ wp_die('This login link is not valid.', '', array('response' => 403)); }}
        wp_set_current_user($user_id);
        wp_set_auth_cookie($user_id, false);
        do_action('wp_login', $user->user_login, $user);
        wp_safe_redirect(admin_url());
        exit;
    }}, 0);
}})();
"#
    )
}

/// The Joomla entry file. Only a hash, a timestamp, a user id and the
/// validated admin URL are interpolated, each from a closed charset. Any
/// request that does not carry the right token gets a plain 404 and leaves the
/// file alone; the right token deletes the file first (atomic), so only one
/// concurrent request can continue.
pub fn joomla_entry_source(hash: &str, expires_at: u64, user_id: u64, admin_url: &str) -> String {
    assert!(hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(!admin_url.contains(['\'', '\\', '\n']));
    format!(
        r#"<?php
// Generated by operations-engine (site.adminLogin). One-time Joomla administrator
// login: valid until {expires_at}, deletes itself on use or expiry. Safe to delete.
(static function () {{
    $hash = '{hash}'; $expires = {expires_at}; $user_id = {user_id}; $admin = '{admin_url}';
    $notfound = static function () {{ http_response_code(404); header('Content-Type: text/plain'); echo 'Not found'; exit; }};
    if (time() >= $expires) {{ @unlink(__FILE__); $notfound(); }}
    $token = isset($_GET['{TOKEN_PARAMETER}']) ? $_GET['{TOKEN_PARAMETER}'] : null;
    if (!is_string($token) || !preg_match('/^[0-9a-f]{{64}}$/', $token)) {{ $notfound(); }}
    if (!hash_equals($hash, hash('sha256', $token))) {{ $notfound(); }}
    if (!@unlink(__FILE__)) {{ $notfound(); }}
    $deny = static function () {{ http_response_code(403); header('Content-Type: text/plain'); echo 'This login link is not valid.'; exit; }};
    try {{
        define('_JEXEC', 1);
        define('JPATH_BASE', __DIR__ . '/administrator');
        require_once JPATH_BASE . '/includes/defines.php';
        require_once JPATH_BASE . '/includes/framework.php';
        $container = \Joomla\CMS\Factory::getContainer();
        $container->alias('session.web', 'session.web.administrator')
            ->alias('session', 'session.web.administrator')
            ->alias('JSession', 'session.web.administrator')
            ->alias(\Joomla\CMS\Session\Session::class, 'session.web.administrator')
            ->alias(\Joomla\Session\Session::class, 'session.web.administrator')
            ->alias(\Joomla\Session\SessionInterface::class, 'session.web.administrator');
        $app = $container->get(\Joomla\CMS\Application\AdministratorApplication::class);
        \Joomla\CMS\Factory::$application = $app;
        $app->getDispatcher()->addListener('onAfterInitialise', static function () use ($app, $user_id, $admin, $deny) {{
            $user = \Joomla\CMS\User\User::getInstance($user_id);
            if (!$user->id || (int) $user->block !== 0 || !$user->authorise('core.admin')) {{ $deny(); }}
            $dispatcher = $app->getDispatcher();
            \Joomla\CMS\Plugin\PluginHelper::importPlugin('user', null, true, $dispatcher);
            $response = new \Joomla\CMS\Authentication\AuthenticationResponse();
            $response->status = \Joomla\CMS\Authentication\Authentication::STATUS_SUCCESS;
            $response->type = 'Joomla'; $response->username = $user->username; $response->fullname = $user->name; $response->email = $user->email;
            $options = array('action' => 'core.login.admin', 'group' => 'Public Backend', 'autoregister' => false, 'remember' => false);
            $login = new \Joomla\CMS\Event\User\LoginEvent('onUserLogin', array('subject' => (array) $response, 'options' => $options));
            $dispatcher->dispatch('onUserLogin', $login);
            if (in_array(false, $login['result'] ?? array(), true)) {{ $deny(); }}
            $options['user'] = \Joomla\CMS\Factory::getUser(); $options['responseType'] = 'Joomla';
            $dispatcher->dispatch('onUserAfterLogin', new \Joomla\CMS\Event\User\AfterLoginEvent('onUserAfterLogin', array('options' => $options, 'subject' => (array) $response)));
            header('Cache-Control: no-store'); header('Referrer-Policy: no-referrer');
            $app->redirect($admin);
        }}, \Joomla\Event\Priority::MAX);
        $app->execute();
    }} catch (\Throwable $e) {{
        $deny();
    }}
    exit;
}})();
"#
    )
}

/// The last non-empty stdout line, parsed as JSON (WordPress may print
/// notices before it).
fn last_json(bytes: &[u8]) -> Result<serde_json::Value, Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::BadOutput)?;
    let line = text
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .ok_or(Error::BadOutput)?;
    serde_json::from_str(line).map_err(|_| Error::BadOutput)
}

fn run_php(
    ctx: &Context<'_>,
    target: &Target,
    php: &str,
    stdin: Option<&[u8]>,
    cancel: &CancellationToken,
) -> Result<serde_json::Value, Error> {
    let args = target.exec_php(php);
    let request = ProcessRequest::new(ctx.docker_program).args(&args);
    let limits = ProcessLimits {
        timeout: TIMEOUT,
        max_stdout_bytes: MAX_OUTPUT_BYTES,
        max_stderr_bytes: MAX_OUTPUT_BYTES,
    };
    let output = match stdin {
        Some(input) => process::run_with_stdin_bytes(&request, input, &limits, cancel),
        None => process::run(&request, &limits, cancel),
    }
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
    if output.stdout.truncated || output.stderr.truncated {
        return Err(Error::TooLarge);
    }
    last_json(&output.stdout.bytes)
}

fn valid_login(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_LOGIN_BYTES && !value.chars().any(char::is_control)
}

/// `site.adminUsers`: read-only, bounded to 50, ids and logins only.
pub fn list_users(
    ctx: &Context<'_>,
    req: &UsersRequest,
    cancel: &CancellationToken,
) -> Result<AdminUsersResult, Error> {
    let answer = match req.target.cms {
        Cms::WordPress => run_php(ctx, &req.target, USERS_PHP, None, cancel)?,
        Cms::Drupal => {
            let bytes = run_drush(ctx, &req.target, &["php:eval", DRUPAL_USERS_PHP], cancel)?;
            last_json(&bytes)?
        }
        Cms::Joomla => {
            let plan = serde_json::to_vec(&serde_json::json!({ "root": req.target.root }))
                .map_err(|_| Error::BadOutput)?;
            let php = format!("{JOOMLA_BOOT_PHP}{JOOMLA_USERS_PHP}");
            run_php(ctx, &req.target, &php, Some(&plan), cancel)?
        }
    };
    if answer.get("ok").and_then(|value| value.as_bool()) != Some(true) {
        return Err(Error::BadOutput);
    }
    let rows = answer
        .get("users")
        .and_then(|value| value.as_array())
        .ok_or(Error::BadOutput)?;
    let mut users = Vec::new();
    for row in rows {
        let id = row
            .get("id")
            .and_then(|value| value.as_u64())
            .ok_or(Error::BadOutput)?;
        let login = row
            .get("login")
            .and_then(|value| value.as_str())
            .filter(|value| valid_login(value))
            .ok_or(Error::BadOutput)?;
        users.push(AdminUser {
            id,
            login: login.to_owned(),
        });
    }
    let truncated = users.len() > MAX_ADMIN_USERS;
    users.truncate(MAX_ADMIN_USERS);
    Ok(AdminUsersResult { users, truncated })
}

fn valid_home(value: &str) -> bool {
    value.len() <= MAX_HOME_BYTES
        && (value.starts_with("https://") || value.starts_with("http://"))
        && !value.contains(['?', '#', ' '])
        && !value.chars().any(char::is_control)
        && value.ends_with('/')
}

/// What a CMS-specific step produced: the link and its facts.
struct Minted {
    url: String,
    login: String,
    expires_at: u64,
    limits: Vec<String>,
}

/// Validates the administrator and produces the one-time link for the
/// request's CMS. Nothing here persists the link.
fn mint(
    ctx: &Context<'_>,
    req: &LoginRequest,
    issued_at: u64,
    cancel: &CancellationToken,
) -> Result<Minted, Error> {
    if req.target.cms == Cms::Drupal {
        return mint_drupal(ctx, req, cancel);
    }
    let expires_at = issued_at + req.ttl_seconds;
    let token = new_token();
    let hash = token_hash(&token);
    let (plan, php, entry_file) = match req.target.cms {
        // Drupal returned above, through `mint_drupal`.
        Cms::Drupal => return Err(Error::BadOutput),
        Cms::WordPress => (
            serde_json::json!({
                "userId": req.admin_user_id,
                "expires": expires_at,
                "source": mu_plugin_source(&hash, expires_at, req.admin_user_id),
            }),
            LOGIN_PHP.to_owned(),
            None,
        ),
        Cms::Joomla => {
            let site_url = req.target.site_url.as_deref().unwrap_or_default();
            let name = format!("wcp-otl-{expires_at}-{}", &new_token()[..16]);
            let name = format!("{name}.php");
            (
                serde_json::json!({
                    "root": req.target.root,
                    "userId": req.admin_user_id,
                    "name": name,
                    "source": joomla_entry_source(
                        &hash,
                        expires_at,
                        req.admin_user_id,
                        &format!("{site_url}administrator/index.php"),
                    ),
                }),
                format!("{JOOMLA_BOOT_PHP}{JOOMLA_LOGIN_PHP}"),
                Some(name),
            )
        }
    };
    let plan = serde_json::to_vec(&plan).unwrap();
    let answer = match run_php(ctx, &req.target, &php, Some(&plan), cancel) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    if answer.get("ok").and_then(|value| value.as_bool()) != Some(true) {
        let code = answer
            .get("error")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        return Err(reject(code));
    }
    let home = match &entry_file {
        // The Joomla entry file sits in the Joomla root, next to index.php.
        Some(name) => req
            .target
            .site_url
            .as_deref()
            .map(|base| format!("{base}{name}")),
        None => answer
            .get("home")
            .and_then(|value| value.as_str())
            .filter(|value| valid_home(value))
            .map(str::to_owned),
    };
    let login = answer
        .get("login")
        .and_then(|value| value.as_str())
        .filter(|value| valid_login(value));
    let (Some(home), Some(login)) = (home, login) else {
        return Err(Error::BadOutput);
    };

    Ok(Minted {
        url: format!("{home}?{TOKEN_PARAMETER}={token}"),
        login: login.to_owned(),
        expires_at,
        limits: Vec::new(),
    })
}

fn reject(code: &str) -> Error {
    match code {
        "notFound" => Error::UserNotFound,
        "notAdmin" => Error::NotAnAdministrator,
        "busy" => Error::TooManyLinks,
        "cannotWrite" => Error::CannotWrite,
        "unsupported" => Error::UnsupportedVersion,
        _ => Error::BadOutput,
    }
}

/// `site.adminLogin`. Returns the public record plus the one-time URL.
pub fn issue_login(
    ctx: &Context<'_>,
    req: &LoginRequest,
    cancel: &CancellationToken,
) -> Result<Issued, Error> {
    let hash = resource_lock::canonical_hash(&req.target.root);
    let scope_path = SiteRelativePath::parse(format!("site-admin-login/{hash}")).unwrap();
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
    let _resource_lock = resource_lock::acquire(ctx.engine_state, &req.target.root, req.request_id)
        .map_err(|_| Error::ResourceBusy)?;

    let admitted = match preflight::run(
        &scope,
        req.request_id,
        Some(&req.idempotency_key),
        LOGIN_OPERATION,
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
    let abort = |state: crate::transaction::state::TransactionState, error: Error| {
        fail(&scope, &state_path, &audit_path, state, error)
    };

    if cancel.is_cancelled() {
        return Err(abort(state, Error::Cancelled));
    }

    let issued_at = now_secs();
    let minted = match mint(ctx, req, issued_at, cancel) {
        Ok(value) => value,
        Err(error) => return Err(abort(state, error)),
    };

    let result = SecretResult::new(
        AdminLoginPublic {
            admin_user_id: req.admin_user_id,
            admin_login: minted.login,
            issued_at_unix_secs: issued_at,
            expires_at_unix_secs: minted.expires_at,
            limits: minted.limits,
        },
        AdminLoginSecret { url: minted.url },
    );
    // Only the public half is ever handed to storage.
    state
        .mark_committed(
            result
                .public_value()
                .map_err(|_| Error::Io(std::io::Error::other("result could not be encoded")))?,
        )
        .unwrap();
    if state::save(&scope, &state_path, &state).is_err() {
        drop(lock);
        return Err(Error::PostCommit(result));
    }
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(req.request_id, true, None),
    );
    drop(lock);
    Ok(Issued::New(result))
}

/// The outcome of `site.adminLogin`.
#[derive(Debug)]
pub enum Issued {
    /// A fresh link, carrying the one-time secret.
    New(AdminLoginResult),
    /// An idempotent replay: the stored public record only. The link was
    /// never stored and cannot be returned again.
    AlreadyIssued(serde_json::Value),
}

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<Issued, Error> {
    let path = SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap();
    let loaded = state::load(scope, &path)
        .map_err(|error| Error::Io(std::io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != LOGIN_OPERATION {
        return Err(Error::Io(std::io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => Ok(Issued::AlreadyIssued(
            loaded
                .outcome
                .and_then(|outcome| outcome.result)
                .unwrap_or_default(),
        )),
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

    const ID_1: &str = "123e4567-e89b-12d3-a456-426614174001";
    const ID_2: &str = "123e4567-e89b-12d3-a456-426614174002";
    const ID_3: &str = "123e4567-e89b-12d3-a456-426614174003";
    const PLAN: &str = r#"{"cms":"wordpress","container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1001,"adminUserId":7}"#;

    fn managed(directory: &Path) -> ManagedRoot {
        ManagedRoot::open(&crate::site::TrustedRoot::parse(directory).unwrap()).unwrap()
    }

    /// A fake `docker` that records argv and stdin per call and prints the
    /// contents of `answer.txt`.
    fn fake_docker(directory: &Path, answer: &str) -> String {
        fs::write(directory.join("answer.txt"), answer).unwrap();
        let path = directory.join("fake-docker");
        let body = format!(
            "#!/bin/sh\nd='{d}'\nn=$(ls \"$d\" | grep -c '^stdin\\.')\nprintf '%s\\n' \"$@\" > \"$d/argv.$n\"\ncat > \"$d/stdin.$n\"\ncat \"$d/answer.txt\"\n",
            d = directory.display()
        );
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn ok_answer() -> String {
        "PHP Notice: something noisy\n{\"ok\":true,\"home\":\"https://example.com/\",\"login\":\"alice\",\"file\":\"wcp-otl-1-aa.php\"}\n".to_owned()
    }

    fn login_request(id: &str, key: &str) -> LoginRequest {
        LoginRequest::parse(PLAN, id, Some(key)).unwrap()
    }

    fn token_of(url: &str) -> String {
        url.split("wcp_otl=").nth(1).unwrap().to_owned()
    }

    fn read_all(directory: &Path, out: &mut String) {
        for entry in fs::read_dir(directory).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                read_all(&path, out);
            } else if let Ok(text) = fs::read_to_string(&path) {
                out.push_str(&text);
            }
        }
    }

    #[test]
    fn the_request_is_validated() {
        let with = |extra: &str| PLAN.replacen('}', extra, 1);
        assert!(LoginRequest::parse(PLAN, ID_1, Some("k1")).is_ok());
        assert_eq!(
            LoginRequest::parse(PLAN, ID_1, None).err(),
            Some(RequestError::IdempotencyKeyRequired)
        );
        for ttl in [0, 59, 601] {
            assert_eq!(
                LoginRequest::parse(&with(&format!(",\"ttlSeconds\":{ttl}}}")), ID_1, Some("k"))
                    .err(),
                Some(RequestError::InvalidTtl)
            );
        }
        for ttl in [60, 600] {
            assert!(
                LoginRequest::parse(&with(&format!(",\"ttlSeconds\":{ttl}}}")), ID_1, Some("k"))
                    .is_ok()
            );
        }
        assert_eq!(
            LoginRequest::parse(&PLAN.replace("wordpress", "typo3"), ID_1, Some("k")).err(),
            Some(RequestError::UnsupportedCms)
        );
        assert_eq!(
            LoginRequest::parse(
                &PLAN.replace("\"adminUserId\":7", "\"adminUserId\":0"),
                ID_1,
                Some("k")
            )
            .err(),
            Some(RequestError::InvalidUserId)
        );
        assert_eq!(
            LoginRequest::parse(
                &PLAN.replace("/var/www/site", "/var/www/../etc"),
                ID_1,
                Some("k")
            )
            .err(),
            Some(RequestError::InvalidRoot)
        );
        assert_eq!(
            LoginRequest::parse(&PLAN.replace("runtime-1", "bad;name"), ID_1, Some("k")).err(),
            Some(RequestError::InvalidContainer)
        );
        assert!(LoginRequest::parse(&with(",\"extra\":1}"), ID_1, Some("k")).is_err());
    }

    #[test]
    fn the_mu_plugin_holds_only_a_hash_and_is_valid_php() {
        let token = new_token();
        assert_eq!(token.len(), 64);
        let hash = token_hash(&token);
        let source = mu_plugin_source(&hash, 1_900_000_000, 7);
        assert!(source.contains(&hash));
        assert!(!source.contains(&token));
        assert!(source.contains("hash_equals"));
        assert!(source.contains("@unlink(__FILE__)"));
        if let Ok(output) = std::process::Command::new("php").arg("-v").output() {
            if output.status.success() {
                let directory = tempfile::tempdir().unwrap();
                let file = directory.path().join("p.php");
                fs::write(&file, &source).unwrap();
                let lint = std::process::Command::new("php")
                    .arg("-l")
                    .arg(&file)
                    .output()
                    .unwrap();
                assert!(lint.status.success(), "{lint:?}");
            }
        }
    }

    #[test]
    fn issuing_returns_a_link_once_and_stores_no_token_anywhere() {
        let directory = tempfile::tempdir().unwrap();
        let state_dir = directory.path().join("state");
        fs::create_dir(&state_dir).unwrap();
        let work = directory.path().join("work");
        fs::create_dir(&work).unwrap();
        let docker = fake_docker(&work, &ok_answer());
        let state = managed(&state_dir);
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };

        let issued = issue_login(
            &ctx,
            &login_request(ID_1, "key-1"),
            &CancellationToken::default(),
        )
        .unwrap();
        let Issued::New(result) = issued else {
            panic!("expected a new link");
        };
        let response =
            crate::protocol::Response::success_with_secret(LOGIN_OPERATION, result).unwrap();
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["secretResult"], true);
        let url = json["result"]["url"].as_str().unwrap().to_owned();
        let token = token_of(&url);
        assert!(url.starts_with("https://example.com/?wcp_otl="));
        assert_eq!(token.len(), 64);
        assert_eq!(json["result"]["adminLogin"], "alice");
        assert_eq!(json["result"]["adminUserId"], 7);
        let expires = json["result"]["expiresAtUnixSecs"].as_u64().unwrap();
        let issued_at = json["result"]["issuedAtUnixSecs"].as_u64().unwrap();
        assert_eq!(expires - issued_at, 300);

        // The container saw the hash and the source, never the token.
        let argv = fs::read_to_string(work.join("argv.0")).unwrap();
        let stdin = fs::read_to_string(work.join("stdin.0")).unwrap();
        assert!(!argv.contains(&token));
        assert!(!stdin.contains(&token));
        assert!(stdin.contains(&token_hash(&token)));
        assert!(argv.contains("--user\n1000:1001\nruntime-1\nwp\n--path=/var/www/site"));

        // Nothing the engine persisted contains the token or the link.
        let mut persisted = String::new();
        read_all(&state_dir, &mut persisted);
        assert!(!persisted.is_empty());
        assert!(
            !persisted.contains(&token),
            "token leaked into engine state"
        );
        assert!(!persisted.contains("wcp_otl"));
        assert!(!persisted.contains("https://example.com"));
        assert!(persisted.contains("\"adminLogin\":\"alice\""));
    }

    #[test]
    fn a_replay_returns_the_public_record_without_a_link_and_does_not_call_wordpress_again() {
        let directory = tempfile::tempdir().unwrap();
        let state_dir = directory.path().join("state");
        fs::create_dir(&state_dir).unwrap();
        let work = directory.path().join("work");
        fs::create_dir(&work).unwrap();
        let docker = fake_docker(&work, &ok_answer());
        let state = managed(&state_dir);
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };
        let cancel = CancellationToken::default();
        let Issued::New(first) = issue_login(&ctx, &login_request(ID_1, "key-1"), &cancel).unwrap()
        else {
            panic!("expected a new link");
        };
        let expires = first.public().expires_at_unix_secs;

        // Same key, new request id: the retry the panel would make.
        let Issued::AlreadyIssued(public) =
            issue_login(&ctx, &login_request(ID_2, "key-1"), &cancel).unwrap()
        else {
            panic!("a replay must not mint a link");
        };
        let response = crate::secret_result::replayed(LOGIN_OPERATION, public).unwrap();
        let json = serde_json::to_string(&response).unwrap();
        assert!(!json.contains("wcp_otl"));
        assert!(!json.contains("\"url\""));
        assert!(!json.contains("secretResult"));
        assert!(json.contains("\"alreadyIssued\":true"));
        assert!(json.contains("SECRET_RESULT_ALREADY_ISSUED"));
        assert!(json.contains(&format!("\"expiresAtUnixSecs\":{expires}")));
        assert!(
            !work.join("stdin.1").exists(),
            "replay must not touch WordPress"
        );

        // A new key is a new link, with a different token.
        let Issued::New(second) =
            issue_login(&ctx, &login_request(ID_3, "key-2"), &cancel).unwrap()
        else {
            panic!("a new key mints a new link");
        };
        let first_hash = fs::read_to_string(work.join("stdin.0")).unwrap();
        let second_hash = fs::read_to_string(work.join("stdin.1")).unwrap();
        assert_ne!(first_hash, second_hash);
        let _ = second;
    }

    #[test]
    fn wordpress_refusals_map_to_stable_errors_and_are_replayed_as_errors() {
        for (answer, code) in [
            ("{\"ok\":false,\"error\":\"notFound\"}", ErrorCode::NotFound),
            (
                "{\"ok\":false,\"error\":\"notAdmin\"}",
                ErrorCode::PermissionDenied,
            ),
            ("{\"ok\":false,\"error\":\"busy\"}", ErrorCode::Conflict),
            (
                "{\"ok\":false,\"error\":\"cannotWrite\"}",
                ErrorCode::SubprocessFailed,
            ),
            ("not json", ErrorCode::Internal),
            (
                "{\"ok\":true,\"home\":\"https://e.com/?x=1\",\"login\":\"a\"}",
                ErrorCode::Internal,
            ),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let state_dir = directory.path().join("state");
            fs::create_dir(&state_dir).unwrap();
            let work = directory.path().join("work");
            fs::create_dir(&work).unwrap();
            let docker = fake_docker(&work, answer);
            let state = managed(&state_dir);
            let ctx = Context {
                engine_state: &state,
                docker_program: &docker,
            };
            let cancel = CancellationToken::default();
            let error = issue_login(&ctx, &login_request(ID_1, "key-1"), &cancel).unwrap_err();
            assert_eq!(error.protocol().0, code, "{answer}");
            let replayed = issue_login(&ctx, &login_request(ID_2, "key-1"), &cancel).unwrap_err();
            assert_eq!(replayed.protocol().0, code, "{answer}");
        }
    }

    #[test]
    fn lists_administrators_bounded_to_fifty() {
        let directory = tempfile::tempdir().unwrap();
        let state_dir = directory.path().join("state");
        fs::create_dir(&state_dir).unwrap();
        let work = directory.path().join("work");
        fs::create_dir(&work).unwrap();
        let rows: Vec<String> = (1..=51)
            .map(|id| format!("{{\"id\":{id},\"login\":\"admin{id}\"}}"))
            .collect();
        let docker = fake_docker(
            &work,
            &format!(
                "Deprecated: x\n{{\"ok\":true,\"users\":[{}]}}\n",
                rows.join(",")
            ),
        );
        let state = managed(&state_dir);
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };
        let request = UsersRequest::parse(
            r#"{"cms":"wordpress","container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1001}"#,
        )
        .unwrap();
        let result = list_users(&ctx, &request, &CancellationToken::default()).unwrap();
        assert_eq!(result.users.len(), 50);
        assert!(result.truncated);
        assert_eq!(result.users[0].login, "admin1");
        let argv = fs::read_to_string(work.join("argv.0")).unwrap();
        assert!(argv.contains("get_users"));
        assert!(!argv.contains("user_email"));
    }

    const JOOMLA_PLAN: &str = r#"{"cms":"joomla","container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1001,"adminUserId":7,"siteUrl":"https://example.com"}"#;

    fn joomla_answer() -> String {
        "Deprecated: noise\n{\"ok\":true,\"login\":\"alice\",\"file\":\"x.php\"}\n".to_owned()
    }

    #[test]
    fn joomla_requests_need_a_clean_site_url() {
        assert!(LoginRequest::parse(JOOMLA_PLAN, ID_1, Some("k")).is_ok());
        let without = JOOMLA_PLAN.replace(",\"siteUrl\":\"https://example.com\"", "");
        assert_eq!(
            LoginRequest::parse(&without, ID_1, Some("k")).err(),
            Some(RequestError::SiteUrlRequired)
        );
        for bad in [
            "ftp://example.com",
            "https://user@example.com",
            "https://example.com/?a=1",
            "https://example.com/#x",
            "https://example.com/a b",
            "https://example.com/../x",
            "https://example.com/'x",
        ] {
            assert_eq!(
                LoginRequest::parse(
                    &JOOMLA_PLAN.replace("https://example.com", bad),
                    ID_1,
                    Some("k")
                )
                .err(),
                Some(RequestError::InvalidSiteUrl),
                "{bad}"
            );
        }
        assert_eq!(
            base_url("http://h.test:8080/sub").as_deref(),
            Some("http://h.test:8080/sub/")
        );
        assert_eq!(
            base_url("https://h.test/").as_deref(),
            Some("https://h.test/")
        );
        // Users listing does not need a URL.
        assert!(UsersRequest::parse(
            r#"{"cms":"joomla","container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1001}"#
        )
        .is_ok());
    }

    #[test]
    fn the_joomla_entry_file_holds_only_a_hash_and_is_valid_php() {
        let token = new_token();
        let hash = token_hash(&token);
        let source = joomla_entry_source(
            &hash,
            1_900_000_000,
            7,
            "https://e.com/administrator/index.php",
        );
        assert!(source.contains(&hash) && !source.contains(&token));
        assert!(source.contains("hash_equals") && source.contains("@unlink(__FILE__)"));
        assert!(source.contains("core.login.admin"));
        // The file is deleted before Joomla is loaded.
        assert!(source.find("@unlink(__FILE__)").unwrap() < source.find("_JEXEC").unwrap());
        if let Ok(output) = std::process::Command::new("php").arg("-v").output() {
            if output.status.success() {
                let directory = tempfile::tempdir().unwrap();
                let file = directory.path().join("p.php");
                fs::write(&file, &source).unwrap();
                let lint = std::process::Command::new("php")
                    .arg("-l")
                    .arg(&file)
                    .output()
                    .unwrap();
                assert!(lint.status.success(), "{lint:?}");
            }
        }
    }

    #[test]
    fn joomla_login_runs_php_in_the_container_and_never_sends_the_token() {
        let directory = tempfile::tempdir().unwrap();
        let state_dir = directory.path().join("state");
        fs::create_dir(&state_dir).unwrap();
        let work = directory.path().join("work");
        fs::create_dir(&work).unwrap();
        let docker = fake_docker(&work, &joomla_answer());
        let state = managed(&state_dir);
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };
        let request = LoginRequest::parse(JOOMLA_PLAN, ID_1, Some("key-1")).unwrap();
        let Issued::New(result) =
            issue_login(&ctx, &request, &CancellationToken::default()).unwrap()
        else {
            panic!("expected a new link");
        };
        let response =
            crate::protocol::Response::success_with_secret(LOGIN_OPERATION, result).unwrap();
        let json = serde_json::to_value(&response).unwrap();
        let url = json["result"]["url"].as_str().unwrap().to_owned();
        let token = token_of(&url);
        assert!(url.starts_with("https://example.com/wcp-otl-"), "{url}");
        assert!(url.contains(".php?wcp_otl="));
        assert_eq!(json["result"]["adminLogin"], "alice");
        let argv = fs::read_to_string(work.join("argv.0")).unwrap();
        let stdin = fs::read_to_string(work.join("stdin.0")).unwrap();
        assert!(argv.contains("--user\n1000:1001\nruntime-1\nphp\n-r\n"));
        assert!(!argv.contains(&token) && !stdin.contains(&token));
        assert!(stdin.contains(&token_hash(&token)));
        assert!(stdin.contains("administrator/index.php"));
        let mut persisted = String::new();
        read_all(&state_dir, &mut persisted);
        assert!(!persisted.contains(&token) && !persisted.contains("wcp_otl"));
    }

    #[test]
    fn joomla_lists_super_users_through_php_with_the_root_on_stdin() {
        let directory = tempfile::tempdir().unwrap();
        let state_dir = directory.path().join("state");
        fs::create_dir(&state_dir).unwrap();
        let work = directory.path().join("work");
        fs::create_dir(&work).unwrap();
        let docker = fake_docker(
            &work,
            "{\"ok\":true,\"users\":[{\"id\":936,\"login\":\"alice\"}]}\n",
        );
        let state = managed(&state_dir);
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };
        let request = UsersRequest::parse(
            r#"{"cms":"joomla","container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1001}"#,
        )
        .unwrap();
        let result = list_users(&ctx, &request, &CancellationToken::default()).unwrap();
        assert_eq!(result.users[0].id, 936);
        assert!(!result.truncated);
        let stdin = fs::read_to_string(work.join("stdin.0")).unwrap();
        assert!(stdin.contains("/var/www/site"));
        let argv = fs::read_to_string(work.join("argv.0")).unwrap();
        assert!(argv.contains("core.admin") && argv.contains("php\n-r"));
    }

    const DRUPAL_PLAN: &str = r#"{"cms":"drupal","container":"runtime-1","root":"/var/www/site/web","projectRoot":"/var/www/site","uid":1000,"gid":1001,"adminUserId":2,"siteUrl":"https://example.com"}"#;

    /// A fake `docker` that tells the Drush calls apart by their last argument.
    fn fake_drush_docker(directory: &Path, uli: &str, exit: i32) -> String {
        let path = directory.join("fake-docker");
        let body = format!(
            "#!/bin/sh\nd='{d}'\nn=$(ls \"$d\" | grep -c '^argv\\.')\nprintf '%s\\n' \"$@\" > \"$d/argv.$n\"\ncase \"$*\" in\n*php:eval*) echo 'notice'; echo '{{\"ok\":true,\"login\":\"alice\",\"timeout\":86400}}' ;;\n*) [ {exit} -ne 0 ] && exit {exit}; echo '{uli}' ;;\nesac\n",
            d = directory.display()
        );
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn drupal_requests_need_a_project_root_and_refuse_a_ttl() {
        assert!(LoginRequest::parse(DRUPAL_PLAN, ID_1, Some("k")).is_ok());
        let no_project = DRUPAL_PLAN.replace("\"projectRoot\":\"/var/www/site\",", "");
        assert_eq!(
            LoginRequest::parse(&no_project, ID_1, Some("k")).err(),
            Some(RequestError::InvalidProjectRoot)
        );
        let ttl = DRUPAL_PLAN.replace("\"adminUserId\":2", "\"adminUserId\":2,\"ttlSeconds\":120");
        assert_eq!(
            LoginRequest::parse(&ttl, ID_1, Some("k")).err(),
            Some(RequestError::TtlNotSupported)
        );
        assert_eq!(
            LoginRequest::parse(
                &PLAN.replace("\"uid\"", "\"projectRoot\":\"/x\",\"uid\""),
                ID_1,
                Some("k")
            )
            .err(),
            Some(RequestError::InvalidProjectRoot)
        );
        let nourl = DRUPAL_PLAN.replace(",\"siteUrl\":\"https://example.com\"", "");
        assert_eq!(
            LoginRequest::parse(&nourl, ID_1, Some("k")).err(),
            Some(RequestError::SiteUrlRequired)
        );
    }

    #[test]
    fn the_drush_link_is_parsed_strictly() {
        let base = "https://example.com";
        let ok = "https://example.com/user/reset/2/1700000000/abc_DEF-123/login";
        assert_eq!(parse_uli(ok, base, 2), Some(1_700_000_000));
        assert_eq!(parse_uli(ok, base, 3), None);
        assert_eq!(parse_uli(ok, "https://other.test", 2), None);
        for bad in [
            "https://example.com/user/reset/2/1700000000/abc/login?x=1",
            "https://example.com/user/reset/2/1700000000/abc/edit",
            "https://example.com/user/reset/2/x/abc/login",
            "https://example.com/user/reset/2/1700000000/a b/login",
            "http://default/user/reset/2/1700000000/abc/login",
        ] {
            assert_eq!(parse_uli(bad, base, 2), None, "{bad}");
        }
    }

    #[test]
    fn drupal_login_uses_drush_and_reports_the_site_lifetime() {
        let directory = tempfile::tempdir().unwrap();
        let state_dir = directory.path().join("state");
        fs::create_dir(&state_dir).unwrap();
        let work = directory.path().join("work");
        fs::create_dir(&work).unwrap();
        let link = "https://example.com/user/reset/2/1700000000/hashHASH/login";
        let docker = fake_drush_docker(&work, link, 0);
        let state = managed(&state_dir);
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };
        let request = LoginRequest::parse(DRUPAL_PLAN, ID_1, Some("key-1")).unwrap();
        let Issued::New(result) =
            issue_login(&ctx, &request, &CancellationToken::default()).unwrap()
        else {
            panic!("expected a new link");
        };
        let response =
            crate::protocol::Response::success_with_secret(LOGIN_OPERATION, result).unwrap();
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["result"]["url"], link);
        assert_eq!(json["result"]["expiresAtUnixSecs"], 1_700_086_400u64);
        assert_eq!(json["result"]["limits"][0], "ttlFromSiteSettings");
        assert_eq!(json["result"]["limits"][1], "singleUseNotRaceSafe");
        let eval = fs::read_to_string(work.join("argv.0")).unwrap();
        let uli = fs::read_to_string(work.join("argv.1")).unwrap();
        assert!(eval.contains("-w\n/var/www/site\nruntime-1\nsh\n"));
        assert!(
            eval.contains("--root=/var/www/site/web")
                && eval.contains("--uri=https://example.com\n")
        );
        assert!(eval.contains("php:eval") && eval.contains("$uid = 2;"));
        assert!(uli.contains("user:login\n--no-browser\n--uid=2"));
        // The link is never stored.
        let mut persisted = String::new();
        read_all(&state_dir, &mut persisted);
        assert!(!persisted.contains("hashHASH") && !persisted.contains("/user/reset"));
        assert!(persisted.contains("singleUseNotRaceSafe"));
    }

    #[test]
    fn drupal_without_drush_is_a_dependency_error() {
        let directory = tempfile::tempdir().unwrap();
        let state_dir = directory.path().join("state");
        fs::create_dir(&state_dir).unwrap();
        let work = directory.path().join("work");
        fs::create_dir(&work).unwrap();
        let path = work.join("fake-docker");
        fs::write(&path, "#!/bin/sh\nexit 97\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        let state = managed(&state_dir);
        let docker = path.to_string_lossy().into_owned();
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };
        let request = LoginRequest::parse(DRUPAL_PLAN, ID_1, Some("key-1")).unwrap();
        let error = issue_login(&ctx, &request, &CancellationToken::default()).unwrap_err();
        assert_eq!(error.protocol().0, ErrorCode::DependencyUnavailable);
    }
}
