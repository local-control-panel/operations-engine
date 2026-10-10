//! `site.adminUsers` and `site.adminLogin`: list a site's administrators and
//! mint a short-lived, single-use login link for one of them.
//!
//! WordPress only for now (`cms: "wordpress"`); Drupal (`drush uli`) and
//! Joomla are documented follow-ups and are refused with a clear error.
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UsersPlan {
    cms: String,
    container: String,
    root: String,
    uid: u32,
    gid: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LoginPlan {
    cms: String,
    container: String,
    root: String,
    uid: u32,
    gid: u32,
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
    InvalidRequestId,
    InvalidIdempotencyKey,
    /// `site.adminLogin` mutates and must be replay-safe.
    IdempotencyKeyRequired,
}

impl RequestError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::UnsupportedCms => {
                "one-time admin login is only implemented for WordPress (cms \"wordpress\")"
            }
            Self::IdempotencyKeyRequired => "site.adminLogin requires an idempotency key",
            Self::InvalidTtl => "ttlSeconds must be between 60 and 600",
            _ => "request-file is not a valid site admin plan",
        }
    }
}

struct Target {
    container: ContainerName,
    root: PathBuf,
    uid: u32,
    gid: u32,
}

fn target(
    cms: &str,
    container: &str,
    root: String,
    uid: u32,
    gid: u32,
) -> Result<Target, RequestError> {
    if cms != "wordpress" {
        return Err(RequestError::UnsupportedCms);
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
        container: ContainerName::parse(container)
            .map_err(|_: RestoreRequestError| RequestError::InvalidContainer)?,
        root,
        uid,
        gid,
    })
}

impl Target {
    fn wp_eval(&self, php: &str) -> Vec<String> {
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
            target: target(&plan.cms, &plan.container, plan.root, plan.uid, plan.gid)?,
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
        let target = target(&plan.cms, &plan.container, plan.root, plan.uid, plan.gid)?;
        if plan.admin_user_id == 0 || plan.admin_user_id > u64::from(u32::MAX) {
            return Err(RequestError::InvalidUserId);
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
                "could not run WordPress for the admin login",
            ),
            Self::Rejected(diagnostics) => fixed(
                if diagnostics.timed_out {
                    ErrorCode::Timeout
                } else if diagnostics.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::SubprocessFailed
                },
                "WordPress rejected the admin login request",
            ),
            Self::TooLarge | Self::BadOutput => fixed(
                ErrorCode::Internal,
                "WordPress returned an unexpected answer",
            ),
            Self::UserNotFound => fixed(ErrorCode::NotFound, "no such user on this site"),
            Self::NotAnAdministrator => fixed(
                ErrorCode::PermissionDenied,
                "the user is not an administrator",
            ),
            Self::CannotWrite => fixed(
                ErrorCode::SubprocessFailed,
                "the site's mu-plugins directory is not writable",
            ),
            Self::TooManyLinks => fixed(
                ErrorCode::Conflict,
                "too many unexpired login links are outstanding; wait a few minutes",
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
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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

fn run_wp(
    ctx: &Context<'_>,
    target: &Target,
    php: &str,
    stdin: Option<&[u8]>,
    cancel: &CancellationToken,
) -> Result<serde_json::Value, Error> {
    let args = target.wp_eval(php);
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
    let answer = run_wp(ctx, &req.target, USERS_PHP, None, cancel)?;
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

    let token = new_token();
    let issued_at = now_secs();
    let expires_at = issued_at + req.ttl_seconds;
    let plan = serde_json::json!({
        "userId": req.admin_user_id,
        "expires": expires_at,
        "source": mu_plugin_source(&token_hash(&token), expires_at, req.admin_user_id),
    });
    let plan = serde_json::to_vec(&plan).unwrap();
    let answer = match run_wp(ctx, &req.target, LOGIN_PHP, Some(&plan), cancel) {
        Ok(value) => value,
        Err(error) => return Err(abort(state, error)),
    };
    let reject = |code: &str| match code {
        "notFound" => Error::UserNotFound,
        "notAdmin" => Error::NotAnAdministrator,
        "busy" => Error::TooManyLinks,
        "cannotWrite" => Error::CannotWrite,
        _ => Error::BadOutput,
    };
    if answer.get("ok").and_then(|value| value.as_bool()) != Some(true) {
        let code = answer
            .get("error")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        return Err(abort(state, reject(code)));
    }
    let home = answer
        .get("home")
        .and_then(|value| value.as_str())
        .filter(|value| valid_home(value));
    let login = answer
        .get("login")
        .and_then(|value| value.as_str())
        .filter(|value| valid_login(value));
    let (Some(home), Some(login)) = (home, login) else {
        return Err(abort(state, Error::BadOutput));
    };

    let result = SecretResult::new(
        AdminLoginPublic {
            admin_user_id: req.admin_user_id,
            admin_login: login.to_owned(),
            issued_at_unix_secs: issued_at,
            expires_at_unix_secs: expires_at,
        },
        AdminLoginSecret {
            url: format!("{home}?{TOKEN_PARAMETER}={token}"),
        },
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
            LoginRequest::parse(&PLAN.replace("wordpress", "drupal"), ID_1, Some("k")).err(),
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
    fn operation_status_style_state_has_no_secret_either() {
        // The stored transaction outcome is exactly the public record.
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
        let Issued::New(result) = issue_login(
            &ctx,
            &login_request(ID_1, "key-1"),
            &CancellationToken::default(),
        )
        .unwrap() else {
            panic!()
        };
        let mut persisted = String::new();
        read_all(&state_dir, &mut persisted);
        let public = serde_json::to_string(result.public()).unwrap();
        assert!(persisted.contains(&public));
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
}
