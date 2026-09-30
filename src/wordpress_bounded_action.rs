//! The `wordpress.boundedAction` operation: a small, fixed set of one-shot
//! WordPress mutations that each previously ran as an unvalidated raw
//! `docker exec ... wp ...` call from `website-control-panel` - creating a
//! subsite in a multisite network, flipping a multisite network between
//! subdomain and subdirectory mode, and clearing all WooCommerce
//! transients. None of the three has enough independent shape to justify
//! its own operation module (unlike, say, `wordpress.multisiteDeleteSite`,
//! which has a real destructive-boundary invariant to enforce on `blogId`),
//! so they share one lock/idempotency/transaction/audit-backed request with
//! an internal `action.kind` discriminator instead. A future bounded action
//! with its own nontrivial validation or recovery story should get its own
//! operation module rather than growing the match arm here.
//!
//! It also carries the typed replacements for the panel's former free-form
//! `wp:cli` mutations (cache/rewrite flush, salts, cron, a fixed set of
//! boolean `wp-config.php` flags, maintenance mode, users, search-replace,
//! the site URL and plugin installation). Every kind maps to fixed argv;
//! the only secret (a new user's password) travels on stdin to a fixed
//! `wp eval` script and never reaches argv or the recorded output. A kind
//! may run several steps in order; a failure after the first reports how
//! many steps were already applied, since none of them is rolled back.

use crate::{
    db_restore::{ContainerName, RestoreRequestError},
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{
        self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination,
        SubprocessDiagnostics,
    },
    site::{Domain, SiteRelativePath},
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

pub const OPERATION: &str = "wordpress.boundedAction";

const MAX_TITLE_BYTES: usize = 200;
const MAX_EMAIL_BYTES: usize = 254;
/// A subdirectory-network slug becomes both a URL path segment and a
/// filesystem directory name; bounded to the same per-label length WP-CLI's
/// own multisite defaults tolerate comfortably.
const MAX_SLUG_BYTES: usize = 63;
const STEP_TIMEOUT: Duration = Duration::from_secs(120);
const LONG_STEP_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const MAX_HOOK_BYTES: usize = 200;
const MAX_LOGIN_BYTES: usize = 60;
const MAX_PASSWORD_BYTES: usize = 1024;
const MAX_REPLACE_BYTES: usize = 2048;
const MAX_PLUGIN_SLUG_BYTES: usize = 100;

/// Creates one user from a stdin JSON plan with `wp_insert_user`, so the
/// password is never an argv element (WP-CLI's `--prompt` would echo it
/// back in the reconstructed command). Fixed text; nothing is interpolated.
pub const USER_CREATE_PHP: &str = r#"$plan = json_decode(stream_get_contents(STDIN), true);
if (!is_array($plan) || !isset($plan['login'], $plan['email'], $plan['role'])) { fwrite(STDERR, "invalid plan\n"); exit(2); }
if (!get_role((string) $plan['role'])) { fwrite(STDERR, "unknown role\n"); exit(3); }
$password = isset($plan['password']) && $plan['password'] !== '' ? (string) $plan['password'] : wp_generate_password(24, true, true);
$id = wp_insert_user(array('user_login' => (string) $plan['login'], 'user_email' => (string) $plan['email'], 'role' => (string) $plan['role'], 'user_pass' => $password));
if (is_wp_error($id)) { fwrite(STDERR, $id->get_error_message() . "\n"); exit(1); }
echo "Success: Created user {$id}.\n";"#;
const MAX_STEP_OUTPUT_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    container: String,
    root: String,
    uid: u32,
    gid: u32,
    action: ActionPlan,
}

#[derive(Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum ActionPlan {
    MultisiteCreateSite {
        title: String,
        email: String,
        slug: Option<String>,
        url: Option<String>,
    },
    MultisiteSetMode {
        subdomain: bool,
    },
    WooClearTransients {},
    CacheFlush {},
    RewriteFlush {},
    ShuffleSalts {},
    CronRun {
        hook: Option<String>,
    },
    CronDelete {
        hook: String,
    },
    SetConfigFlag {
        name: ConfigFlag,
        value: bool,
    },
    Maintenance {
        active: bool,
    },
    UserCreate {
        login: String,
        email: String,
        role: String,
        password: Option<String>,
    },
    UserSetRole {
        id: u64,
        role: String,
    },
    UserDelete {
        id: u64,
    },
    SearchReplace {
        from: String,
        to: String,
        dry_run: bool,
    },
    SetSiteUrl {
        url: String,
        replace_from: Option<String>,
    },
    PluginInstall {
        slug: String,
    },
}

/// The only `wp-config.php` constants the panel toggles, always as a raw
/// PHP boolean.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub enum ConfigFlag {
    #[serde(rename = "WP_DEBUG")]
    WpDebug,
    #[serde(rename = "WP_DEBUG_LOG")]
    WpDebugLog,
    #[serde(rename = "DISABLE_WP_CRON")]
    DisableWpCron,
    #[serde(rename = "AUTOMATIC_UPDATER_DISABLED")]
    AutomaticUpdaterDisabled,
    #[serde(rename = "WP_AUTO_UPDATE_CORE")]
    WpAutoUpdateCore,
}

impl ConfigFlag {
    const fn name(self) -> &'static str {
        match self {
            Self::WpDebug => "WP_DEBUG",
            Self::WpDebugLog => "WP_DEBUG_LOG",
            Self::DisableWpCron => "DISABLE_WP_CRON",
            Self::AutomaticUpdaterDisabled => "AUTOMATIC_UPDATER_DISABLED",
            Self::WpAutoUpdateCore => "WP_AUTO_UPDATE_CORE",
        }
    }
}

/// A value that must never appear in `Debug` output.
#[derive(Clone)]
struct Secret(String);

impl std::fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("[redacted]")
    }
}

#[derive(Clone, Debug)]
enum Action {
    MultisiteCreateSite {
        title: String,
        email: String,
        target: CreateSiteTarget,
    },
    MultisiteSetMode {
        subdomain: bool,
    },
    WooClearTransients,
    CacheFlush,
    RewriteFlush,
    ShuffleSalts,
    CronRun(Option<String>),
    CronDelete(String),
    SetConfigFlag(ConfigFlag, bool),
    Maintenance(bool),
    UserCreate {
        login: String,
        email: String,
        role: String,
        password: Option<Secret>,
    },
    UserSetRole(u64, String),
    UserDelete(u64),
    SearchReplace {
        from: String,
        to: String,
        dry_run: bool,
    },
    SetSiteUrl {
        url: String,
        replace_from: Option<String>,
    },
    PluginInstall(String),
}

#[derive(Clone, Debug)]
enum CreateSiteTarget {
    Slug(String),
    Url(Domain),
}

#[derive(Debug)]
pub struct Request {
    container: ContainerName,
    root: PathBuf,
    uid: u32,
    gid: u32,
    action: Action,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    InvalidRoot,
    InvalidContainer,
    InvalidRequestId,
    InvalidIdempotencyKey,
    InvalidAction,
}

/// A permissive structural email check - one `@`, non-empty local/domain
/// parts, no whitespace or NUL - not a full RFC 5322 validator. `wp site
/// create` itself is the authority on whether the address is actually
/// usable; this only keeps obviously-malformed input from ever reaching
/// argv.
fn validate_email(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_EMAIL_BYTES
        || value.bytes().any(|b| b == 0 || b.is_ascii_whitespace())
    {
        return false;
    }
    let mut parts = value.splitn(2, '@');
    matches!(
        (parts.next(), parts.next()),
        (Some(local), Some(domain))
            if !local.is_empty() && !domain.is_empty() && !domain.contains('@')
    )
}

fn validate_title(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TITLE_BYTES && !value.bytes().any(|b| b == 0)
}

/// Lowercase ASCII letters, digits, or hyphens; never starting or ending
/// with a hyphen; 1-63 bytes - the same per-label character class
/// `site::Domain` enforces. This is what rejects a slug such as `--evil`,
/// which is otherwise a plausible-looking bare word: leading `-` is exactly
/// the byte this excludes, closing off any confusion with a WP-CLI flag
/// even though the slug is always passed as one `--slug=<value>` argv
/// element rather than a bare word.
fn validate_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SLUG_BYTES
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn no_control(value: &str) -> bool {
    !value.chars().any(char::is_control)
}

/// Bounded free text that becomes one argv element: never empty, never a
/// control character, and never starting with `-`, so WP-CLI cannot read
/// it as a flag.
fn validate_arg(value: &str, max_len: usize) -> bool {
    !value.is_empty() && value.len() <= max_len && !value.starts_with('-') && no_control(value)
}

/// Cron hook names are PHP action names: identifier-like, with the
/// separators plugins commonly use.
fn validate_hook(value: &str) -> bool {
    validate_arg(value, MAX_HOOK_BYTES)
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':' | b'/'))
}

fn validate_role(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

fn validate_url(value: &str) -> bool {
    (value.starts_with("https://") || value.starts_with("http://"))
        && value.len() <= MAX_REPLACE_BYTES
        && !value
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
}

/// A wordpress.org plugin slug.
fn validate_plugin_slug(value: &str) -> bool {
    validate_slug_bytes(value, MAX_PLUGIN_SLUG_BYTES)
}

fn validate_slug_bytes(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl ActionPlan {
    fn validate(self) -> Result<Action, RequestError> {
        match self {
            Self::MultisiteCreateSite {
                title,
                email,
                slug,
                url,
            } => {
                if !validate_title(&title) || !validate_email(&email) {
                    return Err(RequestError::InvalidAction);
                }
                let target = match (slug, url) {
                    (Some(slug), None) if validate_slug(&slug) => CreateSiteTarget::Slug(slug),
                    (None, Some(url)) => CreateSiteTarget::Url(
                        Domain::parse(&url).map_err(|_| RequestError::InvalidAction)?,
                    ),
                    _ => return Err(RequestError::InvalidAction),
                };
                Ok(Action::MultisiteCreateSite {
                    title,
                    email,
                    target,
                })
            }
            Self::MultisiteSetMode { subdomain } => Ok(Action::MultisiteSetMode { subdomain }),
            Self::WooClearTransients {} => Ok(Action::WooClearTransients),
            Self::CacheFlush {} => Ok(Action::CacheFlush),
            Self::RewriteFlush {} => Ok(Action::RewriteFlush),
            Self::ShuffleSalts {} => Ok(Action::ShuffleSalts),
            Self::CronRun { hook } => match hook {
                None => Ok(Action::CronRun(None)),
                Some(hook) if validate_hook(&hook) => Ok(Action::CronRun(Some(hook))),
                Some(_) => Err(RequestError::InvalidAction),
            },
            Self::CronDelete { hook } if validate_hook(&hook) => Ok(Action::CronDelete(hook)),
            Self::SetConfigFlag { name, value } => Ok(Action::SetConfigFlag(name, value)),
            Self::Maintenance { active } => Ok(Action::Maintenance(active)),
            Self::UserCreate {
                login,
                email,
                role,
                password,
            } if validate_arg(login.trim(), MAX_LOGIN_BYTES)
                && validate_email(&email)
                && validate_role(&role)
                && password
                    .as_deref()
                    .is_none_or(|p| p.len() <= MAX_PASSWORD_BYTES && no_control(p)) =>
            {
                Ok(Action::UserCreate {
                    login: login.trim().to_owned(),
                    email,
                    role,
                    password: password.filter(|p| !p.is_empty()).map(Secret),
                })
            }
            Self::UserSetRole { id, role } if id >= 1 && validate_role(&role) => {
                Ok(Action::UserSetRole(id, role))
            }
            // Content is reassigned to user 1, so user 1 itself is never a
            // valid deletion target here.
            Self::UserDelete { id } if id >= 2 => Ok(Action::UserDelete(id)),
            Self::SearchReplace { from, to, dry_run }
                if validate_arg(&from, MAX_REPLACE_BYTES)
                    && validate_arg(&to, MAX_REPLACE_BYTES)
                    && from != to =>
            {
                Ok(Action::SearchReplace { from, to, dry_run })
            }
            Self::SetSiteUrl { url, replace_from }
                if validate_url(&url)
                    && replace_from
                        .as_deref()
                        .is_none_or(|from| validate_arg(from, MAX_REPLACE_BYTES)) =>
            {
                Ok(Action::SetSiteUrl {
                    replace_from: replace_from.filter(|from| from != &url),
                    url,
                })
            }
            Self::PluginInstall { slug } if validate_plugin_slug(&slug) => {
                Ok(Action::PluginInstall(slug))
            }
            _ => Err(RequestError::InvalidAction),
        }
    }
}

impl Request {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        let root = PathBuf::from(plan.root);
        if !root.is_absolute()
            || root.as_os_str().len() > 4096
            || root
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(RequestError::InvalidRoot);
        }
        let action = plan.action.validate()?;
        Ok(Self {
            container: ContainerName::parse(&plan.container)
                .map_err(|_: RestoreRequestError| RequestError::InvalidContainer)?,
            root,
            uid: plan.uid,
            gid: plan.gid,
            action,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }

    pub fn root(&self) -> &std::path::Path {
        &self.root
    }

    fn wp(&self, tail: &[&str]) -> Vec<String> {
        let mut args = vec![
            "exec".to_owned(),
            "-i".to_owned(),
            "--user".to_owned(),
            format!("{}:{}", self.uid, self.gid),
            self.container.as_str().to_owned(),
            "wp".to_owned(),
            format!("--path={}", self.root.display()),
            "--allow-root".to_owned(),
        ];
        args.extend(tail.iter().map(|arg| (*arg).to_owned()));
        args
    }

    fn steps(&self) -> Vec<Step> {
        let step = |args: Vec<String>| Step {
            args,
            stdin: None,
            timeout: STEP_TIMEOUT,
        };
        let long = |args: Vec<String>| Step {
            args,
            stdin: None,
            timeout: LONG_STEP_TIMEOUT,
        };
        match &self.action {
            Action::MultisiteCreateSite {
                title,
                email,
                target,
            } => {
                let target = match target {
                    CreateSiteTarget::Slug(slug) => format!("--slug={slug}"),
                    CreateSiteTarget::Url(url) => format!("--url={url}"),
                };
                vec![step(self.wp(&[
                    "site",
                    "create",
                    &target,
                    &format!("--title={title}"),
                    &format!("--email={email}"),
                ]))]
            }
            Action::MultisiteSetMode { subdomain } => vec![step(self.wp(&[
                "config",
                "set",
                "SUBDOMAIN_INSTALL",
                if *subdomain { "1" } else { "0" },
                "--raw",
            ]))],
            Action::WooClearTransients => vec![step(self.wp(&["transient", "delete", "--all"]))],
            Action::CacheFlush => vec![step(self.wp(&["cache", "flush"]))],
            Action::RewriteFlush => vec![step(self.wp(&["rewrite", "flush"]))],
            Action::ShuffleSalts => vec![step(self.wp(&["config", "shuffle-salts"]))],
            Action::CronRun(None) => vec![long(self.wp(&["cron", "event", "run", "--due-now"]))],
            Action::CronRun(Some(hook)) => vec![long(self.wp(&["cron", "event", "run", hook]))],
            Action::CronDelete(hook) => vec![step(self.wp(&["cron", "event", "delete", hook]))],
            Action::SetConfigFlag(flag, value) => vec![step(self.wp(&[
                "config",
                "set",
                flag.name(),
                if *value { "true" } else { "false" },
                "--raw",
            ]))],
            Action::Maintenance(active) => vec![step(self.wp(&[
                "maintenance-mode",
                if *active { "activate" } else { "deactivate" },
            ]))],
            Action::UserCreate {
                login,
                email,
                role,
                password,
            } => {
                let plan = serde_json::json!({
                    "login": login, "email": email, "role": role,
                    "password": password.as_ref().map(|secret| secret.0.as_str()),
                });
                vec![Step {
                    args: self.wp(&["eval", USER_CREATE_PHP]),
                    stdin: Some(plan.to_string().into_bytes()),
                    timeout: STEP_TIMEOUT,
                }]
            }
            Action::UserSetRole(id, role) => vec![step(self.wp(&[
                "user",
                "update",
                &id.to_string(),
                &format!("--role={role}"),
            ]))],
            Action::UserDelete(id) => vec![step(self.wp(&[
                "user",
                "delete",
                &id.to_string(),
                "--yes",
                "--reassign=1",
            ]))],
            Action::SearchReplace { from, to, dry_run } => {
                let mut tail = vec!["search-replace", from.as_str(), to.as_str(), "--all-tables"];
                if *dry_run {
                    tail.push("--dry-run");
                }
                vec![long(self.wp(&tail))]
            }
            Action::SetSiteUrl { url, replace_from } => {
                let mut steps = vec![
                    step(self.wp(&["option", "update", "siteurl", url])),
                    step(self.wp(&["option", "update", "home", url])),
                ];
                if let Some(from) = replace_from {
                    steps.push(long(self.wp(&[
                        "search-replace",
                        from,
                        url,
                        "--all-tables",
                    ])));
                }
                steps
            }
            Action::PluginInstall(slug) => vec![Step {
                args: self.wp(&["plugin", "install", slug, "--activate"]),
                stdin: None,
                timeout: Duration::from_secs(3 * 60),
            }],
        }
    }
}

struct Step {
    args: Vec<String>,
    stdin: Option<Vec<u8>>,
    timeout: Duration,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BoundedActionResult {
    pub output: String,
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
    /// Step `failed` (1-based) of `total` was rejected after the earlier
    /// steps had already been applied; none of them is rolled back.
    StepRejected {
        failed: usize,
        total: usize,
        diagnostics: SubprocessDiagnostics,
    },
    TooLarge,
    InvalidUtf8,
    PostCommit {
        result: BoundedActionResult,
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
                "another WordPress bounded action for this site is in progress".into(),
            ),
            Self::ResourceBusy => (
                ErrorCode::Conflict,
                "another WordPress operation is already in progress for this site".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before the bounded action ran".into(),
            ),
            Self::Run(error) => (
                process::spawn_error_code(error),
                "could not run the WordPress bounded action".into(),
            ),
            Self::Rejected(diagnostics) => (
                if diagnostics.timed_out {
                    ErrorCode::Timeout
                } else if diagnostics.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::SubprocessFailed
                },
                "WordPress rejected the bounded action".into(),
            ),
            Self::StepRejected {
                failed,
                total,
                diagnostics,
            } => (
                if diagnostics.timed_out {
                    ErrorCode::Timeout
                } else {
                    ErrorCode::SubprocessFailed
                },
                format!(
                    "WordPress rejected step {failed} of {total}; the {} earlier step(s) were \
                     applied and were not rolled back",
                    failed - 1
                ),
            ),
            Self::TooLarge => (
                ErrorCode::Internal,
                "WordPress bounded action output exceeded its limit".into(),
            ),
            Self::InvalidUtf8 => (
                ErrorCode::Internal,
                "WordPress bounded action output was not valid UTF-8".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit { .. } => (
                ErrorCode::Internal,
                "internal WordPress bounded action error".into(),
            ),
        }
    }
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<BoundedActionResult, Error> {
    let hash = resource_lock::canonical_hash(&req.root);
    let scope_path = SiteRelativePath::parse(format!("wordpress-bounded-action/{hash}")).unwrap();
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
    let _resource_lock = resource_lock::acquire(ctx.engine_state, &req.root, req.request_id)
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

    if cancel.is_cancelled() {
        return Err(fail(
            &scope,
            &state_path,
            &audit_path,
            state,
            Error::Cancelled,
        ));
    }

    let steps = req.steps();
    let total = steps.len();
    let mut outputs = Vec::with_capacity(total);
    for (index, step) in steps.into_iter().enumerate() {
        // Once a step has been applied, the remaining ones must run to
        // completion rather than stop on a cancellation request.
        let step_cancel = if index == 0 {
            cancel.clone()
        } else {
            CancellationToken::default()
        };
        let request = ProcessRequest::new(ctx.docker_program).args(&step.args);
        let limits = ProcessLimits {
            timeout: step.timeout,
            max_stdout_bytes: MAX_STEP_OUTPUT_BYTES,
            max_stderr_bytes: MAX_STEP_OUTPUT_BYTES,
        };
        let run = match &step.stdin {
            Some(input) => process::run_with_stdin_bytes(&request, input, &limits, &step_cancel),
            None => process::run(&request, &limits, &step_cancel),
        };
        let output = match run {
            Ok(value) => value,
            Err(error) => {
                return Err(fail(
                    &scope,
                    &state_path,
                    &audit_path,
                    state,
                    Error::Run(error),
                ));
            }
        };
        if !matches!(
            output.termination,
            ProcessTermination::Exited { success: true, .. }
        ) {
            let diagnostics = SubprocessDiagnostics::from_output(ctx.docker_program, &output);
            let error = if index == 0 {
                Error::Rejected(diagnostics)
            } else {
                Error::StepRejected {
                    failed: index + 1,
                    total,
                    diagnostics,
                }
            };
            return Err(fail(&scope, &state_path, &audit_path, state, error));
        }
        if output.stdout.truncated || output.stderr.truncated {
            return Err(fail(
                &scope,
                &state_path,
                &audit_path,
                state,
                Error::TooLarge,
            ));
        }
        let bytes = if output.stdout.bytes.is_empty() {
            output.stderr.bytes
        } else {
            output.stdout.bytes
        };
        match String::from_utf8(bytes) {
            Ok(value) => outputs.push(value),
            Err(_) => {
                return Err(fail(
                    &scope,
                    &state_path,
                    &audit_path,
                    state,
                    Error::InvalidUtf8,
                ));
            }
        }
    }
    let output = outputs.join("\n");

    let result = BoundedActionResult {
        output,
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

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<BoundedActionResult, Error> {
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
    use std::{fs, os::unix::fs::PermissionsExt};

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    fn managed(directory: &std::path::Path) -> ManagedRoot {
        ManagedRoot::open(&crate::site::TrustedRoot::parse(directory).unwrap()).unwrap()
    }

    fn fake_docker(directory: &std::path::Path, exit: i32) -> String {
        let path = directory.join("fake-docker");
        fs::write(
            &path,
            format!("#!/bin/sh\nprintf '%s\\n' \"$@\"\nexit {exit}\n"),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn rejects_a_slug_that_looks_like_a_flag() {
        assert_eq!(
            Request::parse(
                r#"{"container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1000,
                    "action":{"kind":"multisiteCreateSite","title":"T","email":"a@b.com","slug":"--evil"}}"#,
                ID,
                None,
            )
            .unwrap_err(),
            RequestError::InvalidAction
        );
    }

    #[test]
    fn rejects_both_slug_and_url_or_neither() {
        assert_eq!(
            Request::parse(
                r#"{"container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1000,
                    "action":{"kind":"multisiteCreateSite","title":"T","email":"a@b.com"}}"#,
                ID,
                None,
            )
            .unwrap_err(),
            RequestError::InvalidAction
        );
        assert_eq!(
            Request::parse(
                r#"{"container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1000,
                    "action":{"kind":"multisiteCreateSite","title":"T","email":"a@b.com",
                    "slug":"news","url":"news.example.com"}}"#,
                ID,
                None,
            )
            .unwrap_err(),
            RequestError::InvalidAction
        );
    }

    #[test]
    fn rejects_a_malformed_email_and_an_escaping_root() {
        assert_eq!(
            Request::parse(
                r#"{"container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1000,
                    "action":{"kind":"multisiteCreateSite","title":"T","email":"not-an-email","slug":"news"}}"#,
                ID,
                None,
            )
            .unwrap_err(),
            RequestError::InvalidAction
        );
        assert_eq!(
            Request::parse(
                r#"{"container":"runtime-1","root":"../escape","uid":1000,"gid":1000,
                    "action":{"kind":"wooClearTransients"}}"#,
                ID,
                None,
            )
            .unwrap_err(),
            RequestError::InvalidRoot
        );
    }

    #[test]
    fn creates_a_site_by_slug_then_replays() {
        let state_dir = tempfile::tempdir().unwrap();
        let docker = fake_docker(state_dir.path(), 0);
        let state = managed(state_dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };
        let req = Request::parse(
            r#"{"container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1000,
                "action":{"kind":"multisiteCreateSite","title":"News","email":"a@b.com","slug":"news"}}"#,
            ID,
            Some("create-key"),
        )
        .unwrap();

        let first = execute(&ctx, &req, &CancellationToken::default()).unwrap();
        let second = execute(&ctx, &req, &CancellationToken::default()).unwrap();
        assert!(first.output.contains("--slug=news"));
        assert!(first.output.contains("--title=News"));
        assert!(first.output.contains("--email=a@b.com"));
        assert_eq!(first.completed_at_unix_secs, second.completed_at_unix_secs);
    }

    #[test]
    fn sets_multisite_mode() {
        let state_dir = tempfile::tempdir().unwrap();
        let docker = fake_docker(state_dir.path(), 0);
        let state = managed(state_dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };
        let req = Request::parse(
            r#"{"container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1000,
                "action":{"kind":"multisiteSetMode","subdomain":true}}"#,
            ID,
            None,
        )
        .unwrap();

        let result = execute(&ctx, &req, &CancellationToken::default()).unwrap();
        assert!(result.output.contains("SUBDOMAIN_INSTALL"));
        assert!(result.output.contains("--raw"));
        let lines: Vec<_> = result.output.lines().collect();
        assert_eq!(lines[lines.len() - 2], "1");
    }

    #[test]
    fn clears_woocommerce_transients() {
        let state_dir = tempfile::tempdir().unwrap();
        let docker = fake_docker(state_dir.path(), 0);
        let state = managed(state_dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };
        let req = Request::parse(
            r#"{"container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1000,
                "action":{"kind":"wooClearTransients"}}"#,
            ID,
            None,
        )
        .unwrap();

        let result = execute(&ctx, &req, &CancellationToken::default()).unwrap();
        assert!(result.output.contains("transient"));
        assert!(result.output.contains("delete"));
        assert!(result.output.contains("--all"));
    }

    #[test]
    fn a_rejected_action_is_reported_and_can_be_retried() {
        let state_dir = tempfile::tempdir().unwrap();
        let docker = fake_docker(state_dir.path(), 1);
        let state = managed(state_dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };
        let req = Request::parse(
            r#"{"container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1000,
                "action":{"kind":"wooClearTransients"}}"#,
            ID,
            None,
        )
        .unwrap();

        let result = execute(&ctx, &req, &CancellationToken::default());
        assert!(matches!(result, Err(Error::Rejected(_))));
    }

    fn plan(action: &str) -> String {
        format!(
            r#"{{"container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1000,"action":{action}}}"#
        )
    }

    /// Logs each call's argv as one `|`-joined line and its stdin to
    /// `stdin.log`; exits `exit_on_call_n` on that 1-based call, else 0.
    fn logging_docker(directory: &std::path::Path, fail_call: usize) -> String {
        let path = directory.join("logging-docker");
        fs::write(
            &path,
            format!(
                r#"#!/bin/sh
DIR="$(dirname "$0")"
n=$(( $(cat "$DIR/count" 2>/dev/null || echo 0) + 1 )); echo $n > "$DIR/count"
out=""; for a in "$@"; do out="$out|$a"; done; printf '%s\n' "$out" >> "$DIR/argv.log"
if [ "$*" != "${{*%eval*}}" ]; then cat >> "$DIR/stdin.log"; fi
[ $n -eq {fail_call} ] && exit 1
echo "step $n ok"
"#
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn run_logged(
        action: &str,
        fail_call: usize,
    ) -> (tempfile::TempDir, Result<BoundedActionResult, Error>) {
        let dir = tempfile::tempdir().unwrap();
        let docker = logging_docker(dir.path(), fail_call);
        let state = managed(dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };
        let req = Request::parse(&plan(action), ID, None).unwrap();
        let result = execute(&ctx, &req, &CancellationToken::default());
        (dir, result)
    }

    fn argv_log(dir: &tempfile::TempDir) -> Vec<String> {
        fs::read_to_string(dir.path().join("argv.log"))
            .unwrap_or_default()
            .lines()
            .filter(|line| line.starts_with('|'))
            .map(|line| {
                let wp = line
                    .find("|--allow-root|")
                    .map_or(0, |at| at + "|--allow-root|".len());
                line[wp..].to_owned()
            })
            .collect()
    }

    #[test]
    fn each_typed_kind_maps_to_its_fixed_argv() {
        for (action, expected) in [
            (r#"{"kind":"cacheFlush"}"#, vec!["cache|flush"]),
            (r#"{"kind":"rewriteFlush"}"#, vec!["rewrite|flush"]),
            (r#"{"kind":"shuffleSalts"}"#, vec!["config|shuffle-salts"]),
            (r#"{"kind":"cronRun"}"#, vec!["cron|event|run|--due-now"]),
            (
                r#"{"kind":"cronRun","hook":"wp_version_check"}"#,
                vec!["cron|event|run|wp_version_check"],
            ),
            (
                r#"{"kind":"cronDelete","hook":"my_plugin/job"}"#,
                vec!["cron|event|delete|my_plugin/job"],
            ),
            (
                r#"{"kind":"setConfigFlag","name":"WP_DEBUG","value":true}"#,
                vec!["config|set|WP_DEBUG|true|--raw"],
            ),
            (
                r#"{"kind":"setConfigFlag","name":"DISABLE_WP_CRON","value":false}"#,
                vec!["config|set|DISABLE_WP_CRON|false|--raw"],
            ),
            (
                r#"{"kind":"maintenance","active":true}"#,
                vec!["maintenance-mode|activate"],
            ),
            (
                r#"{"kind":"maintenance","active":false}"#,
                vec!["maintenance-mode|deactivate"],
            ),
            (
                r#"{"kind":"userSetRole","id":7,"role":"editor"}"#,
                vec!["user|update|7|--role=editor"],
            ),
            (
                r#"{"kind":"userDelete","id":7}"#,
                vec!["user|delete|7|--yes|--reassign=1"],
            ),
            (
                r#"{"kind":"searchReplace","from":"a b'c","to":"x$y","dryRun":true}"#,
                vec!["search-replace|a b'c|x$y|--all-tables|--dry-run"],
            ),
            (
                r#"{"kind":"pluginInstall","slug":"redis-cache"}"#,
                vec!["plugin|install|redis-cache|--activate"],
            ),
            (
                r#"{"kind":"setSiteUrl","url":"https://new.example.com","replaceFrom":"https://old.example.com"}"#,
                vec![
                    "option|update|siteurl|https://new.example.com",
                    "option|update|home|https://new.example.com",
                    "search-replace|https://old.example.com|https://new.example.com|--all-tables",
                ],
            ),
            (
                r#"{"kind":"setSiteUrl","url":"https://same.example.com","replaceFrom":"https://same.example.com"}"#,
                vec![
                    "option|update|siteurl|https://same.example.com",
                    "option|update|home|https://same.example.com",
                ],
            ),
        ] {
            let (dir, result) = run_logged(action, 0);
            result.unwrap_or_else(|error| panic!("{action}: {error:?}"));
            assert_eq!(argv_log(&dir), expected, "{action}");
        }
    }

    #[test]
    fn a_new_users_password_travels_only_on_stdin() {
        let (dir, result) = run_logged(
            r#"{"kind":"userCreate","login":"bob","email":"bob@example.com","role":"editor","password":"p@$$ !w(0)rd"}"#,
            0,
        );
        result.unwrap();
        let argv = fs::read_to_string(dir.path().join("argv.log")).unwrap();
        assert!(!argv.contains("p@$$"));
        assert!(!argv.contains("bob@example.com"));
        assert!(argv.contains("|eval|"));
        let stdin: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(dir.path().join("stdin.log")).unwrap())
                .unwrap();
        assert_eq!(stdin["password"], "p@$$ !w(0)rd");
        assert_eq!(stdin["login"], "bob");

        let req = Request::parse(
            &plan(r#"{"kind":"userCreate","login":"bob","email":"b@e.com","role":"editor","password":"hunter2"}"#),
            ID,
            None,
        )
        .unwrap();
        assert!(!format!("{req:?}").contains("hunter2"));
    }

    #[test]
    fn a_later_step_failure_reports_the_steps_already_applied() {
        let (_dir, result) = run_logged(
            r#"{"kind":"setSiteUrl","url":"https://new.example.com","replaceFrom":"https://old.example.com"}"#,
            3,
        );
        let error = result.unwrap_err();
        assert!(matches!(
            error,
            Error::StepRejected {
                failed: 3,
                total: 3,
                ..
            }
        ));
        assert!(
            error
                .protocol()
                .1
                .contains("the 2 earlier step(s) were applied")
        );

        let (_dir, result) = run_logged(r#"{"kind":"cacheFlush"}"#, 1);
        assert!(matches!(result, Err(Error::Rejected(_))));
    }

    #[test]
    fn rejects_malformed_typed_actions() {
        for action in [
            r#"{"kind":"cronRun","hook":"--due-now"}"#,
            r#"{"kind":"cronDelete","hook":"a b"}"#,
            r#"{"kind":"setConfigFlag","name":"DB_PASSWORD","value":true}"#,
            r#"{"kind":"userCreate","login":"","email":"a@b.com","role":"editor"}"#,
            r#"{"kind":"userCreate","login":"bob","email":"nope","role":"editor"}"#,
            r#"{"kind":"userCreate","login":"bob","email":"a@b.com","role":"Admin!"}"#,
            r#"{"kind":"userCreate","login":"bob","email":"a@b.com","role":"editor","password":"line\nbreak"}"#,
            r#"{"kind":"userSetRole","id":0,"role":"editor"}"#,
            r#"{"kind":"userDelete","id":1}"#,
            r#"{"kind":"searchReplace","from":"--all","to":"x","dryRun":false}"#,
            r#"{"kind":"searchReplace","from":"same","to":"same","dryRun":false}"#,
            r#"{"kind":"setSiteUrl","url":"javascript:alert(1)"}"#,
            r#"{"kind":"setSiteUrl","url":"https://a b.com"}"#,
            r#"{"kind":"pluginInstall","slug":"../evil"}"#,
            r#"{"kind":"pluginInstall","slug":"https://evil.example/p.zip"}"#,
            r#"{"kind":"cacheFlush","extra":true}"#,
            r#"{"kind":"evalAnything","code":"phpinfo();"}"#,
        ] {
            assert_eq!(
                Request::parse(&plan(action), ID, None).unwrap_err(),
                if action.contains("evalAnything")
                    || action.contains("extra")
                    || action.contains("DB_PASSWORD")
                {
                    RequestError::InvalidJson
                } else {
                    RequestError::InvalidAction
                },
                "{action}"
            );
        }
    }
}
