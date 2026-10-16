//! `cms.maintenance`: one typed "site offline / online" switch for the CMSs
//! that have no maintenance operation of their own (WordPress has
//! `wordpress.boundedAction` `maintenance`, Drupal `drupal.maintenance`).
//!
//! * `joomla`: Joomla's own console, `php cli/joomla.php site:down` /
//!   `site:up` (it edits `offline` in `configuration.php` itself; the engine
//!   writes no file). The state is read back from `configuration.php`.
//! * `laravel`: `php artisan down --secret=<token>` / `php artisan up`. The
//!   engine generates the bypass token and returns it exactly once as a
//!   `secretResult`; it is never stored (the transaction state keeps only the
//!   public part), logged or journaled. The state is read back from
//!   `storage/framework/down`, so a project that keeps its maintenance state
//!   in the cache driver is reported as a mismatch, never as OK.
//!
//! The argv is fixed per kind; the caller supplies only the kind, an explicit
//! `on`/`off` and the validated container/root/UID/GID. Commands run as the
//! site user, never root, inside the site's runtime container from the project
//! root. The result carries no command output. Same lock/idempotency/
//! transaction/audit as the Drupal actions.

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
use std::{
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const OPERATION: &str = "cms.maintenance";

const CHECK_TIMEOUT: Duration = Duration::from_secs(60);
const RUN_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const MAX_OUTPUT: usize = 64 * 1024;
const SECRET_LEN: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Joomla,
    Laravel,
}

impl Kind {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "joomla" => Some(Self::Joomla),
            "laravel" => Some(Self::Laravel),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Joomla => "joomla",
            Self::Laravel => "laravel",
        }
    }

    /// The file whose presence proves the project root is this CMS.
    const fn entry_point(self) -> &'static str {
        match self {
            Self::Joomla => "./cli/joomla.php",
            Self::Laravel => "./artisan",
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    kind: String,
    /// `"on"` (site offline) or `"off"`.
    state: String,
    container: String,
    project_root: String,
    uid: u32,
    gid: u32,
}

#[derive(Debug)]
pub struct Request {
    pub kind: Kind,
    enabled: bool,
    container: ContainerName,
    project_root: PathBuf,
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

impl Request {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        let kind = Kind::parse(&plan.kind).ok_or(RequestError::InvalidKind)?;
        let enabled = match plan.state.as_str() {
            "on" => true,
            "off" => false,
            _ => return Err(RequestError::InvalidState),
        };
        let project_root = PathBuf::from(&plan.project_root);
        if !project_root.is_absolute()
            || plan.project_root.len() > 4096
            || plan.project_root.chars().any(char::is_control)
            || project_root
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(RequestError::InvalidRoot);
        }
        Ok(Self {
            kind,
            enabled,
            container: ContainerName::parse(&plan.container)
                .map_err(|_: RestoreRequestError| RequestError::InvalidContainer)?,
            project_root,
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

/// The part of the answer that may be stored and replayed.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MaintenanceResult {
    pub kind: String,
    /// The mode read back from the project after the change.
    pub maintenance_mode: bool,
    /// `false` when the project was already in the requested mode.
    pub changed: bool,
    /// Laravel `on`: a bypass token was issued (and returned once).
    pub secret_issued: bool,
    pub completed_at_unix_secs: u64,
}

/// The one-time Laravel bypass token; visit `/<token>` to get past the 503.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Bypass {
    pub bypass_secret: String,
}

pub enum Done {
    Plain(MaintenanceResult),
    Issued(SecretResult<MaintenanceResult, Bypass>),
    /// A replay of a request that issued a token: the public part only.
    AlreadyIssued(MaintenanceResult),
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
    /// The project root lacks the CMS entry point.
    NotThisCms(Kind),
    Rejected(SubprocessDiagnostics),
    /// The project did not report the mode that was just set.
    StateMismatch,
    Entropy,
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
                "could not run the maintenance command".into(),
            ),
            Self::NotThisCms(kind) => (
                ErrorCode::InvalidInput,
                format!(
                    "the project root has no {}, so it is not a supported {} project",
                    kind.entry_point().trim_start_matches("./"),
                    kind.name()
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
                    format!("the maintenance command reported an error{suffix}"),
                )
            }
            Self::StateMismatch => (
                ErrorCode::SubprocessFailed,
                "the application did not report the requested maintenance mode".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Entropy | Self::Preflight(_) => (
                ErrorCode::Internal,
                "internal maintenance action error".into(),
            ),
        }
    }
}

fn container_exec(
    ctx: &Context<'_>,
    req: &Request,
    argv: &[&str],
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
    args.extend(argv.iter().map(|arg| (*arg).to_owned()));
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

/// `offline` from the line `public $offline = <value>;` of Joomla's
/// `configuration.php`. Anything else is unknown, never "online".
fn joomla_offline(stdout: &[u8]) -> Option<bool> {
    let text = String::from_utf8_lossy(stdout);
    let value = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("public $offline"))?
        .trim()
        .strip_prefix('=')?
        .trim()
        .trim_end_matches(';')
        .trim()
        .trim_matches(['\'', '"']);
    match value {
        "1" | "true" | "TRUE" => Some(true),
        "0" | "false" | "FALSE" => Some(false),
        _ => None,
    }
}

fn read_joomla_offline(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<bool, Error> {
    let output = checked(
        ctx,
        container_exec(
            ctx,
            req,
            &[
                "grep",
                "-E",
                r"^\s*public\s+\$offline\s*=",
                "./configuration.php",
            ],
            CHECK_TIMEOUT,
            cancel,
        )?,
    )?;
    joomla_offline(&output.stdout.bytes).ok_or(Error::StateMismatch)
}

fn laravel_down(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<bool, Error> {
    Ok(exited_ok(&container_exec(
        ctx,
        req,
        &["test", "-f", "./storage/framework/down"],
        CHECK_TIMEOUT,
        cancel,
    )?))
}

/// 32 alphanumeric characters from the kernel's random source.
fn new_secret() -> Result<String, Error> {
    use std::io::Read;
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut urandom = std::fs::File::open("/dev/urandom").map_err(|_| Error::Entropy)?;
    let mut out = String::with_capacity(SECRET_LEN);
    let mut byte = [0u8; 1];
    while out.len() < SECRET_LEN {
        urandom.read_exact(&mut byte).map_err(|_| Error::Entropy)?;
        // 248 = 62 * 4: rejecting the rest keeps every character equally likely.
        if byte[0] < 248 {
            out.push(ALPHABET[usize::from(byte[0]) % ALPHABET.len()] as char);
        }
    }
    Ok(out)
}

/// What one run produced: the read-back mode, whether anything changed and
/// the one-time token, if one was issued.
struct Ran {
    mode: bool,
    changed: bool,
    secret: Option<String>,
}

fn run_joomla(ctx: &Context<'_>, req: &Request, cancel: &CancellationToken) -> Result<Ran, Error> {
    let before = read_joomla_offline(ctx, req, cancel)?;
    if before != req.enabled {
        let command = if req.enabled { "site:down" } else { "site:up" };
        checked(
            ctx,
            container_exec(
                ctx,
                req,
                &["php", "cli/joomla.php", command, "--no-interaction"],
                RUN_TIMEOUT,
                cancel,
            )?,
        )?;
    }
    let mode = read_joomla_offline(ctx, req, cancel)?;
    if mode != req.enabled {
        return Err(Error::StateMismatch);
    }
    Ok(Ran {
        mode,
        changed: before != req.enabled,
        secret: None,
    })
}

fn run_laravel(ctx: &Context<'_>, req: &Request, cancel: &CancellationToken) -> Result<Ran, Error> {
    let before = laravel_down(ctx, req, cancel)?;
    // `artisan down` on a site that is already down keeps the old secret, so
    // no new token is made up for it.
    let mut secret = None;
    if before != req.enabled {
        if req.enabled {
            let token = new_secret()?;
            let flag = format!("--secret={token}");
            checked(
                ctx,
                container_exec(
                    ctx,
                    req,
                    &["php", "artisan", "down", &flag, "--no-interaction"],
                    RUN_TIMEOUT,
                    cancel,
                )?,
            )?;
            secret = Some(token);
        } else {
            checked(
                ctx,
                container_exec(
                    ctx,
                    req,
                    &["php", "artisan", "up", "--no-interaction"],
                    RUN_TIMEOUT,
                    cancel,
                )?,
            )?;
        }
    }
    let mode = laravel_down(ctx, req, cancel)?;
    if mode != req.enabled {
        return Err(Error::StateMismatch);
    }
    Ok(Ran {
        mode,
        changed: before != req.enabled,
        secret,
    })
}

fn run(ctx: &Context<'_>, req: &Request, cancel: &CancellationToken) -> Result<Ran, Error> {
    let kind = req.kind;
    if !exited_ok(&container_exec(
        ctx,
        req,
        &["test", "-f", kind.entry_point()],
        CHECK_TIMEOUT,
        cancel,
    )?) {
        return Err(Error::NotThisCms(kind));
    }
    match kind {
        Kind::Joomla => run_joomla(ctx, req, cancel),
        Kind::Laravel => run_laravel(ctx, req, cancel),
    }
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<Done, Error> {
    let hash = resource_lock::canonical_hash(&req.project_root);
    let scope_path = SiteRelativePath::parse(format!("cms-maintenance/{hash}")).unwrap();
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
        run(ctx, req, cancel)
    };
    let ran = match outcome {
        Ok(ran) => ran,
        Err(error) => return Err(fail(&scope, &state_path, &audit_path, state, error)),
    };
    let public = MaintenanceResult {
        kind: req.kind.name().into(),
        maintenance_mode: ran.mode,
        changed: ran.changed,
        secret_issued: ran.secret.is_some(),
        completed_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    // Only the public part is persisted; the token never touches the state.
    state
        .mark_committed(serde_json::to_value(&public).unwrap())
        .unwrap();
    // The change is already made: a failed save must not turn it into an
    // error (a retry with the same key then finds the request unfinished).
    let _ = state::save(&scope, &state_path, &state);
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(req.request_id, true, None),
    );
    drop(lock);
    Ok(match ran.secret {
        Some(bypass_secret) => Done::Issued(SecretResult::new(public, Bypass { bypass_secret })),
        None => Done::Plain(public),
    })
}

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<Done, Error> {
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
            let public: MaintenanceResult =
                serde_json::from_value(loaded.outcome.unwrap().result.unwrap())
                    .map_err(|error| Error::Io(std::io::Error::other(error)))?;
            Ok(if public.secret_issued {
                Done::AlreadyIssued(public)
            } else {
                Done::Plain(public)
            })
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

    fn request(kind: &str, state: &str, id: &str, key: Option<&str>) -> Request {
        Request::parse(
            &format!(
                r#"{{"kind":"{kind}","state":"{state}","container":"runtime-1","projectRoot":"/var/www/site","uid":1000,"gid":1000}}"#
            ),
            id,
            key,
        )
        .unwrap()
    }

    /// A tiny fake site: `down` is the Laravel marker file / Joomla flag kept
    /// in `site.state`, flipped by the `down`/`site:down` and `up`/`site:up`
    /// commands. Every call is logged. `broken` makes the flip a no-op.
    fn fake_docker(directory: &std::path::Path, entry: bool, broken: bool) -> String {
        let log = directory.join("calls.log");
        let flag = directory.join("site.state");
        let path = directory.join("fake-docker");
        let flip = if broken { ":" } else { "touch" };
        let unflip = if broken { ":" } else { "rm -f" };
        fs::write(
            &path,
            format!(
                r#"#!/bin/sh
printf '%s\n' "$*" >> '{log}'
case "$*" in
  *" test -f ./storage/framework/down"*) [ -f '{flag}' ]; exit $? ;;
  *" test -f "*) exit {entry} ;;
  *"grep -E"*) if [ -f '{flag}' ]; then echo "public \$offline = true;"; else echo "public \$offline = false;"; fi; exit 0 ;;
  *" artisan down "*|*"site:down"*) {flip} '{flag}'; exit 0 ;;
  *" artisan up "*|*"site:up"*) {unflip} '{flag}'; exit 0 ;;
esac
exit 0
"#,
                log = log.display(),
                flag = flag.display(),
                entry = if entry { 0 } else { 1 },
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn log(directory: &std::path::Path) -> String {
        fs::read_to_string(directory.join("calls.log")).unwrap_or_default()
    }

    #[test]
    fn rejects_invalid_requests() {
        let with = |kind: &str, state: &str, extra: &str| {
            format!(
                r#"{{"kind":"{kind}","state":"{state}","container":"runtime-1","projectRoot":"/var/www/site","uid":1,"gid":1{extra}}}"#
            )
        };
        for kind in ["wordpress", "drupal"] {
            assert_eq!(
                Request::parse(&with(kind, "on", ""), ID, None).unwrap_err(),
                RequestError::InvalidKind
            );
        }
        assert_eq!(
            Request::parse(&with("joomla", "toggle", ""), ID, None).unwrap_err(),
            RequestError::InvalidState
        );
        assert_eq!(
            Request::parse(&with("laravel", "on", r#","secret":"x""#), ID, None).unwrap_err(),
            RequestError::InvalidJson
        );
        let traversal = r#"{"kind":"laravel","state":"on","container":"runtime-1","projectRoot":"/var/www/../etc","uid":1,"gid":1}"#;
        assert_eq!(
            Request::parse(traversal, ID, None).unwrap_err(),
            RequestError::InvalidRoot
        );
    }

    #[test]
    fn parses_the_joomla_offline_line() {
        assert_eq!(joomla_offline(b"\tpublic $offline = true;\n"), Some(true));
        assert_eq!(joomla_offline(b"public $offline = '1';"), Some(true));
        assert_eq!(joomla_offline(b"public $offline = false;"), Some(false));
        assert_eq!(joomla_offline(b"public $offline = '0';"), Some(false));
        assert_eq!(joomla_offline(b""), None);
        assert_eq!(joomla_offline(b"public $offline = maybe;"), None);
    }

    #[test]
    fn laravel_on_issues_a_token_once_and_off_clears_it() {
        let dir = tempfile::tempdir().unwrap();
        let docker = fake_docker(dir.path(), true, false);
        let state = managed(dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };
        let on = request("laravel", "on", ID, Some("k1"));
        let first = execute(&ctx, &on, &CancellationToken::default()).unwrap();
        let Done::Issued(issued) = first else {
            panic!("a first enable issues a token")
        };
        assert!(issued.public().maintenance_mode && issued.public().secret_issued);
        let recorded = log(dir.path());
        assert!(recorded.contains("php artisan down --secret="));
        // The stored state holds no token; the replay says so and re-runs nothing.
        let calls = recorded.lines().count();
        match execute(&ctx, &on, &CancellationToken::default()).unwrap() {
            Done::AlreadyIssued(public) => assert!(public.maintenance_mode),
            _ => panic!("a replay must not return the token again"),
        }
        assert_eq!(log(dir.path()).lines().count(), calls);

        // Enabling again changes nothing and issues no new token.
        let again = request("laravel", "on", ID2, None);
        match execute(&ctx, &again, &CancellationToken::default()).unwrap() {
            Done::Plain(public) => assert!(!public.changed && !public.secret_issued),
            _ => panic!("already down: no token"),
        }
        let off = request(
            "laravel",
            "off",
            "123e4567-e89b-12d3-a456-426614174002",
            None,
        );
        match execute(&ctx, &off, &CancellationToken::default()).unwrap() {
            Done::Plain(public) => assert!(!public.maintenance_mode && public.changed),
            _ => panic!("off returns no token"),
        }
        assert!(log(dir.path()).contains("php artisan up --no-interaction"));
    }

    #[test]
    fn the_token_never_reaches_the_engine_state() {
        let dir = tempfile::tempdir().unwrap();
        let docker = fake_docker(dir.path(), true, false);
        let state = managed(dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };
        let Done::Issued(issued) = execute(
            &ctx,
            &request("laravel", "on", ID, Some("k1")),
            &CancellationToken::default(),
        )
        .unwrap() else {
            panic!("token expected")
        };
        let response = crate::protocol::Response::success_with_secret(OPERATION, issued).unwrap();
        let secret = serde_json::to_value(&response).unwrap()["result"]["bypassSecret"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(secret.len(), SECRET_LEN);
        let mut stack = vec![dir.path().to_path_buf()];
        while let Some(path) = stack.pop() {
            for entry in fs::read_dir(path).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.file_name().is_some_and(|name| name != "calls.log") {
                    let text = fs::read_to_string(&path).unwrap_or_default();
                    assert!(
                        !text.contains(&secret),
                        "{} holds the token",
                        path.display()
                    );
                }
            }
        }
    }

    #[test]
    fn joomla_runs_its_own_console_and_reads_the_state_back() {
        let dir = tempfile::tempdir().unwrap();
        let docker = fake_docker(dir.path(), true, false);
        let state = managed(dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };
        let Done::Plain(public) = execute(
            &ctx,
            &request("joomla", "on", ID, None),
            &CancellationToken::default(),
        )
        .unwrap() else {
            panic!("Joomla issues no token")
        };
        assert!(public.maintenance_mode && public.changed && !public.secret_issued);
        assert!(log(dir.path()).contains(
            "exec -i --user 1000:1000 -w /var/www/site runtime-1 php cli/joomla.php site:down --no-interaction"
        ));
        let Done::Plain(public) = execute(
            &ctx,
            &request("joomla", "off", ID2, None),
            &CancellationToken::default(),
        )
        .unwrap() else {
            panic!("Joomla issues no token")
        };
        assert!(!public.maintenance_mode && public.changed);
    }

    #[test]
    fn a_state_that_did_not_change_is_never_reported_ok() {
        let dir = tempfile::tempdir().unwrap();
        let docker = fake_docker(dir.path(), true, true);
        let state = managed(dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };
        for kind in ["joomla", "laravel"] {
            let error = execute(
                &ctx,
                &request(
                    kind,
                    "on",
                    &format!(
                        "123e4567-e89b-12d3-a456-4266141740{}",
                        if kind == "joomla" { "10" } else { "11" }
                    ),
                    None,
                ),
                &CancellationToken::default(),
            )
            .err()
            .unwrap();
            assert!(matches!(error, Error::StateMismatch), "{kind}");
        }
    }

    #[test]
    fn refuses_a_project_without_the_cms_entry_point() {
        let dir = tempfile::tempdir().unwrap();
        let docker = fake_docker(dir.path(), false, false);
        let state = managed(dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };
        let error = execute(
            &ctx,
            &request("joomla", "on", ID, None),
            &CancellationToken::default(),
        )
        .err()
        .unwrap();
        assert!(matches!(error, Error::NotThisCms(Kind::Joomla)));
        assert_eq!(error.protocol().0, ErrorCode::InvalidInput);
        assert_eq!(log(dir.path()).lines().count(), 1, "only the check ran");
    }

    #[test]
    fn a_failed_request_is_replayed_as_failed() {
        let dir = tempfile::tempdir().unwrap();
        let docker = fake_docker(dir.path(), true, true);
        let state = managed(dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };
        assert!(
            execute(
                &ctx,
                &request("joomla", "on", ID, Some("fail")),
                &CancellationToken::default()
            )
            .is_err()
        );
        let calls = log(dir.path()).lines().count();
        assert!(matches!(
            execute(
                &ctx,
                &request("joomla", "on", ID2, Some("fail")),
                &CancellationToken::default()
            )
            .err()
            .unwrap(),
            Error::Replayed { .. }
        ));
        assert_eq!(
            log(dir.path()).lines().count(),
            calls,
            "retry must not re-run"
        );
    }
}
