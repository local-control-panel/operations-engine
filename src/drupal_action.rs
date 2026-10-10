//! Three small, typed Drupal mutations run through the site's Drush under one
//! lock/idempotency/transaction/audit-backed request:
//! `drupal.cacheRebuild` (`drush cache:rebuild`), `drupal.cronRun`
//! (`drush core:cron`) and `drupal.maintenance` (maintenance mode on/off).
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

/// Drush's `cache:rebuild` and `core:cron` can legitimately take minutes on a
/// large site; anything longer is a hang.
const RUN_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const READ_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_OUTPUT: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    CacheRebuild,
    CronRun,
    Maintenance { enabled: bool },
}

impl Action {
    pub const fn operation(self) -> &'static str {
        match self {
            Self::CacheRebuild => CACHE_REBUILD,
            Self::CronRun => CRON_RUN,
            Self::Maintenance { .. } => MAINTENANCE,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::CacheRebuild => "cacheRebuild",
            Self::CronRun => "cronRun",
            Self::Maintenance { .. } => "maintenance",
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
        let action = match (kind, plan.state.as_deref()) {
            ("cache-rebuild", None) => Action::CacheRebuild,
            ("cron-run", None) => Action::CronRun,
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
    /// Drupal did not report the maintenance mode that was just set.
    StateMismatch,
    PostCommit {
        result: ActionResult,
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
            Self::Run(error) => (
                process::spawn_error_code(error),
                "could not run Drush".into(),
            ),
            Self::Rejected(diagnostics) => (
                if diagnostics.timed_out {
                    ErrorCode::Timeout
                } else if diagnostics.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::SubprocessFailed
                },
                "Drush reported an error".into(),
            ),
            Self::StateMismatch => (
                ErrorCode::SubprocessFailed,
                "Drupal did not report the requested maintenance mode".into(),
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

fn maintenance_flag(bytes: &[u8]) -> Option<bool> {
    match String::from_utf8_lossy(bytes).trim() {
        "1" | "true" | "TRUE" => Some(true),
        "0" | "false" | "FALSE" | "" => Some(false),
        _ => None,
    }
}

fn run_action(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<Option<bool>, Error> {
    match req.action {
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

    let maintenance_mode = match run_action(ctx, req, cancel) {
        Ok(value) => value,
        Err(error) => return Err(fail(&scope, &state_path, &audit_path, state, error)),
    };
    let result = ActionResult {
        action: req.action.name().into(),
        maintenance_mode,
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
