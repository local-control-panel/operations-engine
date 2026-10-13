//! `cms.clearCache`: one typed "clear the application caches" action for the
//! CMSs that have no engine operation of their own for it (WordPress has
//! `wordpress.boundedAction` `cacheFlush`, Drupal `drupal.cacheRebuild`).
//!
//! * `laravel`: `php artisan optimize:clear --no-interaction` (the compiled
//!   files, config, route, view and event caches, and the application cache
//!   store). Sessions kept in the cache store are cleared with it.
//!
//! Joomla is deliberately not a kind: its only native console command,
//! `cache:clean`, cleans just the default cache group and cannot be told to
//! clean all of them (that needs Joomla's admin UI), so a "clear cache"
//! button over it would leave page and component caches behind.
//!
//! The argv is fixed per kind; the caller supplies only the kind and the
//! validated container/root/UID/GID. The command runs as the site user, never
//! root, inside the site's runtime container from the project root, and only
//! when the CMS entry point (`artisan`) exists there. The
//! result carries no command output. Same lock/idempotency/transaction/audit
//! as the Drupal actions.

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

pub const OPERATION: &str = "cms.clearCache";

const CHECK_TIMEOUT: Duration = Duration::from_secs(60);
const RUN_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const MAX_OUTPUT: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Laravel,
}

impl Kind {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "laravel" => Some(Self::Laravel),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Laravel => "laravel",
        }
    }

    /// The file whose presence proves the project root is this CMS.
    const fn entry_point(self) -> &'static str {
        match self {
            Self::Laravel => "./artisan",
        }
    }

    const fn argv(self) -> &'static [&'static str] {
        match self {
            Self::Laravel => &["php", "artisan", "optimize:clear", "--no-interaction"],
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    kind: String,
    container: String,
    project_root: String,
    uid: u32,
    gid: u32,
}

#[derive(Debug)]
pub struct Request {
    pub kind: Kind,
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
    InvalidRoot,
    InvalidContainer,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl Request {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        let kind = Kind::parse(&plan.kind).ok_or(RequestError::InvalidKind)?;
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClearResult {
    pub kind: String,
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
    /// The project root has no `artisan`.
    NotThisCms(Kind),
    Rejected(SubprocessDiagnostics),
    PostCommit {
        result: ClearResult,
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
                "could not run the cache command".into(),
            ),
            Self::NotThisCms(kind) => (
                ErrorCode::InvalidInput,
                format!(
                    "the project root has no {}, so it is not a {} project",
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
                (code, format!("the cache command reported an error{suffix}"))
            }
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit { .. } => {
                (ErrorCode::Internal, "internal cache action error".into())
            }
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

fn clear(ctx: &Context<'_>, req: &Request, cancel: &CancellationToken) -> Result<(), Error> {
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
    let output = container_exec(ctx, req, kind.argv(), RUN_TIMEOUT, cancel)?;
    if !exited_ok(&output) {
        return Err(Error::Rejected(SubprocessDiagnostics::from_output(
            ctx.docker_program,
            &output,
        )));
    }
    Ok(())
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<ClearResult, Error> {
    let hash = resource_lock::canonical_hash(&req.project_root);
    let scope_path = SiteRelativePath::parse(format!("cms-cache/{hash}")).unwrap();
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
        clear(ctx, req, cancel)
    };
    if let Err(error) = outcome {
        return Err(fail(&scope, &state_path, &audit_path, state, error));
    }
    let result = ClearResult {
        kind: req.kind.name().into(),
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

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<ClearResult, Error> {
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
    const ID2: &str = "123e4567-e89b-12d3-a456-426614174001";

    fn managed(directory: &std::path::Path) -> ManagedRoot {
        ManagedRoot::open(&crate::site::TrustedRoot::parse(directory).unwrap()).unwrap()
    }

    fn request(kind: &str, id: &str, key: Option<&str>) -> Request {
        Request::parse(
            &format!(
                r#"{{"kind":"{kind}","container":"runtime-1","projectRoot":"/var/www/site","uid":1000,"gid":1000}}"#
            ),
            id,
            key,
        )
        .unwrap()
    }

    /// Records every call; `has_entry` decides the `test -f` answer.
    fn fake_docker(directory: &std::path::Path, has_entry: bool, fail_run: bool) -> String {
        let log = directory.join("calls.log");
        let path = directory.join("fake-docker");
        fs::write(
            &path,
            format!(
                r#"#!/bin/sh
printf '%s\n' "$*" >> '{log}'
case "$*" in
  *" test -f "*) exit {entry} ;;
  *) exit {run} ;;
esac
"#,
                log = log.display(),
                entry = if has_entry { 0 } else { 1 },
                run = if fail_run { 1 } else { 0 },
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
        let with = |kind: &str, extra: &str| {
            format!(
                r#"{{"kind":"{kind}","container":"runtime-1","projectRoot":"/var/www/site","uid":1,"gid":1{extra}}}"#
            )
        };
        // Joomla's only native command cleans one cache group, so it is not a kind.
        for kind in ["wordpress", "joomla", "drupal"] {
            assert_eq!(
                Request::parse(&with(kind, ""), ID, None).unwrap_err(),
                RequestError::InvalidKind
            );
        }
        assert_eq!(
            Request::parse(&with("laravel", r#","command":"tinker""#), ID, None).unwrap_err(),
            RequestError::InvalidJson
        );
        let relative =
            r#"{"kind":"laravel","container":"runtime-1","projectRoot":"site","uid":1,"gid":1}"#;
        assert_eq!(
            Request::parse(relative, ID, None).unwrap_err(),
            RequestError::InvalidRoot
        );
        let traversal = r#"{"kind":"laravel","container":"runtime-1","projectRoot":"/var/www/../etc","uid":1,"gid":1}"#;
        assert_eq!(
            Request::parse(traversal, ID, None).unwrap_err(),
            RequestError::InvalidRoot
        );
    }

    #[test]
    fn runs_the_fixed_argv_as_the_site_user_and_replays() {
        let dir = tempfile::tempdir().unwrap();
        let docker = fake_docker(dir.path(), true, false);
        let state = managed(dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };
        let laravel = request("laravel", ID, Some("k1"));
        let first = execute(&ctx, &laravel, &CancellationToken::default()).unwrap();
        assert_eq!(first.kind, "laravel");
        let recorded = log(dir.path());
        assert!(recorded.contains(
            "exec -i --user 1000:1000 -w /var/www/site runtime-1 php artisan optimize:clear --no-interaction"
        ));
        let replayed = execute(&ctx, &laravel, &CancellationToken::default()).unwrap();
        assert_eq!(
            first.completed_at_unix_secs,
            replayed.completed_at_unix_secs
        );
        assert_eq!(log(dir.path()).lines().count(), 2, "replay must not re-run");
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
            &request("laravel", ID, None),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::NotThisCms(Kind::Laravel)));
        assert_eq!(error.protocol().0, ErrorCode::InvalidInput);
        assert_eq!(log(dir.path()).lines().count(), 1, "only the check ran");
    }

    #[test]
    fn a_failing_command_fails_the_request_and_is_replayed_as_failed() {
        let dir = tempfile::tempdir().unwrap();
        let docker = fake_docker(dir.path(), true, true);
        let state = managed(dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };
        assert!(matches!(
            execute(
                &ctx,
                &request("laravel", ID, Some("fail")),
                &CancellationToken::default()
            ),
            Err(Error::Rejected(_))
        ));
        assert!(matches!(
            execute(
                &ctx,
                &request("laravel", ID2, Some("fail")),
                &CancellationToken::default()
            ),
            Err(Error::Replayed { .. })
        ));
        assert_eq!(log(dir.path()).lines().count(), 2, "retry must not re-run");
    }
}
