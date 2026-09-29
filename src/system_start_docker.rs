use crate::{
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
        state::{self, TransactionStatus},
    },
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const OPERATION: &str = "system.startDocker";

pub struct Request {
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug)]
pub enum RequestError {
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl Request {
    pub fn parse(request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        Ok(Self {
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    Start,
}

impl Stage {
    fn message(self) -> &'static str {
        match self {
            Self::Start => "could not start the Docker service",
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartResult {
    pub completed_at_unix_secs: u64,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub start_program: &'a str,
    pub start_args: &'a [&'a str],
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Run(Stage, process::ProcessRunError),
    Rejected(Stage, SubprocessDiagnostics),
    PostCommit { result: StartResult },
    Replayed { code: ErrorCode, message: String },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another Docker service start is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Run(stage, error) => (process::spawn_error_code(error), stage.message().into()),
            Self::Rejected(stage, diagnostics) => (
                if diagnostics.timed_out {
                    ErrorCode::Timeout
                } else if diagnostics.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::SubprocessFailed
                },
                stage.message().into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit { .. } => (
                ErrorCode::Internal,
                "internal Docker service start error".into(),
            ),
        }
    }
}

fn run_start(ctx: &Context<'_>, cancel: &CancellationToken) -> Result<(), Error> {
    let output = process::run(
        &ProcessRequest::new(ctx.start_program).args(ctx.start_args),
        &ProcessLimits {
            timeout: Duration::from_secs(2 * 60),
            max_stdout_bytes: 64 * 1024,
            max_stderr_bytes: 64 * 1024,
        },
        cancel,
    )
    .map_err(|e| Error::Run(Stage::Start, e))?;
    if !matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        return Err(Error::Rejected(
            Stage::Start,
            SubprocessDiagnostics::from_output(ctx.start_program, &output),
        ));
    }
    Ok(())
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<StartResult, Error> {
    let scope_path = SiteRelativePath::parse("system-start-docker").unwrap();
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

    if let Err(error) = run_start(ctx, cancel) {
        return Err(fail(&scope, &state_path, &audit_path, state, error));
    }

    let result = StartResult {
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

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<StartResult, Error> {
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

    fn fixture(exit: i32) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("start-service");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\necho \"$*\" >> '{}'\nexit {exit}\n",
                dir.path().join("calls.log").display()
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        (dir, script.to_string_lossy().into_owned())
    }

    fn managed(dir: &std::path::Path) -> ManagedRoot {
        ManagedRoot::open(&crate::site::TrustedRoot::parse(dir).unwrap()).unwrap()
    }

    #[test]
    fn starts_service_once_and_replays() {
        let (dir, program) = fixture(0);
        let state = managed(dir.path());
        let ctx = Context {
            engine_state: &state,
            start_program: &program,
            start_args: &["start", "docker"],
        };
        let req = Request::parse(ID, Some("start-docker")).unwrap();
        execute(&ctx, &req, &CancellationToken::default()).unwrap();
        execute(&ctx, &req, &CancellationToken::default()).unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("calls.log")).unwrap(),
            "start docker\n"
        );
    }

    #[test]
    fn rejected_service_start_is_recorded_and_replayed() {
        let (dir, program) = fixture(1);
        let state = managed(dir.path());
        let ctx = Context {
            engine_state: &state,
            start_program: &program,
            start_args: &["start", "docker"],
        };
        let req = Request::parse(ID, Some("start-docker")).unwrap();
        assert!(matches!(
            execute(&ctx, &req, &CancellationToken::default()),
            Err(Error::Rejected(Stage::Start, _))
        ));
        assert!(matches!(
            execute(&ctx, &req, &CancellationToken::default()),
            Err(Error::Replayed { .. })
        ));
        assert_eq!(
            fs::read_to_string(dir.path().join("calls.log")).unwrap(),
            "start docker\n"
        );
    }
}
