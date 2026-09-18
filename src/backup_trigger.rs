use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination},
    site::SiteRelativePath,
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        state::{self, TransactionStatus},
    },
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const OPERATION: &str = "backup.triggerNow";
pub const AGENT_PATH: &str = "/root/.wcp/agents/backup-agent.sh";

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

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TriggerResult {
    pub completed_at_unix_secs: u64,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub bash_program: &'a str,
    pub agent_path: &'a str,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Run(process::ProcessRunError),
    Rejected(ErrorCode),
    PostCommit { result: TriggerResult },
    Replayed { code: ErrorCode, message: String },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another immediate backup is in progress".into(),
            ),
            Self::Preflight(_) => (
                ErrorCode::Internal,
                "could not prepare immediate backup transaction".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Run(error) => (
                process::spawn_error_code(error),
                "could not start backup agent".into(),
            ),
            Self::Rejected(code) => (*code, "backup agent failed".into()),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) => (ErrorCode::Internal, "internal backup trigger error".into()),
            Self::PostCommit { .. } => (
                ErrorCode::Internal,
                "backup completed but its transaction record could not be saved".into(),
            ),
        }
    }
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<TriggerResult, Error> {
    let scope_path = SiteRelativePath::parse("backup-trigger").unwrap();
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
    let output = match process::run(
        &ProcessRequest::new(ctx.bash_program).args([ctx.agent_path]),
        &ProcessLimits {
            timeout: Duration::from_secs(6 * 60 * 60),
            max_stdout_bytes: 64 * 1024,
            max_stderr_bytes: 64 * 1024,
        },
        cancel,
    ) {
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
    if let Some(code) = process::error_code(&output.termination) {
        return Err(fail(
            &scope,
            &state_path,
            &audit_path,
            state,
            Error::Rejected(code),
        ));
    }
    debug_assert!(matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ));
    let result = TriggerResult {
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

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<TriggerResult, Error> {
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

    #[test]
    fn runs_fixed_agent_once_then_replays() {
        let directory = tempfile::tempdir().unwrap();
        let state_path = directory.path().join("state");
        fs::create_dir(&state_path).unwrap();
        let marker = directory.path().join("runs");
        let agent = directory.path().join("agent.sh");
        fs::write(
            &agent,
            format!("#!/bin/sh\necho run >> '{}'\n", marker.display()),
        )
        .unwrap();
        fs::set_permissions(&agent, fs::Permissions::from_mode(0o700)).unwrap();
        let state =
            ManagedRoot::open(&crate::site::TrustedRoot::parse(&state_path).unwrap()).unwrap();
        let request = Request::parse(
            "123e4567-e89b-12d3-a456-426614174000",
            Some("manual-backup"),
        )
        .unwrap();
        let context = Context {
            engine_state: &state,
            bash_program: "/bin/sh",
            agent_path: agent.to_str().unwrap(),
        };
        execute(&context, &request, &CancellationToken::default()).unwrap();
        execute(&context, &request, &CancellationToken::default()).unwrap();
        assert_eq!(fs::read_to_string(marker).unwrap(), "run\n");
        let audit =
            fs::read_to_string(state_path.join("backup-trigger/audit/events.jsonl")).unwrap();
        assert!(audit.contains(OPERATION));
    }
}
