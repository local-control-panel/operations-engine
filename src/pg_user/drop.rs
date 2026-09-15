use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    pg_user::{DROP_OPERATION, DropRequest, DropResult},
    process::{
        self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination,
        SubprocessDiagnostics,
    },
    site::SiteRelativePath,
    transaction::{
        audit::{self, AuditRecord},
        commit::PreCommit,
        state::{self, TransactionStatus},
    },
};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub docker_program: &'a str,
}
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Run(process::ProcessRunError),
    Rejected(SubprocessDiagnostics),
    Cancelled,
    PostCommit { result: DropResult },
    Replayed { code: ErrorCode, message: String },
}
impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another PostgreSQL role removal is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Run(error) => (
                process::spawn_error_code(error),
                "could not run PostgreSQL role removal".into(),
            ),
            Self::Rejected(d) => (
                if d.timed_out {
                    ErrorCode::Timeout
                } else if d.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::SubprocessFailed
                },
                "PostgreSQL rejected the role removal".into(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before role removal ran".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            _ => (
                ErrorCode::Internal,
                "internal PostgreSQL role removal error".into(),
            ),
        }
    }
}

pub fn execute(
    ctx: &Context<'_>,
    req: &DropRequest,
    cancel: &CancellationToken,
) -> Result<DropResult, Error> {
    let scope = open(ctx.engine_state, &req.user).map_err(Error::Io)?;
    let admitted = match preflight::run(
        &scope,
        req.request_id,
        req.idempotency_key.as_ref(),
        DROP_OPERATION,
    )
    .map_err(Error::Preflight)?
    {
        preflight::Outcome::Replay(id) => return replay(&scope, id),
        preflight::Outcome::Proceed(value) => value,
    };
    let preflight::Admitted { lock, mut state } = admitted;
    let sp = state_path(req.request_id);
    let ap = audit_path();
    let pre = PreCommit::new(cancel.clone());
    if pre.check().is_err() {
        return Err(fail(&scope, &sp, &ap, state, Error::Cancelled));
    }
    let args = [
        "exec",
        "-i",
        req.container.as_str(),
        "sh",
        "-c",
        "IFS= read -r PGPASSWORD; export PGPASSWORD; exec psql -U postgres -d postgres -v ON_ERROR_STOP=1",
    ];
    let input = format!("{}\nDROP ROLE \"{}\";\n", req.root_password, req.user);
    let output = process::run_with_stdin_bytes(
        &ProcessRequest::new(ctx.docker_program).args(args),
        input.as_bytes(),
        &ProcessLimits::default(),
        cancel,
    )
    .map_err(|error| fail(&scope, &sp, &ap, state.clone(), Error::Run(error)))?;
    if !matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        return Err(fail(
            &scope,
            &sp,
            &ap,
            state,
            Error::Rejected(SubprocessDiagnostics::from_output(
                ctx.docker_program,
                &output,
            )),
        ));
    }
    let _ = pre.commit();
    let result = DropResult {
        user: req.user.clone(),
        completed_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    state
        .mark_committed(serde_json::to_value(&result).unwrap())
        .unwrap();
    if state::save(&scope, &sp, &state).is_err() {
        drop(lock);
        return Err(Error::PostCommit { result });
    }
    let _ = audit::append(
        &scope,
        &ap,
        &AuditRecord::result(req.request_id, true, None),
    );
    drop(lock);
    Ok(result)
}
fn open(root: &ManagedRoot, user: &str) -> std::io::Result<ManagedRoot> {
    let path = SiteRelativePath::parse(format!("pg-user/{user}")).unwrap();
    root.create_dir_all(&path)?;
    let scope = root.open_managed_dir(&path)?;
    for child in ["locks", "transactions", "audit"] {
        scope.create_dir_all(&SiteRelativePath::parse(child).unwrap())?;
    }
    Ok(scope)
}
fn state_path(id: crate::transaction::RequestId) -> SiteRelativePath {
    SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap()
}
fn audit_path() -> SiteRelativePath {
    SiteRelativePath::parse("audit/events.jsonl").unwrap()
}
fn replay(scope: &ManagedRoot, id: crate::transaction::RequestId) -> Result<DropResult, Error> {
    let loaded = state::load(scope, &state_path(id))
        .map_err(|error| Error::Io(std::io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != DROP_OPERATION {
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
    sp: &SiteRelativePath,
    ap: &SiteRelativePath,
    mut state: crate::transaction::state::TransactionState,
    error: Error,
) -> Error {
    let (code, message) = error.protocol();
    let _ = state.mark_failed(code, message);
    let _ = state::save(scope, sp, &state);
    let _ = audit::append(
        scope,
        ap,
        &AuditRecord::result(state.request_id, false, Some(code)),
    );
    error
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    #[test]
    fn password_stays_out_of_argv_and_drop_is_fixed() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        fs::create_dir(&state_dir).unwrap();
        let stdin = dir.path().join("stdin");
        let docker = dir.path().join("docker");
        fs::write(
            &docker,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" | grep -q root-secret && exit 9\ncat > '{}'\n",
                stdin.display()
            ),
        )
        .unwrap();
        let mut mode = fs::metadata(&docker).unwrap().permissions();
        mode.set_mode(0o755);
        fs::set_permissions(&docker, mode).unwrap();
        let state =
            ManagedRoot::open(&crate::site::TrustedRoot::parse(&state_dir).unwrap()).unwrap();
        let req = DropRequest::parse(
            r#"{"container":"postgres-17","rootPassword":"root-secret","user":"app_user"}"#,
            "123e4567-e89b-12d3-a456-426614174000",
            None,
        )
        .unwrap();
        execute(
            &Context {
                engine_state: &state,
                docker_program: docker.to_str().unwrap(),
            },
            &req,
            &CancellationToken::default(),
        )
        .unwrap();
        let input = fs::read_to_string(stdin).unwrap();
        assert!(input.contains("DROP ROLE \"app_user\""));
        assert!(input.starts_with("root-secret\n"));
    }
}
