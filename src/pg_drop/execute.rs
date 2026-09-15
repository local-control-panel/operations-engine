use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    pg_drop::{DropResult, OPERATION, Request},
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
                "another PostgreSQL drop request is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Run(error) => (
                process::spawn_error_code(error),
                "could not run PostgreSQL database removal".into(),
            ),
            Self::Rejected(diagnostics) => (
                if diagnostics.timed_out {
                    ErrorCode::Timeout
                } else if diagnostics.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::SubprocessFailed
                },
                "PostgreSQL rejected the database removal".into(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before database removal ran".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            _ => (
                ErrorCode::Internal,
                "internal PostgreSQL database removal error".into(),
            ),
        }
    }
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<DropResult, Error> {
    let scope = open(ctx.engine_state, req.database.as_str()).map_err(Error::Io)?;
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
    let state_path = state_path(req.request_id);
    let audit_path = audit_path();
    let pre_commit = PreCommit::new(cancel.clone());
    if pre_commit.check().is_err() {
        return Err(fail(
            &scope,
            &state_path,
            &audit_path,
            state,
            Error::Cancelled,
        ));
    }
    let args = [
        "exec",
        "-i",
        req.container.as_str(),
        "sh",
        "-c",
        "IFS= read -r PGPASSWORD; export PGPASSWORD; exec psql -U postgres -d postgres -v ON_ERROR_STOP=1",
    ];
    // PostgreSQL's FORCE option terminates active sessions as part of DROP,
    // avoiding the reconnect race in a separate terminate-then-drop sequence.
    let input = format!(
        "{}\nDROP DATABASE \"{}\" WITH (FORCE);\n",
        req.root_password,
        req.database.as_str()
    );
    let output = process::run_with_stdin_bytes(
        &ProcessRequest::new(ctx.docker_program).args(args),
        input.as_bytes(),
        &ProcessLimits::default(),
        cancel,
    )
    .map_err(|error| {
        fail(
            &scope,
            &state_path,
            &audit_path,
            state.clone(),
            Error::Run(error),
        )
    })?;
    if !matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        return Err(fail(
            &scope,
            &state_path,
            &audit_path,
            state,
            Error::Rejected(SubprocessDiagnostics::from_output(
                ctx.docker_program,
                &output,
            )),
        ));
    }
    let _ = pre_commit.commit();
    let result = DropResult {
        database: req.database.as_str().into(),
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

fn open(root: &ManagedRoot, name: &str) -> std::io::Result<ManagedRoot> {
    let path = SiteRelativePath::parse(format!("pg-drop/{name}")).unwrap();
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
    fn uses_force_and_keeps_password_out_of_argv() {
        let directory = tempfile::tempdir().unwrap();
        let state_path = directory.path().join("state");
        fs::create_dir(&state_path).unwrap();
        let stdin_path = directory.path().join("stdin");
        let docker = directory.path().join("docker");
        fs::write(
            &docker,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" | grep -q top-secret && exit 9\ncat > '{}'\n",
                stdin_path.display()
            ),
        )
        .unwrap();
        let mut permissions = fs::metadata(&docker).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&docker, permissions).unwrap();
        let state =
            ManagedRoot::open(&crate::site::TrustedRoot::parse(&state_path).unwrap()).unwrap();
        let request = Request::parse(
            r#"{"container":"postgres-17","rootPassword":"top-secret","database":"site_db"}"#,
            "123e4567-e89b-12d3-a456-426614174000",
            None,
        )
        .unwrap();
        execute(
            &Context {
                engine_state: &state,
                docker_program: docker.to_str().unwrap(),
            },
            &request,
            &CancellationToken::default(),
        )
        .unwrap();
        let input = fs::read_to_string(stdin_path).unwrap();
        assert!(input.contains("DROP DATABASE \"site_db\" WITH (FORCE)"));
        assert!(input.starts_with("top-secret\n"));
    }
}
