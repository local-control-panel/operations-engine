use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    pg_provision::{OPERATION, ProvisionResult, Request},
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
    PostCommit { result: ProvisionResult },
    Replayed { code: ErrorCode, message: String },
}
impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another PostgreSQL provisioning request is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Run(e) => (
                process::spawn_error_code(e),
                "could not run PostgreSQL provisioning".into(),
            ),
            Self::Rejected(d) => (
                if d.timed_out {
                    ErrorCode::Timeout
                } else if d.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::SubprocessFailed
                },
                "PostgreSQL rejected the provisioning request".into(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before provisioning ran".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            _ => (
                ErrorCode::Internal,
                "internal PostgreSQL provisioning error".into(),
            ),
        }
    }
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> std::result::Result<ProvisionResult, Error> {
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
        preflight::Outcome::Proceed(v) => v,
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
    let sql = format!(
        "{}\nCREATE DATABASE \"{}\";\n",
        req.root_password,
        req.database.as_str()
    );
    let out = process::run_with_stdin_bytes(
        &ProcessRequest::new(ctx.docker_program).args(args),
        sql.as_bytes(),
        &ProcessLimits::default(),
        cancel,
    )
    .map_err(|e| fail(&scope, &sp, &ap, state.clone(), Error::Run(e)))?;
    if !matches!(
        out.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        return Err(fail(
            &scope,
            &sp,
            &ap,
            state,
            Error::Rejected(SubprocessDiagnostics::from_output(ctx.docker_program, &out)),
        ));
    }
    let _ = pre.commit();
    let result = ProvisionResult {
        database: req.database.as_str().into(),
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
fn open(root: &ManagedRoot, name: &str) -> std::io::Result<ManagedRoot> {
    let p = SiteRelativePath::parse(format!("pg-provision/{name}")).unwrap();
    root.create_dir_all(&p)?;
    let s = root.open_managed_dir(&p)?;
    for d in ["locks", "transactions", "audit"] {
        s.create_dir_all(&SiteRelativePath::parse(d).unwrap())?
    }
    Ok(s)
}
fn state_path(id: crate::transaction::RequestId) -> SiteRelativePath {
    SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap()
}
fn audit_path() -> SiteRelativePath {
    SiteRelativePath::parse("audit/events.jsonl").unwrap()
}
fn replay(
    s: &ManagedRoot,
    id: crate::transaction::RequestId,
) -> std::result::Result<ProvisionResult, Error> {
    let l = state::load(s, &state_path(id))
        .map_err(|e| Error::Io(std::io::Error::other(format!("{e:?}"))))?;
    if l.operation != OPERATION {
        return Err(Error::Io(std::io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match l.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => serde_json::from_value(l.outcome.unwrap().result.unwrap())
            .map_err(|e| Error::Io(std::io::Error::other(e))),
        TransactionStatus::Failed => {
            let o = l.outcome.unwrap();
            Err(Error::Replayed {
                code: o.error_code.unwrap_or(ErrorCode::Internal),
                message: o.error_message.unwrap_or_default(),
            })
        }
    }
}
fn fail(
    s: &ManagedRoot,
    sp: &SiteRelativePath,
    ap: &SiteRelativePath,
    mut st: crate::transaction::state::TransactionState,
    e: Error,
) -> Error {
    let (c, m) = e.protocol();
    let _ = st.mark_failed(c, m);
    let _ = state::save(s, sp, &st);
    let _ = audit::append(s, ap, &AuditRecord::result(st.request_id, false, Some(c)));
    e
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    #[test]
    fn fixed_argv_and_stdin_keep_password_out_of_argv() {
        let d = tempfile::tempdir().unwrap();
        let state_path = d.path().join("state");
        fs::create_dir(&state_path).unwrap();
        let bin = d.path().join("docker");
        fs::write(&bin, "#!/bin/sh\ncat >/dev/null\nexit 0\n").unwrap();
        let mut p = fs::metadata(&bin).unwrap().permissions();
        p.set_mode(0o755);
        fs::set_permissions(&bin, p).unwrap();
        let root = crate::site::TrustedRoot::parse(&state_path).unwrap();
        let state = ManagedRoot::open(&root).unwrap();
        let req = Request::parse(
            r#"{"container":"postgres-17","rootPassword":"top-secret","database":"site_db"}"#,
            "123e4567-e89b-12d3-a456-426614174000",
            None,
        )
        .unwrap();
        let result = execute(
            &Context {
                engine_state: &state,
                docker_program: bin.to_str().unwrap(),
            },
            &req,
            &CancellationToken::default(),
        )
        .unwrap();
        assert_eq!(result.database, "site_db");
    }
}
