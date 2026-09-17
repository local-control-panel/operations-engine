use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    maria_slow_log::{SET_OPERATION, SetRequest, SetResult},
    mutation::preflight,
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
    PostCommit { result: SetResult },
    Replayed { code: ErrorCode, message: String },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another MariaDB slow-log mutation is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Run(error) => (
                process::spawn_error_code(error),
                "could not configure MariaDB slow logging".into(),
            ),
            Self::Rejected(details) => (
                if details.timed_out {
                    ErrorCode::Timeout
                } else if details.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::SubprocessFailed
                },
                "MariaDB rejected the slow-log configuration".into(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before MariaDB slow-log configuration ran".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            _ => (
                ErrorCode::Internal,
                "internal MariaDB slow-log configuration error".into(),
            ),
        }
    }
}

pub fn execute(
    ctx: &Context<'_>,
    req: &SetRequest,
    cancel: &CancellationToken,
) -> Result<SetResult, Error> {
    let scope = open(ctx.engine_state, req.container.as_str()).map_err(Error::Io)?;
    let admitted = match preflight::run(
        &scope,
        req.request_id,
        req.idempotency_key.as_ref(),
        SET_OPERATION,
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

    let sql = sql(req);
    let password = format!("-p{}", req.root_password);
    let args = [
        "exec",
        req.container.as_str(),
        "mariadb",
        "-uroot",
        password.as_str(),
        "-e",
        sql.as_str(),
    ];
    let output = process::run(
        &ProcessRequest::new(ctx.docker_program).args(args),
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
    let result = SetResult {
        enabled: req.enabled,
        long_query_time: if req.enabled {
            req.long_query_time
        } else {
            None
        },
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

fn sql(req: &SetRequest) -> String {
    let enabled = if req.enabled { "ON" } else { "OFF" };
    match (req.enabled, req.long_query_time) {
        (true, Some(value)) => {
            format!("SET GLOBAL long_query_time = {value}; SET GLOBAL slow_query_log = {enabled};")
        }
        _ => format!("SET GLOBAL slow_query_log = {enabled};"),
    }
}

fn open(root: &ManagedRoot, container: &str) -> std::io::Result<ManagedRoot> {
    let path = SiteRelativePath::parse(format!("maria-slow-log/{container}")).unwrap();
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
fn replay(scope: &ManagedRoot, id: crate::transaction::RequestId) -> Result<SetResult, Error> {
    let loaded = state::load(scope, &state_path(id))
        .map_err(|error| Error::Io(std::io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != SET_OPERATION {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_sets_threshold_before_enabling_and_ignores_it_when_disabling() {
        let id = "123e4567-e89b-12d3-a456-426614174000";
        let enabled = SetRequest::parse(
            r#"{"container":"mariadb-11","rootPassword":"secret","enabled":true,"longQueryTime":1.25}"#,
            id,
            None,
        ).unwrap();
        assert_eq!(
            sql(&enabled),
            "SET GLOBAL long_query_time = 1.25; SET GLOBAL slow_query_log = ON;"
        );
        let disabled = SetRequest::parse(
            r#"{"container":"mariadb-11","rootPassword":"secret","enabled":false,"longQueryTime":42}"#,
            id,
            None,
        ).unwrap();
        assert_eq!(sql(&disabled), "SET GLOBAL slow_query_log = OFF;");
    }
}
