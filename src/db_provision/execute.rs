use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    db_provision::{CreateMode, OPERATION, ProvisionRequest, ProvisionResult},
    error::ErrorCode,
    filesystem::ManagedRoot,
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

pub struct ProvisionContext<'a> {
    pub engine_state: &'a ManagedRoot,
    pub docker_program: &'a str,
}

#[derive(Debug)]
pub enum ProvisionError {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Run(process::ProcessRunError),
    Rejected(SubprocessDiagnostics),
    Cancelled,
    PostCommitRecordFailed { result: ProvisionResult },
    Replayed { code: ErrorCode, message: String },
}

impl ProvisionError {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another provisioning request for this database is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request for this idempotency key is still in progress".into(),
            ),
            Self::Run(error) => (
                process::spawn_error_code(error),
                "could not run MariaDB provisioning".into(),
            ),
            Self::Rejected(details) => (
                if details.timed_out {
                    ErrorCode::Timeout
                } else if details.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::SubprocessFailed
                },
                "MariaDB rejected the provisioning request".into(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before provisioning ran".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommitRecordFailed { .. } => (
                ErrorCode::Internal,
                "internal MariaDB provisioning error".into(),
            ),
        }
    }
}

pub fn execute(
    context: &ProvisionContext<'_>,
    request: &ProvisionRequest,
    cancellation: &CancellationToken,
) -> Result<ProvisionResult, ProvisionError> {
    let scope_name = request
        .database
        .as_ref()
        .map(|database| database.name.as_str())
        .or_else(|| request.user.as_ref().map(|user| user.name.as_str()))
        .expect("validated provisioning target");
    let scope = open_state(context.engine_state, scope_name).map_err(ProvisionError::Io)?;
    let admitted = match preflight::run(
        &scope,
        request.request_id,
        request.idempotency_key.as_ref(),
        OPERATION,
    )
    .map_err(ProvisionError::Preflight)?
    {
        preflight::Outcome::Replay(original) => return replay(&scope, original),
        preflight::Outcome::Proceed(admitted) => admitted,
    };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path = state_path(request.request_id);
    let audit_path = audit_path();
    let pre_commit = PreCommit::new(cancellation.clone());
    if pre_commit.check().is_err() {
        return Err(fail(
            &scope,
            &state_path,
            &audit_path,
            state,
            ProvisionError::Cancelled,
        ));
    }
    let output = process::run_with_stdin_bytes(
        &client_request(context, request),
        &client_input(request),
        &ProcessLimits::default(),
        cancellation,
    )
    .map_err(|error| {
        fail(
            &scope,
            &state_path,
            &audit_path,
            state.clone(),
            ProvisionError::Run(error),
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
            ProvisionError::Rejected(SubprocessDiagnostics::from_output(
                context.docker_program,
                &output,
            )),
        ));
    }
    let _post_commit = pre_commit.commit();
    let result = ProvisionResult {
        database: request
            .database
            .as_ref()
            .map(|database| database.name.as_str().to_owned()),
        user_provisioned: request.user.is_some(),
        completed_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    state
        .mark_committed(serde_json::to_value(&result).expect("result serializes"))
        .expect("in progress");
    if state::save(&scope, &state_path, &state).is_err() {
        drop(lock);
        return Err(ProvisionError::PostCommitRecordFailed { result });
    }
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(request.request_id, true, None),
    );
    drop(lock);
    Ok(result)
}

fn client_request(context: &ProvisionContext<'_>, request: &ProvisionRequest) -> ProcessRequest {
    ProcessRequest::new(context.docker_program).args(client_args(request))
}

fn client_args(request: &ProvisionRequest) -> Vec<String> {
    vec![
        "exec".into(),
        "-i".into(),
        request.container.as_str().into(),
        "sh".into(),
        "-c".into(),
        "IFS= read -r MYSQL_PWD; export MYSQL_PWD; exec mariadb -uroot --batch".into(),
    ]
}

fn client_input(request: &ProvisionRequest) -> Vec<u8> {
    let mut sql = String::new();
    if let Some(database) = &request.database {
        let database_clause = match database.mode {
            CreateMode::Create => "CREATE DATABASE",
            CreateMode::Ensure => "CREATE DATABASE IF NOT EXISTS",
        };
        sql.push_str(&format!(
            "{database_clause} `{}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;",
            database.name.as_str()
        ));
    }
    if let Some(user) = &request.user {
        let user_clause = match user.mode {
            CreateMode::Create => "CREATE USER",
            CreateMode::Ensure => "CREATE USER IF NOT EXISTS",
        };
        sql.push_str(&format!(
            " {user_clause} '{}'@'{}' IDENTIFIED BY '{}';",
            sql_string(&user.name),
            sql_string(&user.host),
            sql_string(&user.password)
        ));
        if let Some(database) = &user.grant_database {
            sql.push_str(&format!(
                " GRANT ALL PRIVILEGES ON `{}`.* TO '{}'@'{}'; FLUSH PRIVILEGES;",
                database.as_str(),
                sql_string(&user.name),
                sql_string(&user.host)
            ));
        }
    }
    format!("{}\n{}", request.root_password, sql).into_bytes()
}

fn sql_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "''")
}

fn open_state(engine_state: &ManagedRoot, database: &str) -> std::io::Result<ManagedRoot> {
    let relative = SiteRelativePath::parse(format!("db-provision/{database}")).unwrap();
    engine_state.create_dir_all(&relative)?;
    let scope = engine_state.open_managed_dir(&relative)?;
    for sub in ["locks", "transactions", "audit"] {
        scope.create_dir_all(&SiteRelativePath::parse(sub).unwrap())?;
    }
    Ok(scope)
}
fn state_path(id: crate::transaction::RequestId) -> SiteRelativePath {
    SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap()
}
fn audit_path() -> SiteRelativePath {
    SiteRelativePath::parse("audit/events.jsonl").unwrap()
}

fn replay(
    scope: &ManagedRoot,
    original: crate::transaction::RequestId,
) -> Result<ProvisionResult, ProvisionError> {
    let loaded = state::load(scope, &state_path(original)).map_err(|error| {
        ProvisionError::Io(std::io::Error::other(format!(
            "state load failed: {error:?}"
        )))
    })?;
    if loaded.operation != OPERATION {
        return Err(ProvisionError::Io(std::io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(ProvisionError::ReplayInProgress),
        TransactionStatus::Committed => {
            serde_json::from_value(loaded.outcome.unwrap().result.unwrap())
                .map_err(|error| ProvisionError::Io(std::io::Error::other(error)))
        }
        TransactionStatus::Failed => {
            let outcome = loaded.outcome.unwrap();
            Err(ProvisionError::Replayed {
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
    error: ProvisionError,
) -> ProvisionError {
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
    use crate::db_provision::ProvisionRequest;

    #[test]
    fn builds_argv_without_a_shell_and_escapes_sql_literals() {
        let request = ProvisionRequest::parse(
            r#"{"container":"maria-1","rootPassword":"root pw","database":{"name":"site_db","mode":"ensure"},"user":{"name":"site_user","host":"%","password":"p'ass\\word","mode":"ensure","grantDatabase":"site_db"}}"#,
            "123e4567-e89b-12d3-a456-426614174000", None,
        ).unwrap();
        let built = client_args(&request);
        assert!(
            !built
                .iter()
                .any(|arg| arg.contains("root pw") || arg.contains("p'ass"))
        );
        let input = String::from_utf8(client_input(&request)).unwrap();
        assert!(input.contains("p''ass\\\\word"));
    }
}
