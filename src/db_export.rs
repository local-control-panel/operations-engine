use crate::{
    db_restore::{ContainerName, DatabaseName, DbType, RestoreRequestError},
    error::ErrorCode,
    process::{
        self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination,
        SubprocessDiagnostics,
    },
};
use serde::Deserialize;
use std::time::Duration;

pub const OPERATION: &str = "db.export";
const MAX_DUMP_BYTES: usize = 64 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    db_type: String,
    database: String,
    container: String,
    root_password: String,
}

pub struct Request {
    db_type: DbType,
    database: DatabaseName,
    container: ContainerName,
    root_password: String,
}

impl Request {
    pub fn parse(json: &str) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        Ok(Self {
            db_type: DbType::parse(&plan.db_type).map_err(RequestError::Field)?,
            database: DatabaseName::parse(&plan.database).map_err(RequestError::Field)?,
            container: ContainerName::parse(&plan.container).map_err(RequestError::Field)?,
            root_password: plan.root_password,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    Field(RestoreRequestError),
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportResult {
    pub sql: String,
}

pub enum ExecuteError {
    Run(process::ProcessRunError),
    Rejected(SubprocessDiagnostics),
    TooLarge,
    InvalidUtf8,
}

impl ExecuteError {
    pub fn protocol(&self) -> (ErrorCode, &'static str) {
        match self {
            Self::Run(error) => (
                process::spawn_error_code(error),
                "could not run database export",
            ),
            Self::Rejected(details) if details.timed_out => {
                (ErrorCode::Timeout, "database export timed out")
            }
            Self::Rejected(_) => (ErrorCode::SubprocessFailed, "database export failed"),
            Self::TooLarge => (
                ErrorCode::InvalidInput,
                "database export exceeds the 64 MiB response limit",
            ),
            Self::InvalidUtf8 => (ErrorCode::Internal, "database export was not valid UTF-8"),
        }
    }
}

pub fn execute(
    request: &Request,
    docker_program: &str,
) -> std::result::Result<ExportResult, ExecuteError> {
    let mut args = vec!["exec".to_owned(), "-i".to_owned()];
    if request.db_type == DbType::Postgres {
        args.push("-e".to_owned());
        args.push(format!("PGPASSWORD={}", request.root_password));
    }
    args.push(request.container.as_str().to_owned());
    match request.db_type {
        DbType::Mariadb => args.extend([
            "mariadb-dump".to_owned(),
            "-uroot".to_owned(),
            format!("-p{}", request.root_password),
            "--single-transaction".to_owned(),
            "--routines".to_owned(),
            "--triggers".to_owned(),
            request.database.as_str().to_owned(),
        ]),
        DbType::Postgres => args.extend([
            "pg_dump".to_owned(),
            "-U".to_owned(),
            "postgres".to_owned(),
            request.database.as_str().to_owned(),
        ]),
    }
    let limits = ProcessLimits {
        timeout: Duration::from_secs(300),
        max_stdout_bytes: MAX_DUMP_BYTES,
        max_stderr_bytes: 64 * 1024,
    };
    let output = process::run(
        &ProcessRequest::new(docker_program).args(args),
        &limits,
        &CancellationToken::default(),
    )
    .map_err(ExecuteError::Run)?;
    if !matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        return Err(ExecuteError::Rejected(SubprocessDiagnostics::from_output(
            docker_program,
            &output,
        )));
    }
    if output.stdout.truncated {
        return Err(ExecuteError::TooLarge);
    }
    let sql = String::from_utf8(output.stdout.bytes).map_err(|_| ExecuteError::InvalidUtf8)?;
    Ok(ExportResult { sql })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_rejects_unknown_types_and_unbounded_identifiers() {
        assert!(Request::parse(r#"{"dbType":"mariadb","database":"site_db","container":"db-1","rootPassword":"secret"}"#).is_ok());
        assert!(
            Request::parse(
                r#"{"dbType":"oracle","database":"db","container":"db-1","rootPassword":"secret"}"#
            )
            .is_err()
        );
        assert!(Request::parse(r#"{"dbType":"postgres","database":"db;drop","container":"db-1","rootPassword":"secret"}"#).is_err());
    }
}
