use crate::{
    backup_delete::BACKUP_ROOT,
    db_restore::{ContainerName, DatabaseName, DbType, RestoreRequestError},
    error::ErrorCode,
    filesystem::ManagedRoot,
    process::{
        self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination,
        SubprocessDiagnostics,
    },
    site::SiteRelativePath,
    transaction::{IdempotencyKey, RequestId},
};
use serde::Deserialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const OPERATION: &str = "backup.createDatabase";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    db_type: String,
    database: String,
    container: String,
    root_password: String,
    retention_days: u16,
}

pub struct Request {
    db_type: DbType,
    database: DatabaseName,
    container: ContainerName,
    root_password: String,
    retention_days: u16,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug)]
pub enum RequestError {
    InvalidJson,
    InvalidField(RestoreRequestError),
    InvalidRetention,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl Request {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        if plan.retention_days > 3650 {
            return Err(RequestError::InvalidRetention);
        }
        Ok(Self {
            db_type: DbType::parse(&plan.db_type).map_err(RequestError::InvalidField)?,
            database: DatabaseName::parse(&plan.database).map_err(RequestError::InvalidField)?,
            container: ContainerName::parse(&plan.container).map_err(RequestError::InvalidField)?,
            root_password: plan.root_password,
            retention_days: plan.retention_days,
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
pub struct CreateResult {
    pub file_path: String,
    pub pruned_files: u32,
    pub completed_at_unix_secs: u64,
}

#[derive(Debug)]
pub enum ExecuteError {
    Io(std::io::Error),
    Run(process::ProcessRunError),
    Rejected(SubprocessDiagnostics),
}
impl ExecuteError {
    pub fn protocol(&self) -> (ErrorCode, &'static str) {
        match self {
            Self::Run(e) => (
                process::spawn_error_code(e),
                "could not run database backup",
            ),
            Self::Rejected(d) if d.timed_out => (ErrorCode::Timeout, "database backup timed out"),
            Self::Rejected(_) => (ErrorCode::SubprocessFailed, "database backup failed"),
            Self::Io(_) => (ErrorCode::Internal, "could not write database backup"),
        }
    }
}

pub fn execute(
    request: &Request,
    backup_root: &ManagedRoot,
    docker_program: &str,
    cancel: &CancellationToken,
) -> Result<CreateResult, ExecuteError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let final_name = format!("{}_{}.sql", request.database.as_str(), now);
    let temp_name = format!("{final_name}.partial-{}", request.request_id);
    let final_path = SiteRelativePath::parse(&final_name)
        .map_err(|_| ExecuteError::Io(std::io::Error::other("invalid backup path")))?;
    let temp_path = SiteRelativePath::parse(&temp_name)
        .map_err(|_| ExecuteError::Io(std::io::Error::other("invalid backup path")))?;
    let file = backup_root
        .create_new_file(&temp_path)
        .map_err(ExecuteError::Io)?;
    let mut args = vec!["exec".to_owned(), "-i".to_owned()];
    if request.db_type == DbType::Postgres {
        args.extend(["-e".into(), format!("PGPASSWORD={}", request.root_password)]);
    }
    args.push(request.container.as_str().to_owned());
    match request.db_type {
        DbType::Mariadb => args.extend([
            "mariadb-dump".into(),
            "-uroot".into(),
            format!("-p{}", request.root_password),
            "--single-transaction".into(),
            "--routines".into(),
            "--triggers".into(),
            request.database.as_str().into(),
        ]),
        DbType::Postgres => args.extend([
            "pg_dump".into(),
            "-U".into(),
            "postgres".into(),
            "--clean".into(),
            "--if-exists".into(),
            "--no-owner".into(),
            "--no-privileges".into(),
            request.database.as_str().into(),
        ]),
    }
    let output = process::run_with_stdout_file(
        &ProcessRequest::new(docker_program).args(args),
        file,
        &ProcessLimits {
            timeout: Duration::from_secs(1800),
            max_stdout_bytes: 0,
            max_stderr_bytes: 64 * 1024,
        },
        cancel,
    )
    .map_err(ExecuteError::Run)?;
    if !matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        let _ = backup_root.remove_file(&temp_path);
        return Err(ExecuteError::Rejected(SubprocessDiagnostics::from_output(
            docker_program,
            &output,
        )));
    }
    backup_root
        .rename(&temp_path, &final_path)
        .map_err(ExecuteError::Io)?;
    let mut pruned = 0;
    if request.retention_days > 0 {
        let cutoff =
            SystemTime::now() - Duration::from_secs(u64::from(request.retention_days) * 86_400);
        let prefix = format!("{}_", request.database.as_str());
        for name in backup_root.file_names().map_err(ExecuteError::Io)? {
            if name != final_name && name.starts_with(&prefix) && name.ends_with(".sql") {
                let path = SiteRelativePath::parse(&name)
                    .map_err(|_| ExecuteError::Io(std::io::Error::other("invalid backup entry")))?;
                if backup_root.modified(&path).map_err(ExecuteError::Io)? < cutoff {
                    backup_root.remove_file(&path).map_err(ExecuteError::Io)?;
                    pruned += 1;
                }
            }
        }
    }
    Ok(CreateResult {
        file_path: format!("{BACKUP_ROOT}/{final_name}"),
        pruned_files: pruned,
        completed_at_unix_secs: now,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    #[test]
    fn validates_the_typed_plan() {
        let id = "123e4567-e89b-12d3-a456-426614174000";
        assert!(Request::parse(r#"{"dbType":"mariadb","database":"site_db","container":"db-1","rootPassword":"secret","retentionDays":7}"#, id, None).is_ok());
        assert!(Request::parse(r#"{"dbType":"mariadb","database":"../db","container":"db-1","rootPassword":"secret","retentionDays":7}"#, id, None).is_err());
    }

    #[test]
    fn streams_and_atomically_publishes_the_dump() {
        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("fake-docker");
        fs::write(&script, "#!/bin/sh\nprintf 'CREATE TABLE example;\\n'\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let backups_path = directory.path().join("backups");
        fs::create_dir(&backups_path).unwrap();
        let backups =
            ManagedRoot::open(&crate::site::TrustedRoot::parse(&backups_path).unwrap()).unwrap();
        let request = Request::parse(
            r#"{"dbType":"mariadb","database":"site_db","container":"db-1","rootPassword":"secret","retentionDays":0}"#,
            "123e4567-e89b-12d3-a456-426614174000",
            None,
        ).unwrap();

        let result = execute(
            &request,
            &backups,
            script.to_str().unwrap(),
            &CancellationToken::default(),
        )
        .unwrap();

        let name = result.file_path.rsplit('/').next().unwrap();
        assert_eq!(
            fs::read_to_string(backups_path.join(name)).unwrap(),
            "CREATE TABLE example;\n"
        );
        assert!(fs::read_dir(&backups_path).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".partial-")
        }));
    }
}
