use crate::{
    backup_delete::BACKUP_ROOT,
    db_restore::{ContainerName, DatabaseName, DbType, RestoreRequestError},
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
        commit::PreCommit,
        state::{self, TransactionStatus},
    },
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

    pub fn database(&self) -> &str {
        self.database.as_str()
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

#[derive(Debug)]
pub enum TransactionError {
    Execute(ExecuteError),
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Cancelled,
    PostCommit { result: CreateResult },
    Replayed { code: ErrorCode, message: String },
}

impl TransactionError {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Execute(error) => {
                let (code, message) = error.protocol();
                (code, message.to_owned())
            }
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another backup for this database is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before database backup ran".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Preflight(_) | Self::Io(_) | Self::PostCommit { .. } => {
                (ErrorCode::Internal, "internal database backup error".into())
            }
        }
    }
}

pub fn execute_transactional(
    request: &Request,
    engine_state: &ManagedRoot,
    backup_root: &ManagedRoot,
    docker_program: &str,
    cancel: &CancellationToken,
) -> Result<CreateResult, TransactionError> {
    let scope =
        open_backup_state(engine_state, request.database()).map_err(TransactionError::Io)?;
    let admitted = match preflight::run(
        &scope,
        request.request_id,
        request.idempotency_key.as_ref(),
        OPERATION,
    )
    .map_err(TransactionError::Preflight)?
    {
        preflight::Outcome::Replay(id) => return replay(&scope, id),
        preflight::Outcome::Proceed(value) => value,
    };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path = state_path(request.request_id);
    let audit_path = audit_path();
    let pre_commit = PreCommit::new(cancel.clone());
    if pre_commit.check().is_err() {
        return Err(fail(
            &scope,
            &state_path,
            &audit_path,
            state,
            TransactionError::Cancelled,
        ));
    }
    let result = execute(request, backup_root, docker_program, cancel).map_err(|error| {
        fail(
            &scope,
            &state_path,
            &audit_path,
            state.clone(),
            TransactionError::Execute(error),
        )
    })?;
    let _ = pre_commit.commit();
    state
        .mark_committed(serde_json::to_value(&result).unwrap())
        .unwrap();
    if state::save(&scope, &state_path, &state).is_err() {
        drop(lock);
        return Err(TransactionError::PostCommit { result });
    }
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(request.request_id, true, None),
    );
    drop(lock);
    Ok(result)
}

pub fn open_backup_state(
    engine_state: &ManagedRoot,
    database: &str,
) -> std::io::Result<ManagedRoot> {
    let relative = SiteRelativePath::parse(format!("db-backup/{database}"))
        .expect("a validated DatabaseName always yields a valid relative path");
    engine_state.create_dir_all(&relative)?;
    let scope = engine_state.open_managed_dir(&relative)?;
    for child in ["locks", "transactions", "audit"] {
        scope.create_dir_all(&SiteRelativePath::parse(child).unwrap())?;
    }
    Ok(scope)
}

fn state_path(id: RequestId) -> SiteRelativePath {
    SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap()
}

fn audit_path() -> SiteRelativePath {
    SiteRelativePath::parse("audit/events.jsonl").unwrap()
}

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<CreateResult, TransactionError> {
    let loaded = state::load(scope, &state_path(id))
        .map_err(|error| TransactionError::Io(std::io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != OPERATION {
        return Err(TransactionError::Io(std::io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(TransactionError::ReplayInProgress),
        TransactionStatus::Committed => {
            serde_json::from_value(loaded.outcome.unwrap().result.unwrap())
                .map_err(|error| TransactionError::Io(std::io::Error::other(error)))
        }
        TransactionStatus::Failed => {
            let outcome = loaded.outcome.unwrap();
            Err(TransactionError::Replayed {
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
    error: TransactionError,
) -> TransactionError {
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
    let output = match process::run_with_stdout_file(
        &ProcessRequest::new(docker_program).args(args),
        file,
        &ProcessLimits {
            timeout: Duration::from_secs(1800),
            max_stdout_bytes: 0,
            max_stderr_bytes: 64 * 1024,
        },
        cancel,
    ) {
        Ok(output) => output,
        Err(error) => {
            let _ = backup_root.remove_file(&temp_path);
            return Err(ExecuteError::Run(error));
        }
    };
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
    if let Err(error) = backup_root.rename(&temp_path, &final_path) {
        let _ = backup_root.remove_file(&temp_path);
        return Err(ExecuteError::Io(error));
    }
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

    #[test]
    fn persists_and_replays_a_database_backup_transaction() {
        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("fake-docker-transactional");
        fs::write(&script, "#!/bin/sh\nprintf 'CREATE TABLE example;\\n'\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let backups_path = directory.path().join("backups-transactional");
        let state_dir = directory.path().join("state");
        fs::create_dir(&backups_path).unwrap();
        fs::create_dir(&state_dir).unwrap();
        let backups =
            ManagedRoot::open(&crate::site::TrustedRoot::parse(&backups_path).unwrap()).unwrap();
        let state =
            ManagedRoot::open(&crate::site::TrustedRoot::parse(&state_dir).unwrap()).unwrap();
        let request = Request::parse(
            r#"{"dbType":"mariadb","database":"site_db","container":"db-1","rootPassword":"secret","retentionDays":0}"#,
            "123e4567-e89b-12d3-a456-426614174000",
            Some("backup-site-db"),
        )
        .unwrap();

        let first = execute_transactional(
            &request,
            &state,
            &backups,
            script.to_str().unwrap(),
            &CancellationToken::default(),
        )
        .unwrap();
        let replayed = execute_transactional(
            &request,
            &state,
            &backups,
            script.to_str().unwrap(),
            &CancellationToken::default(),
        )
        .unwrap();

        assert_eq!(replayed.file_path, first.file_path);
        let scope = open_backup_state(&state, "site_db").unwrap();
        let stored = state::load(&scope, &state_path(request.request_id)).unwrap();
        assert_eq!(stored.status, TransactionStatus::Committed);
        assert_eq!(stored.operation, OPERATION);
    }
}
