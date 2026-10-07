use crate::{
    backup_create,
    backup_delete::{
        BACKUP_ROOT, OPERATION, Request, RequestError,
        execute::{Context, Error, execute},
    },
    backup_deploy, backup_import_remote, backup_schedule, backup_trigger,
    cli::BackupCommand,
    commands::read_root_owned_content_file,
    error::ErrorCode,
    process::CancellationToken,
    protocol::{Response, ResponseBuildError},
};

const CONFIG_PATH: &str = "/etc/operations-engine/config.json";

pub fn run(command: BackupCommand) -> Result<Response, ResponseBuildError> {
    match command {
        BackupCommand::InstallRclone {
            request_id,
            idempotency_key,
        } => install_rclone(&request_id, idempotency_key.as_deref()),
        BackupCommand::ImportRemote {
            request_file,
            request_id,
            idempotency_key,
        } => import_remote(&request_file, &request_id, idempotency_key.as_deref()),
        BackupCommand::ActivateConfig {
            request_file,
            request_id,
            idempotency_key,
        } => activate_config(&request_file, &request_id, idempotency_key.as_deref()),
        BackupCommand::TriggerNow {
            request_id,
            idempotency_key,
        } => trigger_now(&request_id, idempotency_key.as_deref()),
        BackupCommand::CreateDatabase {
            request_file,
            request_id,
            idempotency_key,
        } => create_database(&request_file, &request_id, idempotency_key.as_deref()),
        BackupCommand::ScheduleDatabase {
            request_file,
            request_id,
            idempotency_key,
        } => schedule_database(&request_file, &request_id, idempotency_key.as_deref()),
        BackupCommand::UnscheduleDatabase {
            request_file,
            request_id,
            idempotency_key,
        } => unschedule_database(&request_file, &request_id, idempotency_key.as_deref()),
        BackupCommand::ListScheduled => list_scheduled(),
        BackupCommand::RunScheduled {
            db_type,
            database,
            retention_days,
        } => run_scheduled(&db_type, &database, retention_days),
        BackupCommand::Delete {
            request_file,
            request_id,
            idempotency_key,
        } => delete(&request_file, &request_id, idempotency_key.as_deref()),
    }
}

fn import_remote(
    path: &std::path::Path,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{config::EngineConfig, filesystem::ManagedRoot};
        let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    backup_import_remote::OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    backup_import_remote::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match backup_import_remote::Request::parse(&json, request_id, key) {
            Ok(value) => value,
            Err(message) => {
                return Ok(Response::failure(
                    backup_import_remote::OPERATION,
                    ErrorCode::InvalidInput,
                    message,
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    backup_import_remote::OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        let context = backup_import_remote::Context {
            engine_state: &state,
            import_root: std::path::Path::new(backup_import_remote::IMPORT_ROOT),
            rclone_config: std::path::Path::new(backup_import_remote::RCLONE_CONFIG),
            rclone_program: "rclone",
        };
        match backup_import_remote::execute(&context, &request, &CancellationToken::default()) {
            Ok(value) | Err(backup_import_remote::Error::PostCommit { result: value }) => {
                Response::success(backup_import_remote::OPERATION, value)
            }
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(
                    backup_import_remote::OPERATION,
                    code,
                    &message,
                ))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, key);
        Ok(Response::failure(
            backup_import_remote::OPERATION,
            ErrorCode::UnsupportedPlatform,
            "backup.importRemote requires a Unix host",
        ))
    }
}

const INSTALL_RCLONE: &str = "backup.installRclone";

fn install_rclone(request_id: &str, key: Option<&str>) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{
            backup_install_rclone as rclone, config::EngineConfig, engine::fetch,
            filesystem::ManagedRoot, site::TrustedRoot,
        };
        let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    INSTALL_RCLONE,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let request = match rclone::Request::parse(request_id, key) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    INSTALL_RCLONE,
                    ErrorCode::InvalidInput,
                    "request-id or idempotency-key is invalid",
                ));
            }
        };
        let Some(artifact) = rclone::pinned_artifact() else {
            return Ok(Response::failure(
                INSTALL_RCLONE,
                ErrorCode::UnsupportedPlatform,
                "no pinned rclone release for this host (Linux amd64/arm64 only)",
            ));
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    INSTALL_RCLONE,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        let bin_dir_path = std::path::Path::new(rclone::BIN_DIR);
        let bin_dir = match TrustedRoot::parse(bin_dir_path).and_then(|root| {
            ManagedRoot::open(&root).map_err(|_| crate::site::ValidationError::PathResolutionFailed)
        }) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    INSTALL_RCLONE,
                    ErrorCode::Internal,
                    "/usr/bin is unavailable",
                ));
            }
        };
        let existing: Vec<&std::path::Path> = rclone::EXISTING_PATHS
            .iter()
            .map(std::path::Path::new)
            .collect();
        let fetch = |url: &str| {
            fetch::fetch_bytes_bounded(url, rclone::MAX_ARCHIVE_BYTES, rclone::FETCH_TIMEOUT)
        };
        let context = rclone::Context {
            engine_state: &state,
            bin_dir: &bin_dir,
            bin_dir_path,
            existing_paths: &existing,
            artifact: &artifact,
            fetch: &fetch,
        };
        match rclone::execute(&context, &request, &CancellationToken::default()) {
            Ok(value) | Err(rclone::Error::PostCommit { result: value }) => {
                Response::success(INSTALL_RCLONE, value)
            }
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(INSTALL_RCLONE, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (request_id, key);
        Ok(Response::failure(
            INSTALL_RCLONE,
            ErrorCode::UnsupportedPlatform,
            "backup.installRclone requires a Linux host",
        ))
    }
}

fn trigger_now(request_id: &str, key: Option<&str>) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{config::EngineConfig, filesystem::ManagedRoot};
        let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    backup_trigger::OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let request = match backup_trigger::Request::parse(request_id, key) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    backup_trigger::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-id or idempotency-key is invalid",
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    backup_trigger::OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        let context = backup_trigger::Context {
            engine_state: &state,
            bash_program: "bash",
            agent_path: backup_trigger::AGENT_PATH,
        };
        match backup_trigger::execute(&context, &request, &CancellationToken::default()) {
            Ok(value) | Err(backup_trigger::Error::PostCommit { result: value }) => {
                Response::success(backup_trigger::OPERATION, value)
            }
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(backup_trigger::OPERATION, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (request_id, key);
        Ok(Response::failure(
            backup_trigger::OPERATION,
            ErrorCode::UnsupportedPlatform,
            "backup.triggerNow requires a Unix host",
        ))
    }
}

fn activate_config(
    path: &std::path::Path,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{config::EngineConfig, filesystem::ManagedRoot, site::TrustedRoot};
        let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    backup_deploy::OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    backup_deploy::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match backup_deploy::OperationRequest::parse(&json, request_id, key) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    backup_deploy::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file is not a valid backup activation plan",
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    backup_deploy::OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        if std::fs::create_dir_all("/root/.wcp").is_err() {
            return Ok(Response::failure(
                backup_deploy::OPERATION,
                ErrorCode::Internal,
                "backup configuration root is unavailable",
            ));
        }
        let root = match TrustedRoot::parse(std::path::Path::new("/root/.wcp")).and_then(|r| {
            ManagedRoot::open(&r).map_err(|_| crate::site::ValidationError::PathResolutionFailed)
        }) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    backup_deploy::OPERATION,
                    ErrorCode::Internal,
                    "backup configuration root is unavailable",
                ));
            }
        };
        let ctx = backup_deploy::execute::Context {
            engine_state: &state,
            config_root: &root,
            crontab_program: "crontab",
        };
        match backup_deploy::execute::execute(&ctx, &request, &CancellationToken::default()) {
            Ok(v) | Err(backup_deploy::execute::Error::PostCommit { result: v }) => {
                Response::success(backup_deploy::OPERATION, v)
            }
            Err(e) => {
                let (code, message) = e.protocol();
                Ok(Response::failure(backup_deploy::OPERATION, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, key);
        Ok(Response::failure(
            backup_deploy::OPERATION,
            ErrorCode::UnsupportedPlatform,
            "backup.activateConfig requires a Unix host",
        ))
    }
}

fn create_database(
    path: &std::path::Path,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{config::EngineConfig, filesystem::ManagedRoot, site::TrustedRoot};
        let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    backup_create::OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    backup_create::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match backup_create::Request::parse(&json, request_id, key) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    backup_create::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file is not a valid database backup plan",
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    backup_create::OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        if std::fs::create_dir_all(BACKUP_ROOT).is_err() {
            return Ok(Response::failure(
                backup_create::OPERATION,
                ErrorCode::Internal,
                "backup root is unavailable",
            ));
        }
        let backup_root =
            match TrustedRoot::parse(std::path::Path::new(BACKUP_ROOT)).and_then(|root| {
                ManagedRoot::open(&root)
                    .map_err(|_| crate::site::ValidationError::PathResolutionFailed)
            }) {
                Ok(value) => value,
                Err(_) => {
                    return Ok(Response::failure(
                        backup_create::OPERATION,
                        ErrorCode::Internal,
                        "backup root is unavailable",
                    ));
                }
            };
        match backup_create::execute_transactional(
            &request,
            &state,
            &backup_root,
            "docker",
            &CancellationToken::default(),
        ) {
            Ok(value) => Response::success(backup_create::OPERATION, value),
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(backup_create::OPERATION, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, key);
        Ok(Response::failure(
            backup_create::OPERATION,
            ErrorCode::UnsupportedPlatform,
            "backup.createDatabase requires a Unix host",
        ))
    }
}

fn delete(
    path: &std::path::Path,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{config::EngineConfig, filesystem::ManagedRoot, site::TrustedRoot};
        let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match Request::parse(&json, request_id, key) {
            Ok(value) => value,
            Err(error) => {
                return Ok(Response::failure(
                    OPERATION,
                    ErrorCode::InvalidInput,
                    error_message(error),
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        let backup_root =
            match TrustedRoot::parse(std::path::Path::new(BACKUP_ROOT)).and_then(|root| {
                ManagedRoot::open(&root)
                    .map_err(|_| crate::site::ValidationError::PathResolutionFailed)
            }) {
                Ok(value) => value,
                Err(_) => {
                    return Ok(Response::failure(
                        OPERATION,
                        ErrorCode::Internal,
                        "backup root is unavailable",
                    ));
                }
            };
        match execute(
            &Context {
                engine_state: &state,
                backup_root: &backup_root,
            },
            &request,
            &CancellationToken::default(),
        ) {
            Ok(value) => Response::success(OPERATION, value),
            Err(Error::PostCommit { result }) => Response::success(OPERATION, result),
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(OPERATION, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, key);
        Ok(Response::failure(
            OPERATION,
            ErrorCode::UnsupportedPlatform,
            "backup.delete requires a Unix host",
        ))
    }
}

fn error_message(error: RequestError) -> &'static str {
    match error {
        RequestError::InvalidJson => "request-file is not a valid backup deletion plan",
        RequestError::InvalidPath => {
            "file path is outside the managed backup root or is not a SQL artifact"
        }
        RequestError::InvalidRequestId => "request-id is not a canonical UUID",
        RequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}

/// Everything the schedule operations need from the engine config, or the
/// failure response to return instead.
#[cfg(unix)]
struct ScheduleHost {
    state_root: crate::site::TrustedRoot,
    engine_state: crate::filesystem::ManagedRoot,
    credentials: crate::filesystem::ManagedRoot,
}

#[cfg(unix)]
fn schedule_host(operation: &'static str) -> Result<ScheduleHost, Box<Response>> {
    use crate::{config::EngineConfig, filesystem::ManagedRoot};
    let fail = |message: &str| Box::new(Response::failure(operation, ErrorCode::Internal, message));
    let config = EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH))
        .map_err(|_| fail(crate::commands::CONFIG_UNAVAILABLE_MESSAGE))?;
    let engine_state = ManagedRoot::open(&config.state_root)
        .map_err(|_| fail("engine state root is unavailable"))?;
    // A host with no enrolled git-deploy site has no credential directory
    // yet; it is engine-owned, so create it private rather than fail.
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(config.credential_root.as_path())
            .map_err(|_| fail("engine credential root is unavailable"))?;
    }
    let credential_root = ManagedRoot::open(&config.credential_root)
        .map_err(|_| fail("engine credential root is unavailable"))?;
    let credentials = backup_schedule::execute::open_credentials(&credential_root)
        .map_err(|_| fail("backup credential directory is unavailable"))?;
    Ok(ScheduleHost {
        state_root: config.state_root,
        engine_state,
        credentials,
    })
}

fn schedule_request_error(
    operation: &'static str,
    error: backup_schedule::RequestError,
) -> Response {
    use backup_schedule::RequestError;
    let message = match error {
        RequestError::InvalidSchedule => {
            "schedule must be five cron fields or @hourly/@daily/@weekly/@monthly/@yearly"
        }
        RequestError::InvalidRetention => "retentionDays is out of range",
        RequestError::InvalidRequestId => "request-id is not a canonical UUID",
        RequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
        RequestError::InvalidJson | RequestError::InvalidField(_) => {
            "request-file is not a valid scheduled backup plan"
        }
    };
    Response::failure(operation, ErrorCode::InvalidInput, message)
}

fn schedule_database(
    path: &std::path::Path,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use backup_schedule::{SCHEDULE_OPERATION as OP, execute};
        let json = match read_root_owned_content_file(path) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    OP,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match backup_schedule::ScheduleRequest::parse(&json, request_id, key) {
            Ok(value) => value,
            Err(error) => return Ok(schedule_request_error(OP, error)),
        };
        let host = match schedule_host(OP) {
            Ok(host) => host,
            Err(response) => return Ok(*response),
        };
        let context = execute::Context {
            engine_state: &host.engine_state,
            state_root: &host.state_root,
            credentials: &host.credentials,
            crontab_program: "crontab",
        };
        match execute::schedule(&context, &request, &CancellationToken::default()) {
            Ok(value) => Response::success(OP, value),
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(OP, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, key);
        Ok(Response::failure(
            backup_schedule::SCHEDULE_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "backup.scheduleDatabase requires a Unix host",
        ))
    }
}

fn unschedule_database(
    path: &std::path::Path,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use backup_schedule::{UNSCHEDULE_OPERATION as OP, execute};
        let json = match read_root_owned_content_file(path) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    OP,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match backup_schedule::UnscheduleRequest::parse(&json, request_id, key) {
            Ok(value) => value,
            Err(error) => return Ok(schedule_request_error(OP, error)),
        };
        let host = match schedule_host(OP) {
            Ok(host) => host,
            Err(response) => return Ok(*response),
        };
        let context = execute::Context {
            engine_state: &host.engine_state,
            state_root: &host.state_root,
            credentials: &host.credentials,
            crontab_program: "crontab",
        };
        match execute::unschedule(&context, &request, &CancellationToken::default()) {
            Ok(value) => Response::success(OP, value),
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(OP, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, key);
        Ok(Response::failure(
            backup_schedule::UNSCHEDULE_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "backup.unscheduleDatabase requires a Unix host",
        ))
    }
}

fn list_scheduled() -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        match backup_schedule::execute::list("crontab") {
            Ok(value) => Response::success(backup_schedule::LIST_OPERATION, value),
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(
                    backup_schedule::LIST_OPERATION,
                    code,
                    &message,
                ))
            }
        }
    }
    #[cfg(not(unix))]
    {
        Ok(Response::failure(
            backup_schedule::LIST_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "backup.listScheduledDatabase requires a Unix host",
        ))
    }
}

/// The cron entry point. A failure is also written to stderr, because cron
/// discards stdout (`>/dev/null` in the installed line) and mails stderr.
fn run_scheduled(
    db_type: &str,
    database: &str,
    retention_days: u16,
) -> Result<Response, ResponseBuildError> {
    let response = run_scheduled_inner(db_type, database, retention_days)?;
    if let Some(error) = &response.error {
        eprintln!("scheduled backup of {database} failed: {}", error.message);
    }
    Ok(response)
}

fn run_scheduled_inner(
    db_type: &str,
    database: &str,
    retention_days: u16,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{filesystem::ManagedRoot, site::TrustedRoot};
        use backup_schedule::{RUN_OPERATION as OP, execute};
        let request = match backup_schedule::RunRequest::parse(db_type, database, retention_days) {
            Ok(value) => value,
            Err(error) => return Ok(schedule_request_error(OP, error)),
        };
        let host = match schedule_host(OP) {
            Ok(host) => host,
            Err(response) => {
                return Ok(*response);
            }
        };
        if std::fs::create_dir_all(BACKUP_ROOT).is_err() {
            return Ok(Response::failure(
                OP,
                ErrorCode::Internal,
                "backup root is unavailable",
            ));
        }
        let backup_root = match TrustedRoot::parse(std::path::Path::new(BACKUP_ROOT))
            .map_err(|_| ())
            .and_then(|root| ManagedRoot::open(&root).map_err(|_| ()))
        {
            Ok(value) => value,
            Err(()) => {
                return Ok(Response::failure(
                    OP,
                    ErrorCode::Internal,
                    "backup root is unavailable",
                ));
            }
        };
        match execute::run(
            &host.credentials,
            &request,
            &host.engine_state,
            &backup_root,
            "docker",
            &CancellationToken::default(),
        ) {
            Ok(value) => Response::success(OP, value),
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(OP, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (db_type, database, retention_days);
        Ok(Response::failure(
            backup_schedule::RUN_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "backup.runScheduledDatabase requires a Unix host",
        ))
    }
}
