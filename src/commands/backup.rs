use crate::{
    backup_create,
    backup_delete::{
        BACKUP_ROOT, OPERATION, Request, RequestError,
        execute::{Context, Error, execute},
    },
    backup_deploy, backup_trigger,
    cli::BackupCommand,
    commands::read_root_owned_content_file,
    error::ErrorCode,
    process::CancellationToken,
    protocol::{Response, ResponseBuildError},
};

const CONFIG_PATH: &str = "/etc/operations-engine/config.json";

pub fn run(command: BackupCommand) -> Result<Response, ResponseBuildError> {
    match command {
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
        BackupCommand::Delete {
            request_file,
            request_id,
            idempotency_key,
        } => delete(&request_file, &request_id, idempotency_key.as_deref()),
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
        let _state = match ManagedRoot::open(&config.state_root) {
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
        match backup_create::execute(
            &request,
            &backup_root,
            "docker",
            &CancellationToken::default(),
        ) {
            Ok(value) => Response::success(backup_create::OPERATION, value),
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(backup_create::OPERATION, code, message))
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
