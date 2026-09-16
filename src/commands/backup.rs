use crate::{
    backup_delete::{
        BACKUP_ROOT, OPERATION, Request, RequestError,
        execute::{Context, Error, execute},
    },
    cli::BackupCommand,
    commands::read_root_owned_content_file,
    error::ErrorCode,
    process::CancellationToken,
    protocol::{Response, ResponseBuildError},
};

const CONFIG_PATH: &str = "/etc/operations-engine/config.json";

pub fn run(command: BackupCommand) -> Result<Response, ResponseBuildError> {
    match command {
        BackupCommand::Delete {
            request_file,
            request_id,
            idempotency_key,
        } => delete(&request_file, &request_id, idempotency_key.as_deref()),
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
