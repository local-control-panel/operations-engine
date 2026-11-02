use crate::{
    commands::{ContentFileError, read_root_owned_content_file},
    error::{ErrorCode, WarningCode},
    mariadb_migrate::{
        MigrateRequest, OPERATION, RequestError,
        docker::DockerDriver,
        execute::{Context, Error as MigrateError, execute},
    },
    process::CancellationToken,
    protocol::{Response, ResponseBuildError, Warning},
};

const CONFIG_PATH: &str = "/etc/operations-engine/config.json";

pub fn run(
    request_file: &std::path::Path,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{compose, config::EngineConfig, filesystem::ManagedRoot};

        let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
            Ok(config) => config,
            Err(_) => {
                return Ok(Response::failure(
                    OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(request_file) {
            Ok(json) => json,
            Err(ContentFileError::TooLarge) => {
                return Ok(Response::failure(
                    OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file exceeds the maximum allowed size",
                ));
            }
            Err(ContentFileError::Unreadable) => {
                return Ok(Response::failure(
                    OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match MigrateRequest::parse(&json, request_id, idempotency_key) {
            Ok(request) => request,
            Err(error) => {
                return Ok(Response::failure(
                    OPERATION,
                    ErrorCode::InvalidInput,
                    request_error_message(error),
                ));
            }
        };
        let engine_state = match ManagedRoot::open(&config.state_root) {
            Ok(state) => state,
            Err(_) => {
                return Ok(Response::failure(
                    OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        let stack_dir = match compose::compose_base_dir() {
            Ok(path) => path,
            Err(_) => {
                return Ok(Response::failure(
                    OPERATION,
                    ErrorCode::Internal,
                    "compose stack is unavailable",
                ));
            }
        };
        let mut driver = DockerDriver::new(&stack_dir, &config.state_root);
        let mut context = Context {
            engine_state: &engine_state,
            driver: &mut driver,
        };
        match execute(&mut context, &request, &CancellationToken::default()) {
            Ok(result) => Response::success(OPERATION, result),
            Err(MigrateError::PostCommit { result }) => {
                Response::success(OPERATION, result).map(|response| {
                    response.with_warnings(vec![Warning {
                        code: WarningCode::TransactionRecordIncomplete,
                        message:
                            "MariaDB was migrated but its transaction record could not be saved"
                                .into(),
                    }])
                })
            }
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(OPERATION, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (request_file, request_id, idempotency_key);
        Ok(Response::failure(
            OPERATION,
            ErrorCode::UnsupportedPlatform,
            "db.migrateMariadbLine requires a Unix host",
        ))
    }
}

fn request_error_message(error: RequestError) -> &'static str {
    match error {
        RequestError::InvalidJson => "request-file is not a valid MariaDB migration plan",
        RequestError::InvalidStackName => "stackName must identify the managed wp-stack",
        RequestError::InvalidService => {
            "sourceService and targetService must be MariaDB line services"
        }
        RequestError::SameService => "sourceService and targetService must differ",
        RequestError::InvalidSecret => "rootPassword is invalid",
        RequestError::InvalidRequestId => "request-id is not a canonical UUID",
        RequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}
