use crate::{
    cli::PermissionsCommand,
    commands::{ContentFileError, read_root_owned_content_file},
    error::{ErrorCode, WarningCode},
    permissions::{
        FixOwnershipRequest, FixWorldWritableRequest, OPERATION, RequestError,
        WORLD_WRITABLE_OPERATION,
        execute::{self, FixOwnershipError},
        world_writable::{self, FixWorldWritableError},
    },
    process::CancellationToken,
    protocol::{Response, ResponseBuildError, Warning},
};

const CONFIG_PATH: &str = "/etc/operations-engine/config.json";

pub fn run(command: PermissionsCommand) -> Result<Response, ResponseBuildError> {
    match command {
        PermissionsCommand::FixOwnership {
            owners_file,
            request_id,
            idempotency_key,
        } => fix_ownership(&owners_file, &request_id, idempotency_key.as_deref()),
        PermissionsCommand::FixWorldWritable {
            root,
            request_id,
            idempotency_key,
        } => fix_world_writable(&root, &request_id, idempotency_key.as_deref()),
    }
}

fn fix_world_writable(
    root: &std::path::Path,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{config::EngineConfig, filesystem::ManagedRoot};
        let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
            Ok(config) => config,
            Err(_) => {
                return Ok(Response::failure(
                    WORLD_WRITABLE_OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let request = match FixWorldWritableRequest::parse(
            root,
            &config.content_roots,
            request_id,
            idempotency_key,
        ) {
            Ok(request) => request,
            Err(error) => {
                return Ok(Response::failure(
                    WORLD_WRITABLE_OPERATION,
                    ErrorCode::InvalidInput,
                    request_error_message(error),
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(state) => state,
            Err(_) => {
                return Ok(Response::failure(
                    WORLD_WRITABLE_OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        match world_writable::execute(&state, &request, &CancellationToken::default()) {
            Ok(result) => Response::success(WORLD_WRITABLE_OPERATION, result),
            Err(FixWorldWritableError::PostCommitRecordFailed { result }) => {
                Response::success(WORLD_WRITABLE_OPERATION, result).map(|response| {
                    response.with_warnings(vec![Warning {
                        code: WarningCode::TransactionRecordIncomplete,
                        message: "world-writable permissions were repaired but the transaction record could not be saved".to_owned(),
                    }])
                })
            }
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(WORLD_WRITABLE_OPERATION, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (root, request_id, idempotency_key);
        Ok(Response::failure(
            WORLD_WRITABLE_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "permissions.fixWorldWritable requires a Unix host",
        ))
    }
}

fn fix_ownership(
    path: &std::path::Path,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{config::EngineConfig, filesystem::ManagedRoot};
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
        let json = match read_root_owned_content_file(path) {
            Ok(json) => json,
            Err(ContentFileError::TooLarge) => {
                return Ok(Response::failure(
                    OPERATION,
                    ErrorCode::InvalidInput,
                    "owners-file is too large",
                ));
            }
            Err(ContentFileError::Unreadable) => {
                return Ok(Response::failure(
                    OPERATION,
                    ErrorCode::InvalidInput,
                    "owners-file must be a root-owned regular file",
                ));
            }
        };
        let request = match FixOwnershipRequest::parse(
            &json,
            &config.content_roots,
            request_id,
            idempotency_key,
        ) {
            Ok(request) => request,
            Err(error) => {
                return Ok(Response::failure(
                    OPERATION,
                    ErrorCode::InvalidInput,
                    request_error_message(error),
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(state) => state,
            Err(_) => {
                return Ok(Response::failure(
                    OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        match execute::execute(&state, &request, &CancellationToken::default()) {
            Ok(result) => Response::success(OPERATION, result),
            Err(FixOwnershipError::PostCommitRecordFailed { result }) => {
                Response::success(OPERATION, result).map(|response| {
                    response.with_warnings(vec![Warning {
                        code: WarningCode::TransactionRecordIncomplete,
                        message:
                            "ownership was repaired but its transaction record could not be saved"
                                .to_owned(),
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
        let _ = (path, request_id, idempotency_key);
        Ok(Response::failure(
            OPERATION,
            ErrorCode::UnsupportedPlatform,
            "permissions.fixOwnership requires a Unix host",
        ))
    }
}

fn request_error_message(error: RequestError) -> &'static str {
    match error {
        RequestError::InvalidJson => "owners-file is not a valid ownership plan",
        RequestError::TooManyTargets => "ownership plan has too many targets",
        RequestError::InvalidRoot => "ownership target root is invalid",
        RequestError::RootOutsideContentRoots => {
            "ownership target is outside configured content roots"
        }
        RequestError::OverlappingRoots => "ownership target roots overlap",
        RequestError::InvalidRequestId => "request-id is not a canonical UUID",
        RequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}
