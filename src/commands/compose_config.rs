use crate::{
    cli::ComposeCommand,
    commands::{ContentFileError, read_content_file},
    compose_config::{
        ComposeActivateConfigRequest, ComposeActivateConfigRequestError, OPERATION,
        execute::{
            ComposeActivateConfigError, ComposeActivateContext, execute as execute_activate_config,
        },
    },
    error::{ErrorCode, WarningCode},
    process::CancellationToken,
    protocol::{Response, ResponseBuildError, Warning},
    site::StackName,
    transaction::{IdempotencyKey, RequestId},
};

pub fn run(command: ComposeCommand) -> Result<Response, ResponseBuildError> {
    match command {
        ComposeCommand::ActivateConfig {
            stack_name,
            content_file,
            expected_hash,
            request_id,
            idempotency_key,
        } => activate_config(
            &stack_name,
            &content_file,
            expected_hash.as_deref(),
            &request_id,
            idempotency_key.as_deref(),
        ),
    }
}

fn activate_config(
    stack_name: &str,
    content_file: &std::path::Path,
    expected_hash: Option<&str>,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    let guard = match ComposeActivateConfigRequest::guard_from_expected_hash(expected_hash) {
        Ok(guard) => guard,
        Err(error) => {
            return Ok(Response::failure(
                OPERATION,
                ErrorCode::InvalidInput,
                request_error_message(error),
            ));
        }
    };
    if let Err(error) = validate_cheap_fields(stack_name, request_id, idempotency_key) {
        return Ok(Response::failure(
            OPERATION,
            ErrorCode::InvalidInput,
            request_error_message(error),
        ));
    }

    let content = match read_content_file(content_file) {
        Ok(content) => content,
        Err(ContentFileError::TooLarge) => {
            return Ok(Response::failure(
                OPERATION,
                ErrorCode::InvalidInput,
                request_error_message(ComposeActivateConfigRequestError::ContentTooLarge),
            ));
        }
        Err(ContentFileError::Unreadable) => {
            return Ok(Response::failure(
                OPERATION,
                ErrorCode::InvalidInput,
                "content-file could not be read",
            ));
        }
    };

    let request = match ComposeActivateConfigRequest::parse(
        stack_name,
        content,
        guard,
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

    #[cfg(unix)]
    {
        run_activate_config(&request)
    }
    #[cfg(not(unix))]
    {
        let _ = request;
        Ok(Response::failure(
            OPERATION,
            ErrorCode::UnsupportedPlatform,
            "compose.activateConfig requires a Unix host",
        ))
    }
}

#[cfg(unix)]
fn run_activate_config(
    request: &ComposeActivateConfigRequest,
) -> Result<Response, ResponseBuildError> {
    use std::path::Path;

    use crate::{compose, config::EngineConfig, filesystem::ManagedRoot, site::TrustedRoot};

    let engine_config =
        match EngineConfig::load_root_owned(Path::new("/etc/operations-engine/config.json")) {
            Ok(config) => config,
            Err(_) => {
                return Ok(Response::failure(
                    OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
    let engine_state = match ManagedRoot::open(&engine_config.state_root) {
        Ok(root) => root,
        Err(_) => {
            return Ok(Response::failure(
                OPERATION,
                ErrorCode::Internal,
                "engine state root is unavailable",
            ));
        }
    };
    // Unlike every other trusted root here, `compose_root` is not sourced
    // from `EngineConfig` - it is resolved dynamically against this
    // process's own identity (`compose::compose_root_dir`'s doc comment
    // explains why `~/compose` cannot be a fixed, operator-configured
    // absolute path). A resolution failure (no home directory for this
    // process's uid) is reported the same way a missing/invalid configured
    // root is elsewhere - `Internal`, no path in the message.
    let compose_root_path = match compose::compose_root_dir() {
        Ok(path) => path,
        Err(_) => {
            return Ok(Response::failure(
                OPERATION,
                ErrorCode::Internal,
                "compose root is unavailable",
            ));
        }
    };
    let compose_root = match TrustedRoot::parse(&compose_root_path) {
        Ok(root) => root,
        Err(_) => {
            return Ok(Response::failure(
                OPERATION,
                ErrorCode::Internal,
                "compose root is unavailable",
            ));
        }
    };
    let context = ComposeActivateContext {
        compose_root: &compose_root,
        engine_state: &engine_state,
        docker_path: None,
    };

    match execute_activate_config(&context, request, &CancellationToken::default()) {
        Ok(result) => Response::success(OPERATION, result),
        Err(ComposeActivateConfigError::PostCommitRecordFailed { result, .. }) => {
            Response::success(OPERATION, result).map(|response| {
                response.with_warnings(vec![Warning {
                    code: WarningCode::TransactionRecordIncomplete,
                    message: "the compose file was activated but its transaction record could \
                              not be saved"
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

fn validate_cheap_fields(
    stack_name: &str,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<(), ComposeActivateConfigRequestError> {
    StackName::parse(stack_name)
        .map_err(|_| ComposeActivateConfigRequestError::InvalidStackName)?;
    RequestId::parse(request_id)
        .map_err(|_| ComposeActivateConfigRequestError::InvalidRequestId)?;
    if let Some(key) = idempotency_key {
        IdempotencyKey::parse(key)
            .map_err(|_| ComposeActivateConfigRequestError::InvalidIdempotencyKey)?;
    }
    Ok(())
}

fn request_error_message(error: ComposeActivateConfigRequestError) -> &'static str {
    match error {
        ComposeActivateConfigRequestError::InvalidStackName => {
            "stack-name is not a valid Compose stack identifier"
        }
        ComposeActivateConfigRequestError::ContentTooLarge => {
            "content-file exceeds the maximum allowed compose file size"
        }
        ComposeActivateConfigRequestError::InvalidExpectedHash => {
            "expected-hash is not a valid SHA-256 digest"
        }
        ComposeActivateConfigRequestError::InvalidRequestId => "request-id is not a canonical UUID",
        ComposeActivateConfigRequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}
