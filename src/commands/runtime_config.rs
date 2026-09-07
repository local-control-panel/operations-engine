use crate::{
    cli::RuntimeCommand,
    commands::{ContentFileError, read_content_file},
    error::{ErrorCode, WarningCode},
    process::CancellationToken,
    protocol::{Response, ResponseBuildError, Warning},
    runtime_config::{
        OPERATION, RuntimeActivateConfigRequest, RuntimeActivateConfigRequestError,
        execute::{
            RuntimeActivateConfigError, RuntimeActivateContext, execute as execute_activate_config,
        },
    },
    site::{Domain, RuntimeId},
    transaction::{IdempotencyKey, RequestId},
};

const CONFIG_PATH: &str = "/etc/operations-engine/config.json";

pub fn run(command: RuntimeCommand) -> Result<Response, ResponseBuildError> {
    match command {
        RuntimeCommand::ActivateConfig {
            runtime_id,
            domain,
            content_file,
            expected_hash,
            request_id,
            idempotency_key,
        } => activate_config(
            &runtime_id,
            &domain,
            &content_file,
            expected_hash.as_deref(),
            &request_id,
            idempotency_key.as_deref(),
        ),
    }
}

fn activate_config(
    runtime_id: &str,
    domain: &str,
    content_file: &std::path::Path,
    expected_hash: Option<&str>,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    // Same ordering `ingress::commands::activate_config` uses and for the
    // same reason: reject a malformed field before this root-privileged
    // process ever touches the filesystem for the content path.
    // `RuntimeActivateConfigRequest::parse` below re-validates these same
    // fields (it is the single authoritative constructor for the request),
    // but by then they are already known-good, so that is cheap string
    // work, not new I/O.
    let guard = match RuntimeActivateConfigRequest::guard_from_expected_hash(expected_hash) {
        Ok(guard) => guard,
        Err(error) => {
            return Ok(Response::failure(
                OPERATION,
                ErrorCode::InvalidInput,
                request_error_message(error),
            ));
        }
    };
    if let Err(error) = validate_cheap_fields(runtime_id, domain, request_id, idempotency_key) {
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
                request_error_message(RuntimeActivateConfigRequestError::ContentTooLarge),
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

    let request = match RuntimeActivateConfigRequest::parse(
        runtime_id,
        domain,
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
            "runtime.activateConfig requires a Unix host",
        ))
    }
}

#[cfg(unix)]
fn run_activate_config(
    request: &RuntimeActivateConfigRequest,
) -> Result<Response, ResponseBuildError> {
    use std::path::Path;

    use crate::{compose, config::EngineConfig, filesystem::ManagedRoot};

    let engine_config = match EngineConfig::load_root_owned(Path::new(CONFIG_PATH)) {
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
    let compose_access = compose::Access::default();
    let context = RuntimeActivateContext {
        runtime_root: &engine_config.runtime_root,
        engine_state: &engine_state,
        compose: &compose_access,
    };

    match execute_activate_config(&context, request, &CancellationToken::default()) {
        Ok(result) => Response::success(OPERATION, result),
        Err(RuntimeActivateConfigError::PostCommitRecordFailed { result, .. }) => {
            Response::success(OPERATION, result).map(|response| {
                response.with_warnings(vec![Warning {
                    code: WarningCode::TransactionRecordIncomplete,
                    message: "the configuration was activated but its transaction record could \
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

/// Validates `runtime_id`, `domain`, `request_id`, and `idempotency_key` —
/// every field `RuntimeActivateConfigRequest::parse` checks that does not
/// depend on the content file's bytes — using the same underlying parsers
/// it uses, so a malformed request is rejected before `content_file` is
/// ever read. Mirrors `ingress::commands::validate_cheap_fields`.
fn validate_cheap_fields(
    runtime_id: &str,
    domain: &str,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<(), RuntimeActivateConfigRequestError> {
    RuntimeId::parse(runtime_id)
        .map_err(|_| RuntimeActivateConfigRequestError::InvalidRuntimeId)?;
    Domain::parse(domain).map_err(|_| RuntimeActivateConfigRequestError::InvalidDomain)?;
    RequestId::parse(request_id)
        .map_err(|_| RuntimeActivateConfigRequestError::InvalidRequestId)?;
    if let Some(key) = idempotency_key {
        IdempotencyKey::parse(key)
            .map_err(|_| RuntimeActivateConfigRequestError::InvalidIdempotencyKey)?;
    }
    Ok(())
}

fn request_error_message(error: RuntimeActivateConfigRequestError) -> &'static str {
    match error {
        RuntimeActivateConfigRequestError::InvalidRuntimeId => {
            "runtime-id is not a valid runtime pool identifier"
        }
        RuntimeActivateConfigRequestError::InvalidDomain => "domain is not a valid domain name",
        RuntimeActivateConfigRequestError::ContentTooLarge => {
            "content-file exceeds the maximum allowed fragment size"
        }
        RuntimeActivateConfigRequestError::InvalidExpectedHash => {
            "expected-hash is not a valid SHA-256 digest"
        }
        RuntimeActivateConfigRequestError::InvalidRequestId => "request-id is not a canonical UUID",
        RuntimeActivateConfigRequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}
