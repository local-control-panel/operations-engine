use crate::{
    cli::IngressCommand,
    error::{ErrorCode, WarningCode},
    ingress::{
        ActivateConfigRequest, ActivateConfigRequestError, OPERATION as ACTIVATE_OPERATION,
        execute::{ActivateConfigError, ActivateContext, execute as execute_activate_config},
    },
    process::CancellationToken,
    protocol::{Response, ResponseBuildError, Warning},
};

const CONFIG_PATH: &str = "/etc/operations-engine/config.json";

pub fn run(command: IngressCommand) -> Result<Response, ResponseBuildError> {
    match command {
        IngressCommand::ActivateConfig {
            domain,
            content_file,
            expected_hash,
            request_id,
            idempotency_key,
        } => activate_config(
            &domain,
            &content_file,
            expected_hash.as_deref(),
            &request_id,
            idempotency_key.as_deref(),
        ),
    }
}

fn activate_config(
    domain: &str,
    content_file: &std::path::Path,
    expected_hash: Option<&str>,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    let guard = match ActivateConfigRequest::guard_from_expected_hash(expected_hash) {
        Ok(guard) => guard,
        Err(error) => {
            return Ok(Response::failure(
                ACTIVATE_OPERATION,
                ErrorCode::InvalidInput,
                activate_config_request_error_message(error),
            ));
        }
    };

    let content = match std::fs::read_to_string(content_file) {
        Ok(content) => content,
        Err(_) => {
            return Ok(Response::failure(
                ACTIVATE_OPERATION,
                ErrorCode::InvalidInput,
                "content-file could not be read",
            ));
        }
    };

    let request =
        match ActivateConfigRequest::parse(domain, content, guard, request_id, idempotency_key) {
            Ok(request) => request,
            Err(error) => {
                return Ok(Response::failure(
                    ACTIVATE_OPERATION,
                    ErrorCode::InvalidInput,
                    activate_config_request_error_message(error),
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
            ACTIVATE_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "ingress.activateConfig requires a Unix host",
        ))
    }
}

#[cfg(unix)]
fn run_activate_config(request: &ActivateConfigRequest) -> Result<Response, ResponseBuildError> {
    use std::path::Path;

    use crate::{compose, config::EngineConfig, filesystem::ManagedRoot};

    let engine_config = match EngineConfig::load_root_owned(Path::new(CONFIG_PATH)) {
        Ok(config) => config,
        Err(_) => {
            return Ok(Response::failure(
                ACTIVATE_OPERATION,
                ErrorCode::Internal,
                "engine configuration is unavailable",
            ));
        }
    };
    let engine_state = match ManagedRoot::open(&engine_config.state_root) {
        Ok(root) => root,
        Err(_) => {
            return Ok(Response::failure(
                ACTIVATE_OPERATION,
                ErrorCode::Internal,
                "engine state root is unavailable",
            ));
        }
    };
    let compose_access = compose::Access::default();
    let context = ActivateContext {
        ingress_root: &engine_config.ingress_root,
        engine_state: &engine_state,
        compose: &compose_access,
    };

    match execute_activate_config(&context, request, &CancellationToken::default()) {
        Ok(result) => Response::success(ACTIVATE_OPERATION, result),
        Err(ActivateConfigError::PostCommitRecordFailed { result, .. }) => {
            Response::success(ACTIVATE_OPERATION, result).map(|response| {
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
            Ok(Response::failure(ACTIVATE_OPERATION, code, &message))
        }
    }
}

fn activate_config_request_error_message(error: ActivateConfigRequestError) -> &'static str {
    match error {
        ActivateConfigRequestError::InvalidDomain => "domain is not a valid domain name",
        ActivateConfigRequestError::ContentTooLarge => {
            "content-file exceeds the maximum allowed route file size"
        }
        ActivateConfigRequestError::InvalidExpectedHash => {
            "expected-hash is not a valid SHA-256 digest"
        }
        ActivateConfigRequestError::InvalidRequestId => "request-id is not a canonical UUID",
        ActivateConfigRequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}
