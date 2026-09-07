use crate::{
    cli::CronCommand,
    commands::{ContentFileError, read_content_file},
    cron::{
        InstallTabRequest, InstallTabRequestError, OPERATION,
        execute::{InstallTabContext, InstallTabError, execute as execute_install_tab},
    },
    error::{ErrorCode, WarningCode},
    process::CancellationToken,
    protocol::{Response, ResponseBuildError, Warning},
    transaction::{IdempotencyKey, RequestId},
};

const CONFIG_PATH: &str = "/etc/operations-engine/config.json";

pub fn run(command: CronCommand) -> Result<Response, ResponseBuildError> {
    match command {
        CronCommand::InstallTab {
            content_file,
            expected_hash,
            request_id,
            idempotency_key,
        } => install_tab(
            &content_file,
            expected_hash.as_deref(),
            &request_id,
            idempotency_key.as_deref(),
        ),
    }
}

fn install_tab(
    content_file: &std::path::Path,
    expected_hash: Option<&str>,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    let guard = match InstallTabRequest::guard_from_expected_hash(expected_hash) {
        Ok(guard) => guard,
        Err(error) => {
            return Ok(Response::failure(
                OPERATION,
                ErrorCode::InvalidInput,
                request_error_message(error),
            ));
        }
    };
    if let Err(error) = validate_cheap_fields(request_id, idempotency_key) {
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
                request_error_message(InstallTabRequestError::ContentTooLarge),
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

    let request = match InstallTabRequest::parse(content, guard, request_id, idempotency_key) {
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
        run_install_tab(&request)
    }
    #[cfg(not(unix))]
    {
        let _ = request;
        Ok(Response::failure(
            OPERATION,
            ErrorCode::UnsupportedPlatform,
            "cron.installTab requires a Unix host",
        ))
    }
}

#[cfg(unix)]
fn run_install_tab(request: &InstallTabRequest) -> Result<Response, ResponseBuildError> {
    use std::path::Path;

    use crate::{config::EngineConfig, filesystem::ManagedRoot};

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
    let context = InstallTabContext {
        state_root: &engine_config.state_root,
        engine_state: &engine_state,
        crontab_program: "crontab",
    };

    match execute_install_tab(&context, request, &CancellationToken::default()) {
        Ok(result) => Response::success(OPERATION, result),
        Err(InstallTabError::PostCommitRecordFailed { result, .. }) => {
            Response::success(OPERATION, result).map(|response| {
                response.with_warnings(vec![Warning {
                    code: WarningCode::TransactionRecordIncomplete,
                    message: "the crontab was installed but its transaction record could not be \
                              saved"
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
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<(), InstallTabRequestError> {
    RequestId::parse(request_id).map_err(|_| InstallTabRequestError::InvalidRequestId)?;
    if let Some(key) = idempotency_key {
        IdempotencyKey::parse(key).map_err(|_| InstallTabRequestError::InvalidIdempotencyKey)?;
    }
    Ok(())
}

fn request_error_message(error: InstallTabRequestError) -> &'static str {
    match error {
        InstallTabRequestError::ContentTooLarge => {
            "content-file exceeds the maximum allowed crontab size"
        }
        InstallTabRequestError::InvalidExpectedHash => {
            "expected-hash is not a valid SHA-256 digest"
        }
        InstallTabRequestError::InvalidRequestId => "request-id is not a canonical UUID",
        InstallTabRequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}
