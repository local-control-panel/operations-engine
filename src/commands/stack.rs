use crate::{
    cli::StackCommand,
    error::ErrorCode,
    protocol::{Response, ResponseBuildError},
};

const OPERATION: &str = "stack.deploy";
#[cfg(unix)]
const CONFIG_PATH: &str = "/etc/operations-engine/config.json";

pub fn run(command: StackCommand) -> Result<Response, ResponseBuildError> {
    match command {
        StackCommand::Deploy {
            request_file,
            request_id,
            idempotency_key,
        } => deploy(&request_file, &request_id, idempotency_key.as_deref()),
    }
}

#[cfg(unix)]
fn deploy(
    request_file: &std::path::Path,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    use crate::{
        commands::{ContentFileError, read_root_owned_content_file},
        compose,
        config::EngineConfig,
        error::WarningCode,
        filesystem::ManagedRoot,
        process::CancellationToken,
        protocol::Warning,
        site::TrustedRoot,
        stack_deploy::{self, Context, Error, Request, Timing},
    };

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
    let request_json = match read_root_owned_content_file(request_file) {
        Ok(content) => content,
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
                "request-file must be a root-owned file that is not group/world-writable",
            ));
        }
    };
    let request = match Request::parse(&request_json, request_id, idempotency_key) {
        Ok(request) => request,
        Err(error) => {
            return Ok(Response::failure(
                OPERATION,
                ErrorCode::InvalidInput,
                error.message(),
            ));
        }
    };
    if !cfg!(target_os = "linux") {
        return Ok(Response::failure(
            OPERATION,
            ErrorCode::UnsupportedPlatform,
            "stack deploy requires a Linux host",
        ));
    }
    let engine_state = match ManagedRoot::open(&config.state_root) {
        Ok(root) => root,
        Err(_) => {
            return Ok(Response::failure(
                OPERATION,
                ErrorCode::Internal,
                "engine state root is unavailable",
            ));
        }
    };
    let stack_root = match compose::compose_base_dir()
        .ok()
        .filter(|path| std::fs::create_dir_all(path).is_ok())
        .and_then(|path| TrustedRoot::parse(path).ok())
    {
        Some(root) => root,
        None => {
            return Ok(Response::failure(
                OPERATION,
                ErrorCode::Internal,
                "stack directory is unavailable",
            ));
        }
    };
    let context = Context {
        engine_state: &engine_state,
        stack_root: &stack_root,
        docker: "docker",
        timing: Timing::PRODUCTION,
    };
    match stack_deploy::execute(&context, &request, &CancellationToken::default()) {
        Ok(result) => Response::success(OPERATION, result),
        Err(Error::PostCommit { result }) => Response::success(OPERATION, result).map(|response| {
            response.with_warnings(vec![Warning {
                code: WarningCode::TransactionRecordIncomplete,
                message: "the stack was deployed but its transaction record could not be \
                              saved"
                    .to_owned(),
            }])
        }),
        Err(error) => {
            let (code, message) = error.protocol();
            Ok(Response::failure(OPERATION, code, &message))
        }
    }
}

#[cfg(not(unix))]
fn deploy(
    _request_file: &std::path::Path,
    _request_id: &str,
    _idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    Ok(Response::failure(
        OPERATION,
        ErrorCode::UnsupportedPlatform,
        "stack deploy requires a Linux host",
    ))
}
