use crate::{
    cli::MeilisearchCommand,
    commands::{ContentFileError, read_root_owned_content_file},
    error::{ErrorCode, WarningCode},
    meilisearch_upgrade::{
        OPERATION, RequestError, UpgradeRequest,
        docker::DockerDriver,
        execute::{Context, Error as UpgradeError, execute},
    },
    process::CancellationToken,
    protocol::{Response, ResponseBuildError, Warning},
};

const CONFIG_PATH: &str = "/etc/operations-engine/config.json";
const CLEANUP_OPERATION: &str = "meilisearch.cleanup";

pub fn run(command: MeilisearchCommand) -> Result<Response, ResponseBuildError> {
    match command {
        MeilisearchCommand::Upgrade {
            request_file,
            request_id,
            idempotency_key,
        } => upgrade(&request_file, &request_id, idempotency_key.as_deref()),
        MeilisearchCommand::Cleanup => cleanup(),
    }
}

fn cleanup() -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{
            compose,
            config::EngineConfig,
            filesystem::ManagedRoot,
            meilisearch_upgrade::{cleanup::cleanup_expired_now, execute::open_state},
        };

        let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
            Ok(config) => config,
            Err(_) => {
                return Ok(Response::failure(
                    CLEANUP_OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let engine_state = match ManagedRoot::open(&config.state_root) {
            Ok(state) => state,
            Err(_) => {
                return Ok(Response::failure(
                    CLEANUP_OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        let scope = match open_state(&engine_state, "wp-stack") {
            Ok(scope) => scope,
            Err(_) => {
                return Ok(Response::failure(
                    CLEANUP_OPERATION,
                    ErrorCode::Internal,
                    "Meilisearch state is unavailable",
                ));
            }
        };
        let stack_dir = match compose::compose_base_dir() {
            Ok(path) => path,
            Err(_) => {
                return Ok(Response::failure(
                    CLEANUP_OPERATION,
                    ErrorCode::Internal,
                    "compose stack is unavailable",
                ));
            }
        };
        let mut driver = DockerDriver::new(&stack_dir, &config.state_root);
        Response::success(CLEANUP_OPERATION, cleanup_expired_now(&scope, &mut driver))
    }
    #[cfg(not(unix))]
    {
        Ok(Response::failure(
            CLEANUP_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "meilisearch.cleanup requires a Unix host",
        ))
    }
}

fn upgrade(
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
        let request = match UpgradeRequest::parse(&json, request_id, idempotency_key) {
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
            Err(UpgradeError::PostCommit { result }) => {
                Response::success(OPERATION, result).map(|response| {
                    response.with_warnings(vec![Warning {
                        code: WarningCode::TransactionRecordIncomplete,
                        message:
                            "Meilisearch was upgraded but its transaction record could not be saved"
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
            "meilisearch.upgrade requires a Unix host",
        ))
    }
}

fn request_error_message(error: RequestError) -> &'static str {
    match error {
        RequestError::InvalidJson => "request-file is not a valid Meilisearch upgrade plan",
        RequestError::InvalidStackName => "stackName must identify the managed wp-stack",
        RequestError::InvalidService => "service must identify the managed meili-1 service",
        RequestError::InvalidSourceVersion => "expectedSourceVersion must be an exact semver",
        RequestError::UnsupportedTargetImage => "targetImage is not the admitted upgrade target",
        RequestError::InvalidSecret => "masterKey is invalid",
        RequestError::InvalidProbe => "searchProbes contains an invalid probe",
        RequestError::TooManyProbes => "searchProbes exceeds the maximum allowed count",
        RequestError::InvalidRequestId => "request-id is not a canonical UUID",
        RequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_request_error_has_a_non_secret_message() {
        let errors = [
            RequestError::InvalidJson,
            RequestError::InvalidStackName,
            RequestError::InvalidService,
            RequestError::InvalidSourceVersion,
            RequestError::UnsupportedTargetImage,
            RequestError::InvalidSecret,
            RequestError::InvalidProbe,
            RequestError::TooManyProbes,
            RequestError::InvalidRequestId,
            RequestError::InvalidIdempotencyKey,
        ];
        for error in errors {
            let message = request_error_message(error);
            assert!(!message.is_empty());
            assert!(!message.contains("master key"));
        }
    }
}
