use crate::{
    cli::EngineCommand,
    engine::{
        EngineInstallRequest, EngineInstallRequestError, EngineRollbackRequest,
        EngineRollbackRequestError,
        install::{InstallContext, InstallError, execute as execute_install},
        rollback::{RollbackContext, RollbackError, execute as execute_rollback},
    },
    error::{ErrorCode, WarningCode},
    process::CancellationToken,
    protocol::{Response, ResponseBuildError, Warning},
};

/// The fixed, compiled-in GitHub Releases base URL every production
/// `engine install`/`engine rollback` call fetches from. Never a CLI
/// flag or protocol input — see `InstallContext::release_base_url`'s
/// doc comment for why tests pass a different value directly.
pub const GITHUB_RELEASES_BASE: &str =
    "https://github.com/skanevi/operations-engine/releases/download";

const INSTALL_OPERATION: &str = "engine.install";
const ROLLBACK_OPERATION: &str = "engine.rollback";
const CONFIG_PATH: &str = "/etc/operations-engine/config.json";
const BIN_ROOT: &str = "/usr/local/bin";

pub fn run(command: EngineCommand) -> Result<Response, ResponseBuildError> {
    match command {
        EngineCommand::Install {
            version,
            request_id,
            idempotency_key,
        } => install(&version, &request_id, idempotency_key.as_deref()),
        EngineCommand::Rollback {
            request_id,
            idempotency_key,
        } => rollback(&request_id, idempotency_key.as_deref()),
    }
}

fn install(
    version: &str,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    let request = match EngineInstallRequest::parse(version, request_id, idempotency_key) {
        Ok(request) => request,
        Err(error) => {
            return Ok(Response::failure(
                INSTALL_OPERATION,
                ErrorCode::InvalidInput,
                install_request_error_message(error),
            ));
        }
    };

    #[cfg(unix)]
    {
        run_install(&request)
    }
    #[cfg(not(unix))]
    {
        let _ = request;
        Ok(Response::failure(
            INSTALL_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "engine.install requires a Unix host",
        ))
    }
}

#[cfg(unix)]
fn run_install(request: &EngineInstallRequest) -> Result<Response, ResponseBuildError> {
    use std::path::Path;

    use crate::{config::EngineConfig, filesystem::ManagedRoot, site::TrustedRoot};

    let engine_config = match EngineConfig::load_root_owned(Path::new(CONFIG_PATH)) {
        Ok(config) => config,
        Err(_) => {
            return Ok(Response::failure(
                INSTALL_OPERATION,
                ErrorCode::Internal,
                "engine configuration is unavailable",
            ));
        }
    };
    let bin_root =
        TrustedRoot::parse(Path::new(BIN_ROOT)).expect("BIN_ROOT is a valid literal trusted root");
    let engine_state = match ManagedRoot::open(&engine_config.state_root) {
        Ok(root) => root,
        Err(_) => {
            return Ok(Response::failure(
                INSTALL_OPERATION,
                ErrorCode::Internal,
                "engine state root is unavailable",
            ));
        }
    };
    let context = InstallContext {
        bin_root: &bin_root,
        engine_state: &engine_state,
        state_root: &engine_config.state_root,
        release_base_url: GITHUB_RELEASES_BASE,
    };

    match execute_install(&context, request, &CancellationToken::default()) {
        Ok(result) => Response::success(INSTALL_OPERATION, result),
        Err(InstallError::PostCommitRecordFailed { result, .. }) => {
            Response::success(INSTALL_OPERATION, result).map(|response| {
                response.with_warnings(vec![Warning {
                    code: WarningCode::TransactionRecordIncomplete,
                    message: "the install completed but its transaction record could not be saved"
                        .to_owned(),
                }])
            })
        }
        Err(InstallError::PostCommitInstallStateFailed { result, .. }) => {
            Response::success(INSTALL_OPERATION, result).map(|response| {
                response.with_warnings(vec![Warning {
                    code: WarningCode::InstallStateRecordIncomplete,
                    message: "the install completed but the installed-version record could not be \
                              saved — engine rollback may target the wrong version until it is \
                              repaired"
                        .to_owned(),
                }])
            })
        }
        Err(error) => {
            let (code, message) = error.protocol();
            Ok(Response::failure(INSTALL_OPERATION, code, &message))
        }
    }
}

fn install_request_error_message(error: EngineInstallRequestError) -> &'static str {
    match error {
        EngineInstallRequestError::InvalidVersion => {
            "version is not a valid MAJOR.MINOR.PATCH version"
        }
        EngineInstallRequestError::InvalidRequestId => "request-id is not a canonical UUID",
        EngineInstallRequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}

fn rollback(
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    let request = match EngineRollbackRequest::parse(request_id, idempotency_key) {
        Ok(request) => request,
        Err(error) => {
            return Ok(Response::failure(
                ROLLBACK_OPERATION,
                ErrorCode::InvalidInput,
                rollback_request_error_message(error),
            ));
        }
    };

    #[cfg(unix)]
    {
        run_rollback(&request)
    }
    #[cfg(not(unix))]
    {
        let _ = request;
        Ok(Response::failure(
            ROLLBACK_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "engine.rollback requires a Unix host",
        ))
    }
}

#[cfg(unix)]
fn run_rollback(request: &EngineRollbackRequest) -> Result<Response, ResponseBuildError> {
    use std::path::Path;

    use crate::{config::EngineConfig, filesystem::ManagedRoot, site::TrustedRoot};

    let engine_config = match EngineConfig::load_root_owned(Path::new(CONFIG_PATH)) {
        Ok(config) => config,
        Err(_) => {
            return Ok(Response::failure(
                ROLLBACK_OPERATION,
                ErrorCode::Internal,
                "engine configuration is unavailable",
            ));
        }
    };
    let bin_root =
        TrustedRoot::parse(Path::new(BIN_ROOT)).expect("BIN_ROOT is a valid literal trusted root");
    let engine_state = match ManagedRoot::open(&engine_config.state_root) {
        Ok(root) => root,
        Err(_) => {
            return Ok(Response::failure(
                ROLLBACK_OPERATION,
                ErrorCode::Internal,
                "engine state root is unavailable",
            ));
        }
    };
    let context = RollbackContext {
        bin_root: &bin_root,
        engine_state: &engine_state,
    };

    match execute_rollback(&context, request, &CancellationToken::default()) {
        Ok(result) => Response::success(ROLLBACK_OPERATION, result),
        Err(RollbackError::PostCommitRecordFailed { result, .. }) => {
            Response::success(ROLLBACK_OPERATION, result).map(|response| {
                response.with_warnings(vec![Warning {
                    code: WarningCode::TransactionRecordIncomplete,
                    message: "the rollback completed but its transaction record could not be saved"
                        .to_owned(),
                }])
            })
        }
        Err(RollbackError::PostCommitInstallStateFailed { result, .. }) => {
            Response::success(ROLLBACK_OPERATION, result).map(|response| {
                response.with_warnings(vec![Warning {
                    code: WarningCode::InstallStateRecordIncomplete,
                    message: "the rollback completed but the installed-version record could not \
                              be saved — a further engine rollback may target the wrong version \
                              until it is repaired"
                        .to_owned(),
                }])
            })
        }
        Err(error) => {
            let (code, message) = error.protocol();
            Ok(Response::failure(ROLLBACK_OPERATION, code, &message))
        }
    }
}

fn rollback_request_error_message(error: EngineRollbackRequestError) -> &'static str {
    match error {
        EngineRollbackRequestError::InvalidRequestId => "request-id is not a canonical UUID",
        EngineRollbackRequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}
