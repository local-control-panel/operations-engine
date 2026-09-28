use std::path::Path;

use crate::{
    cli::OperationCommand,
    config::EngineConfig,
    error::ErrorCode,
    filesystem::ManagedRoot,
    operation_status::{self, StatusError},
    protocol::{Response, ResponseBuildError},
};

const OPERATION: &str = "operation.status";
const CONFIG_PATH: &str = "/etc/operations-engine/config.json";

pub fn run(command: OperationCommand) -> Result<Response, ResponseBuildError> {
    match command {
        OperationCommand::Status {
            site_id,
            request_id,
        } => status(&site_id, &request_id),
    }
}

fn status(site_id: &str, request_id: &str) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        let config = match EngineConfig::load_root_owned(Path::new(CONFIG_PATH)) {
            Ok(config) => config,
            Err(_) => {
                return Ok(Response::failure(
                    OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let root = match ManagedRoot::open(&config.state_root) {
            Ok(root) => root,
            Err(_) => {
                return Ok(Response::failure(
                    OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        match operation_status::load(&root, site_id, request_id) {
            Ok(state) => Response::success(OPERATION, state),
            Err(StatusError::InvalidSiteId | StatusError::InvalidRequestId) => Ok(
                Response::failure(
                    OPERATION,
                    ErrorCode::InvalidInput,
                    "invalid operation identity",
                ),
            ),
            Err(StatusError::NotFound) => Ok(Response::failure(
                OPERATION,
                ErrorCode::NotFound,
                "operation record was not found",
            )),
            Err(StatusError::Corrupt | StatusError::Io) => Ok(Response::failure(
                OPERATION,
                ErrorCode::Internal,
                "operation record is unavailable",
            )),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (site_id, request_id);
        Ok(Response::failure(
            OPERATION,
            ErrorCode::UnsupportedPlatform,
            "operation.status requires a Unix host",
        ))
    }
}
