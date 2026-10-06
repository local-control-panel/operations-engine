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
const LIST_OPERATION: &str = "operation.list";
const CONFIG_PATH: &str = "/etc/operations-engine/config.json";

pub fn run(command: OperationCommand) -> Result<Response, ResponseBuildError> {
    match command {
        OperationCommand::Status {
            site_id,
            database,
            backup_database,
            stack,
            request_id,
        } => status(
            site_id.as_deref(),
            database.as_deref(),
            backup_database.as_deref(),
            stack.as_deref(),
            &request_id,
        ),
        OperationCommand::List {
            site_id,
            database,
            backup_database,
            stack,
            limit,
        } => list(
            site_id.as_deref(),
            database.as_deref(),
            backup_database.as_deref(),
            stack.as_deref(),
            limit,
        ),
    }
}

fn list(
    site_id: Option<&str>,
    database: Option<&str>,
    backup_database: Option<&str>,
    stack: Option<&str>,
    limit: Option<usize>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        let config = match EngineConfig::load_root_owned(Path::new(CONFIG_PATH)) {
            Ok(config) => config,
            Err(_) => {
                return Ok(Response::failure(
                    LIST_OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let root = match ManagedRoot::open(&config.state_root) {
            Ok(root) => root,
            Err(_) => {
                return Ok(Response::failure(
                    LIST_OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        match operation_status::list(&root, site_id, database, backup_database, stack, limit) {
            Ok(list) => Response::success(LIST_OPERATION, list),
            Err(
                StatusError::InvalidScope
                | StatusError::InvalidSiteId
                | StatusError::InvalidDatabase
                | StatusError::InvalidRequestId,
            ) => Ok(Response::failure(
                LIST_OPERATION,
                ErrorCode::InvalidInput,
                "invalid operation scope",
            )),
            Err(_) => Ok(Response::failure(
                LIST_OPERATION,
                ErrorCode::Internal,
                "operation records are unavailable",
            )),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (site_id, database, backup_database, stack, limit);
        Ok(Response::failure(
            LIST_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "operation.list requires a Unix host",
        ))
    }
}

fn status(
    site_id: Option<&str>,
    database: Option<&str>,
    backup_database: Option<&str>,
    stack: Option<&str>,
    request_id: &str,
) -> Result<Response, ResponseBuildError> {
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
        let state = match (site_id, database, backup_database, stack) {
            (Some(site_id), None, None, None) => {
                operation_status::load_site(&root, site_id, request_id)
            }
            (None, Some(database), None, None) => {
                operation_status::load_database(&root, database, request_id)
            }
            (None, None, Some(database), None) => {
                operation_status::load_backup(&root, database, request_id)
            }
            (None, None, None, Some(stack)) => {
                operation_status::load_stack(&root, stack, request_id)
            }
            _ => Err(StatusError::InvalidScope),
        };
        match state {
            Ok(state) => Response::success(OPERATION, state),
            Err(
                StatusError::InvalidScope
                | StatusError::InvalidSiteId
                | StatusError::InvalidDatabase
                | StatusError::InvalidRequestId,
            ) => Ok(Response::failure(
                OPERATION,
                ErrorCode::InvalidInput,
                "invalid operation identity",
            )),
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
        let _ = (site_id, database, backup_database, stack, request_id);
        Ok(Response::failure(
            OPERATION,
            ErrorCode::UnsupportedPlatform,
            "operation.status requires a Unix host",
        ))
    }
}
