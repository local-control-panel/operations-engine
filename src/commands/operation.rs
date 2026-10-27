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
const INCOMPLETE_OPERATION: &str = "operation.incomplete";
const CONFIG_PATH: &str = "/etc/operations-engine/config.json";

fn incomplete() -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        let Ok(config) = EngineConfig::load_root_owned(Path::new(CONFIG_PATH)) else {
            return Ok(Response::failure(
                INCOMPLETE_OPERATION,
                ErrorCode::Internal,
                crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
            ));
        };
        let Ok(root) = ManagedRoot::open(&config.state_root) else {
            return Ok(Response::failure(
                INCOMPLETE_OPERATION,
                ErrorCode::Internal,
                "engine state root is unavailable",
            ));
        };
        match operation_status::incomplete(&root, config.state_root.as_path()) {
            Ok(list) => Response::success(INCOMPLETE_OPERATION, list),
            Err(_) => Ok(Response::failure(
                INCOMPLETE_OPERATION,
                ErrorCode::Internal,
                "operation records are unavailable",
            )),
        }
    }
    #[cfg(not(unix))]
    {
        Ok(Response::failure(
            INCOMPLETE_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "operation.incomplete requires a Unix host",
        ))
    }
}

pub fn run(command: OperationCommand) -> Result<Response, ResponseBuildError> {
    match command {
        OperationCommand::Incomplete => incomplete(),
        OperationCommand::ResourceStatus {
            resource_operation,
            resource,
            request_id,
        } => resource_status(&resource_operation, &resource, &request_id),
        OperationCommand::Status {
            site_id,
            create_domain,
            database,
            backup_database,
            stack,
            request_id,
        } => status(
            site_id.as_deref(),
            create_domain.as_deref(),
            database.as_deref(),
            backup_database.as_deref(),
            stack.as_deref(),
            &request_id,
        ),
        OperationCommand::List {
            site_id,
            create_domain,
            database,
            backup_database,
            stack,
            limit,
        } => list(
            site_id.as_deref(),
            create_domain.as_deref(),
            database.as_deref(),
            backup_database.as_deref(),
            stack.as_deref(),
            limit,
        ),
    }
}

fn list(
    site_id: Option<&str>,
    create_domain: Option<&str>,
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
        let result = if let Some(domain) = create_domain {
            if site_id.is_some()
                || database.is_some()
                || backup_database.is_some()
                || stack.is_some()
            {
                Err(StatusError::InvalidScope)
            } else {
                operation_status::list_create(&root, domain, limit)
            }
        } else {
            operation_status::list(&root, site_id, database, backup_database, stack, limit)
        };
        match result {
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
        let _ = (
            site_id,
            create_domain,
            database,
            backup_database,
            stack,
            limit,
        );
        Ok(Response::failure(
            LIST_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "operation.list requires a Unix host",
        ))
    }
}

fn status(
    site_id: Option<&str>,
    create_domain: Option<&str>,
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
        let state = if let Some(domain) = create_domain {
            if site_id.is_some()
                || database.is_some()
                || backup_database.is_some()
                || stack.is_some()
            {
                Err(StatusError::InvalidScope)
            } else {
                operation_status::load_create(&root, domain, request_id)
            }
        } else {
            match (site_id, database, backup_database, stack) {
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
            }
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
        let _ = (
            site_id,
            create_domain,
            database,
            backup_database,
            stack,
            request_id,
        );
        Ok(Response::failure(
            OPERATION,
            ErrorCode::UnsupportedPlatform,
            "operation.status requires a Unix host",
        ))
    }
}

fn resource_status(
    operation: &str,
    resource: &str,
    id: &str,
) -> Result<Response, ResponseBuildError> {
    const NAME: &str = "operation.resourceStatus";
    #[cfg(unix)]
    {
        let config = match EngineConfig::load_root_owned(Path::new(CONFIG_PATH)) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    NAME,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let root = match ManagedRoot::open(&config.state_root) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    NAME,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        match operation_status::load_resource(&root, &config.content_roots, operation, resource, id)
        {
            Ok(v) => Response::success(NAME, v),
            Err(StatusError::NotFound) => Ok(Response::failure(
                NAME,
                ErrorCode::NotFound,
                "the engine has no durable record for this request",
            )),
            Err(StatusError::InvalidScope | StatusError::InvalidRequestId) => {
                Ok(Response::failure(
                    NAME,
                    ErrorCode::InvalidInput,
                    "unsupported operation resource",
                ))
            }
            Err(_) => Ok(Response::failure(
                NAME,
                ErrorCode::Internal,
                "operation record could not be validated",
            )),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (operation, resource, id);
        Ok(Response::failure(
            NAME,
            ErrorCode::UnsupportedPlatform,
            "resource status requires Unix",
        ))
    }
}
