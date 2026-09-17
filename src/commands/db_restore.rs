use crate::{
    cli::{DbCommand, DbTypeArg},
    commands::{ContentFileError, read_root_owned_content_file},
    db_export::{self, OPERATION as EXPORT_OPERATION},
    db_provision::{
        OPERATION as PROVISION_OPERATION, ProvisionRequest, RequestError as ProvisionRequestError,
        execute::{ProvisionContext, ProvisionError, execute as execute_provision},
    },
    db_restore::{
        OPERATION, RestoreRequest, RestoreRequestError,
        execute::{RestoreContext, RestoreError, execute as execute_restore},
    },
    db_tool::{
        OPERATION as TOOL_OPERATION, REMOVE_OPERATION, RemoveRequest, Request as ToolRequest,
        RequestError as ToolRequestError,
        execute::{Context as ToolContext, Error as ToolError, execute as execute_tool},
        remove::{Context as RemoveContext, Error as RemoveError, execute as execute_remove},
    },
    error::{ErrorCode, WarningCode},
    maria_drop::{
        OPERATION as MARIA_DROP_OPERATION, Request as MariaDropRequest,
        RequestError as MariaDropRequestError,
        execute::{
            Context as MariaDropContext, Error as MariaDropError, execute as execute_maria_drop,
        },
    },
    maria_slow_log::{
        self, OPERATION as MARIA_SLOW_LOG_OPERATION, SET_OPERATION as MARIA_SLOW_LOG_SET_OPERATION,
        execute::{Context as MariaSlowLogContext, Error as MariaSlowLogError},
        set::{Context as MariaSlowLogSetContext, Error as MariaSlowLogSetError},
    },
    maria_user::{
        DROP_OPERATION as MARIA_USER_DROP_OPERATION, DropRequest as MariaUserDropRequest,
        RequestError as MariaUserRequestError,
        drop::{
            Context as MariaUserDropContext, Error as MariaUserDropError,
            execute as execute_maria_user_drop,
        },
    },
    pg_drop::{
        OPERATION as PG_DROP_OPERATION, Request as PgDropRequest,
        RequestError as PgDropRequestError,
        execute::{Context as PgDropContext, Error as PgDropError, execute as execute_pg_drop},
    },
    pg_provision::{
        OPERATION as PG_PROVISION_OPERATION, Request as PgProvisionRequest,
        RequestError as PgProvisionRequestError,
        execute::{
            Context as PgProvisionContext, Error as PgProvisionError,
            execute as execute_pg_provision,
        },
    },
    pg_user::{
        DROP_OPERATION as PG_USER_DROP_OPERATION, DropRequest as PgUserDropRequest,
        OPERATION as PG_USER_OPERATION, Request as PgUserRequest,
        RequestError as PgUserRequestError,
        drop::{
            Context as PgUserDropContext, Error as PgUserDropError, execute as execute_pg_user_drop,
        },
        execute::{Context as PgUserContext, Error as PgUserError, execute as execute_pg_user},
    },
    process::CancellationToken,
    protocol::{Response, ResponseBuildError, Warning},
    valkey::{
        DELETE_OPERATION as VALKEY_DELETE_OPERATION, DeleteRequest as ValkeyDeleteRequest,
        FLUSH_ALL_OPERATION as VALKEY_FLUSH_ALL_OPERATION,
        FLUSH_DB_OPERATION as VALKEY_FLUSH_DB_OPERATION, FlushAllRequest, FlushDbRequest,
        RequestError as ValkeyRequestError,
        delete::{
            Context as ValkeyDeleteContext, Error as ValkeyDeleteError,
            execute as execute_valkey_delete,
        },
        flush::{
            Context as ValkeyFlushContext, Error as ValkeyFlushError,
            execute as execute_valkey_flush,
        },
        flush_all::{
            Context as ValkeyFlushAllContext, Error as ValkeyFlushAllError,
            execute as execute_valkey_flush_all,
        },
    },
};

const CONFIG_PATH: &str = "/etc/operations-engine/config.json";

pub fn run(command: DbCommand) -> Result<Response, ResponseBuildError> {
    match command {
        DbCommand::Export { request_file } => export(&request_file),
        DbCommand::ToolConverge {
            request_file,
            request_id,
            idempotency_key,
        } => tool_converge(&request_file, &request_id, idempotency_key.as_deref()),
        DbCommand::ToolRemove {
            request_file,
            request_id,
            idempotency_key,
        } => tool_remove(&request_file, &request_id, idempotency_key.as_deref()),
        DbCommand::ProvisionMariadb {
            request_file,
            request_id,
            idempotency_key,
        } => provision_mariadb(&request_file, &request_id, idempotency_key.as_deref()),
        DbCommand::DropMariadb {
            request_file,
            request_id,
            idempotency_key,
        } => drop_mariadb(&request_file, &request_id, idempotency_key.as_deref()),
        DbCommand::DropMariadbUser {
            request_file,
            request_id,
            idempotency_key,
        } => drop_mariadb_user(&request_file, &request_id, idempotency_key.as_deref()),
        DbCommand::ClearMariadbSlowLog {
            request_file,
            request_id,
            idempotency_key,
        } => clear_mariadb_slow_log(&request_file, &request_id, idempotency_key.as_deref()),
        DbCommand::DeleteValkeyKey {
            request_file,
            request_id,
            idempotency_key,
        } => delete_valkey_key(&request_file, &request_id, idempotency_key.as_deref()),
        DbCommand::FlushValkeyDb {
            request_file,
            request_id,
            idempotency_key,
        } => flush_valkey_db(&request_file, &request_id, idempotency_key.as_deref()),
        DbCommand::FlushAllValkey {
            request_file,
            request_id,
            idempotency_key,
        } => flush_all_valkey(&request_file, &request_id, idempotency_key.as_deref()),
        DbCommand::ProvisionPostgres {
            request_file,
            request_id,
            idempotency_key,
        } => provision_postgres(&request_file, &request_id, idempotency_key.as_deref()),
        DbCommand::DropPostgres {
            request_file,
            request_id,
            idempotency_key,
        } => drop_postgres(&request_file, &request_id, idempotency_key.as_deref()),
        DbCommand::ProvisionPostgresUser {
            request_file,
            request_id,
            idempotency_key,
        } => provision_postgres_user(&request_file, &request_id, idempotency_key.as_deref()),
        DbCommand::DropPostgresUser {
            request_file,
            request_id,
            idempotency_key,
        } => drop_postgres_user(&request_file, &request_id, idempotency_key.as_deref()),
        DbCommand::Restore {
            db_type,
            database,
            container,
            file_path,
            root_password,
            request_id,
            idempotency_key,
        } => restore(
            db_type,
            &database,
            &container,
            file_path,
            root_password,
            &request_id,
            idempotency_key.as_deref(),
        ),
        DbCommand::ConfigureMariadbSlowLog {
            request_file,
            request_id,
            idempotency_key,
        } => configure_mariadb_slow_log(&request_file, &request_id, idempotency_key.as_deref()),
    }
}

fn configure_mariadb_slow_log(
    path: &std::path::Path,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{config::EngineConfig, filesystem::ManagedRoot};
        let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    MARIA_SLOW_LOG_SET_OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    MARIA_SLOW_LOG_SET_OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match maria_slow_log::SetRequest::parse(&json, request_id, key) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    MARIA_SLOW_LOG_SET_OPERATION,
                    ErrorCode::InvalidInput,
                    "MariaDB slow-log configuration is invalid",
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    MARIA_SLOW_LOG_SET_OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        match maria_slow_log::set::execute(
            &MariaSlowLogSetContext {
                engine_state: &state,
                docker_program: "docker",
            },
            &request,
            &CancellationToken::default(),
        ) {
            Ok(value) => Response::success(MARIA_SLOW_LOG_SET_OPERATION, value),
            Err(MariaSlowLogSetError::PostCommit { result }) => {
                Response::success(MARIA_SLOW_LOG_SET_OPERATION, result)
            }
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(
                    MARIA_SLOW_LOG_SET_OPERATION,
                    code,
                    &message,
                ))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, key);
        Ok(Response::failure(
            MARIA_SLOW_LOG_SET_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "db.configureMariaSlowLog requires a Unix host",
        ))
    }
}

fn clear_mariadb_slow_log(
    path: &std::path::Path,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{config::EngineConfig, filesystem::ManagedRoot};
        let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    MARIA_SLOW_LOG_OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    MARIA_SLOW_LOG_OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match maria_slow_log::Request::parse(&json, request_id, key) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    MARIA_SLOW_LOG_OPERATION,
                    ErrorCode::InvalidInput,
                    "MariaDB slow-log request is invalid",
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    MARIA_SLOW_LOG_OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        match maria_slow_log::execute::execute(
            &MariaSlowLogContext {
                engine_state: &state,
                docker_program: "docker",
            },
            &request,
            &CancellationToken::default(),
        ) {
            Ok(value) => Response::success(MARIA_SLOW_LOG_OPERATION, value),
            Err(MariaSlowLogError::PostCommit { result }) => {
                Response::success(MARIA_SLOW_LOG_OPERATION, result)
            }
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(MARIA_SLOW_LOG_OPERATION, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, key);
        Ok(Response::failure(
            MARIA_SLOW_LOG_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "db.clearMariaSlowLog requires a Unix host",
        ))
    }
}

fn export(path: &std::path::Path) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        let json = match read_root_owned_content_file(path) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    EXPORT_OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match db_export::Request::parse(&json) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    EXPORT_OPERATION,
                    ErrorCode::InvalidInput,
                    "database export request is invalid",
                ));
            }
        };
        match db_export::execute(&request, "docker") {
            Ok(result) => Response::success(EXPORT_OPERATION, result),
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(EXPORT_OPERATION, code, message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(Response::failure(
            EXPORT_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "db.export requires a Unix host",
        ))
    }
}

fn flush_all_valkey(
    path: &std::path::Path,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{config::EngineConfig, filesystem::ManagedRoot};
        let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    VALKEY_FLUSH_ALL_OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    VALKEY_FLUSH_ALL_OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match FlushAllRequest::parse(&json, request_id, key) {
            Ok(value) => value,
            Err(error) => {
                return Ok(Response::failure(
                    VALKEY_FLUSH_ALL_OPERATION,
                    ErrorCode::InvalidInput,
                    valkey_error_message(error),
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    VALKEY_FLUSH_ALL_OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        match execute_valkey_flush_all(
            &ValkeyFlushAllContext {
                engine_state: &state,
                docker_program: "docker",
            },
            &request,
            &CancellationToken::default(),
        ) {
            Ok(value) => Response::success(VALKEY_FLUSH_ALL_OPERATION, value),
            Err(ValkeyFlushAllError::PostCommit { result }) => {
                Response::success(VALKEY_FLUSH_ALL_OPERATION, result)
            }
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(
                    VALKEY_FLUSH_ALL_OPERATION,
                    code,
                    &message,
                ))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, key);
        Ok(Response::failure(
            VALKEY_FLUSH_ALL_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "db.flushAllValkey requires a Unix host",
        ))
    }
}

fn flush_valkey_db(
    path: &std::path::Path,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{config::EngineConfig, filesystem::ManagedRoot};
        let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    VALKEY_FLUSH_DB_OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    VALKEY_FLUSH_DB_OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match FlushDbRequest::parse(&json, request_id, key) {
            Ok(value) => value,
            Err(error) => {
                return Ok(Response::failure(
                    VALKEY_FLUSH_DB_OPERATION,
                    ErrorCode::InvalidInput,
                    valkey_error_message(error),
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    VALKEY_FLUSH_DB_OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        match execute_valkey_flush(
            &ValkeyFlushContext {
                engine_state: &state,
                docker_program: "docker",
            },
            &request,
            &CancellationToken::default(),
        ) {
            Ok(value) => Response::success(VALKEY_FLUSH_DB_OPERATION, value),
            Err(ValkeyFlushError::PostCommit { result }) => {
                Response::success(VALKEY_FLUSH_DB_OPERATION, result)
            }
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(VALKEY_FLUSH_DB_OPERATION, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, key);
        Ok(Response::failure(
            VALKEY_FLUSH_DB_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "db.flushValkeyDb requires a Unix host",
        ))
    }
}

fn delete_valkey_key(
    path: &std::path::Path,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{config::EngineConfig, filesystem::ManagedRoot};
        let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    VALKEY_DELETE_OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    VALKEY_DELETE_OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match ValkeyDeleteRequest::parse(&json, request_id, key) {
            Ok(value) => value,
            Err(error) => {
                return Ok(Response::failure(
                    VALKEY_DELETE_OPERATION,
                    ErrorCode::InvalidInput,
                    valkey_error_message(error),
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    VALKEY_DELETE_OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        match execute_valkey_delete(
            &ValkeyDeleteContext {
                engine_state: &state,
                docker_program: "docker",
            },
            &request,
            &CancellationToken::default(),
        ) {
            Ok(value) => Response::success(VALKEY_DELETE_OPERATION, value),
            Err(ValkeyDeleteError::PostCommit { result }) => {
                Response::success(VALKEY_DELETE_OPERATION, result)
            }
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(VALKEY_DELETE_OPERATION, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, key);
        Ok(Response::failure(
            VALKEY_DELETE_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "db.deleteValkeyKey requires a Unix host",
        ))
    }
}

fn valkey_error_message(error: ValkeyRequestError) -> &'static str {
    match error {
        ValkeyRequestError::InvalidJson => "request-file is not a valid Valkey key deletion plan",
        ValkeyRequestError::InvalidContainer => "container is invalid",
        ValkeyRequestError::InvalidKey => "key is empty or exceeds the size limit",
        ValkeyRequestError::InvalidFlushDbConfirmation => "confirmation must be exactly FLUSHDB",
        ValkeyRequestError::InvalidFlushAllConfirmation => "confirmation must be exactly FLUSHALL",
        ValkeyRequestError::InvalidRequestId => "request-id is not a canonical UUID",
        ValkeyRequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}

fn drop_mariadb_user(
    path: &std::path::Path,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{config::EngineConfig, filesystem::ManagedRoot};
        let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    MARIA_USER_DROP_OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    MARIA_USER_DROP_OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match MariaUserDropRequest::parse(&json, request_id, key) {
            Ok(value) => value,
            Err(error) => {
                return Ok(Response::failure(
                    MARIA_USER_DROP_OPERATION,
                    ErrorCode::InvalidInput,
                    maria_user_error_message(error),
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    MARIA_USER_DROP_OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        match execute_maria_user_drop(
            &MariaUserDropContext {
                engine_state: &state,
                docker_program: "docker",
            },
            &request,
            &CancellationToken::default(),
        ) {
            Ok(value) => Response::success(MARIA_USER_DROP_OPERATION, value),
            Err(MariaUserDropError::PostCommit { result }) => {
                Response::success(MARIA_USER_DROP_OPERATION, result)
            }
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(MARIA_USER_DROP_OPERATION, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, key);
        Ok(Response::failure(
            MARIA_USER_DROP_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "db.dropMariaDbUser requires a Unix host",
        ))
    }
}

fn maria_user_error_message(error: MariaUserRequestError) -> &'static str {
    match error {
        MariaUserRequestError::InvalidJson => {
            "request-file is not a valid MariaDB user removal plan"
        }
        MariaUserRequestError::InvalidContainer => "container is invalid",
        MariaUserRequestError::InvalidUser => "user is invalid",
        MariaUserRequestError::ProtectedUser => "protected MariaDB users cannot be removed",
        MariaUserRequestError::InvalidHost => "host is invalid",
        MariaUserRequestError::InvalidSecret => "root password is invalid",
        MariaUserRequestError::InvalidRequestId => "request-id is not a canonical UUID",
        MariaUserRequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}

fn drop_mariadb(
    path: &std::path::Path,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{config::EngineConfig, filesystem::ManagedRoot};
        let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    MARIA_DROP_OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    MARIA_DROP_OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match MariaDropRequest::parse(&json, request_id, key) {
            Ok(value) => value,
            Err(error) => {
                return Ok(Response::failure(
                    MARIA_DROP_OPERATION,
                    ErrorCode::InvalidInput,
                    maria_drop_error_message(error),
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    MARIA_DROP_OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        match execute_maria_drop(
            &MariaDropContext {
                engine_state: &state,
                docker_program: "docker",
            },
            &request,
            &CancellationToken::default(),
        ) {
            Ok(value) => Response::success(MARIA_DROP_OPERATION, value),
            Err(MariaDropError::PostCommit { result }) => {
                Response::success(MARIA_DROP_OPERATION, result)
            }
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(MARIA_DROP_OPERATION, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, key);
        Ok(Response::failure(
            MARIA_DROP_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "db.dropMariaDb requires a Unix host",
        ))
    }
}

fn maria_drop_error_message(error: MariaDropRequestError) -> &'static str {
    match error {
        MariaDropRequestError::InvalidJson => "request-file is not a valid MariaDB removal plan",
        MariaDropRequestError::InvalidContainer => "container is invalid",
        MariaDropRequestError::InvalidDatabase => "database is invalid",
        MariaDropRequestError::ProtectedDatabase => "system databases cannot be removed",
        MariaDropRequestError::InvalidSecret => "root password is invalid",
        MariaDropRequestError::InvalidRequestId => "request-id is not a canonical UUID",
        MariaDropRequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}

fn drop_postgres_user(
    path: &std::path::Path,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{config::EngineConfig, filesystem::ManagedRoot};
        let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    PG_USER_DROP_OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    PG_USER_DROP_OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match PgUserDropRequest::parse(&json, request_id, key) {
            Ok(value) => value,
            Err(error) => {
                return Ok(Response::failure(
                    PG_USER_DROP_OPERATION,
                    ErrorCode::InvalidInput,
                    pg_user_error_message(error),
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    PG_USER_DROP_OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        match execute_pg_user_drop(
            &PgUserDropContext {
                engine_state: &state,
                docker_program: "docker",
            },
            &request,
            &CancellationToken::default(),
        ) {
            Ok(value) => Response::success(PG_USER_DROP_OPERATION, value),
            Err(PgUserDropError::PostCommit { result }) => {
                Response::success(PG_USER_DROP_OPERATION, result)
            }
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(PG_USER_DROP_OPERATION, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, key);
        Ok(Response::failure(
            PG_USER_DROP_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "db.dropPostgresUser requires a Unix host",
        ))
    }
}

fn provision_postgres_user(
    path: &std::path::Path,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{config::EngineConfig, filesystem::ManagedRoot};
        let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    PG_USER_OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    PG_USER_OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match PgUserRequest::parse(&json, request_id, key) {
            Ok(value) => value,
            Err(error) => {
                return Ok(Response::failure(
                    PG_USER_OPERATION,
                    ErrorCode::InvalidInput,
                    pg_user_error_message(error),
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    PG_USER_OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        match execute_pg_user(
            &PgUserContext {
                engine_state: &state,
                docker_program: "docker",
            },
            &request,
            &CancellationToken::default(),
        ) {
            Ok(value) => Response::success(PG_USER_OPERATION, value),
            Err(PgUserError::PostCommit { result }) => Response::success(PG_USER_OPERATION, result),
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(PG_USER_OPERATION, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, key);
        Ok(Response::failure(
            PG_USER_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "db.provisionPostgresUser requires a Unix host",
        ))
    }
}

fn pg_user_error_message(error: PgUserRequestError) -> &'static str {
    match error {
        PgUserRequestError::InvalidJson => "request-file is not a valid PostgreSQL role plan",
        PgUserRequestError::InvalidContainer => "container is invalid",
        PgUserRequestError::InvalidUser => "user is invalid",
        PgUserRequestError::ProtectedUser => "protected PostgreSQL roles cannot be provisioned",
        PgUserRequestError::InvalidDatabase => "database is invalid",
        PgUserRequestError::InvalidSecret => "password is invalid",
        PgUserRequestError::InvalidRequestId => "request-id is not a canonical UUID",
        PgUserRequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}

fn drop_postgres(
    path: &std::path::Path,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{config::EngineConfig, filesystem::ManagedRoot};
        let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    PG_DROP_OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    PG_DROP_OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match PgDropRequest::parse(&json, request_id, key) {
            Ok(value) => value,
            Err(error) => {
                return Ok(Response::failure(
                    PG_DROP_OPERATION,
                    ErrorCode::InvalidInput,
                    pg_drop_error_message(error),
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    PG_DROP_OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        match execute_pg_drop(
            &PgDropContext {
                engine_state: &state,
                docker_program: "docker",
            },
            &request,
            &CancellationToken::default(),
        ) {
            Ok(value) => Response::success(PG_DROP_OPERATION, value),
            Err(PgDropError::PostCommit { result }) => Response::success(PG_DROP_OPERATION, result),
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(PG_DROP_OPERATION, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, key);
        Ok(Response::failure(
            PG_DROP_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "db.dropPostgres requires a Unix host",
        ))
    }
}

fn pg_drop_error_message(error: PgDropRequestError) -> &'static str {
    match error {
        PgDropRequestError::InvalidJson => "request-file is not a valid PostgreSQL removal plan",
        PgDropRequestError::InvalidContainer => "container is invalid",
        PgDropRequestError::InvalidDatabase => "database is invalid",
        PgDropRequestError::ProtectedDatabase => "system databases cannot be removed",
        PgDropRequestError::InvalidSecret => "root password is invalid",
        PgDropRequestError::InvalidRequestId => "request-id is not a canonical UUID",
        PgDropRequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}

fn provision_postgres(
    path: &std::path::Path,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{config::EngineConfig, filesystem::ManagedRoot};
        let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    PG_PROVISION_OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    PG_PROVISION_OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match PgProvisionRequest::parse(&json, request_id, key) {
            Ok(v) => v,
            Err(e) => {
                return Ok(Response::failure(
                    PG_PROVISION_OPERATION,
                    ErrorCode::InvalidInput,
                    pg_provision_error_message(e),
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    PG_PROVISION_OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        match execute_pg_provision(
            &PgProvisionContext {
                engine_state: &state,
                docker_program: "docker",
            },
            &request,
            &CancellationToken::default(),
        ) {
            Ok(v) => Response::success(PG_PROVISION_OPERATION, v),
            Err(PgProvisionError::PostCommit { result }) => {
                Response::success(PG_PROVISION_OPERATION, result)
            }
            Err(e) => {
                let (c, m) = e.protocol();
                Ok(Response::failure(PG_PROVISION_OPERATION, c, &m))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, key);
        Ok(Response::failure(
            PG_PROVISION_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "db.provisionPostgres requires a Unix host",
        ))
    }
}
fn pg_provision_error_message(e: PgProvisionRequestError) -> &'static str {
    match e {
        PgProvisionRequestError::InvalidJson => {
            "request-file is not a valid PostgreSQL provisioning plan"
        }
        PgProvisionRequestError::InvalidContainer => "container is invalid",
        PgProvisionRequestError::InvalidDatabase => "database is invalid",
        PgProvisionRequestError::InvalidSecret => "root password is invalid",
        PgProvisionRequestError::InvalidRequestId => "request-id is not a canonical UUID",
        PgProvisionRequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}

fn tool_remove(
    path: &std::path::Path,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{config::EngineConfig, filesystem::ManagedRoot};
        let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    REMOVE_OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    REMOVE_OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match RemoveRequest::parse(&json, request_id, key) {
            Ok(v) => v,
            Err(e) => {
                return Ok(Response::failure(
                    REMOVE_OPERATION,
                    ErrorCode::InvalidInput,
                    tool_error_message(e),
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    REMOVE_OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        let compose = crate::compose::Access::default();
        let context = RemoveContext {
            engine_state: &state,
            ingress_root: &config.ingress_root,
            docker_program: "docker",
            compose: &compose,
        };
        match execute_remove(&context, &request, &CancellationToken::default()) {
            Ok(v) => Response::success(REMOVE_OPERATION, v),
            Err(RemoveError::PostCommit { result }) => Response::success(REMOVE_OPERATION, result),
            Err(e) => {
                let (c, m) = e.protocol();
                Ok(Response::failure(REMOVE_OPERATION, c, &m))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, key);
        Ok(Response::failure(
            REMOVE_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "dbTool.remove requires a Unix host",
        ))
    }
}

fn tool_converge(
    path: &std::path::Path,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{config::EngineConfig, filesystem::ManagedRoot};
        let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    TOOL_OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    TOOL_OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match ToolRequest::parse(&json, request_id, key) {
            Ok(v) => v,
            Err(e) => {
                return Ok(Response::failure(
                    TOOL_OPERATION,
                    ErrorCode::InvalidInput,
                    tool_error_message(e),
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    TOOL_OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        let context = ToolContext {
            engine_state: &state,
            docker_program: "docker",
        };
        match execute_tool(&context, &request, &CancellationToken::default()) {
            Ok(v) => Response::success(TOOL_OPERATION, v),
            Err(ToolError::PostCommit { result }) => Response::success(TOOL_OPERATION, result),
            Err(e) => {
                let (c, m) = e.protocol();
                Ok(Response::failure(TOOL_OPERATION, c, &m))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, key);
        Ok(Response::failure(
            TOOL_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "dbTool.converge requires a Unix host",
        ))
    }
}
fn tool_error_message(e: ToolRequestError) -> &'static str {
    match e {
        ToolRequestError::InvalidJson => "request-file is not a valid tool plan",
        ToolRequestError::InvalidDomain => "domain is invalid",
        ToolRequestError::InvalidShape => "tool action fields are inconsistent",
        ToolRequestError::InvalidRequestId => "request-id is not a canonical UUID",
        ToolRequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}

fn provision_mariadb(
    path: &std::path::Path,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{config::EngineConfig, filesystem::ManagedRoot};
        let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
            Ok(config) => config,
            Err(_) => {
                return Ok(Response::failure(
                    PROVISION_OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(json) => json,
            Err(ContentFileError::TooLarge) => {
                return Ok(Response::failure(
                    PROVISION_OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file is too large",
                ));
            }
            Err(ContentFileError::Unreadable) => {
                return Ok(Response::failure(
                    PROVISION_OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match ProvisionRequest::parse(&json, request_id, idempotency_key) {
            Ok(request) => request,
            Err(error) => {
                return Ok(Response::failure(
                    PROVISION_OPERATION,
                    ErrorCode::InvalidInput,
                    provision_error_message(error),
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(state) => state,
            Err(_) => {
                return Ok(Response::failure(
                    PROVISION_OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        let context = ProvisionContext {
            engine_state: &state,
            docker_program: "docker",
        };
        match execute_provision(&context, &request, &CancellationToken::default()) {
            Ok(result) => Response::success(PROVISION_OPERATION, result),
            Err(ProvisionError::PostCommitRecordFailed { result }) => {
                Response::success(PROVISION_OPERATION, result).map(|response| {
                    response.with_warnings(vec![Warning {
                        code: WarningCode::TransactionRecordIncomplete,
                        message:
                            "MariaDB was provisioned but its transaction record could not be saved"
                                .into(),
                    }])
                })
            }
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(PROVISION_OPERATION, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, idempotency_key);
        Ok(Response::failure(
            PROVISION_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "db.provisionMariaDb requires a Unix host",
        ))
    }
}

fn provision_error_message(error: ProvisionRequestError) -> &'static str {
    match error {
        ProvisionRequestError::InvalidJson => "request-file is not a valid provisioning plan",
        ProvisionRequestError::InvalidContainer => "container is invalid",
        ProvisionRequestError::InvalidDatabase => "database is invalid",
        ProvisionRequestError::InvalidUser => "user is invalid",
        ProvisionRequestError::InvalidHost => "host is invalid",
        ProvisionRequestError::InvalidSecret => "credential value is invalid",
        ProvisionRequestError::InvalidRequestId => "request-id is not a canonical UUID",
        ProvisionRequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}

fn db_type_str(db_type: DbTypeArg) -> &'static str {
    match db_type {
        DbTypeArg::Mariadb => "mariadb",
        DbTypeArg::Postgres => "postgres",
    }
}

#[allow(clippy::too_many_arguments)]
fn restore(
    db_type: DbTypeArg,
    database: &str,
    container: &str,
    file_path: String,
    root_password: String,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    let request = match RestoreRequest::parse(
        db_type_str(db_type),
        database,
        container,
        file_path,
        root_password,
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
        run_restore(&request)
    }
    #[cfg(not(unix))]
    {
        let _ = request;
        Ok(Response::failure(
            OPERATION,
            ErrorCode::UnsupportedPlatform,
            "db.restore requires a Unix host",
        ))
    }
}

#[cfg(unix)]
fn run_restore(request: &RestoreRequest) -> Result<Response, ResponseBuildError> {
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
    let context = RestoreContext {
        engine_state: &engine_state,
        docker_program: "docker",
        gunzip_program: "gunzip",
    };

    match execute_restore(&context, request, &CancellationToken::default()) {
        Ok(result) => Response::success(OPERATION, result),
        Err(RestoreError::PostCommitRecordFailed { result, .. }) => {
            Response::success(OPERATION, result).map(|response| {
                response.with_warnings(vec![Warning {
                    code: WarningCode::TransactionRecordIncomplete,
                    message: "the database was restored but its transaction record could not \
                              be saved"
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

fn request_error_message(error: RestoreRequestError) -> &'static str {
    match error {
        RestoreRequestError::InvalidDbType => "db-type must be 'mariadb' or 'postgres'",
        RestoreRequestError::InvalidDatabaseName => {
            "database is not a valid database name (a-z, A-Z, 0-9, _ only)"
        }
        RestoreRequestError::InvalidContainerName => "container is not a valid container name",
        RestoreRequestError::FilePathTooLong => "file-path is too long",
        RestoreRequestError::InvalidRequestId => "request-id is not a canonical UUID",
        RestoreRequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}
