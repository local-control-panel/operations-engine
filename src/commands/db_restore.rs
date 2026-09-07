use crate::{
    cli::{DbCommand, DbTypeArg},
    db_restore::{
        OPERATION, RestoreRequest, RestoreRequestError,
        execute::{RestoreContext, RestoreError, execute as execute_restore},
    },
    error::{ErrorCode, WarningCode},
    process::CancellationToken,
    protocol::{Response, ResponseBuildError, Warning},
};

const CONFIG_PATH: &str = "/etc/operations-engine/config.json";

pub fn run(command: DbCommand) -> Result<Response, ResponseBuildError> {
    match command {
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
