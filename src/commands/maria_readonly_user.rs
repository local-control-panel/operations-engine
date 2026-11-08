//! `db.ensureReadonlyUser` and `db.revokeReadonlyUser` command handlers (see
//! [`crate::maria_readonly_user`]).

use crate::{
    error::ErrorCode,
    maria_readonly_user::{
        ENSURE_OPERATION, REVOKE_OPERATION, Request, RequestError,
        execute::{self, Ensured, Error},
    },
    protocol::{Response, ResponseBuildError},
    secret_result,
};

pub enum Action {
    Ensure,
    Revoke,
}

fn request_message(error: RequestError) -> &'static str {
    match error {
        RequestError::InvalidJson => "request-file is not a valid read-only MariaDB user plan",
        RequestError::InvalidContainer => "container is invalid",
        RequestError::InvalidDatabase => "database is invalid",
        RequestError::ProtectedDatabase => "system databases cannot get a read-only user",
        RequestError::InvalidSecret => "root password is invalid",
        RequestError::InvalidRequestId => "request-id is not a canonical UUID",
        RequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}

pub fn run(
    action: Action,
    path: &std::path::Path,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    let operation = match action {
        Action::Ensure => ENSURE_OPERATION,
        Action::Revoke => REVOKE_OPERATION,
    };
    #[cfg(unix)]
    {
        use crate::{
            commands::read_root_owned_content_file, config::EngineConfig, filesystem::ManagedRoot,
            process::CancellationToken,
        };
        let config = match EngineConfig::load_root_owned(std::path::Path::new(
            "/etc/operations-engine/config.json",
        )) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    operation,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    operation,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let parsed = match action {
            Action::Ensure => Request::parse_ensure(&json, request_id, idempotency_key),
            Action::Revoke => Request::parse_revoke(&json, request_id, idempotency_key),
        };
        let request = match parsed {
            Ok(value) => value,
            Err(error) => {
                return Ok(Response::failure(
                    operation,
                    ErrorCode::InvalidInput,
                    request_message(error),
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    operation,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        let context = execute::Context {
            engine_state: &state,
            docker_program: "docker",
        };
        let cancel = CancellationToken::default();
        match action {
            Action::Ensure => match execute::ensure(&context, &request, &cancel) {
                Ok(ensured) => ensured_response(operation, ensured),
                Err(Error::PostCommitEnsure(ensured)) => ensured_response(operation, *ensured),
                Err(error) => failure(operation, &error),
            },
            Action::Revoke => match execute::revoke(&context, &request, &cancel) {
                Ok(value) | Err(Error::PostCommitRevoke(value)) => {
                    Response::success(operation, value)
                }
                Err(error) => failure(operation, &error),
            },
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, idempotency_key);
        Ok(Response::failure(
            operation,
            ErrorCode::UnsupportedPlatform,
            "this MariaDB operation requires a Unix host",
        ))
    }
}

#[cfg(unix)]
fn ensured_response(
    operation: &'static str,
    ensured: Ensured,
) -> Result<Response, ResponseBuildError> {
    match ensured {
        Ensured::Issued(result) => Response::success_with_secret(operation, *result),
        Ensured::Existing(public) => Response::success(operation, public),
        Ensured::AlreadyIssued(public) => secret_result::replayed(operation, public),
    }
}

#[cfg(unix)]
fn failure(operation: &'static str, error: &Error) -> Result<Response, ResponseBuildError> {
    let (code, message) = error.protocol();
    Ok(Response::failure(operation, code, &message))
}
