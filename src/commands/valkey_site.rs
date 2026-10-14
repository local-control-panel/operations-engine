//! `db.provisionValkeySite`, `db.revokeValkeySite` and `db.flushValkeySite`
//! command handlers (see [`crate::valkey::site_access`]).

use crate::{
    error::ErrorCode,
    protocol::{Response, ResponseBuildError},
    secret_result,
    valkey::site_access::{self, FLUSH_OPERATION, PROVISION_OPERATION, REVOKE_OPERATION},
};

pub enum Action {
    Provision,
    Revoke,
    Flush,
}

impl Action {
    fn operation(&self) -> &'static str {
        match self {
            Self::Provision => PROVISION_OPERATION,
            Self::Revoke => REVOKE_OPERATION,
            Self::Flush => FLUSH_OPERATION,
        }
    }
}

fn request_message(error: site_access::RequestError) -> &'static str {
    use site_access::RequestError::*;
    match error {
        InvalidJson => "request-file is not a valid Valkey site plan",
        InvalidContainer => "container is invalid",
        InvalidDomain => "domain is invalid",
        InvalidRequestId => "request-id is not a canonical UUID",
        InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}

pub fn run(
    action: Action,
    path: &std::path::Path,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    let operation = action.operation();
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
        let request = match site_access::SiteRequest::parse(&json, request_id, idempotency_key) {
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
        let context = site_access::Context {
            engine_state: &state,
            docker_program: "docker",
        };
        let cancel = CancellationToken::default();
        use site_access::Error;
        match action {
            Action::Provision => match site_access::provision(&context, &request, &cancel) {
                Ok(site_access::Provisioned::New(result))
                | Err(Error::PostCommitProvision(result)) => {
                    Response::success_with_secret(operation, *result)
                }
                Ok(site_access::Provisioned::AlreadyIssued(public)) => {
                    secret_result::replayed(operation, public)
                }
                Err(error) => failure(operation, &error),
            },
            Action::Revoke => match site_access::revoke(&context, &request, &cancel) {
                Ok(value) | Err(Error::PostCommitRevoke(value)) => {
                    Response::success(operation, value)
                }
                Err(error) => failure(operation, &error),
            },
            Action::Flush => match site_access::flush(&context, &request, &cancel) {
                Ok(value) | Err(Error::PostCommitFlush(value)) => {
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
            "this Valkey operation requires a Unix host",
        ))
    }
}

#[cfg(unix)]
fn failure(
    operation: &'static str,
    error: &site_access::Error,
) -> Result<Response, ResponseBuildError> {
    let (code, message) = error.protocol();
    Ok(Response::failure(operation, code, &message))
}
