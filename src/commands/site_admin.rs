//! `site.adminUsers` and `site.adminLogin` command handlers.

use crate::{
    error::ErrorCode,
    protocol::{Response, ResponseBuildError},
    secret_result,
    site_admin::{self, LOGIN_OPERATION, USERS_OPERATION},
};

#[cfg(unix)]
mod unix {
    use super::*;
    use crate::{
        commands::read_root_owned_content_file, config::EngineConfig, filesystem::ManagedRoot,
        process::CancellationToken,
    };

    fn fail(operation: &'static str, code: ErrorCode, message: &str) -> Response {
        Response::failure(operation, code, message)
    }

    /// Config, request document and state root, or the failure response.
    fn open(
        operation: &'static str,
        path: &std::path::Path,
    ) -> Result<(EngineConfig, String, ManagedRoot), Response> {
        let config = EngineConfig::load_root_owned(std::path::Path::new(
            "/etc/operations-engine/config.json",
        ))
        .map_err(|_| {
            fail(
                operation,
                ErrorCode::Internal,
                crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
            )
        })?;
        let json = read_root_owned_content_file(path).map_err(|_| {
            fail(
                operation,
                ErrorCode::InvalidInput,
                "request-file must be a root-owned regular file",
            )
        })?;
        let state = ManagedRoot::open(&config.state_root).map_err(|_| {
            fail(
                operation,
                ErrorCode::Internal,
                "engine state root is unavailable",
            )
        })?;
        Ok((config, json, state))
    }

    fn inside_content_roots(config: &EngineConfig, root: &std::path::Path) -> bool {
        config
            .content_roots
            .iter()
            .any(|allowed| root.starts_with(allowed.as_path()))
    }

    pub fn users(path: &std::path::Path) -> Result<Response, ResponseBuildError> {
        let (config, json, state) = match open(USERS_OPERATION, path) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let request = match site_admin::UsersRequest::parse(&json) {
            Ok(value) => value,
            Err(error) => {
                return Ok(fail(
                    USERS_OPERATION,
                    ErrorCode::InvalidInput,
                    error.message(),
                ));
            }
        };
        if !inside_content_roots(&config, request.root()) {
            return Ok(fail(
                USERS_OPERATION,
                ErrorCode::InvalidInput,
                "WordPress root is outside configured content roots",
            ));
        }
        let context = site_admin::Context {
            engine_state: &state,
            docker_program: "docker",
        };
        match site_admin::list_users(&context, &request, &CancellationToken::default()) {
            Ok(value) => Response::success(USERS_OPERATION, value),
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(fail(USERS_OPERATION, code, &message))
            }
        }
    }

    pub fn login(
        path: &std::path::Path,
        request_id: &str,
        idempotency_key: &str,
    ) -> Result<Response, ResponseBuildError> {
        let (config, json, state) = match open(LOGIN_OPERATION, path) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let request =
            match site_admin::LoginRequest::parse(&json, request_id, Some(idempotency_key)) {
                Ok(value) => value,
                Err(error) => {
                    return Ok(fail(
                        LOGIN_OPERATION,
                        ErrorCode::InvalidInput,
                        error.message(),
                    ));
                }
            };
        if !inside_content_roots(&config, request.root()) {
            return Ok(fail(
                LOGIN_OPERATION,
                ErrorCode::InvalidInput,
                "WordPress root is outside configured content roots",
            ));
        }
        let context = site_admin::Context {
            engine_state: &state,
            docker_program: "docker",
        };
        match site_admin::issue_login(&context, &request, &CancellationToken::default()) {
            Ok(site_admin::Issued::New(result)) | Err(site_admin::Error::PostCommit(result)) => {
                Response::success_with_secret(LOGIN_OPERATION, result)
            }
            Ok(site_admin::Issued::AlreadyIssued(public)) => {
                secret_result::replayed(LOGIN_OPERATION, public)
            }
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(fail(LOGIN_OPERATION, code, &message))
            }
        }
    }
}

#[cfg(unix)]
pub use unix::{login, users};

#[cfg(not(unix))]
pub fn users(_path: &std::path::Path) -> Result<Response, ResponseBuildError> {
    Ok(Response::failure(
        USERS_OPERATION,
        ErrorCode::UnsupportedPlatform,
        "site.adminUsers requires a Unix host",
    ))
}

#[cfg(not(unix))]
pub fn login(
    _path: &std::path::Path,
    _request_id: &str,
    _idempotency_key: &str,
) -> Result<Response, ResponseBuildError> {
    Ok(Response::failure(
        LOGIN_OPERATION,
        ErrorCode::UnsupportedPlatform,
        "site.adminLogin requires a Unix host",
    ))
}
