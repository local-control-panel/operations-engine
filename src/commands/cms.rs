use crate::{
    cli::CmsCommand,
    cms_cache, cms_maintenance,
    commands::read_root_owned_content_file,
    error::ErrorCode,
    protocol::{Response, ResponseBuildError},
};

pub fn run(command: CmsCommand) -> Result<Response, ResponseBuildError> {
    match command {
        CmsCommand::ClearCache {
            request_file,
            request_id,
            idempotency_key,
        } => clear_cache(&request_file, &request_id, idempotency_key.as_deref()),
        CmsCommand::Maintenance {
            request_file,
            request_id,
            idempotency_key,
        } => maintenance(&request_file, &request_id, idempotency_key.as_deref()),
    }
}

fn clear_cache(
    path: &std::path::Path,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    let operation = cms_cache::OPERATION;
    #[cfg(unix)]
    {
        use crate::filesystem::ManagedRoot;
        let config = match crate::config::EngineConfig::load_root_owned(std::path::Path::new(
            "/etc/operations-engine/config.json",
        )) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    operation,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    operation,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match cms_cache::Request::parse(&json, request_id, idempotency_key) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    operation,
                    ErrorCode::InvalidInput,
                    "request-file is not a valid cache clear plan",
                ));
            }
        };
        if !config
            .content_roots
            .iter()
            .any(|root| request.root().starts_with(root.as_path()))
        {
            return Ok(Response::failure(
                operation,
                ErrorCode::InvalidInput,
                "project root is outside configured content roots",
            ));
        }
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    operation,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        let context = cms_cache::Context {
            engine_state: &state,
            docker_program: "docker",
        };
        match cms_cache::execute(
            &context,
            &request,
            &crate::process::CancellationToken::default(),
        ) {
            Ok(v) | Err(cms_cache::Error::PostCommit { result: v }) => {
                Response::success(operation, v)
            }
            Err(e) => {
                let (code, message) = e.protocol();
                Ok(Response::failure(operation, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, idempotency_key);
        Ok(Response::failure(
            operation,
            ErrorCode::UnsupportedPlatform,
            "CMS cache actions require a Unix host",
        ))
    }
}

fn maintenance(
    path: &std::path::Path,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    let operation = cms_maintenance::OPERATION;
    #[cfg(unix)]
    {
        use crate::filesystem::ManagedRoot;
        let config = match crate::config::EngineConfig::load_root_owned(std::path::Path::new(
            "/etc/operations-engine/config.json",
        )) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    operation,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    operation,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match cms_maintenance::Request::parse(&json, request_id, idempotency_key) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    operation,
                    ErrorCode::InvalidInput,
                    "request-file is not a valid maintenance plan",
                ));
            }
        };
        if !config
            .content_roots
            .iter()
            .any(|root| request.root().starts_with(root.as_path()))
        {
            return Ok(Response::failure(
                operation,
                ErrorCode::InvalidInput,
                "project root is outside configured content roots",
            ));
        }
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    operation,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        let context = cms_maintenance::Context {
            engine_state: &state,
            docker_program: "docker",
        };
        match cms_maintenance::execute(
            &context,
            &request,
            &crate::process::CancellationToken::default(),
        ) {
            Ok(cms_maintenance::Done::Plain(v)) => Response::success(operation, v),
            Ok(cms_maintenance::Done::Issued(v)) => Response::success_with_secret(operation, v),
            Ok(cms_maintenance::Done::AlreadyIssued(v)) => crate::secret_result::replayed(
                operation,
                serde_json::to_value(v).map_err(|_| ResponseBuildError)?,
            ),
            Err(e) => {
                let (code, message) = e.protocol();
                Ok(Response::failure(operation, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, idempotency_key);
        Ok(Response::failure(
            operation,
            ErrorCode::UnsupportedPlatform,
            "CMS maintenance actions require a Unix host",
        ))
    }
}
