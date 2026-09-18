use crate::{
    cli::WordpressCommand,
    commands::read_root_owned_content_file,
    error::ErrorCode,
    protocol::{Response, ResponseBuildError},
    wordpress, wordpress_update,
};

pub fn run(command: WordpressCommand) -> Result<Response, ResponseBuildError> {
    match command {
        WordpressCommand::Cleanup { request_file } => cleanup(&request_file),
        WordpressCommand::UpdateCore {
            request_file,
            request_id,
            idempotency_key,
        } => update_core(&request_file, &request_id, idempotency_key.as_deref()),
    }
}

fn update_core(
    path: &std::path::Path,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{backup_delete::BACKUP_ROOT, filesystem::ManagedRoot, site::TrustedRoot};
        let config = match crate::config::EngineConfig::load_root_owned(std::path::Path::new(
            "/etc/operations-engine/config.json",
        )) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress_update::OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress_update::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match wordpress_update::Request::parse(&json, request_id, key) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress_update::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file is not a valid WordPress core update plan",
                ));
            }
        };
        if !config
            .content_roots
            .iter()
            .any(|root| request.root().starts_with(root.as_path()))
        {
            return Ok(Response::failure(
                wordpress_update::OPERATION,
                ErrorCode::InvalidInput,
                "WordPress root is outside configured content roots",
            ));
        }
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress_update::OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        if std::fs::create_dir_all(BACKUP_ROOT).is_err() {
            return Ok(Response::failure(
                wordpress_update::OPERATION,
                ErrorCode::Internal,
                "backup root is unavailable",
            ));
        }
        let backups = match TrustedRoot::parse(std::path::Path::new(BACKUP_ROOT)).and_then(|root| {
            ManagedRoot::open(&root).map_err(|_| crate::site::ValidationError::PathResolutionFailed)
        }) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress_update::OPERATION,
                    ErrorCode::Internal,
                    "backup root is unavailable",
                ));
            }
        };
        let context = wordpress_update::Context {
            engine_state: &state,
            backup_root: &backups,
            docker_program: "docker",
            tar_program: "tar",
        };
        match wordpress_update::execute(
            &context,
            &request,
            &crate::process::CancellationToken::default(),
        ) {
            Ok(v) | Err(wordpress_update::Error::PostCommit { result: v }) => {
                Response::success(wordpress_update::OPERATION, v)
            }
            Err(e) => {
                let (code, message) = e.protocol();
                Ok(Response::failure(
                    wordpress_update::OPERATION,
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
            wordpress_update::OPERATION,
            ErrorCode::UnsupportedPlatform,
            "wordpress.updateCore requires a Unix host",
        ))
    }
}

fn cleanup(path: &std::path::Path) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        let config = match crate::config::EngineConfig::load_root_owned(std::path::Path::new(
            "/etc/operations-engine/config.json",
        )) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress::OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match wordpress::Request::parse(&json) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file is not a valid WordPress cleanup plan",
                ));
            }
        };
        if !config
            .content_roots
            .iter()
            .any(|root| request.root().starts_with(root.as_path()))
        {
            return Ok(Response::failure(
                wordpress::OPERATION,
                ErrorCode::InvalidInput,
                "WordPress root is outside configured content roots",
            ));
        }
        match wordpress::execute(&request, "docker") {
            Ok(value) => Response::success(wordpress::OPERATION, value),
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(wordpress::OPERATION, code, message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(Response::failure(
            wordpress::OPERATION,
            ErrorCode::UnsupportedPlatform,
            "wordpress.cleanup requires a Unix host",
        ))
    }
}
