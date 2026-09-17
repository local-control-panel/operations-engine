use crate::{
    cli::WordpressCommand,
    commands::read_root_owned_content_file,
    error::ErrorCode,
    protocol::{Response, ResponseBuildError},
    wordpress,
};

pub fn run(command: WordpressCommand) -> Result<Response, ResponseBuildError> {
    match command {
        WordpressCommand::Cleanup { request_file } => cleanup(&request_file),
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
