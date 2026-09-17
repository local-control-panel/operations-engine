use crate::{
    agent_config,
    cli::AgentCommand,
    commands::read_root_owned_content_file,
    error::ErrorCode,
    filesystem::ManagedRoot,
    protocol::{Response, ResponseBuildError},
    site::{SiteRelativePath, TrustedRoot},
};

pub fn run(command: AgentCommand) -> Result<Response, ResponseBuildError> {
    match command {
        AgentCommand::ActivateBruteforceConfig { request_file } => activate(&request_file),
    }
}

fn activate(path: &std::path::Path) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        let json = match read_root_owned_content_file(path) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    agent_config::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match agent_config::Request::parse(&json) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    agent_config::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file is not a valid brute-force configuration",
                ));
            }
        };
        if std::fs::create_dir_all(agent_config::ROOT).is_err() {
            return Ok(Response::failure(
                agent_config::OPERATION,
                ErrorCode::Internal,
                "agent configuration root is unavailable",
            ));
        }
        let root =
            match TrustedRoot::parse(std::path::Path::new(agent_config::ROOT)).and_then(|r| {
                ManagedRoot::open(&r)
                    .map_err(|_| crate::site::ValidationError::PathResolutionFailed)
            }) {
                Ok(v) => v,
                Err(_) => {
                    return Ok(Response::failure(
                        agent_config::OPERATION,
                        ErrorCode::Internal,
                        "agent configuration root is unavailable",
                    ));
                }
            };
        let file = SiteRelativePath::parse(agent_config::FILE).unwrap();
        match root.write_atomic(&file, request.render().as_bytes()) {
            Ok(()) => Response::success(
                agent_config::OPERATION,
                agent_config::ActivateResult { activated: true },
            ),
            Err(_) => Ok(Response::failure(
                agent_config::OPERATION,
                ErrorCode::Internal,
                "could not activate brute-force configuration",
            )),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(Response::failure(
            agent_config::OPERATION,
            ErrorCode::UnsupportedPlatform,
            "agent.activateBruteforceConfig requires a Unix host",
        ))
    }
}
