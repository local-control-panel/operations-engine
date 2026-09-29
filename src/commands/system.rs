use crate::{
    cli::SystemCommand,
    commands::read_root_owned_content_file,
    error::ErrorCode,
    process::CancellationToken,
    protocol::{Response, ResponseBuildError},
    system_autoupdates,
};

const CONFIG_PATH: &str = "/etc/operations-engine/config.json";

pub fn run(command: SystemCommand) -> Result<Response, ResponseBuildError> {
    match command {
        SystemCommand::ActivateAutoupdatesConfig {
            request_file,
            request_id,
            idempotency_key,
        } => activate_autoupdates_config(&request_file, &request_id, idempotency_key.as_deref()),
    }
}

fn activate_autoupdates_config(
    path: &std::path::Path,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{config::EngineConfig, filesystem::ManagedRoot, site::TrustedRoot};
        let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    system_autoupdates::OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    system_autoupdates::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match system_autoupdates::Request::parse(&json, request_id, key) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    system_autoupdates::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file is not a valid autoupdates activation plan",
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    system_autoupdates::OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        if std::fs::create_dir_all(system_autoupdates::APT_CONF_DIR).is_err() {
            return Ok(Response::failure(
                system_autoupdates::OPERATION,
                ErrorCode::Internal,
                "apt configuration directory is unavailable",
            ));
        }
        let apt_conf_dir =
            match TrustedRoot::parse(std::path::Path::new(system_autoupdates::APT_CONF_DIR))
                .and_then(|r| {
                    ManagedRoot::open(&r)
                        .map_err(|_| crate::site::ValidationError::PathResolutionFailed)
                }) {
                Ok(v) => v,
                Err(_) => {
                    return Ok(Response::failure(
                        system_autoupdates::OPERATION,
                        ErrorCode::Internal,
                        "apt configuration directory is unavailable",
                    ));
                }
            };
        let ctx = system_autoupdates::Context {
            engine_state: &state,
            apt_conf_dir: &apt_conf_dir,
        };
        match system_autoupdates::execute(&ctx, &request, &CancellationToken::default()) {
            Ok(v) | Err(system_autoupdates::Error::PostCommit { result: v }) => {
                Response::success(system_autoupdates::OPERATION, v)
            }
            Err(e) => {
                let (code, message) = e.protocol();
                Ok(Response::failure(
                    system_autoupdates::OPERATION,
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
            system_autoupdates::OPERATION,
            ErrorCode::UnsupportedPlatform,
            "system.activateAutoupdatesConfig requires a Unix host",
        ))
    }
}
