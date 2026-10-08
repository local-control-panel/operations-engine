use crate::{
    agent_config, agent_lifecycle,
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
        AgentCommand::Install {
            request_file,
            request_id,
            idempotency_key,
        } => lifecycle(
            agent_lifecycle::INSTALL_OPERATION,
            &request_file,
            &request_id,
            idempotency_key.as_deref(),
        ),
        AgentCommand::Remove {
            request_file,
            request_id,
            idempotency_key,
        } => lifecycle(
            agent_lifecycle::REMOVE_OPERATION,
            &request_file,
            &request_id,
            idempotency_key.as_deref(),
        ),
        AgentCommand::BruteforceUnban {
            request_file,
            request_id,
            idempotency_key,
        } => lifecycle(
            agent_lifecycle::UNBAN_OPERATION,
            &request_file,
            &request_id,
            idempotency_key.as_deref(),
        ),
    }
}

const CONFIG_PATH: &str = "/etc/operations-engine/config.json";

fn request_error_message(error: agent_lifecycle::RequestError) -> &'static str {
    use agent_lifecycle::RequestError;
    match error {
        RequestError::InvalidJson => "request-file is not a valid agent request",
        RequestError::UnknownAgent => "agent is not one of the bundled agents",
        RequestError::InvalidSchedule => {
            "schedule must be five cron fields or @hourly/@daily/@weekly/@monthly/@yearly"
        }
        RequestError::ScheduleNotConfigurable => "this agent runs on a fixed schedule",
        RequestError::InvalidIp => "ip is not an IPv4 or IPv6 address",
        RequestError::InvalidRequestId => "request-id is not a canonical UUID",
        RequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}

/// `agent.install`, `agent.remove` and `agent.bruteforceUnban`: all three read
/// a root-owned request file and run one transactional pipeline.
fn lifecycle(
    operation: &'static str,
    path: &std::path::Path,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{
            agent_lifecycle::execute::{self, Context},
            config::EngineConfig,
            filesystem::ManagedRoot,
            process::CancellationToken,
        };
        let failure =
            |code: ErrorCode, message: &str| Ok(Response::failure(operation, code, message));
        let json = match read_root_owned_content_file(path) {
            Ok(v) => v,
            Err(_) => {
                return failure(
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                );
            }
        };
        let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
            Ok(v) => v,
            Err(_) => {
                return failure(
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                );
            }
        };
        let engine_state = match ManagedRoot::open(&config.state_root) {
            Ok(v) => v,
            Err(_) => return failure(ErrorCode::Internal, "engine state root is unavailable"),
        };
        if std::fs::create_dir_all(agent_lifecycle::ROOT).is_err() {
            return failure(ErrorCode::Internal, "agent root is unavailable");
        }
        let root = match TrustedRoot::parse(std::path::Path::new(agent_lifecycle::ROOT))
            .map_err(|_| ())
            .and_then(|r| ManagedRoot::open(&r).map_err(|_| ()))
        {
            Ok(v) => v,
            Err(()) => return failure(ErrorCode::Internal, "agent root is unavailable"),
        };
        let context = Context {
            engine_state: &engine_state,
            state_root: &config.state_root,
            root: &root,
            crontab_program: "crontab",
            shell_program: "bash",
        };
        let cancel = CancellationToken::default();
        macro_rules! run {
            ($request:ty, $pipeline:path) => {{
                let request = match <$request>::parse(&json, request_id, key) {
                    Ok(v) => v,
                    Err(error) => {
                        return failure(ErrorCode::InvalidInput, request_error_message(error));
                    }
                };
                match $pipeline(&context, &request, &cancel) {
                    Ok(value) => Response::success(operation, value),
                    Err(error) => {
                        let (code, message) = error.protocol();
                        failure(code, &message)
                    }
                }
            }};
        }
        match operation {
            agent_lifecycle::INSTALL_OPERATION => {
                run!(agent_lifecycle::InstallRequest, execute::install)
            }
            agent_lifecycle::REMOVE_OPERATION => {
                run!(agent_lifecycle::RemoveRequest, execute::remove)
            }
            _ => run!(agent_lifecycle::UnbanRequest, execute::bruteforce_unban),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, key);
        Ok(Response::failure(
            operation,
            ErrorCode::UnsupportedPlatform,
            "agent operations require a Unix host",
        ))
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
