use crate::{
    agent_config, agent_lifecycle, agent_registry,
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
        AgentCommand::InstallFromRegistry {
            request_file,
            request_id,
            idempotency_key,
        } => lifecycle(
            agent_registry::INSTALL_OPERATION,
            &request_file,
            &request_id,
            idempotency_key.as_deref(),
        ),
        AgentCommand::Approve {
            request_file,
            request_id,
            idempotency_key,
        } => lifecycle(
            agent_registry::APPROVE_OPERATION,
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
            agent_registry::INSTALL_OPERATION => Ok(install_from_registry(
                &context,
                &engine_state,
                &json,
                request_id,
                key,
                &cancel,
            )),
            agent_registry::APPROVE_OPERATION => Ok(approve(&engine_state, &json, request_id)),
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

fn registry_request_message(error: agent_registry::RequestError) -> &'static str {
    use agent_registry::RequestError;
    match error {
        RequestError::InvalidJson => "request-file is not a valid registry agent request",
        RequestError::InvalidName => "name is not a valid agent name",
        RequestError::InvalidRelease => "release must be a plain x.y.z version",
        RequestError::InvalidHash => "sha256 must be 64 lowercase hex characters",
        RequestError::InvalidSchedule => {
            "schedule must be five cron fields or @hourly/@daily/@weekly/@monthly/@yearly"
        }
        RequestError::InvalidRequestId => "request-id is not a canonical UUID",
        RequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}

#[cfg(unix)]
fn install_from_registry(
    context: &agent_lifecycle::execute::Context<'_>,
    engine_state: &ManagedRoot,
    json: &str,
    request_id: &str,
    key: Option<&str>,
    cancel: &crate::process::CancellationToken,
) -> Response {
    use crate::transaction::{IdempotencyKey, RequestId};
    let operation = agent_registry::INSTALL_OPERATION;
    let failure = |code: ErrorCode, message: &str| Response::failure(operation, code, message);
    let request = match agent_registry::InstallRequest::parse(json) {
        Ok(v) => v,
        Err(error) => return failure(ErrorCode::InvalidInput, registry_request_message(error)),
    };
    let Ok(request_id) = RequestId::parse(request_id) else {
        return failure(
            ErrorCode::InvalidInput,
            "request-id is not a canonical UUID",
        );
    };
    let idempotency_key = match key.map(IdempotencyKey::parse).transpose() {
        Ok(v) => v,
        Err(_) => return failure(ErrorCode::InvalidInput, "idempotency-key is invalid"),
    };
    let approved = |name: &str, sha256: &str| {
        crate::site::SiteRelativePath::parse(agent_registry::approval_file(name, sha256))
            .is_ok_and(|path| engine_state.exists(&path))
    };
    // Downloaded before the transaction starts, so no lock is held on the
    // network.
    let verified = match agent_registry::fetch_verified(
        &agent_registry::Source::default(),
        &agent_registry::network_fetch,
        &request,
        env!("CARGO_PKG_VERSION"),
        &approved,
    ) {
        Ok(v) => v,
        Err(error) => {
            let (code, message) = error.protocol();
            return failure(code, &message);
        }
    };
    let install = agent_lifecycle::InstallRequest {
        agent: verified.agent,
        schedule: request.schedule,
        request_id,
        idempotency_key,
    };
    match agent_lifecycle::execute::install(context, &install, cancel) {
        Ok(value) => Response::success(operation, value).unwrap_or_else(|_| {
            failure(
                ErrorCode::InternalSerializationError,
                "could not build the response",
            )
        }),
        Err(error) => {
            let (code, message) = error.protocol();
            failure(code, &message)
        }
    }
}

#[cfg(unix)]
fn approve(engine_state: &ManagedRoot, json: &str, request_id: &str) -> Response {
    use crate::{site::SiteRelativePath, transaction::RequestId};
    let operation = agent_registry::APPROVE_OPERATION;
    let failure = |code: ErrorCode, message: &str| Response::failure(operation, code, message);
    let request = match agent_registry::ApproveRequest::parse(json) {
        Ok(v) => v,
        Err(error) => return failure(ErrorCode::InvalidInput, registry_request_message(error)),
    };
    if RequestId::parse(request_id).is_err() {
        return failure(
            ErrorCode::InvalidInput,
            "request-id is not a canonical UUID",
        );
    }
    let dir = SiteRelativePath::parse(agent_registry::APPROVALS_DIR).expect("literal path");
    let file = SiteRelativePath::parse(agent_registry::approval_file(
        &request.name,
        &request.sha256,
    ))
    .expect("validated name and hash");
    let written = engine_state
        .create_dir_all(&dir)
        .and_then(|()| engine_state.write_atomic_private(&file, b"approved\n"));
    if written.is_err() {
        return failure(ErrorCode::Internal, "could not record the approval");
    }
    let approved_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    Response::success(
        operation,
        serde_json::json!({
            "name": request.name,
            "sha256": request.sha256,
            "approvedAtUnixSecs": approved_at,
        }),
    )
    .unwrap_or_else(|_| {
        failure(
            ErrorCode::InternalSerializationError,
            "could not build the response",
        )
    })
}
