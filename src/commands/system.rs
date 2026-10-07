use crate::{
    cli::SystemCommand,
    commands::read_root_owned_content_file,
    error::ErrorCode,
    process::CancellationToken,
    protocol::{Response, ResponseBuildError},
    system_autoupdates, system_autoupdates_install, system_start_docker,
};

const CONFIG_PATH: &str = "/etc/operations-engine/config.json";

pub fn run(command: SystemCommand) -> Result<Response, ResponseBuildError> {
    match command {
        SystemCommand::ActivateAutoupdatesConfig {
            request_file,
            request_id,
            idempotency_key,
        } => activate_autoupdates_config(&request_file, &request_id, idempotency_key.as_deref()),
        SystemCommand::InstallAutoupdates {
            request_id,
            idempotency_key,
        } => install_autoupdates(&request_id, idempotency_key.as_deref()),
        SystemCommand::InstallDocker {
            request_id,
            idempotency_key,
        } => install_docker(&request_id, idempotency_key.as_deref()),
        SystemCommand::StartDocker {
            request_id,
            idempotency_key,
        } => start_docker(&request_id, idempotency_key.as_deref()),
        SystemCommand::PruneDocker {
            kind,
            confirmation,
            request_id,
            idempotency_key,
        } => prune_docker(
            &kind,
            &confirmation,
            &request_id,
            idempotency_key.as_deref(),
        ),
        SystemCommand::ContainerAction {
            container_id,
            action,
            force,
            confirmation,
            request_id,
            idempotency_key,
        } => container_action(
            &container_id,
            &action,
            force,
            confirmation.as_deref(),
            &request_id,
            idempotency_key.as_deref(),
        ),
        SystemCommand::SetContainerLimits {
            container_id,
            cpus,
            memory_bytes,
            restart_policy,
            request_id,
            idempotency_key,
        } => set_container_limits(
            &container_id,
            cpus,
            memory_bytes,
            restart_policy.as_deref(),
            &request_id,
            idempotency_key.as_deref(),
        ),
        SystemCommand::DockerNetwork {
            action,
            name,
            driver,
            confirmation,
            request_id,
            idempotency_key,
        } => docker_network(
            &action,
            &name,
            driver.as_deref(),
            confirmation.as_deref(),
            &request_id,
            idempotency_key.as_deref(),
        ),
        SystemCommand::PullImage {
            reference,
            request_id,
            idempotency_key,
        } => pull_image(&reference, &request_id, idempotency_key.as_deref()),
        SystemCommand::RemoveImage {
            image_id,
            force,
            confirmation,
            request_id,
            idempotency_key,
        } => remove_image(
            &image_id,
            force,
            confirmation.as_deref(),
            &request_id,
            idempotency_key.as_deref(),
        ),
        SystemCommand::RemoveVolume {
            volume_name,
            confirmation,
            request_id,
            idempotency_key,
        } => remove_volume(
            &volume_name,
            confirmation.as_deref(),
            &request_id,
            idempotency_key.as_deref(),
        ),
        SystemCommand::Service {
            unit,
            action,
            confirmation,
            request_id,
            idempotency_key,
        } => service(
            &unit,
            &action,
            confirmation.as_deref(),
            &request_id,
            idempotency_key.as_deref(),
        ),
        SystemCommand::SignalProcess {
            pid,
            signal,
            expect_comm,
            request_id,
            idempotency_key,
        } => signal_process(
            pid,
            signal.as_deref(),
            expect_comm.as_deref(),
            &request_id,
            idempotency_key.as_deref(),
        ),
        SystemCommand::CreateSwap {
            size_mb,
            request_id,
            idempotency_key,
        } => swap(
            SwapAction::Create { size_mb },
            &request_id,
            idempotency_key.as_deref(),
        ),
        SystemCommand::DeleteSwap {
            request_id,
            idempotency_key,
        } => swap(SwapAction::Delete, &request_id, idempotency_key.as_deref()),
        SystemCommand::ResizeSwap {
            size_mb,
            request_id,
            idempotency_key,
        } => swap(
            SwapAction::Resize { size_mb },
            &request_id,
            idempotency_key.as_deref(),
        ),
    }
}

/// Mirrors `system_swap::Action` so the CLI layer compiles on every
/// platform even though the swap module itself is Unix-only.
#[derive(Clone, Copy)]
enum SwapAction {
    Create { size_mb: u32 },
    Delete,
    Resize { size_mb: u32 },
}

impl SwapAction {
    const fn operation(self) -> &'static str {
        match self {
            Self::Create { .. } => "system.createSwap",
            Self::Delete => "system.deleteSwap",
            Self::Resize { .. } => "system.resizeSwap",
        }
    }
}

fn swap(
    action: SwapAction,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    let operation = action.operation();
    #[cfg(unix)]
    {
        use crate::{
            config::EngineConfig, filesystem::ManagedRoot, site::TrustedRoot, system_swap,
        };
        let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    operation,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let action = match action {
            SwapAction::Create { size_mb } => system_swap::Action::Create { size_mb },
            SwapAction::Delete => system_swap::Action::Delete,
            SwapAction::Resize { size_mb } => system_swap::Action::Resize { size_mb },
        };
        let request = match system_swap::Request::parse(action, request_id, key) {
            Ok(v) => v,
            Err(system_swap::RequestError::InvalidSize) => {
                return Ok(Response::failure(
                    operation,
                    ErrorCode::InvalidInput,
                    &format!(
                        "size-mb must be between {} and {}",
                        system_swap::MIN_SIZE_MB,
                        system_swap::MAX_SIZE_MB
                    ),
                ));
            }
            Err(_) => {
                return Ok(Response::failure(
                    operation,
                    ErrorCode::InvalidInput,
                    "request-id or idempotency-key is invalid",
                ));
            }
        };
        if !cfg!(target_os = "linux") {
            return Ok(Response::failure(
                operation,
                ErrorCode::UnsupportedPlatform,
                "swap management requires a Linux host",
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
        let etc_dir =
            match TrustedRoot::parse(std::path::Path::new(system_swap::ETC_DIR)).and_then(|r| {
                ManagedRoot::open(&r)
                    .map_err(|_| crate::site::ValidationError::PathResolutionFailed)
            }) {
                Ok(v) => v,
                Err(_) => {
                    return Ok(Response::failure(
                        operation,
                        ErrorCode::Internal,
                        "/etc is unavailable",
                    ));
                }
            };
        let ctx = system_swap::Context {
            engine_state: &state,
            etc_dir: &etc_dir,
            swap_path: system_swap::SWAP_PATH,
            proc_swaps: std::path::Path::new(system_swap::PROC_SWAPS),
            tools: system_swap::Tools {
                fallocate: "fallocate",
                mkswap: "mkswap",
                swapon: "swapon",
                swapoff: "swapoff",
            },
            available_bytes: system_swap::statvfs_available_bytes,
        };
        match system_swap::execute(&ctx, &request, &CancellationToken::default()) {
            Ok(v) | Err(system_swap::Error::PostCommit { result: v }) => {
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
        let _ = (request_id, key);
        Ok(Response::failure(
            operation,
            ErrorCode::UnsupportedPlatform,
            "swap management requires a Linux host",
        ))
    }
}

fn install_docker(request_id: &str, key: Option<&str>) -> Result<Response, ResponseBuildError> {
    const OPERATION: &str = "system.installDocker";
    #[cfg(unix)]
    {
        use crate::{
            config::EngineConfig, filesystem::ManagedRoot, site::TrustedRoot,
            system_install_docker as op,
        };
        use std::path::Path;
        let config = match EngineConfig::load_root_owned(Path::new(CONFIG_PATH)) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let request = match op::Request::parse(request_id, key) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    OPERATION,
                    ErrorCode::InvalidInput,
                    "request-id or idempotency-key is invalid",
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        let open_apt_dir = |path: &str| {
            std::fs::create_dir_all(path).ok()?;
            ManagedRoot::open(&TrustedRoot::parse(Path::new(path)).ok()?).ok()
        };
        let (Some(keyrings_dir), Some(sources_dir)) = (
            open_apt_dir(op::KEYRINGS_DIR),
            open_apt_dir(op::SOURCES_DIR),
        ) else {
            return Ok(Response::failure(
                OPERATION,
                ErrorCode::Internal,
                "apt configuration directories are unavailable",
            ));
        };
        let unowned: Vec<&Path> = op::UNOWNED_BINARIES.iter().map(Path::new).collect();
        let cli: Vec<&Path> = op::CLI_BINARIES.iter().map(Path::new).collect();
        let ctx = op::Context {
            engine_state: &state,
            os_release: Path::new(op::OS_RELEASE),
            keyrings_dir: &keyrings_dir,
            sources_dir: &sources_dir,
            sources_list: Path::new(op::SOURCES_LIST),
            unowned_binaries: &unowned,
            cli_binaries: &cli,
            keyring: op::DOCKER_KEYRING,
            keyring_sha256: op::DOCKER_KEYRING_SHA256,
            tools: op::Tools {
                apt_get: "apt-get",
                dpkg: "dpkg",
                dpkg_query: "dpkg-query",
                systemctl: "systemctl",
                docker: "docker",
            },
        };
        match op::execute(&ctx, &request, &CancellationToken::default()) {
            Ok(v) => Response::success(OPERATION, v),
            Err(op::Error::PostCommit { result }) => Response::success(OPERATION, *result),
            Err(e) => {
                let (code, message) = e.protocol();
                Ok(Response::failure(OPERATION, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (request_id, key);
        Ok(Response::failure(
            OPERATION,
            ErrorCode::UnsupportedPlatform,
            "system.installDocker requires a Debian or Ubuntu host",
        ))
    }
}

fn signal_process(
    pid: u32,
    signal: Option<&str>,
    expect_comm: Option<&str>,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(target_os = "linux")]
    {
        use crate::{config::EngineConfig, filesystem::ManagedRoot, system_signal};
        let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    system_signal::OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let request = match system_signal::Request::parse(pid, signal, expect_comm, request_id, key)
        {
            Ok(v) => v,
            Err(error) => {
                return Ok(Response::failure(
                    system_signal::OPERATION,
                    ErrorCode::InvalidInput,
                    error.message(),
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    system_signal::OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        let ctx = system_signal::Context {
            engine_state: &state,
            proc_root: std::path::Path::new(system_signal::PROC_ROOT),
            engine_pid: std::process::id(),
        };
        match system_signal::execute(&ctx, &request) {
            Ok(v) | Err(system_signal::Error::PostCommit { result: v }) => {
                Response::success(system_signal::OPERATION, v)
            }
            Err(e) => {
                let (code, message) = e.protocol();
                Ok(Response::failure(system_signal::OPERATION, code, &message))
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pid, signal, expect_comm, request_id, key);
        Ok(Response::failure(
            "system.signalProcess",
            ErrorCode::UnsupportedPlatform,
            "system.signalProcess requires a Linux host",
        ))
    }
}

fn start_docker(request_id: &str, key: Option<&str>) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{config::EngineConfig, filesystem::ManagedRoot};
        let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    system_start_docker::OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let request = match system_start_docker::Request::parse(request_id, key) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    system_start_docker::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-id or idempotency-key is invalid",
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    system_start_docker::OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        let (program, args): (&str, &[&str]) = if cfg!(target_os = "macos") {
            ("open", &["-a", "Docker"])
        } else {
            ("systemctl", &["start", "docker"])
        };
        let ctx = system_start_docker::Context {
            engine_state: &state,
            start_program: program,
            start_args: args,
        };
        match system_start_docker::execute(&ctx, &request, &CancellationToken::default()) {
            Ok(v) | Err(system_start_docker::Error::PostCommit { result: v }) => {
                Response::success(system_start_docker::OPERATION, v)
            }
            Err(e) => {
                let (code, message) = e.protocol();
                Ok(Response::failure(
                    system_start_docker::OPERATION,
                    code,
                    &message,
                ))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (request_id, key);
        Ok(Response::failure(
            system_start_docker::OPERATION,
            ErrorCode::UnsupportedPlatform,
            "system.startDocker requires a Unix host",
        ))
    }
}

fn prune_docker(
    kind: &str,
    confirmation: &str,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{config::EngineConfig, docker_prune, filesystem::ManagedRoot};
        let request = match docker_prune::Request::parse(kind, confirmation, request_id, key) {
            Ok(v) => v,
            Err(error) => {
                let message = match error {
                    docker_prune::RequestError::InvalidKind => {
                        "kind must be image, volume or system"
                    }
                    docker_prune::RequestError::InvalidConfirmation => {
                        "confirmation does not match the prune kind"
                    }
                    _ => "request-id or idempotency-key is invalid",
                };
                return Ok(Response::failure(
                    docker_prune::OPERATION,
                    ErrorCode::InvalidInput,
                    message,
                ));
            }
        };
        let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    docker_prune::OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    docker_prune::OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        let ctx = docker_prune::Context {
            engine_state: &state,
            docker_program: "docker",
        };
        match docker_prune::execute(&ctx, &request, &CancellationToken::default()) {
            Ok(v) | Err(docker_prune::Error::PostCommit { result: v }) => {
                Response::success(docker_prune::OPERATION, v)
            }
            Err(e) => {
                let (code, message) = e.protocol();
                Ok(Response::failure(docker_prune::OPERATION, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (kind, confirmation, request_id, key);
        Ok(Response::failure(
            "docker.prune",
            ErrorCode::UnsupportedPlatform,
            "docker.prune requires a Unix host",
        ))
    }
}

/// The engine state root for the three Docker/service operations, or the
/// failure response the caller should return.
#[cfg(unix)]
fn open_engine_state(
    operation: &'static str,
) -> Result<crate::filesystem::ManagedRoot, Result<Response, ResponseBuildError>> {
    use crate::{config::EngineConfig, filesystem::ManagedRoot};
    let config =
        EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)).map_err(|_| {
            Ok(Response::failure(
                operation,
                ErrorCode::Internal,
                crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
            ))
        })?;
    ManagedRoot::open(&config.state_root).map_err(|_| {
        Ok(Response::failure(
            operation,
            ErrorCode::Internal,
            "engine state root is unavailable",
        ))
    })
}

fn container_action(
    container_id: &str,
    action: &str,
    force: bool,
    confirmation: Option<&str>,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::docker_container::{self as dc, RequestError};
        let request = match dc::ActionRequest::parse(
            container_id,
            action,
            force,
            confirmation,
            request_id,
            key,
        ) {
            Ok(v) => v,
            Err(error) => {
                let message = match error {
                    RequestError::InvalidContainerId => {
                        "container-id must be 12 to 64 lowercase hex digits"
                    }
                    RequestError::InvalidAction => {
                        "action must be start, stop, restart, pause, unpause or remove"
                    }
                    RequestError::ForceNotApplicable => "force applies to remove only",
                    RequestError::InvalidConfirmation => {
                        "confirmation does not match the container action"
                    }
                    _ => "request-id or idempotency-key is invalid",
                };
                return Ok(Response::failure(
                    dc::ACTION_OPERATION,
                    ErrorCode::InvalidInput,
                    message,
                ));
            }
        };
        let state = match open_engine_state(dc::ACTION_OPERATION) {
            Ok(v) => v,
            Err(response) => return response,
        };
        let ctx = dc::Context {
            engine_state: &state,
            docker_program: "docker",
            host_cores: 0,
            host_memory_bytes: None,
        };
        match dc::execute_action(&ctx, &request, &CancellationToken::default()) {
            Ok(v) => Response::success(dc::ACTION_OPERATION, v),
            Err(dc::Error::PostCommit { result }) => {
                Response::success(dc::ACTION_OPERATION, result)
            }
            Err(e) => {
                let (code, message) = e.protocol();
                Ok(Response::failure(dc::ACTION_OPERATION, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (container_id, action, force, confirmation, request_id, key);
        Ok(Response::failure(
            "docker.containerAction",
            ErrorCode::UnsupportedPlatform,
            "docker.containerAction requires a Unix host",
        ))
    }
}

fn set_container_limits(
    container_id: &str,
    cpus: f64,
    memory_bytes: u64,
    restart_policy: Option<&str>,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::docker_container::{self as dc, RequestError};
        let request = match dc::LimitsRequest::parse(
            container_id,
            cpus,
            memory_bytes,
            restart_policy,
            request_id,
            key,
        ) {
            Ok(v) => v,
            Err(error) => {
                let message = match error {
                    RequestError::InvalidContainerId => {
                        "container-id must be 12 to 64 lowercase hex digits"
                    }
                    RequestError::InvalidCpus => "cpus must be a finite number, 0 or more",
                    RequestError::InvalidMemory => "memory-bytes must be 0 or at least 4 MiB",
                    RequestError::InvalidRestartPolicy => "restart-policy is not allowed",
                    _ => "request-id or idempotency-key is invalid",
                };
                return Ok(Response::failure(
                    dc::LIMITS_OPERATION,
                    ErrorCode::InvalidInput,
                    message,
                ));
            }
        };
        let state = match open_engine_state(dc::LIMITS_OPERATION) {
            Ok(v) => v,
            Err(response) => return response,
        };
        let host_cores = std::thread::available_parallelism()
            .map(|n| u32::try_from(n.get()).unwrap_or(u32::MAX))
            .unwrap_or(1);
        let host_memory_bytes = std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|text| dc::parse_meminfo_total(&text));
        let ctx = dc::Context {
            engine_state: &state,
            docker_program: "docker",
            host_cores,
            host_memory_bytes,
        };
        match dc::execute_limits(&ctx, &request, &CancellationToken::default()) {
            Ok(v) => Response::success(dc::LIMITS_OPERATION, v),
            Err(dc::Error::PostCommit { result }) => {
                Response::success(dc::LIMITS_OPERATION, result)
            }
            Err(e) => {
                let (code, message) = e.protocol();
                Ok(Response::failure(dc::LIMITS_OPERATION, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (
            container_id,
            cpus,
            memory_bytes,
            restart_policy,
            request_id,
            key,
        );
        Ok(Response::failure(
            "docker.setLimits",
            ErrorCode::UnsupportedPlatform,
            "docker.setLimits requires a Unix host",
        ))
    }
}

#[cfg(unix)]
fn resource_request_error(
    operation: &'static str,
    error: crate::docker_resource::RequestError,
) -> Result<Response, ResponseBuildError> {
    use crate::docker_resource::RequestError;
    let message = match error {
        RequestError::InvalidAction => "action must be create or remove",
        RequestError::InvalidName => {
            "name must start with a letter or digit and use letters, digits, _, . or -"
        }
        RequestError::InvalidDriver => "driver is not allowed for this action",
        RequestError::InvalidReference => "reference is not a valid image reference",
        RequestError::RegistryNotAllowed => "the image registry is not allowed",
        RequestError::InvalidImageId => "image-id must be 12 to 64 lowercase hex digits",
        RequestError::InvalidConfirmation => "confirmation does not match the operation",
        RequestError::ForceNotApplicable => "force does not apply to this operation",
        RequestError::InvalidRequestId | RequestError::InvalidIdempotencyKey => {
            "request-id or idempotency-key is invalid"
        }
    };
    Ok(Response::failure(
        operation,
        ErrorCode::InvalidInput,
        message,
    ))
}

#[cfg(unix)]
fn resource_response<T: serde::Serialize>(
    operation: &'static str,
    outcome: Result<T, crate::docker_container::Error>,
) -> Result<Response, ResponseBuildError> {
    use crate::docker_container::Error;
    match outcome {
        Ok(v) => Response::success(operation, v),
        Err(Error::PostCommit { result }) => Response::success(operation, result),
        Err(e) => {
            let (code, message) = e.protocol();
            Ok(Response::failure(operation, code, &message))
        }
    }
}

#[cfg(unix)]
fn with_resource_context(
    operation: &'static str,
    run: impl FnOnce(&crate::docker_resource::Context<'_>) -> Result<Response, ResponseBuildError>,
) -> Result<Response, ResponseBuildError> {
    let state = match open_engine_state(operation) {
        Ok(v) => v,
        Err(response) => return response,
    };
    run(&crate::docker_resource::Context {
        engine_state: &state,
        docker_program: "docker",
        free_bytes: crate::docker_resource::statvfs_free_bytes,
    })
}

#[cfg(not(unix))]
fn resource_unsupported(operation: &'static str) -> Result<Response, ResponseBuildError> {
    Ok(Response::failure(
        operation,
        ErrorCode::UnsupportedPlatform,
        &format!("{operation} requires a Unix host"),
    ))
}

fn docker_network(
    action: &str,
    name: &str,
    driver: Option<&str>,
    confirmation: Option<&str>,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::docker_resource as dr;
        let request =
            match dr::NetworkRequest::parse(action, name, driver, confirmation, request_id, key) {
                Ok(v) => v,
                Err(e) => return resource_request_error(dr::NETWORK_OPERATION, e),
            };
        with_resource_context(dr::NETWORK_OPERATION, |ctx| {
            resource_response(
                dr::NETWORK_OPERATION,
                dr::execute_network(ctx, &request, &CancellationToken::default()),
            )
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (action, name, driver, confirmation, request_id, key);
        resource_unsupported("docker.network")
    }
}

fn pull_image(
    reference: &str,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::docker_resource as dr;
        let request = match dr::PullRequest::parse(reference, request_id, key) {
            Ok(v) => v,
            Err(e) => return resource_request_error(dr::PULL_OPERATION, e),
        };
        with_resource_context(dr::PULL_OPERATION, |ctx| {
            resource_response(
                dr::PULL_OPERATION,
                dr::execute_pull(ctx, &request, &CancellationToken::default()),
            )
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (reference, request_id, key);
        resource_unsupported("docker.imagePull")
    }
}

fn remove_image(
    image_id: &str,
    force: bool,
    confirmation: Option<&str>,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::docker_resource as dr;
        let request =
            match dr::ImageRemoveRequest::parse(image_id, force, confirmation, request_id, key) {
                Ok(v) => v,
                Err(e) => return resource_request_error(dr::IMAGE_REMOVE_OPERATION, e),
            };
        with_resource_context(dr::IMAGE_REMOVE_OPERATION, |ctx| {
            resource_response(
                dr::IMAGE_REMOVE_OPERATION,
                dr::execute_image_remove(ctx, &request, &CancellationToken::default()),
            )
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (image_id, force, confirmation, request_id, key);
        resource_unsupported("docker.imageRemove")
    }
}

fn remove_volume(
    volume_name: &str,
    confirmation: Option<&str>,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::docker_resource as dr;
        let request =
            match dr::VolumeRemoveRequest::parse(volume_name, confirmation, request_id, key) {
                Ok(v) => v,
                Err(e) => return resource_request_error(dr::VOLUME_REMOVE_OPERATION, e),
            };
        with_resource_context(dr::VOLUME_REMOVE_OPERATION, |ctx| {
            resource_response(
                dr::VOLUME_REMOVE_OPERATION,
                dr::execute_volume_remove(ctx, &request, &CancellationToken::default()),
            )
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (volume_name, confirmation, request_id, key);
        resource_unsupported("docker.volumeRemove")
    }
}

fn service(
    unit: &str,
    action: &str,
    confirmation: Option<&str>,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::system_service::{self as svc, RequestError};
        let request = match svc::Request::parse(unit, action, confirmation, request_id, key) {
            Ok(v) => v,
            Err(error) => {
                let message = match error {
                    RequestError::InvalidUnit => "unit must be netdata or docker",
                    RequestError::InvalidAction => "action must be start or restart",
                    RequestError::InvalidConfirmation => {
                        "confirmation does not match the service action"
                    }
                    _ => "request-id or idempotency-key is invalid",
                };
                return Ok(Response::failure(
                    svc::OPERATION,
                    ErrorCode::InvalidInput,
                    message,
                ));
            }
        };
        let state = match open_engine_state(svc::OPERATION) {
            Ok(v) => v,
            Err(response) => return response,
        };
        let ctx = svc::Context {
            engine_state: &state,
            systemctl_program: "systemctl",
        };
        match svc::execute(&ctx, &request, &CancellationToken::default()) {
            Ok(v) | Err(svc::Error::PostCommit { result: v }) => {
                Response::success(svc::OPERATION, v)
            }
            Err(e) => {
                let (code, message) = e.protocol();
                Ok(Response::failure(svc::OPERATION, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (unit, action, confirmation, request_id, key);
        Ok(Response::failure(
            "system.service",
            ErrorCode::UnsupportedPlatform,
            "system.service requires a Unix host",
        ))
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

fn install_autoupdates(
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{config::EngineConfig, filesystem::ManagedRoot};
        let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    system_autoupdates_install::OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let request = match system_autoupdates_install::Request::parse(request_id, key) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    system_autoupdates_install::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-id or idempotency-key is invalid",
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    system_autoupdates_install::OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        let ctx = system_autoupdates_install::Context {
            engine_state: &state,
            apt_get_program: "apt-get",
        };
        match system_autoupdates_install::execute(&ctx, &request, &CancellationToken::default()) {
            Ok(v) | Err(system_autoupdates_install::Error::PostCommit { result: v }) => {
                Response::success(system_autoupdates_install::OPERATION, v)
            }
            Err(e) => {
                let (code, message) = e.protocol();
                Ok(Response::failure(
                    system_autoupdates_install::OPERATION,
                    code,
                    &message,
                ))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (request_id, key);
        Ok(Response::failure(
            system_autoupdates_install::OPERATION,
            ErrorCode::UnsupportedPlatform,
            "system.installAutoupdates requires a Unix host",
        ))
    }
}
