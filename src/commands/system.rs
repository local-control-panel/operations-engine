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
        SystemCommand::StartDocker {
            request_id,
            idempotency_key,
        } => start_docker(&request_id, idempotency_key.as_deref()),
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
