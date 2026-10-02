use crate::{
    cli::StackCommand,
    error::ErrorCode,
    protocol::{Response, ResponseBuildError},
};

const OPERATION: &str = "stack.deploy";
#[cfg(unix)]
const CONFIG_PATH: &str = "/etc/operations-engine/config.json";

pub fn run(command: StackCommand) -> Result<Response, ResponseBuildError> {
    match command {
        StackCommand::Deploy {
            request_file,
            request_id,
            idempotency_key,
        } => deploy(&request_file, &request_id, idempotency_key.as_deref()),
        StackCommand::ReloadCaddy {
            service,
            request_id,
            idempotency_key,
        } => reload_caddy(&service, &request_id, idempotency_key.as_deref()),
        StackCommand::StopIdleRuntime {
            runtime_id,
            request_id,
            idempotency_key,
        } => stop_idle_runtime(&runtime_id, &request_id, idempotency_key.as_deref()),
        StackCommand::EnsureRuntime {
            runtime_id,
            profile,
            request_id,
            idempotency_key,
        } => ensure_runtime(
            &runtime_id,
            profile.as_deref(),
            &request_id,
            idempotency_key.as_deref(),
        ),
        StackCommand::ReloadWorkers {
            runtime_id,
            request_id,
            idempotency_key,
        } => runtime_action(
            crate::stack_service::RELOAD_WORKERS_OPERATION,
            crate::stack_service::reload_workers,
            &runtime_id,
            &request_id,
            idempotency_key.as_deref(),
        ),
        StackCommand::FlushFpc {
            runtime_id,
            request_id,
            idempotency_key,
        } => runtime_action(
            crate::stack_service::FLUSH_FPC_OPERATION,
            crate::stack_service::flush_fpc,
            &runtime_id,
            &request_id,
            idempotency_key.as_deref(),
        ),
        StackCommand::WriteSiteService {
            runtime_id,
            domain,
            uid,
            gid,
            port,
            root,
            worker_mode,
            worker_count,
            request_id,
            idempotency_key,
        } => write_site_service(
            &runtime_id,
            &domain,
            uid,
            gid,
            port,
            root,
            worker_mode,
            worker_count,
            &request_id,
            idempotency_key.as_deref(),
        ),
        StackCommand::ActivateSiteConfig {
            runtime_id,
            domain,
            port,
            root,
            content_file,
            expected_prior_hash,
            request_id,
            idempotency_key,
        } => activate_site_config(
            &runtime_id,
            &domain,
            port,
            root,
            &content_file,
            expected_prior_hash.as_deref(),
            &request_id,
            idempotency_key.as_deref(),
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn write_site_service(
    runtime_id: &str,
    domain: &str,
    uid: u32,
    gid: u32,
    port: u16,
    root: String,
    worker_mode: bool,
    worker_count: i64,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    use crate::stack_service::{
        WRITE_SITE_SERVICE_OPERATION, WriteSiteServiceRequest, write_site_service,
    };

    let request = match WriteSiteServiceRequest::parse(
        runtime_id,
        domain,
        uid,
        gid,
        port,
        root,
        worker_mode,
        worker_count,
        request_id,
        idempotency_key,
    ) {
        Ok(request) => request,
        Err(error) => {
            return Ok(Response::failure(
                WRITE_SITE_SERVICE_OPERATION,
                ErrorCode::InvalidInput,
                error.message(),
            ));
        }
    };
    run_service_operation(WRITE_SITE_SERVICE_OPERATION, |ctx, cancel| {
        write_site_service(ctx, &request, cancel)
    })
}

#[allow(clippy::too_many_arguments)]
fn activate_site_config(
    runtime_id: &str,
    domain: &str,
    port: u16,
    root: String,
    content_file: &std::path::Path,
    expected_prior_hash: Option<&str>,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    use crate::{
        commands::{ContentFileError, read_root_owned_content_file},
        stack_service::{
            ACTIVATE_SITE_CONFIG_OPERATION, ActivateSiteConfigRequest, activate_site_config,
        },
    };

    let caddyfile = match read_root_owned_content_file(content_file) {
        Ok(content) => content,
        Err(ContentFileError::TooLarge) => {
            return Ok(Response::failure(
                ACTIVATE_SITE_CONFIG_OPERATION,
                ErrorCode::InvalidInput,
                "content-file exceeds the maximum allowed size",
            ));
        }
        Err(ContentFileError::Unreadable) => {
            return Ok(Response::failure(
                ACTIVATE_SITE_CONFIG_OPERATION,
                ErrorCode::InvalidInput,
                "content-file must be a root-owned file that is not group/world-writable",
            ));
        }
    };
    let request = match ActivateSiteConfigRequest::parse(
        runtime_id,
        domain,
        port,
        root,
        caddyfile,
        expected_prior_hash,
        request_id,
        idempotency_key,
    ) {
        Ok(request) => request,
        Err(error) => {
            return Ok(Response::failure(
                ACTIVATE_SITE_CONFIG_OPERATION,
                ErrorCode::InvalidInput,
                error.message(),
            ));
        }
    };
    run_service_operation(ACTIVATE_SITE_CONFIG_OPERATION, |ctx, cancel| {
        activate_site_config(ctx, &request, cancel)
    })
}

fn ensure_runtime(
    runtime_id: &str,
    profile: Option<&str>,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    use crate::stack_service::{ENSURE_OPERATION, EnsureRequest, ensure_runtime};

    let request = match EnsureRequest::parse(runtime_id, profile, request_id, idempotency_key) {
        Ok(request) => request,
        Err(error) => {
            return Ok(Response::failure(
                ENSURE_OPERATION,
                ErrorCode::InvalidInput,
                error.message(),
            ));
        }
    };
    run_service_operation(ENSURE_OPERATION, |ctx, cancel| {
        ensure_runtime(ctx, &request, cancel)
    })
}

/// `stack.reloadWorkers` / `stack.flushFpc`: one runtime pool, no other
/// input.
fn runtime_action(
    operation: &'static str,
    action: fn(
        &crate::stack_service::Context<'_>,
        &crate::stack_service::RuntimeRequest,
        &crate::process::CancellationToken,
    )
        -> Result<crate::stack_service::RuntimeActionResult, crate::stack_service::Error>,
    runtime_id: &str,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    let request = match crate::stack_service::RuntimeRequest::parse(
        runtime_id,
        request_id,
        idempotency_key,
    ) {
        Ok(request) => request,
        Err(error) => {
            return Ok(Response::failure(
                operation,
                ErrorCode::InvalidInput,
                error.message(),
            ));
        }
    };
    run_service_operation(operation, |ctx, cancel| action(ctx, &request, cancel))
}

fn reload_caddy(
    service: &str,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    use crate::stack_service::{RELOAD_OPERATION, ReloadRequest, reload};

    let request = match ReloadRequest::parse(service, request_id, idempotency_key) {
        Ok(request) => request,
        Err(error) => {
            return Ok(Response::failure(
                RELOAD_OPERATION,
                ErrorCode::InvalidInput,
                error.message(),
            ));
        }
    };
    run_service_operation(RELOAD_OPERATION, |ctx, cancel| {
        reload(ctx, &request, cancel)
    })
}

fn stop_idle_runtime(
    runtime_id: &str,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    use crate::stack_service::{STOP_OPERATION, StopRequest, stop_idle_runtime};

    let request = match StopRequest::parse(runtime_id, request_id, idempotency_key) {
        Ok(request) => request,
        Err(error) => {
            return Ok(Response::failure(
                STOP_OPERATION,
                ErrorCode::InvalidInput,
                error.message(),
            ));
        }
    };
    run_service_operation(STOP_OPERATION, |ctx, cancel| {
        stop_idle_runtime(ctx, &request, cancel)
    })
}

/// Loads the config, opens the state root, resolves the stack directory and
/// runs one `stack_service` operation, mapping its outcome to a response.
#[cfg(unix)]
fn run_service_operation<T, F>(
    operation: &'static str,
    run: F,
) -> Result<Response, ResponseBuildError>
where
    T: serde::Serialize,
    F: FnOnce(
        &crate::stack_service::Context<'_>,
        &crate::process::CancellationToken,
    ) -> Result<T, crate::stack_service::Error>,
{
    use crate::{
        compose, config::EngineConfig, error::WarningCode, filesystem::ManagedRoot,
        process::CancellationToken, protocol::Warning, stack_service,
    };

    let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
        Ok(config) => config,
        Err(_) => {
            return Ok(Response::failure(
                operation,
                ErrorCode::Internal,
                crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
            ));
        }
    };
    let engine_state = match ManagedRoot::open(&config.state_root) {
        Ok(root) => root,
        Err(_) => {
            return Ok(Response::failure(
                operation,
                ErrorCode::Internal,
                "engine state root is unavailable",
            ));
        }
    };
    let Ok(stack_dir) = compose::compose_base_dir() else {
        return Ok(Response::failure(
            operation,
            ErrorCode::Internal,
            "stack directory is unavailable",
        ));
    };
    let context = stack_service::Context {
        engine_state: &engine_state,
        runtime_root: &config.runtime_root,
        site_services_root: &config.site_services_root,
        stack_dir: &stack_dir,
        docker: "docker",
        health: stack_service::HealthWait::PRODUCTION,
    };
    match run(&context, &CancellationToken::default()) {
        Ok(result) => Response::success(operation, result),
        Err(stack_service::Error::PostCommit(result)) => {
            Response::success(operation, result).map(|response| {
                response.with_warnings(vec![Warning {
                    code: WarningCode::TransactionRecordIncomplete,
                    message: "the operation completed but its transaction record could not be \
                              saved"
                        .to_owned(),
                }])
            })
        }
        Err(error) => {
            let (code, message) = error.protocol();
            Ok(Response::failure(operation, code, &message))
        }
    }
}

#[cfg(not(unix))]
fn run_service_operation<T, F>(
    operation: &'static str,
    _run: F,
) -> Result<Response, ResponseBuildError>
where
    F: FnOnce(
        &crate::stack_service::Context<'_>,
        &crate::process::CancellationToken,
    ) -> Result<T, crate::stack_service::Error>,
{
    Ok(Response::failure(
        operation,
        ErrorCode::UnsupportedPlatform,
        "stack service operations require a Unix host",
    ))
}

#[cfg(unix)]
fn deploy(
    request_file: &std::path::Path,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    use crate::{
        commands::{ContentFileError, read_root_owned_content_file},
        config::EngineConfig,
        error::WarningCode,
        filesystem::ManagedRoot,
        process::CancellationToken,
        protocol::Warning,
        stack_deploy::{self, Context, Error, Request, Timing},
    };

    let config = match EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) {
        Ok(config) => config,
        Err(_) => {
            return Ok(Response::failure(
                OPERATION,
                ErrorCode::Internal,
                crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
            ));
        }
    };
    let request_json = match read_root_owned_content_file(request_file) {
        Ok(content) => content,
        Err(ContentFileError::TooLarge) => {
            return Ok(Response::failure(
                OPERATION,
                ErrorCode::InvalidInput,
                "request-file exceeds the maximum allowed size",
            ));
        }
        Err(ContentFileError::Unreadable) => {
            return Ok(Response::failure(
                OPERATION,
                ErrorCode::InvalidInput,
                "request-file must be a root-owned file that is not group/world-writable",
            ));
        }
    };
    let request = match Request::parse(&request_json, request_id, idempotency_key) {
        Ok(request) => request,
        Err(error) => {
            return Ok(Response::failure(
                OPERATION,
                ErrorCode::InvalidInput,
                error.message(),
            ));
        }
    };
    if !cfg!(target_os = "linux") {
        return Ok(Response::failure(
            OPERATION,
            ErrorCode::UnsupportedPlatform,
            "stack deploy requires a Linux host",
        ));
    }
    let engine_state = match ManagedRoot::open(&config.state_root) {
        Ok(root) => root,
        Err(_) => {
            return Ok(Response::failure(
                OPERATION,
                ErrorCode::Internal,
                "engine state root is unavailable",
            ));
        }
    };
    let Some((stack_root, owner)) = prepare_stack_root() else {
        return Ok(Response::failure(
            OPERATION,
            ErrorCode::Internal,
            "stack directory is unavailable",
        ));
    };
    let context = Context {
        engine_state: &engine_state,
        stack_root: &stack_root,
        docker: "docker",
        timing: Timing::PRODUCTION,
        owner,
    };
    match stack_deploy::execute(&context, &request, &CancellationToken::default()) {
        Ok(result) => Response::success(OPERATION, result),
        Err(Error::PostCommit { result }) => Response::success(OPERATION, result).map(|response| {
            response.with_warnings(vec![Warning {
                code: WarningCode::TransactionRecordIncomplete,
                message: "the stack was deployed but its transaction record could not be \
                              saved"
                    .to_owned(),
            }])
        }),
        Err(error) => {
            let (code, message) = error.protocol();
            Ok(Response::failure(OPERATION, code, &message))
        }
    }
}

/// Creates `~/compose/wp-stack` inside the invoking account's home and
/// returns it with that home's owner, which the stack files keep - the same
/// ownership they had when the control panel wrote them over SSH. A
/// root-owned home means root-owned files, as before. Both directories are
/// created and re-owned through a capability on the home directory, so a
/// symlink cannot point the change elsewhere.
#[cfg(unix)]
fn prepare_stack_root() -> Option<(crate::site::TrustedRoot, Option<(u32, u32)>)> {
    use std::os::unix::fs::MetadataExt;

    use crate::{
        compose,
        filesystem::ManagedRoot,
        site::{SiteRelativePath, TrustedRoot},
    };

    let stack_dir = compose::compose_base_dir().ok()?;
    let home = stack_dir.parent()?.parent()?;
    let home_root = TrustedRoot::parse(home).ok()?;
    let home_dir = ManagedRoot::open(&home_root).ok()?;
    let metadata = std::fs::metadata(home).ok()?;
    let owner = (metadata.uid() != 0).then(|| (metadata.uid(), metadata.gid()));
    for relative in ["compose", "compose/wp-stack"] {
        let relative = SiteRelativePath::parse(relative).ok()?;
        home_dir.create_dir_all(&relative).ok()?;
        if let Some((uid, gid)) = owner {
            home_dir.chown(&relative, uid, gid).ok()?;
        }
    }
    Some((TrustedRoot::parse(stack_dir).ok()?, owner))
}

#[cfg(not(unix))]
fn deploy(
    _request_file: &std::path::Path,
    _request_id: &str,
    _idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    Ok(Response::failure(
        OPERATION,
        ErrorCode::UnsupportedPlatform,
        "stack deploy requires a Linux host",
    ))
}
