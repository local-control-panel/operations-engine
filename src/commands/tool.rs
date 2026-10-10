use crate::{
    cli::ToolCommand,
    error::ErrorCode,
    protocol::{Response, ResponseBuildError},
    tool_manage,
};

pub fn run(command: ToolCommand) -> Result<Response, ResponseBuildError> {
    match command {
        ToolCommand::Install {
            tool,
            request_id,
            idempotency_key,
        } => mutate(
            tool_manage::INSTALL,
            tool_manage::Action::Install,
            &tool,
            &request_id,
            idempotency_key.as_deref(),
        ),
        ToolCommand::Remove {
            tool,
            request_id,
            idempotency_key,
        } => mutate(
            tool_manage::REMOVE,
            tool_manage::Action::Remove,
            &tool,
            &request_id,
            idempotency_key.as_deref(),
        ),
        ToolCommand::Status => status(),
    }
}

/// Opens the engine state root and the tools directory (created root-owned
/// 0755 when missing) and hands both to `f`.
#[cfg(unix)]
fn with_roots<T>(
    operation: &'static str,
    f: impl FnOnce(&crate::filesystem::ManagedRoot, &crate::filesystem::ManagedRoot) -> T,
) -> Result<T, Response> {
    use crate::{config::EngineConfig, filesystem::ManagedRoot, site::TrustedRoot};
    let fail = |code, message: &str| Response::failure(operation, code, message);
    let config =
        EngineConfig::load_root_owned(std::path::Path::new("/etc/operations-engine/config.json"))
            .map_err(|_| {
            fail(
                ErrorCode::Internal,
                crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
            )
        })?;
    let state = ManagedRoot::open(&config.state_root)
        .map_err(|_| fail(ErrorCode::Internal, "engine state root is unavailable"))?;
    let tools_path = std::path::Path::new(tool_manage::TOOLS_DIR);
    std::fs::create_dir_all(tools_path)
        .map_err(|_| fail(ErrorCode::Internal, "the tools directory is unavailable"))?;
    let tools = TrustedRoot::parse(tools_path)
        .ok()
        .and_then(|root| ManagedRoot::open(&root).ok())
        .ok_or_else(|| fail(ErrorCode::Internal, "the tools directory is unavailable"))?;
    Ok(f(&state, &tools))
}

fn mutate(
    operation: &'static str,
    action: tool_manage::Action,
    tool: &str,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        let request = match tool_manage::Request::parse(tool, request_id, key) {
            Ok(value) => value,
            Err(tool_manage::RequestError::UnknownTool) => {
                return Ok(Response::failure(
                    operation,
                    ErrorCode::InvalidInput,
                    "unknown tool",
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
        let fetch = |url: &str| {
            crate::engine::fetch::fetch_bytes_bounded(
                url,
                tool_manage::MAX_ARTIFACT_BYTES,
                tool_manage::FETCH_TIMEOUT,
            )
        };
        let outcome = with_roots(operation, |state, tools| {
            tool_manage::execute(
                &tool_manage::Context {
                    engine_state: state,
                    tools_root: tools,
                    catalog: &tool_manage::Tool::pinned,
                    fetch: &fetch,
                },
                action,
                &request,
                &crate::process::CancellationToken::default(),
            )
        });
        match outcome {
            Err(response) => Ok(response),
            Ok(Ok(value)) | Ok(Err(tool_manage::Error::PostCommit { result: value })) => {
                Response::success(operation, value)
            }
            Ok(Err(error)) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(operation, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (action, tool, request_id, key);
        Ok(Response::failure(
            operation,
            ErrorCode::UnsupportedPlatform,
            "tool operations require a Unix host",
        ))
    }
}

fn status() -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        let fetch = |_: &str| Err(crate::engine::fetch::Error::Timeout);
        let report = with_roots(tool_manage::STATUS, |state, tools| {
            tool_manage::status(
                &tool_manage::Context {
                    engine_state: state,
                    tools_root: tools,
                    catalog: &tool_manage::Tool::pinned,
                    fetch: &fetch,
                },
                tool_manage::TOOLS_DIR,
            )
        });
        match report {
            Ok(value) => Response::success(tool_manage::STATUS, value),
            Err(response) => Ok(response),
        }
    }
    #[cfg(not(unix))]
    {
        Ok(Response::failure(
            tool_manage::STATUS,
            ErrorCode::UnsupportedPlatform,
            "tool operations require a Unix host",
        ))
    }
}
