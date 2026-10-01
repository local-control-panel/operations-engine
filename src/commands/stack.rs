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
    }
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
