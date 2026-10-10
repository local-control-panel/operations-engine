use crate::{
    cli::DrupalCommand,
    commands::read_root_owned_content_file,
    drupal_action,
    error::ErrorCode,
    protocol::{Response, ResponseBuildError},
};

pub fn run(command: DrupalCommand) -> Result<Response, ResponseBuildError> {
    match command {
        DrupalCommand::CacheRebuild {
            request_file,
            request_id,
            idempotency_key,
        } => action(
            "cache-rebuild",
            drupal_action::CACHE_REBUILD,
            &request_file,
            &request_id,
            idempotency_key.as_deref(),
        ),
        DrupalCommand::CronRun {
            request_file,
            request_id,
            idempotency_key,
        } => action(
            "cron-run",
            drupal_action::CRON_RUN,
            &request_file,
            &request_id,
            idempotency_key.as_deref(),
        ),
        DrupalCommand::Maintenance {
            request_file,
            request_id,
            idempotency_key,
        } => action(
            "maintenance",
            drupal_action::MAINTENANCE,
            &request_file,
            &request_id,
            idempotency_key.as_deref(),
        ),
    }
}

fn action(
    kind: &str,
    operation: &'static str,
    path: &std::path::Path,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::filesystem::ManagedRoot;
        let config = match crate::config::EngineConfig::load_root_owned(std::path::Path::new(
            "/etc/operations-engine/config.json",
        )) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    operation,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    operation,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match drupal_action::Request::parse(kind, &json, request_id, idempotency_key)
        {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    operation,
                    ErrorCode::InvalidInput,
                    "request-file is not a valid Drupal action plan",
                ));
            }
        };
        if !config
            .content_roots
            .iter()
            .any(|root| request.root().starts_with(root.as_path()))
        {
            return Ok(Response::failure(
                operation,
                ErrorCode::InvalidInput,
                "Drupal root is outside configured content roots",
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
        let context = drupal_action::Context {
            engine_state: &state,
            docker_program: "docker",
        };
        match drupal_action::execute(
            &context,
            &request,
            &crate::process::CancellationToken::default(),
        ) {
            Ok(v) | Err(drupal_action::Error::PostCommit { result: v }) => {
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
        let _ = (kind, path, request_id, idempotency_key);
        Ok(Response::failure(
            operation,
            ErrorCode::UnsupportedPlatform,
            "Drupal actions require a Unix host",
        ))
    }
}
