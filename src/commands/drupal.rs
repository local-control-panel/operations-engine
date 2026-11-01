use crate::{
    cli::DrupalCommand,
    commands::read_root_owned_content_file,
    drupal_action, drupal_clone,
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
        DrupalCommand::AutomatedCron {
            request_file,
            request_id,
            idempotency_key,
        } => action(
            "automated-cron",
            drupal_action::AUTOMATED_CRON,
            &request_file,
            &request_id,
            idempotency_key.as_deref(),
        ),
        DrupalCommand::InstallDrush {
            request_file,
            request_id,
            idempotency_key,
        } => action(
            "install-drush",
            drupal_action::INSTALL_DRUSH,
            &request_file,
            &request_id,
            idempotency_key.as_deref(),
        ),
        DrupalCommand::UpdateDb {
            request_file,
            request_id,
            idempotency_key,
        } => action(
            "update-db",
            drupal_action::UPDATE_DB,
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
        DrupalCommand::Watchdog { request_file } => watchdog(&request_file),
        DrupalCommand::Clone {
            request_file,
            request_id,
            idempotency_key,
        } => clone_site(&request_file, &request_id, idempotency_key.as_deref()),
    }
}

fn watchdog(path: &std::path::Path) -> Result<Response, ResponseBuildError> {
    use crate::drupal_watchdog::{self as wd, OPERATION};
    #[cfg(unix)]
    {
        let config = match crate::config::EngineConfig::load_root_owned(std::path::Path::new(
            "/etc/operations-engine/config.json",
        )) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match wd::Request::parse(&json) {
            Ok(v) => v,
            Err(error) => {
                return Ok(Response::failure(
                    OPERATION,
                    ErrorCode::InvalidInput,
                    error.message(),
                ));
            }
        };
        if !config
            .content_roots
            .iter()
            .any(|root| request.root().starts_with(root.as_path()))
        {
            return Ok(Response::failure(
                OPERATION,
                ErrorCode::InvalidInput,
                "Drupal root is outside configured content roots",
            ));
        }
        let context = wd::Context {
            docker_program: "docker",
        };
        match wd::read(
            &context,
            &request,
            &crate::process::CancellationToken::default(),
        ) {
            Ok(value) => Response::success(OPERATION, value),
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(OPERATION, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(Response::failure(
            OPERATION,
            ErrorCode::UnsupportedPlatform,
            "Drupal actions require a Unix host",
        ))
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
        use crate::{backup_delete::BACKUP_ROOT, site::TrustedRoot};
        // Only `updateDb` writes here (its pre-update dump); the others
        // never touch it, so a missing root only matters for that one.
        let _ = std::fs::create_dir_all(BACKUP_ROOT);
        let backups = match TrustedRoot::parse(std::path::Path::new(BACKUP_ROOT)).and_then(|root| {
            ManagedRoot::open(&root).map_err(|_| crate::site::ValidationError::PathResolutionFailed)
        }) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    operation,
                    ErrorCode::Internal,
                    "backup root is unavailable",
                ));
            }
        };
        let context = drupal_action::Context {
            engine_state: &state,
            docker_program: "docker",
            tools_dir: std::path::Path::new(crate::tool_manage::TOOLS_DIR),
            backup_root: &backups,
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

fn clone_site(
    path: &std::path::Path,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{backup_delete::BACKUP_ROOT, filesystem::ManagedRoot, site::TrustedRoot};
        let config = match crate::config::EngineConfig::load_root_owned(std::path::Path::new(
            "/etc/operations-engine/config.json",
        )) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    drupal_clone::OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    drupal_clone::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match drupal_clone::Request::parse(&json, request_id, idempotency_key) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    drupal_clone::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file is not a valid Drupal clone plan",
                ));
            }
        };
        let source_content_root = match config
            .content_roots
            .iter()
            .find(|root| request.source_root().starts_with(root.as_path()))
        {
            Some(v) => v,
            None => {
                return Ok(Response::failure(
                    drupal_clone::OPERATION,
                    ErrorCode::InvalidInput,
                    "Drupal source root is outside configured content roots",
                ));
            }
        };
        let staging_content_root = match config
            .content_roots
            .iter()
            .find(|root| request.staging_root().starts_with(root.as_path()))
        {
            Some(v) => v,
            None => {
                return Ok(Response::failure(
                    drupal_clone::OPERATION,
                    ErrorCode::InvalidInput,
                    "Drupal staging root is outside configured content roots",
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    drupal_clone::OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        if std::fs::create_dir_all(BACKUP_ROOT).is_err() {
            return Ok(Response::failure(
                drupal_clone::OPERATION,
                ErrorCode::Internal,
                "backup root is unavailable",
            ));
        }
        let dump_root = match TrustedRoot::parse(std::path::Path::new(BACKUP_ROOT)) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    drupal_clone::OPERATION,
                    ErrorCode::Internal,
                    "backup root is unavailable",
                ));
            }
        };
        let dump_managed = match ManagedRoot::open(&dump_root) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    drupal_clone::OPERATION,
                    ErrorCode::Internal,
                    "backup root is unavailable",
                ));
            }
        };
        let context = drupal_clone::Context {
            engine_state: &state,
            dump_managed: &dump_managed,
            dump_root: &dump_root,
            docker_program: "docker",
            cp_program: "cp",
        };
        match drupal_clone::execute(
            &context,
            source_content_root,
            staging_content_root,
            &request,
            &crate::process::CancellationToken::default(),
        ) {
            Ok(v) | Err(drupal_clone::Error::PostCommit { result: v }) => {
                Response::success(drupal_clone::OPERATION, v)
            }
            Err(e) => {
                let (code, message) = e.protocol();
                Ok(Response::failure(drupal_clone::OPERATION, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, idempotency_key);
        Ok(Response::failure(
            drupal_clone::OPERATION,
            ErrorCode::UnsupportedPlatform,
            "drupal.clone requires a Unix host",
        ))
    }
}
