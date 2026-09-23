use crate::{
    cli::WordpressCommand,
    commands::read_root_owned_content_file,
    error::ErrorCode,
    protocol::{Response, ResponseBuildError},
    wordpress, wordpress_clone, wordpress_install, wordpress_update,
};

pub fn run(command: WordpressCommand) -> Result<Response, ResponseBuildError> {
    match command {
        WordpressCommand::Cleanup { request_file } => cleanup(&request_file),
        WordpressCommand::Install {
            request_file,
            request_id,
            idempotency_key,
        } => install(&request_file, &request_id, idempotency_key.as_deref()),
        WordpressCommand::Clone {
            request_file,
            request_id,
            idempotency_key,
        } => clone(&request_file, &request_id, idempotency_key.as_deref()),
        WordpressCommand::UpdateCore {
            request_file,
            request_id,
            idempotency_key,
        } => update_core(&request_file, &request_id, idempotency_key.as_deref()),
        WordpressCommand::UpdatePlugins {
            request_file,
            request_id,
            idempotency_key,
        } => update_plugins(&request_file, &request_id, idempotency_key.as_deref()),
        WordpressCommand::UpdateThemes {
            request_file,
            request_id,
            idempotency_key,
        } => update_themes(&request_file, &request_id, idempotency_key.as_deref()),
    }
}

fn update_themes(
    path: &std::path::Path,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    update(path, request_id, key, false, true)
}

fn update_plugins(
    path: &std::path::Path,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    update(path, request_id, key, true, false)
}

fn update_core(
    path: &std::path::Path,
    request_id: &str,
    key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    update(path, request_id, key, false, false)
}

fn update(
    path: &std::path::Path,
    request_id: &str,
    key: Option<&str>,
    plugins: bool,
    themes: bool,
) -> Result<Response, ResponseBuildError> {
    let operation = if plugins {
        wordpress_update::PLUGINS_OPERATION
    } else if themes {
        wordpress_update::THEMES_OPERATION
    } else {
        wordpress_update::OPERATION
    };
    #[cfg(unix)]
    {
        use crate::{backup_delete::BACKUP_ROOT, filesystem::ManagedRoot, site::TrustedRoot};
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
        let parsed = if plugins {
            wordpress_update::Request::parse_plugins(&json, request_id, key)
        } else if themes {
            wordpress_update::Request::parse_themes(&json, request_id, key)
        } else {
            wordpress_update::Request::parse(&json, request_id, key)
        };
        let request = match parsed {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    operation,
                    ErrorCode::InvalidInput,
                    "request-file is not a valid WordPress core update plan",
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
                "WordPress root is outside configured content roots",
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
        if std::fs::create_dir_all(BACKUP_ROOT).is_err() {
            return Ok(Response::failure(
                operation,
                ErrorCode::Internal,
                "backup root is unavailable",
            ));
        }
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
        let context = wordpress_update::Context {
            engine_state: &state,
            backup_root: &backups,
            docker_program: "docker",
            tar_program: "tar",
        };
        match wordpress_update::execute(
            &context,
            &request,
            &crate::process::CancellationToken::default(),
        ) {
            Ok(v) | Err(wordpress_update::Error::PostCommit { result: v }) => {
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
        let _ = (path, request_id, key, plugins, themes);
        Ok(Response::failure(
            operation,
            ErrorCode::UnsupportedPlatform,
            "wordpress.updateCore requires a Unix host",
        ))
    }
}

fn install(
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
                    wordpress_install::OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress_install::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match wordpress_install::Request::parse(&json, request_id, idempotency_key) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress_install::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file is not a valid WordPress install plan",
                ));
            }
        };
        let content_root = match config
            .content_roots
            .iter()
            .find(|root| request.root().starts_with(root.as_path()))
        {
            Some(v) => v,
            None => {
                return Ok(Response::failure(
                    wordpress_install::OPERATION,
                    ErrorCode::InvalidInput,
                    "WordPress root is outside configured content roots",
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress_install::OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        let context = wordpress_install::Context {
            engine_state: &state,
            docker_program: "docker",
        };
        match wordpress_install::execute(
            &context,
            content_root,
            &request,
            &crate::process::CancellationToken::default(),
        ) {
            Ok(v) | Err(wordpress_install::Error::PostCommit { result: v }) => {
                Response::success(wordpress_install::OPERATION, v)
            }
            Err(e) => {
                let (code, message) = e.protocol();
                Ok(Response::failure(
                    wordpress_install::OPERATION,
                    code,
                    &message,
                ))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, idempotency_key);
        Ok(Response::failure(
            wordpress_install::OPERATION,
            ErrorCode::UnsupportedPlatform,
            "wordpress.install requires a Unix host",
        ))
    }
}

fn clone(
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
                    wordpress_clone::OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress_clone::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match wordpress_clone::Request::parse(&json, request_id, idempotency_key) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress_clone::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file is not a valid WordPress clone plan",
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
                    wordpress_clone::OPERATION,
                    ErrorCode::InvalidInput,
                    "WordPress source root is outside configured content roots",
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
                    wordpress_clone::OPERATION,
                    ErrorCode::InvalidInput,
                    "WordPress staging root is outside configured content roots",
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress_clone::OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        if std::fs::create_dir_all(BACKUP_ROOT).is_err() {
            return Ok(Response::failure(
                wordpress_clone::OPERATION,
                ErrorCode::Internal,
                "backup root is unavailable",
            ));
        }
        let dump_root = match TrustedRoot::parse(std::path::Path::new(BACKUP_ROOT)) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress_clone::OPERATION,
                    ErrorCode::Internal,
                    "backup root is unavailable",
                ));
            }
        };
        let dump_managed = match ManagedRoot::open(&dump_root) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress_clone::OPERATION,
                    ErrorCode::Internal,
                    "backup root is unavailable",
                ));
            }
        };
        let context = wordpress_clone::Context {
            engine_state: &state,
            dump_managed: &dump_managed,
            dump_root: &dump_root,
            docker_program: "docker",
            cp_program: "cp",
        };
        match wordpress_clone::execute(
            &context,
            source_content_root,
            staging_content_root,
            &request,
            &crate::process::CancellationToken::default(),
        ) {
            Ok(v) | Err(wordpress_clone::Error::PostCommit { result: v }) => {
                Response::success(wordpress_clone::OPERATION, v)
            }
            Err(e) => {
                let (code, message) = e.protocol();
                Ok(Response::failure(
                    wordpress_clone::OPERATION,
                    code,
                    &message,
                ))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, idempotency_key);
        Ok(Response::failure(
            wordpress_clone::OPERATION,
            ErrorCode::UnsupportedPlatform,
            "wordpress.clone requires a Unix host",
        ))
    }
}

fn cleanup(path: &std::path::Path) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        let config = match crate::config::EngineConfig::load_root_owned(std::path::Path::new(
            "/etc/operations-engine/config.json",
        )) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress::OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match wordpress::Request::parse(&json) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file is not a valid WordPress cleanup plan",
                ));
            }
        };
        if !config
            .content_roots
            .iter()
            .any(|root| request.root().starts_with(root.as_path()))
        {
            return Ok(Response::failure(
                wordpress::OPERATION,
                ErrorCode::InvalidInput,
                "WordPress root is outside configured content roots",
            ));
        }
        match wordpress::execute(&request, "docker") {
            Ok(value) => Response::success(wordpress::OPERATION, value),
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(wordpress::OPERATION, code, message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(Response::failure(
            wordpress::OPERATION,
            ErrorCode::UnsupportedPlatform,
            "wordpress.cleanup requires a Unix host",
        ))
    }
}
