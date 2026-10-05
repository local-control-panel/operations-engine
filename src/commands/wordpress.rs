use crate::{
    cli::WordpressCommand,
    commands::read_root_owned_content_file,
    error::ErrorCode,
    protocol::{Response, ResponseBuildError},
    wordpress, wordpress_bounded_action, wordpress_clone, wordpress_import, wordpress_install,
    wordpress_multisite_delete_site, wordpress_rotate_credentials, wordpress_smtp_relay,
    wordpress_update,
};

pub fn run(command: WordpressCommand) -> Result<Response, ResponseBuildError> {
    match command {
        WordpressCommand::Import {
            request_file,
            request_id,
            idempotency_key,
        } => import(&request_file, &request_id, idempotency_key.as_deref()),
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
        WordpressCommand::MigrateExport {
            request_file,
            request_id,
            idempotency_key,
        } => migrate_export(&request_file, &request_id, idempotency_key.as_deref()),
        WordpressCommand::MigrateImport {
            request_file,
            request_id,
            idempotency_key,
        } => migrate_import(&request_file, &request_id, idempotency_key.as_deref()),
        WordpressCommand::MigrateDiscard {
            export_id,
            request_id,
        } => migrate_discard(&export_id, &request_id),
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
        WordpressCommand::RotateCredentials {
            request_file,
            request_id,
            idempotency_key,
        } => rotate_credentials(&request_file, &request_id, idempotency_key.as_deref()),
        WordpressCommand::MultisiteDeleteSite {
            request_file,
            request_id,
            idempotency_key,
        } => multisite_delete_site(&request_file, &request_id, idempotency_key.as_deref()),
        WordpressCommand::BoundedAction {
            request_file,
            request_id,
            idempotency_key,
        } => bounded_action(&request_file, &request_id, idempotency_key.as_deref()),
        WordpressCommand::SetSmtpRelay {
            request_file,
            request_id,
            idempotency_key,
        } => set_smtp_relay(&request_file, &request_id, idempotency_key.as_deref()),
    }
}

fn import(
    path: &std::path::Path,
    request_id: &str,
    key: Option<&str>,
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
                    wordpress_import::OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress_import::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match wordpress_import::Request::parse(&json, request_id, key) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress_import::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file is not a valid WordPress import plan",
                ));
            }
        };
        if !config
            .content_roots
            .iter()
            .any(|root| request.root().starts_with(root.as_path()))
        {
            return Ok(Response::failure(
                wordpress_import::OPERATION,
                ErrorCode::InvalidInput,
                "WordPress root is outside configured content roots",
            ));
        }
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress_import::OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        let context = wordpress_import::Context {
            engine_state: &state,
            artifact_dir: std::path::Path::new("/etc/operations-engine/staging"),
            artifact_owner_uid: 0,
            docker_program: "docker",
        };
        match wordpress_import::execute(
            &context,
            &request,
            &crate::process::CancellationToken::default(),
        ) {
            Ok(v) | Err(wordpress_import::Error::PostCommit { result: v }) => {
                Response::success(wordpress_import::OPERATION, v)
            }
            Err(e) => {
                let (code, message) = e.protocol();
                Ok(Response::failure(
                    wordpress_import::OPERATION,
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
            wordpress_import::OPERATION,
            ErrorCode::UnsupportedPlatform,
            "wordpress.import requires a Unix host",
        ))
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

fn rotate_credentials(
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
                    wordpress_rotate_credentials::OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress_rotate_credentials::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match wordpress_rotate_credentials::Request::parse(
            &json,
            request_id,
            idempotency_key,
        ) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress_rotate_credentials::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file is not a valid WordPress credential rotation plan",
                ));
            }
        };
        if !config
            .content_roots
            .iter()
            .any(|root| request.root().starts_with(root.as_path()))
        {
            return Ok(Response::failure(
                wordpress_rotate_credentials::OPERATION,
                ErrorCode::InvalidInput,
                "WordPress root is outside configured content roots",
            ));
        }
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress_rotate_credentials::OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        let context = wordpress_rotate_credentials::Context {
            engine_state: &state,
            docker_program: "docker",
        };
        match wordpress_rotate_credentials::execute(
            &context,
            &request,
            &crate::process::CancellationToken::default(),
        ) {
            Ok(v) | Err(wordpress_rotate_credentials::Error::PostCommit { result: v }) => {
                Response::success(wordpress_rotate_credentials::OPERATION, v)
            }
            Err(e) => {
                let (code, message) = e.protocol();
                Ok(Response::failure(
                    wordpress_rotate_credentials::OPERATION,
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
            wordpress_rotate_credentials::OPERATION,
            ErrorCode::UnsupportedPlatform,
            "wordpress.rotateCredentials requires a Unix host",
        ))
    }
}

fn multisite_delete_site(
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
                    wordpress_multisite_delete_site::OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress_multisite_delete_site::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match wordpress_multisite_delete_site::Request::parse(
            &json,
            request_id,
            idempotency_key,
        ) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress_multisite_delete_site::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file is not a valid multisite delete-site plan",
                ));
            }
        };
        if !config
            .content_roots
            .iter()
            .any(|root| request.root().starts_with(root.as_path()))
        {
            return Ok(Response::failure(
                wordpress_multisite_delete_site::OPERATION,
                ErrorCode::InvalidInput,
                "WordPress root is outside configured content roots",
            ));
        }
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress_multisite_delete_site::OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        let context = wordpress_multisite_delete_site::Context {
            engine_state: &state,
            docker_program: "docker",
        };
        match wordpress_multisite_delete_site::execute(
            &context,
            &request,
            &crate::process::CancellationToken::default(),
        ) {
            Ok(v) | Err(wordpress_multisite_delete_site::Error::PostCommit { result: v }) => {
                Response::success(wordpress_multisite_delete_site::OPERATION, v)
            }
            Err(e) => {
                let (code, message) = e.protocol();
                Ok(Response::failure(
                    wordpress_multisite_delete_site::OPERATION,
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
            wordpress_multisite_delete_site::OPERATION,
            ErrorCode::UnsupportedPlatform,
            "wordpress.multisiteDeleteSite requires a Unix host",
        ))
    }
}

fn bounded_action(
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
                    wordpress_bounded_action::OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress_bounded_action::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request =
            match wordpress_bounded_action::Request::parse(&json, request_id, idempotency_key) {
                Ok(v) => v,
                Err(_) => {
                    return Ok(Response::failure(
                        wordpress_bounded_action::OPERATION,
                        ErrorCode::InvalidInput,
                        "request-file is not a valid bounded WordPress action plan",
                    ));
                }
            };
        if !config
            .content_roots
            .iter()
            .any(|root| request.root().starts_with(root.as_path()))
        {
            return Ok(Response::failure(
                wordpress_bounded_action::OPERATION,
                ErrorCode::InvalidInput,
                "WordPress root is outside configured content roots",
            ));
        }
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress_bounded_action::OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        let context = wordpress_bounded_action::Context {
            engine_state: &state,
            docker_program: "docker",
        };
        match wordpress_bounded_action::execute(
            &context,
            &request,
            &crate::process::CancellationToken::default(),
        ) {
            Ok(v) | Err(wordpress_bounded_action::Error::PostCommit { result: v }) => {
                Response::success(wordpress_bounded_action::OPERATION, v)
            }
            Err(e) => {
                let (code, message) = e.protocol();
                Ok(Response::failure(
                    wordpress_bounded_action::OPERATION,
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
            wordpress_bounded_action::OPERATION,
            ErrorCode::UnsupportedPlatform,
            "wordpress.boundedAction requires a Unix host",
        ))
    }
}

fn set_smtp_relay(
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
                    wordpress_smtp_relay::OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress_smtp_relay::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match wordpress_smtp_relay::Request::parse(&json, request_id, idempotency_key)
        {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress_smtp_relay::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file is not a valid SMTP relay plan",
                ));
            }
        };
        if !config
            .content_roots
            .iter()
            .any(|root| request.root().starts_with(root.as_path()))
        {
            return Ok(Response::failure(
                wordpress_smtp_relay::OPERATION,
                ErrorCode::InvalidInput,
                "WordPress root is outside configured content roots",
            ));
        }
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    wordpress_smtp_relay::OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        let context = wordpress_smtp_relay::Context {
            engine_state: &state,
            docker_program: "docker",
        };
        match wordpress_smtp_relay::execute(
            &context,
            &request,
            &crate::process::CancellationToken::default(),
        ) {
            Ok(v) | Err(wordpress_smtp_relay::Error::PostCommit { result: v }) => {
                Response::success(wordpress_smtp_relay::OPERATION, v)
            }
            Err(e) => {
                let (code, message) = e.protocol();
                Ok(Response::failure(
                    wordpress_smtp_relay::OPERATION,
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
            wordpress_smtp_relay::OPERATION,
            ErrorCode::UnsupportedPlatform,
            "wordpress.setSmtpRelay requires a Unix host",
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

fn migrate_export(
    path: &std::path::Path,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    use crate::wordpress_migrate_export::{self as export, EXPORT_OPERATION};
    #[cfg(unix)]
    {
        use crate::filesystem::ManagedRoot;
        let fail = |code, message: &str| Ok(Response::failure(EXPORT_OPERATION, code, message));
        let Ok(config) = crate::config::EngineConfig::load_root_owned(std::path::Path::new(
            "/etc/operations-engine/config.json",
        )) else {
            return fail(
                ErrorCode::Internal,
                crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
            );
        };
        let Ok(json) = read_root_owned_content_file(path) else {
            return fail(
                ErrorCode::InvalidInput,
                "request-file must be a root-owned regular file",
            );
        };
        let Ok(request) = export::ExportRequest::parse(&json, request_id, idempotency_key) else {
            return fail(
                ErrorCode::InvalidInput,
                "request-file is not a valid WordPress migration export plan",
            );
        };
        let Some(content_root) = config
            .content_roots
            .iter()
            .find(|root| request.source_root().starts_with(root.as_path()))
        else {
            return fail(
                ErrorCode::InvalidInput,
                "WordPress source root is outside configured content roots",
            );
        };
        let Ok(state) = ManagedRoot::open(&config.state_root) else {
            return fail(ErrorCode::Internal, "engine state root is unavailable");
        };
        let context = export::Context {
            engine_state: &state,
            state_root: &config.state_root,
            content_root,
            docker_program: "docker",
            tar_program: "tar",
            gzip_program: "gzip",
        };
        match export::export(
            &context,
            &request,
            &crate::process::CancellationToken::default(),
        ) {
            Ok(result) => Response::success(EXPORT_OPERATION, result),
            Err(export::Error::PostCommit(result)) => Response::success(EXPORT_OPERATION, *result),
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(EXPORT_OPERATION, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, idempotency_key);
        Ok(Response::failure(
            EXPORT_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "wordpress.migrateExport requires a Unix host",
        ))
    }
}

fn migrate_discard(export_id: &str, request_id: &str) -> Result<Response, ResponseBuildError> {
    use crate::wordpress_migrate_export::{self as export, DISCARD_OPERATION};
    let Ok(request) = export::DiscardRequest::parse(export_id, request_id) else {
        return Ok(Response::failure(
            DISCARD_OPERATION,
            ErrorCode::InvalidInput,
            "export-id and request-id must be canonical UUIDs",
        ));
    };
    let Ok(config) = crate::config::EngineConfig::load_root_owned(std::path::Path::new(
        "/etc/operations-engine/config.json",
    )) else {
        return Ok(Response::failure(
            DISCARD_OPERATION,
            ErrorCode::Internal,
            crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
        ));
    };
    let Ok(state) = crate::filesystem::ManagedRoot::open(&config.state_root) else {
        return Ok(Response::failure(
            DISCARD_OPERATION,
            ErrorCode::Internal,
            "engine state root is unavailable",
        ));
    };
    match export::discard(&state, &request) {
        Ok(result) => Response::success(DISCARD_OPERATION, result),
        Err(error) => {
            let (code, message) = error.protocol();
            Ok(Response::failure(DISCARD_OPERATION, code, &message))
        }
    }
}

fn migrate_import(
    path: &std::path::Path,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    use crate::wordpress_migrate_import::{self as import, OPERATION};
    #[cfg(unix)]
    {
        use crate::{backup_delete::BACKUP_ROOT, filesystem::ManagedRoot, site::TrustedRoot};
        let fail = |code, message: &str| Ok(Response::failure(OPERATION, code, message));
        let Ok(config) = crate::config::EngineConfig::load_root_owned(std::path::Path::new(
            "/etc/operations-engine/config.json",
        )) else {
            return fail(
                ErrorCode::Internal,
                crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
            );
        };
        let Ok(json) = read_root_owned_content_file(path) else {
            return fail(
                ErrorCode::InvalidInput,
                "request-file must be a root-owned regular file",
            );
        };
        let Ok(request) = import::Request::parse(&json, request_id, idempotency_key) else {
            return fail(
                ErrorCode::InvalidInput,
                "request-file is not a valid WordPress migration import plan",
            );
        };
        let Some(content_root) = config
            .content_roots
            .iter()
            .find(|root| request.dest_root().starts_with(root.as_path()))
        else {
            return fail(
                ErrorCode::InvalidInput,
                "WordPress destination root is outside configured content roots",
            );
        };
        let Ok(state) = ManagedRoot::open(&config.state_root) else {
            return fail(ErrorCode::Internal, "engine state root is unavailable");
        };
        if std::fs::create_dir_all(BACKUP_ROOT).is_err() {
            return fail(ErrorCode::Internal, "backup root is unavailable");
        }
        let Ok(recovery_root) = TrustedRoot::parse(std::path::Path::new(BACKUP_ROOT)) else {
            return fail(ErrorCode::Internal, "backup root is unavailable");
        };
        let Ok(recovery_managed) = ManagedRoot::open(&recovery_root) else {
            return fail(ErrorCode::Internal, "backup root is unavailable");
        };
        let context = import::Context {
            engine_state: &state,
            content_root,
            recovery_managed: &recovery_managed,
            recovery_root: &recovery_root,
            artifact_dir: std::path::Path::new("/etc/operations-engine/staging"),
            artifact_owner_uid: 0,
            docker_program: "docker",
            gunzip_program: "gunzip",
        };
        match import::execute(
            &context,
            &request,
            &crate::process::CancellationToken::default(),
        ) {
            Ok(result) | Err(import::Error::PostCommit(result)) => {
                Response::success(OPERATION, result)
            }
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(OPERATION, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, idempotency_key);
        Ok(Response::failure(
            OPERATION,
            ErrorCode::UnsupportedPlatform,
            "wordpress.migrateImport requires a Unix host",
        ))
    }
}
