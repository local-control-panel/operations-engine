use crate::{
    cli::JoomlaCommand,
    commands::read_root_owned_content_file,
    error::ErrorCode,
    joomla_clone,
    protocol::{Response, ResponseBuildError},
};

pub fn run(command: JoomlaCommand) -> Result<Response, ResponseBuildError> {
    match command {
        JoomlaCommand::Clone {
            request_file,
            request_id,
            idempotency_key,
        } => clone_site(&request_file, &request_id, idempotency_key.as_deref()),
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
                    joomla_clone::OPERATION,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    joomla_clone::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match joomla_clone::Request::parse(&json, request_id, idempotency_key) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    joomla_clone::OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file is not a valid Joomla clone plan",
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
                    joomla_clone::OPERATION,
                    ErrorCode::InvalidInput,
                    "Joomla source root is outside configured content roots",
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
                    joomla_clone::OPERATION,
                    ErrorCode::InvalidInput,
                    "Joomla staging root is outside configured content roots",
                ));
            }
        };
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    joomla_clone::OPERATION,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        if std::fs::create_dir_all(BACKUP_ROOT).is_err() {
            return Ok(Response::failure(
                joomla_clone::OPERATION,
                ErrorCode::Internal,
                "backup root is unavailable",
            ));
        }
        let dump_root = match TrustedRoot::parse(std::path::Path::new(BACKUP_ROOT)) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    joomla_clone::OPERATION,
                    ErrorCode::Internal,
                    "backup root is unavailable",
                ));
            }
        };
        let dump_managed = match ManagedRoot::open(&dump_root) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    joomla_clone::OPERATION,
                    ErrorCode::Internal,
                    "backup root is unavailable",
                ));
            }
        };
        let context = joomla_clone::Context {
            engine_state: &state,
            dump_managed: &dump_managed,
            dump_root: &dump_root,
            docker_program: "docker",
            cp_program: "cp",
        };
        match joomla_clone::execute(
            &context,
            source_content_root,
            staging_content_root,
            &request,
            &crate::process::CancellationToken::default(),
        ) {
            Ok(v) | Err(joomla_clone::Error::PostCommit { result: v }) => {
                Response::success(joomla_clone::OPERATION, v)
            }
            Err(e) => {
                let (code, message) = e.protocol();
                Ok(Response::failure(joomla_clone::OPERATION, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, idempotency_key);
        Ok(Response::failure(
            joomla_clone::OPERATION,
            ErrorCode::UnsupportedPlatform,
            "joomla.clone requires a Unix host",
        ))
    }
}
