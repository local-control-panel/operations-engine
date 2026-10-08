use crate::{
    cli::SiteCommand,
    deploy::{
        DeployRequest, DeployRequestError,
        execute::{DeployContext, DeployError, execute as execute_deploy},
    },
    error::{ErrorCode, WarningCode},
    process::CancellationToken,
    protocol::{Response, ResponseBuildError, Warning},
    rollback::{
        RollbackRequest, RollbackRequestError,
        execute::{RollbackContext, RollbackError, execute as execute_rollback},
    },
};

pub fn run(command: SiteCommand) -> Result<Response, ResponseBuildError> {
    match command {
        SiteCommand::Deploy {
            site_id,
            revision,
            request_id,
            idempotency_key,
        } => deploy(&site_id, &revision, &request_id, idempotency_key.as_deref()),
        SiteCommand::Rollback {
            site_id,
            release,
            request_id,
            idempotency_key,
        } => rollback(&site_id, &release, &request_id, idempotency_key.as_deref()),
        SiteCommand::MoveRoot {
            from_domain,
            to_domain,
            request_id,
            idempotency_key,
        } => move_root(
            &from_domain,
            &to_domain,
            &request_id,
            idempotency_key.as_deref(),
        ),
        SiteCommand::PrepareRoot {
            domain,
            relative_root,
            uid,
            gid,
            existing,
            request_id,
            idempotency_key,
        } => prepare_root(
            &domain,
            relative_root.as_deref(),
            uid,
            gid,
            existing.as_deref(),
            &request_id,
            idempotency_key.as_deref(),
        ),
        SiteCommand::ExportArchive {
            request_file,
            request_id,
            idempotency_key,
        } => export_archive(&request_file, &request_id, idempotency_key.as_deref()),
        SiteCommand::ImportArchive {
            request_file,
            request_id,
            idempotency_key,
        } => import_archive(&request_file, &request_id, idempotency_key.as_deref()),
        SiteCommand::DiscardArchive {
            kind,
            archive_id,
            request_id,
        } => discard_archive(&kind, archive_id.as_deref(), &request_id),
        SiteCommand::WriteEnvFile {
            request_file,
            request_id,
            idempotency_key,
        } => write_env_file(&request_file, &request_id, idempotency_key.as_deref()),
        SiteCommand::PhpInfoSession {
            action,
            directory,
            ttl_minutes,
            request_id,
            idempotency_key,
        } => php_info_session(
            &action,
            &directory,
            ttl_minutes,
            &request_id,
            idempotency_key.as_deref(),
        ),
        SiteCommand::QuarantineFile {
            path,
            request_id,
            idempotency_key,
        } => quarantine_file(&path, &request_id, idempotency_key.as_deref()),
        SiteCommand::RemoveRoot {
            domain,
            relative_root,
            site_id,
            confirm_contents,
            request_id,
            idempotency_key,
        } => remove_root(
            &domain,
            relative_root.as_deref(),
            site_id.as_deref(),
            confirm_contents,
            &request_id,
            idempotency_key.as_deref(),
        ),
        SiteCommand::ReleaseRoot {
            domain,
            site_id,
            request_id,
            idempotency_key,
        } => release_root(
            &domain,
            site_id.as_deref(),
            &request_id,
            idempotency_key.as_deref(),
        ),
        SiteCommand::RenameManifest {
            site_id,
            domain,
            request_id,
            idempotency_key,
        } => rename_manifest(&site_id, &domain, &request_id, idempotency_key.as_deref()),
        SiteCommand::Enroll {
            request_file,
            request_id,
            idempotency_key,
        } => enroll(&request_file, &request_id, idempotency_key.as_deref()),
        SiteCommand::Unenroll {
            site_id,
            request_id,
            idempotency_key,
        } => unenroll(&site_id, &request_id, idempotency_key.as_deref()),
        SiteCommand::AllocateIdentity {
            runtime_id,
            domain,
            os_user,
            root,
            worker_mode,
            worker_count,
            request_id,
            idempotency_key,
        } => identity::allocate(
            &runtime_id,
            &domain,
            os_user.as_deref(),
            &root,
            worker_mode,
            worker_count,
            &request_id,
            idempotency_key.as_deref(),
        ),
        SiteCommand::ReleaseIdentity {
            runtime_id,
            domain,
            remove_user,
            request_id,
            idempotency_key,
        } => identity::release(
            &runtime_id,
            &domain,
            remove_user,
            &request_id,
            idempotency_key.as_deref(),
        ),
        SiteCommand::UpdateIdentity {
            runtime_id,
            domain,
            root,
            request_id,
            idempotency_key,
        } => identity::update(
            &runtime_id,
            &domain,
            &root,
            &request_id,
            idempotency_key.as_deref(),
        ),
        SiteCommand::RenameIdentity {
            runtime_id,
            from_domain,
            to_domain,
            root,
            request_id,
            idempotency_key,
        } => identity::rename(
            &runtime_id,
            &from_domain,
            &to_domain,
            &root,
            &request_id,
            idempotency_key.as_deref(),
        ),
    }
}

/// `site.allocateIdentity`, `site.releaseIdentity`, `site.updateIdentity`
/// and `site.renameIdentity` (milestone 064).
mod identity {
    use crate::{
        error::ErrorCode,
        protocol::{Response, ResponseBuildError},
    };

    #[cfg(unix)]
    use crate::site_identity::{
        ALLOCATE_OPERATION, AllocateRequest, RELEASE_OPERATION, RENAME_OPERATION, ReleaseRequest,
        RenameRequest, UPDATE_OPERATION, UpdateRequest,
    };

    #[allow(clippy::too_many_arguments)]
    pub(super) fn allocate(
        runtime_id: &str,
        domain: &str,
        os_user: Option<&str>,
        root: &str,
        worker_mode: bool,
        worker_count: i64,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Response, ResponseBuildError> {
        #[cfg(unix)]
        {
            run(ALLOCATE_OPERATION, |config, ctx| {
                let request = AllocateRequest::parse(
                    runtime_id,
                    domain,
                    os_user,
                    root,
                    worker_mode,
                    worker_count,
                    &config.content_roots,
                    request_id,
                    key,
                )
                .map_err(Rejected::Request)?;
                crate::site_identity::allocate(ctx, &request, &Default::default())
                    .map(serde_json::to_value)
                    .map_err(Rejected::Operation)
            })
        }
        #[cfg(not(unix))]
        {
            let _ = (runtime_id, domain, os_user, root, worker_mode, worker_count);
            unsupported("site.allocateIdentity", request_id, key)
        }
    }

    pub(super) fn release(
        runtime_id: &str,
        domain: &str,
        remove_user: bool,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Response, ResponseBuildError> {
        #[cfg(unix)]
        {
            run(RELEASE_OPERATION, |_, ctx| {
                let request =
                    ReleaseRequest::parse(runtime_id, domain, remove_user, request_id, key)
                        .map_err(Rejected::Request)?;
                crate::site_identity::release(ctx, &request, &Default::default())
                    .map(serde_json::to_value)
                    .map_err(Rejected::Operation)
            })
        }
        #[cfg(not(unix))]
        {
            let _ = (runtime_id, domain, remove_user);
            unsupported("site.releaseIdentity", request_id, key)
        }
    }

    pub(super) fn update(
        runtime_id: &str,
        domain: &str,
        root: &str,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Response, ResponseBuildError> {
        #[cfg(unix)]
        {
            run(UPDATE_OPERATION, |config, ctx| {
                let request = UpdateRequest::parse(
                    runtime_id,
                    domain,
                    root,
                    &config.content_roots,
                    request_id,
                    key,
                )
                .map_err(Rejected::Request)?;
                crate::site_identity::update(ctx, &request, &Default::default())
                    .map(serde_json::to_value)
                    .map_err(Rejected::Operation)
            })
        }
        #[cfg(not(unix))]
        {
            let _ = (runtime_id, domain, root);
            unsupported("site.updateIdentity", request_id, key)
        }
    }

    pub(super) fn rename(
        runtime_id: &str,
        from_domain: &str,
        to_domain: &str,
        root: &str,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Response, ResponseBuildError> {
        #[cfg(unix)]
        {
            run(RENAME_OPERATION, |config, ctx| {
                let request = RenameRequest::parse(
                    runtime_id,
                    from_domain,
                    to_domain,
                    root,
                    &config.content_roots,
                    request_id,
                    key,
                )
                .map_err(Rejected::Request)?;
                crate::site_identity::rename(ctx, &request, &Default::default())
                    .map(serde_json::to_value)
                    .map_err(Rejected::Operation)
            })
        }
        #[cfg(not(unix))]
        {
            let _ = (runtime_id, from_domain, to_domain, root);
            unsupported("site.renameIdentity", request_id, key)
        }
    }

    #[cfg(not(unix))]
    fn unsupported(
        operation: &'static str,
        _request_id: &str,
        _key: Option<&str>,
    ) -> Result<Response, ResponseBuildError> {
        Ok(Response::failure(
            operation,
            ErrorCode::UnsupportedPlatform,
            "site identity operations require a Unix host",
        ))
    }

    #[cfg(unix)]
    enum Rejected {
        Request(crate::site_identity::RequestError),
        Operation(crate::site_identity::Error),
    }

    /// Loads the engine config, opens the state root, builds the context
    /// and runs one identity operation, mapping its outcome to a response.
    #[cfg(unix)]
    fn run(
        operation: &'static str,
        run: impl FnOnce(
            &crate::config::EngineConfig,
            &crate::site_identity::Context<'_>,
        ) -> Result<serde_json::Result<serde_json::Value>, Rejected>,
    ) -> Result<Response, ResponseBuildError> {
        use std::path::Path;

        use crate::{
            config::EngineConfig,
            error::WarningCode,
            filesystem::ManagedRoot,
            protocol::Warning,
            site_identity::{Context, Error, UserTools},
        };

        let config = match EngineConfig::load_root_owned(Path::new(super::CONFIG_PATH)) {
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
        let context = Context {
            engine_state: &engine_state,
            runtime_root: &config.runtime_root,
            site_services_root: &config.site_services_root,
            passwd_file: Path::new("/etc/passwd"),
            group_file: Path::new("/etc/group"),
            legacy_uid_counter: Some(Path::new(LEGACY_UID_COUNTER)),
            tools: UserTools::PRODUCTION,
        };
        match run(&config, &context) {
            Ok(value) => {
                let value = value.expect("operation results always serialize");
                Response::success(operation, value)
            }
            Err(Rejected::Request(error)) => Ok(Response::failure(
                operation,
                ErrorCode::InvalidInput,
                error.message(),
            )),
            Err(Rejected::Operation(Error::PostCommit(result))) => {
                Response::success(operation, result).map(|response| {
                    response.with_warnings(vec![Warning {
                        code: WarningCode::TransactionRecordIncomplete,
                        message: "the operation completed but its transaction record could \
                                  not be saved"
                            .to_owned(),
                    }])
                })
            }
            Err(Rejected::Operation(error)) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(operation, code, &message))
            }
        }
    }

    /// The control panel's old host-wide counter, read once to seed the
    /// engine's own.
    #[cfg(unix)]
    const LEGACY_UID_COUNTER: &str = "/etc/wcp/site-uid-counter";
}

fn enroll(
    path: &std::path::Path,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    use crate::site_enroll::{ENROLL_OPERATION, EnrollRequest};

    #[cfg(unix)]
    {
        let json = match crate::commands::read_root_owned_content_file(path) {
            Ok(json) => json,
            Err(_) => {
                return Ok(Response::failure(
                    ENROLL_OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match EnrollRequest::parse(&json, request_id, idempotency_key) {
            Ok(request) => request,
            Err(error) => {
                return Ok(Response::failure(
                    ENROLL_OPERATION,
                    ErrorCode::InvalidInput,
                    error.message(),
                ));
            }
        };
        run_enrollment(ENROLL_OPERATION, |context| {
            crate::site_enroll::enroll(context, &request).map(serde_json::to_value)
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, idempotency_key);
        Ok(Response::failure(
            ENROLL_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "site.enroll requires a Unix host",
        ))
    }
}

fn unenroll(
    site_id: &str,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    use crate::site_enroll::{UNENROLL_OPERATION, UnenrollRequest};

    let request = match UnenrollRequest::parse(site_id, request_id, idempotency_key) {
        Ok(request) => request,
        Err(error) => {
            return Ok(Response::failure(
                UNENROLL_OPERATION,
                ErrorCode::InvalidInput,
                error.message(),
            ));
        }
    };
    #[cfg(unix)]
    {
        run_enrollment(UNENROLL_OPERATION, |context| {
            crate::site_enroll::unenroll(context, &request).map(serde_json::to_value)
        })
    }
    #[cfg(not(unix))]
    {
        let _ = request;
        Ok(Response::failure(
            UNENROLL_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "site.unenroll requires a Unix host",
        ))
    }
}

#[cfg(unix)]
fn run_enrollment(
    operation: &'static str,
    run: impl FnOnce(
        &crate::site_enroll::Context<'_>,
    ) -> Result<serde_json::Result<serde_json::Value>, crate::site_enroll::Error>,
) -> Result<Response, ResponseBuildError> {
    use std::path::Path;

    use crate::{
        config::EngineConfig,
        deploy::staging::resolve_site_identity,
        filesystem::ManagedRoot,
        site_enroll::{Context, Error, MIN_SITE_IDENTITY},
    };

    let engine_config = match EngineConfig::load_root_owned(Path::new(CONFIG_PATH)) {
        Ok(config) => config,
        Err(_) => {
            return Ok(Response::failure(
                operation,
                ErrorCode::Internal,
                crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
            ));
        }
    };
    let engine_state = match ManagedRoot::open(&engine_config.state_root) {
        Ok(root) => root,
        Err(_) => {
            return Ok(Response::failure(
                operation,
                ErrorCode::Internal,
                "engine state root is unavailable",
            ));
        }
    };
    let cancellation = CancellationToken::default();
    let resolve = |user: &str| {
        resolve_site_identity(user, &cancellation)
            .ok()
            .map(|identity| (identity.uid, identity.gid))
    };
    let context = Context {
        engine_state: &engine_state,
        sites_dir: Path::new(SITES_DIR),
        credential_dir: engine_config.credential_root.as_path(),
        required_uid: 0,
        min_identity: MIN_SITE_IDENTITY,
        resolve_identity: &resolve,
    };
    match run(&context) {
        Ok(value) => {
            let value = value.expect("operation results always serialize");
            Response::success(operation, value)
        }
        Err(Error::PostCommit(result)) => Response::success(operation, result).map(|response| {
            response.with_warnings(vec![Warning {
                code: WarningCode::TransactionRecordIncomplete,
                message: "the operation completed but its transaction record could not be \
                          saved"
                    .to_owned(),
            }])
        }),
        Err(error) => {
            let (code, message) = error.protocol();
            Ok(Response::failure(operation, code, &message))
        }
    }
}

fn rename_manifest(
    site_id: &str,
    domain: &str,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    use crate::site_manifest::{RENAME_OPERATION, RenameRequest};

    let request = match RenameRequest::parse(site_id, domain, request_id, idempotency_key) {
        Ok(request) => request,
        Err(error) => {
            return Ok(Response::failure(
                RENAME_OPERATION,
                ErrorCode::InvalidInput,
                error.message(),
            ));
        }
    };

    #[cfg(unix)]
    {
        run_rename_manifest(&request)
    }
    #[cfg(not(unix))]
    {
        let _ = request;
        Ok(Response::failure(
            RENAME_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "site.renameManifest requires a Unix host",
        ))
    }
}

#[cfg(unix)]
fn run_rename_manifest(
    request: &crate::site_manifest::RenameRequest,
) -> Result<Response, ResponseBuildError> {
    use std::path::Path;

    use crate::{
        config::EngineConfig,
        filesystem::ManagedRoot,
        site_manifest::{self, RENAME_OPERATION},
    };

    let engine_config = match EngineConfig::load_root_owned(Path::new(CONFIG_PATH)) {
        Ok(config) => config,
        Err(_) => {
            return Ok(Response::failure(
                RENAME_OPERATION,
                ErrorCode::Internal,
                crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
            ));
        }
    };
    let engine_state = match ManagedRoot::open(&engine_config.state_root) {
        Ok(root) => root,
        Err(_) => {
            return Ok(Response::failure(
                RENAME_OPERATION,
                ErrorCode::Internal,
                "engine state root is unavailable",
            ));
        }
    };
    match site_manifest::rename_manifest(&engine_state, Path::new(SITES_DIR), 0, request) {
        Ok(result) => Response::success(RENAME_OPERATION, result),
        Err(site_manifest::Error::PostCommit(result)) => {
            Response::success(RENAME_OPERATION, result).map(|response| {
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
            Ok(Response::failure(RENAME_OPERATION, code, &message))
        }
    }
}

fn move_root(
    from_domain: &str,
    to_domain: &str,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    use crate::site_root::{MOVE_OPERATION, MoveRequest};

    let request = match MoveRequest::parse(from_domain, to_domain, request_id, idempotency_key) {
        Ok(request) => request,
        Err(error) => {
            return Ok(Response::failure(
                MOVE_OPERATION,
                ErrorCode::InvalidInput,
                error.message(),
            ));
        }
    };

    #[cfg(unix)]
    {
        run_move_root(&request)
    }
    #[cfg(not(unix))]
    {
        let _ = request;
        Ok(Response::failure(
            MOVE_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "site.moveRoot requires a Unix host",
        ))
    }
}

#[cfg(unix)]
fn run_move_root(request: &crate::site_root::MoveRequest) -> Result<Response, ResponseBuildError> {
    use std::path::Path;

    use crate::{
        config::EngineConfig,
        filesystem::ManagedRoot,
        site_root::{self, MOVE_OPERATION},
    };

    let engine_config = match EngineConfig::load_root_owned(Path::new(CONFIG_PATH)) {
        Ok(config) => config,
        Err(_) => {
            return Ok(Response::failure(
                MOVE_OPERATION,
                ErrorCode::Internal,
                crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
            ));
        }
    };
    let engine_state = match ManagedRoot::open(&engine_config.state_root) {
        Ok(root) => root,
        Err(_) => {
            return Ok(Response::failure(
                MOVE_OPERATION,
                ErrorCode::Internal,
                "engine state root is unavailable",
            ));
        }
    };
    match site_root::move_root(&engine_state, &engine_config.content_roots, request) {
        Ok(result) => Response::success(MOVE_OPERATION, result),
        Err(site_root::Error::PostCommit(result)) => {
            Response::success(MOVE_OPERATION, result).map(|response| {
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
            Ok(Response::failure(MOVE_OPERATION, code, &message))
        }
    }
}

fn prepare_root(
    domain: &str,
    relative_root: Option<&str>,
    uid: u32,
    gid: u32,
    existing: Option<&str>,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    use crate::site_root::{PREPARE_OPERATION, PrepareRequest};

    let request = match PrepareRequest::parse(
        domain,
        relative_root,
        uid,
        gid,
        existing,
        request_id,
        idempotency_key,
    ) {
        Ok(request) => request,
        Err(error) => {
            return Ok(Response::failure(
                PREPARE_OPERATION,
                ErrorCode::InvalidInput,
                error.message(),
            ));
        }
    };

    #[cfg(unix)]
    {
        run_site_root(PREPARE_OPERATION, |engine_state, config| {
            crate::site_root::prepare_root(engine_state, &config.content_roots, &request)
        })
    }
    #[cfg(not(unix))]
    {
        let _ = request;
        Ok(Response::failure(
            PREPARE_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "site.prepareRoot requires a Unix host",
        ))
    }
}

fn remove_root(
    domain: &str,
    relative_root: Option<&str>,
    site_id: Option<&str>,
    confirm_contents: bool,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    use crate::site_root::{REMOVE_OPERATION, RemoveRequest};

    let request = match RemoveRequest::parse(
        domain,
        relative_root,
        site_id,
        confirm_contents,
        request_id,
        idempotency_key,
    ) {
        Ok(request) => request,
        Err(error) => {
            return Ok(Response::failure(
                REMOVE_OPERATION,
                ErrorCode::InvalidInput,
                error.message(),
            ));
        }
    };

    #[cfg(unix)]
    {
        run_site_root(REMOVE_OPERATION, |engine_state, config| {
            crate::site_root::remove_root(
                engine_state,
                &config.content_roots,
                std::path::Path::new(SITES_DIR),
                0,
                &request,
            )
        })
    }
    #[cfg(not(unix))]
    {
        let _ = request;
        Ok(Response::failure(
            REMOVE_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "site.removeRoot requires a Unix host",
        ))
    }
}

fn write_env_file(
    request_file: &std::path::Path,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::site_file::{ENV_OPERATION, EnvRequest};

        let json = match crate::commands::read_root_owned_content_file(request_file) {
            Ok(json) => json,
            Err(_) => {
                return Ok(Response::failure(
                    ENV_OPERATION,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request = match EnvRequest::parse(&json, request_id, idempotency_key) {
            Ok(request) => request,
            Err(error) => {
                return Ok(Response::failure(
                    ENV_OPERATION,
                    ErrorCode::InvalidInput,
                    error.message(),
                ));
            }
        };
        run_site_root(ENV_OPERATION, |engine_state, config| {
            crate::site_file::write_env_file(engine_state, &config.content_roots, &request)
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (request_file, request_id, idempotency_key);
        Ok(Response::failure(
            "site.writeEnvFile",
            ErrorCode::UnsupportedPlatform,
            "site.writeEnvFile requires a Unix host",
        ))
    }
}

fn php_info_session(
    action: &str,
    directory: &str,
    ttl_minutes: Option<u32>,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::site_file::{PHPINFO_OPERATION, PhpInfoRequest};

        let request = match PhpInfoRequest::parse(
            directory,
            action,
            ttl_minutes,
            request_id,
            idempotency_key,
        ) {
            Ok(request) => request,
            Err(error) => {
                return Ok(Response::failure(
                    PHPINFO_OPERATION,
                    ErrorCode::InvalidInput,
                    error.message(),
                ));
            }
        };
        run_site_root(PHPINFO_OPERATION, |engine_state, config| {
            crate::site_file::php_info_session(engine_state, &config.content_roots, &request)
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (action, directory, ttl_minutes, request_id, idempotency_key);
        Ok(Response::failure(
            "site.phpInfoSession",
            ErrorCode::UnsupportedPlatform,
            "site.phpInfoSession requires a Unix host",
        ))
    }
}

fn export_archive(
    path: &std::path::Path,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    use crate::site_archive::{self as archive, EXPORT_OPERATION};
    #[cfg(unix)]
    {
        use crate::{commands::read_root_owned_content_file, filesystem::ManagedRoot};
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
        let Ok(request) = archive::ExportRequest::parse(&json, request_id, idempotency_key) else {
            return fail(
                ErrorCode::InvalidInput,
                "request-file is not a valid site archive export plan",
            );
        };
        let Some(content_root) = config
            .content_roots
            .iter()
            .find(|root| request.source_root().starts_with(root.as_path()))
        else {
            return fail(
                ErrorCode::InvalidInput,
                "site root is outside configured content roots",
            );
        };
        let Ok(state) = ManagedRoot::open(&config.state_root) else {
            return fail(ErrorCode::Internal, "engine state root is unavailable");
        };
        let context = archive::Context {
            engine_state: &state,
            state_root: &config.state_root,
            content_root,
            tar_program: "tar",
        };
        match archive::export(
            &context,
            &request,
            &crate::process::CancellationToken::default(),
        ) {
            Ok(result) => Response::success(EXPORT_OPERATION, result),
            Err(archive::Error::PostCommit(value)) => Response::success(EXPORT_OPERATION, value),
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
            "site.exportArchive requires a Unix host",
        ))
    }
}

fn import_archive(
    path: &std::path::Path,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    use crate::site_archive::{self as archive, import::OPERATION};
    #[cfg(unix)]
    {
        use crate::{commands::read_root_owned_content_file, filesystem::ManagedRoot};
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
        let Ok(request) = archive::import::Request::parse(&json, request_id, idempotency_key)
        else {
            return fail(
                ErrorCode::InvalidInput,
                "request-file is not a valid site archive import plan",
            );
        };
        let Some(content_root) = config
            .content_roots
            .iter()
            .find(|root| request.dest_root().starts_with(root.as_path()))
        else {
            return fail(
                ErrorCode::InvalidInput,
                "destination root is outside configured content roots",
            );
        };
        let Ok(state) = ManagedRoot::open(&config.state_root) else {
            return fail(ErrorCode::Internal, "engine state root is unavailable");
        };
        let context = archive::import::Context {
            engine_state: &state,
            state_root: &config.state_root,
            content_root,
            artifact_dir: std::path::Path::new("/etc/operations-engine/staging"),
            artifact_owner_uid: 0,
        };
        match archive::import::execute(&context, &request) {
            Ok(result) => Response::success(OPERATION, result),
            Err(archive::Error::PostCommit(value)) => Response::success(OPERATION, value),
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
            "site.importArchive requires a Unix host",
        ))
    }
}

fn discard_archive(
    kind: &str,
    archive_id: Option<&str>,
    request_id: &str,
) -> Result<Response, ResponseBuildError> {
    use crate::site_archive::{self as archive, DISCARD_OPERATION};
    #[cfg(unix)]
    {
        let fail = |code, message: &str| Ok(Response::failure(DISCARD_OPERATION, code, message));
        let Ok(request) = archive::DiscardRequest::parse(kind, archive_id, request_id) else {
            return fail(
                ErrorCode::InvalidInput,
                "kind must be export, snapshot or stale; archive-id (required except for stale) and request-id must be canonical UUIDs",
            );
        };
        let Ok(config) = crate::config::EngineConfig::load_root_owned(std::path::Path::new(
            "/etc/operations-engine/config.json",
        )) else {
            return fail(
                ErrorCode::Internal,
                crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
            );
        };
        let Ok(state) = crate::filesystem::ManagedRoot::open(&config.state_root) else {
            return fail(ErrorCode::Internal, "engine state root is unavailable");
        };
        match archive::discard(&state, &config.state_root, &config.content_roots, &request) {
            Ok(result) => Response::success(DISCARD_OPERATION, result),
            Err(archive::Error::PostCommit(value)) => Response::success(DISCARD_OPERATION, value),
            Err(error) => {
                let (code, message) = error.protocol();
                Ok(Response::failure(DISCARD_OPERATION, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (kind, archive_id, request_id);
        Ok(Response::failure(
            DISCARD_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "site.discardArchive requires a Unix host",
        ))
    }
}

fn quarantine_file(
    path: &str,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::site_file::{QUARANTINE_OPERATION, QuarantineRequest};

        let request = match QuarantineRequest::parse(path, request_id, idempotency_key) {
            Ok(request) => request,
            Err(error) => {
                return Ok(Response::failure(
                    QUARANTINE_OPERATION,
                    ErrorCode::InvalidInput,
                    error.message(),
                ));
            }
        };
        run_site_root(QUARANTINE_OPERATION, |engine_state, config| {
            crate::site_file::quarantine_file(engine_state, &config.content_roots, &request)
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, idempotency_key);
        Ok(Response::failure(
            "site.quarantineFile",
            ErrorCode::UnsupportedPlatform,
            "site.quarantineFile requires a Unix host",
        ))
    }
}

fn release_root(
    domain: &str,
    site_id: Option<&str>,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    use crate::site_root::{RELEASE_OPERATION, ReleaseRequest};

    let request = match ReleaseRequest::parse(domain, site_id, request_id, idempotency_key) {
        Ok(request) => request,
        Err(error) => {
            return Ok(Response::failure(
                RELEASE_OPERATION,
                ErrorCode::InvalidInput,
                error.message(),
            ));
        }
    };

    #[cfg(unix)]
    {
        run_site_root(RELEASE_OPERATION, |engine_state, config| {
            crate::site_root::release_root(
                engine_state,
                &config.content_roots,
                std::path::Path::new(SITES_DIR),
                0,
                &request,
            )
        })
    }
    #[cfg(not(unix))]
    {
        let _ = request;
        Ok(Response::failure(
            RELEASE_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "site.releaseRoot requires a Unix host",
        ))
    }
}

/// Loads the engine config and state root, runs one `site_root` operation
/// and maps its outcome to a protocol response.
#[cfg(unix)]
fn run_site_root<T: serde::Serialize>(
    operation: &'static str,
    run: impl FnOnce(
        &crate::filesystem::ManagedRoot,
        &crate::config::EngineConfig,
    ) -> Result<T, crate::site_root::Error>,
) -> Result<Response, ResponseBuildError> {
    use std::path::Path;

    use crate::{config::EngineConfig, filesystem::ManagedRoot, site_root};

    let engine_config = match EngineConfig::load_root_owned(Path::new(CONFIG_PATH)) {
        Ok(config) => config,
        Err(_) => {
            return Ok(Response::failure(
                operation,
                ErrorCode::Internal,
                crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
            ));
        }
    };
    let engine_state = match ManagedRoot::open(&engine_config.state_root) {
        Ok(root) => root,
        Err(_) => {
            return Ok(Response::failure(
                operation,
                ErrorCode::Internal,
                "engine state root is unavailable",
            ));
        }
    };
    match run(&engine_state, &engine_config) {
        Ok(result) => Response::success(operation, result),
        Err(site_root::Error::PostCommit(result)) => {
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

const DEPLOY_OPERATION: &str = "site.deploy";
const ROLLBACK_OPERATION: &str = "site.rollback";
const CONFIG_PATH: &str = "/etc/operations-engine/config.json";
const SITES_DIR: &str = "/etc/operations-engine/sites";

fn deploy(
    site_id: &str,
    revision: &str,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    let request = match DeployRequest::parse(site_id, revision, request_id, idempotency_key) {
        Ok(request) => request,
        Err(error) => {
            return Ok(Response::failure(
                DEPLOY_OPERATION,
                ErrorCode::InvalidInput,
                deploy_request_error_message(error),
            ));
        }
    };

    #[cfg(unix)]
    {
        run_deploy(&request)
    }
    #[cfg(not(unix))]
    {
        let _ = request;
        Ok(Response::failure(
            DEPLOY_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "site.deploy requires a Unix host",
        ))
    }
}

#[cfg(unix)]
fn run_deploy(request: &DeployRequest) -> Result<Response, ResponseBuildError> {
    use std::path::Path;

    use crate::{
        config::{EngineConfig, SiteManifest},
        filesystem::ManagedRoot,
        site::TrustedRoot,
    };

    let engine_config = match EngineConfig::load_root_owned(Path::new(CONFIG_PATH)) {
        Ok(config) => config,
        Err(_) => {
            return Ok(Response::failure(
                DEPLOY_OPERATION,
                ErrorCode::Internal,
                crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
            ));
        }
    };
    let manifest_path = Path::new(SITES_DIR).join(format!("{}.json", request.site_id));
    let manifest = match SiteManifest::load_root_owned(&manifest_path, request.site_id) {
        Ok(manifest) => manifest,
        Err(_) => {
            return Ok(Response::failure(
                DEPLOY_OPERATION,
                ErrorCode::InvalidInput,
                "site is not configured or its manifest could not be loaded",
            ));
        }
    };
    let content_root: &TrustedRoot = match engine_config.content_roots.as_slice() {
        [root] => root,
        _ => {
            return Ok(Response::failure(
                DEPLOY_OPERATION,
                ErrorCode::Internal,
                "engine configuration must have exactly one content root for this build",
            ));
        }
    };
    let engine_state = match ManagedRoot::open(&engine_config.state_root) {
        Ok(root) => root,
        Err(_) => {
            return Ok(Response::failure(
                DEPLOY_OPERATION,
                ErrorCode::Internal,
                "engine state root is unavailable",
            ));
        }
    };
    let context = DeployContext {
        content_root,
        credential_root: &engine_config.credential_root,
        engine_state: &engine_state,
    };

    match execute_deploy(&context, &manifest, request, &CancellationToken::default()) {
        Ok(result) => Response::success(DEPLOY_OPERATION, result),
        Err(DeployError::PostCommitRecordFailed { result, .. }) => {
            Response::success(DEPLOY_OPERATION, result).map(|response| {
                response.with_warnings(vec![Warning {
                    code: WarningCode::TransactionRecordIncomplete,
                    message:
                        "the deployment completed but its transaction record could not be saved"
                            .to_owned(),
                }])
            })
        }
        Err(error) => {
            let (code, message) = error.protocol();
            Ok(Response::failure(DEPLOY_OPERATION, code, &message))
        }
    }
}

fn deploy_request_error_message(error: DeployRequestError) -> &'static str {
    match error {
        DeployRequestError::InvalidSiteId => "site-id is not a canonical UUID",
        DeployRequestError::InvalidRevision => "revision is not a full Git object ID",
        DeployRequestError::InvalidRequestId => "request-id is not a canonical UUID",
        DeployRequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}

fn rollback(
    site_id: &str,
    release: &str,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    let request = match RollbackRequest::parse(site_id, release, request_id, idempotency_key) {
        Ok(request) => request,
        Err(error) => {
            return Ok(Response::failure(
                ROLLBACK_OPERATION,
                ErrorCode::InvalidInput,
                rollback_request_error_message(error),
            ));
        }
    };

    #[cfg(unix)]
    {
        run_rollback(&request)
    }
    #[cfg(not(unix))]
    {
        let _ = request;
        Ok(Response::failure(
            ROLLBACK_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "site.rollback requires a Unix host",
        ))
    }
}

#[cfg(unix)]
fn run_rollback(request: &RollbackRequest) -> Result<Response, ResponseBuildError> {
    use std::path::Path;

    use crate::{
        config::{EngineConfig, SiteManifest},
        filesystem::ManagedRoot,
        site::TrustedRoot,
    };

    let engine_config = match EngineConfig::load_root_owned(Path::new(CONFIG_PATH)) {
        Ok(config) => config,
        Err(_) => {
            return Ok(Response::failure(
                ROLLBACK_OPERATION,
                ErrorCode::Internal,
                crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
            ));
        }
    };
    let manifest_path = Path::new(SITES_DIR).join(format!("{}.json", request.site_id));
    let manifest = match SiteManifest::load_root_owned(&manifest_path, request.site_id) {
        Ok(manifest) => manifest,
        Err(_) => {
            return Ok(Response::failure(
                ROLLBACK_OPERATION,
                ErrorCode::InvalidInput,
                "site is not configured or its manifest could not be loaded",
            ));
        }
    };
    let content_root: &TrustedRoot = match engine_config.content_roots.as_slice() {
        [root] => root,
        _ => {
            return Ok(Response::failure(
                ROLLBACK_OPERATION,
                ErrorCode::Internal,
                "engine configuration must have exactly one content root for this build",
            ));
        }
    };
    let engine_state = match ManagedRoot::open(&engine_config.state_root) {
        Ok(root) => root,
        Err(_) => {
            return Ok(Response::failure(
                ROLLBACK_OPERATION,
                ErrorCode::Internal,
                "engine state root is unavailable",
            ));
        }
    };
    let context = RollbackContext {
        content_root,
        engine_state: &engine_state,
    };

    match execute_rollback(&context, &manifest, request, &CancellationToken::default()) {
        Ok(result) => Response::success(ROLLBACK_OPERATION, result),
        Err(RollbackError::PostCommitRecordFailed { result, .. }) => {
            Response::success(ROLLBACK_OPERATION, result).map(|response| {
                response.with_warnings(vec![Warning {
                    code: WarningCode::TransactionRecordIncomplete,
                    message: "the rollback completed but its transaction record could not be saved"
                        .to_owned(),
                }])
            })
        }
        Err(error) => {
            let (code, message) = error.protocol();
            Ok(Response::failure(ROLLBACK_OPERATION, code, &message))
        }
    }
}

fn rollback_request_error_message(error: RollbackRequestError) -> &'static str {
    match error {
        RollbackRequestError::InvalidSiteId => "site-id is not a canonical UUID",
        RollbackRequestError::InvalidReleaseId => "release is not a canonical release identifier",
        RollbackRequestError::InvalidRequestId => "request-id is not a canonical UUID",
        RollbackRequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}
