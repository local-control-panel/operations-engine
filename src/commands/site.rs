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
            request_id,
            idempotency_key,
        } => prepare_root(
            &domain,
            relative_root.as_deref(),
            uid,
            gid,
            &request_id,
            idempotency_key.as_deref(),
        ),
        SiteCommand::RemoveRoot {
            domain,
            site_id,
            confirm_contents,
            request_id,
            idempotency_key,
        } => remove_root(
            &domain,
            site_id.as_deref(),
            confirm_contents,
            &request_id,
            idempotency_key.as_deref(),
        ),
        SiteCommand::RenameManifest {
            site_id,
            domain,
            request_id,
            idempotency_key,
        } => rename_manifest(&site_id, &domain, &request_id, idempotency_key.as_deref()),
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
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    use crate::site_root::{PREPARE_OPERATION, PrepareRequest};

    let request =
        match PrepareRequest::parse(domain, relative_root, uid, gid, request_id, idempotency_key) {
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
    site_id: Option<&str>,
    confirm_contents: bool,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    use crate::site_root::{REMOVE_OPERATION, RemoveRequest};

    let request = match RemoveRequest::parse(
        domain,
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
