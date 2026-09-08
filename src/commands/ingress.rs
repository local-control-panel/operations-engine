use crate::{
    cli::{IngressCommand, IngressTarget},
    commands::{ContentFileError, read_content_file},
    error::{ErrorCode, WarningCode},
    ingress::{
        ActivateConfigRequest, ActivateConfigRequestError, OPERATION as ACTIVATE_OPERATION,
        PARK_OPERATION, ParkRequest, ParkRequestError, RouteTarget, UNPARK_OPERATION,
        UnparkRequest, UnparkRequestError,
        execute::{ActivateConfigError, ActivateContext, execute as execute_activate_config},
        park::{ParkError, execute as execute_park},
        reconcile::{
            RECONCILE_OPERATION, ReconcileContext, ReconcileError, ReconcileRequest,
            ReconcileRequestError, execute as execute_reconcile,
        },
        unpark::{UnparkError, execute as execute_unpark},
    },
    process::CancellationToken,
    protocol::{Response, ResponseBuildError, Warning},
    site::Domain,
    transaction::{IdempotencyKey, RequestId},
};

const CONFIG_PATH: &str = "/etc/operations-engine/config.json";

pub fn run(command: IngressCommand) -> Result<Response, ResponseBuildError> {
    match command {
        IngressCommand::ActivateConfig {
            domain,
            content_file,
            expected_hash,
            request_id,
            idempotency_key,
            target,
        } => activate_config(
            &domain,
            &content_file,
            expected_hash.as_deref(),
            target,
            &request_id,
            idempotency_key.as_deref(),
        ),
        IngressCommand::Park {
            domain,
            content_file,
            request_id,
            idempotency_key,
        } => park(
            &domain,
            &content_file,
            &request_id,
            idempotency_key.as_deref(),
        ),
        IngressCommand::Unpark {
            domain,
            request_id,
            idempotency_key,
        } => unpark(&domain, &request_id, idempotency_key.as_deref()),
        IngressCommand::Reconcile {
            request_id,
            idempotency_key,
        } => reconcile(&request_id, idempotency_key.as_deref()),
    }
}

fn activate_config(
    domain: &str,
    content_file: &std::path::Path,
    expected_hash: Option<&str>,
    target: IngressTarget,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    // Validate every field that does not require reading `content_file`
    // first, so a request with e.g. an invalid domain is rejected before
    // this root-privileged process ever touches the filesystem for the
    // content path. `ActivateConfigRequest::parse` below re-validates these
    // same fields (it is the single authoritative constructor for the
    // request), but by then they are already known-good, so that is cheap
    // string work, not new I/O.
    let guard = match ActivateConfigRequest::guard_from_expected_hash(expected_hash) {
        Ok(guard) => guard,
        Err(error) => {
            return Ok(Response::failure(
                ACTIVATE_OPERATION,
                ErrorCode::InvalidInput,
                activate_config_request_error_message(error),
            ));
        }
    };
    if let Err(error) = validate_cheap_fields(domain, request_id, idempotency_key) {
        return Ok(Response::failure(
            ACTIVATE_OPERATION,
            ErrorCode::InvalidInput,
            activate_config_request_error_message(error),
        ));
    }

    let content = match read_content_file(content_file) {
        Ok(content) => content,
        Err(ContentFileError::TooLarge) => {
            return Ok(Response::failure(
                ACTIVATE_OPERATION,
                ErrorCode::InvalidInput,
                activate_config_request_error_message(ActivateConfigRequestError::ContentTooLarge),
            ));
        }
        Err(ContentFileError::Unreadable) => {
            return Ok(Response::failure(
                ACTIVATE_OPERATION,
                ErrorCode::InvalidInput,
                "content-file could not be read",
            ));
        }
    };

    let request = match ActivateConfigRequest::parse(
        domain,
        content,
        guard,
        route_target(target),
        request_id,
        idempotency_key,
    ) {
        Ok(request) => request,
        Err(error) => {
            return Ok(Response::failure(
                ACTIVATE_OPERATION,
                ErrorCode::InvalidInput,
                activate_config_request_error_message(error),
            ));
        }
    };

    #[cfg(unix)]
    {
        run_activate_config(&request)
    }
    #[cfg(not(unix))]
    {
        let _ = request;
        Ok(Response::failure(
            ACTIVATE_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "ingress.activateConfig requires a Unix host",
        ))
    }
}

#[cfg(unix)]
fn run_activate_config(request: &ActivateConfigRequest) -> Result<Response, ResponseBuildError> {
    use std::path::Path;

    use crate::{compose, config::EngineConfig, filesystem::ManagedRoot};

    let engine_config = match EngineConfig::load_root_owned(Path::new(CONFIG_PATH)) {
        Ok(config) => config,
        Err(_) => {
            return Ok(Response::failure(
                ACTIVATE_OPERATION,
                ErrorCode::Internal,
                crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
            ));
        }
    };
    let engine_state = match ManagedRoot::open(&engine_config.state_root) {
        Ok(root) => root,
        Err(_) => {
            return Ok(Response::failure(
                ACTIVATE_OPERATION,
                ErrorCode::Internal,
                "engine state root is unavailable",
            ));
        }
    };
    let compose_access = compose::Access::default();
    let context = ActivateContext {
        ingress_root: &engine_config.ingress_root,
        engine_state: &engine_state,
        compose: &compose_access,
    };

    match execute_activate_config(&context, request, &CancellationToken::default()) {
        Ok(result) => Response::success(ACTIVATE_OPERATION, result),
        Err(ActivateConfigError::PostCommitRecordFailed { result, .. }) => {
            Response::success(ACTIVATE_OPERATION, result).map(|response| {
                response.with_warnings(vec![Warning {
                    code: WarningCode::TransactionRecordIncomplete,
                    message: "the configuration was activated but its transaction record could \
                              not be saved"
                        .to_owned(),
                }])
            })
        }
        Err(error) => {
            let (code, message) = error.protocol();
            Ok(Response::failure(ACTIVATE_OPERATION, code, &message))
        }
    }
}

fn park(
    domain: &str,
    content_file: &std::path::Path,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    // Same ordering `activate_config` uses and for the same reason: reject
    // a malformed domain/request-id/idempotency-key before this
    // root-privileged process ever opens `content_file`. `ParkRequest::parse`
    // below re-validates these same fields — cheap string work by then,
    // not new I/O.
    if let Err(error) = validate_park_cheap_fields(domain, request_id, idempotency_key) {
        return Ok(Response::failure(
            PARK_OPERATION,
            ErrorCode::InvalidInput,
            park_request_error_message(error),
        ));
    }

    let maintenance_content = match read_content_file(content_file) {
        Ok(content) => content,
        Err(ContentFileError::TooLarge) => {
            return Ok(Response::failure(
                PARK_OPERATION,
                ErrorCode::InvalidInput,
                park_request_error_message(ParkRequestError::ContentTooLarge),
            ));
        }
        Err(ContentFileError::Unreadable) => {
            return Ok(Response::failure(
                PARK_OPERATION,
                ErrorCode::InvalidInput,
                "content-file could not be read",
            ));
        }
    };

    let request = match ParkRequest::parse(domain, maintenance_content, request_id, idempotency_key)
    {
        Ok(request) => request,
        Err(error) => {
            return Ok(Response::failure(
                PARK_OPERATION,
                ErrorCode::InvalidInput,
                park_request_error_message(error),
            ));
        }
    };

    #[cfg(unix)]
    {
        run_park(&request)
    }
    #[cfg(not(unix))]
    {
        let _ = request;
        Ok(Response::failure(
            PARK_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "ingress.park requires a Unix host",
        ))
    }
}

#[cfg(unix)]
fn run_park(request: &ParkRequest) -> Result<Response, ResponseBuildError> {
    use std::path::Path;

    use crate::{compose, config::EngineConfig, filesystem::ManagedRoot};

    let engine_config = match EngineConfig::load_root_owned(Path::new(CONFIG_PATH)) {
        Ok(config) => config,
        Err(_) => {
            return Ok(Response::failure(
                PARK_OPERATION,
                ErrorCode::Internal,
                crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
            ));
        }
    };
    let engine_state = match ManagedRoot::open(&engine_config.state_root) {
        Ok(root) => root,
        Err(_) => {
            return Ok(Response::failure(
                PARK_OPERATION,
                ErrorCode::Internal,
                "engine state root is unavailable",
            ));
        }
    };
    let compose_access = compose::Access::default();
    let context = ActivateContext {
        ingress_root: &engine_config.ingress_root,
        engine_state: &engine_state,
        compose: &compose_access,
    };

    match execute_park(&context, request, &CancellationToken::default()) {
        Ok(result) => Response::success(PARK_OPERATION, result),
        Err(ParkError::PostCommitRecordFailed { result, .. }) => {
            Response::success(PARK_OPERATION, result).map(|response| {
                response.with_warnings(vec![Warning {
                    code: WarningCode::TransactionRecordIncomplete,
                    message: "the domain was parked but its transaction record could not be \
                              saved"
                        .to_owned(),
                }])
            })
        }
        Err(error) => {
            let (code, message) = error.protocol();
            Ok(Response::failure(PARK_OPERATION, code, &message))
        }
    }
}

fn unpark(
    domain: &str,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    // `UnparkRequest` has no content field — nothing here reads an
    // arbitrary host path, so there is no cheap-fields-first split to make:
    // `UnparkRequest::parse` is the single validation pass.
    let request = match UnparkRequest::parse(domain, request_id, idempotency_key) {
        Ok(request) => request,
        Err(error) => {
            return Ok(Response::failure(
                UNPARK_OPERATION,
                ErrorCode::InvalidInput,
                unpark_request_error_message(error),
            ));
        }
    };

    #[cfg(unix)]
    {
        run_unpark(&request)
    }
    #[cfg(not(unix))]
    {
        let _ = request;
        Ok(Response::failure(
            UNPARK_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "ingress.unpark requires a Unix host",
        ))
    }
}

#[cfg(unix)]
fn run_unpark(request: &UnparkRequest) -> Result<Response, ResponseBuildError> {
    use std::path::Path;

    use crate::{compose, config::EngineConfig, filesystem::ManagedRoot};

    let engine_config = match EngineConfig::load_root_owned(Path::new(CONFIG_PATH)) {
        Ok(config) => config,
        Err(_) => {
            return Ok(Response::failure(
                UNPARK_OPERATION,
                ErrorCode::Internal,
                crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
            ));
        }
    };
    let engine_state = match ManagedRoot::open(&engine_config.state_root) {
        Ok(root) => root,
        Err(_) => {
            return Ok(Response::failure(
                UNPARK_OPERATION,
                ErrorCode::Internal,
                "engine state root is unavailable",
            ));
        }
    };
    let compose_access = compose::Access::default();
    let context = ActivateContext {
        ingress_root: &engine_config.ingress_root,
        engine_state: &engine_state,
        compose: &compose_access,
    };

    match execute_unpark(&context, request, &CancellationToken::default()) {
        Ok(result) => Response::success(UNPARK_OPERATION, result),
        Err(UnparkError::PostCommitRecordFailed { result, .. }) => {
            Response::success(UNPARK_OPERATION, result).map(|response| {
                response.with_warnings(vec![Warning {
                    code: WarningCode::TransactionRecordIncomplete,
                    message: "the domain was unparked but its transaction record could not be \
                              saved"
                        .to_owned(),
                }])
            })
        }
        Err(error) => {
            let (code, message) = error.protocol();
            Ok(Response::failure(UNPARK_OPERATION, code, &message))
        }
    }
}

fn reconcile(
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    let request = match ReconcileRequest::parse(request_id, idempotency_key) {
        Ok(request) => request,
        Err(error) => {
            return Ok(Response::failure(
                RECONCILE_OPERATION,
                ErrorCode::InvalidInput,
                reconcile_request_error_message(error),
            ));
        }
    };

    #[cfg(unix)]
    {
        run_reconcile(&request)
    }
    #[cfg(not(unix))]
    {
        let _ = request;
        Ok(Response::failure(
            RECONCILE_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "ingress.reconcile requires a Unix host",
        ))
    }
}

#[cfg(unix)]
fn run_reconcile(request: &ReconcileRequest) -> Result<Response, ResponseBuildError> {
    use std::path::Path;

    use crate::{config::EngineConfig, filesystem::ManagedRoot};

    let engine_config = match EngineConfig::load_root_owned(Path::new(CONFIG_PATH)) {
        Ok(config) => config,
        Err(_) => {
            return Ok(Response::failure(
                RECONCILE_OPERATION,
                ErrorCode::Internal,
                crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
            ));
        }
    };
    let engine_state = match ManagedRoot::open(&engine_config.state_root) {
        Ok(root) => root,
        Err(_) => {
            return Ok(Response::failure(
                RECONCILE_OPERATION,
                ErrorCode::Internal,
                "engine state root is unavailable",
            ));
        }
    };
    let context = ReconcileContext {
        ingress_root: &engine_config.ingress_root,
        engine_state: &engine_state,
    };

    match execute_reconcile(&context, request, &CancellationToken::default()) {
        Ok(result) => Response::success(RECONCILE_OPERATION, result),
        Err(ReconcileError::PostCommitRecordFailed { result, .. }) => {
            Response::success(RECONCILE_OPERATION, result).map(|response| {
                response.with_warnings(vec![Warning {
                    code: WarningCode::TransactionRecordIncomplete,
                    message: "the sweep completed but its transaction record could not be saved"
                        .to_owned(),
                }])
            })
        }
        Err(error) => {
            let (code, message) = error.protocol();
            Ok(Response::failure(RECONCILE_OPERATION, code, &message))
        }
    }
}

fn reconcile_request_error_message(error: ReconcileRequestError) -> &'static str {
    match error {
        ReconcileRequestError::InvalidRequestId => "request-id is not a canonical UUID",
        ReconcileRequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}

/// Validates `domain`, `request_id`, and `idempotency_key` — every field
/// `ActivateConfigRequest::parse` checks that does not depend on the
/// content file's bytes — using the same underlying parsers it uses, so a
/// malformed request is rejected before `content_file` is ever read.
fn validate_cheap_fields(
    domain: &str,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<(), ActivateConfigRequestError> {
    Domain::parse(domain).map_err(|_| ActivateConfigRequestError::InvalidDomain)?;
    RequestId::parse(request_id).map_err(|_| ActivateConfigRequestError::InvalidRequestId)?;
    if let Some(key) = idempotency_key {
        IdempotencyKey::parse(key)
            .map_err(|_| ActivateConfigRequestError::InvalidIdempotencyKey)?;
    }
    Ok(())
}

/// Validates `domain`, `request_id`, and `idempotency_key` — every field
/// `ParkRequest::parse` checks that does not depend on the content file's
/// bytes — using the same underlying parsers it uses, so a malformed
/// request is rejected before `content_file` is ever read. Mirrors
/// `validate_cheap_fields` above, returning `ParkRequestError` instead.
fn validate_park_cheap_fields(
    domain: &str,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<(), ParkRequestError> {
    Domain::parse(domain).map_err(|_| ParkRequestError::InvalidDomain)?;
    RequestId::parse(request_id).map_err(|_| ParkRequestError::InvalidRequestId)?;
    if let Some(key) = idempotency_key {
        IdempotencyKey::parse(key).map_err(|_| ParkRequestError::InvalidIdempotencyKey)?;
    }
    Ok(())
}

/// Maps the CLI-facing `--target` value to the domain `RouteTarget` it
/// selects. Kept separate from `IngressTarget` itself the same way
/// `guard_from_expected_hash` keeps the raw `Option<&str>` the CLI receives
/// apart from `HashGuard`, the domain type `ActivateConfigRequest::parse`
/// actually consumes.
const fn route_target(target: IngressTarget) -> RouteTarget {
    match target {
        IngressTarget::Live => RouteTarget::Live,
        IngressTarget::Backup => RouteTarget::Backup,
    }
}

fn activate_config_request_error_message(error: ActivateConfigRequestError) -> &'static str {
    match error {
        ActivateConfigRequestError::InvalidDomain => "domain is not a valid domain name",
        ActivateConfigRequestError::ContentTooLarge => {
            "content-file exceeds the maximum allowed route file size"
        }
        ActivateConfigRequestError::InvalidExpectedHash => {
            "expected-hash is not a valid SHA-256 digest"
        }
        ActivateConfigRequestError::InvalidRequestId => "request-id is not a canonical UUID",
        ActivateConfigRequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}

fn park_request_error_message(error: ParkRequestError) -> &'static str {
    match error {
        ParkRequestError::InvalidDomain => "domain is not a valid domain name",
        ParkRequestError::ContentTooLarge => {
            "content-file exceeds the maximum allowed route file size"
        }
        ParkRequestError::InvalidRequestId => "request-id is not a canonical UUID",
        ParkRequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}

fn unpark_request_error_message(error: UnparkRequestError) -> &'static str {
    match error {
        UnparkRequestError::InvalidDomain => "domain is not a valid domain name",
        UnparkRequestError::InvalidRequestId => "request-id is not a canonical UUID",
        UnparkRequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::route_target;
    use crate::{
        cli::{Cli, Command, IngressCommand, IngressTarget},
        ingress::{ActivateConfigRequest, HashGuard, RouteTarget},
    };

    fn parse_activate_config_target(args: &[&str]) -> IngressTarget {
        let mut full_args = vec!["ops-engine"];
        full_args.extend_from_slice(args);
        let cli = Cli::try_parse_from(full_args).expect("cli args should parse");
        match cli.command {
            Command::Ingress {
                command: IngressCommand::ActivateConfig { target, .. },
            } => target,
            other => panic!("expected an ingress activate-config command, got {other:?}"),
        }
    }

    #[test]
    fn target_backup_flag_parses_into_a_backup_route_target_on_the_request() {
        let target = parse_activate_config_target(&[
            "ingress",
            "activate-config",
            "--domain",
            "example.com",
            "--content-file",
            "route.caddyfile",
            "--request-id",
            "123e4567-e89b-12d3-a456-426614174000",
            "--target",
            "backup",
        ]);
        assert_eq!(target, IngressTarget::Backup);

        let request = ActivateConfigRequest::parse(
            "example.com",
            "example.com {\n}\n",
            HashGuard::Absent,
            route_target(target),
            "123e4567-e89b-12d3-a456-426614174000",
            None,
        )
        .expect("request should parse");
        assert_eq!(request.target, RouteTarget::Backup);
    }

    #[test]
    fn omitting_target_defaults_to_a_live_route_target_on_the_request() {
        let target = parse_activate_config_target(&[
            "ingress",
            "activate-config",
            "--domain",
            "example.com",
            "--content-file",
            "route.caddyfile",
            "--request-id",
            "123e4567-e89b-12d3-a456-426614174000",
        ]);
        assert_eq!(target, IngressTarget::Live);

        let request = ActivateConfigRequest::parse(
            "example.com",
            "example.com {\n}\n",
            HashGuard::Absent,
            route_target(target),
            "123e4567-e89b-12d3-a456-426614174000",
            None,
        )
        .expect("request should parse");
        assert_eq!(request.target, RouteTarget::Live);
    }
}
