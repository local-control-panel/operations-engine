use crate::{
    cli::{IngressCommand, IngressTarget},
    error::{ErrorCode, WarningCode},
    ingress::{
        ActivateConfigRequest, ActivateConfigRequestError, MAX_CONTENT_BYTES,
        OPERATION as ACTIVATE_OPERATION, PARK_OPERATION, ParkRequest, ParkRequestError,
        RouteTarget, UNPARK_OPERATION, UnparkRequest, UnparkRequestError,
        execute::{ActivateConfigError, ActivateContext, execute as execute_activate_config},
        park::{ParkError, execute as execute_park},
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

/// Why `--content-file` could not be turned into submittable content.
/// Deliberately coarse: the caller is told "unreadable" for a missing
/// file, a FIFO, a directory, a device node, and a permission error alike,
/// because which one it was is a property of the host's filesystem rather
/// than of the request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContentFileError {
    Unreadable,
    TooLarge,
}

/// Reads the submitted route file from `path`.
///
/// `--content-file` is the only field in this engine's whole request
/// surface that names an arbitrary host path — everything else selects a
/// root-owned manifest or a site-relative path resolved through a trusted
/// root (`docs/site-model.md`). It is therefore also the only place where
/// "read the file the caller named" has to be written defensively rather
/// than delegated to `ManagedRoot`, because this process is root and the
/// path is not resolved through any root at all:
///
/// - the path must name a **regular file**. A FIFO would otherwise block
///   this root process in `read` until something on the other end wrote or
///   closed it — indefinitely, while holding nothing back but also
///   finishing nothing; a directory or a device node (`/dev/zero`,
///   `/dev/urandom`) would be read as content.
/// - the read is **bounded at `MAX_CONTENT_BYTES + 1`**. The extra byte is
///   what distinguishes "exactly at the bound" from "over it" without ever
///   holding more than 256 KiB + 1 in memory. `ActivateConfigRequest::parse`
///   enforces the same bound again, but it can only do so *after* the read;
///   an unbounded read of `/dev/zero` never reaches it.
///
/// The metadata check races with the open in principle. It is done through
/// the already-open handle (`File::metadata`, i.e. `fstat` on this
/// descriptor) rather than on the path, so what is checked is exactly what
/// is read — a path swapped after the open cannot change the verdict.
///
/// The open itself is `O_NONBLOCK` (`OpenOptionsExt::custom_flags`), which
/// is the part that actually keeps a FIFO from blocking this root process:
/// a blocking `open()` of a FIFO's read end waits for a writer to show up
/// *before returning at all*, so the regular-file check below would never
/// even run — the metadata check alone does not close this, only a
/// non-blocking open does. `O_NONBLOCK` has no effect on a regular file's
/// `read`, so the flag is dropped once the type check passes; nothing
/// downstream needs to know it was ever set.
///
/// What this deliberately still does *not* do is require the path to
/// resolve under a trusted root. That would be strictly better — it is how
/// every other path here is handled — but it needs a configured staging
/// root, hence a config-schema bump and a coordinated client change, so it
/// is recorded as a follow-up in `docs/site-model.md` rather than done
/// under this fix.
fn read_content_file(path: &std::path::Path) -> Result<String, ContentFileError> {
    use std::io::Read as _;

    let file = open_content_file(path).map_err(|_| ContentFileError::Unreadable)?;
    let metadata = file.metadata().map_err(|_| ContentFileError::Unreadable)?;
    if !metadata.is_file() {
        return Err(ContentFileError::Unreadable);
    }

    let mut content = String::new();
    let read = file
        .take(MAX_CONTENT_BYTES as u64 + 1)
        .read_to_string(&mut content)
        .map_err(|_| ContentFileError::Unreadable)?;
    if read > MAX_CONTENT_BYTES {
        return Err(ContentFileError::TooLarge);
    }
    Ok(content)
}

/// Opens `path` non-blocking, so a FIFO's read end returns immediately
/// instead of waiting for a writer — see `read_content_file`'s doc comment.
/// `O_NONBLOCK` is Unix-specific; on any other platform this operation is
/// already rejected before `run_activate_config` runs (`activate_config`'s
/// `#[cfg(not(unix))]` arm), so a plain blocking open is fine here too.
#[cfg(unix)]
fn open_content_file(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(unix))]
fn open_content_file(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
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

    use super::{ContentFileError, read_content_file, route_target};
    use crate::{
        cli::{Cli, Command, IngressCommand, IngressTarget},
        ingress::{ActivateConfigRequest, HashGuard, MAX_CONTENT_BYTES, RouteTarget},
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

    #[test]
    fn a_regular_file_at_or_under_the_bound_is_read_verbatim() {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let path = directory.path().join("route.caddyfile");

        std::fs::write(&path, "example.com {\n}\n").expect("content should be written");
        assert_eq!(
            read_content_file(&path).expect("a small regular file should be read"),
            "example.com {\n}\n"
        );

        // Exactly at the bound is accepted, matching
        // `ActivateConfigRequest::parse`'s own boundary: the +1 byte the
        // read takes exists to detect "over", not to reject "at".
        std::fs::write(&path, "x".repeat(MAX_CONTENT_BYTES)).expect("content should be written");
        assert_eq!(
            read_content_file(&path)
                .expect("content at exactly the bound should be read")
                .len(),
            MAX_CONTENT_BYTES
        );
    }

    /// The bound is enforced *during* the read, so one byte over is
    /// reported as too large rather than being read in full and rejected
    /// afterward.
    #[test]
    fn one_byte_over_the_bound_is_rejected() {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let path = directory.path().join("route.caddyfile");
        std::fs::write(&path, "x".repeat(MAX_CONTENT_BYTES + 1))
            .expect("content should be written");

        assert_eq!(read_content_file(&path), Err(ContentFileError::TooLarge));
    }

    #[test]
    fn a_missing_path_and_a_directory_are_both_unreadable() {
        let directory = tempfile::tempdir().expect("temporary directory should exist");

        assert_eq!(
            read_content_file(&directory.path().join("absent.caddyfile")),
            Err(ContentFileError::Unreadable)
        );
        // A directory opens successfully on Unix; only the regular-file
        // check rejects it.
        assert_eq!(
            read_content_file(directory.path()),
            Err(ContentFileError::Unreadable)
        );
    }

    /// The two host paths a root process must never be pointed at by a
    /// remote caller: an endless character device (an unbounded read that
    /// never returns EOF) and a FIFO with no writer (a read that blocks
    /// forever). Both are rejected on the regular-file check, before a
    /// single byte is read — which is why this test can afford to name
    /// `/dev/zero` at all.
    #[cfg(unix)]
    #[test]
    fn an_endless_device_and_a_fifo_are_rejected_without_being_read() {
        let zero = std::path::Path::new("/dev/zero");
        if zero.exists() {
            assert_eq!(
                read_content_file(zero),
                Err(ContentFileError::Unreadable),
                "/dev/zero must be rejected as a non-regular file, not read"
            );
        }

        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let fifo = directory.path().join("route.caddyfile");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if made {
            // No writer is ever opened. A blocking `open()` of this FIFO's
            // read end would hang right here, before a single byte is
            // read or the regular-file check runs at all — proving the
            // open itself must be non-blocking, not just the read.
            assert_eq!(read_content_file(&fifo), Err(ContentFileError::Unreadable));
        }
    }
}
