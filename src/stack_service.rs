//! `stack.reloadCaddy` and `stack.stopIdleRuntime`: the two container
//! mutations the control panel used to run over raw SSH against the managed
//! WCP Compose project (`docker compose exec -T <service> caddy reload` and
//! `docker compose stop runtime-<id>`).
//!
//! Both take the shared `stacks/wcp` lock (milestone 048) as their outermost
//! lock, so neither can land in a container that `stack.deploy`'s `up -d`
//! is recreating, and both record a transaction and an audit entry in their
//! own `stack-service` scope like every other engine mutation.
//!
//! The commands are fixed argv. The caller picks only which service: the
//! ingress or one runtime pool. `stack.stopIdleRuntime` refuses to stop a
//! pool that still has a site's exec config under `runtime_root/<id>/` and
//! reports `stopped: false` instead, so a stale panel view cannot take a
//! pool down under a live site.

use std::{
    io,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{
    compose::COMPOSE_PROJECT,
    error::ErrorCode,
    filesystem::ManagedRoot,
    ingress::{LIVE_CONFIG_PATH, ROUTE_EXTENSION},
    mutation::preflight,
    process::{
        self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination,
        SubprocessDiagnostics,
    },
    site::{RuntimeId, SiteRelativePath, TrustedRoot},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        state::{self, TransactionState, TransactionStatus},
    },
};

pub const RELOAD_OPERATION: &str = "stack.reloadCaddy";
pub const STOP_OPERATION: &str = "stack.stopIdleRuntime";

/// Engine-state scope for both operations. Separate from `stacks/wcp`,
/// whose own preflight lock *is* the shared stack lock.
const SCOPE: &str = "stack-service";

/// The one ingress Compose service (`images/stack/docker-compose.v2.yml`).
pub const INGRESS_SERVICE: &str = "ingress";

/// Same bound `compose::exec` uses for an in-container `caddy reload`.
const RELOAD_TIMEOUT: Duration = Duration::from_secs(30);

/// `docker compose stop` waits up to 10 s per container before it kills;
/// the rest is Compose's own start-up and the API round trips.
const STOP_TIMEOUT: Duration = Duration::from_secs(60);

const MAX_OUTPUT_BYTES: usize = 64 * 1024;

/// A Compose service in the managed stack that runs Caddy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Service {
    Ingress,
    Runtime(RuntimeId),
}

impl Service {
    /// Accepts exactly `ingress` or `runtime-<runtime id>`.
    pub fn parse(value: &str) -> Option<Self> {
        if value == INGRESS_SERVICE {
            return Some(Self::Ingress);
        }
        let runtime_id = value.strip_prefix("runtime-")?;
        RuntimeId::parse(runtime_id).ok().map(Self::Runtime)
    }

    pub fn name(&self) -> String {
        match self {
            Self::Ingress => INGRESS_SERVICE.to_owned(),
            Self::Runtime(runtime_id) => runtime_service(runtime_id),
        }
    }
}

fn runtime_service(runtime_id: &RuntimeId) -> String {
    format!("runtime-{runtime_id}")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidService,
    InvalidRuntimeId,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl RequestError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidService => "service must be ingress or runtime-<runtime id>",
            Self::InvalidRuntimeId => "runtime-id is not a valid runtime pool identifier",
            Self::InvalidRequestId => "request-id is not a canonical UUID",
            Self::InvalidIdempotencyKey => "idempotency-key is invalid",
        }
    }
}

fn parse_ids(
    request_id: &str,
    key: Option<&str>,
) -> Result<(RequestId, Option<IdempotencyKey>), RequestError> {
    Ok((
        RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
        key.map(IdempotencyKey::parse)
            .transpose()
            .map_err(|_| RequestError::InvalidIdempotencyKey)?,
    ))
}

pub struct ReloadRequest {
    pub service: Service,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl ReloadRequest {
    pub fn parse(service: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let service = Service::parse(service).ok_or(RequestError::InvalidService)?;
        let (request_id, idempotency_key) = parse_ids(request_id, key)?;
        Ok(Self {
            service,
            request_id,
            idempotency_key,
        })
    }
}

pub struct StopRequest {
    pub runtime_id: RuntimeId,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl StopRequest {
    pub fn parse(
        runtime_id: &str,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let runtime_id =
            RuntimeId::parse(runtime_id).map_err(|_| RequestError::InvalidRuntimeId)?;
        let (request_id, idempotency_key) = parse_ids(request_id, key)?;
        Ok(Self {
            runtime_id,
            request_id,
            idempotency_key,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReloadResult {
    pub service: String,
    pub reloaded_at_unix_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StopResult {
    pub runtime_id: String,
    pub service: String,
    /// `false` when the pool still had site configs and was left running.
    pub stopped: bool,
    /// How many `*.caddyfile` exec configs the pool's directory held.
    pub site_configs: usize,
    pub completed_at_unix_secs: u64,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    /// `EngineConfig::runtime_root`; one subdirectory per runtime pool.
    pub runtime_root: &'a TrustedRoot,
    /// The managed stack directory (`~/compose/wp-stack`).
    pub stack_dir: &'a Path,
    /// `docker` in production; a fixture path in tests.
    pub docker: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    Reload,
    Stop,
}

impl Stage {
    const fn message(self) -> &'static str {
        match self {
            Self::Reload => "the Caddy reload failed",
            Self::Stop => "the runtime pool could not be stopped",
        }
    }
}

#[derive(Debug)]
pub enum Error {
    /// Another operation holds the shared `stacks/wcp` lock. Nothing ran.
    StackBusy,
    Io(io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Run(Stage, process::ProcessRunError),
    Rejected(Stage, SubprocessDiagnostics),
    PostCommit(serde_json::Value),
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::StackBusy => (
                ErrorCode::Conflict,
                "another operation on the wcp stack is in progress".into(),
            ),
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another stack service operation is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Run(stage, error) => (process::spawn_error_code(error), stage.message().into()),
            Self::Rejected(stage, diagnostics) => (
                if diagnostics.timed_out {
                    ErrorCode::Timeout
                } else if diagnostics.cancelled {
                    ErrorCode::Cancelled
                } else if *stage == Stage::Reload {
                    ErrorCode::ConfigReloadFailed
                } else {
                    ErrorCode::SubprocessFailed
                },
                stage.message().into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit(_) => {
                (ErrorCode::Internal, "internal stack service error".into())
            }
        }
    }
}

pub fn reload(
    ctx: &Context<'_>,
    req: &ReloadRequest,
    cancel: &CancellationToken,
) -> Result<ReloadResult, Error> {
    run_admitted(
        ctx,
        RELOAD_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        || {
            let service = req.service.name();
            compose(
                ctx,
                Stage::Reload,
                &[
                    "exec",
                    "-T",
                    &service,
                    "caddy",
                    "reload",
                    "--config",
                    LIVE_CONFIG_PATH,
                    "--adapter",
                    "caddyfile",
                ],
                RELOAD_TIMEOUT,
                cancel,
            )?;
            Ok(ReloadResult {
                service,
                reloaded_at_unix_secs: unix_now_secs(),
            })
        },
    )
}

pub fn stop_idle_runtime(
    ctx: &Context<'_>,
    req: &StopRequest,
    cancel: &CancellationToken,
) -> Result<StopResult, Error> {
    run_admitted(
        ctx,
        STOP_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        || {
            let service = runtime_service(&req.runtime_id);
            let site_configs = count_site_configs(ctx.runtime_root, &req.runtime_id)?;
            if site_configs == 0 {
                compose(ctx, Stage::Stop, &["stop", &service], STOP_TIMEOUT, cancel)?;
            }
            Ok(StopResult {
                runtime_id: req.runtime_id.as_str().to_owned(),
                service,
                stopped: site_configs == 0,
                site_configs,
                completed_at_unix_secs: unix_now_secs(),
            })
        },
    )
}

/// Live exec configs in `runtime_root/<runtime id>/`. Staging and rollback
/// files (`.tmp`, `.rollback-*`) are not imported by the pool's Caddy and do
/// not count. A missing directory means no configs.
fn count_site_configs(runtime_root: &TrustedRoot, runtime_id: &RuntimeId) -> Result<usize, Error> {
    let root = ManagedRoot::open(runtime_root).map_err(Error::Io)?;
    let relative = SiteRelativePath::parse(runtime_id.as_str())
        .expect("a validated RuntimeId is a valid relative path");
    let pool_dir = match root.open_managed_dir(&relative) {
        Ok(dir) => dir,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(Error::Io(error)),
    };
    let suffix = format!(".{ROUTE_EXTENSION}");
    Ok(pool_dir
        .file_names()
        .map_err(Error::Io)?
        .iter()
        .filter(|name| name.ends_with(&suffix) && name.len() > suffix.len())
        .count())
}

fn compose(
    ctx: &Context<'_>,
    stage: Stage,
    tail: &[&str],
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let mut argv = vec![
        "compose",
        "-p",
        COMPOSE_PROJECT,
        "--env-file",
        ".env",
        "-f",
        "stack/docker-compose.yml",
    ];
    argv.extend_from_slice(tail);
    let output = process::run(
        &ProcessRequest::new(ctx.docker)
            .args(argv)
            .current_dir(ctx.stack_dir),
        &ProcessLimits {
            timeout,
            max_stdout_bytes: MAX_OUTPUT_BYTES,
            max_stderr_bytes: MAX_OUTPUT_BYTES,
        },
        cancel,
    )
    .map_err(|error| Error::Run(stage, error))?;
    if !matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        return Err(Error::Rejected(
            stage,
            SubprocessDiagnostics::from_output(ctx.docker, &output),
        ));
    }
    Ok(())
}

/// Stack lock, then this scope's preflight (lock + idempotency), then
/// `body`, then the transaction record and audit entry.
fn run_admitted<T, F>(
    ctx: &Context<'_>,
    operation: &'static str,
    request_id: RequestId,
    key: Option<&IdempotencyKey>,
    body: F,
) -> Result<T, Error>
where
    T: Serialize + for<'de> Deserialize<'de>,
    F: FnOnce() -> Result<T, Error>,
{
    let scope = open_scope(ctx.engine_state).map_err(Error::Io)?;
    let stack_scope = crate::stack_deploy::open_scope(ctx.engine_state).map_err(Error::Io)?;
    let _stack_lock = crate::stack_deploy::acquire_stack_lock(&stack_scope, request_id)
        .map_err(|_| Error::StackBusy)?;

    let admitted =
        match preflight::run(&scope, request_id, key, operation).map_err(Error::Preflight)? {
            preflight::Outcome::Replay(original) => return replay(&scope, operation, original),
            preflight::Outcome::Proceed(admitted) => admitted,
        };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path = transaction_path(request_id);
    let audit_path = rel("audit/events.jsonl");

    let value = match body() {
        Ok(value) => value,
        Err(error) => return Err(fail(&scope, &state_path, &audit_path, state, error)),
    };

    let encoded = serde_json::to_value(&value).expect("operation results always serialize");
    state
        .mark_committed(encoded.clone())
        .expect("state is always InProgress at this point");
    if state::save(&scope, &state_path, &state).is_err() {
        drop(lock);
        return Err(Error::PostCommit(encoded));
    }
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(request_id, true, None),
    );
    drop(lock);
    Ok(value)
}

fn open_scope(engine_state: &ManagedRoot) -> io::Result<ManagedRoot> {
    engine_state.create_dir_all(&rel(SCOPE))?;
    let scope = engine_state.open_managed_dir(&rel(SCOPE))?;
    for child in ["locks", "transactions", "audit"] {
        scope.create_dir_all(&rel(child))?;
    }
    Ok(scope)
}

fn replay<T>(scope: &ManagedRoot, operation: &'static str, original: RequestId) -> Result<T, Error>
where
    T: for<'de> Deserialize<'de>,
{
    let loaded = state::load(scope, &transaction_path(original))
        .map_err(|error| Error::Io(io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != operation {
        return Err(Error::Io(io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => loaded
            .outcome
            .and_then(|outcome| outcome.result)
            .ok_or_else(|| Error::Io(io::Error::other("committed outcome has no result")))
            .and_then(|value| {
                serde_json::from_value(value).map_err(|error| Error::Io(io::Error::other(error)))
            }),
        TransactionStatus::Failed => {
            let outcome = loaded
                .outcome
                .expect("a failed transaction always has an outcome");
            Err(Error::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}

fn fail(
    scope: &ManagedRoot,
    state_path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut state: TransactionState,
    error: Error,
) -> Error {
    let (code, message) = error.protocol();
    let _ = state.mark_failed(code, message);
    let _ = state::save(scope, state_path, &state);
    let _ = audit::append(
        scope,
        audit_path,
        &AuditRecord::result(state.request_id, false, Some(code)),
    );
    error
}

fn transaction_path(request_id: RequestId) -> SiteRelativePath {
    rel(&format!("transactions/{request_id}.json"))
}

fn rel(path: &str) -> SiteRelativePath {
    SiteRelativePath::parse(path).expect("literal path is valid")
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(all(test, unix))]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, sync::Mutex};

    use super::*;

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const OTHER_ID: &str = "123e4567-e89b-12d3-a456-426614174001";

    /// Fork-heavy fixture tests share flock state with forked children;
    /// serialize them like `tests/deploy.rs` does.
    static SERIAL: Mutex<()> = Mutex::new(());

    struct Fixture {
        _dir: tempfile::TempDir,
        state: ManagedRoot,
        runtime_root: TrustedRoot,
        stack_dir: PathBuf,
        docker: String,
        calls: PathBuf,
    }

    impl Fixture {
        fn new(exit: i32) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path().canonicalize().unwrap();
            for sub in ["state", "runtimes", "stack"] {
                fs::create_dir(base.join(sub)).unwrap();
            }
            let calls = base.join("calls.log");
            let docker = base.join("docker");
            fs::write(
                &docker,
                format!(
                    "#!/bin/sh\necho \"$(pwd) $*\" >> '{}'\nexit {exit}\n",
                    calls.display()
                ),
            )
            .unwrap();
            fs::set_permissions(&docker, fs::Permissions::from_mode(0o755)).unwrap();
            Self {
                state: ManagedRoot::open(&TrustedRoot::parse(base.join("state")).unwrap()).unwrap(),
                runtime_root: TrustedRoot::parse(base.join("runtimes")).unwrap(),
                stack_dir: base.join("stack"),
                docker: docker.to_string_lossy().into_owned(),
                calls,
                _dir: dir,
            }
        }

        fn ctx(&self) -> Context<'_> {
            Context {
                engine_state: &self.state,
                runtime_root: &self.runtime_root,
                stack_dir: &self.stack_dir,
                docker: &self.docker,
            }
        }

        fn calls(&self) -> Vec<String> {
            fs::read_to_string(&self.calls)
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect()
        }

        fn site_config(&self, runtime_id: &str, name: &str) {
            let dir = self.runtime_root.as_path().join(runtime_id);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join(name), "example.com {\n}\n").unwrap();
        }
    }

    fn compose_prefix(fixture: &Fixture) -> String {
        format!(
            "{} compose -p wcp --env-file .env -f stack/docker-compose.yml",
            fixture.stack_dir.display()
        )
    }

    #[test]
    fn service_accepts_only_ingress_or_a_runtime_pool() {
        assert_eq!(Service::parse("ingress"), Some(Service::Ingress));
        assert_eq!(
            Service::parse("runtime-fp1-php83").map(|s| s.name()),
            Some("runtime-fp1-php83".to_owned())
        );
        for bad in [
            "",
            "mariadb",
            "runtime-",
            "runtime-FP1",
            "runtime-../x",
            "runtime--x",
            "ingress ",
        ] {
            assert_eq!(Service::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn reload_runs_the_fixed_caddy_reload_in_the_stack_directory_once() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new(0);
        let req = ReloadRequest::parse("runtime-fp1-php83", ID, Some("reload-1")).unwrap();

        let result = reload(&fixture.ctx(), &req, &CancellationToken::default()).unwrap();
        assert_eq!(result.service, "runtime-fp1-php83");
        // A retried request replays the outcome without reloading twice.
        reload(&fixture.ctx(), &req, &CancellationToken::default()).unwrap();

        assert_eq!(
            fixture.calls(),
            vec![format!(
                "{} exec -T runtime-fp1-php83 caddy reload --config /etc/caddy/Caddyfile \
                 --adapter caddyfile",
                compose_prefix(&fixture)
            )]
        );
    }

    #[test]
    fn a_rejected_reload_is_a_reload_failure_and_replays_as_one() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new(1);
        let req = ReloadRequest::parse("ingress", ID, Some("reload-2")).unwrap();

        let error = reload(&fixture.ctx(), &req, &CancellationToken::default()).unwrap_err();
        assert!(matches!(error, Error::Rejected(Stage::Reload, _)));
        assert_eq!(error.protocol().0, ErrorCode::ConfigReloadFailed);
        let replayed = reload(&fixture.ctx(), &req, &CancellationToken::default()).unwrap_err();
        assert!(matches!(
            replayed,
            Error::Replayed {
                code: ErrorCode::ConfigReloadFailed,
                ..
            }
        ));
        assert_eq!(fixture.calls().len(), 1);
    }

    #[test]
    fn a_held_stack_lock_blocks_a_reload_before_docker_runs() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new(0);
        let stack_scope = crate::stack_deploy::open_scope(&fixture.state).unwrap();
        let _held = crate::stack_deploy::acquire_stack_lock(
            &stack_scope,
            RequestId::parse(OTHER_ID).unwrap(),
        )
        .unwrap();

        let req = ReloadRequest::parse("ingress", ID, None).unwrap();
        let error = reload(&fixture.ctx(), &req, &CancellationToken::default()).unwrap_err();
        assert!(matches!(error, Error::StackBusy));
        assert_eq!(error.protocol().0, ErrorCode::Conflict);
        assert!(fixture.calls().is_empty());
    }

    #[test]
    fn stop_stops_a_pool_with_no_site_configs() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new(0);
        // Leftover staging/rollback files do not keep a pool alive.
        fixture.site_config("fp1-php84", "example.com.caddyfile.tmp");
        fixture.site_config("fp1-php84", "example.com.caddyfile.rollback-x");
        let req = StopRequest::parse("fp1-php84", ID, None).unwrap();

        let result =
            stop_idle_runtime(&fixture.ctx(), &req, &CancellationToken::default()).unwrap();
        assert!(result.stopped);
        assert_eq!(result.site_configs, 0);
        assert_eq!(
            fixture.calls(),
            vec![format!(
                "{} stop runtime-fp1-php84",
                compose_prefix(&fixture)
            )]
        );
    }

    #[test]
    fn stop_treats_a_missing_pool_directory_as_idle() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new(0);
        let req = StopRequest::parse("fp1-php84", ID, None).unwrap();

        let result =
            stop_idle_runtime(&fixture.ctx(), &req, &CancellationToken::default()).unwrap();
        assert!(result.stopped);
        assert_eq!(fixture.calls().len(), 1);
    }

    #[test]
    fn stop_leaves_a_pool_with_a_site_config_running() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new(0);
        fixture.site_config("fp1-php84", "example.com.caddyfile");
        let req = StopRequest::parse("fp1-php84", ID, None).unwrap();

        let result =
            stop_idle_runtime(&fixture.ctx(), &req, &CancellationToken::default()).unwrap();
        assert!(!result.stopped);
        assert_eq!(result.site_configs, 1);
        assert!(fixture.calls().is_empty());
    }

    #[test]
    fn a_failed_stop_is_reported_as_a_subprocess_failure() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new(1);
        let req = StopRequest::parse("fp1-php84", ID, None).unwrap();

        let error =
            stop_idle_runtime(&fixture.ctx(), &req, &CancellationToken::default()).unwrap_err();
        assert!(matches!(error, Error::Rejected(Stage::Stop, _)));
        assert_eq!(error.protocol().0, ErrorCode::SubprocessFailed);
    }

    #[test]
    fn a_held_stack_lock_blocks_a_stop_before_docker_runs() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new(0);
        let stack_scope = crate::stack_deploy::open_scope(&fixture.state).unwrap();
        let _held = crate::stack_deploy::acquire_stack_lock(
            &stack_scope,
            RequestId::parse(OTHER_ID).unwrap(),
        )
        .unwrap();

        let req = StopRequest::parse("fp1-php84", ID, None).unwrap();
        assert!(matches!(
            stop_idle_runtime(&fixture.ctx(), &req, &CancellationToken::default()),
            Err(Error::StackBusy)
        ));
        assert!(fixture.calls().is_empty());
    }

    #[test]
    fn requests_reject_malformed_fields() {
        assert_eq!(
            ReloadRequest::parse("db", ID, None).err(),
            Some(RequestError::InvalidService)
        );
        assert_eq!(
            ReloadRequest::parse("ingress", "nope", None).err(),
            Some(RequestError::InvalidRequestId)
        );
        assert_eq!(
            StopRequest::parse("../x", ID, None).err(),
            Some(RequestError::InvalidRuntimeId)
        );
    }
}
