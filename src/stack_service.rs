//! `stack.reloadCaddy`, `stack.stopIdleRuntime`, `stack.ensureRuntime`,
//! `stack.reloadWorkers` and `stack.flushFpc`: the container mutations the
//! control panel used to run over raw SSH against the managed WCP Compose
//! project (`caddy reload`, `stop runtime-<id>`, `up -d runtime-<id>` plus a
//! health poll, the worker reload and the Souin cache purge).
//!
//! Both take the shared `stacks/wcp` lock (milestone 048) as their outermost
//! lock, so neither can land in a container that `stack.deploy`'s `up -d`
//! is recreating, and both record a transaction and an audit entry in their
//! own `stack-service` scope like every other engine mutation.
//! `stack.ensureRuntime` holds the stack lock through its health wait, so a
//! deploy cannot recreate the pool between `up -d` and `healthy`.
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
    ingress::{ConfigHash, HashGuard, LIVE_CONFIG_PATH, ROUTE_EXTENSION},
    mutation::preflight,
    process::{
        self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination,
        SubprocessDiagnostics,
    },
    site::{Domain, RuntimeId, SiteRelativePath, TrustedRoot},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        state::{self, TransactionState, TransactionStatus},
    },
};

pub const RELOAD_OPERATION: &str = "stack.reloadCaddy";
pub const STOP_OPERATION: &str = "stack.stopIdleRuntime";
pub const ENSURE_OPERATION: &str = "stack.ensureRuntime";
pub const RELOAD_WORKERS_OPERATION: &str = "stack.reloadWorkers";
pub const FLUSH_FPC_OPERATION: &str = "stack.flushFpc";
pub const WRITE_SITE_SERVICE_OPERATION: &str = "stack.writeSiteService";
pub const ACTIVATE_SITE_CONFIG_OPERATION: &str = "stack.activateSiteConfig";
pub const REMOVE_SITE_SERVICE_OPERATION: &str = "stack.removeSiteService";

/// Where each pool sees its own `site_services_root/<runtime id>/` subtree,
/// bind-mounted bare so the path is the same inside every pool. A site's
/// own directory is `SITE_SERVICES_CONTAINER_ROOT/<domain>`; that is the
/// `--config` base its `run` script and every `s6-svc` target use, and the
/// directory `s6-svscanctl -a` rescans.
pub const SITE_SERVICES_CONTAINER_ROOT: &str = "/etc/wcp/site-services";

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

/// `docker compose up -d` for one service may pull nothing but still has to
/// create the container and its network attachments.
const UP_TIMEOUT: Duration = Duration::from_secs(120);

/// One `ps -q` or `docker inspect` round trip during the health wait.
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);

/// `kill -USR2 1` and the cache purge are both instant inside the container.
const SIGNAL_TIMEOUT: Duration = Duration::from_secs(30);

/// PHP workers run in each site's own FrankenPHP child process (`admin off`,
/// supervised by s6 under `/etc/wcp/site-services/<domain>`), not in the
/// pool's main Caddy, and pid 1 is `s6-svscan`. Reloading them means
/// restarting every site service that has a `run` script; a leftover
/// directory without one is skipped.
const RELOAD_WORKERS_SCRIPT: &str = "for d in /etc/wcp/site-services/*/; do \
     [ -f \"${d}run\" ] || continue; s6-svc -r \"$d\" || exit 1; done";

/// Fixed in-container FPC purge: a `PURGE` to Souin plus a wipe of its
/// BadgerDB store, both best-effort, exactly what the panel ran before.
const FLUSH_FPC_SCRIPT: &str =
    "curl -sf -X PURGE http://localhost/ 2>/dev/null; rm -rf /tmp/souin 2>/dev/null; echo ok";

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
    InvalidProfile,
    InvalidRequestId,
    InvalidIdempotencyKey,
    InvalidDomain,
    InvalidPort,
    InvalidPriorHash,
    InvalidIdentity,
}

impl RequestError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidService => "service must be ingress or runtime-<runtime id>",
            Self::InvalidRuntimeId => "runtime-id is not a valid runtime pool identifier",
            Self::InvalidProfile => "profile must be php-<major>.<minor>",
            Self::InvalidRequestId => "request-id is not a canonical UUID",
            Self::InvalidIdempotencyKey => "idempotency-key is invalid",
            Self::InvalidDomain => "domain is not a valid site domain",
            Self::InvalidPort => "port must be a nonzero TCP port",
            Self::InvalidPriorHash => "expected-prior-hash must be 64 hex digits",
            Self::InvalidIdentity => "uid and gid must be site identities (at least 1000)",
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

/// `php-<major>.<minor>`: the Compose profile that gates a non-default
/// runtime pool (`images/stack/docker-compose.v2.yml`).
fn valid_profile(profile: &str) -> bool {
    let Some(version) = profile.strip_prefix("php-") else {
        return false;
    };
    let Some((major, minor)) = version.split_once('.') else {
        return false;
    };
    [major, minor]
        .iter()
        .all(|part| (1..=2).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_digit()))
}

pub struct EnsureRequest {
    pub runtime_id: RuntimeId,
    /// `None` for the default runtime, which is in the base `up -d`.
    pub profile: Option<String>,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl EnsureRequest {
    pub fn parse(
        runtime_id: &str,
        profile: Option<&str>,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let StopRequest {
            runtime_id,
            request_id,
            idempotency_key,
        } = StopRequest::parse(runtime_id, request_id, key)?;
        if profile.is_some_and(|p| !valid_profile(p)) {
            return Err(RequestError::InvalidProfile);
        }
        Ok(Self {
            runtime_id,
            profile: profile.map(str::to_owned),
            request_id,
            idempotency_key,
        })
    }
}

/// The runtime pool a `stack.reloadWorkers` / `stack.flushFpc` targets.
/// Same fields as a stop request.
pub type RuntimeRequest = StopRequest;

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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnsureResult {
    pub runtime_id: String,
    pub service: String,
    pub healthy_at_unix_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeActionResult {
    pub runtime_id: String,
    pub service: String,
    pub completed_at_unix_secs: u64,
}

/// How long `stack.ensureRuntime` waits for `healthy`, and how often it
/// looks.
#[derive(Clone, Copy, Debug)]
pub struct HealthWait {
    pub timeout: Duration,
    pub interval: Duration,
}

impl HealthWait {
    /// Covers the pool healthcheck's `start_period: 15s` plus a couple of
    /// `interval: 30s` cycles on a slow host (the panel's own 90 s poll).
    pub const PRODUCTION: Self = Self {
        timeout: Duration::from_secs(90),
        interval: Duration::from_secs(1),
    };
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    /// `EngineConfig::runtime_root`; one subdirectory per runtime pool.
    pub runtime_root: &'a TrustedRoot,
    /// `EngineConfig::site_services_root` (`/etc/wcp/site-services`): one
    /// `<runtime id>/<domain>/` directory per site. The host side of the
    /// bind mount each pool sees at `SITE_SERVICES_CONTAINER_ROOT`.
    pub site_services_root: &'a TrustedRoot,
    /// The host's shared Caddy log directory (`/var/log/caddy`), where each
    /// site's own runtime log is pre-created for it.
    pub log_root: &'a TrustedRoot,
    /// Hand each runtime log to the site identity. Always `true` in
    /// production; unit tests that run unprivileged cannot chown to an
    /// arbitrary uid.
    pub chown_logs: bool,
    /// The managed stack directory (`~/compose/wp-stack`).
    pub stack_dir: &'a Path,
    /// `docker` in production; a fixture path in tests.
    pub docker: &'a str,
    pub health: HealthWait,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    Reload,
    Stop,
    Up,
    Probe,
    ReloadWorkers,
    FlushFpc,
    ScanService,
    ValidateConfig,
    RestartService,
    SiteProbe,
    StopService,
}

impl Stage {
    const fn message(self) -> &'static str {
        match self {
            Self::Reload => "the Caddy reload failed",
            Self::Stop => "the runtime pool could not be stopped",
            Self::Up => "the runtime pool could not be started",
            Self::Probe => "the runtime pool's health could not be read",
            Self::ReloadWorkers => "the PHP workers could not be reloaded",
            Self::FlushFpc => "the full-page cache could not be flushed",
            Self::ScanService => "the site service could not be registered with s6",
            Self::ValidateConfig => "the site's Caddy config is invalid",
            Self::RestartService => "the site process could not be restarted",
            Self::SiteProbe => "the site process did not become ready",
            Self::StopService => "the site process could not be stopped",
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
    /// The pool started but was not `healthy` within the health wait. The
    /// last health status seen, if any.
    Unhealthy(Option<String>),
    /// `activateSiteConfig`'s `expected-prior-hash` did not match the file
    /// currently on disk; nothing was changed.
    HashMismatch,
    /// The new site config was staged and swapped in, but the restarted
    /// process never answered its readiness probe. The previous config was
    /// restored and the process brought back up on it.
    SiteRolledBack,
    /// The site probe (or the new-config restart) failed *and* restoring the
    /// previous config also failed. The site is left down and needs manual
    /// recovery.
    SiteRecoveryFailed,
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
                } else if matches!(stage, Stage::Reload | Stage::RestartService) {
                    ErrorCode::ConfigReloadFailed
                } else if *stage == Stage::ValidateConfig {
                    ErrorCode::ConfigValidationFailed
                } else {
                    ErrorCode::SubprocessFailed
                },
                stage.message().into(),
            ),
            Self::Unhealthy(_) => (
                ErrorCode::Timeout,
                "the runtime pool did not become healthy in time".into(),
            ),
            Self::HashMismatch => (
                ErrorCode::ConfigHashMismatch,
                "the site config changed since it was read".into(),
            ),
            Self::SiteRolledBack => (
                ErrorCode::ConfigReloadFailed,
                "the site process did not become ready; the previous config was restored".into(),
            ),
            Self::SiteRecoveryFailed => (
                ErrorCode::ConfigRecoveryFailed,
                "the site process failed and restoring the previous config also failed".into(),
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

pub fn ensure_runtime(
    ctx: &Context<'_>,
    req: &EnsureRequest,
    cancel: &CancellationToken,
) -> Result<EnsureResult, Error> {
    run_admitted(
        ctx,
        ENSURE_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        || {
            let service = runtime_service(&req.runtime_id);
            let mut tail = Vec::new();
            if let Some(profile) = &req.profile {
                tail.extend(["--profile", profile.as_str()]);
            }
            tail.extend(["up", "-d", service.as_str()]);
            compose(ctx, Stage::Up, &tail, UP_TIMEOUT, cancel)?;
            wait_healthy(ctx, &service, cancel)?;
            Ok(EnsureResult {
                runtime_id: req.runtime_id.as_str().to_owned(),
                service,
                healthy_at_unix_secs: unix_now_secs(),
            })
        },
    )
}

pub fn reload_workers(
    ctx: &Context<'_>,
    req: &RuntimeRequest,
    cancel: &CancellationToken,
) -> Result<RuntimeActionResult, Error> {
    runtime_action(
        ctx,
        RELOAD_WORKERS_OPERATION,
        Stage::ReloadWorkers,
        req,
        &["sh", "-c", RELOAD_WORKERS_SCRIPT],
        cancel,
    )
}

pub fn flush_fpc(
    ctx: &Context<'_>,
    req: &RuntimeRequest,
    cancel: &CancellationToken,
) -> Result<RuntimeActionResult, Error> {
    runtime_action(
        ctx,
        FLUSH_FPC_OPERATION,
        Stage::FlushFpc,
        req,
        &["sh", "-c", FLUSH_FPC_SCRIPT],
        cancel,
    )
}

/// `exec -T runtime-<id> <command>` under the stack lock.
fn runtime_action(
    ctx: &Context<'_>,
    operation: &'static str,
    stage: Stage,
    req: &RuntimeRequest,
    command: &[&str],
    cancel: &CancellationToken,
) -> Result<RuntimeActionResult, Error> {
    run_admitted(
        ctx,
        operation,
        req.request_id,
        req.idempotency_key.as_ref(),
        || {
            let service = runtime_service(&req.runtime_id);
            let mut tail = vec!["exec", "-T", service.as_str()];
            tail.extend_from_slice(command);
            compose(ctx, stage, &tail, SIGNAL_TIMEOUT, cancel)?;
            Ok(RuntimeActionResult {
                runtime_id: req.runtime_id.as_str().to_owned(),
                service,
                completed_at_unix_secs: unix_now_secs(),
            })
        },
    )
}

// ===================== site-service lifecycle (051) =====================
//
// `stack.writeSiteService` and `stack.activateSiteConfig`: the per-site s6
// service directory and its dedicated FrankenPHP child's config, which the
// control panel used to write and reload over raw SSH against the pool's
// Compose project (`runtime_pool::site_identity`/`activation`). Both reuse
// this module's shared `stacks/wcp` lock, `stack-service` scope, `compose`
// exec and the `Context` the pool operations already run under. File writes
// go through `site_services_root` (a `ManagedRoot`), the container-side
// `s6-svc`/`s6-svscanctl`/`caddy validate`/`curl` go through `compose`.

/// A site's own directory inside its pool (`SITE_SERVICES_CONTAINER_ROOT/
/// <domain>`): the `--config` base its `run` script and `s6-svc` targets
/// use, and what `s6-svscanctl -a` rescans.
fn container_dir(domain: &Domain) -> String {
    format!("{SITE_SERVICES_CONTAINER_ROOT}/{domain}")
}

/// `site_services_root`-relative path of one of a site's service files, or
/// the directory itself when `file` is empty.
fn service_rel(runtime_id: &RuntimeId, domain: &Domain, file: &str) -> SiteRelativePath {
    let path = if file.is_empty() {
        format!("{runtime_id}/{domain}")
    } else {
        format!("{runtime_id}/{domain}/{file}")
    };
    SiteRelativePath::parse(path).expect("validated runtime id and domain form a valid path")
}

/// Ported verbatim from the control panel's
/// `sites::build_site_process_caddyfile` so the engine, not the panel, is
/// the single generator of this file's bytes (brief decision 3).
fn site_process_caddyfile(
    domain: &Domain,
    runtime_id: &RuntimeId,
    port: u16,
    root: &str,
    worker_mode: bool,
    worker_count: i64,
) -> String {
    let mut lines: Vec<String> = vec![
        "{".into(),
        "    admin off".into(),
        "}".into(),
        String::new(),
    ];
    lines.push(format!("http://127.0.0.1:{port} {{"));
    lines.push(format!("    root * {root}"));
    lines.push("    encode zstd gzip".into());
    if worker_mode {
        lines.push("    frankenphp {".into());
        lines.push(format!("        worker {root}/index.php {worker_count}"));
        lines.push("    }".into());
    }
    lines.push(String::new());
    lines.push("    @static {".into());
    lines.push("        file".into());
    lines.push(
        "        path *.css *.js *.png *.jpg *.jpeg *.gif *.webp *.avif *.svg *.woff *.woff2 *.ico"
            .into(),
    );
    lines.push("    }".into());
    lines.push("    header @static Cache-Control \"public, max-age=31536000, immutable\"".into());
    lines.push("    header @static Vary Accept-Encoding".into());
    lines.push(String::new());
    lines.push("    php_server".into());
    lines.push(String::new());
    lines.push("    log {".into());
    lines.push(format!(
        "        output file /var/log/caddy/runtime-{runtime_id}-{domain}.log {{"
    ));
    lines.push("            mode 0600".into());
    lines.push("        }".into());
    lines.push("        format json".into());
    lines.push("    }".into());
    lines.push("    log_append request_id {http.request.header.X-Request-ID}".into());
    lines.push(format!("    log_append domain {domain}"));
    lines.push(format!("    log_append runtime_id {runtime_id}"));
    lines.push("}".into());
    lines.join("\n")
}

/// Ported from the panel's `build_site_run_script`: drops privileges to the
/// site's UID/GID and execs its own FrankenPHP child.
fn site_run_script(uid: u32, gid: u32, container_dir: &str) -> String {
    format!(
        "#!/bin/sh\nexport PHP_INI_SCAN_DIR=\"/usr/local/etc/php/conf.d:{container_dir}\"\nexec setpriv --reuid={uid} --regid={gid} --clear-groups \\\n    frankenphp run --config {container_dir}/Caddyfile --adapter caddyfile\n"
    )
}

/// Ported from the panel's `build_site_open_basedir_ini`.
fn site_open_basedir_ini(root: &str) -> String {
    format!(
        "; Managed by Website Control Panel - do not edit manually\nopen_basedir = {root}:/tmp:/var/tmp:/run/valkey/valkey.sock\n"
    )
}

/// The identity a site's config carries: its loopback port, document root
/// and FrankenPHP worker settings. Shared by both site operations.
pub struct SiteConfig {
    pub port: u16,
    pub root: String,
    pub worker_mode: bool,
    pub worker_count: i64,
}

fn parse_site_config(
    port: u16,
    root: String,
    worker_mode: bool,
    worker_count: i64,
) -> Result<SiteConfig, RequestError> {
    if port == 0 {
        return Err(RequestError::InvalidPort);
    }
    Ok(SiteConfig {
        port,
        root,
        worker_mode,
        worker_count,
    })
}

/// The run script drops to this identity and the runtime log is handed to
/// it: never root or a system account. Checked at the command boundary.
pub fn validate_site_identity(uid: u32, gid: u32) -> Result<(), RequestError> {
    let minimum = crate::site_enroll::MIN_SITE_IDENTITY;
    if uid < minimum || gid < minimum {
        return Err(RequestError::InvalidIdentity);
    }
    Ok(())
}

pub struct WriteSiteServiceRequest {
    pub runtime_id: RuntimeId,
    pub domain: Domain,
    pub uid: u32,
    pub gid: u32,
    pub config: SiteConfig,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl WriteSiteServiceRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn parse(
        runtime_id: &str,
        domain: &str,
        uid: u32,
        gid: u32,
        port: u16,
        root: String,
        worker_mode: bool,
        worker_count: i64,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let runtime_id =
            RuntimeId::parse(runtime_id).map_err(|_| RequestError::InvalidRuntimeId)?;
        let domain = Domain::parse(domain).map_err(|_| RequestError::InvalidDomain)?;
        let (request_id, idempotency_key) = parse_ids(request_id, key)?;
        Ok(Self {
            runtime_id,
            domain,
            uid,
            gid,
            config: parse_site_config(port, root, worker_mode, worker_count)?,
            request_id,
            idempotency_key,
        })
    }
}

pub struct ActivateSiteConfigRequest {
    pub runtime_id: RuntimeId,
    pub domain: Domain,
    /// The site process's loopback port, for the readiness probe.
    pub port: u16,
    /// The document root, for regenerating `open-basedir.ini` (which is
    /// never edited textually, only derived from the root).
    pub root: String,
    /// The complete new `Caddyfile`, opaque to the engine: the panel edits
    /// this file textually (error pages, PHP settings), so it cannot be
    /// regenerated from typed parameters. Validated inside the pool before
    /// it can take effect.
    pub caddyfile: String,
    /// The precondition the swap runs under: `Absent` for a first write,
    /// `Sha256` of what the caller last read otherwise.
    pub guard: HashGuard,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl ActivateSiteConfigRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn parse(
        runtime_id: &str,
        domain: &str,
        port: u16,
        root: String,
        caddyfile: String,
        expected_prior_hash: Option<&str>,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let runtime_id =
            RuntimeId::parse(runtime_id).map_err(|_| RequestError::InvalidRuntimeId)?;
        let domain = Domain::parse(domain).map_err(|_| RequestError::InvalidDomain)?;
        if port == 0 {
            return Err(RequestError::InvalidPort);
        }
        let guard = match expected_prior_hash {
            None => HashGuard::Absent,
            Some(value) => HashGuard::Sha256(
                ConfigHash::parse(value).map_err(|_| RequestError::InvalidPriorHash)?,
            ),
        };
        let (request_id, idempotency_key) = parse_ids(request_id, key)?;
        Ok(Self {
            runtime_id,
            domain,
            port,
            root,
            caddyfile,
            guard,
            request_id,
            idempotency_key,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteServiceResult {
    pub runtime_id: String,
    pub domain: String,
    pub completed_at_unix_secs: u64,
}

fn site_result(runtime_id: &RuntimeId, domain: &Domain) -> SiteServiceResult {
    SiteServiceResult {
        runtime_id: runtime_id.as_str().to_owned(),
        domain: domain.as_str().to_owned(),
        completed_at_unix_secs: unix_now_secs(),
    }
}

/// Writes (or overwrites) one site's s6 service directory — `run` script,
/// dedicated `Caddyfile` and `open-basedir.ini` — then makes the running
/// `s6-svscan` pick the directory up. No restart or readiness probe: this
/// is site creation/migration, where the process has not served yet.
pub fn write_site_service(
    ctx: &Context<'_>,
    req: &WriteSiteServiceRequest,
    cancel: &CancellationToken,
) -> Result<SiteServiceResult, Error> {
    run_admitted(
        ctx,
        WRITE_SITE_SERVICE_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        || {
            let root = ManagedRoot::open(ctx.site_services_root).map_err(Error::Io)?;
            root.create_dir_all(&service_rel(&req.runtime_id, &req.domain, ""))
                .map_err(Error::Io)?;
            let cdir = container_dir(&req.domain);
            root.write_new_executable(
                &service_rel(&req.runtime_id, &req.domain, "run"),
                site_run_script(req.uid, req.gid, &cdir).as_bytes(),
            )
            .or_else(|error| {
                // `write_new_executable` fails if `run` already exists
                // (create-new); a rewrite overwrites it atomically instead.
                if error.kind() == io::ErrorKind::AlreadyExists {
                    overwrite_executable(
                        &root,
                        &service_rel(&req.runtime_id, &req.domain, "run"),
                        site_run_script(req.uid, req.gid, &cdir).as_bytes(),
                    )
                } else {
                    Err(error)
                }
            })
            .map_err(Error::Io)?;
            root.write_atomic(
                &service_rel(&req.runtime_id, &req.domain, "open-basedir.ini"),
                site_open_basedir_ini(&req.config.root).as_bytes(),
            )
            .map_err(Error::Io)?;
            root.write_atomic(
                &service_rel(&req.runtime_id, &req.domain, "Caddyfile"),
                site_process_caddyfile(
                    &req.domain,
                    &req.runtime_id,
                    req.config.port,
                    &req.config.root,
                    req.config.worker_mode,
                    req.config.worker_count,
                )
                .as_bytes(),
            )
            .map_err(Error::Io)?;
            prepare_runtime_log(ctx, req)?;
            scan_services(ctx, &req.runtime_id, cancel)?;
            Ok(site_result(&req.runtime_id, &req.domain))
        },
    )
}

/// Pre-creates the site's own runtime log, `0600` and owned by the site
/// identity, before the service is registered: the site process runs as an
/// unprivileged uid and cannot create a file in the root-owned shared log
/// directory. The ingress log has a different name and stays root-owned.
/// The file is opened through the log directory's capability, must be a
/// regular file, and is changed through its own descriptor.
fn prepare_runtime_log(ctx: &Context<'_>, req: &WriteSiteServiceRequest) -> Result<(), Error> {
    use std::os::unix::fs::{PermissionsExt, fchown};

    let logs = ManagedRoot::open(ctx.log_root).map_err(Error::Io)?;
    let name = rel(&format!("runtime-{}-{}.log", req.runtime_id, req.domain));
    let file = logs.open_or_create_file(&name).map_err(Error::Io)?;
    if !file.metadata().map_err(Error::Io)?.is_file() {
        return Err(Error::Io(io::Error::other(
            "runtime log is not a regular file",
        )));
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(Error::Io)?;
    if ctx.chown_logs {
        fchown(&file, Some(req.uid), Some(req.gid)).map_err(Error::Io)?;
    }
    Ok(())
}

/// Regenerates a site's `Caddyfile` (and `open-basedir.ini`) from typed
/// parameters, validates the new `Caddyfile` inside the pool, swaps it in
/// atomically, restarts the site process and waits for it to answer. If the
/// restarted process never becomes ready the previous files are restored and
/// the process is brought back up on them (brief decision 2).
pub fn activate_site_config(
    ctx: &Context<'_>,
    req: &ActivateSiteConfigRequest,
    cancel: &CancellationToken,
) -> Result<SiteServiceResult, Error> {
    run_admitted(
        ctx,
        ACTIVATE_SITE_CONFIG_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        || {
            let root = ManagedRoot::open(ctx.site_services_root).map_err(Error::Io)?;
            let caddy_rel = service_rel(&req.runtime_id, &req.domain, "Caddyfile");
            let basedir_rel = service_rel(&req.runtime_id, &req.domain, "open-basedir.ini");
            let tmp_rel = service_rel(&req.runtime_id, &req.domain, "Caddyfile.tmp");

            // Hash-guard the file currently on disk before touching anything.
            let prior_caddy = read_optional(&root, &caddy_rel)?;
            if !req.guard.is_satisfied_by(prior_caddy.as_deref()) {
                return Err(Error::HashMismatch);
            }
            let prior_basedir = read_optional(&root, &basedir_rel)?;

            // The Caddyfile is the caller's opaque, validated-in-container
            // content; open-basedir is derived from the root.
            let new_caddy = req.caddyfile.clone();
            let new_basedir = site_open_basedir_ini(&req.root);

            // Stage the new Caddyfile next to the live one and validate it
            // inside the pool before it can take effect. A `.tmp` sibling is
            // not loaded by the running process.
            root.write_atomic(&tmp_rel, new_caddy.as_bytes())
                .map_err(Error::Io)?;
            let cdir = container_dir(&req.domain);
            if let Err(error) = validate_site_config(ctx, &req.runtime_id, &cdir, cancel) {
                let _ = root.remove_file(&tmp_rel);
                return Err(error);
            }

            // Commit: swap the validated Caddyfile in and refresh the ini.
            root.rename(&tmp_rel, &caddy_rel).map_err(Error::Io)?;
            root.write_atomic(&basedir_rel, new_basedir.as_bytes())
                .map_err(Error::Io)?;

            // Restart the child and probe it. Any failure rolls both files
            // back to what was on disk and restarts on the old config.
            let outcome = restart_service(ctx, &req.runtime_id, &cdir, cancel)
                .and_then(|()| site_probe(ctx, &req.runtime_id, req.port, cancel));
            match outcome {
                Ok(()) => Ok(site_result(&req.runtime_id, &req.domain)),
                Err(_down) => Err(restore_site(
                    &root,
                    ctx,
                    req,
                    &caddy_rel,
                    &basedir_rel,
                    &cdir,
                    prior_caddy.as_deref(),
                    prior_basedir.as_deref(),
                    cancel,
                )),
            }
        },
    )
}

pub struct RemoveSiteServiceRequest {
    pub runtime_id: RuntimeId,
    pub domain: Domain,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl RemoveSiteServiceRequest {
    pub fn parse(
        runtime_id: &str,
        domain: &str,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let runtime_id =
            RuntimeId::parse(runtime_id).map_err(|_| RequestError::InvalidRuntimeId)?;
        let domain = Domain::parse(domain).map_err(|_| RequestError::InvalidDomain)?;
        let (request_id, idempotency_key) = parse_ids(request_id, key)?;
        Ok(Self {
            runtime_id,
            domain,
            request_id,
            idempotency_key,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveSiteServiceResult {
    pub runtime_id: String,
    pub domain: String,
    /// `false` when there was no service directory to remove: a site whose
    /// service was never created (or is already gone) is a no-op, not an
    /// error, so cleanup paths can call this unconditionally.
    pub removed: bool,
    /// Whether the pool was running, i.e. whether a process could exist to
    /// be stopped and an `s6-svscan` to tell about the removal.
    pub pool_running: bool,
    pub completed_at_unix_secs: u64,
}

/// Tears down one site's s6 service: `s6-svc -d` stops its FrankenPHP
/// child, the service directory is removed, and `s6-svscanctl -a` drops
/// its supervisor. A failed stop changes nothing on disk (brief decision 3:
/// a visible `FAILED`, never a half-removed service reported as success).
/// A stopped pool has no process to stop, so only the directory goes.
pub fn remove_site_service(
    ctx: &Context<'_>,
    req: &RemoveSiteServiceRequest,
    cancel: &CancellationToken,
) -> Result<RemoveSiteServiceResult, Error> {
    run_admitted(
        ctx,
        REMOVE_SITE_SERVICE_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        || {
            let root = ManagedRoot::open(ctx.site_services_root).map_err(Error::Io)?;
            let dir_rel = service_rel(&req.runtime_id, &req.domain, "");
            let result = |removed, pool_running| RemoveSiteServiceResult {
                runtime_id: req.runtime_id.as_str().to_owned(),
                domain: req.domain.as_str().to_owned(),
                removed,
                pool_running,
                completed_at_unix_secs: unix_now_secs(),
            };
            if !root.exists(&dir_rel) {
                return Ok(result(false, false));
            }

            let service = runtime_service(&req.runtime_id);
            let running = !compose(
                ctx,
                Stage::Probe,
                &["ps", "-q", &service],
                PROBE_TIMEOUT,
                cancel,
            )?
            .trim()
            .is_empty();
            let cdir = container_dir(&req.domain);
            if running {
                compose(
                    ctx,
                    Stage::StopService,
                    &["exec", "-T", &service, "s6-svc", "-d", &cdir],
                    SIGNAL_TIMEOUT,
                    cancel,
                )?;
            }
            root.remove_dir_all(&dir_rel).map_err(Error::Io)?;
            if running {
                scan_services(ctx, &req.runtime_id, cancel)?;
            }
            Ok(result(true, running))
        },
    )
}

/// Overwrites an existing file atomically and marks it executable, matching
/// `write_new_executable`'s result for a path that already exists.
fn overwrite_executable(
    root: &ManagedRoot,
    path: &SiteRelativePath,
    contents: &[u8],
) -> io::Result<()> {
    root.write_atomic(path, contents)?;
    root.set_mode(path, 0o755)
}

fn read_optional(root: &ManagedRoot, path: &SiteRelativePath) -> Result<Option<Vec<u8>>, Error> {
    match root.read_bytes(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Error::Io(error)),
    }
}

/// `s6-svscanctl -a` with the same bounded retry the panel used: a freshly
/// started pool's nested `s6-svscan` may not have its control FIFO yet.
fn scan_services(
    ctx: &Context<'_>,
    runtime_id: &RuntimeId,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let service = runtime_service(runtime_id);
    let script = format!(
        "i=0; while [ \"$i\" -lt 10 ]; do s6-svscanctl -a {SITE_SERVICES_CONTAINER_ROOT} && exit 0; i=$((i+1)); sleep 0.3; done; exit 1"
    );
    compose(
        ctx,
        Stage::ScanService,
        &["exec", "-T", &service, "sh", "-c", &script],
        SIGNAL_TIMEOUT,
        cancel,
    )?;
    Ok(())
}

fn validate_site_config(
    ctx: &Context<'_>,
    runtime_id: &RuntimeId,
    container_dir: &str,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let service = runtime_service(runtime_id);
    let config = format!("{container_dir}/Caddyfile.tmp");
    compose(
        ctx,
        Stage::ValidateConfig,
        &[
            "exec",
            "-T",
            &service,
            "caddy",
            "validate",
            "--config",
            &config,
            "--adapter",
            "caddyfile",
        ],
        RELOAD_TIMEOUT,
        cancel,
    )?;
    Ok(())
}

/// `s6-svc -r <dir>`: restart the site's supervised FrankenPHP child so a
/// config change takes effect.
fn restart_service(
    ctx: &Context<'_>,
    runtime_id: &RuntimeId,
    container_dir: &str,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let service = runtime_service(runtime_id);
    compose(
        ctx,
        Stage::RestartService,
        &["exec", "-T", &service, "s6-svc", "-r", container_dir],
        SIGNAL_TIMEOUT,
        cancel,
    )?;
    Ok(())
}

/// The readiness probe the panel ran: up to 20 one-second tries for any
/// HTTP status on the site's loopback port. Each `curl` is capped at 5 s,
/// so a process that accepts the connection but never answers cannot hold
/// the probe (and the stack lock) until the `compose exec` timeout.
fn site_probe(
    ctx: &Context<'_>,
    runtime_id: &RuntimeId,
    port: u16,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let service = runtime_service(runtime_id);
    let probe = format!(
        "i=0; while [ \"$i\" -lt 20 ]; do code=$(curl -s --max-time 5 -o /dev/null -w '%{{http_code}}' -H 'Host: 127.0.0.1' http://127.0.0.1:{port}/ || true); [ \"$code\" != 000 ] && exit 0; i=$((i+1)); sleep 1; done; exit 1"
    );
    compose(
        ctx,
        Stage::SiteProbe,
        &["exec", "-T", &service, "sh", "-c", &probe],
        UP_TIMEOUT,
        cancel,
    )?;
    Ok(())
}

/// Restores the previous `Caddyfile`/`open-basedir.ini` (or removes a file
/// that had none) and restarts the child on the old config. Maps to
/// `SiteRolledBack` on success, `SiteRecoveryFailed` if the restore itself
/// fails.
#[allow(clippy::too_many_arguments)]
fn restore_site(
    root: &ManagedRoot,
    ctx: &Context<'_>,
    req: &ActivateSiteConfigRequest,
    caddy_rel: &SiteRelativePath,
    basedir_rel: &SiteRelativePath,
    container_dir: &str,
    prior_caddy: Option<&[u8]>,
    prior_basedir: Option<&[u8]>,
    cancel: &CancellationToken,
) -> Error {
    let restore = |path: &SiteRelativePath, prior: Option<&[u8]>| -> io::Result<()> {
        match prior {
            Some(bytes) => root.write_atomic(path, bytes),
            None => match root.remove_file(path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
            },
        }
    };
    if restore(caddy_rel, prior_caddy).is_err() || restore(basedir_rel, prior_basedir).is_err() {
        return Error::SiteRecoveryFailed;
    }
    // Only a prior config can be restarted into; a rolled-back first write
    // leaves nothing to run, so skip the restart there. No re-probe: the
    // restored config is the one that was serving before this request.
    if prior_caddy.is_some()
        && restart_service(ctx, &req.runtime_id, container_dir, cancel).is_err()
    {
        return Error::SiteRecoveryFailed;
    }
    Error::SiteRolledBack
}

/// Polls `ps -q <service>` and the container's `.State.Health.Status` until
/// it reads `healthy`. A container that is not created yet, or has no health
/// status yet, is polled again rather than failed.
fn wait_healthy(ctx: &Context<'_>, service: &str, cancel: &CancellationToken) -> Result<(), Error> {
    let deadline = std::time::Instant::now() + ctx.health.timeout;
    let mut last = None;
    loop {
        let id = compose(
            ctx,
            Stage::Probe,
            &["ps", "-q", service],
            PROBE_TIMEOUT,
            cancel,
        )?;
        let id = id.trim();
        if !id.is_empty() {
            let status = docker(
                ctx,
                Stage::Probe,
                &[
                    "inspect",
                    "-f",
                    "{{if .State.Health}}{{.State.Health.Status}}{{end}}",
                    id,
                ],
                PROBE_TIMEOUT,
                cancel,
            )?;
            let status = status.trim();
            if status == "healthy" {
                return Ok(());
            }
            if !status.is_empty() {
                last = Some(status.to_owned());
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(Error::Unhealthy(last));
        }
        std::thread::sleep(ctx.health.interval);
    }
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
) -> Result<String, Error> {
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
    docker(ctx, stage, &argv, timeout, cancel)
}

/// Runs `docker <argv>` in the stack directory and returns its stdout.
fn docker(
    ctx: &Context<'_>,
    stage: Stage,
    argv: &[&str],
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<String, Error> {
    let output = process::run(
        &ProcessRequest::new(ctx.docker)
            .args(argv.iter().copied())
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
    Ok(String::from_utf8_lossy(&output.stdout.bytes).into_owned())
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
        site_services_root: TrustedRoot,
        log_root: TrustedRoot,
        stack_dir: PathBuf,
        docker: String,
        calls: PathBuf,
        health: PathBuf,
    }

    impl Fixture {
        fn new(exit: i32) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path().canonicalize().unwrap();
            for sub in ["state", "runtimes", "site-services", "stack", "logs"] {
                fs::create_dir(base.join(sub)).unwrap();
            }
            let calls = base.join("calls.log");
            let docker = base.join("docker");
            fs::write(
                &docker,
                format!(
                    "#!/bin/sh\necho \"$(pwd) $*\" >> '{calls}'\n\
                     case \"$*\" in\n\
                     *' ps -q '*) echo c0ffee ;;\n\
                     inspect*) cat '{health}' 2>/dev/null || echo healthy ;;\n\
                     esac\nexit {exit}\n",
                    calls = calls.display(),
                    health = base.join("health").display(),
                ),
            )
            .unwrap();
            fs::set_permissions(&docker, fs::Permissions::from_mode(0o755)).unwrap();
            Self {
                state: ManagedRoot::open(&TrustedRoot::parse(base.join("state")).unwrap()).unwrap(),
                runtime_root: TrustedRoot::parse(base.join("runtimes")).unwrap(),
                site_services_root: TrustedRoot::parse(base.join("site-services")).unwrap(),
                log_root: TrustedRoot::parse(base.join("logs")).unwrap(),
                stack_dir: base.join("stack"),
                docker: docker.to_string_lossy().into_owned(),
                health: base.join("health"),
                calls,
                _dir: dir,
            }
        }

        fn ctx(&self) -> Context<'_> {
            Context {
                engine_state: &self.state,
                runtime_root: &self.runtime_root,
                site_services_root: &self.site_services_root,
                log_root: &self.log_root,
                chown_logs: false,
                stack_dir: &self.stack_dir,
                docker: &self.docker,
                health: HealthWait {
                    timeout: Duration::from_millis(200),
                    interval: Duration::from_millis(20),
                },
            }
        }

        fn health(&self, status: &str) {
            fs::write(&self.health, format!("{status}\n")).unwrap();
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

        /// Rewrites the fake `docker` so it exits 1 only when its arguments
        /// contain `marker`, and 0 otherwise — the one knob the shared
        /// single-exit fixture lacks, used to fail just the readiness probe.
        fn fail_on(&self, marker: &str) {
            fs::write(
                &self.docker,
                format!(
                    "#!/bin/sh\necho \"$(pwd) $*\" >> '{calls}'\n\
                     case \"$*\" in *'{marker}'*) exit 1 ;; esac\nexit 0\n",
                    calls = self.calls.display(),
                ),
            )
            .unwrap();
            fs::set_permissions(&self.docker, fs::Permissions::from_mode(0o755)).unwrap();
        }

        fn seed_dir(&self, runtime_id: &str, domain: &str) {
            fs::create_dir_all(
                self.site_services_root
                    .as_path()
                    .join(runtime_id)
                    .join(domain),
            )
            .unwrap();
        }

        fn service_file(&self, runtime_id: &str, domain: &str, name: &str) -> String {
            fs::read_to_string(
                self.site_services_root
                    .as_path()
                    .join(runtime_id)
                    .join(domain)
                    .join(name),
            )
            .unwrap()
        }
    }

    fn write_req(id: &str, key: Option<&str>) -> WriteSiteServiceRequest {
        WriteSiteServiceRequest::parse(
            "fp1-php83",
            "example.test",
            10123,
            10123,
            9000,
            "/var/www/example".into(),
            true,
            2,
            id,
            key,
        )
        .unwrap()
    }

    fn sample_caddyfile(port: u16) -> String {
        site_process_caddyfile(
            &Domain::parse("example.test").unwrap(),
            &RuntimeId::parse("fp1-php83").unwrap(),
            port,
            "/var/www/example",
            true,
            2,
        )
    }

    fn activate_req(hash: Option<&str>, id: &str, key: Option<&str>) -> ActivateSiteConfigRequest {
        ActivateSiteConfigRequest::parse(
            "fp1-php83",
            "example.test",
            9000,
            "/var/www/example".into(),
            sample_caddyfile(9000),
            hash,
            id,
            key,
        )
        .unwrap()
    }

    #[test]
    fn write_site_service_writes_the_three_files_and_scans_once() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new(0);

        let result = write_site_service(
            &fixture.ctx(),
            &write_req(ID, Some("ws-1")),
            &CancellationToken::default(),
        )
        .unwrap();
        assert_eq!(result.domain, "example.test");
        // A retried request replays without writing or scanning twice.
        write_site_service(
            &fixture.ctx(),
            &write_req(ID, Some("ws-1")),
            &CancellationToken::default(),
        )
        .unwrap();

        let run = fixture.service_file("fp1-php83", "example.test", "run");
        assert!(run.starts_with("#!/bin/sh\n"));
        assert!(run.contains("setpriv --reuid=10123 --regid=10123"));
        assert!(run.contains("--config /etc/wcp/site-services/example.test/Caddyfile"));
        let caddy = fixture.service_file("fp1-php83", "example.test", "Caddyfile");
        assert!(caddy.contains("http://127.0.0.1:9000 {"));
        assert!(caddy.contains("root * /var/www/example"));
        assert!(caddy.contains("worker /var/www/example/index.php 2"));
        let ini = fixture.service_file("fp1-php83", "example.test", "open-basedir.ini");
        assert!(ini.contains("open_basedir = /var/www/example:/tmp"));
        assert_eq!(
            fixture.calls(),
            vec![format!(
                "{} exec -T runtime-fp1-php83 sh -c i=0; while [ \"$i\" -lt 10 ]; do \
                 s6-svscanctl -a /etc/wcp/site-services && exit 0; i=$((i+1)); sleep 0.3; done; \
                 exit 1",
                compose_prefix(&fixture)
            )]
        );
    }

    #[test]
    fn write_site_service_precreates_the_runtime_log_for_the_site_identity() {
        use std::os::unix::fs::MetadataExt;

        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new(0);
        // Chowning to oneself works unprivileged, which is all a unit test
        // can prove about the handover; the Lima run covers a foreign uid.
        let own = fs::metadata(fixture.log_root.as_path()).unwrap();
        let (uid, gid) = (own.uid(), own.gid());
        let mut ctx = fixture.ctx();
        ctx.chown_logs = true;
        let request = WriteSiteServiceRequest::parse(
            "fp1-php83",
            "example.test",
            uid,
            gid,
            9000,
            "/var/www/example".into(),
            false,
            2,
            ID,
            None,
        )
        .unwrap();
        // A pre-existing wider-mode log is tightened, not truncated.
        let log = fixture
            .log_root
            .as_path()
            .join("runtime-fp1-php83-example.test.log");
        fs::write(&log, "kept\n").unwrap();
        fs::set_permissions(&log, fs::Permissions::from_mode(0o644)).unwrap();

        write_site_service(&ctx, &request, &CancellationToken::default()).unwrap();

        let meta = fs::metadata(&log).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!((meta.uid(), meta.gid()), (uid, gid));
        assert_eq!(fs::read_to_string(&log).unwrap(), "kept\n");
        // Only the site's own runtime log is created; the ingress log is not.
        assert_eq!(fs::read_dir(fixture.log_root.as_path()).unwrap().count(), 1);
    }

    #[test]
    fn write_site_service_refuses_a_runtime_log_that_is_not_a_regular_file() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new(0);
        fs::create_dir(
            fixture
                .log_root
                .as_path()
                .join("runtime-fp1-php83-example.test.log"),
        )
        .unwrap();
        let error = write_site_service(
            &fixture.ctx(),
            &write_req(ID, None),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::Io(_)));
        // Nothing was registered with s6.
        assert!(fixture.calls().is_empty());
    }

    #[test]
    fn only_site_identities_may_run_a_service() {
        assert!(validate_site_identity(1000, 1000).is_ok());
        for (uid, gid) in [(0, 0), (0, 1000), (1000, 0), (999, 999), (10_000, 33)] {
            assert_eq!(
                validate_site_identity(uid, gid),
                Err(RequestError::InvalidIdentity)
            );
        }
    }

    #[test]
    fn write_site_service_overwrites_an_existing_run_script() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new(0);
        write_site_service(
            &fixture.ctx(),
            &write_req(ID, None),
            &CancellationToken::default(),
        )
        .unwrap();
        // A second, distinct request over the same directory must not fail
        // on the already-present `run` file.
        write_site_service(
            &fixture.ctx(),
            &write_req(OTHER_ID, None),
            &CancellationToken::default(),
        )
        .unwrap();
        assert!(
            fixture
                .service_file("fp1-php83", "example.test", "run")
                .contains("setpriv")
        );
    }

    #[test]
    fn activate_validates_swaps_restarts_and_probes_in_order() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new(0);
        fixture.seed_dir("fp1-php83", "example.test");

        activate_site_config(
            &fixture.ctx(),
            &activate_req(None, ID, Some("act-1")),
            &CancellationToken::default(),
        )
        .unwrap();

        let prefix = compose_prefix(&fixture);
        let calls = fixture.calls();
        assert_eq!(
            calls[0],
            format!(
                "{prefix} exec -T runtime-fp1-php83 caddy validate --config \
                 /etc/wcp/site-services/example.test/Caddyfile.tmp --adapter caddyfile"
            )
        );
        assert_eq!(
            calls[1],
            format!(
                "{prefix} exec -T runtime-fp1-php83 s6-svc -r \
                 /etc/wcp/site-services/example.test"
            )
        );
        assert!(
            calls[2].contains("curl -s --max-time 5 -o /dev/null"),
            "{}",
            calls[2]
        );
        // The validated Caddyfile is live and no staging file is left behind.
        assert!(
            fixture
                .service_file("fp1-php83", "example.test", "Caddyfile")
                .contains("http://127.0.0.1:9000 {")
        );
        assert!(
            !fixture
                .site_services_root
                .as_path()
                .join("fp1-php83/example.test/Caddyfile.tmp")
                .exists()
        );
    }

    #[test]
    fn activate_rejects_a_stale_prior_hash_before_touching_docker() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new(0);
        fixture.site_config("ignored", "x"); // unrelated
        // Seed a live Caddyfile, then present a wrong expected hash.
        write_site_service(
            &fixture.ctx(),
            &write_req(ID, None),
            &CancellationToken::default(),
        )
        .unwrap();
        fs::read_to_string(&fixture.calls).ok();
        fs::write(&fixture.calls, "").unwrap();

        let bad = ConfigHash::of(b"something else");
        let error = activate_site_config(
            &fixture.ctx(),
            &activate_req(Some(bad.as_str()), OTHER_ID, None),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::HashMismatch));
        assert_eq!(error.protocol().0, ErrorCode::ConfigHashMismatch);
        assert!(fixture.calls().is_empty());
    }

    #[test]
    fn activate_absent_guard_refuses_an_existing_file() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new(0);
        write_site_service(
            &fixture.ctx(),
            &write_req(ID, None),
            &CancellationToken::default(),
        )
        .unwrap();
        fs::write(&fixture.calls, "").unwrap();

        let error = activate_site_config(
            &fixture.ctx(),
            &activate_req(None, OTHER_ID, None),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::HashMismatch));
    }

    #[test]
    fn an_invalid_new_config_removes_the_staging_file_and_fails() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new(0);
        fixture.seed_dir("fp1-php83", "example.test");
        fixture.fail_on("caddy validate");

        let error = activate_site_config(
            &fixture.ctx(),
            &activate_req(None, ID, Some("act-bad")),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::Rejected(Stage::ValidateConfig, _)));
        assert_eq!(error.protocol().0, ErrorCode::ConfigValidationFailed);
        assert!(
            !fixture
                .site_services_root
                .as_path()
                .join("fp1-php83/example.test/Caddyfile.tmp")
                .exists()
        );
    }

    #[test]
    fn a_probe_failure_restores_the_previous_config_and_restarts_it() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new(0);
        // Seed a known-good live config to roll back to.
        let prior = write_req(ID, None);
        write_site_service(&fixture.ctx(), &prior, &CancellationToken::default()).unwrap();
        let live = fixture.service_file("fp1-php83", "example.test", "Caddyfile");
        let live_hash = ConfigHash::of(live.as_bytes());
        // A newer activation whose restarted process never answers.
        fixture.fail_on("http_code");
        fs::write(&fixture.calls, "").unwrap();

        let req = ActivateSiteConfigRequest::parse(
            "fp1-php83",
            "example.test",
            9100, // a changed port, so the file content differs
            "/var/www/example".into(),
            sample_caddyfile(9100),
            Some(live_hash.as_str()),
            OTHER_ID,
            None,
        )
        .unwrap();
        let error =
            activate_site_config(&fixture.ctx(), &req, &CancellationToken::default()).unwrap_err();
        assert!(matches!(error, Error::SiteRolledBack));
        assert_eq!(error.protocol().0, ErrorCode::ConfigReloadFailed);
        // The live Caddyfile is byte-for-byte the previous one again.
        assert_eq!(
            fixture.service_file("fp1-php83", "example.test", "Caddyfile"),
            live
        );
        // validate, restart(new), probe(fail), restart(restored).
        let restarts = fixture
            .calls()
            .iter()
            .filter(|c| c.contains("s6-svc -r"))
            .count();
        assert_eq!(restarts, 2);
    }

    #[test]
    fn a_held_stack_lock_blocks_a_site_write_before_docker_runs() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new(0);
        let stack_scope = crate::stack_deploy::open_scope(&fixture.state).unwrap();
        let _held = crate::stack_deploy::acquire_stack_lock(
            &stack_scope,
            RequestId::parse(OTHER_ID).unwrap(),
        )
        .unwrap();

        let error = write_site_service(
            &fixture.ctx(),
            &write_req(ID, None),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::StackBusy));
        assert!(fixture.calls().is_empty());
    }

    fn remove_req(id: &str, key: Option<&str>) -> RemoveSiteServiceRequest {
        RemoveSiteServiceRequest::parse("fp1-php83", "example.test", id, key).unwrap()
    }

    fn service_dir_exists(fixture: &Fixture) -> bool {
        fixture
            .site_services_root
            .as_path()
            .join("fp1-php83/example.test")
            .exists()
    }

    #[test]
    fn remove_site_service_stops_removes_and_rescans_in_order() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new(0);
        write_site_service(
            &fixture.ctx(),
            &write_req(OTHER_ID, None),
            &CancellationToken::default(),
        )
        .unwrap();
        fs::remove_file(&fixture.calls).unwrap();

        let result = remove_site_service(
            &fixture.ctx(),
            &remove_req(ID, Some("rs-1")),
            &CancellationToken::default(),
        )
        .unwrap();
        assert!(result.removed);
        assert!(result.pool_running);
        assert!(!service_dir_exists(&fixture));
        // A retried request replays the outcome without a second stop.
        let replayed = remove_site_service(
            &fixture.ctx(),
            &remove_req(ID, Some("rs-1")),
            &CancellationToken::default(),
        )
        .unwrap();
        assert!(replayed.removed);

        let prefix = compose_prefix(&fixture);
        assert_eq!(
            fixture.calls(),
            vec![
                format!("{prefix} ps -q runtime-fp1-php83"),
                format!(
                    "{prefix} exec -T runtime-fp1-php83 s6-svc -d \
                     /etc/wcp/site-services/example.test"
                ),
                format!(
                    "{prefix} exec -T runtime-fp1-php83 sh -c i=0; while [ \"$i\" -lt 10 ]; do \
                     s6-svscanctl -a /etc/wcp/site-services && exit 0; i=$((i+1)); sleep 0.3; \
                     done; exit 1"
                ),
            ]
        );
    }

    #[test]
    fn remove_site_service_without_a_directory_is_a_no_op() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new(0);

        let result = remove_site_service(
            &fixture.ctx(),
            &remove_req(ID, None),
            &CancellationToken::default(),
        )
        .unwrap();
        assert!(!result.removed);
        assert!(fixture.calls().is_empty());
    }

    #[test]
    fn a_failed_stop_leaves_the_service_directory_in_place() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new(0);
        fixture.seed_dir("fp1-php83", "example.test");
        // `ps -q` must report the pool running for the stop to be attempted.
        fs::write(
            &fixture.docker,
            format!(
                "#!/bin/sh\necho \"$(pwd) $*\" >> '{calls}'\n\
                 case \"$*\" in *' ps -q '*) echo c0ffee ;; *'s6-svc -d'*) exit 1 ;; esac\nexit 0\n",
                calls = fixture.calls.display(),
            ),
        )
        .unwrap();

        let error = remove_site_service(
            &fixture.ctx(),
            &remove_req(ID, None),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::Rejected(Stage::StopService, _)));
        assert!(service_dir_exists(&fixture));
        assert!(!fixture.calls().iter().any(|c| c.contains("s6-svscanctl")));
    }

    #[test]
    fn a_stopped_pool_only_loses_the_directory() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new(0);
        fixture.seed_dir("fp1-php83", "example.test");
        // Empty `ps -q` output: no running container for the pool.
        fixture.fail_on("never-matches");

        let result = remove_site_service(
            &fixture.ctx(),
            &remove_req(ID, None),
            &CancellationToken::default(),
        )
        .unwrap();
        assert!(result.removed);
        assert!(!result.pool_running);
        assert!(!service_dir_exists(&fixture));
        assert_eq!(
            fixture.calls().len(),
            1,
            "only the ps probe: {:?}",
            fixture.calls()
        );
    }

    #[test]
    fn a_held_stack_lock_blocks_a_site_removal_before_docker_runs() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new(0);
        fixture.seed_dir("fp1-php83", "example.test");
        let stack_scope = crate::stack_deploy::open_scope(&fixture.state).unwrap();
        let _held = crate::stack_deploy::acquire_stack_lock(
            &stack_scope,
            RequestId::parse(OTHER_ID).unwrap(),
        )
        .unwrap();

        let error = remove_site_service(
            &fixture.ctx(),
            &remove_req(ID, None),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::StackBusy));
        assert!(fixture.calls().is_empty());
        assert!(service_dir_exists(&fixture));
    }

    #[test]
    fn remove_site_service_rejects_malformed_fields() {
        assert_eq!(
            RemoveSiteServiceRequest::parse("fp1-php83", "../etc", ID, None).err(),
            Some(RequestError::InvalidDomain)
        );
        assert_eq!(
            RemoveSiteServiceRequest::parse("bad id", "example.test", ID, None).err(),
            Some(RequestError::InvalidRuntimeId)
        );
    }

    #[test]
    fn site_requests_reject_malformed_fields() {
        assert_eq!(
            ActivateSiteConfigRequest::parse(
                "fp1-php83",
                "example.test",
                0,
                "/r".into(),
                "x {}".into(),
                None,
                ID,
                None
            )
            .err(),
            Some(RequestError::InvalidPort)
        );
        assert_eq!(
            ActivateSiteConfigRequest::parse(
                "fp1-php83",
                "-bad.test",
                80,
                "/r".into(),
                "x {}".into(),
                None,
                ID,
                None
            )
            .err(),
            Some(RequestError::InvalidDomain)
        );
        assert_eq!(
            ActivateSiteConfigRequest::parse(
                "fp1-php83",
                "example.test",
                80,
                "/r".into(),
                "x {}".into(),
                Some("zz"),
                ID,
                None
            )
            .err(),
            Some(RequestError::InvalidPriorHash)
        );
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
    fn ensure_starts_the_pool_under_its_profile_and_waits_for_healthy() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new(0);
        let req = EnsureRequest::parse("fp1-php84", Some("php-8.4"), ID, Some("up-1")).unwrap();

        let result = ensure_runtime(&fixture.ctx(), &req, &CancellationToken::default()).unwrap();
        assert_eq!(result.service, "runtime-fp1-php84");
        ensure_runtime(&fixture.ctx(), &req, &CancellationToken::default()).unwrap();

        let prefix = compose_prefix(&fixture);
        assert_eq!(
            fixture.calls(),
            vec![
                format!("{prefix} --profile php-8.4 up -d runtime-fp1-php84"),
                format!("{prefix} ps -q runtime-fp1-php84"),
                format!(
                    "{} inspect -f {{{{if .State.Health}}}}{{{{.State.Health.Status}}}}{{{{end}}}} \
                     c0ffee",
                    fixture.stack_dir.display()
                ),
            ]
        );
    }

    #[test]
    fn ensure_without_a_profile_is_a_plain_up() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new(0);
        let req = EnsureRequest::parse("fp1-php83", None, ID, None).unwrap();

        ensure_runtime(&fixture.ctx(), &req, &CancellationToken::default()).unwrap();
        assert_eq!(
            fixture.calls()[0],
            format!("{} up -d runtime-fp1-php83", compose_prefix(&fixture))
        );
    }

    #[test]
    fn a_pool_that_never_turns_healthy_times_out_and_replays_as_one() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new(0);
        fixture.health("starting");
        let req = EnsureRequest::parse("fp1-php83", None, ID, Some("up-2")).unwrap();

        let error =
            ensure_runtime(&fixture.ctx(), &req, &CancellationToken::default()).unwrap_err();
        assert!(matches!(&error, Error::Unhealthy(Some(status)) if status == "starting"));
        assert_eq!(error.protocol().0, ErrorCode::Timeout);
        let calls = fixture.calls().len();
        assert!(calls > 3, "polled more than once: {calls}");
        assert!(matches!(
            ensure_runtime(&fixture.ctx(), &req, &CancellationToken::default()),
            Err(Error::Replayed {
                code: ErrorCode::Timeout,
                ..
            })
        ));
        assert_eq!(fixture.calls().len(), calls);
    }

    #[test]
    fn a_failed_up_skips_the_health_wait() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new(1);
        let req = EnsureRequest::parse("fp1-php83", None, ID, None).unwrap();

        let error =
            ensure_runtime(&fixture.ctx(), &req, &CancellationToken::default()).unwrap_err();
        assert!(matches!(error, Error::Rejected(Stage::Up, _)));
        assert_eq!(error.protocol().0, ErrorCode::SubprocessFailed);
        assert_eq!(fixture.calls().len(), 1);
    }

    #[test]
    fn reload_workers_restarts_the_pool_site_services() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new(0);
        let req = RuntimeRequest::parse("fp1-php84", ID, None).unwrap();

        let result = reload_workers(&fixture.ctx(), &req, &CancellationToken::default()).unwrap();
        assert_eq!(result.service, "runtime-fp1-php84");
        assert_eq!(
            fixture.calls(),
            vec![format!(
                "{} exec -T runtime-fp1-php84 sh -c {RELOAD_WORKERS_SCRIPT}",
                compose_prefix(&fixture)
            )]
        );
    }

    #[test]
    fn flush_fpc_runs_the_fixed_purge_in_the_pool() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new(0);
        let req = RuntimeRequest::parse("fp1-php84", ID, None).unwrap();

        flush_fpc(&fixture.ctx(), &req, &CancellationToken::default()).unwrap();
        assert_eq!(
            fixture.calls(),
            vec![format!(
                "{} exec -T runtime-fp1-php84 sh -c {FLUSH_FPC_SCRIPT}",
                compose_prefix(&fixture)
            )]
        );
    }

    #[test]
    fn a_held_stack_lock_blocks_ensure_and_both_pool_actions() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new(0);
        let stack_scope = crate::stack_deploy::open_scope(&fixture.state).unwrap();
        let _held = crate::stack_deploy::acquire_stack_lock(
            &stack_scope,
            RequestId::parse(OTHER_ID).unwrap(),
        )
        .unwrap();
        let cancel = CancellationToken::default();
        let ensure = EnsureRequest::parse("fp1-php83", None, ID, None).unwrap();
        let pool = RuntimeRequest::parse("fp1-php83", ID, None).unwrap();

        assert!(matches!(
            ensure_runtime(&fixture.ctx(), &ensure, &cancel),
            Err(Error::StackBusy)
        ));
        assert!(matches!(
            reload_workers(&fixture.ctx(), &pool, &cancel),
            Err(Error::StackBusy)
        ));
        assert!(matches!(
            flush_fpc(&fixture.ctx(), &pool, &cancel),
            Err(Error::StackBusy)
        ));
        assert!(fixture.calls().is_empty());
    }

    #[test]
    fn ensure_accepts_only_a_php_version_profile() {
        for good in ["php-8.4", "php-10.12"] {
            assert!(
                EnsureRequest::parse("fp1-php84", Some(good), ID, None).is_ok(),
                "{good}"
            );
        }
        for bad in [
            "",
            "php-8",
            "php-8.4.1",
            "php-8.x",
            "PHP-8.4",
            "php-8.4 ",
            "db",
        ] {
            assert_eq!(
                EnsureRequest::parse("fp1-php84", Some(bad), ID, None).err(),
                Some(RequestError::InvalidProfile),
                "{bad:?}"
            );
        }
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
