//! `site.migrateRuntime` (milestone 089): moves one site from its runtime pool
//! to another, as one operation with one transaction and a compensation
//! journal, instead of the nine-call sequence the panel used to orchestrate.
//!
//! The sequence (every step is an existing engine operation, driven through
//! [`Backend`]):
//!
//! 1. read the site's route (maintenance backup first, then the live one; a
//!    disabled route is refused), its current pool and its identity;
//! 2. on the target pool: allocate the identity (same account, the pool's own
//!    port), write the s6 service, activate the pool's exec config, and probe
//!    the site through the target pool (`site.probe` token or the configured
//!    health check);
//! 3. cutover: `ingress.activateConfig` with the route pointing at the target
//!    pool, guarded by the hash of the route read in step 1;
//! 4. verify through the ingress (only for a publicly routable route);
//! 5. clean up the old pool: exec config, service, identity record, idle stop.
//!
//! A failure before step 5 undoes what was done, in reverse order: the route
//! first (when the cutover was attempted), then the target's exec config,
//! service and identity. A failure in step 5 does **not** undo the migration:
//! the site already runs on the target pool, so the result is a success with
//! `warnings` naming what could not be cleaned up.
//!
//! The target pool must already be running: the engine does not start pools
//! (`stack.ensureRuntime` does), and activating the exec config in a stopped
//! pool fails and is compensated.
//!
//! Before anything changes a journal is written to
//! `site-migrate-runtime/<domain>/pending/<request id>.json` with the previous
//! route and which target artifacts may exist (flags are set *before* the step
//! that creates them). A killed engine leaves the journal behind and
//! `site.reconcile` finishes the job: before the cleanup phase it rolls back
//! (route restored if the cutover was attempted, target artifacts removed);
//! once the cleanup phase started it rolls forward.
//!
//! Locking: each sub-operation takes the shared stack lock for itself; the
//! lock is not held across the whole sequence (`stack.deploy` can run between
//! two steps), and one migration per domain is serialised by the scope lock.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    ingress::ConfigHash,
    mutation::preflight,
    site::{Domain, RuntimeId, SiteRelativePath},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        lock,
        state::{self, TransactionStatus},
    },
};

#[cfg(unix)]
pub mod host;

pub const OPERATION: &str = "site.migrateRuntime";
pub const SCOPE: &str = "site-migrate-runtime";

const MAX_HEALTH_PATH_BYTES: usize = 2048;
const MAX_HEALTH_BODY_BYTES: usize = 64 * 1024;

/// `--health-*`: an HTTP check to run instead of the control-token probe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthCheck {
    pub path: String,
    pub expected_status: u16,
    pub expected_body: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestError {
    InvalidDomain,
    InvalidRuntimeId,
    InvalidHealthPath,
    InvalidHealthStatus,
    HealthBodyTooLarge,
    IncompleteHealthCheck,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl RequestError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidDomain => "domain is not a valid domain name",
            Self::InvalidRuntimeId => "target-runtime-id is not a valid runtime id",
            Self::InvalidHealthPath => {
                "health path must be a same-origin absolute path beginning with one /, with no \
                 fragment or control characters, at most 2048 bytes"
            }
            Self::InvalidHealthStatus => "health status must be between 100 and 599",
            Self::HealthBodyTooLarge => "health body must be at most 64 KiB",
            Self::IncompleteHealthCheck => "health-status and health-body need health-path",
            Self::InvalidRequestId => "request-id is not a canonical UUID",
            Self::InvalidIdempotencyKey => "idempotency-key is invalid",
        }
    }
}

pub struct Request {
    pub domain: Domain,
    pub target: RuntimeId,
    pub health: Option<HealthCheck>,
    /// Stop the old pool once its last site is gone. The caller decides: the
    /// engine does not know which pool is the base install's default, which
    /// must keep running.
    pub stop_idle_source: bool,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl Request {
    #[allow(clippy::too_many_arguments)]
    pub fn parse(
        domain: &str,
        target_runtime_id: &str,
        health_path: Option<&str>,
        health_status: Option<u16>,
        health_body: Option<&str>,
        stop_idle_source: bool,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let health = match health_path {
            None if health_status.is_some() || health_body.is_some() => {
                return Err(RequestError::IncompleteHealthCheck);
            }
            None => None,
            Some(path) => {
                let path = path.trim();
                if !path.starts_with('/')
                    || path.starts_with("//")
                    || path.contains('#')
                    || path.len() > MAX_HEALTH_PATH_BYTES
                    || path.chars().any(char::is_control)
                {
                    return Err(RequestError::InvalidHealthPath);
                }
                let expected_status = health_status.unwrap_or(200);
                if !(100..=599).contains(&expected_status) {
                    return Err(RequestError::InvalidHealthStatus);
                }
                if health_body.is_some_and(|body| body.len() > MAX_HEALTH_BODY_BYTES) {
                    return Err(RequestError::HealthBodyTooLarge);
                }
                Some(HealthCheck {
                    path: path.to_owned(),
                    expected_status,
                    expected_body: health_body.map(str::to_owned),
                })
            }
        };
        Ok(Self {
            domain: Domain::parse(domain).map_err(|_| RequestError::InvalidDomain)?,
            target: RuntimeId::parse(target_runtime_id)
                .map_err(|_| RequestError::InvalidRuntimeId)?,
            health,
            stop_idle_source,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }
}

/// Which of the domain's route files the migration retargets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RouteKind {
    /// `<domain>.caddyfile`: validated and reloaded; publicly routable.
    Live,
    /// `<domain>.maintenance-backup`: a parked site; not imported, so there is
    /// nothing to verify through the ingress.
    Backup,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub kind: RouteKind,
    pub content: String,
}

/// One site's record in one pool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub os_user: String,
    pub uid: u32,
    pub gid: u32,
    pub port: u16,
    pub root: String,
    pub worker_mode: bool,
    pub worker_count: i64,
}

#[derive(Clone, Debug)]
pub struct StepError {
    pub code: ErrorCode,
    pub message: String,
}

impl StepError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// The engine operations the migration is made of. [`host::HostBackend`] runs
/// the real ones; tests use a recording fake.
pub trait Backend {
    fn read_route(&self, domain: &Domain) -> Result<Route, StepError>;
    fn read_identity(
        &self,
        runtime: &RuntimeId,
        domain: &Domain,
    ) -> Result<Option<Identity>, StepError>;
    /// `site.allocateIdentity` on `runtime` for the account `from` already uses.
    fn allocate_identity(
        &self,
        runtime: &RuntimeId,
        domain: &Domain,
        from: &Identity,
    ) -> Result<Identity, StepError>;
    /// `stack.writeSiteService`.
    fn write_service(
        &self,
        runtime: &RuntimeId,
        domain: &Domain,
        identity: &Identity,
    ) -> Result<(), StepError>;
    /// `runtime.activateConfig` for a config that must not exist yet.
    fn activate_exec_config(
        &self,
        runtime: &RuntimeId,
        domain: &Domain,
        content: &str,
    ) -> Result<(), StepError>;
    /// The application probe through `service` (`runtime-<id>` or `ingress`),
    /// with retries.
    fn probe(
        &self,
        service: &str,
        domain: &Domain,
        root: &str,
        health: Option<&HealthCheck>,
    ) -> Result<(), StepError>;
    /// `ingress.activateConfig` on `kind`, guarded by the hash `expected`.
    fn activate_route(
        &self,
        domain: &Domain,
        kind: RouteKind,
        content: &str,
        expected: &ConfigHash,
    ) -> Result<(), StepError>;
    /// `runtime.removeConfig`; a missing config is success.
    fn remove_exec_config(&self, runtime: &RuntimeId, domain: &Domain) -> Result<(), StepError>;
    /// `stack.removeSiteService`; a missing service is success.
    fn remove_service(&self, runtime: &RuntimeId, domain: &Domain) -> Result<(), StepError>;
    /// `site.releaseIdentity` without removing the account.
    fn release_identity(&self, runtime: &RuntimeId, domain: &Domain) -> Result<(), StepError>;
    /// `stack.stopIdleRuntime`.
    fn stop_idle_pool(&self, runtime: &RuntimeId) -> Result<(), StepError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Phase {
    /// Nothing outside the target pool has changed.
    Preparing,
    /// The route may already point at the target.
    Cutover,
    /// The site runs on the target; only the old pool is being cleaned up.
    Cleanup,
}

/// Which target artifacts may exist. Set before the step that creates them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetArtifacts {
    pub identity: bool,
    pub service: bool,
    pub exec_config: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Journal {
    pub request_id: String,
    pub domain: String,
    pub from_runtime: String,
    pub to_runtime: String,
    pub route_kind: RouteKind,
    pub previous_route: String,
    pub previous_route_sha256: String,
    pub new_route_sha256: String,
    pub phase: Phase,
    pub target: TargetArtifacts,
    #[serde(default)]
    pub stop_idle_source: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrateResult {
    pub domain: String,
    pub from_runtime_id: String,
    pub to_runtime_id: String,
    pub port: u16,
    /// What could not be cleaned up on the old pool; the site is on the new one.
    pub warnings: Vec<String>,
    pub completed_at_unix_secs: u64,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Replayed { code: ErrorCode, message: String },
    Failed(StepError),
    PostCommit(MigrateResult),
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) | Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "another migration of this site is already in progress".into(),
            ),
            Self::Failed(step) => (step.code, step.message.clone()),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit(_) => (
                ErrorCode::Internal,
                "internal runtime migration error".into(),
            ),
        }
    }
}

fn rel(path: &str) -> SiteRelativePath {
    SiteRelativePath::parse(path).expect("static or validated path")
}

pub fn scope_path(domain: &Domain) -> SiteRelativePath {
    rel(&format!("{SCOPE}/{domain}"))
}

fn journal_path(id: &str) -> SiteRelativePath {
    rel(&format!("pending/{id}.json"))
}

fn open_scope(engine_state: &ManagedRoot, domain: &Domain) -> std::io::Result<ManagedRoot> {
    let path = scope_path(domain);
    engine_state.create_dir_all(&path)?;
    let scope = engine_state.open_managed_dir(&path)?;
    for child in ["locks", "transactions", "audit", "pending"] {
        scope.create_dir_all(&rel(child))?;
    }
    Ok(scope)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn sha(content: &str) -> ConfigHash {
    ConfigHash::of(content.as_bytes())
}

/// The runtime pool a route proxies to: the `runtime-<id>` in its
/// `reverse_proxy runtime-<id>:80` line.
pub fn runtime_of_route(route: &str) -> Option<RuntimeId> {
    route.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("reverse_proxy ")?;
        let container = rest.split(':').next()?;
        RuntimeId::parse(container.strip_prefix("runtime-")?).ok()
    })
}

/// Swaps only the `reverse_proxy` target (and the two lines that name the
/// runtime) inside an existing route, keeping every other block: basic auth,
/// security headers, redirects, IP ACL. `None` when there is no
/// `reverse_proxy` line to retarget.
pub fn retarget_route(route: &str, new_target: &RuntimeId) -> Option<String> {
    let service = format!("runtime-{new_target}");
    let mut found = false;
    let updated: Vec<String> = route
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            let indent = &line[..line.len() - trimmed.len()];
            if trimmed.starts_with("reverse_proxy ") {
                found = true;
                let block = if line.trim_end().ends_with('{') {
                    " {"
                } else {
                    ""
                };
                format!("{indent}reverse_proxy {service}:80{block}")
            } else if trimmed.starts_with("header_up X-WCP-Runtime-ID ") {
                format!("{indent}header_up X-WCP-Runtime-ID {new_target}")
            } else if trimmed.starts_with("log_append runtime_id ") {
                format!("{indent}log_append runtime_id {new_target}")
            } else {
                line.to_owned()
            }
        })
        .collect();
    if !found {
        return None;
    }
    let mut result = updated.join("\n");
    if route.ends_with('\n') {
        result.push('\n');
    }
    Some(result)
}

/// The pool's own route to one site's child process (the exec config).
pub fn pool_reverse_proxy_caddyfile(domain: &Domain, port: u16) -> String {
    // The child listens on a loopback-only site address; Host is retargeted
    // for that private hop.
    format!(
        "http://{domain} {{\n    reverse_proxy 127.0.0.1:{port} {{\n        header_up Host 127.0.0.1:{port}\n    }}\n}}\n"
    )
}

/// `docker compose exec -T <service> curl ...` for a configured health check:
/// plain HTTP with the site's `Host` header against a runtime pool, HTTPS with
/// `--resolve` against the ingress. The status code follows `marker` in stdout.
pub fn health_curl_args(
    service: &str,
    domain: &Domain,
    check: &HealthCheck,
    marker: &str,
) -> Vec<String> {
    let mut args: Vec<String> = ["exec", "-T", service, "curl"].map(str::to_owned).to_vec();
    let write_out = format!("{marker}%{{http_code}}");
    if service == "ingress" {
        args.extend(
            [
                "-sSk",
                "--max-time",
                "5",
                "--max-filesize",
                "65536",
                "--resolve",
                &format!("{domain}:443:127.0.0.1"),
                "-w",
                &write_out,
                &format!("https://{domain}{}", check.path),
            ]
            .map(str::to_owned),
        );
    } else {
        args.extend(
            [
                "-sS",
                "--max-time",
                "5",
                "--max-filesize",
                "65536",
                "-H",
                &format!("Host: {domain}"),
                "-w",
                &write_out,
                &format!("http://127.0.0.1{}", check.path),
            ]
            .map(str::to_owned),
        );
    }
    args
}

/// The curl `-w` suffix result of a configured health probe against `check`.
pub fn check_health(output: &str, marker: &str, check: &HealthCheck) -> Result<(), String> {
    let (body, status) = output
        .rsplit_once(marker)
        .ok_or("the health probe returned no HTTP status marker")?;
    let status: u16 = status
        .parse()
        .map_err(|_| format!("the health probe returned an invalid HTTP status {status:?}"))?;
    if status != check.expected_status {
        return Err(format!(
            "the health probe for {} returned HTTP {status}, expected {}",
            check.path, check.expected_status
        ));
    }
    if let Some(expected) = &check.expected_body {
        if body != expected {
            return Err(format!(
                "the health probe for {} returned unexpected content",
                check.path
            ));
        }
    }
    Ok(())
}

struct Store<'a> {
    scope: &'a ManagedRoot,
}

impl Store<'_> {
    fn create(&self, journal: &Journal) -> Result<(), StepError> {
        let bytes = serde_json::to_vec(journal).expect("a journal always serializes");
        self.scope
            .create_new(&journal_path(&journal.request_id), &bytes)
            .map_err(|_| {
                StepError::new(
                    ErrorCode::Conflict,
                    "a migration journal for this request already exists",
                )
            })
    }

    fn save(&self, journal: &Journal) -> Result<(), StepError> {
        let bytes = serde_json::to_vec(journal).expect("a journal always serializes");
        self.scope
            .write_atomic(&journal_path(&journal.request_id), &bytes)
            .map_err(|_| {
                StepError::new(
                    ErrorCode::Internal,
                    "the migration journal could not be saved",
                )
            })
    }

    fn remove(&self, journal: &Journal) {
        let _ = self.scope.remove_file(&journal_path(&journal.request_id));
    }
}

/// Undoes a migration that did not reach the cleanup phase: the route first
/// (when the cutover was attempted), then the target's exec config, service and
/// identity. Every step that fails is reported and the rest still run; the
/// journal flags of what was removed are saved, so a repeat only retries the
/// remainder. `Ok` means nothing of the migration is left.
fn roll_back(
    backend: &dyn Backend,
    store: &Store<'_>,
    journal: &mut Journal,
) -> Result<(), String> {
    let (Ok(domain), Ok(to)) = (
        Domain::parse(&journal.domain),
        RuntimeId::parse(&journal.to_runtime),
    ) else {
        return Err("the journal names an invalid domain or runtime".into());
    };
    let mut errors = Vec::new();
    if journal.phase == Phase::Cutover {
        let current = backend.read_route(&domain);
        let restored = match &current {
            Ok(route) if sha(&route.content).as_str() == journal.previous_route_sha256 => true,
            // Only our own new route is put back; anything else was written by
            // someone since and is not ours to overwrite.
            Ok(route) if sha(&route.content).as_str() == journal.new_route_sha256 => backend
                .activate_route(
                    &domain,
                    journal.route_kind,
                    &journal.previous_route,
                    &sha(&route.content),
                )
                .map(|()| true)
                .unwrap_or_else(|error| {
                    errors.push(format!("route restore failed: {}", error.message));
                    false
                }),
            Ok(_) => {
                errors.push("the route was changed by someone else; left as it is".into());
                false
            }
            Err(error) => {
                errors.push(format!("route could not be read: {}", error.message));
                false
            }
        };
        if !restored {
            // The route may still reference the target: leave its artifacts.
            return Err(errors.join("; "));
        }
        journal.phase = Phase::Preparing;
        let _ = store.save(journal);
    }
    if journal.target.exec_config {
        match backend.remove_exec_config(&to, &domain) {
            Ok(()) => journal.target.exec_config = false,
            Err(error) => errors.push(format!("remove runtime config: {}", error.message)),
        }
    }
    if journal.target.service {
        match backend.remove_service(&to, &domain) {
            Ok(()) => journal.target.service = false,
            Err(error) => errors.push(format!("remove site service: {}", error.message)),
        }
    }
    // The record only: the account belongs to the site and stays with its pool.
    if journal.target.identity {
        match backend.release_identity(&to, &domain) {
            Ok(()) => journal.target.identity = false,
            Err(error) => errors.push(format!("remove site identity: {}", error.message)),
        }
    }
    let _ = store.save(journal);
    if errors.is_empty()
        && !journal.target.exec_config
        && !journal.target.service
        && !journal.target.identity
    {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// Cleans up the old pool. Each failure is a warning, never an error.
fn clean_old_pool(backend: &dyn Backend, journal: &Journal) -> Vec<String> {
    let (Ok(domain), Ok(from)) = (
        Domain::parse(&journal.domain),
        RuntimeId::parse(&journal.from_runtime),
    ) else {
        return vec!["oldPoolCleanupFailed: the journal names an invalid domain or runtime".into()];
    };
    let mut warnings = Vec::new();
    let mut note = |what: &str, result: Result<(), StepError>| {
        if let Err(error) = result {
            warnings.push(format!("oldPoolCleanupFailed: {what}: {}", error.message));
        }
    };
    note(
        "remove runtime config",
        backend.remove_exec_config(&from, &domain),
    );
    note(
        "remove site service",
        backend.remove_service(&from, &domain),
    );
    note(
        "remove site identity",
        backend.release_identity(&from, &domain),
    );
    if journal.stop_idle_source {
        note("stop the idle pool", backend.stop_idle_pool(&from));
    }
    warnings
}

/// Runs the migration. `journal` records progress under `scope`; on success
/// it is gone, on a failed rollback it stays for `site.reconcile`.
fn run(
    backend: &dyn Backend,
    store: &Store<'_>,
    req: &Request,
) -> Result<MigrateResult, StepError> {
    let fail = |code, message: String| Err(StepError::new(code, message));
    let domain = &req.domain;
    let route = backend.read_route(domain)?;
    let Some(from) = runtime_of_route(&route.content) else {
        return fail(
            ErrorCode::InvalidInput,
            format!("{domain}'s route does not proxy to a runtime pool"),
        );
    };
    if from == req.target {
        return fail(
            ErrorCode::InvalidInput,
            format!("{domain} is already on runtime {}", req.target),
        );
    }
    let Some(new_route) = retarget_route(&route.content, &req.target) else {
        return fail(
            ErrorCode::InvalidInput,
            "the ingress route has no reverse_proxy line to retarget".into(),
        );
    };
    let Some(identity) = backend.read_identity(&from, domain)? else {
        return fail(
            ErrorCode::NotFound,
            format!("{domain} has no identity record on runtime {from}"),
        );
    };

    let mut journal = Journal {
        request_id: req.request_id.to_string(),
        domain: domain.to_string(),
        from_runtime: from.to_string(),
        to_runtime: req.target.to_string(),
        route_kind: route.kind,
        previous_route: route.content.clone(),
        previous_route_sha256: sha(&route.content).as_str().to_owned(),
        new_route_sha256: sha(&new_route).as_str().to_owned(),
        phase: Phase::Preparing,
        target: TargetArtifacts::default(),
        stop_idle_source: req.stop_idle_source,
    };
    store.create(&journal)?;

    // Undo everything and say how it went.
    let abort = |journal: &mut Journal, error: StepError| -> StepError {
        match roll_back(backend, store, journal) {
            Ok(()) => {
                store.remove(journal);
                StepError::new(
                    error.code,
                    format!("{}; rolled back to {}", error.message, journal.from_runtime),
                )
            }
            Err(problem) => StepError::new(
                error.code,
                format!(
                    "{}; the rollback is incomplete and needs site.reconcile: {problem}",
                    error.message
                ),
            ),
        }
    };

    let prepared = (|| -> Result<Identity, StepError> {
        journal.target.identity = true;
        store.save(&journal)?;
        let target_identity = backend.allocate_identity(&req.target, domain, &identity)?;
        if target_identity.uid != identity.uid || target_identity.gid != identity.gid {
            return Err(StepError::new(
                ErrorCode::Conflict,
                format!(
                    "the engine allocated a different identity for {domain} on the target pool \
                     than the site already runs as"
                ),
            ));
        }
        journal.target.service = true;
        store.save(&journal)?;
        backend.write_service(&req.target, domain, &target_identity)?;
        journal.target.exec_config = true;
        store.save(&journal)?;
        backend.activate_exec_config(
            &req.target,
            domain,
            &pool_reverse_proxy_caddyfile(domain, target_identity.port),
        )?;
        crate::failpoint::hit("migrate-runtime.prepared");
        backend
            .probe(
                &format!("runtime-{}", req.target),
                domain,
                &identity.root,
                req.health.as_ref(),
            )
            .map_err(|error| {
                StepError::new(
                    error.code,
                    format!(
                        "target runtime pool runtime-{} is not ready for {domain}: {}",
                        req.target, error.message
                    ),
                )
            })?;
        Ok(target_identity)
    })();
    let target_identity = match prepared {
        Ok(value) => value,
        Err(error) => return Err(abort(&mut journal, error)),
    };

    // Cutover. From here the route may point at the target.
    journal.phase = Phase::Cutover;
    if let Err(error) = store.save(&journal) {
        journal.phase = Phase::Preparing;
        return Err(abort(&mut journal, error));
    }
    if let Err(error) = backend.activate_route(domain, route.kind, &new_route, &sha(&route.content))
    {
        return Err(abort(&mut journal, error));
    }
    crate::failpoint::hit("migrate-runtime.cutover");
    if route.kind == RouteKind::Live {
        if let Err(error) = backend.probe("ingress", domain, &identity.root, req.health.as_ref()) {
            let error = StepError::new(
                error.code,
                format!("Post-cutover check failed for {domain}: {}", error.message),
            );
            return Err(abort(&mut journal, error));
        }
    }

    // The site runs on the target now; what follows never undoes it.
    journal.phase = Phase::Cleanup;
    let _ = store.save(&journal);
    crate::failpoint::hit("migrate-runtime.cleanup");
    let warnings = clean_old_pool(backend, &journal);
    Ok(MigrateResult {
        domain: domain.to_string(),
        from_runtime_id: from.to_string(),
        to_runtime_id: req.target.to_string(),
        port: target_identity.port,
        warnings,
        completed_at_unix_secs: unix_now(),
    })
}

/// Admission (scope lock, idempotency, transaction), the migration, then the
/// transaction record and audit entry.
pub fn execute(
    engine_state: &ManagedRoot,
    backend: &dyn Backend,
    req: &Request,
) -> Result<MigrateResult, Error> {
    let scope = open_scope(engine_state, &req.domain).map_err(Error::Io)?;
    let admitted = match preflight::run(
        &scope,
        req.request_id,
        req.idempotency_key.as_ref(),
        OPERATION,
    )
    .map_err(Error::Preflight)?
    {
        preflight::Outcome::Replay(original) => return replay(&scope, original),
        preflight::Outcome::Proceed(admitted) => admitted,
    };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path = rel(&format!("transactions/{}.json", req.request_id));
    let audit_path = rel("audit/events.jsonl");
    let store = Store { scope: &scope };

    match run(backend, &store, req) {
        Err(error) => {
            let _ = state.mark_failed(error.code, error.message.clone());
            let _ = state::save(&scope, &state_path, &state);
            let _ = audit::append(
                &scope,
                &audit_path,
                &AuditRecord::result(req.request_id, false, Some(error.code)),
            );
            Err(Error::Failed(error))
        }
        Ok(result) => {
            state
                .mark_committed(serde_json::to_value(&result).expect("results always serialize"))
                .expect("state is always InProgress at this point");
            let saved = state::save(&scope, &state_path, &state);
            // The record first: a journal left beside a committed record is
            // only removed by site.reconcile, never acted on.
            let _ = scope.remove_file(&journal_path(&req.request_id.to_string()));
            if saved.is_err() {
                drop(lock);
                return Err(Error::PostCommit(result));
            }
            let _ = audit::append(
                &scope,
                &audit_path,
                &AuditRecord::result(req.request_id, true, None),
            );
            drop(lock);
            Ok(result)
        }
    }
}

fn replay(scope: &ManagedRoot, original: RequestId) -> Result<MigrateResult, Error> {
    let path = rel(&format!("transactions/{original}.json"));
    let recorded = state::load(scope, &path).map_err(|_| {
        Error::Io(std::io::Error::other(
            "the original transaction cannot be read",
        ))
    })?;
    match recorded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => recorded
            .outcome
            .and_then(|outcome| outcome.result)
            .and_then(|value| serde_json::from_value(value).ok())
            .ok_or_else(|| Error::Io(std::io::Error::other("the recorded result is unreadable"))),
        TransactionStatus::Failed => {
            let outcome = recorded.outcome;
            Err(Error::Replayed {
                code: outcome
                    .as_ref()
                    .and_then(|o| o.error_code)
                    .unwrap_or(ErrorCode::Internal),
                message: outcome
                    .and_then(|o| o.error_message)
                    .unwrap_or_else(|| "the original request failed".into()),
            })
        }
    }
}

/// What `site.reconcile` made of one journal.
#[derive(Debug, PartialEq, Eq)]
pub enum Recovery {
    /// Rolled back to the old pool.
    RolledBack,
    /// The cleanup phase had started: finished it.
    Completed,
    /// The migration had committed; only the journal was left.
    Cleared,
    /// A live migration holds the domain.
    Busy,
    /// Nothing was changed or the rollback is incomplete; an operator has to look.
    Attention(String),
}

/// Finishes one interrupted migration from its journal, under the scope lock.
pub fn recover(
    engine_state: &ManagedRoot,
    backend: &dyn Backend,
    domain: &Domain,
    journal_name: &str,
    holder: RequestId,
) -> Recovery {
    let Ok(scope) = open_scope(engine_state, domain) else {
        return Recovery::Attention("the migration scope cannot be opened".into());
    };
    let Ok(_lock) = lock::acquire(&scope, &rel("locks/mutation.lock"), holder) else {
        return Recovery::Busy;
    };
    let Some(path) = journal_name
        .strip_suffix(".json")
        .and_then(|id| RequestId::parse(id).ok())
        .map(|id| journal_path(&id.to_string()))
    else {
        return Recovery::Attention("the journal has an invalid name".into());
    };
    let mut journal: Journal = match scope
        .read_to_string(&path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
    {
        Some(journal) => journal,
        None => return Recovery::Attention("the journal cannot be read".into()),
    };
    if journal.domain != domain.as_str() || !journal_name.starts_with(&journal.request_id) {
        return Recovery::Attention("the journal does not match its scope".into());
    }
    let Ok(id) = RequestId::parse(&journal.request_id) else {
        return Recovery::Attention("the journal names an invalid request id".into());
    };
    let state_path = rel(&format!("transactions/{id}.json"));
    let mut transaction = state::load(&scope, &state_path).ok();
    let store = Store { scope: &scope };

    if transaction
        .as_ref()
        .is_some_and(|t| t.status == TransactionStatus::Committed)
    {
        store.remove(&journal);
        return Recovery::Cleared;
    }
    if journal.phase == Phase::Cleanup {
        // The site already runs on the target: finish the cleanup.
        let warnings = clean_old_pool(backend, &journal);
        if let Some(t) = transaction.as_mut() {
            if t.status == TransactionStatus::InProgress {
                let result = MigrateResult {
                    domain: journal.domain.clone(),
                    from_runtime_id: journal.from_runtime.clone(),
                    to_runtime_id: journal.to_runtime.clone(),
                    port: 0,
                    warnings,
                    completed_at_unix_secs: unix_now(),
                };
                let _ = t.mark_committed(
                    serde_json::to_value(result).expect("results always serialize"),
                );
                let _ = state::save(&scope, &state_path, t);
            }
        }
        store.remove(&journal);
        return Recovery::Completed;
    }
    match roll_back(backend, &store, &mut journal) {
        Ok(()) => {
            store.remove(&journal);
            if let Some(t) = transaction.as_mut() {
                if t.status == TransactionStatus::InProgress
                    && t.mark_failed(
                        ErrorCode::Internal,
                        "interrupted; rolled back by site.reconcile",
                    )
                    .is_ok()
                {
                    let _ = state::save(&scope, &state_path, t);
                }
            }
            Recovery::RolledBack
        }
        Err(problem) => Recovery::Attention(format!("the rollback is incomplete: {problem}")),
    }
}

/// Pause between probe attempts (the panel's 5 x 500 ms window).
pub const PROBE_ATTEMPTS: usize = 5;
pub const PROBE_PAUSE: Duration = Duration::from_millis(500);

#[cfg(all(test, unix))]
mod tests;
