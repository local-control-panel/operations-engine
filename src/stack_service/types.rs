use super::*;

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

pub(super) fn runtime_service(runtime_id: &RuntimeId) -> String {
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
    InvalidRoot,
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
            Self::InvalidRoot => {
                "root must be a plain absolute path under a content root, without spaces or dot segments"
            }
        }
    }
}

pub(super) fn parse_ids(
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
pub(super) fn valid_profile(profile: &str) -> bool {
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
    /// The request `site.probe` makes through the pool.
    ApplicationProbe,
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
            Self::ApplicationProbe => "the probe request to the site failed",
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
    /// `site.probe`: the site directory could not be opened safely.
    SiteDirectory(crate::site_root::Error),
    /// `site.probe`: the page answered, but not with what the probe expects
    /// (wrong document root, a PHP error page, OPcache not available).
    ProbeUnexpected(&'static str),
    /// `site.setErrorPages`: the site has no process `Caddyfile` to edit.
    SiteConfigMissing,
    /// `site.setErrorPages`: the `Caddyfile` could not be edited (unbalanced
    /// markers, no site block).
    ConfigMalformed(&'static str),
    /// `site.setErrorPages`: the config activation failed and the error page
    /// files could not be put back as they were.
    PagesRecoveryFailed,
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
            Self::SiteDirectory(error) => error.protocol(),
            Self::ProbeUnexpected(message) => (ErrorCode::SubprocessFailed, (*message).to_owned()),
            Self::SiteConfigMissing => (
                ErrorCode::NotFound,
                "the site has no process config to edit".into(),
            ),
            Self::ConfigMalformed(message) => (ErrorCode::InvalidInput, (*message).to_owned()),
            Self::PagesRecoveryFailed => (
                ErrorCode::ConfigRecoveryFailed,
                "the site config was not activated and the previous error page files could not be restored"
                    .into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit(_) => {
                (ErrorCode::Internal, "internal stack service error".into())
            }
        }
    }
}
