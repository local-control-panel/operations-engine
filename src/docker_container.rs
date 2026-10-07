//! `docker.containerAction` and `docker.setLimits`: the per-container verbs
//! the control panel's Containers tab offers (`start`, `stop`, `restart`,
//! `pause`, `unpause`, `rm [-f]`, and `docker update` limits) as typed,
//! audited, transactional operations instead of raw `docker` over SSH.
//!
//! Decisions (milestone 069):
//!
//! - Fixed argv, no shell. The caller names a container by a 12-64 digit hex
//!   id; the engine resolves it with `docker inspect` to the full 64 digit id
//!   (which must start with what the caller sent, so a container *named* like
//!   an id cannot be hit by mistake) and runs the verb against the full id.
//! - Labels are resolved engine-side, never taken from the caller. A
//!   container whose `com.docker.compose.project` label is `wcp` belongs to
//!   the engine-managed stack: every verb on it takes the shared `stacks/wcp`
//!   lock (a stop or restart racing `stack.deploy`'s `up -d` is the same race
//!   `docker.prune` closes), and `remove` is refused outright with
//!   `INVALID_INPUT` (the stack is torn down by `stack.deploy`/`compose`, not
//!   by deleting its containers one by one). Containers of other Compose
//!   projects, and plain containers, take no stack lock.
//! - Destructive verbs need their exact confirmation token: `CONTAINER_STOP`,
//!   `CONTAINER_RESTART`, `CONTAINER_REMOVE`, and `CONTAINER_REMOVE_FORCE`
//!   (`--force` is an explicit flag, valid for `remove` only, with a token of
//!   its own so a plain remove token never authorises a forced one). `start`,
//!   `pause`, `unpause` and `setLimits` are reversible and need none.
//! - `remove` never passes `-v`: anonymous volumes of the container are left
//!   for `docker.prune` rather than silently deleted with it.
//! - `setLimits` is `docker update --cpus --memory --memory-swap
//!   [--restart]`, bound by the host: `cpus` must be finite and not above the
//!   host's core count, `memoryBytes` is `0` or between 4 MiB and the host's
//!   RAM, the restart policy comes from a fixed allowlist. The limits are
//!   runtime-only: they live in the container's HostConfig, not in its
//!   Compose file, and are lost the next time Compose recreates the
//!   container (`up -d` after an image or config change, `stack.deploy`).
//! - `0` cannot mean "remove the limit": `docker update` treats `0` as
//!   "unchanged" (the old raw call silently did nothing). The engine reads the
//!   container's current limits during the inspect: `0` for a limit it does
//!   not have changes nothing, `0` for one it has raises it to the host's
//!   cores or RAM (the closest a running container gets to unlimited) and
//!   says so with `raisedToHostMax`. Recreating the container is the only
//!   way to truly remove a limit.
//! - Both operations share one scope (`docker-container`); lock, idempotency
//!   key, transaction record and audit entry come from `mutation::preflight`.
//!   The stack lock is taken before the scope's own lock whenever the
//!   container is managed, and a busy stack is `CONFLICT` without a recorded
//!   transaction (a retry with the same key runs). If the container is
//!   already gone a replay of a recorded request still returns its outcome.

use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{
        self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination,
        SubprocessDiagnostics,
    },
    site::SiteRelativePath,
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        state::{self, TransactionStatus},
    },
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const ACTION_OPERATION: &str = "docker.containerAction";
pub const LIMITS_OPERATION: &str = "docker.setLimits";
const SCOPE: &str = "docker-container";

/// The Compose project name of the engine-managed hosting stack.
pub const MANAGED_PROJECT: &str = "wcp";
const PROJECT_LABEL: &str = "com.docker.compose.project";
const INSPECT_TIMEOUT: Duration = Duration::from_secs(30);
const ACTION_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const MIN_MEMORY_BYTES: u64 = 4 * 1024 * 1024;
const RESTART_POLICIES: &[&str] = &[
    "no",
    "always",
    "unless-stopped",
    "on-failure",
    "on-failure:3",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Action {
    Start,
    Stop,
    Restart,
    Pause,
    Unpause,
    Remove,
}

impl Action {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "start" => Some(Self::Start),
            "stop" => Some(Self::Stop),
            "restart" => Some(Self::Restart),
            "pause" => Some(Self::Pause),
            "unpause" => Some(Self::Unpause),
            "remove" => Some(Self::Remove),
            _ => None,
        }
    }

    /// The token the caller must send, or `None` for a reversible verb.
    pub const fn confirmation(self, force: bool) -> Option<&'static str> {
        match (self, force) {
            (Self::Stop, _) => Some("CONTAINER_STOP"),
            (Self::Restart, _) => Some("CONTAINER_RESTART"),
            (Self::Remove, false) => Some("CONTAINER_REMOVE"),
            (Self::Remove, true) => Some("CONTAINER_REMOVE_FORCE"),
            _ => None,
        }
    }

    fn argv(self, force: bool, id: &str) -> Vec<String> {
        let verb = match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
            Self::Pause => "pause",
            Self::Unpause => "unpause",
            Self::Remove => "rm",
        };
        let mut argv = vec![verb.to_owned()];
        if self == Self::Remove && force {
            argv.push("-f".into());
        }
        argv.push(id.to_owned());
        argv
    }

    fn stage(self) -> Stage {
        match self {
            Self::Start => Stage::Start,
            Self::Stop => Stage::Stop,
            Self::Restart => Stage::Restart,
            Self::Pause => Stage::Pause,
            Self::Unpause => Stage::Unpause,
            Self::Remove => Stage::Remove,
        }
    }
}

/// A 12-64 digit lowercase hex container id, as the panel sends it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainerId(String);

impl ContainerId {
    pub fn parse(value: &str) -> Option<Self> {
        let ok = (12..=64).contains(&value.len())
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        ok.then(|| Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidContainerId,
    InvalidAction,
    /// `--force` was given for a verb other than `remove`.
    ForceNotApplicable,
    InvalidConfirmation,
    InvalidCpus,
    InvalidMemory,
    InvalidRestartPolicy,
    InvalidRequestId,
    InvalidIdempotencyKey,
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

#[derive(Debug)]
pub struct ActionRequest {
    pub container_id: ContainerId,
    pub action: Action,
    pub force: bool,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl ActionRequest {
    pub fn parse(
        container_id: &str,
        action: &str,
        force: bool,
        confirmation: Option<&str>,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let container_id =
            ContainerId::parse(container_id).ok_or(RequestError::InvalidContainerId)?;
        let action = Action::parse(action).ok_or(RequestError::InvalidAction)?;
        if force && action != Action::Remove {
            return Err(RequestError::ForceNotApplicable);
        }
        if let Some(token) = action.confirmation(force) {
            if confirmation != Some(token) {
                return Err(RequestError::InvalidConfirmation);
            }
        }
        let (request_id, idempotency_key) = parse_ids(request_id, key)?;
        Ok(Self {
            container_id,
            action,
            force,
            request_id,
            idempotency_key,
        })
    }
}

#[derive(Debug)]
pub struct LimitsRequest {
    pub container_id: ContainerId,
    /// `0` clears the limit.
    pub cpus: f64,
    /// `0` clears the limit.
    pub memory_bytes: u64,
    pub restart_policy: Option<String>,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl LimitsRequest {
    pub fn parse(
        container_id: &str,
        cpus: f64,
        memory_bytes: u64,
        restart_policy: Option<&str>,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let container_id =
            ContainerId::parse(container_id).ok_or(RequestError::InvalidContainerId)?;
        if !cpus.is_finite() || cpus < 0.0 {
            return Err(RequestError::InvalidCpus);
        }
        if memory_bytes != 0 && memory_bytes < MIN_MEMORY_BYTES {
            return Err(RequestError::InvalidMemory);
        }
        let restart_policy = match restart_policy {
            None | Some("") => None,
            Some(p) if RESTART_POLICIES.contains(&p) => Some(p.to_owned()),
            Some(_) => return Err(RequestError::InvalidRestartPolicy),
        };
        let (request_id, idempotency_key) = parse_ids(request_id, key)?;
        Ok(Self {
            container_id,
            cpus,
            memory_bytes,
            restart_policy,
            request_id,
            idempotency_key,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    Inspect,
    Start,
    Stop,
    Restart,
    Pause,
    Unpause,
    Remove,
    Update,
}

impl Stage {
    fn message(self) -> &'static str {
        match self {
            Self::Inspect => "could not inspect the container",
            Self::Start => "Docker rejected the container start",
            Self::Stop => "Docker rejected the container stop",
            Self::Restart => "Docker rejected the container restart",
            Self::Pause => "Docker rejected the container pause",
            Self::Unpause => "Docker rejected the container unpause",
            Self::Remove => "Docker rejected the container removal",
            Self::Update => "Docker rejected the container limits",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionResult {
    /// The full 64 digit id the verb ran against.
    pub container_id: String,
    pub action: Action,
    pub force: bool,
    /// The container belongs to the engine-managed `wcp` stack.
    pub managed: bool,
    pub completed_at_unix_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LimitsResult {
    pub container_id: String,
    /// The limit in force afterwards (`0` = none).
    pub cpus: f64,
    pub memory_bytes: u64,
    pub restart_policy: Option<String>,
    pub managed: bool,
    /// Always `true`: the limits are in the running container's HostConfig
    /// only and are lost when Compose recreates it.
    pub runtime_only: bool,
    /// A requested `0` could not remove a limit the container had (`docker
    /// update` ignores `0`), so it was raised to the host maximum instead.
    pub raised_to_host_max: bool,
    pub completed_at_unix_secs: u64,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub docker_program: &'a str,
    /// Logical cores of the host; `cpus` may not exceed it.
    pub host_cores: u32,
    /// Physical RAM of the host in bytes, or `None` when it cannot be read.
    pub host_memory_bytes: Option<u64>,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    StackBusy,
    ReplayInProgress,
    NotFound,
    /// `remove` of a container of the managed `wcp` stack.
    ManagedRemoveRefused,
    CpusAboveHost,
    MemoryAboveHost,
    HostResourcesUnknown,
    Run(Stage, process::ProcessRunError),
    Rejected(Stage, SubprocessDiagnostics),
    PostCommit {
        result: serde_json::Value,
    },
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
                "another stack operation is in progress".into(),
            ),
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another container operation is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::NotFound => (ErrorCode::NotFound, "no such container".into()),
            Self::ManagedRemoveRefused => (
                ErrorCode::InvalidInput,
                "containers of the managed wcp stack cannot be removed; stop the stack \
                 through the stack operations instead"
                    .into(),
            ),
            Self::CpusAboveHost => (
                ErrorCode::InvalidInput,
                "cpus exceeds the number of cores of the host".into(),
            ),
            Self::MemoryAboveHost => (
                ErrorCode::InvalidInput,
                "memory exceeds the RAM of the host".into(),
            ),
            Self::HostResourcesUnknown => (
                ErrorCode::DependencyUnavailable,
                "the host memory size could not be read, so the limit cannot be checked".into(),
            ),
            Self::Run(stage, error) => (process::spawn_error_code(error), stage.message().into()),
            Self::Rejected(stage, diagnostics) => (
                if diagnostics.timed_out {
                    ErrorCode::Timeout
                } else if diagnostics.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::SubprocessFailed
                },
                stage.message().into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit { .. } => (
                ErrorCode::Internal,
                "internal container operation error".into(),
            ),
        }
    }
}

/// The container as Docker reports it: its full id and Compose project.
#[derive(Debug)]
struct Resolved {
    id: String,
    managed: bool,
    /// The CPU limit the container has now (`0` = none).
    nano_cpus: u64,
    /// The memory limit the container has now (`0` = none).
    memory_bytes: u64,
}

fn run_docker(
    ctx: &Context<'_>,
    stage: Stage,
    argv: &[String],
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<process::ProcessOutput, Error> {
    let output = process::run(
        &ProcessRequest::new(ctx.docker_program).args(argv),
        &ProcessLimits {
            timeout,
            max_stdout_bytes: 64 * 1024,
            max_stderr_bytes: 64 * 1024,
        },
        cancel,
    )
    .map_err(|e| Error::Run(stage, e))?;
    if !matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        // Only the runner's own bookkeeping leaves this function; stderr is
        // looked at by the caller for the one case it classifies.
        return Err(Error::Rejected(
            stage,
            SubprocessDiagnostics::from_output(ctx.docker_program, &output),
        ));
    }
    Ok(output)
}

/// Resolves the caller's id to the full id and decides whether the container
/// belongs to the managed stack. Docker's "No such" answer is `NotFound`.
fn resolve(
    ctx: &Context<'_>,
    requested: &ContainerId,
    cancel: &CancellationToken,
) -> Result<Resolved, Error> {
    let argv = [
        "inspect".to_owned(),
        "--type".into(),
        "container".into(),
        "--format".into(),
        // The label goes last: it is free text and may contain spaces.
        format!(
            "{{{{.Id}}}} {{{{.HostConfig.NanoCpus}}}} {{{{.HostConfig.Memory}}}} \
             {{{{index .Config.Labels \"{PROJECT_LABEL}\"}}}}"
        ),
        requested.as_str().to_owned(),
    ];
    let output = process::run(
        &ProcessRequest::new(ctx.docker_program).args(&argv),
        &ProcessLimits {
            timeout: INSPECT_TIMEOUT,
            max_stdout_bytes: 16 * 1024,
            max_stderr_bytes: 16 * 1024,
        },
        cancel,
    )
    .map_err(|e| Error::Run(Stage::Inspect, e))?;
    match output.termination {
        ProcessTermination::Exited { success: true, .. } => {}
        ProcessTermination::Exited { .. }
            if String::from_utf8_lossy(&output.stderr.bytes).contains("No such") =>
        {
            return Err(Error::NotFound);
        }
        _ => {
            return Err(Error::Rejected(
                Stage::Inspect,
                SubprocessDiagnostics::from_output(ctx.docker_program, &output),
            ));
        }
    }
    parse_inspect(&String::from_utf8_lossy(&output.stdout.bytes), requested)
}

fn parse_inspect(stdout: &str, requested: &ContainerId) -> Result<Resolved, Error> {
    // Only the first line: a label value cannot smuggle a second record past
    // this parser.
    let line = stdout.lines().next().unwrap_or("");
    let mut fields = line.splitn(4, ' ');
    let id = fields.next().unwrap_or("");
    let nano_cpus = fields.next().and_then(|v| v.parse::<u64>().ok());
    let memory_bytes = fields.next().and_then(|v| v.parse::<u64>().ok());
    let project = fields.next().unwrap_or("");
    let full = ContainerId::parse(id)
        .filter(|full| full.as_str().len() == 64 && full.as_str().starts_with(requested.as_str()))
        .ok_or(Error::NotFound)?;
    Ok(Resolved {
        id: full.0,
        managed: project == MANAGED_PROJECT,
        nano_cpus: nano_cpus.ok_or(Error::NotFound)?,
        memory_bytes: memory_bytes.ok_or(Error::NotFound)?,
    })
}

fn rel(path: &str) -> SiteRelativePath {
    SiteRelativePath::parse(path).expect("literal path is valid")
}

fn open_scope(engine_state: &ManagedRoot) -> std::io::Result<ManagedRoot> {
    engine_state.create_dir_all(&rel(SCOPE))?;
    let scope = engine_state.open_managed_dir(&rel(SCOPE))?;
    for child in ["locks", "transactions", "audit"] {
        scope.create_dir_all(&rel(child))?;
    }
    Ok(scope)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Resolution, the stack lock, preflight and the transaction scaffolding
/// common to both operations. `body` runs with the transaction `InProgress`.
#[allow(clippy::too_many_arguments)]
fn run_transaction<T, F>(
    ctx: &Context<'_>,
    container: &ContainerId,
    request_id: RequestId,
    key: Option<&IdempotencyKey>,
    operation: &'static str,
    refuse_managed: bool,
    cancel: &CancellationToken,
    body: F,
) -> Result<T, Error>
where
    T: Serialize + DeserializeOwned,
    F: FnOnce(&Resolved) -> Result<T, Error>,
{
    let scope = open_scope(ctx.engine_state).map_err(Error::Io)?;
    // A failed resolution is held back until the transaction exists: a
    // replay of a recorded request must still answer after the container is
    // gone (a removed container is the whole point of `remove`).
    let resolved = resolve(ctx, container, cancel);
    let stack_scope = crate::stack_deploy::open_scope(ctx.engine_state).map_err(Error::Io)?;
    let _stack_lock = match &resolved {
        Ok(r) if r.managed && !refuse_managed => Some(
            crate::stack_deploy::acquire_stack_lock(&stack_scope, request_id)
                .map_err(|_| Error::StackBusy)?,
        ),
        _ => None,
    };

    let admitted =
        match preflight::run(&scope, request_id, key, operation).map_err(Error::Preflight)? {
            preflight::Outcome::Replay(id) => return replay(&scope, id, operation),
            preflight::Outcome::Proceed(value) => value,
        };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path = SiteRelativePath::parse(format!("transactions/{request_id}.json")).unwrap();
    let audit_path = rel("audit/events.jsonl");

    let outcome = resolved.and_then(|resolved| {
        if refuse_managed && resolved.managed {
            return Err(Error::ManagedRemoveRefused);
        }
        body(&resolved)
    });
    let result = match outcome {
        Ok(result) => result,
        Err(error) => return Err(fail(&scope, &state_path, &audit_path, state, error)),
    };
    let value = serde_json::to_value(&result).expect("results always serialize");
    state.mark_committed(value.clone()).unwrap();
    if state::save(&scope, &state_path, &state).is_err() {
        drop(lock);
        return Err(Error::PostCommit { result: value });
    }
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(request_id, true, None),
    );
    drop(lock);
    Ok(result)
}

pub fn execute_action(
    ctx: &Context<'_>,
    req: &ActionRequest,
    cancel: &CancellationToken,
) -> Result<ActionResult, Error> {
    run_transaction(
        ctx,
        &req.container_id,
        req.request_id,
        req.idempotency_key.as_ref(),
        ACTION_OPERATION,
        req.action == Action::Remove,
        cancel,
        |resolved| {
            run_docker(
                ctx,
                req.action.stage(),
                &req.action.argv(req.force, &resolved.id),
                ACTION_TIMEOUT,
                cancel,
            )?;
            Ok(ActionResult {
                container_id: resolved.id.clone(),
                action: req.action,
                force: req.force,
                managed: resolved.managed,
                completed_at_unix_secs: now_secs(),
            })
        },
    )
}

fn check_limit_bounds(ctx: &Context<'_>, req: &LimitsRequest) -> Result<(), Error> {
    if req.cpus > f64::from(ctx.host_cores) {
        return Err(Error::CpusAboveHost);
    }
    if req.memory_bytes != 0 {
        match ctx.host_memory_bytes {
            None => return Err(Error::HostResourcesUnknown),
            Some(total) if req.memory_bytes > total => return Err(Error::MemoryAboveHost),
            Some(_) => {}
        }
    }
    Ok(())
}

pub fn execute_limits(
    ctx: &Context<'_>,
    req: &LimitsRequest,
    cancel: &CancellationToken,
) -> Result<LimitsResult, Error> {
    check_limit_bounds(ctx, req)?;
    run_transaction(
        ctx,
        &req.container_id,
        req.request_id,
        req.idempotency_key.as_ref(),
        LIMITS_OPERATION,
        false,
        cancel,
        |resolved| {
            let plan = plan_limits(ctx, req, resolved)?;
            if let Some(prelude) = &plan.prelude {
                let mut argv = vec!["update".to_owned()];
                argv.extend(prelude.iter().cloned());
                argv.push(resolved.id.clone());
                run_docker(ctx, Stage::Update, &argv, ACTION_TIMEOUT, cancel)?;
            }
            if !plan.flags.is_empty() {
                let mut argv = vec!["update".to_owned()];
                argv.extend(plan.flags);
                argv.push(resolved.id.clone());
                run_docker(ctx, Stage::Update, &argv, ACTION_TIMEOUT, cancel)?;
            }
            Ok(LimitsResult {
                container_id: resolved.id.clone(),
                cpus: plan.cpus,
                memory_bytes: plan.memory_bytes,
                restart_policy: req.restart_policy.clone(),
                managed: resolved.managed,
                runtime_only: true,
                raised_to_host_max: plan.raised_to_host_max,
                completed_at_unix_secs: now_secs(),
            })
        },
    )
}

/// What `docker update` is asked to do and the limits that result.
#[derive(Debug, PartialEq)]
struct LimitsPlan {
    /// A first `docker update` that frees the swap limit at the current
    /// memory limit, needed before the memory limit can be raised (see
    /// [`plan_limits`]).
    prelude: Option<Vec<String>>,
    flags: Vec<String>,
    cpus: f64,
    memory_bytes: u64,
    raised_to_host_max: bool,
}

/// Raising a memory limit that has a swap limit next to it fails in runc
/// (`memory+swap limit should be >= memory limit`): Docker validates the pair
/// together but runc applies the new memory first, against the old swap, and
/// the daemon refuses to change only one of them. Docker's `run --memory`
/// sets swap to twice the memory, so this is the usual state of a container.
/// The engine therefore first re-sets the *current* memory with swap `-1`
/// (nothing for runc to trip over), then applies the new memory with swap
/// `-1`. Lowering a limit, or setting one on a container without any, takes a
/// single call.
///
/// `docker update` treats `0` as "leave unchanged", so a limit that is set
/// cannot be removed from a running container (verified on Docker 29: `--cpus
/// 0 --memory 0 --memory-swap 0` changes nothing). Asking for `0` therefore
/// means: nothing to do when the container has no such limit, otherwise raise
/// it to the host's maximum, which is the closest a running container gets to
/// unlimited. The result says so (`raisedToHostMax`).
fn plan_limits(
    ctx: &Context<'_>,
    req: &LimitsRequest,
    resolved: &Resolved,
) -> Result<LimitsPlan, Error> {
    let mut flags = Vec::new();
    let mut raised = false;
    let mut prelude = None;

    let cpus = if req.cpus > 0.0 {
        flags.extend(["--cpus".to_owned(), format!("{:.6}", req.cpus)]);
        req.cpus
    } else if resolved.nano_cpus > 0 {
        raised = true;
        flags.extend([
            "--cpus".to_owned(),
            format!("{:.6}", f64::from(ctx.host_cores)),
        ]);
        f64::from(ctx.host_cores)
    } else {
        0.0
    };

    let memory_bytes = if req.memory_bytes > 0 {
        flags.extend([
            "--memory".to_owned(),
            req.memory_bytes.to_string(),
            "--memory-swap".to_owned(),
            "-1".to_owned(),
        ]);
        req.memory_bytes
    } else if resolved.memory_bytes > 0 {
        let host = ctx.host_memory_bytes.ok_or(Error::HostResourcesUnknown)?;
        raised = true;
        flags.extend([
            "--memory".to_owned(),
            host.to_string(),
            "--memory-swap".to_owned(),
            "-1".to_owned(),
        ]);
        host
    } else {
        0
    };

    if resolved.memory_bytes > 0 && memory_bytes > resolved.memory_bytes {
        prelude = Some(vec![
            "--memory".to_owned(),
            resolved.memory_bytes.to_string(),
            "--memory-swap".to_owned(),
            "-1".to_owned(),
        ]);
    }
    if let Some(policy) = &req.restart_policy {
        flags.extend(["--restart".to_owned(), policy.clone()]);
    }
    Ok(LimitsPlan {
        prelude,
        flags,
        cpus,
        memory_bytes,
        raised_to_host_max: raised,
    })
}

/// `MemTotal` of a `/proc/meminfo` text, in bytes.
pub fn parse_meminfo_total(meminfo: &str) -> Option<u64> {
    let line = meminfo.lines().find(|l| l.starts_with("MemTotal:"))?;
    let mut fields = line.split_whitespace().skip(1);
    let value: u64 = fields.next()?.parse().ok()?;
    match fields.next() {
        Some("kB") => value.checked_mul(1024),
        None => Some(value),
        Some(_) => None,
    }
}

fn replay<T: DeserializeOwned>(
    scope: &ManagedRoot,
    id: RequestId,
    operation: &'static str,
) -> Result<T, Error> {
    let path = SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap();
    let loaded = state::load(scope, &path)
        .map_err(|error| Error::Io(std::io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != operation {
        return Err(Error::Io(std::io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => {
            serde_json::from_value(loaded.outcome.unwrap().result.unwrap())
                .map_err(|error| Error::Io(std::io::Error::other(error)))
        }
        TransactionStatus::Failed => {
            let outcome = loaded.outcome.unwrap();
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
    mut state: crate::transaction::state::TransactionState,
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt, sync::Mutex};
    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const ID2: &str = "123e4567-e89b-12d3-a456-426614174001";
    const ID3: &str = "123e4567-e89b-12d3-a456-426614174002";
    const PLAIN: &str = "aaaaaaaaaaaa";
    const MANAGED: &str = "bbbbbbbbbbbb";
    const LIMITED: &str = "111111111111";
    const FULL_LIMITED: &str = "1111111111110000000000000000000000000000000000000000000000000000";
    const FULL_PLAIN: &str = "aaaaaaaaaaaa0000000000000000000000000000000000000000000000000000";
    const FULL_MANAGED: &str = "bbbbbbbbbbbb0000000000000000000000000000000000000000000000000000";

    static SERIAL: Mutex<()> = Mutex::new(());

    /// A fake `docker` that records its argv, answers `inspect` for two known
    /// containers (one plain, one of the `wcp` project) and fails the verbs
    /// when `verb_exit` is nonzero.
    struct Fixture {
        dir: tempfile::TempDir,
        docker: String,
    }

    impl Fixture {
        fn new(verb_exit: i32) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let log = dir.path().join("calls.log");
            let script = dir.path().join("docker");
            fs::write(
                &script,
                format!(
                    "#!/bin/sh\necho \"$*\" >> '{log}'\n\
                     if [ \"$1\" = inspect ]; then\n\
                       for last; do :; done\n\
                       case \"$last\" in\n\
                         {PLAIN}) echo '{FULL_PLAIN} 0 0 ';;\n\
                         {MANAGED}) echo '{FULL_MANAGED} 0 0 wcp';;\n\
                         {LIMITED}) echo '{FULL_LIMITED} 2000000000 1073741824 label with spaces';;
                         cccccccccccc) echo '{FULL_PLAIN}X 0 0 other';;\n\
                         dddddddddddd) echo 'dddddddddddd0000000000000000000000000000000000000000000000000000 0 0 wcp-not';;\n\
                         *) echo 'Error: No such container: '\"$last\" >&2; exit 1;;\n\
                       esac\n\
                       exit 0\n\
                     fi\n\
                     exit {verb_exit}\n",
                    log = log.display(),
                ),
            )
            .unwrap();
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
            let docker = script.to_string_lossy().into_owned();
            Self { dir, docker }
        }

        fn state(&self) -> ManagedRoot {
            let root = self.dir.path().join("state");
            fs::create_dir_all(&root).unwrap();
            ManagedRoot::open(&crate::site::TrustedRoot::parse(&root).unwrap()).unwrap()
        }

        fn calls(&self) -> String {
            fs::read_to_string(self.dir.path().join("calls.log")).unwrap_or_default()
        }

        /// Calls other than the inspect that precedes each operation.
        fn verb_calls(&self) -> Vec<String> {
            self.calls()
                .lines()
                .filter(|l| !l.starts_with("inspect "))
                .map(str::to_owned)
                .collect()
        }
    }

    fn ctx<'a>(f: &'a Fixture, state: &'a ManagedRoot) -> Context<'a> {
        Context {
            engine_state: state,
            docker_program: &f.docker,
            host_cores: 4,
            host_memory_bytes: Some(8 * 1024 * 1024 * 1024),
        }
    }

    fn action(id: &str, verb: &str, force: bool, request: &str) -> ActionRequest {
        let action = Action::parse(verb).unwrap();
        ActionRequest::parse(
            id,
            verb,
            force,
            action.confirmation(force),
            request,
            Some(&format!("key-{request}")),
        )
        .unwrap()
    }

    fn run(ctx: &Context<'_>, req: &ActionRequest) -> Result<ActionResult, Error> {
        execute_action(ctx, req, &CancellationToken::default())
    }

    #[test]
    fn destructive_verbs_need_their_exact_token() {
        for (verb, force, token) in [
            ("stop", false, "CONTAINER_STOP"),
            ("restart", false, "CONTAINER_RESTART"),
            ("remove", false, "CONTAINER_REMOVE"),
            ("remove", true, "CONTAINER_REMOVE_FORCE"),
        ] {
            assert!(ActionRequest::parse(PLAIN, verb, force, Some(token), ID, None).is_ok());
            for wrong in [
                None,
                Some(""),
                Some("container_stop"),
                Some("CONTAINER_STOP "),
                Some("PRUNE_SYSTEM"),
            ] {
                if wrong == Some(token) {
                    continue;
                }
                assert_eq!(
                    ActionRequest::parse(PLAIN, verb, force, wrong, ID, None).unwrap_err(),
                    RequestError::InvalidConfirmation,
                    "{verb} accepted {wrong:?}"
                );
            }
        }
        // The plain remove token never authorises a forced removal.
        assert_eq!(
            ActionRequest::parse(PLAIN, "remove", true, Some("CONTAINER_REMOVE"), ID, None)
                .unwrap_err(),
            RequestError::InvalidConfirmation
        );
        for verb in ["start", "pause", "unpause"] {
            assert!(ActionRequest::parse(PLAIN, verb, false, None, ID, None).is_ok());
        }
    }

    #[test]
    fn request_validation() {
        assert_eq!(
            ActionRequest::parse("short", "start", false, None, ID, None).unwrap_err(),
            RequestError::InvalidContainerId
        );
        for bad in ["my-container", "AAAAAAAAAAAA", "aaaaaaaaaaaa;ls", "--all"] {
            assert_eq!(
                ActionRequest::parse(bad, "start", false, None, ID, None).unwrap_err(),
                RequestError::InvalidContainerId,
                "{bad}"
            );
        }
        assert_eq!(
            ActionRequest::parse(PLAIN, "kill", false, None, ID, None).unwrap_err(),
            RequestError::InvalidAction
        );
        assert_eq!(
            ActionRequest::parse(PLAIN, "stop", true, Some("CONTAINER_STOP"), ID, None)
                .unwrap_err(),
            RequestError::ForceNotApplicable
        );
        assert_eq!(
            ActionRequest::parse(PLAIN, "start", false, None, "nope", None).unwrap_err(),
            RequestError::InvalidRequestId
        );
    }

    #[test]
    fn runs_the_verb_against_the_resolved_full_id() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new(0);
        let state = f.state();
        let ctx = ctx(&f, &state);
        for (n, verb) in ["start", "stop", "restart", "pause", "unpause"]
            .into_iter()
            .enumerate()
        {
            let id = format!("123e4567-e89b-12d3-a456-42661417410{n}");
            let result = run(&ctx, &action(PLAIN, verb, false, &id)).unwrap();
            assert_eq!(result.container_id, FULL_PLAIN);
            assert!(!result.managed);
        }
        let result = run(
            &ctx,
            &action(
                PLAIN,
                "remove",
                true,
                "123e4567-e89b-12d3-a456-426614174199",
            ),
        )
        .unwrap();
        assert!(result.force);
        assert_eq!(
            f.verb_calls(),
            [
                format!("start {FULL_PLAIN}"),
                format!("stop {FULL_PLAIN}"),
                format!("restart {FULL_PLAIN}"),
                format!("pause {FULL_PLAIN}"),
                format!("unpause {FULL_PLAIN}"),
                format!("rm -f {FULL_PLAIN}"),
            ]
        );
        // Never `-v`, never a shell.
        assert!(!f.calls().contains(" -v"));
    }

    #[test]
    fn replay_runs_docker_once_and_survives_the_container_being_gone() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new(0);
        let state = f.state();
        let ctx = ctx(&f, &state);
        let req = action(PLAIN, "remove", false, ID);
        let first = run(&ctx, &req).unwrap();
        // The fake now forgets the container, as a real removal would.
        fs::write(
            &f.docker,
            "#!/bin/sh\necho \"$*\" >> /dev/null\necho 'No such container' >&2\nexit 1\n",
        )
        .unwrap();
        let again = run(&ctx, &req).unwrap();
        assert_eq!(first.container_id, again.container_id);
        assert_eq!(f.verb_calls(), [format!("rm {FULL_PLAIN}")]);
    }

    #[test]
    fn unknown_container_is_not_found_and_recorded() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new(0);
        let state = f.state();
        let ctx = ctx(&f, &state);
        let req = action("eeeeeeeeeeee", "start", false, ID);
        let error = run(&ctx, &req).unwrap_err();
        assert!(matches!(error, Error::NotFound));
        assert_eq!(error.protocol().0, ErrorCode::NotFound);
        assert!(f.verb_calls().is_empty());
        assert!(matches!(
            run(&ctx, &req),
            Err(Error::Replayed {
                code: ErrorCode::NotFound,
                ..
            })
        ));
    }

    #[test]
    fn an_inspect_answer_for_another_container_is_not_accepted() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new(0);
        let state = f.state();
        let ctx = ctx(&f, &state);
        // `cccccccccccc` answers with an id that does not start with it.
        let error = run(&ctx, &action("cccccccccccc", "start", false, ID)).unwrap_err();
        assert!(matches!(error, Error::NotFound));
        assert!(f.verb_calls().is_empty());
    }

    #[test]
    fn removing_a_managed_container_is_refused_without_the_stack_lock() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new(0);
        let state = f.state();
        let ctx = ctx(&f, &state);
        // Even with the stack lock held the answer is the refusal, not a
        // busy stack: the request could never have run.
        let stack_scope = crate::stack_deploy::open_scope(&state).unwrap();
        let _held =
            crate::stack_deploy::acquire_stack_lock(&stack_scope, RequestId::parse(ID2).unwrap())
                .unwrap();
        for (force, id) in [(false, ID), (true, ID3)] {
            let req = action(MANAGED, "remove", force, id);
            let error = run(&ctx, &req).unwrap_err();
            assert!(matches!(error, Error::ManagedRemoveRefused));
            assert_eq!(error.protocol().0, ErrorCode::InvalidInput);
        }
        assert!(f.verb_calls().is_empty());
    }

    #[test]
    fn a_project_label_that_only_starts_with_wcp_is_not_managed() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new(0);
        let state = f.state();
        let ctx = ctx(&f, &state);
        let result = run(&ctx, &action("dddddddddddd", "remove", false, ID)).unwrap();
        assert!(!result.managed);
    }

    #[test]
    fn managed_containers_take_the_stack_lock_and_plain_ones_do_not() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new(0);
        let state = f.state();
        let ctx = ctx(&f, &state);
        let stack_scope = crate::stack_deploy::open_scope(&state).unwrap();
        let _held =
            crate::stack_deploy::acquire_stack_lock(&stack_scope, RequestId::parse(ID2).unwrap())
                .unwrap();

        let error = run(&ctx, &action(MANAGED, "restart", false, ID)).unwrap_err();
        assert!(matches!(error, Error::StackBusy));
        assert_eq!(error.protocol().0, ErrorCode::Conflict);
        assert!(f.verb_calls().is_empty());
        // The busy stack was not recorded, so the same key runs once it frees.
        // (A plain container is unaffected while the lock is still held.)
        run(&ctx, &action(PLAIN, "restart", false, ID3)).unwrap();
        assert_eq!(f.verb_calls(), [format!("restart {FULL_PLAIN}")]);

        drop(_held);
        let result = run(&ctx, &action(MANAGED, "restart", false, ID)).unwrap();
        assert!(result.managed);
        assert_eq!(result.container_id, FULL_MANAGED);
    }

    #[test]
    fn rejected_verb_is_recorded_and_replayed() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new(1);
        let state = f.state();
        let ctx = ctx(&f, &state);
        let req = action(PLAIN, "start", false, ID);
        assert!(matches!(
            run(&ctx, &req),
            Err(Error::Rejected(Stage::Start, _))
        ));
        assert!(matches!(run(&ctx, &req), Err(Error::Replayed { .. })));
        assert_eq!(f.verb_calls().len(), 1);
    }

    fn limits(
        id: &str,
        cpus: f64,
        memory: u64,
        policy: Option<&str>,
        request: &str,
    ) -> LimitsRequest {
        LimitsRequest::parse(
            id,
            cpus,
            memory,
            policy,
            request,
            Some(&format!("key-{request}")),
        )
        .unwrap()
    }

    #[test]
    fn limits_argv_matches_the_panel_contract() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new(0);
        let state = f.state();
        let ctx = ctx(&f, &state);
        let token = CancellationToken::default();
        let result = execute_limits(
            &ctx,
            &limits(PLAIN, 1.5, 512 * 1024 * 1024, Some("unless-stopped"), ID),
            &token,
        )
        .unwrap();
        assert!(result.runtime_only);
        assert!(!result.raised_to_host_max);
        // A container without limits: `0` changes nothing, and docker is not
        // called at all (`docker update` with no flags is an error).
        let nothing = execute_limits(&ctx, &limits(PLAIN, 0.0, 0, None, ID2), &token).unwrap();
        assert_eq!((nothing.cpus, nothing.memory_bytes), (0.0, 0));
        assert!(!nothing.raised_to_host_max);
        // ...except for the restart policy, which has no such quirk.
        execute_limits(&ctx, &limits(PLAIN, 0.0, 0, Some("no"), ID3), &token).unwrap();
        assert_eq!(
            f.verb_calls(),
            [
                format!(
                    "update --cpus 1.500000 --memory 536870912 --memory-swap -1 --restart unless-stopped {FULL_PLAIN}"
                ),
                format!("update --restart no {FULL_PLAIN}"),
            ]
        );
    }

    #[test]
    fn zero_raises_an_existing_limit_to_the_host_maximum() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new(0);
        let state = f.state();
        let mut ctx = ctx(&f, &state);
        let token = CancellationToken::default();
        // LIMITED has 2 CPUs and 1 GiB; docker ignores `0`, so both are
        // raised to the host's 4 cores and 8 GiB instead.
        let result = execute_limits(&ctx, &limits(LIMITED, 0.0, 0, None, ID), &token).unwrap();
        assert!(result.raised_to_host_max);
        assert_eq!(result.cpus, 4.0);
        assert_eq!(result.memory_bytes, 8 * 1024 * 1024 * 1024);
        // Only the limit being cleared is raised; the other is set as asked.
        let result = execute_limits(&ctx, &limits(LIMITED, 1.0, 0, None, ID2), &token).unwrap();
        assert_eq!(result.cpus, 1.0);
        assert!(result.raised_to_host_max);
        // Raising the memory limit first frees the swap at the current value.
        let prelude = format!("update --memory 1073741824 --memory-swap -1 {FULL_LIMITED}");
        assert_eq!(
            f.verb_calls(),
            [
                prelude.clone(),
                format!(
                    "update --cpus 4.000000 --memory 8589934592 --memory-swap -1 {FULL_LIMITED}"
                ),
                prelude,
                format!(
                    "update --cpus 1.000000 --memory 8589934592 --memory-swap -1 {FULL_LIMITED}"
                ),
            ]
        );
        // Without a readable host size the memory limit cannot be raised.
        ctx.host_memory_bytes = None;
        assert!(matches!(
            execute_limits(&ctx, &limits(LIMITED, 1.0, 0, None, ID3), &token),
            Err(Error::HostResourcesUnknown)
        ));
        assert_eq!(f.verb_calls().len(), 4);
    }

    #[test]
    fn lowering_a_memory_limit_is_a_single_call() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new(0);
        let state = f.state();
        let ctx = ctx(&f, &state);
        // LIMITED has 1 GiB: 512 MiB is lower, so no prelude.
        execute_limits(
            &ctx,
            &limits(LIMITED, 0.5, 512 * 1024 * 1024, None, ID),
            &CancellationToken::default(),
        )
        .unwrap();
        assert_eq!(
            f.verb_calls(),
            [format!(
                "update --cpus 0.500000 --memory 536870912 --memory-swap -1 {FULL_LIMITED}"
            )]
        );
    }

    #[test]
    fn limits_are_bound_by_the_host_and_the_allowlist() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(
            LimitsRequest::parse(PLAIN, f64::NAN, 0, None, ID, None).unwrap_err(),
            RequestError::InvalidCpus
        );
        assert_eq!(
            LimitsRequest::parse(PLAIN, -1.0, 0, None, ID, None).unwrap_err(),
            RequestError::InvalidCpus
        );
        assert_eq!(
            LimitsRequest::parse(PLAIN, f64::INFINITY, 0, None, ID, None).unwrap_err(),
            RequestError::InvalidCpus
        );
        assert_eq!(
            LimitsRequest::parse(PLAIN, 1.0, 1024, None, ID, None).unwrap_err(),
            RequestError::InvalidMemory
        );
        assert_eq!(
            LimitsRequest::parse(PLAIN, 1.0, 0, Some("always; reboot"), ID, None).unwrap_err(),
            RequestError::InvalidRestartPolicy
        );

        let f = Fixture::new(0);
        let state = f.state();
        let mut ctx = ctx(&f, &state);
        let token = CancellationToken::default();
        let too_many = limits(PLAIN, 4.5, 0, None, ID);
        assert!(matches!(
            execute_limits(&ctx, &too_many, &token),
            Err(Error::CpusAboveHost)
        ));
        let too_much = limits(PLAIN, 1.0, 9 * 1024 * 1024 * 1024, None, ID2);
        assert!(matches!(
            execute_limits(&ctx, &too_much, &token),
            Err(Error::MemoryAboveHost)
        ));
        // Exactly the host's size is allowed; an unreadable host size is not.
        let at_limit = limits(PLAIN, 4.0, 8 * 1024 * 1024 * 1024, None, ID2);
        execute_limits(&ctx, &at_limit, &token).unwrap();
        ctx.host_memory_bytes = None;
        assert!(matches!(
            execute_limits(
                &ctx,
                &limits(PLAIN, 1.0, MIN_MEMORY_BYTES, None, ID3),
                &token
            ),
            Err(Error::HostResourcesUnknown)
        ));
        // Clearing the memory limit needs no host memory figure.
        execute_limits(&ctx, &limits(PLAIN, 1.0, 0, None, ID3), &token).unwrap();
        // Bound failures never reached docker (only the two successes did).
        assert_eq!(f.verb_calls().len(), 2);
    }

    #[test]
    fn limits_on_a_managed_container_take_the_stack_lock() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new(0);
        let state = f.state();
        let ctx = ctx(&f, &state);
        let stack_scope = crate::stack_deploy::open_scope(&state).unwrap();
        let _held =
            crate::stack_deploy::acquire_stack_lock(&stack_scope, RequestId::parse(ID2).unwrap())
                .unwrap();
        let error = execute_limits(
            &ctx,
            &limits(MANAGED, 1.0, 0, None, ID),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::StackBusy));
        assert!(f.verb_calls().is_empty());
    }

    #[test]
    fn parses_meminfo() {
        assert_eq!(
            parse_meminfo_total("MemTotal:       16384 kB\nMemFree: 1 kB\n"),
            Some(16384 * 1024)
        );
        assert_eq!(parse_meminfo_total("MemFree: 1 kB\n"), None);
        assert_eq!(parse_meminfo_total("MemTotal: lots kB\n"), None);
        assert_eq!(parse_meminfo_total("MemTotal: 1 MB\n"), None);
    }
}
