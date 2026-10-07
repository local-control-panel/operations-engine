//! `compose.action` and `compose.remove`: the lifecycle verbs the control
//! panel's Compose tab offers for a user stack under `~/compose/<name>`
//! (`up`, `down`, `restart`, `pull`, and removing the stack), as typed,
//! audited, transactional operations instead of raw `docker compose` over SSH.
//!
//! Decisions (milestone 062):
//!
//! - Fixed argv, no shell: `docker compose -f <file> <verb>`. The file is
//!   `<compose root>/<stack>/docker-compose.yml`, where the stack name is the
//!   validated [`StackName`] and the compose root is the engine's own
//!   `~/compose` resolution (the same rule `compose.activateConfig` uses). The
//!   resolved path must stay inside the root (a planted symlink is refused).
//! - Success is the exit status and nothing else. Compose writes all of its
//!   progress to stderr, so a healthy `down` or `up` is never an error.
//! - The managed hosting stack is protected. `down` and `remove` are refused
//!   with `INVALID_INPUT` for the `wp-stack` directory, for a stack called
//!   `wcp`, and for any stack whose compose file declares the project name
//!   `wcp` (`docker compose config --format json`), before any lock or state.
//!   `up`, `restart` and `pull` on `wp-stack` stay available and hold the
//!   shared `stacks/wcp` lock like `compose.activateConfig` does.
//! - `down` and `remove` need their exact confirmation token
//!   (`COMPOSE_DOWN`, `COMPOSE_REMOVE`).
//! - Each stack has its own scope (`compose/<stack>`, the one
//!   `compose.activateConfig` uses), so an edit and a lifecycle verb on the
//!   same stack exclude each other; lock, idempotency key, transaction record
//!   and audit entry come from `mutation::preflight`.
//! - `remove` runs `down` first (volumes are kept: no `-v`), keeps the last
//!   compose file in `compose/<stack>/removed/docker-compose.yml`, then deletes
//!   the stack directory through an opened directory capability. A failed
//!   `down` leaves the directory untouched. A directory that is already gone is
//!   a successful no-op.
//! - Output is bounded: the child's stdout (or stderr when stdout is empty,
//!   which is where Compose reports progress) is captured to a limit and the
//!   recorded/returned text is cut to [`MAX_OUTPUT_BYTES`]. A failure records
//!   only [`SubprocessDiagnostics`], never the child's text.
//! - Timeouts bound every verb; after a timeout the outcome is unknown and a
//!   retry with the same idempotency key replays the recorded failure.

use crate::{
    compose_config::{execute::open_compose_state, route_path},
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{
        self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination,
        SubprocessDiagnostics,
    },
    site::{SiteRelativePath, StackName, TrustedRoot, ValidationError},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        state::{self, TransactionStatus},
    },
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const ACTION_OPERATION: &str = "compose.action";
pub const REMOVE_OPERATION: &str = "compose.remove";

pub const DOWN_CONFIRMATION: &str = "COMPOSE_DOWN";
pub const REMOVE_CONFIRMATION: &str = "COMPOSE_REMOVE";

/// The Compose project name of the engine-managed hosting stack.
const MANAGED_PROJECT: &str = "wcp";
const CONFIG_TIMEOUT: Duration = Duration::from_secs(30);
/// What the child may write before the runner stops keeping it.
const CAPTURE_BYTES: usize = 256 * 1024;
/// What is returned and kept in the transaction record.
pub const MAX_OUTPUT_BYTES: usize = 16 * 1024;
/// A compose file larger than this is not archived (it could not have been
/// activated through the engine either).
const MAX_ARCHIVE_BYTES: usize = crate::ingress::MAX_CONTENT_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Action {
    Up,
    Down,
    Restart,
    Pull,
}

impl Action {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "up" => Some(Self::Up),
            "down" => Some(Self::Down),
            "restart" => Some(Self::Restart),
            "pull" => Some(Self::Pull),
            _ => None,
        }
    }

    fn argv(self) -> &'static [&'static str] {
        match self {
            Self::Up => &["up", "-d"],
            Self::Down => &["down"],
            Self::Restart => &["restart"],
            Self::Pull => &["pull"],
        }
    }

    fn timeout(self) -> Duration {
        match self {
            Self::Up => Duration::from_secs(10 * 60),
            Self::Down | Self::Restart => Duration::from_secs(5 * 60),
            Self::Pull => Duration::from_secs(30 * 60),
        }
    }

    const fn stage(self) -> Stage {
        match self {
            Self::Up => Stage::Up,
            Self::Down => Stage::Down,
            Self::Restart => Stage::Restart,
            Self::Pull => Stage::Pull,
        }
    }

    pub const fn is_destructive(self) -> bool {
        matches!(self, Self::Down)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidStackName,
    InvalidAction,
    InvalidConfirmation,
    /// `down`/`remove` of the engine-managed hosting stack.
    ManagedStack,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

/// Names that always address the managed hosting stack: its directory
/// (`wp-stack`) and its Compose project (`wcp`, which is also what a stack
/// directory of that name would be called by default).
pub fn is_managed_stack(name: &StackName) -> bool {
    let name = name.as_str();
    name == crate::stack_deploy::STACK_NAME || name.eq_ignore_ascii_case(MANAGED_PROJECT)
}

#[derive(Debug)]
pub struct ActionRequest {
    pub stack_name: StackName,
    pub action: Action,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Debug)]
pub struct RemoveRequest {
    pub stack_name: StackName,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
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

impl ActionRequest {
    pub fn parse(
        stack_name: &str,
        action: &str,
        confirmation: Option<&str>,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let stack_name =
            StackName::parse(stack_name).map_err(|_| RequestError::InvalidStackName)?;
        let action = Action::parse(action).ok_or(RequestError::InvalidAction)?;
        if action.is_destructive() {
            if confirmation != Some(DOWN_CONFIRMATION) {
                return Err(RequestError::InvalidConfirmation);
            }
            if is_managed_stack(&stack_name) {
                return Err(RequestError::ManagedStack);
            }
        }
        let (request_id, idempotency_key) = parse_ids(request_id, key)?;
        Ok(Self {
            stack_name,
            action,
            request_id,
            idempotency_key,
        })
    }
}

impl RemoveRequest {
    pub fn parse(
        stack_name: &str,
        confirmation: &str,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let stack_name =
            StackName::parse(stack_name).map_err(|_| RequestError::InvalidStackName)?;
        if confirmation != REMOVE_CONFIRMATION {
            return Err(RequestError::InvalidConfirmation);
        }
        if is_managed_stack(&stack_name) {
            return Err(RequestError::ManagedStack);
        }
        let (request_id, idempotency_key) = parse_ids(request_id, key)?;
        Ok(Self {
            stack_name,
            request_id,
            idempotency_key,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    Config,
    Up,
    Down,
    Restart,
    Pull,
}

impl Stage {
    fn message(self) -> &'static str {
        match self {
            Self::Config => "docker compose could not read the stack's compose file",
            Self::Up => "docker compose up failed",
            Self::Down => "docker compose down failed",
            Self::Restart => "docker compose restart failed",
            Self::Pull => "docker compose pull failed",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionResult {
    pub stack_name: String,
    pub action: Action,
    /// Compose's own report, cut to [`MAX_OUTPUT_BYTES`].
    pub output: String,
    pub truncated: bool,
    pub completed_at_unix_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveResult {
    pub stack_name: String,
    /// `false` when the stack directory was already gone.
    pub removed: bool,
    pub output: String,
    pub truncated: bool,
    pub completed_at_unix_secs: u64,
}

pub struct Context<'a> {
    pub compose_root: &'a TrustedRoot,
    pub engine_state: &'a ManagedRoot,
    pub docker_program: &'a str,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    StackBusy,
    ReplayInProgress,
    /// No stack directory / compose file for this name.
    NotFound,
    /// The stack directory or file is a symlink, not a directory, or
    /// resolves outside the compose root.
    PathRefused,
    /// The compose file declares the managed project.
    ManagedProject,
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
                "another operation on this compose stack is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::NotFound => (
                ErrorCode::NotFound,
                "no compose file exists for this stack".into(),
            ),
            Self::PathRefused => (
                ErrorCode::InvalidInput,
                "the stack path is not a plain directory inside the compose root".into(),
            ),
            Self::ManagedProject => (
                ErrorCode::InvalidInput,
                "this stack is the managed hosting project (wcp) and cannot be taken down or \
                 removed here"
                    .into(),
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
                "internal compose operation error".into(),
            ),
        }
    }
}

/// The protocol message for a request that was refused before any state.
pub fn request_error_message(error: RequestError) -> &'static str {
    match error {
        RequestError::InvalidStackName => "stack-name is not a valid Compose stack identifier",
        RequestError::InvalidAction => "action must be up, down, restart or pull",
        RequestError::InvalidConfirmation => "confirmation does not match the operation",
        RequestError::ManagedStack => {
            "wp-stack and the wcp project are the managed hosting stack and cannot be taken down \
             or removed here"
        }
        RequestError::InvalidRequestId => "request-id is not a canonical UUID",
        RequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}

fn run_docker(
    ctx: &Context<'_>,
    stage: Stage,
    args: &[&str],
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<process::ProcessOutput, Error> {
    let output = process::run(
        &ProcessRequest::new(ctx.docker_program).args(args),
        &ProcessLimits {
            timeout,
            max_stdout_bytes: CAPTURE_BYTES,
            max_stderr_bytes: CAPTURE_BYTES,
        },
        cancel,
    )
    .map_err(|e| Error::Run(stage, e))?;
    if !matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        return Err(Error::Rejected(
            stage,
            SubprocessDiagnostics::from_output("docker compose", &output),
        ));
    }
    Ok(output)
}

fn bounded(bytes: &[u8], already_truncated: bool) -> (String, bool) {
    let text = String::from_utf8_lossy(bytes);
    if text.len() <= MAX_OUTPUT_BYTES {
        return (text.into_owned(), already_truncated);
    }
    let mut end = MAX_OUTPUT_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_owned(), true)
}

/// stdout when there is any, otherwise stderr: Compose reports progress of
/// `up`, `down`, `pull` and `restart` on stderr.
fn report(output: &process::ProcessOutput) -> (String, bool) {
    if output.stdout.bytes.is_empty() {
        bounded(&output.stderr.bytes, output.stderr.truncated)
    } else {
        bounded(&output.stdout.bytes, output.stdout.truncated)
    }
}

fn rel(path: &str) -> SiteRelativePath {
    SiteRelativePath::parse(path).expect("literal path is valid")
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Resolves the stack's compose file to an absolute path inside the compose
/// root. `NotFound` for a missing file, `PathRefused` for a symlinked stack
/// directory or an escape.
fn compose_file(ctx: &Context<'_>, stack: &StackName) -> Result<String, Error> {
    let root = ManagedRoot::open(ctx.compose_root).map_err(Error::Io)?;
    let dir = rel(stack.as_str());
    match root.symlink_metadata(&dir) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => return Err(Error::PathRefused),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Error::NotFound),
        Err(e) => return Err(Error::Io(e)),
    }
    let file = route_path(stack);
    match root.symlink_metadata(&file) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Error::NotFound),
        Err(e) => return Err(Error::Io(e)),
    }
    let resolved = ctx
        .compose_root
        .resolve_existing(&file)
        .map_err(|e| match e {
            ValidationError::PathResolutionFailed => Error::NotFound,
            _ => Error::PathRefused,
        })?;
    resolved
        .to_str()
        .map(str::to_owned)
        .ok_or(Error::PathRefused)
}

/// Refuses a compose file that declares the managed project. Needs
/// `docker compose config --format json`; a file Compose cannot parse fails
/// here, which is also why a later `down` could not have worked.
fn require_not_managed_project(
    ctx: &Context<'_>,
    file: &str,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let output = run_docker(
        ctx,
        Stage::Config,
        &["compose", "-f", file, "config", "--format", "json"],
        CONFIG_TIMEOUT,
        cancel,
    )?;
    let project = serde_json::from_slice::<serde_json::Value>(&output.stdout.bytes)
        .ok()
        .and_then(|v| v.get("name").and_then(|n| n.as_str().map(str::to_owned)));
    if project
        .as_deref()
        .is_some_and(|name| name.eq_ignore_ascii_case(MANAGED_PROJECT))
    {
        return Err(Error::ManagedProject);
    }
    Ok(())
}

/// Locks, preflight and the transaction scaffolding common to both verbs.
/// `body` runs with the transaction `InProgress` and returns the result to
/// commit.
fn run_transaction<T, F>(
    ctx: &Context<'_>,
    stack: &StackName,
    request_id: RequestId,
    key: Option<&IdempotencyKey>,
    operation: &'static str,
    take_stack_lock: bool,
    body: F,
) -> Result<T, Error>
where
    T: Serialize + DeserializeOwned,
    F: FnOnce(&ManagedRoot) -> Result<T, Error>,
{
    let scope = open_compose_state(ctx.engine_state, stack).map_err(Error::Io)?;
    // Only the managed stack shares containers with `stack.deploy`; another
    // stack name under `~/compose` is independent.
    let stack_scope = take_stack_lock
        .then(|| crate::stack_deploy::open_scope(ctx.engine_state))
        .transpose()
        .map_err(Error::Io)?;
    let _stack_lock = stack_scope
        .as_ref()
        .map(|s| crate::stack_deploy::acquire_stack_lock(s, request_id))
        .transpose()
        .map_err(|_| Error::StackBusy)?;

    let admitted =
        match preflight::run(&scope, request_id, key, operation).map_err(Error::Preflight)? {
            preflight::Outcome::Replay(id) => return replay(&scope, id, operation),
            preflight::Outcome::Proceed(value) => value,
        };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path = SiteRelativePath::parse(format!("transactions/{request_id}.json")).unwrap();
    let audit_path = rel("audit/events.jsonl");

    let result = match body(&scope) {
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
        &req.stack_name,
        req.request_id,
        req.idempotency_key.as_ref(),
        ACTION_OPERATION,
        req.stack_name.as_str() == crate::stack_deploy::STACK_NAME,
        |_scope| {
            let file = compose_file(ctx, &req.stack_name)?;
            if req.action.is_destructive() {
                require_not_managed_project(ctx, &file, cancel)?;
            }
            let mut args = vec!["compose", "-f", file.as_str()];
            args.extend_from_slice(req.action.argv());
            let output = run_docker(ctx, req.action.stage(), &args, req.action.timeout(), cancel)?;
            let (text, truncated) = report(&output);
            Ok(ActionResult {
                stack_name: req.stack_name.as_str().to_owned(),
                action: req.action,
                output: text,
                truncated,
                completed_at_unix_secs: now_secs(),
            })
        },
    )
}

pub fn execute_remove(
    ctx: &Context<'_>,
    req: &RemoveRequest,
    cancel: &CancellationToken,
) -> Result<RemoveResult, Error> {
    run_transaction(
        ctx,
        &req.stack_name,
        req.request_id,
        req.idempotency_key.as_ref(),
        REMOVE_OPERATION,
        false,
        |scope| {
            let done = |removed, output: String, truncated| RemoveResult {
                stack_name: req.stack_name.as_str().to_owned(),
                removed,
                output,
                truncated,
                completed_at_unix_secs: now_secs(),
            };
            let file = match compose_file(ctx, &req.stack_name) {
                Ok(file) => file,
                Err(Error::NotFound) => {
                    // Nothing to take down. A directory without a compose
                    // file is not a stack and is not deleted here.
                    let root = ManagedRoot::open(ctx.compose_root).map_err(Error::Io)?;
                    return match root.symlink_metadata(&rel(req.stack_name.as_str())) {
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            Ok(done(false, String::new(), false))
                        }
                        _ => Err(Error::NotFound),
                    };
                }
                Err(error) => return Err(error),
            };
            require_not_managed_project(ctx, &file, cancel)?;
            let down = run_docker(
                ctx,
                Stage::Down,
                &["compose", "-f", file.as_str(), "down"],
                Action::Down.timeout(),
                cancel,
            )?;
            let (text, truncated) = report(&down);

            // Keep the last compose file with the engine's records.
            let root = ManagedRoot::open(ctx.compose_root).map_err(Error::Io)?;
            if let Ok(bytes) = root.read_bytes(&route_path(&req.stack_name)) {
                if bytes.len() <= MAX_ARCHIVE_BYTES {
                    scope.create_dir_all(&rel("removed")).map_err(Error::Io)?;
                    scope
                        .write_atomic(&rel("removed/docker-compose.yml"), &bytes)
                        .map_err(Error::Io)?;
                }
            }
            root.remove_dir_all(&rel(req.stack_name.as_str()))
                .map_err(Error::Io)?;
            Ok(done(true, text, truncated))
        },
    )
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
    const COMPOSE: &str = "services:\n  app:\n    image: nginx\n";

    static SERIAL: Mutex<()> = Mutex::new(());

    /// A fake `docker` that records its argv, answers `config --format json`
    /// with a project name, and prints Compose-style progress on stderr.
    struct Fixture {
        dir: tempfile::TempDir,
        docker: String,
    }

    impl Fixture {
        fn new(project: &str, exit: i32, stderr: &str) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let log = dir.path().join("calls.log");
            let script = dir.path().join("docker");
            fs::write(dir.path().join("err.txt"), stderr).unwrap();
            fs::write(
                &script,
                format!(
                    "#!/bin/sh\necho \"$*\" >> '{log}'\n\
                     for a in \"$@\"; do if [ \"$a\" = config ]; then \
                       echo '{{\"name\":\"{project}\",\"services\":{{}}}}'; exit 0; fi; done\n\
                     cat '{err}' >&2\nexit {exit}\n",
                    log = log.display(),
                    err = dir.path().join("err.txt").display(),
                ),
            )
            .unwrap();
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
            let docker = script.to_string_lossy().into_owned();
            fs::create_dir_all(dir.path().join("state")).unwrap();
            fs::create_dir_all(dir.path().join("compose")).unwrap();
            Self { dir, docker }
        }

        fn stack(&self, name: &str) {
            let d = self.dir.path().join("compose").join(name);
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("docker-compose.yml"), COMPOSE).unwrap();
            fs::write(d.join("data.txt"), "x").unwrap();
        }

        fn stack_dir(&self, name: &str) -> std::path::PathBuf {
            self.dir.path().join("compose").join(name)
        }

        fn state(&self) -> ManagedRoot {
            ManagedRoot::open(&TrustedRoot::parse(self.dir.path().join("state")).unwrap()).unwrap()
        }

        fn root(&self) -> TrustedRoot {
            TrustedRoot::parse(self.dir.path().join("compose")).unwrap()
        }

        fn calls(&self) -> String {
            fs::read_to_string(self.dir.path().join("calls.log")).unwrap_or_default()
        }
    }

    macro_rules! ctx {
        ($f:expr, $state:ident, $root:ident) => {
            let $state = $f.state();
            let $root = $f.root();
        };
    }

    fn action(stack: &str, action: &str, id: &str) -> ActionRequest {
        let token = (action == "down").then_some(DOWN_CONFIRMATION);
        ActionRequest::parse(stack, action, token, id, Some(&format!("act-{id}"))).unwrap()
    }

    fn remove(stack: &str, id: &str) -> RemoveRequest {
        RemoveRequest::parse(stack, REMOVE_CONFIRMATION, id, Some(&format!("rm-{id}"))).unwrap()
    }

    #[test]
    fn requests_validate_names_actions_and_tokens() {
        assert_eq!(
            ActionRequest::parse("../x", "up", None, ID, None).unwrap_err(),
            RequestError::InvalidStackName
        );
        assert_eq!(
            ActionRequest::parse("web", "logs", None, ID, None).unwrap_err(),
            RequestError::InvalidAction
        );
        assert_eq!(
            ActionRequest::parse("web", "down", None, ID, None).unwrap_err(),
            RequestError::InvalidConfirmation
        );
        assert_eq!(
            ActionRequest::parse("web", "down", Some("COMPOSE_REMOVE"), ID, None).unwrap_err(),
            RequestError::InvalidConfirmation
        );
        assert!(ActionRequest::parse("web", "up", None, ID, None).is_ok());
        assert!(ActionRequest::parse("web", "down", Some("COMPOSE_DOWN"), ID, None).is_ok());
        assert_eq!(
            RemoveRequest::parse("web", "COMPOSE_DOWN", ID, None).unwrap_err(),
            RequestError::InvalidConfirmation
        );
        assert_eq!(
            ActionRequest::parse("web", "up", None, "nope", None).unwrap_err(),
            RequestError::InvalidRequestId
        );
    }

    #[test]
    fn the_managed_stack_cannot_be_taken_down_or_removed() {
        for name in ["wp-stack", "wcp", "WCP"] {
            assert_eq!(
                ActionRequest::parse(name, "down", Some(DOWN_CONFIRMATION), ID, None).unwrap_err(),
                RequestError::ManagedStack,
                "{name}"
            );
            assert_eq!(
                RemoveRequest::parse(name, REMOVE_CONFIRMATION, ID, None).unwrap_err(),
                RequestError::ManagedStack,
                "{name}"
            );
        }
        // Non-destructive verbs stay available for the platform stack.
        for verb in ["up", "restart", "pull"] {
            assert!(ActionRequest::parse("wp-stack", verb, None, ID, None).is_ok());
        }
    }

    #[test]
    fn argv_is_fixed_and_uses_the_resolved_absolute_file() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new("web", 0, "");
        f.stack("web");
        ctx!(f, state, root);
        let ctx = Context {
            compose_root: &root,
            engine_state: &state,
            docker_program: &f.docker,
        };
        for (n, verb) in ["up", "restart", "pull", "down"].into_iter().enumerate() {
            let id = format!("123e4567-e89b-12d3-a456-42661417400{n}");
            execute_action(
                &ctx,
                &action("web", verb, &id),
                &CancellationToken::default(),
            )
            .unwrap();
        }
        let file = f
            .stack_dir("web")
            .canonicalize()
            .unwrap()
            .join("docker-compose.yml");
        let file = file.display();
        assert_eq!(
            f.calls(),
            format!(
                "compose -f {file} up -d\n\
                 compose -f {file} restart\n\
                 compose -f {file} pull\n\
                 compose -f {file} config --format json\n\
                 compose -f {file} down\n"
            )
        );
        // `down` never removes volumes or the directory.
        assert!(f.stack_dir("web").exists());
    }

    #[test]
    fn success_is_the_exit_status_not_stderr() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new(
            "web",
            0,
            " Container web-app-1  Stopped\n Container web-app-1  Removed\n",
        );
        f.stack("web");
        ctx!(f, state, root);
        let ctx = Context {
            compose_root: &root,
            engine_state: &state,
            docker_program: &f.docker,
        };
        let result = execute_action(
            &ctx,
            &action("web", "down", ID),
            &CancellationToken::default(),
        )
        .unwrap();
        assert!(result.output.contains("Removed"));
        assert!(!result.truncated);
    }

    #[test]
    fn a_nonzero_exit_fails_without_leaking_the_childs_text() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new("web", 1, "secret-token pull access denied\n");
        f.stack("web");
        ctx!(f, state, root);
        let ctx = Context {
            compose_root: &root,
            engine_state: &state,
            docker_program: &f.docker,
        };
        let req = action("web", "pull", ID);
        let error = execute_action(&ctx, &req, &CancellationToken::default()).unwrap_err();
        let (code, message) = error.protocol();
        assert_eq!(code, ErrorCode::SubprocessFailed);
        assert!(!message.contains("secret"));
        // Recorded and replayed, not retried.
        assert!(matches!(
            execute_action(&ctx, &req, &CancellationToken::default()),
            Err(Error::Replayed { .. })
        ));
        assert_eq!(f.calls().matches("pull").count(), 1);
    }

    #[test]
    fn replay_runs_docker_once() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new("web", 0, "ok\n");
        f.stack("web");
        ctx!(f, state, root);
        let ctx = Context {
            compose_root: &root,
            engine_state: &state,
            docker_program: &f.docker,
        };
        let req = action("web", "up", ID);
        let first = execute_action(&ctx, &req, &CancellationToken::default()).unwrap();
        let again = execute_action(&ctx, &req, &CancellationToken::default()).unwrap();
        assert_eq!(first.output, again.output);
        assert_eq!(f.calls().matches(" up -d").count(), 1);
    }

    #[test]
    fn output_is_bounded_on_a_character_boundary() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new("web", 0, &"я".repeat(MAX_OUTPUT_BYTES));
        f.stack("web");
        ctx!(f, state, root);
        let ctx = Context {
            compose_root: &root,
            engine_state: &state,
            docker_program: &f.docker,
        };
        let result = execute_action(
            &ctx,
            &action("web", "pull", ID),
            &CancellationToken::default(),
        )
        .unwrap();
        assert!(result.truncated);
        assert!(result.output.len() <= MAX_OUTPUT_BYTES);
        assert!(!result.output.is_empty());
    }

    #[test]
    fn a_stack_that_declares_the_wcp_project_is_refused_for_down_and_remove() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new("wcp", 0, "");
        f.stack("sneaky");
        ctx!(f, state, root);
        let ctx = Context {
            compose_root: &root,
            engine_state: &state,
            docker_program: &f.docker,
        };
        let error = execute_action(
            &ctx,
            &action("sneaky", "down", ID),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::ManagedProject));
        assert_eq!(error.protocol().0, ErrorCode::InvalidInput);
        let error = execute_remove(&ctx, &remove("sneaky", ID2), &CancellationToken::default())
            .unwrap_err();
        assert!(matches!(error, Error::ManagedProject));
        assert!(f.stack_dir("sneaky").join("docker-compose.yml").exists());
        assert!(!f.calls().contains(" down"));
        // up is not destructive and does not consult the project name.
        execute_action(
            &ctx,
            &action("sneaky", "up", "123e4567-e89b-12d3-a456-426614174002"),
            &CancellationToken::default(),
        )
        .unwrap();
    }

    #[test]
    fn missing_stack_is_not_found_and_symlinks_are_refused() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new("web", 0, "");
        ctx!(f, state, root);
        let ctx = Context {
            compose_root: &root,
            engine_state: &state,
            docker_program: &f.docker,
        };
        let error = execute_action(
            &ctx,
            &action("ghost", "up", ID),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::NotFound));
        assert_eq!(error.protocol().0, ErrorCode::NotFound);

        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("docker-compose.yml"), COMPOSE).unwrap();
        std::os::unix::fs::symlink(outside.path(), f.stack_dir("linked")).unwrap();
        let error = execute_action(
            &ctx,
            &action("linked", "up", ID2),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::PathRefused));
        assert_eq!(f.calls(), "");
        let error = execute_remove(
            &ctx,
            &remove("linked", "123e4567-e89b-12d3-a456-426614174002"),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::PathRefused));
        assert!(outside.path().join("docker-compose.yml").exists());
    }

    #[test]
    fn remove_downs_archives_and_deletes_the_directory() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new("web", 0, " Container web-app-1  Removed\n");
        f.stack("web");
        ctx!(f, state, root);
        let ctx = Context {
            compose_root: &root,
            engine_state: &state,
            docker_program: &f.docker,
        };
        let req = remove("web", ID);
        let result = execute_remove(&ctx, &req, &CancellationToken::default()).unwrap();
        assert!(result.removed);
        assert!(result.output.contains("Removed"));
        assert!(!f.stack_dir("web").exists());
        let archived = fs::read_to_string(
            f.dir
                .path()
                .join("state/compose/web/removed/docker-compose.yml"),
        )
        .unwrap();
        assert_eq!(archived, COMPOSE);
        assert!(f.calls().contains(" down"));
        // Replay: no second down.
        execute_remove(&ctx, &req, &CancellationToken::default()).unwrap();
        assert_eq!(f.calls().matches(" down").count(), 1);
        // Audit has start + result.
        let audit =
            fs::read_to_string(f.dir.path().join("state/compose/web/audit/events.jsonl")).unwrap();
        assert!(audit.lines().count() >= 2);
    }

    #[test]
    fn a_failed_down_keeps_the_directory() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new("web", 1, "daemon unreachable\n");
        f.stack("web");
        ctx!(f, state, root);
        let ctx = Context {
            compose_root: &root,
            engine_state: &state,
            docker_program: &f.docker,
        };
        let error =
            execute_remove(&ctx, &remove("web", ID), &CancellationToken::default()).unwrap_err();
        assert!(matches!(error, Error::Rejected(Stage::Down, _)));
        assert!(f.stack_dir("web").join("data.txt").exists());
    }

    #[test]
    fn removing_an_absent_stack_is_a_no_op_and_a_bare_directory_is_refused() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new("web", 0, "");
        fs::create_dir_all(f.stack_dir("bare")).unwrap();
        fs::write(f.stack_dir("bare").join("keep.txt"), "x").unwrap();
        ctx!(f, state, root);
        let ctx = Context {
            compose_root: &root,
            engine_state: &state,
            docker_program: &f.docker,
        };
        let result =
            execute_remove(&ctx, &remove("gone", ID), &CancellationToken::default()).unwrap();
        assert!(!result.removed);
        let error =
            execute_remove(&ctx, &remove("bare", ID2), &CancellationToken::default()).unwrap_err();
        assert!(matches!(error, Error::NotFound));
        assert!(f.stack_dir("bare").join("keep.txt").exists());
        assert_eq!(f.calls(), "");
    }

    #[test]
    fn up_on_the_managed_stack_holds_the_shared_stack_lock() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new("wcp", 0, "");
        f.stack("wp-stack");
        ctx!(f, state, root);
        let ctx = Context {
            compose_root: &root,
            engine_state: &state,
            docker_program: &f.docker,
        };
        let scope = crate::stack_deploy::open_scope(&state).unwrap();
        let _held = crate::stack_deploy::acquire_stack_lock(&scope, RequestId::parse(ID2).unwrap())
            .unwrap();
        let error = execute_action(
            &ctx,
            &action("wp-stack", "restart", ID),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::StackBusy));
        assert_eq!(f.calls(), "");
    }
}
