//! `system.service`: `systemctl start|restart` for the two host services the
//! control panel's health fixes touch (`netdata` and `docker`), as a typed,
//! audited, transactional operation instead of `sudo systemctl` over SSH.
//!
//! Decisions (milestone 069):
//!
//! - A fixed allowlist, never a free unit name: units `netdata` and `docker`,
//!   actions `start` and `restart`. The argv is `systemctl <action> <unit>`,
//!   no shell. `stop`, `disable` and every other unit stay out of reach.
//! - Success is the action's exit status **and** a follow-up
//!   `systemctl is-active <unit>` that answers `active`: a start that returns
//!   0 for a unit that immediately fails is a failed operation.
//! - Restarting `docker` stops every container on the host (unless the daemon
//!   has `live-restore`), so it needs its exact token
//!   `SERVICE_RESTART_DOCKER`. Starting a service and restarting `netdata`
//!   need none.
//! - Every action on `docker` takes the shared `stacks/wcp` lock first (the
//!   daemon going away under a running `stack.deploy` is the worst race the
//!   engine has); a busy stack is `CONFLICT` without a recorded transaction.
//!   `netdata` takes only this scope's own lock.
//! - `system.startDocker` stays for the setup wizard (it has its own scope and
//!   the macOS desktop launch); this operation is the general verb.

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
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const OPERATION: &str = "system.service";
const SCOPE: &str = "system-service";
pub const RESTART_DOCKER_CONFIRMATION: &str = "SERVICE_RESTART_DOCKER";
const ACTION_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const VERIFY_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Unit {
    Netdata,
    Docker,
}

impl Unit {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "netdata" => Some(Self::Netdata),
            "docker" => Some(Self::Docker),
            _ => None,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Netdata => "netdata",
            Self::Docker => "docker",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Action {
    Start,
    Restart,
}

impl Action {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "start" => Some(Self::Start),
            "restart" => Some(Self::Restart),
            _ => None,
        }
    }

    const fn verb(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Restart => "restart",
        }
    }
}

#[derive(Debug)]
pub struct Request {
    pub unit: Unit,
    pub action: Action,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidUnit,
    InvalidAction,
    InvalidConfirmation,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl Request {
    pub fn parse(
        unit: &str,
        action: &str,
        confirmation: Option<&str>,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let unit = Unit::parse(unit).ok_or(RequestError::InvalidUnit)?;
        let action = Action::parse(action).ok_or(RequestError::InvalidAction)?;
        if unit == Unit::Docker
            && action == Action::Restart
            && confirmation != Some(RESTART_DOCKER_CONFIRMATION)
        {
            return Err(RequestError::InvalidConfirmation);
        }
        Ok(Self {
            unit,
            action,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    Action,
    Verify,
}

impl Stage {
    fn message(self) -> &'static str {
        match self {
            Self::Action => "systemctl rejected the service action",
            Self::Verify => "the service is not active after the action",
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceResult {
    pub unit: Unit,
    pub action: Action,
    pub active: bool,
    pub completed_at_unix_secs: u64,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub systemctl_program: &'a str,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    StackBusy,
    ReplayInProgress,
    Run(Stage, process::ProcessRunError),
    Rejected(Stage, SubprocessDiagnostics),
    PostCommit { result: ServiceResult },
    Replayed { code: ErrorCode, message: String },
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
                "another service action is in progress".into(),
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
                } else {
                    ErrorCode::SubprocessFailed
                },
                stage.message().into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit { .. } => {
                (ErrorCode::Internal, "internal service action error".into())
            }
        }
    }
}

fn run_systemctl(
    ctx: &Context<'_>,
    stage: Stage,
    argv: &[&str],
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let output = process::run(
        &ProcessRequest::new(ctx.systemctl_program).args(argv),
        &ProcessLimits {
            timeout,
            max_stdout_bytes: 16 * 1024,
            max_stderr_bytes: 16 * 1024,
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
            SubprocessDiagnostics::from_output(ctx.systemctl_program, &output),
        ));
    }
    Ok(())
}

fn rel(path: &str) -> SiteRelativePath {
    SiteRelativePath::parse(path).expect("literal path is valid")
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<ServiceResult, Error> {
    ctx.engine_state
        .create_dir_all(&rel(SCOPE))
        .map_err(Error::Io)?;
    let scope = ctx
        .engine_state
        .open_managed_dir(&rel(SCOPE))
        .map_err(Error::Io)?;
    for child in ["locks", "transactions", "audit"] {
        scope.create_dir_all(&rel(child)).map_err(Error::Io)?;
    }
    let stack_scope = (req.unit == Unit::Docker)
        .then(|| crate::stack_deploy::open_scope(ctx.engine_state))
        .transpose()
        .map_err(Error::Io)?;
    let _stack_lock = stack_scope
        .as_ref()
        .map(|s| crate::stack_deploy::acquire_stack_lock(s, req.request_id))
        .transpose()
        .map_err(|_| Error::StackBusy)?;

    let admitted = match preflight::run(
        &scope,
        req.request_id,
        req.idempotency_key.as_ref(),
        OPERATION,
    )
    .map_err(Error::Preflight)?
    {
        preflight::Outcome::Replay(id) => return replay(&scope, id),
        preflight::Outcome::Proceed(value) => value,
    };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path =
        SiteRelativePath::parse(format!("transactions/{}.json", req.request_id)).unwrap();
    let audit_path = rel("audit/events.jsonl");

    let unit = req.unit.name();
    let run = run_systemctl(
        ctx,
        Stage::Action,
        &[req.action.verb(), unit],
        ACTION_TIMEOUT,
        cancel,
    )
    .and_then(|()| {
        run_systemctl(
            ctx,
            Stage::Verify,
            &["is-active", "--quiet", unit],
            VERIFY_TIMEOUT,
            cancel,
        )
    });
    if let Err(error) = run {
        return Err(fail(&scope, &state_path, &audit_path, state, error));
    }

    let result = ServiceResult {
        unit: req.unit,
        action: req.action,
        active: true,
        completed_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    state
        .mark_committed(serde_json::to_value(&result).unwrap())
        .unwrap();
    if state::save(&scope, &state_path, &state).is_err() {
        drop(lock);
        return Err(Error::PostCommit { result });
    }
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(req.request_id, true, None),
    );
    drop(lock);
    Ok(result)
}

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<ServiceResult, Error> {
    let path = SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap();
    let loaded = state::load(scope, &path)
        .map_err(|error| Error::Io(std::io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != OPERATION {
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

    static SERIAL: Mutex<()> = Mutex::new(());

    /// A fake `systemctl` that records argv; the action verbs exit with
    /// `action_exit`, `is-active` with `active_exit`.
    struct Fixture {
        dir: tempfile::TempDir,
        program: String,
    }

    impl Fixture {
        fn new(action_exit: i32, active_exit: i32) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let script = dir.path().join("systemctl");
            fs::write(
                &script,
                format!(
                    "#!/bin/sh\necho \"$*\" >> '{}'\n\
                     if [ \"$1\" = is-active ]; then exit {active_exit}; fi\nexit {action_exit}\n",
                    dir.path().join("calls.log").display()
                ),
            )
            .unwrap();
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
            let program = script.to_string_lossy().into_owned();
            Self { dir, program }
        }

        fn state(&self) -> ManagedRoot {
            let root = self.dir.path().join("state");
            fs::create_dir_all(&root).unwrap();
            ManagedRoot::open(&crate::site::TrustedRoot::parse(&root).unwrap()).unwrap()
        }

        fn calls(&self) -> String {
            fs::read_to_string(self.dir.path().join("calls.log")).unwrap_or_default()
        }
    }

    fn request(unit: &str, action: &str, id: &str) -> Request {
        let token =
            (unit == "docker" && action == "restart").then_some(RESTART_DOCKER_CONFIRMATION);
        Request::parse(unit, action, token, id, Some(&format!("key-{id}"))).unwrap()
    }

    #[test]
    fn only_the_allowlisted_units_and_actions_parse() {
        assert!(Request::parse("netdata", "restart", None, ID, None).is_ok());
        assert!(Request::parse("netdata", "start", None, ID, None).is_ok());
        assert!(Request::parse("docker", "start", None, ID, None).is_ok());
        for unit in [
            "sshd",
            "docker.socket",
            "netdata ",
            "",
            "../docker",
            "NETDATA",
        ] {
            assert_eq!(
                Request::parse(unit, "start", None, ID, None).unwrap_err(),
                RequestError::InvalidUnit,
                "{unit:?}"
            );
        }
        for action in ["stop", "disable", "reload", "start docker", ""] {
            assert_eq!(
                Request::parse("netdata", action, None, ID, None).unwrap_err(),
                RequestError::InvalidAction,
                "{action:?}"
            );
        }
    }

    #[test]
    fn restarting_docker_needs_its_exact_token() {
        for wrong in [None, Some(""), Some("restart"), Some("PRUNE_SYSTEM")] {
            assert_eq!(
                Request::parse("docker", "restart", wrong, ID, None).unwrap_err(),
                RequestError::InvalidConfirmation
            );
        }
        assert!(
            Request::parse(
                "docker",
                "restart",
                Some(RESTART_DOCKER_CONFIRMATION),
                ID,
                None
            )
            .is_ok()
        );
    }

    #[test]
    fn runs_the_action_then_verifies_and_replays_once() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new(0, 0);
        let state = f.state();
        let ctx = Context {
            engine_state: &state,
            systemctl_program: &f.program,
        };
        let req = request("netdata", "restart", ID);
        let first = execute(&ctx, &req, &CancellationToken::default()).unwrap();
        assert!(first.active);
        execute(&ctx, &req, &CancellationToken::default()).unwrap();
        assert_eq!(f.calls(), "restart netdata\nis-active --quiet netdata\n");
    }

    #[test]
    fn a_unit_that_is_not_active_afterwards_is_a_failure() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new(0, 3);
        let state = f.state();
        let ctx = Context {
            engine_state: &state,
            systemctl_program: &f.program,
        };
        let req = request("netdata", "start", ID);
        assert!(matches!(
            execute(&ctx, &req, &CancellationToken::default()),
            Err(Error::Rejected(Stage::Verify, _))
        ));
        assert!(matches!(
            execute(&ctx, &req, &CancellationToken::default()),
            Err(Error::Replayed { .. })
        ));
    }

    #[test]
    fn a_rejected_action_skips_the_verification() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new(1, 0);
        let state = f.state();
        let ctx = Context {
            engine_state: &state,
            systemctl_program: &f.program,
        };
        assert!(matches!(
            execute(
                &ctx,
                &request("netdata", "start", ID),
                &CancellationToken::default()
            ),
            Err(Error::Rejected(Stage::Action, _))
        ));
        assert_eq!(f.calls(), "start netdata\n");
    }

    #[test]
    fn docker_takes_the_stack_lock_and_netdata_does_not() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let f = Fixture::new(0, 0);
        let state = f.state();
        let ctx = Context {
            engine_state: &state,
            systemctl_program: &f.program,
        };
        let stack_scope = crate::stack_deploy::open_scope(&state).unwrap();
        let held =
            crate::stack_deploy::acquire_stack_lock(&stack_scope, RequestId::parse(ID2).unwrap())
                .unwrap();
        let error = execute(
            &ctx,
            &request("docker", "start", ID),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::StackBusy));
        assert_eq!(error.protocol().0, ErrorCode::Conflict);
        assert_eq!(f.calls(), "");
        execute(
            &ctx,
            &request("netdata", "start", ID2),
            &CancellationToken::default(),
        )
        .unwrap();
        drop(held);
        // The busy stack was not recorded: the same key now runs.
        execute(
            &ctx,
            &request("docker", "start", ID),
            &CancellationToken::default(),
        )
        .unwrap();
        assert!(f.calls().contains("start docker\n"));
    }
}
