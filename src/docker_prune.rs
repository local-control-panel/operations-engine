//! `docker.prune`: the three host-wide Docker prune actions the control panel
//! offers (`image`, `volume`, `system`) as one typed, confirmation-gated
//! operation.
//!
//! Decisions (milestone 059):
//!
//! - Fixed argv per kind, no shell, no `2>&1`. stdout is captured with a
//!   bound, then cut again to [`MAX_OUTPUT_BYTES`] for the stored result.
//! - Exclusive: the shared `stacks/wcp` lock is taken first (a prune racing
//!   `stack.deploy`'s `up -d` could remove a container or network that was
//!   created but not yet started), then this scope's own lock, idempotency
//!   key, transaction record and audit entry.
//! - Every destructive kind requires its exact confirmation token, so a
//!   request cannot be produced by accident or by a client that never asked
//!   the operator.
//! - The platform's own resources are never candidates. `volume` and `system`
//!   carry `--filter label!=com.docker.compose.project=wcp`, which keeps every
//!   container, network and volume Compose created for the stack out of the
//!   prune whether or not the stack is running. `system` never passes
//!   `--volumes`. `volume` additionally refuses to run on Docker older than
//!   23: there `docker volume prune` removes every unused *named* volume,
//!   including the stack's data volumes of a stopped service and the
//!   engine-created, unlabelled Meilisearch upgrade volumes. From 23 on it
//!   removes anonymous volumes only, and the engine never passes `--all`.
//!   `image` removes dangling images only and cannot touch a volume.

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

pub const OPERATION: &str = "docker.prune";
const SCOPE: &str = "docker-prune";

/// Excludes everything Compose created for the engine-managed `wcp` stack.
pub const STACK_FILTER: &str = "label!=com.docker.compose.project=wcp";
/// First Docker release whose `volume prune` leaves named volumes alone.
const MIN_VOLUME_PRUNE_MAJOR: u32 = 23;
const PRUNE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const VERSION_TIMEOUT: Duration = Duration::from_secs(30);
/// What the child may write before the runner stops keeping it.
const CAPTURE_BYTES: usize = 256 * 1024;
/// What is returned and kept in the transaction record.
pub const MAX_OUTPUT_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Kind {
    Image,
    Volume,
    System,
}

impl Kind {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "image" => Some(Self::Image),
            "volume" => Some(Self::Volume),
            "system" => Some(Self::System),
            _ => None,
        }
    }

    pub const fn confirmation(self) -> &'static str {
        match self {
            Self::Image => "PRUNE_IMAGE",
            Self::Volume => "PRUNE_VOLUME",
            Self::System => "PRUNE_SYSTEM",
        }
    }

    fn argv(self) -> &'static [&'static str] {
        match self {
            Self::Image => &["image", "prune", "-f"],
            Self::Volume => &["volume", "prune", "-f", "--filter", STACK_FILTER],
            Self::System => &["system", "prune", "-f", "--filter", STACK_FILTER],
        }
    }

    fn stage(self) -> Stage {
        match self {
            Self::Image => Stage::ImagePrune,
            Self::Volume => Stage::VolumePrune,
            Self::System => Stage::SystemPrune,
        }
    }
}

#[derive(Debug)]
pub struct Request {
    pub kind: Kind,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidKind,
    InvalidConfirmation,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl Request {
    pub fn parse(
        kind: &str,
        confirmation: &str,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let kind = Kind::parse(kind).ok_or(RequestError::InvalidKind)?;
        if confirmation != kind.confirmation() {
            return Err(RequestError::InvalidConfirmation);
        }
        Ok(Self {
            kind,
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
    DockerVersion,
    ImagePrune,
    VolumePrune,
    SystemPrune,
}

impl Stage {
    fn message(self) -> &'static str {
        match self {
            Self::DockerVersion => "could not determine the Docker version",
            Self::ImagePrune => "Docker rejected the image prune",
            Self::VolumePrune => "Docker rejected the volume prune",
            Self::SystemPrune => "Docker rejected the system prune",
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PruneResult {
    pub kind: Kind,
    /// Docker's own report, cut to [`MAX_OUTPUT_BYTES`].
    pub output: String,
    pub truncated: bool,
    pub completed_at_unix_secs: u64,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub docker_program: &'a str,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    StackBusy,
    ReplayInProgress,
    Run(Stage, process::ProcessRunError),
    Rejected(Stage, SubprocessDiagnostics),
    /// `docker volume prune` on this Docker would also remove named volumes.
    VolumePruneUnsafe,
    PostCommit {
        result: PruneResult,
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
                "another Docker prune is in progress".into(),
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
            Self::VolumePruneUnsafe => (
                ErrorCode::DependencyUnavailable,
                "volume prune needs Docker 23 or newer: older versions also remove unused \
                 named volumes, which can include database data"
                    .into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit { .. } => {
                (ErrorCode::Internal, "internal Docker prune error".into())
            }
        }
    }
}

fn run_docker(
    ctx: &Context<'_>,
    stage: Stage,
    argv: &[&str],
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<process::ProcessOutput, Error> {
    let output = process::run(
        &ProcessRequest::new(ctx.docker_program).args(argv),
        &ProcessLimits {
            timeout,
            max_stdout_bytes: CAPTURE_BYTES,
            max_stderr_bytes: 64 * 1024,
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
            SubprocessDiagnostics::from_output(ctx.docker_program, &output),
        ));
    }
    Ok(output)
}

/// Major version of a `docker version --format {{.Server.Version}}` line.
fn server_major(output: &str) -> Option<u32> {
    output
        .trim()
        .split(['.', '-', '+'])
        .next()?
        .parse::<u32>()
        .ok()
}

fn require_named_volume_safe_docker(
    ctx: &Context<'_>,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let output = run_docker(
        ctx,
        Stage::DockerVersion,
        &["version", "--format", "{{.Server.Version}}"],
        VERSION_TIMEOUT,
        cancel,
    )?;
    match server_major(&String::from_utf8_lossy(&output.stdout.bytes)) {
        Some(major) if major >= MIN_VOLUME_PRUNE_MAJOR => Ok(()),
        _ => Err(Error::VolumePruneUnsafe),
    }
}

fn bounded_output(stdout: &process::CapturedOutput) -> (String, bool) {
    let text = String::from_utf8_lossy(&stdout.bytes);
    let mut truncated = stdout.truncated;
    if text.len() <= MAX_OUTPUT_BYTES {
        return (text.into_owned(), truncated);
    }
    truncated = true;
    let mut end = MAX_OUTPUT_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_owned(), truncated)
}

fn run_prune(
    ctx: &Context<'_>,
    kind: Kind,
    cancel: &CancellationToken,
) -> Result<PruneResult, Error> {
    if kind == Kind::Volume {
        require_named_volume_safe_docker(ctx, cancel)?;
    }
    let output = run_docker(ctx, kind.stage(), kind.argv(), PRUNE_TIMEOUT, cancel)?;
    let (text, truncated) = bounded_output(&output.stdout);
    Ok(PruneResult {
        kind,
        output: text,
        truncated,
        completed_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
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

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<PruneResult, Error> {
    let scope = open_scope(ctx.engine_state).map_err(Error::Io)?;
    let stack_scope = crate::stack_deploy::open_scope(ctx.engine_state).map_err(Error::Io)?;
    let _stack_lock = crate::stack_deploy::acquire_stack_lock(&stack_scope, req.request_id)
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

    let result = match run_prune(ctx, req.kind, cancel) {
        Ok(result) => result,
        Err(error) => return Err(fail(&scope, &state_path, &audit_path, state, error)),
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

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<PruneResult, Error> {
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

    /// A fake `docker` that records its argv and answers `version` and the
    /// prune verbs from files next to it.
    struct Fixture {
        dir: tempfile::TempDir,
        docker: String,
    }

    impl Fixture {
        fn new(version: &str, prune_stdout: &str, prune_exit: i32) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let log = dir.path().join("calls.log");
            let script = dir.path().join("docker");
            fs::write(dir.path().join("out.txt"), prune_stdout).unwrap();
            fs::write(
                &script,
                format!(
                    "#!/bin/sh\necho \"$*\" >> '{log}'\n\
                     if [ \"$1\" = version ]; then echo '{version}'; exit 0; fi\n\
                     cat '{out}'\nexit {prune_exit}\n",
                    log = log.display(),
                    out = dir.path().join("out.txt").display(),
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
    }

    fn request(kind: &str, id: &str) -> Request {
        let kind_value = Kind::parse(kind).unwrap();
        Request::parse(kind, kind_value.confirmation(), id, Some("prune-key")).unwrap()
    }

    #[test]
    fn every_kind_needs_its_own_exact_confirmation_token() {
        for (kind, token) in [
            ("image", "PRUNE_IMAGE"),
            ("volume", "PRUNE_VOLUME"),
            ("system", "PRUNE_SYSTEM"),
        ] {
            assert!(Request::parse(kind, token, ID, None).is_ok());
            for wrong in ["", "prune_image", " PRUNE_IMAGE", "PRUNE_ALL", "FLUSHALL"] {
                if wrong == token {
                    continue;
                }
                assert_eq!(
                    Request::parse(kind, wrong, ID, None).unwrap_err(),
                    RequestError::InvalidConfirmation,
                    "{kind} accepted {wrong:?}"
                );
            }
        }
        // A token for another kind never authorises this one.
        assert_eq!(
            Request::parse("volume", "PRUNE_IMAGE", ID, None).unwrap_err(),
            RequestError::InvalidConfirmation
        );
        assert_eq!(
            Request::parse("images", "PRUNE_IMAGE", ID, None).unwrap_err(),
            RequestError::InvalidKind
        );
        assert_eq!(
            Request::parse("image", "PRUNE_IMAGE", "nope", None).unwrap_err(),
            RequestError::InvalidRequestId
        );
    }

    #[test]
    fn argv_is_fixed_and_never_names_volumes_or_all() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new("27.3.1", "Total reclaimed space: 0B\n", 0);
        let state = fixture.state();
        let ctx = Context {
            engine_state: &state,
            docker_program: &fixture.docker,
        };
        for (n, kind) in ["image", "volume", "system"].into_iter().enumerate() {
            let id = format!("123e4567-e89b-12d3-a456-42661417400{n}");
            let req =
                Request::parse(kind, Kind::parse(kind).unwrap().confirmation(), &id, None).unwrap();
            execute(&ctx, &req, &CancellationToken::default()).unwrap();
        }
        let calls = fixture.calls();
        assert_eq!(
            calls,
            "image prune -f\n\
             version --format {{.Server.Version}}\n\
             volume prune -f --filter label!=com.docker.compose.project=wcp\n\
             system prune -f --filter label!=com.docker.compose.project=wcp\n"
        );
        assert!(!calls.contains("--volumes"));
        assert!(!calls.contains("--all"));
        assert!(!calls.contains(" -a"));
    }

    #[test]
    fn replay_runs_docker_once_and_returns_the_recorded_result() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new("27.3.1", "Deleted Images:\nabc\n", 0);
        let state = fixture.state();
        let ctx = Context {
            engine_state: &state,
            docker_program: &fixture.docker,
        };
        let req = request("image", ID);
        let first = execute(&ctx, &req, &CancellationToken::default()).unwrap();
        let again = execute(&ctx, &req, &CancellationToken::default()).unwrap();
        assert_eq!(first.output, "Deleted Images:\nabc\n");
        assert_eq!(again.output, first.output);
        assert_eq!(fixture.calls(), "image prune -f\n");
    }

    #[test]
    fn volume_prune_is_refused_on_old_or_unparseable_docker() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        for (n, version) in ["20.10.24", "22.99.0", "garbage", ""]
            .into_iter()
            .enumerate()
        {
            let fixture = Fixture::new(version, "x", 0);
            let state = fixture.state();
            let ctx = Context {
                engine_state: &state,
                docker_program: &fixture.docker,
            };
            let req = request("volume", ID);
            let error = execute(&ctx, &req, &CancellationToken::default()).unwrap_err();
            assert!(
                matches!(error, Error::VolumePruneUnsafe),
                "case {n}: {error:?}"
            );
            assert!(!fixture.calls().contains("volume prune"));
            // The refusal is recorded and replayed, not retried.
            assert!(matches!(
                execute(&ctx, &req, &CancellationToken::default()),
                Err(Error::Replayed {
                    code: ErrorCode::DependencyUnavailable,
                    ..
                })
            ));
        }
    }

    #[test]
    fn image_and_system_prune_do_not_need_the_version_gate() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new("20.10.24", "ok\n", 0);
        let state = fixture.state();
        let ctx = Context {
            engine_state: &state,
            docker_program: &fixture.docker,
        };
        execute(&ctx, &request("image", ID), &CancellationToken::default()).unwrap();
        execute(&ctx, &request("system", ID2), &CancellationToken::default()).unwrap();
        assert!(!fixture.calls().contains("version"));
    }

    #[test]
    fn output_is_bounded_and_marked_truncated() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let big = "я".repeat(MAX_OUTPUT_BYTES);
        let fixture = Fixture::new("27.3.1", &big, 0);
        let state = fixture.state();
        let ctx = Context {
            engine_state: &state,
            docker_program: &fixture.docker,
        };
        let result = execute(&ctx, &request("image", ID), &CancellationToken::default()).unwrap();
        assert!(result.truncated);
        assert!(result.output.len() <= MAX_OUTPUT_BYTES);
        assert!(!result.output.is_empty());
    }

    #[test]
    fn rejected_prune_is_recorded_and_replayed() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new("27.3.1", "", 1);
        let state = fixture.state();
        let ctx = Context {
            engine_state: &state,
            docker_program: &fixture.docker,
        };
        let req = request("system", ID);
        assert!(matches!(
            execute(&ctx, &req, &CancellationToken::default()),
            Err(Error::Rejected(Stage::SystemPrune, _))
        ));
        assert!(matches!(
            execute(&ctx, &req, &CancellationToken::default()),
            Err(Error::Replayed { .. })
        ));
        assert_eq!(fixture.calls().matches("system prune").count(), 1);
    }

    #[test]
    fn a_held_stack_lock_blocks_the_prune_before_docker_runs() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new("27.3.1", "ok\n", 0);
        let state = fixture.state();
        let ctx = Context {
            engine_state: &state,
            docker_program: &fixture.docker,
        };
        let stack_scope = crate::stack_deploy::open_scope(&state).unwrap();
        let holder = RequestId::parse(ID2).unwrap();
        let _held = crate::stack_deploy::acquire_stack_lock(&stack_scope, holder).unwrap();
        let error =
            execute(&ctx, &request("system", ID), &CancellationToken::default()).unwrap_err();
        assert!(matches!(error, Error::StackBusy));
        assert_eq!(error.protocol().0, ErrorCode::Conflict);
        assert_eq!(fixture.calls(), "");
    }

    #[test]
    fn parses_docker_server_versions() {
        assert_eq!(server_major("27.3.1\n"), Some(27));
        assert_eq!(server_major("23.0.0-rc.1"), Some(23));
        assert_eq!(server_major("v27"), None);
        assert_eq!(server_major(""), None);
    }
}
