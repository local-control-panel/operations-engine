//! Installs the `unattended-upgrades` apt package under one lock/
//! idempotency/transaction/audit-backed request. Replaces the panel's raw
//! `sudo apt-get update && sudo apt-get install -y unattended-upgrades`
//! shell one-liner. Host-wide, like `backup.triggerNow`: there is no
//! per-site resource here, only one package manager per host.
//!
//! Package installation is naturally idempotent — reinstalling an
//! already-installed package is a successful no-op — so unlike
//! `system.activateAutoupdatesConfig` this operation has nothing to revert
//! on failure. A failed `apt-get install` simply leaves the package not
//! installed, which is also the pre-attempt state.

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

pub const OPERATION: &str = "system.installAutoupdates";
const PACKAGE: &str = "unattended-upgrades";

pub struct Request {
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug)]
pub enum RequestError {
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl Request {
    pub fn parse(request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        Ok(Self {
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
    Update,
    Install,
}

impl Stage {
    fn message(self) -> &'static str {
        match self {
            Self::Update => "could not refresh the apt package index",
            Self::Install => "could not install the unattended-upgrades package",
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallResult {
    pub completed_at_unix_secs: u64,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub apt_get_program: &'a str,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Run(Stage, process::ProcessRunError),
    Rejected(Stage, SubprocessDiagnostics),
    PostCommit { result: InstallResult },
    Replayed { code: ErrorCode, message: String },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another autoupdates package installation is in progress".into(),
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
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit { .. } => (
                ErrorCode::Internal,
                "internal autoupdates package installation error".into(),
            ),
        }
    }
}

fn run_apt(
    ctx: &Context<'_>,
    stage: Stage,
    args: &[&str],
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let output = process::run(
        &ProcessRequest::new(ctx.apt_get_program)
            .args(args)
            .env("DEBIAN_FRONTEND", "noninteractive"),
        &ProcessLimits {
            timeout: Duration::from_secs(10 * 60),
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
        return Err(Error::Rejected(
            stage,
            SubprocessDiagnostics::from_output(ctx.apt_get_program, &output),
        ));
    }
    Ok(())
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<InstallResult, Error> {
    let scope_path = SiteRelativePath::parse("system-autoupdates-install").unwrap();
    ctx.engine_state
        .create_dir_all(&scope_path)
        .map_err(Error::Io)?;
    let scope = ctx
        .engine_state
        .open_managed_dir(&scope_path)
        .map_err(Error::Io)?;
    for child in ["locks", "transactions", "audit"] {
        scope
            .create_dir_all(&SiteRelativePath::parse(child).unwrap())
            .map_err(Error::Io)?;
    }
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
    let audit_path = SiteRelativePath::parse("audit/events.jsonl").unwrap();

    if let Err(error) = run_apt(ctx, Stage::Update, &["update", "-y"], cancel) {
        return Err(fail(&scope, &state_path, &audit_path, state, error));
    }
    if let Err(error) = run_apt(ctx, Stage::Install, &["install", "-y", PACKAGE], cancel) {
        return Err(fail(&scope, &state_path, &audit_path, state, error));
    }

    let result = InstallResult {
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

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<InstallResult, Error> {
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
    use std::fs;

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    fn managed(directory: &std::path::Path) -> ManagedRoot {
        ManagedRoot::open(&crate::site::TrustedRoot::parse(directory).unwrap()).unwrap()
    }

    /// A fake `apt-get` that records each invocation's argv (one line per
    /// call) and exits with `exit` — standing in for the real host package
    /// manager the same way `backup_trigger`'s tests stand in for `bash`.
    fn fake_apt(directory: &std::path::Path, exit: i32) -> String {
        use std::os::unix::fs::PermissionsExt;

        let path = directory.join("fake-apt-get");
        let log = directory.join("calls.log");
        fs::write(
            &path,
            format!(
                "#!/bin/sh\necho \"$*\" >> '{}'\nexit {exit}\n",
                log.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn installs_the_package_by_updating_then_installing_then_replays() {
        let state_dir = tempfile::tempdir().unwrap();
        let apt = fake_apt(state_dir.path(), 0);
        let state = managed(state_dir.path());
        let ctx = Context {
            engine_state: &state,
            apt_get_program: &apt,
        };
        let req = Request::parse(ID, Some("autoupdates-install")).unwrap();

        execute(&ctx, &req, &CancellationToken::default()).unwrap();
        execute(&ctx, &req, &CancellationToken::default()).unwrap();

        let calls = fs::read_to_string(state_dir.path().join("calls.log")).unwrap();
        assert_eq!(calls.lines().count(), 2, "replay must not re-run apt-get");
        assert_eq!(calls.lines().next().unwrap(), "update -y");
        assert_eq!(
            calls.lines().nth(1).unwrap(),
            "install -y unattended-upgrades"
        );
    }

    #[test]
    fn a_rejected_update_never_attempts_the_install() {
        let state_dir = tempfile::tempdir().unwrap();
        let apt = fake_apt(state_dir.path(), 1);
        let state = managed(state_dir.path());
        let ctx = Context {
            engine_state: &state,
            apt_get_program: &apt,
        };
        let req = Request::parse(ID, None).unwrap();

        let result = execute(&ctx, &req, &CancellationToken::default());
        assert!(matches!(result, Err(Error::Rejected(Stage::Update, _))));

        let calls = fs::read_to_string(state_dir.path().join("calls.log")).unwrap();
        assert_eq!(calls.lines().count(), 1);
    }
}
