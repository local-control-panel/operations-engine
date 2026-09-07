//! The assembled `cron.installTab` pipeline: preflight, the install itself
//! (read current tab, hash-guard, `crontab <staged-file>`), and
//! result/audit persistence. Same shape as `ingress::execute`, minus the
//! validate/reload/rollback cycle that operation needs and this one
//! doesn't - `crontab` is atomic about accepting or rejecting a whole
//! submission itself.

use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    cron::{ConfigHash, InstallTabRequest, InstallTabResult, OPERATION},
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{self, CancellationToken, ProcessLimits, ProcessRequest},
    site::{SiteRelativePath, TrustedRoot},
    transaction::{
        RequestId,
        audit::{self, AuditRecord},
        commit::PreCommit,
        state::{self, TransactionState, TransactionStatus},
    },
};

const CRON_SUBTREE: &str = "cron";
const INSTALL_STAGING_PATH: &str = "cron/pending.tab";

pub struct InstallTabContext<'a> {
    /// The engine-wide state root, plain (unwrapped) so a staged crontab
    /// file can be handed to the `crontab` subprocess by a real path -
    /// `ManagedRoot`'s capability handle deliberately exposes no such path.
    pub state_root: &'a TrustedRoot,
    pub engine_state: &'a ManagedRoot,
    /// The `crontab` binary to invoke - `"crontab"` (PATH-resolved) in
    /// production; tests point this at a fake script instead of touching a
    /// real user crontab.
    pub crontab_program: &'a str,
}

#[derive(Debug)]
pub enum InstallTabError {
    Io(io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    HashGuardMismatch,
    /// `crontab -l` failed for a reason other than "no crontab installed
    /// yet" (that case is treated as an empty tab, not an error).
    ReadFailed(process::ProcessRunError),
    /// `crontab <file>` rejected the submission (bad syntax) or could not
    /// be run at all.
    InstallFailed(InstallFailure),
    State(state::StateError),
    Cancelled,
    PostCommitRecordFailed {
        result: InstallTabResult,
        cause: state::StateError,
    },
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

#[derive(Debug)]
pub enum InstallFailure {
    Run(process::ProcessRunError),
    Rejected(process::SubprocessDiagnostics),
}

impl InstallTabError {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Io(_) | Self::State(_) | Self::PostCommitRecordFailed { .. } => (
                ErrorCode::Internal,
                "internal cron installation error".to_owned(),
            ),
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another crontab installation is already in progress".to_owned(),
            ),
            Self::Preflight(_) => (ErrorCode::Internal, "preflight failed".to_owned()),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request for this idempotency key is still in progress".to_owned(),
            ),
            Self::HashGuardMismatch => (
                ErrorCode::ConfigHashMismatch,
                "the crontab changed since it was read - re-read it and retry".to_owned(),
            ),
            Self::ReadFailed(error) => (
                process::spawn_error_code(error),
                "could not read the current crontab".to_owned(),
            ),
            Self::InstallFailed(InstallFailure::Run(error)) => (
                process::spawn_error_code(error),
                "could not run crontab".to_owned(),
            ),
            Self::InstallFailed(InstallFailure::Rejected(diagnostics)) => (
                if diagnostics.timed_out {
                    ErrorCode::Timeout
                } else if diagnostics.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::ConfigValidationFailed
                },
                "the submitted crontab was rejected".to_owned(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before the commit point".to_owned(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
        }
    }
}

pub fn execute(
    context: &InstallTabContext<'_>,
    request: &InstallTabRequest,
    cancellation: &CancellationToken,
) -> Result<InstallTabResult, InstallTabError> {
    let cron_state = open_cron_state(context.engine_state).map_err(InstallTabError::Io)?;

    let admitted = match preflight::run(
        &cron_state,
        request.request_id,
        request.idempotency_key.as_ref(),
        OPERATION,
    )
    .map_err(InstallTabError::Preflight)?
    {
        preflight::Outcome::Replay(original) => return replay(&cron_state, original),
        preflight::Outcome::Proceed(admitted) => admitted,
    };
    let preflight::Admitted { lock, mut state } = admitted;

    let state_path = state_path_for(request.request_id);
    let audit_path = audit_log_path();
    let pre_commit = PreCommit::new(cancellation.clone());

    if pre_commit.check().is_err() {
        return Err(fail(
            &cron_state,
            &state_path,
            &audit_path,
            state,
            InstallTabError::Cancelled,
        ));
    }

    let current = match read_current_tab(context.crontab_program) {
        Ok(current) => current,
        Err(error) => {
            return Err(fail(
                &cron_state,
                &state_path,
                &audit_path,
                state,
                InstallTabError::ReadFailed(error),
            ));
        }
    };
    if !request.guard.is_satisfied_by(current.as_deref()) {
        return Err(fail(
            &cron_state,
            &state_path,
            &audit_path,
            state,
            InstallTabError::HashGuardMismatch,
        ));
    }

    let activated = current.as_deref() != Some(request.content.as_bytes());
    if activated {
        if let Err(error) = install(
            context.state_root,
            context.crontab_program,
            &request.content,
        ) {
            return Err(fail(
                &cron_state,
                &state_path,
                &audit_path,
                state,
                InstallTabError::InstallFailed(error),
            ));
        }
    }

    let _post_commit = pre_commit.commit();
    drop(lock);

    let result = InstallTabResult {
        activated,
        content_sha256: ConfigHash::of(request.content.as_bytes()),
        activated_at_unix_secs: unix_now_secs(),
    };
    let result_value = serde_json::to_value(&result).expect("InstallTabResult always serializes");
    state
        .mark_committed(result_value)
        .expect("state is always InProgress at this point");

    if let Err(cause) = state::save(&cron_state, &state_path, &state) {
        return Err(InstallTabError::PostCommitRecordFailed { result, cause });
    }
    let _ = audit::append(
        &cron_state,
        &audit_path,
        &AuditRecord::result(request.request_id, true, None),
    );

    Ok(result)
}

/// `crontab -l`. A non-zero exit (typically "no crontab for <user>") is
/// treated as an absent tab, not an error - the same tolerance
/// `website-control-panel`'s own `crontab -l 2>/dev/null || echo ""` already
/// applies client-side.
fn read_current_tab(crontab_program: &str) -> Result<Option<Vec<u8>>, process::ProcessRunError> {
    let output = process::run(
        &ProcessRequest::new(crontab_program).args(["-l"]),
        &ProcessLimits::default(),
        &CancellationToken::default(),
    )?;
    match output.termination {
        process::ProcessTermination::Exited { success: true, .. } => Ok(Some(output.stdout.bytes)),
        _ => Ok(None),
    }
}

/// Stages `content` to a well-known path under the state root and installs
/// it via `crontab <path>` - not stdin, since `process::run` always spawns
/// with `Stdio::null()` and this operation would rather reuse that shared
/// runner unmodified than special-case stdin piping for one caller.
fn install(
    state_root: &TrustedRoot,
    crontab_program: &str,
    content: &str,
) -> Result<(), InstallFailure> {
    let staged_path = state_root.as_path().join(INSTALL_STAGING_PATH);
    if let Some(parent) = staged_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| InstallFailure::Run(process::ProcessRunError::Spawn(e)))?;
    }
    std::fs::write(&staged_path, content)
        .map_err(|e| InstallFailure::Run(process::ProcessRunError::Spawn(e)))?;

    let outcome = process::run(
        &ProcessRequest::new(crontab_program).args([staged_path.as_os_str()]),
        &ProcessLimits::default(),
        &CancellationToken::default(),
    );
    let _ = std::fs::remove_file(&staged_path);

    let output = outcome.map_err(InstallFailure::Run)?;
    if matches!(
        output.termination,
        process::ProcessTermination::Exited { success: true, .. }
    ) {
        return Ok(());
    }
    Err(InstallFailure::Rejected(
        process::SubprocessDiagnostics::from_output("crontab", &output),
    ))
}

pub fn open_cron_state(engine_state: &ManagedRoot) -> io::Result<ManagedRoot> {
    let relative = SiteRelativePath::parse(CRON_SUBTREE).expect("literal path is valid");
    engine_state.create_dir_all(&relative)?;
    let scoped = engine_state.open_managed_dir(&relative)?;
    for sub in ["locks", "transactions", "audit"] {
        scoped.create_dir_all(&SiteRelativePath::parse(sub).expect("literal path is valid"))?;
    }
    Ok(scoped)
}

fn replay(
    cron_state: &ManagedRoot,
    original: RequestId,
) -> Result<InstallTabResult, InstallTabError> {
    let original_state =
        state::load(cron_state, &state_path_for(original)).map_err(InstallTabError::State)?;
    if original_state.operation != OPERATION {
        return Err(InstallTabError::State(state::StateError::Corrupt));
    }
    match original_state.status {
        TransactionStatus::InProgress => Err(InstallTabError::ReplayInProgress),
        TransactionStatus::Committed => {
            let outcome = original_state
                .outcome
                .expect("a committed transaction always has an outcome");
            let result_value = outcome
                .result
                .expect("a committed outcome always has a result");
            serde_json::from_value(result_value)
                .map_err(|_| InstallTabError::State(state::StateError::Corrupt))
        }
        TransactionStatus::Failed => {
            let outcome = original_state
                .outcome
                .expect("a failed transaction always has an outcome");
            Err(InstallTabError::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}

fn fail(
    cron_state: &ManagedRoot,
    state_path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut state: TransactionState,
    error: InstallTabError,
) -> InstallTabError {
    let (code, message) = error.protocol();
    let _ = state.mark_failed(code, message);
    let _ = state::save(cron_state, state_path, &state);
    let _ = audit::append(
        cron_state,
        audit_path,
        &AuditRecord::result(state.request_id, false, Some(code)),
    );
    error
}

fn state_path_for(request_id: RequestId) -> SiteRelativePath {
    SiteRelativePath::parse(format!("transactions/{request_id}.json"))
        .expect("a canonical RequestId always yields a valid relative path")
}

fn audit_log_path() -> SiteRelativePath {
    SiteRelativePath::parse("audit/events.jsonl").expect("literal path is valid")
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(all(test, unix))]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::{InstallTabContext, execute};
    use crate::{
        cron::{ConfigHash, HashGuard, InstallTabRequest},
        error::ErrorCode,
        filesystem::ManagedRoot,
        process::CancellationToken,
        site::TrustedRoot,
    };

    const REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const RETRY_REQUEST_ID: &str = "9b2f1c34-5678-4abc-9def-0123456789ab";

    struct Host {
        _state_dir: tempfile::TempDir,
        _fake_dir: tempfile::TempDir,
        state_root: TrustedRoot,
        engine_state: ManagedRoot,
        fake_crontab: String,
        installed_tab: std::path::PathBuf,
    }

    /// A fake `crontab` that reads/writes a plain file standing in for "the
    /// installed tab" - `-l` cats it (exit 1 if absent), any other single
    /// arg is treated as a file to copy in as the new tab (exit 1 instead,
    /// simulating rejection, if `REJECT` exists next to it).
    fn host(existing: Option<&str>) -> Host {
        let state_dir = tempfile::tempdir().expect("state root should be created");
        let fake_dir = tempfile::tempdir().expect("fake bin dir should be created");
        let engine_state = ManagedRoot::open(
            &TrustedRoot::parse(state_dir.path()).expect("state root should be valid"),
        )
        .expect("state root should open");
        let state_root = TrustedRoot::parse(state_dir.path()).expect("state root should be valid");

        let installed_tab = fake_dir.path().join("installed.tab");
        let reject_flag = fake_dir.path().join("REJECT");
        if let Some(contents) = existing {
            fs::write(&installed_tab, contents).expect("existing tab should be written");
        }
        let script = format!(
            "#!/bin/sh\nif [ \"$1\" = \"-l\" ]; then\n  [ -f {tab} ] && cat {tab} || exit 1\nelse\n  [ -f {reject} ] && exit 1\n  cp \"$1\" {tab}\nfi\n",
            tab = shell_quote(&installed_tab),
            reject = shell_quote(&reject_flag),
        );
        let fake_crontab = fake_dir.path().join("crontab");
        fs::write(&fake_crontab, script).expect("fake crontab script should be written");
        fs::set_permissions(&fake_crontab, fs::Permissions::from_mode(0o755))
            .expect("fake crontab should be executable");

        Host {
            _state_dir: state_dir,
            _fake_dir: fake_dir,
            state_root,
            engine_state,
            fake_crontab: fake_crontab
                .to_str()
                .expect("path should be utf8")
                .to_owned(),
            installed_tab,
        }
    }

    fn shell_quote(path: &std::path::Path) -> String {
        format!("'{}'", path.to_str().expect("path should be utf8"))
    }

    fn context(host: &Host) -> InstallTabContext<'_> {
        InstallTabContext {
            state_root: &host.state_root,
            engine_state: &host.engine_state,
            crontab_program: &host.fake_crontab,
        }
    }

    fn request(guard: HashGuard, request_id: &str, key: Option<&str>) -> InstallTabRequest {
        InstallTabRequest::parse("* * * * * true\n", guard, request_id, key)
            .expect("request should parse")
    }

    #[test]
    fn a_fresh_install_writes_the_tab_and_reports_activated() {
        let host = host(None);
        let result = execute(
            &context(&host),
            &request(HashGuard::Absent, REQUEST_ID, None),
            &CancellationToken::default(),
        )
        .expect("fresh install should succeed");

        assert!(result.activated);
        assert_eq!(
            fs::read_to_string(&host.installed_tab).unwrap(),
            "* * * * * true\n"
        );
    }

    #[test]
    fn a_stale_hash_guard_is_rejected_before_any_write() {
        let host = host(Some("0 0 * * * old\n"));
        let error = execute(
            &context(&host),
            &request(
                HashGuard::Sha256(ConfigHash::of(b"not what's there")),
                REQUEST_ID,
                None,
            ),
            &CancellationToken::default(),
        )
        .expect_err("a stale guard must not install");

        assert_eq!(error.protocol().0, ErrorCode::ConfigHashMismatch);
        assert_eq!(
            fs::read_to_string(&host.installed_tab).unwrap(),
            "0 0 * * * old\n"
        );
    }

    #[test]
    fn a_retried_idempotency_key_replays_the_original_result() {
        let host = host(None);
        let key = Some("cron-1");
        let first = execute(
            &context(&host),
            &request(HashGuard::Absent, REQUEST_ID, key),
            &CancellationToken::default(),
        )
        .expect("first attempt should install");

        let replayed = execute(
            &context(&host),
            &request(HashGuard::Absent, RETRY_REQUEST_ID, key),
            &CancellationToken::default(),
        )
        .expect("retry should replay the original outcome");

        assert_eq!(replayed.content_sha256, first.content_sha256);
    }

    #[test]
    fn a_rejected_install_is_reported_and_recorded() {
        let host = host(None);
        fs::write(host._fake_dir.path().join("REJECT"), "").unwrap();

        let error = execute(
            &context(&host),
            &request(HashGuard::Absent, REQUEST_ID, None),
            &CancellationToken::default(),
        )
        .expect_err("a rejected install must fail");

        assert_eq!(error.protocol().0, ErrorCode::ConfigValidationFailed);
    }

    #[test]
    fn identical_content_is_reported_unactivated() {
        let host = host(Some("* * * * * true\n"));
        let result = execute(
            &context(&host),
            &request(
                HashGuard::Sha256(ConfigHash::of(b"* * * * * true\n")),
                REQUEST_ID,
                None,
            ),
            &CancellationToken::default(),
        )
        .expect("re-submitting the current tab should succeed");

        assert!(!result.activated);
    }
}
