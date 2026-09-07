//! The assembled `db.restore` pipeline: preflight, running the restore
//! subprocess, and result/audit persistence. No validate/reload/rollback
//! cycle (see `db_restore`'s module doc comment for why) - this is the
//! smallest of this engine's mutation pipelines.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    db_restore::{DbType, OPERATION, RestoreRequest, RestoreResult},
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{
        self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination,
        SubprocessDiagnostics,
    },
    site::SiteRelativePath,
    transaction::{
        RequestId,
        audit::{self, AuditRecord},
        commit::PreCommit,
        state::{self, TransactionState, TransactionStatus},
    },
};

pub struct RestoreContext<'a> {
    pub engine_state: &'a ManagedRoot,
    /// The `docker` binary - `"docker"` (PATH-resolved) in production;
    /// tests point this at a fake script.
    pub docker_program: &'a str,
    /// The `gunzip` binary, used only for `.gz` dumps - integrity-checked
    /// (`-t`) before the actual `-c | client` pipe, mirroring
    /// `website-control-panel`'s own pre-check (see `run`'s doc comment).
    pub gunzip_program: &'a str,
}

#[derive(Debug)]
pub enum RestoreError {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    /// The `.gz` integrity check (`gunzip -t`) failed - the archive is
    /// corrupt or unreadable. Nothing was run against the database.
    ArchiveIntegrityFailed(SubprocessDiagnostics),
    /// The archive integrity check itself could not be run.
    ArchiveCheckRunFailed(process::ProcessRunError),
    /// The restore client could not be run at all (docker unreachable,
    /// binary missing).
    RunFailed(process::ProcessRunError),
    /// The restore client ran and rejected the import.
    Rejected(SubprocessDiagnostics),
    State(state::StateError),
    Cancelled,
    PostCommitRecordFailed {
        result: RestoreResult,
        cause: state::StateError,
    },
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl RestoreError {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Io(_) | Self::State(_) | Self::PostCommitRecordFailed { .. } => {
                (ErrorCode::Internal, "internal restore error".to_owned())
            }
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another restore for this database is already in progress".to_owned(),
            ),
            Self::Preflight(_) => (ErrorCode::Internal, "preflight failed".to_owned()),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request for this idempotency key is still in progress".to_owned(),
            ),
            Self::ArchiveIntegrityFailed(diagnostics) => (
                if diagnostics.timed_out {
                    ErrorCode::Timeout
                } else {
                    ErrorCode::InvalidInput
                },
                "the backup archive failed its integrity check".to_owned(),
            ),
            Self::ArchiveCheckRunFailed(error) => (
                process::spawn_error_code(error),
                "could not verify the backup archive".to_owned(),
            ),
            Self::RunFailed(error) => (
                process::spawn_error_code(error),
                "could not run the database restore".to_owned(),
            ),
            Self::Rejected(diagnostics) => (
                if diagnostics.timed_out {
                    ErrorCode::Timeout
                } else if diagnostics.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::SubprocessFailed
                },
                "the database rejected the restore".to_owned(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before the restore ran".to_owned(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
        }
    }
}

pub fn execute(
    context: &RestoreContext<'_>,
    request: &RestoreRequest,
    cancellation: &CancellationToken,
) -> Result<RestoreResult, RestoreError> {
    let restore_state = open_restore_state(context.engine_state, request.database.as_str())
        .map_err(RestoreError::Io)?;

    let admitted = match preflight::run(
        &restore_state,
        request.request_id,
        request.idempotency_key.as_ref(),
        OPERATION,
    )
    .map_err(RestoreError::Preflight)?
    {
        preflight::Outcome::Replay(original) => return replay(&restore_state, original),
        preflight::Outcome::Proceed(admitted) => admitted,
    };
    let preflight::Admitted { lock, mut state } = admitted;

    let state_path = state_path_for(request.request_id);
    let audit_path = audit_log_path();
    let pre_commit = PreCommit::new(cancellation.clone());

    if pre_commit.check().is_err() {
        return Err(fail(
            &restore_state,
            &state_path,
            &audit_path,
            state,
            RestoreError::Cancelled,
        ));
    }

    if let Err(error) = run_restore(context, request, cancellation) {
        return Err(fail(&restore_state, &state_path, &audit_path, state, error));
    }

    let _post_commit = pre_commit.commit();
    drop(lock);

    let result = RestoreResult {
        restored_at_unix_secs: unix_now_secs(),
    };
    let result_value = serde_json::to_value(&result).expect("RestoreResult always serializes");
    state
        .mark_committed(result_value)
        .expect("state is always InProgress at this point");

    if let Err(cause) = state::save(&restore_state, &state_path, &state) {
        return Err(RestoreError::PostCommitRecordFailed { result, cause });
    }
    let _ = audit::append(
        &restore_state,
        &audit_path,
        &AuditRecord::result(request.request_id, true, None),
    );

    Ok(result)
}

/// Builds the `docker exec` client invocation for `request`, matching
/// `website-control-panel`'s own `build_restore_command` argument-for-
/// argument (mariadb: `-uroot -p<password>`; postgres: `-e
/// PGPASSWORD=<password>` ahead of the container name, `psql -v
/// ON_ERROR_STOP=1 -U postgres`) - argv elements here, never a shell
/// string, so nothing needs escaping the way the client-side shell-string
/// builder does.
fn client_request(context: &RestoreContext<'_>, request: &RestoreRequest) -> ProcessRequest {
    let mut args: Vec<String> = vec!["exec".to_owned(), "-i".to_owned()];
    match request.db_type {
        DbType::Postgres => {
            args.push("-e".to_owned());
            args.push(format!("PGPASSWORD={}", request.root_password));
        }
        DbType::Mariadb => {}
    }
    args.push(request.container.as_str().to_owned());
    match request.db_type {
        DbType::Mariadb => {
            args.push("mariadb".to_owned());
            args.push("-uroot".to_owned());
            args.push(format!("-p{}", request.root_password));
            args.push(request.database.as_str().to_owned());
        }
        DbType::Postgres => {
            args.push("psql".to_owned());
            args.push("-v".to_owned());
            args.push("ON_ERROR_STOP=1".to_owned());
            args.push("-U".to_owned());
            args.push("postgres".to_owned());
            args.push(request.database.as_str().to_owned());
        }
    }
    ProcessRequest::new(context.docker_program).args(args)
}

fn run_restore(
    context: &RestoreContext<'_>,
    request: &RestoreRequest,
    cancellation: &CancellationToken,
) -> Result<(), RestoreError> {
    let limits = ProcessLimits::default();
    let client = client_request(context, request);

    let output = if request.file_path.ends_with(".gz") {
        let integrity = process::run(
            &ProcessRequest::new(context.gunzip_program).args(["-t", &request.file_path]),
            &limits,
            cancellation,
        )
        .map_err(RestoreError::ArchiveCheckRunFailed)?;
        if !matches!(
            integrity.termination,
            ProcessTermination::Exited { success: true, .. }
        ) {
            return Err(RestoreError::ArchiveIntegrityFailed(
                SubprocessDiagnostics::from_output(context.gunzip_program, &integrity),
            ));
        }

        let (_gunzip_termination, client_output) = process::run_piped(
            &ProcessRequest::new(context.gunzip_program).args(["-c", &request.file_path]),
            &client,
            &limits,
            cancellation,
        )
        .map_err(RestoreError::RunFailed)?;
        client_output
    } else {
        process::run_with_stdin_file(
            &client,
            std::path::Path::new(&request.file_path),
            &limits,
            cancellation,
        )
        .map_err(RestoreError::RunFailed)?
    };

    if matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        return Ok(());
    }
    Err(RestoreError::Rejected(SubprocessDiagnostics::from_output(
        context.docker_program,
        &output,
    )))
}

/// One subtree per `database` name, not host-wide: two concurrent restores
/// of the *same* database race (both writing over each other's import into
/// the same tables), but two different databases' restores share nothing -
/// docker exec against different containers/databases has no common
/// resource to serialize. Mirrors `runtime_config`'s per-`runtime_id`
/// choice for the identical reason, scaled to this operation's own
/// resource boundary.
pub fn open_restore_state(
    engine_state: &ManagedRoot,
    database: &str,
) -> std::io::Result<ManagedRoot> {
    let relative = SiteRelativePath::parse(format!("db-restore/{database}"))
        .expect("a validated DatabaseName always yields a valid relative path");
    engine_state.create_dir_all(&relative)?;
    let scoped = engine_state.open_managed_dir(&relative)?;
    for sub in ["locks", "transactions", "audit"] {
        scoped.create_dir_all(&SiteRelativePath::parse(sub).expect("literal path is valid"))?;
    }
    Ok(scoped)
}

fn replay(restore_state: &ManagedRoot, original: RequestId) -> Result<RestoreResult, RestoreError> {
    let original_state =
        state::load(restore_state, &state_path_for(original)).map_err(RestoreError::State)?;
    if original_state.operation != OPERATION {
        return Err(RestoreError::State(state::StateError::Corrupt));
    }
    match original_state.status {
        TransactionStatus::InProgress => Err(RestoreError::ReplayInProgress),
        TransactionStatus::Committed => {
            let outcome = original_state
                .outcome
                .expect("a committed transaction always has an outcome");
            let result_value = outcome
                .result
                .expect("a committed outcome always has a result");
            serde_json::from_value(result_value)
                .map_err(|_| RestoreError::State(state::StateError::Corrupt))
        }
        TransactionStatus::Failed => {
            let outcome = original_state
                .outcome
                .expect("a failed transaction always has an outcome");
            Err(RestoreError::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}

fn fail(
    restore_state: &ManagedRoot,
    state_path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut state: TransactionState,
    error: RestoreError,
) -> RestoreError {
    let (code, message) = error.protocol();
    let _ = state.mark_failed(code, message);
    let _ = state::save(restore_state, state_path, &state);
    let _ = audit::append(
        restore_state,
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

    use super::{RestoreContext, execute};
    use crate::{
        db_restore::RestoreRequest, error::ErrorCode, filesystem::ManagedRoot,
        process::CancellationToken, site::TrustedRoot,
    };

    const REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const RETRY_REQUEST_ID: &str = "9b2f1c34-5678-4abc-9def-0123456789ab";

    struct Host {
        _state_dir: tempfile::TempDir,
        _fake_dir: tempfile::TempDir,
        _dump_dir: tempfile::TempDir,
        engine_state: ManagedRoot,
        docker_program: String,
        gunzip_program: String,
        dump_path: String,
        received: std::path::PathBuf,
    }

    /// A fake `docker` that only understands `exec -i [-e K=V] <container>
    /// <client> ...` shaped enough to prove argv/stdin plumbing: it copies
    /// whatever it receives on stdin to `received` and exits 0, unless a
    /// `REJECT` marker file exists next to it (simulating the database
    /// rejecting the import). A fake `gunzip` supports `-t <file>` (checks
    /// a `CORRUPT` marker) and `-c <file>` (cats it).
    fn host(reject: bool, corrupt_gz: bool) -> Host {
        let state_dir = tempfile::tempdir().expect("state root should be created");
        let fake_dir = tempfile::tempdir().expect("fake bin dir should be created");
        let dump_dir = tempfile::tempdir().expect("dump dir should be created");
        let engine_state = ManagedRoot::open(
            &TrustedRoot::parse(state_dir.path()).expect("state root should be valid"),
        )
        .expect("state root should open");

        let received = fake_dir.path().join("received.sql");
        let reject_flag = fake_dir.path().join("REJECT");
        if reject {
            fs::write(&reject_flag, "").unwrap();
        }
        let docker_script = format!(
            "#!/bin/sh\n[ -f {reject} ] && exit 1\ncat > {received}\nexit 0\n",
            reject = shell_quote(&reject_flag),
            received = shell_quote(&received),
        );
        let docker_program = fake_dir.path().join("docker");
        fs::write(&docker_program, docker_script).unwrap();
        fs::set_permissions(&docker_program, fs::Permissions::from_mode(0o755)).unwrap();

        let corrupt_flag = fake_dir.path().join("CORRUPT");
        if corrupt_gz {
            fs::write(&corrupt_flag, "").unwrap();
        }
        let gunzip_script = format!(
            "#!/bin/sh\nif [ \"$1\" = \"-t\" ]; then\n  [ -f {corrupt} ] && exit 1\n  exit 0\nelse\n  cat \"$2\"\nfi\n",
            corrupt = shell_quote(&corrupt_flag),
        );
        let gunzip_program = fake_dir.path().join("gunzip");
        fs::write(&gunzip_program, gunzip_script).unwrap();
        fs::set_permissions(&gunzip_program, fs::Permissions::from_mode(0o755)).unwrap();

        let dump_path = dump_dir.path().join("dump.sql");
        fs::write(&dump_path, "INSERT INTO t VALUES (1);\n").unwrap();

        Host {
            _state_dir: state_dir,
            _fake_dir: fake_dir,
            _dump_dir: dump_dir,
            engine_state,
            docker_program: docker_program.to_str().unwrap().to_owned(),
            gunzip_program: gunzip_program.to_str().unwrap().to_owned(),
            dump_path: dump_path.to_str().unwrap().to_owned(),
            received,
        }
    }

    fn shell_quote(path: &std::path::Path) -> String {
        format!("'{}'", path.to_str().unwrap())
    }

    fn context(host: &Host) -> RestoreContext<'_> {
        RestoreContext {
            engine_state: &host.engine_state,
            docker_program: &host.docker_program,
            gunzip_program: &host.gunzip_program,
        }
    }

    fn request(host: &Host, request_id: &str, key: Option<&str>) -> RestoreRequest {
        RestoreRequest::parse(
            "mariadb",
            "site_db",
            "wcp-mariadb-1",
            host.dump_path.clone(),
            "s3cret",
            request_id,
            key,
        )
        .expect("request should parse")
    }

    #[test]
    fn a_successful_restore_pipes_the_file_to_the_client_and_records_a_committed_transaction() {
        let host = host(false, false);
        let result = execute(
            &context(&host),
            &request(&host, REQUEST_ID, None),
            &CancellationToken::default(),
        )
        .expect("restore should succeed");

        assert!(result.restored_at_unix_secs > 0);
        assert_eq!(
            fs::read_to_string(&host.received).unwrap(),
            "INSERT INTO t VALUES (1);\n"
        );
    }

    #[test]
    fn a_rejected_restore_is_reported_as_subprocess_failed() {
        let host = host(true, false);
        let error = execute(
            &context(&host),
            &request(&host, REQUEST_ID, None),
            &CancellationToken::default(),
        )
        .expect_err("a rejected restore must fail");

        assert_eq!(error.protocol().0, ErrorCode::SubprocessFailed);
    }

    #[test]
    fn a_gzip_dump_is_integrity_checked_then_decompressed_into_the_client() {
        let host = host(false, false);
        let gz_path = format!("{}.gz", host.dump_path);
        fs::copy(&host.dump_path, &gz_path).unwrap();
        let request = RestoreRequest::parse(
            "mariadb",
            "site_db",
            "wcp-mariadb-1",
            gz_path,
            "s3cret",
            REQUEST_ID,
            None,
        )
        .unwrap();

        let result = execute(&context(&host), &request, &CancellationToken::default())
            .expect("gzip restore should succeed");

        assert!(result.restored_at_unix_secs > 0);
        assert_eq!(
            fs::read_to_string(&host.received).unwrap(),
            "INSERT INTO t VALUES (1);\n"
        );
    }

    #[test]
    fn a_corrupt_gzip_dump_fails_the_integrity_check_before_touching_the_database() {
        let host = host(false, true);
        let gz_path = format!("{}.gz", host.dump_path);
        fs::copy(&host.dump_path, &gz_path).unwrap();
        let request = RestoreRequest::parse(
            "mariadb",
            "site_db",
            "wcp-mariadb-1",
            gz_path,
            "s3cret",
            REQUEST_ID,
            None,
        )
        .unwrap();

        let error = execute(&context(&host), &request, &CancellationToken::default())
            .expect_err("a corrupt archive must not reach the database");

        assert_eq!(error.protocol().0, ErrorCode::InvalidInput);
        assert!(!host.received.exists());
    }

    #[test]
    fn a_retried_idempotency_key_replays_the_original_result_without_restoring_again() {
        let host = host(false, false);
        let key = Some("restore-1");
        execute(
            &context(&host),
            &request(&host, REQUEST_ID, key),
            &CancellationToken::default(),
        )
        .expect("first attempt should restore");
        fs::remove_file(&host.received).unwrap();

        let replayed = execute(
            &context(&host),
            &request(&host, RETRY_REQUEST_ID, key),
            &CancellationToken::default(),
        )
        .expect("retry should replay the original outcome");

        assert!(replayed.restored_at_unix_secs > 0);
        assert!(
            !host.received.exists(),
            "a replay must not run the restore again"
        );
    }
}
