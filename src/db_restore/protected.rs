//! Offline, single-database restore with a private durable rollback snapshot.
//! The existing raw import helper remains available to enclosing CMS transactions.
use super::execute::{RestoreContext, open_restore_state};
use crate::{
    db_restore::{DbType, RestoreRequest, RestoreResult},
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{
        self, CancellationToken, ProcessLimits, ProcessOutput, ProcessRequest, ProcessTermination,
    },
    site::SiteRelativePath,
    transaction::{
        RequestId,
        audit::{self, AuditRecord},
        state::{self, TransactionState, TransactionStatus},
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const OPERATION: &str = "db.restoreProtected";
pub const RECOVER_OPERATION: &str = "db.recoverRestore";

/// A surrounding content transaction owns the lock, evidence and terminal state.
/// This only replays a validated private snapshot with independent client proof.
pub(crate) fn restore_snapshot_file(
    c: &RestoreContext<'_>,
    r: &RestoreRequest,
    file: File,
    expected_container_id: &str,
) -> Result<(), Error> {
    if container_id(c, r)? != expected_container_id {
        return Err(Error::RecoveryRequired);
    }
    let pinned = bound_request(r, expected_container_id);
    let cancel = CancellationToken::default();
    if !run_client(c, &pinned, file, true, &cancel)? || !verify(c, &pinned, &cancel) {
        return Err(Error::RecoveryRequired);
    }
    Ok(())
}
const TIMEOUT: Duration = Duration::from_secs(3600);
const MAX_MARKER: u64 = 16 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    db_type: String,
    database: String,
    container: String,
    root_password: String,
    #[serde(default)]
    file_path: String,
    /// The operator has stopped application/worker writers. A dump cannot ensure this.
    confirm_offline: bool,
    #[serde(default)]
    original_request_id: Option<String>,
    /// Required for explicit recovery after loss of the supervising process.
    #[serde(default)]
    confirm_clients_stopped: bool,
}
pub struct Request {
    pub restore: RestoreRequest,
    original: Option<RequestId>,
}
impl Request {
    pub fn parse(json: &str, id: &str, key: Option<&str>, recover: bool) -> Result<Self, Error> {
        let p: Plan = serde_json::from_str(json).map_err(|_| Error::Invalid)?;
        if key.is_none()
            || (recover && !p.file_path.is_empty())
            || !p.confirm_offline
            || (recover && !p.confirm_clients_stopped)
            || (!recover && (p.original_request_id.is_some() || p.confirm_clients_stopped))
        {
            return Err(Error::Invalid);
        }
        let original = p
            .original_request_id
            .map(|s| RequestId::parse(&s).map_err(|_| Error::Invalid))
            .transpose()?;
        if recover != original.is_some()
            || (!recover
                && (p.file_path.is_empty() || !std::path::Path::new(&p.file_path).is_absolute()))
        {
            return Err(Error::Invalid);
        }
        let restore = RestoreRequest::parse(
            &p.db_type,
            &p.database,
            &p.container,
            p.file_path,
            p.root_password,
            id,
            key,
        )
        .map_err(|_| Error::Invalid)?;
        if matches!(
            restore.database.as_str().to_ascii_lowercase().as_str(),
            "mysql"
                | "information_schema"
                | "performance_schema"
                | "sys"
                | "postgres"
                | "template0"
                | "template1"
        ) || restore.container.as_str().starts_with(['-', '.'])
            || restore.root_password.contains('\0')
        {
            return Err(Error::Invalid);
        }
        Ok(Self { restore, original })
    }
}

#[derive(Debug)]
pub enum Error {
    Invalid,
    Io,
    Conflict,
    Snapshot,
    ImportRestored,
    RecoveryRequired,
    ReplayFailed,
    Cancelled,
}
impl Error {
    pub fn protocol(&self) -> (ErrorCode, &'static str) {
        match self {
            Self::Invalid => (
                ErrorCode::InvalidInput,
                "invalid protected restore request; offline confirmation is required",
            ),
            Self::Io => (
                ErrorCode::Internal,
                "could not persist protected restore state",
            ),
            Self::Conflict => (
                ErrorCode::Conflict,
                "restore is active or unresolved; inspect the original request before recovery",
            ),
            Self::Snapshot => (
                ErrorCode::SubprocessFailed,
                "could not snapshot the database; import was not started",
            ),
            Self::ImportRestored => (
                ErrorCode::SubprocessFailed,
                "import or verification failed; the previous database was restored",
            ),
            Self::RecoveryRequired => (
                ErrorCode::DatabaseRecoveryRequired,
                "database outcome is unknown; keep writers stopped and explicitly recover the retained snapshot after confirming the import client has stopped",
            ),
            Self::ReplayFailed => (
                ErrorCode::SubprocessFailed,
                "the original protected restore failed; inspect its recorded outcome",
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "protected restore cancelled before import",
            ),
        }
    }
}
impl From<io::Error> for Error {
    fn from(_: io::Error) -> Self {
        Self::Io
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Pending {
    version: u8,
    request_id: String,
    database: String,
    container: String,
    db_type: String,
    snapshot_sha256: String,
    container_id: String,
}
fn rel(s: impl Into<String>) -> SiteRelativePath {
    SiteRelativePath::parse(s.into()).expect("validated state path")
}
fn state_path(id: RequestId) -> SiteRelativePath {
    rel(format!("transactions/{id}.json"))
}
fn snapshot_path(id: RequestId) -> SiteRelativePath {
    rel(format!("snapshots/{id}.sql"))
}
fn marker() -> SiteRelativePath {
    rel("restore-pending.json")
}
fn db_type(r: &RestoreRequest) -> &'static str {
    match r.db_type {
        DbType::Mariadb => "mariadb",
        DbType::Postgres => "postgres",
    }
}
fn limits() -> ProcessLimits {
    ProcessLimits {
        timeout: TIMEOUT,
        ..ProcessLimits::default()
    }
}
fn succeeded(p: &ProcessOutput) -> bool {
    matches!(
        p.termination,
        ProcessTermination::Exited { success: true, .. }
    )
}
fn completed(p: &ProcessOutput) -> bool {
    matches!(p.termination, ProcessTermination::Exited { .. })
}
fn command(c: &RestoreContext<'_>, r: &RestoreRequest, tool_args: &[&str]) -> ProcessRequest {
    let env = if r.db_type == DbType::Mariadb {
        "MYSQL_PWD"
    } else {
        "PGPASSWORD"
    };
    ProcessRequest::new(c.docker_program)
        .env(env, &r.root_password)
        .args(["exec", "-i", "-e", env, r.container.as_str()])
        .args(tool_args.iter().copied())
}
fn client(c: &RestoreContext<'_>, r: &RestoreRequest, rollback: bool) -> ProcessRequest {
    match r.db_type {
        DbType::Mariadb if rollback => command(c, r, &["mariadb", "--binary-mode", "-uroot"]),
        DbType::Mariadb => command(
            c,
            r,
            &["mariadb", "--binary-mode", "-uroot", r.database.as_str()],
        ),
        DbType::Postgres => command(
            c,
            r,
            &[
                "psql",
                "-X",
                "-v",
                "ON_ERROR_STOP=1",
                "-U",
                "postgres",
                if rollback {
                    "postgres"
                } else {
                    r.database.as_str()
                },
            ],
        ),
    }
}
// This fixed root-owned script records completion *inside* the container. A
// nonzero Docker CLI exit alone cannot distinguish SQL rejection from transport loss.
const CLIENT_SCRIPT: &[u8] = br#"#!/bin/sh
set -u
case "$1" in
 mariadb) mariadb --binary-mode -uroot "$2" < "$3"; result=$? ;;
 mariadb-rollback) mariadb --binary-mode -uroot < "$3"; result=$? ;;
 postgres) psql -X -v ON_ERROR_STOP=1 -U postgres "$2" < "$3"; result=$? ;;
 *) exit 125 ;;
esac
printf '%s\n' "$result" > "$4.tmp" && mv "$4.tmp" "$4"
exit "$result"
"#;
fn client_directory(id: RequestId, rollback: bool) -> String {
    format!(
        "/tmp/.ops-engine-restore-{id}-{}",
        if rollback { "rollback" } else { "import" }
    )
}
fn container_command(c: &RestoreContext<'_>, r: &RestoreRequest, args: &[&str]) -> ProcessRequest {
    ProcessRequest::new(c.docker_program)
        .args(["exec", r.container.as_str()])
        .args(args.iter().copied())
}
fn container_input_command(
    c: &RestoreContext<'_>,
    r: &RestoreRequest,
    args: &[&str],
) -> ProcessRequest {
    ProcessRequest::new(c.docker_program)
        .args(["exec", "-i", r.container.as_str()])
        .args(args.iter().copied())
}
fn cleanup_client(c: &RestoreContext<'_>, r: &RestoreRequest, id: RequestId, rollback: bool) {
    let _ = process::run(
        &container_command(c, r, &["rm", "-rf", &client_directory(id, rollback)]),
        &ProcessLimits::default(),
        &CancellationToken::default(),
    );
}
fn run_client(
    c: &RestoreContext<'_>,
    r: &RestoreRequest,
    input: File,
    rollback: bool,
    cancel: &CancellationToken,
) -> Result<bool, Error> {
    let dir = client_directory(r.request_id, rollback);
    let input_path = format!("{dir}/input.sql");
    let script_path = format!("{dir}/client.sh");
    let done = format!("{dir}/done");
    let created = process::run(
        &container_command(c, r, &["mkdir", "-m", "0700", &dir]),
        &ProcessLimits::default(),
        cancel,
    )
    .map_err(|_| Error::RecoveryRequired)?;
    if !succeeded(&created) {
        return Err(Error::RecoveryRequired);
    }
    let staged = process::run_with_stdin_handle(
        &container_input_command(c, r, &["dd", &format!("of={input_path}"), "status=none"]),
        input,
        &limits(),
        cancel,
    )
    .map_err(|_| Error::RecoveryRequired)?;
    if !succeeded(&staged) {
        return Err(Error::RecoveryRequired);
    }
    let staged = process::run_with_stdin_bytes(
        &container_input_command(c, r, &["dd", &format!("of={script_path}"), "status=none"]),
        CLIENT_SCRIPT,
        &ProcessLimits::default(),
        cancel,
    )
    .map_err(|_| Error::RecoveryRequired)?;
    if !succeeded(&staged) {
        return Err(Error::RecoveryRequired);
    }
    let kind = match (r.db_type, rollback) {
        (DbType::Mariadb, false) => "mariadb",
        (DbType::Mariadb, true) => "mariadb-rollback",
        (DbType::Postgres, _) => "postgres",
    };
    let database = if rollback && r.db_type == DbType::Postgres {
        "postgres"
    } else {
        r.database.as_str()
    };
    let out = process::run(
        &command(
            c,
            r,
            &["sh", &script_path, kind, database, &input_path, &done],
        ),
        &limits(),
        cancel,
    )
    .map_err(|_| Error::RecoveryRequired)?;
    if !completed(&out) {
        return Err(Error::RecoveryRequired);
    }
    let proof = process::run(
        &container_command(c, r, &["cat", &done]),
        &ProcessLimits {
            max_stdout_bytes: 16,
            ..ProcessLimits::default()
        },
        &CancellationToken::default(),
    )
    .map_err(|_| Error::RecoveryRequired)?;
    if !succeeded(&proof) || proof.stdout.truncated {
        return Err(Error::RecoveryRequired);
    }
    let text = std::str::from_utf8(&proof.stdout.bytes).map_err(|_| Error::RecoveryRequired)?;
    let exit_code = text
        .trim()
        .parse::<u8>()
        .map_err(|_| Error::RecoveryRequired)?;
    cleanup_client(c, r, r.request_id, rollback);
    Ok(exit_code == 0)
}
fn digest(mut f: File) -> Result<String, Error> {
    let mut hash = Sha256::new();
    let mut buf = [0; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    let bytes = hash.finalize();
    let mut hex = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        hex.push(HEX[(byte >> 4) as usize] as char);
        hex.push(HEX[(byte & 15) as usize] as char);
    }
    Ok(hex)
}
fn container_id(c: &RestoreContext<'_>, r: &RestoreRequest) -> Result<String, Error> {
    let out = process::run(
        &ProcessRequest::new(c.docker_program).args([
            "inspect",
            "--format",
            "{{.Id}}",
            r.container.as_str(),
        ]),
        &ProcessLimits::default(),
        &CancellationToken::default(),
    )
    .map_err(|_| Error::RecoveryRequired)?;
    let id = String::from_utf8_lossy(&out.stdout.bytes).trim().to_owned();
    if !succeeded(&out)
        || out.stdout.truncated
        || id.len() != 64
        || !id.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(Error::RecoveryRequired);
    }
    Ok(id)
}
// Pin every DB command to the immutable Docker ID, not a replaceable container name.
fn bound_request(r: &RestoreRequest, id: &str) -> RestoreRequest {
    RestoreRequest {
        db_type: r.db_type,
        database: r.database.clone(),
        container: super::ContainerName::parse(id).expect("validated container ID"),
        file_path: r.file_path.clone(),
        root_password: r.root_password.clone(),
        request_id: r.request_id,
        idempotency_key: r.idempotency_key.clone(),
    }
}
fn snapshot(
    c: &RestoreContext<'_>,
    r: &RestoreRequest,
    scope: &ManagedRoot,
    cancel: &CancellationToken,
) -> Result<String, Error> {
    scope.create_dir_all(&rel("snapshots"))?;
    scope.set_mode(&rel("snapshots"), 0o700)?;
    let file = scope.create_new_file_with_mode(&snapshot_path(r.request_id), 0o600)?;
    let sync_file = file.try_clone()?;
    let cmd = match r.db_type {
        DbType::Mariadb => command(
            c,
            r,
            &[
                "mariadb-dump",
                "-uroot",
                "--single-transaction",
                "--routines",
                "--events",
                "--triggers",
                "--add-drop-database",
                "--databases",
                r.database.as_str(),
            ],
        ),
        DbType::Postgres => command(
            c,
            r,
            &[
                "pg_dump",
                "-U",
                "postgres",
                "--clean",
                "--if-exists",
                "--create",
                r.database.as_str(),
            ],
        ),
    };
    let output = process::run_with_stdout_file(&cmd, file, &limits(), cancel)
        .map_err(|_| Error::Snapshot)?;
    if !succeeded(&output) || sync_file.metadata()?.len() == 0 {
        return Err(Error::Snapshot);
    }
    sync_file.sync_all()?;
    scope.open_managed_dir(&rel("snapshots"))?.sync_all()?;
    scope.sync_all()?;
    digest(scope.open_regular_read(&snapshot_path(r.request_id))?)
}
fn verify(c: &RestoreContext<'_>, r: &RestoreRequest, cancel: &CancellationToken) -> bool {
    let Ok(output) =
        process::run_with_stdin_bytes(&client(c, r, false), b"SELECT 1;\n", &limits(), cancel)
    else {
        return false;
    };
    succeeded(&output)
        && !output.stdout.truncated
        && String::from_utf8_lossy(&output.stdout.bytes)
            .lines()
            .any(|line| line.trim() == "1")
}
pub(super) fn read_pending(scope: &ManagedRoot) -> Result<Option<Pending>, Error> {
    let f = match scope.open_regular_read(&marker()) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Error::RecoveryRequired),
    };
    let mut bytes = Vec::new();
    f.take(MAX_MARKER + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_MARKER {
        return Err(Error::RecoveryRequired);
    }
    let p: Pending = serde_json::from_slice(&bytes).map_err(|_| Error::RecoveryRequired)?;
    if p.version != 1 || RequestId::parse(&p.request_id).is_err() {
        return Err(Error::RecoveryRequired);
    }
    Ok(Some(p))
}
fn save_terminal(
    scope: &ManagedRoot,
    tx: &mut TransactionState,
    result: Option<&RestoreResult>,
    err: Option<&Error>,
) -> Result<(), Error> {
    if let Some(result) = result {
        tx.mark_committed(serde_json::to_value(result).map_err(|_| Error::Io)?)
            .map_err(|_| Error::Io)?;
    } else {
        let (code, msg) = err.unwrap().protocol();
        tx.mark_failed(code, msg).map_err(|_| Error::Io)?;
    }
    state::save(scope, &state_path(tx.request_id), tx).map_err(|_| Error::Io)?;
    scope.open_managed_dir(&rel("transactions"))?.sync_all()?;
    audit::append(
        scope,
        &rel("audit/events.jsonl"),
        &AuditRecord::result(tx.request_id, result.is_some(), err.map(|e| e.protocol().0)),
    )
    .map_err(|_| Error::Io)?;
    Ok(())
}
fn clean(scope: &ManagedRoot, id: RequestId) -> Result<(), Error> {
    scope.remove_file(&marker())?;
    scope.sync_all()?;
    // A completed snapshot is no longer needed; failed cleanup never permits an import replay.
    let _ = scope.remove_file(&snapshot_path(id));
    let _ = scope.remove_file(&rel(format!("inputs/{id}.sql")));
    Ok(())
}
fn rollback(
    c: &RestoreContext<'_>,
    r: &RestoreRequest,
    scope: &ManagedRoot,
    pending: &Pending,
) -> Result<(), Error> {
    let original = RequestId::parse(&pending.request_id).map_err(|_| Error::RecoveryRequired)?;
    if pending.database != r.database.as_str()
        || pending.container != r.container.as_str()
        || pending.db_type != db_type(r)
        || pending.container_id != container_id(c, r)?
        || digest(
            scope
                .open_regular_read(&snapshot_path(original))
                .map_err(|_| Error::RecoveryRequired)?,
        )? != pending.snapshot_sha256
    {
        return Err(Error::RecoveryRequired);
    }
    let pinned = bound_request(r, &pending.container_id);
    let target = &pinned;
    // Never propagate an import cancellation into the compensating restore.
    let cancel = CancellationToken::default();
    if r.db_type == DbType::Postgres {
        let cmd = command(
            c,
            target,
            &[
                "psql",
                "-X",
                "-v",
                "ON_ERROR_STOP=1",
                "-U",
                "postgres",
                "postgres",
            ],
        );
        let sql = format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{}' AND pid <> pg_backend_pid();",
            r.database.as_str()
        );
        let out = process::run_with_stdin_bytes(&cmd, sql.as_bytes(), &limits(), &cancel)
            .map_err(|_| Error::RecoveryRequired)?;
        if !succeeded(&out) {
            return Err(Error::RecoveryRequired);
        }
    }
    let file = scope
        .open_regular_read(&snapshot_path(original))
        .map_err(|_| Error::RecoveryRequired)?;
    if !run_client(c, target, file, true, &cancel)? || !verify(c, target, &cancel) {
        return Err(Error::RecoveryRequired);
    }
    Ok(())
}

pub fn execute(
    c: &RestoreContext<'_>,
    request: &Request,
    cancel: &CancellationToken,
) -> Result<RestoreResult, Error> {
    let r = &request.restore;
    let scope = open_restore_state(c.engine_state, r.database.as_str())?;
    if request.original.is_some() {
        return recover(c, request, &scope);
    }
    let admitted = preflight::run(&scope, r.request_id, r.idempotency_key.as_ref(), OPERATION)
        .map_err(|_| Error::Conflict)?;
    let preflight::Outcome::Proceed(preflight::Admitted {
        lock: _guard,
        mut state,
    }) = admitted
    else {
        let preflight::Outcome::Replay(id) = admitted else {
            unreachable!()
        };
        let tx = state::load(&scope, &state_path(id)).map_err(|_| Error::Io)?;
        if tx.operation != OPERATION {
            return Err(Error::Conflict);
        }
        return match tx.status {
            TransactionStatus::Committed => {
                serde_json::from_value(tx.outcome.and_then(|o| o.result).ok_or(Error::Io)?)
                    .map_err(|_| Error::Io)
            }
            TransactionStatus::Failed => Err(Error::ReplayFailed),
            TransactionStatus::InProgress => Err(Error::Conflict),
        };
    };
    if read_pending(&scope)?.is_some() {
        save_terminal(&scope, &mut state, None, Some(&Error::Conflict))?;
        return Err(Error::Conflict);
    }
    if cancel.is_cancelled() {
        save_terminal(&scope, &mut state, None, Some(&Error::Cancelled))?;
        return Err(Error::Cancelled);
    }
    // Stage a plain, immutable input before the destructive boundary; archive producer failure cannot look like a successful import.
    scope.create_dir_all(&rel("inputs"))?;
    scope.set_mode(&rel("inputs"), 0o700)?;
    let input_path = rel(format!("inputs/{}.sql", r.request_id));
    let stage_result = stage_input(c, r, &scope, &input_path, cancel);
    if stage_result.is_err() {
        let _ = scope.remove_file(&input_path);
        save_terminal(&scope, &mut state, None, Some(&Error::Invalid))?;
        return Err(Error::Invalid);
    }
    let immutable_id = container_id(c, r)?;
    let pinned = bound_request(r, &immutable_id);
    let hash = match snapshot(c, &pinned, &scope, cancel) {
        Ok(h) => h,
        Err(e) => {
            save_terminal(&scope, &mut state, None, Some(&e))?;
            let _ = scope.remove_file(&input_path);
            let _ = scope.remove_file(&snapshot_path(r.request_id));
            return Err(e);
        }
    };
    let pending = Pending {
        version: 1,
        request_id: r.request_id.to_string(),
        database: r.database.as_str().into(),
        container: r.container.as_str().into(),
        db_type: db_type(r).into(),
        snapshot_sha256: hash,
        container_id: immutable_id,
    };
    scope.write_atomic_private(
        &marker(),
        &serde_json::to_vec(&pending).map_err(|_| Error::Io)?,
    )?;
    scope.sync_all()?;
    scope
        .open_regular_read(&state_path(r.request_id))?
        .sync_all()?;
    scope.open_managed_dir(&rel("transactions"))?.sync_all()?;
    crate::failpoint::hit("dbRestore.afterSnapshot");
    let input = scope.open_regular_read(&input_path)?;
    let imported = run_client(c, &pinned, input, false, cancel);
    let _ = scope.remove_file(&input_path);
    crate::failpoint::hit("dbRestore.afterImport");
    let imported = imported?;
    if !imported || !verify(c, &pinned, &CancellationToken::default()) {
        rollback(c, r, &scope, &pending)?;
        save_terminal(&scope, &mut state, None, Some(&Error::ImportRestored))?;
        clean(&scope, r.request_id)?;
        return Err(Error::ImportRestored);
    }
    let result = RestoreResult {
        restored_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    save_terminal(&scope, &mut state, Some(&result), None)?;
    clean(&scope, r.request_id)?;
    Ok(result)
}
fn stage_input(
    c: &RestoreContext<'_>,
    r: &RestoreRequest,
    scope: &ManagedRoot,
    path: &SiteRelativePath,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    // Ambient input is explicitly supplied by root, but final symlinks and special files are refused.
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    use std::os::unix::fs::OpenOptionsExt;
    let mut source = options.open(&r.file_path)?;
    if !source.metadata()?.is_file() {
        return Err(Error::Invalid);
    }
    let mut target = scope.create_new_file_with_mode(path, 0o600)?;
    if r.file_path.ends_with(".gz") {
        // Both descriptors stay pinned while gunzip checks the complete archive.
        let out = process::run_with_files(
            &ProcessRequest::new(c.gunzip_program).args(["-c"]),
            source,
            target.try_clone()?,
            &limits(),
            cancel,
        )
        .map_err(|_| Error::Invalid)?;
        if !succeeded(&out) {
            return Err(Error::Invalid);
        }
    } else {
        io::copy(&mut source, &mut target)?;
    }
    target.sync_all()?;
    Ok(())
}
fn replay(scope: &ManagedRoot, id: RequestId, operation: &str) -> Result<RestoreResult, Error> {
    let tx = state::load(scope, &state_path(id)).map_err(|_| Error::Io)?;
    if tx.operation != operation {
        return Err(Error::Conflict);
    }
    match tx.status {
        TransactionStatus::Committed => {
            serde_json::from_value(tx.outcome.and_then(|o| o.result).ok_or(Error::Io)?)
                .map_err(|_| Error::Io)
        }
        TransactionStatus::Failed => Err(Error::ReplayFailed),
        TransactionStatus::InProgress => Err(Error::Conflict),
    }
}
fn recover(
    c: &RestoreContext<'_>,
    request: &Request,
    scope: &ManagedRoot,
) -> Result<RestoreResult, Error> {
    let r = &request.restore;
    let admission = preflight::run(
        scope,
        r.request_id,
        r.idempotency_key.as_ref(),
        RECOVER_OPERATION,
    )
    .map_err(|_| Error::Conflict)?;
    let (guard, mut recovery) = match admission {
        preflight::Outcome::Replay(id) => return replay(scope, id, RECOVER_OPERATION),
        preflight::Outcome::Proceed(admitted) => (admitted.lock, admitted.state),
    };
    let outcome = recover_original(c, request, scope);
    match outcome {
        Ok(result) => {
            save_terminal(scope, &mut recovery, Some(&result), None)?;
            drop(guard);
            Ok(result)
        }
        Err(e @ (Error::RecoveryRequired | Error::Io)) => Err(e),
        Err(e) => {
            save_terminal(scope, &mut recovery, None, Some(&e))?;
            Err(e)
        }
    }
}
fn recover_original(
    c: &RestoreContext<'_>,
    request: &Request,
    scope: &ManagedRoot,
) -> Result<RestoreResult, Error> {
    let r = &request.restore;
    let original = request.original.ok_or(Error::Invalid)?;
    let mut tx = state::load(scope, &state_path(original)).map_err(|_| Error::Conflict)?;
    if tx.operation != OPERATION {
        return Err(Error::Conflict);
    }
    let Some(pending) = read_pending(scope)? else {
        return Err(Error::Conflict);
    };
    if pending.request_id != original.to_string()
        || pending.database != r.database.as_str()
        || pending.container != r.container.as_str()
        || pending.db_type != db_type(r)
    {
        return Err(Error::Conflict);
    }
    // A terminal original is never undone after a crash in snapshot cleanup.
    if tx.status == TransactionStatus::Committed {
        clean(scope, original)?;
        return Err(Error::Conflict);
    }
    if tx.status == TransactionStatus::InProgress {
        rollback(c, r, scope, &pending)?;
        save_terminal(scope, &mut tx, None, Some(&Error::ImportRestored))?;
    } else if tx
        .outcome
        .as_ref()
        .is_none_or(|o| o.error_message.as_deref() != Some(Error::ImportRestored.protocol().1))
    {
        return Err(Error::Conflict);
    }
    let pinned = bound_request(r, &pending.container_id);
    cleanup_client(c, &pinned, original, false);
    cleanup_client(c, &pinned, original, true);
    clean(scope, original)?;
    Ok(RestoreResult {
        restored_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    })
}

/// Discovery never reads the SQL snapshot or exposes its hash/content.
pub fn available(scope: &ManagedRoot, tx: &TransactionState) -> bool {
    tx.operation == OPERATION
        && tx.status == TransactionStatus::InProgress
        && read_pending(scope)
            .ok()
            .flatten()
            .is_some_and(|p| p.request_id == tx.request_id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::site::TrustedRoot;
    use std::os::unix::fs::PermissionsExt;
    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const RETRY: &str = "9b2f1c34-5678-4abc-9def-0123456789ab";
    struct Host {
        dir: tempfile::TempDir,
        state: ManagedRoot,
        docker: String,
        input: String,
    }
    impl Host {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            std::fs::create_dir(dir.path().join("state")).unwrap();
            let state =
                ManagedRoot::open(&TrustedRoot::parse(dir.path().join("state")).unwrap()).unwrap();
            let db = dir.path().join("database");
            std::fs::write(&db, "OLD DATA\n").unwrap();
            let docker = dir.path().join("docker");
            std::fs::write(&docker,format!(r#"#!/bin/sh
set -eu
base='{}'
printf '%s\n' "$*" >> "$base/argv"
if [ "$1" = inspect ]; then printf '%064d\n' 0; exit 0; fi
case "$*" in
 *mariadb-dump*|*pg_dump*) [ ! -f "$base/reject_snapshot" ] || exit 1; cat "$base/database"; exit 0;;
esac
case "$*" in
 *" mkdir "*) rm -f "$base/done"; exit 0;;
 *" dd "*"/input.sql"*) cat > "$base/input"; exit 0;;
 *" dd "*) cat > /dev/null; exit 0;;
 *" cat "*"/done") [ -f "$base/done" ] || exit 1; cat "$base/done"; exit 0;;
 *" rm -rf "*) rm -f "$base/done" "$base/input"; exit 0;;
 *" sh "*) input=$(cat "$base/input"); [ -f "$base/missing_completion" ] || printf '0\n' > "$base/done";;
 *) input=$(cat);;
esac
case "$input" in
 "SELECT 1;") [ ! -f "$base/reject_verify" ] || exit 1; printf '1\n'; exit 0;;
 OLD*) [ ! -f "$base/reject_rollback" ] || {{ printf '1\n' > "$base/done"; exit 1; }}; printf '%s\n' "$input" > "$base/database"; exit 0;;
 BROKEN*) printf 'PARTIAL NEW DATA\n' > "$base/database"; [ -f "$base/missing_completion" ] || printf '1\n' > "$base/done"; exit 1;;
esac
printf '%s\n' "$input" > "$base/database"
"#,dir.path().display())).unwrap();
            std::fs::set_permissions(&docker, std::fs::Permissions::from_mode(0o755)).unwrap();
            let input = dir.path().join("dump.sql");
            std::fs::write(&input, "NEW DATA\n").unwrap();
            Self {
                dir,
                state,
                docker: docker.to_str().unwrap().into(),
                input: input.to_str().unwrap().into(),
            }
        }
        fn context(&self) -> RestoreContext<'_> {
            RestoreContext {
                engine_state: &self.state,
                docker_program: &self.docker,
                gunzip_program: "gunzip",
            }
        }
        fn request(&self, id: &str, key: &str) -> Request {
            Request::parse(&serde_json::json!({"dbType":"mariadb","database":"site_db","container":"maria","filePath":self.input,"rootPassword":"never-log-this-secret","confirmOffline":true}).to_string(),id,Some(key),false).unwrap()
        }
        fn data(&self) -> String {
            std::fs::read_to_string(self.dir.path().join("database")).unwrap()
        }
        fn flag(&self, name: &str) {
            std::fs::write(self.dir.path().join(name), "").unwrap();
        }
        fn scope(&self) -> ManagedRoot {
            open_restore_state(&self.state, "site_db").unwrap()
        }
        fn pending(&self) {
            let scope = self.scope();
            let r = self.request(ID, "original");
            let admitted = preflight::run(
                &scope,
                r.restore.request_id,
                r.restore.idempotency_key.as_ref(),
                OPERATION,
            )
            .unwrap();
            assert!(matches!(admitted, preflight::Outcome::Proceed(_)));
            let hash = snapshot(
                &self.context(),
                &r.restore,
                &scope,
                &CancellationToken::default(),
            )
            .unwrap();
            let p = Pending {
                version: 1,
                request_id: ID.into(),
                database: "site_db".into(),
                container: "maria".into(),
                db_type: "mariadb".into(),
                snapshot_sha256: hash,
                container_id: "0".repeat(64),
            };
            scope
                .write_atomic_private(&marker(), &serde_json::to_vec(&p).unwrap())
                .unwrap();
        }
        fn recover(&self, id: &str, key: &str) -> Request {
            Request::parse(&serde_json::json!({"dbType":"mariadb","database":"site_db","container":"maria","rootPassword":"never-log-this-secret","confirmOffline":true,"originalRequestId":ID,"confirmClientsStopped":true}).to_string(),id,Some(key),true).unwrap()
        }
    }
    #[test]
    fn success_is_verified_and_replay_does_not_import_again() {
        let h = Host::new();
        let c = h.context();
        let first = execute(&c, &h.request(ID, "one"), &CancellationToken::default()).unwrap();
        assert_eq!(h.data(), "NEW DATA\n");
        assert!(!h.scope().exists(&marker()));
        std::fs::write(&h.input, "SHOULD NOT IMPORT").unwrap();
        assert_eq!(
            execute(&c, &h.request(RETRY, "one"), &CancellationToken::default())
                .unwrap()
                .restored_at_unix_secs,
            first.restored_at_unix_secs
        );
        assert_eq!(h.data(), "NEW DATA\n");
        let argv = std::fs::read_to_string(h.dir.path().join("argv")).unwrap();
        assert!(!argv.contains("never-log-this-secret"));
        let json = h
            .scope()
            .read_to_string(&state_path(RequestId::parse(ID).unwrap()))
            .unwrap();
        assert!(!json.contains("never-log-this-secret"));
    }
    #[test]
    fn partially_applied_import_rolls_back_before_recording_failure() {
        let h = Host::new();
        std::fs::write(&h.input, "BROKEN SQL").unwrap();
        assert!(matches!(
            execute(
                &h.context(),
                &h.request(ID, "one"),
                &CancellationToken::default()
            ),
            Err(Error::ImportRestored)
        ));
        assert_eq!(h.data(), "OLD DATA\n");
        assert!(!h.scope().exists(&marker()));
        assert_eq!(
            state::load(&h.scope(), &state_path(RequestId::parse(ID).unwrap()))
                .unwrap()
                .status,
            TransactionStatus::Failed
        );
    }
    #[test]
    fn failed_compensation_keeps_snapshot_and_blocks_new_and_legacy_imports() {
        let h = Host::new();
        std::fs::write(&h.input, "BROKEN SQL").unwrap();
        h.flag("reject_rollback");
        assert!(matches!(
            execute(
                &h.context(),
                &h.request(ID, "one"),
                &CancellationToken::default()
            ),
            Err(Error::RecoveryRequired)
        ));
        assert!(h.scope().exists(&marker()));
        assert_eq!(
            state::load(&h.scope(), &state_path(RequestId::parse(ID).unwrap()))
                .unwrap()
                .status,
            TransactionStatus::InProgress
        );
        assert!(matches!(
            execute(
                &h.context(),
                &h.request(RETRY, "two"),
                &CancellationToken::default()
            ),
            Err(Error::Conflict)
        ));
        let legacy = h
            .request("550e8400-e29b-41d4-a716-446655440000", "legacy")
            .restore;
        assert!(
            super::super::execute::execute(&h.context(), &legacy, &CancellationToken::default())
                .is_err()
        );
        assert_eq!(h.data(), "PARTIAL NEW DATA\n");
    }
    #[test]
    fn snapshot_failure_does_not_start_import() {
        let h = Host::new();
        h.flag("reject_snapshot");
        assert!(matches!(
            execute(
                &h.context(),
                &h.request(ID, "one"),
                &CancellationToken::default()
            ),
            Err(Error::Snapshot)
        ));
        assert_eq!(h.data(), "OLD DATA\n");
        assert!(!h.scope().exists(&marker()));
    }
    #[test]
    fn explicit_recovery_uses_original_identity_and_is_idempotent() {
        let h = Host::new();
        h.pending();
        std::fs::write(h.dir.path().join("database"), "PARTIAL").unwrap();
        let scope = h.scope();
        let original = state::load(&scope, &state_path(RequestId::parse(ID).unwrap())).unwrap();
        assert!(available(&scope, &original));
        let p = scope
            .open_regular_read(&snapshot_path(original.request_id))
            .unwrap();
        assert_eq!(p.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        let recovered = execute(
            &h.context(),
            &h.recover(RETRY, "recovery"),
            &CancellationToken::default(),
        )
        .unwrap();
        assert_eq!(h.data(), "OLD DATA\n");
        assert!(!h.scope().exists(&marker()));
        let replay = execute(
            &h.context(),
            &h.recover("550e8400-e29b-41d4-a716-446655440000", "recovery"),
            &CancellationToken::default(),
        )
        .unwrap();
        assert_eq!(
            recovered.restored_at_unix_secs,
            replay.restored_at_unix_secs
        );
    }
    #[test]
    fn tampered_snapshot_and_changed_container_are_refused() {
        let h = Host::new();
        h.pending();
        h.scope()
            .write_atomic(&snapshot_path(RequestId::parse(ID).unwrap()), b"tampered")
            .unwrap();
        assert!(matches!(
            execute(
                &h.context(),
                &h.recover(RETRY, "recovery"),
                &CancellationToken::default()
            ),
            Err(Error::RecoveryRequired)
        ));
        assert!(h.scope().exists(&marker()));
        assert_eq!(h.data(), "OLD DATA\n");
        let mut plan = serde_json::json!({"dbType":"mariadb","database":"site_db","container":"other","rootPassword":"pw","confirmOffline":true,"originalRequestId":ID,"confirmClientsStopped":true});
        let r = Request::parse(
            &plan.to_string(),
            "550e8400-e29b-41d4-a716-446655440000",
            Some("other"),
            true,
        )
        .unwrap();
        assert!(matches!(
            execute(&h.context(), &r, &CancellationToken::default()),
            Err(Error::Conflict)
        ));
        plan["confirmClientsStopped"] = false.into();
        assert!(Request::parse(&plan.to_string(), RETRY, Some("k"), true).is_err());
    }
    #[test]
    fn corrupt_archive_and_symlink_are_refused_before_snapshot() {
        let mut h = Host::new();
        let gz = format!("{}.gz", h.input);
        std::fs::write(&gz, "not gzip").unwrap();
        h.input = gz;
        assert!(
            execute(
                &h.context(),
                &h.request(ID, "gzip"),
                &CancellationToken::default()
            )
            .is_err()
        );
        assert_eq!(h.data(), "OLD DATA\n");
        let target = h.dir.path().join("link.sql");
        std::os::unix::fs::symlink(&h.input, &target).unwrap();
        h.input = target.to_str().unwrap().into();
        assert!(
            execute(
                &h.context(),
                &h.request(RETRY, "symlink"),
                &CancellationToken::default()
            )
            .is_err()
        );
        assert_eq!(h.data(), "OLD DATA\n");
        assert!(!h.dir.path().join("argv").exists());
    }
    #[test]
    fn requests_require_offline_confirmation_and_refuse_system_databases() {
        let h = Host::new();
        for database in ["mysql", "postgres", "template1", "sys"] {
            let p = serde_json::json!({"dbType":"mariadb","database":database,"container":"maria","filePath":h.input,"rootPassword":"pw","confirmOffline":true});
            assert!(Request::parse(&p.to_string(), ID, Some("k"), false).is_err());
        }
        let p = serde_json::json!({"dbType":"mariadb","database":"site","container":"maria","filePath":h.input,"rootPassword":"pw","confirmOffline":false});
        assert!(Request::parse(&p.to_string(), ID, Some("k"), false).is_err());
    }
    #[test]
    fn valid_gzip_is_fully_staged_before_import() {
        use std::io::Write;
        let mut h = Host::new();
        let path = format!("{}.gz", h.input);
        let mut archive = flate2::write::GzEncoder::new(
            std::fs::File::create(&path).unwrap(),
            flate2::Compression::default(),
        );
        archive.write_all(b"NEW DATA\n").unwrap();
        archive.finish().unwrap();
        h.input = path;
        execute(
            &h.context(),
            &h.request(ID, "gzip"),
            &CancellationToken::default(),
        )
        .unwrap();
        assert_eq!(h.data(), "NEW DATA\n");
    }
    #[test]
    fn terminal_original_is_never_rolled_back_during_cleanup_recovery() {
        let h = Host::new();
        h.pending();
        let scope = h.scope();
        let id = RequestId::parse(ID).unwrap();
        std::fs::write(h.dir.path().join("database"), "COMMITTED DATA\n").unwrap();
        let mut tx = state::load(&scope, &state_path(id)).unwrap();
        save_terminal(
            &scope,
            &mut tx,
            Some(&RestoreResult {
                restored_at_unix_secs: 1,
            }),
            None,
        )
        .unwrap();
        assert!(matches!(
            execute(
                &h.context(),
                &h.recover(RETRY, "cleanup"),
                &CancellationToken::default()
            ),
            Err(Error::Conflict)
        ));
        assert_eq!(h.data(), "COMMITTED DATA\n");
        assert!(!scope.exists(&marker()));
    }
    #[test]
    fn a_recreated_container_is_not_a_recovery_target() {
        let h = Host::new();
        h.pending();
        let script = std::fs::read_to_string(&h.docker)
            .unwrap()
            .replace("printf '%064d\\n' 0", "printf '%064d\\n' 1");
        std::fs::write(&h.docker, script).unwrap();
        assert!(matches!(
            execute(
                &h.context(),
                &h.recover(RETRY, "changed-container"),
                &CancellationToken::default()
            ),
            Err(Error::RecoveryRequired)
        ));
        assert!(h.scope().exists(&marker()));
        assert_eq!(h.data(), "OLD DATA\n");
    }
    #[test]
    fn docker_exit_without_in_container_completion_never_starts_compensation() {
        let h = Host::new();
        h.flag("missing_completion");
        std::fs::write(&h.input, "BROKEN SQL").unwrap();
        assert!(matches!(
            execute(
                &h.context(),
                &h.request(ID, "lost-docker"),
                &CancellationToken::default()
            ),
            Err(Error::RecoveryRequired)
        ));
        assert_eq!(h.data(), "PARTIAL NEW DATA\n");
        assert!(h.scope().exists(&marker()));
        std::fs::remove_file(h.dir.path().join("missing_completion")).unwrap();
        execute(
            &h.context(),
            &h.recover(RETRY, "confirmed-client-stopped"),
            &CancellationToken::default(),
        )
        .unwrap();
        assert_eq!(h.data(), "OLD DATA\n");
    }
}
