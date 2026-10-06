//! `system.signalProcess`: deliver one allowlisted signal to one process,
//! after the engine itself has verified what that process is. Replaces the
//! panel's `ps -p <pid> -o comm=` followed by a separate `sudo kill -9 <pid>`
//! SSH call, whose gap let a PID be reused between the safety check and the
//! kill, and whose protected-process policy lived outside the engine.
//!
//! Identity is pinned with a pidfd: the process's `/proc/<pid>/stat`
//! (comm + start time) is read before and after `pidfd_open`, and the signal
//! is sent through the pidfd (`pidfd_send_signal`), never through the bare
//! PID. A PID that was recycled between the reads shows a different start
//! time and is refused; a process that exits after the pidfd is open is
//! never replaced by another one behind it. Linux only (kernel 5.3+); a host
//! without pidfd support gets `DEPENDENCY_UNAVAILABLE`, never a raw `kill`.
//!
//! Protected targets (checked on the pinned identity, so the verdict is about
//! the exact process that would be signalled): PID 0/1 (rejected at parse),
//! the engine's own process, kernel threads, and every `sshd` / `sshd-*`
//! process. Idempotency: with an idempotency key a replay returns the first
//! outcome without signalling again; without one every request signals once.
//! A signal that was delivered is reported as delivered — whether the
//! process then died is not claimed.

use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    site::SiteRelativePath,
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        state::{self, TransactionStatus},
    },
};
use std::{
    fs, io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub const OPERATION: &str = "system.signalProcess";
pub const PROC_ROOT: &str = "/proc";
/// PID 1 and below are never valid targets.
pub const MIN_PID: u32 = 2;
/// Linux `PID_MAX_LIMIT` (2^22).
pub const MAX_PID: u32 = 4_194_304;
const PF_KTHREAD: u64 = 0x0020_0000;
const MAX_COMM_LEN: usize = 15;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Signal {
    Term,
    Kill,
    Hup,
    Int,
}

impl Signal {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "TERM" => Some(Self::Term),
            "KILL" => Some(Self::Kill),
            "HUP" => Some(Self::Hup),
            "INT" => Some(Self::Int),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Term => "TERM",
            Self::Kill => "KILL",
            Self::Hup => "HUP",
            Self::Int => "INT",
        }
    }

    const fn number(self) -> i32 {
        match self {
            Self::Term => libc::SIGTERM,
            Self::Kill => libc::SIGKILL,
            Self::Hup => libc::SIGHUP,
            Self::Int => libc::SIGINT,
        }
    }
}

pub struct Request {
    pub pid: u32,
    pub signal: Signal,
    /// When set, the process must still carry exactly this `comm` name.
    pub expect_comm: Option<String>,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidPid,
    InvalidSignal,
    InvalidExpectedComm,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl RequestError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidPid => "pid must be between 2 and 4194304",
            Self::InvalidSignal => "signal must be one of TERM, KILL, HUP, INT",
            Self::InvalidExpectedComm => "expect-comm must be 1-15 printable ASCII characters",
            Self::InvalidRequestId | Self::InvalidIdempotencyKey => {
                "request-id or idempotency-key is invalid"
            }
        }
    }
}

impl Request {
    /// An absent `signal` means `TERM`.
    pub fn parse(
        pid: u32,
        signal: Option<&str>,
        expect_comm: Option<&str>,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        if !(MIN_PID..=MAX_PID).contains(&pid) {
            return Err(RequestError::InvalidPid);
        }
        let signal = match signal {
            None => Signal::Term,
            Some(value) => Signal::parse(value).ok_or(RequestError::InvalidSignal)?,
        };
        if let Some(comm) = expect_comm {
            if comm.is_empty()
                || comm.len() > MAX_COMM_LEN
                || !comm.bytes().all(|b| (0x20..0x7f).contains(&b))
            {
                return Err(RequestError::InvalidExpectedComm);
            }
        }
        Ok(Self {
            pid,
            signal,
            expect_comm: expect_comm.map(str::to_owned),
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignalResult {
    pub pid: u32,
    /// The verified `comm` of the process the signal was delivered to.
    pub comm: String,
    pub signal: String,
    pub completed_at_unix_secs: u64,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub proc_root: &'a Path,
    pub engine_pid: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
    pub comm: String,
    pub start_time: u64,
    pub flags: u64,
}

#[derive(Debug)]
pub enum Refusal {
    Gone,
    Protected(&'static str),
    IdentityChanged,
    Permission,
    PidfdUnsupported,
    Io(io::Error),
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Refused(Refusal),
    PostCommit { result: SignalResult },
    Replayed { code: ErrorCode, message: String },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another process signal is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Refused(Refusal::Gone) => (ErrorCode::NotFound, "no such process".into()),
            Self::Refused(Refusal::Protected(why)) => (
                ErrorCode::InvalidInput,
                format!("refusing to signal a protected process ({why})"),
            ),
            Self::Refused(Refusal::IdentityChanged) => (
                ErrorCode::Conflict,
                "the process is not the one that was expected".into(),
            ),
            Self::Refused(Refusal::Permission) => (
                ErrorCode::PermissionDenied,
                "not permitted to signal this process".into(),
            ),
            Self::Refused(Refusal::PidfdUnsupported) => (
                ErrorCode::DependencyUnavailable,
                "this kernel does not support pidfd".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Refused(Refusal::Io(_))
            | Self::Io(_)
            | Self::Preflight(_)
            | Self::PostCommit { .. } => {
                (ErrorCode::Internal, "internal process signal error".into())
            }
        }
    }
}

/// Parses `/proc/<pid>/stat`. The comm field sits in parentheses and may
/// itself contain spaces and parentheses, so it is delimited by the first
/// `(` and the *last* `)`.
pub fn parse_stat(stat: &str) -> Option<Identity> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    if close < open {
        return None;
    }
    let comm = stat[open + 1..close].to_owned();
    let rest: Vec<&str> = stat[close + 1..].split_whitespace().collect();
    // Overall field n (1-based) is rest[n - 3]: flags is 9, starttime is 22.
    let flags = rest.get(6)?.parse().ok()?;
    let start_time = rest.get(19)?.parse().ok()?;
    Some(Identity {
        comm,
        start_time,
        flags,
    })
}

fn read_identity(proc_root: &Path, pid: u32) -> Result<Identity, Refusal> {
    match fs::read_to_string(proc_root.join(pid.to_string()).join("stat")) {
        Ok(stat) => parse_stat(&stat).ok_or_else(|| {
            Refusal::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "unparseable /proc stat",
            ))
        }),
        Err(e) if matches!(e.kind(), io::ErrorKind::NotFound) => Err(Refusal::Gone),
        // A process that exits mid-read yields ESRCH.
        Err(e) if e.raw_os_error() == Some(libc::ESRCH) => Err(Refusal::Gone),
        Err(e) => Err(Refusal::Io(e)),
    }
}

pub fn protected_reason(pid: u32, identity: &Identity, engine_pid: u32) -> Option<&'static str> {
    if pid <= 1 {
        return Some("init");
    }
    if pid == engine_pid {
        return Some("the engine itself");
    }
    if identity.flags & PF_KTHREAD != 0 {
        return Some("kernel thread");
    }
    if identity.comm == "sshd" || identity.comm.starts_with("sshd-") {
        return Some("sshd");
    }
    None
}

fn pidfd_open(pid: u32) -> Result<OwnedFd, Refusal> {
    // SAFETY: plain syscall; the returned descriptor is owned immediately.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd < 0 {
        let e = io::Error::last_os_error();
        return Err(match e.raw_os_error() {
            Some(libc::ESRCH) => Refusal::Gone,
            Some(libc::ENOSYS) | Some(libc::EPERM) | Some(libc::EINVAL) => {
                Refusal::PidfdUnsupported
            }
            _ => Refusal::Io(e),
        });
    }
    // SAFETY: `fd` is a fresh valid descriptor returned by the kernel.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

fn pidfd_send_signal(fd: &OwnedFd, signal: Signal) -> Result<(), Refusal> {
    // SAFETY: valid pidfd, null siginfo, no flags.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            signal.number(),
            std::ptr::null::<libc::siginfo_t>(),
            0u32,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    let e = io::Error::last_os_error();
    Err(match e.raw_os_error() {
        Some(libc::ESRCH) => Refusal::Gone,
        Some(libc::EPERM) => Refusal::Permission,
        Some(libc::ENOSYS) => Refusal::PidfdUnsupported,
        _ => Refusal::Io(e),
    })
}

/// Pins the process, verifies it, and signals it through the pidfd.
fn verify_and_signal(ctx: &Context<'_>, req: &Request) -> Result<SignalResult, Refusal> {
    let before = read_identity(ctx.proc_root, req.pid)?;
    let pidfd = pidfd_open(req.pid)?;
    let after = read_identity(ctx.proc_root, req.pid)?;
    // The same start time on both sides of `pidfd_open` proves the pidfd
    // refers to the process that was inspected, not a recycled PID.
    if before.start_time != after.start_time || before.comm != after.comm {
        return Err(Refusal::IdentityChanged);
    }
    if let Some(why) = protected_reason(req.pid, &after, ctx.engine_pid) {
        return Err(Refusal::Protected(why));
    }
    if let Some(expected) = &req.expect_comm {
        if *expected != after.comm {
            return Err(Refusal::IdentityChanged);
        }
    }
    pidfd_send_signal(&pidfd, req.signal)?;
    Ok(SignalResult {
        pid: req.pid,
        comm: after.comm,
        signal: req.signal.name().to_owned(),
        completed_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    })
}

pub fn execute(ctx: &Context<'_>, req: &Request) -> Result<SignalResult, Error> {
    let scope_path = SiteRelativePath::parse("system-signal-process").unwrap();
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

    let result = match verify_and_signal(ctx, req) {
        Ok(v) => v,
        Err(refusal) => {
            return Err(fail(
                &scope,
                &state_path,
                &audit_path,
                state,
                Error::Refused(refusal),
            ));
        }
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

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<SignalResult, Error> {
    let path = SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap();
    let loaded = state::load(scope, &path)
        .map_err(|error| Error::Io(io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != OPERATION {
        return Err(Error::Io(io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => {
            serde_json::from_value(loaded.outcome.unwrap().result.unwrap())
                .map_err(|error| Error::Io(io::Error::other(error)))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::{fs::PermissionsExt, process::ExitStatusExt},
        process::{Child, Command},
        sync::Mutex,
        time::{Duration, Instant},
    };

    // Tests signal real processes; keep them from overlapping.
    static SERIAL: Mutex<()> = Mutex::new(());
    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const ID2: &str = "223e4567-e89b-12d3-a456-426614174000";

    fn managed(dir: &Path) -> ManagedRoot {
        ManagedRoot::open(&crate::site::TrustedRoot::parse(dir).unwrap()).unwrap()
    }

    fn ctx(state: &ManagedRoot) -> Context<'_> {
        Context {
            engine_state: state,
            proc_root: Path::new(PROC_ROOT),
            engine_pid: std::process::id(),
        }
    }

    fn which_sleep() -> std::path::PathBuf {
        ["/bin/sleep", "/usr/bin/sleep"]
            .iter()
            .map(std::path::PathBuf::from)
            .find(|p| p.exists())
            .unwrap()
    }

    /// Spawns `sleep` under `name` (a copy of the binary) in its own
    /// directory, and waits until the new image's comm is visible.
    fn spawn_named(name: &str) -> (tempfile::TempDir, Child) {
        let dir = tempfile::tempdir().unwrap();
        let program = dir.path().join(name);
        fs::copy(which_sleep(), &program).unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();
        let child = Command::new(&program).arg("300").spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let want: String = name.chars().take(MAX_COMM_LEN).collect();
        loop {
            if let Ok(id) = read_identity(Path::new(PROC_ROOT), child.id()) {
                if id.comm == want {
                    return (dir, child);
                }
            }
            assert!(Instant::now() < deadline, "child never reached its comm");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn request(pid: u32, signal: &str, id: &str) -> Request {
        Request::parse(pid, Some(signal), None, id, None).unwrap()
    }

    #[test]
    fn parse_rejects_init_and_out_of_range_pids_and_bad_signals() {
        for pid in [0, 1, MAX_PID + 1] {
            assert_eq!(
                Request::parse(pid, None, None, ID, None).err(),
                Some(RequestError::InvalidPid)
            );
        }
        assert_eq!(
            Request::parse(5, Some("SEGV"), None, ID, None).err(),
            Some(RequestError::InvalidSignal)
        );
        assert_eq!(
            Request::parse(5, Some("9"), None, ID, None).err(),
            Some(RequestError::InvalidSignal)
        );
        assert_eq!(
            Request::parse(5, None, Some(""), ID, None).err(),
            Some(RequestError::InvalidExpectedComm)
        );
        assert_eq!(
            Request::parse(5, None, None, ID, None).unwrap().signal,
            Signal::Term
        );
    }

    #[test]
    fn stat_parser_handles_hostile_comm() {
        let stat = "42 (a) b (c d) S 1 42 42 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 98765 1000 \
                    100 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0";
        let id = parse_stat(stat).unwrap();
        assert_eq!(id.comm, "a) b (c d");
        assert_eq!(id.start_time, 98765);
        assert_eq!(id.flags, 4194560);
        assert!(parse_stat("garbage").is_none());
    }

    #[test]
    fn protected_policy() {
        let plain = Identity {
            comm: "php-fpm".into(),
            start_time: 1,
            flags: 0,
        };
        assert_eq!(protected_reason(1, &plain, 99), Some("init"));
        assert_eq!(protected_reason(99, &plain, 99), Some("the engine itself"));
        assert_eq!(protected_reason(50, &plain, 99), None);
        let sshd = Identity {
            comm: "sshd".into(),
            ..plain.clone()
        };
        assert_eq!(protected_reason(50, &sshd, 99), Some("sshd"));
        let session = Identity {
            comm: "sshd-session".into(),
            ..plain.clone()
        };
        assert_eq!(protected_reason(50, &session, 99), Some("sshd"));
        let kthread = Identity {
            flags: PF_KTHREAD,
            ..plain
        };
        assert_eq!(protected_reason(2, &kthread, 99), Some("kernel thread"));
    }

    #[test]
    fn kills_a_spawned_process_and_records_it() {
        let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let state_dir = tempfile::tempdir().unwrap();
        let state = managed(state_dir.path());
        let (_dir, mut child) = spawn_named("wcpvictim");
        let result = execute(&ctx(&state), &request(child.id(), "KILL", ID)).unwrap();
        assert_eq!(result.comm, "wcpvictim");
        assert_eq!(result.signal, "KILL");
        assert_eq!(child.wait().unwrap().signal(), Some(libc::SIGKILL));
        let audit = fs::read_to_string(
            state_dir
                .path()
                .join("system-signal-process/audit/events.jsonl"),
        )
        .unwrap();
        assert!(audit.contains("\"ok\":true"));
    }

    #[test]
    fn default_term_and_idempotent_replay_do_not_signal_twice() {
        let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let state_dir = tempfile::tempdir().unwrap();
        let state = managed(state_dir.path());
        let (_dir, mut child) = spawn_named("wcpvictim");
        let req = Request::parse(child.id(), None, None, ID, Some("kill-once")).unwrap();
        execute(&ctx(&state), &req).unwrap();
        assert_eq!(child.wait().unwrap().signal(), Some(libc::SIGTERM));
        // The replay returns the recorded outcome even though the process
        // is gone; a fresh request for the same PID is NOT_FOUND.
        let replayed = execute(&ctx(&state), &req).unwrap();
        assert_eq!(replayed.signal, "TERM");
        let fresh = execute(&ctx(&state), &request(child.id(), "TERM", ID2));
        assert!(matches!(fresh, Err(Error::Refused(Refusal::Gone))));
    }

    #[test]
    fn missing_process_is_not_found() {
        let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let state_dir = tempfile::tempdir().unwrap();
        let state = managed(state_dir.path());
        let err = execute(&ctx(&state), &request(MAX_PID, "TERM", ID)).unwrap_err();
        assert_eq!(err.protocol().0, ErrorCode::NotFound);
    }

    #[test]
    fn refuses_sshd_named_process_and_the_engine_itself() {
        let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let state_dir = tempfile::tempdir().unwrap();
        let state = managed(state_dir.path());
        let (_dir, mut child) = spawn_named("sshd");
        let err = execute(&ctx(&state), &request(child.id(), "KILL", ID)).unwrap_err();
        assert_eq!(err.protocol().0, ErrorCode::InvalidInput);
        assert!(
            child.try_wait().unwrap().is_none(),
            "protected process must survive"
        );
        child.kill().unwrap();
        child.wait().unwrap();

        let own = request(std::process::id(), "KILL", ID2);
        assert!(matches!(
            execute(&ctx(&state), &own),
            Err(Error::Refused(Refusal::Protected(_)))
        ));
    }

    #[test]
    fn refuses_when_the_process_is_not_the_expected_one() {
        let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let state_dir = tempfile::tempdir().unwrap();
        let state = managed(state_dir.path());
        let (_dir, mut child) = spawn_named("wcpvictim");
        let req = Request::parse(child.id(), Some("KILL"), Some("php-fpm"), ID, None).unwrap();
        let err = execute(&ctx(&state), &req).unwrap_err();
        assert_eq!(err.protocol().0, ErrorCode::Conflict);
        assert!(
            child.try_wait().unwrap().is_none(),
            "mismatched process must survive"
        );
        child.kill().unwrap();
        child.wait().unwrap();
    }
}
