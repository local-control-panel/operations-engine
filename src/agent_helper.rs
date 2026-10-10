//! `ops-engine agent heartbeat|lock|log`: the helpers every agent script needs,
//! identical for Bash and Python agents.
//!
//! These are not protocol operations. They run inside an agent's own process
//! tree, so they follow the agent contract instead of the envelope rules:
//!
//! - stdout is empty on success unless `--json` is given (then one protocol
//!   envelope), because a script's stdout belongs to the script;
//! - the exit code is the contract (0 success, 1 runtime failure, 2 invalid
//!   input, 75 for `lock --check` on a held lock; `lock -- CMD` returns the
//!   command's own code);
//! - `WCP_DRY_RUN=1` suppresses the files an agent run would leave behind
//!   (heartbeat and log lines) but still takes the lock;
//! - state lives under `$WCP_DIR` (default `/root/.wcp`), the same files the
//!   hand-written prologue used (`agents/<name>.heartbeat`, `agents/<name>.lock`,
//!   `logs/<name>.log`), so old and new agents interoperate.
//!
//! See `docs/agent-api.md` in the agents repository.

use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};

use crate::{
    agent_lifecycle::{ROOT, valid_agent_name},
    cli::{AgentCommand, LogLevel},
    error::ErrorCode,
    protocol::Response,
};

pub const EXIT_OK: i32 = 0;
pub const EXIT_FAILURE: i32 = 1;
pub const EXIT_INVALID: i32 = 2;
/// `lock --check` on a lock that is held (sysexits EX_TEMPFAIL).
pub const EXIT_HELD: i32 = 75;
pub const EXIT_NOT_EXECUTABLE: i32 = 126;
pub const EXIT_NOT_FOUND: i32 = 127;

pub const DEFAULT_MAX_LINES: usize = 2000;
const MAX_LINES_LIMIT: usize = 100_000;
const MAX_MESSAGE_CHARS: usize = 2000;
const MAX_STDIN_BYTES: u64 = 16 * 1024;
/// Set in the environment of a command run under `lock`, so a script that
/// re-executes itself through the wrapper can tell it already holds the lock.
pub const LOCK_HELD_ENV: &str = "WCP_LOCK_HELD";

/// What went wrong, with the exit code and the protocol error it maps to.
#[derive(Debug, Eq, PartialEq)]
pub enum HelperError {
    Invalid(String),
    Failed(String),
}

impl HelperError {
    fn code(&self) -> (i32, ErrorCode) {
        match self {
            Self::Invalid(_) => (EXIT_INVALID, ErrorCode::InvalidInput),
            Self::Failed(_) => (EXIT_FAILURE, ErrorCode::Internal),
        }
    }

    fn message(&self) -> &str {
        match self {
            Self::Invalid(message) | Self::Failed(message) => message,
        }
    }
}

/// Where the agents' state lives: `$WCP_DIR` when set and non-empty.
pub fn state_dir() -> PathBuf {
    match std::env::var_os("WCP_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => PathBuf::from(ROOT),
    }
}

pub fn dry_run() -> bool {
    std::env::var("WCP_DRY_RUN").is_ok_and(|value| value == "1")
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn check_name(name: &str) -> Result<(), HelperError> {
    if valid_agent_name(name) {
        Ok(())
    } else {
        Err(HelperError::Invalid(
            "agent name must be lowercase letters, digits and '-' (at most 64)".into(),
        ))
    }
}

fn io_failure(what: &str, error: &io::Error) -> HelperError {
    HelperError::Failed(format!("{what}: {error}"))
}

fn create_dir(path: &Path) -> Result<(), HelperError> {
    fs::create_dir_all(path)
        .map_err(|error| io_failure(&format!("cannot create {}", path.display()), &error))
}

pub fn heartbeat_path(dir: &Path, name: &str) -> PathBuf {
    dir.join("agents").join(format!("{name}.heartbeat"))
}

pub fn lock_path(dir: &Path, name: &str) -> PathBuf {
    dir.join("agents").join(format!("{name}.lock"))
}

pub fn log_path(dir: &Path, name: &str) -> PathBuf {
    dir.join("logs").join(format!("{name}.log"))
}

/// Writes `{"ts":..,"exit_code":..}` atomically (temporary file in the same
/// directory, then rename), so the panel never reads a half-written line.
pub fn write_heartbeat(
    dir: &Path,
    name: &str,
    exit_code: i32,
    ts: u64,
) -> Result<PathBuf, HelperError> {
    check_name(name)?;
    let path = heartbeat_path(dir, name);
    create_dir(path.parent().unwrap_or(dir))?;
    let temporary = path.with_extension(format!("heartbeat.{}.tmp", std::process::id()));
    let line = format!("{{\"ts\":{ts},\"exit_code\":{exit_code}}}\n");
    let written = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .and_then(|mut file| file.write_all(line.as_bytes()))
        .and_then(|()| fs::rename(&temporary, &path));
    if let Err(error) = written {
        let _ = fs::remove_file(&temporary);
        return Err(io_failure("cannot write the heartbeat", &error));
    }
    Ok(path)
}

/// Opens (creating, mode 0600) the lock file and takes the exclusive
/// non-blocking `flock`. `Ok(None)` means another process holds it. The lock
/// lives as long as the returned file's open file description.
pub fn try_lock(dir: &Path, name: &str) -> Result<Option<File>, HelperError> {
    check_name(name)?;
    let path = lock_path(dir, name);
    create_dir(path.parent().unwrap_or(dir))?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|error| io_failure("cannot open the lock file", &error))?;
    // SAFETY: `file` is open for the duration of the call.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        return Ok(Some(file));
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::WouldBlock {
        Ok(None)
    } else {
        Err(io_failure("cannot lock", &error))
    }
}

/// The JSON line `agent log` appends.
pub fn log_line(name: &str, level: LogLevel, message: &str, ts: u64) -> String {
    let message: String = message.chars().take(MAX_MESSAGE_CHARS).collect();
    let mut line = json!({
        "ts": ts,
        "agent": name,
        "level": level.as_str(),
        "msg": message,
    })
    .to_string();
    line.push('\n');
    line
}

/// Appends `line` to the agent's log and keeps only the last `max_lines`
/// lines. The file is locked while it changes, so concurrent helper calls
/// (the agent and a child of it) cannot lose each other's lines.
pub fn append_log(
    dir: &Path,
    name: &str,
    line: &str,
    max_lines: usize,
) -> Result<PathBuf, HelperError> {
    check_name(name)?;
    let path = log_path(dir, name);
    create_dir(path.parent().unwrap_or(dir))?;
    let fail = |error: io::Error| io_failure("cannot write the log", &error);
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(fail)?;
    // SAFETY: `file` is open; the lock is released when it closes.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(fail(io::Error::last_os_error()));
    }
    file.write_all(line.as_bytes()).map_err(fail)?;
    trim(&path, &mut file, max_lines).map_err(fail)?;
    Ok(path)
}

fn trim(path: &Path, file: &mut File, max_lines: usize) -> io::Result<()> {
    let mut content = Vec::new();
    File::open(path)?.read_to_end(&mut content)?;
    let newlines = content.iter().filter(|byte| **byte == b'\n').count();
    if newlines <= max_lines {
        return Ok(());
    }
    let mut skip = newlines - max_lines;
    let start = content
        .iter()
        .position(|byte| {
            if *byte == b'\n' {
                skip -= 1;
                skip == 0
            } else {
                false
            }
        })
        .map_or(0, |index| index + 1);
    // Rewrite in place: a rename would orphan the lock held on `file`.
    file.set_len(0)?;
    // The descriptor is in append mode, so the write lands at the new end.
    file.write_all(&content[start..])
}

/// Replaces the current process with `command`, keeping `lock` open (its
/// descriptor is made inheritable) so the lock lasts exactly as long as the
/// command. Returns only if the exec failed, as the exit code to use.
fn exec_locked(lock: &File, name: &str, command: &[String]) -> i32 {
    // SAFETY: plain fcntl calls on a descriptor we own.
    unsafe {
        let flags = libc::fcntl(lock.as_raw_fd(), libc::F_GETFD);
        if flags < 0 || libc::fcntl(lock.as_raw_fd(), libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0
        {
            eprintln!("agent lock: cannot pass the lock to the command");
            return EXIT_FAILURE;
        }
    }
    let Ok(program) = CString::new(command[0].as_bytes()) else {
        eprintln!("agent lock: the command contains a NUL byte");
        return EXIT_INVALID;
    };
    let mut argv = Vec::with_capacity(command.len());
    for argument in command {
        match CString::new(argument.as_bytes()) {
            Ok(value) => argv.push(value),
            Err(_) => {
                eprintln!("agent lock: an argument contains a NUL byte");
                return EXIT_INVALID;
            }
        }
    }
    let mut pointers: Vec<*const libc::c_char> = argv.iter().map(|value| value.as_ptr()).collect();
    pointers.push(std::ptr::null());
    // SAFETY: single-threaded here; no other thread has run since the lock
    // was taken, and setenv only touches our own environment.
    unsafe {
        let key = CString::new(LOCK_HELD_ENV).expect("literal has no NUL");
        let value = CString::new(name).expect("validated name has no NUL");
        libc::setenv(key.as_ptr(), value.as_ptr(), 1);
        libc::execvp(program.as_ptr(), pointers.as_ptr());
    }
    let error = io::Error::last_os_error();
    eprintln!("agent lock: cannot run {}: {error}", command[0]);
    if error.kind() == io::ErrorKind::NotFound {
        EXIT_NOT_FOUND
    } else {
        EXIT_NOT_EXECUTABLE
    }
}

fn read_stdin_message() -> Result<String, HelperError> {
    let mut text = String::new();
    io::stdin()
        .take(MAX_STDIN_BYTES)
        .read_to_string(&mut text)
        .map_err(|error| io_failure("cannot read standard input", &error))?;
    Ok(text.trim_end_matches(['\n', '\r']).to_owned())
}

fn emit(operation: &'static str, outcome: Result<Value, HelperError>, json: bool) -> i32 {
    match outcome {
        Ok(result) => {
            if json {
                if let Ok(response) = Response::success(operation, result) {
                    print_envelope(&response);
                }
            }
            EXIT_OK
        }
        Err(error) => {
            let (code, error_code) = error.code();
            if json {
                print_envelope(&Response::failure(operation, error_code, error.message()));
            }
            eprintln!("{operation}: {}", error.message());
            code
        }
    }
}

fn print_envelope(response: &Response) {
    if let Ok(text) = serde_json::to_string(response) {
        println!("{text}");
    }
}

/// Whether `command` is one of the helpers handled here instead of through
/// the protocol path.
pub fn is_helper(command: &AgentCommand) -> bool {
    matches!(
        command,
        AgentCommand::Heartbeat { .. } | AgentCommand::Lock { .. } | AgentCommand::Log { .. }
    )
}

/// Runs a helper and returns the process exit code. Panics on a non-helper
/// (callers check `is_helper`).
pub fn run(command: &AgentCommand) -> i32 {
    run_in(&state_dir(), dry_run(), command)
}

pub fn run_in(dir: &Path, dry_run: bool, command: &AgentCommand) -> i32 {
    match command {
        AgentCommand::Heartbeat {
            name,
            exit_code,
            json,
        } => {
            let outcome = if dry_run {
                check_name(name).map(|()| {
                    json!({"agent": name, "exitCode": exit_code, "written": false, "dryRun": true})
                })
            } else {
                write_heartbeat(dir, name, *exit_code, now()).map(|path| {
                    json!({"agent": name, "exitCode": exit_code, "written": true,
                           "dryRun": false, "path": path})
                })
            };
            emit("agent.heartbeat", outcome, *json)
        }
        AgentCommand::Log {
            name,
            level,
            max_lines,
            message,
            json,
        } => {
            let outcome = log_outcome(dir, dry_run, name, *level, *max_lines, message);
            emit("agent.log", outcome, *json)
        }
        AgentCommand::Lock {
            name,
            check,
            held_exit_code,
            json,
            command,
        } => run_lock(dir, name, *check, *held_exit_code, *json, command),
        _ => unreachable!("run is only called for helper commands"),
    }
}

fn log_outcome(
    dir: &Path,
    dry_run: bool,
    name: &str,
    level: LogLevel,
    max_lines: usize,
    message: &[String],
) -> Result<Value, HelperError> {
    check_name(name)?;
    if max_lines == 0 || max_lines > MAX_LINES_LIMIT {
        return Err(HelperError::Invalid(format!(
            "--max-lines must be between 1 and {MAX_LINES_LIMIT}"
        )));
    }
    let text = if message.is_empty() || message == ["-"] {
        read_stdin_message()?
    } else {
        message.join(" ")
    };
    let line = log_line(name, level, &text, now());
    if dry_run {
        return Ok(json!({"agent": name, "written": false, "dryRun": true,
                         "line": serde_json::from_str::<Value>(&line).unwrap_or(Value::Null)}));
    }
    let path = append_log(dir, name, &line, max_lines)?;
    Ok(json!({"agent": name, "written": true, "dryRun": false, "path": path}))
}

fn run_lock(
    dir: &Path,
    name: &str,
    check: bool,
    held_exit_code: u8,
    json: bool,
    command: &[String],
) -> i32 {
    if check != command.is_empty() {
        let error = HelperError::Invalid(
            "give either --check or a command after `--` (`lock NAME -- CMD...`)".into(),
        );
        return emit("agent.lock", Err(error), json);
    }
    let held = match try_lock(dir, name) {
        Ok(held) => held,
        Err(error) => return emit("agent.lock", Err(error), json),
    };
    match (held, check) {
        (Some(_free), true) => {
            // Dropping the file at the end of the arm releases the probe.
            emit(
                "agent.lock",
                Ok(json!({"agent": name, "held": false})),
                json,
            )
        }
        (None, true) => {
            emit("agent.lock", Ok(json!({"agent": name, "held": true})), json);
            EXIT_HELD
        }
        (None, false) => {
            emit(
                "agent.lock",
                Ok(json!({"agent": name, "held": true, "ran": false})),
                json,
            );
            i32::from(held_exit_code)
        }
        (Some(lock), false) => exec_locked(&lock, name, command),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(line: &str) -> Value {
        serde_json::from_str(line).unwrap()
    }

    #[test]
    fn heartbeat_has_exactly_ts_and_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_heartbeat(dir.path(), "demo", 3, 1_700_000_000).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(text, "{\"ts\":1700000000,\"exit_code\":3}\n");
        assert_eq!(path, dir.path().join("agents/demo.heartbeat"));
        let leftovers: Vec<_> = fs::read_dir(dir.path().join("agents")).unwrap().collect();
        assert_eq!(leftovers.len(), 1, "no temporary file may remain");
    }

    #[test]
    fn heartbeat_replaces_the_previous_one_and_takes_negative_codes() {
        let dir = tempfile::tempdir().unwrap();
        write_heartbeat(dir.path(), "demo", 0, 1).unwrap();
        let path = write_heartbeat(dir.path(), "demo", -1, 2).unwrap();
        assert_eq!(
            fs::read_to_string(path).unwrap(),
            "{\"ts\":2,\"exit_code\":-1}\n"
        );
    }

    #[test]
    fn names_that_could_leave_the_directory_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        for bad in ["", "../x", "a/b", "A", "x y", ".hidden", "a.b"] {
            assert!(matches!(
                write_heartbeat(dir.path(), bad, 0, 1),
                Err(HelperError::Invalid(_))
            ));
            assert!(matches!(
                try_lock(dir.path(), bad),
                Err(HelperError::Invalid(_))
            ));
            assert!(matches!(
                append_log(dir.path(), bad, "x\n", 5),
                Err(HelperError::Invalid(_))
            ));
        }
        assert!(!dir.path().join("agents").exists());
    }

    #[test]
    fn a_symlinked_heartbeat_target_is_not_followed_through_the_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let agents = dir.path().join("agents");
        fs::create_dir_all(&agents).unwrap();
        let victim = dir.path().join("victim");
        fs::write(&victim, "keep").unwrap();
        let temporary = agents.join(format!("demo.heartbeat.{}.tmp", std::process::id()));
        std::os::unix::fs::symlink(&victim, &temporary).unwrap();
        assert!(write_heartbeat(dir.path(), "demo", 0, 1).is_err());
        assert_eq!(fs::read_to_string(&victim).unwrap(), "keep");
    }

    #[test]
    fn the_lock_is_exclusive_until_released() {
        let dir = tempfile::tempdir().unwrap();
        let first = try_lock(dir.path(), "demo").unwrap();
        assert!(first.is_some());
        assert!(try_lock(dir.path(), "demo").unwrap().is_none());
        assert!(try_lock(dir.path(), "other").unwrap().is_some());
        drop(first);
        assert!(try_lock(dir.path(), "demo").unwrap().is_some());
    }

    #[test]
    fn the_lock_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let _held = try_lock(dir.path(), "demo").unwrap();
        let mode = fs::metadata(lock_path(dir.path(), "demo"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn log_lines_are_single_line_json() {
        let line = log_line("demo", LogLevel::Warn, "a\nb \"c\"", 5);
        assert!(line.ends_with('\n'));
        assert_eq!(line.matches('\n').count(), 1);
        let value = parse(&line);
        assert_eq!(value["ts"], 5);
        assert_eq!(value["agent"], "demo");
        assert_eq!(value["level"], "warn");
        assert_eq!(value["msg"], "a\nb \"c\"");
    }

    #[test]
    fn long_messages_are_cut() {
        let line = log_line("demo", LogLevel::Info, &"x".repeat(5000), 1);
        assert_eq!(
            parse(&line)["msg"].as_str().unwrap().len(),
            MAX_MESSAGE_CHARS
        );
    }

    #[test]
    fn the_log_keeps_only_the_last_lines() {
        let dir = tempfile::tempdir().unwrap();
        for n in 0..10 {
            append_log(dir.path(), "demo", &format!("{n}\n"), 4).unwrap();
        }
        let text = fs::read_to_string(log_path(dir.path(), "demo")).unwrap();
        assert_eq!(text, "6\n7\n8\n9\n");
    }

    #[test]
    fn a_log_under_the_limit_is_untouched() {
        let dir = tempfile::tempdir().unwrap();
        append_log(dir.path(), "demo", "a\n", 3).unwrap();
        append_log(dir.path(), "demo", "b\n", 3).unwrap();
        let text = fs::read_to_string(log_path(dir.path(), "demo")).unwrap();
        assert_eq!(text, "a\nb\n");
    }

    #[test]
    fn dry_run_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let heartbeat = AgentCommand::Heartbeat {
            name: "demo".into(),
            exit_code: 0,
            json: false,
        };
        let log = AgentCommand::Log {
            name: "demo".into(),
            level: LogLevel::Info,
            max_lines: 10,
            message: vec!["hello".into()],
            json: false,
        };
        assert_eq!(run_in(dir.path(), true, &heartbeat), EXIT_OK);
        assert_eq!(run_in(dir.path(), true, &log), EXIT_OK);
        assert!(!dir.path().join("agents").exists());
        assert!(!dir.path().join("logs").exists());
    }

    #[test]
    fn run_writes_heartbeat_and_log() {
        let dir = tempfile::tempdir().unwrap();
        let heartbeat = AgentCommand::Heartbeat {
            name: "demo".into(),
            exit_code: 7,
            json: false,
        };
        let log = AgentCommand::Log {
            name: "demo".into(),
            level: LogLevel::Error,
            max_lines: 10,
            message: vec!["disk".into(), "full".into()],
            json: false,
        };
        assert_eq!(run_in(dir.path(), false, &heartbeat), EXIT_OK);
        assert_eq!(run_in(dir.path(), false, &log), EXIT_OK);
        let beat = parse(&fs::read_to_string(heartbeat_path(dir.path(), "demo")).unwrap());
        assert_eq!(beat["exit_code"], 7);
        let line = parse(&fs::read_to_string(log_path(dir.path(), "demo")).unwrap());
        assert_eq!(line["msg"], "disk full");
        assert_eq!(line["level"], "error");
    }

    #[test]
    fn log_limits_are_validated() {
        let dir = tempfile::tempdir().unwrap();
        for bad in [0, MAX_LINES_LIMIT + 1] {
            let outcome = log_outcome(
                dir.path(),
                false,
                "demo",
                LogLevel::Info,
                bad,
                &["x".into()],
            );
            assert!(matches!(outcome, Err(HelperError::Invalid(_))));
        }
    }

    #[test]
    fn lock_needs_exactly_one_of_check_and_a_command() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            run_lock(dir.path(), "demo", false, 0, false, &[]),
            EXIT_INVALID
        );
        assert_eq!(
            run_lock(dir.path(), "demo", true, 0, false, &["true".into()]),
            EXIT_INVALID
        );
    }

    #[test]
    fn lock_check_reports_free_and_held() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(run_lock(dir.path(), "demo", true, 0, false, &[]), EXIT_OK);
        let _held = try_lock(dir.path(), "demo").unwrap();
        assert_eq!(run_lock(dir.path(), "demo", true, 0, false, &[]), EXIT_HELD);
    }

    #[test]
    fn a_held_lock_skips_the_command_with_the_configured_code() {
        let dir = tempfile::tempdir().unwrap();
        let _held = try_lock(dir.path(), "demo").unwrap();
        let command = vec!["definitely-not-run".to_owned()];
        assert_eq!(run_lock(dir.path(), "demo", false, 0, false, &command), 0);
        assert_eq!(run_lock(dir.path(), "demo", false, 9, false, &command), 9);
    }
}
