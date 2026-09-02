use std::{
    ffi::{OsStr, OsString},
    io::{self, Read},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use serde::Serialize;

use crate::error::ErrorCode;

#[derive(Clone, Debug, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Clone, Debug)]
pub struct ProcessLimits {
    pub timeout: Duration,
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
}

impl Default for ProcessLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_stdout_bytes: 64 * 1024,
            max_stderr_bytes: 64 * 1024,
        }
    }
}

#[derive(Debug)]
pub struct ProcessRequest {
    program: OsString,
    args: Vec<OsString>,
}

impl ProcessRequest {
    pub fn new(program: impl AsRef<OsStr>) -> Self {
        Self {
            program: program.as_ref().to_owned(),
            args: Vec::new(),
        }
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args
            .extend(args.into_iter().map(|arg| arg.as_ref().to_owned()));
        self
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ProcessTermination {
    Exited { code: Option<i32>, success: bool },
    TimedOut,
    Cancelled,
}

#[derive(Debug)]
pub struct CapturedOutput {
    pub bytes: Vec<u8>,
    pub truncated: bool,
}

#[derive(Debug)]
pub struct ProcessOutput {
    pub termination: ProcessTermination,
    pub stdout: CapturedOutput,
    pub stderr: CapturedOutput,
}

#[derive(Debug)]
pub enum ProcessRunError {
    Spawn(io::Error),
    MissingPipe(&'static str),
    Wait(io::Error),
    Capture(io::Error),
    CaptureThreadPanicked,
}

/// Maps a completed run to the stable protocol code documented in
/// `docs/subprocess.md`, or `None` for a successful exit.
pub fn error_code(termination: &ProcessTermination) -> Option<ErrorCode> {
    match termination {
        ProcessTermination::Exited { success: true, .. } => None,
        ProcessTermination::Exited { success: false, .. } => Some(ErrorCode::SubprocessFailed),
        ProcessTermination::TimedOut => Some(ErrorCode::Timeout),
        ProcessTermination::Cancelled => Some(ErrorCode::Cancelled),
    }
}

/// Maps a failure to start or supervise the child to the stable protocol
/// code documented in `docs/subprocess.md`. A missing executable is a
/// dependency-availability problem; every other runner failure is internal.
pub fn spawn_error_code(error: &ProcessRunError) -> ErrorCode {
    match error {
        ProcessRunError::Spawn(_) => ErrorCode::DependencyUnavailable,
        ProcessRunError::MissingPipe(_)
        | ProcessRunError::Wait(_)
        | ProcessRunError::Capture(_)
        | ProcessRunError::CaptureThreadPanicked => ErrorCode::Internal,
    }
}

/// A protocol-safe summary of a subprocess outcome for use as `SUBPROCESS_FAILED`
/// error `details`. It is built only from the program name and the runner's own
/// termination/truncation bookkeeping, never from captured stdout/stderr bytes,
/// the full argument list, or environment — so it cannot carry secrets or
/// command lines regardless of what the child was told to do.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubprocessDiagnostics {
    pub program: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub cancelled: bool,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

impl SubprocessDiagnostics {
    pub fn from_output(program: impl Into<String>, output: &ProcessOutput) -> Self {
        let (exit_code, timed_out, cancelled) = match output.termination {
            ProcessTermination::Exited { code, .. } => (code, false, false),
            ProcessTermination::TimedOut => (None, true, false),
            ProcessTermination::Cancelled => (None, false, true),
        };
        Self {
            program: program.into(),
            exit_code,
            timed_out,
            cancelled,
            stdout_truncated: output.stdout.truncated,
            stderr_truncated: output.stderr.truncated,
        }
    }
}

pub fn run(
    request: &ProcessRequest,
    limits: &ProcessLimits,
    cancellation: &CancellationToken,
) -> Result<ProcessOutput, ProcessRunError> {
    let mut child = Command::new(&request.program)
        .args(&request.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(ProcessRunError::Spawn)?;

    let stdout = child
        .stdout
        .take()
        .ok_or(ProcessRunError::MissingPipe("stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or(ProcessRunError::MissingPipe("stderr"))?;
    let stdout_limit = limits.max_stdout_bytes;
    let stderr_limit = limits.max_stderr_bytes;
    let stdout_thread = thread::spawn(move || capture(stdout, stdout_limit));
    let stderr_thread = thread::spawn(move || capture(stderr, stderr_limit));

    let started = Instant::now();
    let termination = loop {
        if cancellation.is_cancelled() {
            child.kill().map_err(ProcessRunError::Wait)?;
            child.wait().map_err(ProcessRunError::Wait)?;
            break ProcessTermination::Cancelled;
        }

        if started.elapsed() >= limits.timeout {
            child.kill().map_err(ProcessRunError::Wait)?;
            child.wait().map_err(ProcessRunError::Wait)?;
            break ProcessTermination::TimedOut;
        }

        if let Some(status) = child.try_wait().map_err(ProcessRunError::Wait)? {
            break ProcessTermination::Exited {
                code: status.code(),
                success: status.success(),
            };
        }

        thread::sleep(Duration::from_millis(10));
    };

    let stdout = join_capture(stdout_thread)?;
    let stderr = join_capture(stderr_thread)?;

    Ok(ProcessOutput {
        termination,
        stdout,
        stderr,
    })
}

fn capture(mut reader: impl Read, limit: usize) -> io::Result<CapturedOutput> {
    let mut bytes = Vec::with_capacity(limit.min(8 * 1024));
    let mut truncated = false;
    let mut chunk = [0_u8; 8 * 1024];

    loop {
        let count = reader.read(&mut chunk)?;
        if count == 0 {
            break;
        }

        let remaining = limit.saturating_sub(bytes.len());
        let retained = remaining.min(count);
        bytes.extend_from_slice(&chunk[..retained]);
        truncated |= retained < count;
    }

    Ok(CapturedOutput { bytes, truncated })
}

fn join_capture(
    handle: thread::JoinHandle<io::Result<CapturedOutput>>,
) -> Result<CapturedOutput, ProcessRunError> {
    handle
        .join()
        .map_err(|_| ProcessRunError::CaptureThreadPanicked)?
        .map_err(ProcessRunError::Capture)
}

#[cfg(all(test, unix))]
mod tests {
    use std::{io, thread, time::Duration};

    use super::{
        CancellationToken, CapturedOutput, ProcessLimits, ProcessOutput, ProcessRequest,
        ProcessRunError, ProcessTermination, SubprocessDiagnostics, error_code, run,
        spawn_error_code,
    };
    use crate::error::ErrorCode;

    #[test]
    fn bounds_captured_output() {
        let output = run(
            &ProcessRequest::new("printf").args(["123456789"]),
            &ProcessLimits {
                timeout: Duration::from_secs(1),
                max_stdout_bytes: 4,
                max_stderr_bytes: 4,
            },
            &CancellationToken::default(),
        )
        .expect("process should run");

        assert_eq!(output.stdout.bytes, b"1234");
        assert!(output.stdout.truncated);
    }

    #[test]
    fn terminates_after_timeout() {
        let output = run(
            &ProcessRequest::new("sleep").args(["5"]),
            &ProcessLimits {
                timeout: Duration::from_millis(20),
                ..ProcessLimits::default()
            },
            &CancellationToken::default(),
        )
        .expect("process should run");

        assert_eq!(output.termination, ProcessTermination::TimedOut);
    }

    #[test]
    fn terminates_after_cancellation() {
        let cancellation = CancellationToken::default();
        let trigger = cancellation.clone();
        let cancellation_thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            trigger.cancel();
        });

        let output = run(
            &ProcessRequest::new("sleep").args(["5"]),
            &ProcessLimits::default(),
            &cancellation,
        )
        .expect("process should run");
        cancellation_thread.join().expect("thread should finish");

        assert_eq!(output.termination, ProcessTermination::Cancelled);
    }

    #[test]
    fn error_code_maps_each_termination_to_its_stable_code() {
        assert_eq!(
            error_code(&ProcessTermination::Exited {
                code: Some(0),
                success: true
            }),
            None
        );
        assert_eq!(
            error_code(&ProcessTermination::Exited {
                code: Some(1),
                success: false
            }),
            Some(ErrorCode::SubprocessFailed)
        );
        assert_eq!(
            error_code(&ProcessTermination::TimedOut),
            Some(ErrorCode::Timeout)
        );
        assert_eq!(
            error_code(&ProcessTermination::Cancelled),
            Some(ErrorCode::Cancelled)
        );
    }

    #[test]
    fn spawn_error_code_distinguishes_missing_executable_from_internal_failure() {
        assert_eq!(
            spawn_error_code(&ProcessRunError::Spawn(io::Error::from(
                io::ErrorKind::NotFound
            ))),
            ErrorCode::DependencyUnavailable
        );
        assert_eq!(
            spawn_error_code(&ProcessRunError::Wait(io::Error::other("boom"))),
            ErrorCode::Internal
        );
        assert_eq!(
            spawn_error_code(&ProcessRunError::CaptureThreadPanicked),
            ErrorCode::Internal
        );
    }

    #[test]
    fn diagnostics_never_carry_captured_output_bytes() {
        let output = ProcessOutput {
            termination: ProcessTermination::Exited {
                code: Some(1),
                success: false,
            },
            stdout: CapturedOutput {
                bytes: b"leaked-token=super-secret".to_vec(),
                truncated: false,
            },
            stderr: CapturedOutput {
                bytes: b"fatal: authentication failed for secret-repo".to_vec(),
                truncated: true,
            },
        };

        let diagnostics = SubprocessDiagnostics::from_output("git", &output);
        let json = serde_json::to_string(&diagnostics).expect("diagnostics should serialize");

        assert!(!json.contains("secret"));
        assert!(!json.contains("token"));
        assert_eq!(diagnostics.program, "git");
        assert_eq!(diagnostics.exit_code, Some(1));
        assert!(!diagnostics.stdout_truncated);
        assert!(diagnostics.stderr_truncated);
    }

    #[test]
    fn diagnostics_report_timeout_and_cancellation_as_flags_not_a_code() {
        let timed_out = ProcessOutput {
            termination: ProcessTermination::TimedOut,
            stdout: CapturedOutput {
                bytes: Vec::new(),
                truncated: false,
            },
            stderr: CapturedOutput {
                bytes: Vec::new(),
                truncated: false,
            },
        };
        let diagnostics = SubprocessDiagnostics::from_output("git", &timed_out);
        assert!(diagnostics.timed_out);
        assert!(!diagnostics.cancelled);
        assert_eq!(diagnostics.exit_code, None);
    }
}
