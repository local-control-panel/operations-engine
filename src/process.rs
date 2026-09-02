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
    use std::{thread, time::Duration};

    use super::{CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination, run};

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
}
