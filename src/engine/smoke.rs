//! Proves that an `ops-engine` binary actually runs on this host, by
//! executing it and reading back the version it reports.
//!
//! Why an install needs this: `docs/site-model.md` states that the
//! automation user's sudo policy permits only the root-owned `ops-engine`
//! executable — not a shell, not filesystem utilities. So
//! `engine rollback`, which `docs/incident-recovery.md` names as the
//! first response to a bad upgrade, *is* the binary the upgrade just
//! installed. A binary that matches its signed checksum but cannot
//! execute here (the realistic case being a glibc mismatch against the
//! release runner's) would therefore take the host's only recovery path
//! down with it, leaving a verified, runnable previous binary sitting on
//! disk and unreachable. Running the staged copy *before* activating it
//! turns that into "install rejected, nothing changed".
//!
//! Shape mirrors `deploy::validate::validate_staged_release`: one
//! bounded, argv-only subprocess through `process::run` — no shell, no
//! environment passed deliberately, output capped and never echoed into a
//! protocol response.

use std::{path::Path, time::Duration};

use serde::Deserialize;

use crate::process::{
    CancellationToken, ProcessLimits, ProcessRequest, ProcessRunError, ProcessTermination,
    SubprocessDiagnostics, run,
};

/// A `version` call does no I/O beyond writing one line, so this bound
/// only ever fires on a binary that hangs rather than one that is merely
/// slow.
const TIMEOUT: Duration = Duration::from_secs(30);
const MAX_OUTPUT_BYTES: usize = 64 * 1024;

/// The subcommand every `ops-engine` build answers with its own version
/// and no side effects whatsoever (`commands::version::run`).
const VERSION_ARGUMENT: &str = "version";

#[derive(Debug)]
pub enum Error {
    /// The runner could not start or supervise the child at all. A
    /// `ProcessRunError::Spawn` here is the "won't execute on this host"
    /// case (`ENOEXEC`, a missing interpreter or loader); the rest are
    /// internal.
    Run(ProcessRunError),
    /// It started but did not exit successfully — including the runner's
    /// own timeout termination. Distinct from `Cancelled`: this is a
    /// property of the binary (or host), not of the caller having asked
    /// to stop.
    NotRunnable(SubprocessDiagnostics),
    /// It ran and exited successfully but did not print a version
    /// envelope this engine can read.
    UnreadableVersion(SubprocessDiagnostics),
    /// The probe was cancelled before the binary finished - this says
    /// nothing about whether the binary itself would have run
    /// successfully, so it must not be reported the same way as
    /// `NotRunnable`.
    Cancelled,
}

/// Every caller of this module hands it a binary that was just written and
/// renamed into place a moment ago (`install`'s freshly staged copy,
/// `rollback`'s restored previous one) - immediately executing that can
/// transiently fail with `ExecutableFileBusy` on Linux, the kernel briefly
/// still treating the inode as open for writing right after the rename that
/// created it. Observed in practice (CI, `installing_the_same_version_
/// twice_is_rejected_as_already_active`), not hypothetical.
///
/// ponytail: a fixed bounded retry against this one specific, well-known
/// transient race, not a general "retry any spawn failure" policy - raise
/// `BUSY_RETRY_ATTEMPTS` only if this exact error is ever seen to outlast
/// it.
const BUSY_RETRY_ATTEMPTS: u32 = 5;
const BUSY_RETRY_DELAY: Duration = Duration::from_millis(20);

fn run_tolerating_transient_busy(
    request: &ProcessRequest,
    limits: &ProcessLimits,
    cancellation: &CancellationToken,
) -> Result<crate::process::ProcessOutput, ProcessRunError> {
    for attempt in 1..=BUSY_RETRY_ATTEMPTS {
        match run(request, limits, cancellation) {
            Err(ProcessRunError::Spawn(io_error))
                if attempt < BUSY_RETRY_ATTEMPTS
                    && io_error.kind() == std::io::ErrorKind::ExecutableFileBusy =>
            {
                std::thread::sleep(BUSY_RETRY_DELAY);
            }
            other => return other,
        }
    }
    unreachable!("the loop above always returns by the last attempt")
}

/// Runs `<binary> version` and returns the engine version it reports.
pub fn probe_version(binary: &Path, cancellation: &CancellationToken) -> Result<String, Error> {
    let limits = ProcessLimits {
        timeout: TIMEOUT,
        max_stdout_bytes: MAX_OUTPUT_BYTES,
        max_stderr_bytes: MAX_OUTPUT_BYTES,
    };
    let request = ProcessRequest::new(binary).args([VERSION_ARGUMENT]);
    let output =
        run_tolerating_transient_busy(&request, &limits, cancellation).map_err(Error::Run)?;

    if matches!(output.termination, ProcessTermination::Cancelled) {
        return Err(Error::Cancelled);
    }
    if !matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        return Err(Error::NotRunnable(SubprocessDiagnostics::from_output(
            "ops-engine",
            &output,
        )));
    }

    parse_reported_version(&output.stdout.bytes).ok_or_else(|| {
        Error::UnreadableVersion(SubprocessDiagnostics::from_output("ops-engine", &output))
    })
}

/// The subset of the `version` response envelope this check depends on.
/// Deliberately structural rather than a substring search: a binary that
/// prints something version-shaped on its way to failing does not pass.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VersionEnvelope {
    operation: String,
    ok: bool,
    result: Option<VersionResult>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VersionResult {
    engine_version: String,
}

fn parse_reported_version(stdout: &[u8]) -> Option<String> {
    let envelope: VersionEnvelope = serde_json::from_slice(stdout).ok()?;
    if !envelope.ok || envelope.operation != VERSION_ARGUMENT {
        return None;
    }
    let version = envelope.result?.engine_version;
    (!version.is_empty()).then_some(version)
}

#[cfg(test)]
mod tests {
    use super::{Error, parse_reported_version, probe_version};
    use crate::process::CancellationToken;

    #[test]
    fn reads_the_version_out_of_a_real_response_envelope() {
        let stdout = br#"{"protocolVersion":1,"operation":"version","ok":true,"result":{"engineVersion":"0.5.0","protocolVersion":1,"build":{"targetOs":"linux","targetArchitecture":"x86_64","gitCommit":null}},"warnings":[],"error":null}"#;
        assert_eq!(parse_reported_version(stdout), Some("0.5.0".to_owned()));
    }

    #[test]
    fn rejects_output_that_is_not_a_successful_version_envelope() {
        assert_eq!(parse_reported_version(b"0.5.0"), None);
        assert_eq!(parse_reported_version(b""), None);
        assert_eq!(
            parse_reported_version(
                br#"{"operation":"version","ok":false,"result":{"engineVersion":"0.5.0"}}"#
            ),
            None
        );
        assert_eq!(
            parse_reported_version(
                br#"{"operation":"doctor","ok":true,"result":{"engineVersion":"0.5.0"}}"#
            ),
            None
        );
        assert_eq!(
            parse_reported_version(br#"{"operation":"version","ok":true,"result":null}"#),
            None
        );
        assert_eq!(
            parse_reported_version(
                br#"{"operation":"version","ok":true,"result":{"engineVersion":""}}"#
            ),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_binary_that_cannot_execute_is_reported_as_not_runnable() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let path = directory.path().join("ops-engine");
        std::fs::write(&path, b"\x7fELF not really an executable for this host")
            .expect("stand-in should be written");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("stand-in should be executable");

        let outcome = probe_version(&path, &CancellationToken::default());
        assert!(
            matches!(outcome, Err(Error::Run(_)) | Err(Error::NotRunnable(_))),
            "a file that is not a runnable program must not pass the smoke test"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_binary_that_runs_but_answers_with_nothing_useful_is_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let path = directory.path().join("ops-engine");
        std::fs::write(&path, "#!/bin/sh\necho 'not a protocol envelope'\n")
            .expect("stand-in should be written");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("stand-in should be executable");

        let outcome = probe_version(&path, &CancellationToken::default());
        assert!(matches!(outcome, Err(Error::UnreadableVersion(_))));
    }

    #[cfg(unix)]
    #[test]
    fn a_pre_cancelled_probe_reports_cancelled_not_not_runnable() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let path = directory.path().join("ops-engine");
        std::fs::write(
            &path,
            "#!/bin/sh\nprintf '%s\\n' '{\"protocolVersion\":1,\"operation\":\"version\",\"ok\":true,\"result\":{\"engineVersion\":\"9.9.8\"},\"warnings\":[],\"error\":null}'\n",
        )
        .expect("stand-in should be written");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("stand-in should be executable");

        // Cancelled before the probe even starts its supervise loop - the
        // runner's own cancellation check runs before its exit-status
        // check on every iteration (`process::spawn_and_supervise`), so
        // this is deterministic, not a timing race. A perfectly runnable
        // binary must still be reported as cancelled, not as an artifact
        // rejection - the two mean different things to a caller deciding
        // whether to retry with a different version or just retry.
        let cancellation = CancellationToken::default();
        cancellation.cancel();

        let outcome = probe_version(&path, &cancellation);
        assert!(
            matches!(outcome, Err(Error::Cancelled)),
            "expected Cancelled, got {outcome:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_binary_that_answers_correctly_reports_its_version() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let path = directory.path().join("ops-engine");
        std::fs::write(
            &path,
            "#!/bin/sh\nprintf '%s\\n' '{\"protocolVersion\":1,\"operation\":\"version\",\"ok\":true,\"result\":{\"engineVersion\":\"9.9.8\"},\"warnings\":[],\"error\":null}'\n",
        )
        .expect("stand-in should be written");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("stand-in should be executable");

        assert_eq!(
            probe_version(&path, &CancellationToken::default()).expect("probe should succeed"),
            "9.9.8"
        );
    }
}
