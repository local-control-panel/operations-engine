//! Phase 4, item 1 (of the current list): bounded validation of a staged
//! release before it is eligible for the atomic switch. Scoped to what is
//! genuinely generic across every Git deploy — repository integrity and a
//! clean checkout — not site- or framework-specific build/test steps,
//! which are out of scope for this pilot (see README's "Scope").

use std::{path::Path, time::Duration};

use crate::{
    deploy::SiteIdentity,
    process::{
        CancellationToken, ProcessLimits, ProcessOutput, ProcessRequest, ProcessRunError,
        ProcessTermination, SubprocessDiagnostics, run,
    },
};

const TIMEOUT: Duration = Duration::from_secs(60);
const MAX_OUTPUT_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub enum Error {
    Run(ProcessRunError),
    /// `git fsck` reported a corrupt or incomplete object database.
    Corrupt(SubprocessDiagnostics),
    /// The working tree does not exactly match `HEAD` immediately after a
    /// fresh clone — an unexpected local modification, or a filesystem
    /// problem during checkout.
    DirtyWorkingTree(SubprocessDiagnostics),
}

/// Runs bounded, Git-generic integrity checks against a release staging
/// already produced. Both checks run as the site's own identity, matching
/// every other subprocess this engine runs against a site-owned directory.
pub fn validate_staged_release(
    release_path: &Path,
    identity: SiteIdentity,
    cancellation: &CancellationToken,
) -> Result<(), Error> {
    run_check(
        release_path,
        identity,
        &["fsck", "--no-progress", "--no-dangling"],
        cancellation,
        Error::Corrupt,
    )?;

    let status = run_git(
        release_path,
        identity,
        &["status", "--porcelain"],
        cancellation,
    )
    .map_err(Error::Run)?;
    if !matches!(
        status.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        return Err(Error::DirtyWorkingTree(SubprocessDiagnostics::from_output(
            "git", &status,
        )));
    }
    if !status.stdout.bytes.is_empty() {
        return Err(Error::DirtyWorkingTree(SubprocessDiagnostics::from_output(
            "git", &status,
        )));
    }

    Ok(())
}

fn run_check(
    release_path: &Path,
    identity: SiteIdentity,
    args: &[&str],
    cancellation: &CancellationToken,
    on_failure: fn(SubprocessDiagnostics) -> Error,
) -> Result<(), Error> {
    let output = run_git(release_path, identity, args, cancellation).map_err(Error::Run)?;
    if matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        Ok(())
    } else {
        Err(on_failure(SubprocessDiagnostics::from_output(
            "git", &output,
        )))
    }
}

fn run_git(
    release_path: &Path,
    identity: SiteIdentity,
    args: &[&str],
    cancellation: &CancellationToken,
) -> Result<ProcessOutput, ProcessRunError> {
    let limits = ProcessLimits {
        timeout: TIMEOUT,
        max_stdout_bytes: MAX_OUTPUT_BYTES,
        max_stderr_bytes: MAX_OUTPUT_BYTES,
    };
    let request = ProcessRequest::new("git")
        .args(["-C", &release_path.to_string_lossy()])
        .args(args)
        .run_as(identity.uid, identity.gid);
    run(&request, &limits, cancellation)
}

#[cfg(all(test, unix))]
mod tests {
    use std::process::Command;

    use super::{Error, validate_staged_release};
    use crate::{deploy::staging::resolve_site_identity, process::CancellationToken};

    fn own_identity() -> crate::deploy::SiteIdentity {
        let whoami = Command::new("whoami").output().expect("whoami should run");
        let user = String::from_utf8(whoami.stdout)
            .expect("username should be UTF-8")
            .trim()
            .to_owned();
        resolve_site_identity(&user, &CancellationToken::default())
            .expect("resolving one's own identity should succeed")
    }

    fn cloned_checkout() -> tempfile::TempDir {
        let remote = tempfile::tempdir().expect("remote directory should exist");
        let run = |args: &[&str], dir: &std::path::Path| {
            let status = Command::new("git")
                .arg("-C")
                .arg(dir)
                .args(args)
                .status()
                .expect("git should run");
            assert!(status.success(), "git {args:?} should succeed");
        };
        run(&["init", "--quiet"], remote.path());
        run(
            &[
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "--allow-empty",
                "--quiet",
                "-m",
                "initial",
            ],
            remote.path(),
        );

        let checkout = tempfile::tempdir().expect("checkout directory should exist");
        let status = Command::new("git")
            .args([
                "clone",
                "--quiet",
                remote.path().to_str().expect("path should be UTF-8"),
            ])
            .arg(checkout.path())
            .status()
            .expect("git clone should run");
        assert!(status.success());

        checkout
    }

    #[test]
    fn accepts_a_clean_freshly_cloned_checkout() {
        let checkout = cloned_checkout();
        validate_staged_release(
            checkout.path(),
            own_identity(),
            &CancellationToken::default(),
        )
        .expect("a clean checkout should validate");
    }

    #[test]
    fn rejects_a_working_tree_with_unexpected_local_changes() {
        let checkout = cloned_checkout();
        std::fs::write(checkout.path().join("untracked-file"), "surprise")
            .expect("untracked file should be written");

        let outcome = validate_staged_release(
            checkout.path(),
            own_identity(),
            &CancellationToken::default(),
        );
        assert!(matches!(outcome, Err(Error::DirtyWorkingTree(_))));
    }

    #[test]
    fn rejects_a_directory_that_is_not_a_git_repository_at_all() {
        let not_a_repo = tempfile::tempdir().expect("directory should exist");
        let outcome = validate_staged_release(
            not_a_repo.path(),
            own_identity(),
            &CancellationToken::default(),
        );
        assert!(outcome.is_err());
    }
}
