//! Phase 4, item 1 (of the current list): decide whether a requested
//! revision is one this site is actually allowed to deploy, without ever
//! cloning or touching a local working tree. A syntactically valid full
//! object ID (`GitCommitSha`) is not authorization by itself — per
//! `docs/site-model.md`, it becomes eligible only by being the current tip
//! of one of the site's registered allowed branches on its remote.

use std::{path::Path, time::Duration};

use crate::{
    process::{
        CancellationToken, ProcessLimits, ProcessRequest, ProcessRunError, ProcessTermination,
        SubprocessDiagnostics, run,
    },
    site::GitCommitSha,
};

const TIMEOUT: Duration = Duration::from_secs(20);
const MAX_OUTPUT_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub enum Error {
    /// `remote_url` starts with `-`, so `git` could parse it as a flag
    /// (e.g. `--upload-pack=<command>`) instead of the repository argument.
    /// Rejected before a subprocess is even started.
    InvalidRemoteUrl,
    Run(ProcessRunError),
    /// The query itself succeeded, but no allowed branch currently points
    /// at the requested revision.
    NotAuthorized,
    SubprocessFailed(SubprocessDiagnostics),
}

/// Resolves whether `revision` is the current tip of one of
/// `allowed_branches` on `remote_url`. One bounded `git ls-remote` call,
/// explicit argv only — no shell, no local clone, no working tree.
///
/// `identity_file`, when given, pins the SSH key for this one call via
/// `-c core.sshCommand=...` rather than the process environment or a shared
/// SSH config. The path must already be trusted and engine-derived (an
/// installed credential file resolved through the manifest's
/// `credentialId`) — never raw request input — because git itself
/// shell-interprets `core.sshCommand`'s value when it invokes `ssh`.
pub fn resolve_allowed_revision(
    remote_url: &str,
    allowed_branches: &[String],
    revision: &GitCommitSha,
    identity_file: Option<&Path>,
    cancellation: &CancellationToken,
) -> Result<(), Error> {
    if remote_url.starts_with('-') {
        return Err(Error::InvalidRemoteUrl);
    }

    let mut args: Vec<String> = Vec::new();
    if let Some(path) = identity_file {
        args.push("-c".to_owned());
        args.push(super::ssh_command_config(path));
    }
    args.push("ls-remote".to_owned());
    // `--` stops option parsing so a permitted-but-unusual URL (one
    // containing no leading `-` but still resembling a flag downstream)
    // can never be reinterpreted as one of git's own options.
    args.push("--".to_owned());
    args.push(remote_url.to_owned());
    args.extend(
        allowed_branches
            .iter()
            .map(|branch| format!("refs/heads/{branch}")),
    );

    let request = ProcessRequest::new("git").args(&args);
    let limits = ProcessLimits {
        timeout: TIMEOUT,
        max_stdout_bytes: MAX_OUTPUT_BYTES,
        max_stderr_bytes: MAX_OUTPUT_BYTES,
    };
    let output = run(&request, &limits, cancellation).map_err(Error::Run)?;

    if !matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        return Err(Error::SubprocessFailed(SubprocessDiagnostics::from_output(
            "git", &output,
        )));
    }

    let resolved = String::from_utf8_lossy(&output.stdout.bytes)
        .lines()
        .filter_map(|line| line.split('\t').next())
        .any(|sha| sha == revision.as_str());

    if resolved {
        Ok(())
    } else {
        Err(Error::NotAuthorized)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::process::Command;

    use super::{Error, resolve_allowed_revision};
    use crate::{process::CancellationToken, site::GitCommitSha};

    /// Creates a throwaway local repository with one commit and returns its
    /// path, current branch name, and HEAD SHA. `git ls-remote` supports a
    /// plain local path as the remote, so this exercises the real `git`
    /// binary without any network or SSH credential.
    fn local_remote() -> (tempfile::TempDir, String, GitCommitSha) {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let path = directory.path();
        let run = |args: &[&str]| {
            let status = Command::new("git")
                .arg("-C")
                .arg(path)
                .args(args)
                .status()
                .expect("git should run");
            assert!(status.success(), "git {args:?} should succeed");
        };

        run(&["init", "--quiet"]);
        run(&[
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "--allow-empty",
            "--quiet",
            "-m",
            "initial",
        ]);

        let branch = Command::new("git")
            .arg("-C")
            .arg(path)
            .args(["symbolic-ref", "--short", "HEAD"])
            .output()
            .expect("git symbolic-ref should run");
        let branch = String::from_utf8(branch.stdout)
            .expect("branch name should be UTF-8")
            .trim()
            .to_owned();

        let head = Command::new("git")
            .arg("-C")
            .arg(path)
            .args(["rev-parse", "HEAD"])
            .output()
            .expect("git rev-parse should run");
        let sha = String::from_utf8(head.stdout)
            .expect("HEAD SHA should be UTF-8")
            .trim()
            .to_owned();

        (
            directory,
            branch,
            GitCommitSha::parse(&sha).expect("HEAD SHA should be a valid object ID"),
        )
    }

    #[test]
    fn accepts_the_current_tip_of_an_allowed_branch() {
        let (directory, branch, head) = local_remote();
        let url = directory.path().to_str().expect("path should be UTF-8");

        resolve_allowed_revision(url, &[branch], &head, None, &CancellationToken::default())
            .expect("the branch tip should be authorized");
    }

    #[test]
    fn rejects_a_revision_no_allowed_branch_points_at() {
        let (directory, branch, _head) = local_remote();
        let url = directory.path().to_str().expect("path should be UTF-8");
        let unrelated = GitCommitSha::parse(&"a".repeat(40)).expect("test SHA should be valid");

        let outcome = resolve_allowed_revision(
            url,
            &[branch],
            &unrelated,
            None,
            &CancellationToken::default(),
        );
        assert!(matches!(outcome, Err(Error::NotAuthorized)));
    }

    #[test]
    fn rejects_the_tip_of_a_branch_that_is_not_allow_listed() {
        let (directory, _branch, head) = local_remote();
        let url = directory.path().to_str().expect("path should be UTF-8");

        let outcome = resolve_allowed_revision(
            url,
            &["some-other-branch".to_owned()],
            &head,
            None,
            &CancellationToken::default(),
        );
        assert!(matches!(outcome, Err(Error::NotAuthorized)));
    }

    #[test]
    fn a_nonexistent_remote_is_reported_as_a_subprocess_failure() {
        let head = GitCommitSha::parse(&"a".repeat(40)).expect("test SHA should be valid");
        let outcome = resolve_allowed_revision(
            "/nonexistent/definitely/not/a/repo",
            &["main".to_owned()],
            &head,
            None,
            &CancellationToken::default(),
        );
        assert!(matches!(outcome, Err(Error::SubprocessFailed(_))));
    }

    #[test]
    fn a_remote_url_starting_with_a_dash_is_rejected_before_any_subprocess_runs() {
        let head = GitCommitSha::parse(&"a".repeat(40)).expect("test SHA should be valid");
        let outcome = resolve_allowed_revision(
            "--upload-pack=touch /tmp/should-not-run",
            &["main".to_owned()],
            &head,
            None,
            &CancellationToken::default(),
        );
        assert!(matches!(outcome, Err(Error::InvalidRemoteUrl)));
    }
}
