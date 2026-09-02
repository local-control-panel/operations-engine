//! Phase 4, item 2 (of the current list): prepare an isolated staging
//! release. Unlike `resolve` (a pure read against the remote), this item
//! writes real content into a site-owned directory, so the site's own
//! Unix identity — never the engine's own privilege level — must own that
//! write from the moment the directory exists.

use std::{
    io,
    path::{Path, PathBuf},
    time::Duration,
};

use crate::{
    deploy::ReleaseId,
    filesystem::ManagedRoot,
    process::{
        CancellationToken, ProcessLimits, ProcessRequest, ProcessRunError, ProcessTermination,
        SubprocessDiagnostics, run,
    },
    site::{GitCommitSha, SiteId, SiteRelativePath, TrustedRoot},
};

const ID_TIMEOUT: Duration = Duration::from_secs(5);
const ID_MAX_OUTPUT_BYTES: usize = 1024;
const CLONE_TIMEOUT: Duration = Duration::from_secs(300);
const CLONE_MAX_OUTPUT_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct SiteIdentity {
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug)]
pub enum IdentityError {
    Run(ProcessRunError),
    Lookup(SubprocessDiagnostics),
    Parse,
}

/// Resolves `site_user` to its numeric identity via `id -u`/`id -g` — never
/// a raw FFI/NSS lookup — so it follows the same bounded, argv-only
/// subprocess discipline as every other external program this engine runs.
/// `site_user` must already be validated (`config::validate_site_user`,
/// which forbids a leading `-`) since it becomes a positional argument; a
/// `--` separator is still added as defense in depth.
pub fn resolve_site_identity(
    site_user: &str,
    cancellation: &CancellationToken,
) -> Result<SiteIdentity, IdentityError> {
    Ok(SiteIdentity {
        uid: run_id("-u", site_user, cancellation)?,
        gid: run_id("-g", site_user, cancellation)?,
    })
}

fn run_id(
    flag: &str,
    site_user: &str,
    cancellation: &CancellationToken,
) -> Result<u32, IdentityError> {
    let limits = ProcessLimits {
        timeout: ID_TIMEOUT,
        max_stdout_bytes: ID_MAX_OUTPUT_BYTES,
        max_stderr_bytes: ID_MAX_OUTPUT_BYTES,
    };
    let request = ProcessRequest::new("id").args([flag, "--", site_user]);
    let output = run(&request, &limits, cancellation).map_err(IdentityError::Run)?;

    if !matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        return Err(IdentityError::Lookup(SubprocessDiagnostics::from_output(
            "id", &output,
        )));
    }

    String::from_utf8_lossy(&output.stdout.bytes)
        .trim()
        .parse()
        .map_err(|_| IdentityError::Parse)
}

#[derive(Debug)]
pub enum Error {
    InvalidRemoteUrl,
    Io(io::Error),
    AlreadyExists,
    Ownership(io::Error),
    Clone(ProcessRunError),
    CloneFailed(SubprocessDiagnostics),
    /// The clone succeeded, but its checked-out HEAD is not `revision` —
    /// the remote branch moved between `resolve::resolve_allowed_revision`
    /// and this call. The staged directory is left in place for the
    /// caller to remove; nothing here silently deploys the wrong commit.
    RevisionMismatch,
    Verify(ProcessRunError),
}

pub struct StagedRelease {
    pub release_id: ReleaseId,
    /// Path to `releases/<releaseId>`, relative to `content_root`.
    pub relative_path: SiteRelativePath,
}

/// Clones `branch` from `remote_url` into a brand-new, exclusively-created
/// `sites/<siteId>/releases/<releaseId>/` directory beneath `content_root`,
/// chowned to `identity` before `git` itself runs as that uid/gid — so a
/// compromised or malicious repository can write only where the site's own
/// user already could, never at the engine's own privilege level.
#[allow(clippy::too_many_arguments)]
pub fn prepare(
    content_root: &TrustedRoot,
    site_id: SiteId,
    release_id: ReleaseId,
    identity: SiteIdentity,
    remote_url: &str,
    branch: &str,
    revision: &GitCommitSha,
    identity_file: Option<&Path>,
    cancellation: &CancellationToken,
) -> Result<StagedRelease, Error> {
    if remote_url.starts_with('-') {
        return Err(Error::InvalidRemoteUrl);
    }

    let managed = ManagedRoot::open(content_root).map_err(Error::Io)?;
    let releases_dir = SiteRelativePath::parse(format!("sites/{site_id}/releases"))
        .expect("a canonical SiteId always yields a valid relative path");
    managed.create_dir_all(&releases_dir).map_err(Error::Io)?;

    let release_relative =
        SiteRelativePath::parse(format!("sites/{site_id}/releases/{release_id}"))
            .expect("a canonical SiteId and ReleaseId always yield a valid relative path");
    managed.create_dir(&release_relative).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            Error::AlreadyExists
        } else {
            Error::Io(error)
        }
    })?;

    // Re-resolved and containment-checked through the already-audited
    // `TrustedRoot::resolve_existing` rather than a bare string join, even
    // though we just created this exact directory ourselves.
    let release_absolute: PathBuf = content_root
        .resolve_existing(&release_relative)
        .map_err(|_| Error::Io(io::Error::other("release path escaped content root")))?;

    std::os::unix::fs::chown(&release_absolute, Some(identity.uid), Some(identity.gid))
        .map_err(Error::Ownership)?;

    clone_as(
        &release_absolute,
        identity,
        remote_url,
        branch,
        identity_file,
        cancellation,
    )?;
    verify_head(&release_absolute, identity, revision, cancellation)?;

    Ok(StagedRelease {
        release_id,
        relative_path: release_relative,
    })
}

fn clone_as(
    target: &Path,
    identity: SiteIdentity,
    remote_url: &str,
    branch: &str,
    identity_file: Option<&Path>,
    cancellation: &CancellationToken,
) -> Result<(), Error> {
    let mut args: Vec<String> = Vec::new();
    if let Some(path) = identity_file {
        args.push("-c".to_owned());
        args.push(super::ssh_command_config(path));
    }
    args.push("clone".to_owned());
    args.push("--branch".to_owned());
    args.push(branch.to_owned());
    args.push("--single-branch".to_owned());
    args.push("--".to_owned());
    args.push(remote_url.to_owned());
    args.push(target.to_string_lossy().into_owned());

    let limits = ProcessLimits {
        timeout: CLONE_TIMEOUT,
        max_stdout_bytes: CLONE_MAX_OUTPUT_BYTES,
        max_stderr_bytes: CLONE_MAX_OUTPUT_BYTES,
    };
    let request = ProcessRequest::new("git")
        .args(&args)
        .run_as(identity.uid, identity.gid);
    let output = run(&request, &limits, cancellation).map_err(Error::Clone)?;

    if matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        Ok(())
    } else {
        Err(Error::CloneFailed(SubprocessDiagnostics::from_output(
            "git", &output,
        )))
    }
}

fn verify_head(
    target: &Path,
    identity: SiteIdentity,
    revision: &GitCommitSha,
    cancellation: &CancellationToken,
) -> Result<(), Error> {
    let limits = ProcessLimits {
        timeout: ID_TIMEOUT,
        max_stdout_bytes: ID_MAX_OUTPUT_BYTES,
        max_stderr_bytes: ID_MAX_OUTPUT_BYTES,
    };
    let request = ProcessRequest::new("git")
        .args(["-C", &target.to_string_lossy(), "rev-parse", "HEAD"])
        .run_as(identity.uid, identity.gid);
    let output = run(&request, &limits, cancellation).map_err(Error::Verify)?;

    let head = String::from_utf8_lossy(&output.stdout.bytes)
        .trim()
        .to_owned();
    if head == revision.as_str() {
        Ok(())
    } else {
        Err(Error::RevisionMismatch)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::process::Command;

    use super::{Error, StagedRelease, prepare, resolve_site_identity};
    use crate::{
        deploy::ReleaseId,
        process::CancellationToken,
        site::{GitCommitSha, SiteId, TrustedRoot},
        transaction::RequestId,
    };

    const SITE_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
    const REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174000";

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

    /// The environment this runs in has no root and cannot create a second
    /// real Unix user, so these tests resolve and use the *current* user's
    /// own identity end to end (chown-to-self and `Command::uid`/`gid`
    /// set to one's own ids are always permitted, unlike a genuine
    /// cross-user drop). That exercises every mechanism for real — identity
    /// resolution, exclusive directory creation, chown, a privilege-scoped
    /// `git clone`, and HEAD verification — except the one thing only root
    /// can prove: that a *different* uid/gid is actually enforced. See the
    /// PLAN.md note for this item.
    fn own_identity() -> super::SiteIdentity {
        let whoami = Command::new("whoami").output().expect("whoami should run");
        let user = String::from_utf8(whoami.stdout)
            .expect("username should be UTF-8")
            .trim()
            .to_owned();
        resolve_site_identity(&user, &CancellationToken::default())
            .expect("resolving one's own identity should succeed")
    }

    #[test]
    fn resolves_the_current_users_own_identity() {
        let identity = own_identity();
        assert!(
            identity.uid > 0 || identity.gid > 0,
            "expected a real uid/gid, got {identity:?}"
        );
    }

    #[test]
    fn stages_a_real_clone_owned_by_the_resolved_identity_and_verifies_head() {
        let (remote_dir, branch, head) = local_remote();
        let remote_url = remote_dir.path().to_str().expect("path should be UTF-8");
        let content_dir = tempfile::tempdir().expect("content root should exist");
        let content_root =
            TrustedRoot::parse(content_dir.path()).expect("content root should be valid");
        let site_id = SiteId::parse(SITE_ID).expect("site id should be canonical");
        let release_id =
            ReleaseId::from(RequestId::parse(REQUEST_ID).expect("request id should be canonical"));
        let identity = own_identity();

        let StagedRelease {
            release_id: staged_release_id,
            relative_path,
        } = prepare(
            &content_root,
            site_id,
            release_id,
            identity,
            remote_url,
            &branch,
            &head,
            None,
            &CancellationToken::default(),
        )
        .expect("staging should succeed");

        assert_eq!(staged_release_id, release_id);
        assert_eq!(
            relative_path.as_path(),
            std::path::Path::new(&format!("sites/{SITE_ID}/releases/{REQUEST_ID}"))
        );
        assert!(
            content_dir
                .path()
                .join(format!("sites/{SITE_ID}/releases/{REQUEST_ID}/.git"))
                .exists()
        );
    }

    #[test]
    fn refuses_to_stage_into_an_already_existing_release_directory() {
        let (remote_dir, branch, head) = local_remote();
        let remote_url = remote_dir.path().to_str().expect("path should be UTF-8");
        let content_dir = tempfile::tempdir().expect("content root should exist");
        let content_root =
            TrustedRoot::parse(content_dir.path()).expect("content root should be valid");
        let site_id = SiteId::parse(SITE_ID).expect("site id should be canonical");
        let release_id =
            ReleaseId::from(RequestId::parse(REQUEST_ID).expect("request id should be canonical"));
        let identity = own_identity();

        prepare(
            &content_root,
            site_id,
            release_id,
            identity,
            remote_url,
            &branch,
            &head,
            None,
            &CancellationToken::default(),
        )
        .expect("first staging attempt should succeed");

        let outcome = prepare(
            &content_root,
            site_id,
            release_id,
            identity,
            remote_url,
            &branch,
            &head,
            None,
            &CancellationToken::default(),
        );
        assert!(matches!(outcome, Err(Error::AlreadyExists)));
    }

    #[test]
    fn a_remote_url_starting_with_a_dash_is_rejected_before_any_subprocess_runs() {
        let content_dir = tempfile::tempdir().expect("content root should exist");
        let content_root =
            TrustedRoot::parse(content_dir.path()).expect("content root should be valid");
        let site_id = SiteId::parse(SITE_ID).expect("site id should be canonical");
        let release_id =
            ReleaseId::from(RequestId::parse(REQUEST_ID).expect("request id should be canonical"));
        let head = GitCommitSha::parse(&"a".repeat(40)).expect("test SHA should be valid");

        let outcome = prepare(
            &content_root,
            site_id,
            release_id,
            own_identity(),
            "--upload-pack=touch /tmp/should-not-run",
            "main",
            &head,
            None,
            &CancellationToken::default(),
        );
        assert!(matches!(outcome, Err(Error::InvalidRemoteUrl)));
    }
}
