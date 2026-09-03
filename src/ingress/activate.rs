//! The activation sequence: hash guard, write a `.tmp` sibling, validate
//! it inside the ingress container, retain the previous file, atomically
//! rename into place, reload — and, if that reload fails, put the previous
//! file back and reload it again.
//!
//! A direct behavioral port of `website-control-panel`'s
//! `activate_caddyfile`/`activate_caddyfile_checked`
//! (`src-tauri/src/commands/runtime_pool.rs:834-1038`). Nothing here knows
//! about transactions, locks, or audit records — `execute.rs` wraps this
//! the way `deploy::execute` wraps `deploy::activate`.

use std::io;

use crate::{
    compose,
    filesystem::ManagedRoot,
    ingress::{HashGuard, INGRESS_SERVICE, LIVE_CONFIG_PATH},
    process::{ProcessOutput, ProcessTermination, SubprocessDiagnostics},
    site::{Domain, SiteRelativePath, TrustedRoot, ValidationError},
};

/// What one activation did. `activated` is `false` only for the no-op
/// case described on `activate`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Activation {
    pub activated: bool,
}

/// One `caddy validate`/`caddy reload` attempt that did not succeed.
/// `Rejected` carries `SubprocessDiagnostics` rather than the child's
/// output: `docs/protocol.md`'s `details` allowlist forbids putting
/// captured stdout/stderr into a response, and a rejected Caddyfile's
/// error text can quote the config itself.
#[derive(Debug)]
pub enum ComposeFailure {
    /// `docker compose exec` could not be run at all (no `docker`, no
    /// resolvable stack directory, runner failure).
    Run(compose::Error),
    /// It ran, and the command inside the container did not succeed.
    Rejected(SubprocessDiagnostics),
}

/// Why restoring the previous configuration after a failed reload did not
/// finish.
#[derive(Debug)]
pub enum RestoreFailure {
    /// The previous file could not be put back on disk (or, when there was
    /// no previous file, the newly-activated one could not be removed).
    File(io::Error),
    /// The previous file *was* put back, but reloading it failed too — so
    /// the running server is still on a configuration nobody chose.
    Reload(ComposeFailure),
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    /// The route file resolved to something outside `ingress_root`. Only
    /// reachable through a symlink planted inside the root, since the file
    /// name itself is derived from an already-validated `Domain`.
    Path(ValidationError),
    /// The file's current contents do not satisfy the request's
    /// `HashGuard`. Nothing was written.
    HashGuardMismatch,
    /// `caddy validate` rejected the new content, or could not be run.
    /// The live path was never touched.
    ValidateFailed(ComposeFailure),
    /// The reload after activation failed, and the previous state was
    /// fully restored *and* reloaded — so what is live now is exactly what
    /// was live before this call.
    ReloadFailedAndRestored(ComposeFailure),
    /// The route file already held the requested content, so nothing was
    /// written — but the reload that has to confirm the running server is
    /// actually on it failed. Nothing on disk was changed by this call.
    ReloadFailedUnchanged(ComposeFailure),
    /// The reload after activation failed and recovery did not complete.
    /// Both failures are reported, because the second one is the reason
    /// this needs an operator rather than a retry.
    RecoveryFailed {
        reload: ComposeFailure,
        restore: RestoreFailure,
    },
}

/// Replaces `domain`'s route file under `ingress_root` with `content`.
///
/// `backup_suffix` names the `.rollback-<suffix>` file the previous
/// contents are retained in while the new ones are proven live; see
/// `execute.rs` for what this engine passes.
///
/// When the route file already holds exactly `content`, the write, the
/// backup, and the rename are all skipped and the call reports
/// `activated: false` — but the reload still runs. That last part is not
/// optional. "The file already says X" does not imply "the running server
/// is already on X": a previous attempt can leave exactly that divergence
/// behind, by renaming the new content into place and then failing both
/// its reload *and* its restore (`RecoveryFailed { restore:
/// RestoreFailure::File(_) }`). Skipping the reload here would make the
/// operator's or the client's natural next move — re-submitting the same
/// request — return success while the server stayed on the stale config.
/// `activate_caddyfile` cannot have that failure mode because it always
/// reloads, so neither does this.
///
/// Reporting `activated: false` for that case is the one deliberate
/// divergence from `activate_caddyfile` that remains, and it is only about
/// what is *reported*: a caller of a whole-file-replacement API cannot
/// otherwise tell "already in the requested state" from "changed", and
/// re-running a converged mutation is the common case
/// (`disable_basic_auth` on a site that already has no basic auth).
pub fn activate(
    ingress_root: &TrustedRoot,
    domain: &Domain,
    content: &str,
    guard: &HashGuard,
    backup_suffix: &str,
    compose: &compose::Access,
) -> Result<Activation, Error> {
    let root = ManagedRoot::open(ingress_root).map_err(Error::Io)?;
    let paths = RoutePaths::new(domain, backup_suffix);

    let current = read_optional(&root, &paths.live)?;
    if !guard.is_satisfied_by(current.as_deref()) {
        return Err(Error::HashGuardMismatch);
    }
    if current.as_deref() == Some(content.as_bytes()) {
        // Converge, do not assume. See this function's doc comment for the
        // exact sequence that leaves the file already correct while the
        // running server is not.
        return match reload(compose) {
            Ok(()) => Ok(Activation { activated: false }),
            Err(failure) => Err(Error::ReloadFailedUnchanged(failure)),
        };
    }

    // The `.tmp` sibling is deliberately not named `*.caddyfile`, so the
    // running server's `import /etc/wcp/ingress.d/*.caddyfile` glob cannot
    // pick it up while it is being validated. `write_atomic` itself stages
    // through a further `.tmp.tmp` sibling, which is likewise invisible.
    root.write_atomic(&paths.staged, content.as_bytes())
        .map_err(Error::Io)?;

    // The one path this operation has to name to something outside its own
    // process. `resolve_existing` canonicalizes it and proves it is really
    // inside `ingress_root` — a symlink planted at the route name cannot
    // get a file elsewhere on the host validated (or, below, replaced).
    // The container sees this exact path: the ingress service bind-mounts
    // the routes directory at the identical location inside the container
    // (`images/stack/docker-compose.v2.yml`:
    // `/etc/wcp/ingress.d:/etc/wcp/ingress.d:ro`), which is why
    // `activate_caddyfile`'s ingress call sites pass one value as both
    // `host_dest` and `container_dest` (`runtime_pool.rs:2773-2778`).
    // Deriving the container path from the host path rather than from a
    // compiled-in container-side prefix also fails safe: if `ingress_root`
    // is ever configured somewhere that is not the mounted directory,
    // `caddy validate` reports a missing file instead of silently
    // validating whatever unrelated file happens to sit at the same
    // relative position inside the container.
    let staged_path = match ingress_root.resolve_existing(&paths.staged) {
        Ok(path) => path,
        Err(error) => {
            discard(&root, &paths.staged);
            return Err(Error::Path(error));
        }
    };
    // `ingress_root` is read from a JSON config file, so a non-UTF-8 path
    // here is unreachable in practice — but it must not panic, and it must
    // not be passed to `docker` half-formed either.
    let Some(staged_path) = staged_path.to_str() else {
        discard(&root, &paths.staged);
        return Err(Error::Path(ValidationError::PathResolutionFailed));
    };
    if let Err(failure) = validate(compose, staged_path) {
        discard(&root, &paths.staged);
        return Err(Error::ValidateFailed(failure));
    }

    // Keep the previous config outside the import glob until the new one
    // has also survived a live reload: standalone validation above catches
    // syntax errors, but a reload can still reject a conflict with another
    // imported file. Copying (rather than renaming) the previous contents
    // aside means the live path never briefly ceases to exist, matching
    // `activate_caddyfile`'s `cp -p` + `mv -f` ordering.
    if let Some(previous) = &current {
        if let Err(error) = root.write_atomic(&paths.backup, previous) {
            discard(&root, &paths.staged);
            return Err(Error::Io(error));
        }
    }
    if let Err(error) = root.rename(&paths.staged, &paths.live) {
        discard(&root, &paths.staged);
        discard(&root, &paths.backup);
        return Err(Error::Io(error));
    }

    // Commit point: the live path now holds `content`.
    let Err(reload_failure) = reload(compose) else {
        discard(&root, &paths.backup);
        return Ok(Activation { activated: true });
    };

    let restored = if current.is_some() {
        root.rename(&paths.backup, &paths.live)
    } else {
        root.remove_file(&paths.live)
    };
    if let Err(error) = restored {
        return Err(Error::RecoveryFailed {
            reload: reload_failure,
            restore: RestoreFailure::File(error),
        });
    }
    if let Err(second) = reload(compose) {
        return Err(Error::RecoveryFailed {
            reload: reload_failure,
            restore: RestoreFailure::Reload(second),
        });
    }
    Err(Error::ReloadFailedAndRestored(reload_failure))
}

/// The three files one activation touches, all siblings under
/// `ingress_root`.
struct RoutePaths {
    live: SiteRelativePath,
    staged: SiteRelativePath,
    backup: SiteRelativePath,
}

impl RoutePaths {
    fn new(domain: &Domain, backup_suffix: &str) -> Self {
        let live = super::route_path(domain);
        let sibling = |suffix: &str| {
            SiteRelativePath::parse(format!("{}{suffix}", live.as_path().display()))
                .expect("appending a literal suffix to a valid route name stays valid")
        };
        Self {
            staged: sibling(".tmp"),
            backup: sibling(&format!(".rollback-{backup_suffix}")),
            live,
        }
    }
}

/// Reads a file that may legitimately not exist yet (a domain's first
/// activation).
fn read_optional(root: &ManagedRoot, path: &SiteRelativePath) -> Result<Option<Vec<u8>>, Error> {
    match root.read_bytes(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Error::Io(error)),
    }
}

/// Removes a file this call created and no longer wants, ignoring the
/// outcome. Deliberately best-effort, exactly as the corresponding
/// `sudo rm -f ... .ok()` calls in `activate_caddyfile` are: the error the
/// caller is about to return is the actionable one, and a leftover
/// non-`*.caddyfile` sibling is invisible to the running server.
fn discard(root: &ManagedRoot, path: &SiteRelativePath) {
    let _ = root.remove_file(path);
}

fn validate(compose: &compose::Access, staged: &str) -> Result<(), ComposeFailure> {
    check(
        "caddy validate",
        compose.exec(
            INGRESS_SERVICE,
            &[
                "caddy",
                "validate",
                "--config",
                staged,
                "--adapter",
                "caddyfile",
            ],
        ),
    )
}

fn reload(compose: &compose::Access) -> Result<(), ComposeFailure> {
    check(
        "caddy reload",
        compose.exec(
            INGRESS_SERVICE,
            &[
                "caddy",
                "reload",
                "--config",
                LIVE_CONFIG_PATH,
                "--adapter",
                "caddyfile",
            ],
        ),
    )
}

fn check(
    program: &str,
    outcome: Result<ProcessOutput, compose::Error>,
) -> Result<(), ComposeFailure> {
    let output = outcome.map_err(ComposeFailure::Run)?;
    if matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        return Ok(());
    }
    Err(ComposeFailure::Rejected(
        SubprocessDiagnostics::from_output(program, &output),
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use std::{fs, path::Path};

    use super::{Activation, ComposeFailure, Error, RestoreFailure, activate};
    use crate::{
        compose,
        ingress::{ConfigHash, HashGuard, fake_docker::FakeDocker},
        site::{Domain, TrustedRoot},
    };

    const DOMAIN: &str = "example.com";
    const ROUTE: &str = "example.com.caddyfile";
    const SUFFIX: &str = "123e4567-e89b-12d3-a456-426614174000";
    const PREVIOUS: &str = "example.com {\n  respond \"old\"\n}\n";
    const UPDATED: &str = "example.com {\n  respond \"new\"\n}\n";

    struct Root {
        dir: tempfile::TempDir,
        trusted: TrustedRoot,
    }

    fn ingress_root(existing: Option<&str>) -> Root {
        let dir = tempfile::tempdir().expect("ingress root should be created");
        if let Some(contents) = existing {
            fs::write(dir.path().join(ROUTE), contents).expect("existing route should be written");
        }
        let trusted = TrustedRoot::parse(dir.path()).expect("ingress root should be valid");
        Root { dir, trusted }
    }

    impl Root {
        fn live(&self) -> Option<String> {
            fs::read_to_string(self.dir.path().join(ROUTE)).ok()
        }

        /// Every entry in the root, so a test can assert that no `.tmp` or
        /// `.rollback-*` sibling was left behind.
        fn entries(&self) -> Vec<String> {
            let mut names: Vec<String> = fs::read_dir(self.dir.path())
                .expect("ingress root should be readable")
                .map(|entry| {
                    entry
                        .expect("directory entry should be readable")
                        .file_name()
                        .to_string_lossy()
                        .into_owned()
                })
                .collect();
            names.sort();
            names
        }
    }

    fn domain() -> Domain {
        Domain::parse(DOMAIN).expect("test domain should be valid")
    }

    /// The guard a caller that just read `contents` would send.
    fn guard_on(contents: &str) -> HashGuard {
        HashGuard::Sha256(ConfigHash::of(contents.as_bytes()))
    }

    fn run(
        root: &Root,
        docker: &FakeDocker,
        content: &str,
        guard: HashGuard,
    ) -> Result<Activation, Error> {
        activate(
            &root.trusted,
            &domain(),
            content,
            &guard,
            SUFFIX,
            &docker.access(),
        )
    }

    #[test]
    fn fresh_activation_writes_the_route_file_and_reloads() {
        let root = ingress_root(None);
        let docker = FakeDocker::new();

        let activation =
            run(&root, &docker, UPDATED, HashGuard::Absent).expect("fresh activation should apply");

        assert_eq!(activation, Activation { activated: true });
        assert_eq!(root.live().as_deref(), Some(UPDATED));
        assert_eq!(root.entries(), vec![ROUTE.to_owned()]);
        assert_eq!(docker.calls("validate").len(), 1);
        assert_eq!(docker.calls("reload").len(), 1);
    }

    /// The validated path must be the `.tmp` sibling's real, absolute
    /// location under the ingress root — not the live route name (which
    /// would validate the old file) and not a relative path (which the
    /// container could not resolve).
    #[test]
    fn validation_targets_the_staged_sibling_by_absolute_path() {
        let root = ingress_root(None);
        let docker = FakeDocker::new();

        run(&root, &docker, UPDATED, HashGuard::Absent).expect("activation should apply");

        let expected = root
            .dir
            .path()
            .canonicalize()
            .expect("ingress root should canonicalize")
            .join(format!("{ROUTE}.tmp"));
        let call = docker.calls("validate").remove(0);
        assert!(
            call.contains(&format!(
                "exec -T ingress caddy validate --config {} --adapter caddyfile",
                expected.display()
            )),
            "unexpected validate argv: {call}"
        );
        assert!(Path::new(&expected).is_absolute());
        assert!(
            docker.calls("reload")[0]
                .contains("caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile"),
            "unexpected reload argv"
        );
    }

    #[test]
    fn a_matching_hash_guard_replaces_the_previous_contents() {
        let root = ingress_root(Some(PREVIOUS));
        let docker = FakeDocker::new();

        let activation = run(
            &root,
            &docker,
            UPDATED,
            HashGuard::Sha256(ConfigHash::of(PREVIOUS.as_bytes())),
        )
        .expect("an activation whose guard matches should apply");

        assert_eq!(activation, Activation { activated: true });
        assert_eq!(root.live().as_deref(), Some(UPDATED));
        assert_eq!(root.entries(), vec![ROUTE.to_owned()]);
    }

    #[test]
    fn a_stale_hash_guard_is_rejected_before_anything_is_written() {
        let root = ingress_root(Some(PREVIOUS));
        let docker = FakeDocker::new();

        let error = run(
            &root,
            &docker,
            UPDATED,
            HashGuard::Sha256(ConfigHash::of(b"what the caller thought was there")),
        )
        .expect_err("a stale guard must not activate");

        assert!(matches!(error, Error::HashGuardMismatch));
        assert_eq!(root.live().as_deref(), Some(PREVIOUS));
        assert_eq!(root.entries(), vec![ROUTE.to_owned()]);
        // Fail *closed*: not even the staging write, let alone a container
        // call, may happen once the guard is known to be stale.
        assert!(docker.calls("validate").is_empty());
        assert!(docker.calls("reload").is_empty());
    }

    #[test]
    fn an_absent_guard_is_rejected_when_the_file_already_exists() {
        let root = ingress_root(Some(PREVIOUS));
        let docker = FakeDocker::new();

        let error = run(&root, &docker, UPDATED, HashGuard::Absent)
            .expect_err("a first-activation guard must not overwrite an existing file");

        assert!(matches!(error, Error::HashGuardMismatch));
        assert_eq!(root.live().as_deref(), Some(PREVIOUS));
    }

    #[test]
    fn validate_failure_leaves_the_live_file_untouched() {
        let root = ingress_root(Some(PREVIOUS));
        let docker = FakeDocker::new().failing("validate", "all");

        let error = run(&root, &docker, UPDATED, guard_on(PREVIOUS))
            .expect_err("a rejected config must not activate");

        assert!(matches!(
            error,
            Error::ValidateFailed(ComposeFailure::Rejected(_))
        ));
        assert_eq!(root.live().as_deref(), Some(PREVIOUS));
        // The staged sibling is cleaned up, and the reload never runs:
        // nothing about the live server was disturbed.
        assert_eq!(root.entries(), vec![ROUTE.to_owned()]);
        assert!(docker.calls("reload").is_empty());
    }

    #[test]
    fn validate_failure_on_a_first_activation_leaves_no_file_at_all() {
        let root = ingress_root(None);
        let docker = FakeDocker::new().failing("validate", "all");

        let error = run(&root, &docker, UPDATED, HashGuard::Absent)
            .expect_err("a rejected config must not activate");

        assert!(matches!(error, Error::ValidateFailed(_)));
        assert_eq!(root.live(), None);
        assert!(root.entries().is_empty(), "{:?}", root.entries());
    }

    #[test]
    fn reload_failure_restores_and_reloads_the_previous_file() {
        let root = ingress_root(Some(PREVIOUS));
        // Only the first reload fails - the one for the new config. The
        // second, for the restored previous config, succeeds.
        let docker = FakeDocker::new().failing("reload", "1");

        let error = run(&root, &docker, UPDATED, guard_on(PREVIOUS))
            .expect_err("a config the server refuses to load must not stay live");

        assert!(matches!(
            error,
            Error::ReloadFailedAndRestored(ComposeFailure::Rejected(_))
        ));
        assert_eq!(
            root.live().as_deref(),
            Some(PREVIOUS),
            "the exact previous file must be back"
        );
        assert_eq!(root.entries(), vec![ROUTE.to_owned()]);
        assert_eq!(
            docker.calls("reload").len(),
            2,
            "the restored file must itself be reloaded, not just written back"
        );
    }

    #[test]
    fn reload_failure_on_a_first_activation_removes_the_new_file() {
        let root = ingress_root(None);
        let docker = FakeDocker::new().failing("reload", "1");

        let error = run(&root, &docker, UPDATED, HashGuard::Absent)
            .expect_err("a config the server refuses to load must not stay live");

        assert!(matches!(error, Error::ReloadFailedAndRestored(_)));
        assert_eq!(root.live(), None, "there was no previous file to restore");
        assert!(root.entries().is_empty(), "{:?}", root.entries());
        assert_eq!(docker.calls("reload").len(), 2);
    }

    #[test]
    fn a_reload_failure_after_restoring_reports_both_failures() {
        let root = ingress_root(Some(PREVIOUS));
        let docker = FakeDocker::new().failing("reload", "all");

        let error = run(&root, &docker, UPDATED, guard_on(PREVIOUS))
            .expect_err("a config the server refuses to load must not stay live");

        // Both halves are reported: the original reload failure and the
        // fact that reloading the restored file failed too. Reporting only
        // the first would hide that the running server is still on a
        // configuration nobody chose.
        let Error::RecoveryFailed { reload, restore } = error else {
            panic!("expected a recovery failure, got {error:?}")
        };
        assert!(matches!(reload, ComposeFailure::Rejected(_)));
        assert!(matches!(
            restore,
            RestoreFailure::Reload(ComposeFailure::Rejected(_))
        ));
        // The file itself was still put back, which is why the second
        // reload is what failed rather than the restore.
        assert_eq!(root.live().as_deref(), Some(PREVIOUS));
        assert_eq!(root.entries(), vec![ROUTE.to_owned()]);
        assert_eq!(docker.calls("reload").len(), 2);
    }

    /// Re-submitting the current contents skips the write, the backup and
    /// the rename - but *not* the reload. "The file already says X" does
    /// not imply "the server is already running X"; see the next test for
    /// the sequence that produces exactly that divergence.
    #[test]
    fn identical_content_skips_the_write_but_still_reloads() {
        let root = ingress_root(Some(PREVIOUS));
        let docker = FakeDocker::new();

        let activation = run(&root, &docker, PREVIOUS, guard_on(PREVIOUS))
            .expect("re-submitting the current contents should succeed");

        assert_eq!(activation, Activation { activated: false });
        assert_eq!(root.live().as_deref(), Some(PREVIOUS));
        assert!(
            docker.calls("validate").is_empty(),
            "unchanged content needs no revalidation"
        );
        assert_eq!(
            docker.calls("reload").len(),
            1,
            "the running server must still be converged onto the file"
        );
    }

    /// The regression this reload exists to prevent. A previous attempt
    /// can leave the live *file* holding the new content while the running
    /// server is still on the old one: rename in, reload fails, restore
    /// fails too. Standing in for that state directly - the file already
    /// holds the requested content, the server does not - a re-submission
    /// must not report success just because the bytes match.
    #[test]
    fn a_converge_reload_failure_is_reported_instead_of_a_false_success() {
        let root = ingress_root(Some(UPDATED));
        let docker = FakeDocker::new().failing("reload", "all");

        let error = run(&root, &docker, UPDATED, guard_on(UPDATED))
            .expect_err("a server that will not load the current file is not a success");

        assert!(
            matches!(
                error,
                Error::ReloadFailedUnchanged(ComposeFailure::Rejected(_))
            ),
            "unexpected error: {error:?}"
        );
        // Nothing on disk was touched: this call only tried to converge
        // the server onto what was already there.
        assert_eq!(root.live().as_deref(), Some(UPDATED));
        assert_eq!(root.entries(), vec![ROUTE.to_owned()]);
        assert!(docker.calls("validate").is_empty());
    }

    /// The guard is checked before the no-op short-circuit, so a caller
    /// working from a stale read is still told so even when what it
    /// submits happens to match what is on disk.
    #[test]
    fn a_stale_guard_is_rejected_even_when_the_content_already_matches() {
        let root = ingress_root(Some(PREVIOUS));
        let docker = FakeDocker::new();

        let error = run(
            &root,
            &docker,
            PREVIOUS,
            HashGuard::Sha256(ConfigHash::of(b"stale")),
        )
        .expect_err("a stale guard must be reported");

        assert!(matches!(error, Error::HashGuardMismatch));
    }

    #[test]
    fn an_unrunnable_docker_is_reported_as_a_run_failure_not_an_invalid_config() {
        let root = ingress_root(Some(PREVIOUS));
        let empty = tempfile::tempdir().expect("empty directory should be created");
        let access = compose::Access::default()
            .stack_dir(empty.path())
            .docker_path(empty.path());

        let error = activate(
            &root.trusted,
            &domain(),
            UPDATED,
            &guard_on(PREVIOUS),
            SUFFIX,
            &access,
        )
        .expect_err("an unreachable docker must fail the activation");

        assert!(matches!(
            error,
            Error::ValidateFailed(ComposeFailure::Run(compose::Error::Run(_)))
        ));
        assert_eq!(root.live().as_deref(), Some(PREVIOUS));
        assert_eq!(root.entries(), vec![ROUTE.to_owned()]);
    }

    /// A symlink planted at the live route name cannot be used to read or
    /// overwrite a file outside the ingress root: every filesystem step
    /// here goes through `ManagedRoot`, whose capability-scoped directory
    /// handle refuses to traverse out of the root at all. It fails at the
    /// very first step - reading the current contents for the hash guard -
    /// so nothing is staged and no container call is made.
    #[test]
    fn a_route_name_symlinked_outside_the_root_cannot_be_read_or_overwritten() {
        use std::os::unix::fs::symlink;

        let outside = tempfile::tempdir().expect("outside directory should exist");
        let target = outside.path().join("secret");
        fs::write(&target, "not managed by this engine").expect("target should be written");

        let root = ingress_root(None);
        symlink(&target, root.dir.path().join(ROUTE)).expect("symlink should be created");
        let docker = FakeDocker::new();

        let error = run(&root, &docker, UPDATED, HashGuard::Absent)
            .expect_err("a route escaping the root must not be activated");

        assert!(matches!(error, Error::Io(_)), "unexpected error: {error:?}");
        assert_eq!(
            fs::read_to_string(&target).expect("target should still be readable"),
            "not managed by this engine"
        );
        assert!(docker.calls("validate").is_empty());
        assert!(docker.calls("reload").is_empty());
    }

    /// The staged sibling is written through `write_atomic`, which renames
    /// a fresh file over whatever name it is given. So a `.tmp` left
    /// pointing outside the root by some earlier interrupted run is
    /// replaced, not followed - the outside file is never written through,
    /// and the activation proceeds normally.
    #[test]
    fn a_stale_staging_symlink_is_replaced_rather_than_followed() {
        use std::os::unix::fs::symlink;

        let outside = tempfile::tempdir().expect("outside directory should exist");
        let target = outside.path().join("secret");
        fs::write(&target, "not managed by this engine").expect("target should be written");

        let root = ingress_root(None);
        symlink(&target, root.dir.path().join(format!("{ROUTE}.tmp")))
            .expect("symlink should be created");
        let docker = FakeDocker::new();

        run(&root, &docker, UPDATED, HashGuard::Absent).expect("activation should apply");

        assert_eq!(root.live().as_deref(), Some(UPDATED));
        assert_eq!(
            fs::read_to_string(&target).expect("target should still be readable"),
            "not managed by this engine"
        );
        assert_eq!(root.entries(), vec![ROUTE.to_owned()]);
    }
}
