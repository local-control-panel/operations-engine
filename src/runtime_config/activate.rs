//! The activation sequence: hash guard, write a `.tmp` sibling, validate it
//! inside the site's current runtime-service container, retain the
//! previous fragment, atomically rename into place, reload — and, if that
//! reload fails, put the previous fragment back and reload it again.
//!
//! Structurally identical to `ingress::activate::activate_live` (the same
//! validate/write/rename/reload/rollback sequence `website-control-panel`'s
//! `activate_caddyfile` already runs against any `service`/host path pair —
//! see that function's own doc comment, `runtime_pool.rs:955-1045`, which
//! this is also a port of), just parameterized by which container and
//! which subdirectory of `runtime_root` a request names, since — unlike
//! `ingress`'s single, fixed `INGRESS_SERVICE` — the target runtime pool
//! varies per request.

use std::io;

use crate::{
    compose,
    filesystem::ManagedRoot,
    ingress::{HashGuard, LIVE_CONFIG_PATH},
    process::{ProcessOutput, ProcessTermination, SubprocessDiagnostics},
    site::{Domain, RuntimeId, SiteRelativePath, TrustedRoot, ValidationError},
};

/// What one activation did. `activated` is `false` only for the no-op case
/// described on `activate`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Activation {
    pub activated: bool,
}

/// One `caddy validate`/`caddy reload` attempt that did not succeed.
/// `Rejected` carries `SubprocessDiagnostics` rather than the child's
/// output — see `ingress::activate::ComposeFailure`'s doc comment; the same
/// `docs/protocol.md` `details` allowlist applies here.
#[derive(Debug)]
pub enum ComposeFailure {
    /// `docker compose exec` could not be run at all (no `docker`, no
    /// resolvable stack directory, runner failure).
    Run(compose::Error),
    /// It ran, and the command inside the container did not succeed.
    Rejected(SubprocessDiagnostics),
}

/// Why restoring the previous fragment after a failed reload did not
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
    /// The fragment resolved to something outside `runtime_root`. Only
    /// reachable through a symlink planted inside the root, since the file
    /// name itself is derived from an already-validated `RuntimeId`/
    /// `Domain` pair.
    Path(ValidationError),
    /// The file's current contents do not satisfy the request's
    /// `HashGuard`. Nothing was written.
    HashGuardMismatch,
    /// `caddy validate` rejected the new content, or could not be run. The
    /// live path was never touched.
    ValidateFailed(ComposeFailure),
    /// The reload after activation failed, and the previous state was fully
    /// restored *and* reloaded — so what is live now is exactly what was
    /// live before this call.
    ReloadFailedAndRestored(ComposeFailure),
    /// The fragment already held the requested content, so nothing was
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

/// Replaces `domain`'s runtime-service Caddyfile fragment under
/// `runtime_root/<runtime_id>/` with `content`.
///
/// `backup_suffix` names the `.rollback-<suffix>` file the previous
/// contents are retained in while the new ones are proven live; see
/// `execute.rs` for what this engine passes.
///
/// When the fragment already holds exactly `content`, the write, the
/// backup, and the rename are all skipped and the call reports
/// `activated: false` — but the reload still runs, for exactly the reason
/// `ingress::activate::activate`'s doc comment gives: "the file already
/// says X" does not imply "the running server is already on X", since an
/// earlier attempt can leave that divergence behind by renaming the new
/// content into place and then failing both its reload *and* its restore.
///
/// `pub(crate)`, not `pub`, for the same reason as
/// `ingress::activate::activate`: `backup_suffix` has no validating type
/// behind it, and the only caller inside this crate (`execute::execute`)
/// always passes an already-validated canonical `RequestId`.
pub(crate) fn activate(
    runtime_root: &TrustedRoot,
    runtime_id: &RuntimeId,
    domain: &Domain,
    content: &str,
    guard: &HashGuard,
    backup_suffix: &str,
    compose: &compose::Access,
) -> Result<Activation, Error> {
    let root = ManagedRoot::open(runtime_root).map_err(Error::Io)?;
    let paths = RoutePaths::new(runtime_id, domain, backup_suffix);
    let service = runtime_service_name(runtime_id);

    // Unlike `ingress_root` (flat — every route file lives directly in it),
    // `runtime_root` nests one subdirectory per `runtime_id`, which a given
    // runtime pool's very first activation on this host has never had
    // reason to create yet. `create_dir_all` is idempotent/race-safe and
    // never the atomicity-bearing step here (the hash guard and the
    // rename below are), so doing this unconditionally on every call is
    // cheap and correct rather than only on a detected first-activation
    // path.
    root.create_dir_all(
        &SiteRelativePath::parse(runtime_id.to_string())
            .expect("a validated RuntimeId always yields a valid relative path"),
    )
    .map_err(Error::Io)?;

    let current = read_optional(&root, &paths.live)?;
    if !guard.is_satisfied_by(current.as_deref()) {
        return Err(Error::HashGuardMismatch);
    }
    if current.as_deref() == Some(content.as_bytes()) {
        return match reload(compose, &service) {
            Ok(()) => Ok(Activation { activated: false }),
            Err(failure) => Err(Error::ReloadFailedUnchanged(failure)),
        };
    }

    // The `.tmp` sibling is deliberately not named `*.caddyfile`, so the
    // running server's `import`-glob (mirroring the ingress container's own
    // `/etc/wcp/ingress.d/*.caddyfile`) cannot pick it up while it is being
    // validated. `write_atomic` itself stages through a further `.tmp.tmp`
    // sibling, which is likewise invisible.
    root.write_atomic(&paths.staged, content.as_bytes())
        .map_err(Error::Io)?;

    // The one path this operation has to name to something outside its own
    // process. `resolve_existing` canonicalizes it and proves it is really
    // inside `runtime_root` — a symlink planted at the fragment name cannot
    // get a file elsewhere on the host validated (or, below, replaced). The
    // container sees this exact path: the runtime-service bind-mounts its
    // config directory at the identical location inside the container
    // (mirroring the ingress container's own bind-mount), which is why
    // `activate_caddyfile`'s runtime call sites also pass one value as both
    // `host_dest` and `container_dest`.
    let staged_path = match runtime_root.resolve_existing(&paths.staged) {
        Ok(path) => path,
        Err(error) => {
            discard(&root, &paths.staged);
            return Err(Error::Path(error));
        }
    };
    let Some(staged_path) = staged_path.to_str() else {
        discard(&root, &paths.staged);
        return Err(Error::Path(ValidationError::PathResolutionFailed));
    };
    if let Err(failure) = validate(compose, &service, staged_path) {
        discard(&root, &paths.staged);
        return Err(Error::ValidateFailed(failure));
    }

    // Keep the previous config outside the import glob until the new one
    // has also survived a live reload — same ordering as
    // `ingress::activate::activate_live`, and for the same reason.
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
    let Err(reload_failure) = reload(compose, &service) else {
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
    if let Err(second) = reload(compose, &service) {
        return Err(Error::RecoveryFailed {
            reload: reload_failure,
            restore: RestoreFailure::Reload(second),
        });
    }
    Err(Error::ReloadFailedAndRestored(reload_failure))
}

/// The Compose service name a `RuntimeId` addresses — mirrors
/// `website-control-panel`'s own `runtime_service_name`
/// (`runtime_pool.rs:90-92`, `format!("runtime-{runtime_id}")`) verbatim.
fn runtime_service_name(id: &RuntimeId) -> String {
    format!("runtime-{id}")
}

/// The three files one activation touches, all siblings under
/// `runtime_root/<runtime_id>/`.
struct RoutePaths {
    live: SiteRelativePath,
    staged: SiteRelativePath,
    backup: SiteRelativePath,
}

impl RoutePaths {
    fn new(runtime_id: &RuntimeId, domain: &Domain, backup_suffix: &str) -> Self {
        let live = super::route_path(runtime_id, domain);
        let sibling = |suffix: &str| {
            SiteRelativePath::parse(format!("{}{suffix}", live.as_path().display()))
                .expect("appending a literal suffix to a valid fragment name stays valid")
        };
        Self {
            staged: sibling(".tmp"),
            backup: sibling(&format!(".rollback-{backup_suffix}")),
            live,
        }
    }
}

/// Reads a file that may legitimately not exist yet (a site's first
/// activation on this runtime pool).
fn read_optional(root: &ManagedRoot, path: &SiteRelativePath) -> Result<Option<Vec<u8>>, Error> {
    match root.read_bytes(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Error::Io(error)),
    }
}

/// Removes a file this call created and no longer wants, ignoring the
/// outcome — see `ingress::activate::discard`'s doc comment; the same
/// reasoning applies verbatim.
fn discard(root: &ManagedRoot, path: &SiteRelativePath) {
    let _ = root.remove_file(path);
}

fn validate(compose: &compose::Access, service: &str, staged: &str) -> Result<(), ComposeFailure> {
    check(
        "caddy validate",
        compose.exec(
            service,
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

fn reload(compose: &compose::Access, service: &str) -> Result<(), ComposeFailure> {
    check(
        "caddy reload",
        compose.exec(
            service,
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
        site::{Domain, RuntimeId, TrustedRoot},
    };

    const RUNTIME_ID: &str = "fp1-php83";
    const DOMAIN: &str = "example.com";
    const ROUTE: &str = "fp1-php83/example.com.caddyfile";
    const SUFFIX: &str = "123e4567-e89b-12d3-a456-426614174000";
    const PREVIOUS: &str = "example.com {\n  respond \"old\"\n}\n";
    const UPDATED: &str = "example.com {\n  respond \"new\"\n}\n";

    struct Root {
        dir: tempfile::TempDir,
        trusted: TrustedRoot,
    }

    fn runtime_root(existing: Option<&str>) -> Root {
        let dir = tempfile::tempdir().expect("runtime root should be created");
        if let Some(contents) = existing {
            let subdir = dir.path().join(RUNTIME_ID);
            fs::create_dir_all(&subdir).expect("runtime-id subdirectory should be created");
            fs::write(subdir.join(format!("{DOMAIN}.caddyfile")), contents)
                .expect("existing fragment should be written");
        }
        let trusted = TrustedRoot::parse(dir.path()).expect("runtime root should be valid");
        Root { dir, trusted }
    }

    impl Root {
        fn live(&self) -> Option<String> {
            fs::read_to_string(self.dir.path().join(ROUTE)).ok()
        }

        /// Every entry under the `<runtime_id>/` subdirectory, so a test can
        /// assert that no `.tmp` or `.rollback-*` sibling was left behind.
        fn entries(&self) -> Vec<String> {
            let subdir = self.dir.path().join(RUNTIME_ID);
            if !subdir.exists() {
                return Vec::new();
            }
            let mut names: Vec<String> = fs::read_dir(&subdir)
                .expect("runtime-id subdirectory should be readable")
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

    fn runtime_id() -> RuntimeId {
        RuntimeId::parse(RUNTIME_ID).expect("test runtime id should be valid")
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
            &runtime_id(),
            &domain(),
            content,
            &guard,
            SUFFIX,
            &docker.access(),
        )
    }

    #[test]
    fn fresh_activation_writes_the_fragment_and_reloads() {
        let root = runtime_root(None);
        let docker = FakeDocker::new();

        let activation =
            run(&root, &docker, UPDATED, HashGuard::Absent).expect("fresh activation should apply");

        assert_eq!(activation, Activation { activated: true });
        assert_eq!(root.live().as_deref(), Some(UPDATED));
        assert_eq!(root.entries(), vec![format!("{DOMAIN}.caddyfile")]);
        assert_eq!(docker.calls("validate").len(), 1);
        assert_eq!(docker.calls("reload").len(), 1);
    }

    /// Validation and reload must run against the runtime-service container
    /// this `runtime_id` actually names, not a fixed one — the whole reason
    /// this operation exists separately from `ingress.activateConfig`.
    #[test]
    fn validation_and_reload_target_the_named_runtime_service() {
        let root = runtime_root(None);
        let docker = FakeDocker::new();

        run(&root, &docker, UPDATED, HashGuard::Absent).expect("activation should apply");

        let expected = root
            .dir
            .path()
            .canonicalize()
            .expect("runtime root should canonicalize")
            .join(format!("{ROUTE}.tmp"));
        let call = docker.calls("validate").remove(0);
        assert!(
            call.contains(&format!(
                "exec -T runtime-{RUNTIME_ID} caddy validate --config {} --adapter caddyfile",
                expected.display()
            )),
            "unexpected validate argv: {call}"
        );
        assert!(Path::new(&expected).is_absolute());
        assert!(
            docker.calls("reload")[0].contains(&format!(
                "exec -T runtime-{RUNTIME_ID} caddy reload --config /etc/caddy/Caddyfile \
                 --adapter caddyfile"
            )),
            "unexpected reload argv"
        );
    }

    #[test]
    fn a_matching_hash_guard_replaces_the_previous_contents() {
        let root = runtime_root(Some(PREVIOUS));
        let docker = FakeDocker::new();

        let activation = run(&root, &docker, UPDATED, guard_on(PREVIOUS))
            .expect("an activation whose guard matches should apply");

        assert_eq!(activation, Activation { activated: true });
        assert_eq!(root.live().as_deref(), Some(UPDATED));
        assert_eq!(root.entries(), vec![format!("{DOMAIN}.caddyfile")]);
    }

    #[test]
    fn a_stale_hash_guard_is_rejected_before_anything_is_written() {
        let root = runtime_root(Some(PREVIOUS));
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
        assert_eq!(root.entries(), vec![format!("{DOMAIN}.caddyfile")]);
        assert!(docker.calls("validate").is_empty());
        assert!(docker.calls("reload").is_empty());
    }

    #[test]
    fn an_absent_guard_is_rejected_when_the_file_already_exists() {
        let root = runtime_root(Some(PREVIOUS));
        let docker = FakeDocker::new();

        let error = run(&root, &docker, UPDATED, HashGuard::Absent)
            .expect_err("a first-activation guard must not overwrite an existing file");

        assert!(matches!(error, Error::HashGuardMismatch));
        assert_eq!(root.live().as_deref(), Some(PREVIOUS));
    }

    #[test]
    fn validate_failure_leaves_the_live_file_untouched() {
        let root = runtime_root(Some(PREVIOUS));
        let docker = FakeDocker::new().failing("validate", "all");

        let error = run(&root, &docker, UPDATED, guard_on(PREVIOUS))
            .expect_err("a rejected config must not activate");

        assert!(matches!(
            error,
            Error::ValidateFailed(ComposeFailure::Rejected(_))
        ));
        assert_eq!(root.live().as_deref(), Some(PREVIOUS));
        assert_eq!(root.entries(), vec![format!("{DOMAIN}.caddyfile")]);
        assert!(docker.calls("reload").is_empty());
    }

    #[test]
    fn validate_failure_on_a_first_activation_leaves_no_file_at_all() {
        let root = runtime_root(None);
        let docker = FakeDocker::new().failing("validate", "all");

        let error = run(&root, &docker, UPDATED, HashGuard::Absent)
            .expect_err("a rejected config must not activate");

        assert!(matches!(error, Error::ValidateFailed(_)));
        assert_eq!(root.live(), None);
        assert!(root.entries().is_empty(), "{:?}", root.entries());
    }

    #[test]
    fn reload_failure_restores_and_reloads_the_previous_file() {
        let root = runtime_root(Some(PREVIOUS));
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
        assert_eq!(root.entries(), vec![format!("{DOMAIN}.caddyfile")]);
        assert_eq!(
            docker.calls("reload").len(),
            2,
            "the restored file must itself be reloaded, not just written back"
        );
    }

    #[test]
    fn reload_failure_on_a_first_activation_removes_the_new_file() {
        let root = runtime_root(None);
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
        let root = runtime_root(Some(PREVIOUS));
        let docker = FakeDocker::new().failing("reload", "all");

        let error = run(&root, &docker, UPDATED, guard_on(PREVIOUS))
            .expect_err("a config the server refuses to load must not stay live");

        let Error::RecoveryFailed { reload, restore } = error else {
            panic!("expected a recovery failure, got {error:?}")
        };
        assert!(matches!(reload, ComposeFailure::Rejected(_)));
        assert!(matches!(
            restore,
            RestoreFailure::Reload(ComposeFailure::Rejected(_))
        ));
        assert_eq!(root.live().as_deref(), Some(PREVIOUS));
        assert_eq!(root.entries(), vec![format!("{DOMAIN}.caddyfile")]);
        assert_eq!(docker.calls("reload").len(), 2);
    }

    #[test]
    fn identical_content_skips_the_write_but_still_reloads() {
        let root = runtime_root(Some(PREVIOUS));
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

    #[test]
    fn a_converge_reload_failure_is_reported_instead_of_a_false_success() {
        let root = runtime_root(Some(UPDATED));
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
        assert_eq!(root.live().as_deref(), Some(UPDATED));
        assert_eq!(root.entries(), vec![format!("{DOMAIN}.caddyfile")]);
        assert!(docker.calls("validate").is_empty());
    }

    #[test]
    fn a_stale_guard_is_rejected_even_when_the_content_already_matches() {
        let root = runtime_root(Some(PREVIOUS));
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
        let root = runtime_root(Some(PREVIOUS));
        let empty = tempfile::tempdir().expect("empty directory should be created");
        let access = compose::Access::default()
            .stack_dir(empty.path())
            .docker_path(empty.path());

        let error = activate(
            &root.trusted,
            &runtime_id(),
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
        assert_eq!(root.entries(), vec![format!("{DOMAIN}.caddyfile")]);
    }

    /// A symlink planted at the fragment name cannot be used to read or
    /// overwrite a file outside the runtime root: every filesystem step
    /// here goes through `ManagedRoot`.
    #[test]
    fn a_fragment_name_symlinked_outside_the_root_cannot_be_read_or_overwritten() {
        use std::os::unix::fs::symlink;

        let outside = tempfile::tempdir().expect("outside directory should exist");
        let target = outside.path().join("secret");
        fs::write(&target, "not managed by this engine").expect("target should be written");

        let root = runtime_root(None);
        let subdir = root.dir.path().join(RUNTIME_ID);
        fs::create_dir_all(&subdir).expect("runtime-id subdirectory should be created");
        symlink(&target, subdir.join(format!("{DOMAIN}.caddyfile")))
            .expect("symlink should be created");
        let docker = FakeDocker::new();

        let error = run(&root, &docker, UPDATED, HashGuard::Absent)
            .expect_err("a fragment escaping the root must not be activated");

        assert!(matches!(error, Error::Io(_)), "unexpected error: {error:?}");
        assert_eq!(
            fs::read_to_string(&target).expect("target should still be readable"),
            "not managed by this engine"
        );
        assert!(docker.calls("validate").is_empty());
        assert!(docker.calls("reload").is_empty());
    }

    /// The staged sibling is written through `write_atomic`, which renames
    /// a fresh file over whatever name it is given, so a `.tmp` left
    /// pointing outside the root by some earlier interrupted run is
    /// replaced, not followed.
    #[test]
    fn a_stale_staging_symlink_is_replaced_rather_than_followed() {
        use std::os::unix::fs::symlink;

        let outside = tempfile::tempdir().expect("outside directory should exist");
        let target = outside.path().join("secret");
        fs::write(&target, "not managed by this engine").expect("target should be written");

        let root = runtime_root(None);
        let subdir = root.dir.path().join(RUNTIME_ID);
        fs::create_dir_all(&subdir).expect("runtime-id subdirectory should be created");
        symlink(&target, subdir.join(format!("{DOMAIN}.caddyfile.tmp")))
            .expect("symlink should be created");
        let docker = FakeDocker::new();

        run(&root, &docker, UPDATED, HashGuard::Absent).expect("activation should apply");

        assert_eq!(root.live().as_deref(), Some(UPDATED));
        assert_eq!(
            fs::read_to_string(&target).expect("target should still be readable"),
            "not managed by this engine"
        );
        assert_eq!(root.entries(), vec![format!("{DOMAIN}.caddyfile")]);
    }
}
