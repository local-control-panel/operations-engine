//! The activation sequence: hash guard, write a `.tmp` sibling, validate it
//! with `docker compose config` (a static parse/render check that needs no
//! running containers), retain the previous file, atomically rename into
//! place, bring the stack up with `docker compose up -d` — and, if that
//! fails, put the previous file back and bring it up again.
//!
//! Structurally identical to `runtime_config::activate::activate`'s
//! validate/write/rename/reload/rollback shape, but the "container" this
//! validates/reloads against is the stack's *own* compose file passed via
//! `-f <path>` rather than a fixed sibling service — `docker compose` is
//! invoked directly via `process::run` (this operates the stack's own file,
//! not a command inside one of its already-running containers, so
//! `compose::Access`'s `exec` — which is specifically `docker compose exec`
//! into the one fixed WCP stack — does not apply here).

use std::{io, path::Path};

use crate::{
    filesystem::ManagedRoot,
    ingress::HashGuard,
    process::{
        CancellationToken, ProcessLimits, ProcessOutput, ProcessRequest, ProcessRunError,
        ProcessTermination, SubprocessDiagnostics, run,
    },
    site::{SiteRelativePath, StackName, TrustedRoot, ValidationError},
};

const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const MAX_OUTPUT_BYTES: usize = 64 * 1024;

/// What one activation did. `activated` is `false` only for the no-op case
/// described on `activate`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Activation {
    pub activated: bool,
}

/// One `docker compose config`/`docker compose up -d` attempt that did not
/// succeed. `Rejected` carries `SubprocessDiagnostics` rather than the
/// child's output — same `docs/protocol.md` `details` allowlist reasoning
/// as `ingress::activate::ComposeFailure`.
#[derive(Debug)]
pub enum ComposeFailure {
    /// `docker` could not be run at all (missing binary, spawn failure).
    Run(ProcessRunError),
    /// It ran, and did not succeed.
    Rejected(SubprocessDiagnostics),
}

/// Why restoring the previous file after a failed reload did not finish.
#[derive(Debug)]
pub enum RestoreFailure {
    File(io::Error),
    Reload(ComposeFailure),
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    /// The file resolved to something outside `compose_root`. Only
    /// reachable through a symlink planted inside the root, since the file
    /// name itself is derived from an already-validated `StackName`.
    Path(ValidationError),
    /// The file's current contents do not satisfy the request's
    /// `HashGuard`. Nothing was written.
    HashGuardMismatch,
    /// `docker compose config` rejected the new content, or could not be
    /// run. The live path was never touched.
    ValidateFailed(ComposeFailure),
    /// `docker compose up -d` failed after activation, and the previous
    /// file was fully restored *and* brought up again.
    ReloadFailedAndRestored(ComposeFailure),
    /// The file already held the requested content, so nothing was
    /// written — but the `up -d` that has to confirm the stack is actually
    /// running it failed. Nothing on disk was changed by this call.
    ReloadFailedUnchanged(ComposeFailure),
    /// The reload after activation failed and recovery did not complete.
    RecoveryFailed {
        reload: ComposeFailure,
        restore: RestoreFailure,
    },
}

/// Replaces `stack_name`'s `docker-compose.yml` under
/// `compose_root/<stack_name>/` with `content`.
///
/// `backup_suffix` names the `.rollback-<suffix>` file the previous
/// contents are retained in while the new ones are proven up; see
/// `execute.rs` for what this engine passes. `docker_path`, when set,
/// overrides `PATH` for the spawned `docker compose` children — production
/// always passes `None`; tests point it at a fake `docker` fixture (mirrors
/// `compose::exec_inner`'s own `path_override`).
///
/// `pub(crate)` for the same reason as `runtime_config::activate::activate`:
/// `backup_suffix` has no validating type behind it, and the only caller
/// inside this crate (`execute::execute`) always passes an already-validated
/// canonical `RequestId`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn activate(
    compose_root: &TrustedRoot,
    stack_name: &StackName,
    content: &str,
    guard: &HashGuard,
    backup_suffix: &str,
    docker_path: Option<&std::ffi::OsStr>,
) -> Result<Activation, Error> {
    let root = ManagedRoot::open(compose_root).map_err(Error::Io)?;
    let paths = ComposePaths::new(stack_name, backup_suffix);

    // `compose_root` nests one subdirectory per stack, which a stack's very
    // first activation on this host has never had reason to create yet -
    // mirrors `runtime_config::activate`'s identical `create_dir_all` call
    // and reasoning.
    root.create_dir_all(
        &SiteRelativePath::parse(stack_name.to_string())
            .expect("a validated StackName always yields a valid relative path"),
    )
    .map_err(Error::Io)?;

    let current = read_optional(&root, &paths.live)?;
    if !guard.is_satisfied_by(current.as_deref()) {
        return Err(Error::HashGuardMismatch);
    }
    if current.as_deref() == Some(content.as_bytes()) {
        let live_path = compose_root.join(&paths.live);
        return match up(&live_path, docker_path) {
            Ok(()) => Ok(Activation { activated: false }),
            Err(failure) => Err(Error::ReloadFailedUnchanged(failure)),
        };
    }

    root.write_atomic(&paths.staged, content.as_bytes())
        .map_err(Error::Io)?;

    let staged_path = match compose_root.resolve_existing(&paths.staged) {
        Ok(path) => path,
        Err(error) => {
            discard(&root, &paths.staged);
            return Err(Error::Path(error));
        }
    };
    if let Err(failure) = config_check(&staged_path, docker_path) {
        discard(&root, &paths.staged);
        return Err(Error::ValidateFailed(failure));
    }

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
    let live_path = compose_root.join(&paths.live);
    let Err(reload_failure) = up(&live_path, docker_path) else {
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
    if let Err(second) = up(&live_path, docker_path) {
        return Err(Error::RecoveryFailed {
            reload: reload_failure,
            restore: RestoreFailure::Reload(second),
        });
    }
    Err(Error::ReloadFailedAndRestored(reload_failure))
}

struct ComposePaths {
    live: SiteRelativePath,
    staged: SiteRelativePath,
    backup: SiteRelativePath,
}

impl ComposePaths {
    fn new(stack_name: &StackName, backup_suffix: &str) -> Self {
        let live = super::route_path(stack_name);
        let sibling = |suffix: &str| {
            SiteRelativePath::parse(format!("{}{suffix}", live.as_path().display()))
                .expect("appending a literal suffix to a valid file name stays valid")
        };
        Self {
            staged: sibling(".tmp"),
            backup: sibling(&format!(".rollback-{backup_suffix}")),
            live,
        }
    }
}

fn read_optional(root: &ManagedRoot, path: &SiteRelativePath) -> Result<Option<Vec<u8>>, Error> {
    match root.read_bytes(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Error::Io(error)),
    }
}

fn discard(root: &ManagedRoot, path: &SiteRelativePath) {
    let _ = root.remove_file(path);
}

fn config_check(
    staged_path: &Path,
    docker_path: Option<&std::ffi::OsStr>,
) -> Result<(), ComposeFailure> {
    let Some(staged_path) = staged_path.to_str() else {
        // Unreachable in practice (compose_root is always valid UTF-8 in
        // this deployment), but `check`/`run` need a `&str` argv entry, not
        // a lossily-converted one that could name a different file.
        return Err(ComposeFailure::Rejected(SubprocessDiagnostics {
            program: "docker compose config".to_owned(),
            exit_code: None,
            timed_out: false,
            cancelled: false,
            stdout_truncated: false,
            stderr_truncated: false,
        }));
    };
    check(
        "docker compose config",
        docker_compose(&["-f", staged_path, "config"], docker_path),
    )
}

fn up(live_path: &Path, docker_path: Option<&std::ffi::OsStr>) -> Result<(), ComposeFailure> {
    let Some(live_path) = live_path.to_str() else {
        return Err(ComposeFailure::Rejected(SubprocessDiagnostics {
            program: "docker compose up".to_owned(),
            exit_code: None,
            timed_out: false,
            cancelled: false,
            stdout_truncated: false,
            stderr_truncated: false,
        }));
    };
    check(
        "docker compose up",
        docker_compose(&["-f", live_path, "up", "-d"], docker_path),
    )
}

/// Runs `docker <args...>` argv-only via `process::run` - no working
/// directory override needed (unlike `compose::exec_inner`'s fixed stack
/// checkout) since every invocation here names its target file explicitly
/// via `-f <absolute-path>`.
fn docker_compose(
    args: &[&str],
    docker_path: Option<&std::ffi::OsStr>,
) -> Result<ProcessOutput, ProcessRunError> {
    let mut argv: Vec<&str> = vec!["compose"];
    argv.extend_from_slice(args);

    let limits = ProcessLimits {
        timeout: TIMEOUT,
        max_stdout_bytes: MAX_OUTPUT_BYTES,
        max_stderr_bytes: MAX_OUTPUT_BYTES,
    };
    let mut request = ProcessRequest::new("docker").args(argv);
    if let Some(path) = docker_path {
        request = request.env("PATH", path);
    }
    run(&request, &limits, &CancellationToken::default())
}

fn check(
    program: &str,
    outcome: Result<ProcessOutput, ProcessRunError>,
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
    use std::fs;

    use super::{Activation, ComposeFailure, Error, RestoreFailure, activate};
    use crate::{
        ingress::{ConfigHash, HashGuard},
        site::{StackName, TrustedRoot},
    };

    const STACK: &str = "wp-stack";
    const COMPOSE_FILE: &str = "wp-stack/docker-compose.yml";
    const SUFFIX: &str = "123e4567-e89b-12d3-a456-426614174000";
    const PREVIOUS: &str = "services:\n  app:\n    image: old\n";
    const UPDATED: &str = "services:\n  app:\n    image: new\n";

    struct Root {
        dir: tempfile::TempDir,
        trusted: TrustedRoot,
    }

    fn compose_root(existing: Option<&str>) -> Root {
        let dir = tempfile::tempdir().expect("compose root should be created");
        if let Some(contents) = existing {
            let stack_dir = dir.path().join(STACK);
            fs::create_dir_all(&stack_dir).expect("stack dir should be created");
            fs::write(stack_dir.join("docker-compose.yml"), contents)
                .expect("existing compose file should be written");
        }
        let trusted = TrustedRoot::parse(dir.path()).expect("compose root should be valid");
        Root { dir, trusted }
    }

    impl Root {
        fn live(&self) -> Option<String> {
            fs::read_to_string(self.dir.path().join(COMPOSE_FILE)).ok()
        }

        fn entries(&self) -> Vec<String> {
            let stack_dir = self.dir.path().join(STACK);
            if !stack_dir.exists() {
                return Vec::new();
            }
            let mut names: Vec<String> = fs::read_dir(&stack_dir)
                .expect("stack dir should be readable")
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

    fn stack_name() -> StackName {
        StackName::parse(STACK).expect("test stack name should be valid")
    }

    fn guard_on(contents: &str) -> HashGuard {
        HashGuard::Sha256(ConfigHash::of(contents.as_bytes()))
    }

    /// Writes a fake `docker` script (its body, after the `#!/bin/sh`
    /// shebang) into `directory` and returns the `PATH`-override value for
    /// `activate`'s `docker_path` parameter - mirrors
    /// `ingress::fake_docker`'s technique, hand-rolled here since this
    /// module's `docker compose` invocations (arbitrary `-f <path>`, no
    /// fixed stack directory/project) don't fit that harness's shape.
    fn fake_docker(directory: &std::path::Path, script: &str) -> std::ffi::OsString {
        use std::os::unix::fs::PermissionsExt;

        let path = directory.join("docker");
        fs::write(&path, format!("#!/bin/sh\n{script}\n")).expect("fake docker should be written");
        let mut perms = fs::metadata(&path)
            .expect("fake docker metadata")
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).expect("fake docker permissions");
        directory.as_os_str().to_owned()
    }

    fn passing_docker(directory: &std::path::Path) -> std::ffi::OsString {
        fake_docker(directory, "exit 0")
    }

    #[test]
    fn fresh_activation_writes_the_file_and_brings_the_stack_up() {
        let root = compose_root(None);
        let bin = tempfile::tempdir().expect("bin dir should be created");
        let docker_path = passing_docker(bin.path());

        let activation = activate(
            &root.trusted,
            &stack_name(),
            UPDATED,
            &HashGuard::Absent,
            SUFFIX,
            Some(&docker_path),
        )
        .expect("fresh activation should apply");

        assert_eq!(activation, Activation { activated: true });
        assert_eq!(root.live().as_deref(), Some(UPDATED));
        assert_eq!(root.entries(), vec!["docker-compose.yml".to_owned()]);
    }

    #[test]
    fn a_matching_hash_guard_replaces_the_previous_contents() {
        let root = compose_root(Some(PREVIOUS));
        let bin = tempfile::tempdir().expect("bin dir should be created");
        let docker_path = passing_docker(bin.path());

        let activation = activate(
            &root.trusted,
            &stack_name(),
            UPDATED,
            &guard_on(PREVIOUS),
            SUFFIX,
            Some(&docker_path),
        )
        .expect("an activation whose guard matches should apply");

        assert_eq!(activation, Activation { activated: true });
        assert_eq!(root.live().as_deref(), Some(UPDATED));
        assert_eq!(root.entries(), vec!["docker-compose.yml".to_owned()]);
    }

    #[test]
    fn a_stale_hash_guard_is_rejected_before_anything_is_written() {
        let root = compose_root(Some(PREVIOUS));
        let bin = tempfile::tempdir().expect("bin dir should be created");
        let docker_path = passing_docker(bin.path());

        let error = activate(
            &root.trusted,
            &stack_name(),
            UPDATED,
            &HashGuard::Sha256(ConfigHash::of(b"stale")),
            SUFFIX,
            Some(&docker_path),
        )
        .expect_err("a stale guard must not activate");

        assert!(matches!(error, Error::HashGuardMismatch));
        assert_eq!(root.live().as_deref(), Some(PREVIOUS));
    }

    #[test]
    fn validate_failure_leaves_the_live_file_untouched() {
        let root = compose_root(Some(PREVIOUS));
        let bin = tempfile::tempdir().expect("bin dir should be created");
        // `config` (validate) fails, `up` would succeed - only the first
        // invocation should ever run in this scenario.
        let docker_path = fake_docker(
            bin.path(),
            "case \"$*\" in *config*) exit 1;; *) exit 0;; esac",
        );

        let error = activate(
            &root.trusted,
            &stack_name(),
            UPDATED,
            &guard_on(PREVIOUS),
            SUFFIX,
            Some(&docker_path),
        )
        .expect_err("a rejected compose file must not activate");

        assert!(matches!(
            error,
            Error::ValidateFailed(ComposeFailure::Rejected(_))
        ));
        assert_eq!(root.live().as_deref(), Some(PREVIOUS));
        assert_eq!(root.entries(), vec!["docker-compose.yml".to_owned()]);
    }

    #[test]
    fn reload_failure_restores_and_brings_up_the_previous_file() {
        let root = compose_root(Some(PREVIOUS));
        let bin = tempfile::tempdir().expect("bin dir should be created");
        // `config` always succeeds; `up` fails exactly once (the first
        // attempt, for the new file), then succeeds (the restore's own
        // `up` of the restored previous file). Tracked via a marker file's
        // mere existence (`[ -e ... ]`/`>`, both shell builtins) rather than
        // a counter read back with `cat` - `cat` is an external binary, and
        // this fake `docker`'s `PATH` override points *only* at the fixture
        // directory (mirroring `compose::exec_inner`'s own `path_override`
        // semantics), so a script that shells out to anything not in that
        // directory silently fails and corrupts the very state it's trying
        // to track.
        let marker = bin.path().join("up-called-once");
        let script = format!(
            "case \"$*\" in *config*) exit 0 ;; *) if [ -e {0} ]; then exit 0; else : > {0}; exit 1; fi ;; esac",
            marker.display()
        );
        let docker_path = fake_docker(bin.path(), &script);

        let error = activate(
            &root.trusted,
            &stack_name(),
            UPDATED,
            &guard_on(PREVIOUS),
            SUFFIX,
            Some(&docker_path),
        )
        .expect_err("a stack that fails to come up must not stay on the new file");

        assert!(matches!(
            error,
            Error::ReloadFailedAndRestored(ComposeFailure::Rejected(_))
        ));
        assert_eq!(
            root.live().as_deref(),
            Some(PREVIOUS),
            "the exact previous file must be back"
        );
        assert_eq!(root.entries(), vec!["docker-compose.yml".to_owned()]);
    }

    #[test]
    fn a_reload_failure_after_restoring_reports_both_failures() {
        let root = compose_root(Some(PREVIOUS));
        let bin = tempfile::tempdir().expect("bin dir should be created");
        let docker_path = fake_docker(
            bin.path(),
            "case \"$*\" in *config*) exit 0;; *) exit 1;; esac",
        );

        let error = activate(
            &root.trusted,
            &stack_name(),
            UPDATED,
            &guard_on(PREVIOUS),
            SUFFIX,
            Some(&docker_path),
        )
        .expect_err("a stack that never comes up must be reported");

        let Error::RecoveryFailed { reload, restore } = error else {
            panic!("expected a recovery failure, got {error:?}")
        };
        assert!(matches!(reload, ComposeFailure::Rejected(_)));
        assert!(matches!(
            restore,
            RestoreFailure::Reload(ComposeFailure::Rejected(_))
        ));
        assert_eq!(root.live().as_deref(), Some(PREVIOUS));
    }

    #[test]
    fn identical_content_skips_the_write_but_still_brings_up() {
        let root = compose_root(Some(PREVIOUS));
        let bin = tempfile::tempdir().expect("bin dir should be created");
        let docker_path = passing_docker(bin.path());

        let activation = activate(
            &root.trusted,
            &stack_name(),
            PREVIOUS,
            &guard_on(PREVIOUS),
            SUFFIX,
            Some(&docker_path),
        )
        .expect("re-submitting the current contents should succeed");

        assert_eq!(activation, Activation { activated: false });
        assert_eq!(root.live().as_deref(), Some(PREVIOUS));
    }
}
