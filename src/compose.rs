//! `docker compose exec` primitive for the single WCP-managed stack.
//!
//! Ported from `website-control-panel`'s shell-string invocation
//! (`src-tauri/src/commands/runtime_pool.rs`'s `compose_prefix()`, joined
//! with `cd {STACK_REMOTE_BASE} &&` at each call site) to the argv-only
//! form `process::run` (`src/process.rs`) requires: no shell, no
//! string-built command, an explicit working directory via
//! `ProcessRequest::current_dir` instead of a `cd &&` prefix.

use std::{
    env,
    path::{Path, PathBuf},
    time::Duration,
};

use crate::process::{
    CancellationToken, ProcessLimits, ProcessOutput, ProcessRequest, ProcessRunError, run,
};

/// Stable Compose project identity for the one WCP-managed stack. Mirrors
/// `website-control-panel`'s `STACK_COMPOSE_PROJECT` constant
/// (`src-tauri/src/commands/mod.rs`) verbatim, so both codebases address
/// the same Compose project/network instead of Compose silently creating a
/// second one for the same stack.
pub const COMPOSE_PROJECT: &str = "wcp";

/// Compose stack directory, relative to the invoking user's home. Mirrors
/// `website-control-panel`'s `STACK_REMOTE_BASE` constant verbatim. `~` is
/// not expanded by any subprocess here (there is no shell to do it) — call
/// `compose_base_dir` to resolve it to an absolute path first.
pub const COMPOSE_BASE_DIR: &str = "~/compose/wp-stack";

/// `COMPOSE_BASE_DIR` with its leading `~/` stripped, joined onto a
/// resolved home directory by `compose_base_dir`.
const COMPOSE_BASE_DIR_SUFFIX: &str = "compose/wp-stack";

/// A `caddy validate`/`reload` call run through this primitive has no
/// reason to need longer than `process.rs`'s own existing default timeout
/// — both are local, in-container operations against a config file already
/// on disk. If a future caller finds a real Compose operation that needs
/// more than 30s, that caller should pass its own bound rather than this
/// default growing to cover it.
const TIMEOUT: Duration = Duration::from_secs(30);
const MAX_OUTPUT_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub enum Error {
    /// Neither `$HOME` nor a passwd lookup for this process's own effective
    /// user could produce a home directory to resolve `COMPOSE_BASE_DIR`
    /// against, and the caller did not supply an explicit `cwd`.
    NoHomeDirectory,
    Run(ProcessRunError),
}

/// Resolves the invoking user's home directory for expanding
/// `COMPOSE_BASE_DIR`'s leading `~/`.
///
/// This engine runs as root under `sudo` in production, so "the invoking
/// user's home" needs a real, non-guessed answer — hardcoding `/root`
/// would be wrong on any host where the engine runs under a different
/// account (a dedicated service user, `sudo -u`, etc.), and would also be
/// wrong the moment `sudo`'s own `env_reset`/`always_set_home` policy
/// changes what `$HOME` this process inherits.
///
/// Resolution order:
/// 1. `$HOME`, if the environment provides a non-empty value. This is the
///    same value every other program this process spawns (`docker`
///    included) would see, so honoring it first keeps this resolution
///    consistent with whatever the invoking shell/session/service unit
///    already set up — including the common case where an operator
///    deliberately overrides `HOME` to point Compose at a different stack
///    checkout.
/// 2. A passwd lookup (`getpwuid(getuid())`) for this process's own real
///    effective user, when `$HOME` is absent or empty (a minimal `env`
///    invocation, a systemd unit with no `Environment=HOME=...`, etc.).
///    This asks the OS directly for the same identity `~` would expand to
///    if a real shell resolved it for this uid, which is the closest
///    available approximation to "the invoking user's actual home
///    directory" without assuming any particular account name.
fn home_dir() -> Option<PathBuf> {
    match env::var("HOME") {
        Ok(home) if !home.is_empty() => Some(PathBuf::from(home)),
        _ => passwd_home_dir(),
    }
}

#[cfg(unix)]
fn passwd_home_dir() -> Option<PathBuf> {
    use std::ffi::CStr;

    // SAFETY: `getuid` takes no arguments, performs no pointer access, and
    // cannot fail.
    let uid = unsafe { libc::getuid() };
    // SAFETY: `getpwuid` is called with a valid `uid_t` and returns either
    // a null pointer or a pointer to a `libc::passwd` owned by libc's own
    // internal (thread-local-ish, reused-on-next-call) buffer. The pointer
    // is only dereferenced here, immediately, to copy `pw_dir` out as an
    // owned `PathBuf` before this function returns — it is never stored or
    // used after a subsequent call could invalidate it.
    let passwd = unsafe { libc::getpwuid(uid) };
    if passwd.is_null() {
        return None;
    }
    // SAFETY: a non-null `passwd` from `getpwuid` always has a non-null,
    // NUL-terminated `pw_dir` per POSIX.
    let pw_dir = unsafe { CStr::from_ptr((*passwd).pw_dir) };
    let dir = pw_dir.to_str().ok()?;
    if dir.is_empty() {
        None
    } else {
        Some(PathBuf::from(dir))
    }
}

#[cfg(not(unix))]
fn passwd_home_dir() -> Option<PathBuf> {
    None
}

/// Resolves `COMPOSE_BASE_DIR` to an absolute path using `home_dir`.
pub fn compose_base_dir() -> Result<PathBuf, Error> {
    home_dir()
        .map(|home| home.join(COMPOSE_BASE_DIR_SUFFIX))
        .ok_or(Error::NoHomeDirectory)
}

/// Runs `docker compose -p wcp --env-file .env -f stack/docker-compose.yml
/// exec -T <service> <args...>` through the bounded, argv-only
/// `process::run` — the shell-free equivalent of `website-control-panel`'s
/// `compose_prefix()` joined with `cd {STACK_REMOTE_BASE} &&` at each call
/// site.
///
/// `cwd` overrides the working directory the Compose invocation runs from;
/// pass `None` to use `compose_base_dir()`'s resolution of
/// `COMPOSE_BASE_DIR` against the invoking user's home. Callers that
/// already know the stack directory (or, in tests, want to bypass home-dir
/// resolution entirely) may pass it explicitly instead.
pub fn exec(service: &str, args: &[&str], cwd: Option<&Path>) -> Result<ProcessOutput, Error> {
    exec_inner(service, args, cwd, None)
}

/// Shared implementation behind `exec`. `path_override`, when set,
/// replaces `PATH` for this one child only (`ProcessRequest::env`, which
/// merges into — rather than mutating — this *process's* own inherited
/// environment). Production `exec` never sets it, so `docker` always
/// resolves against this process's real `PATH`; tests use it to point the
/// literal `docker` argv entry at a fixture directory without touching
/// process-global state, which would otherwise race every other test in
/// this binary that spawns a bareword-resolved subprocess concurrently.
fn exec_inner(
    service: &str,
    args: &[&str],
    cwd: Option<&Path>,
    path_override: Option<&std::ffi::OsStr>,
) -> Result<ProcessOutput, Error> {
    let resolved_cwd;
    let cwd = match cwd {
        Some(path) => path,
        None => {
            resolved_cwd = compose_base_dir()?;
            &resolved_cwd
        }
    };

    let mut argv: Vec<&str> = vec![
        "compose",
        "-p",
        COMPOSE_PROJECT,
        "--env-file",
        ".env",
        "-f",
        "stack/docker-compose.yml",
        "exec",
        "-T",
        service,
    ];
    argv.extend_from_slice(args);

    let limits = ProcessLimits {
        timeout: TIMEOUT,
        max_stdout_bytes: MAX_OUTPUT_BYTES,
        max_stderr_bytes: MAX_OUTPUT_BYTES,
    };
    let mut request = ProcessRequest::new("docker").args(argv).current_dir(cwd);
    if let Some(path) = path_override {
        request = request.env("PATH", path);
    }

    // `exec`'s signature (fixed by the task brief this module was built
    // against) does not thread a caller-supplied `CancellationToken`
    // through — every call gets a fresh, never-cancelled one. Compose
    // `exec` calls made through this primitive are short and bounded by
    // `TIMEOUT` regardless, but a caller that later needs to cancel one
    // mid-flight (e.g. wiring this up to the engine's own cancellation
    // mechanism) will need this signature extended first.
    run(&request, &limits, &CancellationToken::default()).map_err(Error::Run)
}

#[cfg(all(test, unix))]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::{COMPOSE_PROJECT, Error, exec_inner};
    use crate::process::{ProcessRunError, ProcessTermination};

    /// Writes a fake `docker` executable (`script` is its body, after the
    /// `#!/bin/sh` shebang line) into a fresh, dedicated temp directory
    /// and returns that directory. `exec_inner`'s `path_override` then
    /// points the literal `docker` argv entry at exactly this directory —
    /// a per-child `PATH` (`ProcessRequest::env`), never a mutation of
    /// this whole test process's own environment — so `Command::new
    /// ("docker")` resolves to the fixture instead of any real `docker` on
    /// this machine. Unlike mutating `std::env::set_var("PATH", ..)`
    /// directly, this is safe under Cargo's default parallel test
    /// execution: every test gets its own directory and its own
    /// unshared override, so nothing here can race another test's fake
    /// binary or starve an unrelated bareword-resolved subprocess (`git`,
    /// `id`, `printf`, ...) spawned concurrently elsewhere in this binary.
    /// Same fixture-script technique `tests/cli.rs`'s
    /// `doctor_is_deterministic_with_controlled_dependencies` and
    /// `tests/engine.rs` use to exercise the real subprocess path without a
    /// real target binary.
    fn fake_docker_dir(script: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("temp directory should be created");
        let path = dir.path().join("docker");
        fs::write(&path, format!("#!/bin/sh\n{script}\n")).expect("fake docker should be written");
        let mut permissions = fs::metadata(&path)
            .expect("fake docker metadata should exist")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).expect("fake docker should be executable");
        dir
    }

    #[test]
    fn builds_the_expected_compose_argv_and_reaches_the_fake_binary() {
        let fake_dir = fake_docker_dir("printf '%s\\n' \"$*\"");
        let cwd = tempfile::tempdir().expect("cwd should be created");

        let output = exec_inner(
            "caddy",
            &["caddy", "validate"],
            Some(cwd.path()),
            Some(fake_dir.path().as_os_str()),
        )
        .expect("fake docker should run");

        assert!(matches!(
            output.termination,
            ProcessTermination::Exited { success: true, .. }
        ));
        let stdout = String::from_utf8_lossy(&output.stdout.bytes);
        assert_eq!(
            stdout.trim(),
            format!(
                "compose -p {COMPOSE_PROJECT} --env-file .env -f stack/docker-compose.yml exec -T caddy caddy validate"
            )
        );
    }

    #[test]
    fn runs_with_the_requested_working_directory() {
        let fake_dir = fake_docker_dir("pwd");
        let cwd = tempfile::tempdir().expect("cwd should be created");
        let canonical = cwd.path().canonicalize().expect("cwd should canonicalize");

        let output = exec_inner(
            "caddy",
            &[],
            Some(&canonical),
            Some(fake_dir.path().as_os_str()),
        )
        .expect("fake docker should run");

        assert_eq!(
            String::from_utf8_lossy(&output.stdout.bytes).trim(),
            canonical.to_string_lossy()
        );
    }

    #[test]
    fn a_nonzero_exit_from_the_fake_binary_is_reported_as_a_failed_termination() {
        let fake_dir = fake_docker_dir("exit 3");
        let cwd = tempfile::tempdir().expect("cwd should be created");

        let output = exec_inner(
            "caddy",
            &["caddy", "reload"],
            Some(cwd.path()),
            Some(fake_dir.path().as_os_str()),
        )
        .expect("fake docker should run");

        assert_eq!(
            output.termination,
            ProcessTermination::Exited {
                code: Some(3),
                success: false,
            }
        );
    }

    #[test]
    fn a_missing_docker_binary_is_reported_as_a_spawn_error() {
        // The override points at an empty directory, so `Command::new
        // ("docker")`'s search of that (and only that) `PATH` cannot
        // resolve anything.
        let empty_dir = tempfile::tempdir().expect("empty directory should be created");
        let cwd = tempfile::tempdir().expect("cwd should be created");

        let result = exec_inner(
            "caddy",
            &[],
            Some(cwd.path()),
            Some(empty_dir.path().as_os_str()),
        );

        assert!(matches!(result, Err(Error::Run(ProcessRunError::Spawn(_)))));
    }

    /// Unlike the fake-`docker` tests above, `home_dir`/`compose_base_dir`
    /// read `$HOME` (a resource nothing else in this crate touches — see
    /// `grep -rn '"HOME"' src`), so mutating it is safe with respect to
    /// every other test in this binary. It is still process-global state,
    /// though, so calls to `with_home` below are serialized against each
    /// other via this lock to avoid two of *these* tests racing.
    static HOME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_home<T>(home: Option<&std::ffi::OsStr>, body: impl FnOnce() -> T) -> T {
        let _guard = HOME_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let original_home = std::env::var_os("HOME");
        // SAFETY: serialized by `HOME_LOCK` above.
        unsafe {
            match home {
                Some(home) => std::env::set_var("HOME", home),
                None => std::env::remove_var("HOME"),
            }
        }

        let result = body();

        // SAFETY: see above.
        unsafe {
            match &original_home {
                Some(home) => std::env::set_var("HOME", home),
                None => std::env::remove_var("HOME"),
            }
        }

        result
    }

    #[test]
    fn home_dir_prefers_a_nonempty_home_env_var() {
        let fake_home = tempfile::tempdir().expect("fake home should be created");

        let resolved = with_home(Some(fake_home.path().as_os_str()), super::home_dir);

        assert_eq!(resolved, Some(fake_home.path().to_path_buf()));
    }

    #[test]
    fn home_dir_falls_back_to_the_passwd_entry_when_home_is_unset_or_empty() {
        // No real home directory to assert an exact value against in a
        // sandboxed test environment, but this process's own `getpwuid`
        // lookup must still succeed and agree with itself, proving the
        // fallback path (not just `$HOME`) actually runs.
        let via_env_removed = with_home(None, super::home_dir);
        let via_env_empty = with_home(Some(std::ffi::OsStr::new("")), super::home_dir);
        let via_passwd_directly = super::passwd_home_dir();

        assert_eq!(via_env_removed, via_passwd_directly);
        assert_eq!(via_env_empty, via_passwd_directly);
        assert!(
            via_passwd_directly.is_some(),
            "this process's own uid should resolve to a home directory via getpwuid"
        );
    }

    #[test]
    fn compose_base_dir_joins_the_resolved_home_with_the_expected_suffix() {
        let fake_home = tempfile::tempdir().expect("fake home should be created");

        let resolved = with_home(Some(fake_home.path().as_os_str()), super::compose_base_dir)
            .expect("a resolvable home should yield a compose base dir");

        assert_eq!(resolved, fake_home.path().join("compose/wp-stack"));
    }
}
