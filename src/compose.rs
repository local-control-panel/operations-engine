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
    ffi::OsString,
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
    home_dir_inner(env::var_os("HOME"))
}

/// Core of `home_dir`, taking the `$HOME` value as an explicit parameter
/// (`None` for "absent") instead of reading the environment itself.
///
/// This split exists so tests can exercise both the "`$HOME` present" and
/// "`$HOME` absent/empty" branches by passing a value directly, rather
/// than mutating this whole process's real `$HOME` via
/// `std::env::set_var`/`remove_var` — both `unsafe` on this toolchain
/// precisely because mutating them concurrently with *any other thread's*
/// env reads is a data race, and Cargo runs every unit test in this
/// binary on multiple threads by default, including tests elsewhere that
/// read unrelated env vars (`PATH` in `process.rs`,
/// `MINISIGN_TEST_KEY_PASSWORD` in `engine/verify.rs`). `exec_inner`'s
/// `path_override` parameter (below) applies the same injection pattern
/// to `PATH`.
fn home_dir_inner(home: Option<OsString>) -> Option<PathBuf> {
    match home {
        Some(home) if !home.is_empty() => Some(PathBuf::from(home)),
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
    compose_base_dir_inner(home_dir())
}

/// Core of `compose_base_dir`, taking the already-resolved home directory
/// as an explicit parameter — same injection pattern as `home_dir_inner`,
/// so tests can exercise the join (and the `NoHomeDirectory` failure
/// path) without going through real env state at all.
fn compose_base_dir_inner(home: Option<PathBuf>) -> Result<PathBuf, Error> {
    home.map(|home| home.join(COMPOSE_BASE_DIR_SUFFIX))
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

/// How one caller reaches the Compose stack, as a value it can hold and
/// pass down instead of threading two optional parameters through every
/// intermediate function. `Access::default()` is the production
/// configuration in every case: the stack directory resolved from
/// `COMPOSE_BASE_DIR` against the invoking user's home, and `docker`
/// resolved against this process's own real `PATH`.
///
/// The two overrides exist for the same reason `exec_inner`'s parameters
/// do, and carry the same warning: `stack_dir` names a Compose project
/// checkout other than the resolved default, and `docker_path` replaces
/// `PATH` for the spawned child only (never this process's own
/// environment, so it is safe under parallel test execution). Tests use
/// them to drive `caddy validate`/`caddy reload` outcomes through a fake
/// `docker` fixture without a real Compose stack; nothing in production
/// should set either.
#[derive(Clone, Debug, Default)]
pub struct Access {
    stack_dir: Option<PathBuf>,
    docker_path: Option<OsString>,
}

impl Access {
    pub fn stack_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.stack_dir = Some(dir.into());
        self
    }

    pub fn docker_path(mut self, path: impl Into<OsString>) -> Self {
        self.docker_path = Some(path.into());
        self
    }

    /// Runs one `docker compose exec -T <service> <args...>` against this
    /// access's stack, exactly as the free `exec` function above does.
    pub fn exec(&self, service: &str, args: &[&str]) -> Result<ProcessOutput, Error> {
        exec_inner(
            service,
            args,
            self.stack_dir.as_deref(),
            self.docker_path.as_deref(),
        )
    }
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

/// Writes a fake `docker` executable (`script` is its body, after the
/// `#!/bin/sh` shebang line) into `directory`, which callers then point
/// `Access::docker_path`/`exec_inner`'s `path_override` at so
/// `Command::new("docker")` resolves to the fixture instead of any real
/// `docker` on this machine.
///
/// A per-child `PATH` (`ProcessRequest::env`), never a mutation of the
/// test process's own environment, so this is safe under Cargo's default
/// parallel test execution: every test gets its own directory and its own
/// unshared override, and nothing here can race another test's fake binary
/// or starve an unrelated bareword-resolved subprocess (`git`, `id`,
/// `printf`, ...) spawned concurrently elsewhere in this binary. Same
/// fixture-script technique `tests/cli.rs`'s
/// `doctor_is_deterministic_with_controlled_dependencies` and
/// `tests/engine.rs` use to exercise the real subprocess path without a
/// real target binary.
///
/// `pub(crate)` rather than private to this module's tests because
/// `ingress::activate`'s tests drive `caddy validate`/`caddy reload`
/// outcomes through exactly this fixture.
#[cfg(all(test, unix))]
pub(crate) fn write_fake_docker(directory: &std::path::Path, script: &str) {
    use std::{fs, os::unix::fs::PermissionsExt};

    let path = directory.join("docker");
    fs::write(&path, format!("#!/bin/sh\n{script}\n")).expect("fake docker should be written");
    let mut permissions = fs::metadata(&path)
        .expect("fake docker metadata should exist")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions).expect("fake docker should be executable");
}

#[cfg(all(test, unix))]
mod tests {
    use super::{COMPOSE_PROJECT, Error, exec_inner, write_fake_docker};
    use crate::process::{ProcessRunError, ProcessTermination};

    /// `write_fake_docker` into a fresh, dedicated temp directory, which
    /// is returned. `exec_inner`'s `path_override` then points the literal
    /// `docker` argv entry at exactly this directory, so
    /// `Command::new("docker")` resolves to the fixture instead of any
    /// real `docker` on this machine.
    fn fake_docker_dir(script: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("temp directory should be created");
        write_fake_docker(dir.path(), script);
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

    /// `home_dir`/`compose_base_dir` are exercised through their `_inner`
    /// cores below, passing the `$HOME` value (or resolved home
    /// directory) as an explicit argument rather than mutating this
    /// process's real environment — see `home_dir_inner`'s doc comment
    /// for why. No lock, no `unsafe`, and no risk of racing any other
    /// test in this binary.
    #[test]
    fn home_dir_prefers_a_nonempty_home_env_var() {
        let fake_home = tempfile::tempdir().expect("fake home should be created");

        let resolved = super::home_dir_inner(Some(fake_home.path().as_os_str().to_owned()));

        assert_eq!(resolved, Some(fake_home.path().to_path_buf()));
    }

    #[test]
    fn home_dir_falls_back_to_the_passwd_entry_when_home_is_unset_or_empty() {
        // No real home directory to assert an exact value against in a
        // sandboxed test environment, but this process's own `getpwuid`
        // lookup must still succeed and agree with itself, proving the
        // fallback path (not just `$HOME`) actually runs.
        let via_none = super::home_dir_inner(None);
        let via_empty = super::home_dir_inner(Some(std::ffi::OsString::new()));
        let via_passwd_directly = super::passwd_home_dir();

        assert_eq!(via_none, via_passwd_directly);
        assert_eq!(via_empty, via_passwd_directly);
        assert!(
            via_passwd_directly.is_some(),
            "this process's own uid should resolve to a home directory via getpwuid"
        );
    }

    #[test]
    fn compose_base_dir_joins_the_resolved_home_with_the_expected_suffix() {
        let fake_home = tempfile::tempdir().expect("fake home should be created");

        let resolved = super::compose_base_dir_inner(Some(fake_home.path().to_path_buf()))
            .expect("a resolvable home should yield a compose base dir");

        assert_eq!(resolved, fake_home.path().join("compose/wp-stack"));
    }

    #[test]
    fn compose_base_dir_fails_closed_when_no_home_is_resolvable() {
        assert!(matches!(
            super::compose_base_dir_inner(None),
            Err(Error::NoHomeDirectory)
        ));
    }
}
