//! Black-box, end-to-end tests for `ingress::execute::execute` — the
//! `ingress.activateConfig` operation — driven entirely through the
//! crate's public surface (`operations_engine::ingress::*`,
//! `operations_engine::compose::Access`), the same way `tests/deploy.rs`,
//! `tests/rollback.rs`, and `tests/engine.rs` exercise their own
//! operations from outside the crate.
//!
//! `src/ingress/activate.rs` and `execute.rs` already carry ~28 white-box
//! unit tests covering every branch of the activation sequence using
//! `crate::ingress::fake_docker::FakeDocker`, a `pub(crate)` fixture that
//! is unreachable from here — this file is not trying to rediscover those
//! bugs. What it proves instead is that the same six properties
//! (fresh activation, matching-hash update, stale-hash rejection,
//! validate failure, reload failure with restore, and a failed restore
//! reporting both halves) still hold through the real public contract:
//! `ActivateContext`, `ActivateConfigRequest`, `HashGuard`, `execute`, and
//! `ActivateConfigResult`. A bug where the public API failed to expose
//! what the internal implementation does correctly would show up here,
//! not in the white-box suite.
//!
//! No real Docker Compose or Caddy is involved — a fake `docker` reachable
//! through `compose::Access::docker_path`'s `PATH` override (both public
//! builder methods) stands in, using the identical
//! write-a-shell-script-and-`chmod`-it technique `compose::write_fake_docker`
//! uses internally (that helper itself is `pub(crate)` and so is
//! reimplemented here). Proving this against the real stack is Task 6's
//! job.

#![cfg(unix)]

use std::fs;

use operations_engine::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    ingress::{
        ActivateConfigRequest, ActivateConfigResult, ConfigHash, HashGuard,
        activate::{ComposeFailure, RestoreFailure},
        execute::{ActivateConfigError, ActivateContext, execute},
    },
    process::CancellationToken,
    site::TrustedRoot,
};

const DOMAIN: &str = "example.com";
const ROUTE: &str = "example.com.caddyfile";
const REQUEST_ID_1: &str = "123e4567-e89b-12d3-a456-426614174000";
const REQUEST_ID_2: &str = "9b2f1c34-5678-4abc-9def-0123456789ab";
const PREVIOUS: &str = "example.com {\n  basicauth {\n  }\n}\n";
const UPDATED: &str = "example.com {\n}\n";

/// A fake `docker` reachable through `compose::Access::docker_path`,
/// built with the same "write a `#!/bin/sh` script, chmod it executable"
/// technique `compose::write_fake_docker`/`ingress::fake_docker::FakeDocker`
/// use internally — reimplemented here because both are `pub(crate)` and
/// therefore invisible to a real integration-test crate. It records every
/// `caddy validate`/`caddy reload` invocation and can be told to fail
/// either one, a fixed number of times or forever.
struct FakeDocker {
    dir: tempfile::TempDir,
}

impl FakeDocker {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("fake docker directory should be created");
        fs::create_dir(dir.path().join("bin")).expect("bin directory should be created");
        fs::create_dir(dir.path().join("control")).expect("control directory should be created");
        let control = dir.path().join("control");
        let script = format!(
            r#"#!/bin/sh
mode=unknown
for arg in "$@"; do
  case "$arg" in
validate) mode=validate ;;
reload) mode=reload ;;
  esac
done
control='{control}'
printf '%s\n' "$*" >> "$control/$mode.calls"
count=0
while read -r _line; do count=$((count+1)); done < "$control/$mode.calls"
if [ -f "$control/fail-$mode" ]; then
  read -r limit < "$control/fail-$mode"
  if [ "$limit" = all ] || [ "$count" -le "$limit" ]; then
printf 'simulated %s failure\n' "$mode" >&2
exit 1
  fi
fi
exit 0
"#,
            control = control.display()
        );
        let docker_path = dir.path().join("bin").join("docker");
        fs::write(&docker_path, script).expect("fake docker should be written");
        set_executable(&docker_path);
        Self { dir }
    }

    /// Fails the next `times` calls of `mode` (`"all"` for every call from
    /// now on).
    fn failing(self, mode: &str, times: &str) -> Self {
        fs::write(
            self.dir.path().join(format!("control/fail-{mode}")),
            format!("{times}\n"),
        )
        .expect("control file should be written");
        self
    }

    fn access(&self) -> operations_engine::compose::Access {
        operations_engine::compose::Access::default()
            // The fake `docker` never reads a Compose file, so any
            // existing directory works as the stack directory — real
            // resolution of the stack path is `compose.rs`'s own tested
            // concern, not this operation's.
            .stack_dir(self.dir.path())
            .docker_path(self.dir.path().join("bin"))
    }

    fn calls(&self, mode: &str) -> Vec<String> {
        match fs::read_to_string(self.dir.path().join(format!("control/{mode}.calls"))) {
            Ok(log) => log.lines().map(str::to_owned).collect(),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(unix)]
fn set_executable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)
        .expect("fake docker metadata should exist")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("fake docker should be executable");
}

/// The ingress root and the engine-wide state root, as separate real
/// directories — the same separation `EngineConfig` enforces in
/// production, and the same shape `src/ingress/execute.rs`'s own `Host`
/// fixture uses.
struct Host {
    ingress_dir: tempfile::TempDir,
    state_dir: tempfile::TempDir,
    ingress_root: TrustedRoot,
    engine_state: ManagedRoot,
}

fn host(existing: Option<&str>) -> Host {
    let ingress_dir = tempfile::tempdir().expect("ingress root should be created");
    let state_dir = tempfile::tempdir().expect("state root should be created");
    if let Some(contents) = existing {
        fs::write(ingress_dir.path().join(ROUTE), contents)
            .expect("existing route file should be written");
    }
    let ingress_root =
        TrustedRoot::parse(ingress_dir.path()).expect("ingress root should be valid");
    let engine_state = ManagedRoot::open(
        &TrustedRoot::parse(state_dir.path()).expect("state root should be valid"),
    )
    .expect("state root should open");
    Host {
        ingress_dir,
        state_dir,
        ingress_root,
        engine_state,
    }
}

impl Host {
    fn live(&self) -> Option<String> {
        fs::read_to_string(self.ingress_dir.path().join(ROUTE)).ok()
    }

    /// Every entry left in the ingress root, so a test can assert no
    /// `.tmp`/`.rollback-*` sibling leaked out of a failed attempt.
    fn entries(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.ingress_dir.path())
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

    fn transaction(&self, request_id: &str) -> serde_json::Value {
        let path = self
            .state_dir
            .path()
            .join(format!("ingress/transactions/{request_id}.json"));
        serde_json::from_str(&fs::read_to_string(path).expect("transaction record should exist"))
            .expect("transaction record should be JSON")
    }
}

fn request(guard: HashGuard, request_id: &str) -> ActivateConfigRequest {
    ActivateConfigRequest::parse(DOMAIN, UPDATED, guard, request_id, None)
        .expect("request should parse")
}

fn guard_on(contents: &str) -> HashGuard {
    HashGuard::Sha256(ConfigHash::of(contents.as_bytes()))
}

fn run(
    host: &Host,
    docker: &FakeDocker,
    request: &ActivateConfigRequest,
) -> Result<ActivateConfigResult, ActivateConfigError> {
    let access = docker.access();
    let context = ActivateContext {
        ingress_root: &host.ingress_root,
        engine_state: &host.engine_state,
        compose: &access,
    };
    execute(&context, request, &CancellationToken::default())
}

#[test]
fn a_fresh_activation_writes_the_route_file_and_reports_it_activated() {
    let host = host(None);
    let docker = FakeDocker::new();

    let result = run(&host, &docker, &request(HashGuard::Absent, REQUEST_ID_1))
        .expect("a fresh activation with no live file should succeed");

    assert!(result.activated);
    assert_eq!(result.domain, DOMAIN);
    assert_eq!(result.content_sha256, ConfigHash::of(UPDATED.as_bytes()));
    assert_eq!(host.live().as_deref(), Some(UPDATED));
    assert_eq!(host.entries(), vec![ROUTE.to_owned()]);
    assert_eq!(docker.calls("validate").len(), 1);
    assert_eq!(docker.calls("reload").len(), 1);
    assert_eq!(host.transaction(REQUEST_ID_1)["status"], "COMMITTED");
}

#[test]
fn a_matching_hash_guard_replaces_the_previous_live_content() {
    let host = host(Some(PREVIOUS));
    let docker = FakeDocker::new();

    let result = run(&host, &docker, &request(guard_on(PREVIOUS), REQUEST_ID_1))
        .expect("an activation whose guard matches the live file should succeed");

    assert!(result.activated);
    assert_eq!(host.live().as_deref(), Some(UPDATED));
    // No `.rollback-*` sibling survives a successful activation.
    assert_eq!(host.entries(), vec![ROUTE.to_owned()]);
}

#[test]
fn a_stale_hash_guard_is_rejected_and_the_previous_file_stays_live() {
    let host = host(Some(PREVIOUS));
    let docker = FakeDocker::new();
    let stale = HashGuard::Sha256(ConfigHash::of(b"read before someone else wrote"));

    let error = run(&host, &docker, &request(stale, REQUEST_ID_1))
        .expect_err("a guard that does not match the live file must be rejected");

    assert_eq!(error.protocol().0, ErrorCode::ConfigHashMismatch);
    assert_eq!(host.live().as_deref(), Some(PREVIOUS));
    assert_eq!(host.entries(), vec![ROUTE.to_owned()]);
    // Fail closed, before any container call is made.
    assert!(docker.calls("validate").is_empty());
    assert!(docker.calls("reload").is_empty());
    assert_eq!(
        host.transaction(REQUEST_ID_1)["outcome"]["errorCode"],
        "CONFIG_HASH_MISMATCH"
    );
}

#[test]
fn a_validate_failure_is_rejected_and_the_live_file_is_never_touched() {
    let host = host(Some(PREVIOUS));
    let docker = FakeDocker::new().failing("validate", "all");

    let error = run(&host, &docker, &request(guard_on(PREVIOUS), REQUEST_ID_1))
        .expect_err("a config the validator rejects must not activate");

    assert_eq!(error.protocol().0, ErrorCode::ConfigValidationFailed);
    assert!(matches!(
        error,
        ActivateConfigError::Activate(operations_engine::ingress::activate::Error::ValidateFailed(
            ComposeFailure::Rejected(_)
        ))
    ));
    assert_eq!(host.live().as_deref(), Some(PREVIOUS));
    // The staged `.tmp` sibling is cleaned up and no reload was attempted.
    assert_eq!(host.entries(), vec![ROUTE.to_owned()]);
    assert!(docker.calls("reload").is_empty());
}

#[test]
fn a_reload_failure_restores_and_reloads_the_previous_file() {
    let host = host(Some(PREVIOUS));
    // Only the first reload (for the new config) fails; the second, for
    // the restored previous file, succeeds.
    let docker = FakeDocker::new().failing("reload", "1");

    let error = run(&host, &docker, &request(guard_on(PREVIOUS), REQUEST_ID_1))
        .expect_err("a config the server refuses to load must not stay live");

    assert_eq!(error.protocol().0, ErrorCode::ConfigReloadFailed);
    assert_eq!(
        host.live().as_deref(),
        Some(PREVIOUS),
        "the exact previous file must be restored"
    );
    assert_eq!(host.entries(), vec![ROUTE.to_owned()]);
    assert_eq!(
        docker.calls("reload").len(),
        2,
        "the restored file must itself be reloaded, not just written back"
    );
    assert_eq!(
        host.transaction(REQUEST_ID_1)["outcome"]["errorCode"],
        "CONFIG_RELOAD_FAILED"
    );
}

#[test]
fn a_failed_restore_reload_reports_both_failures_with_its_own_code() {
    let host = host(Some(PREVIOUS));
    let docker = FakeDocker::new().failing("reload", "all");

    let error = run(&host, &docker, &request(guard_on(PREVIOUS), REQUEST_ID_2))
        .expect_err("an unrecoverable reload failure must be reported");

    assert_eq!(error.protocol().0, ErrorCode::ConfigRecoveryFailed);
    let (reload, restore) = error
        .recovery_failure()
        .expect("a recovery failure must expose both halves");
    assert!(matches!(reload, ComposeFailure::Rejected(_)));
    assert!(matches!(
        restore,
        RestoreFailure::Reload(ComposeFailure::Rejected(_))
    ));
    // The file itself was still put back — it is the *reload* of it that
    // failed, not the restore write.
    assert_eq!(host.live().as_deref(), Some(PREVIOUS));
    assert_eq!(host.entries(), vec![ROUTE.to_owned()]);
    assert_eq!(docker.calls("reload").len(), 2);
    assert_eq!(
        host.transaction(REQUEST_ID_2)["outcome"]["errorCode"],
        "CONFIG_RECOVERY_FAILED"
    );
}
