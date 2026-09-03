//! End-to-end tests for `engine::install::execute` and
//! `engine::rollback::execute`, run for real against a local fixture
//! HTTP server (no mocking of `ureq`) and real temp-directory roots
//! standing in for `/usr/local/bin` and the state root. Mirrors
//! `tests/deploy.rs`/`tests/rollback.rs`'s style of calling the
//! orchestration function directly rather than through the CLI.

use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpListener},
};

use operations_engine::{
    engine::{
        EngineInstallRequest, EngineRollbackRequest,
        install::{InstallContext, InstallError, execute as execute_install},
        release,
        rollback::{RollbackContext, RollbackError, execute as execute_rollback},
        state,
    },
    filesystem::ManagedRoot,
    process::CancellationToken,
    site::TrustedRoot,
};

const REQUEST_ID_1: &str = "123e4567-e89b-12d3-a456-426614174000";
const REQUEST_ID_2: &str = "9b2f1c34-5678-4abc-9def-0123456789ab";
/// The publishable fixture versions, newest first — every one of
/// them a real, correctly signed release in `tests/fixtures/engine`.
const VERSION: &str = "9.9.9";
const PREVIOUS_VERSION: &str = "9.9.8";
/// Published and signed exactly like the others, but not a runnable
/// program — the "verifies but will not start on this host" case.
const BROKEN_VERSION: &str = "9.9.6";
/// Published and signed as `9.9.5`, but reports some other version when
/// asked — a mis-tagged release.
const MISREPORTING_VERSION: &str = "9.9.5";

/// Serves the fixture files for the versions a test publishes (and, for
/// the corrupted-artifact test, a caller-substituted binary) from a
/// background thread, one request at a time — sufficient for this test's
/// handful of sequential requests. The
/// listener is dropped (and the thread's `accept` loop ends) when the
/// test function returns.
struct FixtureServer {
    base_url: String,
}

fn start_fixture_server(routes: HashMap<String, Vec<u8>>) -> FixtureServer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let addr: SocketAddr = listener
        .local_addr()
        .expect("listener should have an address");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().expect("stream should clone"));
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
                continue;
            }
            let path = request_line
                .split_whitespace()
                .nth(1)
                .unwrap_or("/")
                .trim_start_matches('/')
                .to_owned();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() || line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            match routes.get(path.as_str()) {
                Some(body) => {
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(header.as_bytes());
                    let _ = stream.write_all(body);
                }
                None => {
                    let _ = stream.write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                }
            }
        }
    });
    FixtureServer {
        base_url: format!("http://{addr}"),
    }
}

/// The release asset name for `version` on *this* test host's
/// architecture — `release::target_triple` maps from
/// `std::env::consts::ARCH` alone (not the host OS), so this differs
/// between an x86_64 and an aarch64 machine even though every fixture
/// binary was generated on this repo's own (non-Linux) dev machines.
/// `tests/fixtures/engine/` carries one per (version, architecture), all
/// covered by the one signed `SHA256SUMS`, so the fixture server can
/// serve whichever one this host's build of `install::execute` will
/// actually request. Each has distinguishable content, so an assertion on
/// installed bytes pins down both the version and the architecture.
fn fixture_asset_name(version: &str) -> String {
    let version = release::EngineVersion::parse(version).expect("literal version is valid");
    let target_triple = release::target_triple()
        .expect("this test host's architecture must be one release::target_triple supports");
    release::binary_asset_name(&version, target_triple)
}

fn fixture_bytes(version: &str) -> Vec<u8> {
    std::fs::read(format!(
        "tests/fixtures/engine/{}",
        fixture_asset_name(version)
    ))
    .expect("fixture binary for this host's architecture should exist — see regenerate.sh")
}

/// Routes for one or more published versions. Every version's manifest
/// route serves the same signed `SHA256SUMS`, exactly as `verify.rs`
/// expects: it covers every fixture asset at once, and the parser picks
/// only the line naming the asset it is about to fetch.
fn fixture_routes(versions: &[&str]) -> HashMap<String, Vec<u8>> {
    let manifest =
        std::fs::read("tests/fixtures/engine/SHA256SUMS").expect("fixture manifest should exist");
    let signature = std::fs::read("tests/fixtures/engine/SHA256SUMS.minisig")
        .expect("fixture signature should exist");
    let mut routes = HashMap::new();
    for version in versions {
        routes.insert(format!("v{version}/SHA256SUMS"), manifest.clone());
        routes.insert(format!("v{version}/SHA256SUMS.minisig"), signature.clone());
        routes.insert(
            format!("v{version}/{}", fixture_asset_name(version)),
            fixture_bytes(version),
        );
    }
    routes
}

/// The same routes, but with `VERSION`'s binary replaced by bytes that no
/// longer match the signed checksum.
fn fixture_routes_with_corrupted_binary() -> HashMap<String, Vec<u8>> {
    let mut routes = fixture_routes(&[VERSION]);
    routes.insert(
        format!("v{VERSION}/{}", fixture_asset_name(VERSION)),
        b"corrupted, wrong bytes".to_vec(),
    );
    routes
}

fn roots() -> (
    tempfile::TempDir,
    tempfile::TempDir,
    TrustedRoot,
    TrustedRoot,
    ManagedRoot,
) {
    let bin_dir = tempfile::tempdir().expect("bin directory should exist");
    let state_dir = tempfile::tempdir().expect("state directory should exist");
    let bin_root = TrustedRoot::parse(bin_dir.path()).expect("bin root should be valid");
    let state_root = TrustedRoot::parse(state_dir.path()).expect("state root should be valid");
    let engine_state = ManagedRoot::open(&state_root).expect("state root should open");
    (bin_dir, state_dir, bin_root, state_root, engine_state)
}

/// `install::execute`/`rollback::execute` both narrow the broad
/// `engine_state` root passed in via `InstallContext`/`RollbackContext`
/// down to its `engine/` subtree (`state::open_engine_state`) before
/// calling `state::load`/`state::save` — so a test that wants to read or
/// seed the same `install.state` file those calls act on must scope down
/// the same way, not call `state::load`/`state::save` on the broad root
/// directly.
fn scoped_state(engine_state: &ManagedRoot) -> ManagedRoot {
    state::open_engine_state(engine_state).expect("engine state should open")
}

#[test]
fn a_fresh_install_activates_the_verified_binary() {
    let server = start_fixture_server(fixture_routes(&[VERSION]));
    let (bin_dir, _state_dir, bin_root, state_root, engine_state) = roots();
    let context = InstallContext {
        bin_root: &bin_root,
        engine_state: &engine_state,
        state_root: &state_root,
        release_base_url: &server.base_url,
    };
    let request =
        EngineInstallRequest::parse(VERSION, REQUEST_ID_1, None).expect("request should parse");

    let result = execute_install(&context, &request, &CancellationToken::default())
        .expect("install should succeed");

    assert_eq!(result.version, VERSION);
    assert_eq!(result.previous_version, None);
    assert_eq!(
        std::fs::read(bin_dir.path().join("ops-engine")).unwrap(),
        fixture_bytes(VERSION)
    );

    let saved = state::load(&scoped_state(&engine_state))
        .unwrap()
        .expect("install state should be recorded");
    assert_eq!(saved.active_version, VERSION);
    assert_eq!(saved.previous_version, None);
}

#[test]
fn installing_the_same_version_twice_is_rejected_as_already_active() {
    let server = start_fixture_server(fixture_routes(&[VERSION]));
    let (_bin_dir, _state_dir, bin_root, state_root, engine_state) = roots();
    let context = InstallContext {
        bin_root: &bin_root,
        engine_state: &engine_state,
        state_root: &state_root,
        release_base_url: &server.base_url,
    };
    let first =
        EngineInstallRequest::parse(VERSION, REQUEST_ID_1, None).expect("request should parse");
    execute_install(&context, &first, &CancellationToken::default())
        .expect("first install should succeed");

    let second =
        EngineInstallRequest::parse(VERSION, REQUEST_ID_2, None).expect("request should parse");
    let error = execute_install(&context, &second, &CancellationToken::default()).unwrap_err();
    assert!(matches!(error, InstallError::AlreadyActive));
}

#[test]
fn a_corrupted_artifact_is_rejected_and_leaves_the_filesystem_untouched() {
    let server = start_fixture_server(fixture_routes_with_corrupted_binary());
    let (bin_dir, _state_dir, bin_root, state_root, engine_state) = roots();
    let context = InstallContext {
        bin_root: &bin_root,
        engine_state: &engine_state,
        state_root: &state_root,
        release_base_url: &server.base_url,
    };
    let request =
        EngineInstallRequest::parse(VERSION, REQUEST_ID_1, None).expect("request should parse");

    let error = execute_install(&context, &request, &CancellationToken::default()).unwrap_err();
    assert!(matches!(error, InstallError::ChecksumMismatch));
    assert!(!bin_dir.path().join("ops-engine").exists());
    assert_eq!(state::load(&scoped_state(&engine_state)).unwrap(), None);
}

#[test]
fn rollback_after_an_install_restores_the_previous_binary_and_can_roll_forward_again() {
    let (bin_dir, _state_dir, bin_root, _state_root, engine_state) = roots();

    // This test targets `rollback::execute` in isolation — installing's
    // own fetch/verify/stage path is already covered by
    // `a_fresh_install_activates_the_verified_binary`. Seed an
    // already-installed active/previous pair directly (both the
    // `install.state` record and the two retained binaries under
    // `versions/`) rather than driving two real HTTP-backed installs.
    let scoped = scoped_state(&engine_state);
    state::save(
        &scoped,
        &state::InstallState {
            active_version: "9.9.9".to_owned(),
            previous_version: Some("9.9.8".to_owned()),
        },
    )
    .expect("seeded install state should save");
    // Seed both retained binaries directly (this test targets rollback,
    // not install — `a_fresh_install_activates_the_verified_binary`
    // already covers install's own staging).
    for (version, content) in [
        ("9.9.9", b"nine binary".to_vec()),
        ("9.9.8", b"eight binary".to_vec()),
    ] {
        let dir = operations_engine::site::SiteRelativePath::parse(format!("versions/{version}"))
            .unwrap();
        let path = operations_engine::site::SiteRelativePath::parse(format!(
            "versions/{version}/ops-engine"
        ))
        .unwrap();
        scoped.create_dir_all(&dir).unwrap();
        scoped.write_new_executable(&path, &content).unwrap();
    }

    let rollback_context = RollbackContext {
        bin_root: &bin_root,
        engine_state: &engine_state,
    };
    let rollback_request =
        EngineRollbackRequest::parse(REQUEST_ID_1, None).expect("request should parse");
    let result = execute_rollback(
        &rollback_context,
        &rollback_request,
        &CancellationToken::default(),
    )
    .expect("rollback should succeed");

    assert_eq!(result.version, "9.9.8");
    assert_eq!(result.previous_version, "9.9.9");
    assert_eq!(
        std::fs::read(bin_dir.path().join("ops-engine")).unwrap(),
        b"eight binary"
    );
    let after_rollback = state::load(&scoped).unwrap().unwrap();
    assert_eq!(after_rollback.active_version, "9.9.8");
    assert_eq!(after_rollback.previous_version, Some("9.9.9".to_owned()));

    // Roll forward again — proves the source version was not
    // invalidated by the first rollback.
    let roll_forward_request =
        EngineRollbackRequest::parse(REQUEST_ID_2, None).expect("request should parse");
    let result = execute_rollback(
        &rollback_context,
        &roll_forward_request,
        &CancellationToken::default(),
    )
    .expect("second rollback should succeed");
    assert_eq!(result.version, "9.9.9");
    assert_eq!(
        std::fs::read(bin_dir.path().join("ops-engine")).unwrap(),
        b"nine binary"
    );
}

#[test]
fn rollback_with_no_retained_previous_version_fails_closed() {
    let (bin_dir, _state_dir, bin_root, _state_root, engine_state) = roots();
    let context = RollbackContext {
        bin_root: &bin_root,
        engine_state: &engine_state,
    };
    let request = EngineRollbackRequest::parse(REQUEST_ID_1, None).expect("request should parse");

    let error = execute_rollback(&context, &request, &CancellationToken::default()).unwrap_err();
    assert!(matches!(error, RollbackError::NoPreviousVersion));
    assert!(!bin_dir.path().join("ops-engine").exists());
}

#[test]
fn a_verified_binary_that_will_not_run_here_is_rejected_before_activation() {
    // `BROKEN_VERSION`'s fixture is correctly published and correctly
    // signed — it just is not a runnable program (see regenerate.sh).
    // That is the glibc-mismatch case in miniature: everything
    // cryptographic passes, and the binary still cannot start. Nothing
    // may be activated, because `engine rollback` would be that same
    // binary.
    let server = start_fixture_server(fixture_routes(&[BROKEN_VERSION]));
    let (bin_dir, _state_dir, bin_root, state_root, engine_state) = roots();
    let context = InstallContext {
        bin_root: &bin_root,
        engine_state: &engine_state,
        state_root: &state_root,
        release_base_url: &server.base_url,
    };
    let request = EngineInstallRequest::parse(BROKEN_VERSION, REQUEST_ID_1, None)
        .expect("request should parse");

    let error = execute_install(&context, &request, &CancellationToken::default()).unwrap_err();
    assert!(
        matches!(error, InstallError::NotRunnable(_)),
        "expected the staged binary to fail its smoke test, got {error:?}"
    );
    assert!(!bin_dir.path().join("ops-engine").exists());
    assert_eq!(state::load(&scoped_state(&engine_state)).unwrap(), None);
}

#[test]
fn a_binary_that_reports_a_different_version_is_rejected_before_activation() {
    // `MISREPORTING_VERSION`'s fixture runs and answers `version`, but
    // names a different version than the one it was published as — a
    // mis-tagged release. Installing it would leave `install.state`, the
    // published release, and the binary's own `version` output
    // disagreeing about what is on the host.
    let server = start_fixture_server(fixture_routes(&[MISREPORTING_VERSION]));
    let (bin_dir, _state_dir, bin_root, state_root, engine_state) = roots();
    let context = InstallContext {
        bin_root: &bin_root,
        engine_state: &engine_state,
        state_root: &state_root,
        release_base_url: &server.base_url,
    };
    let request = EngineInstallRequest::parse(MISREPORTING_VERSION, REQUEST_ID_1, None)
        .expect("request should parse");

    let error = execute_install(&context, &request, &CancellationToken::default()).unwrap_err();
    assert!(
        matches!(error, InstallError::VersionMismatch),
        "expected a version mismatch, got {error:?}"
    );
    assert!(!bin_dir.path().join("ops-engine").exists());
}

/// Writes `content` to `bin_dir/ops-engine` with the executable bit set,
/// standing in for a binary that was already on the host before this
/// engine ever managed it.
fn seed_unmanaged_binary(bin_dir: &tempfile::TempDir, content: &[u8]) {
    use std::os::unix::fs::PermissionsExt;

    let path = bin_dir.path().join("ops-engine");
    std::fs::write(&path, content).expect("unmanaged binary should be written");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("unmanaged binary should be executable");
}

#[test]
fn the_first_install_on_an_unmanaged_host_retains_the_binary_it_replaces() {
    // The highest-risk moment in a rollout: a host with no
    // `install.state` at all, whose working binary is about to be
    // overwritten. It must still be possible to roll back afterwards.
    let server = start_fixture_server(fixture_routes(&[VERSION]));
    let (bin_dir, _state_dir, bin_root, state_root, engine_state) = roots();
    let unmanaged = fixture_bytes(PREVIOUS_VERSION);
    seed_unmanaged_binary(&bin_dir, &unmanaged);

    let context = InstallContext {
        bin_root: &bin_root,
        engine_state: &engine_state,
        state_root: &state_root,
        release_base_url: &server.base_url,
    };
    let request =
        EngineInstallRequest::parse(VERSION, REQUEST_ID_1, None).expect("request should parse");
    let result = execute_install(&context, &request, &CancellationToken::default())
        .expect("install should succeed");

    // The replaced binary was asked what version it is, and retained
    // under that name.
    assert_eq!(result.previous_version, Some(PREVIOUS_VERSION.to_owned()));
    assert_eq!(
        std::fs::read(bin_dir.path().join("ops-engine")).unwrap(),
        fixture_bytes(VERSION)
    );

    // And rollback really can restore it — the point of retaining it.
    let rollback_context = RollbackContext {
        bin_root: &bin_root,
        engine_state: &engine_state,
    };
    let rollback_request =
        EngineRollbackRequest::parse(REQUEST_ID_2, None).expect("request should parse");
    let rolled_back = execute_rollback(
        &rollback_context,
        &rollback_request,
        &CancellationToken::default(),
    )
    .expect("rollback should succeed");

    assert_eq!(rolled_back.version, PREVIOUS_VERSION);
    assert_eq!(
        std::fs::read(bin_dir.path().join("ops-engine")).unwrap(),
        unmanaged
    );
}

#[test]
fn an_unmanaged_binary_that_cannot_be_identified_is_retained_under_a_sentinel() {
    let server = start_fixture_server(fixture_routes(&[VERSION]));
    let (bin_dir, _state_dir, bin_root, state_root, engine_state) = roots();
    let unmanaged = b"an older ops-engine that will not answer for itself".to_vec();
    seed_unmanaged_binary(&bin_dir, &unmanaged);

    let context = InstallContext {
        bin_root: &bin_root,
        engine_state: &engine_state,
        state_root: &state_root,
        release_base_url: &server.base_url,
    };
    let request =
        EngineInstallRequest::parse(VERSION, REQUEST_ID_1, None).expect("request should parse");
    let result = execute_install(&context, &request, &CancellationToken::default())
        .expect("install should succeed");

    assert_eq!(result.previous_version, Some("pre-managed".to_owned()));

    let rollback_context = RollbackContext {
        bin_root: &bin_root,
        engine_state: &engine_state,
    };
    let rollback_request =
        EngineRollbackRequest::parse(REQUEST_ID_2, None).expect("request should parse");
    execute_rollback(
        &rollback_context,
        &rollback_request,
        &CancellationToken::default(),
    )
    .expect("rollback to the retained pre-managed binary should succeed");
    assert_eq!(
        std::fs::read(bin_dir.path().join("ops-engine")).unwrap(),
        unmanaged
    );
}
