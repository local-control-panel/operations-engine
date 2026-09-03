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
const VERSION: &str = "9.9.9";

/// Serves the four fixture files (and, for the corrupted-artifact test, a
/// caller-substituted binary) from a background thread, one request at a
/// time — sufficient for this test's handful of sequential requests. The
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

/// The release asset name for `VERSION` on *this* test host's
/// architecture — `release::target_triple` maps from
/// `std::env::consts::ARCH` alone (not the host OS), so this differs
/// between an x86_64 and an aarch64 machine even though both fixture
/// binaries were generated on this repo's own (non-Linux) dev machines.
/// `tests/fixtures/engine/` carries a binary for each architecture
/// `release::target_triple` supports, both covered by the one signed
/// `SHA256SUMS`, so the fixture server can serve whichever one this
/// host's build of `install::execute` will actually request.
fn fixture_asset_name() -> String {
    let version = release::EngineVersion::parse(VERSION).expect("literal version is valid");
    let target_triple = release::target_triple()
        .expect("this test host's architecture must be one release::target_triple supports");
    release::binary_asset_name(&version, target_triple)
}

fn fixture_routes(binary_override: Option<Vec<u8>>) -> HashMap<String, Vec<u8>> {
    let asset_name = fixture_asset_name();
    let binary = binary_override.unwrap_or_else(|| {
        std::fs::read(format!("tests/fixtures/engine/{asset_name}"))
            .expect("fixture binary for this host's architecture should exist — see Task 13 Step 1")
    });
    let mut routes = HashMap::new();
    routes.insert(
        "v9.9.9/SHA256SUMS".to_owned(),
        std::fs::read("tests/fixtures/engine/SHA256SUMS").expect("fixture manifest should exist"),
    );
    routes.insert(
        "v9.9.9/SHA256SUMS.minisig".to_owned(),
        std::fs::read("tests/fixtures/engine/SHA256SUMS.minisig")
            .expect("fixture signature should exist"),
    );
    routes.insert(format!("v9.9.9/{asset_name}"), binary);
    routes
}

fn roots() -> (
    tempfile::TempDir,
    tempfile::TempDir,
    TrustedRoot,
    ManagedRoot,
) {
    let bin_dir = tempfile::tempdir().expect("bin directory should exist");
    let state_dir = tempfile::tempdir().expect("state directory should exist");
    let bin_root = TrustedRoot::parse(bin_dir.path()).expect("bin root should be valid");
    let state_root = TrustedRoot::parse(state_dir.path()).expect("state root should be valid");
    let engine_state = ManagedRoot::open(&state_root).expect("state root should open");
    (bin_dir, state_dir, bin_root, engine_state)
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
    let server = start_fixture_server(fixture_routes(None));
    let (bin_dir, _state_dir, bin_root, engine_state) = roots();
    let context = InstallContext {
        bin_root: &bin_root,
        engine_state: &engine_state,
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
        std::fs::read(format!("tests/fixtures/engine/{}", fixture_asset_name())).unwrap()
    );

    let saved = state::load(&scoped_state(&engine_state))
        .unwrap()
        .expect("install state should be recorded");
    assert_eq!(saved.active_version, VERSION);
    assert_eq!(saved.previous_version, None);
}

#[test]
fn installing_the_same_version_twice_is_rejected_as_already_active() {
    let server = start_fixture_server(fixture_routes(None));
    let (_bin_dir, _state_dir, bin_root, engine_state) = roots();
    let context = InstallContext {
        bin_root: &bin_root,
        engine_state: &engine_state,
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
    let server = start_fixture_server(fixture_routes(Some(b"corrupted, wrong bytes".to_vec())));
    let (bin_dir, _state_dir, bin_root, engine_state) = roots();
    let context = InstallContext {
        bin_root: &bin_root,
        engine_state: &engine_state,
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
    let (bin_dir, _state_dir, bin_root, engine_state) = roots();

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
    let (bin_dir, _state_dir, bin_root, engine_state) = roots();
    let context = RollbackContext {
        bin_root: &bin_root,
        engine_state: &engine_state,
    };
    let request = EngineRollbackRequest::parse(REQUEST_ID_1, None).expect("request should parse");

    let error = execute_rollback(&context, &request, &CancellationToken::default()).unwrap_err();
    assert!(matches!(error, RollbackError::NoPreviousVersion));
    assert!(!bin_dir.path().join("ops-engine").exists());
}
