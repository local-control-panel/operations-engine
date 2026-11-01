use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, sync::Mutex};

use super::*;

const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
const OTHER_ID: &str = "123e4567-e89b-12d3-a456-426614174001";

/// Fork-heavy fixture tests share flock state with forked children;
/// serialize them like `tests/deploy.rs` does.
static SERIAL: Mutex<()> = Mutex::new(());

struct Fixture {
    _dir: tempfile::TempDir,
    state: ManagedRoot,
    runtime_root: TrustedRoot,
    site_services_root: TrustedRoot,
    log_root: TrustedRoot,
    stack_dir: PathBuf,
    docker: String,
    calls: PathBuf,
    health: PathBuf,
}

impl Fixture {
    fn new(exit: i32) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        for sub in ["state", "runtimes", "site-services", "stack", "logs"] {
            fs::create_dir(base.join(sub)).unwrap();
        }
        let calls = base.join("calls.log");
        let docker = base.join("docker");
        fs::write(
            &docker,
            format!(
                "#!/bin/sh\necho \"$(pwd) $*\" >> '{calls}'\n\
                 case \"$*\" in\n\
                 *' ps -q '*) echo c0ffee ;;\n\
                 inspect*) cat '{health}' 2>/dev/null || echo healthy ;;\n\
                 esac\nexit {exit}\n",
                calls = calls.display(),
                health = base.join("health").display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&docker, fs::Permissions::from_mode(0o755)).unwrap();
        Self {
            state: ManagedRoot::open(&TrustedRoot::parse(base.join("state")).unwrap()).unwrap(),
            runtime_root: TrustedRoot::parse(base.join("runtimes")).unwrap(),
            site_services_root: TrustedRoot::parse(base.join("site-services")).unwrap(),
            log_root: TrustedRoot::parse(base.join("logs")).unwrap(),
            stack_dir: base.join("stack"),
            docker: docker.to_string_lossy().into_owned(),
            health: base.join("health"),
            calls,
            _dir: dir,
        }
    }

    fn ctx(&self) -> Context<'_> {
        self.ctx_waiting(Duration::from_millis(200))
    }

    /// A context whose health wait gives up after `timeout`.
    fn ctx_waiting(&self, timeout: Duration) -> Context<'_> {
        Context {
            engine_state: &self.state,
            runtime_root: &self.runtime_root,
            site_services_root: &self.site_services_root,
            log_root: &self.log_root,
            chown_logs: false,
            stack_dir: &self.stack_dir,
            docker: &self.docker,
            health: HealthWait {
                timeout,
                interval: Duration::from_millis(20),
            },
        }
    }

    fn health(&self, status: &str) {
        fs::write(&self.health, format!("{status}\n")).unwrap();
    }

    fn calls(&self) -> Vec<String> {
        fs::read_to_string(&self.calls)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn site_config(&self, runtime_id: &str, name: &str) {
        let dir = self.runtime_root.as_path().join(runtime_id);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(name), "example.com {\n}\n").unwrap();
    }

    /// Rewrites the fake `docker` so it exits 1 only when its arguments
    /// contain `marker`, and 0 otherwise — the one knob the shared
    /// single-exit fixture lacks, used to fail just the readiness probe.
    fn fail_on(&self, marker: &str) {
        fs::write(
            &self.docker,
            format!(
                "#!/bin/sh\necho \"$(pwd) $*\" >> '{calls}'\n\
                 case \"$*\" in *'{marker}'*) exit 1 ;; esac\nexit 0\n",
                calls = self.calls.display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&self.docker, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn seed_dir(&self, runtime_id: &str, domain: &str) {
        fs::create_dir_all(
            self.site_services_root
                .as_path()
                .join(runtime_id)
                .join(domain),
        )
        .unwrap();
    }

    fn service_file(&self, runtime_id: &str, domain: &str, name: &str) -> String {
        fs::read_to_string(
            self.site_services_root
                .as_path()
                .join(runtime_id)
                .join(domain)
                .join(name),
        )
        .unwrap()
    }
}

fn content_roots() -> Vec<TrustedRoot> {
    vec![TrustedRoot::parse("/var/www").unwrap()]
}

fn write_req(id: &str, key: Option<&str>) -> WriteSiteServiceRequest {
    WriteSiteServiceRequest::parse(
        "fp1-php83",
        "example.test",
        10123,
        10123,
        9000,
        "/var/www/example".into(),
        true,
        2,
        &content_roots(),
        id,
        key,
    )
    .unwrap()
}

fn sample_caddyfile(port: u16) -> String {
    site_process_caddyfile(
        &Domain::parse("example.test").unwrap(),
        &RuntimeId::parse("fp1-php83").unwrap(),
        port,
        "/var/www/example",
        true,
        2,
    )
}

fn activate_req(hash: Option<&str>, id: &str, key: Option<&str>) -> ActivateSiteConfigRequest {
    ActivateSiteConfigRequest::parse(
        "fp1-php83",
        "example.test",
        9000,
        "/var/www/example".into(),
        sample_caddyfile(9000),
        hash,
        &content_roots(),
        id,
        key,
    )
    .unwrap()
}

#[test]
fn write_site_service_writes_the_three_files_and_scans_once() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(0);

    let result = write_site_service(
        &fixture.ctx(),
        &write_req(ID, Some("ws-1")),
        &CancellationToken::default(),
    )
    .unwrap();
    assert_eq!(result.domain, "example.test");
    // A retried request replays without writing or scanning twice.
    write_site_service(
        &fixture.ctx(),
        &write_req(ID, Some("ws-1")),
        &CancellationToken::default(),
    )
    .unwrap();

    let run = fixture.service_file("fp1-php83", "example.test", "run");
    assert!(run.starts_with("#!/bin/sh\n"));
    assert!(run.contains("setpriv --reuid=10123 --regid=10123"));
    assert!(run.contains("--config /etc/wcp/site-services/example.test/Caddyfile"));
    let caddy = fixture.service_file("fp1-php83", "example.test", "Caddyfile");
    assert!(caddy.contains("http://127.0.0.1:9000 {"));
    assert!(caddy.contains("root * /var/www/example"));
    assert!(caddy.contains("worker /var/www/example/index.php 2"));
    let ini = fixture.service_file("fp1-php83", "example.test", "open-basedir.ini");
    assert!(ini.contains("open_basedir = /var/www/example:/tmp"));
    assert_eq!(
        fixture.calls(),
        vec![format!(
            "{} exec -T runtime-fp1-php83 sh -c i=0; while [ \"$i\" -lt 10 ]; do \
             s6-svscanctl -a /etc/wcp/site-services && exit 0; i=$((i+1)); sleep 0.3; done; \
             exit 1",
            compose_prefix(&fixture)
        )]
    );
}

#[test]
fn write_site_service_precreates_the_runtime_log_for_the_site_identity() {
    use std::os::unix::fs::MetadataExt;

    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(0);
    // Chowning to oneself works unprivileged, which is all a unit test
    // can prove about the handover; the Lima run covers a foreign uid.
    let own = fs::metadata(fixture.log_root.as_path()).unwrap();
    let (uid, gid) = (own.uid(), own.gid());
    let mut ctx = fixture.ctx();
    ctx.chown_logs = true;
    let request = WriteSiteServiceRequest::parse(
        "fp1-php83",
        "example.test",
        uid,
        gid,
        9000,
        "/var/www/example".into(),
        false,
        2,
        &content_roots(),
        ID,
        None,
    )
    .unwrap();
    // A pre-existing wider-mode log is tightened, not truncated.
    let log = fixture
        .log_root
        .as_path()
        .join("runtime-fp1-php83-example.test.log");
    fs::write(&log, "kept\n").unwrap();
    fs::set_permissions(&log, fs::Permissions::from_mode(0o644)).unwrap();

    write_site_service(&ctx, &request, &CancellationToken::default()).unwrap();

    let meta = fs::metadata(&log).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    assert_eq!((meta.uid(), meta.gid()), (uid, gid));
    assert_eq!(fs::read_to_string(&log).unwrap(), "kept\n");
    // Only the site's own runtime log is created; the ingress log is not.
    assert_eq!(fs::read_dir(fixture.log_root.as_path()).unwrap().count(), 1);
}

#[test]
fn write_site_service_refuses_a_runtime_log_that_is_not_a_regular_file() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(0);
    fs::create_dir(
        fixture
            .log_root
            .as_path()
            .join("runtime-fp1-php83-example.test.log"),
    )
    .unwrap();
    let error = write_site_service(
        &fixture.ctx(),
        &write_req(ID, None),
        &CancellationToken::default(),
    )
    .unwrap_err();
    assert!(matches!(error, Error::Io(_)));
    // Nothing was registered with s6.
    assert!(fixture.calls().is_empty());
}

#[test]
fn only_site_identities_may_run_a_service() {
    assert!(validate_site_identity(1000, 1000).is_ok());
    for (uid, gid) in [(0, 0), (0, 1000), (1000, 0), (999, 999), (10_000, 33)] {
        assert_eq!(
            validate_site_identity(uid, gid),
            Err(RequestError::InvalidIdentity)
        );
    }
}

#[test]
fn write_site_service_overwrites_an_existing_run_script() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(0);
    write_site_service(
        &fixture.ctx(),
        &write_req(ID, None),
        &CancellationToken::default(),
    )
    .unwrap();
    // A second, distinct request over the same directory must not fail
    // on the already-present `run` file.
    write_site_service(
        &fixture.ctx(),
        &write_req(OTHER_ID, None),
        &CancellationToken::default(),
    )
    .unwrap();
    assert!(
        fixture
            .service_file("fp1-php83", "example.test", "run")
            .contains("setpriv")
    );
}

#[test]
fn activate_validates_swaps_restarts_and_probes_in_order() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(0);
    fixture.seed_dir("fp1-php83", "example.test");

    activate_site_config(
        &fixture.ctx(),
        &activate_req(None, ID, Some("act-1")),
        &CancellationToken::default(),
    )
    .unwrap();

    let prefix = compose_prefix(&fixture);
    let calls = fixture.calls();
    assert_eq!(
        calls[0],
        format!(
            "{prefix} exec -T runtime-fp1-php83 caddy validate --config \
             /etc/wcp/site-services/example.test/Caddyfile.tmp --adapter caddyfile"
        )
    );
    assert_eq!(
        calls[1],
        format!(
            "{prefix} exec -T runtime-fp1-php83 s6-svc -r \
             /etc/wcp/site-services/example.test"
        )
    );
    assert!(
        calls[2].contains("curl -s --max-time 5 -o /dev/null"),
        "{}",
        calls[2]
    );
    // The validated Caddyfile is live and no staging file is left behind.
    assert!(
        fixture
            .service_file("fp1-php83", "example.test", "Caddyfile")
            .contains("http://127.0.0.1:9000 {")
    );
    assert!(
        !fixture
            .site_services_root
            .as_path()
            .join("fp1-php83/example.test/Caddyfile.tmp")
            .exists()
    );
}

#[test]
fn activate_rejects_a_stale_prior_hash_before_touching_docker() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(0);
    fixture.site_config("ignored", "x"); // unrelated
    // Seed a live Caddyfile, then present a wrong expected hash.
    write_site_service(
        &fixture.ctx(),
        &write_req(ID, None),
        &CancellationToken::default(),
    )
    .unwrap();
    fs::read_to_string(&fixture.calls).ok();
    fs::write(&fixture.calls, "").unwrap();

    let bad = ConfigHash::of(b"something else");
    let error = activate_site_config(
        &fixture.ctx(),
        &activate_req(Some(bad.as_str()), OTHER_ID, None),
        &CancellationToken::default(),
    )
    .unwrap_err();
    assert!(matches!(error, Error::HashMismatch));
    assert_eq!(error.protocol().0, ErrorCode::ConfigHashMismatch);
    assert!(fixture.calls().is_empty());
}

#[test]
fn activate_absent_guard_refuses_an_existing_file() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(0);
    write_site_service(
        &fixture.ctx(),
        &write_req(ID, None),
        &CancellationToken::default(),
    )
    .unwrap();
    fs::write(&fixture.calls, "").unwrap();

    let error = activate_site_config(
        &fixture.ctx(),
        &activate_req(None, OTHER_ID, None),
        &CancellationToken::default(),
    )
    .unwrap_err();
    assert!(matches!(error, Error::HashMismatch));
}

#[test]
fn an_invalid_new_config_removes_the_staging_file_and_fails() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(0);
    fixture.seed_dir("fp1-php83", "example.test");
    fixture.fail_on("caddy validate");

    let error = activate_site_config(
        &fixture.ctx(),
        &activate_req(None, ID, Some("act-bad")),
        &CancellationToken::default(),
    )
    .unwrap_err();
    assert!(matches!(error, Error::Rejected(Stage::ValidateConfig, _)));
    assert_eq!(error.protocol().0, ErrorCode::ConfigValidationFailed);
    assert!(
        !fixture
            .site_services_root
            .as_path()
            .join("fp1-php83/example.test/Caddyfile.tmp")
            .exists()
    );
}

#[test]
fn a_probe_failure_restores_the_previous_config_and_restarts_it() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(0);
    // Seed a known-good live config to roll back to.
    let prior = write_req(ID, None);
    write_site_service(&fixture.ctx(), &prior, &CancellationToken::default()).unwrap();
    let live = fixture.service_file("fp1-php83", "example.test", "Caddyfile");
    let live_hash = ConfigHash::of(live.as_bytes());
    // A newer activation whose restarted process never answers.
    fixture.fail_on("http_code");
    fs::write(&fixture.calls, "").unwrap();

    let req = ActivateSiteConfigRequest::parse(
        "fp1-php83",
        "example.test",
        9100, // a changed port, so the file content differs
        "/var/www/example".into(),
        sample_caddyfile(9100),
        Some(live_hash.as_str()),
        &content_roots(),
        OTHER_ID,
        None,
    )
    .unwrap();
    let error =
        activate_site_config(&fixture.ctx(), &req, &CancellationToken::default()).unwrap_err();
    assert!(matches!(error, Error::SiteRolledBack));
    assert_eq!(error.protocol().0, ErrorCode::ConfigReloadFailed);
    // The live Caddyfile is byte-for-byte the previous one again.
    assert_eq!(
        fixture.service_file("fp1-php83", "example.test", "Caddyfile"),
        live
    );
    // validate, restart(new), probe(fail), restart(restored).
    let restarts = fixture
        .calls()
        .iter()
        .filter(|c| c.contains("s6-svc -r"))
        .count();
    assert_eq!(restarts, 2);
}

#[test]
fn a_held_stack_lock_blocks_a_site_write_before_docker_runs() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(0);
    let stack_scope = crate::stack_deploy::open_scope(&fixture.state).unwrap();
    let _held =
        crate::stack_deploy::acquire_stack_lock(&stack_scope, RequestId::parse(OTHER_ID).unwrap())
            .unwrap();

    let error = write_site_service(
        &fixture.ctx(),
        &write_req(ID, None),
        &CancellationToken::default(),
    )
    .unwrap_err();
    assert!(matches!(error, Error::StackBusy));
    assert!(fixture.calls().is_empty());
}

fn remove_req(id: &str, key: Option<&str>) -> RemoveSiteServiceRequest {
    RemoveSiteServiceRequest::parse("fp1-php83", "example.test", id, key).unwrap()
}

fn service_dir_exists(fixture: &Fixture) -> bool {
    fixture
        .site_services_root
        .as_path()
        .join("fp1-php83/example.test")
        .exists()
}

#[test]
fn guarded_service_removal_preserves_changed_configuration() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(0);
    write_site_service(
        &fixture.ctx(),
        &write_req(OTHER_ID, None),
        &CancellationToken::default(),
    )
    .unwrap();
    fs::remove_file(&fixture.calls).unwrap();
    let mut req = remove_req(ID, None);
    req.expected_files = Some(vec![(
        service_rel(&req.runtime_id, &req.domain, "Caddyfile"),
        "a different creation attempt".into(),
    )]);
    assert!(matches!(
        remove_site_service(&fixture.ctx(), &req, &CancellationToken::default()),
        Err(Error::HashMismatch)
    ));
    assert!(service_dir_exists(&fixture));
    assert!(
        fixture.calls().is_empty(),
        "a mismatched service must not even be stopped"
    );
}

#[test]
fn remove_site_service_stops_removes_and_rescans_in_order() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(0);
    write_site_service(
        &fixture.ctx(),
        &write_req(OTHER_ID, None),
        &CancellationToken::default(),
    )
    .unwrap();
    fs::remove_file(&fixture.calls).unwrap();

    let result = remove_site_service(
        &fixture.ctx(),
        &remove_req(ID, Some("rs-1")),
        &CancellationToken::default(),
    )
    .unwrap();
    assert!(result.removed);
    assert!(result.pool_running);
    assert!(!service_dir_exists(&fixture));
    // A retried request replays the outcome without a second stop.
    let replayed = remove_site_service(
        &fixture.ctx(),
        &remove_req(ID, Some("rs-1")),
        &CancellationToken::default(),
    )
    .unwrap();
    assert!(replayed.removed);

    let prefix = compose_prefix(&fixture);
    assert_eq!(
        fixture.calls(),
        vec![
            format!("{prefix} ps -q runtime-fp1-php83"),
            format!(
                "{prefix} exec -T runtime-fp1-php83 s6-svc -d \
                 /etc/wcp/site-services/example.test"
            ),
            format!(
                "{prefix} exec -T runtime-fp1-php83 sh -c i=0; while [ \"$i\" -lt 10 ]; do \
                 s6-svscanctl -a /etc/wcp/site-services && exit 0; i=$((i+1)); sleep 0.3; \
                 done; exit 1"
            ),
        ]
    );
}

#[test]
fn remove_site_service_without_a_directory_is_a_no_op() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(0);

    let result = remove_site_service(
        &fixture.ctx(),
        &remove_req(ID, None),
        &CancellationToken::default(),
    )
    .unwrap();
    assert!(!result.removed);
    assert!(fixture.calls().is_empty());
}

#[test]
fn a_failed_stop_leaves_the_service_directory_in_place() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(0);
    fixture.seed_dir("fp1-php83", "example.test");
    // `ps -q` must report the pool running for the stop to be attempted.
    fs::write(
        &fixture.docker,
        format!(
            "#!/bin/sh\necho \"$(pwd) $*\" >> '{calls}'\n\
             case \"$*\" in *' ps -q '*) echo c0ffee ;; *'s6-svc -d'*) exit 1 ;; esac\nexit 0\n",
            calls = fixture.calls.display(),
        ),
    )
    .unwrap();

    let error = remove_site_service(
        &fixture.ctx(),
        &remove_req(ID, None),
        &CancellationToken::default(),
    )
    .unwrap_err();
    assert!(matches!(error, Error::Rejected(Stage::StopService, _)));
    assert!(service_dir_exists(&fixture));
    assert!(!fixture.calls().iter().any(|c| c.contains("s6-svscanctl")));
}

#[test]
fn a_service_without_a_supervisor_is_removed_without_a_stop() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(0);
    fixture.seed_dir("fp1-php83", "example.test");
    fs::write(
        &fixture.docker,
        format!(
            "#!/bin/sh\necho \"$(pwd) $*\" >> '{calls}'\n\
             case \"$*\" in *' ps -q '*) echo c0ffee ;; *'s6-svc -d'*) exit 1 ;; \
             *s6-svstat*) echo 's6-svstat: fatal: unable to read status: s6-supervise not running' ;; esac\nexit 0\n",
            calls = fixture.calls.display(),
        ),
    )
    .unwrap();

    let result = remove_site_service(
        &fixture.ctx(),
        &remove_req(ID, None),
        &CancellationToken::default(),
    )
    .unwrap();
    assert!(result.removed);
    assert!(!service_dir_exists(&fixture));
}

#[test]
fn a_stopped_pool_only_loses_the_directory() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(0);
    fixture.seed_dir("fp1-php83", "example.test");
    // Empty `ps -q` output: no running container for the pool.
    fixture.fail_on("never-matches");

    let result = remove_site_service(
        &fixture.ctx(),
        &remove_req(ID, None),
        &CancellationToken::default(),
    )
    .unwrap();
    assert!(result.removed);
    assert!(!result.pool_running);
    assert!(!service_dir_exists(&fixture));
    assert_eq!(
        fixture.calls().len(),
        1,
        "only the ps probe: {:?}",
        fixture.calls()
    );
}

#[test]
fn a_held_stack_lock_blocks_a_site_removal_before_docker_runs() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(0);
    fixture.seed_dir("fp1-php83", "example.test");
    let stack_scope = crate::stack_deploy::open_scope(&fixture.state).unwrap();
    let _held =
        crate::stack_deploy::acquire_stack_lock(&stack_scope, RequestId::parse(OTHER_ID).unwrap())
            .unwrap();

    let error = remove_site_service(
        &fixture.ctx(),
        &remove_req(ID, None),
        &CancellationToken::default(),
    )
    .unwrap_err();
    assert!(matches!(error, Error::StackBusy));
    assert!(fixture.calls().is_empty());
    assert!(service_dir_exists(&fixture));
}

#[test]
fn remove_site_service_rejects_malformed_fields() {
    assert_eq!(
        RemoveSiteServiceRequest::parse("fp1-php83", "../etc", ID, None).err(),
        Some(RequestError::InvalidDomain)
    );
    assert_eq!(
        RemoveSiteServiceRequest::parse("bad id", "example.test", ID, None).err(),
        Some(RequestError::InvalidRuntimeId)
    );
}

#[test]
fn site_requests_reject_malformed_fields() {
    assert_eq!(
        ActivateSiteConfigRequest::parse(
            "fp1-php83",
            "example.test",
            0,
            "/var/www/r".into(),
            "x {}".into(),
            None,
            &content_roots(),
            ID,
            None
        )
        .err(),
        Some(RequestError::InvalidPort)
    );
    assert_eq!(
        ActivateSiteConfigRequest::parse(
            "fp1-php83",
            "-bad.test",
            80,
            "/var/www/r".into(),
            "x {}".into(),
            None,
            &content_roots(),
            ID,
            None
        )
        .err(),
        Some(RequestError::InvalidDomain)
    );
    assert_eq!(
        ActivateSiteConfigRequest::parse(
            "fp1-php83",
            "example.test",
            80,
            "/var/www/r".into(),
            "x {}".into(),
            Some("zz"),
            &content_roots(),
            ID,
            None
        )
        .err(),
        Some(RequestError::InvalidPriorHash)
    );
}

const HOSTILE_ROOTS: &[&str] = &[
    "",
    "/",
    "/var/www",
    "/var/www/",
    "/etc/passwd",
    "/var/wwwx/a",
    "var/www/a",
    "/var/www/a b",
    "/var/www/a\nroot * /etc",
    "/var/www/a\r\nimport /etc/x",
    "/var/www/a}",
    "/var/www/a {",
    "/var/www/a{",
    "/var/www/a}\nhandle {",
    "/var/www/../etc",
    "/var/www/a/../../etc",
    "/var/www/a/./b",
    "/var/www//a",
    "/var/www/a;rm",
    "/var/www/a:/etc",
    "/var/www/a\"b",
    "/var/www/a`b",
    "/var/www/a$HOME",
    "/var/www/a\0b",
];

#[test]
fn site_requests_reject_hostile_roots() {
    for root in HOSTILE_ROOTS {
        assert_eq!(
            WriteSiteServiceRequest::parse(
                "fp1-php83",
                "example.test",
                10123,
                10123,
                9000,
                (*root).into(),
                true,
                2,
                &content_roots(),
                ID,
                None,
            )
            .err(),
            Some(RequestError::InvalidRoot),
            "write {root:?}"
        );
        assert_eq!(
            ActivateSiteConfigRequest::parse(
                "fp1-php83",
                "example.test",
                9000,
                (*root).into(),
                "x {}".into(),
                None,
                &content_roots(),
                ID,
                None,
            )
            .err(),
            Some(RequestError::InvalidRoot),
            "activate {root:?}"
        );
    }
}

#[test]
fn site_requests_accept_the_roots_the_panel_sends() {
    for root in [
        "/var/www/example.test",
        "/var/www/example.test/public",
        "/var/www/sites/0b0c5b0e-6a39-4f55-8b8c-0f6a3d8b7b10/current",
    ] {
        assert!(
            WriteSiteServiceRequest::parse(
                "fp1-php83",
                "example.test",
                10123,
                10123,
                9000,
                root.into(),
                false,
                1,
                &content_roots(),
                ID,
                None,
            )
            .is_ok(),
            "{root}"
        );
        assert!(
            ActivateSiteConfigRequest::parse(
                "fp1-php83",
                "example.test",
                9000,
                root.into(),
                "x {}".into(),
                None,
                &content_roots(),
                ID,
                None,
            )
            .is_ok(),
            "{root}"
        );
    }
    // No content root configured means nothing is acceptable.
    assert_eq!(
        WriteSiteServiceRequest::parse(
            "fp1-php83",
            "example.test",
            10123,
            10123,
            9000,
            "/var/www/example.test".into(),
            false,
            1,
            &[],
            ID,
            None,
        )
        .err(),
        Some(RequestError::InvalidRoot)
    );
}

fn compose_prefix(fixture: &Fixture) -> String {
    format!(
        "{} compose -p wcp --env-file .env -f stack/docker-compose.yml",
        fixture.stack_dir.display()
    )
}

#[test]
fn service_accepts_only_ingress_or_a_runtime_pool() {
    assert_eq!(Service::parse("ingress"), Some(Service::Ingress));
    assert_eq!(
        Service::parse("runtime-fp1-php83").map(|s| s.name()),
        Some("runtime-fp1-php83".to_owned())
    );
    for bad in [
        "",
        "mariadb",
        "runtime-",
        "runtime-FP1",
        "runtime-../x",
        "runtime--x",
        "ingress ",
    ] {
        assert_eq!(Service::parse(bad), None, "{bad:?}");
    }
}

#[test]
fn reload_runs_the_fixed_caddy_reload_in_the_stack_directory_once() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(0);
    let req = ReloadRequest::parse("runtime-fp1-php83", ID, Some("reload-1")).unwrap();

    let result = reload(&fixture.ctx(), &req, &CancellationToken::default()).unwrap();
    assert_eq!(result.service, "runtime-fp1-php83");
    // A retried request replays the outcome without reloading twice.
    reload(&fixture.ctx(), &req, &CancellationToken::default()).unwrap();

    assert_eq!(
        fixture.calls(),
        vec![format!(
            "{} exec -T runtime-fp1-php83 caddy reload --config /etc/caddy/Caddyfile \
             --adapter caddyfile",
            compose_prefix(&fixture)
        )]
    );
}

#[test]
fn a_rejected_reload_is_a_reload_failure_and_replays_as_one() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(1);
    let req = ReloadRequest::parse("ingress", ID, Some("reload-2")).unwrap();

    let error = reload(&fixture.ctx(), &req, &CancellationToken::default()).unwrap_err();
    assert!(matches!(error, Error::Rejected(Stage::Reload, _)));
    assert_eq!(error.protocol().0, ErrorCode::ConfigReloadFailed);
    let replayed = reload(&fixture.ctx(), &req, &CancellationToken::default()).unwrap_err();
    assert!(matches!(
        replayed,
        Error::Replayed {
            code: ErrorCode::ConfigReloadFailed,
            ..
        }
    ));
    assert_eq!(fixture.calls().len(), 1);
}

#[test]
fn a_held_stack_lock_blocks_a_reload_before_docker_runs() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(0);
    let stack_scope = crate::stack_deploy::open_scope(&fixture.state).unwrap();
    let _held =
        crate::stack_deploy::acquire_stack_lock(&stack_scope, RequestId::parse(OTHER_ID).unwrap())
            .unwrap();

    let req = ReloadRequest::parse("ingress", ID, None).unwrap();
    let error = reload(&fixture.ctx(), &req, &CancellationToken::default()).unwrap_err();
    assert!(matches!(error, Error::StackBusy));
    assert_eq!(error.protocol().0, ErrorCode::Conflict);
    assert!(fixture.calls().is_empty());
}

#[test]
fn stop_stops_a_pool_with_no_site_configs() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(0);
    // Leftover staging/rollback files do not keep a pool alive.
    fixture.site_config("fp1-php84", "example.com.caddyfile.tmp");
    fixture.site_config("fp1-php84", "example.com.caddyfile.rollback-x");
    let req = StopRequest::parse("fp1-php84", ID, None).unwrap();

    let result = stop_idle_runtime(&fixture.ctx(), &req, &CancellationToken::default()).unwrap();
    assert!(result.stopped);
    assert_eq!(result.site_configs, 0);
    assert_eq!(
        fixture.calls(),
        vec![format!(
            "{} stop runtime-fp1-php84",
            compose_prefix(&fixture)
        )]
    );
}

#[test]
fn stop_treats_a_missing_pool_directory_as_idle() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(0);
    let req = StopRequest::parse("fp1-php84", ID, None).unwrap();

    let result = stop_idle_runtime(&fixture.ctx(), &req, &CancellationToken::default()).unwrap();
    assert!(result.stopped);
    assert_eq!(fixture.calls().len(), 1);
}

#[test]
fn stop_leaves_a_pool_with_a_site_config_running() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(0);
    fixture.site_config("fp1-php84", "example.com.caddyfile");
    let req = StopRequest::parse("fp1-php84", ID, None).unwrap();

    let result = stop_idle_runtime(&fixture.ctx(), &req, &CancellationToken::default()).unwrap();
    assert!(!result.stopped);
    assert_eq!(result.site_configs, 1);
    assert!(fixture.calls().is_empty());
}

#[test]
fn a_failed_stop_is_reported_as_a_subprocess_failure() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(1);
    let req = StopRequest::parse("fp1-php84", ID, None).unwrap();

    let error = stop_idle_runtime(&fixture.ctx(), &req, &CancellationToken::default()).unwrap_err();
    assert!(matches!(error, Error::Rejected(Stage::Stop, _)));
    assert_eq!(error.protocol().0, ErrorCode::SubprocessFailed);
}

#[test]
fn a_held_stack_lock_blocks_a_stop_before_docker_runs() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(0);
    let stack_scope = crate::stack_deploy::open_scope(&fixture.state).unwrap();
    let _held =
        crate::stack_deploy::acquire_stack_lock(&stack_scope, RequestId::parse(OTHER_ID).unwrap())
            .unwrap();

    let req = StopRequest::parse("fp1-php84", ID, None).unwrap();
    assert!(matches!(
        stop_idle_runtime(&fixture.ctx(), &req, &CancellationToken::default()),
        Err(Error::StackBusy)
    ));
    assert!(fixture.calls().is_empty());
}

#[test]
fn ensure_starts_the_pool_under_its_profile_and_waits_for_healthy() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(0);
    let req = EnsureRequest::parse("fp1-php84", Some("php-8.4"), ID, Some("up-1")).unwrap();

    let result = ensure_runtime(&fixture.ctx(), &req, &CancellationToken::default()).unwrap();
    assert_eq!(result.service, "runtime-fp1-php84");
    ensure_runtime(&fixture.ctx(), &req, &CancellationToken::default()).unwrap();

    let prefix = compose_prefix(&fixture);
    assert_eq!(
        fixture.calls(),
        vec![
            format!("{prefix} --profile php-8.4 up -d runtime-fp1-php84"),
            format!("{prefix} ps -q runtime-fp1-php84"),
            format!(
                "{} inspect -f {{{{if .State.Health}}}}{{{{.State.Health.Status}}}}{{{{end}}}} \
                 c0ffee",
                fixture.stack_dir.display()
            ),
        ]
    );
}

#[test]
fn ensure_without_a_profile_is_a_plain_up() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(0);
    let req = EnsureRequest::parse("fp1-php83", None, ID, None).unwrap();

    ensure_runtime(&fixture.ctx(), &req, &CancellationToken::default()).unwrap();
    assert_eq!(
        fixture.calls()[0],
        format!("{} up -d runtime-fp1-php83", compose_prefix(&fixture))
    );
}

#[test]
fn a_pool_that_never_turns_healthy_times_out_and_replays_as_one() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(0);
    fixture.health("starting");
    let req = EnsureRequest::parse("fp1-php83", None, ID, Some("up-2")).unwrap();

    // Each poll starts a shell script, so on a loaded machine a short
    // window can hold fewer than two of them; a generous one cannot.
    let waiting = fixture.ctx_waiting(Duration::from_secs(3));
    let error = ensure_runtime(&waiting, &req, &CancellationToken::default()).unwrap_err();
    assert!(matches!(&error, Error::Unhealthy(Some(status)) if status == "starting"));
    assert_eq!(error.protocol().0, ErrorCode::Timeout);
    let polls = fixture
        .calls()
        .iter()
        .filter(|call| call.contains(" inspect"))
        .count();
    assert!(polls >= 2, "polled more than once: {polls}");
    let calls = fixture.calls().len();
    assert!(matches!(
        ensure_runtime(&fixture.ctx(), &req, &CancellationToken::default()),
        Err(Error::Replayed {
            code: ErrorCode::Timeout,
            ..
        })
    ));
    assert_eq!(fixture.calls().len(), calls);
}

#[test]
fn a_failed_up_skips_the_health_wait() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(1);
    let req = EnsureRequest::parse("fp1-php83", None, ID, None).unwrap();

    let error = ensure_runtime(&fixture.ctx(), &req, &CancellationToken::default()).unwrap_err();
    assert!(matches!(error, Error::Rejected(Stage::Up, _)));
    assert_eq!(error.protocol().0, ErrorCode::SubprocessFailed);
    assert_eq!(fixture.calls().len(), 1);
}

#[test]
fn reload_workers_restarts_the_pool_site_services() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(0);
    let req = RuntimeRequest::parse("fp1-php84", ID, None).unwrap();

    let result = reload_workers(&fixture.ctx(), &req, &CancellationToken::default()).unwrap();
    assert_eq!(result.service, "runtime-fp1-php84");
    assert_eq!(
        fixture.calls(),
        vec![format!(
            "{} exec -T runtime-fp1-php84 sh -c {RELOAD_WORKERS_SCRIPT}",
            compose_prefix(&fixture)
        )]
    );
}

#[test]
fn flush_fpc_runs_the_fixed_purge_in_the_pool() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(0);
    let req = RuntimeRequest::parse("fp1-php84", ID, None).unwrap();

    flush_fpc(&fixture.ctx(), &req, &CancellationToken::default()).unwrap();
    assert_eq!(
        fixture.calls(),
        vec![format!(
            "{} exec -T runtime-fp1-php84 sh -c {FLUSH_FPC_SCRIPT}",
            compose_prefix(&fixture)
        )]
    );
}

#[test]
fn a_held_stack_lock_blocks_ensure_and_both_pool_actions() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new(0);
    let stack_scope = crate::stack_deploy::open_scope(&fixture.state).unwrap();
    let _held =
        crate::stack_deploy::acquire_stack_lock(&stack_scope, RequestId::parse(OTHER_ID).unwrap())
            .unwrap();
    let cancel = CancellationToken::default();
    let ensure = EnsureRequest::parse("fp1-php83", None, ID, None).unwrap();
    let pool = RuntimeRequest::parse("fp1-php83", ID, None).unwrap();

    assert!(matches!(
        ensure_runtime(&fixture.ctx(), &ensure, &cancel),
        Err(Error::StackBusy)
    ));
    assert!(matches!(
        reload_workers(&fixture.ctx(), &pool, &cancel),
        Err(Error::StackBusy)
    ));
    assert!(matches!(
        flush_fpc(&fixture.ctx(), &pool, &cancel),
        Err(Error::StackBusy)
    ));
    assert!(fixture.calls().is_empty());
}

#[test]
fn ensure_accepts_only_a_php_version_profile() {
    for good in ["php-8.4", "php-10.12"] {
        assert!(
            EnsureRequest::parse("fp1-php84", Some(good), ID, None).is_ok(),
            "{good}"
        );
    }
    for bad in [
        "",
        "php-8",
        "php-8.4.1",
        "php-8.x",
        "PHP-8.4",
        "php-8.4 ",
        "db",
    ] {
        assert_eq!(
            EnsureRequest::parse("fp1-php84", Some(bad), ID, None).err(),
            Some(RequestError::InvalidProfile),
            "{bad:?}"
        );
    }
}

#[test]
fn requests_reject_malformed_fields() {
    assert_eq!(
        ReloadRequest::parse("db", ID, None).err(),
        Some(RequestError::InvalidService)
    );
    assert_eq!(
        ReloadRequest::parse("ingress", "nope", None).err(),
        Some(RequestError::InvalidRequestId)
    );
    assert_eq!(
        StopRequest::parse("../x", ID, None).err(),
        Some(RequestError::InvalidRuntimeId)
    );
}
