//! Opt-in real-container coverage for the production Meilisearch driver.
//! Run with `scripts/test-meilisearch-docker.sh` on a Linux Docker host (or
//! inside DinD). Nothing in this suite publishes the Meilisearch API port.

#![cfg(unix)]

use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::Path,
    process::Command,
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};

use operations_engine::{
    filesystem::ManagedRoot,
    meilisearch_upgrade::{
        TARGET_IMAGE, UpgradeRequest,
        docker::{DockerDriver, Error as DockerError},
        execute::{Baseline, Context, Driver, ExportedDump, ImportedTarget, execute},
    },
    process::CancellationToken,
    site::TrustedRoot,
};

const SOURCE_IMAGE: &str = "getmeili/meilisearch:v1.12.8";
const SOURCE_VERSION: &str = "1.12.8";
const MASTER_KEY: &str = "integration-test-master-key-32bytes";
const REQUEST_ID: &str = "5d27415b-e403-4f31-b0c7-81ffdb92fc61";
const FAILURE_REQUEST_ID: &str = "6e38526c-f514-4032-a1d8-92aaeca30d72";
const IMPORT_FAILURE_REQUEST_ID: &str = "7f49637d-a625-4143-b2e9-a3bbfdb41e83";
static DOCKER_TEST_LOCK: Mutex<()> = Mutex::new(());

struct Stack {
    root: tempfile::TempDir,
}

impl Stack {
    fn start() -> Self {
        assert!(
            docker(&["info"]).status().unwrap().success(),
            "Docker daemon is required"
        );
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("stack")).unwrap();
        fs::write(root.path().join(".env"), format!(
            "WCP_MEILISEARCH_IMAGE={SOURCE_IMAGE}\nWCP_MEILISEARCH_VOLUME=wcp_meilisearch_data_it\nMEILISEARCH_MASTER_KEY={MASTER_KEY}\n"
        )).unwrap();
        fs::write(
            root.path().join("stack/docker-compose.yml"),
            r#"
services:
  meili-1:
    image: ${WCP_MEILISEARCH_IMAGE}
    profiles: ["meilisearch"]
    environment:
      MEILI_MASTER_KEY: ${MEILISEARCH_MASTER_KEY}
      MEILI_ENV: production
      MEILI_NO_ANALYTICS: "true"
      MEILI_DB_PATH: /meili_data
    volumes:
      - meilisearch_data:/meili_data
    networks: [backend]
volumes:
  meilisearch_data:
    name: ${WCP_MEILISEARCH_VOLUME}
networks:
  backend: {}
"#,
        )
        .unwrap();
        assert!(
            compose(
                root.path(),
                &["--profile", "meilisearch", "up", "-d", "meili-1"]
            )
            .status()
            .unwrap()
            .success()
        );
        let stack = Self { root };
        stack.wait_ready();
        stack
    }

    fn address(&self) -> Option<SocketAddr> {
        let id = output(compose(
            self.root.path(),
            &["--profile", "meilisearch", "ps", "-q", "meili-1"],
        ));
        if id.trim().is_empty() {
            return None;
        }
        let json = output(docker(&[
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            id.trim(),
        ]));
        format!("{}:7700", json.trim()).parse().ok()
    }

    fn wait_ready(&self) {
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(60) {
            if self.address().is_some_and(|address| {
                try_http(address, "GET", "/health", None)
                    .is_ok_and(|response| response.starts_with("HTTP/1.1 200"))
            }) {
                return;
            }
            thread::sleep(Duration::from_millis(250));
        }
        panic!("source Meilisearch did not become ready");
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        let _ = compose(
            self.root.path(),
            &["--profile", "meilisearch", "down", "-v", "--remove-orphans"],
        )
        .status();
        let _ = docker(&["volume", "rm", "-f", "wcp_meilisearch_1_53_2_5d27415be403"]).status();
        let _ = docker(&["volume", "rm", "-f", "wcp_meilisearch_1_53_2_6e38526cf514"]).status();
    }
}

#[test]
#[ignore = "requires a Linux Docker daemon and pulls real Meilisearch images"]
fn production_driver_migrates_real_unicode_documents_without_publishing_a_port() {
    let _guard = DOCKER_TEST_LOCK.lock().unwrap();
    let stack = Stack::start();
    let task = json_post(
        stack.address().unwrap(),
        "/indexes/products/documents?primaryKey=id",
        r#"[{"id":1,"title":"Здравей свят"},{"id":2,"title":"coffee grinder"}]"#,
    );
    wait_task(stack.address().unwrap(), task);
    let settings_task = json_task(
        stack.address().unwrap(),
        "PATCH",
        "/indexes/products/settings",
        r#"{"filterableAttributes":["title"]}"#,
    );
    wait_task(stack.address().unwrap(), settings_task);

    let state_dir = tempfile::tempdir_in(stack.root.path()).unwrap();
    let trusted = TrustedRoot::parse(state_dir.path()).unwrap();
    let state = ManagedRoot::open(&trusted).unwrap();
    let request = UpgradeRequest::parse(&format!(r#"{{"stackName":"wp-stack","service":"meili-1","expectedSourceVersion":"{SOURCE_VERSION}","targetImage":"{TARGET_IMAGE}","masterKey":"{MASTER_KEY}","searchProbes":[{{"indexUid":"products","query":"Здравей"}}]}}"#), REQUEST_ID, None).unwrap();
    let mut driver = DockerDriver::new(stack.root.path(), &trusted);
    let mut context = Context {
        engine_state: &state,
        driver: &mut driver,
    };
    let result = execute(&mut context, &request, &CancellationToken::default()).unwrap();

    assert_eq!(result.source_version, SOURCE_VERSION);
    assert_eq!(result.target_version, "1.53.2");
    assert_eq!(result.target_volume, "wcp_meilisearch_1_53_2_5d27415be403");
    let env = fs::read_to_string(stack.root.path().join(".env")).unwrap();
    assert!(env.contains(TARGET_IMAGE));
    assert!(env.contains(&format!("WCP_MEILISEARCH_VOLUME={}", result.target_volume)));
    stack.wait_ready();
    let search = json_post(
        stack.address().unwrap(),
        "/indexes/products/search",
        r#"{"q":"Здравей"}"#,
    );
    wait_task_or_assert_search(stack.address().unwrap(), search);
    let settings = http(
        stack.address().unwrap(),
        "GET",
        "/indexes/products/settings",
        None,
    );
    assert!(
        settings.contains(r#""filterableAttributes":["title"]"#),
        "{settings}"
    );

    assert!(
        compose(
            stack.root.path(),
            &["--profile", "meilisearch", "restart", "meili-1"]
        )
        .status()
        .unwrap()
        .success()
    );
    stack.wait_ready();
    let restarted_search = http(
        stack.address().unwrap(),
        "POST",
        "/indexes/products/search",
        Some(r#"{"q":"Здравей"}"#),
    );
    assert!(
        restarted_search.contains("Здравей свят"),
        "{restarted_search}"
    );
}

#[test]
#[ignore = "requires a Linux Docker daemon and pulls real Meilisearch images"]
fn validation_failure_restores_the_real_source_image_volume_and_documents() {
    let _guard = DOCKER_TEST_LOCK.lock().unwrap();
    let stack = Stack::start();
    let task = json_post(
        stack.address().unwrap(),
        "/indexes/products/documents?primaryKey=id",
        r#"[{"id":1,"title":"rollback sentinel"}]"#,
    );
    wait_task(stack.address().unwrap(), task);

    let state_dir = tempfile::tempdir_in(stack.root.path()).unwrap();
    let trusted = TrustedRoot::parse(state_dir.path()).unwrap();
    let state = ManagedRoot::open(&trusted).unwrap();
    let request = upgrade_request(FAILURE_REQUEST_ID, "rollback");
    let driver = DockerDriver::new(stack.root.path(), &trusted);
    let mut driver = ValidationFailureDriver { inner: driver };
    let mut context = Context {
        engine_state: &state,
        driver: &mut driver,
    };
    let error = execute(&mut context, &request, &CancellationToken::default()).unwrap_err();

    assert!(
        matches!(
            error,
            operations_engine::meilisearch_upgrade::execute::Error::PhaseFailed {
                phase: "target validation",
                rollback_attempted: true,
                rollback_succeeded: true,
            }
        ),
        "{error:?}"
    );
    stack.wait_ready();
    let version = http(stack.address().unwrap(), "GET", "/version", None);
    assert!(version.contains(SOURCE_VERSION), "{version}");
    let search = http(
        stack.address().unwrap(),
        "POST",
        "/indexes/products/search",
        Some(r#"{"q":"rollback"}"#),
    );
    assert!(search.contains("rollback sentinel"), "{search}");
    let env = fs::read_to_string(stack.root.path().join(".env")).unwrap();
    assert!(env.contains(&format!("WCP_MEILISEARCH_IMAGE={SOURCE_IMAGE}")));
    assert!(env.contains("WCP_MEILISEARCH_VOLUME=wcp_meilisearch_data_it"));
}

#[test]
#[ignore = "requires a Linux Docker daemon and pulls real Meilisearch images"]
fn import_failure_after_real_shutdown_restores_the_source_and_documents() {
    let _guard = DOCKER_TEST_LOCK.lock().unwrap();
    let stack = Stack::start();
    let task = json_post(
        stack.address().unwrap(),
        "/indexes/products/documents?primaryKey=id",
        r#"[{"id":1,"title":"import rollback sentinel"}]"#,
    );
    wait_task(stack.address().unwrap(), task);

    let state_dir = tempfile::tempdir_in(stack.root.path()).unwrap();
    let trusted = TrustedRoot::parse(state_dir.path()).unwrap();
    let state = ManagedRoot::open(&trusted).unwrap();
    let request = upgrade_request(IMPORT_FAILURE_REQUEST_ID, "sentinel");
    let driver = DockerDriver::new(stack.root.path(), &trusted);
    let mut driver = ImportFailureDriver { inner: driver };
    let mut context = Context {
        engine_state: &state,
        driver: &mut driver,
    };
    let error = execute(&mut context, &request, &CancellationToken::default()).unwrap_err();

    assert!(
        matches!(
            error,
            operations_engine::meilisearch_upgrade::execute::Error::PhaseFailed {
                phase: "target import",
                rollback_attempted: true,
                rollback_succeeded: true,
            }
        ),
        "{error:?}"
    );
    stack.wait_ready();
    let version = http(stack.address().unwrap(), "GET", "/version", None);
    assert!(version.contains(SOURCE_VERSION), "{version}");
    let search = http(
        stack.address().unwrap(),
        "POST",
        "/indexes/products/search",
        Some(r#"{"q":"sentinel"}"#),
    );
    assert!(search.contains("import rollback sentinel"), "{search}");
    let env = fs::read_to_string(stack.root.path().join(".env")).unwrap();
    assert!(env.contains(&format!("WCP_MEILISEARCH_IMAGE={SOURCE_IMAGE}")));
    assert!(env.contains("WCP_MEILISEARCH_VOLUME=wcp_meilisearch_data_it"));
}

struct ImportFailureDriver<'a> {
    inner: DockerDriver<'a>,
}

impl Driver for ImportFailureDriver<'_> {
    type Error = DockerError;
    fn capture_baseline(
        &mut self,
        request: &UpgradeRequest,
        cancellation: &CancellationToken,
    ) -> Result<Baseline, Self::Error> {
        self.inner.capture_baseline(request, cancellation)
    }
    fn create_and_export_dump(
        &mut self,
        request: &UpgradeRequest,
        cancellation: &CancellationToken,
    ) -> Result<ExportedDump, Self::Error> {
        self.inner.create_and_export_dump(request, cancellation)
    }
    fn stop_source(
        &mut self,
        request: &UpgradeRequest,
        cancellation: &CancellationToken,
    ) -> Result<(), Self::Error> {
        self.inner.stop_source(request, cancellation)
    }
    fn import_target(
        &mut self,
        _request: &UpgradeRequest,
        _dump: &ExportedDump,
        _cancellation: &CancellationToken,
    ) -> Result<ImportedTarget, Self::Error> {
        Err(DockerError::InvalidDump)
    }
    fn validate_target(
        &mut self,
        request: &UpgradeRequest,
        baseline: &Baseline,
        target: &ImportedTarget,
        cancellation: &CancellationToken,
    ) -> Result<(), Self::Error> {
        self.inner
            .validate_target(request, baseline, target, cancellation)
    }
    fn cutover(
        &mut self,
        request: &UpgradeRequest,
        target: &ImportedTarget,
        cancellation: &CancellationToken,
    ) -> Result<(), Self::Error> {
        self.inner.cutover(request, target, cancellation)
    }
    fn rollback_source(&mut self, request: &UpgradeRequest) -> Result<(), Self::Error> {
        self.inner.rollback_source(request)
    }
}

struct ValidationFailureDriver<'a> {
    inner: DockerDriver<'a>,
}

impl Driver for ValidationFailureDriver<'_> {
    type Error = DockerError;
    fn capture_baseline(
        &mut self,
        request: &UpgradeRequest,
        cancellation: &CancellationToken,
    ) -> Result<Baseline, Self::Error> {
        self.inner.capture_baseline(request, cancellation)
    }
    fn create_and_export_dump(
        &mut self,
        request: &UpgradeRequest,
        cancellation: &CancellationToken,
    ) -> Result<ExportedDump, Self::Error> {
        self.inner.create_and_export_dump(request, cancellation)
    }
    fn stop_source(
        &mut self,
        request: &UpgradeRequest,
        cancellation: &CancellationToken,
    ) -> Result<(), Self::Error> {
        self.inner.stop_source(request, cancellation)
    }
    fn import_target(
        &mut self,
        request: &UpgradeRequest,
        dump: &ExportedDump,
        cancellation: &CancellationToken,
    ) -> Result<ImportedTarget, Self::Error> {
        self.inner.import_target(request, dump, cancellation)
    }
    fn validate_target(
        &mut self,
        _request: &UpgradeRequest,
        _baseline: &Baseline,
        _target: &ImportedTarget,
        _cancellation: &CancellationToken,
    ) -> Result<(), Self::Error> {
        Err(DockerError::ValidationMismatch)
    }
    fn cutover(
        &mut self,
        request: &UpgradeRequest,
        target: &ImportedTarget,
        cancellation: &CancellationToken,
    ) -> Result<(), Self::Error> {
        self.inner.cutover(request, target, cancellation)
    }
    fn rollback_source(&mut self, request: &UpgradeRequest) -> Result<(), Self::Error> {
        self.inner.rollback_source(request)
    }
}

fn upgrade_request(request_id: &str, query: &str) -> UpgradeRequest {
    UpgradeRequest::parse(&format!(r#"{{"stackName":"wp-stack","service":"meili-1","expectedSourceVersion":"{SOURCE_VERSION}","targetImage":"{TARGET_IMAGE}","masterKey":"{MASTER_KEY}","searchProbes":[{{"indexUid":"products","query":"{query}"}}]}}"#), request_id, None).unwrap()
}

fn json_post(address: SocketAddr, path: &str, body: &str) -> u64 {
    json_task(address, "POST", path, body)
}

fn json_task(address: SocketAddr, method: &str, path: &str, body: &str) -> u64 {
    let response = http(address, method, path, Some(body));
    assert!(
        response.starts_with("HTTP/1.1 202") || response.starts_with("HTTP/1.1 200"),
        "{response}"
    );
    let body = response.split("\r\n\r\n").nth(1).unwrap();
    let value: serde_json::Value = serde_json::from_str(body).unwrap();
    value
        .get("taskUid")
        .and_then(|v| v.as_u64())
        .unwrap_or(u64::MAX)
}

fn wait_task(address: SocketAddr, uid: u64) {
    let started = Instant::now();
    loop {
        let response = http(address, "GET", &format!("/tasks/{uid}"), None);
        if response.contains(r#""status":"succeeded""#) {
            return;
        }
        assert!(!response.contains(r#""status":"failed""#), "{response}");
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "task timed out"
        );
        thread::sleep(Duration::from_millis(200));
    }
}

fn wait_task_or_assert_search(address: SocketAddr, marker: u64) {
    assert_eq!(marker, u64::MAX, "search unexpectedly returned a task");
    let response = http(
        address,
        "POST",
        "/indexes/products/search",
        Some(r#"{"q":"Здравей"}"#),
    );
    assert!(response.contains("Здравей свят"), "{response}");
}

fn http(address: SocketAddr, method: &str, path: &str, body: Option<&str>) -> String {
    try_http(address, method, path, body).unwrap()
}

fn try_http(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> std::io::Result<String> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let body = body.unwrap_or("");
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {MASTER_KEY}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

fn compose(root: &Path, args: &[&str]) -> Command {
    let mut command = Command::new("docker");
    command
        .current_dir(root)
        .args([
            "compose",
            "-p",
            "wcp",
            "--env-file",
            ".env",
            "-f",
            "stack/docker-compose.yml",
        ])
        .args(args);
    command
}

fn docker(args: &[&str]) -> Command {
    let mut command = Command::new("docker");
    command.args(args);
    command
}
fn output(mut command: Command) -> String {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
