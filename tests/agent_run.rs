//! Public behaviour of `ops-engine agent run` and `agent configure`.
#![cfg(unix)]

use std::{fs, os::unix::fs::PermissionsExt, path::Path};

use assert_cmd::Command;
use serde_json::Value;

fn engine(dir: &Path, args: &[&str]) -> Command {
    let mut command = Command::cargo_bin("ops-engine").expect("binary should build");
    command
        .env("WCP_DIR", dir)
        .env("OPS_ENGINE", "/nonexistent/ops-engine")
        .env_remove("WCP_DRY_RUN")
        .env_remove("WCP_LOCK_HELD")
        .args(args);
    command
}

fn envelope(output: &[u8]) -> Value {
    let text = std::str::from_utf8(output).unwrap();
    assert_eq!(text.lines().count(), 1, "exactly one line: {text}");
    serde_json::from_str(text).unwrap()
}

fn install(dir: &Path, name: &str, script: &str) {
    fs::create_dir_all(dir.join("agents")).unwrap();
    let path = dir.join("agents").join(format!("{name}.sh"));
    fs::write(&path, script).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(
        dir.join("agents/manifest.json"),
        format!(r#"{{"{name}":{{"version":"1.0.0"}}}}"#),
    )
    .unwrap();
}

const AGENT: &str = r#"#!/usr/bin/env bash
echo "dry=$WCP_DRY_RUN dir=$WCP_DIR"
if [ "$WCP_DRY_RUN" != "1" ]; then
  mkdir -p "$WCP_DIR/logs"
  echo "{\"ts\":$(date +%s),\"exit_code\":0}" > "$WCP_DIR/agents/demo.heartbeat"
  echo "{\"ts\":$(date +%s),\"agent\":\"demo\",\"status\":\"ok\",\"summary\":\"fine\",\"data\":{}}" >> "$WCP_DIR/logs/demo.log"
fi
"#;

#[test]
fn run_reports_exit_code_heartbeat_and_result() {
    let dir = tempfile::tempdir().unwrap();
    install(dir.path(), "demo", AGENT);
    let output = engine(dir.path(), &["agent", "run", "demo"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let response = envelope(&output);
    assert_eq!(response["operation"], "agent.run");
    assert_eq!(response["ok"], true);
    let result = &response["result"];
    assert_eq!(result["agent"], "demo");
    assert_eq!(result["exitCode"], 0);
    assert_eq!(result["timedOut"], false);
    assert_eq!(result["dryRun"], false);
    assert_eq!(result["scheduler"], "cron");
    assert_eq!(result["heartbeat"]["exit_code"], 0);
    assert_eq!(result["result"]["status"], "ok");
    assert!(
        result["stdout"]
            .as_str()
            .unwrap()
            .contains(&format!("dir={}", dir.path().display()))
    );
}

#[test]
fn run_dry_writes_nothing_and_says_so() {
    let dir = tempfile::tempdir().unwrap();
    install(dir.path(), "demo", AGENT);
    let output = engine(dir.path(), &["agent", "run", "demo", "--dry-run"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result = &envelope(&output)["result"];
    assert_eq!(result["dryRun"], true);
    assert!(result["stdout"].as_str().unwrap().contains("dry=1"));
    assert!(result["heartbeat"].is_null());
    assert!(result["result"].is_null());
    assert!(!dir.path().join("logs").exists());
}

#[test]
fn run_reports_a_failing_agent_as_an_answer_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    install(
        dir.path(),
        "demo",
        "#!/usr/bin/env bash\necho oops >&2\nexit 7\n",
    );
    let output = engine(dir.path(), &["agent", "run", "demo"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result = &envelope(&output)["result"];
    assert_eq!(result["exitCode"], 7);
    assert_eq!(result["stderr"], "oops\n");
}

#[test]
fn run_refuses_what_it_should() {
    let dir = tempfile::tempdir().unwrap();
    let code = |args: &[&str]| -> Value {
        let output = engine(dir.path(), args)
            .assert()
            .failure()
            .get_output()
            .stdout
            .clone();
        envelope(&output)
    };
    assert_eq!(
        code(&["agent", "run", "missing"])["error"]["code"],
        "NOT_FOUND"
    );
    assert_eq!(
        code(&["agent", "run", "../x"])["error"]["code"],
        "INVALID_INPUT"
    );
    install(dir.path(), "demo", AGENT);
    assert_eq!(
        code(&["agent", "run", "demo", "--timeout-seconds", "0"])["error"]["code"],
        "INVALID_INPUT"
    );
    assert_eq!(
        code(&["agent", "run", "demo", "--timeout-seconds", "3601"])["error"]["code"],
        "INVALID_INPUT"
    );
}

#[test]
fn run_does_not_start_an_agent_whose_lock_is_held() {
    let dir = tempfile::tempdir().unwrap();
    install(
        dir.path(),
        "demo",
        "#!/usr/bin/env bash\ntouch \"$WCP_DIR/started\"\n",
    );
    // `agent lock` holds the lock for as long as its command runs.
    let mut holder = std::process::Command::new(env!("CARGO_BIN_EXE_ops-engine"))
        .args(["agent", "lock", "demo", "--", "sleep", "20"])
        .env("WCP_DIR", dir.path())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while engine(dir.path(), &["agent", "lock", "demo", "--check"])
        .output()
        .unwrap()
        .status
        .code()
        != Some(75)
    {
        assert!(std::time::Instant::now() < deadline, "lock never taken");
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let output = engine(dir.path(), &["agent", "run", "demo"])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    assert_eq!(envelope(&output)["error"]["code"], "CONFLICT");
    assert!(!dir.path().join("started").exists());
    holder.kill().unwrap();
    holder.wait().unwrap();
}

#[test]
fn configure_refuses_a_request_file_that_is_not_root_owned() {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        return; // the file below would be accepted; the root path is covered next
    }
    let dir = tempfile::tempdir().unwrap();
    install(dir.path(), "demo", AGENT);
    let request = dir.path().join("request.json");
    fs::write(&request, r#"{"name":"demo","values":{"A":"1"}}"#).unwrap();
    let output = engine(
        dir.path(),
        &[
            "agent",
            "configure",
            "--request-file",
            request.to_str().unwrap(),
        ],
    )
    .assert()
    .failure()
    .get_output()
    .stdout
    .clone();
    assert_eq!(envelope(&output)["error"]["code"], "INVALID_INPUT");
    assert!(!dir.path().join("agents/demo.conf").exists());
}

#[test]
fn configure_writes_the_file_config_get_reads_and_never_echoes_values() {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return; // the request file must be root-owned
    }
    let dir = tempfile::tempdir().unwrap();
    install(dir.path(), "demo", AGENT);
    let request = dir.path().join("request.json");
    fs::write(
        &request,
        r#"{"name":"demo","values":{"TOKEN_FILE":"/x","WEBHOOK_URL":"https://h.example/s3cret"}}"#,
    )
    .unwrap();
    fs::set_permissions(&request, fs::Permissions::from_mode(0o600)).unwrap();
    let output = engine(
        dir.path(),
        &[
            "agent",
            "configure",
            "--request-file",
            request.to_str().unwrap(),
        ],
    )
    .assert()
    .success()
    .get_output()
    .stdout
    .clone();
    assert!(!String::from_utf8_lossy(&output).contains("s3cret"));
    let response = envelope(&output);
    assert_eq!(response["result"]["changed"], true);
    assert_eq!(response["result"]["keys"][1], "WEBHOOK_URL");
    engine(
        dir.path(),
        &["agent", "config", "get", "demo", "WEBHOOK_URL"],
    )
    .assert()
    .success()
    .stdout("https://h.example/s3cret\n");
    let mode = fs::metadata(dir.path().join("agents/demo.conf"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}
