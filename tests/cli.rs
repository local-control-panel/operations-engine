use assert_cmd::Command;
use serde_json::Value;

fn run_json(args: &[&str]) -> Value {
    let output = Command::cargo_bin("ops-engine")
        .expect("binary should build")
        .args(args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    serde_json::from_slice(&output).expect("stdout should contain one JSON response")
}

#[test]
fn version_returns_protocol_envelope() {
    let response = run_json(&["version", "--output", "json"]);

    assert_eq!(response["protocolVersion"], 1);
    assert_eq!(response["operation"], "version");
    assert_eq!(response["ok"], true);
    assert_eq!(
        response["result"]["engineVersion"],
        env!("CARGO_PKG_VERSION")
    );
    assert!(response["result"]["build"]["targetOs"].is_string());
    assert!(response["result"]["build"]["targetArchitecture"].is_string());
    assert!(response["error"].is_null());
}

#[test]
fn capabilities_describe_only_implemented_operations() {
    let response = run_json(&["capabilities"]);

    assert_eq!(
        response["result"]["operations"],
        serde_json::json!([
            "version",
            "capabilities",
            "doctor",
            "site.deploy",
            "site.rollback",
            "engine.install",
            "engine.rollback",
            "ingress.activateConfig"
        ])
    );
    assert_eq!(response["result"]["features"]["mutations"], true);
    // Neither mechanism is wired to the CLI process lifecycle yet: nothing
    // ever calls `CancellationToken::cancel()` from a signal, and `--output`
    // has no JSON Lines variant. Advertising either now would be a real
    // regression under the "don't advertise before implemented" rule.
    assert_eq!(response["result"]["features"]["cancellation"], false);
    assert_eq!(response["result"]["features"]["jsonLinesProgress"], false);
}

#[test]
fn doctor_returns_structured_checks() {
    let response = run_json(&["doctor"]);

    assert_eq!(response["operation"], "doctor");
    assert_eq!(response["ok"], true);
    assert!(response["result"]["ready"].is_boolean());
    assert!(response["result"]["platform"]["os"].is_string());
    assert!(response["result"]["dependencies"].is_array());
}

#[cfg(target_os = "linux")]
#[test]
fn doctor_is_deterministic_with_controlled_dependencies() {
    use std::{fs, os::unix::fs::PermissionsExt};

    let directory = tempfile::tempdir().expect("temporary directory should be created");
    for (name, version) in [
        ("git", "git test 1.0"),
        ("docker", "docker test 1.0"),
        ("caddy", "caddy test 1.0"),
    ] {
        let path = directory.path().join(name);
        fs::write(&path, format!("#!/bin/sh\nprintf '%s\\n' '{version}'\n"))
            .expect("fake dependency should be written");
        let mut permissions = fs::metadata(&path)
            .expect("fake dependency metadata should exist")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("fake dependency should be executable");
    }

    let output = Command::cargo_bin("ops-engine")
        .expect("binary should build")
        .arg("doctor")
        .env("PATH", directory.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let response: Value =
        serde_json::from_slice(&output).expect("stdout should contain one JSON response");

    assert_eq!(response["result"]["ready"], true);
    assert_eq!(response["warnings"], serde_json::json!([]));
    assert_eq!(
        response["result"]["dependencies"][0]["version"],
        "git test 1.0"
    );
}

#[test]
fn engine_install_requires_a_version_and_request_id() {
    let output = Command::cargo_bin("ops-engine")
        .expect("binary should build")
        .args(["engine", "install"])
        .assert()
        .failure();
    let stderr =
        String::from_utf8(output.get_output().stderr.clone()).expect("stderr should be UTF-8");
    assert!(
        stderr.contains("--version"),
        "clap should report the missing --version flag"
    );
}

#[test]
fn ingress_activate_config_requires_a_domain_content_file_and_request_id() {
    let output = Command::cargo_bin("ops-engine")
        .expect("binary should build")
        .args(["ingress", "activate-config"])
        .assert()
        .failure();
    let stderr =
        String::from_utf8(output.get_output().stderr.clone()).expect("stderr should be UTF-8");
    assert!(
        stderr.contains("--domain"),
        "clap should report the missing --domain flag"
    );
    assert!(
        stderr.contains("--content-file"),
        "clap should report the missing --content-file flag"
    );
}

#[test]
fn ingress_activate_config_rejects_an_invalid_domain_before_touching_the_filesystem() {
    let output = Command::cargo_bin("ops-engine")
        .expect("binary should build")
        .args([
            "ingress",
            "activate-config",
            "--domain",
            "NOT A DOMAIN",
            "--content-file",
            "/nonexistent/path/should/not/be/read.caddyfile",
            "--request-id",
            "123e4567-e89b-12d3-a456-426614174000",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let response: Value =
        serde_json::from_slice(&output).expect("stdout should contain one JSON response");

    assert_eq!(response["operation"], "ingress.activateConfig");
    assert_eq!(response["ok"], false);
    assert_eq!(response["error"]["code"], "INVALID_INPUT");
    // `content-file` also produces `INVALID_INPUT` when it cannot be read,
    // so pin the message too: this must be a domain-validation rejection,
    // not the file-read failure it would be if the content file were read
    // before the cheap fields were validated.
    assert_eq!(
        response["error"]["message"],
        "domain is not a valid domain name"
    );
}
