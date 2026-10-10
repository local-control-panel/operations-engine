// The capability list outgrew serde_json::json!'s default macro depth.
#![recursion_limit = "256"]

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
            "operation.status",
            "operation.list",
            "operation.incomplete",
            "backup.delete",
            "backup.importRemote",
            "backup.installRclone",
            "backup.createDatabase",
            "backup.scheduleDatabase",
            "backup.unscheduleDatabase",
            "backup.listScheduledDatabase",
            "backup.runScheduledDatabase",
            "backup.activateConfig",
            "backup.triggerNow",
            "site.list",
            "site.deploy",
            "site.rollback",
            "site.moveRoot",
            "site.prepareRoot",
            "site.removeRoot",
            "site.releaseRoot",
            "site.renameManifest",
            "site.enroll",
            "site.unenroll",
            "site.allocateIdentity",
            "site.releaseIdentity",
            "site.updateIdentity",
            "site.renameIdentity",
            "engine.install",
            "engine.rollback",
            "ingress.activateConfig",
            "ingress.park",
            "ingress.unpark",
            "ingress.removeRoute",
            "ingress.setEnabled",
            "ingress.applyBans",
            "ingress.reconcile",
            "runtime.activateConfig",
            "runtime.removeConfig",
            "runtime.reconcile",
            "cron.installTab",
            "db.restore",
            "db.export",
            "db.provisionMariaDb",
            "db.dropMariaDb",
            "db.dropMariaDbUser",
            "db.clearMariaSlowLog",
            "db.configureMariaSlowLog",
            "db.deleteValkeyKey",
            "db.flushValkeyDb",
            "db.flushAllValkey",
            "db.provisionPostgres",
            "db.dropPostgres",
            "db.provisionPostgresUser",
            "db.dropPostgresUser",
            "dbTool.converge",
            "dbTool.remove",
            "compose.activateConfig",
            "meilisearch.upgrade",
            "meilisearch.cleanup",
            "permissions.fixOwnership",
            "permissions.fixWorldWritable",
            "wordpress.cleanup",
            "wordpress.install",
            "wordpress.import",
            "wordpress.clone",
            "wordpress.migrateExport",
            "wordpress.migrateDiscard",
            "wordpress.migrateImport",
            "wordpress.updateCore",
            "wordpress.updatePlugins",
            "wordpress.updateThemes",
            "wordpress.rotateCredentials",
            "wordpress.multisiteDeleteSite",
            "wordpress.dropTables",
            "wordpress.boundedAction",
            "wordpress.typedActions",
            "wordpress.setSmtpRelay",
            "drupal.cacheRebuild",
            "drupal.cronRun",
            "drupal.maintenance",
            "tool.install",
            "tool.remove",
            "tool.status",
            "agent.activateBruteforceConfig",
            "agent.install",
            "agent.installFromRegistry",
            "agent.approve",
            "agent.unapprove",
            "agent.remove",
            "agent.bruteforceUnban",
            "agent.run",
            "agent.configure",
            "system.activateAutoupdatesConfig",
            "system.installAutoupdates",
            "system.installDocker",
            "system.startDocker",
            "system.signalProcess",
            "system.createSwap",
            "system.deleteSwap",
            "system.resizeSwap",
            "stack.deploy",
            "stack.reloadCaddy",
            "stack.stopIdleRuntime",
            "stack.ensureRuntime",
            "stack.reloadWorkers",
            "stack.flushFpc",
            "stack.writeSiteService",
            "stack.activateSiteConfig",
            "stack.removeSiteService",
            "docker.prune",
            "docker.containerAction",
            "docker.setLimits",
            "docker.network",
            "docker.imagePull",
            "docker.imageRemove",
            "docker.volumeRemove",
            "site.writeEnvFile",
            "site.quarantineFile",
            "site.phpInfoSession",
            "site.probe",
            "site.setErrorPages",
            "site.exportArchive",
            "site.importArchive",
            "site.discardArchive",
            "site.reconcile",
            "site.migrateRuntime",
            "system.service",
            "compose.action",
            "compose.remove",
            "site.changeLog.append",
            "site.changeLog.list"
        ])
    );
    assert_eq!(response["result"]["features"]["mutations"], true);
    assert_eq!(response["result"]["features"]["changeLog"], cfg!(unix));
    assert_eq!(
        response["result"]["features"]["agentHelpers"],
        serde_json::json!([
            "heartbeat",
            "lock",
            "log",
            "result",
            "config",
            "site",
            "version",
            "tool"
        ])
    );
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

#[test]
fn ingress_park_requires_a_domain_content_file_and_request_id() {
    let output = Command::cargo_bin("ops-engine")
        .expect("binary should build")
        .args(["ingress", "park"])
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
fn ingress_park_rejects_an_invalid_domain_before_touching_the_filesystem() {
    let output = Command::cargo_bin("ops-engine")
        .expect("binary should build")
        .args([
            "ingress",
            "park",
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

    assert_eq!(response["operation"], "ingress.park");
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

#[test]
fn ingress_unpark_requires_a_domain_and_request_id() {
    let output = Command::cargo_bin("ops-engine")
        .expect("binary should build")
        .args(["ingress", "unpark"])
        .assert()
        .failure();
    let stderr =
        String::from_utf8(output.get_output().stderr.clone()).expect("stderr should be UTF-8");
    assert!(
        stderr.contains("--domain"),
        "clap should report the missing --domain flag"
    );
    assert!(
        stderr.contains("--request-id"),
        "clap should report the missing --request-id flag"
    );
}

#[test]
fn ingress_unpark_rejects_an_invalid_domain_before_touching_the_filesystem() {
    let output = Command::cargo_bin("ops-engine")
        .expect("binary should build")
        .args([
            "ingress",
            "unpark",
            "--domain",
            "NOT A DOMAIN",
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

    assert_eq!(response["operation"], "ingress.unpark");
    assert_eq!(response["ok"], false);
    assert_eq!(response["error"]["code"], "INVALID_INPUT");
    assert_eq!(
        response["error"]["message"],
        "domain is not a valid domain name"
    );
}

#[cfg(unix)]
fn journal_failure(args: &[&str]) -> Value {
    let output = Command::cargo_bin("ops-engine")
        .expect("binary should build")
        .args(args)
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&output).expect("stdout should contain one JSON response")
}

/// Validation runs before the engine configuration is read, so these
/// answers do not depend on the host the tests run on.
#[cfg(unix)]
#[test]
fn journal_append_rejects_invalid_fields_before_touching_state() {
    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    let base = |extra: &[&str]| {
        let mut args = vec![
            "change-log",
            "append",
            "--actor",
            "admin@example.com",
            "--action",
            "cms.adminLogin",
            "--result",
            "ok",
            "--request-id",
            ID,
        ];
        args.extend_from_slice(extra);
        journal_failure(&args)
    };
    for (extra, message) in [
        (
            vec!["--summary", "open https://example.com/?token=abc"],
            "summary is not allowed",
        ),
        (
            vec!["--summary", "password=hunter2"],
            "summary is not allowed",
        ),
        (
            vec!["--target", "https://example.com/login"],
            "target is invalid",
        ),
        (vec!["--site", "a b"], "site is invalid"),
        (vec!["--environment", "prod"], "environment is invalid"),
        (vec!["--error-code", "lower"], "error-code is invalid"),
        (
            vec!["--idempotency-key", "has space"],
            "idempotency-key is invalid",
        ),
    ] {
        let response = base(&extra);
        assert_eq!(response["operation"], "site.changeLog.append");
        assert_eq!(response["ok"], false);
        assert_eq!(response["error"]["code"], "INVALID_INPUT");
        assert_eq!(response["error"]["message"], message);
        // Rejected values are never echoed back.
        let text = response.to_string();
        assert!(
            !text.contains("hunter2") && !text.contains("example.com/"),
            "{text}"
        );
    }

    let response = journal_failure(&[
        "change-log",
        "append",
        "--actor",
        "u",
        "--action",
        "nope.thing",
        "--result",
        "ok",
        "--request-id",
        ID,
    ]);
    assert_eq!(response["error"]["message"], "action is invalid");
    let response = journal_failure(&[
        "change-log",
        "append",
        "--actor",
        "u",
        "--action",
        "site.deploy",
        "--result",
        "ok",
        "--request-id",
        "not-a-uuid",
    ]);
    assert_eq!(response["error"]["code"], "INVALID_INPUT");
}

#[cfg(unix)]
#[test]
fn journal_list_rejects_invalid_filters() {
    for (args, message) in [
        (vec!["--result", "maybe"], "result is invalid"),
        (vec!["--source", "panel"], "source is invalid"),
        (vec!["--site", "a b"], "site is invalid"),
        (vec!["--environment", "prod"], "environment is invalid"),
        (vec!["--subsite", "a b"], "subsite is invalid"),
        (vec!["--action-prefix", "cms?"], "action-prefix is invalid"),
    ] {
        let mut full = vec!["change-log", "list"];
        full.extend(args);
        let response = journal_failure(&full);
        assert_eq!(response["operation"], "site.changeLog.list");
        assert_eq!(response["error"]["code"], "INVALID_INPUT");
        assert_eq!(response["error"]["message"], message);
    }
}
