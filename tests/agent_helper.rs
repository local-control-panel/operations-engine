//! Public behaviour of `ops-engine agent heartbeat|lock|log`: exit codes,
//! stdout and the files left in `$WCP_DIR`.
#![cfg(unix)]

use std::{fs, os::fd::AsRawFd, path::Path};

use assert_cmd::Command;
use serde_json::Value;

fn engine(dir: &Path, args: &[&str]) -> Command {
    let mut command = Command::cargo_bin("ops-engine").expect("binary should build");
    command
        .env("WCP_DIR", dir)
        .env_remove("WCP_DRY_RUN")
        .env_remove("WCP_LOCK_HELD")
        .args(args);
    command
}

fn json_lines(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn heartbeat_is_silent_and_writes_ts_and_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    engine(
        dir.path(),
        &["agent", "heartbeat", "demo", "--exit-code", "3"],
    )
    .assert()
    .success()
    .stdout("");
    let beat: Value = serde_json::from_str(
        &fs::read_to_string(dir.path().join("agents/demo.heartbeat")).unwrap(),
    )
    .unwrap();
    assert_eq!(beat["exit_code"], 3);
    assert!(beat["ts"].as_u64().unwrap() > 1_700_000_000);
    assert_eq!(beat.as_object().unwrap().len(), 2);
}

#[test]
fn heartbeat_json_prints_one_envelope() {
    let dir = tempfile::tempdir().unwrap();
    let output = engine(dir.path(), &["agent", "heartbeat", "demo", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let response: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(response["operation"], "agent.heartbeat");
    assert_eq!(response["ok"], true);
    assert_eq!(response["result"]["written"], true);
}

#[test]
fn heartbeat_accepts_a_negative_exit_code_and_rejects_bad_names() {
    let dir = tempfile::tempdir().unwrap();
    engine(
        dir.path(),
        &["agent", "heartbeat", "demo", "--exit-code", "-1"],
    )
    .assert()
    .success();
    let output = engine(dir.path(), &["agent", "heartbeat", "../etc", "--json"])
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let response: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(response["ok"], false);
    assert_eq!(response["error"]["code"], "INVALID_INPUT");
}

#[test]
fn dry_run_leaves_no_heartbeat_and_no_log() {
    let dir = tempfile::tempdir().unwrap();
    engine(dir.path(), &["agent", "heartbeat", "demo"])
        .env("WCP_DRY_RUN", "1")
        .assert()
        .success();
    engine(dir.path(), &["agent", "log", "demo", "hello"])
        .env("WCP_DRY_RUN", "1")
        .assert()
        .success();
    assert!(!dir.path().join("agents/demo.heartbeat").exists());
    assert!(!dir.path().join("logs/demo.log").exists());
}

#[test]
fn log_appends_json_lines_and_stays_bounded() {
    let dir = tempfile::tempdir().unwrap();
    for n in 0..6 {
        engine(
            dir.path(),
            &[
                "agent",
                "log",
                "demo",
                "--max-lines",
                "3",
                "--level",
                "warn",
                &format!("line {n}"),
            ],
        )
        .assert()
        .success()
        .stdout("");
    }
    let lines = json_lines(&dir.path().join("logs/demo.log"));
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0]["msg"], "line 3");
    assert_eq!(lines[2]["msg"], "line 5");
    assert_eq!(lines[2]["level"], "warn");
    assert_eq!(lines[2]["agent"], "demo");
}

#[test]
fn log_reads_the_message_from_stdin_when_none_is_given() {
    let dir = tempfile::tempdir().unwrap();
    engine(dir.path(), &["agent", "log", "demo"])
        .write_stdin("from a pipe\n")
        .assert()
        .success();
    let lines = json_lines(&dir.path().join("logs/demo.log"));
    assert_eq!(lines[0]["msg"], "from a pipe");
}

#[test]
fn lock_runs_the_command_and_returns_its_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    engine(
        dir.path(),
        &[
            "agent",
            "lock",
            "demo",
            "--",
            "sh",
            "-c",
            "echo out; exit 7",
        ],
    )
    .assert()
    .code(7)
    .stdout("out\n");
}

#[test]
fn lock_is_held_while_the_command_runs_and_released_after() {
    let dir = tempfile::tempdir().unwrap();
    let probe = format!(
        "'{}' agent lock demo --check; echo probe=$?",
        env!("CARGO_BIN_EXE_ops-engine")
    );
    engine(
        dir.path(),
        &["agent", "lock", "demo", "--", "sh", "-c", &probe],
    )
    .assert()
    .success()
    .stdout("probe=75\n");
    engine(dir.path(), &["agent", "lock", "demo", "--check"])
        .assert()
        .success();
}

#[test]
fn the_command_sees_which_lock_it_holds() {
    let dir = tempfile::tempdir().unwrap();
    engine(
        dir.path(),
        &[
            "agent",
            "lock",
            "demo",
            "--",
            "sh",
            "-c",
            "echo $WCP_LOCK_HELD",
        ],
    )
    .assert()
    .success()
    .stdout("demo\n");
}

#[test]
fn a_second_run_exits_zero_without_starting_the_command() {
    let dir = tempfile::tempdir().unwrap();
    // Another run, simulated by holding the same flock from this process.
    fs::create_dir_all(dir.path().join("agents")).unwrap();
    let holder = fs::File::create(dir.path().join("agents/demo.lock")).unwrap();
    assert_eq!(
        unsafe { libc::flock(holder.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    engine(dir.path(), &["agent", "lock", "demo", "--check"])
        .assert()
        .code(75);

    let marker = dir.path().join("ran");
    let script = format!("touch '{}'", marker.display());
    engine(
        dir.path(),
        &["agent", "lock", "demo", "--", "sh", "-c", &script],
    )
    .assert()
    .success()
    .stdout("");
    assert!(!marker.exists(), "the command must not start while locked");

    let output = engine(
        dir.path(),
        &[
            "agent",
            "lock",
            "demo",
            "--json",
            "--held-exit-code",
            "4",
            "--",
            "true",
        ],
    )
    .assert()
    .code(4)
    .get_output()
    .stdout
    .clone();
    let response: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(response["result"]["held"], true);
    assert_eq!(response["result"]["ran"], false);

    drop(holder);
}

#[test]
fn lock_reports_a_missing_command_as_127() {
    let dir = tempfile::tempdir().unwrap();
    engine(
        dir.path(),
        &["agent", "lock", "demo", "--", "no-such-command-here"],
    )
    .assert()
    .code(127);
}

#[test]
fn lock_needs_a_command_or_check() {
    let dir = tempfile::tempdir().unwrap();
    engine(dir.path(), &["agent", "lock", "demo"])
        .assert()
        .code(2);
}

fn one_envelope(output: &[u8]) -> Value {
    let text = std::str::from_utf8(output).unwrap();
    assert_eq!(text.lines().count(), 1, "exactly one line: {text}");
    serde_json::from_str(text).unwrap()
}

#[test]
fn result_emit_appends_the_result_line_after_log_lines() {
    let dir = tempfile::tempdir().unwrap();
    engine(dir.path(), &["agent", "log", "demo", "started"])
        .assert()
        .success();
    engine(
        dir.path(),
        &[
            "agent",
            "result",
            "emit",
            "demo",
            "--status",
            "warn",
            "--summary",
            "checked 3 sites",
            "--data",
            "sites=3",
            "--data-json",
            r#"{"slow": ["a.example.com"]}"#,
        ],
    )
    .assert()
    .success()
    .stdout("");
    let lines = json_lines(&dir.path().join("logs/demo.log"));
    assert_eq!(lines.len(), 2);
    let result = &lines[1];
    assert_eq!(result["agent"], "demo");
    assert_eq!(result["status"], "warn");
    assert_eq!(result["summary"], "checked 3 sites");
    assert_eq!(result["data"]["sites"], "3");
    assert_eq!(result["data"]["slow"][0], "a.example.com");
    assert!(result["ts"].as_u64().unwrap() > 1_700_000_000);
}

#[test]
fn result_emit_json_and_dry_run() {
    let dir = tempfile::tempdir().unwrap();
    let output = engine(
        dir.path(),
        &[
            "agent",
            "result",
            "emit",
            "demo",
            "--status",
            "ok",
            "--summary",
            "fine",
            "--json",
        ],
    )
    .env("WCP_DRY_RUN", "1")
    .assert()
    .success()
    .get_output()
    .stdout
    .clone();
    let response = one_envelope(&output);
    assert_eq!(response["operation"], "agent.result.emit");
    assert_eq!(response["result"]["written"], false);
    assert_eq!(response["result"]["dryRun"], true);
    assert_eq!(response["result"]["line"]["status"], "ok");
    assert!(!dir.path().join("logs").exists());
}

#[test]
fn result_emit_rejects_bad_input_with_exit_2_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let base = [
        "agent",
        "result",
        "emit",
        "demo",
        "--status",
        "ok",
        "--summary",
        "s",
    ];
    for extra in [
        vec!["--data", "novalue"],
        vec!["--data", "api_token=abc"],
        vec!["--data-json", "[1]"],
        vec!["--max-lines", "0"],
    ] {
        let mut args = base.to_vec();
        args.extend(extra);
        engine(dir.path(), &args).assert().code(2).stdout("");
    }
    engine(
        dir.path(),
        &[
            "agent",
            "result",
            "emit",
            "demo",
            "--status",
            "ok",
            "--summary",
            " ",
        ],
    )
    .assert()
    .code(2);
    engine(
        dir.path(),
        &[
            "agent",
            "result",
            "emit",
            "demo",
            "--status",
            "bogus",
            "--summary",
            "s",
        ],
    )
    .assert()
    .code(2);
    engine(
        dir.path(),
        &[
            "agent",
            "result",
            "emit",
            "../x",
            "--status",
            "ok",
            "--summary",
            "s",
        ],
    )
    .assert()
    .code(2);
    assert!(!dir.path().join("logs").exists());
}

fn write_conf(dir: &Path, name: &str, text: &str) {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(dir.join("agents")).unwrap();
    let path = dir.join("agents").join(format!("{name}.conf"));
    fs::write(&path, text).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn config_get_prints_the_value_and_falls_back_to_the_default() {
    let dir = tempfile::tempdir().unwrap();
    write_conf(
        dir.path(),
        "demo",
        "# c\nWEBHOOK_URL=https://h.example/x?a=b\nEMPTY=\n",
    );
    engine(
        dir.path(),
        &["agent", "config", "get", "demo", "WEBHOOK_URL"],
    )
    .assert()
    .success()
    .stdout("https://h.example/x?a=b\n");
    engine(dir.path(), &["agent", "config", "get", "demo", "EMPTY"])
        .assert()
        .success()
        .stdout("\n");
    engine(
        dir.path(),
        &[
            "agent",
            "config",
            "get",
            "demo",
            "MISSING",
            "--default",
            "7",
        ],
    )
    .assert()
    .success()
    .stdout("7\n");
    engine(dir.path(), &["agent", "config", "get", "demo", "MISSING"])
        .assert()
        .code(1)
        .stdout("");
    engine(
        dir.path(),
        &["agent", "config", "get", "nofile", "K", "--default", "d"],
    )
    .assert()
    .success()
    .stdout("d\n");
    engine(dir.path(), &["agent", "config", "get", "nofile", "K"])
        .assert()
        .code(1);
    engine(dir.path(), &["agent", "config", "get", "demo", "bad-key"])
        .assert()
        .code(2);
}

#[test]
fn config_get_json_carries_the_value_and_list_never_does() {
    let dir = tempfile::tempdir().unwrap();
    write_conf(dir.path(), "demo", "B=2\nA_SECRET=hunter2\n");
    let output = engine(
        dir.path(),
        &["agent", "config", "get", "demo", "B", "--json"],
    )
    .assert()
    .success()
    .get_output()
    .stdout
    .clone();
    let response = one_envelope(&output);
    assert_eq!(response["result"]["value"], "2");
    assert_eq!(response["result"]["source"], "file");
    let output = engine(dir.path(), &["agent", "config", "list", "demo"])
        .assert()
        .success()
        .stdout("A_SECRET\nB\n")
        .get_output()
        .stdout
        .clone();
    assert!(!String::from_utf8(output).unwrap().contains("hunter2"));
    let output = engine(dir.path(), &["agent", "config", "list", "demo", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(output).unwrap();
    assert!(!text.contains("hunter2"));
    assert_eq!(one_envelope(text.as_bytes())["result"]["keys"][1], "B");
}

#[test]
fn a_broken_configuration_fails_without_echoing_it() {
    let dir = tempfile::tempdir().unwrap();
    write_conf(dir.path(), "demo", "A=1\nhunter2-no-equals\n");
    let output = engine(
        dir.path(),
        &["agent", "config", "get", "demo", "A", "--default", "x"],
    )
    .assert()
    .code(1)
    .stdout("")
    .get_output()
    .stderr
    .clone();
    let stderr = String::from_utf8(output).unwrap();
    assert!(stderr.contains("line 2"));
    assert!(!stderr.contains("hunter2"));
}

#[test]
fn site_list_prints_domains_and_the_full_records_with_json() {
    let dir = tempfile::tempdir().unwrap();
    let manifests = dir.path().join("manifests");
    let www = dir.path().join("www");
    fs::create_dir_all(&manifests).unwrap();
    fs::create_dir_all(www.join("plain.example.com")).unwrap();
    let id = "11111111-1111-4111-8111-111111111111";
    fs::write(
        manifests.join(format!("{id}.json")),
        serde_json::json!({
            "schemaVersion": 1, "siteId": id, "domain": "app.example.com",
            "contentRoot": format!("sites/{id}/current"), "siteUser": "site1",
            "repository": {"url": "https://example.test/r.git",
                           "allowedBranches": ["main"], "credentialId": id}
        })
        .to_string(),
    )
    .unwrap();
    let run = |extra: &[&str]| {
        let mut args = vec!["agent", "site", "list"];
        args.extend(extra);
        let mut command = engine(dir.path(), &args);
        command
            .env("WCP_SITES_MANIFEST_DIR", &manifests)
            .env("SITES_ROOT", &www);
        command
    };
    run(&[])
        .assert()
        .success()
        .stdout("app.example.com\nplain.example.com\n");
    let output = run(&["--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let response = one_envelope(&output);
    assert_eq!(response["operation"], "agent.site.list");
    let sites = response["result"]["sites"].as_array().unwrap();
    assert_eq!(sites.len(), 2);
    assert_eq!(sites[0]["siteId"], id);
    assert_eq!(sites[0]["siteUser"], "site1");
    assert_eq!(sites[0]["source"], "manifest");
    assert_eq!(sites[1]["source"], "filesystem");
    assert!(!String::from_utf8_lossy(&output).contains("example.test"));
}

#[test]
fn site_list_on_an_empty_server_prints_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let mut command = engine(dir.path(), &["agent", "site", "list"]);
    command
        .env("WCP_SITES_MANIFEST_DIR", dir.path().join("none"))
        .env("SITES_ROOT", dir.path().join("none2"));
    command.assert().success().stdout("");
}

#[test]
fn version_lists_the_helpers_and_help_names_the_subcommands() {
    let dir = tempfile::tempdir().unwrap();
    let output = engine(dir.path(), &["agent", "version"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(output).unwrap();
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some("agent-helpers 1"));
    let names: Vec<_> = lines.collect();
    for expected in [
        "heartbeat",
        "lock",
        "log",
        "result",
        "config",
        "site",
        "version",
    ] {
        assert!(names.contains(&expected), "{expected}");
    }
    let output = engine(dir.path(), &["agent", "version", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let response = one_envelope(&output);
    assert_eq!(response["result"]["helperApi"], 1);
    assert!(
        response["result"]["helpers"]
            .as_array()
            .unwrap()
            .contains(&"result".into())
    );
    let help = engine(dir.path(), &["agent", "help"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let help = String::from_utf8(help).unwrap();
    for word in [
        "heartbeat",
        "lock",
        "log",
        "result",
        "config",
        "site",
        "version",
    ] {
        assert!(help.contains(word), "{word}");
    }
}

#[test]
fn site_list_is_a_protocol_operation_too() {
    let output = Command::cargo_bin("ops-engine")
        .unwrap()
        .args(["site", "list"])
        .assert()
        .get_output()
        .stdout
        .clone();
    let response = one_envelope(&output);
    assert_eq!(response["operation"], "site.list");
    assert_eq!(response["ok"], true);
    assert!(response["result"]["sites"].is_array());
}
