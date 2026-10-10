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
