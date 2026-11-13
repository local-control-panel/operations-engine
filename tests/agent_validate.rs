//! Public behaviour of `ops-engine agent validate`.

use std::{fs, path::Path};

use assert_cmd::Command;
use serde_json::{Value, json};

fn validate(directory: &Path, manifest: &Path) -> (Value, bool) {
    let output = Command::cargo_bin("ops-engine")
        .expect("binary should build")
        .args(["agent", "validate", "--directory"])
        .arg(directory)
        .arg("--manifest-file")
        .arg(manifest)
        .output()
        .unwrap();
    let text = std::str::from_utf8(&output.stdout).unwrap();
    assert_eq!(text.lines().count(), 1, "exactly one line: {text}");
    (serde_json::from_str(text).unwrap(), output.status.success())
}

fn agent(root: &Path, script: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let directory = root.join("demo");
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join("agent.sh"), script).unwrap();
    let manifest = root.join("demo.json");
    fs::write(
        &manifest,
        json!({"name": "demo", "version": "1.0.0", "tier": "community", "author": "Ada",
               "script": "agent.sh", "schedule": "none", "default_schedule": "",
               "min_engine": "0.1.0", "description": "d", "paths": ["/root/.wcp"]})
        .to_string(),
    )
    .unwrap();
    (directory, manifest)
}

const GOOD: &str =
    "#!/usr/bin/env bash\n# wcp-agent: demo\n# wcp-agent-version: 1.0.0\nflock -n 9 || exit 0\n";

#[test]
fn a_good_agent_is_valid_and_the_command_is_listed() {
    let root = tempfile::tempdir().unwrap();
    let (directory, manifest) = agent(root.path(), GOOD);
    let (answer, ok) = validate(&directory, &manifest);
    assert!(ok);
    assert_eq!(answer["operation"], "agent.validate");
    assert_eq!(answer["result"]["valid"], true);
    assert_eq!(answer["result"]["agent"], "demo");
    assert_eq!(answer["result"]["problems"], json!([]));
    assert_eq!(answer["result"]["warnings"][0]["code"], "no_heartbeat");

    let capabilities = Command::cargo_bin("ops-engine")
        .unwrap()
        .arg("capabilities")
        .output()
        .unwrap();
    let capabilities: Value = serde_json::from_slice(&capabilities.stdout).unwrap();
    assert!(
        capabilities["result"]["operations"]
            .as_array()
            .unwrap()
            .contains(&json!("agent.validate"))
    );
}

#[test]
fn an_invalid_agent_is_an_answer_with_typed_problems_and_nothing_is_written() {
    let root = tempfile::tempdir().unwrap();
    let (directory, manifest) = agent(root.path(), &GOOD.replace("1.0.0", "2.0.0"));
    let before: Vec<_> = fs::read_dir(root.path())
        .unwrap()
        .count()
        .to_string()
        .into();
    let (answer, ok) = validate(&directory, &manifest);
    assert!(ok, "an answered check is not a failure");
    assert_eq!(answer["result"]["valid"], false);
    assert_eq!(
        answer["result"]["problems"][0]["code"],
        "header_version_mismatch"
    );
    assert_eq!(answer["result"]["problems"][0]["field"], "version");
    let after: Vec<_> = fs::read_dir(root.path())
        .unwrap()
        .count()
        .to_string()
        .into();
    assert_eq!(before, after);
}

#[test]
fn what_it_cannot_read_is_a_failure_never_valid() {
    let root = tempfile::tempdir().unwrap();
    let (directory, manifest) = agent(root.path(), GOOD);
    fs::write(&manifest, "not json").unwrap();
    let (answer, ok) = validate(&directory, &manifest);
    assert!(!ok);
    assert_eq!(answer["ok"], false);
    assert_eq!(answer["error"]["code"], "INVALID_INPUT");
    assert!(answer["result"].is_null());

    let (answer, ok) = validate(&root.path().join("missing"), &manifest);
    assert!(!ok);
    assert_eq!(answer["error"]["code"], "INVALID_INPUT");
}

#[test]
fn a_missing_or_linked_script_is_a_problem() {
    let root = tempfile::tempdir().unwrap();
    let (directory, manifest) = agent(root.path(), GOOD);
    fs::remove_file(directory.join("agent.sh")).unwrap();
    let (answer, _) = validate(&directory, &manifest);
    assert_eq!(answer["result"]["valid"], false);
    assert_eq!(answer["result"]["problems"][0]["code"], "script_missing");
    #[cfg(unix)]
    {
        fs::write(root.path().join("real.sh"), GOOD).unwrap();
        std::os::unix::fs::symlink(root.path().join("real.sh"), directory.join("agent.sh"))
            .unwrap();
        let (answer, _) = validate(&directory, &manifest);
        assert_eq!(answer["result"]["problems"][0]["code"], "script_missing");
    }
}
