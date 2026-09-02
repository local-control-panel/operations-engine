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
    assert!(response["error"].is_null());
}

#[test]
fn capabilities_describe_only_implemented_operations() {
    let response = run_json(&["capabilities"]);

    assert_eq!(
        response["result"]["operations"],
        serde_json::json!(["version", "capabilities", "doctor"])
    );
    assert_eq!(response["result"]["features"]["mutations"], false);
}

#[test]
fn doctor_returns_structured_checks() {
    let response = run_json(&["doctor"]);

    assert_eq!(response["operation"], "doctor");
    assert!(response["result"]["platform"]["os"].is_string());
    assert!(response["result"]["dependencies"].is_array());
}
