use super::*;
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
const ID2: &str = "123e4567-e89b-12d3-a456-426614174001";
const ID3: &str = "123e4567-e89b-12d3-a456-426614174002";

struct Fixture {
    directory: tempfile::TempDir,
    state: ManagedRoot,
    docker: PathBuf,
}

impl Fixture {
    /// Logs argv and stdin of every call. A SELECT is answered from the
    /// `PROBE` file (default: no account, database present); marker files
    /// make the statements fail.
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let state_path = directory.path().join("state");
        fs::create_dir(&state_path).unwrap();
        let docker = directory.path().join("docker");
        fs::write(
            &docker,
            r#"#!/bin/sh
base="$(dirname "$0")"
printf '%s\n' "$*" >> "$base/argv.log"
input="$(cat)"
printf '%s\n--\n' "$input" >> "$base/stdin.log"
case "$input" in
  *"COUNT(*)"*) printf '%b\n' "$(cat "$base/PROBE" 2>/dev/null || printf '0\\t1')" ;;
  *"ALTER USER"*) test -f "$base/REJECT_ALTER" && exit 1; exit 0 ;;
  *) exit 0 ;;
esac
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&docker).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&docker, permissions).unwrap();
        let state =
            ManagedRoot::open(&crate::site::TrustedRoot::parse(&state_path).unwrap()).unwrap();
        Self {
            directory,
            state,
            docker,
        }
    }

    fn context(&self) -> Context<'_> {
        Context {
            engine_state: &self.state,
            docker_program: self.docker.to_str().unwrap(),
        }
    }

    fn mark(&self, name: &str, content: &str) {
        fs::write(self.directory.path().join(name), content).unwrap();
    }

    fn read(&self, name: &str) -> String {
        fs::read_to_string(self.directory.path().join(name)).unwrap_or_default()
    }

    /// Every file under the engine state directory, concatenated.
    fn state_dump(&self) -> String {
        fn walk(path: &std::path::Path, out: &mut String) {
            for entry in fs::read_dir(path).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if let Ok(text) = fs::read_to_string(&path) {
                    out.push_str(&text);
                }
            }
        }
        let mut out = String::new();
        walk(&self.directory.path().join("state"), &mut out);
        out
    }
}

fn ensure_request(id: &str, key: Option<&str>, rotate: bool) -> Request {
    Request::parse_ensure(
        &serde_json::json!({"container":"mariadb-11","rootPassword":"top-secret","database":"site_db","rotate":rotate})
            .to_string(),
        id,
        key,
    )
    .unwrap()
}

fn revoke_request(id: &str, key: Option<&str>) -> Request {
    Request::parse_revoke(
        r#"{"container":"mariadb-11","rootPassword":"top-secret","database":"site_db"}"#,
        id,
        key,
    )
    .unwrap()
}

fn issued(ensured: Ensured) -> (EnsurePublic, String) {
    let Ensured::Issued(result) = ensured else {
        panic!("expected an issued password: {ensured:?}");
    };
    let response =
        crate::protocol::Response::success_with_secret(ENSURE_OPERATION, *result).unwrap();
    let value = serde_json::to_value(&response).unwrap();
    let result = value["result"].clone();
    (
        serde_json::from_value(result.clone()).unwrap(),
        result["password"].as_str().unwrap().to_owned(),
    )
}

#[test]
fn new_account_gets_a_generated_password_over_stdin_only() {
    let fixture = Fixture::new();
    let ensured = ensure(
        &fixture.context(),
        &ensure_request(ID, None, false),
        &CancellationToken::default(),
    )
    .unwrap();
    let (public, password) = issued(ensured);
    assert_eq!(public.username, "ro_site_db");
    assert_eq!(public.host, "localhost");
    assert!(public.created && public.password_issued);
    assert_eq!(public.limits, LIMITS);
    assert_eq!(password.len(), 32);
    assert!(password.chars().all(|c| c.is_ascii_alphanumeric()));

    let stdin = fixture.read("stdin.log");
    let calls: Vec<&str> = stdin.split("\n--\n").filter(|s| !s.is_empty()).collect();
    assert_eq!(calls.len(), 2, "one probe and one statement run");
    assert!(calls[0].starts_with("top-secret\nSELECT"));
    let expected = ensure_statements(
        "ro_site_db",
        &crate::db_restore::DatabaseName::parse("site_db").unwrap(),
        Some(&password),
    );
    assert_eq!(calls[1], format!("top-secret\n{}", expected.join("\n")));

    let argv = fixture.read("argv.log");
    assert!(!argv.contains("top-secret") && !argv.contains(&password));
    assert!(argv.contains("exec -i mariadb-11 sh -c"));
    // Neither secret reaches state or audit.
    let dump = fixture.state_dump();
    assert!(!dump.contains("top-secret") && !dump.contains(&password));
    assert!(dump.contains("ro_site_db"));
}

#[test]
fn existing_account_keeps_its_password_unless_rotating() {
    let fixture = Fixture::new();
    fixture.mark("PROBE", "1\\t1");
    let ensured = ensure(
        &fixture.context(),
        &ensure_request(ID, None, false),
        &CancellationToken::default(),
    )
    .unwrap();
    let Ensured::Existing(public) = ensured else {
        panic!("expected no password");
    };
    assert!(!public.created && !public.password_issued);
    let stdin = fixture.read("stdin.log");
    assert!(!stdin.contains("ALTER USER"));
    // The grant and limits are re-asserted anyway.
    assert!(stdin.contains("GRANT SELECT ON `site\\_db`.*"));
    assert!(stdin.contains("FLUSH PRIVILEGES;"));

    let rotated = ensure(
        &fixture.context(),
        &ensure_request(ID2, None, true),
        &CancellationToken::default(),
    )
    .unwrap();
    let (public, password) = issued(rotated);
    assert!(!public.created && public.password_issued);
    assert!(
        fixture
            .read("stdin.log")
            .contains(&format!("IDENTIFIED BY '{password}'"))
    );
}

#[test]
fn replay_returns_the_public_record_without_a_password() {
    let fixture = Fixture::new();
    let first = ensure(
        &fixture.context(),
        &ensure_request(ID, Some("key-1"), false),
        &CancellationToken::default(),
    )
    .unwrap();
    let (_, password) = issued(first);
    let calls_before = fixture.read("argv.log").lines().count();

    let replay = ensure(
        &fixture.context(),
        &ensure_request(ID2, Some("key-1"), false),
        &CancellationToken::default(),
    )
    .unwrap();
    let Ensured::AlreadyIssued(public) = replay else {
        panic!("expected a replay");
    };
    assert_eq!(public["username"], "ro_site_db");
    assert!(public.get("password").is_none());
    assert!(!public.to_string().contains(&password));
    assert_eq!(fixture.read("argv.log").lines().count(), calls_before);

    let response = crate::secret_result::replayed(ENSURE_OPERATION, public).unwrap();
    let value = serde_json::to_value(&response).unwrap();
    assert_eq!(value["result"]["alreadyIssued"], true);
    assert_ne!(value["secretResult"], true);
    assert!(!value.to_string().contains(&password));
}

#[test]
fn missing_database_is_refused_before_any_change() {
    let fixture = Fixture::new();
    fixture.mark("PROBE", "0\\t0");
    let error = ensure(
        &fixture.context(),
        &ensure_request(ID, None, false),
        &CancellationToken::default(),
    )
    .unwrap_err();
    assert!(matches!(error, Error::DatabaseMissing));
    assert_eq!(error.protocol().0, ErrorCode::InvalidInput);
    assert!(!fixture.read("stdin.log").contains("CREATE USER"));
}

#[test]
fn failed_statements_drop_the_account_this_request_created() {
    let fixture = Fixture::new();
    fixture.mark("REJECT_ALTER", "");
    let error = ensure(
        &fixture.context(),
        &ensure_request(ID, Some("key-1"), false),
        &CancellationToken::default(),
    )
    .unwrap_err();
    assert!(matches!(error, Error::Rejected(_)));
    let stdin = fixture.read("stdin.log");
    assert!(
        stdin
            .trim_end()
            .ends_with("DROP USER IF EXISTS 'ro_site_db'@'localhost';\n--")
    );
    assert!(!error.protocol().1.contains("top-secret"));
    assert!(!fixture.state_dump().contains("top-secret"));

    // An account that already existed is not dropped on failure.
    let fixture = Fixture::new();
    fixture.mark("PROBE", "1\\t1");
    fixture.mark("REJECT_ALTER", "");
    ensure(
        &fixture.context(),
        &ensure_request(ID, None, true),
        &CancellationToken::default(),
    )
    .unwrap_err();
    assert!(!fixture.read("stdin.log").contains("DROP USER"));
}

#[test]
fn revoke_drops_the_account_and_is_idempotent() {
    let fixture = Fixture::new();
    fixture.mark("PROBE", "1\\t1");
    let result = revoke(
        &fixture.context(),
        &revoke_request(ID, None),
        &CancellationToken::default(),
    )
    .unwrap();
    assert!(result.revoked);
    assert_eq!(result.username, "ro_site_db");
    let stdin = fixture.read("stdin.log");
    assert!(stdin.contains("top-secret\nDROP USER IF EXISTS 'ro_site_db'@'localhost';"));
    assert!(!fixture.read("argv.log").contains("top-secret"));

    // A missing account (and a missing database) is a success.
    fixture.mark("PROBE", "0\\t0");
    let result = revoke(
        &fixture.context(),
        &revoke_request(ID2, Some("key-r")),
        &CancellationToken::default(),
    )
    .unwrap();
    assert!(!result.revoked);

    // Same request id again: recorded result, no new subprocess.
    let calls = fixture.read("argv.log").lines().count();
    let again = revoke(
        &fixture.context(),
        &revoke_request(ID3, Some("key-r")),
        &CancellationToken::default(),
    )
    .unwrap();
    assert!(!again.revoked);
    assert_eq!(fixture.read("argv.log").lines().count(), calls);
    assert!(!fixture.state_dump().contains("top-secret"));
}
