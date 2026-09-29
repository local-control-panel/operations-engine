//! The `wordpress.rotateCredentials` operation: rotates a WordPress site's
//! database user password. Unlike `wordpress_install`/`wordpress_clone`,
//! this operation never touches the host filesystem directly — both
//! mutations (`ALTER USER` and `wp config set`) run inside containers via
//! `docker exec`, so no `TrustedRoot`/`ManagedRoot` content-root resolution
//! is needed in `execute()` itself (the dispatch layer in
//! `commands/wordpress.rs` still validates `root` against the configured
//! content roots before calling in, matching every other WordPress
//! operation). The engine reads the site's *current* `DB_USER`/
//! `DB_PASSWORD` from `wp-config.php` itself rather than trusting values
//! the panel already resolved, so the old password used for automatic
//! rollback is always the value actually in effect at the moment this
//! operation runs.

use crate::{
    db_restore::{ContainerName, RestoreRequestError},
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{self, CancellationToken, ProcessLimits, ProcessRequest, ProcessRunError},
    site::SiteRelativePath,
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        resource_lock,
        state::{self, TransactionStatus},
    },
};
use serde::Deserialize;
use std::path::PathBuf;

pub const OPERATION: &str = "wordpress.rotateCredentials";

const MAX_SECRET_BYTES: usize = 256;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    container: String,
    root: String,
    uid: u32,
    gid: u32,
    mariadb_container: String,
    db_root_password: String,
    new_password: String,
}

pub struct Request {
    container: ContainerName,
    root: PathBuf,
    uid: u32,
    gid: u32,
    mariadb_container: ContainerName,
    db_root_password: String,
    new_password: String,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug)]
pub struct RequestError;

/// Mirrors `website-control-panel`'s own `validate_db_credentials`: no NUL,
/// CR or LF, and non-empty.
fn validate_secret(value: &str) -> Result<(), RequestError> {
    if value.is_empty()
        || value.len() > MAX_SECRET_BYTES
        || value.bytes().any(|b| matches!(b, 0 | b'\n' | b'\r'))
    {
        return Err(RequestError);
    }
    Ok(())
}

impl Request {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError)?;
        let root = PathBuf::from(plan.root);
        if !root.is_absolute()
            || root.as_os_str().len() > 4096
            || root
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(RequestError);
        }
        if plan.uid == 0 || plan.gid == 0 {
            return Err(RequestError);
        }
        validate_secret(&plan.db_root_password)?;
        validate_secret(&plan.new_password)?;

        Ok(Self {
            container: ContainerName::parse(&plan.container)
                .map_err(|_: RestoreRequestError| RequestError)?,
            root,
            uid: plan.uid,
            gid: plan.gid,
            mariadb_container: ContainerName::parse(&plan.mariadb_container)
                .map_err(|_: RestoreRequestError| RequestError)?,
            db_root_password: plan.db_root_password,
            new_password: plan.new_password,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError)?,
        })
    }

    pub fn root(&self) -> &std::path::Path {
        &self.root
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateResult {
    pub db_user: String,
    pub completed_at_unix_secs: u64,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub docker_program: &'a str,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Run(ProcessRunError),
    Rejected(ErrorCode),
    ResourceBusy,
    InvalidCredentials,
    RecoveryRequired,
    PostCommit { result: RotateResult },
    Replayed { code: ErrorCode, message: String },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another WordPress credential rotation is in progress for this site".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Run(error) => (
                process::spawn_error_code(error),
                "could not run a WordPress credential rotation prerequisite".into(),
            ),
            Self::Rejected(code) => (*code, "WordPress credential rotation step failed".into()),
            Self::ResourceBusy => (
                ErrorCode::Conflict,
                "another WordPress operation is already in progress for this site".into(),
            ),
            Self::InvalidCredentials => (
                ErrorCode::Internal,
                "the site's wp-config did not report usable database credentials".into(),
            ),
            Self::RecoveryRequired => (
                ErrorCode::Conflict,
                "WordPress credential rotation requires manual recovery; the database and wp-config may disagree on the current password".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            _ => (
                ErrorCode::Internal,
                "internal WordPress credential rotation error".into(),
            ),
        }
    }
}

fn wp_command(ctx: &Context<'_>, req: &Request) -> ProcessRequest {
    ProcessRequest::new(ctx.docker_program).args([
        "exec".to_owned(),
        "-i".into(),
        "--user".into(),
        format!("{}:{}", req.uid, req.gid),
        req.container.as_str().into(),
        "wp".into(),
        format!("--path={}", req.root.display()),
        "--skip-plugins".into(),
        "--skip-themes".into(),
    ])
}

fn mariadb_command(ctx: &Context<'_>, req: &Request) -> ProcessRequest {
    ProcessRequest::new(ctx.docker_program).args([
        "exec",
        "-i",
        req.mariadb_container.as_str(),
        "sh",
        "-c",
        "IFS= read -r MYSQL_PWD; export MYSQL_PWD; exec mariadb -uroot --batch",
    ])
}

fn sql_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "''")
}

fn alter_user_stdin(root_password: &str, user: &str, password: &str) -> Vec<u8> {
    format!(
        "{root_password}\nALTER USER '{}'@'%' IDENTIFIED BY '{}'; FLUSH PRIVILEGES;\n",
        sql_string(user),
        sql_string(password)
    )
    .into_bytes()
}

fn critical(output: Result<process::ProcessOutput, ProcessRunError>) -> Result<(), Error> {
    let output = output.map_err(Error::Run)?;
    if let Some(code) = process::error_code(&output.termination) {
        return Err(Error::Rejected(code));
    }
    Ok(())
}

fn read_config(
    ctx: &Context<'_>,
    req: &Request,
    key: &str,
    cancel: &CancellationToken,
) -> Result<String, Error> {
    let output = process::run(
        &wp_command(ctx, req).args(["config", "get", key, "--format=json"]),
        &ProcessLimits::default(),
        cancel,
    )
    .map_err(Error::Run)?;
    if let Some(code) = process::error_code(&output.termination) {
        return Err(Error::Rejected(code));
    }
    let value: String =
        serde_json::from_slice(&output.stdout.bytes).map_err(|_| Error::InvalidCredentials)?;
    validate_secret(&value).map_err(|_| Error::InvalidCredentials)?;
    Ok(value)
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<RotateResult, Error> {
    let hash = resource_lock::canonical_hash(&req.root);
    let scope_path =
        SiteRelativePath::parse(format!("wordpress-rotate-credentials/{hash}")).unwrap();
    ctx.engine_state
        .create_dir_all(&scope_path)
        .map_err(Error::Io)?;
    let scope = ctx
        .engine_state
        .open_managed_dir(&scope_path)
        .map_err(Error::Io)?;
    for child in ["locks", "transactions", "audit"] {
        scope
            .create_dir_all(&SiteRelativePath::parse(child).unwrap())
            .map_err(Error::Io)?;
    }

    let _resource_lock = resource_lock::acquire(ctx.engine_state, &req.root, req.request_id)
        .map_err(|_| Error::ResourceBusy)?;

    let admitted = match preflight::run(
        &scope,
        req.request_id,
        req.idempotency_key.as_ref(),
        OPERATION,
    )
    .map_err(Error::Preflight)?
    {
        preflight::Outcome::Replay(id) => return replay(&scope, id),
        preflight::Outcome::Proceed(value) => value,
    };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path =
        SiteRelativePath::parse(format!("transactions/{}.json", req.request_id)).unwrap();
    let audit_path = SiteRelativePath::parse("audit/events.jsonl").unwrap();

    macro_rules! fail_now {
        ($error:expr) => {
            return Err(fail(
                &scope,
                &state_path,
                &audit_path,
                state.clone(),
                $error,
            ))
        };
    }

    let old_user = match read_config(ctx, req, "DB_USER", cancel) {
        Ok(value) => value,
        Err(error) => fail_now!(error),
    };
    let old_password = match read_config(ctx, req, "DB_PASSWORD", cancel) {
        Ok(value) => value,
        Err(error) => fail_now!(error),
    };

    let mut credential_mutated = false;
    let work = (|| -> Result<(), Error> {
        critical(process::run_with_stdin_bytes(
            &mariadb_command(ctx, req),
            &alter_user_stdin(&req.db_root_password, &old_user, &req.new_password),
            &ProcessLimits::default(),
            cancel,
        ))?;
        credential_mutated = true;

        critical(process::run_with_stdin_bytes(
            &wp_command(ctx, req).args([
                "config",
                "set",
                "DB_PASSWORD",
                "--type=constant",
                "--prompt=value",
            ]),
            format!("{}\n", req.new_password).as_bytes(),
            &ProcessLimits::default(),
            cancel,
        ))?;

        critical(process::run(
            &wp_command(ctx, req).args(["db", "check", "--quiet"]),
            &ProcessLimits::default(),
            cancel,
        ))?;
        Ok(())
    })();

    if let Err(error) = work {
        let mut recovered = true;
        if credential_mutated {
            recovered &= critical(process::run_with_stdin_bytes(
                &wp_command(ctx, req).args([
                    "config",
                    "set",
                    "DB_PASSWORD",
                    "--type=constant",
                    "--prompt=value",
                ]),
                format!("{old_password}\n").as_bytes(),
                &ProcessLimits::default(),
                &CancellationToken::default(),
            ))
            .is_ok();
            if recovered {
                recovered &= critical(process::run_with_stdin_bytes(
                    &mariadb_command(ctx, req),
                    &alter_user_stdin(&req.db_root_password, &old_user, &old_password),
                    &ProcessLimits::default(),
                    &CancellationToken::default(),
                ))
                .is_ok();
            }
        }
        if recovered {
            fail_now!(error);
        } else {
            fail_now!(Error::RecoveryRequired);
        }
    }

    let result = RotateResult {
        db_user: old_user,
        completed_at_unix_secs: {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        },
    };
    state
        .mark_committed(serde_json::to_value(&result).unwrap())
        .unwrap();
    if state::save(&scope, &state_path, &state).is_err() {
        drop(lock);
        return Err(Error::PostCommit { result });
    }
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(req.request_id, true, None),
    );
    drop(lock);
    Ok(result)
}

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<RotateResult, Error> {
    let loaded = state::load(
        scope,
        &SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap(),
    )
    .map_err(|e| Error::Io(std::io::Error::other(format!("{e:?}"))))?;
    if loaded.operation != OPERATION {
        return Err(Error::Io(std::io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => {
            serde_json::from_value(loaded.outcome.unwrap().result.unwrap())
                .map_err(|e| Error::Io(std::io::Error::other(e)))
        }
        TransactionStatus::Failed => {
            let outcome = loaded.outcome.unwrap();
            Err(Error::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}

fn fail(
    scope: &ManagedRoot,
    path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut state: crate::transaction::state::TransactionState,
    error: Error,
) -> Error {
    let (code, message) = error.protocol();
    let _ = state.mark_failed(code, message);
    let _ = state::save(scope, path, &state);
    let _ = audit::append(
        scope,
        audit_path,
        &AuditRecord::result(state.request_id, false, Some(code)),
    );
    error
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    fn valid_json() -> String {
        r#"{
            "container": "runtime-1",
            "root": "/var/www/example.com",
            "uid": 1000,
            "gid": 1000,
            "mariadbContainer": "mariadb-1",
            "dbRootPassword": "root-secret",
            "newPassword": "new-secret-value"
        }"#
        .to_string()
    }

    #[test]
    fn parses_a_valid_request() {
        let request = Request::parse(&valid_json(), REQUEST_ID, None).expect("should parse");
        assert_eq!(request.root(), std::path::Path::new("/var/www/example.com"));
    }

    #[test]
    fn rejects_a_relative_root() {
        let json = valid_json().replace("/var/www/example.com", "relative/path");
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn rejects_a_root_containing_parent_dir_segments() {
        let json = valid_json().replace("/var/www/example.com", "/var/www/../etc");
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn rejects_uid_zero() {
        let json = valid_json().replace("\"uid\": 1000", "\"uid\": 0");
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn rejects_gid_zero() {
        let json = valid_json().replace("\"gid\": 1000", "\"gid\": 0");
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn rejects_an_empty_new_password() {
        let json = valid_json().replace(
            "\"newPassword\": \"new-secret-value\"",
            "\"newPassword\": \"\"",
        );
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn rejects_a_new_password_containing_a_newline() {
        let json = valid_json().replace("new-secret-value", "new-secret\\nvalue");
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn rejects_an_empty_db_root_password() {
        let json = valid_json().replace(
            "\"dbRootPassword\": \"root-secret\"",
            "\"dbRootPassword\": \"\"",
        );
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn rejects_a_malformed_mariadb_container_name() {
        let json = valid_json().replace("mariadb-1", "not a container name");
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn rejects_an_unknown_field() {
        let json = valid_json().replace("\"uid\": 1000,", "\"uid\": 1000, \"unexpected\": true,");
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn rejects_a_new_password_containing_a_nul_byte() {
        let password_with_nul = "new-secret\0value";
        let json = format!(
            r#"{{
            "container": "runtime-1",
            "root": "/var/www/example.com",
            "uid": 1000,
            "gid": 1000,
            "mariadbContainer": "mariadb-1",
            "dbRootPassword": "root-secret",
            "newPassword": "{}"
        }}"#,
            password_with_nul
        );
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn rejects_a_new_password_containing_a_carriage_return() {
        let json = valid_json().replace("new-secret-value", "new-secret\rvalue");
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn rejects_a_new_password_exceeding_the_length_bound() {
        let long_password = "x".repeat(257);
        let json = valid_json().replace("\"new-secret-value\"", &format!("\"{}\"", long_password));
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

    fn write_script(directory: &std::path::Path, name: &str, body: &str) -> PathBuf {
        let path = directory.join(name);
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    struct Fixture {
        _directory: tempfile::TempDir,
        state: ManagedRoot,
        docker: PathBuf,
        site_root: PathBuf,
    }

    fn fixture(script_body: &str) -> Fixture {
        let directory = tempfile::tempdir().unwrap();
        let state_dir = directory.path().join("state");
        fs::create_dir_all(&state_dir).unwrap();
        let state =
            ManagedRoot::open(&crate::site::TrustedRoot::parse(&state_dir).unwrap()).unwrap();
        let docker = write_script(directory.path(), "fake-docker", script_body);
        Fixture {
            site_root: PathBuf::from("/var/www/example.com"),
            _directory: directory,
            state,
            docker,
        }
    }

    fn calls_log(fixture: &Fixture) -> Vec<String> {
        let log_path = fixture.docker.parent().unwrap().join("calls.log");
        match fs::read_to_string(log_path) {
            Ok(contents) => contents.lines().map(str::to_owned).collect(),
            Err(_) => Vec::new(),
        }
    }

    fn request_for(fx: &Fixture, request_id: &str, key: Option<&str>) -> Request {
        let json = valid_json().replace("/var/www/example.com", fx.site_root.to_str().unwrap());
        Request::parse(&json, request_id, key).expect("request should parse")
    }

    /// `wp config get` returns the current DB_USER/DB_PASSWORD as JSON strings;
    /// every other call (ALTER USER, config set, db check) just succeeds.
    const ALWAYS_SUCCEED: &str = r#"#!/bin/sh
echo "$@" >> "$(dirname "$0")/calls.log"
case "$*" in
  *"config get DB_USER"*) echo '"old_user"'; exit 0 ;;
  *"config get DB_PASSWORD"*) echo '"old_password"'; exit 0 ;;
esac
exit 0
"#;

    #[test]
    fn rotates_credentials_end_to_end() {
        let fx = fixture(ALWAYS_SUCCEED);
        let request = request_for(&fx, REQUEST_ID, None);
        let context = Context {
            engine_state: &fx.state,
            docker_program: fx.docker.to_str().unwrap(),
        };

        let result = execute(&context, &request, &CancellationToken::default())
            .expect("rotation should succeed");
        assert_eq!(result.db_user, "old_user");

        let calls = calls_log(&fx);
        assert_eq!(calls.len(), 5, "unexpected call sequence: {calls:#?}");
        assert!(calls[0].contains("config get DB_USER"));
        assert!(calls[1].contains("config get DB_PASSWORD"));
        assert!(calls[2].contains("mariadb-1")); // ALTER USER, run against the MariaDB container
        assert!(calls[3].contains("config set DB_PASSWORD"));
        assert!(calls[4].contains("db check"));
    }

    #[test]
    fn reverts_both_mutations_when_verification_fails() {
        let script = r#"#!/bin/sh
echo "$@" >> "$(dirname "$0")/calls.log"
case "$*" in
  *"config get DB_USER"*) echo '"old_user"'; exit 0 ;;
  *"config get DB_PASSWORD"*) echo '"old_password"'; exit 0 ;;
  *"db check"*) exit 1 ;;
esac
exit 0
"#;
        let fx = fixture(script);
        let request = request_for(&fx, REQUEST_ID, None);
        let context = Context {
            engine_state: &fx.state,
            docker_program: fx.docker.to_str().unwrap(),
        };

        let error = execute(&context, &request, &CancellationToken::default())
            .expect_err("a failed verification should fail the whole request");
        assert_eq!(error.protocol().0, ErrorCode::SubprocessFailed);

        let calls = calls_log(&fx);
        // get x2, ALTER (new), config set (new), db check (fails), config set (revert to old), ALTER (revert to old)
        assert_eq!(calls.len(), 7, "unexpected call sequence: {calls:#?}");
        assert!(
            calls[5].contains("config set DB_PASSWORD"),
            "expected a revert config set: {calls:#?}"
        );
        assert!(
            calls[6].contains("mariadb-1"),
            "expected a revert ALTER USER: {calls:#?}"
        );
    }

    #[test]
    fn reports_recovery_required_when_the_revert_itself_fails() {
        let script = r#"#!/bin/sh
echo "$@" >> "$(dirname "$0")/calls.log"
case "$*" in
  *"config get DB_USER"*) echo '"old_user"'; exit 0 ;;
  *"config get DB_PASSWORD"*) echo '"old_password"'; exit 0 ;;
  *"db check"*) exit 1 ;;
  *"config set DB_PASSWORD"*)
    n=$(grep -c "config set DB_PASSWORD" "$(dirname "$0")/calls.log")
    if [ "$n" -ge 2 ]; then exit 1; fi
    ;;
esac
exit 0
"#;
        let fx = fixture(script);
        let request = request_for(&fx, REQUEST_ID, None);
        let context = Context {
            engine_state: &fx.state,
            docker_program: fx.docker.to_str().unwrap(),
        };

        let error = execute(&context, &request, &CancellationToken::default())
            .expect_err("a failed revert must not be reported as a clean failure");
        assert_eq!(error.protocol().0, ErrorCode::Conflict);
        assert!(
            matches!(error, Error::RecoveryRequired),
            "expected RecoveryRequired, got {error:?}"
        );
    }

    #[test]
    fn replaying_the_same_idempotency_key_returns_the_original_result_without_rerunning() {
        let fx = fixture(ALWAYS_SUCCEED);
        let context = Context {
            engine_state: &fx.state,
            docker_program: fx.docker.to_str().unwrap(),
        };
        let first = request_for(&fx, REQUEST_ID, Some("rotate-once"));
        let first_result = execute(&context, &first, &CancellationToken::default())
            .expect("first attempt should succeed");
        let calls_after_first = calls_log(&fx).len();
        assert!(calls_after_first > 0);

        let second_request_id = "223e4567-e89b-12d3-a456-426614174000";
        let second = request_for(&fx, second_request_id, Some("rotate-once"));
        let second_result = execute(&context, &second, &CancellationToken::default())
            .expect("replay should return the recorded result, not fail");

        assert_eq!(first_result.db_user, second_result.db_user);
        assert_eq!(
            calls_log(&fx).len(),
            calls_after_first,
            "a replayed idempotency key must not rotate the password again"
        );
    }

    #[test]
    fn a_concurrent_operation_holding_the_resource_lock_blocks_rotation() {
        let fx = fixture(ALWAYS_SUCCEED);
        let other_holder = RequestId::parse("223e4567-e89b-12d3-a456-426614174000")
            .expect("test UUID should be canonical");
        let _held = resource_lock::acquire(&fx.state, &fx.site_root, other_holder)
            .expect("resource lock should be free to acquire");

        let request = request_for(&fx, REQUEST_ID, None);
        let context = Context {
            engine_state: &fx.state,
            docker_program: fx.docker.to_str().unwrap(),
        };

        let error = execute(&context, &request, &CancellationToken::default())
            .expect_err("a held resource lock should block rotation");
        assert_eq!(error.protocol().0, ErrorCode::Conflict);
        assert!(calls_log(&fx).is_empty(), "no WP-CLI step should have run");
    }
}
