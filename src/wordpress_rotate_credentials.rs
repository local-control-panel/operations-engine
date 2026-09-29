//! Rotates a WordPress site's MariaDB credentials: reads the site's current
//! `DB_USER`/`DB_PASSWORD` from `wp-config.php`, applies a caller-supplied
//! new password to the MariaDB account and to `wp-config.php`, then verifies
//! database connectivity with `wp db check`. Replaces the panel's former
//! raw-SSH sequence (`ALTER USER` over a shell-built `docker exec`, then a
//! shell-escaped `wp config set`, with a best-effort revert on failure) with
//! the same compensation logic run here instead, under one lock/idempotency/
//! transaction/audit-backed request. The MariaDB root password and both the
//! old and new site passwords stay out of every subprocess argument list:
//! the `ALTER USER` statement is fed to `mariadb` over stdin, exactly like
//! `db_provision` and `maria_user::drop`.

use crate::{
    db_restore::{ContainerName, RestoreRequestError},
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{
        self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination,
        SubprocessDiagnostics,
    },
    site::SiteRelativePath,
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        commit::PreCommit,
        resource_lock,
        state::{self, TransactionStatus},
    },
};
use serde::Deserialize;
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

pub const OPERATION: &str = "wordpress.rotateCredentials";

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

fn valid_secret(value: &str, max_len: usize) -> bool {
    !value.is_empty() && value.len() <= max_len && !value.contains(['\n', '\r', '\0'])
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
        if !valid_secret(&plan.db_root_password, 4096) || !valid_secret(&plan.new_password, 1024) {
            return Err(RequestError);
        }
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
pub struct RotateCredentialsResult {
    pub db_user: String,
    pub completed_at_unix_secs: u64,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub docker_program: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    ReadCredentials,
    AlterUser,
    SetConfig,
    Verify,
}

impl Stage {
    fn message(self) -> &'static str {
        match self {
            Self::ReadCredentials => "could not read the site's existing database credentials",
            Self::AlterUser => "MariaDB rejected the credential rotation",
            Self::SetConfig => "could not write the new database password to wp-config.php",
            Self::Verify => {
                "could not verify WordPress database connectivity after rotation; the \
                 previous credentials were restored"
            }
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    ResourceBusy,
    Cancelled,
    InvalidCredentialOutput,
    Run(Stage, process::ProcessRunError),
    Rejected(Stage, SubprocessDiagnostics),
    PostCommit { result: RotateCredentialsResult },
    Replayed { code: ErrorCode, message: String },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another credential rotation for this site is in progress".into(),
            ),
            Self::ResourceBusy => (
                ErrorCode::Conflict,
                "another WordPress operation is already in progress for this site".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before the database credential rotation ran".into(),
            ),
            Self::InvalidCredentialOutput => (
                ErrorCode::Internal,
                "could not read the site's existing database credentials".into(),
            ),
            Self::Run(stage, error) => (process::spawn_error_code(error), stage.message().into()),
            Self::Rejected(stage, diagnostics) => (
                if diagnostics.timed_out {
                    ErrorCode::Timeout
                } else if diagnostics.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::SubprocessFailed
                },
                stage.message().into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit { .. } => (
                ErrorCode::Internal,
                "internal WordPress credential rotation error".into(),
            ),
        }
    }
}

fn sql_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "''")
}

fn valid_db_user(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 80
        && user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '@' | '%'))
        && !matches!(
            user.to_ascii_lowercase().as_str(),
            "root" | "mysql" | "mariadb.sys" | "healthcheck"
        )
}

fn wp_args<I, S>(req: &Request, tail: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut args = vec![
        "exec".to_owned(),
        "-i".to_owned(),
        "--user".to_owned(),
        format!("{}:{}", req.uid, req.gid),
        req.container.as_str().to_owned(),
        "wp".to_owned(),
        format!("--path={}", req.root.display()),
        "--allow-root".to_owned(),
    ];
    args.extend(tail.into_iter().map(|v| v.as_ref().to_owned()));
    args
}

fn read_config_value(
    ctx: &Context<'_>,
    req: &Request,
    key: &str,
    cancel: &CancellationToken,
) -> Result<String, Error> {
    let output = process::run(
        &ProcessRequest::new(ctx.docker_program)
            .args(wp_args(req, ["config", "get", key, "--format=json"])),
        &ProcessLimits::default(),
        cancel,
    )
    .map_err(|e| Error::Run(Stage::ReadCredentials, e))?;
    if !matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        return Err(Error::Rejected(
            Stage::ReadCredentials,
            SubprocessDiagnostics::from_output(ctx.docker_program, &output),
        ));
    }
    if output.stdout.truncated {
        return Err(Error::InvalidCredentialOutput);
    }
    String::from_utf8(output.stdout.bytes)
        .map(|value| value.trim().trim_matches('"').to_owned())
        .map_err(|_| Error::InvalidCredentialOutput)
}

fn mariadb_alter_user(
    ctx: &Context<'_>,
    req: &Request,
    user: &str,
    password: &str,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let args = [
        "exec".to_owned(),
        "-i".to_owned(),
        req.mariadb_container.as_str().to_owned(),
        "sh".to_owned(),
        "-c".to_owned(),
        "IFS= read -r MYSQL_PWD; export MYSQL_PWD; exec mariadb -uroot --batch".to_owned(),
    ];
    let input = format!(
        "{}\nALTER USER '{}'@'%' IDENTIFIED BY '{}'; FLUSH PRIVILEGES;\n",
        req.db_root_password,
        sql_string(user),
        sql_string(password)
    );
    let output = process::run_with_stdin_bytes(
        &ProcessRequest::new(ctx.docker_program).args(args),
        input.as_bytes(),
        &ProcessLimits::default(),
        cancel,
    )
    .map_err(|e| Error::Run(Stage::AlterUser, e))?;
    if !matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        return Err(Error::Rejected(
            Stage::AlterUser,
            SubprocessDiagnostics::from_output(ctx.docker_program, &output),
        ));
    }
    Ok(())
}

fn set_wp_password(
    ctx: &Context<'_>,
    req: &Request,
    password: &str,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let output = process::run(
        &ProcessRequest::new(ctx.docker_program).args(wp_args(
            req,
            ["config", "set", "DB_PASSWORD", password, "--type=constant"],
        )),
        &ProcessLimits::default(),
        cancel,
    )
    .map_err(|e| Error::Run(Stage::SetConfig, e))?;
    if !matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        return Err(Error::Rejected(
            Stage::SetConfig,
            SubprocessDiagnostics::from_output(ctx.docker_program, &output),
        ));
    }
    Ok(())
}

fn verify_db(ctx: &Context<'_>, req: &Request, cancel: &CancellationToken) -> Result<(), Error> {
    let output = process::run(
        &ProcessRequest::new(ctx.docker_program).args(wp_args(req, ["db", "check", "--quiet"])),
        &ProcessLimits::default(),
        cancel,
    )
    .map_err(|e| Error::Run(Stage::Verify, e))?;
    if !matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        return Err(Error::Rejected(
            Stage::Verify,
            SubprocessDiagnostics::from_output(ctx.docker_program, &output),
        ));
    }
    Ok(())
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<RotateCredentialsResult, Error> {
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
    let pre_commit = PreCommit::new(cancel.clone());

    let db_user = match read_config_value(ctx, req, "DB_USER", cancel) {
        Ok(value) if valid_db_user(&value) => value,
        Ok(_) => {
            return Err(fail(
                &scope,
                &state_path,
                &audit_path,
                state,
                Error::InvalidCredentialOutput,
            ));
        }
        Err(error) => return Err(fail(&scope, &state_path, &audit_path, state, error)),
    };
    let old_password = match read_config_value(ctx, req, "DB_PASSWORD", cancel) {
        Ok(value) if valid_secret(&value, 1024) => value,
        Ok(_) => {
            return Err(fail(
                &scope,
                &state_path,
                &audit_path,
                state,
                Error::InvalidCredentialOutput,
            ));
        }
        Err(error) => return Err(fail(&scope, &state_path, &audit_path, state, error)),
    };

    if pre_commit.check().is_err() {
        return Err(fail(
            &scope,
            &state_path,
            &audit_path,
            state,
            Error::Cancelled,
        ));
    }

    if let Err(error) = mariadb_alter_user(ctx, req, &db_user, &req.new_password, cancel) {
        return Err(fail(&scope, &state_path, &audit_path, state, error));
    }
    let _post_commit = pre_commit.commit();

    // The MariaDB password has already changed at this point: from here on
    // every failure must be compensated by reverting wp-config.php and
    // MariaDB back to `old_password`, not just reported.
    let failure = set_wp_password(ctx, req, &req.new_password, cancel)
        .and_then(|()| verify_db(ctx, req, cancel))
        .err();
    if let Some(error) = failure {
        let _ = set_wp_password(ctx, req, &old_password, cancel);
        let _ = mariadb_alter_user(ctx, req, &db_user, &old_password, cancel);
        return Err(fail(&scope, &state_path, &audit_path, state, error));
    }

    let result = RotateCredentialsResult {
        db_user,
        completed_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
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

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<RotateCredentialsResult, Error> {
    let loaded = state::load(
        scope,
        &SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap(),
    )
    .map_err(|error| Error::Io(std::io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != OPERATION {
        return Err(Error::Io(std::io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => {
            serde_json::from_value(loaded.outcome.unwrap().result.unwrap())
                .map_err(|error| Error::Io(std::io::Error::other(error)))
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::site::TrustedRoot;
    use std::{fs, os::unix::fs::PermissionsExt};

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    fn valid_json(root: &str) -> String {
        format!(
            r#"{{"container":"runtime-1","root":"{root}","uid":1000,"gid":1000,"mariadbContainer":"mariadb-11","dbRootPassword":"top-secret","newPassword":"new-secret"}}"#
        )
    }

    #[test]
    fn parses_a_well_formed_plan() {
        assert!(Request::parse(&valid_json("/var/www/site"), ID, None).is_ok());
    }

    #[test]
    fn rejects_a_relative_or_escaping_root() {
        assert!(Request::parse(&valid_json("var/www/site"), ID, None).is_err());
        assert!(Request::parse(&valid_json("/var/www/../site"), ID, None).is_err());
    }

    #[test]
    fn rejects_an_invalid_container_name() {
        let json = valid_json("/var/www/site").replace("runtime-1", "bad;name");
        assert!(Request::parse(&json, ID, None).is_err());
    }

    #[test]
    fn rejects_secrets_with_control_characters_or_that_are_empty() {
        for bad in ["", "has\nnewline", "has\0null"] {
            let json = valid_json("/var/www/site").replace("new-secret", bad);
            assert!(Request::parse(&json, ID, None).is_err());
        }
    }

    #[test]
    fn a_concurrent_operation_holding_the_resource_lock_blocks_rotation() {
        let directory = tempfile::tempdir().unwrap();
        let content_dir = directory.path().join("content");
        let state_dir = directory.path().join("state");
        std::fs::create_dir_all(content_dir.join("example.com")).unwrap();
        std::fs::create_dir_all(&state_dir).unwrap();
        let engine_state = ManagedRoot::open(&TrustedRoot::parse(&state_dir).unwrap()).unwrap();
        let site_root = content_dir.join("example.com");

        let other_holder = RequestId::parse("223e4567-e89b-12d3-a456-426614174000")
            .expect("test UUID should be canonical");
        let _held = resource_lock::acquire(&engine_state, &site_root, other_holder)
            .expect("resource lock should be free to acquire");

        let request_json = valid_json(site_root.to_str().unwrap());
        let req = Request::parse(&request_json, ID, None).expect("request should parse");
        let ctx = Context {
            engine_state: &engine_state,
            docker_program: "/bin/true",
        };

        let outcome = execute(&ctx, &req, &CancellationToken::default());
        assert!(
            matches!(outcome, Err(Error::ResourceBusy)),
            "a rotation must not proceed while another operation holds this root's resource \
             lock: {outcome:?}"
        );
    }

    /// A fake `docker` that answers each call this module makes in sequence,
    /// logging every argv line and every byte of stdin it receives so tests
    /// can assert secrets never reach argv, and can force a chosen call to
    /// fail by dropping a marker file next to the script.
    fn fake_docker(directory: &std::path::Path) -> std::path::PathBuf {
        let script = directory.join("docker");
        fs::write(
            &script,
            r#"#!/bin/sh
DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
printf '%s\n' "$*" >> "$DIR/argv.log"
case "$*" in
  *"config get DB_USER"*)
    printf '"site_user"\n'
    exit 0
    ;;
  *"config get DB_PASSWORD"*)
    printf '"old-secret"\n'
    exit 0
    ;;
  *"mariadb -uroot --batch"*)
    { cat; printf '\n---\n'; } >> "$DIR/stdin.log"
    [ -f "$DIR/fail_alter" ] && exit 5
    exit 0
    ;;
  *"config set DB_PASSWORD"*)
    [ -f "$DIR/fail_set" ] && exit 6
    exit 0
    ;;
  *"db check --quiet"*)
    [ -f "$DIR/fail_verify" ] && exit 7
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions).unwrap();
        script
    }

    #[test]
    fn rotates_credentials_and_keeps_secrets_out_of_argv() {
        let directory = tempfile::tempdir().unwrap();
        let content_dir = directory.path().join("content");
        let state_dir = directory.path().join("state");
        std::fs::create_dir_all(content_dir.join("example.com")).unwrap();
        std::fs::create_dir_all(&state_dir).unwrap();
        let engine_state = ManagedRoot::open(&TrustedRoot::parse(&state_dir).unwrap()).unwrap();
        let site_root = content_dir.join("example.com");
        let docker = fake_docker(directory.path());

        let request_json = valid_json(site_root.to_str().unwrap());
        let req = Request::parse(&request_json, ID, None).expect("request should parse");
        let ctx = Context {
            engine_state: &engine_state,
            docker_program: docker.to_str().unwrap(),
        };

        let result = execute(&ctx, &req, &CancellationToken::default()).unwrap();
        assert_eq!(result.db_user, "site_user");

        let argv = fs::read_to_string(directory.path().join("argv.log")).unwrap();
        assert!(!argv.contains("top-secret"));
        assert!(!argv.contains("old-secret"));
        assert!(argv.contains("config set DB_PASSWORD new-secret --type=constant"));

        let stdin = fs::read_to_string(directory.path().join("stdin.log")).unwrap();
        assert!(stdin.contains("top-secret"));
        assert!(stdin.contains("IDENTIFIED BY 'new-secret'"));
    }

    #[test]
    fn reverts_both_credentials_when_post_rotation_verification_fails() {
        let directory = tempfile::tempdir().unwrap();
        let content_dir = directory.path().join("content");
        let state_dir = directory.path().join("state");
        std::fs::create_dir_all(content_dir.join("example.com")).unwrap();
        std::fs::create_dir_all(&state_dir).unwrap();
        let engine_state = ManagedRoot::open(&TrustedRoot::parse(&state_dir).unwrap()).unwrap();
        let site_root = content_dir.join("example.com");
        let docker = fake_docker(directory.path());
        fs::write(directory.path().join("fail_verify"), "").unwrap();

        let request_json = valid_json(site_root.to_str().unwrap());
        let req = Request::parse(&request_json, ID, None).expect("request should parse");
        let ctx = Context {
            engine_state: &engine_state,
            docker_program: docker.to_str().unwrap(),
        };

        let outcome = execute(&ctx, &req, &CancellationToken::default());
        assert!(matches!(outcome, Err(Error::Rejected(Stage::Verify, _))));

        let argv = fs::read_to_string(directory.path().join("argv.log")).unwrap();
        // The revert must have re-applied the old password to wp-config...
        assert!(argv.contains("config set DB_PASSWORD old-secret --type=constant"));
        // ...and the initial rotation attempt did apply the new one first.
        assert!(argv.contains("config set DB_PASSWORD new-secret --type=constant"));

        let stdin = fs::read_to_string(directory.path().join("stdin.log")).unwrap();
        // ALTER USER ran twice: once to the new password, once back to the old.
        assert!(stdin.contains("IDENTIFIED BY 'new-secret'"));
        assert!(stdin.contains("IDENTIFIED BY 'old-secret'"));
    }
}
