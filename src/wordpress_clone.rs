//! Complete same-server WordPress clone. Files and the target database are
//! snapshotted before mutation. Credentials, domain replacement and a health
//! probe run before commit; handled failures restore the target. Interrupted
//! or failed recovery leaves a durable marker and artifacts for manual repair.

use crate::{
    db_restore::{
        ContainerName, DatabaseName, DbType, RestoreRequestError,
        execute::{RestoreContext, RestoreError, run_restore},
    },
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    permissions::execute::repair_tree,
    process::{self, CancellationToken, ProcessLimits, ProcessRequest, ProcessRunError},
    site::{Domain, SiteRelativePath, TrustedRoot},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        state::{self, TransactionStatus},
    },
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fmt::Write as _,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const OPERATION: &str = "wordpress.clone";

const MAX_DB_PASSWORD_BYTES: usize = 256;
const COPY_TIMEOUT: Duration = Duration::from_secs(1800);
const MAX_STEP_OUTPUT_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    source_container: String,
    source_root: String,
    source_uid: u32,
    source_gid: u32,
    staging_root: String,
    staging_container: String,
    source_domain: String,
    staging_domain: String,
    db_user: String,
    db_password: String,
    staging_uid: u32,
    staging_gid: u32,
    mariadb_container: String,
    db_name: String,
    db_root_password: String,
}

pub struct Request {
    source_container: ContainerName,
    source_root: PathBuf,
    source_uid: u32,
    source_gid: u32,
    staging_root: PathBuf,
    staging_container: ContainerName,
    source_domain: Domain,
    staging_domain: Domain,
    db_user: DatabaseName,
    db_password: String,
    staging_uid: u32,
    staging_gid: u32,
    mariadb_container: ContainerName,
    db_name: DatabaseName,
    db_root_password: String,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug)]
pub struct RequestError;

fn parse_root(value: String) -> Result<PathBuf, RequestError> {
    let root = PathBuf::from(value);
    if !root.is_absolute()
        || root.as_os_str().len() > 4096
        || root
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(RequestError);
    }
    Ok(root)
}

/// Mirrors `website-control-panel`'s own `validate_db_credentials`: no NUL,
/// CR or LF.
fn validate_db_password(value: &str) -> Result<(), RequestError> {
    if value.is_empty()
        || value.len() > MAX_DB_PASSWORD_BYTES
        || value.bytes().any(|b| matches!(b, 0 | b'\n' | b'\r'))
    {
        return Err(RequestError);
    }
    Ok(())
}

impl Request {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError)?;
        let source_root = parse_root(plan.source_root)?;
        let staging_root = parse_root(plan.staging_root)?;
        if source_root == staging_root
            || source_root.starts_with(&staging_root)
            || staging_root.starts_with(&source_root)
        {
            return Err(RequestError);
        }
        validate_db_password(&plan.db_root_password)?;
        validate_db_password(&plan.db_password)?;
        if [
            plan.source_uid,
            plan.source_gid,
            plan.staging_uid,
            plan.staging_gid,
        ]
        .contains(&0)
        {
            return Err(RequestError);
        }

        Ok(Self {
            source_container: ContainerName::parse(&plan.source_container)
                .map_err(|_: RestoreRequestError| RequestError)?,
            source_root,
            source_uid: plan.source_uid,
            source_gid: plan.source_gid,
            staging_root,
            staging_container: ContainerName::parse(&plan.staging_container)
                .map_err(|_| RequestError)?,
            source_domain: Domain::parse(&plan.source_domain).map_err(|_| RequestError)?,
            staging_domain: Domain::parse(&plan.staging_domain).map_err(|_| RequestError)?,
            db_user: DatabaseName::parse(&plan.db_user).map_err(|_| RequestError)?,
            db_password: plan.db_password,
            staging_uid: plan.staging_uid,
            staging_gid: plan.staging_gid,
            mariadb_container: ContainerName::parse(&plan.mariadb_container)
                .map_err(|_: RestoreRequestError| RequestError)?,
            db_name: DatabaseName::parse(&plan.db_name)
                .map_err(|_: RestoreRequestError| RequestError)?,
            db_root_password: plan.db_root_password,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError)?,
        })
    }

    pub fn source_root(&self) -> &std::path::Path {
        &self.source_root
    }

    pub fn staging_root(&self) -> &std::path::Path {
        &self.staging_root
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloneResult {
    pub recovery_id: String,
    pub completed_at_unix_secs: u64,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    /// Fd-relative capability for the fixed dump-staging root (a
    /// `wordpress-clone/` subtree of the same backup root
    /// `wordpress.updateCore` uses for its own recovery snapshots).
    pub dump_managed: &'a ManagedRoot,
    /// The same root as `dump_managed`, as a `TrustedRoot`, so the dump's
    /// absolute host path can be resolved for `db_restore`'s
    /// ambient-path-based restore client.
    pub dump_root: &'a TrustedRoot,
    pub docker_program: &'a str,
    pub cp_program: &'a str,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Run(ProcessRunError),
    Rejected(ErrorCode),
    SourceUnavailable,
    UnsafeTarget,
    RecoveryRequired,
    Import(RestoreError),
    PostCommit { result: CloneResult },
    Replayed { code: ErrorCode, message: String },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another WordPress clone into this staging site is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Run(error) => (
                process::spawn_error_code(error),
                "could not run a WordPress clone prerequisite".into(),
            ),
            Self::Rejected(code) => (
                *code,
                "WordPress clone step failed".into(),
            ),
            Self::SourceUnavailable => (
                ErrorCode::InvalidInput,
                "WordPress source root does not exist or is outside the configured content root"
                    .into(),
            ),
            Self::UnsafeTarget => (ErrorCode::InvalidInput, "clone target overlaps the source or has an unsafe configuration".into()),
            Self::RecoveryRequired => (ErrorCode::Conflict, "WordPress clone requires manual recovery; retained artifacts and pending.json identify the target".into()),
            Self::Import(error) => error.protocol(),
            Self::Replayed { code, message } => (*code, message.clone()),
            _ => (ErrorCode::Internal, "internal WordPress clone error".into()),
        }
    }
}

pub fn execute(
    ctx: &Context<'_>,
    source_content_root: &TrustedRoot,
    staging_content_root: &TrustedRoot,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<CloneResult, Error> {
    let digest = Sha256::digest(req.staging_root.as_os_str().as_encoded_bytes());
    let mut hash = String::new();
    for byte in digest {
        write!(&mut hash, "{byte:02x}").unwrap();
    }
    let scope_path = SiteRelativePath::parse(format!("wordpress-clone/{hash}")).unwrap();
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

    let staging_managed = match ManagedRoot::open(staging_content_root) {
        Ok(value) => value,
        Err(error) => fail_now!(Error::Io(error)),
    };

    let source_relative = match req
        .source_root
        .strip_prefix(source_content_root.as_path())
        .ok()
        .filter(|value| !value.as_os_str().is_empty())
        .and_then(|value| SiteRelativePath::parse(value).ok())
    {
        Some(value) => value,
        None => fail_now!(Error::SourceUnavailable),
    };
    let source_absolute = match source_content_root.resolve_existing(&source_relative) {
        Ok(value) => value,
        Err(_) => fail_now!(Error::SourceUnavailable),
    };
    let source_str = match source_absolute.to_str() {
        Some(value) => value.to_owned(),
        None => fail_now!(Error::SourceUnavailable),
    };

    let staging_relative = match req
        .staging_root
        .strip_prefix(staging_content_root.as_path())
        .ok()
        .filter(|value| !value.as_os_str().is_empty())
        .and_then(|value| SiteRelativePath::parse(value).ok())
    {
        Some(value) => value,
        None => fail_now!(Error::SourceUnavailable),
    };

    if let Err(error) = clone_with_recovery(
        ctx,
        req,
        &scope,
        &staging_managed,
        staging_content_root,
        &staging_relative,
        &source_str,
        cancel,
    ) {
        fail_now!(error);
    }

    let result = CloneResult {
        recovery_id: req.request_id.to_string(),
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
    // A crash before this point leaves pending.json and prevents a blind retry.
    let _ = scope.remove_file(&SiteRelativePath::parse("pending.json").unwrap());
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(req.request_id, true, None),
    );
    drop(lock);
    Ok(result)
}

fn step_limits() -> ProcessLimits {
    ProcessLimits {
        timeout: COPY_TIMEOUT,
        max_stdout_bytes: MAX_STEP_OUTPUT_BYTES,
        max_stderr_bytes: MAX_STEP_OUTPUT_BYTES,
    }
}

fn wp_command(ctx: &Context<'_>, req: &Request, source: bool) -> ProcessRequest {
    let (container, root, uid, gid) = if source {
        (
            &req.source_container,
            &req.source_root,
            req.source_uid,
            req.source_gid,
        )
    } else {
        (
            &req.staging_container,
            &req.staging_root,
            req.staging_uid,
            req.staging_gid,
        )
    };
    ProcessRequest::new(ctx.docker_program).args([
        "exec".to_owned(),
        "-i".into(),
        "--user".into(),
        format!("{uid}:{gid}"),
        container.as_str().into(),
        "wp".into(),
        format!("--path={}", root.display()),
        "--skip-plugins".into(),
        "--skip-themes".into(),
    ])
}

// The bounded process runner deliberately excludes argv/output from errors.
fn wp_step(
    ctx: &Context<'_>,
    req: &Request,
    args: &[&str],
    cancel: &CancellationToken,
) -> Result<(), Error> {
    critical(process::run(
        &wp_command(ctx, req, false).args(args),
        &step_limits(),
        cancel,
    ))
}

#[allow(clippy::too_many_arguments)]
fn clone_with_recovery(
    ctx: &Context<'_>,
    req: &Request,
    scope: &ManagedRoot,
    staging: &ManagedRoot,
    content_root: &TrustedRoot,
    relative: &SiteRelativePath,
    source: &str,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    // Reject symlinked targets/parents and overlapping canonical paths before
    // snapshotting or executing any application code against the destination.
    let parent = relative
        .as_path()
        .parent()
        .filter(|p| !p.as_os_str().is_empty());
    let parent_absolute = match parent {
        Some(p) => content_root
            .resolve_existing(&SiteRelativePath::parse(p).map_err(|_| Error::UnsafeTarget)?)
            .map_err(|_| Error::UnsafeTarget)?,
        None => content_root.as_path().canonicalize().map_err(Error::Io)?,
    };
    let target = parent_absolute.join(relative.as_path().file_name().ok_or(Error::UnsafeTarget)?);
    let source = std::path::Path::new(source);
    if target.starts_with(source) || source.starts_with(&target) {
        return Err(Error::UnsafeTarget);
    }
    match staging.open_dir(relative) {
        Ok(_) => {
            let resolved = content_root
                .resolve_existing(relative)
                .map_err(|_| Error::UnsafeTarget)?;
            if resolved != target {
                return Err(Error::UnsafeTarget);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(Error::UnsafeTarget),
    }

    let identity = process::run(
        &wp_command(ctx, req, true).args(["config", "get", "DB_NAME", "--type=constant"]),
        &step_limits(),
        cancel,
    )
    .map_err(Error::Run)?;
    if let Some(code) = process::error_code(&identity.termination) {
        return Err(Error::Rejected(code));
    }
    let source_db = String::from_utf8(identity.stdout.bytes).map_err(|_| Error::UnsafeTarget)?;
    if identity.stdout.truncated
        || DatabaseName::parse(source_db.trim()).is_err()
        || source_db.trim() == req.db_name.as_str()
    {
        return Err(Error::UnsafeTarget);
    }

    let pending = SiteRelativePath::parse("pending.json").unwrap();
    let recovery_dir =
        SiteRelativePath::parse(format!("wordpress-clone/{}", req.request_id)).unwrap();
    let recovery_sql =
        SiteRelativePath::parse(format!("wordpress-clone/{}/target.sql", req.request_id)).unwrap();
    let source_sql =
        SiteRelativePath::parse(format!("wordpress-clone/{}/dump.sql", req.request_id)).unwrap();
    let saved_dir = SiteRelativePath::parse(format!(".wcp-clone-{}", req.request_id)).unwrap();
    let saved_files =
        SiteRelativePath::parse(format!(".wcp-clone-{}/site", req.request_id)).unwrap();
    let manifest = serde_json::to_vec(&serde_json::json!({
        "requestId": req.request_id, "stagingRoot": req.staging_root,
        "database": req.db_name.as_str(), "databaseContainer": req.mariadb_container.as_str(),
        "databaseSnapshot": ctx.dump_root.join(&recovery_sql),
        "savedFiles": content_root.join(&saved_files),
    }))
    .map_err(|_| Error::UnsafeTarget)?;
    scope
        .create_new(&pending, &manifest)
        .map_err(|_| Error::RecoveryRequired)?;

    let mut moved_files = false;
    let mut created_target = false;
    let mut database_mutated = false;
    let work = (|| -> Result<(), Error> {
        ctx.dump_managed
            .create_dir_all(&recovery_dir)
            .map_err(Error::Io)?;
        ctx.dump_managed
            .set_mode(&recovery_dir, 0o700)
            .map_err(Error::Io)?;
        ctx.dump_managed
            .create_new(
                &SiteRelativePath::parse(format!(
                    "wordpress-clone/{}/manifest.json",
                    req.request_id
                ))
                .unwrap(),
                &manifest,
            )
            .map_err(Error::Io)?;
        let snapshot = ctx
            .dump_managed
            .create_new_file(&recovery_sql)
            .map_err(Error::Io)?;
        ctx.dump_managed
            .set_mode(&recovery_sql, 0o600)
            .map_err(Error::Io)?;
        // Include DROP/CREATE DATABASE so rollback also removes tables newly
        // introduced by the clone. The target database already exists.
        critical(process::run_with_stdout_file(
            &ProcessRequest::new(ctx.docker_program)
                .env("MYSQL_PWD", &req.db_root_password)
                .args([
                    "exec",
                    "-i",
                    "-e",
                    "MYSQL_PWD",
                    req.mariadb_container.as_str(),
                    "mariadb-dump",
                    "-uroot",
                    "--single-transaction",
                    "--routines",
                    "--triggers",
                    "--events",
                    "--add-drop-database",
                    "--databases",
                    req.db_name.as_str(),
                ]),
            snapshot,
            &step_limits(),
            cancel,
        ))?;
        staging.create_dir(&saved_dir).map_err(Error::Io)?;
        staging.set_mode(&saved_dir, 0o700).map_err(Error::Io)?;
        match staging.rename(relative, &saved_files) {
            Ok(()) => moved_files = true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::Io(e)),
        }
        staging.create_dir(relative).map_err(Error::Io)?;
        created_target = true;
        let absolute = content_root
            .resolve_existing(relative)
            .map_err(|_| Error::UnsafeTarget)?;
        critical(process::run(
            &ProcessRequest::new(ctx.cp_program).args([
                "-a",
                "--",
                &format!("{}/.", source.display()),
                absolute.to_str().ok_or(Error::UnsafeTarget)?,
            ]),
            &step_limits(),
            cancel,
        ))?;
        // A symlinked wp-config could make `wp config set` modify the source.
        let config = staging
            .open_dir(relative)
            .map_err(Error::Io)?
            .symlink_metadata("wp-config.php")
            .map_err(Error::Io)?;
        if !config.is_file() {
            return Err(Error::UnsafeTarget);
        }
        repair_tree(&absolute, req.staging_uid, req.staging_gid, &[]).map_err(Error::Io)?;
        for (key, value) in [
            ("DB_NAME", req.db_name.as_str()),
            ("DB_USER", req.db_user.as_str()),
            ("DB_PASSWORD", req.db_password.as_str()),
            ("DB_HOST", req.mariadb_container.as_str()),
        ] {
            // WP-CLI reads the value from stdin, keeping credentials out of argv.
            critical(process::run_with_stdin_bytes(
                &wp_command(ctx, req, false).args([
                    "config",
                    "set",
                    key,
                    "--type=constant",
                    "--prompt=value",
                ]),
                format!("{value}\n").as_bytes(),
                &step_limits(),
                cancel,
            ))?;
        }
        let dump = ctx
            .dump_managed
            .create_new_file(&source_sql)
            .map_err(Error::Io)?;
        ctx.dump_managed
            .set_mode(&source_sql, 0o600)
            .map_err(Error::Io)?;
        critical(process::run_with_stdout_file(
            &wp_command(ctx, req, true).args(["db", "export", "-", "--add-drop-table"]),
            dump,
            &step_limits(),
            cancel,
        ))?;
        database_mutated = true; // Even a failed import may have changed tables.
        restore(ctx, req, &source_sql, cancel)?;
        wp_step(
            ctx,
            req,
            &[
                "search-replace",
                req.source_domain.as_str(),
                req.staging_domain.as_str(),
                "--all-tables",
                "--report-changed-only",
            ],
            cancel,
        )?;
        wp_step(ctx, req, &["core", "is-installed"], cancel)?;
        Ok(())
    })();
    let _ = ctx.dump_managed.remove_file(&source_sql);
    if let Err(error) = work {
        // A cancelled forward operation must still be allowed to recover.
        let recovered_db = !database_mutated
            || restore(ctx, req, &recovery_sql, &CancellationToken::default()).is_ok();
        let removed = !created_target || staging.remove_dir_all(relative).is_ok();
        let recovered_files = if moved_files && recovered_db && removed {
            staging.rename(&saved_files, relative).is_ok()
        } else {
            !moved_files
        };
        if !recovered_db || !removed || !recovered_files {
            return Err(Error::RecoveryRequired);
        }
        scope.remove_file(&pending).map_err(Error::Io)?;
        return Err(error);
    }
    // Keep target.sql, manifest.json and old files for explicit recovery.
    // pending.json is cleared only after execute() durably records commit.
    Ok(())
}

fn restore(
    ctx: &Context<'_>,
    req: &Request,
    file: &SiteRelativePath,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let absolute = ctx
        .dump_root
        .resolve_existing(file)
        .map_err(|_| Error::UnsafeTarget)?;
    let request = crate::db_restore::RestoreRequest {
        db_type: DbType::Mariadb,
        database: req.db_name.clone(),
        container: req.mariadb_container.clone(),
        file_path: absolute.to_str().ok_or(Error::UnsafeTarget)?.into(),
        root_password: req.db_root_password.clone(),
        request_id: req.request_id,
        idempotency_key: req.idempotency_key.clone(),
    };
    run_restore(
        &RestoreContext {
            engine_state: ctx.engine_state,
            docker_program: ctx.docker_program,
            gunzip_program: "gunzip",
        },
        &request,
        cancel,
    )
    .map_err(Error::Import)
}

fn critical(output: Result<process::ProcessOutput, ProcessRunError>) -> Result<(), Error> {
    let output = output.map_err(Error::Run)?;
    if let Some(code) = process::error_code(&output.termination) {
        return Err(Error::Rejected(code));
    }
    Ok(())
}

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<CloneResult, Error> {
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
    use std::{fs, os::unix::fs::PermissionsExt};

    const REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    fn valid_json(source_root: &std::path::Path, staging_root: &std::path::Path) -> String {
        format!(
            r#"{{
                "sourceContainer": "runtime-source",
                "sourceRoot": "{source}",
                "sourceUid": 5000,
                "sourceGid": 5000,
                "stagingRoot": "{staging}",
                "stagingContainer": "runtime-staging",
                "sourceDomain": "source.example.com",
                "stagingDomain": "staging.example.com",
                "dbUser": "staging_user",
                "dbPassword": "staging-secret",
                "stagingUid": {uid},
                "stagingGid": {gid},
                "mariadbContainer": "mariadb-1",
                "dbName": "staging_db",
                "dbRootPassword": "rootpw"
            }}"#,
            source = source_root.display(),
            staging = staging_root.display(),
            uid = current_uid(),
            gid = current_gid(),
        )
    }

    fn current_uid() -> u32 {
        unsafe { libc::getuid().max(1) }
    }

    fn current_gid() -> u32 {
        unsafe { libc::getgid().max(1) }
    }

    #[test]
    fn parses_a_well_formed_plan() {
        let json = valid_json(
            std::path::Path::new("/var/www/source.example.com"),
            std::path::Path::new("/var/www/staging.example.com"),
        );
        let request = Request::parse(&json, REQUEST_ID, None).expect("should parse");
        assert_eq!(
            request.source_root(),
            std::path::Path::new("/var/www/source.example.com")
        );
        assert_eq!(
            request.staging_root(),
            std::path::Path::new("/var/www/staging.example.com")
        );
    }

    #[test]
    fn rejects_identical_source_and_staging_roots() {
        let json = valid_json(
            std::path::Path::new("/var/www/same.example.com"),
            std::path::Path::new("/var/www/same.example.com"),
        );
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn rejects_a_staging_root_nested_inside_the_source_root() {
        let json = valid_json(
            std::path::Path::new("/var/www/source.example.com"),
            std::path::Path::new("/var/www/source.example.com/staging"),
        );
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn rejects_a_source_root_nested_inside_the_staging_root() {
        let json = valid_json(
            std::path::Path::new("/var/www/staging.example.com/nested"),
            std::path::Path::new("/var/www/staging.example.com"),
        );
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn rejects_a_malformed_container_name() {
        let json = valid_json(
            std::path::Path::new("/var/www/source.example.com"),
            std::path::Path::new("/var/www/staging.example.com"),
        )
        .replace("runtime-source", "bad;name");
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn rejects_a_db_root_password_containing_control_bytes() {
        let json = valid_json(
            std::path::Path::new("/var/www/source.example.com"),
            std::path::Path::new("/var/www/staging.example.com"),
        )
        .replace("rootpw", "line1\\nline2");
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    // ── `execute` integration tests ──────────────────────────────────────

    fn write_script(directory: &std::path::Path, name: &str, body: &str) -> PathBuf {
        let path = directory.join(name);
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// A fake `cp` that logs its argv then delegates to the real system
    /// `cp`, so the copy step is exercised for real (content really lands
    /// in the staging directory) while still proving the exact argv this
    /// module builds.
    const FAKE_CP: &str =
        "#!/bin/sh\necho \"$@\" >> \"$(dirname \"$0\")/cp-calls.log\"\nexec cp \"$@\"\n";

    // Simulates the bounded Docker/WP-CLI boundary; file copy stays real.
    fn fake_docker(reject_import: bool) -> String {
        let script = r#"#!/bin/sh
base="$(dirname "$0")"
echo "$@" >> "$base/docker-calls.log"
case "$*" in
  *"config get DB_NAME"*) echo source_db ;;
  *"mariadb-dump"*) echo '-- original target database --' ;;
  *"config set"*) cat >> "$base/config-inputs" ;;
  *"db export"*) printf '%s\n' '-- dump --' "INSERT INTO wp_options VALUES (1,'x');" ;;
  *"search-replace"*) test ! -f "$base/REJECT_REPLACE" ;;
  *"core is-installed"*) test ! -f "$base/REJECT_HEALTH" ;;
  *"mariadb "*)
    cat > "$base/last-import.sql"
    if grep -q 'original target' "$base/last-import.sql"; then
      cp "$base/last-import.sql" "$base/recovered.sql"
      test ! -f "$base/REJECT_RECOVERY"
    else
      cp "$base/last-import.sql" "$base/received.sql"
      REJECT_IMPORT
    fi ;;
  *) exit 2 ;;
esac
"#;
        script.replace(
            "REJECT_IMPORT",
            if reject_import { "exit 1" } else { "exit 0" },
        )
    }

    struct Fixture {
        _directory: tempfile::TempDir,
        content_root: TrustedRoot,
        engine_state: ManagedRoot,
        dump_managed: ManagedRoot,
        dump_root: TrustedRoot,
        docker: PathBuf,
        cp: PathBuf,
        source_root: PathBuf,
        staging_root: PathBuf,
    }

    fn fixture(docker_body: &str, pre_existing_staging_file: Option<&str>) -> Fixture {
        let directory = tempfile::tempdir().unwrap();
        let content_dir = directory.path().join("content");
        let state_dir = directory.path().join("state");
        let dump_dir = directory.path().join("dumps");
        fs::create_dir_all(content_dir.join("source.example.com/wp-content")).unwrap();
        fs::write(
            content_dir.join("source.example.com/wp-config.php"),
            "<?php // source config\n",
        )
        .unwrap();
        fs::write(
            content_dir.join("source.example.com/wp-content/plugin.php"),
            "<?php // plugin\n",
        )
        .unwrap();
        if let Some(stale) = pre_existing_staging_file {
            let staging_dir = content_dir.join("staging.example.com");
            fs::create_dir_all(&staging_dir).unwrap();
            fs::write(staging_dir.join(stale), "stale content").unwrap();
        }
        fs::create_dir_all(&state_dir).unwrap();
        fs::create_dir_all(&dump_dir).unwrap();

        let content_root = TrustedRoot::parse(&content_dir).unwrap();
        let engine_state = ManagedRoot::open(&TrustedRoot::parse(&state_dir).unwrap()).unwrap();
        let dump_root = TrustedRoot::parse(&dump_dir).unwrap();
        let dump_managed = ManagedRoot::open(&dump_root).unwrap();
        let docker = write_script(directory.path(), "fake-docker", docker_body);
        let cp = write_script(directory.path(), "fake-cp", FAKE_CP);

        Fixture {
            source_root: content_dir.join("source.example.com"),
            staging_root: content_dir.join("staging.example.com"),
            _directory: directory,
            content_root,
            engine_state,
            dump_managed,
            dump_root,
            docker,
            cp,
        }
    }

    fn context(fx: &Fixture) -> Context<'_> {
        Context {
            engine_state: &fx.engine_state,
            dump_managed: &fx.dump_managed,
            dump_root: &fx.dump_root,
            docker_program: fx.docker.to_str().unwrap(),
            cp_program: fx.cp.to_str().unwrap(),
        }
    }

    fn request_for(fx: &Fixture, request_id: &str, key: Option<&str>) -> Request {
        let json = valid_json(&fx.source_root, &fx.staging_root);
        Request::parse(&json, request_id, key).expect("request should parse")
    }

    #[test]
    fn clones_content_and_database_and_fixes_ownership() {
        let fx = fixture(&fake_docker(false), None);
        let request = request_for(&fx, REQUEST_ID, None);

        let result = execute(
            &context(&fx),
            &fx.content_root,
            &fx.content_root,
            &request,
            &CancellationToken::default(),
        )
        .expect("clone should succeed");
        assert!(result.completed_at_unix_secs > 0);

        assert_eq!(
            fs::read_to_string(fx.staging_root.join("wp-config.php")).unwrap(),
            "<?php // source config\n"
        );
        assert_eq!(
            fs::read_to_string(fx.staging_root.join("wp-content/plugin.php")).unwrap(),
            "<?php // plugin\n"
        );

        let received = fx.docker.parent().unwrap().join("received.sql");
        assert_eq!(
            fs::read_to_string(received).unwrap(),
            "-- dump --\nINSERT INTO wp_options VALUES (1,'x');\n"
        );

        // The dump is transient working state, not a recovery artifact -
        // it must not survive a successful clone.
        assert!(
            !fx.dump_root
                .as_path()
                .join(format!("wordpress-clone/{REQUEST_ID}/dump.sql"))
                .exists()
        );
    }

    #[test]
    fn wipes_pre_existing_staging_content_before_copying() {
        let fx = fixture(&fake_docker(false), Some("stale.txt"));
        assert!(fx.staging_root.join("stale.txt").exists());
        let request = request_for(&fx, REQUEST_ID, None);

        execute(
            &context(&fx),
            &fx.content_root,
            &fx.content_root,
            &request,
            &CancellationToken::default(),
        )
        .expect("clone should succeed");

        assert!(!fx.staging_root.join("stale.txt").exists());
        assert!(fx.staging_root.join("wp-config.php").exists());
    }

    #[test]
    fn rejects_a_source_root_that_does_not_exist() {
        let fx = fixture(&fake_docker(false), None);
        let missing_source = fx.content_root.as_path().join("never-created.example.com");
        let json = valid_json(&missing_source, &fx.staging_root);
        let request = Request::parse(&json, REQUEST_ID, None).unwrap();

        let error = execute(
            &context(&fx),
            &fx.content_root,
            &fx.content_root,
            &request,
            &CancellationToken::default(),
        )
        .expect_err("a missing source root should be rejected");
        assert_eq!(error.protocol().0, ErrorCode::InvalidInput);
        assert!(!fx.staging_root.exists(), "staging must not be touched");
    }

    #[test]
    fn fails_closed_and_removes_the_staging_directory_when_the_import_is_rejected() {
        let fx = fixture(&fake_docker(true), None);
        let request = request_for(&fx, REQUEST_ID, None);

        let error = execute(
            &context(&fx),
            &fx.content_root,
            &fx.content_root,
            &request,
            &CancellationToken::default(),
        )
        .expect_err("a rejected import should fail the whole clone");
        assert_eq!(error.protocol().0, ErrorCode::SubprocessFailed);
        assert!(
            !fx.staging_root.exists(),
            "a failed clone must not leave a half-cloned staging directory"
        );
    }

    #[test]
    fn replaying_the_same_idempotency_key_returns_the_original_result_without_recloning() {
        let fx = fixture(&fake_docker(false), None);
        let first = request_for(&fx, REQUEST_ID, Some("clone-once"));

        let first_result = execute(
            &context(&fx),
            &fx.content_root,
            &fx.content_root,
            &first,
            &CancellationToken::default(),
        )
        .expect("first attempt should succeed");

        // Remove the staging content and the docker call log; a replay must
        // not touch either again.
        fs::remove_dir_all(&fx.staging_root).unwrap();
        let docker_log = fx.docker.parent().unwrap().join("docker-calls.log");
        fs::remove_file(&docker_log).ok();

        let second_request_id = "223e4567-e89b-12d3-a456-426614174000";
        let second = request_for(&fx, second_request_id, Some("clone-once"));
        let second_result = execute(
            &context(&fx),
            &fx.content_root,
            &fx.content_root,
            &second,
            &CancellationToken::default(),
        )
        .expect("replay should return the recorded result");

        assert_eq!(
            first_result.completed_at_unix_secs,
            second_result.completed_at_unix_secs
        );
        assert!(
            !fx.staging_root.exists(),
            "a replayed idempotency key must not re-run the clone"
        );
        assert!(!docker_log.exists());
    }
    #[test]
    fn finalization_failure_restores_old_files_and_database_and_keeps_secrets_out_of_state() {
        for failure in ["REJECT_REPLACE", "REJECT_HEALTH"] {
            let fx = fixture(&fake_docker(false), Some("original.txt"));
            fs::write(fx.docker.parent().unwrap().join(failure), "").unwrap();
            let req = request_for(&fx, REQUEST_ID, None);
            let err = execute(
                &context(&fx),
                &fx.content_root,
                &fx.content_root,
                &req,
                &CancellationToken::default(),
            )
            .unwrap_err();
            assert_eq!(err.protocol().0, ErrorCode::SubprocessFailed);
            assert_eq!(
                fs::read_to_string(fx.staging_root.join("original.txt")).unwrap(),
                "stale content"
            );
            assert!(!fx.staging_root.join("wp-config.php").exists());
            assert!(fx.docker.parent().unwrap().join("recovered.sql").exists());
            let manifest = fs::read_to_string(
                fx.dump_root
                    .as_path()
                    .join(format!("wordpress-clone/{REQUEST_ID}/manifest.json")),
            )
            .unwrap();
            assert!(!manifest.contains("staging-secret"));
            assert!(!manifest.contains("rootpw"));
        }
    }

    #[test]
    fn successful_clone_finalizes_on_staging_runtime_before_health_check() {
        let fx = fixture(&fake_docker(false), None);
        let req = request_for(&fx, REQUEST_ID, None);
        execute(
            &context(&fx),
            &fx.content_root,
            &fx.content_root,
            &req,
            &CancellationToken::default(),
        )
        .unwrap();
        let log = fs::read_to_string(fx.docker.parent().unwrap().join("docker-calls.log")).unwrap();
        assert!(log.contains("runtime-staging wp"));
        assert!(log.contains("config set DB_HOST --type=constant --prompt=value"));
        assert!(log.contains("search-replace source.example.com staging.example.com --all-tables"));
        assert!(log.find("config set DB_PASSWORD").unwrap() < log.find("search-replace").unwrap());
        assert!(log.find("search-replace").unwrap() < log.find("core is-installed").unwrap());
        assert!(!log.contains("staging-secret"));
        assert!(
            fs::read_to_string(fx.docker.parent().unwrap().join("config-inputs"))
                .unwrap()
                .contains("staging-secret")
        );
    }

    #[test]
    fn recovery_failure_retains_artifacts_and_blocks_another_clone() {
        let fx = fixture(&fake_docker(false), Some("original.txt"));
        for marker in ["REJECT_REPLACE", "REJECT_RECOVERY"] {
            fs::write(fx.docker.parent().unwrap().join(marker), "").unwrap();
        }
        let req = request_for(&fx, REQUEST_ID, None);
        let err = execute(
            &context(&fx),
            &fx.content_root,
            &fx.content_root,
            &req,
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert_eq!(err.protocol().0, ErrorCode::Conflict);
        assert!(
            fx.content_root
                .as_path()
                .join(format!(".wcp-clone-{REQUEST_ID}/site/original.txt"))
                .exists()
        );
        assert!(
            fx.dump_root
                .as_path()
                .join(format!("wordpress-clone/{REQUEST_ID}/target.sql"))
                .exists()
        );
        assert!(!fx.staging_root.exists());
        let req2 = request_for(&fx, "223e4567-e89b-12d3-a456-426614174000", None);
        assert_eq!(
            execute(
                &context(&fx),
                &fx.content_root,
                &fx.content_root,
                &req2,
                &CancellationToken::default()
            )
            .unwrap_err()
            .protocol()
            .0,
            ErrorCode::Conflict
        );
    }

    #[test]
    fn refuses_source_database_as_target_and_symlinked_wp_config() {
        let fx = fixture(&fake_docker(false), Some("original.txt"));
        let mut req = request_for(&fx, REQUEST_ID, None);
        req.db_name = DatabaseName::parse("source_db").unwrap();
        assert!(
            execute(
                &context(&fx),
                &fx.content_root,
                &fx.content_root,
                &req,
                &CancellationToken::default()
            )
            .is_err()
        );
        assert!(fx.staging_root.join("original.txt").exists());
        assert!(!fx.docker.parent().unwrap().join("received.sql").exists());

        let fx = fixture(&fake_docker(false), Some("original.txt"));
        fs::remove_file(fx.source_root.join("wp-config.php")).unwrap();
        std::os::unix::fs::symlink(
            "wp-content/plugin.php",
            fx.source_root.join("wp-config.php"),
        )
        .unwrap();
        let req = request_for(&fx, REQUEST_ID, None);
        assert!(
            execute(
                &context(&fx),
                &fx.content_root,
                &fx.content_root,
                &req,
                &CancellationToken::default()
            )
            .is_err()
        );
        assert!(fx.staging_root.join("original.txt").exists());
        assert!(!fx.docker.parent().unwrap().join("received.sql").exists());
    }

    #[test]
    fn rejects_missing_finalization_fields_root_identity_and_invalid_domain() {
        let json = valid_json(
            std::path::Path::new("/var/www/source"),
            std::path::Path::new("/var/www/target"),
        );
        for field in [
            "stagingContainer",
            "sourceDomain",
            "stagingDomain",
            "dbUser",
            "dbPassword",
        ] {
            let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
            value.as_object_mut().unwrap().remove(field);
            assert!(Request::parse(&value.to_string(), REQUEST_ID, None).is_err());
        }
        assert!(
            Request::parse(
                &json.replace("source.example.com", "--evil"),
                REQUEST_ID,
                None
            )
            .is_err()
        );
        assert!(
            Request::parse(
                &json.replace("\"sourceUid\": 5000", "\"sourceUid\": 0"),
                REQUEST_ID,
                None
            )
            .is_err()
        );
    }
}
