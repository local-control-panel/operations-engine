//! The `wordpress.clone` operation: clone a WordPress site's content and
//! database into a fresh staging directory on the same server, as one
//! lock/idempotency/transaction/audit-backed request - the same shape as
//! `wordpress_install`, and the follow-up the risk audit (`wp_clone`,
//! Critical: "`rsync --delete`, DB creation/import, ownership and config
//! changes lack one transaction. Decompose, then orchestrate.") called for.
//!
//! Three steps, all critical, run in this fixed order under one lock scoped
//! to the *staging* root (the resource actually being mutated; the source
//! is only ever read from):
//!
//! 1. **Content copy** - the staging directory is freshly (re)created (any
//!    prior contents are removed first, matching the mirror semantics of
//!    the raw `rsync --delete` this replaces) under a configured content
//!    root, then populated with a fixed, bounded `cp -a` subprocess. No
//!    `rsync` - a plain recursive archive copy is enough for a same-host,
//!    same-filesystem-class copy, and drops an extra dependency together
//!    with `rsync --delete`'s harder-to-reason-about semantics.
//! 2. **Database export + import** - `wp db export -` streams the source
//!    database (run as the source site's own UID/GID, exactly like
//!    `wordpress.updateCore`'s own recovery snapshot) into a request-scoped
//!    file beneath the fixed backup root, then the same bounded restore
//!    client `db.restore` uses (`db_restore::execute::run_restore`) imports
//!    it into the already-provisioned staging database. The dump is
//!    deleted immediately after the import attempt, success or failure -
//!    it is transient working state, not a recovery artifact.
//! 3. **Ownership fix** - `permissions.fixOwnership`'s own fd-relative,
//!    `AT_SYMLINK_NOFOLLOW`, same-filesystem repair walk
//!    (`permissions::execute::repair_tree`) re-chowns the freshly copied
//!    tree to the staging site's own UID/GID; `cp -a` preserves the
//!    *source*'s ownership, exactly like `rsync -a` did before it.
//!
//! Any failure removes the staging directory this request itself just
//! (re)created - unlike `wordpress.install`, this operation genuinely owns
//! that directory's lifecycle for the duration of the request, so cleaning
//! it up on failure does not risk destroying another component's prior
//! work. `wp-config.php`'s DB credentials and the source→staging
//! domain search-replace remain outside this operation, run by the client
//! afterward exactly as before - see `raw-mutation-risk-audit.md`'s backlog
//! item 5.

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
    site::{SiteRelativePath, TrustedRoot},
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
const EXPORT_TIMEOUT: Duration = Duration::from_secs(1800);
const MAX_STEP_OUTPUT_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    source_container: String,
    source_root: String,
    source_uid: u32,
    source_gid: u32,
    staging_root: String,
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

        Ok(Self {
            source_container: ContainerName::parse(&plan.source_container)
                .map_err(|_: RestoreRequestError| RequestError)?,
            source_root,
            source_uid: plan.source_uid,
            source_gid: plan.source_gid,
            staging_root,
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
                "WordPress site copy or database export failed".into(),
            ),
            Self::SourceUnavailable => (
                ErrorCode::InvalidInput,
                "WordPress source root does not exist or is outside the configured content root"
                    .into(),
            ),
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

    // Fresh, mirror-equivalent staging directory: drop anything already
    // there (a prior clone attempt, most likely), then recreate it empty.
    let _ = staging_managed.remove_dir_all(&staging_relative);
    if let Err(error) = staging_managed.create_dir_all(&staging_relative) {
        fail_now!(Error::Io(error));
    }
    let staging_absolute = match staging_content_root.resolve_existing(&staging_relative) {
        Ok(value) => value,
        Err(_) => fail_now!(Error::SourceUnavailable),
    };
    let staging_str = match staging_absolute.to_str() {
        Some(value) => value.to_owned(),
        None => fail_now!(Error::SourceUnavailable),
    };

    // ── Step 1: content copy ──
    let copy = process::run(
        &ProcessRequest::new(ctx.cp_program).args([
            "-a",
            "--",
            &format!("{source_str}/."),
            &staging_str,
        ]),
        &ProcessLimits {
            timeout: COPY_TIMEOUT,
            max_stdout_bytes: MAX_STEP_OUTPUT_BYTES,
            max_stderr_bytes: MAX_STEP_OUTPUT_BYTES,
        },
        cancel,
    );
    if let Err(error) = critical(copy) {
        let _ = staging_managed.remove_dir_all(&staging_relative);
        fail_now!(error);
    }

    // ── Step 2a: export the source database to a request-scoped dump ──
    let dump_dir = SiteRelativePath::parse(format!("wordpress-clone/{}", req.request_id)).unwrap();
    if let Err(error) = ctx.dump_managed.create_dir_all(&dump_dir) {
        let _ = staging_managed.remove_dir_all(&staging_relative);
        fail_now!(Error::Io(error));
    }
    let dump_relative =
        SiteRelativePath::parse(format!("wordpress-clone/{}/dump.sql", req.request_id)).unwrap();
    let dump_file = match ctx.dump_managed.create_new_file(&dump_relative) {
        Ok(value) => value,
        Err(error) => {
            let _ = staging_managed.remove_dir_all(&staging_relative);
            fail_now!(Error::Io(error));
        }
    };
    let export_args = [
        "exec".to_owned(),
        "-i".to_owned(),
        "--user".to_owned(),
        format!("{}:{}", req.source_uid, req.source_gid),
        req.source_container.as_str().to_owned(),
        "wp".to_owned(),
        format!("--path={source_str}"),
        "--allow-root".to_owned(),
        "db".to_owned(),
        "export".to_owned(),
        "-".to_owned(),
        "--add-drop-table".to_owned(),
    ];
    let export = process::run_with_stdout_file(
        &ProcessRequest::new(ctx.docker_program).args(export_args),
        dump_file,
        &ProcessLimits {
            timeout: EXPORT_TIMEOUT,
            max_stdout_bytes: 0,
            max_stderr_bytes: MAX_STEP_OUTPUT_BYTES,
        },
        cancel,
    );
    if let Err(error) = critical(export) {
        let _ = ctx.dump_managed.remove_file(&dump_relative);
        let _ = staging_managed.remove_dir_all(&staging_relative);
        fail_now!(error);
    }

    // ── Step 2b: import the dump into the already-provisioned staging DB ──
    let dump_absolute = match ctx.dump_root.resolve_existing(&dump_relative) {
        Ok(value) => value,
        Err(_) => {
            let _ = ctx.dump_managed.remove_file(&dump_relative);
            let _ = staging_managed.remove_dir_all(&staging_relative);
            fail_now!(Error::Io(std::io::Error::other(
                "exported dump escaped the dump root"
            )));
        }
    };
    let dump_path_str = match dump_absolute.to_str() {
        Some(value) => value.to_owned(),
        None => {
            let _ = ctx.dump_managed.remove_file(&dump_relative);
            let _ = staging_managed.remove_dir_all(&staging_relative);
            fail_now!(Error::Io(std::io::Error::other(
                "exported dump path is not valid UTF-8"
            )));
        }
    };
    let restore_request = crate::db_restore::RestoreRequest {
        db_type: DbType::Mariadb,
        database: req.db_name.clone(),
        container: req.mariadb_container.clone(),
        file_path: dump_path_str,
        root_password: req.db_root_password.clone(),
        request_id: req.request_id,
        idempotency_key: req.idempotency_key.clone(),
    };
    let restore_context = RestoreContext {
        engine_state: ctx.engine_state,
        docker_program: ctx.docker_program,
        // Never reached: the dump this operation writes is always `.sql`,
        // never `.gz`, so `run_restore`'s gzip branch never runs.
        gunzip_program: "gunzip",
    };
    let import_result = run_restore(&restore_context, &restore_request, cancel);
    let _ = ctx.dump_managed.remove_file(&dump_relative);
    if let Err(error) = import_result {
        let _ = staging_managed.remove_dir_all(&staging_relative);
        fail_now!(Error::Import(error));
    }

    // ── Step 3: ownership fix ──
    if let Err(error) = repair_tree(&staging_absolute, req.staging_uid, req.staging_gid, &[]) {
        let _ = staging_managed.remove_dir_all(&staging_relative);
        fail_now!(Error::Io(error));
    }

    let result = CloneResult {
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
        unsafe { libc::getuid() }
    }

    fn current_gid() -> u32 {
        unsafe { libc::getgid() }
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

    /// A fake `docker` standing in for both WP-CLI (`db export -`, prints a
    /// fixed dump to stdout) and the MariaDB client (`exec -i ... mariadb
    /// ...`, reads stdin into `received.sql`) - matching `db_restore::
    /// execute`'s own test fake. A `REJECT` marker file makes the import
    /// branch fail, simulating the database rejecting the dump.
    fn fake_docker(reject_import: bool) -> String {
        format!(
            "#!/bin/sh\necho \"$@\" >> \"$(dirname \"$0\")/docker-calls.log\"\ncase \"$*\" in\n  *\"db export\"*)\n    printf '%s\\n' '-- dump --' \"INSERT INTO wp_options VALUES (1,'x');\"\n    exit 0\n    ;;\n  *)\n    {reject}\n    cat > \"$(dirname \"$0\")/received.sql\"\n    exit 0\n    ;;\nesac\n",
            reject = if reject_import { "exit 1" } else { ":" }
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
}
