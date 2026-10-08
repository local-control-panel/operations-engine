//! `wordpress.migrateImport`: the destination half of a cross-server
//! WordPress migration (milestone 055, `wp-migrate` design brief).
//!
//! The panel relays the two artifacts `wordpress.migrateExport` produced on
//! the source and stages them root-owned (`0600`, one link) as
//! `<artifact dir>/<request id>.db.sql.gz` and `.files.tar.gz`; the plan
//! carries the source manifest. Nothing is mutated until both artifacts
//! match the manifest's size and SHA-256 (brief decision 1) and the
//! manifest is within the confirmed limits (decision 4).
//!
//! Then, under the destination root's resource lock and a per-root `pending/<hash>.json`
//! recovery marker, the same recovery shape as `wordpress.clone` (brief
//! decision 2): snapshot the target database (`--add-drop-database`) and
//! move any existing site directory aside; extract the archive with the
//! bounded `tar_extract` reader (decision 3: in-root relative symlinks only)
//! into a fresh directory; fix ownership; set the `DB_*` constants over
//! stdin; import the dump with the root password in `MYSQL_PWD`; replace
//! the source domain; probe `core is-installed`. Any failure restores the
//! database and the previous directory. If that restore itself fails, the
//! marker and the recovery files stay for manual repair (`RecoveryRequired`).
//! The staged artifacts are removed either way. After a commit the target
//! snapshot and the previous files are kept for explicit recovery, as clone
//! keeps them.

use std::{
    fs,
    io::{self, Seek},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};

use crate::{
    db_restore::{ContainerName, DatabaseName},
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    permissions::execute::repair_tree,
    process::{self, CancellationToken, ProcessLimits, ProcessRequest, ProcessRunError},
    site::{Domain, SiteRelativePath, TrustedRoot},
    tar_extract::{self, ExtractError, Limits},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        resource_lock,
        state::{self, TransactionStatus},
    },
    wordpress_migrate_export::{
        MANIFEST_SCHEMA_VERSION, MAX_DUMP_BYTES, MAX_ENTRIES, MAX_FILES_BYTES, Manifest,
        sha256_file,
    },
};

pub const OPERATION: &str = "wordpress.migrateImport";

const SCOPE: &str = "wordpress-migrate-import";
const RECOVERY_DIR: &str = "wordpress-migrate";
const MAX_DB_PASSWORD_BYTES: usize = 256;
const STEP_TIMEOUT: Duration = Duration::from_secs(3600);
const MAX_STEP_OUTPUT_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    manifest: Manifest,
    dest_container: String,
    dest_root: String,
    dest_uid: u32,
    dest_gid: u32,
    dest_domain: String,
    mariadb_container: String,
    /// `DB_HOST` for `wp-config.php`: the stable Compose service name, which
    /// is not the container name `docker exec` uses.
    db_host: String,
    db_root_password: String,
    db_name: String,
    db_user: String,
    db_password: String,
}

pub struct Request {
    manifest: Manifest,
    source_domain: Domain,
    dest_container: ContainerName,
    dest_root: PathBuf,
    dest_uid: u32,
    dest_gid: u32,
    dest_domain: Domain,
    mariadb_container: ContainerName,
    db_host: ContainerName,
    db_root_password: String,
    db_name: DatabaseName,
    db_user: DatabaseName,
    db_password: String,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestError;

fn secret(value: &str) -> Result<(), RequestError> {
    if value.is_empty()
        || value.len() > MAX_DB_PASSWORD_BYTES
        || value.bytes().any(|b| matches!(b, 0 | b'\n' | b'\r'))
    {
        return Err(RequestError);
    }
    Ok(())
}

fn hex64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

impl Request {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError)?;
        let dest_root = PathBuf::from(&plan.dest_root);
        if !dest_root.is_absolute()
            || plan.dest_root.len() > 4096
            || plan.dest_root.ends_with('/')
            || dest_root.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(RequestError);
        }
        secret(&plan.db_root_password)?;
        secret(&plan.db_password)?;
        let manifest = plan.manifest;
        if manifest.schema_version != MANIFEST_SCHEMA_VERSION
            || !hex64(&manifest.database.sha256)
            || !hex64(&manifest.files.sha256)
        {
            return Err(RequestError);
        }
        Ok(Self {
            source_domain: Domain::parse(&manifest.source_domain).map_err(|_| RequestError)?,
            manifest,
            dest_container: ContainerName::parse(&plan.dest_container).map_err(|_| RequestError)?,
            dest_root,
            dest_uid: plan.dest_uid,
            dest_gid: plan.dest_gid,
            dest_domain: Domain::parse(&plan.dest_domain).map_err(|_| RequestError)?,
            mariadb_container: ContainerName::parse(&plan.mariadb_container)
                .map_err(|_| RequestError)?,
            db_host: ContainerName::parse(&plan.db_host).map_err(|_| RequestError)?,
            db_root_password: plan.db_root_password,
            db_name: DatabaseName::parse(&plan.db_name).map_err(|_| RequestError)?,
            db_user: DatabaseName::parse(&plan.db_user).map_err(|_| RequestError)?,
            db_password: plan.db_password,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError)?,
        })
    }

    pub fn dest_root(&self) -> &Path {
        &self.dest_root
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    pub recovery_id: String,
    pub file_entries: u64,
    pub symlinks: u64,
    pub completed_at_unix_secs: u64,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub content_root: &'a TrustedRoot,
    /// Where the target database snapshot is kept (`wordpress-migrate/<id>/`).
    pub recovery_managed: &'a ManagedRoot,
    pub recovery_root: &'a TrustedRoot,
    pub artifact_dir: &'a Path,
    pub artifact_owner_uid: u32,
    pub docker_program: &'a str,
    pub gunzip_program: &'a str,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Run(ProcessRunError),
    Rejected(ErrorCode),
    /// An artifact is missing, not root-owned `0600` with one link, or does
    /// not match the manifest's size and SHA-256.
    ArtifactMismatch,
    /// The manifest is over the migration limits.
    ManifestOverLimit,
    UnsafeTarget,
    Extract(ExtractError),
    ResourceBusy,
    RecoveryRequired,
    PostCommit(ImportResult),
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::ReplayInProgress | Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::ResourceBusy => (
                ErrorCode::Conflict,
                "another WordPress operation is already in progress for this site".into(),
            ),
            Self::Run(error) => (
                process::spawn_error_code(error),
                "a WordPress migration step could not run".into(),
            ),
            Self::Rejected(code) => (
                *code,
                "a WordPress migration step failed; the destination was restored".into(),
            ),
            Self::ArtifactMismatch => (
                ErrorCode::InvalidInput,
                "a migration artifact is missing, unsafe, or does not match the manifest".into(),
            ),
            Self::ManifestOverLimit => (
                ErrorCode::InvalidInput,
                "the migration exceeds the 20 GiB files / 10 GiB database / 1M entries limits"
                    .into(),
            ),
            Self::UnsafeTarget => (
                ErrorCode::InvalidInput,
                "the destination root is outside the content root, a symlink, or not a directory"
                    .into(),
            ),
            Self::Extract(ExtractError::Unsafe(name)) => (
                ErrorCode::InvalidInput,
                format!(
                    "the archive contains an entry that is not allowed (hardlink, device, \
                     absolute or escaping path or symlink): {name}; the destination was restored"
                ),
            ),
            Self::Extract(ExtractError::TooManyEntries | ExtractError::TooLarge) => (
                ErrorCode::InvalidInput,
                "the archive exceeds the migration limits; the destination was restored".into(),
            ),
            Self::Extract(_) => (
                ErrorCode::InvalidInput,
                "the files archive is corrupt; the destination was restored".into(),
            ),
            Self::RecoveryRequired => (
                ErrorCode::Conflict,
                "the migration failed and restoring the destination also failed; \
                 the root's pending marker and the recovery files identify what to repair"
                    .into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit(_) => (
                ErrorCode::Internal,
                "internal WordPress migration error".into(),
            ),
        }
    }
}

pub fn artifact_path(artifact_dir: &Path, request_id: RequestId, kind: &str) -> PathBuf {
    artifact_dir.join(format!("{request_id}.{kind}"))
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<ImportResult, Error> {
    let manifest = &req.manifest;
    if manifest.database_uncompressed_bytes > MAX_DUMP_BYTES
        || manifest.file_content_bytes > MAX_FILES_BYTES
        || manifest.file_entries > MAX_ENTRIES
    {
        return Err(Error::ManifestOverLimit);
    }
    let relative = req
        .dest_root
        .strip_prefix(ctx.content_root.as_path())
        .ok()
        .filter(|value| !value.as_os_str().is_empty())
        .and_then(|value| SiteRelativePath::parse(value).ok())
        .ok_or(Error::UnsafeTarget)?;

    let _resource_lock = resource_lock::acquire(ctx.engine_state, &req.dest_root, req.request_id)
        .map_err(|_| Error::ResourceBusy)?;
    let scope = open_scope(ctx.engine_state).map_err(Error::Io)?;
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
    let state_path = rel(&format!("transactions/{}.json", req.request_id));
    let audit_path = rel("audit/events.jsonl");

    let db_artifact = artifact_path(ctx.artifact_dir, req.request_id, "db.sql.gz");
    let files_artifact = artifact_path(ctx.artifact_dir, req.request_id, "files.tar.gz");
    let outcome = (|| {
        verify_artifact(
            ctx,
            &db_artifact,
            &manifest.database.sha256,
            manifest.database.bytes,
        )?;
        let files = verify_artifact(
            ctx,
            &files_artifact,
            &manifest.files.sha256,
            manifest.files.bytes,
        )?;
        import_with_recovery(ctx, req, &scope, &relative, &db_artifact, files, cancel)
    })();
    // The staged artifacts hold a full dump: they go whatever happened.
    let _ = fs::remove_file(&db_artifact);
    let _ = fs::remove_file(&files_artifact);

    let summary = match outcome {
        Ok(summary) => summary,
        Err(error) => {
            let (code, message) = error.protocol();
            let _ = state.mark_failed(code, message);
            let _ = state::save(&scope, &state_path, &state);
            let _ = audit::append(
                &scope,
                &audit_path,
                &AuditRecord::result(req.request_id, false, Some(code)),
            );
            return Err(error);
        }
    };
    let result = ImportResult {
        recovery_id: req.request_id.to_string(),
        file_entries: summary.entries,
        symlinks: summary.symlinks,
        completed_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    state
        .mark_committed(serde_json::to_value(&result).expect("results always serialize"))
        .expect("state is always InProgress at this point");
    if state::save(&scope, &state_path, &state).is_err() {
        drop(lock);
        return Err(Error::PostCommit(result));
    }
    // A crash before this point leaves the root's marker and prevents a blind retry.
    let _ = scope.remove_file(&pending_marker(&req.dest_root));
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(req.request_id, true, None),
    );
    drop(lock);
    Ok(result)
}

/// Opens an artifact without following a symlink, checks it is a
/// root-owned `0600` single-link regular file, and hashes it. Returns the
/// open handle, rewound, so what was hashed is what gets used.
fn verify_artifact(
    ctx: &Context<'_>,
    path: &Path,
    sha256: &str,
    bytes: u64,
) -> Result<fs::File, Error> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| Error::ArtifactMismatch)?;
    let meta = file.metadata().map_err(|_| Error::ArtifactMismatch)?;
    if !meta.is_file()
        || meta.uid() != ctx.artifact_owner_uid
        || meta.nlink() != 1
        || meta.mode() & 0o777 != 0o600
        || meta.len() != bytes
    {
        return Err(Error::ArtifactMismatch);
    }
    let (total, digest) = sha256_file(path).map_err(|_| Error::ArtifactMismatch)?;
    if total != bytes || !digest.eq_ignore_ascii_case(sha256) {
        return Err(Error::ArtifactMismatch);
    }
    file.rewind().map_err(Error::Io)?;
    Ok(file)
}

fn import_with_recovery(
    ctx: &Context<'_>,
    req: &Request,
    scope: &ManagedRoot,
    relative: &SiteRelativePath,
    db_artifact: &Path,
    files: fs::File,
    cancel: &CancellationToken,
) -> Result<tar_extract::Summary, Error> {
    let content = ManagedRoot::open(ctx.content_root).map_err(Error::Io)?;
    // The parent must resolve to itself (no symlink on the way) and an
    // existing destination must be a real directory.
    let canonical_root = ctx
        .content_root
        .as_path()
        .canonicalize()
        .map_err(|_| Error::UnsafeTarget)?;
    if let Some(parent) = relative
        .as_path()
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        let parent_rel = SiteRelativePath::parse(parent).map_err(|_| Error::UnsafeTarget)?;
        let resolved = ctx
            .content_root
            .resolve_existing(&parent_rel)
            .map_err(|_| Error::UnsafeTarget)?;
        if resolved != canonical_root.join(parent) {
            return Err(Error::UnsafeTarget);
        }
    }
    let absolute = canonical_root.join(relative.as_path());
    let target_exists = match fs::symlink_metadata(&absolute) {
        Ok(meta) if meta.is_dir() => true,
        Ok(_) => return Err(Error::UnsafeTarget),
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(Error::Io(error)),
    };

    let pending = pending_marker(&req.dest_root);
    if legacy_marker_blocks(scope, &req.dest_root) {
        return Err(Error::RecoveryRequired);
    }
    scope.create_dir_all(&rel("pending")).map_err(Error::Io)?;
    let recovery_dir = rel(&format!("{RECOVERY_DIR}/{}", req.request_id));
    let recovery_sql = rel(&format!("{RECOVERY_DIR}/{}/target.sql", req.request_id));
    let saved_dir = rel(&format!(".wcp-migrate-{}", req.request_id));
    let saved_files = rel(&format!(".wcp-migrate-{}/site", req.request_id));
    let marker = serde_json::to_vec(&serde_json::json!({
        "requestId": req.request_id, "destRoot": req.dest_root,
        "database": req.db_name.as_str(), "databaseContainer": req.mariadb_container.as_str(),
        "databaseSnapshot": ctx.recovery_root.join(&recovery_sql),
        "savedFiles": ctx.content_root.join(&saved_files),
    }))
    .map_err(|_| Error::UnsafeTarget)?;
    scope
        .create_new(&pending, &marker)
        .map_err(|_| Error::RecoveryRequired)?;

    let mut moved_files = false;
    let mut created_target = false;
    let mut database_mutated = false;
    let mut summary = tar_extract::Summary::default();
    let work = (|| -> Result<(), Error> {
        ctx.recovery_managed
            .create_dir_all(&recovery_dir)
            .map_err(Error::Io)?;
        ctx.recovery_managed
            .set_mode(&recovery_dir, 0o700)
            .map_err(Error::Io)?;
        let snapshot = ctx
            .recovery_managed
            .create_new_file(&recovery_sql)
            .map_err(Error::Io)?;
        ctx.recovery_managed
            .set_mode(&recovery_sql, 0o600)
            .map_err(Error::Io)?;
        critical(process::run_with_stdout_file(
            &mariadb(ctx, req, "mariadb-dump").args([
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

        content.create_dir(&saved_dir).map_err(Error::Io)?;
        content.set_mode(&saved_dir, 0o700).map_err(Error::Io)?;
        if target_exists {
            content.rename(relative, &saved_files).map_err(Error::Io)?;
            moved_files = true;
        }
        content.create_dir(relative).map_err(Error::Io)?;
        created_target = true;
        let dest = content.open_managed_dir(relative).map_err(Error::Io)?;
        summary = tar_extract::extract(
            GzDecoder::new(io::BufReader::new(files)),
            &dest,
            Limits {
                max_entries: MAX_ENTRIES,
                max_file_bytes: MAX_FILES_BYTES,
            },
        )
        .map_err(Error::Extract)?;

        // A symlinked wp-config.php would let `wp config set` write elsewhere.
        if !fs::symlink_metadata(absolute.join("wp-config.php"))
            .map_err(|_| Error::UnsafeTarget)?
            .is_file()
        {
            return Err(Error::UnsafeTarget);
        }
        repair_tree(&absolute, req.dest_uid, req.dest_gid, &[]).map_err(Error::Io)?;
        for (key, value) in [
            ("DB_NAME", req.db_name.as_str()),
            ("DB_USER", req.db_user.as_str()),
            ("DB_PASSWORD", req.db_password.as_str()),
            ("DB_HOST", req.db_host.as_str()),
        ] {
            // WP-CLI reads the value from stdin, keeping credentials out of argv.
            critical(process::run_with_stdin_bytes(
                &wp(ctx, req).args(["config", "set", key, "--type=constant", "--prompt"]),
                format!("{value}\n").as_bytes(),
                &step_limits(),
                cancel,
            ))?;
        }

        database_mutated = true; // Even a failed import may have changed tables.
        critical(process::run(
            &ProcessRequest::new(ctx.gunzip_program)
                .args(["-t".to_owned(), db_artifact.to_string_lossy().into_owned()]),
            &step_limits(),
            cancel,
        ))?;
        let (upstream, output) = process::run_piped(
            &ProcessRequest::new(ctx.gunzip_program)
                .args(["-c".to_owned(), db_artifact.to_string_lossy().into_owned()]),
            &mariadb(ctx, req, "mariadb").args([req.db_name.as_str()]),
            &step_limits(),
            cancel,
        )
        .map_err(Error::Run)?;
        if let Some(code) = process::error_code(&upstream) {
            return Err(Error::Rejected(code));
        }
        critical(Ok(output))?;

        if req.source_domain.as_str() != req.dest_domain.as_str() {
            critical(process::run(
                &wp(ctx, req).args([
                    "search-replace",
                    req.source_domain.as_str(),
                    req.dest_domain.as_str(),
                    "--all-tables",
                    "--report-changed-only",
                ]),
                &step_limits(),
                cancel,
            ))?;
        }
        critical(process::run(
            &wp(ctx, req).args(["core", "is-installed"]),
            &step_limits(),
            cancel,
        ))?;
        Ok(())
    })();

    if let Err(error) = work {
        // A cancelled forward operation must still be allowed to recover.
        let recovered_db = !database_mutated
            || restore_snapshot(ctx, req, &recovery_sql, &CancellationToken::default()).is_ok();
        let removed = !created_target || content.remove_dir_all(relative).is_ok();
        let recovered_files = if moved_files && recovered_db && removed {
            content.rename(&saved_files, relative).is_ok()
        } else {
            !moved_files
        };
        if !recovered_db || !removed || !recovered_files {
            return Err(Error::RecoveryRequired);
        }
        let _ = content.remove_dir_all(&saved_dir);
        let _ = ctx.recovery_managed.remove_dir_all(&recovery_dir);
        scope.remove_file(&pending).map_err(Error::Io)?;
        return Err(error);
    }
    Ok(summary)
}

/// Replays the `--add-drop-database` snapshot, which recreates the database
/// exactly as it was (tables the import added are dropped with it).
fn restore_snapshot(
    ctx: &Context<'_>,
    req: &Request,
    snapshot: &SiteRelativePath,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let path = ctx
        .recovery_root
        .resolve_existing(snapshot)
        .map_err(|_| Error::UnsafeTarget)?;
    critical(process::run_with_stdin_file(
        &mariadb(ctx, req, "mariadb"),
        &path,
        &step_limits(),
        cancel,
    ))
}

/// `docker exec -i -e MYSQL_PWD <mariadb> <client> -uroot`, the password only
/// in this process's environment.
fn mariadb(ctx: &Context<'_>, req: &Request, client: &str) -> ProcessRequest {
    ProcessRequest::new(ctx.docker_program)
        .env("MYSQL_PWD", &req.db_root_password)
        .args([
            "exec",
            "-i",
            "-e",
            "MYSQL_PWD",
            req.mariadb_container.as_str(),
            client,
            "-uroot",
        ])
}

fn wp(ctx: &Context<'_>, req: &Request) -> ProcessRequest {
    ProcessRequest::new(ctx.docker_program).args([
        "exec".to_owned(),
        "-i".into(),
        "--user".into(),
        format!("{}:{}", req.dest_uid, req.dest_gid),
        req.dest_container.as_str().into(),
        "wp".into(),
        format!("--path={}", req.dest_root.display()),
        "--skip-plugins".into(),
        "--skip-themes".into(),
    ])
}

fn critical(output: Result<process::ProcessOutput, ProcessRunError>) -> Result<(), Error> {
    let output = output.map_err(Error::Run)?;
    match process::error_code(&output.termination) {
        Some(code) => Err(Error::Rejected(code)),
        None => Ok(()),
    }
}

fn step_limits() -> ProcessLimits {
    ProcessLimits {
        timeout: STEP_TIMEOUT,
        max_stdout_bytes: MAX_STEP_OUTPUT_BYTES,
        max_stderr_bytes: MAX_STEP_OUTPUT_BYTES,
    }
}

/// The recovery marker of one destination root: `pending/<hash of the root>.json`,
/// so a failed restore blocks only imports into that root.
fn pending_marker(dest_root: &Path) -> SiteRelativePath {
    rel(&format!(
        "pending/{}.json",
        resource_lock::canonical_hash(dest_root)
    ))
}

/// Before markers were per root, one `pending.json` guarded the whole scope. A
/// leftover one still blocks the root it names, and every root if it cannot be
/// read; it is never removed here (it is the operator's recovery pointer).
fn legacy_marker_blocks(scope: &ManagedRoot, dest_root: &Path) -> bool {
    let legacy = rel("pending.json");
    if !scope.exists(&legacy) {
        return false;
    }
    scope
        .read_to_string(&legacy)
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|value| value.get("destRoot")?.as_str().map(PathBuf::from))
        .is_none_or(|named| named == dest_root)
}

fn open_scope(engine_state: &ManagedRoot) -> io::Result<ManagedRoot> {
    engine_state.create_dir_all(&rel(SCOPE))?;
    let scope = engine_state.open_managed_dir(&rel(SCOPE))?;
    for child in ["locks", "transactions", "audit"] {
        scope.create_dir_all(&rel(child))?;
    }
    Ok(scope)
}

fn replay(scope: &ManagedRoot, original: RequestId) -> Result<ImportResult, Error> {
    let loaded = state::load(scope, &rel(&format!("transactions/{original}.json")))
        .map_err(|error| Error::Io(io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != OPERATION {
        return Err(Error::Io(io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => loaded
            .outcome
            .and_then(|outcome| outcome.result)
            .ok_or_else(|| Error::Io(io::Error::other("committed outcome has no result")))
            .and_then(|value| {
                serde_json::from_value(value).map_err(|error| Error::Io(io::Error::other(error)))
            }),
        TransactionStatus::Failed => {
            let outcome = loaded
                .outcome
                .expect("a failed transaction always has an outcome");
            Err(Error::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}

fn rel(path: &str) -> SiteRelativePath {
    SiteRelativePath::parse(path).expect("literal path is valid")
}

#[cfg(test)]
mod tests {
    use std::{
        io::Write,
        os::unix::fs::{PermissionsExt, symlink},
        sync::Mutex,
    };

    use flate2::{Compression, write::GzEncoder};

    use super::*;
    use crate::wordpress_migrate_export::ArtifactInfo;

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const OTHER_ID: &str = "123e4567-e89b-12d3-a456-426614174001";
    const ROOT_PW: &str = "root-pw-123";
    const DB_PW: &str = "site-pw-456";

    static SERIAL: Mutex<()> = Mutex::new(());

    struct Fixture {
        _dir: tempfile::TempDir,
        base: PathBuf,
        state: ManagedRoot,
        content: TrustedRoot,
        recovery: ManagedRoot,
        recovery_root: TrustedRoot,
        artifacts: PathBuf,
        docker: String,
        uid: u32,
        gid: u32,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path().canonicalize().unwrap();
            for sub in ["state", "www", "recovery", "staging", "src"] {
                fs::create_dir(base.join(sub)).unwrap();
            }
            let recovery_root = TrustedRoot::parse(base.join("recovery")).unwrap();
            let fixture = Self {
                state: ManagedRoot::open(&TrustedRoot::parse(base.join("state")).unwrap()).unwrap(),
                content: TrustedRoot::parse(base.join("www")).unwrap(),
                recovery: ManagedRoot::open(&recovery_root).unwrap(),
                recovery_root,
                artifacts: base.join("staging"),
                docker: base.join("docker").to_string_lossy().into_owned(),
                uid: unsafe { libc::geteuid() },
                gid: unsafe { libc::getegid() },
                base,
                _dir: dir,
            };
            fixture.fake_docker("");
            fixture
        }

        fn fake_docker(&self, fail_on: &str) {
            let fail = if fail_on.is_empty() {
                String::new()
            } else {
                format!("case \"$*\" in *'{fail_on}'*) cat >/dev/null; exit 1 ;; esac\n")
            };
            let base = self.base.display();
            fs::write(
                &self.docker,
                format!(
                    "#!/bin/sh\necho \"$* pw=${{MYSQL_PWD:-}}\" >> '{base}/calls.log'\n{fail}\
                     case \"$*\" in\n\
                     *mariadb-dump*) echo '-- snapshot of target' ;;\n\
                     *' mariadb -uroot'*) cat >> '{base}/imported.sql' ;;\n\
                     *'config set'*) cat >> '{base}/stdin.log' ;;\n\
                     esac\nexit 0\n"
                ),
            )
            .unwrap();
            fs::set_permissions(&self.docker, fs::Permissions::from_mode(0o755)).unwrap();
        }

        fn ctx(&self) -> Context<'_> {
            Context {
                engine_state: &self.state,
                content_root: &self.content,
                recovery_managed: &self.recovery,
                recovery_root: &self.recovery_root,
                artifact_dir: &self.artifacts,
                artifact_owner_uid: self.uid,
                docker_program: &self.docker,
                gunzip_program: "gunzip",
            }
        }

        fn calls(&self) -> Vec<String> {
            fs::read_to_string(self.base.join("calls.log"))
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect()
        }

        fn site(&self) -> PathBuf {
            self.content.as_path().join("dest.test")
        }

        /// Stages both artifacts for `id` and returns the manifest that
        /// matches them; `tree` adds extra entries to the archived site.
        fn stage(&self, id: &str, tree: impl Fn(&Path)) -> Manifest {
            let src = self.base.join("src").join(id);
            fs::create_dir_all(&src).unwrap();
            fs::write(src.join("wp-config.php"), "<?php // new").unwrap();
            fs::write(src.join("index.php"), "<?php echo 'migrated';").unwrap();
            tree(&src);
            let tar = self.base.join(format!("{id}.tar"));
            assert!(
                std::process::Command::new("tar")
                    .arg("--create")
                    .arg("--file")
                    .arg(&tar)
                    .arg("--directory")
                    .arg(&src)
                    .arg(".")
                    .status()
                    .unwrap()
                    .success()
            );
            let files = gzip(&fs::read(&tar).unwrap());
            let db = gzip(b"CREATE TABLE wp_posts (id int);\n");
            let info = |kind: &str, bytes: &[u8]| {
                let path = artifact_path(&self.artifacts, RequestId::parse(id).unwrap(), kind);
                fs::write(&path, bytes).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                let (len, sha256) = sha256_file(&path).unwrap();
                ArtifactInfo {
                    file: kind.into(),
                    bytes: len,
                    sha256,
                }
            };
            Manifest {
                schema_version: MANIFEST_SCHEMA_VERSION,
                export_id: OTHER_ID.into(),
                source_domain: "source.test".into(),
                database_name: "wp_source".into(),
                table_prefix: "wp_".into(),
                wordpress_version: "6.6.2".into(),
                database: info("db.sql.gz", &db),
                database_uncompressed_bytes: 32,
                files: info("files.tar.gz", &files),
                file_entries: 2,
                file_content_bytes: 40,
                created_at_unix_secs: 0,
            }
        }

        fn request(&self, manifest: &Manifest, id: &str, key: Option<&str>) -> Request {
            let plan = serde_json::json!({
                "manifest": manifest,
                "destContainer": "wcp-runtime-fp1-php83-1",
                "destRoot": self.site(),
                "destUid": self.uid,
                "destGid": self.gid,
                "destDomain": "dest.test",
                "mariadbContainer": "wcp-mariadb-1",
                "dbHost": "mariadb",
                "dbRootPassword": ROOT_PW,
                "dbName": "wp_dest",
                "dbUser": "wp_dest_user",
                "dbPassword": DB_PW,
            });
            Request::parse(&plan.to_string(), id, key).unwrap()
        }

        fn existing_site(&self) {
            fs::create_dir(self.site()).unwrap();
            fs::write(self.site().join("index.php"), "<?php echo 'old';").unwrap();
        }

        fn pending(&self) -> bool {
            self.base
                .join("state")
                .join(SCOPE)
                .join(format!(
                    "{}",
                    pending_marker(&self.site()).as_path().display()
                ))
                .exists()
        }

        fn scope_file(&self, name: &str, contents: &str) {
            let dir = self.base.join("state").join(SCOPE);
            fs::create_dir_all(dir.join(name).parent().unwrap()).unwrap();
            fs::write(dir.join(name), contents).unwrap();
        }

        fn artifacts_left(&self) -> usize {
            fs::read_dir(&self.artifacts).unwrap().count()
        }
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn run(fixture: &Fixture, req: &Request) -> Result<ImportResult, Error> {
        execute(&fixture.ctx(), req, &CancellationToken::default())
    }

    #[test]
    fn migrates_over_an_existing_site_keeping_it_for_recovery() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        fixture.existing_site();
        let manifest = fixture.stage(ID, |_| {});

        let result = run(&fixture, &fixture.request(&manifest, ID, Some("im-1"))).unwrap();
        assert_eq!(result.recovery_id, ID);
        assert_eq!(
            fs::read_to_string(fixture.site().join("index.php")).unwrap(),
            "<?php echo 'migrated';"
        );
        let saved = fixture
            .content
            .as_path()
            .join(format!(".wcp-migrate-{ID}/site/index.php"));
        assert_eq!(fs::read_to_string(saved).unwrap(), "<?php echo 'old';");
        assert!(
            fixture
                .base
                .join(format!("recovery/wordpress-migrate/{ID}/target.sql"))
                .exists()
        );
        assert_eq!(
            fs::read_to_string(fixture.base.join("imported.sql")).unwrap(),
            "CREATE TABLE wp_posts (id int);\n"
        );
        assert!(!fixture.pending());
        assert_eq!(fixture.artifacts_left(), 0, "staged artifacts are removed");

        let calls = fixture.calls();
        let position = |needle: &str| {
            calls
                .iter()
                .position(|c| c.contains(needle))
                .unwrap_or_else(|| panic!("{needle} missing: {calls:?}"))
        };
        assert!(position("mariadb-dump") < position("config set DB_NAME"));
        assert!(position("config set DB_HOST") < position(" mariadb -uroot wp_dest"));
        assert!(
            position(" mariadb -uroot wp_dest") < position("search-replace source.test dest.test")
        );
        assert!(position("search-replace") < position("core is-installed"));
        // Secrets never reach argv.
        for call in &calls {
            let argv = call.split(" pw=").next().unwrap();
            assert!(!argv.contains(ROOT_PW) && !argv.contains(DB_PW), "{call}");
        }
        assert!(
            fs::read_to_string(fixture.base.join("stdin.log"))
                .unwrap()
                .contains(DB_PW)
        );

        // The same key replays the outcome without touching anything again.
        let before = calls.len();
        let replayed = run(&fixture, &fixture.request(&manifest, ID, Some("im-1"))).unwrap();
        assert_eq!(replayed.recovery_id, ID);
        assert_eq!(fixture.calls().len(), before);
    }

    #[test]
    fn a_digest_mismatch_changes_nothing() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        fixture.existing_site();
        let mut manifest = fixture.stage(ID, |_| {});
        manifest.files.sha256 = "0".repeat(64);

        let error = run(&fixture, &fixture.request(&manifest, ID, None)).unwrap_err();
        assert!(matches!(error, Error::ArtifactMismatch));
        assert!(fixture.calls().is_empty());
        assert_eq!(
            fs::read_to_string(fixture.site().join("index.php")).unwrap(),
            "<?php echo 'old';"
        );
        assert_eq!(fixture.artifacts_left(), 0);
        assert!(!fixture.pending());
    }

    #[test]
    fn a_group_readable_artifact_is_refused() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        let manifest = fixture.stage(ID, |_| {});
        let db = artifact_path(
            &fixture.artifacts,
            RequestId::parse(ID).unwrap(),
            "db.sql.gz",
        );
        fs::set_permissions(&db, fs::Permissions::from_mode(0o640)).unwrap();

        let error = run(&fixture, &fixture.request(&manifest, ID, None)).unwrap_err();
        assert!(matches!(error, Error::ArtifactMismatch));
        assert!(fixture.calls().is_empty());
    }

    #[test]
    fn a_failure_after_the_import_restores_the_database_and_the_old_site() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        fixture.existing_site();
        let manifest = fixture.stage(ID, |_| {});
        fixture.fake_docker("search-replace");

        let error = run(&fixture, &fixture.request(&manifest, ID, None)).unwrap_err();
        assert!(matches!(
            error,
            Error::Rejected(ErrorCode::SubprocessFailed)
        ));
        assert_eq!(
            fs::read_to_string(fixture.site().join("index.php")).unwrap(),
            "<?php echo 'old';"
        );
        // The import, then the snapshot replayed over it.
        let imported = fs::read_to_string(fixture.base.join("imported.sql")).unwrap();
        assert!(imported.ends_with("-- snapshot of target\n"), "{imported}");
        assert!(
            !fixture
                .content
                .as_path()
                .join(format!(".wcp-migrate-{ID}"))
                .exists()
        );
        assert!(!fixture.pending());
        assert_eq!(fixture.artifacts_left(), 0);
    }

    #[test]
    fn an_escaping_symlink_in_the_archive_restores_the_old_site() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        fixture.existing_site();
        let manifest = fixture.stage(ID, |src| {
            symlink("../../etc/passwd", src.join("leak")).unwrap()
        });

        let error = run(&fixture, &fixture.request(&manifest, ID, None)).unwrap_err();
        assert!(matches!(error, Error::Extract(ExtractError::Unsafe(_))));
        assert_eq!(
            fs::read_to_string(fixture.site().join("index.php")).unwrap(),
            "<?php echo 'old';"
        );
        assert!(
            !fixture
                .calls()
                .iter()
                .any(|c| c.contains(" mariadb -uroot"))
        );
        assert!(!fixture.pending());
    }

    #[test]
    fn a_failed_restore_leaves_the_recovery_marker() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        fixture.existing_site();
        let manifest = fixture.stage(ID, |_| {});
        // Both the import and the snapshot replay fail.
        fixture.fake_docker(" mariadb -uroot");

        let error = run(&fixture, &fixture.request(&manifest, ID, None)).unwrap_err();
        assert!(matches!(error, Error::RecoveryRequired));
        assert!(fixture.pending());
        assert!(
            fixture
                .base
                .join(format!("recovery/wordpress-migrate/{ID}/target.sql"))
                .exists()
        );
    }

    #[test]
    fn a_failed_restore_of_one_site_does_not_block_another_site() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        fixture.existing_site();
        let other = fixture.content.as_path().join("other.test");
        fixture.scope_file(
            &format!("pending/{}.json", resource_lock::canonical_hash(&other)),
            "{}",
        );
        let manifest = fixture.stage(ID, |_| {});
        run(&fixture, &fixture.request(&manifest, ID, None)).unwrap();
        assert!(!fixture.pending());
    }

    #[test]
    fn a_legacy_scope_marker_blocks_only_the_root_it_names() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        fixture.existing_site();
        let other = fixture.content.as_path().join("other.test");
        fixture.scope_file(
            "pending.json",
            &serde_json::json!({ "destRoot": other }).to_string(),
        );
        let manifest = fixture.stage(ID, |_| {});
        run(&fixture, &fixture.request(&manifest, ID, None)).unwrap();

        let fixture = Fixture::new();
        fixture.existing_site();
        fixture.scope_file(
            "pending.json",
            &serde_json::json!({ "destRoot": fixture.site() }).to_string(),
        );
        let manifest = fixture.stage(ID, |_| {});
        let error = run(&fixture, &fixture.request(&manifest, ID, None)).unwrap_err();
        assert!(matches!(error, Error::RecoveryRequired));
        assert_eq!(
            fs::read_to_string(fixture.site().join("index.php")).unwrap(),
            "<?php echo 'old';"
        );
    }

    #[test]
    fn an_unreadable_legacy_scope_marker_blocks_every_root() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        fixture.existing_site();
        fixture.scope_file("pending.json", "not json");
        let manifest = fixture.stage(ID, |_| {});
        let error = run(&fixture, &fixture.request(&manifest, ID, None)).unwrap_err();
        assert!(matches!(error, Error::RecoveryRequired));
    }

    #[test]
    fn migrates_into_a_new_directory_and_removes_it_on_failure() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        let manifest = fixture.stage(ID, |_| {});
        run(&fixture, &fixture.request(&manifest, ID, None)).unwrap();
        assert!(fixture.site().join("wp-config.php").is_file());

        let fixture = Fixture::new();
        let manifest = fixture.stage(ID, |_| {});
        fixture.fake_docker("core is-installed");
        run(&fixture, &fixture.request(&manifest, ID, None)).unwrap_err();
        assert!(!fixture.site().exists());
        assert!(!fixture.pending());
    }

    #[test]
    fn refuses_a_manifest_over_the_limits_or_a_symlinked_destination() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        let mut manifest = fixture.stage(ID, |_| {});
        manifest.database_uncompressed_bytes = MAX_DUMP_BYTES + 1;
        assert!(matches!(
            run(&fixture, &fixture.request(&manifest, ID, None)),
            Err(Error::ManifestOverLimit)
        ));

        let manifest = fixture.stage(OTHER_ID, |_| {});
        fs::create_dir(fixture.content.as_path().join("real")).unwrap();
        symlink(fixture.content.as_path().join("real"), fixture.site()).unwrap();
        assert!(matches!(
            run(&fixture, &fixture.request(&manifest, OTHER_ID, None)),
            Err(Error::UnsafeTarget)
        ));
        assert!(fixture.calls().is_empty());
    }

    #[test]
    fn a_held_resource_lock_blocks_the_import() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        let manifest = fixture.stage(ID, |_| {});
        let request = fixture.request(&manifest, ID, None);
        let _held = resource_lock::acquire(
            &fixture.state,
            request.dest_root(),
            RequestId::parse(OTHER_ID).unwrap(),
        )
        .unwrap();
        assert!(matches!(run(&fixture, &request), Err(Error::ResourceBusy)));
        assert!(fixture.calls().is_empty());
    }
}
