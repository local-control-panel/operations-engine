//! `wordpress.migrateExport` and `wordpress.migrateDiscard`: the source half
//! of a cross-server WordPress migration (milestone 054, `wp-migrate`
//! design brief).
//!
//! The export never changes the source site. Under the source root's
//! cross-operation resource lock it reads `DB_NAME`, `table_prefix` and the
//! core version through fixed WP-CLI argv as the site's own UID, scans the
//! root, dumps the database with the root password in `MYSQL_PWD` (never
//! argv), archives the root with `tar --hard-dereference`, and writes both
//! artifacts plus a `manifest.json` with their sizes and SHA-256 digests to
//! `state_root/wordpress-migrate/<request id>/` (root-only). The destination
//! engine verifies the artifacts against that manifest before it mutates
//! anything (milestone 055).
//!
//! The scan enforces the brief's confirmed rules before any artifact is
//! written: at most `MAX_FILES_BYTES` of regular-file content and
//! `MAX_ENTRIES` entries; no devices, FIFOs or sockets; symlinks only with a
//! relative target that stays inside the root. The dump is limited to
//! `MAX_DUMP_BYTES` uncompressed.
//!
//! `wordpress.migrateDiscard` removes one export directory. The artifacts
//! hold a full database dump, so the panel discards them as soon as they are
//! transferred, and also after a failed migration.

use std::{
    fs,
    io::{self, Read},
    os::unix::fs::FileTypeExt,
    path::{Component, Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    db_restore::{ContainerName, DatabaseName},
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{self, CancellationToken, ProcessLimits, ProcessRequest, ProcessRunError},
    site::{Domain, SiteRelativePath, TrustedRoot},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        resource_lock,
        state::{self, TransactionStatus},
    },
};

pub const EXPORT_OPERATION: &str = "wordpress.migrateExport";
pub const DISCARD_OPERATION: &str = "wordpress.migrateDiscard";

/// Confirmed limits (brief decision 4).
pub const MAX_FILES_BYTES: u64 = 20 * 1024 * 1024 * 1024;
pub const MAX_DUMP_BYTES: u64 = 10 * 1024 * 1024 * 1024;
pub const MAX_ENTRIES: u64 = 1_000_000;

pub const MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const EXPORTS_DIR: &str = "wordpress-migrate";
pub const DATABASE_FILE: &str = "db.sql.gz";
pub const FILES_FILE: &str = "files.tar.gz";
pub const MANIFEST_FILE: &str = "manifest.json";

const SCOPE: &str = "wordpress-migrate-export";
const MAX_DB_PASSWORD_BYTES: usize = 256;
const STEP_TIMEOUT: Duration = Duration::from_secs(3600);
const MAX_STEP_OUTPUT_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    source_container: String,
    source_root: String,
    source_uid: u32,
    source_gid: u32,
    source_domain: String,
    mariadb_container: String,
    db_root_password: String,
}

pub struct ExportRequest {
    source_container: ContainerName,
    source_root: PathBuf,
    source_uid: u32,
    source_gid: u32,
    source_domain: Domain,
    mariadb_container: ContainerName,
    db_root_password: String,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestError;

impl ExportRequest {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError)?;
        let source_root = PathBuf::from(&plan.source_root);
        if !source_root.is_absolute()
            || plan.source_root.len() > 4096
            || source_root
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
            || plan.source_root.ends_with('/')
        {
            return Err(RequestError);
        }
        if plan.db_root_password.is_empty()
            || plan.db_root_password.len() > MAX_DB_PASSWORD_BYTES
            || plan
                .db_root_password
                .bytes()
                .any(|b| matches!(b, 0 | b'\n' | b'\r'))
        {
            return Err(RequestError);
        }
        Ok(Self {
            source_container: ContainerName::parse(&plan.source_container)
                .map_err(|_| RequestError)?,
            source_root,
            source_uid: plan.source_uid,
            source_gid: plan.source_gid,
            source_domain: Domain::parse(&plan.source_domain).map_err(|_| RequestError)?,
            mariadb_container: ContainerName::parse(&plan.mariadb_container)
                .map_err(|_| RequestError)?,
            db_root_password: plan.db_root_password,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError)?,
        })
    }

    pub fn source_root(&self) -> &Path {
        &self.source_root
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactInfo {
    pub file: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub schema_version: u32,
    pub export_id: String,
    pub source_domain: String,
    pub database_name: String,
    pub table_prefix: String,
    pub wordpress_version: String,
    pub database: ArtifactInfo,
    pub database_uncompressed_bytes: u64,
    pub files: ArtifactInfo,
    pub file_entries: u64,
    pub file_content_bytes: u64,
    pub created_at_unix_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportResult {
    /// Absolute host path of the export directory (root-only).
    pub export_dir: String,
    pub manifest: Manifest,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    /// The state root as a path, for the artifacts' absolute host paths.
    pub state_root: &'a TrustedRoot,
    pub content_root: &'a TrustedRoot,
    pub docker_program: &'a str,
    pub tar_program: &'a str,
    pub gzip_program: &'a str,
}

/// Why the scan refused the source tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnsafeContent {
    SpecialFile(PathBuf),
    SymlinkEscapes(PathBuf),
    TooManyEntries,
    TooLarge,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Run(ProcessRunError),
    Rejected(ErrorCode),
    SourceUnavailable,
    UnsafeContent(UnsafeContent),
    DumpTooLarge,
    ResourceBusy,
    PostCommit(Box<ExportResult>),
    Replayed { code: ErrorCode, message: String },
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
                "a WordPress export step could not run".into(),
            ),
            Self::Rejected(code) => (*code, "a WordPress export step failed".into()),
            Self::SourceUnavailable => (
                ErrorCode::InvalidInput,
                "the WordPress source root is missing, not a directory, or outside the content root"
                    .into(),
            ),
            Self::UnsafeContent(UnsafeContent::SpecialFile(path)) => (
                ErrorCode::InvalidInput,
                format!("the site contains a device, FIFO or socket: {}", path.display()),
            ),
            Self::UnsafeContent(UnsafeContent::SymlinkEscapes(path)) => (
                ErrorCode::InvalidInput,
                format!(
                    "the site contains a symlink that is absolute or leaves the site root: {}",
                    path.display()
                ),
            ),
            Self::UnsafeContent(UnsafeContent::TooManyEntries) => (
                ErrorCode::InvalidInput,
                format!("the site has more than {MAX_ENTRIES} files and directories"),
            ),
            Self::UnsafeContent(UnsafeContent::TooLarge) => (
                ErrorCode::InvalidInput,
                "the site's files exceed the 20 GiB migration limit".into(),
            ),
            Self::DumpTooLarge => (
                ErrorCode::InvalidInput,
                "the database dump exceeds the 10 GiB migration limit".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit(_) => {
                (ErrorCode::Internal, "internal WordPress export error".into())
            }
        }
    }
}

pub fn export(
    ctx: &Context<'_>,
    req: &ExportRequest,
    cancel: &CancellationToken,
) -> Result<ExportResult, Error> {
    let source = resolve_source(ctx.content_root, &req.source_root)?;
    let _resource_lock = resource_lock::acquire(ctx.engine_state, &req.source_root, req.request_id)
        .map_err(|_| Error::ResourceBusy)?;
    crate::site_archive::sweep_stale_exports(ctx.engine_state, ctx.state_root, SystemTime::now());
    run_admitted(
        ctx.engine_state,
        EXPORT_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        || {
            let export_rel = export_rel(req.request_id);
            let result = export_into(ctx, req, &source, &export_rel, cancel);
            if result.is_err() {
                // Nothing on the source changed; only the partial export goes.
                let _ = ctx.engine_state.remove_dir_all(&export_rel);
            }
            result
        },
    )
}

fn export_into(
    ctx: &Context<'_>,
    req: &ExportRequest,
    source: &Path,
    export_rel: &SiteRelativePath,
    cancel: &CancellationToken,
) -> Result<ExportResult, Error> {
    let (file_entries, file_content_bytes) = scan_tree(source).map_err(|error| match error {
        ScanError::Io(error) => Error::Io(error),
        ScanError::Unsafe(reason) => Error::UnsafeContent(reason),
    })?;

    let database_name = wp_read(
        ctx,
        req,
        &["config", "get", "DB_NAME", "--type=constant"],
        cancel,
    )?;
    let database_name = DatabaseName::parse(&database_name)
        .map_err(|_| Error::SourceUnavailable)?
        .as_str()
        .to_owned();
    let table_prefix = wp_read(
        ctx,
        req,
        &["config", "get", "table_prefix", "--type=variable"],
        cancel,
    )?;
    let wordpress_version = wp_read(ctx, req, &["core", "version"], cancel)?;

    ctx.engine_state
        .create_dir_all(export_rel)
        .map_err(Error::Io)?;
    ctx.engine_state
        .set_mode(export_rel, 0o700)
        .map_err(Error::Io)?;
    let export_dir = ctx.state_root.join(export_rel);

    // Database: dump to a 0600 file, check the uncompressed size, gzip it.
    let dump_rel = child(export_rel, "db.sql");
    let dump_file = ctx
        .engine_state
        .create_new_file(&dump_rel)
        .map_err(Error::Io)?;
    ctx.engine_state
        .set_mode(&dump_rel, 0o600)
        .map_err(Error::Io)?;
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
                &database_name,
            ]),
        dump_file,
        &step_limits(),
        cancel,
    ))?;
    let database_uncompressed_bytes = fs::metadata(export_dir.join("db.sql"))
        .map_err(Error::Io)?
        .len();
    if database_uncompressed_bytes > MAX_DUMP_BYTES {
        return Err(Error::DumpTooLarge);
    }
    critical(process::run(
        &ProcessRequest::new(ctx.gzip_program).args([
            "-n".to_owned(),
            export_dir.join("db.sql").to_string_lossy().into_owned(),
        ]),
        &step_limits(),
        cancel,
    ))?;

    // Files: hardlinks become regular files so the destination never has to
    // accept a hardlink entry.
    let files_path = export_dir.join(FILES_FILE);
    let files_file = ctx
        .engine_state
        .create_new_file(&child(export_rel, FILES_FILE))
        .map_err(Error::Io)?;
    drop(files_file);
    ctx.engine_state
        .set_mode(&child(export_rel, FILES_FILE), 0o600)
        .map_err(Error::Io)?;
    critical(process::run(
        &ProcessRequest::new(ctx.tar_program).args([
            "--create".to_owned(),
            "--gzip".into(),
            "--file".into(),
            files_path.to_string_lossy().into_owned(),
            "--hard-dereference".into(),
            "--numeric-owner".into(),
            "--directory".into(),
            source.to_string_lossy().into_owned(),
            ".".into(),
        ]),
        &step_limits(),
        cancel,
    ))?;

    let database = artifact_info(&export_dir, DATABASE_FILE)?;
    let files = artifact_info(&export_dir, FILES_FILE)?;
    ctx.engine_state
        .set_mode(&child(export_rel, DATABASE_FILE), 0o600)
        .map_err(Error::Io)?;
    let manifest = Manifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        export_id: req.request_id.to_string(),
        source_domain: req.source_domain.as_str().to_owned(),
        database_name,
        table_prefix,
        wordpress_version,
        database,
        database_uncompressed_bytes,
        files,
        file_entries,
        file_content_bytes,
        created_at_unix_secs: unix_now_secs(),
    };
    let encoded = serde_json::to_vec_pretty(&manifest).expect("a manifest always serializes");
    ctx.engine_state
        .create_new(&child(export_rel, MANIFEST_FILE), &encoded)
        .map_err(Error::Io)?;
    ctx.engine_state
        .set_mode(&child(export_rel, MANIFEST_FILE), 0o600)
        .map_err(Error::Io)?;
    Ok(ExportResult {
        export_dir: export_dir.to_string_lossy().into_owned(),
        manifest,
    })
}

pub struct DiscardRequest {
    pub export_id: RequestId,
    pub request_id: RequestId,
}

impl DiscardRequest {
    pub fn parse(export_id: &str, request_id: &str) -> Result<Self, RequestError> {
        Ok(Self {
            export_id: RequestId::parse(export_id).map_err(|_| RequestError)?,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError)?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscardResult {
    pub export_id: String,
    /// `false` when the export directory was already gone.
    pub removed: bool,
}

/// Removes one export directory. A missing directory is a no-op.
pub fn discard(engine_state: &ManagedRoot, req: &DiscardRequest) -> Result<DiscardResult, Error> {
    run_admitted(
        engine_state,
        DISCARD_OPERATION,
        req.request_id,
        None,
        || {
            let rel = export_rel(req.export_id);
            let removed = match engine_state.remove_dir_all(&rel) {
                Ok(()) => true,
                Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                Err(error) => return Err(Error::Io(error)),
            };
            Ok(DiscardResult {
                export_id: req.export_id.to_string(),
                removed,
            })
        },
    )
}

/// The source root as a canonical, real directory inside the content root.
pub(crate) fn resolve_source(
    content_root: &TrustedRoot,
    source_root: &Path,
) -> Result<PathBuf, Error> {
    let relative = source_root
        .strip_prefix(content_root.as_path())
        .ok()
        .filter(|value| !value.as_os_str().is_empty())
        .and_then(|value| SiteRelativePath::parse(value).ok())
        .ok_or(Error::SourceUnavailable)?;
    let resolved = content_root
        .resolve_existing(&relative)
        .map_err(|_| Error::SourceUnavailable)?;
    let canonical_root = content_root
        .as_path()
        .canonicalize()
        .map_err(|_| Error::SourceUnavailable)?;
    // A symlink anywhere on the way would make the resolved path differ from
    // the literal one.
    if resolved != canonical_root.join(relative.as_path())
        || !fs::symlink_metadata(&resolved)
            .map_err(|_| Error::SourceUnavailable)?
            .is_dir()
    {
        return Err(Error::SourceUnavailable);
    }
    Ok(resolved)
}

pub(crate) enum ScanError {
    Io(io::Error),
    Unsafe(UnsafeContent),
}

/// Walks `root` without following symlinks and returns the number of
/// entries and the total regular-file bytes, or the first rule it breaks.
pub(crate) fn scan_tree(root: &Path) -> Result<(u64, u64), ScanError> {
    let mut entries = 0u64;
    let mut bytes = 0u64;
    let mut stack = vec![PathBuf::new()];
    while let Some(relative) = stack.pop() {
        let dir = root.join(&relative);
        for entry in fs::read_dir(&dir).map_err(ScanError::Io)? {
            let entry = entry.map_err(ScanError::Io)?;
            entries += 1;
            if entries > MAX_ENTRIES {
                return Err(ScanError::Unsafe(UnsafeContent::TooManyEntries));
            }
            let path = relative.join(entry.file_name());
            let file_type = entry.file_type().map_err(ScanError::Io)?;
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                bytes += entry.metadata().map_err(ScanError::Io)?.len();
                if bytes > MAX_FILES_BYTES {
                    return Err(ScanError::Unsafe(UnsafeContent::TooLarge));
                }
            } else if file_type.is_symlink() {
                let target = fs::read_link(root.join(&path)).map_err(ScanError::Io)?;
                if !symlink_stays_inside(&path, &target) {
                    return Err(ScanError::Unsafe(UnsafeContent::SymlinkEscapes(path)));
                }
            } else if file_type.is_block_device()
                || file_type.is_char_device()
                || file_type.is_fifo()
                || file_type.is_socket()
            {
                return Err(ScanError::Unsafe(UnsafeContent::SpecialFile(path)));
            }
        }
    }
    Ok((entries, bytes))
}

/// Whether a symlink at root-relative `link` with target `target` resolves,
/// lexically, to a path inside the root. Absolute targets never do.
pub fn symlink_stays_inside(link: &Path, target: &Path) -> bool {
    if target.is_absolute() {
        return false;
    }
    let mut depth: Vec<&std::ffi::OsStr> = link
        .parent()
        .map(|parent| {
            parent
                .components()
                .filter_map(|c| match c {
                    Component::Normal(name) => Some(name),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    for component in target.components() {
        match component {
            Component::Normal(name) => depth.push(name),
            Component::CurDir => {}
            Component::ParentDir => {
                if depth.pop().is_none() {
                    return false;
                }
            }
            Component::RootDir | Component::Prefix(_) => return false,
        }
    }
    true
}

pub(crate) fn artifact_info(export_dir: &Path, file: &str) -> Result<ArtifactInfo, Error> {
    let (bytes, sha256) = sha256_file(&export_dir.join(file)).map_err(Error::Io)?;
    Ok(ArtifactInfo {
        file: file.to_owned(),
        bytes,
        sha256,
    })
}

pub fn sha256_file(path: &Path) -> io::Result<(u64, String)> {
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut total = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        total += read as u64;
    }
    let mut hex = String::with_capacity(64);
    for byte in digest.finalize() {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    Ok((total, hex))
}

fn wp_read(
    ctx: &Context<'_>,
    req: &ExportRequest,
    args: &[&str],
    cancel: &CancellationToken,
) -> Result<String, Error> {
    let output = process::run(
        &ProcessRequest::new(ctx.docker_program)
            .args([
                "exec".to_owned(),
                "-i".into(),
                "--user".into(),
                format!("{}:{}", req.source_uid, req.source_gid),
                req.source_container.as_str().into(),
                "wp".into(),
                format!("--path={}", req.source_root.display()),
                "--skip-plugins".into(),
                "--skip-themes".into(),
            ])
            .args(args.iter().copied()),
        &step_limits(),
        cancel,
    )
    .map_err(Error::Run)?;
    if let Some(code) = process::error_code(&output.termination) {
        return Err(Error::Rejected(code));
    }
    if output.stdout.truncated {
        return Err(Error::SourceUnavailable);
    }
    let value = String::from_utf8(output.stdout.bytes).map_err(|_| Error::SourceUnavailable)?;
    let value = value.trim();
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(Error::SourceUnavailable);
    }
    Ok(value.to_owned())
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

pub fn export_rel(export_id: RequestId) -> SiteRelativePath {
    SiteRelativePath::parse(format!("{EXPORTS_DIR}/{export_id}"))
        .expect("a canonical UUID forms a valid path")
}

fn child(dir: &SiteRelativePath, name: &str) -> SiteRelativePath {
    SiteRelativePath::parse(dir.as_path().join(name)).expect("a fixed file name forms a valid path")
}

fn run_admitted<T, F>(
    engine_state: &ManagedRoot,
    operation: &'static str,
    request_id: RequestId,
    key: Option<&IdempotencyKey>,
    body: F,
) -> Result<T, Error>
where
    T: Serialize + for<'de> Deserialize<'de>,
    F: FnOnce() -> Result<T, Error>,
{
    let scope = open_scope(engine_state).map_err(Error::Io)?;
    let admitted =
        match preflight::run(&scope, request_id, key, operation).map_err(Error::Preflight)? {
            preflight::Outcome::Replay(original) => return replay(&scope, operation, original),
            preflight::Outcome::Proceed(admitted) => admitted,
        };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path = rel(&format!("transactions/{request_id}.json"));
    let audit_path = rel("audit/events.jsonl");

    let value = match body() {
        Ok(value) => value,
        Err(error) => {
            let (code, message) = error.protocol();
            let _ = state.mark_failed(code, message);
            let _ = state::save(&scope, &state_path, &state);
            let _ = audit::append(
                &scope,
                &audit_path,
                &AuditRecord::result(request_id, false, Some(code)),
            );
            return Err(error);
        }
    };
    let encoded = serde_json::to_value(&value).expect("operation results always serialize");
    state
        .mark_committed(encoded.clone())
        .expect("state is always InProgress at this point");
    if state::save(&scope, &state_path, &state).is_err() {
        drop(lock);
        return match serde_json::from_value::<ExportResult>(encoded) {
            Ok(result) => Err(Error::PostCommit(Box::new(result))),
            Err(_) => Ok(value),
        };
    }
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(request_id, true, None),
    );
    drop(lock);
    Ok(value)
}

fn open_scope(engine_state: &ManagedRoot) -> io::Result<ManagedRoot> {
    engine_state.create_dir_all(&rel(SCOPE))?;
    let scope = engine_state.open_managed_dir(&rel(SCOPE))?;
    for child in ["locks", "transactions", "audit"] {
        scope.create_dir_all(&rel(child))?;
    }
    Ok(scope)
}

fn replay<T>(scope: &ManagedRoot, operation: &'static str, original: RequestId) -> Result<T, Error>
where
    T: for<'de> Deserialize<'de>,
{
    let loaded = state::load(scope, &rel(&format!("transactions/{original}.json")))
        .map_err(|error| Error::Io(io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != operation {
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

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::{os::unix::fs::PermissionsExt, os::unix::fs::symlink, sync::Mutex};

    use super::*;

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const OTHER_ID: &str = "123e4567-e89b-12d3-a456-426614174001";
    const PASSWORD: &str = "s3cret-root-pw";

    /// Fork-heavy fixture tests; serialize like the other engine modules.
    static SERIAL: Mutex<()> = Mutex::new(());

    struct Fixture {
        _dir: tempfile::TempDir,
        base: PathBuf,
        state: ManagedRoot,
        state_root: TrustedRoot,
        content: TrustedRoot,
        docker: String,
        tar: String,
        calls: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path().canonicalize().unwrap();
            for sub in ["state", "www", "www/site.test"] {
                fs::create_dir(base.join(sub)).unwrap();
            }
            fs::write(base.join("www/site.test/index.php"), "<?php echo 1;").unwrap();
            let calls = base.join("calls.log");
            let fixture = Self {
                state: ManagedRoot::open(&TrustedRoot::parse(base.join("state")).unwrap()).unwrap(),
                state_root: TrustedRoot::parse(base.join("state")).unwrap(),
                content: TrustedRoot::parse(base.join("www")).unwrap(),
                docker: base.join("docker").to_string_lossy().into_owned(),
                tar: base.join("tar").to_string_lossy().into_owned(),
                calls,
                base,
                _dir: dir,
            };
            fixture.fake_docker("");
            fixture.script(
                &fixture.tar,
                "while [ $# -gt 0 ]; do [ \"$1\" = --file ] && printf TARBYTES > \"$2\"; shift; done",
            );
            fixture
        }

        fn script(&self, path: &str, body: &str) {
            fs::write(
                path,
                format!(
                    "#!/bin/sh\necho \"$(basename $0) $* pw=${{MYSQL_PWD:-}}\" >> '{}'\n{body}\n",
                    self.calls.display()
                ),
            )
            .unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }

        /// A fake docker answering the three WP-CLI reads and the dump;
        /// `fail_on` makes any call containing it exit 1.
        fn fake_docker(&self, fail_on: &str) {
            let fail = if fail_on.is_empty() {
                String::new()
            } else {
                format!("case \"$*\" in *'{fail_on}'*) exit 1 ;; esac\n")
            };
            self.script(
                &self.docker,
                &format!(
                    "{fail}case \"$*\" in\n\
                     *DB_NAME*) echo wp_site ;;\n\
                     *table_prefix*) echo wp_ ;;\n\
                     *'core version'*) echo 6.6.2 ;;\n\
                     *mariadb-dump*) echo '-- dump'; echo 'CREATE TABLE t (id int);' ;;\n\
                     esac\nexit 0"
                ),
            );
        }

        fn ctx(&self) -> Context<'_> {
            Context {
                engine_state: &self.state,
                state_root: &self.state_root,
                content_root: &self.content,
                docker_program: &self.docker,
                tar_program: &self.tar,
                gzip_program: "gzip",
            }
        }

        fn calls(&self) -> Vec<String> {
            fs::read_to_string(&self.calls)
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect()
        }

        fn request(&self, id: &str, key: Option<&str>) -> ExportRequest {
            self.request_for("site.test", id, key)
        }

        fn request_for(&self, dir: &str, id: &str, key: Option<&str>) -> ExportRequest {
            let plan = serde_json::json!({
                "sourceContainer": "wcp-runtime-fp1-php83-1",
                "sourceRoot": self.content.as_path().join(dir),
                "sourceUid": 10001,
                "sourceGid": 10001,
                "sourceDomain": "site.test",
                "mariadbContainer": "wcp-mariadb-1",
                "dbRootPassword": PASSWORD,
            });
            ExportRequest::parse(&plan.to_string(), id, key).unwrap()
        }

        fn export_dir(&self, id: &str) -> PathBuf {
            self.base.join("state").join(EXPORTS_DIR).join(id)
        }
    }

    #[test]
    fn exports_both_artifacts_with_a_matching_manifest_and_replays() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();

        let result = export(
            &fixture.ctx(),
            &fixture.request(ID, Some("ex-1")),
            &CancellationToken::default(),
        )
        .unwrap();
        let dir = fixture.export_dir(ID);
        assert_eq!(result.export_dir, dir.to_string_lossy());
        let manifest = &result.manifest;
        assert_eq!(manifest.database_name, "wp_site");
        assert_eq!(manifest.table_prefix, "wp_");
        assert_eq!(manifest.wordpress_version, "6.6.2");
        assert_eq!(manifest.source_domain, "site.test");
        assert_eq!(manifest.file_entries, 1);
        assert_eq!(manifest.file_content_bytes, 13);
        for artifact in [&manifest.database, &manifest.files] {
            let (bytes, sha) = sha256_file(&dir.join(&artifact.file)).unwrap();
            assert_eq!(
                (bytes, sha.as_str()),
                (artifact.bytes, artifact.sha256.as_str())
            );
        }
        assert!(
            !dir.join("db.sql").exists(),
            "the uncompressed dump is gone"
        );
        let on_disk: Manifest =
            serde_json::from_slice(&fs::read(dir.join(MANIFEST_FILE)).unwrap()).unwrap();
        assert_eq!(&on_disk, manifest);
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for file in [DATABASE_FILE, FILES_FILE, MANIFEST_FILE] {
            assert_eq!(
                fs::metadata(dir.join(file)).unwrap().permissions().mode() & 0o777,
                0o600,
                "{file}"
            );
        }

        // The root password reaches the dump only through the environment.
        let calls = fixture.calls();
        assert!(
            calls
                .iter()
                .all(|call| !call.split(" pw=").next().unwrap().contains(PASSWORD))
        );
        assert!(
            calls
                .iter()
                .any(|c| c.contains("mariadb-dump") && c.ends_with(&format!("pw={PASSWORD}")))
        );
        assert!(calls.iter().any(|c| c.contains("--hard-dereference")));
        assert!(calls.iter().any(|c| c.contains("--user 10001:10001")));

        // Same key: the committed manifest comes back without a second run.
        let before = fixture.calls().len();
        let replayed = export(
            &fixture.ctx(),
            &fixture.request(ID, Some("ex-1")),
            &CancellationToken::default(),
        )
        .unwrap();
        assert_eq!(replayed.manifest, result.manifest);
        assert_eq!(fixture.calls().len(), before);
    }

    #[test]
    fn a_symlink_leaving_the_root_stops_the_export_before_any_step() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        symlink(
            "../../etc/passwd",
            fixture.content.as_path().join("site.test/leak"),
        )
        .unwrap();

        let error = export(
            &fixture.ctx(),
            &fixture.request(ID, None),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            Error::UnsafeContent(UnsafeContent::SymlinkEscapes(_))
        ));
        assert!(fixture.calls().is_empty());
        assert!(!fixture.export_dir(ID).exists());
    }

    #[test]
    fn relative_symlinks_inside_the_root_are_exported() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        let root = fixture.content.as_path().join("site.test");
        fs::create_dir(root.join("shared")).unwrap();
        symlink("../index.php", root.join("shared/index-link.php")).unwrap();

        let result = export(
            &fixture.ctx(),
            &fixture.request(ID, None),
            &CancellationToken::default(),
        )
        .unwrap();
        assert_eq!(result.manifest.file_entries, 3);
    }

    #[test]
    fn a_fifo_in_the_root_is_refused() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        let fifo = fixture.content.as_path().join("site.test/pipe");
        let path = std::ffi::CString::new(fifo.to_string_lossy().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);

        let error = export(
            &fixture.ctx(),
            &fixture.request(ID, None),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            Error::UnsafeContent(UnsafeContent::SpecialFile(_))
        ));
    }

    #[test]
    fn a_failed_dump_removes_the_partial_export() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        fixture.fake_docker("mariadb-dump");

        let error = export(
            &fixture.ctx(),
            &fixture.request(ID, None),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            Error::Rejected(ErrorCode::SubprocessFailed)
        ));
        assert!(!fixture.export_dir(ID).exists());
        assert!(
            fixture
                .content
                .as_path()
                .join("site.test/index.php")
                .exists()
        );
    }

    #[test]
    fn a_source_outside_the_content_root_or_through_a_symlink_is_refused() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        symlink(
            fixture.content.as_path().join("site.test"),
            fixture.content.as_path().join("alias.test"),
        )
        .unwrap();
        for dir in ["alias.test", "missing.test"] {
            let error = export(
                &fixture.ctx(),
                &fixture.request_for(dir, ID, None),
                &CancellationToken::default(),
            )
            .unwrap_err();
            assert!(matches!(error, Error::SourceUnavailable), "{dir}");
        }
        assert!(fixture.calls().is_empty());
    }

    #[test]
    fn a_held_resource_lock_blocks_the_export() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        let request = fixture.request(ID, None);
        let _held = resource_lock::acquire(
            &fixture.state,
            request.source_root(),
            RequestId::parse(OTHER_ID).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            export(&fixture.ctx(), &request, &CancellationToken::default()),
            Err(Error::ResourceBusy)
        ));
        assert!(fixture.calls().is_empty());
    }

    #[test]
    fn discard_removes_an_export_once() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = Fixture::new();
        export(
            &fixture.ctx(),
            &fixture.request(ID, None),
            &CancellationToken::default(),
        )
        .unwrap();

        let first = discard(
            &fixture.state,
            &DiscardRequest::parse(ID, OTHER_ID).unwrap(),
        )
        .unwrap();
        assert!(first.removed);
        assert!(!fixture.export_dir(ID).exists());
        let second = discard(
            &fixture.state,
            &DiscardRequest::parse(ID, "123e4567-e89b-12d3-a456-426614174002").unwrap(),
        )
        .unwrap();
        assert!(!second.removed);
    }

    #[test]
    fn symlink_targets_are_judged_lexically_from_the_link() {
        let inside = [
            ("a/link", "../b"),
            ("link", "b/c"),
            ("a/b/link", "../../x"),
            ("link", "./x"),
        ];
        for (link, target) in inside {
            assert!(
                symlink_stays_inside(Path::new(link), Path::new(target)),
                "{link} -> {target}"
            );
        }
        let outside = [
            ("link", "../x"),
            ("a/link", "../../x"),
            ("link", "/etc/passwd"),
            ("a/link", "b/../../../x"),
        ];
        for (link, target) in outside {
            assert!(
                !symlink_stays_inside(Path::new(link), Path::new(target)),
                "{link} -> {target}"
            );
        }
    }

    #[test]
    fn rejects_malformed_plans() {
        let good = serde_json::json!({
            "sourceContainer": "c", "sourceRoot": "/var/www/site.test", "sourceUid": 1,
            "sourceGid": 1, "sourceDomain": "site.test", "mariadbContainer": "m",
            "dbRootPassword": "pw",
        });
        assert!(ExportRequest::parse(&good.to_string(), ID, None).is_ok());
        for (field, value) in [
            ("sourceRoot", serde_json::json!("relative/path")),
            ("sourceRoot", serde_json::json!("/var/www/../etc")),
            ("sourceDomain", serde_json::json!("../x")),
            ("dbRootPassword", serde_json::json!("")),
            ("dbRootPassword", serde_json::json!("a\nb")),
        ] {
            let mut plan = good.clone();
            plan[field] = value;
            assert!(
                ExportRequest::parse(&plan.to_string(), ID, None).is_err(),
                "{field}"
            );
        }
        assert!(ExportRequest::parse(&good.to_string(), "nope", None).is_err());
    }
}
