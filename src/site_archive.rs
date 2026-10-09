//! `site.exportArchive` and `site.discardArchive`: the source half of a
//! server-to-server site sync (W2-11, `sync-relay` design brief). The
//! destination half is [`import`].
//!
//! The export never changes the source site. Under the source root's
//! cross-operation resource lock it scans the root, refuses anything the
//! destination's bounded extractor would refuse (devices, FIFOs, sockets,
//! absolute or escaping symlinks, more than `MAX_ENTRIES` entries or
//! `MAX_FILES_BYTES` of content), checks that the state root has room for the
//! archive, archives the root with `tar --hard-dereference`, and writes the
//! archive plus a `manifest.json` with its size and SHA-256 to
//! `state_root/site-sync/<request id>/` (root-only). The archive holds the
//! site's configuration files, so the panel discards it as soon as it has
//! been transferred, and also after a failed sync.
//!
//! `site.discardArchive` removes one export directory (`--kind export`), the
//! previous-state snapshot a destination keeps after an import
//! (`--kind snapshot`), or every export of either kind that has outlived
//! `STALE_AFTER` (`--kind stale`). Both exports also sweep stale exports
//! before they write a new one, so a panel that died mid-sync cannot leave a
//! copy of a site (or a database dump) behind forever.

use std::{
    io,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{self, CancellationToken, ProcessLimits, ProcessRequest, ProcessRunError},
    site::{SiteRelativePath, TrustedRoot},
    tar_extract::ExtractError,
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        resource_lock,
        state::{self, TransactionStatus},
    },
    wordpress_migrate_export::{
        ArtifactInfo, MAX_ENTRIES, MAX_FILES_BYTES, ScanError, UnsafeContent, artifact_info,
        resolve_source, scan_tree,
    },
};

#[cfg(unix)]
pub mod import;

pub const EXPORT_OPERATION: &str = "site.exportArchive";
pub const DISCARD_OPERATION: &str = "site.discardArchive";

pub const MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const EXPORTS_DIR: &str = "site-sync";
pub const ARCHIVE_FILE: &str = "site.tar.gz";
pub const MANIFEST_FILE: &str = "manifest.json";
/// Directory (directly under a content root) that holds the previous state of
/// a destination root after an import: `.wcp-sync-<import id>/site`.
pub const SNAPSHOT_PREFIX: &str = ".wcp-sync-";

/// An export older than this is nobody's: the panel's longest step times out
/// after an hour. Used by [`sweep_stale_exports`].
pub const STALE_AFTER: Duration = Duration::from_secs(24 * 60 * 60);

const EXPORT_SCOPE: &str = "site-archive-export";
const DISCARD_SCOPE: &str = "site-archive-discard";
const STEP_TIMEOUT: Duration = Duration::from_secs(3600);
const MAX_STEP_OUTPUT_BYTES: usize = 64 * 1024;
/// The archive can be a little larger than the content it holds (tar headers,
/// incompressible data), and the filesystem needs some slack.
const SPACE_HEADROOM_NUM: u64 = 1;
const SPACE_HEADROOM_DEN: u64 = 16;
const SPACE_HEADROOM_FIXED: u64 = 64 * 1024 * 1024;

/// The source manifest, relayed unchanged to the destination.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    pub export_id: String,
    pub archive: ArtifactInfo,
    /// Entries (files, directories, symlinks) below the root.
    pub entries: u64,
    /// Bytes of regular-file content, before compression.
    pub content_bytes: u64,
    pub created_at_unix_secs: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExportPlan {
    source_root: String,
}

pub struct ExportRequest {
    source_root: PathBuf,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestError;

pub(crate) fn absolute_root(value: &str) -> Result<PathBuf, RequestError> {
    let path = PathBuf::from(value);
    if !path.is_absolute()
        || value.len() > 4096
        || value.ends_with('/')
        || path.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(RequestError);
    }
    Ok(path)
}

pub(crate) fn ids(
    request_id: &str,
    key: Option<&str>,
) -> Result<(RequestId, Option<IdempotencyKey>), RequestError> {
    Ok((
        RequestId::parse(request_id).map_err(|_| RequestError)?,
        key.map(IdempotencyKey::parse)
            .transpose()
            .map_err(|_| RequestError)?,
    ))
}

impl ExportRequest {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: ExportPlan = serde_json::from_str(json).map_err(|_| RequestError)?;
        let (request_id, idempotency_key) = ids(request_id, key)?;
        Ok(Self {
            source_root: absolute_root(&plan.source_root)?,
            request_id,
            idempotency_key,
        })
    }

    pub fn source_root(&self) -> &Path {
        &self.source_root
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportResult {
    pub export_id: String,
    pub manifest: Manifest,
    /// Absolute host path of the archive, for the panel's relay.
    pub archive_path: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscardKind {
    Export,
    Snapshot,
    /// Every export (site archives and WordPress migrations) past `STALE_AFTER`.
    Stale,
}

pub struct DiscardRequest {
    pub kind: DiscardKind,
    /// Required for `export` and `snapshot`, forbidden for `stale`.
    pub archive_id: Option<RequestId>,
    pub request_id: RequestId,
}

impl DiscardRequest {
    pub fn parse(
        kind: &str,
        archive_id: Option<&str>,
        request_id: &str,
    ) -> Result<Self, RequestError> {
        let kind = match kind {
            "export" => DiscardKind::Export,
            "snapshot" => DiscardKind::Snapshot,
            "stale" => DiscardKind::Stale,
            _ => return Err(RequestError),
        };
        let archive_id = match (kind, archive_id) {
            (DiscardKind::Stale, None) => None,
            (DiscardKind::Stale, Some(_)) | (_, None) => return Err(RequestError),
            (_, Some(id)) => Some(RequestId::parse(id).map_err(|_| RequestError)?),
        };
        Ok(Self {
            kind,
            archive_id,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError)?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscardResult {
    /// Absent for `stale`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_id: Option<String>,
    /// `false` when there was nothing left to remove.
    pub removed: bool,
    /// How many directories went (1 or 0, except for `stale`).
    #[serde(default)]
    pub removed_count: u32,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub state_root: &'a TrustedRoot,
    pub content_root: &'a TrustedRoot,
    pub tar_program: &'a str,
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
    InsufficientSpace,
    ResourceBusy,
    /// An artifact is missing, not root-owned `0600` with one link, or does
    /// not match the manifest's size and SHA-256.
    ArtifactMismatch,
    ManifestOverLimit,
    UnsafeTarget,
    /// The destination root is on another filesystem than the content root,
    /// where the snapshot of the previous state has to go (a rename).
    OtherFilesystem,
    Extract(ExtractError),
    RecoveryRequired,
    /// The operation committed but its record could not be saved; the result
    /// is still good.
    PostCommit(serde_json::Value),
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
                "another operation is already in progress for this site".into(),
            ),
            Self::Run(error) => (
                process::spawn_error_code(error),
                "a site archive step could not run".into(),
            ),
            Self::Rejected(code) => (*code, "a site archive step failed".into()),
            Self::SourceUnavailable => (
                ErrorCode::InvalidInput,
                "the site root is missing, not a directory, or outside the content root".into(),
            ),
            Self::UnsafeContent(UnsafeContent::SpecialFile(path)) => (
                ErrorCode::InvalidInput,
                format!(
                    "the site contains a device, FIFO or socket: {}",
                    path.display()
                ),
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
                "the site's files exceed the 20 GiB sync limit".into(),
            ),
            Self::InsufficientSpace => (
                ErrorCode::InvalidInput,
                "there is not enough free disk space for the site archive".into(),
            ),
            Self::ArtifactMismatch => (
                ErrorCode::InvalidInput,
                "the site archive is missing, unsafe, or does not match the manifest".into(),
            ),
            Self::ManifestOverLimit => (
                ErrorCode::InvalidInput,
                "the site exceeds the 20 GiB / 1M entries sync limits".into(),
            ),
            Self::UnsafeTarget => (
                ErrorCode::InvalidInput,
                "the destination root is outside the content root, a symlink, a mount point \
                 or not an existing directory"
                    .into(),
            ),
            Self::OtherFilesystem => (
                ErrorCode::InvalidInput,
                "the destination root is on a different filesystem than the content root; \
                 the previous state is kept beside the content root, so a sync cannot replace it"
                    .into(),
            ),
            Self::Extract(ExtractError::Io(error))
                if error.raw_os_error() == Some(libc::ENOSPC) =>
            {
                (
                    ErrorCode::InvalidInput,
                    "the destination ran out of disk space while the archive was extracted; \
                 the destination was restored"
                        .into(),
                )
            }
            Self::Extract(ExtractError::Unsafe(name)) => (
                ErrorCode::InvalidInput,
                format!(
                    "the archive contains an entry that is not allowed (hardlink, device, \
                     absolute or escaping path or symlink): {name}; the destination was restored"
                ),
            ),
            Self::Extract(ExtractError::TooManyEntries | ExtractError::TooLarge) => (
                ErrorCode::InvalidInput,
                "the archive exceeds the sync limits; the destination was restored".into(),
            ),
            Self::Extract(_) => (
                ErrorCode::InvalidInput,
                "the site archive is corrupt; the destination was restored".into(),
            ),
            Self::RecoveryRequired => (
                ErrorCode::Conflict,
                "the sync failed and restoring the destination also failed; pending.json and \
                 the .wcp-sync snapshot identify what to repair"
                    .into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit(_) => {
                (ErrorCode::Internal, "internal site archive error".into())
            }
        }
    }
}

pub fn export(
    ctx: &Context<'_>,
    req: &ExportRequest,
    cancel: &CancellationToken,
) -> Result<ExportResult, Error> {
    let source =
        resolve_source(ctx.content_root, &req.source_root).map_err(|_| Error::SourceUnavailable)?;
    let _resource_lock = resource_lock::acquire(ctx.engine_state, &req.source_root, req.request_id)
        .map_err(|_| Error::ResourceBusy)?;
    sweep_stale_exports(ctx.engine_state, ctx.state_root, SystemTime::now());
    run_admitted(
        ctx.engine_state,
        EXPORT_SCOPE,
        EXPORT_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        |_| {
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
    let (entries, content_bytes) = scan_tree(source).map_err(|error| match error {
        ScanError::Io(error) => Error::Io(error),
        ScanError::Unsafe(reason) => Error::UnsafeContent(reason),
    })?;
    ensure_space(ctx.state_root.as_path(), content_bytes)?;

    ctx.engine_state
        .create_dir_all(export_rel)
        .map_err(Error::Io)?;
    ctx.engine_state
        .set_mode(export_rel, 0o700)
        .map_err(Error::Io)?;
    let export_dir = ctx.state_root.join(export_rel);

    // Hardlinks become regular files so the destination never has to accept a
    // hardlink entry.
    let archive_rel = child(export_rel, ARCHIVE_FILE);
    drop(
        ctx.engine_state
            .create_new_file(&archive_rel)
            .map_err(Error::Io)?,
    );
    ctx.engine_state
        .set_mode(&archive_rel, 0o600)
        .map_err(Error::Io)?;
    let archive_path = export_dir.join(ARCHIVE_FILE);
    critical(process::run(
        &ProcessRequest::new(ctx.tar_program).args([
            "--create".to_owned(),
            "--gzip".into(),
            "--file".into(),
            archive_path.to_string_lossy().into_owned(),
            "--hard-dereference".into(),
            "--numeric-owner".into(),
            "--directory".into(),
            source.to_string_lossy().into_owned(),
            ".".into(),
        ]),
        &step_limits(),
        cancel,
    ))?;

    let archive = artifact_info(&export_dir, ARCHIVE_FILE).map_err(|error| match error {
        crate::wordpress_migrate_export::Error::Io(error) => Error::Io(error),
        _ => Error::ArtifactMismatch,
    })?;
    let manifest = Manifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        export_id: req.request_id.to_string(),
        archive,
        entries,
        content_bytes,
        created_at_unix_secs: unix_now_secs(),
    };
    let encoded = serde_json::to_vec_pretty(&manifest).expect("a manifest always serializes");
    let manifest_rel = child(export_rel, MANIFEST_FILE);
    ctx.engine_state
        .create_new(&manifest_rel, &encoded)
        .map_err(Error::Io)?;
    ctx.engine_state
        .set_mode(&manifest_rel, 0o600)
        .map_err(Error::Io)?;
    Ok(ExportResult {
        export_id: req.request_id.to_string(),
        manifest,
        archive_path: archive_path.to_string_lossy().into_owned(),
    })
}

/// Removes one export directory or one snapshot. Missing is a no-op.
pub fn discard(
    engine_state: &ManagedRoot,
    state_root: &TrustedRoot,
    content_roots: &[TrustedRoot],
    req: &DiscardRequest,
) -> Result<DiscardResult, Error> {
    run_admitted(
        engine_state,
        DISCARD_SCOPE,
        DISCARD_OPERATION,
        req.request_id,
        None,
        |_| {
            let id = req.archive_id;
            let count = match (req.kind, id) {
                (DiscardKind::Export, Some(id)) => {
                    u32::from(remove_if_present(engine_state, &export_rel(id))?)
                }
                (DiscardKind::Snapshot, Some(id)) => {
                    let name = snapshot_dir_name(id);
                    let mut count = 0;
                    for root in content_roots {
                        let managed = ManagedRoot::open(root).map_err(Error::Io)?;
                        let rel = SiteRelativePath::parse(&name)
                            .expect("a canonical UUID forms a valid path");
                        count += u32::from(remove_if_present(&managed, &rel)?);
                    }
                    count
                }
                _ => sweep_stale_exports(engine_state, state_root, SystemTime::now()),
            };
            Ok(DiscardResult {
                archive_id: id.map(|id| id.to_string()),
                removed: count > 0,
                removed_count: count,
            })
        },
    )
}

/// Directories whose children are export directories named by a request id.
const EXPORT_PARENTS: [&str; 2] = [EXPORTS_DIR, "wordpress-migrate"];

/// Removes every export directory (`site-sync/<uuid>` and
/// `wordpress-migrate/<uuid>`) whose last change is older than
/// [`STALE_AFTER`]. Best effort: an entry that cannot be inspected or removed
/// is left for the next sweep. Returns how many went.
pub fn sweep_stale_exports(
    engine_state: &ManagedRoot,
    state_root: &TrustedRoot,
    now: SystemTime,
) -> u32 {
    let mut removed = 0;
    for parent in EXPORT_PARENTS {
        let Ok(entries) = std::fs::read_dir(state_root.as_path().join(parent)) else {
            continue;
        };
        for entry in entries.flatten() {
            let Some(id) = entry
                .file_name()
                .to_str()
                .and_then(|name| RequestId::parse(name).ok())
            else {
                continue; // `snapshots/` and anything that is not an export
            };
            let stale = entry
                .metadata()
                .ok()
                .filter(|meta| meta.is_dir())
                .and_then(|meta| meta.modified().ok())
                .and_then(|modified| now.duration_since(modified).ok())
                .is_some_and(|age| age >= STALE_AFTER);
            if !stale {
                continue;
            }
            let Ok(relative) = SiteRelativePath::parse(format!("{parent}/{id}")) else {
                continue;
            };
            if engine_state.remove_dir_all(&relative).is_ok() {
                removed += 1;
            }
        }
    }
    removed
}

fn remove_if_present(root: &ManagedRoot, rel: &SiteRelativePath) -> Result<bool, Error> {
    match root.remove_dir_all(rel) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Error::Io(error)),
    }
}

pub fn snapshot_dir_name(id: RequestId) -> String {
    format!("{SNAPSHOT_PREFIX}{id}")
}

pub fn export_rel(export_id: RequestId) -> SiteRelativePath {
    SiteRelativePath::parse(format!("{EXPORTS_DIR}/{export_id}"))
        .expect("a canonical UUID forms a valid path")
}

/// Refuses before anything is written when the filesystem holding `path` has
/// less free space than `content_bytes` plus headroom.
// The statvfs field widths differ between platforms (u32 on macOS, u64 on Linux).
#[allow(clippy::unnecessary_cast)]
pub(crate) fn ensure_space(path: &Path, content_bytes: u64) -> Result<(), Error> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains a NUL byte",
        ))
    })?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) } != 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }
    let available = (stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64);
    let needed = content_bytes
        .saturating_add(content_bytes / SPACE_HEADROOM_DEN * SPACE_HEADROOM_NUM)
        .saturating_add(SPACE_HEADROOM_FIXED);
    if available < needed {
        return Err(Error::InsufficientSpace);
    }
    Ok(())
}

pub(crate) fn critical(
    output: Result<process::ProcessOutput, ProcessRunError>,
) -> Result<(), Error> {
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

pub(crate) fn child(dir: &SiteRelativePath, name: &str) -> SiteRelativePath {
    SiteRelativePath::parse(dir.as_path().join(name)).expect("a fixed file name forms a valid path")
}

pub(crate) fn rel(path: &str) -> SiteRelativePath {
    SiteRelativePath::parse(path).expect("literal path is valid")
}

pub(crate) fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// The preflight / transaction-record / audit envelope shared by every
/// operation here. `body` gets the operation's scope directory.
pub(crate) fn run_admitted<T, F>(
    engine_state: &ManagedRoot,
    scope_name: &'static str,
    operation: &'static str,
    request_id: RequestId,
    key: Option<&IdempotencyKey>,
    body: F,
) -> Result<T, Error>
where
    T: Serialize + for<'de> Deserialize<'de>,
    F: FnOnce(&ManagedRoot) -> Result<T, Error>,
{
    let scope = open_scope(engine_state, scope_name).map_err(Error::Io)?;
    let admitted =
        match preflight::run(&scope, request_id, key, operation).map_err(Error::Preflight)? {
            preflight::Outcome::Replay(original) => {
                return replay(&scope, operation, original);
            }
            preflight::Outcome::Proceed(admitted) => admitted,
        };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path = rel(&format!("transactions/{request_id}.json"));
    let audit_path = rel("audit/events.jsonl");

    let value = match body(&scope) {
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
        return Err(Error::PostCommit(encoded));
    }
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(request_id, true, None),
    );
    drop(lock);
    Ok(value)
}

fn open_scope(engine_state: &ManagedRoot, scope_name: &str) -> io::Result<ManagedRoot> {
    let scope_rel = rel(scope_name);
    engine_state.create_dir_all(&scope_rel)?;
    let scope = engine_state.open_managed_dir(&scope_rel)?;
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

/// Limits shared with the import: the same confirmed numbers as wp-migrate.
pub(crate) const fn limits() -> (u64, u64) {
    (MAX_ENTRIES, MAX_FILES_BYTES)
}

#[cfg(all(test, unix))]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt, os::unix::fs::symlink};

    use super::*;

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const OTHER_ID: &str = "123e4567-e89b-12d3-a456-426614174001";

    struct Fixture {
        _dir: tempfile::TempDir,
        base: PathBuf,
        state: ManagedRoot,
        state_root: TrustedRoot,
        content: TrustedRoot,
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
                tar: base.join("tar").to_string_lossy().into_owned(),
                calls,
                base,
                _dir: dir,
            };
            fixture.fake_tar("printf TARBYTES > \"$2\"");
            fixture
        }

        /// A fake tar: records its argv and runs `on_file` for the `--file`
        /// argument (`$2` after the shift loop reaches it).
        fn fake_tar(&self, on_file: &str) {
            fs::write(
                &self.tar,
                format!(
                    "#!/bin/sh\necho \"tar $*\" >> '{}'\n\
                     while [ $# -gt 0 ]; do [ \"$1\" = --file ] && {{ {on_file}; }}; shift; done\nexit 0\n",
                    self.calls.display()
                ),
            )
            .unwrap();
            fs::set_permissions(&self.tar, fs::Permissions::from_mode(0o755)).unwrap();
        }

        fn failing_tar(&self) {
            fs::write(&self.tar, "#!/bin/sh\necho partial > \"$3\"\nexit 2\n").unwrap();
            fs::set_permissions(&self.tar, fs::Permissions::from_mode(0o755)).unwrap();
        }

        fn ctx(&self) -> Context<'_> {
            Context {
                engine_state: &self.state,
                state_root: &self.state_root,
                content_root: &self.content,
                tar_program: &self.tar,
            }
        }

        fn tar_calls(&self) -> usize {
            fs::read_to_string(&self.calls)
                .unwrap_or_default()
                .lines()
                .count()
        }

        fn request(&self, dir: &str, id: &str, key: Option<&str>) -> ExportRequest {
            let plan = serde_json::json!({ "sourceRoot": self.content.as_path().join(dir) });
            ExportRequest::parse(&plan.to_string(), id, key).unwrap()
        }

        fn export_dir(&self, id: &str) -> PathBuf {
            self.base.join("state").join(EXPORTS_DIR).join(id)
        }
    }

    fn cancel() -> CancellationToken {
        CancellationToken::default()
    }

    #[test]
    fn export_writes_a_private_archive_and_a_manifest_that_matches_it() {
        let fx = Fixture::new();
        let result = export(&fx.ctx(), &fx.request("site.test", ID, None), &cancel()).unwrap();

        let dir = fx.export_dir(ID);
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for file in [ARCHIVE_FILE, MANIFEST_FILE] {
            let mode = fs::metadata(dir.join(file)).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{file}");
        }
        let (bytes, sha256) =
            crate::wordpress_migrate_export::sha256_file(&dir.join(ARCHIVE_FILE)).unwrap();
        assert_eq!(result.manifest.archive.bytes, bytes);
        assert_eq!(result.manifest.archive.sha256, sha256);
        assert_eq!(result.manifest.archive.file, ARCHIVE_FILE);
        assert_eq!(result.manifest.export_id, ID);
        assert_eq!(result.manifest.entries, 1);
        assert_eq!(result.manifest.content_bytes, 13);
        assert_eq!(
            result.archive_path,
            dir.join(ARCHIVE_FILE).to_string_lossy()
        );
        let on_disk: Manifest =
            serde_json::from_slice(&fs::read(dir.join(MANIFEST_FILE)).unwrap()).unwrap();
        assert_eq!(on_disk, result.manifest);
        // Hardlinks are copied, owners are numeric, and the source is only read.
        let calls = fs::read_to_string(&fx.calls).unwrap();
        assert!(calls.contains("--hard-dereference") && calls.contains("--numeric-owner"));
        assert_eq!(
            fs::read_to_string(fx.content.as_path().join("site.test/index.php")).unwrap(),
            "<?php echo 1;"
        );
    }

    #[test]
    fn a_retry_with_the_same_key_replays_without_a_second_archive() {
        let fx = Fixture::new();
        let first = export(
            &fx.ctx(),
            &fx.request("site.test", ID, Some("key-1")),
            &cancel(),
        )
        .unwrap();
        let second = export(
            &fx.ctx(),
            &fx.request("site.test", OTHER_ID, Some("key-1")),
            &cancel(),
        )
        .unwrap();
        assert_eq!(first.manifest, second.manifest);
        assert_eq!(fx.tar_calls(), 1);
        assert!(!fx.export_dir(OTHER_ID).exists());
    }

    #[test]
    fn a_symlink_that_leaves_the_root_stops_the_export_before_any_artifact() {
        let fx = Fixture::new();
        symlink("/etc/passwd", fx.content.as_path().join("site.test/link")).unwrap();
        let error = export(&fx.ctx(), &fx.request("site.test", ID, None), &cancel()).unwrap_err();
        assert!(matches!(
            error,
            Error::UnsafeContent(UnsafeContent::SymlinkEscapes(_))
        ));
        assert_eq!(fx.tar_calls(), 0);
        assert!(!fx.export_dir(ID).exists());
    }

    #[test]
    fn a_symlink_that_stays_inside_is_archived() {
        let fx = Fixture::new();
        symlink("index.php", fx.content.as_path().join("site.test/alias")).unwrap();
        let result = export(&fx.ctx(), &fx.request("site.test", ID, None), &cancel()).unwrap();
        assert_eq!(result.manifest.entries, 2);
    }

    #[test]
    fn a_fifo_stops_the_export() {
        let fx = Fixture::new();
        let path = std::ffi::CString::new(
            fx.content
                .as_path()
                .join("site.test/pipe")
                .to_string_lossy()
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let error = export(&fx.ctx(), &fx.request("site.test", ID, None), &cancel()).unwrap_err();
        assert!(matches!(
            error,
            Error::UnsafeContent(UnsafeContent::SpecialFile(_))
        ));
        assert!(!fx.export_dir(ID).exists());
    }

    #[test]
    fn a_failing_tar_removes_the_partial_export_and_leaves_the_source_alone() {
        let fx = Fixture::new();
        fx.failing_tar();
        let error = export(&fx.ctx(), &fx.request("site.test", ID, None), &cancel()).unwrap_err();
        assert!(matches!(error, Error::Rejected(_)));
        assert!(!fx.export_dir(ID).exists());
        assert!(fx.content.as_path().join("site.test/index.php").exists());
    }

    #[test]
    fn a_root_outside_the_content_root_or_behind_a_symlink_is_refused() {
        let fx = Fixture::new();
        let outside = fx.base.join("elsewhere");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, fx.content.as_path().join("linked")).unwrap();
        for dir in ["linked", "missing"] {
            let error = export(&fx.ctx(), &fx.request(dir, ID, None), &cancel()).unwrap_err();
            assert!(matches!(error, Error::SourceUnavailable), "{dir}");
        }
        let plan = serde_json::json!({ "sourceRoot": outside });
        let request = ExportRequest::parse(&plan.to_string(), ID, None).unwrap();
        assert!(matches!(
            export(&fx.ctx(), &request, &cancel()).unwrap_err(),
            Error::SourceUnavailable
        ));
        assert_eq!(fx.tar_calls(), 0);
    }

    #[test]
    fn a_busy_root_stops_the_export() {
        let fx = Fixture::new();
        let root = fx.content.as_path().join("site.test");
        let _held =
            resource_lock::acquire(&fx.state, &root, RequestId::parse(OTHER_ID).unwrap()).unwrap();
        let error = export(&fx.ctx(), &fx.request("site.test", ID, None), &cancel()).unwrap_err();
        assert!(matches!(error, Error::ResourceBusy));
        assert_eq!(fx.tar_calls(), 0);
    }

    #[test]
    fn space_is_checked_before_anything_is_written() {
        let fx = Fixture::new();
        assert!(ensure_space(fx.base.as_path(), 1024).is_ok());
        assert!(matches!(
            ensure_space(fx.base.as_path(), u64::MAX / 2),
            Err(Error::InsufficientSpace)
        ));
    }

    #[test]
    fn a_full_disk_and_another_filesystem_have_their_own_messages() {
        let (code, message) = Error::OtherFilesystem.protocol();
        assert_eq!(code, ErrorCode::InvalidInput);
        assert!(message.contains("different filesystem"), "{message}");
        let full = Error::Extract(ExtractError::Io(io::Error::from_raw_os_error(libc::ENOSPC)));
        let (code, message) = full.protocol();
        assert_eq!(code, ErrorCode::InvalidInput);
        assert!(message.contains("ran out of disk space"), "{message}");
        let other = Error::Extract(ExtractError::Io(io::Error::from_raw_os_error(libc::EIO)));
        assert!(other.protocol().1.contains("corrupt"));
    }

    #[test]
    fn requests_with_a_relative_trailing_or_unknown_field_are_refused() {
        for plan in [
            r#"{"sourceRoot":"var/www/x"}"#,
            r#"{"sourceRoot":"/var/www/x/"}"#,
            r#"{"sourceRoot":"/var/www/../etc"}"#,
            r#"{"sourceRoot":"/var/www/x","extra":1}"#,
            r#"{}"#,
        ] {
            assert!(ExportRequest::parse(plan, ID, None).is_err(), "{plan}");
        }
        assert!(ExportRequest::parse(r#"{"sourceRoot":"/var/www/x"}"#, "nope", None).is_err());
    }

    #[test]
    fn discard_removes_an_export_and_is_a_no_op_the_second_time() {
        let fx = Fixture::new();
        export(&fx.ctx(), &fx.request("site.test", ID, None), &cancel()).unwrap();
        let first = DiscardRequest::parse("export", Some(ID), OTHER_ID).unwrap();
        let removed = discard(
            &fx.state,
            &fx.state_root,
            std::slice::from_ref(&fx.content),
            &first,
        )
        .unwrap();
        assert!(removed.removed);
        assert!(!fx.export_dir(ID).exists());
        let again =
            DiscardRequest::parse("export", Some(ID), "123e4567-e89b-12d3-a456-426614174002")
                .unwrap();
        assert!(
            !discard(
                &fx.state,
                &fx.state_root,
                std::slice::from_ref(&fx.content),
                &again
            )
            .unwrap()
            .removed
        );
    }

    #[test]
    fn discard_of_a_snapshot_removes_only_the_named_snapshot_directory() {
        let fx = Fixture::new();
        let keep = fx
            .content
            .as_path()
            .join(snapshot_dir_name(RequestId::parse(OTHER_ID).unwrap()));
        let drop_dir = fx
            .content
            .as_path()
            .join(snapshot_dir_name(RequestId::parse(ID).unwrap()));
        for dir in [&keep, &drop_dir] {
            fs::create_dir_all(dir.join("site")).unwrap();
            fs::write(dir.join("site/index.php"), "old").unwrap();
        }
        let request =
            DiscardRequest::parse("snapshot", Some(ID), "123e4567-e89b-12d3-a456-426614174003")
                .unwrap();
        let result = discard(
            &fx.state,
            &fx.state_root,
            std::slice::from_ref(&fx.content),
            &request,
        )
        .unwrap();
        assert!(result.removed);
        assert!(!drop_dir.exists());
        assert!(keep.join("site/index.php").exists());
        assert!(fx.content.as_path().join("site.test/index.php").exists());
    }

    #[test]
    fn discard_rejects_an_unknown_kind_and_non_uuid_ids() {
        assert!(DiscardRequest::parse("everything", Some(ID), OTHER_ID).is_err());
        assert!(DiscardRequest::parse("export", Some("../etc"), OTHER_ID).is_err());
        assert!(DiscardRequest::parse("export", Some(ID), "x").is_err());
        // An id is required except for `stale`, which takes none.
        assert!(DiscardRequest::parse("export", None, OTHER_ID).is_err());
        assert!(DiscardRequest::parse("snapshot", None, OTHER_ID).is_err());
        assert!(DiscardRequest::parse("stale", Some(ID), OTHER_ID).is_err());
        assert!(DiscardRequest::parse("stale", None, OTHER_ID).is_ok());
    }

    fn age(path: &Path, hours: u64) {
        let when = SystemTime::now() - Duration::from_secs(hours * 60 * 60);
        fs::File::open(path).unwrap().set_modified(when).unwrap();
    }

    fn fake_export(fx: &Fixture, parent: &str, id: &str, hours_old: u64) -> PathBuf {
        let dir = fx.base.join("state").join(parent).join(id);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("db.sql.gz"), "dump").unwrap();
        age(&dir, hours_old);
        dir
    }

    #[test]
    fn the_sweep_removes_only_exports_past_the_cutoff_in_both_directories() {
        let fx = Fixture::new();
        let old_wp = fake_export(&fx, "wordpress-migrate", ID, 30);
        let old_site = fake_export(&fx, EXPORTS_DIR, OTHER_ID, 25);
        let fresh_wp = fake_export(
            &fx,
            "wordpress-migrate",
            "123e4567-e89b-12d3-a456-426614174002",
            1,
        );
        let fresh_site = fake_export(&fx, EXPORTS_DIR, "123e4567-e89b-12d3-a456-426614174003", 23);
        // Things that are not exports are left alone however old they are.
        let records = fx.base.join("state").join(EXPORTS_DIR).join("snapshots");
        fs::create_dir_all(&records).unwrap();
        age(&records, 100);
        let stray = fx.base.join("state/wordpress-migrate/not-an-export");
        fs::create_dir_all(&stray).unwrap();
        age(&stray, 100);
        let file = fx
            .base
            .join("state/wordpress-migrate/123e4567-e89b-12d3-a456-426614174004");
        fs::write(&file, "a file, not a directory").unwrap();
        age(&file, 100);

        assert_eq!(
            sweep_stale_exports(&fx.state, &fx.state_root, SystemTime::now()),
            2
        );
        assert!(!old_wp.exists() && !old_site.exists());
        assert!(fresh_wp.exists() && fresh_site.exists());
        assert!(records.exists() && stray.exists() && file.exists());
        assert_eq!(
            sweep_stale_exports(&fx.state, &fx.state_root, SystemTime::now()),
            0
        );
    }

    #[test]
    fn a_new_export_sweeps_stale_ones_first_and_leaves_fresh_ones() {
        let fx = Fixture::new();
        let old = fake_export(&fx, "wordpress-migrate", ID, 48);
        let fresh = fake_export(&fx, EXPORTS_DIR, "123e4567-e89b-12d3-a456-426614174005", 2);
        export(
            &fx.ctx(),
            &fx.request("site.test", OTHER_ID, None),
            &cancel(),
        )
        .unwrap();
        assert!(
            !old.exists(),
            "the old WordPress export holds a database dump"
        );
        assert!(fresh.exists());
        assert!(fx.export_dir(OTHER_ID).exists());
    }

    #[test]
    fn discard_stale_reports_how_many_it_removed() {
        let fx = Fixture::new();
        fake_export(&fx, "wordpress-migrate", ID, 72);
        fake_export(&fx, EXPORTS_DIR, OTHER_ID, 72);
        let request =
            DiscardRequest::parse("stale", None, "123e4567-e89b-12d3-a456-426614174006").unwrap();
        let result = discard(
            &fx.state,
            &fx.state_root,
            std::slice::from_ref(&fx.content),
            &request,
        )
        .unwrap();
        assert!(result.removed);
        assert_eq!(result.removed_count, 2);
        assert!(result.archive_id.is_none());
        let again =
            DiscardRequest::parse("stale", None, "123e4567-e89b-12d3-a456-426614174007").unwrap();
        let result = discard(
            &fx.state,
            &fx.state_root,
            std::slice::from_ref(&fx.content),
            &again,
        )
        .unwrap();
        assert!(!result.removed);
        assert_eq!(result.removed_count, 0);
    }
}
