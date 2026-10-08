//! `site.importArchive`: the destination half of a server-to-server site sync
//! (W2-11, `sync-relay` design brief).
//!
//! The panel relays the archive `site.exportArchive` produced on the source
//! and stages it root-owned (`0600`, one link) as
//! `<artifact dir>/<request id>.site.tar.gz`; the plan carries the source
//! manifest. Nothing is mutated until the archive matches the manifest's size
//! and SHA-256, the manifest is within the confirmed limits, and the
//! filesystem has room for a second copy of the tree.
//!
//! Then, under the destination root's resource lock and a `pending.json`
//! marker (the recovery shape of `wordpress.migrateImport`): the existing root
//! moves to `<content root>/.wcp-sync-<request id>/site` (a rename, so no
//! second copy of the old tree), the archive is extracted with the bounded
//! `tar_extract` reader into a fresh directory that takes the old root's mode,
//! and ownership is repaired to the site's UID/GID. Any failure removes the
//! new directory and renames the old one back; if that itself fails the marker
//! and the snapshot stay for manual repair (`RecoveryRequired`).
//!
//! After a commit the snapshot is kept, but only one per root: the snapshot a
//! previous import left for the same root is removed (the record of which one
//! it was lives in `site-sync/snapshots/<hash of the root>.json` in the engine
//! state). The staged archive is removed whatever happened.

use std::{
    fs,
    io::{self, Seek},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    EXPORTS_DIR, Error, Manifest, MANIFEST_SCHEMA_VERSION, absolute_root, child, ensure_space,
    ids, limits, rel, run_admitted, snapshot_dir_name, unix_now_secs,
};
use crate::{
    filesystem::ManagedRoot,
    permissions::execute::repair_tree,
    site::{SiteRelativePath, TrustedRoot},
    tar_extract::{self, Limits},
    transaction::{IdempotencyKey, RequestId, resource_lock},
    wordpress_migrate_export::sha256_file,
};

pub const OPERATION: &str = "site.importArchive";

const SCOPE: &str = "site-archive-import";
const ARTIFACT_KIND: &str = "site.tar.gz";
const SNAPSHOT_RECORDS: &str = "snapshots";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    manifest: Manifest,
    dest_root: String,
    dest_uid: u32,
    dest_gid: u32,
}

pub struct Request {
    manifest: Manifest,
    dest_root: PathBuf,
    dest_uid: u32,
    dest_gid: u32,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestError;

fn hex64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

impl Request {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError)?;
        let manifest = plan.manifest;
        if manifest.schema_version != MANIFEST_SCHEMA_VERSION
            || !hex64(&manifest.archive.sha256)
            || RequestId::parse(&manifest.export_id).is_err()
        {
            return Err(RequestError);
        }
        let (request_id, idempotency_key) = ids(request_id, key).map_err(|_| RequestError)?;
        Ok(Self {
            dest_root: absolute_root(&plan.dest_root).map_err(|_| RequestError)?,
            manifest,
            dest_uid: plan.dest_uid,
            dest_gid: plan.dest_gid,
            request_id,
            idempotency_key,
        })
    }

    pub fn dest_root(&self) -> &Path {
        &self.dest_root
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    /// Names the kept previous state; `site.discardArchive --kind snapshot`.
    pub snapshot_id: String,
    pub entries: u64,
    pub symlinks: u64,
    pub content_bytes: u64,
    /// Whether the snapshot of an earlier import of this root was removed.
    pub previous_snapshot_removed: bool,
    pub completed_at_unix_secs: u64,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub state_root: &'a TrustedRoot,
    pub content_root: &'a TrustedRoot,
    pub artifact_dir: &'a Path,
    pub artifact_owner_uid: u32,
}

pub fn artifact_path(artifact_dir: &Path, request_id: RequestId) -> PathBuf {
    artifact_dir.join(format!("{request_id}.{ARTIFACT_KIND}"))
}

pub fn execute(ctx: &Context<'_>, req: &Request) -> Result<ImportResult, Error> {
    let manifest = &req.manifest;
    let (max_entries, max_bytes) = limits();
    if manifest.content_bytes > max_bytes || manifest.entries > max_entries {
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
    let artifact = artifact_path(ctx.artifact_dir, req.request_id);
    let result = run_admitted(
        ctx.engine_state,
        SCOPE,
        OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        |scope| {
            let file = verify_artifact(ctx, &artifact, &manifest.archive.sha256, manifest.archive.bytes)?;
            import_with_recovery(ctx, req, scope, &relative, file)
        },
    );
    // The staged archive holds the site's configuration files: it goes
    // whatever happened.
    let _ = fs::remove_file(&artifact);
    result
}

/// Opens the archive without following a symlink, checks it is a root-owned
/// `0600` single-link regular file, and hashes it. Returns the open handle,
/// rewound, so what was hashed is what gets extracted.
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
    archive: fs::File,
) -> Result<ImportResult, Error> {
    let content = ManagedRoot::open(ctx.content_root).map_err(Error::Io)?;
    let canonical_root = ctx
        .content_root
        .as_path()
        .canonicalize()
        .map_err(|_| Error::UnsafeTarget)?;
    let parent = relative
        .as_path()
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    if let Some(parent) = parent {
        // The parent must resolve to itself: no symlink on the way.
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
    // A sync replaces the content of an existing site: the root must exist,
    // be a real directory, and not be a mount point (it is renamed).
    let existing = fs::symlink_metadata(&absolute).map_err(|_| Error::UnsafeTarget)?;
    if !existing.is_dir() {
        return Err(Error::UnsafeTarget);
    }
    let parent_dev = fs::symlink_metadata(absolute.parent().unwrap_or(&canonical_root))
        .map_err(|_| Error::UnsafeTarget)?
        .dev();
    if existing.dev() != parent_dev {
        return Err(Error::UnsafeTarget);
    }
    let old_mode = existing.mode() & 0o7777;
    ensure_space(&canonical_root, req.manifest.content_bytes)?;

    let pending = rel("pending.json");
    let snapshot_dir = SiteRelativePath::parse(snapshot_dir_name(req.request_id))
        .expect("a canonical UUID forms a valid path");
    let saved = child(&snapshot_dir, "site");
    let marker = serde_json::to_vec(&serde_json::json!({
        "requestId": req.request_id,
        "destRoot": req.dest_root,
        "savedFiles": ctx.content_root.join(&saved),
    }))
    .map_err(|_| Error::UnsafeTarget)?;
    scope
        .create_new(&pending, &marker)
        .map_err(|_| Error::RecoveryRequired)?;

    let mut moved = false;
    let mut created = false;
    let mut summary = tar_extract::Summary::default();
    let work = (|| -> Result<(), Error> {
        content.create_dir(&snapshot_dir).map_err(Error::Io)?;
        content.set_mode(&snapshot_dir, 0o700).map_err(Error::Io)?;
        content.rename(relative, &saved).map_err(Error::Io)?;
        moved = true;
        content.create_dir(relative).map_err(Error::Io)?;
        created = true;
        content.set_mode(relative, old_mode).map_err(Error::Io)?;
        let dest = content.open_managed_dir(relative).map_err(Error::Io)?;
        let (max_entries, max_bytes) = limits();
        summary = tar_extract::extract(
            GzDecoder::new(io::BufReader::new(archive)),
            &dest,
            Limits {
                max_entries,
                max_file_bytes: max_bytes,
            },
        )
        .map_err(Error::Extract)?;
        repair_tree(&absolute, req.dest_uid, req.dest_gid, &[]).map_err(Error::Io)?;
        // What replaced the root is a directory the site's user owns.
        let after = fs::symlink_metadata(&absolute).map_err(|_| Error::UnsafeTarget)?;
        if !after.is_dir() || after.uid() != req.dest_uid {
            return Err(Error::UnsafeTarget);
        }
        Ok(())
    })();

    if let Err(error) = work {
        let removed = !created || content.remove_dir_all(relative).is_ok();
        let restored = if moved && removed {
            content.rename(&saved, relative).is_ok()
        } else {
            !moved
        };
        if !removed || !restored {
            return Err(Error::RecoveryRequired);
        }
        let _ = content.remove_dir_all(&snapshot_dir);
        scope.remove_file(&pending).map_err(Error::Io)?;
        return Err(error);
    }

    let previous_snapshot_removed =
        replace_snapshot_record(ctx, &content, &req.dest_root, req.request_id);
    // A crash before this point leaves pending.json and prevents a blind retry.
    let _ = scope.remove_file(&pending);
    Ok(ImportResult {
        snapshot_id: req.request_id.to_string(),
        entries: summary.entries,
        symlinks: summary.symlinks,
        content_bytes: summary.file_bytes,
        previous_snapshot_removed,
        completed_at_unix_secs: unix_now_secs(),
    })
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SnapshotRecord {
    snapshot_id: String,
    root: String,
}

fn record_rel(root: &Path) -> SiteRelativePath {
    let digest = Sha256::digest(root.as_os_str().as_encoded_bytes());
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    rel(&format!("{EXPORTS_DIR}/{SNAPSHOT_RECORDS}/{hex}.json"))
}

/// Keeps one snapshot per root: removes the one an earlier import recorded and
/// records this one. Best effort; a failure leaves an extra snapshot, never
/// less than the new one.
fn replace_snapshot_record(
    ctx: &Context<'_>,
    content: &ManagedRoot,
    dest_root: &Path,
    snapshot_id: RequestId,
) -> bool {
    let record = record_rel(dest_root);
    let previous = fs::read(ctx.engine_state_path(&record))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<SnapshotRecord>(&bytes).ok())
        .and_then(|old| RequestId::parse(&old.snapshot_id).ok())
        .filter(|old| *old != snapshot_id);
    let removed = previous
        .and_then(|old| SiteRelativePath::parse(snapshot_dir_name(old)).ok())
        .is_some_and(|dir| content.remove_dir_all(&dir).is_ok());
    let body = serde_json::to_vec(&SnapshotRecord {
        snapshot_id: snapshot_id.to_string(),
        root: dest_root.to_string_lossy().into_owned(),
    })
    .expect("a record always serializes");
    let _ = ctx
        .engine_state
        .create_dir_all(&rel(&format!("{EXPORTS_DIR}/{SNAPSHOT_RECORDS}")));
    let _ = ctx.engine_state.write_atomic_private(&record, &body);
    removed
}

impl Context<'_> {
    /// Absolute path of a file under the engine state, for plain reads.
    fn engine_state_path(&self, relative: &SiteRelativePath) -> PathBuf {
        self.state_root.join(relative)
    }
}
