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
//! Then, under the destination root's resource lock and a `pending/<root>.json`
//! marker, one per root so that a failed restore of one site blocks only that
//! site (the recovery shape of `wordpress.migrateImport`, whose marker is one
//! per scope): the existing root
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
    EXPORTS_DIR, Error, MANIFEST_SCHEMA_VERSION, Manifest, absolute_root, child, ensure_space, ids,
    limits, rel, run_admitted, snapshot_dir_name, unix_now_secs,
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
            let file = verify_artifact(
                ctx,
                &artifact,
                &manifest.archive.sha256,
                manifest.archive.bytes,
            )?;
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

    scope.create_dir_all(&rel("pending")).map_err(Error::Io)?;
    let pending = rel(&format!("pending/{}.json", root_hash(&req.dest_root)));
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

/// SHA-256 of the root path, hex: names the root's marker and snapshot record.
fn root_hash(root: &Path) -> String {
    let digest = Sha256::digest(root.as_os_str().as_encoded_bytes());
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

fn record_rel(root: &Path) -> SiteRelativePath {
    rel(&format!(
        "{EXPORTS_DIR}/{SNAPSHOT_RECORDS}/{}.json",
        root_hash(root)
    ))
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

#[cfg(test)]
mod tests {
    use std::{
        io::Write,
        os::unix::fs::{PermissionsExt, symlink},
    };

    use flate2::{Compression, write::GzEncoder};

    use super::*;
    use crate::{
        site_archive::{ARCHIVE_FILE, Manifest},
        tar_extract::ExtractError,
        wordpress_migrate_export::ArtifactInfo,
    };

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const SECOND_ID: &str = "123e4567-e89b-12d3-a456-426614174001";
    const EXPORT_ID: &str = "123e4567-e89b-12d3-a456-426614174099";

    struct Fixture {
        _dir: tempfile::TempDir,
        base: PathBuf,
        state: ManagedRoot,
        state_root: TrustedRoot,
        content: TrustedRoot,
        artifacts: PathBuf,
        uid: u32,
        gid: u32,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path().canonicalize().unwrap();
            for sub in ["state", "www", "staging", "src"] {
                fs::create_dir(base.join(sub)).unwrap();
            }
            Self {
                state: ManagedRoot::open(&TrustedRoot::parse(base.join("state")).unwrap()).unwrap(),
                state_root: TrustedRoot::parse(base.join("state")).unwrap(),
                content: TrustedRoot::parse(base.join("www")).unwrap(),
                artifacts: base.join("staging"),
                uid: unsafe { libc::geteuid() },
                gid: unsafe { libc::getegid() },
                base,
                _dir: dir,
            }
        }

        fn ctx(&self) -> Context<'_> {
            Context {
                engine_state: &self.state,
                state_root: &self.state_root,
                content_root: &self.content,
                artifact_dir: &self.artifacts,
                artifact_owner_uid: self.uid,
            }
        }

        fn site(&self) -> PathBuf {
            self.content.as_path().join("dest.test")
        }

        fn existing_site(&self) {
            fs::create_dir(self.site()).unwrap();
            fs::set_permissions(self.site(), fs::Permissions::from_mode(0o750)).unwrap();
            fs::write(self.site().join("index.php"), "<?php echo 'old';").unwrap();
            fs::write(self.site().join("only-here.txt"), "dest only").unwrap();
        }

        /// Stages the archive of a small tree for request `id` and returns the
        /// manifest that matches it; `tree` adds entries to the archived site.
        fn stage(&self, id: &str, tree: impl Fn(&Path)) -> Manifest {
            let src = self.base.join("src").join(id);
            fs::create_dir_all(&src).unwrap();
            fs::write(src.join("index.php"), "<?php echo 'new';").unwrap();
            fs::create_dir_all(src.join("wp-content")).unwrap();
            fs::write(src.join("wp-content/a.txt"), "a").unwrap();
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
            let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
            encoder.write_all(&fs::read(&tar).unwrap()).unwrap();
            let bytes = encoder.finish().unwrap();
            let path = artifact_path(&self.artifacts, RequestId::parse(id).unwrap());
            fs::write(&path, &bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let (len, sha256) = sha256_file(&path).unwrap();
            Manifest {
                schema_version: MANIFEST_SCHEMA_VERSION,
                export_id: EXPORT_ID.into(),
                archive: ArtifactInfo {
                    file: ARCHIVE_FILE.into(),
                    bytes: len,
                    sha256,
                },
                entries: 3,
                content_bytes: 18,
                created_at_unix_secs: 0,
            }
        }

        fn request(&self, manifest: &Manifest, id: &str, key: Option<&str>) -> Request {
            let plan = serde_json::json!({
                "manifest": manifest,
                "destRoot": self.site(),
                "destUid": self.uid,
                "destGid": self.gid,
            });
            Request::parse(&plan.to_string(), id, key).unwrap()
        }

        fn pending(&self) -> bool {
            fs::read_dir(self.base.join("state").join(SCOPE).join("pending"))
                .map(|mut dir| dir.next().is_some())
                .unwrap_or(false)
        }

        fn snapshot(&self, id: &str) -> PathBuf {
            self.content
                .as_path()
                .join(snapshot_dir_name(RequestId::parse(id).unwrap()))
        }

        fn staged_left(&self) -> usize {
            fs::read_dir(&self.artifacts).unwrap().count()
        }

        fn read(&self, relative: &str) -> Option<String> {
            fs::read_to_string(self.site().join(relative)).ok()
        }
    }

    #[test]
    fn import_replaces_the_root_keeps_its_mode_and_snapshots_the_old_state() {
        let fx = Fixture::new();
        fx.existing_site();
        let manifest = fx.stage(ID, |_| {});
        let result = execute(&fx.ctx(), &fx.request(&manifest, ID, None)).unwrap();

        assert_eq!(fx.read("index.php").as_deref(), Some("<?php echo 'new';"));
        assert_eq!(fx.read("wp-content/a.txt").as_deref(), Some("a"));
        // An exact mirror: a file that exists only on the destination is gone...
        assert!(fx.read("only-here.txt").is_none());
        // ...but it is in the snapshot, together with the old index.
        let saved = fx.snapshot(ID).join("site");
        assert_eq!(
            fs::read_to_string(saved.join("only-here.txt")).unwrap(),
            "dest only"
        );
        assert_eq!(
            fs::read_to_string(saved.join("index.php")).unwrap(),
            "<?php echo 'old';"
        );
        assert_eq!(
            fs::metadata(fx.site()).unwrap().permissions().mode() & 0o7777,
            0o750
        );
        assert_eq!(
            fs::metadata(fx.snapshot(ID)).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(result.snapshot_id, ID);
        // bsdtar on macOS adds AppleDouble entries, so only a lower bound holds.
        assert!(result.entries >= 4, "{}", result.entries);
        assert!(!result.previous_snapshot_removed);
        assert_eq!(fx.staged_left(), 0, "the staged archive is removed");
        assert!(!fx.pending());
    }

    #[test]
    fn a_second_import_keeps_only_one_snapshot_per_root() {
        let fx = Fixture::new();
        fx.existing_site();
        let first = fx.stage(ID, |_| {});
        execute(&fx.ctx(), &fx.request(&first, ID, None)).unwrap();
        let second = fx.stage(SECOND_ID, |src| {
            fs::write(src.join("index.php"), "<?php echo 'third';").unwrap();
        });
        let result = execute(&fx.ctx(), &fx.request(&second, SECOND_ID, None)).unwrap();

        assert!(result.previous_snapshot_removed);
        assert!(!fx.snapshot(ID).exists());
        assert_eq!(
            fs::read_to_string(fx.snapshot(SECOND_ID).join("site/index.php")).unwrap(),
            "<?php echo 'new';"
        );
        assert_eq!(fx.read("index.php").as_deref(), Some("<?php echo 'third';"));
    }

    #[test]
    fn a_corrupt_or_mismatched_archive_changes_nothing_and_is_removed() {
        let fx = Fixture::new();
        fx.existing_site();
        let mut manifest = fx.stage(ID, |_| {});
        manifest.archive.sha256 = "0".repeat(64);
        let error = execute(&fx.ctx(), &fx.request(&manifest, ID, None)).unwrap_err();
        assert!(matches!(error, Error::ArtifactMismatch));
        assert_eq!(fx.read("index.php").as_deref(), Some("<?php echo 'old';"));
        assert!(!fx.snapshot(ID).exists());
        assert_eq!(fx.staged_left(), 0);
        assert!(!fx.pending());
    }

    #[test]
    fn an_archive_with_the_wrong_size_or_mode_or_a_symlink_is_refused() {
        let fx = Fixture::new();
        fx.existing_site();
        let mut manifest = fx.stage(ID, |_| {});
        let path = artifact_path(&fx.artifacts, RequestId::parse(ID).unwrap());
        manifest.archive.bytes += 1;
        assert!(matches!(
            execute(&fx.ctx(), &fx.request(&manifest, ID, None)).unwrap_err(),
            Error::ArtifactMismatch
        ));

        let manifest = fx.stage(SECOND_ID, |_| {});
        let second = artifact_path(&fx.artifacts, RequestId::parse(SECOND_ID).unwrap());
        fs::set_permissions(&second, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            execute(&fx.ctx(), &fx.request(&manifest, SECOND_ID, None)).unwrap_err(),
            Error::ArtifactMismatch
        ));

        let third = "123e4567-e89b-12d3-a456-426614174002";
        let manifest = fx.stage(third, |_| {});
        let staged = artifact_path(&fx.artifacts, RequestId::parse(third).unwrap());
        let real = fx.base.join("real.tar.gz");
        fs::rename(&staged, &real).unwrap();
        symlink(&real, &staged).unwrap();
        assert!(matches!(
            execute(&fx.ctx(), &fx.request(&manifest, third, None)).unwrap_err(),
            Error::ArtifactMismatch
        ));
        assert_eq!(fx.read("index.php").as_deref(), Some("<?php echo 'old';"));
        let _ = path;
    }

    #[test]
    fn an_archive_symlink_that_leaves_the_root_restores_the_old_site_exactly() {
        let fx = Fixture::new();
        fx.existing_site();
        let manifest = fx.stage(ID, |src| symlink("/etc/passwd", src.join("evil")).unwrap());
        let error = execute(&fx.ctx(), &fx.request(&manifest, ID, None)).unwrap_err();
        assert!(
            matches!(error, Error::Extract(ExtractError::Unsafe(_))),
            "{error:?}"
        );
        assert_eq!(fx.read("index.php").as_deref(), Some("<?php echo 'old';"));
        assert_eq!(fx.read("only-here.txt").as_deref(), Some("dest only"));
        assert!(fx.read("evil").is_none() && !fx.site().join("evil").exists());
        assert_eq!(
            fs::metadata(fx.site()).unwrap().permissions().mode() & 0o7777,
            0o750
        );
        assert!(
            !fx.snapshot(ID).exists(),
            "a failed import keeps no snapshot"
        );
        assert!(!fx.pending());
        assert_eq!(fx.staged_left(), 0);
    }

    #[test]
    fn a_missing_destination_a_file_and_the_content_root_itself_are_refused() {
        let fx = Fixture::new();
        let manifest = fx.stage(ID, |_| {});
        assert!(matches!(
            execute(&fx.ctx(), &fx.request(&manifest, ID, None)).unwrap_err(),
            Error::UnsafeTarget
        ));
        assert!(!fx.site().exists(), "a sync never creates the site");

        fs::write(fx.site(), "not a directory").unwrap();
        let manifest = fx.stage(SECOND_ID, |_| {});
        assert!(matches!(
            execute(&fx.ctx(), &fx.request(&manifest, SECOND_ID, None)).unwrap_err(),
            Error::UnsafeTarget
        ));

        let third = "123e4567-e89b-12d3-a456-426614174002";
        let manifest = fx.stage(third, |_| {});
        let plan = serde_json::json!({
            "manifest": manifest,
            "destRoot": fx.content.as_path(),
            "destUid": fx.uid, "destGid": fx.gid,
        });
        let request = Request::parse(&plan.to_string(), third, None).unwrap();
        assert!(matches!(
            execute(&fx.ctx(), &request).unwrap_err(),
            Error::UnsafeTarget
        ));
    }

    #[test]
    fn a_destination_behind_a_symlinked_parent_is_refused() {
        let fx = Fixture::new();
        let outside = fx.base.join("outside");
        fs::create_dir_all(outside.join("site")).unwrap();
        symlink(&outside, fx.content.as_path().join("linked")).unwrap();
        let manifest = fx.stage(ID, |_| {});
        let plan = serde_json::json!({
            "manifest": manifest,
            "destRoot": fx.content.as_path().join("linked/site"),
            "destUid": fx.uid, "destGid": fx.gid,
        });
        let request = Request::parse(&plan.to_string(), ID, None).unwrap();
        assert!(matches!(
            execute(&fx.ctx(), &request).unwrap_err(),
            Error::UnsafeTarget
        ));
        assert!(fs::read_dir(outside.join("site")).unwrap().next().is_none());
    }

    #[test]
    fn a_manifest_over_the_limits_is_refused_before_the_archive_is_opened() {
        let fx = Fixture::new();
        fx.existing_site();
        for tweak in [
            |m: &mut Manifest| m.content_bytes = 21 * 1024 * 1024 * 1024,
            |m: &mut Manifest| m.entries = 1_000_001,
        ] {
            let mut manifest = fx.stage(ID, |_| {});
            tweak(&mut manifest);
            assert!(matches!(
                execute(&fx.ctx(), &fx.request(&manifest, ID, None)).unwrap_err(),
                Error::ManifestOverLimit
            ));
            assert_eq!(fx.read("index.php").as_deref(), Some("<?php echo 'old';"));
        }
    }

    #[test]
    fn a_leftover_pending_marker_blocks_the_next_import() {
        let fx = Fixture::new();
        fx.existing_site();
        let scope = open_scope_for_test(&fx);
        scope.create_dir_all(&rel("pending")).unwrap();
        scope
            .create_new(
                &rel(&format!("pending/{}.json", root_hash(&fx.site()))),
                b"{}",
            )
            .unwrap();
        let manifest = fx.stage(ID, |_| {});
        let error = execute(&fx.ctx(), &fx.request(&manifest, ID, None)).unwrap_err();
        assert!(matches!(error, Error::RecoveryRequired));
        assert_eq!(fx.read("index.php").as_deref(), Some("<?php echo 'old';"));
        assert!(fx.pending(), "the marker is not ours to remove");
    }

    #[test]
    fn a_leftover_marker_of_one_site_does_not_block_another() {
        let fx = Fixture::new();
        fx.existing_site();
        let other = fx.content.as_path().join("other.test");
        fs::create_dir(&other).unwrap();
        fs::write(other.join("index.php"), "other").unwrap();
        let scope = open_scope_for_test(&fx);
        scope.create_dir_all(&rel("pending")).unwrap();
        scope
            .create_new(&rel(&format!("pending/{}.json", root_hash(&other))), b"{}")
            .unwrap();
        let manifest = fx.stage(ID, |_| {});
        execute(&fx.ctx(), &fx.request(&manifest, ID, None)).unwrap();
        assert_eq!(fx.read("index.php").as_deref(), Some("<?php echo 'new';"));
        assert_eq!(
            fs::read_to_string(other.join("index.php")).unwrap(),
            "other"
        );
    }

    #[test]
    fn a_retry_with_the_same_key_replays_without_a_second_swap() {
        let fx = Fixture::new();
        fx.existing_site();
        let manifest = fx.stage(ID, |_| {});
        let first = execute(&fx.ctx(), &fx.request(&manifest, ID, Some("key-1"))).unwrap();
        fs::write(fx.site().join("index.php"), "<?php echo 'edited after';").unwrap();
        let again = execute(&fx.ctx(), &fx.request(&manifest, SECOND_ID, Some("key-1"))).unwrap();
        assert_eq!(first.snapshot_id, again.snapshot_id);
        assert_eq!(
            fx.read("index.php").as_deref(),
            Some("<?php echo 'edited after';")
        );
        assert!(!fx.snapshot(SECOND_ID).exists());
    }

    #[test]
    fn a_busy_destination_stops_the_import() {
        let fx = Fixture::new();
        fx.existing_site();
        let _held =
            resource_lock::acquire(&fx.state, &fx.site(), RequestId::parse(SECOND_ID).unwrap())
                .unwrap();
        let manifest = fx.stage(ID, |_| {});
        assert!(matches!(
            execute(&fx.ctx(), &fx.request(&manifest, ID, None)).unwrap_err(),
            Error::ResourceBusy
        ));
        assert_eq!(fx.read("index.php").as_deref(), Some("<?php echo 'old';"));
    }

    #[test]
    fn requests_with_bad_manifests_roots_or_unknown_fields_are_refused() {
        let fx = Fixture::new();
        let manifest = fx.stage(ID, |_| {});
        let good = serde_json::json!({
            "manifest": manifest, "destRoot": "/var/www/x", "destUid": 1, "destGid": 1,
        });
        assert!(Request::parse(&good.to_string(), ID, None).is_ok());
        let mutate = |f: &dyn Fn(&mut serde_json::Value)| {
            let mut value = good.clone();
            f(&mut value);
            Request::parse(&value.to_string(), ID, None).is_err()
        };
        assert!(mutate(&|v| v["destRoot"] = "var/www/x".into()));
        assert!(mutate(&|v| v["destRoot"] = "/var/www/x/".into()));
        assert!(mutate(&|v| v["destRoot"] = "/var/www/../x".into()));
        assert!(mutate(&|v| v["manifest"]["archive"]["sha256"] = "zz".into()));
        assert!(mutate(&|v| v["manifest"]["schemaVersion"] = 2.into()));
        assert!(mutate(&|v| v["manifest"]["exportId"] = "not-a-uuid".into()));
        assert!(mutate(&|v| v["extra"] = 1.into()));
    }

    fn open_scope_for_test(fx: &Fixture) -> ManagedRoot {
        fx.state.create_dir_all(&rel(SCOPE)).unwrap();
        fx.state.open_managed_dir(&rel(SCOPE)).unwrap()
    }
}
