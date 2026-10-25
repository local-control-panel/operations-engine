//! `wordpress.rotateDebugLog`: rotates `wp-content/debug.log` so a log that
//! grew without bound can be cut without a raw write on a customer site.
//!
//! The request names the log by absolute path below a content root; the last
//! two components must be `wp-content/debug.log`. Every directory down to
//! `wp-content` is opened with `O_NOFOLLOW` (the `site_file` walk), and the
//! log and every rotated copy must be a regular file or absent: a symlink is
//! refused before anything is renamed. Content is never read, only sizes.
//!
//! Rotation is renames inside `wp-content` (no copy, so a 2 GiB log rotates
//! at once): `debug.log.<keep>` is dropped, `debug.log.N` becomes
//! `debug.log.N+1`, `debug.log` becomes `debug.log.1`, and a fresh empty
//! `debug.log` with the old owner, group and mode is renamed into place. The
//! empty file is staged first, so a failure before the first rename changes
//! nothing. A missing or empty log is not rotated, which makes a repeated
//! call a no-op that never pushes real history out of the retention window.
//!
//! With `compress`, the new `debug.log.1` is gzipped after the rotation has
//! completed: streamed into a private temp file, read back and checked to
//! decompress to exactly the bytes written (and the source must not have
//! grown meanwhile), then renamed to `debug.log.1.gz` and the plain copy
//! removed. Any failure leaves the plain `debug.log.1` untouched and the
//! rotation still succeeds (`compressed: false`). Older copies are only
//! renamed, whichever form they have, so plain and `.gz` copies may mix; a
//! slot counts as one copy either way and retention is unchanged. This is
//! the one place the engine reads log content, and it never returns it.
//!
//! Takes the site directory's resource lock like the other `site_file`
//! operations and records a transaction and audit entry in the `site-file`
//! scope.

use std::{
    io::{self, Read as _},
    path::PathBuf,
};

use cap_std::fs::MetadataExt as _;
use serde::{Deserialize, Serialize};

use crate::{
    filesystem::ManagedRoot,
    site::{SiteRelativePath, TrustedRoot},
    site_file::{RequestError, open_parent, parse_ids, parse_path, split_path},
    site_root::{Error, transact_in, unix_now_secs},
    transaction::{IdempotencyKey, RequestId},
};

pub const OPERATION: &str = "wordpress.rotateDebugLog";
const SCOPE: &str = "site-file";
pub const DEFAULT_KEEP: u32 = 5;
pub const MAX_KEEP: u32 = 10;
const LOG_NAME: &str = "debug.log";
const DIR_NAME: &str = "wp-content";

#[derive(Debug)]
pub struct RotateRequest {
    pub path: PathBuf,
    pub keep: u32,
    /// Gzip the rotated `debug.log.1` into `debug.log.1.gz`.
    pub compress: bool,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl RotateRequest {
    pub fn parse(
        path: &str,
        keep: Option<u32>,
        compress: bool,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let path = parse_path(path)?;
        let mut parts = path.components().rev();
        let is_log = parts.next().is_some_and(|c| c.as_os_str() == LOG_NAME)
            && parts.next().is_some_and(|c| c.as_os_str() == DIR_NAME);
        if !is_log {
            return Err(RequestError::InvalidPath);
        }
        let keep = keep.unwrap_or(DEFAULT_KEEP);
        if !(1..=MAX_KEEP).contains(&keep) {
            return Err(RequestError::InvalidRequest);
        }
        let (request_id, idempotency_key) = parse_ids(request_id, key)?;
        Ok(Self {
            path: path.to_owned(),
            keep,
            compress,
            request_id,
            idempotency_key,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RotateResult {
    pub path: String,
    /// False when there was nothing to rotate (no log, or an empty one).
    pub rotated: bool,
    pub size_before_bytes: u64,
    pub size_after_bytes: u64,
    /// Rotated copies (`debug.log.1..keep`) present afterwards.
    pub kept_copies: u32,
    /// The oldest copy was dropped to stay within `keep`.
    pub dropped_oldest: bool,
    /// The rotated copy was gzipped to `debug.log.1.gz`. False when
    /// compression was not requested, nothing was rotated, or it failed
    /// (the plain copy is then kept).
    #[serde(default)]
    pub compressed: bool,
    pub completed_at_unix_secs: u64,
}

fn name(value: &str) -> SiteRelativePath {
    SiteRelativePath::parse(value).expect("a generated name is one component")
}

fn copy_name(n: u32) -> SiteRelativePath {
    name(&format!("{LOG_NAME}.{n}"))
}

fn gz_name(n: u32) -> SiteRelativePath {
    name(&format!("{LOG_NAME}.{n}.gz"))
}

/// Gzips `debug.log.1` into `debug.log.1.gz` and removes the plain copy
/// only once the archive is verified. Any error leaves the plain copy.
fn compress_first_copy(
    dir: &ManagedRoot,
    uid: u32,
    gid: u32,
    mode: u32,
    id: &str,
) -> io::Result<()> {
    #[cfg(test)]
    if tests::FAIL_COMPRESS.with(std::cell::Cell::get) {
        return Err(io::Error::other("injected gzip failure"));
    }
    let src = copy_name(1);
    let dst = gz_name(1);
    let tmp = name(&format!(".{LOG_NAME}.wcp-{id}.gz.tmp"));
    let build = || -> io::Result<()> {
        let mut input = dir.open_read(&src)?;
        if !input.metadata()?.is_file() {
            return Err(io::Error::other("rotated copy is not a regular file"));
        }
        let out = dir.create_new_file_with_mode(&tmp, 0o600)?;
        dir.chown(&tmp, uid, gid)?;
        let mut enc = flate2::write::GzEncoder::new(out, flate2::Compression::default());
        let copied = io::copy(&mut input, &mut enc)?;
        let out = enc.finish()?;
        out.sync_all()?;
        drop(out);
        // The archive must decompress to exactly what was read, and the
        // source must not have grown while it was being read.
        let mut check = flate2::read::GzDecoder::new(dir.open_read(&tmp)?);
        let mut seen = 0u64;
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = check.read(&mut buf)?;
            if n == 0 {
                break;
            }
            seen += n as u64;
        }
        if seen != copied || input.metadata()?.len() != copied {
            return Err(io::Error::other("gzip verification failed"));
        }
        dir.set_mode(&tmp, mode)?;
        dir.rename(&tmp, &dst)
    };
    if let Err(error) = build() {
        let _ = dir.remove_file(&tmp);
        return Err(error);
    }
    if let Err(error) = dir.remove_file(&src) {
        // Both forms present is harmless but wasteful; drop the archive so
        // the slot stays unambiguous.
        let _ = dir.remove_file(&dst);
        return Err(error);
    }
    Ok(())
}

/// `Some(size)` for a regular file, `None` when absent; a symlink or
/// anything else is refused.
fn regular_size(dir: &ManagedRoot, entry: &SiteRelativePath) -> Result<Option<u64>, Error> {
    match dir.symlink_metadata(entry) {
        Ok(m) if m.is_file() => Ok(Some(m.size())),
        Ok(m) if m.file_type().is_symlink() => Err(Error::UnsafePath),
        Ok(_) => Err(Error::NotRegularFile),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::Io(e)),
    }
}

pub fn rotate_debug_log(
    engine_state: &ManagedRoot,
    content_roots: &[TrustedRoot],
    req: &RotateRequest,
) -> Result<RotateResult, Error> {
    let (content_root, names) = split_path(content_roots, &req.path)?;
    let lock = content_root.as_path().join(names[0].as_path());
    transact_in(
        SCOPE,
        engine_state,
        OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        &[lock.as_path()],
        || rotate(content_root, &names, req),
    )
}

fn rotate(
    content_root: &TrustedRoot,
    names: &[SiteRelativePath],
    req: &RotateRequest,
) -> Result<RotateResult, Error> {
    let (dir, log) = open_parent(content_root, names)?;
    let path = req.path.to_string_lossy().into_owned();
    let done = |rotated, before, dropped, compressed| {
        let kept = (1..=req.keep)
            .filter(|n| {
                matches!(regular_size(&dir, &copy_name(*n)), Ok(Some(_)))
                    || matches!(regular_size(&dir, &gz_name(*n)), Ok(Some(_)))
            })
            .count() as u32;
        RotateResult {
            path: path.clone(),
            rotated,
            size_before_bytes: before,
            size_after_bytes: if rotated { 0 } else { before },
            kept_copies: kept,
            dropped_oldest: dropped,
            compressed,
            completed_at_unix_secs: unix_now_secs(),
        }
    };

    let Some(size) = regular_size(&dir, &log)? else {
        return Ok(done(false, 0, false, false));
    };
    // Refuse before touching anything if a copy is not a plain file.
    // Each slot may hold a plain copy, a `.gz` copy, or (after an
    // interrupted compression) both; remember which.
    let mut copies = Vec::new();
    for n in 1..=req.keep {
        let plain = regular_size(&dir, &copy_name(n))?.is_some();
        let gz = regular_size(&dir, &gz_name(n))?.is_some();
        copies.push((plain, gz));
    }
    if size == 0 {
        return Ok(done(false, 0, false, false));
    }

    let old = dir.symlink_metadata(&log).map_err(Error::Io)?;
    let (uid, gid, mode) = (old.uid(), old.gid(), old.mode() & 0o777);
    let fresh = name(&format!(".{LOG_NAME}.wcp-{}.tmp", req.request_id));
    let staged = (|| -> io::Result<()> {
        drop(dir.create_new_file_with_mode(&fresh, 0o600)?);
        dir.chown(&fresh, uid, gid)?;
        dir.set_mode(&fresh, mode)
    })();
    if let Err(error) = staged {
        let _ = dir.remove_file(&fresh);
        return Err(Error::Io(error));
    }

    let (last_plain, last_gz) = copies[req.keep as usize - 1];
    let dropped = last_plain || last_gz;
    let moved = (|| -> io::Result<()> {
        if last_plain {
            dir.remove_file(&copy_name(req.keep))?;
        }
        if last_gz {
            dir.remove_file(&gz_name(req.keep))?;
        }
        for n in (1..req.keep).rev() {
            let (plain, gz) = copies[n as usize - 1];
            if plain {
                dir.rename(&copy_name(n), &copy_name(n + 1))?;
            }
            if gz {
                dir.rename(&gz_name(n), &gz_name(n + 1))?;
            }
        }
        dir.rename(&log, &copy_name(1))?;
        dir.rename(&fresh, &log)
    })();
    if let Err(error) = moved {
        let _ = dir.remove_file(&fresh);
        // Put the live log back if it was already moved aside and nothing
        // took its place; the shifted copies are only renamed, none is lost.
        if regular_size(&dir, &log).ok().flatten().is_none() {
            let _ = dir.rename(&copy_name(1), &log);
        }
        return Err(Error::Io(error));
    }
    let compressed = req.compress
        && compress_first_copy(&dir, uid, gid, mode, &req.request_id.to_string()).is_ok();
    Ok(done(true, size, dropped, compressed))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        cell::Cell,
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };

    thread_local! {
        pub(super) static FAIL_COMPRESS: Cell<bool> = const { Cell::new(false) };
    }

    const ID: [&str; 4] = [
        "123e4567-e89b-12d3-a456-426614174001",
        "123e4567-e89b-12d3-a456-426614174002",
        "123e4567-e89b-12d3-a456-426614174003",
        "123e4567-e89b-12d3-a456-426614174004",
    ];

    struct Fixture {
        dir: tempfile::TempDir,
        roots: Vec<TrustedRoot>,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            fs::create_dir_all(dir.path().join("www/site/wp-content")).unwrap();
            fs::create_dir_all(dir.path().join("state")).unwrap();
            let roots = vec![TrustedRoot::parse(dir.path().join("www")).unwrap()];
            Self { dir, roots }
        }

        fn content(&self) -> PathBuf {
            self.dir.path().join("www/site/wp-content")
        }

        fn rotate(&self, keep: Option<u32>, id: &str) -> Result<RotateResult, Error> {
            self.rotate_with(keep, false, id)
        }

        fn rotate_with(
            &self,
            keep: Option<u32>,
            compress: bool,
            id: &str,
        ) -> Result<RotateResult, Error> {
            let state =
                ManagedRoot::open(&TrustedRoot::parse(self.dir.path().join("state")).unwrap())
                    .unwrap();
            let path = self.content().join("debug.log");
            let req =
                RotateRequest::parse(path.to_str().unwrap(), keep, compress, id, None).unwrap();
            rotate_debug_log(&state, &self.roots, &req)
        }

        fn read(&self, file: &str) -> Option<String> {
            fs::read_to_string(self.content().join(file)).ok()
        }
    }

    #[test]
    fn request_validation() {
        let ok = |p: &str, k: Option<u32>| RotateRequest::parse(p, k, false, ID[0], None).is_ok();
        assert!(ok("/var/www/a/wp-content/debug.log", None));
        assert!(ok("/var/www/a/wp-content/debug.log", Some(10)));
        assert!(!ok("/var/www/a/wp-content/debug.log", Some(0)));
        assert!(!ok("/var/www/a/wp-content/debug.log", Some(11)));
        assert!(!ok("/var/www/a/wp-content/error.log", None));
        assert!(!ok("/var/www/a/debug.log", None));
        assert!(!ok("wp-content/debug.log", None));
    }

    #[test]
    fn numbering_and_retention() {
        let f = Fixture::new();
        for (i, id) in ID.iter().enumerate() {
            fs::write(f.content().join("debug.log"), format!("log{i}")).unwrap();
            let r = f.rotate(Some(3), id).unwrap();
            assert!(r.rotated);
            assert_eq!(r.size_before_bytes, 4);
            assert_eq!(r.size_after_bytes, 0);
            assert_eq!(r.dropped_oldest, i == 3);
        }
        assert_eq!(f.read("debug.log").as_deref(), Some(""));
        assert_eq!(f.read("debug.log.1").as_deref(), Some("log3"));
        assert_eq!(f.read("debug.log.2").as_deref(), Some("log2"));
        assert_eq!(f.read("debug.log.3").as_deref(), Some("log1"));
        assert_eq!(f.read("debug.log.4"), None, "log0 fell out of the window");
    }

    #[test]
    fn fresh_file_keeps_mode_and_repeat_is_a_noop() {
        let f = Fixture::new();
        let log = f.content().join("debug.log");
        fs::write(&log, "x").unwrap();
        fs::set_permissions(&log, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(f.rotate(None, ID[0]).unwrap().rotated);
        let mode = fs::metadata(&log).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
        let again = f.rotate(None, ID[1]).unwrap();
        assert!(!again.rotated);
        assert_eq!(again.kept_copies, 1);
        assert_eq!(f.read("debug.log.1").as_deref(), Some("x"));
        assert_eq!(f.read("debug.log.2"), None);
    }

    #[test]
    fn missing_log_is_not_an_error() {
        let f = Fixture::new();
        let r = f.rotate(None, ID[0]).unwrap();
        assert!(!r.rotated);
        assert!(!f.content().join("debug.log").exists());
    }

    #[test]
    fn symlinks_are_refused_and_nothing_moves() {
        let f = Fixture::new();
        let target = f.dir.path().join("elsewhere");
        fs::write(&target, "keep").unwrap();
        let log = f.content().join("debug.log");
        symlink(&target, &log).unwrap();
        assert!(matches!(f.rotate(None, ID[0]), Err(Error::UnsafePath)));
        fs::remove_file(&log).unwrap();
        // A symlinked rotated copy.
        fs::write(&log, "x").unwrap();
        symlink(&target, f.content().join("debug.log.2")).unwrap();
        assert!(matches!(f.rotate(None, ID[1]), Err(Error::UnsafePath)));
        assert_eq!(f.read("debug.log").as_deref(), Some("x"));
        // A symlinked wp-content.
        let moved = f.dir.path().join("www/real");
        fs::rename(f.content(), &moved).unwrap();
        symlink(&moved, f.content()).unwrap();
        assert!(matches!(f.rotate(None, ID[2]), Err(Error::UnsafePath)));
        assert_eq!(fs::read_to_string(&target).unwrap(), "keep");
    }

    fn gunzip(path: &std::path::Path) -> String {
        let mut out = String::new();
        flate2::read::GzDecoder::new(fs::File::open(path).unwrap())
            .read_to_string(&mut out)
            .unwrap();
        out
    }

    #[test]
    fn compress_gzips_the_rotated_copy_and_retention_holds() {
        let f = Fixture::new();
        let log = f.content().join("debug.log");
        fs::write(&log, "plain-old").unwrap();
        fs::set_permissions(&log, fs::Permissions::from_mode(0o640)).unwrap();
        let r = f.rotate_with(Some(2), false, ID[0]).unwrap();
        assert!(r.rotated && !r.compressed);
        fs::write(&log, "zipped-new").unwrap();
        let r = f.rotate_with(Some(2), true, ID[1]).unwrap();
        assert!(r.rotated && r.compressed);
        assert_eq!(r.kept_copies, 2);
        assert!(!f.content().join("debug.log.1").exists());
        assert_eq!(gunzip(&f.content().join("debug.log.1.gz")), "zipped-new");
        assert_eq!(f.read("debug.log.2").as_deref(), Some("plain-old"));
        let mode = fs::metadata(f.content().join("debug.log.1.gz"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o640);
        // The gz copy shifts and finally drops with the window.
        fs::write(&log, "third").unwrap();
        let r = f.rotate_with(Some(2), true, ID[2]).unwrap();
        assert!(r.dropped_oldest && r.compressed);
        assert_eq!(gunzip(&f.content().join("debug.log.1.gz")), "third");
        assert_eq!(gunzip(&f.content().join("debug.log.2.gz")), "zipped-new");
        assert_eq!(f.read("debug.log.2"), None, "plain-old fell out");
        let leftovers: Vec<_> = fs::read_dir(f.content())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn gzip_failure_keeps_the_plain_copy() {
        let f = Fixture::new();
        fs::write(f.content().join("debug.log"), "precious").unwrap();
        FAIL_COMPRESS.with(|c| c.set(true));
        let r = f.rotate_with(None, true, ID[0]);
        FAIL_COMPRESS.with(|c| c.set(false));
        let r = r.unwrap();
        assert!(r.rotated && !r.compressed);
        assert_eq!(f.read("debug.log.1").as_deref(), Some("precious"));
        assert!(!f.content().join("debug.log.1.gz").exists());
        assert_eq!(f.read("debug.log").as_deref(), Some(""));
    }
}
