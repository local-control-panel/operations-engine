//! The bounded, read-only walk that produces the path -> SHA-256 map.
//!
//! * Never follows a symlink: directories are opened with `O_NOFOLLOW`
//!   one component at a time, files with `O_NOFOLLOW`; a symlink whose name
//!   has a code extension is recorded by the hash of its link text and never
//!   read through.
//! * Only paths and hashes are produced. File content is hashed in a
//!   streaming loop and dropped.
//! * Anything it cannot establish makes the scan incomplete (a limit, an
//!   unreadable or special file, a file that keeps changing while it is read,
//!   a name it cannot record). An incomplete scan is `unknown`, never a
//!   partial "match".

use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Read},
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};

use super::Scope;
use crate::{filesystem::ManagedRoot, site::SiteRelativePath};

/// A file is read again (up to this many times) when it changed during the read.
const READ_ATTEMPTS: u32 = 3;
const MAX_DEPTH: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_files: usize,
    pub max_bytes: u64,
    pub timeout: Duration,
}

impl Limits {
    pub const DEFAULT: Self = Self {
        max_files: 50_000,
        max_bytes: 256 * 1024 * 1024,
        timeout: Duration::from_secs(120),
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Incomplete {
    Files,
    Bytes,
    Time,
    Unreadable,
    Unstable,
    Depth,
    Name,
}

impl Incomplete {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Files => "fileLimit",
            Self::Bytes => "byteLimit",
            Self::Time => "timeLimit",
            Self::Unreadable => "unreadable",
            Self::Unstable => "unstable",
            Self::Depth => "tooDeep",
            Self::Name => "unrecordableName",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        [
            Self::Files,
            Self::Bytes,
            Self::Time,
            Self::Unreadable,
            Self::Unstable,
            Self::Depth,
            Self::Name,
        ]
        .into_iter()
        .find(|reason| reason.as_str() == value)
    }
}

#[derive(Debug)]
pub struct Scan {
    pub files: BTreeMap<String, String>,
    pub bytes_read: u64,
    /// `None` when the walk finished.
    pub incomplete: Option<Incomplete>,
    /// Relative path that stopped the walk, when there is one.
    pub stopped_at: Option<String>,
}

struct Walk<'a> {
    scope: &'a Scope,
    limits: &'a Limits,
    started: Instant,
    files: BTreeMap<String, String>,
    bytes: u64,
    stopped_at: Option<String>,
}

enum FileError {
    Unreadable,
    Unstable,
    Bytes,
}

pub fn scan(root: &ManagedRoot, scope: &Scope, limits: &Limits) -> Scan {
    let mut walk = Walk {
        scope,
        limits,
        started: Instant::now(),
        files: BTreeMap::new(),
        bytes: 0,
        stopped_at: None,
    };
    let incomplete = walk.dir(root, "", 0).err();
    Scan {
        files: walk.files,
        bytes_read: walk.bytes,
        incomplete,
        stopped_at: walk.stopped_at,
    }
}

impl Walk<'_> {
    fn stop(&mut self, reason: Incomplete, path: &str) -> Incomplete {
        if !path.is_empty() {
            self.stopped_at = Some(path.to_owned());
        }
        reason
    }

    fn dir(&mut self, dir: &ManagedRoot, prefix: &str, depth: usize) -> Result<(), Incomplete> {
        if depth > MAX_DEPTH {
            return Err(self.stop(Incomplete::Depth, prefix));
        }
        let children = dir
            .child_entries()
            .map_err(|_| self.stop(Incomplete::Unreadable, prefix))?;
        for child in children {
            if self.started.elapsed() > self.limits.timeout {
                return Err(self.stop(Incomplete::Time, prefix));
            }
            let Some(name) = child.name.to_str() else {
                return Err(self.stop(Incomplete::Name, prefix));
            };
            let rel = if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}/{name}")
            };
            if rel.chars().any(char::is_control) {
                return Err(self.stop(Incomplete::Name, prefix));
            }
            let Ok(name_path) = SiteRelativePath::parse(name) else {
                return Err(self.stop(Incomplete::Name, prefix));
            };
            let Ok(metadata) = dir.symlink_metadata(&name_path) else {
                return Err(self.stop(Incomplete::Unreadable, &rel));
            };
            let code = self.scope.is_code_file(name);
            if metadata.is_symlink() {
                if code {
                    let target = read_link_text(dir, name)
                        .map_err(|_| self.stop(Incomplete::Unreadable, &rel))?;
                    let mut hasher = Sha256::new();
                    hasher.update(b"symlink\0");
                    hasher.update(&target);
                    self.record(rel, hex(&hasher.finalize()))?;
                }
            } else if metadata.is_dir() {
                if self.scope.is_excluded(&rel, name) {
                    continue;
                }
                let sub = dir
                    .open_child_dir_nofollow(&name_path)
                    .map_err(|_| self.stop(Incomplete::Unreadable, &rel))?;
                self.dir(&sub, &rel, depth + 1)?;
            } else if code {
                if !metadata.is_file() {
                    return Err(self.stop(Incomplete::Unreadable, &rel));
                }
                let remaining = self.limits.max_bytes.saturating_sub(self.bytes);
                let result = hash_stable(
                    &mut || dir.open_regular_read(&name_path),
                    &mut |_| {},
                    remaining,
                );
                match result {
                    Ok((digest, size)) => {
                        self.bytes += size;
                        self.record(rel, digest)?;
                    }
                    Err(FileError::Unreadable) => {
                        return Err(self.stop(Incomplete::Unreadable, &rel));
                    }
                    Err(FileError::Unstable) => {
                        return Err(self.stop(Incomplete::Unstable, &rel));
                    }
                    Err(FileError::Bytes) => return Err(self.stop(Incomplete::Bytes, &rel)),
                }
            }
        }
        Ok(())
    }

    fn record(&mut self, rel: String, digest: String) -> Result<(), Incomplete> {
        if self.files.len() >= self.limits.max_files {
            return Err(self.stop(Incomplete::Files, &rel));
        }
        self.files.insert(rel, digest);
        Ok(())
    }
}

/// SHA-256 of a regular file, read until two `fstat`s around the read agree.
/// `after_read(attempt)` is a test hook that runs between the read and the
/// second `fstat`.
fn hash_stable(
    open: &mut dyn FnMut() -> io::Result<File>,
    after_read: &mut dyn FnMut(u32),
    budget: u64,
) -> Result<(String, u64), FileError> {
    for attempt in 0..READ_ATTEMPTS {
        let mut file = open().map_err(|_| FileError::Unreadable)?;
        let before = file.metadata().map_err(|_| FileError::Unreadable)?;
        if !before.is_file() {
            return Err(FileError::Unreadable);
        }
        if before.len() > budget {
            return Err(FileError::Bytes);
        }
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        let mut read_total = 0u64;
        loop {
            let read = file.read(&mut buffer).map_err(|_| FileError::Unreadable)?;
            if read == 0 {
                break;
            }
            read_total += read as u64;
            if read_total > budget {
                return Err(FileError::Bytes);
            }
            hasher.update(&buffer[..read]);
        }
        after_read(attempt);
        let after = file.metadata().map_err(|_| FileError::Unreadable)?;
        if before.len() == after.len()
            && before.modified().ok() == after.modified().ok()
            && read_total == before.len()
        {
            return Ok((hex(&hasher.finalize()), read_total));
        }
    }
    Err(FileError::Unstable)
}

/// The link text itself (`readlinkat`), also for absolute targets that the
/// capability API refuses to resolve. The target is never opened.
fn read_link_text(dir: &ManagedRoot, name: &str) -> io::Result<Vec<u8>> {
    use std::os::fd::AsRawFd;
    let fd = dir.try_clone_fd()?;
    let c_name = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid name"))?;
    let mut buffer = vec![0u8; 4097];
    // SAFETY: the descriptor is open, `c_name` is NUL-terminated and the
    // buffer length is passed exactly.
    let length = unsafe {
        libc::readlinkat(
            fd.as_raw_fd(),
            c_name.as_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
        )
    };
    if length < 0 {
        return Err(io::Error::last_os_error());
    }
    let length = length as usize;
    if length >= buffer.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "link text too long",
        ));
    }
    buffer.truncate(length);
    Ok(buffer)
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut out, "{byte:02x}").unwrap();
    }
    out
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::{security_baseline::Kind, site::TrustedRoot};
    use std::{fs, io::Write as _, os::unix::fs::symlink};

    fn managed(path: &std::path::Path) -> ManagedRoot {
        ManagedRoot::open(&TrustedRoot::parse(path).unwrap()).unwrap()
    }

    fn put(root: &std::path::Path, rel: &str, body: &str) {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
    }

    fn run(root: &std::path::Path, kind: Kind, limits: &Limits) -> Scan {
        scan(&managed(root), &Scope::for_kind(kind), limits)
    }

    #[test]
    fn hashes_code_files_and_skips_the_rest_and_excluded_trees() {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        put(r, "index.php", "<?php echo 1;");
        put(r, "wp-content/plugins/a/a.PHP", "x");
        put(r, "wp-content/plugins/a/readme.txt", "x");
        put(r, "wp-content/plugins/a/node_modules/p/x.php", "x");
        put(r, "wp-content/uploads/2026/evil.php", "x");
        put(r, "wp-content/cache/c.php", "x");
        put(r, "sub/lib.inc", "x");
        let scan = run(r, Kind::Wordpress, &Limits::DEFAULT);
        assert!(scan.incomplete.is_none());
        let paths: Vec<&str> = scan.files.keys().map(String::as_str).collect();
        assert_eq!(
            paths,
            ["index.php", "sub/lib.inc", "wp-content/plugins/a/a.PHP"]
        );
        assert_eq!(
            scan.files["index.php"],
            hex(&Sha256::digest(b"<?php echo 1;"))
        );
    }

    #[test]
    fn drupal_wildcard_excludes_apply_per_site() {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        put(r, "sites/default/files/php/x.php", "x");
        put(r, "sites/other/private/y.php", "x");
        put(r, "sites/default/settings.php", "x");
        put(r, "vendor/autoload.php", "x");
        let scan = run(r, Kind::Drupal, &Limits::DEFAULT);
        let paths: Vec<&str> = scan.files.keys().map(String::as_str).collect();
        assert_eq!(paths, ["sites/default/settings.php"]);
    }

    #[test]
    fn does_not_follow_symlinks_out_of_the_root() {
        let outside = tempfile::tempdir().unwrap();
        put(outside.path(), "secret.php", "outside");
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        put(r, "a.php", "x");
        symlink(outside.path(), r.join("linked-dir")).unwrap();
        symlink(outside.path().join("secret.php"), r.join("link.php")).unwrap();
        let scan = run(r, Kind::Laravel, &Limits::DEFAULT);
        assert!(scan.incomplete.is_none());
        let paths: Vec<&str> = scan.files.keys().map(String::as_str).collect();
        assert_eq!(paths, ["a.php", "link.php"]);
        // The link is hashed by its text, never by the file behind it.
        assert_ne!(scan.files["link.php"], hex(&Sha256::digest(b"outside")));
    }

    #[test]
    fn limits_make_the_scan_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        for n in 0..5 {
            put(r, &format!("f{n}.php"), "0123456789");
        }
        let files = Limits {
            max_files: 3,
            ..Limits::DEFAULT
        };
        assert_eq!(
            run(r, Kind::Joomla, &files).incomplete,
            Some(Incomplete::Files)
        );
        let bytes = Limits {
            max_bytes: 25,
            ..Limits::DEFAULT
        };
        assert_eq!(
            run(r, Kind::Joomla, &bytes).incomplete,
            Some(Incomplete::Bytes)
        );
        let time = Limits {
            timeout: Duration::ZERO,
            ..Limits::DEFAULT
        };
        std::thread::sleep(Duration::from_millis(2));
        assert_eq!(
            run(r, Kind::Joomla, &time).incomplete,
            Some(Incomplete::Time)
        );
    }

    #[test]
    fn a_special_file_with_a_code_name_is_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        put(r, "ok.php", "x");
        let fifo = std::ffi::CString::new(r.join("pipe.php").to_str().unwrap()).unwrap();
        // SAFETY: valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let scan = run(r, Kind::Laravel, &Limits::DEFAULT);
        assert_eq!(scan.incomplete, Some(Incomplete::Unreadable));
        assert_eq!(scan.stopped_at.as_deref(), Some("pipe.php"));
    }

    #[test]
    fn a_file_that_changes_while_read_is_retried_then_unstable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("moving.php");
        fs::write(&path, "one").unwrap();
        let mut opens = 0;
        let mut open = || {
            opens += 1;
            File::open(&path)
        };
        let mut changed_once = false;
        let ok = hash_stable(
            &mut open,
            &mut |_| {
                if !changed_once {
                    changed_once = true;
                    let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
                    file.write_all(b"more").unwrap();
                }
            },
            1 << 20,
        );
        let (digest, size) = ok.ok().unwrap();
        assert_eq!(size, 7);
        assert_eq!(digest, hex(&Sha256::digest(b"onemore")));
        assert_eq!(opens, 2);

        let mut counter = 0u8;
        let always = hash_stable(
            &mut || File::open(&path),
            &mut |_| {
                counter += 1;
                let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
                file.write_all(&[counter]).unwrap();
            },
            1 << 20,
        );
        assert!(matches!(always, Err(FileError::Unstable)));
    }
}
