use std::{
    io::{self, Write},
    path::{Path, PathBuf},
};

use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};

use crate::site::{SiteRelativePath, TrustedRoot};

/// One direct child of a directory, as reported by
/// `ManagedRoot::child_entries`.
pub struct ChildEntry {
    pub name: std::ffi::OsString,
    pub is_dir: bool,
}

pub struct ManagedRoot {
    directory: Dir,
}

impl ManagedRoot {
    pub fn open(root: &TrustedRoot) -> io::Result<Self> {
        Ok(Self {
            directory: Dir::open_ambient_dir(root.as_path(), ambient_authority())?,
        })
    }

    pub fn open_dir(&self, path: &SiteRelativePath) -> io::Result<Dir> {
        self.directory.open_dir(path.as_path())
    }

    /// Descends into `path` and returns it as its own `ManagedRoot`, so
    /// every operation on the result is capability-scoped to that
    /// subdirectory rather than merely path-prefixed under this one — a
    /// bug that builds a wrong relative path still cannot reach outside
    /// `path`. Used to scope a single site's locks/transactions/audit state
    /// beneath the engine-wide state root.
    pub fn open_managed_dir(&self, path: &SiteRelativePath) -> io::Result<Self> {
        Ok(Self {
            directory: self.open_dir(path)?,
        })
    }

    /// Changes the owner of the file or directory at `path`. The target is
    /// opened through this root's capability first and changed through
    /// that descriptor, so a symlink cannot redirect the change outside the
    /// root.
    #[cfg(unix)]
    pub fn chown(&self, path: &SiteRelativePath, uid: u32, gid: u32) -> io::Result<()> {
        use std::os::fd::AsRawFd;

        let target = match self.directory.open_dir(path.as_path()) {
            Ok(dir) => dir.into_std_file(),
            Err(_) => self.directory.open(path.as_path())?.into_std(),
        };
        // Directories may be opened `O_PATH` on Linux, which `fchown`
        // rejects; `fchownat` with an empty path accepts any descriptor.
        #[cfg(target_os = "linux")]
        // SAFETY: `target` is open for the call and the path is a valid,
        // NUL-terminated empty string.
        let result = unsafe {
            libc::fchownat(
                target.as_raw_fd(),
                c"".as_ptr(),
                uid,
                gid,
                libc::AT_EMPTY_PATH,
            )
        };
        #[cfg(not(target_os = "linux"))]
        // SAFETY: `target` is an open descriptor for the duration of the call.
        let result = unsafe { libc::fchown(target.as_raw_fd(), uid, gid) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Sets the modification time of the file, directory or symlink at `path`
    /// (the access time is left alone). The entry's parent is opened through
    /// this root's capability and the time is set with `utimensat` and
    /// `AT_SYMLINK_NOFOLLOW`, so a symlink is changed itself and never its target.
    #[cfg(unix)]
    pub fn set_modified_nofollow(
        &self,
        path: &SiteRelativePath,
        secs: i64,
        nanos: u32,
    ) -> io::Result<()> {
        use std::os::fd::AsRawFd;

        let name = path.as_path().file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "path has no final component")
        })?;
        let name = std::ffi::CString::new(name.as_encoded_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains NUL"))?;
        let parent_dir;
        let parent = match path
            .as_path()
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
        {
            Some(parent) => {
                parent_dir = self.directory.open_dir(parent)?;
                &parent_dir
            }
            None => &self.directory,
        };
        let times = [
            libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
            },
            libc::timespec {
                tv_sec: secs as libc::time_t,
                tv_nsec: nanos as _,
            },
        ];
        // SAFETY: the descriptor is open for the call, `name` is a valid
        // NUL-terminated string and `times` points at two timespecs.
        let result = unsafe {
            libc::utimensat(
                parent.as_raw_fd(),
                name.as_ptr(),
                times.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Opens the direct child directory `name` without following a symlink
    /// in the final component (`openat` with `O_NOFOLLOW | O_DIRECTORY`),
    /// returning it as its own capability-scoped root. A symlink or a
    /// non-directory there fails with `ELOOP`/`ENOTDIR`; unlike
    /// `open_managed_dir`, a link swapped in under a tenant-writable
    /// directory can never redirect the caller to another site's tree.
    #[cfg(unix)]
    pub fn open_child_dir_nofollow(&self, name: &SiteRelativePath) -> io::Result<Self> {
        use std::{
            ffi::CString,
            os::{
                fd::{AsRawFd, FromRawFd},
                unix::ffi::OsStrExt,
            },
        };

        let mut components = name.as_path().components();
        let (Some(_), None) = (components.next(), components.next()) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a single path component is required",
            ));
        };
        let c_name = CString::new(name.as_path().as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid name"))?;
        // SAFETY: the directory descriptor is open for the call and `c_name`
        // is a valid NUL-terminated string.
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a freshly opened descriptor owned by nobody else.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        Ok(Self {
            directory: Dir::from_std_file(file),
        })
    }

    /// A duplicate of this directory's descriptor, for the descriptor-based
    /// ownership walk.
    #[cfg(unix)]
    pub fn try_clone_fd(&self) -> io::Result<std::os::fd::OwnedFd> {
        Ok(std::os::fd::OwnedFd::from(
            self.directory.try_clone()?.into_std_file(),
        ))
    }

    /// Metadata of this directory itself (an `fstat` on the open handle).
    pub fn own_metadata(&self) -> io::Result<cap_std::fs::Metadata> {
        self.directory.dir_metadata()
    }

    /// Metadata of `path` without following a symlink in the final
    /// component.
    pub fn symlink_metadata(&self, path: &SiteRelativePath) -> io::Result<cap_std::fs::Metadata> {
        self.directory.symlink_metadata(path.as_path())
    }

    /// Changes the owner of this directory itself through its own
    /// descriptor. Never recursive.
    #[cfg(unix)]
    pub fn chown_self(&self, uid: u32, gid: u32) -> io::Result<()> {
        use std::os::fd::AsRawFd;

        let target = self.directory.try_clone()?.into_std_file();
        #[cfg(target_os = "linux")]
        // SAFETY: `target` is open for the call and the path is a valid,
        // NUL-terminated empty string.
        let result = unsafe {
            libc::fchownat(
                target.as_raw_fd(),
                c"".as_ptr(),
                uid,
                gid,
                libc::AT_EMPTY_PATH,
            )
        };
        #[cfg(not(target_os = "linux"))]
        // SAFETY: `target` is an open descriptor for the duration of the call.
        let result = unsafe { libc::fchown(target.as_raw_fd(), uid, gid) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Sets the permission bits of this directory itself.
    #[cfg(unix)]
    pub fn set_own_mode(&self, mode: u32) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        self.directory.set_permissions(
            ".",
            cap_std::fs::Permissions::from_std(std::fs::Permissions::from_mode(mode)),
        )
    }

    /// The direct children of this directory, with whether each is a real
    /// directory (not a symlink to one).
    pub fn child_entries(&self) -> io::Result<Vec<ChildEntry>> {
        let mut children = Vec::new();
        for entry in self.directory.entries()? {
            let entry = entry?;
            children.push(ChildEntry {
                name: entry.file_name(),
                is_dir: entry.file_type()?.is_dir(),
            });
        }
        Ok(children)
    }

    /// Removes the empty directory `path` (never recursive).
    pub fn remove_dir(&self, path: &SiteRelativePath) -> io::Result<()> {
        self.directory.remove_dir(path.as_path())
    }

    /// Creates `path` as a new directory, failing if it already exists (its
    /// parent must already exist — use `create_dir_all` for that first).
    /// Use this, not `create_dir_all`, wherever the caller needs a
    /// guarantee of a brand-new, empty directory rather than "this
    /// directory now exists, possibly with prior contents."
    pub fn create_dir(&self, path: &SiteRelativePath) -> io::Result<()> {
        self.directory.create_dir(path.as_path())
    }

    pub fn create_dir_all(&self, path: &SiteRelativePath) -> io::Result<()> {
        self.directory.create_dir_all(path.as_path())
    }

    pub fn read_to_string(&self, path: &SiteRelativePath) -> io::Result<String> {
        self.directory.read_to_string(path.as_path())
    }

    pub fn exists(&self, path: &SiteRelativePath) -> bool {
        self.directory.exists(path.as_path())
    }

    /// Names of the regular files directly inside this `ManagedRoot`'s own
    /// root (non-recursive, directories and anything not valid UTF-8
    /// silently skipped - every current caller lists a directory this
    /// engine itself only ever populates with UTF-8-named files, so
    /// skipping the rest is a safe simplification, not silent data loss).
    /// To list a *subdirectory*, `open_managed_dir` into it first and call
    /// this on the result, the same way any other capability-scoped
    /// descent works here - there is deliberately no path-taking variant,
    /// so nothing can list a subdirectory's contents without also holding
    /// a capability scoped to exactly that subdirectory. Used by retention
    /// sweeps (`transaction::prune`) and content sweeps
    /// (`ingress::reconcile`) that need to enumerate what is on disk
    /// before deciding what to do with it.
    pub fn file_names(&self) -> io::Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in self.directory.entries()? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                if let Ok(name) = entry.file_name().into_string() {
                    names.push(name);
                }
            }
        }
        Ok(names)
    }

    /// Creates `path` only if it does not already exist and writes `contents`
    /// to it. The create-and-open step is atomic, so this is safe to use as a
    /// mutual-exclusion primitive between racing processes.
    pub fn create_new(&self, path: &SiteRelativePath, contents: &[u8]) -> io::Result<()> {
        let mut file = self.directory.open_with(
            path.as_path(),
            OpenOptions::new().write(true).create_new(true),
        )?;
        file.write_all(contents)
    }

    /// Opens a brand-new file beneath this capability root for streaming
    /// content directly into it. The exclusive create prevents accidental
    /// replacement of an existing artifact.
    pub fn create_new_file(&self, path: &SiteRelativePath) -> io::Result<std::fs::File> {
        self.directory
            .open_with(
                path.as_path(),
                OpenOptions::new().write(true).create_new(true),
            )
            .map(cap_std::fs::File::into_std)
    }

    /// Like `create_new_file`, but the file is created with `mode` from the
    /// start (subject to the umask, which only ever removes bits), so
    /// secret-bearing content is never briefly readable by another user.
    #[cfg(unix)]
    pub fn create_new_file_with_mode(
        &self,
        path: &SiteRelativePath,
        mode: u32,
    ) -> io::Result<std::fs::File> {
        use cap_std::fs::OpenOptionsExt;
        self.directory
            .open_with(
                path.as_path(),
                OpenOptions::new().write(true).create_new(true).mode(mode),
            )
            .map(cap_std::fs::File::into_std)
    }

    /// Opens an existing file beneath this capability root for reading.
    pub fn open_read(&self, path: &SiteRelativePath) -> io::Result<std::fs::File> {
        self.directory
            .open(path.as_path())
            .map(cap_std::fs::File::into_std)
    }

    /// Opens `path` for reading and writing, creating it if absent but
    /// never truncating or replacing an existing file - the counterpart to
    /// `create_new_file` for callers that need one persistent file reused
    /// across calls (an OS-level advisory lock target) rather than a fresh
    /// artifact every time.
    pub fn open_or_create_file(&self, path: &SiteRelativePath) -> io::Result<std::fs::File> {
        self.directory
            .open_with(
                path.as_path(),
                OpenOptions::new().read(true).write(true).create(true),
            )
            .map(cap_std::fs::File::into_std)
    }

    pub fn modified(&self, path: &SiteRelativePath) -> io::Result<std::time::SystemTime> {
        self.directory
            .metadata(path.as_path())?
            .modified()
            .map(cap_std::time::SystemTime::into_std)
    }

    #[cfg(unix)]
    pub fn set_mode(&self, path: &SiteRelativePath, mode: u32) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        self.directory.set_permissions(
            path.as_path(),
            cap_std::fs::Permissions::from_std(std::fs::Permissions::from_mode(mode)),
        )
    }

    #[cfg(unix)]
    pub fn mode(&self, path: &SiteRelativePath) -> io::Result<u32> {
        use cap_std::fs::PermissionsExt;
        Ok(self
            .directory
            .metadata(path.as_path())?
            .permissions()
            .mode()
            & 0o777)
    }

    pub fn remove_file(&self, path: &SiteRelativePath) -> io::Result<()> {
        self.directory.remove_file(path.as_path())
    }

    /// Recursively removes `path` and everything beneath it.
    pub fn remove_dir_all(&self, path: &SiteRelativePath) -> io::Result<()> {
        self.directory.remove_dir_all(path.as_path())
    }

    /// Appends `contents` to `path`, creating it first if necessary. Meant
    /// for an append-only history (e.g. an audit log), not a document with a
    /// single current value — use `write_atomic` for that.
    pub fn append(&self, path: &SiteRelativePath, contents: &[u8]) -> io::Result<()> {
        let mut file = self
            .directory
            .open_with(path.as_path(), OpenOptions::new().create(true).append(true))?;
        file.write_all(contents)?;
        file.sync_all()
    }

    /// Replaces `path` with `contents` through a same-directory temp file and
    /// rename, so a reader never observes a partially written file and an
    /// interruption mid-write leaves the previous contents (or nothing)
    /// rather than a corrupt file. Callers that may run concurrently for the
    /// same path must serialize through a lock; this alone only prevents
    /// torn reads, not lost updates.
    pub fn write_atomic(&self, path: &SiteRelativePath, contents: &[u8]) -> io::Result<()> {
        let temp_path = temp_sibling_path(path)?;
        {
            let mut file = self.directory.create(temp_path.as_path())?;
            file.write_all(contents)?;
            file.sync_all()?;
        }
        self.directory
            .rename(temp_path.as_path(), &self.directory, path.as_path())
    }

    /// Like `write_atomic`, but the temp file is made owner-only (`0o600`)
    /// before any content is written, so secret-bearing content is never
    /// readable by another user, not even for the moment between write and
    /// rename.
    #[cfg(unix)]
    pub fn write_atomic_private(&self, path: &SiteRelativePath, contents: &[u8]) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp_path = temp_sibling_path(path)?;
        {
            let mut file = self.directory.create(temp_path.as_path())?;
            file.set_permissions(cap_std::fs::Permissions::from_std(
                std::fs::Permissions::from_mode(0o600),
            ))?;
            file.write_all(contents)?;
            file.sync_all()?;
        }
        self.directory
            .rename(temp_path.as_path(), &self.directory, path.as_path())
    }

    /// Reads `path` in full as raw bytes — the binary counterpart of
    /// `read_to_string`, for content (a fetched engine executable) that
    /// is not valid UTF-8.
    pub fn read_bytes(&self, path: &SiteRelativePath) -> io::Result<Vec<u8>> {
        self.directory.read(path.as_path())
    }

    /// Like `write_atomic`, but additionally marks the written file
    /// executable (mode `0o755`) before the same same-directory atomic
    /// rename makes it visible at `path`. The only writer of executable
    /// content in this codebase — used to stage and activate a fetched,
    /// checksum- and signature-verified `ops-engine` binary.
    #[cfg(unix)]
    pub fn write_new_executable(&self, path: &SiteRelativePath, contents: &[u8]) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp_path = temp_sibling_path(path)?;
        {
            let mut file = self.directory.create(temp_path.as_path())?;
            file.write_all(contents)?;
            file.sync_all()?;
        }
        self.directory.set_permissions(
            temp_path.as_path(),
            cap_std::fs::Permissions::from_std(std::fs::Permissions::from_mode(0o755)),
        )?;
        self.directory
            .rename(temp_path.as_path(), &self.directory, path.as_path())
    }

    /// Creates `link` as a new relative symlink pointing at `target`,
    /// failing if `link` already exists (symlink creation is inherently
    /// exclusive — there is no "replace" mode). Pair with `rename` for an
    /// atomic same-directory symlink swap: create the new link under a
    /// unique temporary name, then `rename` it over the real one.
    pub fn symlink(&self, link: &SiteRelativePath, target: &SiteRelativePath) -> io::Result<()> {
        self.directory.symlink(target.as_path(), link.as_path())
    }

    /// Like `symlink`, but the target is a raw relative path that may use
    /// `..` (a `SiteRelativePath` cannot). The caller decides whether the
    /// target is acceptable; it is never resolved here.
    pub fn symlink_relative(&self, link: &SiteRelativePath, target: &Path) -> io::Result<()> {
        if target.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "symlink target must be relative",
            ));
        }
        self.directory.symlink(target, link.as_path())
    }

    pub fn read_link(&self, link: &SiteRelativePath) -> io::Result<PathBuf> {
        self.directory.read_link(link.as_path())
    }

    /// Renames `from` to `to` within this same directory. This is the
    /// atomic commit point for callers that stage a temp file or symlink
    /// under `from` and want it to become `to` in one step.
    pub fn rename(&self, from: &SiteRelativePath, to: &SiteRelativePath) -> io::Result<()> {
        self.directory
            .rename(from.as_path(), &self.directory, to.as_path())
    }
}

fn temp_sibling_path(path: &SiteRelativePath) -> io::Result<SiteRelativePath> {
    let mut temp = path.as_path().as_os_str().to_os_string();
    temp.push(".tmp");
    SiteRelativePath::parse(temp).map_err(|_| io::Error::other("invalid temp path"))
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        fs,
        io::{Read, Seek, SeekFrom, Write},
        os::unix::fs::symlink,
        path::Path,
    };

    use crate::site::{SiteRelativePath, TrustedRoot};

    use super::ManagedRoot;

    #[test]
    fn creates_and_reads_only_beneath_opened_root() {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let root = TrustedRoot::parse(directory.path()).expect("root should be valid");
        let managed = ManagedRoot::open(&root).expect("root should open");
        let nested = SiteRelativePath::parse("sites/example").expect("path should be valid");
        managed
            .create_dir_all(&nested)
            .expect("directory should be created");
        fs::write(directory.path().join("sites/example/state"), "ready")
            .expect("state should be written");
        let state = SiteRelativePath::parse("sites/example/state").expect("path should be valid");
        assert_eq!(managed.read_to_string(&state).unwrap(), "ready");
    }

    #[test]
    fn open_managed_dir_scopes_operations_beneath_the_subdirectory() {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let root = TrustedRoot::parse(directory.path()).expect("root should be valid");
        let managed = ManagedRoot::open(&root).expect("root should open");
        let site_dir = SiteRelativePath::parse("sites/example").expect("path should be valid");
        managed
            .create_dir_all(&site_dir)
            .expect("site directory should be created");

        let site_root = managed
            .open_managed_dir(&site_dir)
            .expect("subdirectory should open");
        let marker = SiteRelativePath::parse("marker").expect("path should be valid");
        site_root
            .create_new(&marker, b"scoped")
            .expect("write beneath the subdirectory should succeed");

        assert_eq!(
            fs::read_to_string(directory.path().join("sites/example/marker")).unwrap(),
            "scoped"
        );
    }

    #[test]
    fn create_dir_fails_instead_of_reusing_an_existing_directory() {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let root = TrustedRoot::parse(directory.path()).expect("root should be valid");
        let managed = ManagedRoot::open(&root).expect("root should open");
        let path = SiteRelativePath::parse("fresh").expect("path should be valid");

        managed
            .create_dir(&path)
            .expect("first create should succeed");
        assert!(managed.create_dir(&path).is_err());
    }

    #[test]
    fn symlink_and_rename_perform_an_atomic_swap() {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let root = TrustedRoot::parse(directory.path()).expect("root should be valid");
        let managed = ManagedRoot::open(&root).expect("root should open");
        let a = SiteRelativePath::parse("releases/a").expect("path should be valid");
        let b = SiteRelativePath::parse("releases/b").expect("path should be valid");
        let current = SiteRelativePath::parse("current").expect("path should be valid");
        let temp = SiteRelativePath::parse("current.tmp").expect("path should be valid");

        managed
            .symlink(&current, &a)
            .expect("initial link should be created");
        assert_eq!(managed.read_link(&current).unwrap(), a.as_path());

        managed
            .symlink(&temp, &b)
            .expect("temp link should be created");
        managed
            .rename(&temp, &current)
            .expect("rename should swap the link atomically");

        assert_eq!(managed.read_link(&current).unwrap(), b.as_path());
        assert!(!directory.path().join("current.tmp").exists());
    }

    #[test]
    fn symlink_does_not_replace_an_existing_link() {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let root = TrustedRoot::parse(directory.path()).expect("root should be valid");
        let managed = ManagedRoot::open(&root).expect("root should open");
        let a = SiteRelativePath::parse("releases/a").expect("path should be valid");
        let b = SiteRelativePath::parse("releases/b").expect("path should be valid");
        let current = SiteRelativePath::parse("current").expect("path should be valid");

        managed
            .symlink(&current, &a)
            .expect("first link should succeed");
        assert!(managed.symlink(&current, &b).is_err());
    }

    #[test]
    fn remove_dir_all_deletes_a_directory_and_its_contents() {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let root = TrustedRoot::parse(directory.path()).expect("root should be valid");
        let managed = ManagedRoot::open(&root).expect("root should open");
        let nested = SiteRelativePath::parse("releases/a/nested").expect("path should be valid");
        managed
            .create_dir_all(&nested)
            .expect("nested directory should be created");

        let target = SiteRelativePath::parse("releases/a").expect("path should be valid");
        managed
            .remove_dir_all(&target)
            .expect("removal should succeed");
        assert!(!directory.path().join("releases/a").exists());
    }

    #[test]
    fn write_atomic_replaces_contents_and_leaves_no_temp_file() {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let root = TrustedRoot::parse(directory.path()).expect("root should be valid");
        let managed = ManagedRoot::open(&root).expect("root should open");
        let path = SiteRelativePath::parse("state.json").expect("path should be valid");

        managed
            .write_atomic(&path, b"first")
            .expect("initial write should succeed");
        assert_eq!(managed.read_to_string(&path).unwrap(), "first");

        managed
            .write_atomic(&path, b"second")
            .expect("overwrite should succeed");
        assert_eq!(managed.read_to_string(&path).unwrap(), "second");
        assert!(!directory.path().join("state.json.tmp").exists());
    }

    #[test]
    fn append_creates_the_file_and_grows_it_across_calls() {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let root = TrustedRoot::parse(directory.path()).expect("root should be valid");
        let managed = ManagedRoot::open(&root).expect("root should open");
        let path = SiteRelativePath::parse("events.jsonl").expect("path should be valid");

        managed
            .append(&path, b"first\n")
            .expect("first append should create the file");
        managed
            .append(&path, b"second\n")
            .expect("second append should not truncate");

        assert_eq!(managed.read_to_string(&path).unwrap(), "first\nsecond\n");
    }

    #[test]
    fn rejects_preexisting_symlink_escape() {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let outside = tempfile::tempdir().expect("outside directory should exist");
        fs::write(outside.path().join("secret"), "secret").expect("secret should be written");
        symlink(outside.path(), directory.path().join("escape"))
            .expect("symlink should be created");

        let root = TrustedRoot::parse(directory.path()).expect("root should be valid");
        let managed = ManagedRoot::open(&root).expect("root should open");
        let secret = SiteRelativePath::parse(Path::new("escape/secret"))
            .expect("relative path should be valid");
        assert!(managed.read_to_string(&secret).is_err());
    }

    #[test]
    fn read_bytes_reads_arbitrary_binary_content() {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let root = TrustedRoot::parse(directory.path()).expect("root should be valid");
        let managed = ManagedRoot::open(&root).expect("root should open");
        let path = SiteRelativePath::parse("blob").expect("path should be valid");
        fs::write(directory.path().join("blob"), [0u8, 159, 255, 1])
            .expect("blob should be written");

        assert_eq!(managed.read_bytes(&path).unwrap(), vec![0u8, 159, 255, 1]);
    }

    #[test]
    fn write_new_executable_replaces_content_and_sets_the_executable_bit() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let root = TrustedRoot::parse(directory.path()).expect("root should be valid");
        let managed = ManagedRoot::open(&root).expect("root should open");
        let path = SiteRelativePath::parse("ops-engine").expect("path should be valid");

        managed
            .write_new_executable(&path, b"first binary")
            .expect("first write should succeed");
        let first_metadata = fs::metadata(directory.path().join("ops-engine")).unwrap();
        assert_eq!(first_metadata.permissions().mode() & 0o777, 0o755);
        assert_eq!(
            fs::read(directory.path().join("ops-engine")).unwrap(),
            b"first binary"
        );

        managed
            .write_new_executable(&path, b"second binary, longer than the first")
            .expect("overwrite should succeed");
        assert_eq!(
            fs::read(directory.path().join("ops-engine")).unwrap(),
            b"second binary, longer than the first"
        );
        assert!(!directory.path().join("ops-engine.tmp").exists());
    }

    #[test]
    fn open_or_create_file_creates_once_and_reuses_the_same_file_on_later_calls() {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let root = TrustedRoot::parse(directory.path()).expect("root should be valid");
        let managed = ManagedRoot::open(&root).expect("root should open");
        let path = SiteRelativePath::parse("reused").expect("path should be valid");

        {
            let mut file = managed
                .open_or_create_file(&path)
                .expect("first open should create the file");
            file.write_all(b"first").expect("write should succeed");
        }

        let mut file = managed
            .open_or_create_file(&path)
            .expect("second open should reuse the existing file, not fail or truncate it");
        file.seek(SeekFrom::Start(0)).expect("seek should succeed");
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .expect("read should succeed");
        assert_eq!(
            contents, "first",
            "open_or_create_file must not truncate an existing file"
        );
    }
}
