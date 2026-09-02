use std::io::{self, Write};

use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};

use crate::site::{SiteRelativePath, TrustedRoot};

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

    pub fn create_dir_all(&self, path: &SiteRelativePath) -> io::Result<()> {
        self.directory.create_dir_all(path.as_path())
    }

    pub fn read_to_string(&self, path: &SiteRelativePath) -> io::Result<String> {
        self.directory.read_to_string(path.as_path())
    }

    pub fn exists(&self, path: &SiteRelativePath) -> bool {
        self.directory.exists(path.as_path())
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

    pub fn remove_file(&self, path: &SiteRelativePath) -> io::Result<()> {
        self.directory.remove_file(path.as_path())
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
}

fn temp_sibling_path(path: &SiteRelativePath) -> io::Result<SiteRelativePath> {
    let mut temp = path.as_path().as_os_str().to_os_string();
    temp.push(".tmp");
    SiteRelativePath::parse(temp).map_err(|_| io::Error::other("invalid temp path"))
}

#[cfg(all(test, unix))]
mod tests {
    use std::{fs, os::unix::fs::symlink, path::Path};

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
}
