use std::io;

use cap_std::{ambient_authority, fs::Dir};

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

    pub fn create_dir_all(&self, path: &SiteRelativePath) -> io::Result<()> {
        self.directory.create_dir_all(path.as_path())
    }

    pub fn read_to_string(&self, path: &SiteRelativePath) -> io::Result<String> {
        self.directory.read_to_string(path.as_path())
    }

    pub fn exists(&self, path: &SiteRelativePath) -> bool {
        self.directory.exists(path.as_path())
    }
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
