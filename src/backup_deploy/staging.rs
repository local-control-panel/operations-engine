use crate::{
    backup_deploy::{ARTIFACTS, Request},
    filesystem::ManagedRoot,
    site::SiteRelativePath,
    transaction::RequestId,
};

#[derive(Debug)]
pub enum Error {
    InvalidRequestId,
    Io(std::io::Error),
    RollbackFailed,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ActivationResult {
    pub staging_cleanup_incomplete: bool,
}

struct Previous {
    path: SiteRelativePath,
    content: Option<Vec<u8>>,
    mode: Option<u32>,
}

pub struct StagedConfig<'a> {
    root: &'a ManagedRoot,
    directory: SiteRelativePath,
}

impl StagedConfig<'_> {
    pub fn directory(&self) -> &SiteRelativePath {
        &self.directory
    }

    pub fn discard(self) -> std::io::Result<()> {
        self.root.remove_dir_all(&self.directory)
    }

    pub fn activate(self) -> Result<ActivationResult, Error> {
        self.root
            .create_dir_all(&SiteRelativePath::parse("agents").unwrap())
            .map_err(Error::Io)?;
        let mut committed = Vec::new();
        for artifact in ARTIFACTS {
            let live = SiteRelativePath::parse(artifact.relative_path).unwrap();
            let staged = SiteRelativePath::parse(format!(
                "{}/{}",
                self.directory.as_path().display(),
                artifact.relative_path
            ))
            .unwrap();
            let previous = if self.root.exists(&live) {
                let content = match self.root.read_bytes(&live) {
                    Ok(v) => v,
                    Err(e) => return Err(rollback(self.root, &committed, e)),
                };
                let mode = match self.root.mode(&live) {
                    Ok(v) => v,
                    Err(e) => return Err(rollback(self.root, &committed, e)),
                };
                Previous {
                    path: live,
                    content: Some(content),
                    mode: Some(mode),
                }
            } else {
                Previous {
                    path: live,
                    content: None,
                    mode: None,
                }
            };
            let content = match self.root.read_bytes(&staged) {
                Ok(v) => v,
                Err(e) => return Err(rollback(self.root, &committed, e)),
            };
            if let Err(error) = self
                .root
                .write_atomic(&previous.path, &content)
                .and_then(|_| self.root.set_mode(&previous.path, artifact.mode))
            {
                committed.push(previous);
                return Err(rollback(self.root, &committed, error));
            }
            committed.push(previous);
        }
        Ok(ActivationResult {
            staging_cleanup_incomplete: self.root.remove_dir_all(&self.directory).is_err(),
        })
    }
}

fn rollback(root: &ManagedRoot, committed: &[Previous], original: std::io::Error) -> Error {
    let mut failed = false;
    for previous in committed.iter().rev() {
        let restored = match (&previous.content, previous.mode) {
            (Some(content), Some(mode)) => root
                .write_atomic(&previous.path, content)
                .and_then(|_| root.set_mode(&previous.path, mode)),
            (None, None) => match root.remove_file(&previous.path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e),
            },
            _ => unreachable!(),
        };
        failed |= restored.is_err();
    }
    if failed {
        Error::RollbackFailed
    } else {
        Error::Io(original)
    }
}

/// Writes the complete file bundle beneath a fresh request-scoped directory.
/// Nothing live is replaced here; dropping without `discard` intentionally
/// leaves recovery evidence for a later reconciliation pass.
pub fn stage<'a>(
    root: &'a ManagedRoot,
    request: &Request,
    request_id: &str,
) -> Result<StagedConfig<'a>, Error> {
    let request_id = RequestId::parse(request_id).map_err(|_| Error::InvalidRequestId)?;
    let directory = SiteRelativePath::parse(format!(".backup-activate/{request_id}"))
        .expect("a validated request id forms a safe relative path");
    root.create_dir_all(&SiteRelativePath::parse(".backup-activate").unwrap())
        .map_err(Error::Io)?;
    root.create_dir(&directory).map_err(Error::Io)?;

    let result = (|| {
        let agents = SiteRelativePath::parse(format!("{}/agents", directory.as_path().display()))
            .expect("fixed child path is valid");
        root.create_dir(&agents)?;
        for artifact in request.artifacts() {
            let path = SiteRelativePath::parse(format!(
                "{}/{}",
                directory.as_path().display(),
                artifact.relative_path
            ))
            .expect("fixed artifact path is valid");
            root.create_new(&path, artifact.content.as_bytes())?;
            root.set_mode(&path, artifact.mode)?;
        }
        Ok::<(), std::io::Error>(())
    })();

    if let Err(error) = result {
        let _ = root.remove_dir_all(&directory);
        return Err(Error::Io(error));
    }
    Ok(StagedConfig { root, directory })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    fn request() -> Request {
        Request::parse(r##"{"rcloneConfig":"[remote]","backupConfig":"{}","notifyConfig":"{}","agentScript":"#!/bin/sh\nexit 0","crontab":""}"##).unwrap()
    }

    #[test]
    fn stages_the_complete_bundle_with_exact_modes_and_discards_it() {
        let directory = tempfile::tempdir().unwrap();
        let root =
            ManagedRoot::open(&crate::site::TrustedRoot::parse(directory.path()).unwrap()).unwrap();
        let staged = stage(&root, &request(), ID).unwrap();
        let base = directory.path().join(staged.directory().as_path());
        for (path, mode) in [
            ("rclone.conf", 0o600),
            ("backup.conf", 0o600),
            ("notify.conf", 0o600),
            ("agents/backup-agent.sh", 0o700),
        ] {
            assert_eq!(
                fs::metadata(base.join(path)).unwrap().permissions().mode() & 0o777,
                mode
            );
        }
        staged.discard().unwrap();
        assert!(!base.exists());
    }

    #[test]
    fn rejects_invalid_request_ids_before_creating_staging_state() {
        let directory = tempfile::tempdir().unwrap();
        let root =
            ManagedRoot::open(&crate::site::TrustedRoot::parse(directory.path()).unwrap()).unwrap();
        assert!(matches!(
            stage(&root, &request(), "../bad"),
            Err(Error::InvalidRequestId)
        ));
        assert!(!directory.path().join(".backup-activate").exists());
    }

    #[test]
    fn activates_all_live_files_and_removes_staging() {
        let directory = tempfile::tempdir().unwrap();
        let root =
            ManagedRoot::open(&crate::site::TrustedRoot::parse(directory.path()).unwrap()).unwrap();
        let staged = stage(&root, &request(), ID).unwrap();
        assert_eq!(
            staged.activate().unwrap(),
            ActivationResult {
                staging_cleanup_incomplete: false
            }
        );
        assert_eq!(
            fs::read_to_string(directory.path().join("rclone.conf")).unwrap(),
            "[remote]"
        );
        assert_eq!(
            fs::metadata(directory.path().join("agents/backup-agent.sh"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(!directory.path().join(".backup-activate").join(ID).exists());
    }

    #[test]
    fn mid_commit_failure_restores_previous_files_and_modes() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("rclone.conf"), "old-rclone").unwrap();
        fs::write(directory.path().join("backup.conf"), "old-backup").unwrap();
        fs::set_permissions(
            directory.path().join("rclone.conf"),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        fs::set_permissions(
            directory.path().join("backup.conf"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        fs::create_dir(directory.path().join("notify.conf")).unwrap();
        let root =
            ManagedRoot::open(&crate::site::TrustedRoot::parse(directory.path()).unwrap()).unwrap();
        let staged = stage(&root, &request(), ID).unwrap();

        assert!(staged.activate().is_err());
        assert_eq!(
            fs::read_to_string(directory.path().join("rclone.conf")).unwrap(),
            "old-rclone"
        );
        assert_eq!(
            fs::read_to_string(directory.path().join("backup.conf")).unwrap(),
            "old-backup"
        );
        assert_eq!(
            fs::metadata(directory.path().join("rclone.conf"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        assert_eq!(
            fs::metadata(directory.path().join("backup.conf"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        assert!(directory.path().join(".backup-activate").join(ID).exists());
    }
}
