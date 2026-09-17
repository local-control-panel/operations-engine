use crate::{
    backup_deploy::Request, filesystem::ManagedRoot, site::SiteRelativePath, transaction::RequestId,
};

#[derive(Debug)]
pub enum Error {
    InvalidRequestId,
    Io(std::io::Error),
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
}
