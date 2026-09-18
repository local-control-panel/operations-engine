use crate::{
    backup_deploy::{
        Request,
        staging::{self, ActivationResult},
    },
    filesystem::ManagedRoot,
    process::{self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination},
};
use std::time::Duration;

#[derive(Debug)]
pub enum Error {
    Files(staging::Error),
    Crontab(process::ProcessRunError),
    CrontabRejected,
    RollbackFailed,
}

/// Activates the file bundle first and installs the complete root crontab as
/// the final commit step. `crontab -` is atomic from the caller's perspective:
/// a rejected input leaves the prior tab installed, so only the file bundle
/// needs explicit rollback on failure.
pub fn activate(
    root: &ManagedRoot,
    request: &Request,
    request_id: &str,
    crontab_program: &str,
    cancellation: &CancellationToken,
) -> Result<ActivationResult, Error> {
    let staged = staging::stage(root, request, request_id).map_err(Error::Files)?;
    let activated = staged.activate_files().map_err(Error::Files)?;
    let output = match process::run_with_stdin_bytes(
        &ProcessRequest::new(crontab_program).args(["-"]),
        request.crontab.as_bytes(),
        &ProcessLimits {
            timeout: Duration::from_secs(30),
            max_stdout_bytes: 64 * 1024,
            max_stderr_bytes: 64 * 1024,
        },
        cancellation,
    ) {
        Ok(value) => value,
        Err(error) => {
            activated.rollback().map_err(|_| Error::RollbackFailed)?;
            return Err(Error::Crontab(error));
        }
    };
    if !matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        activated.rollback().map_err(|_| Error::RollbackFailed)?;
        return Err(Error::CrontabRejected);
    }
    Ok(activated.commit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    fn request() -> Request {
        Request::parse(r##"{"rcloneConfig":"new","backupConfig":"{}","notifyConfig":"{}","agentScript":"#!/bin/sh\nexit 0","crontab":"0 2 * * * true\n"}"##).unwrap()
    }

    fn script(directory: &std::path::Path, exit: i32) -> String {
        let path = directory.join(format!("fake-crontab-{exit}"));
        fs::write(&path, format!("#!/bin/sh\ncat >/dev/null\nexit {exit}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn rejected_crontab_rolls_back_the_file_bundle() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("rclone.conf"), "old").unwrap();
        let root =
            ManagedRoot::open(&crate::site::TrustedRoot::parse(directory.path()).unwrap()).unwrap();
        let result = activate(
            &root,
            &request(),
            ID,
            &script(directory.path(), 1),
            &CancellationToken::default(),
        );
        assert!(matches!(result, Err(Error::CrontabRejected)));
        assert_eq!(
            fs::read_to_string(directory.path().join("rclone.conf")).unwrap(),
            "old"
        );
        assert!(!directory.path().join("backup.conf").exists());
    }

    #[test]
    fn accepted_crontab_commits_files_and_cleans_staging() {
        let directory = tempfile::tempdir().unwrap();
        let root =
            ManagedRoot::open(&crate::site::TrustedRoot::parse(directory.path()).unwrap()).unwrap();
        let result = activate(
            &root,
            &request(),
            ID,
            &script(directory.path(), 0),
            &CancellationToken::default(),
        )
        .unwrap();
        assert!(!result.staging_cleanup_incomplete);
        assert_eq!(
            fs::read_to_string(directory.path().join("rclone.conf")).unwrap(),
            "new"
        );
        assert!(!directory.path().join(".backup-activate").join(ID).exists());
    }
}
