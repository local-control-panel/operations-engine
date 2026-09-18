use crate::{
    backup_deploy::{ActivateResult, OPERATION, OperationRequest, activation},
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    site::SiteRelativePath,
    transaction::{
        audit::{self, AuditRecord},
        commit::PreCommit,
        state::{self, TransactionStatus},
    },
};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub config_root: &'a ManagedRoot,
    pub crontab_program: &'a str,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Cancelled,
    Activation(activation::Error),
    PostCommit { result: ActivateResult },
    Replayed { code: ErrorCode, message: String },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another backup configuration activation is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before backup configuration activation".into(),
            ),
            Self::Activation(activation::Error::CrontabRejected) => (
                ErrorCode::SubprocessFailed,
                "crontab rejected backup configuration".into(),
            ),
            Self::Activation(activation::Error::Crontab(error)) => (
                crate::process::spawn_error_code(error),
                "could not install backup crontab".into(),
            ),
            Self::Activation(activation::Error::RollbackFailed) => (
                ErrorCode::Internal,
                "backup configuration rollback failed".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            _ => (
                ErrorCode::Internal,
                "internal backup configuration activation error".into(),
            ),
        }
    }
}

pub fn execute(
    ctx: &Context<'_>,
    req: &OperationRequest,
    cancel: &crate::process::CancellationToken,
) -> Result<ActivateResult, Error> {
    let scope_path = SiteRelativePath::parse("backup-activate").unwrap();
    ctx.engine_state
        .create_dir_all(&scope_path)
        .map_err(Error::Io)?;
    let scope = ctx
        .engine_state
        .open_managed_dir(&scope_path)
        .map_err(Error::Io)?;
    for child in ["locks", "transactions", "audit"] {
        scope
            .create_dir_all(&SiteRelativePath::parse(child).unwrap())
            .map_err(Error::Io)?;
    }
    let admitted = match preflight::run(
        &scope,
        req.request_id,
        req.idempotency_key.as_ref(),
        OPERATION,
    )
    .map_err(Error::Preflight)?
    {
        preflight::Outcome::Replay(id) => return replay(&scope, id),
        preflight::Outcome::Proceed(value) => value,
    };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path =
        SiteRelativePath::parse(format!("transactions/{}.json", req.request_id)).unwrap();
    let audit_path = SiteRelativePath::parse("audit/events.jsonl").unwrap();
    if PreCommit::new(cancel.clone()).check().is_err() {
        return Err(fail(
            &scope,
            &state_path,
            &audit_path,
            state,
            Error::Cancelled,
        ));
    }
    let activated = match activation::activate(
        ctx.config_root,
        &req.config,
        &req.request_id.to_string(),
        ctx.crontab_program,
        cancel,
    ) {
        Ok(value) => value,
        Err(error) => {
            return Err(fail(
                &scope,
                &state_path,
                &audit_path,
                state,
                Error::Activation(error),
            ));
        }
    };
    let result = ActivateResult {
        activated_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        staging_cleanup_incomplete: activated.staging_cleanup_incomplete,
    };
    state
        .mark_committed(serde_json::to_value(&result).unwrap())
        .unwrap();
    if state::save(&scope, &state_path, &state).is_err() {
        drop(lock);
        return Err(Error::PostCommit { result });
    }
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(req.request_id, true, None),
    );
    drop(lock);
    Ok(result)
}

fn replay(scope: &ManagedRoot, id: crate::transaction::RequestId) -> Result<ActivateResult, Error> {
    let path = SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap();
    let loaded = state::load(scope, &path)
        .map_err(|e| Error::Io(std::io::Error::other(format!("{e:?}"))))?;
    if loaded.operation != OPERATION {
        return Err(Error::Io(std::io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => {
            serde_json::from_value(loaded.outcome.unwrap().result.unwrap())
                .map_err(|e| Error::Io(std::io::Error::other(e)))
        }
        TransactionStatus::Failed => {
            let outcome = loaded.outcome.unwrap();
            Err(Error::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}

fn fail(
    scope: &ManagedRoot,
    path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut state: crate::transaction::state::TransactionState,
    error: Error,
) -> Error {
    let (code, message) = error.protocol();
    let _ = state.mark_failed(code, message);
    let _ = state::save(scope, path, &state);
    let _ = audit::append(
        scope,
        audit_path,
        &AuditRecord::result(state.request_id, false, Some(code)),
    );
    error
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    #[test]
    fn commits_audits_and_replays_without_running_twice() {
        let directory = tempfile::tempdir().unwrap();
        let state_path = directory.path().join("state");
        let config_path = directory.path().join("config");
        fs::create_dir(&state_path).unwrap();
        fs::create_dir(&config_path).unwrap();
        let marker = directory.path().join("runs");
        let crontab = directory.path().join("fake-crontab");
        fs::write(
            &crontab,
            format!(
                "#!/bin/sh\ncat >/dev/null\necho run >> '{}'\n",
                marker.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&crontab, fs::Permissions::from_mode(0o755)).unwrap();
        let state =
            ManagedRoot::open(&crate::site::TrustedRoot::parse(&state_path).unwrap()).unwrap();
        let config =
            ManagedRoot::open(&crate::site::TrustedRoot::parse(&config_path).unwrap()).unwrap();
        let request = OperationRequest::parse(
            r##"{"rcloneConfig":"new","backupConfig":"{}","notifyConfig":"{}","agentScript":"#!/bin/sh\nexit 0","crontab":"0 2 * * * true\n"}"##,
            "123e4567-e89b-12d3-a456-426614174000", Some("backup-config-v1"),
        ).unwrap();
        let context = Context {
            engine_state: &state,
            config_root: &config,
            crontab_program: crontab.to_str().unwrap(),
        };

        let first = execute(
            &context,
            &request,
            &crate::process::CancellationToken::default(),
        )
        .unwrap();
        let replay = execute(
            &context,
            &request,
            &crate::process::CancellationToken::default(),
        )
        .unwrap();

        assert_eq!(first.activated_at_unix_secs, replay.activated_at_unix_secs);
        assert_eq!(fs::read_to_string(marker).unwrap().lines().count(), 1);
        assert!(
            state
                .read_to_string(
                    &SiteRelativePath::parse("backup-activate/audit/events.jsonl").unwrap()
                )
                .unwrap()
                .contains("backup.activateConfig")
        );
    }
}
