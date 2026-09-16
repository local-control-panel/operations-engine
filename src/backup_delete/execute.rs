use crate::{
    backup_delete::{DeleteResult, OPERATION, Request},
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
use sha2::{Digest, Sha256};
use std::{
    fmt::Write as _,
    time::{SystemTime, UNIX_EPOCH},
};

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub backup_root: &'a ManagedRoot,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Cancelled,
    PostCommit { result: DeleteResult },
    Replayed { code: ErrorCode, message: String },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another deletion for this backup is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before backup deletion ran".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            _ => (ErrorCode::Internal, "internal backup deletion error".into()),
        }
    }
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &crate::process::CancellationToken,
) -> Result<DeleteResult, Error> {
    let scope = open_state(
        ctx.engine_state,
        req.relative_path.as_path().as_os_str().as_encoded_bytes(),
    )
    .map_err(Error::Io)?;
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
    let state_path = state_path(req.request_id);
    let audit_path = audit_path();
    let pre_commit = PreCommit::new(cancel.clone());
    if pre_commit.check().is_err() {
        return Err(fail(
            &scope,
            &state_path,
            &audit_path,
            state,
            Error::Cancelled,
        ));
    }

    let deleted = match ctx.backup_root.remove_file(&req.relative_path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(fail(
                &scope,
                &state_path,
                &audit_path,
                state,
                Error::Io(error),
            ));
        }
    };
    let _ = pre_commit.commit();
    let result = DeleteResult {
        deleted,
        completed_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
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

fn open_state(root: &ManagedRoot, identity: &[u8]) -> std::io::Result<ManagedRoot> {
    let digest = Sha256::digest(identity);
    let mut hash = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut hash, "{byte:02x}").expect("String writes cannot fail");
    }
    let path = SiteRelativePath::parse(format!("backup-delete/{hash}")).unwrap();
    root.create_dir_all(&path)?;
    let scope = root.open_managed_dir(&path)?;
    for child in ["locks", "transactions", "audit"] {
        scope.create_dir_all(&SiteRelativePath::parse(child).unwrap())?;
    }
    Ok(scope)
}
fn state_path(id: crate::transaction::RequestId) -> SiteRelativePath {
    SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap()
}
fn audit_path() -> SiteRelativePath {
    SiteRelativePath::parse("audit/events.jsonl").unwrap()
}
fn replay(scope: &ManagedRoot, id: crate::transaction::RequestId) -> Result<DeleteResult, Error> {
    let loaded = state::load(scope, &state_path(id))
        .map_err(|error| Error::Io(std::io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != OPERATION {
        return Err(Error::Io(std::io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => {
            serde_json::from_value(loaded.outcome.unwrap().result.unwrap())
                .map_err(|error| Error::Io(std::io::Error::other(error)))
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
    state_path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut state: crate::transaction::state::TransactionState,
    error: Error,
) -> Error {
    let (code, message) = error.protocol();
    let _ = state.mark_failed(code, message);
    let _ = state::save(scope, state_path, &state);
    let _ = audit::append(
        scope,
        audit_path,
        &AuditRecord::result(state.request_id, false, Some(code)),
    );
    error
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn deletes_only_through_the_open_backup_root_and_replays() {
        let directory = tempfile::tempdir().unwrap();
        let state_path = directory.path().join("state");
        let backup_path = directory.path().join("backups");
        fs::create_dir(&state_path).unwrap();
        fs::create_dir(&backup_path).unwrap();
        fs::write(backup_path.join("site.sql"), "dump").unwrap();
        let state =
            ManagedRoot::open(&crate::site::TrustedRoot::parse(&state_path).unwrap()).unwrap();
        let backups =
            ManagedRoot::open(&crate::site::TrustedRoot::parse(&backup_path).unwrap()).unwrap();
        let request = Request::parse(
            r#"{"filePath":"/root/db-backups/site.sql"}"#,
            "123e4567-e89b-12d3-a456-426614174000",
            Some("delete-site-backup"),
        )
        .unwrap();
        let first = execute(
            &Context {
                engine_state: &state,
                backup_root: &backups,
            },
            &request,
            &crate::process::CancellationToken::default(),
        )
        .unwrap();
        assert!(first.deleted);
        assert!(!backup_path.join("site.sql").exists());
        let replayed = execute(
            &Context {
                engine_state: &state,
                backup_root: &backups,
            },
            &request,
            &crate::process::CancellationToken::default(),
        )
        .unwrap();
        assert!(replayed.deleted);
    }
}
