use std::{
    ffi::{CStr, CString},
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    permissions::{
        FixWorldWritableRequest, FixWorldWritableResult, WORLD_WRITABLE_OPERATION,
        execute::{directory_names, open_directory, stat_fd},
    },
    process::CancellationToken,
    site::SiteRelativePath,
    transaction::{
        audit::{self, AuditRecord},
        commit::PreCommit,
        state::{self, TransactionStatus},
    },
};

#[derive(Debug)]
pub enum FixWorldWritableError {
    Io(io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Cancelled,
    PostCommitRecordFailed { result: FixWorldWritableResult },
    Replayed { code: ErrorCode, message: String },
}

impl FixWorldWritableError {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another permissions repair is already in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request for this idempotency key is still in progress".into(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before the commit point".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommitRecordFailed { .. } => (
                ErrorCode::Internal,
                "internal world-writable repair error".into(),
            ),
        }
    }
}

pub fn execute(
    engine_state: &ManagedRoot,
    request: &FixWorldWritableRequest,
    cancellation: &CancellationToken,
) -> Result<FixWorldWritableResult, FixWorldWritableError> {
    let scope = open_state(engine_state).map_err(FixWorldWritableError::Io)?;
    let admitted = match preflight::run(
        &scope,
        request.request_id,
        request.idempotency_key.as_ref(),
        WORLD_WRITABLE_OPERATION,
    )
    .map_err(FixWorldWritableError::Preflight)?
    {
        preflight::Outcome::Replay(original) => return replay(&scope, original),
        preflight::Outcome::Proceed(admitted) => admitted,
    };
    let preflight::Admitted { lock, mut state } = admitted;
    let transaction_path = state_path(request.request_id);
    let audit_path = audit_path();
    let pre_commit = PreCommit::new(cancellation.clone());
    if pre_commit.check().is_err() {
        return Err(fail(
            &scope,
            &transaction_path,
            &audit_path,
            state,
            FixWorldWritableError::Cancelled,
        ));
    }

    let _post_commit = pre_commit.commit();
    let hardened_entries = harden_tree(&request.root).map_err(|error| {
        fail(
            &scope,
            &transaction_path,
            &audit_path,
            state.clone(),
            FixWorldWritableError::Io(error),
        )
    })?;
    let result = FixWorldWritableResult {
        processed_roots: 1,
        hardened_entries,
        completed_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    state
        .mark_committed(serde_json::to_value(&result).expect("result serializes"))
        .expect("in progress");
    if state::save(&scope, &transaction_path, &state).is_err() {
        drop(lock);
        return Err(FixWorldWritableError::PostCommitRecordFailed { result });
    }
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(request.request_id, true, None),
    );
    drop(lock);
    Ok(result)
}

fn harden_tree(path: &std::path::Path) -> io::Result<u64> {
    let root = open_directory(path)?;
    let root_stat = stat_fd(root.as_raw_fd())?;
    let mut hardened = harden_directory(&root, root_stat.st_dev as u64)?;
    if root_stat.st_mode & libc::S_IWOTH != 0 {
        chmod_fd(&root, root_stat.st_mode & 0o7777 & !libc::S_IWOTH)?;
        hardened += 1;
    }
    Ok(hardened)
}

fn harden_directory(directory: &OwnedFd, device: u64) -> io::Result<u64> {
    let mut hardened = 0;
    for name in directory_names(directory.as_raw_fd())? {
        let name = CString::new(name.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains NUL"))?;
        let child = match open_entry(directory.as_raw_fd(), &name) {
            Ok(child) => child,
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => continue,
            Err(error) => return Err(error),
        };
        let stat = stat_fd(child.as_raw_fd())?;
        if stat.st_dev as u64 != device || stat.st_mode & libc::S_IFMT == libc::S_IFLNK {
            continue;
        }
        let kind = stat.st_mode & libc::S_IFMT;
        if kind != libc::S_IFDIR && kind != libc::S_IFREG {
            continue;
        }
        if kind == libc::S_IFDIR {
            hardened += harden_directory(&child, device)?;
        }
        if stat.st_mode & libc::S_IWOTH != 0 {
            chmod_fd(&child, stat.st_mode & 0o7777 & !libc::S_IWOTH)?;
            hardened += 1;
        }
    }
    Ok(hardened)
}

fn open_entry(parent: libc::c_int, name: &CStr) -> io::Result<OwnedFd> {
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn chmod_fd(fd: &OwnedFd, mode: libc::mode_t) -> io::Result<()> {
    if unsafe { libc::fchmod(fd.as_raw_fd(), mode) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn open_state(engine_state: &ManagedRoot) -> io::Result<ManagedRoot> {
    let relative = SiteRelativePath::parse("permissions").expect("literal is valid");
    engine_state.create_dir_all(&relative)?;
    let scoped = engine_state.open_managed_dir(&relative)?;
    for sub in ["locks", "transactions", "audit"] {
        scoped.create_dir_all(&SiteRelativePath::parse(sub).unwrap())?;
    }
    Ok(scoped)
}

fn state_path(id: crate::transaction::RequestId) -> SiteRelativePath {
    SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap()
}

fn audit_path() -> SiteRelativePath {
    SiteRelativePath::parse("audit/events.jsonl").unwrap()
}

fn replay(
    scope: &ManagedRoot,
    original: crate::transaction::RequestId,
) -> Result<FixWorldWritableResult, FixWorldWritableError> {
    let loaded = state::load(scope, &state_path(original)).map_err(|error| {
        FixWorldWritableError::Io(io::Error::other(format!("state load failed: {error:?}")))
    })?;
    if loaded.operation != WORLD_WRITABLE_OPERATION {
        return Err(FixWorldWritableError::Io(io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(FixWorldWritableError::ReplayInProgress),
        TransactionStatus::Committed => {
            serde_json::from_value(loaded.outcome.unwrap().result.unwrap())
                .map_err(|error| FixWorldWritableError::Io(io::Error::other(error)))
        }
        TransactionStatus::Failed => {
            let outcome = loaded.outcome.unwrap();
            Err(FixWorldWritableError::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}

fn fail(
    scope: &ManagedRoot,
    transaction_path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut state: crate::transaction::state::TransactionState,
    error: FixWorldWritableError,
) -> FixWorldWritableError {
    let (code, message) = error.protocol();
    let _ = state.mark_failed(code, message);
    let _ = state::save(scope, transaction_path, &state);
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
    use crate::{filesystem::ManagedRoot, site::TrustedRoot};
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn removes_only_world_write_and_skips_symlinks() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("content");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("file"), b"x").unwrap();
        std::fs::write(&outside, b"x").unwrap();
        std::fs::set_permissions(root.join("file"), std::fs::Permissions::from_mode(0o676))
            .unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o666)).unwrap();
        symlink(&outside, root.join("escape")).unwrap();

        assert_eq!(harden_tree(&root).unwrap(), 1);
        assert_eq!(
            std::fs::metadata(root.join("file"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o674
        );
        assert_eq!(
            std::fs::metadata(&outside).unwrap().permissions().mode() & 0o777,
            0o666
        );
    }

    #[test]
    fn records_and_replays_a_completed_hardening_walk() {
        let temp = tempfile::tempdir().unwrap();
        let content = temp.path().join("content");
        let state = temp.path().join("state");
        std::fs::create_dir_all(&content).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(content.join("file"), b"x").unwrap();
        let roots = [TrustedRoot::parse(&content).unwrap()];
        let request = FixWorldWritableRequest::parse(
            &content,
            &roots,
            "123e4567-e89b-12d3-a456-426614174000",
            Some("world-writable-replay"),
        )
        .unwrap();
        let managed = ManagedRoot::open(&TrustedRoot::parse(&state).unwrap()).unwrap();

        let first = execute(&managed, &request, &CancellationToken::default()).unwrap();
        let replayed = execute(&managed, &request, &CancellationToken::default()).unwrap();
        assert_eq!(replayed.hardened_entries, first.hardened_entries);
        assert_eq!(
            replayed.completed_at_unix_secs,
            first.completed_at_unix_secs
        );
    }
}
