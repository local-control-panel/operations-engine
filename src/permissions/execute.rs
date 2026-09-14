use std::{
    ffi::{CStr, CString, OsString},
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::ffi::{OsStrExt, OsStringExt},
    },
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    permissions::{FixOwnershipRequest, FixOwnershipResult, OPERATION},
    process::CancellationToken,
    site::SiteRelativePath,
    transaction::{
        audit::{self, AuditRecord},
        commit::PreCommit,
        state::{self, TransactionStatus},
    },
};

#[derive(Debug)]
pub enum FixOwnershipError {
    Io(io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Cancelled,
    PostCommitRecordFailed { result: FixOwnershipResult },
    Replayed { code: ErrorCode, message: String },
}

impl FixOwnershipError {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another ownership repair is already in progress".into(),
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
                "internal ownership repair error".into(),
            ),
        }
    }
}

pub fn execute(
    engine_state: &ManagedRoot,
    request: &FixOwnershipRequest,
    cancellation: &CancellationToken,
) -> Result<FixOwnershipResult, FixOwnershipError> {
    let scope = open_state(engine_state).map_err(FixOwnershipError::Io)?;
    let admitted = match preflight::run(
        &scope,
        request.request_id,
        request.idempotency_key.as_ref(),
        OPERATION,
    )
    .map_err(FixOwnershipError::Preflight)?
    {
        preflight::Outcome::Replay(original) => return replay(&scope, original),
        preflight::Outcome::Proceed(admitted) => admitted,
    };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path = state_path(request.request_id);
    let audit_path = audit_path();
    let pre_commit = PreCommit::new(cancellation.clone());
    if pre_commit.check().is_err() {
        return Err(fail(
            &scope,
            &state_path,
            &audit_path,
            state,
            FixOwnershipError::Cancelled,
        ));
    }

    let _post_commit = pre_commit.commit();
    let mut repaired_entries = 0;
    for target in &request.targets {
        repaired_entries +=
            repair_tree(&target.root, target.uid, target.gid, &[]).map_err(|e| {
                fail(
                    &scope,
                    &state_path,
                    &audit_path,
                    state.clone(),
                    FixOwnershipError::Io(e),
                )
            })?;
    }
    let exclusions: Vec<&Path> = request
        .targets
        .iter()
        .map(|target| target.root.as_path())
        .collect();
    repaired_entries += repair_tree(
        &request.default.root,
        request.default.uid,
        request.default.gid,
        &exclusions,
    )
    .map_err(|e| {
        fail(
            &scope,
            &state_path,
            &audit_path,
            state.clone(),
            FixOwnershipError::Io(e),
        )
    })?;
    drop(lock);

    let result = FixOwnershipResult {
        processed_roots: request.targets.len() + 1,
        repaired_entries,
        completed_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    state
        .mark_committed(serde_json::to_value(&result).expect("result serializes"))
        .expect("in progress");
    if state::save(&scope, &state_path, &state).is_err() {
        return Err(FixOwnershipError::PostCommitRecordFailed { result });
    }
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(request.request_id, true, None),
    );
    Ok(result)
}

fn repair_tree(path: &Path, uid: u32, gid: u32, exclusions: &[&Path]) -> io::Result<u64> {
    let root = open_directory(path)?;
    let root_stat = stat_fd(root.as_raw_fd())?;
    let relative_exclusions: Vec<Vec<OsString>> = exclusions
        .iter()
        .filter_map(|excluded| excluded.strip_prefix(path).ok())
        .map(|relative| {
            relative
                .components()
                .map(|part| part.as_os_str().to_owned())
                .collect()
        })
        .collect();
    let mut repaired = repair_directory(
        &root,
        uid,
        gid,
        root_stat.st_dev as u64,
        &relative_exclusions,
        &[],
    )?;
    if root_stat.st_uid != uid || root_stat.st_gid != gid {
        if unsafe { libc::fchown(root.as_raw_fd(), uid, gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        repaired += 1;
    }
    Ok(repaired)
}

pub(super) fn open_directory(path: &Path) -> io::Result<OwnedFd> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn repair_directory(
    directory: &OwnedFd,
    uid: u32,
    gid: u32,
    device: u64,
    exclusions: &[Vec<OsString>],
    relative: &[OsString],
) -> io::Result<u64> {
    let mut repaired = 0;
    for name in directory_names(directory.as_raw_fd())? {
        let mut child_relative = relative.to_vec();
        child_relative.push(name.clone());
        if exclusions
            .iter()
            .any(|excluded| excluded == &child_relative)
        {
            continue;
        }
        let name = CString::new(name.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains NUL"))?;
        let stat = stat_at(directory.as_raw_fd(), &name)?;
        if stat.st_dev as u64 != device || stat.st_mode & libc::S_IFMT == libc::S_IFLNK {
            continue;
        }
        if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
            let child = open_directory_at(directory.as_raw_fd(), &name)?;
            repaired += repair_directory(&child, uid, gid, device, exclusions, &child_relative)?;
        }
        if (stat.st_uid != uid || stat.st_gid != gid)
            && unsafe {
                libc::fchownat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    uid,
                    gid,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
        {
            return Err(io::Error::last_os_error());
        } else if stat.st_uid != uid || stat.st_gid != gid {
            repaired += 1;
        }
    }
    Ok(repaired)
}

pub(super) fn open_directory_at(parent: libc::c_int, name: &CStr) -> io::Result<OwnedFd> {
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

pub(super) fn stat_fd(fd: libc::c_int) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::uninit();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { stat.assume_init() })
    }
}

pub(super) fn stat_at(parent: libc::c_int, name: &CStr) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::uninit();
    if unsafe {
        libc::fstatat(
            parent,
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { stat.assume_init() })
    }
}

pub(super) fn directory_names(fd: libc::c_int) -> io::Result<Vec<OsString>> {
    let duplicate = unsafe { libc::dup(fd) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        unsafe { libc::close(duplicate) };
        return Err(io::Error::last_os_error());
    }
    let mut names = Vec::new();
    loop {
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if bytes != b"." && bytes != b".." {
            names.push(OsString::from_vec(bytes.to_vec()));
        }
    }
    if unsafe { libc::closedir(stream) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(names)
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
) -> Result<FixOwnershipResult, FixOwnershipError> {
    let loaded = state::load(scope, &state_path(original)).map_err(|e| {
        FixOwnershipError::Io(io::Error::other(format!("state load failed: {e:?}")))
    })?;
    if loaded.operation != OPERATION {
        return Err(FixOwnershipError::Io(io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(FixOwnershipError::ReplayInProgress),
        TransactionStatus::Committed => {
            serde_json::from_value(loaded.outcome.unwrap().result.unwrap())
                .map_err(|e| FixOwnershipError::Io(io::Error::other(e)))
        }
        TransactionStatus::Failed => {
            let outcome = loaded.outcome.unwrap();
            Err(FixOwnershipError::Replayed {
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
    error: FixOwnershipError,
) -> FixOwnershipError {
    let (code, message) = error.protocol();
    let _ = state.mark_failed(code, message.clone());
    let _ = state::save(scope, state_path, &state);
    let _ = audit::append(
        scope,
        audit_path,
        &AuditRecord::result(state.request_id, false, Some(code)),
    );
    error
}

#[cfg(test)]
mod tests {
    use super::{execute, repair_tree};
    use crate::{
        filesystem::ManagedRoot, permissions::FixOwnershipRequest, process::CancellationToken,
        site::TrustedRoot,
    };
    use std::os::unix::fs::{MetadataExt, symlink};

    #[test]
    fn skips_symlinks_and_excluded_site_roots() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let excluded = root.join("site");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&excluded).unwrap();
        std::fs::write(root.join("orphan"), b"x").unwrap();
        std::fs::write(excluded.join("owned"), b"x").unwrap();
        std::fs::write(&outside, b"outside").unwrap();
        symlink(&outside, root.join("escape")).unwrap();

        let repaired = repair_tree(
            &root,
            std::fs::metadata(&root).unwrap().uid(),
            std::fs::metadata(&root).unwrap().gid(),
            &[excluded.as_path()],
        )
        .unwrap();

        assert_eq!(repaired, 0);
        assert_eq!(std::fs::read(&outside).unwrap(), b"outside");
    }

    #[test]
    fn records_and_replays_a_completed_ownership_walk() {
        let temp = tempfile::tempdir().unwrap();
        let content = temp.path().join("content");
        let state = temp.path().join("state");
        std::fs::create_dir_all(&content).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(content.join("file"), b"x").unwrap();
        let metadata = std::fs::metadata(&content).unwrap();
        let json = serde_json::json!({
            "default": { "root": content, "uid": metadata.uid(), "gid": metadata.gid() },
            "targets": []
        })
        .to_string();
        let roots = [TrustedRoot::parse(&content).unwrap()];
        let request = FixOwnershipRequest::parse(
            &json,
            &roots,
            "123e4567-e89b-12d3-a456-426614174000",
            Some("ownership-replay"),
        )
        .unwrap();
        let managed = ManagedRoot::open(&TrustedRoot::parse(&state).unwrap()).unwrap();

        let first = execute(&managed, &request, &CancellationToken::default()).unwrap();
        let replayed = execute(&managed, &request, &CancellationToken::default()).unwrap();
        assert_eq!(first.processed_roots, 1);
        assert_eq!(first.repaired_entries, 0);
        assert_eq!(replayed.repaired_entries, first.repaired_entries);
        assert_eq!(
            replayed.completed_at_unix_secs,
            first.completed_at_unix_secs
        );
    }
}
