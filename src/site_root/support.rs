use super::*;

/// A real directory (not a symlink to one) named `domain` directly under
/// `root`.
pub(super) fn is_real_dir(root: &TrustedRoot, domain: &Domain) -> bool {
    std::fs::symlink_metadata(root.as_path().join(domain.as_str()))
        .is_ok_and(|metadata| metadata.file_type().is_dir())
}

/// Anything at all named `domain` directly under `root`, including a
/// dangling symlink (`symlink_metadata` does not follow it).
pub(super) fn entry_exists(root: &TrustedRoot, domain: &Domain) -> bool {
    std::fs::symlink_metadata(root.as_path().join(domain.as_str())).is_ok()
}

pub(super) fn domain_rel(domain: &Domain) -> SiteRelativePath {
    SiteRelativePath::parse(domain.as_str()).expect("a validated domain is one path component")
}

pub(super) fn open_scope(engine_state: &ManagedRoot) -> io::Result<ManagedRoot> {
    open_named_scope(engine_state, SCOPE)
}

pub(super) fn open_named_scope(engine_state: &ManagedRoot, name: &str) -> io::Result<ManagedRoot> {
    engine_state.create_dir_all(&rel(name))?;
    let scope = engine_state.open_managed_dir(&rel(name))?;
    for child in ["locks", "transactions", "audit"] {
        scope.create_dir_all(&rel(child))?;
    }
    Ok(scope)
}

pub(super) fn replay<T: DeserializeOwned>(
    scope: &ManagedRoot,
    original: RequestId,
    operation: &str,
) -> Result<T, Error> {
    let loaded = state::load(scope, &transaction_path(original))
        .map_err(|error| Error::Io(io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != operation {
        return Err(Error::Io(io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => loaded
            .outcome
            .and_then(|outcome| outcome.result)
            .ok_or_else(|| Error::Io(io::Error::other("committed outcome has no result")))
            .and_then(|value| {
                serde_json::from_value(value).map_err(|error| Error::Io(io::Error::other(error)))
            }),
        TransactionStatus::Failed => {
            let outcome = loaded
                .outcome
                .expect("a failed transaction always has an outcome");
            Err(Error::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}

pub(super) fn fail(
    scope: &ManagedRoot,
    state_path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut state: TransactionState,
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

pub(super) fn transaction_path(request_id: RequestId) -> SiteRelativePath {
    rel(&format!("transactions/{request_id}.json"))
}

pub(crate) fn rel(path: &str) -> SiteRelativePath {
    SiteRelativePath::parse(path).expect("literal path is valid")
}

pub(crate) fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
