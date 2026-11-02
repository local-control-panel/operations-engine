use super::*;

/// Runs `body` as one recorded operation: resource locks on every path in
/// `lock_paths`, idempotency admission, a transaction record and an audit
/// entry in the `site-root` scope.
pub(super) fn transact<T, F>(
    engine_state: &ManagedRoot,
    operation: &'static str,
    request_id: RequestId,
    key: Option<&IdempotencyKey>,
    lock_paths: &[&Path],
    body: F,
) -> Result<T, Error>
where
    T: Serialize + DeserializeOwned,
    F: FnOnce() -> Result<T, Error>,
{
    transact_in(
        SCOPE,
        engine_state,
        operation,
        request_id,
        key,
        lock_paths,
        body,
    )
}

/// `transact` in a named scope, for the file operations of `site_file`
/// (`site-file`), which share this scaffolding and error type.
pub(crate) fn transact_in<T, F>(
    scope_name: &'static str,
    engine_state: &ManagedRoot,
    operation: &'static str,
    request_id: RequestId,
    key: Option<&IdempotencyKey>,
    lock_paths: &[&Path],
    body: F,
) -> Result<T, Error>
where
    T: Serialize + DeserializeOwned,
    F: FnOnce() -> Result<T, Error>,
{
    let scope = open_named_scope(engine_state, scope_name).map_err(Error::Io)?;
    let _resource_locks = resource_lock::acquire_many(engine_state, lock_paths, request_id)
        .map_err(|_| Error::ResourceBusy)?;

    let admitted =
        match preflight::run(&scope, request_id, key, operation).map_err(Error::Preflight)? {
            preflight::Outcome::Replay(original) => return replay(&scope, original, operation),
            preflight::Outcome::Proceed(admitted) => admitted,
        };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path = transaction_path(request_id);
    let audit_path = rel("audit/events.jsonl");

    let value = match body() {
        Ok(value) => value,
        Err(error) => return Err(fail(&scope, &state_path, &audit_path, state, error)),
    };

    let encoded = serde_json::to_value(&value).expect("operation results always serialize");
    state
        .mark_committed(encoded.clone())
        .expect("state is always InProgress at this point");
    if state::save(&scope, &state_path, &state).is_err() {
        drop(lock);
        return Err(Error::PostCommit(encoded));
    }
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(request_id, true, None),
    );
    drop(lock);
    Ok(value)
}

/// The content root a request addresses: the first one that already has an
/// entry named after any of `names`, else the first configured one.
pub(super) fn pick_content_root<'a>(
    content_roots: &'a [TrustedRoot],
    names: &[PathBuf],
) -> Result<&'a TrustedRoot, Error> {
    content_roots
        .iter()
        .find(|root| {
            names
                .iter()
                .any(|name| std::fs::symlink_metadata(root.as_path().join(name)).is_ok())
        })
        .or_else(|| content_roots.first())
        .ok_or_else(|| Error::Io(io::Error::other("no content root is configured")))
}

pub(crate) fn refuse_system_dir(content_root: &TrustedRoot) -> Result<(), Error> {
    if SYSTEM_DIRS
        .iter()
        .any(|dir| content_root.as_path() == Path::new(dir))
    {
        return Err(Error::UnsafeContentRoot);
    }
    Ok(())
}

/// `ELOOP`/`ENOTDIR` from a no-follow directory open mean the entry is a
/// symlink or not a directory.
pub(crate) fn open_error(error: io::Error) -> Error {
    match error.raw_os_error() {
        Some(code) if code == libc::ELOOP || code == libc::ENOTDIR => Error::UnsafePath,
        _ => Error::Io(error),
    }
}
