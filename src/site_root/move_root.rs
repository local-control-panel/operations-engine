use super::*;

pub struct MoveRequest {
    pub from: Domain,
    pub to: Domain,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl MoveRequest {
    pub fn parse(
        from: &str,
        to: &str,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let from = parse_domain(from)?;
        let to = parse_domain(to)?;
        if from.as_str() == to.as_str() {
            return Err(RequestError::SameDomain);
        }
        let request_id =
            RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?;
        let idempotency_key = key
            .map(IdempotencyKey::parse)
            .transpose()
            .map_err(|_| RequestError::InvalidIdempotencyKey)?;
        Ok(Self {
            from,
            to,
            request_id,
            idempotency_key,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MoveResult {
    pub from: String,
    pub to: String,
    pub completed_at_unix_secs: u64,
}

/// Moves `<root>/<from>` to `<root>/<to>` inside the first content root
/// that has a real directory named `from`.
pub fn move_root(
    engine_state: &ManagedRoot,
    content_roots: &[TrustedRoot],
    req: &MoveRequest,
) -> Result<MoveResult, Error> {
    // Pick the root before admission so the locks and a replay see the same
    // paths: the one holding the source, else the one already holding the
    // target (a retried, already-committed move), else the first. Whether
    // the move is possible is checked under the locks.
    let Some(content_root) = content_roots
        .iter()
        .find(|root| is_real_dir(root, &req.from))
        .or_else(|| {
            content_roots
                .iter()
                .find(|root| entry_exists(root, &req.to))
        })
        .or_else(|| content_roots.first())
    else {
        return Err(Error::SourceMissing);
    };
    let from_path = content_root.as_path().join(req.from.as_str());
    let to_path = content_root.as_path().join(req.to.as_str());

    let scope = open_scope(engine_state).map_err(Error::Io)?;
    let _resource_locks =
        resource_lock::acquire_pair(engine_state, &from_path, &to_path, req.request_id)
            .map_err(|_| Error::ResourceBusy)?;

    let admitted = match preflight::run(
        &scope,
        req.request_id,
        req.idempotency_key.as_ref(),
        MOVE_OPERATION,
    )
    .map_err(Error::Preflight)?
    {
        preflight::Outcome::Replay(original) => return replay(&scope, original, MOVE_OPERATION),
        preflight::Outcome::Proceed(admitted) => admitted,
    };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path = transaction_path(req.request_id);
    let audit_path = rel("audit/events.jsonl");

    let value = match rename(content_root, req, from_path, to_path) {
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
        &AuditRecord::result(req.request_id, true, None),
    );
    drop(lock);
    Ok(value)
}

pub(super) fn rename(
    content_root: &TrustedRoot,
    req: &MoveRequest,
    from_path: PathBuf,
    to_path: PathBuf,
) -> Result<MoveResult, Error> {
    let root = ManagedRoot::open(content_root).map_err(Error::Io)?;
    let from = domain_rel(&req.from);
    let to = domain_rel(&req.to);
    // Checked under the locks: the pre-lock look only chose the root.
    if !is_real_dir(content_root, &req.from) {
        return Err(Error::SourceMissing);
    }
    if entry_exists(content_root, &req.to) {
        return Err(Error::TargetExists);
    }
    root.rename(&from, &to).map_err(Error::Io)?;
    Ok(MoveResult {
        from: from_path.to_string_lossy().into_owned(),
        to: to_path.to_string_lossy().into_owned(),
        completed_at_unix_secs: unix_now_secs(),
    })
}
