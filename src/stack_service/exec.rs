use super::*;

pub(crate) fn compose(
    ctx: &Context<'_>,
    stage: Stage,
    tail: &[&str],
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<String, Error> {
    let mut argv = vec![
        "compose",
        "-p",
        COMPOSE_PROJECT,
        "--env-file",
        ".env",
        "-f",
        "stack/docker-compose.yml",
    ];
    argv.extend_from_slice(tail);
    docker(ctx, stage, &argv, timeout, cancel)
}

/// Runs `docker <argv>` in the stack directory and returns its stdout.
pub(super) fn docker(
    ctx: &Context<'_>,
    stage: Stage,
    argv: &[&str],
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<String, Error> {
    let output = process::run(
        &ProcessRequest::new(ctx.docker)
            .args(argv.iter().copied())
            .current_dir(ctx.stack_dir),
        &ProcessLimits {
            timeout,
            max_stdout_bytes: MAX_OUTPUT_BYTES,
            max_stderr_bytes: MAX_OUTPUT_BYTES,
        },
        cancel,
    )
    .map_err(|error| Error::Run(stage, error))?;
    if !matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        return Err(Error::Rejected(
            stage,
            SubprocessDiagnostics::from_output(ctx.docker, &output),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout.bytes).into_owned())
}

/// Stack lock, then this scope's preflight (lock + idempotency), then
/// `body`, then the transaction record and audit entry.
pub(crate) fn run_admitted<T, F>(
    ctx: &Context<'_>,
    operation: &'static str,
    request_id: RequestId,
    key: Option<&IdempotencyKey>,
    body: F,
) -> Result<T, Error>
where
    T: Serialize + for<'de> Deserialize<'de>,
    F: FnOnce() -> Result<T, Error>,
{
    let scope = open_scope(ctx.engine_state).map_err(Error::Io)?;
    let stack_scope = crate::stack_deploy::open_scope(ctx.engine_state).map_err(Error::Io)?;
    let _stack_lock = crate::stack_deploy::acquire_stack_lock(&stack_scope, request_id)
        .map_err(|_| Error::StackBusy)?;

    let admitted =
        match preflight::run(&scope, request_id, key, operation).map_err(Error::Preflight)? {
            preflight::Outcome::Replay(original) => return replay(&scope, operation, original),
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

pub(super) fn open_scope(engine_state: &ManagedRoot) -> io::Result<ManagedRoot> {
    engine_state.create_dir_all(&rel(SCOPE))?;
    let scope = engine_state.open_managed_dir(&rel(SCOPE))?;
    for child in ["locks", "transactions", "audit"] {
        scope.create_dir_all(&rel(child))?;
    }
    Ok(scope)
}

pub(super) fn replay<T>(
    scope: &ManagedRoot,
    operation: &'static str,
    original: RequestId,
) -> Result<T, Error>
where
    T: for<'de> Deserialize<'de>,
{
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

pub(super) fn rel(path: &str) -> SiteRelativePath {
    SiteRelativePath::parse(path).expect("literal path is valid")
}

pub(super) fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
