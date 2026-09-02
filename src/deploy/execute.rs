//! Phase 4, item 1 (of the current list): the assembled `site.deploy`
//! pipeline — preflight, resolve, stage, validate, the atomic switch, and
//! result/audit persistence — as one function. Every step already exists
//! and is independently tested in its own module; this only orders them,
//! threads cancellation through the pre-commit/post-commit boundary
//! (`transaction::commit`), and records what happened.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    config::SiteManifest,
    deploy::{
        DeployRequest, DeployResult, OPERATION, ReleaseId, activate, cleanup, resolve, staging,
        validate,
    },
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{self, CancellationToken},
    site::{SiteRelativePath, TrustedRoot},
    transaction::{
        RequestId,
        audit::{self, AuditRecord},
        commit::PreCommit,
        state::{self, TransactionState, TransactionStatus},
    },
};

/// The engine-wide roots and already-opened state directory a deploy needs.
/// Bundled because they are request-independent — the caller resolves them
/// once (from `EngineConfig` and `SiteManifest`) and reuses them across
/// requests, unlike `DeployRequest`.
pub struct DeployContext<'a> {
    /// The specific configured content root this site's manifest resolves
    /// under. Picking the right one when more than one is configured is
    /// the caller's responsibility — not yet solved generically (see the
    /// `content_roots` note in `PLAN.md`).
    pub content_root: &'a TrustedRoot,
    pub credential_root: &'a TrustedRoot,
    /// The engine-wide state root, opened once. `execute` scopes it down
    /// to this one site via `preflight::open_site_state`.
    pub engine_state: &'a ManagedRoot,
}

#[derive(Debug)]
pub enum DeployError {
    Io(std::io::Error),
    /// The manifest's `contentRoot` isn't the standard
    /// `sites/<siteId>/current` this engine's staging/activation code
    /// assumes. Refusing to guess at a non-standard layout rather than
    /// silently deploying to the wrong place.
    ContentRootMismatch,
    Preflight(preflight::Error),
    /// The idempotency key was already claimed, but the original attempt
    /// is still `InProgress` — nothing to replay yet. The caller should
    /// report this as a conflict and let the client retry later.
    ReplayInProgress,
    Identity(staging::IdentityError),
    Resolve(resolve::Error),
    Staging(staging::Error),
    Validate(validate::Error),
    Activate(activate::Error),
    State(state::StateError),
    Cancelled,
    /// The deployment itself succeeded — `current` was switched — but its
    /// `TransactionState` could not be saved afterward. Carries the result
    /// so the caller never loses it even though persistence failed; see
    /// the exit criterion that post-commit failures must still report that
    /// deployment changed state.
    PostCommitRecordFailed {
        result: DeployResult,
        cause: state::StateError,
    },
    /// A replayed request whose original attempt failed. Carries the
    /// original attempt's stable code and safe message so a retry reports
    /// the same outcome instead of silently succeeding or inventing a new
    /// error.
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl DeployError {
    /// The stable code and a safe, generic message for this failure —
    /// used both as the response to the caller and as what gets persisted
    /// into the failed `TransactionState` (see `docs/protocol.md`'s
    /// `details` allowlist: no subprocess output, paths, or command lines
    /// beyond what `SubprocessDiagnostics` already redacted).
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Io(_) | Self::ContentRootMismatch | Self::State(_) => {
                (ErrorCode::Internal, "internal deploy error".to_owned())
            }
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another mutation is already in progress for this site".to_owned(),
            ),
            Self::Preflight(_) => (ErrorCode::Internal, "preflight failed".to_owned()),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request for this idempotency key is still in progress".to_owned(),
            ),
            Self::Identity(staging::IdentityError::Run(error)) => (
                process::spawn_error_code(error),
                "could not resolve the site's system identity".to_owned(),
            ),
            Self::Identity(_) => (
                ErrorCode::Internal,
                "could not resolve the site's system identity".to_owned(),
            ),
            Self::Resolve(resolve::Error::InvalidRemoteUrl) => (
                ErrorCode::InvalidInput,
                "repository URL is not valid".to_owned(),
            ),
            Self::Resolve(resolve::Error::NotAuthorized) => (
                ErrorCode::InvalidInput,
                "revision is not the current tip of an allowed branch".to_owned(),
            ),
            Self::Resolve(resolve::Error::Run(error)) => (
                process::spawn_error_code(error),
                "could not query the remote repository".to_owned(),
            ),
            Self::Resolve(resolve::Error::SubprocessFailed(_)) => (
                ErrorCode::SubprocessFailed,
                "querying the remote repository failed".to_owned(),
            ),
            Self::Staging(staging::Error::InvalidRemoteUrl) => (
                ErrorCode::InvalidInput,
                "repository URL is not valid".to_owned(),
            ),
            Self::Staging(staging::Error::RevisionMismatch) => (
                ErrorCode::Conflict,
                "the remote branch changed while the release was being staged".to_owned(),
            ),
            Self::Staging(staging::Error::Clone(error) | staging::Error::Verify(error)) => (
                process::spawn_error_code(error),
                "staging the release failed".to_owned(),
            ),
            Self::Staging(staging::Error::CloneFailed(_)) => (
                ErrorCode::SubprocessFailed,
                "cloning the release failed".to_owned(),
            ),
            Self::Staging(_) => (ErrorCode::Internal, "staging the release failed".to_owned()),
            Self::Validate(validate::Error::Run(error)) => (
                process::spawn_error_code(error),
                "validating the release failed".to_owned(),
            ),
            Self::Validate(_) => (
                ErrorCode::SubprocessFailed,
                "validating the release failed".to_owned(),
            ),
            Self::Activate(_) => (
                ErrorCode::Internal,
                "activating the release failed".to_owned(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before the commit point".to_owned(),
            ),
            Self::PostCommitRecordFailed { .. } => {
                (ErrorCode::Internal, "internal deploy error".to_owned())
            }
            Self::Replayed { code, message } => (*code, message.clone()),
        }
    }
}

pub fn execute(
    context: &DeployContext<'_>,
    manifest: &SiteManifest,
    request: &DeployRequest,
    cancellation: &CancellationToken,
) -> Result<DeployResult, DeployError> {
    if manifest.site_id != request.site_id {
        return Err(DeployError::ContentRootMismatch);
    }
    let expected_current = SiteRelativePath::parse(format!("sites/{}/current", request.site_id))
        .expect("a canonical SiteId always yields a valid relative path");
    if manifest.content_root != expected_current {
        return Err(DeployError::ContentRootMismatch);
    }

    let site_state = preflight::open_site_state(context.engine_state, request.site_id)
        .map_err(DeployError::Io)?;

    let admitted = match preflight::run(
        &site_state,
        request.request_id,
        request.idempotency_key.as_ref(),
        OPERATION,
    )
    .map_err(DeployError::Preflight)?
    {
        preflight::Outcome::Replay(original) => return replay(&site_state, original),
        preflight::Outcome::Proceed(admitted) => admitted,
    };
    let preflight::Admitted { lock, mut state } = admitted;

    let state_path = state_path_for(request.request_id);
    let audit_path = audit_log_path();
    let pre_commit = PreCommit::new(cancellation.clone());

    let identity = match staging::resolve_site_identity(&manifest.site_user, cancellation) {
        Ok(identity) => identity,
        Err(error) => {
            return Err(fail(
                &site_state,
                &state_path,
                &audit_path,
                state,
                DeployError::Identity(error),
            ));
        }
    };

    if pre_commit.check().is_err() {
        return Err(fail(
            &site_state,
            &state_path,
            &audit_path,
            state,
            DeployError::Cancelled,
        ));
    }

    let credential_path = context.credential_root.join(
        &SiteRelativePath::parse(manifest.repository.credential_id.to_string())
            .expect("a canonical SiteId always yields a valid relative path"),
    );

    let branch = match resolve::resolve_allowed_revision(
        &manifest.repository.url,
        &manifest.repository.allowed_branches,
        &request.revision,
        Some(&credential_path),
        cancellation,
    ) {
        Ok(branch) => branch,
        Err(error) => {
            return Err(fail(
                &site_state,
                &state_path,
                &audit_path,
                state,
                DeployError::Resolve(error),
            ));
        }
    };

    if pre_commit.check().is_err() {
        return Err(fail(
            &site_state,
            &state_path,
            &audit_path,
            state,
            DeployError::Cancelled,
        ));
    }

    let release_id = ReleaseId::from(request.request_id);
    let staged = match staging::prepare(
        context.content_root,
        request.site_id,
        release_id,
        identity,
        &manifest.repository.url,
        &branch,
        &request.revision,
        Some(&credential_path),
        cancellation,
    ) {
        Ok(staged) => staged,
        Err(error) => {
            return Err(fail(
                &site_state,
                &state_path,
                &audit_path,
                state,
                DeployError::Staging(error),
            ));
        }
    };

    if pre_commit.check().is_err() {
        return Err(fail(
            &site_state,
            &state_path,
            &audit_path,
            state,
            DeployError::Cancelled,
        ));
    }

    if let Err(error) =
        validate::validate_staged_release(&staged.absolute_path, identity, cancellation)
    {
        return Err(fail(
            &site_state,
            &state_path,
            &audit_path,
            state,
            DeployError::Validate(error),
        ));
    }

    if pre_commit.check().is_err() {
        return Err(fail(
            &site_state,
            &state_path,
            &audit_path,
            state,
            DeployError::Cancelled,
        ));
    }

    let previous = match activate::activate(context.content_root, request.site_id, release_id) {
        Ok(previous) => previous,
        Err(error) => {
            return Err(fail(
                &site_state,
                &state_path,
                &audit_path,
                state,
                DeployError::Activate(error),
            ));
        }
    };

    // Commit point: `current` now points at `release_id`, and nothing from
    // here may be aborted by cancellation — the deployment already
    // happened. Only its bookkeeping remains.
    let _post_commit = pre_commit.commit();
    drop(lock);

    let result = DeployResult {
        release_id,
        previous_release_id: previous,
        commit: request.revision.clone(),
        activated_at_unix_secs: unix_now_secs(),
    };
    let result_value = serde_json::to_value(&result).expect("DeployResult always serializes");
    state
        .mark_committed(result_value)
        .expect("state is always InProgress at this point");

    if let Err(cause) = state::save(&site_state, &state_path, &state) {
        return Err(DeployError::PostCommitRecordFailed { result, cause });
    }
    let _ = audit::append(
        &site_state,
        &audit_path,
        &AuditRecord::result(request.request_id, true, None),
    );

    // Best-effort: retention is a disk-usage concern, not a correctness
    // one, and must never turn this successful deploy into a reported
    // failure.
    let _ = cleanup::prune_old_releases(
        context.content_root,
        request.site_id,
        release_id,
        cleanup::DEFAULT_RETAIN_COUNT,
    );

    Ok(result)
}

fn replay(site_state: &ManagedRoot, original: RequestId) -> Result<DeployResult, DeployError> {
    let original_state =
        state::load(site_state, &state_path_for(original)).map_err(DeployError::State)?;
    match original_state.status {
        TransactionStatus::InProgress => Err(DeployError::ReplayInProgress),
        TransactionStatus::Committed => {
            let outcome = original_state
                .outcome
                .expect("a committed transaction always has an outcome");
            let result_value = outcome
                .result
                .expect("a committed outcome always has a result");
            serde_json::from_value(result_value)
                .map_err(|_| DeployError::State(state::StateError::Corrupt))
        }
        TransactionStatus::Failed => {
            let outcome = original_state
                .outcome
                .expect("a failed transaction always has an outcome");
            Err(DeployError::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}

/// Records a pre-commit failure — transitions `state` to `Failed`, saves
/// it, and appends a result audit event — then returns `error` unchanged
/// so call sites can write `return Err(fail(..., error))`. Persistence
/// failures here are swallowed deliberately: the original `error` is
/// already the most actionable thing to return, and nothing was activated,
/// so there is no successful deployment this call site could otherwise
/// lose track of.
fn fail(
    site_state: &ManagedRoot,
    state_path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut state: TransactionState,
    error: DeployError,
) -> DeployError {
    let (code, message) = error.protocol();
    let _ = state.mark_failed(code, message);
    let _ = state::save(site_state, state_path, &state);
    let _ = audit::append(
        site_state,
        audit_path,
        &AuditRecord::result(state.request_id, false, Some(code)),
    );
    error
}

fn state_path_for(request_id: RequestId) -> SiteRelativePath {
    SiteRelativePath::parse(format!("transactions/{request_id}.json"))
        .expect("a canonical RequestId always yields a valid relative path")
}

fn audit_log_path() -> SiteRelativePath {
    SiteRelativePath::parse("audit/events.jsonl").expect("literal path is valid")
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
