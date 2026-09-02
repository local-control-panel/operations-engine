//! Phase 5: the assembled `site.rollback` pipeline — preflight,
//! eligibility, identity, integrity validation, the atomic switch, and
//! result/audit persistence. Deliberately mirrors `deploy::execute::execute`
//! step for step; see that module's doc comments for the reasoning behind
//! each shared primitive. The two steps that are genuinely rollback-specific
//! are `eligibility::resolve_retained_release` (item 1) and nothing else —
//! validation (item 2) and the atomic switch (item 3) are the exact same
//! `deploy::validate`/`deploy::activate` functions deploy already uses,
//! called here unchanged rather than forked into rollback-owned copies.
//!
//! Retention interaction (item 4): a successful rollback runs the same
//! best-effort `deploy::cleanup::prune_old_releases` deploy runs, passing
//! the newly active release as `active_release`. Rollback does not reset
//! "recency" for the release it switches away from — cleanup's age
//! ordering is still each release directory's own filesystem modification
//! time (set once, at staging), not last-activation time. A previous
//! release therefore remains a valid, retained rollback target immediately
//! after this rollback (nothing here removes it), but its eligibility for
//! a *later* rollback is still bounded by the same retention count a
//! subsequent deploy would apply — this is a deliberate, documented
//! approximation shared with deploy's own retention behavior, not a new
//! guarantee invented for rollback.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    config::SiteManifest,
    deploy::{activate, cleanup, staging, validate},
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{self, CancellationToken},
    rollback::{OPERATION, RollbackRequest, RollbackResult, eligibility},
    site::{SiteRelativePath, TrustedRoot},
    transaction::{
        RequestId,
        audit::{self, AuditRecord},
        commit::PreCommit,
        state::{self, TransactionState, TransactionStatus},
    },
};

/// The engine-wide roots and already-opened state directory a rollback
/// needs. Smaller than `deploy::execute::DeployContext`: rollback never
/// fetches from a remote, so it needs no `credential_root`.
pub struct RollbackContext<'a> {
    pub content_root: &'a TrustedRoot,
    pub engine_state: &'a ManagedRoot,
}

#[derive(Debug)]
pub enum RollbackError {
    Io(std::io::Error),
    /// Mirrors `DeployError::ContentRootMismatch`: the manifest's
    /// `contentRoot` isn't the standard `sites/<siteId>/current` this
    /// engine's activation code assumes.
    ContentRootMismatch,
    Preflight(preflight::Error),
    /// The idempotency key was already claimed, but the original attempt
    /// is still `InProgress` — nothing to replay yet.
    ReplayInProgress,
    Identity(staging::IdentityError),
    /// No retained release matches the requested `ReleaseId`.
    NotFound(eligibility::Error),
    Validate(validate::Error),
    Activate(activate::Error),
    State(state::StateError),
    Cancelled,
    /// The rollback itself succeeded — `current` was switched — but its
    /// `TransactionState` could not be saved afterward.
    PostCommitRecordFailed {
        result: RollbackResult,
        cause: state::StateError,
    },
    /// A replayed request whose original attempt failed.
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl RollbackError {
    /// The stable code and a safe, generic message for this failure — see
    /// `DeployError::protocol` for the same contract.
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Io(_) | Self::ContentRootMismatch | Self::State(_) => {
                (ErrorCode::Internal, "internal rollback error".to_owned())
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
            Self::NotFound(_) => (
                ErrorCode::InvalidInput,
                "release is not a retained rollback target for this site".to_owned(),
            ),
            Self::Validate(validate::Error::Run(error)) => (
                process::spawn_error_code(error),
                "validating the release failed".to_owned(),
            ),
            Self::Validate(_) => (
                ErrorCode::SubprocessFailed,
                "the retained release failed integrity validation".to_owned(),
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
                (ErrorCode::Internal, "internal rollback error".to_owned())
            }
            Self::Replayed { code, message } => (*code, message.clone()),
        }
    }
}

pub fn execute(
    context: &RollbackContext<'_>,
    manifest: &SiteManifest,
    request: &RollbackRequest,
    cancellation: &CancellationToken,
) -> Result<RollbackResult, RollbackError> {
    if manifest.site_id != request.site_id {
        return Err(RollbackError::ContentRootMismatch);
    }
    let expected_current = SiteRelativePath::parse(format!("sites/{}/current", request.site_id))
        .expect("a canonical SiteId always yields a valid relative path");
    if manifest.content_root != expected_current {
        return Err(RollbackError::ContentRootMismatch);
    }

    let site_state = preflight::open_site_state(context.engine_state, request.site_id)
        .map_err(RollbackError::Io)?;

    let admitted = match preflight::run(
        &site_state,
        request.request_id,
        request.idempotency_key.as_ref(),
        OPERATION,
    )
    .map_err(RollbackError::Preflight)?
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
                RollbackError::Identity(error),
            ));
        }
    };

    if pre_commit.check().is_err() {
        return Err(fail(
            &site_state,
            &state_path,
            &audit_path,
            state,
            RollbackError::Cancelled,
        ));
    }

    let release_path = match eligibility::resolve_retained_release(
        context.content_root,
        request.site_id,
        request.release_id,
    ) {
        Ok(path) => path,
        Err(error) => {
            return Err(fail(
                &site_state,
                &state_path,
                &audit_path,
                state,
                RollbackError::NotFound(error),
            ));
        }
    };

    if pre_commit.check().is_err() {
        return Err(fail(
            &site_state,
            &state_path,
            &audit_path,
            state,
            RollbackError::Cancelled,
        ));
    }

    if let Err(error) = validate::validate_staged_release(&release_path, identity, cancellation) {
        return Err(fail(
            &site_state,
            &state_path,
            &audit_path,
            state,
            RollbackError::Validate(error),
        ));
    }

    if pre_commit.check().is_err() {
        return Err(fail(
            &site_state,
            &state_path,
            &audit_path,
            state,
            RollbackError::Cancelled,
        ));
    }

    let previous =
        match activate::activate(context.content_root, request.site_id, request.release_id) {
            Ok(previous) => previous,
            Err(error) => {
                return Err(fail(
                    &site_state,
                    &state_path,
                    &audit_path,
                    state,
                    RollbackError::Activate(error),
                ));
            }
        };

    // Commit point: `current` now points back at `request.release_id`, and
    // nothing from here may be aborted by cancellation.
    let _post_commit = pre_commit.commit();
    drop(lock);

    let result = RollbackResult {
        release_id: request.release_id,
        previous_release_id: previous,
        activated_at_unix_secs: unix_now_secs(),
    };
    let result_value = serde_json::to_value(&result).expect("RollbackResult always serializes");
    state
        .mark_committed(result_value)
        .expect("state is always InProgress at this point");

    if let Err(cause) = state::save(&site_state, &state_path, &state) {
        return Err(RollbackError::PostCommitRecordFailed { result, cause });
    }
    let _ = audit::append(
        &site_state,
        &audit_path,
        &AuditRecord::result(request.request_id, true, None),
    );

    // Best-effort, same as deploy: never turn a successful rollback into a
    // reported failure.
    let _ = cleanup::prune_old_releases(
        context.content_root,
        request.site_id,
        request.release_id,
        cleanup::DEFAULT_RETAIN_COUNT,
    );

    Ok(result)
}

fn replay(site_state: &ManagedRoot, original: RequestId) -> Result<RollbackResult, RollbackError> {
    let original_state =
        state::load(site_state, &state_path_for(original)).map_err(RollbackError::State)?;
    match original_state.status {
        TransactionStatus::InProgress => Err(RollbackError::ReplayInProgress),
        TransactionStatus::Committed => {
            let outcome = original_state
                .outcome
                .expect("a committed transaction always has an outcome");
            let result_value = outcome
                .result
                .expect("a committed outcome always has a result");
            serde_json::from_value(result_value)
                .map_err(|_| RollbackError::State(state::StateError::Corrupt))
        }
        TransactionStatus::Failed => {
            let outcome = original_state
                .outcome
                .expect("a failed transaction always has an outcome");
            Err(RollbackError::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}

/// Records a pre-commit failure the same way `deploy::execute::fail` does.
fn fail(
    site_state: &ManagedRoot,
    state_path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut state: TransactionState,
    error: RollbackError,
) -> RollbackError {
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
