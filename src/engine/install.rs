//! The assembled `engine.install` pipeline: preflight, fetch and verify
//! the signed release manifest, fetch and checksum the binary, stage it
//! under a retained version directory, atomically activate it at
//! `/usr/local/bin/ops-engine`, and record what happened. Mirrors
//! `deploy::execute::execute`'s shape — see that module's doc comments
//! for the reasoning behind the shared preflight/commit/audit pattern.

use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::{
    engine::{
        EngineInstallRequest, EngineInstallResult, INSTALL_OPERATION, fetch, release, state, verify,
    },
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    site::{SiteRelativePath, TrustedRoot},
    transaction::{
        RequestId,
        audit::{self, AuditRecord},
        commit::PreCommit,
        state::{self as tx_state, TransactionStatus},
    },
};

/// The roots and already-opened state directory an install needs.
pub struct InstallContext<'a> {
    /// `/usr/local/bin` — the one directory `engine install`/
    /// `engine rollback` are permitted to write into outside the
    /// engine's own state root.
    pub bin_root: &'a TrustedRoot,
    /// The engine-wide state root, opened once by the caller (mirrors
    /// `DeployContext::engine_state`). `execute` scopes it down to the
    /// `engine/` subtree via `state::open_engine_state`.
    pub engine_state: &'a ManagedRoot,
    /// The GitHub Releases base URL every asset is fetched relative to.
    /// A parameter (not a hardcoded constant in this file) purely so
    /// tests can point it at a local fixture server; every production
    /// call site passes `commands::engine::GITHUB_RELEASES_BASE`.
    pub release_base_url: &'a str,
}

#[derive(Debug)]
pub enum InstallError {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    AlreadyActive,
    UnsupportedArchitecture,
    Verify(verify::Error),
    Fetch(fetch::Error),
    ChecksumMismatch,
    State(tx_state::StateError),
    InstallState(state::Error),
    Cancelled,
    /// The install itself succeeded — the binary at
    /// `/usr/local/bin/ops-engine` was switched — but its
    /// `TransactionState` could not be saved afterward.
    PostCommitRecordFailed {
        result: EngineInstallResult,
        cause: tx_state::StateError,
    },
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl InstallError {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Io(_) | Self::State(_) | Self::InstallState(_) => (
                ErrorCode::Internal,
                "internal engine install error".to_owned(),
            ),
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another engine install or rollback is already in progress".to_owned(),
            ),
            Self::Preflight(_) => (ErrorCode::Internal, "preflight failed".to_owned()),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request for this idempotency key is still in progress".to_owned(),
            ),
            Self::AlreadyActive => (
                ErrorCode::InvalidInput,
                "the requested version is already active".to_owned(),
            ),
            Self::UnsupportedArchitecture => (
                ErrorCode::UnsupportedPlatform,
                "this host's architecture has no published engine build".to_owned(),
            ),
            Self::Verify(verify::Error::Fetch(_)) => (
                ErrorCode::ArtifactFetchFailed,
                "the release manifest could not be fetched".to_owned(),
            ),
            Self::Verify(_) => (
                ErrorCode::ArtifactVerificationFailed,
                "the release manifest failed verification".to_owned(),
            ),
            Self::Fetch(_) => (
                ErrorCode::ArtifactFetchFailed,
                "the release binary could not be fetched".to_owned(),
            ),
            Self::ChecksumMismatch => (
                ErrorCode::ArtifactVerificationFailed,
                "the downloaded binary did not match its verified checksum".to_owned(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before the commit point".to_owned(),
            ),
            Self::PostCommitRecordFailed { .. } => (
                ErrorCode::Internal,
                "internal engine install error".to_owned(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
        }
    }
}

pub fn execute(
    context: &InstallContext<'_>,
    request: &EngineInstallRequest,
    cancellation: &crate::process::CancellationToken,
) -> Result<EngineInstallResult, InstallError> {
    let engine_state = state::open_engine_state(context.engine_state).map_err(InstallError::Io)?;

    let admitted = match preflight::run(
        &engine_state,
        request.request_id,
        request.idempotency_key.as_ref(),
        INSTALL_OPERATION,
    )
    .map_err(InstallError::Preflight)?
    {
        preflight::Outcome::Replay(original) => return replay(&engine_state, original),
        preflight::Outcome::Proceed(admitted) => admitted,
    };
    // `Admitted`'s field is named `state` (it holds the mutation's
    // `TransactionState`); rename it to `tx` on destructuring so it
    // never collides, even visually, with the `state` module imported
    // above (`crate::engine::state`) — Rust's separate value/module
    // namespaces mean it would compile either way, but a shared name
    // for two different things here would only confuse a reader.
    let preflight::Admitted {
        lock,
        state: mut tx,
    } = admitted;

    let state_path = state_path_for(request.request_id);
    let audit_path = audit_log_path();
    let pre_commit = PreCommit::new(cancellation.clone());

    let current = match state::load(&engine_state) {
        Ok(current) => current,
        Err(error) => {
            return Err(fail(
                &engine_state,
                &state_path,
                &audit_path,
                tx,
                InstallError::InstallState(error),
            ));
        }
    };
    if let Some(current) = &current {
        if current.active_version == request.version.as_str() {
            return Err(fail(
                &engine_state,
                &state_path,
                &audit_path,
                tx,
                InstallError::AlreadyActive,
            ));
        }
    }

    let Some(target_triple) = release::target_triple() else {
        return Err(fail(
            &engine_state,
            &state_path,
            &audit_path,
            tx,
            InstallError::UnsupportedArchitecture,
        ));
    };

    let expected =
        match verify::fetch_and_verify(context.release_base_url, &request.version, target_triple) {
            Ok(expected) => expected,
            Err(error) => {
                return Err(fail(
                    &engine_state,
                    &state_path,
                    &audit_path,
                    tx,
                    InstallError::Verify(error),
                ));
            }
        };

    if pre_commit.check().is_err() {
        return Err(fail(
            &engine_state,
            &state_path,
            &audit_path,
            tx,
            InstallError::Cancelled,
        ));
    }

    let binary_url = release::binary_url(context.release_base_url, &request.version, target_triple);
    let bytes = match fetch::fetch_bytes(&binary_url) {
        Ok(bytes) => bytes,
        Err(error) => {
            return Err(fail(
                &engine_state,
                &state_path,
                &audit_path,
                tx,
                InstallError::Fetch(error),
            ));
        }
    };
    if sha256_hex(&bytes) != expected.sha256_hex {
        return Err(fail(
            &engine_state,
            &state_path,
            &audit_path,
            tx,
            InstallError::ChecksumMismatch,
        ));
    }

    if pre_commit.check().is_err() {
        return Err(fail(
            &engine_state,
            &state_path,
            &audit_path,
            tx,
            InstallError::Cancelled,
        ));
    }

    let version_dir = SiteRelativePath::parse(format!("versions/{}", request.version))
        .expect("a validated EngineVersion always yields a valid relative path");
    let version_binary =
        SiteRelativePath::parse(format!("versions/{}/ops-engine", request.version))
            .expect("a validated EngineVersion always yields a valid relative path");
    if let Err(error) = engine_state
        .create_dir_all(&version_dir)
        .and_then(|()| engine_state.write_new_executable(&version_binary, &bytes))
    {
        return Err(fail(
            &engine_state,
            &state_path,
            &audit_path,
            tx,
            InstallError::Io(error),
        ));
    }

    if pre_commit.check().is_err() {
        return Err(fail(
            &engine_state,
            &state_path,
            &audit_path,
            tx,
            InstallError::Cancelled,
        ));
    }

    let bin_root = match ManagedRoot::open(context.bin_root) {
        Ok(root) => root,
        Err(error) => {
            return Err(fail(
                &engine_state,
                &state_path,
                &audit_path,
                tx,
                InstallError::Io(error),
            ));
        }
    };
    // Commit point: `/usr/local/bin/ops-engine` now contains the new,
    // already-verified binary. Nothing from here may be aborted by
    // cancellation — the switch already happened.
    if let Err(error) = bin_root.write_new_executable(&binary_path(), &bytes) {
        return Err(fail(
            &engine_state,
            &state_path,
            &audit_path,
            tx,
            InstallError::Io(error),
        ));
    }
    let _post_commit = pre_commit.commit();
    drop(lock);

    // The version that falls out of retention after this install: it
    // was `previous` *before* this call (not the new `previous`, which
    // is the version we just switched away from and must keep). Capture
    // it before `current` is consumed below.
    let superseded_version = current
        .as_ref()
        .and_then(|previous| previous.previous_version.clone());
    let previous_version = current.map(|previous| previous.active_version);
    let new_state = state::InstallState {
        active_version: request.version.as_str().to_owned(),
        previous_version: previous_version.clone(),
    };
    // Best-effort: the commit already happened (the binary at
    // `/usr/local/bin/ops-engine` is already switched), so a failure to
    // save `install.state` or prune the superseded version directory is
    // a bookkeeping/disk-usage concern, not grounds for turning a
    // successful install into a reported failure.
    let _ = state::save(&engine_state, &new_state);
    let _ = prune_superseded_version(&engine_state, superseded_version.as_deref(), &new_state);

    let result = EngineInstallResult {
        version: request.version.as_str().to_owned(),
        previous_version,
        activated_at_unix_secs: unix_now_secs(),
    };
    let result_value =
        serde_json::to_value(&result).expect("EngineInstallResult always serializes");
    tx.mark_committed(result_value)
        .expect("state is always InProgress at this point");

    if let Err(cause) = tx_state::save(&engine_state, &state_path, &tx) {
        return Err(InstallError::PostCommitRecordFailed { result, cause });
    }
    let _ = audit::append(
        &engine_state,
        &audit_path,
        &AuditRecord::result(request.request_id, true, None),
    );

    Ok(result)
}

fn prune_superseded_version(
    engine_state: &ManagedRoot,
    superseded: Option<&str>,
    new_state: &state::InstallState,
) -> std::io::Result<()> {
    let Some(superseded) = superseded else {
        return Ok(());
    };
    if superseded == new_state.active_version
        || Some(superseded) == new_state.previous_version.as_deref()
    {
        return Ok(());
    }
    let path = SiteRelativePath::parse(format!("versions/{superseded}"))
        .expect("a previously-installed version string always yields a valid relative path");
    engine_state.remove_dir_all(&path)
}

fn replay(
    engine_state: &ManagedRoot,
    original: RequestId,
) -> Result<EngineInstallResult, InstallError> {
    let original_state =
        tx_state::load(engine_state, &state_path_for(original)).map_err(InstallError::State)?;
    match original_state.status {
        TransactionStatus::InProgress => Err(InstallError::ReplayInProgress),
        TransactionStatus::Committed => {
            let outcome = original_state
                .outcome
                .expect("a committed transaction always has an outcome");
            let result_value = outcome
                .result
                .expect("a committed outcome always has a result");
            serde_json::from_value(result_value)
                .map_err(|_| InstallError::State(tx_state::StateError::Corrupt))
        }
        TransactionStatus::Failed => {
            let outcome = original_state
                .outcome
                .expect("a failed transaction always has an outcome");
            Err(InstallError::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}

fn fail(
    engine_state: &ManagedRoot,
    state_path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut tx: tx_state::TransactionState,
    error: InstallError,
) -> InstallError {
    let (code, message) = error.protocol();
    let _ = tx.mark_failed(code, message);
    let _ = tx_state::save(engine_state, state_path, &tx);
    let _ = audit::append(
        engine_state,
        audit_path,
        &AuditRecord::result(tx.request_id, false, Some(code)),
    );
    error
}

fn binary_path() -> SiteRelativePath {
    SiteRelativePath::parse("ops-engine").expect("literal path is valid")
}

fn state_path_for(request_id: RequestId) -> SiteRelativePath {
    SiteRelativePath::parse(format!("transactions/{request_id}.json"))
        .expect("a canonical RequestId always yields a valid relative path")
}

fn audit_log_path() -> SiteRelativePath {
    SiteRelativePath::parse("audit/events.jsonl").expect("literal path is valid")
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
