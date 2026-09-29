//! Activates the paired `unattended-upgrades` apt configuration
//! (`/etc/apt/apt.conf.d/50unattended-upgrades` and `.../20auto-upgrades`)
//! as one lock/idempotency/transaction/audit-backed request. Replaces the
//! panel's two independent `sudo`-staged SFTP writes, which could leave the
//! pair disagreeing — interval enabled in one file, the blacklist or reboot
//! policy unwritten in the other — if the connection dropped between them.
//! The panel still renders both files' content (exactly as
//! `backup.activateConfig` already trusts the panel to render its own
//! bundle); the engine's job is only to make writing them one atomic-enough
//! unit, with the first file reverted to its prior content (or removed, if
//! it did not previously exist) whenever the second write fails.

use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::CancellationToken,
    site::SiteRelativePath,
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        commit::PreCommit,
        state::{self, TransactionStatus},
    },
};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

pub const OPERATION: &str = "system.activateAutoupdatesConfig";
pub const MAX_CONTENT_BYTES: usize = 64 * 1024;
pub const APT_CONF_DIR: &str = "/etc/apt/apt.conf.d";
const UNATTENDED_UPGRADES_FILE: &str = "50unattended-upgrades";
const AUTO_UPGRADES_FILE: &str = "20auto-upgrades";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    unattended_upgrades: String,
    auto_upgrades: String,
}

pub struct Request {
    unattended_upgrades: String,
    auto_upgrades: String,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    ContentTooLarge,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

fn valid_content(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_CONTENT_BYTES && !value.contains('\0')
}

impl Request {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        if !valid_content(&plan.unattended_upgrades) || !valid_content(&plan.auto_upgrades) {
            return Err(RequestError::ContentTooLarge);
        }
        Ok(Self {
            unattended_upgrades: plan.unattended_upgrades,
            auto_upgrades: plan.auto_upgrades,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivateResult {
    pub activated_at_unix_secs: u64,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    /// Opened directly on `APT_CONF_DIR` — a fixed, well-known Debian/Ubuntu
    /// directory apt itself reads, not a per-site or per-deployment root.
    pub apt_conf_dir: &'a ManagedRoot,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Cancelled,
    Write(std::io::Error),
    /// The second file's write failed and reverting the first file (to its
    /// prior content, or by removing it if it had none) also failed. The
    /// two files may now disagree; `ops-engine doctor` and a follow-up
    /// activation are the only way out, not an automatic retry.
    RollbackFailed,
    PostCommit {
        result: ActivateResult,
    },
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another autoupdates configuration activation is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before the autoupdates configuration was written".into(),
            ),
            Self::Write(_) => (
                ErrorCode::Internal,
                "could not write the autoupdates configuration".into(),
            ),
            Self::RollbackFailed => (
                ErrorCode::Internal,
                "autoupdates configuration activation failed and the previous file could not be \
                 restored; the two config files may now disagree"
                    .into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit { .. } => (
                ErrorCode::Internal,
                "internal autoupdates configuration error".into(),
            ),
        }
    }
}

fn read_optional(root: &ManagedRoot, path: &SiteRelativePath) -> Result<Option<Vec<u8>>, Error> {
    match root.read_bytes(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Error::Io(error)),
    }
}

fn restore(root: &ManagedRoot, path: &SiteRelativePath, previous: &Option<Vec<u8>>) -> bool {
    match previous {
        Some(bytes) => root.write_atomic(path, bytes).is_ok(),
        None => match root.remove_file(path) {
            Ok(()) => true,
            Err(error) => error.kind() == std::io::ErrorKind::NotFound,
        },
    }
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<ActivateResult, Error> {
    let scope_path = SiteRelativePath::parse("system-autoupdates").unwrap();
    ctx.engine_state
        .create_dir_all(&scope_path)
        .map_err(Error::Io)?;
    let scope = ctx
        .engine_state
        .open_managed_dir(&scope_path)
        .map_err(Error::Io)?;
    for child in ["locks", "transactions", "audit"] {
        scope
            .create_dir_all(&SiteRelativePath::parse(child).unwrap())
            .map_err(Error::Io)?;
    }
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
    let state_path =
        SiteRelativePath::parse(format!("transactions/{}.json", req.request_id)).unwrap();
    let audit_path = SiteRelativePath::parse("audit/events.jsonl").unwrap();
    let pre_commit = PreCommit::new(cancel.clone());

    let upgrades_path = SiteRelativePath::parse(UNATTENDED_UPGRADES_FILE).unwrap();
    let auto_upgrades_path = SiteRelativePath::parse(AUTO_UPGRADES_FILE).unwrap();

    let previous_upgrades = match read_optional(ctx.apt_conf_dir, &upgrades_path) {
        Ok(value) => value,
        Err(error) => return Err(fail(&scope, &state_path, &audit_path, state, error)),
    };

    if pre_commit.check().is_err() {
        return Err(fail(
            &scope,
            &state_path,
            &audit_path,
            state,
            Error::Cancelled,
        ));
    }

    if let Err(error) = ctx
        .apt_conf_dir
        .write_atomic(&upgrades_path, req.unattended_upgrades.as_bytes())
    {
        return Err(fail(
            &scope,
            &state_path,
            &audit_path,
            state,
            Error::Write(error),
        ));
    }
    let _post_commit = pre_commit.commit();

    // 50unattended-upgrades is now live. From here on, a failure to also
    // write 20auto-upgrades must revert it rather than just report.
    if let Err(error) = ctx
        .apt_conf_dir
        .write_atomic(&auto_upgrades_path, req.auto_upgrades.as_bytes())
    {
        if !restore(ctx.apt_conf_dir, &upgrades_path, &previous_upgrades) {
            return Err(fail(
                &scope,
                &state_path,
                &audit_path,
                state,
                Error::RollbackFailed,
            ));
        }
        return Err(fail(
            &scope,
            &state_path,
            &audit_path,
            state,
            Error::Write(error),
        ));
    }

    let result = ActivateResult {
        activated_at_unix_secs: SystemTime::now()
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

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<ActivateResult, Error> {
    let path = SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap();
    let loaded = state::load(scope, &path)
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

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    fn managed(directory: &std::path::Path) -> ManagedRoot {
        ManagedRoot::open(&crate::site::TrustedRoot::parse(directory).unwrap()).unwrap()
    }

    fn request(id: &str, key: Option<&str>) -> Request {
        Request::parse(
            r#"{"unattendedUpgrades":"upgrades-v1","autoUpgrades":"auto-v1"}"#,
            id,
            key,
        )
        .unwrap()
    }

    #[test]
    fn activates_both_files_under_one_transaction_then_replays() {
        let state_dir = tempfile::tempdir().unwrap();
        let apt_dir = tempfile::tempdir().unwrap();
        let state = managed(state_dir.path());
        let apt_conf_dir = managed(apt_dir.path());
        let ctx = Context {
            engine_state: &state,
            apt_conf_dir: &apt_conf_dir,
        };
        let req = request(ID, Some("autoupdates-key"));

        let first = execute(&ctx, &req, &CancellationToken::default()).unwrap();
        let second = execute(&ctx, &req, &CancellationToken::default()).unwrap();
        assert_eq!(first.activated_at_unix_secs, second.activated_at_unix_secs);

        assert_eq!(
            fs::read_to_string(apt_dir.path().join(UNATTENDED_UPGRADES_FILE)).unwrap(),
            "upgrades-v1"
        );
        assert_eq!(
            fs::read_to_string(apt_dir.path().join(AUTO_UPGRADES_FILE)).unwrap(),
            "auto-v1"
        );
        // One MutationStart event from preflight plus one result event from
        // the single real execution; the replayed second call appends
        // neither.
        let audit = fs::read_to_string(
            state_dir
                .path()
                .join("system-autoupdates/audit/events.jsonl"),
        )
        .unwrap();
        assert_eq!(audit.lines().count(), 2);
    }

    #[test]
    fn second_write_failure_reverts_the_first_file_to_its_previous_content() {
        let state_dir = tempfile::tempdir().unwrap();
        let apt_dir = tempfile::tempdir().unwrap();
        fs::write(
            apt_dir.path().join(UNATTENDED_UPGRADES_FILE),
            "old-upgrades",
        )
        .unwrap();
        // A directory in place of the second file makes its write_atomic
        // rename fail deterministically (EISDIR/ENOTDIR), without needing
        // filesystem permission tricks.
        fs::create_dir(apt_dir.path().join(AUTO_UPGRADES_FILE)).unwrap();
        let state = managed(state_dir.path());
        let apt_conf_dir = managed(apt_dir.path());
        let ctx = Context {
            engine_state: &state,
            apt_conf_dir: &apt_conf_dir,
        };
        let req = request(ID, None);

        let result = execute(&ctx, &req, &CancellationToken::default());
        assert!(matches!(result, Err(Error::Write(_))));
        assert_eq!(
            fs::read_to_string(apt_dir.path().join(UNATTENDED_UPGRADES_FILE)).unwrap(),
            "old-upgrades"
        );
    }

    #[test]
    fn second_write_failure_removes_the_first_file_when_it_had_no_previous_content() {
        let state_dir = tempfile::tempdir().unwrap();
        let apt_dir = tempfile::tempdir().unwrap();
        fs::create_dir(apt_dir.path().join(AUTO_UPGRADES_FILE)).unwrap();
        let state = managed(state_dir.path());
        let apt_conf_dir = managed(apt_dir.path());
        let ctx = Context {
            engine_state: &state,
            apt_conf_dir: &apt_conf_dir,
        };
        let req = request(ID, None);

        let result = execute(&ctx, &req, &CancellationToken::default());
        assert!(matches!(result, Err(Error::Write(_))));
        assert!(!apt_dir.path().join(UNATTENDED_UPGRADES_FILE).exists());
    }
}
