//! `site.moveRoot`: renames a site's content directory from
//! `<content root>/<from domain>` to `<content root>/<to domain>` when the
//! control panel renames a site (milestone 053). The panel used to run a
//! raw `sudo mv` for this and `mv` it back on rollback.
//!
//! The caller names two domains, never paths: the engine builds both paths
//! itself as direct children of one configured content root, so the move can
//! never leave that root or cross filesystems. It is a single `rename(2)`
//! through the content root's directory handle (no symlink is followed),
//! refused if the source is missing or not a real directory, or if anything
//! already exists at the target. Both paths take their cross-operation
//! resource lock (the same one the WordPress operations use), so a move
//! cannot run under an install, update or clone of either root, and every
//! request records a transaction and an audit entry in its own scope.
//!
//! A rollback is the same operation with the domains swapped.

use std::{
    io,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    site::{Domain, SiteRelativePath, TrustedRoot},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        resource_lock,
        state::{self, TransactionState, TransactionStatus},
    },
};

pub const MOVE_OPERATION: &str = "site.moveRoot";

const SCOPE: &str = "site-root";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestError {
    InvalidDomain,
    SameDomain,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl RequestError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidDomain => "domain is invalid",
            Self::SameDomain => "the source and target domains are the same",
            Self::InvalidRequestId => "request-id must be a canonical UUID",
            Self::InvalidIdempotencyKey => "idempotency-key is invalid",
        }
    }
}

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
        let from = Domain::parse(from).map_err(|_| RequestError::InvalidDomain)?;
        let to = Domain::parse(to).map_err(|_| RequestError::InvalidDomain)?;
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

#[derive(Debug)]
pub enum Error {
    /// Another operation holds the resource lock of the source or target.
    ResourceBusy,
    Io(io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    /// No configured content root has a real directory named after the
    /// source domain (missing, a file, or a symlink).
    SourceMissing,
    /// Something already exists at the target path. Nothing was moved.
    TargetExists,
    PostCommit(serde_json::Value),
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::ResourceBusy | Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another operation on this site's directory is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::SourceMissing => (
                ErrorCode::NotFound,
                "the site directory to move does not exist".into(),
            ),
            Self::TargetExists => (
                ErrorCode::InvalidInput,
                "a file or directory already exists at the target".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit(_) => (
                ErrorCode::Internal,
                "internal site directory move error".into(),
            ),
        }
    }
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
        preflight::Outcome::Replay(original) => return replay(&scope, original),
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

fn rename(
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

/// A real directory (not a symlink to one) named `domain` directly under
/// `root`.
fn is_real_dir(root: &TrustedRoot, domain: &Domain) -> bool {
    std::fs::symlink_metadata(root.as_path().join(domain.as_str()))
        .is_ok_and(|metadata| metadata.file_type().is_dir())
}

/// Anything at all named `domain` directly under `root`, including a
/// dangling symlink (`symlink_metadata` does not follow it).
fn entry_exists(root: &TrustedRoot, domain: &Domain) -> bool {
    std::fs::symlink_metadata(root.as_path().join(domain.as_str())).is_ok()
}

fn domain_rel(domain: &Domain) -> SiteRelativePath {
    SiteRelativePath::parse(domain.as_str()).expect("a validated domain is one path component")
}

fn open_scope(engine_state: &ManagedRoot) -> io::Result<ManagedRoot> {
    engine_state.create_dir_all(&rel(SCOPE))?;
    let scope = engine_state.open_managed_dir(&rel(SCOPE))?;
    for child in ["locks", "transactions", "audit"] {
        scope.create_dir_all(&rel(child))?;
    }
    Ok(scope)
}

fn replay(scope: &ManagedRoot, original: RequestId) -> Result<MoveResult, Error> {
    let loaded = state::load(scope, &transaction_path(original))
        .map_err(|error| Error::Io(io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != MOVE_OPERATION {
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

fn fail(
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

fn transaction_path(request_id: RequestId) -> SiteRelativePath {
    rel(&format!("transactions/{request_id}.json"))
}

fn rel(path: &str) -> SiteRelativePath {
    SiteRelativePath::parse(path).expect("literal path is valid")
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::symlink};

    use super::*;

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const OTHER_ID: &str = "123e4567-e89b-12d3-a456-426614174001";
    const THIRD_ID: &str = "123e4567-e89b-12d3-a456-426614174002";

    struct Fixture {
        _dir: tempfile::TempDir,
        state: ManagedRoot,
        content: TrustedRoot,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path().canonicalize().unwrap();
            fs::create_dir(base.join("state")).unwrap();
            fs::create_dir(base.join("www")).unwrap();
            Self {
                state: ManagedRoot::open(&TrustedRoot::parse(base.join("state")).unwrap()).unwrap(),
                content: TrustedRoot::parse(base.join("www")).unwrap(),
                _dir: dir,
            }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.content.as_path().join(name)
        }

        fn site(&self, name: &str) {
            fs::create_dir(self.path(name)).unwrap();
            fs::write(self.path(name).join("index.php"), "<?php").unwrap();
        }

        fn run(&self, req: &MoveRequest) -> Result<MoveResult, Error> {
            move_root(&self.state, std::slice::from_ref(&self.content), req)
        }
    }

    fn req(from: &str, to: &str, id: &str, key: Option<&str>) -> MoveRequest {
        MoveRequest::parse(from, to, id, key).unwrap()
    }

    #[test]
    fn moves_the_directory_with_its_contents_and_replays() {
        let fixture = Fixture::new();
        fixture.site("old.test");

        let result = fixture
            .run(&req("old.test", "new.test", ID, Some("mv-1")))
            .unwrap();
        assert_eq!(result.to, fixture.path("new.test").to_string_lossy());
        assert!(!fixture.path("old.test").exists());
        assert!(fixture.path("new.test/index.php").exists());

        // The same key replays the committed outcome instead of failing on
        // the now-missing source.
        let replayed = fixture
            .run(&req("old.test", "new.test", ID, Some("mv-1")))
            .unwrap_or_else(|error| panic!("{error:?}"));
        assert_eq!(replayed.from, result.from);
    }

    #[test]
    fn swapping_the_domains_rolls_the_move_back() {
        let fixture = Fixture::new();
        fixture.site("old.test");
        fixture.run(&req("old.test", "new.test", ID, None)).unwrap();
        fixture
            .run(&req("new.test", "old.test", OTHER_ID, None))
            .unwrap();
        assert!(fixture.path("old.test/index.php").exists());
        assert!(!fixture.path("new.test").exists());
    }

    #[test]
    fn refuses_an_existing_target_and_moves_nothing() {
        let fixture = Fixture::new();
        fixture.site("old.test");
        fixture.site("new.test");

        let error = fixture
            .run(&req("old.test", "new.test", ID, None))
            .unwrap_err();
        assert!(matches!(error, Error::TargetExists));
        assert!(fixture.path("old.test/index.php").exists());
    }

    #[test]
    fn refuses_a_dangling_symlink_at_the_target() {
        let fixture = Fixture::new();
        fixture.site("old.test");
        symlink("/nonexistent", fixture.path("new.test")).unwrap();

        let error = fixture
            .run(&req("old.test", "new.test", ID, None))
            .unwrap_err();
        assert!(matches!(error, Error::TargetExists));
    }

    #[test]
    fn refuses_a_missing_file_or_symlinked_source() {
        let fixture = Fixture::new();
        assert!(matches!(
            fixture.run(&req("old.test", "new.test", ID, None)),
            Err(Error::SourceMissing)
        ));

        fs::write(fixture.path("file.test"), "x").unwrap();
        assert!(matches!(
            fixture.run(&req("file.test", "new.test", OTHER_ID, None)),
            Err(Error::SourceMissing)
        ));

        fixture.site("real.test");
        symlink(fixture.path("real.test"), fixture.path("link.test")).unwrap();
        assert!(matches!(
            fixture.run(&req("link.test", "new.test", THIRD_ID, None)),
            Err(Error::SourceMissing)
        ));
        assert!(fixture.path("real.test/index.php").exists());
    }

    #[test]
    fn a_held_resource_lock_on_either_side_blocks_the_move() {
        let fixture = Fixture::new();
        fixture.site("old.test");
        for held in ["old.test", "new.test"] {
            let _held = resource_lock::acquire(
                &fixture.state,
                &fixture.path(held),
                RequestId::parse(OTHER_ID).unwrap(),
            )
            .unwrap();
            assert!(matches!(
                fixture.run(&req("old.test", "new.test", ID, None)),
                Err(Error::ResourceBusy)
            ));
        }
        assert!(fixture.path("old.test/index.php").exists());
    }

    #[test]
    fn rejects_malformed_requests() {
        assert_eq!(
            MoveRequest::parse("../etc", "new.test", ID, None).err(),
            Some(RequestError::InvalidDomain)
        );
        assert_eq!(
            MoveRequest::parse("old.test", "a/b", ID, None).err(),
            Some(RequestError::InvalidDomain)
        );
        assert_eq!(
            MoveRequest::parse("same.test", "same.test", ID, None).err(),
            Some(RequestError::SameDomain)
        );
        assert_eq!(
            MoveRequest::parse("old.test", "new.test", "not-a-uuid", None).err(),
            Some(RequestError::InvalidRequestId)
        );
    }
}
