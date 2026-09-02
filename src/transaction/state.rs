use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    site::SiteRelativePath,
    transaction::{IdempotencyKey, RequestId},
};

const STATE_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransactionStatus {
    InProgress,
    Committed,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionOutcome {
    pub ok: bool,
    pub result: Option<Value>,
    pub error_code: Option<ErrorCode>,
    pub error_message: Option<String>,
}

/// A mutation attempt's durable record, keyed by `RequestId` and persisted
/// outside process memory so an interrupted request leaves enough state for
/// deterministic recovery.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionState {
    schema_version: u32,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
    pub operation: String,
    pub status: TransactionStatus,
    pub started_at_unix_secs: u64,
    pub finished_at_unix_secs: Option<u64>,
    pub outcome: Option<TransactionOutcome>,
}

impl TransactionState {
    pub fn start(
        request_id: RequestId,
        idempotency_key: Option<IdempotencyKey>,
        operation: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: STATE_SCHEMA_VERSION,
            request_id,
            idempotency_key,
            operation: operation.into(),
            status: TransactionStatus::InProgress,
            started_at_unix_secs: unix_now_secs(),
            finished_at_unix_secs: None,
            outcome: None,
        }
    }

    pub fn mark_committed(&mut self, result: Value) -> Result<(), TransitionError> {
        self.finish(
            TransactionStatus::Committed,
            TransactionOutcome {
                ok: true,
                result: Some(result),
                error_code: None,
                error_message: None,
            },
        )
    }

    pub fn mark_failed(
        &mut self,
        error_code: ErrorCode,
        message: impl Into<String>,
    ) -> Result<(), TransitionError> {
        self.finish(
            TransactionStatus::Failed,
            TransactionOutcome {
                ok: false,
                result: None,
                error_code: Some(error_code),
                error_message: Some(message.into()),
            },
        )
    }

    fn finish(
        &mut self,
        status: TransactionStatus,
        outcome: TransactionOutcome,
    ) -> Result<(), TransitionError> {
        if self.status != TransactionStatus::InProgress {
            return Err(TransitionError::AlreadyFinished);
        }
        self.status = status;
        self.outcome = Some(outcome);
        self.finished_at_unix_secs = Some(unix_now_secs());
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionError {
    AlreadyFinished,
}

#[derive(Debug, Eq, PartialEq)]
pub enum StateError {
    /// A state file already exists at this path; `create` never overwrites.
    AlreadyExists,
    NotFound,
    /// The stored bytes are not a state record this build understands.
    Corrupt,
    Io,
}

/// Persists `state` for the first time. Fails with `AlreadyExists` instead of
/// overwriting, since a colliding `RequestId` indicates a caller bug rather
/// than a legitimate retry.
pub fn create(
    root: &ManagedRoot,
    path: &SiteRelativePath,
    state: &TransactionState,
) -> Result<(), StateError> {
    let bytes = serde_json::to_vec(state).map_err(|_| StateError::Corrupt)?;
    root.create_new(path, &bytes).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            StateError::AlreadyExists
        } else {
            StateError::Io
        }
    })
}

/// Persists an update to a state record that was already `create`d.
pub fn save(
    root: &ManagedRoot,
    path: &SiteRelativePath,
    state: &TransactionState,
) -> Result<(), StateError> {
    let bytes = serde_json::to_vec(state).map_err(|_| StateError::Corrupt)?;
    root.write_atomic(path, &bytes).map_err(|_| StateError::Io)
}

pub fn load(root: &ManagedRoot, path: &SiteRelativePath) -> Result<TransactionState, StateError> {
    let json = root.read_to_string(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            StateError::NotFound
        } else {
            StateError::Io
        }
    })?;
    let state: TransactionState = serde_json::from_str(&json).map_err(|_| StateError::Corrupt)?;
    if state.schema_version != STATE_SCHEMA_VERSION {
        return Err(StateError::Corrupt);
    }
    Ok(state)
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{TransactionState, TransitionError, create, load, save};
    use crate::{
        error::ErrorCode,
        filesystem::ManagedRoot,
        site::{SiteRelativePath, TrustedRoot},
        transaction::RequestId,
    };

    fn request_id() -> RequestId {
        RequestId::parse("550e8400-e29b-41d4-a716-446655440000")
            .expect("test UUID should be canonical")
    }

    fn managed_root() -> (tempfile::TempDir, ManagedRoot) {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let root = TrustedRoot::parse(directory.path()).expect("root should be valid");
        let managed = ManagedRoot::open(&root).expect("root should open");
        let transactions_dir =
            SiteRelativePath::parse("transactions").expect("transactions dir path should be valid");
        managed
            .create_dir_all(&transactions_dir)
            .expect("transactions dir should be created");
        (directory, managed)
    }

    fn state_path() -> SiteRelativePath {
        SiteRelativePath::parse("transactions/550e8400-e29b-41d4-a716-446655440000.json")
            .expect("state path should be valid")
    }

    #[test]
    fn create_then_load_round_trips_in_progress_state() {
        let (_directory, managed) = managed_root();
        let path = state_path();
        let state = TransactionState::start(request_id(), None, "site.deploy");

        create(&managed, &path, &state).expect("create should succeed");
        let loaded = load(&managed, &path).expect("load should succeed");
        assert_eq!(loaded, state);
    }

    #[test]
    fn create_rejects_a_second_write_to_the_same_path() {
        let (_directory, managed) = managed_root();
        let path = state_path();
        let state = TransactionState::start(request_id(), None, "site.deploy");

        create(&managed, &path, &state).expect("first create should succeed");
        let outcome = create(&managed, &path, &state);
        assert_eq!(outcome.unwrap_err(), super::StateError::AlreadyExists);
    }

    #[test]
    fn mark_committed_records_result_and_finish_time() {
        let mut state = TransactionState::start(request_id(), None, "site.deploy");
        state
            .mark_committed(json!({"releaseId": "r-1"}))
            .expect("commit transition should succeed");

        assert_eq!(state.status, super::TransactionStatus::Committed);
        let outcome = state.outcome.expect("outcome should be recorded");
        assert!(outcome.ok);
        assert_eq!(outcome.result, Some(json!({"releaseId": "r-1"})));
        assert!(state.finished_at_unix_secs.is_some());
    }

    #[test]
    fn finishing_twice_is_rejected() {
        let mut state = TransactionState::start(request_id(), None, "site.deploy");
        state
            .mark_committed(json!({}))
            .expect("first transition should succeed");

        let second = state.mark_failed(ErrorCode::Internal, "should not apply");
        assert_eq!(second.unwrap_err(), TransitionError::AlreadyFinished);
        assert_eq!(state.status, super::TransactionStatus::Committed);
    }

    #[test]
    fn save_persists_a_transition_without_leaving_a_temp_file() {
        let (directory, managed) = managed_root();
        let path = state_path();
        let mut state = TransactionState::start(request_id(), None, "site.deploy");
        create(&managed, &path, &state).expect("create should succeed");

        state
            .mark_failed(ErrorCode::SubprocessFailed, "git clone failed")
            .expect("failure transition should succeed");
        save(&managed, &path, &state).expect("save should succeed");

        let loaded = load(&managed, &path).expect("load should succeed");
        assert_eq!(loaded, state);
        assert!(
            !directory
                .path()
                .join("transactions/550e8400-e29b-41d4-a716-446655440000.json.tmp")
                .exists()
        );
    }

    #[test]
    fn load_reports_missing_and_corrupt_state() {
        let (directory, managed) = managed_root();
        let path = state_path();

        assert_eq!(
            load(&managed, &path).unwrap_err(),
            super::StateError::NotFound
        );

        std::fs::create_dir_all(directory.path().join("transactions"))
            .expect("transactions dir should be created");
        std::fs::write(
            directory
                .path()
                .join("transactions/550e8400-e29b-41d4-a716-446655440000.json"),
            b"not json",
        )
        .expect("corrupt state file should be written");
        assert_eq!(
            load(&managed, &path).unwrap_err(),
            super::StateError::Corrupt
        );
    }
}
