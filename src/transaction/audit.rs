use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    protocol::progress::{ProgressStatus, Step},
    site::SiteRelativePath,
    transaction::{IdempotencyKey, RequestId},
};

const AUDIT_SCHEMA_VERSION: u32 = 1;

/// One safe-to-persist mutation lifecycle fact. Deliberately excludes error
/// messages, subprocess output, and every other free-text field — only
/// stable identifiers and codes are ever recorded, matching the same
/// allowlist `docs/protocol.md` sets for error `details`.
#[derive(Debug, Serialize)]
#[serde(tag = "event", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditEvent {
    #[serde(rename_all = "camelCase")]
    MutationStart {
        request_id: RequestId,
        idempotency_key: Option<IdempotencyKey>,
        operation: String,
    },
    #[serde(rename_all = "camelCase")]
    Progress {
        request_id: RequestId,
        step: Step,
        status: ProgressStatus,
    },
    #[serde(rename_all = "camelCase")]
    Result {
        request_id: RequestId,
        ok: bool,
        error_code: Option<ErrorCode>,
    },
    /// A stale per-site lock was reclaimed on this request's behalf. See
    /// `transaction::lock`; this is currently the only recovery path that
    /// exists to have an audit event.
    #[serde(rename_all = "camelCase")]
    LockRecovered {
        request_id: RequestId,
        previous_holder: RequestId,
        held_for_secs: u64,
    },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditRecord {
    pub schema_version: u32,
    pub recorded_at_unix_secs: u64,
    #[serde(flatten)]
    pub event: AuditEvent,
}

impl AuditRecord {
    fn new(event: AuditEvent) -> Self {
        Self {
            schema_version: AUDIT_SCHEMA_VERSION,
            recorded_at_unix_secs: unix_now_secs(),
            event,
        }
    }

    pub fn mutation_start(
        request_id: RequestId,
        idempotency_key: Option<IdempotencyKey>,
        operation: impl Into<String>,
    ) -> Self {
        Self::new(AuditEvent::MutationStart {
            request_id,
            idempotency_key,
            operation: operation.into(),
        })
    }

    pub fn progress(request_id: RequestId, step: Step, status: ProgressStatus) -> Self {
        Self::new(AuditEvent::Progress {
            request_id,
            step,
            status,
        })
    }

    pub fn result(request_id: RequestId, ok: bool, error_code: Option<ErrorCode>) -> Self {
        Self::new(AuditEvent::Result {
            request_id,
            ok,
            error_code,
        })
    }

    pub fn lock_recovered(
        request_id: RequestId,
        previous_holder: RequestId,
        held_for: Duration,
    ) -> Self {
        Self::new(AuditEvent::LockRecovered {
            request_id,
            previous_holder,
            held_for_secs: held_for.as_secs(),
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum AuditError {
    Serialization,
    Io,
}

/// Appends `record` as one JSON Lines entry. Appending — rather than the
/// create-or-atomic-replace primitives the rest of this module uses — is
/// deliberate: the audit log is a growing history, not a single document
/// with one current value.
pub fn append(
    root: &ManagedRoot,
    path: &SiteRelativePath,
    record: &AuditRecord,
) -> Result<(), AuditError> {
    let mut json = serde_json::to_vec(record).map_err(|_| AuditError::Serialization)?;
    json.push(b'\n');
    root.append(path, &json).map_err(|_| AuditError::Io)
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::{AuditRecord, append};
    use crate::{
        error::ErrorCode,
        filesystem::ManagedRoot,
        protocol::progress::ProgressStatus,
        site::{SiteRelativePath, TrustedRoot},
        transaction::{IdempotencyKey, RequestId},
    };

    fn request_id() -> RequestId {
        RequestId::parse("550e8400-e29b-41d4-a716-446655440000")
            .expect("test UUID should be canonical")
    }

    fn managed_root() -> (tempfile::TempDir, ManagedRoot) {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let root = TrustedRoot::parse(directory.path()).expect("root should be valid");
        let managed = ManagedRoot::open(&root).expect("root should open");
        let audit_dir = SiteRelativePath::parse("audit").expect("audit dir path should be valid");
        managed
            .create_dir_all(&audit_dir)
            .expect("audit dir should be created");
        (directory, managed)
    }

    fn audit_path() -> SiteRelativePath {
        SiteRelativePath::parse("audit/events.jsonl").expect("audit path should be valid")
    }

    fn lines(bytes: &[u8]) -> Vec<Value> {
        String::from_utf8(bytes.to_vec())
            .expect("audit log should be UTF-8")
            .lines()
            .map(|line| serde_json::from_str(line).expect("each line should be valid JSON"))
            .collect()
    }

    #[test]
    fn successive_events_append_as_separate_lines_in_order() {
        let (directory, managed) = managed_root();
        let path = audit_path();
        let id = request_id();

        append(
            &managed,
            &path,
            &AuditRecord::mutation_start(id, None, "site.deploy"),
        )
        .expect("mutation start should append");
        append(
            &managed,
            &path,
            &AuditRecord::progress(id, "validate", ProgressStatus::Ok),
        )
        .expect("progress should append");
        append(&managed, &path, &AuditRecord::result(id, true, None))
            .expect("result should append");

        let bytes = std::fs::read(directory.path().join("audit/events.jsonl"))
            .expect("audit log should exist");
        let events = lines(&bytes);
        assert_eq!(events.len(), 3);
        assert_eq!(events[0]["event"], "MUTATION_START");
        assert_eq!(events[0]["operation"], "site.deploy");
        assert_eq!(events[1]["event"], "PROGRESS");
        assert_eq!(events[1]["step"], "validate");
        assert_eq!(events[2]["event"], "RESULT");
        assert_eq!(events[2]["ok"], true);
    }

    #[test]
    fn mutation_start_carries_idempotency_key_when_present() {
        let (directory, managed) = managed_root();
        let path = audit_path();
        let key = IdempotencyKey::parse("deploy-2026-09-02-01").expect("key should be valid");

        append(
            &managed,
            &path,
            &AuditRecord::mutation_start(request_id(), Some(key), "site.deploy"),
        )
        .expect("mutation start should append");

        let bytes = std::fs::read(directory.path().join("audit/events.jsonl"))
            .expect("audit log should exist");
        let events = lines(&bytes);
        assert_eq!(events[0]["idempotencyKey"], "deploy-2026-09-02-01");
    }

    #[test]
    fn result_event_carries_error_code_but_never_a_message_field() {
        let (directory, managed) = managed_root();
        let path = audit_path();

        append(
            &managed,
            &path,
            &AuditRecord::result(request_id(), false, Some(ErrorCode::SubprocessFailed)),
        )
        .expect("result should append");

        let bytes = std::fs::read(directory.path().join("audit/events.jsonl"))
            .expect("audit log should exist");
        let events = lines(&bytes);
        assert_eq!(events[0]["errorCode"], "SUBPROCESS_FAILED");
        assert!(events[0].get("errorMessage").is_none());
        assert!(events[0].get("message").is_none());
    }

    #[test]
    fn lock_recovered_records_the_previous_holder_and_age() {
        let (directory, managed) = managed_root();
        let path = audit_path();
        let previous_holder = RequestId::parse("123e4567-e89b-12d3-a456-426614174000")
            .expect("test UUID should be canonical");

        append(
            &managed,
            &path,
            &AuditRecord::lock_recovered(
                request_id(),
                previous_holder,
                std::time::Duration::from_secs(900),
            ),
        )
        .expect("lock recovered should append");

        let bytes = std::fs::read(directory.path().join("audit/events.jsonl"))
            .expect("audit log should exist");
        let events = lines(&bytes);
        assert_eq!(events[0]["event"], "LOCK_RECOVERED");
        assert_eq!(
            events[0]["previousHolder"],
            "123e4567-e89b-12d3-a456-426614174000"
        );
        assert_eq!(events[0]["heldForSecs"], 900);
    }
}
