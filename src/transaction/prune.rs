//! Retention sweep for completed transaction state - the fix for
//! `transactions/<requestId>.json` and `transactions/idempotency/<hash>.json`
//! both accumulating forever (every mutation ever run leaves one of each
//! behind; neither had a removal path before this module existed). Called
//! from `mutation::preflight::run`, the one choke point every current and
//! future mutating operation already goes through - so a future operation
//! cannot add unbounded per-request state by forgetting to call this the
//! way it could if pruning were each operation module's own responsibility.
//! `audit/events.jsonl` is deliberately untouched: an append-only audit
//! trail is unbounded by design, and "bounding" it (rotation vs. a size
//! cap vs. leaving it be) is a real, separate design decision, not a prune
//! loop like this one.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{
    filesystem::ManagedRoot,
    site::SiteRelativePath,
    transaction::{
        idempotency,
        state::{self, TransactionStatus},
    },
};

/// How long a finished (`Committed`/`Failed`) transaction's state and
/// idempotency-index entry are kept before this sweep removes them. Long
/// enough to cover any realistic offline-client retry (a client that was
/// disconnected for days and retries the same idempotency key on
/// reconnect should still replay cleanly), short enough that per-site
/// state does not grow without bound over a server's real lifetime.
pub const DEFAULT_COMPLETED_RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);

fn transactions_dir() -> SiteRelativePath {
    SiteRelativePath::parse("transactions").expect("a fixed literal path is always valid")
}

/// Removes every `Committed`/`Failed` transaction whose `finished_at_unix_secs`
/// is older than `retain_for`, and its idempotency-index entry if it had
/// one. `InProgress` transactions (interrupted mid-flight, still
/// recoverable) and anything without a `finished_at_unix_secs` are never
/// touched regardless of age. Best-effort throughout, matching
/// `install::prune_superseded_version`'s shape: one file this sweep
/// cannot read, parse, or remove is skipped, not fatal to the sweep or to
/// the caller's own mutation attempt.
pub fn prune_completed(root: &ManagedRoot, retain_for: Duration) {
    let Ok(transactions) = root.open_managed_dir(&transactions_dir()) else {
        return;
    };
    let Ok(names) = transactions.file_names() else {
        return;
    };
    let now = unix_now_secs();
    for name in names {
        if !name.ends_with(".json") {
            continue;
        }
        let Ok(path) = SiteRelativePath::parse(format!("transactions/{name}")) else {
            continue;
        };
        let Ok(transaction) = state::load(root, &path) else {
            continue;
        };
        if transaction.status == TransactionStatus::InProgress {
            continue;
        }
        let Some(finished_at) = transaction.finished_at_unix_secs else {
            continue;
        };
        let age = Duration::from_secs(now.saturating_sub(finished_at));
        if age < retain_for {
            continue;
        }
        if let Some(key) = &transaction.idempotency_key {
            let _ = idempotency::remove(root, key);
        }
        let _ = root.remove_file(&path);
    }
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{DEFAULT_COMPLETED_RETENTION, prune_completed};
    use crate::{
        error::ErrorCode,
        filesystem::ManagedRoot,
        site::TrustedRoot,
        transaction::{
            IdempotencyKey, RequestId,
            idempotency::{self, Resolution},
            state::{self, TransactionState},
        },
    };

    fn managed_root() -> (tempfile::TempDir, ManagedRoot) {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let root = TrustedRoot::parse(directory.path()).expect("root should be valid");
        let managed = ManagedRoot::open(&root).expect("root should open");
        managed
            .create_dir_all(&super::transactions_dir())
            .expect("transactions dir should be created");
        (directory, managed)
    }

    fn request_id(value: &str) -> RequestId {
        RequestId::parse(value).expect("test UUID should be canonical")
    }

    fn state_path(id: RequestId) -> crate::site::SiteRelativePath {
        crate::site::SiteRelativePath::parse(format!("transactions/{id}.json"))
            .expect("state path should be valid")
    }

    #[test]
    fn a_committed_transaction_older_than_the_retention_bound_is_removed() {
        let (_directory, managed) = managed_root();
        let id = request_id("550e8400-e29b-41d4-a716-446655440000");
        let path = state_path(id);
        let mut transaction = TransactionState::start(id, None, "site.deploy");
        transaction
            .mark_committed(serde_json::json!({}))
            .expect("commit should succeed");
        state::create(&managed, &path, &transaction).expect("create should succeed");

        // Retention has whole-second resolution, so a zero bound is the
        // deterministic way to exercise "older than the bound" without a
        // real sleep - same trick `transaction::lock`'s staleness test
        // uses, for the same reason.
        prune_completed(&managed, Duration::ZERO);

        assert!(
            !managed.exists(&path),
            "the completed transaction should have been pruned"
        );
    }

    #[test]
    fn an_in_progress_transaction_is_never_pruned_regardless_of_retention() {
        let (_directory, managed) = managed_root();
        let id = request_id("9b2f1c34-5678-4abc-9def-0123456789ab");
        let path = state_path(id);
        let transaction = TransactionState::start(id, None, "site.deploy");
        state::create(&managed, &path, &transaction).expect("create should succeed");

        prune_completed(&managed, Duration::ZERO);

        assert!(
            managed.exists(&path),
            "an in-progress transaction must never be pruned, even with a zero retention bound"
        );
    }

    #[test]
    fn a_recent_transaction_survives_the_default_retention_window() {
        let (_directory, managed) = managed_root();
        let id = request_id("3f0d5a71-2c48-4f6b-8b21-7d5e9c1a4b60");
        let path = state_path(id);
        let mut transaction = TransactionState::start(id, None, "site.deploy");
        transaction
            .mark_failed(ErrorCode::Internal, "transient")
            .expect("fail transition should succeed");
        state::create(&managed, &path, &transaction).expect("create should succeed");

        prune_completed(&managed, DEFAULT_COMPLETED_RETENTION);

        assert!(
            managed.exists(&path),
            "a transaction finished moments ago must survive a 7-day retention window"
        );
    }

    #[test]
    fn pruning_a_transaction_with_an_idempotency_key_also_removes_its_index_entry() {
        let (_directory, managed) = managed_root();
        let id = request_id("c41a8e02-9d37-4a55-b8f2-6e0c73d91af8");
        let key = IdempotencyKey::parse("deploy-2026-09-08-01").expect("key should be valid");
        idempotency::claim(&managed, &key, id).expect("claim should succeed");
        let path = state_path(id);
        let mut transaction = TransactionState::start(id, Some(key.clone()), "site.deploy");
        transaction
            .mark_committed(serde_json::json!({}))
            .expect("commit should succeed");
        state::create(&managed, &path, &transaction).expect("create should succeed");

        prune_completed(&managed, Duration::ZERO);

        assert!(
            !managed.exists(&path),
            "the transaction state should be pruned"
        );
        assert_eq!(
            idempotency::lookup(&managed, &key),
            Ok(None),
            "the idempotency claim must not outlive the transaction it points to"
        );
        // A retry with the same key after both are pruned is treated as a
        // fresh attempt, not an error - the graceful outcome this ordering
        // is chosen for.
        let retried_id = request_id("123e4567-e89b-12d3-a456-426614174000");
        assert_eq!(
            idempotency::claim(&managed, &key, retried_id),
            Ok(Resolution::Claimed)
        );
    }
}
