//! Exercises the Phase 3 transaction framework (locking, persisted state,
//! the commit/cancellation boundary, progress framing, audit events, and
//! idempotency) together, the way a future mutation operation will combine
//! them. There is no real operation yet (Git deploy lands in Phase 4), so
//! these tests stand in for it against the exit criteria in `PLAN.md`:
//! mutual exclusion, idempotent retries, recoverable interruption, and a
//! commit point cancellation cannot cross.

use std::{thread, time::Duration};

use operations_engine::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    process::CancellationToken,
    protocol::{
        Response,
        progress::{JsonLinesWriter, ProgressStatus},
    },
    site::{SiteRelativePath, TrustedRoot},
    transaction::{
        IdempotencyKey, RequestId, audit,
        commit::PreCommit,
        idempotency::{self, Resolution},
        lock::{self, DEFAULT_STALE_AFTER},
        state::{self, TransactionState},
    },
};

const OPERATION: &str = "site.deploy";

fn managed_root() -> (tempfile::TempDir, ManagedRoot) {
    let directory = tempfile::tempdir().expect("temporary directory should exist");
    let root = TrustedRoot::parse(directory.path()).expect("root should be valid");
    let managed = ManagedRoot::open(&root).expect("root should open");
    for relative in ["locks", "transactions", "audit"] {
        managed
            .create_dir_all(&SiteRelativePath::parse(relative).expect("dir path should be valid"))
            .expect("required directory should be created");
    }
    (directory, managed)
}

fn lock_path() -> SiteRelativePath {
    SiteRelativePath::parse("locks/mutation.lock").expect("lock path should be valid")
}

fn state_path(request_id: RequestId) -> SiteRelativePath {
    SiteRelativePath::parse(format!("transactions/{request_id}.json"))
        .expect("state path should be valid")
}

fn audit_path() -> SiteRelativePath {
    SiteRelativePath::parse("audit/events.jsonl").expect("audit path should be valid")
}

fn request_id(uuid: &str) -> RequestId {
    RequestId::parse(uuid).expect("test UUID should be canonical")
}

#[test]
fn concurrent_requests_cannot_hold_the_same_site_lock_at_once() {
    let (_directory, managed) = managed_root();
    let path = lock_path();
    let first = request_id("550e8400-e29b-41d4-a716-446655440000");
    let second = request_id("123e4567-e89b-12d3-a456-426614174000");

    let guard =
        lock::acquire(&managed, &path, first, DEFAULT_STALE_AFTER).expect("first should acquire");

    // A genuinely concurrent attempt from another OS thread, while `guard`
    // is still held on this one.
    let contended = thread::scope(|scope| {
        scope
            .spawn(|| {
                matches!(
                    lock::acquire(&managed, &path, second, DEFAULT_STALE_AFTER),
                    Err(lock::LockError::Held { holder, .. }) if holder == first
                )
            })
            .join()
            .expect("contending thread should not panic")
    });
    assert!(
        contended,
        "second request should observe the lock held while the first is alive"
    );

    drop(guard);
    lock::acquire(&managed, &path, second, DEFAULT_STALE_AFTER)
        .expect("lock should be free once the first guard is dropped");
}

#[test]
fn full_lifecycle_persists_state_emits_progress_and_releases_the_lock_on_success() {
    let (_directory, managed) = managed_root();
    let id = request_id("550e8400-e29b-41d4-a716-446655440000");
    let lock_file = lock_path();
    let state_file = state_path(id);
    let audit_log = audit_path();

    let guard = lock::acquire(&managed, &lock_file, id, DEFAULT_STALE_AFTER)
        .expect("lock should be free at the start of a lifecycle");
    audit::append(
        &managed,
        &audit_log,
        &audit::AuditRecord::mutation_start(id, None, OPERATION),
    )
    .expect("mutation-start audit event should append");
    let mut transaction_state = TransactionState::start(id, None, OPERATION);
    state::create(&managed, &state_file, &transaction_state).expect("state should be created");

    let mut progress = Vec::new();
    let mut lines = JsonLinesWriter::new(&mut progress);
    let pre_commit = PreCommit::new(CancellationToken::default());
    lines
        .progress("validate", ProgressStatus::Start)
        .expect("progress line should write");
    pre_commit.check().expect("uncancelled preflight passes");
    lines
        .progress("validate", ProgressStatus::Ok)
        .expect("progress line should write");
    audit::append(
        &managed,
        &audit_log,
        &audit::AuditRecord::progress(id, "validate", ProgressStatus::Ok),
    )
    .expect("progress audit event should append");

    let _post_commit = pre_commit.commit();
    let result = serde_json::json!({"releaseId": "r-1"});
    transaction_state
        .mark_committed(result.clone())
        .expect("commit transition should succeed");
    state::save(&managed, &state_file, &transaction_state).expect("state save should succeed");
    audit::append(
        &managed,
        &audit_log,
        &audit::AuditRecord::result(id, true, None),
    )
    .expect("result audit event should append");
    lines
        .finish(Response::success(OPERATION, result.clone()).expect("response should build"))
        .expect("result line should write");
    drop(guard);

    let loaded = state::load(&managed, &state_file).expect("state should load");
    assert_eq!(loaded.status, state::TransactionStatus::Committed);
    assert_eq!(
        loaded.outcome.expect("outcome should exist").result,
        Some(result)
    );

    let lines: Vec<_> = String::from_utf8(progress)
        .expect("progress output should be UTF-8")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("line should be JSON"))
        .collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[2]["type"], "result");
    assert_eq!(lines[2]["ok"], true);

    let audit_lines: Vec<_> = std::fs::read_to_string(_directory.path().join("audit/events.jsonl"))
        .expect("audit log should exist")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("line should be JSON"))
        .collect();
    assert_eq!(audit_lines.len(), 3);

    lock::acquire(
        &managed,
        &lock_file,
        request_id("123e4567-e89b-12d3-a456-426614174000"),
        DEFAULT_STALE_AFTER,
    )
    .expect("lock should be free once the guard was dropped");
}

#[test]
fn cancellation_before_commit_aborts_without_crossing_the_commit_point() {
    let (_directory, managed) = managed_root();
    let id = request_id("550e8400-e29b-41d4-a716-446655440000");
    let lock_file = lock_path();
    let state_file = state_path(id);

    let guard =
        lock::acquire(&managed, &lock_file, id, DEFAULT_STALE_AFTER).expect("lock should acquire");
    let mut transaction_state = TransactionState::start(id, None, OPERATION);
    state::create(&managed, &state_file, &transaction_state).expect("state should be created");

    let cancellation = CancellationToken::default();
    let pre_commit = PreCommit::new(cancellation.clone());
    cancellation.cancel();

    assert!(
        pre_commit.check().is_err(),
        "cancellation before commit must be observable"
    );
    transaction_state
        .mark_failed(ErrorCode::Cancelled, "cancelled before the commit point")
        .expect("failure transition should succeed");
    state::save(&managed, &state_file, &transaction_state).expect("state save should succeed");
    drop(guard);

    let loaded = state::load(&managed, &state_file).expect("state should load");
    assert_eq!(loaded.status, state::TransactionStatus::Failed);
    assert_eq!(
        loaded.outcome.expect("outcome should exist").error_code,
        Some(ErrorCode::Cancelled)
    );
    lock::acquire(
        &managed,
        &lock_file,
        request_id("123e4567-e89b-12d3-a456-426614174000"),
        DEFAULT_STALE_AFTER,
    )
    .expect("aborting before commit must leave the lock free for the next attempt");
}

#[test]
fn cancellation_after_commit_does_not_abort_the_operation() {
    let (_directory, managed) = managed_root();
    let id = request_id("550e8400-e29b-41d4-a716-446655440000");
    let state_file = state_path(id);
    let mut transaction_state = TransactionState::start(id, None, OPERATION);
    state::create(&managed, &state_file, &transaction_state).expect("state should be created");

    let cancellation = CancellationToken::default();
    let pre_commit = PreCommit::new(cancellation.clone());
    pre_commit.check().expect("uncancelled preflight passes");
    let _post_commit = pre_commit.commit();

    // A disconnect or cancellation request arrives only now, after the
    // commit point. There is no method on `_post_commit` to consult it —
    // the operation simply finishes, which this call demonstrates.
    cancellation.cancel();
    transaction_state
        .mark_committed(serde_json::json!({"releaseId": "r-1"}))
        .expect("post-commit work must still be able to finish");
    state::save(&managed, &state_file, &transaction_state).expect("state save should succeed");

    let loaded = state::load(&managed, &state_file).expect("state should load");
    assert_eq!(loaded.status, state::TransactionStatus::Committed);
}

#[test]
fn a_crashed_holder_leaves_recoverable_state_for_the_next_attempt() {
    let (_directory, managed) = managed_root();
    let lock_file = lock_path();
    let crashed = request_id("550e8400-e29b-41d4-a716-446655440000");
    let recovering = request_id("123e4567-e89b-12d3-a456-426614174000");
    let state_file = state_path(crashed);

    let guard =
        lock::acquire(&managed, &lock_file, crashed, Duration::ZERO).expect("lock should acquire");
    let transaction_state = TransactionState::start(crashed, None, OPERATION);
    state::create(&managed, &state_file, &transaction_state).expect("state should be created");
    // Simulate a crash: the process exits without releasing the lock or
    // ever transitioning the state out of `InProgress`.
    std::mem::forget(guard);

    let reclaimed = lock::acquire(&managed, &lock_file, recovering, Duration::ZERO)
        .expect("stale lock should be reclaimed by the next attempt");
    audit::append(
        &managed,
        &audit_path(),
        &audit::AuditRecord::lock_recovered(recovering, crashed, Duration::from_secs(0)),
    )
    .expect("lock-recovered audit event should append");

    let abandoned = state::load(&managed, &state_file)
        .expect("the crashed attempt's state must still be on disk for inspection");
    assert_eq!(
        abandoned.status,
        state::TransactionStatus::InProgress,
        "an abandoned transaction must not silently appear finished"
    );
    drop(reclaimed);
}

#[test]
fn retrying_with_the_same_idempotency_key_returns_the_original_outcome_without_new_work() {
    let (_directory, managed) = managed_root();
    let key = IdempotencyKey::parse("deploy-2026-09-02-01").expect("key should be valid");
    let first_attempt = request_id("550e8400-e29b-41d4-a716-446655440000");
    let retry_attempt = request_id("123e4567-e89b-12d3-a456-426614174000");

    assert_eq!(
        idempotency::claim(&managed, &key, first_attempt).expect("claim should succeed"),
        Resolution::Claimed
    );
    let mut transaction_state =
        TransactionState::start(first_attempt, Some(key.clone()), OPERATION);
    state::create(&managed, &state_path(first_attempt), &transaction_state)
        .expect("state should be created");
    transaction_state
        .mark_committed(serde_json::json!({"releaseId": "r-1"}))
        .expect("commit transition should succeed");
    state::save(&managed, &state_path(first_attempt), &transaction_state)
        .expect("state save should succeed");

    // The control plane retries with a fresh RequestId but the same key.
    let resolution =
        idempotency::claim(&managed, &key, retry_attempt).expect("claim lookup should succeed");
    assert_eq!(resolution, Resolution::AlreadyClaimed(first_attempt));

    let replayed = state::load(&managed, &state_path(first_attempt))
        .expect("the original attempt's outcome should be loadable for replay");
    assert_eq!(replayed.status, state::TransactionStatus::Committed);
    assert!(
        !managed.exists(&state_path(retry_attempt)),
        "a retried idempotent request must not create a second transaction"
    );
}
