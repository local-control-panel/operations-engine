//! Everything a mutation attempt must establish before it is allowed to
//! touch operation-specific content (a deploy's `releases/`/`current`, a
//! rollback's `current`) — and that must never, by itself, change any of
//! it. Originally built for Phase 4 deploy (`src/deploy/preflight.rs`) and
//! generalized here once Phase 5 rollback needed the identical sequence:
//! idempotency-key replay, site lock, transaction state, and the
//! `MutationStart` audit event. Only `request_id`, `idempotency_key`, and
//! `operation` are parameters — the caller's request type is otherwise
//! irrelevant to this step.

use std::io;

use crate::{
    filesystem::ManagedRoot,
    site::{SiteId, SiteRelativePath},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditError, AuditRecord},
        idempotency::{self, IndexError, Resolution},
        lock::{self, DEFAULT_STALE_AFTER, LockError, SiteLockGuard},
        state::{self, StateError, TransactionState},
    },
};

/// Everything a caller needs to proceed into its own operation-specific
/// work: the held site lock (dropping it releases the site for the next
/// attempt) and the `InProgress` transaction state to keep transitioning
/// and saving.
pub struct Admitted<'a> {
    pub lock: SiteLockGuard<'a>,
    pub state: TransactionState,
}

pub enum Outcome<'a> {
    Proceed(Admitted<'a>),
    /// This request's idempotency key was already claimed by
    /// `RequestId`. The caller must load that request's `TransactionState`
    /// and return its outcome rather than doing any new work — this, not
    /// anything in `Admitted`, is what makes a retry idempotent.
    Replay(RequestId),
}

#[derive(Debug)]
pub enum Error {
    Idempotency(IndexError),
    Lock(LockError),
    State(StateError),
    Audit(AuditError),
}

/// Runs preflight for one mutation attempt against `site_state`, a
/// `ManagedRoot` already scoped to this one site's state subtree (see
/// `open_site_state`) — never the shared engine-wide state root, so
/// nothing here can address another site's lock, state, or audit log even
/// by a path-construction bug. `operation` is the stable protocol
/// operation name (e.g. `"site.deploy"`, `"site.rollback"`) recorded as
/// `TransactionState::operation` and in the `MutationStart` audit event.
pub fn run<'a>(
    site_state: &'a ManagedRoot,
    request_id: RequestId,
    idempotency_key: Option<&IdempotencyKey>,
    operation: &'static str,
) -> Result<Outcome<'a>, Error> {
    if let Some(key) = idempotency_key {
        match idempotency::claim(site_state, key, request_id).map_err(Error::Idempotency)? {
            Resolution::AlreadyClaimed(existing) => return Ok(Outcome::Replay(existing)),
            Resolution::Claimed => {}
        }
    }

    let lock = lock::acquire(site_state, &lock_path(), request_id, DEFAULT_STALE_AFTER)
        .map_err(Error::Lock)?;

    let transaction_state =
        TransactionState::start(request_id, idempotency_key.cloned(), operation);
    state::create(site_state, &state_path(request_id), &transaction_state).map_err(Error::State)?;

    audit::append(
        site_state,
        &audit_path(),
        &AuditRecord::mutation_start(request_id, idempotency_key.cloned(), operation),
    )
    .map_err(Error::Audit)?;

    Ok(Outcome::Proceed(Admitted {
        lock,
        state: transaction_state,
    }))
}

/// Opens (creating if necessary) the site-scoped state root that `run`
/// expects, and ensures the `locks`/`transactions`/`audit` subdirectories
/// `lock`/`state`/`audit`/`idempotency` write into already exist.
pub fn open_site_state(engine_state: &ManagedRoot, site_id: SiteId) -> io::Result<ManagedRoot> {
    let relative = SiteRelativePath::parse(format!("sites/{site_id}"))
        .expect("a canonical SiteId always yields a valid relative path");
    engine_state.create_dir_all(&relative)?;
    let site_state = engine_state.open_managed_dir(&relative)?;
    for sub in ["locks", "transactions", "audit"] {
        site_state.create_dir_all(&SiteRelativePath::parse(sub).expect("literal path is valid"))?;
    }
    Ok(site_state)
}

fn lock_path() -> SiteRelativePath {
    SiteRelativePath::parse("locks/mutation.lock").expect("literal path is valid")
}

fn state_path(request_id: RequestId) -> SiteRelativePath {
    SiteRelativePath::parse(format!("transactions/{request_id}.json"))
        .expect("a canonical RequestId always yields a valid relative path")
}

fn audit_path() -> SiteRelativePath {
    SiteRelativePath::parse("audit/events.jsonl").expect("literal path is valid")
}

#[cfg(test)]
mod tests {
    use super::{Error, Outcome, lock_path, open_site_state, run};
    use crate::{
        filesystem::ManagedRoot,
        site::{SiteId, TrustedRoot},
        transaction::{
            IdempotencyKey, RequestId,
            lock::{self, DEFAULT_STALE_AFTER},
            state::TransactionStatus,
        },
    };

    const SITE_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
    const REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const RETRY_REQUEST_ID: &str = "9b2f1c34-5678-4abc-9def-0123456789ab";
    const OPERATION: &str = "site.deploy";

    fn site_state() -> (tempfile::TempDir, ManagedRoot) {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let root = TrustedRoot::parse(directory.path()).expect("root should be valid");
        let engine_state = ManagedRoot::open(&root).expect("root should open");
        let site_id = SiteId::parse(SITE_ID).expect("site id should be canonical");
        let site_state = open_site_state(&engine_state, site_id).expect("site state should open");
        (directory, site_state)
    }

    fn request_id(value: &str) -> RequestId {
        RequestId::parse(value).expect("test UUID should be canonical")
    }

    #[test]
    fn admits_a_fresh_request_and_leaves_state_and_lock_in_place() {
        let (_directory, site_state) = site_state();
        let outcome = run(&site_state, request_id(REQUEST_ID), None, OPERATION)
            .expect("preflight should run");

        let admitted = match outcome {
            Outcome::Proceed(admitted) => admitted,
            Outcome::Replay(_) => panic!("a fresh request must not be treated as a replay"),
        };
        assert_eq!(admitted.state.status, TransactionStatus::InProgress);

        // The lock is genuinely held: a second attempt for the same site
        // must observe it, not silently acquire it too.
        let contended = lock::acquire(
            &site_state,
            &lock_path(),
            request_id(RETRY_REQUEST_ID),
            DEFAULT_STALE_AFTER,
        );
        assert!(matches!(contended, Err(lock::LockError::Held { .. })));
    }

    #[test]
    fn a_second_preflight_for_the_same_site_is_rejected_while_the_first_is_admitted() {
        let (_directory, site_state) = site_state();
        let _admitted =
            run(&site_state, request_id(REQUEST_ID), None, OPERATION).expect("first should admit");

        let second = run(&site_state, request_id(RETRY_REQUEST_ID), None, OPERATION);
        assert!(matches!(
            second,
            Err(Error::Lock(lock::LockError::Held { .. }))
        ));
    }

    #[test]
    fn a_retry_with_the_same_idempotency_key_is_reported_as_a_replay_without_touching_the_lock() {
        let (_directory, site_state) = site_state();
        let key = IdempotencyKey::parse("deploy-2026-09-02-01").expect("key should be valid");

        let first = run(&site_state, request_id(REQUEST_ID), Some(&key), OPERATION)
            .expect("first should admit");
        let Outcome::Proceed(admitted) = first else {
            panic!("first attempt must proceed")
        };
        // The first attempt's lock is still held at this point.

        let retry = run(
            &site_state,
            request_id(RETRY_REQUEST_ID),
            Some(&key),
            OPERATION,
        )
        .expect("replay should resolve");
        match retry {
            Outcome::Replay(original) => {
                assert_eq!(original.to_string(), REQUEST_ID);
            }
            Outcome::Proceed(_) => panic!("a retried idempotency key must not start new work"),
        }
        drop(admitted);
    }
}
