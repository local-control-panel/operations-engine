//! A resource-identity lock keyed purely by canonical filesystem path,
//! independent of which operation - or which of its own per-operation-type
//! preflight scope - is mutating that resource. `mutation::preflight::run`'s
//! own site lock only serializes retries of the *same* operation against
//! its *own* scope directory (`wordpress-install/<hash>` and
//! `wordpress-update/<hash>` hash the identical root to two different
//! scope paths); it cannot see that two different operation types target
//! the same physical root. This module is the missing cross-operation
//! exclusivity: `wordpress_{install,update,clone}` and
//! `permissions::{execute,world_writable}` each acquire the lock here for
//! every canonical root they touch, in a fixed order when more than one, and
//! before doing any of their own operation-specific work.
//!
//! `resource-locks/` is never swept: unlike `transactions/` and
//! `transactions/idempotency/`, a lock file here is kept forever once
//! created (deleting it would be unsafe under the current design - see
//! `transaction::lock`'s module doc for why a lock file is never unlinked).
//! In practice this is bounded by the number of distinct roots the engine
//! is ever asked to touch, which content-root validation upstream already
//! keeps finite.

use std::{fmt::Write as _, path::Path};

use sha2::{Digest, Sha256};

use crate::{
    filesystem::ManagedRoot,
    site::SiteRelativePath,
    transaction::{
        RequestId,
        lock::{self, LockError, SiteLockGuard},
    },
};

fn locks_dir() -> SiteRelativePath {
    SiteRelativePath::parse("resource-locks").expect("a fixed literal path is always valid")
}

/// The path-independent identity two operations must agree on to be
/// considered "the same resource" - the root path, hashed the same way
/// regardless of which operation, or which of its own scope directories,
/// is asking. Hashes the raw path bytes only - it does not resolve `.`/`..`,
/// symlinks, or a trailing separator, so callers are responsible for passing
/// an already-canonical spelling of a root for cross-operation exclusivity
/// to actually hold (every current caller does: the same `req.root`/
/// `req.staging_root`/`req.source_root` string this crate's own preflight
/// scopes already hash the identical way).
pub fn canonical_hash(root: &Path) -> String {
    let digest = Sha256::digest(root.as_os_str().as_encoded_bytes());
    let mut hash = String::new();
    for byte in digest {
        write!(&mut hash, "{byte:02x}").unwrap();
    }
    hash
}

/// Acquires the exclusive resource lock for `root` beneath `engine_state` -
/// the engine-wide state root every WordPress operation already holds as
/// `Context::engine_state`, never a per-operation scope, so every
/// operation type computes the identical lock path for the identical
/// root. Creates `resource-locks/` on first use.
pub fn acquire<'a>(
    engine_state: &'a ManagedRoot,
    root: &Path,
    holder: RequestId,
) -> Result<SiteLockGuard<'a>, LockError> {
    engine_state
        .create_dir_all(&locks_dir())
        .map_err(|_| LockError::Io)?;
    let path = SiteRelativePath::parse(format!("resource-locks/{}.lock", canonical_hash(root)))
        .map_err(|_| LockError::Io)?;
    lock::acquire(engine_state, &path, holder)
}

/// Acquires the resource locks for `first` and `second`, always in
/// canonical-hash order regardless of which the caller considers primary -
/// so two operations racing on the same pair from opposite directions
/// (e.g. a clone from A to B racing a clone from B to A) always attempt
/// the same resource first. Every lock in this module is already
/// non-blocking (`LockError::Held` returns immediately rather than
/// waiting), so this cannot produce a classic mutual-wait deadlock; fixed
/// ordering instead prevents a livelock where two opposite-direction
/// retriers keep failing against each other's second lock forever.
/// Returns a single guard when `first` and `second` resolve to the same
/// resource, rather than attempting to lock an already-held path again.
// ponytail: the ordering-avoids-livelock property is argued here, not
// exercised under real concurrent threads/processes - this module's own
// tests are sequential. If a Docker/integration-level bidirectional-clone
// regression is ever added (the codebase's existing pattern for real
// concurrency claims, per `migration-status.md`'s own note that
// thread-only tests do not prove inter-process exclusivity), it belongs
// alongside `workflow_tests::`, not here.
pub fn acquire_pair<'a>(
    engine_state: &'a ManagedRoot,
    first: &Path,
    second: &Path,
    holder: RequestId,
) -> Result<(SiteLockGuard<'a>, Option<SiteLockGuard<'a>>), LockError> {
    let first_hash = canonical_hash(first);
    let second_hash = canonical_hash(second);
    if first_hash == second_hash {
        return Ok((acquire(engine_state, first, holder)?, None));
    }
    let (lower, higher) = if first_hash < second_hash {
        (first, second)
    } else {
        (second, first)
    };
    let lower_guard = acquire(engine_state, lower, holder)?;
    let higher_guard = acquire(engine_state, higher, holder)?;
    Ok((lower_guard, Some(higher_guard)))
}

/// Acquires the resource locks for every root in `roots`, deduplicated and
/// always attempted in canonical-hash order regardless of the input order -
/// the N-ary generalization of `acquire_pair` for operations that touch an
/// arbitrary number of roots in one request (e.g. `permissions::execute`'s
/// per-target ownership repair). If any acquisition fails, every guard
/// already acquired in this call is dropped (released) before the error
/// returns, since they are only ever held locally in the returned `Vec`.
pub fn acquire_many<'a>(
    engine_state: &'a ManagedRoot,
    roots: &[&Path],
    holder: RequestId,
) -> Result<Vec<SiteLockGuard<'a>>, LockError> {
    let mut hashed: Vec<(String, &Path)> = Vec::with_capacity(roots.len());
    for &root in roots {
        let hash = canonical_hash(root);
        if !hashed.iter().any(|(existing, _)| existing == &hash) {
            hashed.push((hash, root));
        }
    }
    hashed.sort_by(|(a, _), (b, _)| a.cmp(b));

    let mut guards = Vec::with_capacity(hashed.len());
    for (_, root) in hashed {
        guards.push(acquire(engine_state, root, holder)?);
    }
    Ok(guards)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{acquire, acquire_many, acquire_pair, canonical_hash};
    use crate::{
        filesystem::ManagedRoot,
        site::TrustedRoot,
        transaction::{RequestId, lock::LockError},
    };

    fn holder(uuid: &str) -> RequestId {
        RequestId::parse(uuid).expect("test UUID should be canonical")
    }

    fn managed_root() -> (tempfile::TempDir, ManagedRoot) {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let root = TrustedRoot::parse(directory.path()).expect("root should be valid");
        (
            directory,
            ManagedRoot::open(&root).expect("root should open"),
        )
    }

    #[test]
    fn canonical_hash_is_deterministic_and_distinguishes_different_paths() {
        let a = canonical_hash(Path::new("/content/example.com"));
        let a_again = canonical_hash(Path::new("/content/example.com"));
        let b = canonical_hash(Path::new("/content/other.com"));
        assert_eq!(a, a_again);
        assert_ne!(a, b);
    }

    #[test]
    fn acquire_on_the_same_root_is_held_across_calls_regardless_of_the_caller() {
        let (_directory, engine_state) = managed_root();
        let root = Path::new("/content/example.com");

        let _held = acquire(
            &engine_state,
            root,
            holder("550e8400-e29b-41d4-a716-446655440000"),
        )
        .expect("first acquire should succeed");

        let contended = acquire(
            &engine_state,
            root,
            holder("123e4567-e89b-12d3-a456-426614174000"),
        );
        assert!(matches!(contended, Err(LockError::Held { .. })));
    }

    #[test]
    fn acquire_pair_locks_both_distinct_roots() {
        let (_directory, engine_state) = managed_root();
        let a = Path::new("/content/a.example.com");
        let b = Path::new("/content/b.example.com");
        let owner = holder("550e8400-e29b-41d4-a716-446655440000");
        let racer = holder("123e4567-e89b-12d3-a456-426614174000");

        let (_first, _second) =
            acquire_pair(&engine_state, a, b, owner).expect("pair acquire should succeed");

        assert!(matches!(
            acquire(&engine_state, a, racer),
            Err(LockError::Held { .. })
        ));
        assert!(matches!(
            acquire(&engine_state, b, racer),
            Err(LockError::Held { .. })
        ));
    }

    #[test]
    fn acquire_pair_returns_a_single_guard_for_a_degenerate_same_path_pair() {
        let (_directory, engine_state) = managed_root();
        let root = Path::new("/content/example.com");
        let owner = holder("550e8400-e29b-41d4-a716-446655440000");

        let (_first, second) =
            acquire_pair(&engine_state, root, root, owner).expect("pair acquire should succeed");
        assert!(
            second.is_none(),
            "a same-path pair must acquire the resource exactly once, not twice"
        );
    }

    #[test]
    fn acquire_pair_locks_in_the_same_order_regardless_of_argument_order() {
        let (_directory, engine_state_ab) = managed_root();
        let (_directory2, engine_state_ba) = managed_root();
        let a = Path::new("/content/a.example.com");
        let b = Path::new("/content/b.example.com");
        let owner = holder("550e8400-e29b-41d4-a716-446655440000");

        let _ab = acquire_pair(&engine_state_ab, a, b, owner).expect("a,b order should succeed");
        let _ba = acquire_pair(&engine_state_ba, b, a, owner).expect("b,a order should succeed");

        // Both orderings must have locked the exact same two canonical
        // paths - proven by both engine states now holding both locks,
        // not by inspecting internal call order.
        let racer = holder("123e4567-e89b-12d3-a456-426614174000");
        assert!(matches!(
            acquire(&engine_state_ab, a, racer),
            Err(LockError::Held { .. })
        ));
        assert!(matches!(
            acquire(&engine_state_ab, b, racer),
            Err(LockError::Held { .. })
        ));
        assert!(matches!(
            acquire(&engine_state_ba, a, racer),
            Err(LockError::Held { .. })
        ));
        assert!(matches!(
            acquire(&engine_state_ba, b, racer),
            Err(LockError::Held { .. })
        ));
    }

    /// Regression test for the E-01/E-03 whole-branch review's Minor #7:
    /// proves attempt *order* is governed by hash comparison, not argument
    /// position, using the fact that `acquire` creates the lock file before
    /// attempting the flock - so a never-attempted root leaves no file
    /// behind, and an attempted-then-released one does.
    #[test]
    fn acquire_pair_attempts_the_lower_hash_root_first_regardless_of_argument_order() {
        let (directory, engine_state) = managed_root();
        let a = Path::new("/content/a.example.com");
        let b = Path::new("/content/b.example.com");
        let (lower, higher) = if canonical_hash(a) < canonical_hash(b) {
            (a, b)
        } else {
            (b, a)
        };
        let owner = holder("550e8400-e29b-41d4-a716-446655440000");
        let racer = holder("123e4567-e89b-12d3-a456-426614174000");

        let _held_higher =
            acquire(&engine_state, higher, racer).expect("higher lock should be free");

        // `higher` is passed in argument position 1 - the opposite of hash
        // order. Under argument-ordered attempts this would fail on
        // `higher` immediately and never touch `lower`; under hash-ordered
        // attempts (the actual implementation) it tries `lower` first.
        let outcome = acquire_pair(&engine_state, higher, lower, owner);
        assert!(
            matches!(outcome, Err(LockError::Held { .. })),
            "expected failure on the already-held higher-hash root: {outcome:?}"
        );

        let lower_lock_path = directory
            .path()
            .join(format!("resource-locks/{}.lock", canonical_hash(lower)));
        assert!(
            lower_lock_path.exists(),
            "the lower-hash root must have been attempted (and released) before failing on \
             the higher-hash root - proving attempt order is hash-based, not argument-based"
        );
    }

    #[test]
    fn acquire_many_locks_every_distinct_root_and_dedups_repeats() {
        let (_directory, engine_state) = managed_root();
        let a = Path::new("/content/a.example.com");
        let b = Path::new("/content/b.example.com");
        let c = Path::new("/content/c.example.com");
        let owner = holder("550e8400-e29b-41d4-a716-446655440000");
        let racer = holder("123e4567-e89b-12d3-a456-426614174000");

        let guards =
            acquire_many(&engine_state, &[a, b, a, c], owner).expect("acquire_many should succeed");
        assert_eq!(
            guards.len(),
            3,
            "a repeated root must be locked once, not attempted twice"
        );

        for root in [a, b, c] {
            assert!(matches!(
                acquire(&engine_state, root, racer),
                Err(LockError::Held { .. })
            ));
        }
    }

    #[test]
    fn acquire_many_releases_already_acquired_guards_when_a_later_one_fails() {
        let (_directory, engine_state) = managed_root();
        let a = Path::new("/content/a.example.com");
        let b = Path::new("/content/b.example.com");
        let owner = holder("550e8400-e29b-41d4-a716-446655440000");
        let racer = holder("123e4567-e89b-12d3-a456-426614174000");

        let _held_b = acquire(&engine_state, b, racer).expect("b should be free to acquire");

        let outcome = acquire_many(&engine_state, &[a, b], owner);
        assert!(matches!(outcome, Err(LockError::Held { .. })));

        // `a` must have been released (not left dangling) once the call
        // failed on `b` - `acquire_many` never returns partial guards, so
        // the `Vec` holding `a`'s guard was dropped when `?` returned early.
        let a_reacquired = acquire(&engine_state, a, owner);
        assert!(
            a_reacquired.is_ok(),
            "a must be released after acquire_many fails on a later root: {a_reacquired:?}"
        );
    }
}
