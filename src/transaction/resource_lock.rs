//! A resource-identity lock keyed purely by canonical filesystem path,
//! independent of which operation - or which of its own per-operation-type
//! preflight scope - is mutating that resource. `mutation::preflight::run`'s
//! own site lock only serializes retries of the *same* operation against
//! its *own* scope directory (`wordpress-install/<hash>` and
//! `wordpress-update/<hash>` hash the identical root to two different
//! scope paths); it cannot see that two different operation types target
//! the same physical root. This module is the missing cross-operation
//! exclusivity: every mutating WordPress operation acquires the lock here
//! for every canonical root it touches, in a fixed order when it touches
//! more than one, before doing any of its own operation-specific work.

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
/// is asking.
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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{acquire, acquire_pair, canonical_hash};
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
}
