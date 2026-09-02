use std::{
    io,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{filesystem::ManagedRoot, site::SiteRelativePath, transaction::RequestId};

const LOCK_SCHEMA_VERSION: u32 = 1;

/// Default bound after which an unreleased lock is treated as abandoned and
/// reclaimed by the next request, regardless of whether its original holder
/// process is still running.
// ponytail: staleness is purely time-based; it does not check whether the
// holder's process is still alive (e.g. via /proc/<pid> on Linux). Add that
// check if recovery needs to be faster than this bound without shortening it
// for every caller.
pub const DEFAULT_STALE_AFTER: Duration = Duration::from_secs(15 * 60);

/// Holds an exclusive per-site mutation lock. Dropping it releases the lock.
pub struct SiteLockGuard<'a> {
    root: &'a ManagedRoot,
    path: SiteRelativePath,
}

impl std::fmt::Debug for SiteLockGuard<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SiteLockGuard")
            .field("path", &self.path)
            .finish()
    }
}

impl Drop for SiteLockGuard<'_> {
    fn drop(&mut self) {
        let _ = self.root.remove_file(&self.path);
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum LockError {
    /// Another request holds the lock and it is not yet stale.
    Held {
        holder: RequestId,
        held_for: Duration,
    },
    /// The lock file could not be created, read, or removed as expected.
    Io,
}

/// Acquires the lock at `path` beneath `root` for `holder`, reclaiming it
/// first if the existing lock is older than `stale_after`.
///
/// Reclaiming makes exactly one retry attempt: if another request wins that
/// retry, this call reports the lock as held rather than retrying further.
pub fn acquire<'a>(
    root: &'a ManagedRoot,
    path: &SiteRelativePath,
    holder: RequestId,
    stale_after: Duration,
) -> Result<SiteLockGuard<'a>, LockError> {
    let record = lock_record_bytes(holder)?;

    match root.create_new(path, &record) {
        Ok(()) => {
            return Ok(SiteLockGuard {
                root,
                path: path.clone(),
            });
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(LockError::Io),
    }

    let existing = read_lock(root, path)?;
    if existing.held_for < stale_after {
        return Err(LockError::Held {
            holder: existing.record.holder,
            held_for: existing.held_for,
        });
    }

    let _ = root.remove_file(path);
    match root.create_new(path, &record) {
        Ok(()) => Ok(SiteLockGuard {
            root,
            path: path.clone(),
        }),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let existing = read_lock(root, path)?;
            Err(LockError::Held {
                holder: existing.record.holder,
                held_for: existing.held_for,
            })
        }
        Err(_) => Err(LockError::Io),
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LockRecord {
    schema_version: u32,
    holder: RequestId,
    acquired_at_unix_secs: u64,
}

struct ExistingLock {
    record: LockRecord,
    held_for: Duration,
}

fn lock_record_bytes(holder: RequestId) -> Result<Vec<u8>, LockError> {
    let record = LockRecord {
        schema_version: LOCK_SCHEMA_VERSION,
        holder,
        acquired_at_unix_secs: unix_now_secs(),
    };
    serde_json::to_vec(&record).map_err(|_| LockError::Io)
}

fn read_lock(root: &ManagedRoot, path: &SiteRelativePath) -> Result<ExistingLock, LockError> {
    let json = root.read_to_string(path).map_err(|_| LockError::Io)?;
    let record: LockRecord = serde_json::from_str(&json).map_err(|_| LockError::Io)?;
    if record.schema_version != LOCK_SCHEMA_VERSION {
        return Err(LockError::Io);
    }
    let held_for =
        Duration::from_secs(unix_now_secs().saturating_sub(record.acquired_at_unix_secs));
    Ok(ExistingLock { record, held_for })
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use std::{mem, time::Duration};

    use super::{DEFAULT_STALE_AFTER, LockError, acquire};
    use crate::{
        filesystem::ManagedRoot,
        site::{SiteRelativePath, TrustedRoot},
        transaction::RequestId,
    };

    fn holder(uuid: &str) -> RequestId {
        RequestId::parse(uuid).expect("test UUID should be canonical")
    }

    fn managed_root() -> (tempfile::TempDir, ManagedRoot) {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let root = TrustedRoot::parse(directory.path()).expect("root should be valid");
        let managed = ManagedRoot::open(&root).expect("root should open");
        let locks_dir = SiteRelativePath::parse("locks").expect("locks dir path should be valid");
        managed
            .create_dir_all(&locks_dir)
            .expect("locks dir should be created");
        (directory, managed)
    }

    fn lock_path() -> SiteRelativePath {
        SiteRelativePath::parse("locks/mutation.lock").expect("lock path should be valid")
    }

    #[test]
    fn second_acquire_is_held_while_first_guard_is_alive() {
        let (_directory, managed) = managed_root();
        let path = lock_path();
        let first = holder("550e8400-e29b-41d4-a716-446655440000");
        let second = holder("123e4567-e89b-12d3-a456-426614174000");

        let _guard = acquire(&managed, &path, first, DEFAULT_STALE_AFTER)
            .expect("first acquire should succeed");

        match acquire(&managed, &path, second, DEFAULT_STALE_AFTER) {
            Err(LockError::Held { holder, held_for }) => {
                assert_eq!(holder, first);
                assert!(held_for < DEFAULT_STALE_AFTER);
            }
            other => panic!("expected Held, got {other:?}"),
        }
    }

    #[test]
    fn dropping_the_guard_releases_the_lock() {
        let (_directory, managed) = managed_root();
        let path = lock_path();
        let first = holder("550e8400-e29b-41d4-a716-446655440000");
        let second = holder("123e4567-e89b-12d3-a456-426614174000");

        drop(acquire(&managed, &path, first, DEFAULT_STALE_AFTER).expect("acquire should succeed"));

        acquire(&managed, &path, second, DEFAULT_STALE_AFTER)
            .expect("lock should be free after release");
    }

    #[test]
    fn abandoned_lock_is_reclaimed_once_it_is_older_than_the_stale_bound() {
        let (_directory, managed) = managed_root();
        let path = lock_path();
        let first = holder("550e8400-e29b-41d4-a716-446655440000");
        let second = holder("123e4567-e89b-12d3-a456-426614174000");

        // Lock staleness has whole-second resolution, so a zero bound is the
        // deterministic way to exercise "older than the bound" without a
        // real sleep: as soon as it exists, its age (>= 0s) is >= 0s.
        let guard =
            acquire(&managed, &path, first, Duration::ZERO).expect("first acquire should succeed");
        // Simulate a crashed holder: the lock file stays behind without ever
        // running the release-on-drop path.
        mem::forget(guard);

        let reclaimed = acquire(&managed, &path, second, Duration::ZERO);
        assert!(reclaimed.is_ok(), "expected reclaim, got {reclaimed:?}");
    }

    #[test]
    fn corrupt_lock_file_is_reported_instead_of_silently_reclaimed() {
        let (directory, managed) = managed_root();
        let path = lock_path();
        std::fs::write(directory.path().join("locks/mutation.lock"), b"not json")
            .expect("corrupt lock file should be written");

        let outcome = acquire(
            &managed,
            &path,
            holder("550e8400-e29b-41d4-a716-446655440000"),
            DEFAULT_STALE_AFTER,
        );
        assert_eq!(outcome.unwrap_err(), LockError::Io);
    }
}
