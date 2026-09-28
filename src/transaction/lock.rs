use std::{
    io::{self, Seek, SeekFrom, Write},
    os::fd::AsRawFd,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{filesystem::ManagedRoot, site::SiteRelativePath, transaction::RequestId};

const LOCK_SCHEMA_VERSION: u32 = 1;

/// Holds an exclusive per-site mutation lock, backed by an OS `flock` on
/// the lock file's file descriptor rather than the file's mere existence
/// or age. The kernel releases the lock the instant every file descriptor
/// referring to it closes - including on process crash or `SIGKILL`, with
/// no code here needing to run - so a live holder stays exclusive
/// indefinitely and a dead one's lock is available to the very next
/// `acquire` call, with no time-based staleness bound at all. Dropping the
/// guard closes the file descriptor (releasing the lock) and deliberately
/// never unlinks the file: unlinking on drop was the previous design's
/// actual bug (a guard whose lock had already been reclaimed by a later
/// holder would delete *that* holder's lock file out from under it).
/// Reusing the same file forever means an old guard has nothing left to
/// delete.
pub struct SiteLockGuard<'a> {
    _root: &'a ManagedRoot,
    _file: std::fs::File,
}

impl std::fmt::Debug for SiteLockGuard<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SiteLockGuard").finish()
    }
}

/// Exposes the guard's underlying file descriptor so external callers (e.g.
/// integration tests outside this crate's module tree, which cannot reach
/// the private `_file` field) can perform a faithful crash simulation - an
/// explicit `close` on this fd, not just dropping or forgetting the guard -
/// the same way `std::fs::File` itself exposes its own fd.
#[doc(hidden)]
impl std::os::fd::AsRawFd for SiteLockGuard<'_> {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self._file.as_raw_fd()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum LockError {
    /// Another request holds the lock right now. `holder` is `None` when
    /// the lock is genuinely held (the kernel's `flock` proved it) but this
    /// holder's own diagnostic record could not be read back - e.g. it is
    /// mid-write - which is still ordinary contention, not an internal
    /// failure.
    Held {
        holder: Option<RequestId>,
        held_for: Duration,
    },
    /// The lock file could not be opened, locked, read, or written as
    /// expected.
    Io,
}

/// Acquires the OS-level exclusive lock on the file at `path` beneath
/// `root` for `holder`. Never blocks: if another live process holds the
/// lock, this returns `LockError::Held` immediately with that holder's
/// identity and how long it has held the lock, read from the file's own
/// content (best-effort diagnostics only - it plays no part in whether the
/// lock is granted).
pub fn acquire<'a>(
    root: &'a ManagedRoot,
    path: &SiteRelativePath,
    holder: RequestId,
) -> Result<SiteLockGuard<'a>, LockError> {
    let mut file = root.open_or_create_file(path).map_err(|_| LockError::Io)?;

    // SAFETY: `file`'s raw fd is open and valid for the duration of this
    // call, which is all `flock` needs.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result != 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock {
            return Err(match read_lock(root, path) {
                Ok(existing) => LockError::Held {
                    holder: Some(existing.record.holder),
                    held_for: existing.held_for,
                },
                Err(_) => LockError::Held {
                    holder: None,
                    held_for: Duration::ZERO,
                },
            });
        }
        return Err(LockError::Io);
    }

    let record = lock_record_bytes(holder)?;
    file.set_len(0).map_err(|_| LockError::Io)?;
    file.seek(SeekFrom::Start(0)).map_err(|_| LockError::Io)?;
    file.write_all(&record).map_err(|_| LockError::Io)?;
    file.sync_all().map_err(|_| LockError::Io)?;

    Ok(SiteLockGuard {
        _root: root,
        _file: file,
    })
}

/// Reports the live kernel lock holder without changing the diagnostic
/// record. A free lock returns `None`; stale file contents alone never count
/// as an active operation.
pub fn holder(
    root: &ManagedRoot,
    path: &SiteRelativePath,
) -> Result<Option<RequestId>, LockError> {
    let file = root.open_or_create_file(path).map_err(|_| LockError::Io)?;
    // SAFETY: `file` remains open for the duration of both flock calls.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        unsafe {
            libc::flock(file.as_raw_fd(), libc::LOCK_UN);
        }
        return Ok(None);
    }
    let error = io::Error::last_os_error();
    if error.kind() != io::ErrorKind::WouldBlock {
        return Err(LockError::Io);
    }
    Ok(read_lock(root, path).ok().map(|existing| existing.record.holder))
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
    use std::os::fd::AsRawFd;

    use super::{LockError, acquire, holder as current_holder};
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

        let _guard = acquire(&managed, &path, first).expect("first acquire should succeed");

        match acquire(&managed, &path, second) {
            Err(LockError::Held {
                holder,
                held_for: _,
            }) => {
                assert_eq!(holder, Some(first));
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

        drop(acquire(&managed, &path, first).expect("acquire should succeed"));

        acquire(&managed, &path, second).expect("lock should be free after release");
    }

    #[test]
    fn holder_uses_the_kernel_lock_not_stale_file_contents() {
        let (_directory, managed) = managed_root();
        let path = lock_path();
        let first = holder("550e8400-e29b-41d4-a716-446655440000");
        let guard = acquire(&managed, &path, first).unwrap();
        assert_eq!(current_holder(&managed, &path).unwrap(), Some(first));
        drop(guard);
        assert_eq!(current_holder(&managed, &path).unwrap(), None);
    }

    #[test]
    fn a_crashed_holders_lock_is_immediately_available_to_the_next_acquire() {
        let (_directory, managed) = managed_root();
        let path = lock_path();
        let first = holder("550e8400-e29b-41d4-a716-446655440000");
        let second = holder("123e4567-e89b-12d3-a456-426614174000");

        let guard = acquire(&managed, &path, first).expect("first acquire should succeed");
        // Simulate the holder process dying: the kernel closes every file
        // descriptor the process held - including this one - without
        // running any of this guard's own Drop logic. `mem::forget` skips
        // Drop but leaves the fd open, so an explicit `close` here is what
        // actually reproduces "the fd is gone", the only thing that
        // releases an flock.
        let fd = guard._file.as_raw_fd();
        std::mem::forget(guard);
        unsafe {
            libc::close(fd);
        }

        let reclaimed = acquire(&managed, &path, second);
        assert!(
            reclaimed.is_ok(),
            "a lock left by a crashed holder must be immediately available, not merely \
             stale-eligible after a timeout: {reclaimed:?}"
        );
    }

    #[test]
    fn a_corrupt_but_unheld_lock_file_is_acquired_and_repaired_instead_of_permanently_blocked() {
        let (directory, managed) = managed_root();
        let path = lock_path();
        std::fs::write(directory.path().join("locks/mutation.lock"), b"not json")
            .expect("corrupt lock file should be written");

        let outcome = acquire(
            &managed,
            &path,
            holder("550e8400-e29b-41d4-a716-446655440000"),
        );
        assert!(
            outcome.is_ok(),
            "corrupt content with no live OS-level holder must not block acquisition \
             (exclusivity is the kernel's flock, never the file's content): {outcome:?}"
        );

        // The record is now valid again for the next caller's diagnostics.
        let second = acquire(
            &managed,
            &path,
            holder("123e4567-e89b-12d3-a456-426614174000"),
        );
        match second {
            Err(LockError::Held {
                holder: found_holder,
                ..
            }) => {
                assert_eq!(
                    found_holder,
                    Some(holder("550e8400-e29b-41d4-a716-446655440000"))
                );
            }
            other => panic!("expected the repaired record to report the new holder: {other:?}"),
        }
    }
}
