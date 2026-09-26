use std::io;

use serde::{Deserialize, Serialize};

use crate::{
    filesystem::ManagedRoot,
    site::SiteRelativePath,
    transaction::{IdempotencyKey, RequestId},
};

const INDEX_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Eq, PartialEq)]
pub enum Resolution {
    /// No prior attempt was recorded for this key; the caller's `RequestId`
    /// is now the canonical attempt and it should proceed with new work.
    Claimed,
    /// A prior attempt already owns this key. The caller should load that
    /// `RequestId`'s `TransactionState` and return its outcome instead of
    /// starting new work — this is what makes a retried request idempotent.
    AlreadyClaimed(RequestId),
}

#[derive(Debug, Eq, PartialEq)]
pub enum IndexError {
    /// Two different idempotency keys hashed to the same lookup path. This
    /// is expected to be exceedingly rare (64-bit hash space against a
    /// single site's request volume); failing the claim is safer than
    /// risking a return of some other request's outcome.
    // ponytail: a bucket holds exactly one key. If per-site request volume
    // ever makes collisions non-negligible, store multiple records per
    // bucket instead of widening the hash.
    HashCollision,
    Io,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IndexRecord {
    schema_version: u32,
    idempotency_key: String,
    request_id: RequestId,
    #[serde(default)]
    claimed_at_unix_secs: u64,
}

fn idempotency_dir() -> SiteRelativePath {
    SiteRelativePath::parse("transactions/idempotency")
        .expect("a fixed literal path is always a valid relative path")
}

/// Where the lookup entry for `key` lives. An implementation detail of this
/// module — callers use `claim`/`lookup`, not this path, directly.
fn index_path(key: &IdempotencyKey) -> SiteRelativePath {
    let hash = fnv1a(key.as_str().as_bytes());
    SiteRelativePath::parse(format!("transactions/idempotency/{hash:016x}.json"))
        .expect("a 16-character lowercase hex string is always a valid relative path")
}

/// Registers `request_id` as the attempt for `key` if no attempt is
/// registered yet. Concurrent callers racing on the same key see exactly
/// one `Claimed` and every other caller `AlreadyClaimed` with the winner's
/// `RequestId`, because the underlying write is
/// `ManagedRoot::create_new`'s atomic create-if-absent.
pub fn claim(
    root: &ManagedRoot,
    key: &IdempotencyKey,
    request_id: RequestId,
) -> Result<Resolution, IndexError> {
    root.create_dir_all(&idempotency_dir())
        .map_err(|_| IndexError::Io)?;
    let path = index_path(key);
    let record = IndexRecord {
        schema_version: INDEX_SCHEMA_VERSION,
        idempotency_key: key.as_str().to_owned(),
        request_id,
        claimed_at_unix_secs: unix_now_secs(),
    };
    let bytes = serde_json::to_vec(&record).map_err(|_| IndexError::Io)?;

    match root.create_new(&path, &bytes) {
        Ok(()) => Ok(Resolution::Claimed),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            resolve_existing(root, &path, key)
        }
        Err(_) => Err(IndexError::Io),
    }
}

/// Removes the claim for `key`, if one exists. Not-found is not an error -
/// the caller (`transaction::prune`) wants "no claim on disk afterward",
/// which an already-absent file already satisfies. Used to keep the
/// idempotency index from retaining an entry that points at a
/// `RequestId` whose `TransactionState` is about to be (or already was)
/// pruned - an index entry surviving its target only turns a future
/// retry into a `StateError::NotFound` instead of a clean "not claimed,
/// proceed as new" resolution, so this is deliberately called before the
/// state file it points to is removed, not after.
pub fn remove(root: &ManagedRoot, key: &IdempotencyKey) -> Result<(), IndexError> {
    match root.remove_file(&index_path(key)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(IndexError::Io),
    }
}

/// Overwrites the claim for `key` to point at `request_id`, regardless of
/// what (if anything) was recorded there before. Used only to recover an
/// orphaned claim - one whose `RequestId` has no backing transaction state,
/// typically because the original attempt crashed between claiming the key
/// and creating its transaction record. Callers must only call this after
/// independently establishing exclusivity (the site lock), never as a
/// substitute for `claim`'s atomic create-if-absent.
pub fn reclaim(
    root: &ManagedRoot,
    key: &IdempotencyKey,
    request_id: RequestId,
) -> Result<(), IndexError> {
    let path = index_path(key);
    let record = IndexRecord {
        schema_version: INDEX_SCHEMA_VERSION,
        idempotency_key: key.as_str().to_owned(),
        request_id,
        claimed_at_unix_secs: unix_now_secs(),
    };
    let bytes = serde_json::to_vec(&record).map_err(|_| IndexError::Io)?;
    root.write_atomic(&path, &bytes).map_err(|_| IndexError::Io)
}

/// One idempotency claim on disk, as much detail as a retention sweep
/// needs to decide whether it is orphaned.
pub struct ClaimEntry {
    pub path: SiteRelativePath,
    pub request_id: RequestId,
    pub claimed_at_unix_secs: u64,
}

/// Lists every idempotency claim on disk, for `transaction::prune`'s
/// orphaned-claim sweep. Not for ordinary lookup - use `claim`/`lookup` for
/// that. Best-effort: an entry this cannot list, read, or parse is
/// silently skipped, matching `transaction::prune`'s existing tolerance for
/// a directory sweep.
pub fn list(root: &ManagedRoot) -> Vec<ClaimEntry> {
    let Ok(dir) = root.open_managed_dir(&idempotency_dir()) else {
        return Vec::new();
    };
    let Ok(names) = dir.file_names() else {
        return Vec::new();
    };
    let mut entries = Vec::new();
    for name in names {
        if !name.ends_with(".json") {
            continue;
        }
        let Ok(path) = SiteRelativePath::parse(format!("transactions/idempotency/{name}")) else {
            continue;
        };
        let Ok(json) = root.read_to_string(&path) else {
            continue;
        };
        let Ok(record) = serde_json::from_str::<IndexRecord>(&json) else {
            continue;
        };
        entries.push(ClaimEntry {
            path,
            request_id: record.request_id,
            claimed_at_unix_secs: record.claimed_at_unix_secs,
        });
    }
    entries
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Looks up an existing claim for `key` without creating one.
pub fn lookup(root: &ManagedRoot, key: &IdempotencyKey) -> Result<Option<RequestId>, IndexError> {
    let path = index_path(key);
    if !root.exists(&path) {
        return Ok(None);
    }
    match resolve_existing(root, &path, key)? {
        Resolution::AlreadyClaimed(request_id) => Ok(Some(request_id)),
        Resolution::Claimed => unreachable!("an existing index entry is never freshly claimed"),
    }
}

fn resolve_existing(
    root: &ManagedRoot,
    path: &SiteRelativePath,
    key: &IdempotencyKey,
) -> Result<Resolution, IndexError> {
    let json = root.read_to_string(path).map_err(|_| IndexError::Io)?;
    let existing: IndexRecord = serde_json::from_str(&json).map_err(|_| IndexError::Io)?;
    if existing.schema_version != INDEX_SCHEMA_VERSION {
        return Err(IndexError::Io);
    }
    if existing.idempotency_key == key.as_str() {
        Ok(Resolution::AlreadyClaimed(existing.request_id))
    } else {
        Err(IndexError::HashCollision)
    }
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::{IndexError, Resolution, claim, index_path, lookup};
    use crate::{
        filesystem::ManagedRoot,
        site::TrustedRoot,
        transaction::{IdempotencyKey, RequestId},
    };

    fn managed_root() -> (tempfile::TempDir, ManagedRoot) {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let root = TrustedRoot::parse(directory.path()).expect("root should be valid");
        let managed = ManagedRoot::open(&root).expect("root should open");
        (directory, managed)
    }

    fn key(value: &str) -> IdempotencyKey {
        IdempotencyKey::parse(value).expect("test key should be valid")
    }

    fn id(uuid: &str) -> RequestId {
        RequestId::parse(uuid).expect("test UUID should be canonical")
    }

    #[test]
    fn a_retry_with_the_same_key_is_reported_instead_of_claimed_again() {
        let (_directory, managed) = managed_root();
        let deploy_key = key("deploy-2026-09-02-01");
        let first_attempt = id("550e8400-e29b-41d4-a716-446655440000");
        let retry_attempt = id("123e4567-e89b-12d3-a456-426614174000");

        assert_eq!(
            claim(&managed, &deploy_key, first_attempt).unwrap(),
            Resolution::Claimed
        );
        assert_eq!(
            claim(&managed, &deploy_key, retry_attempt).unwrap(),
            Resolution::AlreadyClaimed(first_attempt)
        );
    }

    #[test]
    fn lookup_distinguishes_unknown_from_claimed_keys() {
        let (_directory, managed) = managed_root();
        let deploy_key = key("deploy-2026-09-02-01");
        let first_attempt = id("550e8400-e29b-41d4-a716-446655440000");

        assert_eq!(lookup(&managed, &deploy_key).unwrap(), None);
        claim(&managed, &deploy_key, first_attempt).unwrap();
        assert_eq!(lookup(&managed, &deploy_key).unwrap(), Some(first_attempt));
    }

    #[test]
    fn a_hash_bucket_owned_by_a_different_key_is_reported_as_a_collision_not_a_match() {
        let (directory, managed) = managed_root();
        let colliding_key = key("some-other-callers-key");
        let path = index_path(&colliding_key);
        std::fs::create_dir_all(directory.path().join("transactions/idempotency"))
            .expect("idempotency dir should be created");
        std::fs::write(
            directory.path().join(path.as_path()),
            r#"{"schemaVersion":1,"idempotencyKey":"a-different-key","requestId":"550e8400-e29b-41d4-a716-446655440000"}"#,
        )
        .expect("colliding index entry should be written");

        let outcome = claim(
            &managed,
            &colliding_key,
            id("123e4567-e89b-12d3-a456-426614174000"),
        );
        assert_eq!(outcome.unwrap_err(), IndexError::HashCollision);
        assert_eq!(
            lookup(&managed, &colliding_key).unwrap_err(),
            IndexError::HashCollision
        );
    }

    #[test]
    fn reclaim_overwrites_an_existing_claim_regardless_of_its_current_target() {
        let (_directory, managed) = managed_root();
        let deploy_key = key("deploy-2026-09-02-01");
        let orphan = id("550e8400-e29b-41d4-a716-446655440000");
        let reclaimer = id("123e4567-e89b-12d3-a456-426614174000");

        claim(&managed, &deploy_key, orphan).unwrap();
        super::reclaim(&managed, &deploy_key, reclaimer).unwrap();

        assert_eq!(lookup(&managed, &deploy_key).unwrap(), Some(reclaimer));
    }

    #[test]
    fn list_reports_every_claim_with_its_request_id_and_claimed_at_time() {
        let (_directory, managed) = managed_root();
        let first_key = key("deploy-2026-09-02-01");
        let second_key = key("deploy-2026-09-02-02");
        let first_id = id("550e8400-e29b-41d4-a716-446655440000");
        let second_id = id("123e4567-e89b-12d3-a456-426614174000");
        claim(&managed, &first_key, first_id).unwrap();
        claim(&managed, &second_key, second_id).unwrap();

        let mut entries = super::list(&managed);
        entries.sort_by_key(|entry| entry.request_id.to_string());
        let mut expected = [first_id, second_id];
        expected.sort_by_key(|id| id.to_string());

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].request_id, expected[0]);
        assert_eq!(entries[1].request_id, expected[1]);
        assert!(entries.iter().all(|entry| entry.claimed_at_unix_secs > 0));
    }
}
