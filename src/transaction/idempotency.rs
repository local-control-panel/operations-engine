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
}
