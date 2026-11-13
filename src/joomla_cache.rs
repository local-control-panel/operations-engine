//! `joomla.clearCache`: empty a Joomla site's file caches.
//!
//! Joomla's console has no "clear all caches" command (`cache:clean` cleans
//! only the default group), so the engine deletes the *contents* of the two
//! cache directories itself: `cache/` (site) and `administrator/cache/`.
//! Nothing else is touched: not the directories themselves, not their
//! owner or mode, not `tmp/`, `logs/`, sessions or the database.
//!
//! Every step is descriptor-relative through `ManagedRoot`: the project root
//! is opened once, `cache`, `administrator` and `administrator/cache` are
//! opened with `O_NOFOLLOW`, and children are entered the same way, so a
//! symlink planted in a tenant-writable tree can neither redirect the walk
//! outside the two roots nor be followed (a symlink is unlinked, never
//! entered). If either root is a symlink or not a directory the request is
//! refused before anything is deleted. The directory placeholders Joomla
//! ships (`index.html`, `.htaccess`, `web.config`) directly inside a root
//! stay.
//!
//! The result is the number of entries removed and their size in bytes
//! (regular files only; directories and links count as entries). Same
//! lock/idempotency/transaction/audit as the other site operations. A
//! second call with the same idempotency key replays the recorded result and
//! deletes nothing.

use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    site::{SiteRelativePath, TrustedRoot},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        resource_lock,
        state::{self, TransactionStatus},
    },
};
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

pub const OPERATION: &str = "joomla.clearCache";

/// Files Joomla ships inside its cache directories; they are kept.
const KEEP: [&str; 3] = ["index.html", ".htaccess", "web.config"];
/// A cache tree is a few levels deep; this stops a pathological tree.
const MAX_DEPTH: usize = 32;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    project_root: String,
}

#[derive(Debug)]
pub struct Request {
    project_root: PathBuf,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    InvalidRoot,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl Request {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        if plan.project_root.len() > 4096 || plan.project_root.chars().any(char::is_control) {
            return Err(RequestError::InvalidRoot);
        }
        let project_root = TrustedRoot::parse(&plan.project_root)
            .map_err(|_| RequestError::InvalidRoot)?
            .as_path()
            .to_owned();
        Ok(Self {
            project_root,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }

    pub fn root(&self) -> &std::path::Path {
        &self.project_root
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClearResult {
    /// Entries removed (files, links and directories) under both roots.
    pub removed_entries: u64,
    /// Bytes of the regular files removed.
    pub removed_bytes: u64,
    pub completed_at_unix_secs: u64,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    ResourceBusy,
    /// No `configuration.php` in the project root.
    NotJoomla,
    /// A cache root is a symlink or not a directory, or the tree is too deep.
    UnsafeTarget,
    Delete(std::io::Error),
    PostCommit {
        result: ClearResult,
    },
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) | Self::ResourceBusy => (
                ErrorCode::Conflict,
                "another operation is already in progress for this site".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::NotJoomla => (
                ErrorCode::InvalidInput,
                "the project root has no configuration.php, so it is not a Joomla project".into(),
            ),
            Self::UnsafeTarget => (
                ErrorCode::InvalidInput,
                "a Joomla cache directory is a symlink, not a directory, or too deeply nested"
                    .into(),
            ),
            Self::Delete(_) => (
                ErrorCode::Internal,
                "could not remove everything from the Joomla cache directories".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit { .. } => {
                (ErrorCode::Internal, "internal cache action error".into())
            }
        }
    }
}

fn rel(name: &str) -> SiteRelativePath {
    SiteRelativePath::parse(name).unwrap()
}

/// Opens `name` below `parent` without following a symlink. `None` when it
/// does not exist (a site that never wrote a cache); an error for a link or
/// a non-directory.
fn open_cache_dir(parent: &ManagedRoot, name: &str) -> Result<Option<ManagedRoot>, Error> {
    match parent.open_child_dir_nofollow(&rel(name)) {
        Ok(dir) => Ok(Some(dir)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        // ELOOP (symlink) or ENOTDIR (a file or link to one).
        Err(_) => Err(Error::UnsafeTarget),
    }
}

#[derive(Default)]
struct Counts {
    entries: u64,
    bytes: u64,
}

/// Removes everything inside `dir`. A directory is emptied through a
/// no-follow handle and then removed; anything else (file, symlink, socket)
/// is unlinked.
fn empty_dir(
    dir: &ManagedRoot,
    depth: usize,
    keep: &[&str],
    counts: &mut Counts,
) -> Result<(), Error> {
    if depth > MAX_DEPTH {
        return Err(Error::UnsafeTarget);
    }
    for child in dir.child_entries().map_err(Error::Delete)? {
        let Some(name) = child.name.to_str() else {
            // A name that is not UTF-8 cannot be a SiteRelativePath; leave it.
            continue;
        };
        if keep.contains(&name) {
            continue;
        }
        let path = SiteRelativePath::parse(name).map_err(|_| Error::UnsafeTarget)?;
        if child.is_dir {
            // A link swapped in since the listing fails here and is unlinked below.
            if let Ok(inner) = dir.open_child_dir_nofollow(&path) {
                empty_dir(&inner, depth + 1, &[], counts)?;
                dir.remove_dir(&path).map_err(Error::Delete)?;
                counts.entries += 1;
                continue;
            }
        }
        let size = dir
            .symlink_metadata(&path)
            .map(|meta| if meta.is_file() { meta.len() } else { 0 })
            .unwrap_or(0);
        match dir.remove_file(&path) {
            Ok(()) => {
                counts.entries += 1;
                counts.bytes += size;
            }
            // Removed meanwhile (PHP rewriting its cache): not an error.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(Error::Delete(error)),
        }
    }
    Ok(())
}

fn clear(req: &Request) -> Result<ClearResult, Error> {
    let project = ManagedRoot::open(&TrustedRoot::parse(&req.project_root).unwrap())
        .map_err(|_| Error::NotJoomla)?;
    if !project
        .symlink_metadata(&rel("configuration.php"))
        .is_ok_and(|meta| meta.is_file())
    {
        return Err(Error::NotJoomla);
    }
    // Open both roots first: a refusal happens before the first deletion.
    let site = open_cache_dir(&project, "cache")?;
    let admin = match open_cache_dir(&project, "administrator")? {
        Some(administrator) => open_cache_dir(&administrator, "cache")?,
        None => None,
    };
    let mut counts = Counts::default();
    for root in [site, admin].into_iter().flatten() {
        empty_dir(&root, 0, &KEEP, &mut counts)?;
    }
    Ok(ClearResult {
        removed_entries: counts.entries,
        removed_bytes: counts.bytes,
        completed_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    })
}

pub fn execute(ctx: &Context<'_>, req: &Request) -> Result<ClearResult, Error> {
    let hash = resource_lock::canonical_hash(&req.project_root);
    let scope_path = SiteRelativePath::parse(format!("joomla-cache/{hash}")).unwrap();
    ctx.engine_state
        .create_dir_all(&scope_path)
        .map_err(Error::Io)?;
    let scope = ctx
        .engine_state
        .open_managed_dir(&scope_path)
        .map_err(Error::Io)?;
    for child in ["locks", "transactions", "audit"] {
        scope
            .create_dir_all(&SiteRelativePath::parse(child).unwrap())
            .map_err(Error::Io)?;
    }
    let _resource_lock =
        resource_lock::acquire(ctx.engine_state, &req.project_root, req.request_id)
            .map_err(|_| Error::ResourceBusy)?;

    let admitted = match preflight::run(
        &scope,
        req.request_id,
        req.idempotency_key.as_ref(),
        OPERATION,
    )
    .map_err(Error::Preflight)?
    {
        preflight::Outcome::Replay(id) => return replay(&scope, id),
        preflight::Outcome::Proceed(value) => value,
    };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path =
        SiteRelativePath::parse(format!("transactions/{}.json", req.request_id)).unwrap();
    let audit_path = SiteRelativePath::parse("audit/events.jsonl").unwrap();

    let result = match clear(req) {
        Ok(result) => result,
        Err(error) => return Err(fail(&scope, &state_path, &audit_path, state, error)),
    };
    state
        .mark_committed(serde_json::to_value(&result).unwrap())
        .unwrap();
    if state::save(&scope, &state_path, &state).is_err() {
        drop(lock);
        return Err(Error::PostCommit { result });
    }
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(req.request_id, true, None),
    );
    drop(lock);
    Ok(result)
}

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<ClearResult, Error> {
    let path = SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap();
    let loaded = state::load(scope, &path)
        .map_err(|error| Error::Io(std::io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != OPERATION {
        return Err(Error::Io(std::io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => {
            serde_json::from_value(loaded.outcome.unwrap().result.unwrap())
                .map_err(|error| Error::Io(std::io::Error::other(error)))
        }
        TransactionStatus::Failed => {
            let outcome = loaded.outcome.unwrap();
            Err(Error::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}

fn fail(
    scope: &ManagedRoot,
    state_path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut state: crate::transaction::state::TransactionState,
    error: Error,
) -> Error {
    let (code, message) = error.protocol();
    let _ = state.mark_failed(code, message);
    let _ = state::save(scope, state_path, &state);
    let _ = audit::append(
        scope,
        audit_path,
        &AuditRecord::result(state.request_id, false, Some(code)),
    );
    error
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::symlink, path::Path};

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const ID2: &str = "123e4567-e89b-12d3-a456-426614174001";

    fn managed(directory: &Path) -> ManagedRoot {
        ManagedRoot::open(&TrustedRoot::parse(directory).unwrap()).unwrap()
    }

    fn request(root: &Path, id: &str, key: Option<&str>) -> Request {
        Request::parse(
            &format!(r#"{{"projectRoot":"{}"}}"#, root.display()),
            id,
            key,
        )
        .unwrap()
    }

    /// A Joomla-shaped tree with cache content, and `other/` files that must
    /// survive.
    fn site(base: &Path) -> PathBuf {
        let root = base.join("site");
        for dir in [
            "cache/com_content/sub",
            "administrator/cache/com_menus",
            "tmp",
            "logs",
        ] {
            fs::create_dir_all(root.join(dir)).unwrap();
        }
        fs::write(root.join("configuration.php"), "<?php class JConfig {}").unwrap();
        fs::write(root.join("cache/index.html"), "<html></html>").unwrap();
        fs::write(root.join("cache/.htaccess"), "Require all denied").unwrap();
        fs::write(root.join("cache/page.php"), "12345").unwrap();
        fs::write(root.join("cache/com_content/a.cache"), "1234567890").unwrap();
        fs::write(root.join("cache/com_content/sub/b.cache"), "abc").unwrap();
        fs::write(root.join("administrator/cache/index.html"), "x").unwrap();
        fs::write(root.join("administrator/cache/com_menus/m.cache"), "zz").unwrap();
        fs::write(root.join("tmp/keep.txt"), "tmp").unwrap();
        fs::write(root.join("logs/error.php"), "log").unwrap();
        root
    }

    #[test]
    fn rejects_invalid_requests() {
        let parse = |json: &str| Request::parse(json, ID, None).unwrap_err();
        assert_eq!(parse("{"), RequestError::InvalidJson);
        assert_eq!(
            parse(r#"{"projectRoot":"/var/www/site","kind":"joomla"}"#),
            RequestError::InvalidJson
        );
        assert_eq!(
            parse(r#"{"projectRoot":"site"}"#),
            RequestError::InvalidRoot
        );
        assert_eq!(
            parse(r#"{"projectRoot":"/var/www/../etc"}"#),
            RequestError::InvalidRoot
        );
        assert_eq!(
            Request::parse(r#"{"projectRoot":"/var/www/site"}"#, "nope", None).unwrap_err(),
            RequestError::InvalidRequestId
        );
    }

    #[test]
    fn empties_both_cache_roots_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let root = site(dir.path());
        let state_dir = dir.path().join("state");
        fs::create_dir(&state_dir).unwrap();
        let state = managed(&state_dir);
        let result = execute(
            &Context {
                engine_state: &state,
            },
            &request(&root, ID, None),
        )
        .unwrap();
        // page.php, a.cache, b.cache, sub, com_content, m.cache, com_menus
        assert_eq!(result.removed_entries, 7);
        assert_eq!(result.removed_bytes, 5 + 10 + 3 + 2);
        for kept in [
            "cache/index.html",
            "cache/.htaccess",
            "administrator/cache/index.html",
            "tmp/keep.txt",
            "logs/error.php",
            "configuration.php",
        ] {
            assert!(root.join(kept).exists(), "{kept} must stay");
        }
        for gone in [
            "cache/page.php",
            "cache/com_content",
            "administrator/cache/com_menus",
        ] {
            assert!(!root.join(gone).exists(), "{gone} must go");
        }
        assert!(root.join("cache").is_dir() && root.join("administrator/cache").is_dir());
    }

    #[test]
    fn a_symlink_inside_the_cache_is_unlinked_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let root = site(dir.path());
        let outside = dir.path().join("outside");
        fs::create_dir_all(outside.join("deep")).unwrap();
        fs::write(outside.join("secret.txt"), "secret").unwrap();
        fs::write(outside.join("deep/x"), "x").unwrap();
        symlink(&outside, root.join("cache/link_dir")).unwrap();
        symlink(outside.join("secret.txt"), root.join("cache/link_file")).unwrap();
        symlink(&outside, root.join("cache/com_content/sub/up")).unwrap();
        let state_dir = dir.path().join("state");
        fs::create_dir(&state_dir).unwrap();
        let state = managed(&state_dir);
        execute(
            &Context {
                engine_state: &state,
            },
            &request(&root, ID, None),
        )
        .unwrap();
        assert!(!root.join("cache/link_dir").exists());
        assert!(!root.join("cache/link_file").exists());
        assert!(outside.join("secret.txt").exists(), "target must survive");
        assert!(outside.join("deep/x").exists(), "target tree must survive");
    }

    #[test]
    fn a_cache_root_that_is_a_symlink_is_refused_before_any_deletion() {
        let dir = tempfile::tempdir().unwrap();
        let root = site(dir.path());
        let outside = dir.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("precious"), "p").unwrap();
        fs::remove_dir_all(root.join("administrator/cache")).unwrap();
        symlink(&outside, root.join("administrator/cache")).unwrap();
        let state_dir = dir.path().join("state");
        fs::create_dir(&state_dir).unwrap();
        let state = managed(&state_dir);
        let error = execute(
            &Context {
                engine_state: &state,
            },
            &request(&root, ID, None),
        )
        .unwrap_err();
        assert!(matches!(error, Error::UnsafeTarget));
        assert_eq!(error.protocol().0, ErrorCode::InvalidInput);
        assert!(outside.join("precious").exists());
        assert!(
            root.join("cache/page.php").exists(),
            "the site cache must be untouched when the other root is refused"
        );

        // `administrator` itself a link is refused the same way.
        fs::remove_file(root.join("administrator/cache")).unwrap();
        fs::remove_dir_all(root.join("administrator")).unwrap();
        symlink(&outside, root.join("administrator")).unwrap();
        let error = execute(
            &Context {
                engine_state: &state,
            },
            &request(&root, ID2, None),
        )
        .unwrap_err();
        assert!(matches!(error, Error::UnsafeTarget));
        assert!(outside.join("precious").exists());
    }

    #[test]
    fn refuses_a_project_without_configuration_php() {
        let dir = tempfile::tempdir().unwrap();
        let root = site(dir.path());
        fs::remove_file(root.join("configuration.php")).unwrap();
        let state_dir = dir.path().join("state");
        fs::create_dir(&state_dir).unwrap();
        let state = managed(&state_dir);
        let error = execute(
            &Context {
                engine_state: &state,
            },
            &request(&root, ID, None),
        )
        .unwrap_err();
        assert!(matches!(error, Error::NotJoomla));
        assert!(root.join("cache/page.php").exists());
    }

    #[test]
    fn a_missing_cache_directory_is_zero_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let root = site(dir.path());
        fs::remove_dir_all(root.join("administrator")).unwrap();
        fs::remove_dir_all(root.join("cache")).unwrap();
        let state_dir = dir.path().join("state");
        fs::create_dir(&state_dir).unwrap();
        let state = managed(&state_dir);
        let result = execute(
            &Context {
                engine_state: &state,
            },
            &request(&root, ID, None),
        )
        .unwrap();
        assert_eq!((result.removed_entries, result.removed_bytes), (0, 0));
    }

    #[test]
    fn a_replay_returns_the_recorded_result_and_deletes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let root = site(dir.path());
        let state_dir = dir.path().join("state");
        fs::create_dir(&state_dir).unwrap();
        let state = managed(&state_dir);
        let ctx = Context {
            engine_state: &state,
        };
        let first = execute(&ctx, &request(&root, ID, Some("k1"))).unwrap();
        assert_eq!(first.removed_entries, 7);
        // New cache content appears, then the same key is replayed.
        fs::write(root.join("cache/new.cache"), "fresh").unwrap();
        let replayed = execute(&ctx, &request(&root, ID2, Some("k1"))).unwrap();
        assert_eq!(replayed.removed_entries, 7);
        assert_eq!(
            first.completed_at_unix_secs,
            replayed.completed_at_unix_secs
        );
        assert!(
            root.join("cache/new.cache").exists(),
            "a replay must not delete"
        );
        // A different key does run again.
        let again = execute(
            &ctx,
            &request(&root, "123e4567-e89b-12d3-a456-426614174002", Some("k2")),
        )
        .unwrap();
        assert_eq!(again.removed_entries, 1);
        assert!(!root.join("cache/new.cache").exists());
    }
}
