//! `site.moveRoot`: renames a site's content directory from
//! `<content root>/<from domain>` to `<content root>/<to domain>` when the
//! control panel renames a site (milestone 053). The panel used to run a
//! raw `sudo mv` for this and `mv` it back on rollback.
//!
//! The caller names two domains, never paths: the engine builds both paths
//! itself as direct children of one configured content root, so the move can
//! never leave that root or cross filesystems. It is a single `rename(2)`
//! through the content root's directory handle (no symlink is followed),
//! refused if the source is missing or not a real directory, or if anything
//! already exists at the target. Both paths take their cross-operation
//! resource lock (the same one the WordPress operations use), so a move
//! cannot run under an install, update or clone of either root, and every
//! request records a transaction and an audit entry in its own scope.
//!
//! A rollback is the same operation with the domains swapped.
//!
//! `site.prepareRoot` and `site.removeRoot` (milestone 061) create and
//! delete a site's content directory the same way: the caller names a
//! domain (and a relative path under it), never an absolute path, and
//! every step is a descriptor-relative operation that refuses to follow a
//! symlink. See `prepare_root` and `remove_root` for their contracts.

use std::{
    ffi::OsString,
    io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use cap_std::fs::MetadataExt;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    config::SiteManifest,
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    site::{Domain, SiteId, SiteRelativePath, TrustedRoot},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        resource_lock,
        state::{self, TransactionState, TransactionStatus},
    },
};

pub const MOVE_OPERATION: &str = "site.moveRoot";

const SCOPE: &str = "site-root";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestError {
    InvalidDomain,
    SameDomain,
    InvalidRequestId,
    InvalidIdempotencyKey,
    /// `sites` is where engine release trees live inside a content root.
    ReservedDomain,
    InvalidRelativeRoot,
    InvalidIdentity,
    InvalidSiteId,
    InvalidExistingPolicy,
}

impl RequestError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidDomain => "domain is invalid",
            Self::SameDomain => "the source and target domains are the same",
            Self::InvalidRequestId => "request-id must be a canonical UUID",
            Self::InvalidIdempotencyKey => "idempotency-key is invalid",
            Self::ReservedDomain => "the domain name is reserved",
            Self::InvalidRelativeRoot => {
                "relative-root must be a short relative path without '..' or empty segments"
            }
            Self::InvalidIdentity => "uid and gid must be site identities (1000 or higher)",
            Self::InvalidSiteId => "site-id must be a canonical UUID",
            Self::InvalidExistingPolicy => "existing must be refuse, adopt-directory or adopt-tree",
        }
    }
}

pub struct MoveRequest {
    pub from: Domain,
    pub to: Domain,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl MoveRequest {
    pub fn parse(
        from: &str,
        to: &str,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let from = parse_domain(from)?;
        let to = parse_domain(to)?;
        if from.as_str() == to.as_str() {
            return Err(RequestError::SameDomain);
        }
        let request_id =
            RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?;
        let idempotency_key = key
            .map(IdempotencyKey::parse)
            .transpose()
            .map_err(|_| RequestError::InvalidIdempotencyKey)?;
        Ok(Self {
            from,
            to,
            request_id,
            idempotency_key,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MoveResult {
    pub from: String,
    pub to: String,
    pub completed_at_unix_secs: u64,
}

#[derive(Debug)]
pub enum Error {
    /// Another operation holds the resource lock of the source or target.
    ResourceBusy,
    Io(io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    /// No configured content root has a real directory named after the
    /// source domain (missing, a file, or a symlink).
    SourceMissing,
    /// Something already exists at the target path. Nothing was moved.
    TargetExists,
    /// A path component the request resolves through is a symlink or not a
    /// directory (or was swapped for one while the request ran). Nothing
    /// is followed.
    UnsafePath,
    /// The configured content root is a system directory the engine never
    /// manages sites in.
    UnsafeContentRoot,
    /// `prepareRoot`: the target already exists, holds content and is not
    /// already owned by the requested identity. Nothing was changed.
    ExistingContent,
    /// `removeRoot`: the directory is owned by a system account (uid 1-999).
    UnknownOwner,
    /// `removeRoot`: the directory holds entries and the request did not
    /// confirm deleting them.
    NotEmpty,
    /// `removeRoot`: the tree is deeper or larger than the bound, or crosses
    /// onto another filesystem. Nothing was removed.
    OutOfBounds,
    /// `removeRoot`: the release tree named by `--site-id` has no manifest
    /// for this domain.
    ManifestMismatch,
    /// `writeEnvFile`: the file's current content is not the one the caller
    /// read (`expectedHash`).
    HashMismatch,
    /// `writeEnvFile`/`quarantineFile`: the target exists but is not a
    /// regular file.
    NotRegularFile,
    /// `writeEnvFile`/`quarantineFile`: no such file (or the directory
    /// holding it does not exist).
    FileMissing,
    /// `quarantineFile`: larger than the quarantine bound.
    FileTooLarge,
    /// `quarantineFile`: the file changed while it was being copied; it was
    /// left where it was.
    FileChanged,
    /// `writeEnvFile`/`quarantineFile`: the path is not a file below a site
    /// directory of a configured content root.
    OutsideContentRoot,
    PostCommit(serde_json::Value),
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::ResourceBusy | Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another operation on this site's directory is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::SourceMissing => (
                ErrorCode::NotFound,
                "the site directory to move does not exist".into(),
            ),
            Self::TargetExists => (
                ErrorCode::InvalidInput,
                "a file or directory already exists at the target".into(),
            ),
            Self::UnsafePath => (
                ErrorCode::InvalidInput,
                "a path component of the site directory is a symlink or not a directory".into(),
            ),
            Self::UnsafeContentRoot => (
                ErrorCode::InvalidInput,
                "the configured content root is a system directory".into(),
            ),
            Self::ExistingContent => (
                ErrorCode::Conflict,
                "the directory already holds content owned by another identity".into(),
            ),
            Self::UnknownOwner => (
                ErrorCode::Conflict,
                "the directory is owned by a system account".into(),
            ),
            Self::NotEmpty => (
                ErrorCode::Conflict,
                "the directory is not empty and deleting its contents was not confirmed".into(),
            ),
            Self::OutOfBounds => (
                ErrorCode::InvalidInput,
                "the directory tree is too large or deep, or crosses a filesystem boundary".into(),
            ),
            Self::ManifestMismatch => (
                ErrorCode::InvalidInput,
                "no engine manifest for this domain matches the release tree".into(),
            ),
            Self::HashMismatch => (
                ErrorCode::ConfigHashMismatch,
                "the file changed since it was read; reload it and apply the edit again".into(),
            ),
            Self::NotRegularFile => (
                ErrorCode::InvalidInput,
                "the path is not a regular file".into(),
            ),
            Self::FileMissing => (ErrorCode::NotFound, "no such file".into()),
            Self::OutsideContentRoot => (
                ErrorCode::InvalidInput,
                "the path is not a file inside a site directory of a content root".into(),
            ),
            Self::FileTooLarge => (
                ErrorCode::InvalidInput,
                "the file is larger than the quarantine limit".into(),
            ),
            Self::FileChanged => (
                ErrorCode::Conflict,
                "the file changed while it was being quarantined; it was left in place".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit(_) => (
                ErrorCode::Internal,
                "internal site directory move error".into(),
            ),
        }
    }
}

/// Moves `<root>/<from>` to `<root>/<to>` inside the first content root
/// that has a real directory named `from`.
pub fn move_root(
    engine_state: &ManagedRoot,
    content_roots: &[TrustedRoot],
    req: &MoveRequest,
) -> Result<MoveResult, Error> {
    // Pick the root before admission so the locks and a replay see the same
    // paths: the one holding the source, else the one already holding the
    // target (a retried, already-committed move), else the first. Whether
    // the move is possible is checked under the locks.
    let Some(content_root) = content_roots
        .iter()
        .find(|root| is_real_dir(root, &req.from))
        .or_else(|| {
            content_roots
                .iter()
                .find(|root| entry_exists(root, &req.to))
        })
        .or_else(|| content_roots.first())
    else {
        return Err(Error::SourceMissing);
    };
    let from_path = content_root.as_path().join(req.from.as_str());
    let to_path = content_root.as_path().join(req.to.as_str());

    let scope = open_scope(engine_state).map_err(Error::Io)?;
    let _resource_locks =
        resource_lock::acquire_pair(engine_state, &from_path, &to_path, req.request_id)
            .map_err(|_| Error::ResourceBusy)?;

    let admitted = match preflight::run(
        &scope,
        req.request_id,
        req.idempotency_key.as_ref(),
        MOVE_OPERATION,
    )
    .map_err(Error::Preflight)?
    {
        preflight::Outcome::Replay(original) => return replay(&scope, original, MOVE_OPERATION),
        preflight::Outcome::Proceed(admitted) => admitted,
    };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path = transaction_path(req.request_id);
    let audit_path = rel("audit/events.jsonl");

    let value = match rename(content_root, req, from_path, to_path) {
        Ok(value) => value,
        Err(error) => return Err(fail(&scope, &state_path, &audit_path, state, error)),
    };

    let encoded = serde_json::to_value(&value).expect("operation results always serialize");
    state
        .mark_committed(encoded.clone())
        .expect("state is always InProgress at this point");
    if state::save(&scope, &state_path, &state).is_err() {
        drop(lock);
        return Err(Error::PostCommit(encoded));
    }
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(req.request_id, true, None),
    );
    drop(lock);
    Ok(value)
}

fn rename(
    content_root: &TrustedRoot,
    req: &MoveRequest,
    from_path: PathBuf,
    to_path: PathBuf,
) -> Result<MoveResult, Error> {
    let root = ManagedRoot::open(content_root).map_err(Error::Io)?;
    let from = domain_rel(&req.from);
    let to = domain_rel(&req.to);
    // Checked under the locks: the pre-lock look only chose the root.
    if !is_real_dir(content_root, &req.from) {
        return Err(Error::SourceMissing);
    }
    if entry_exists(content_root, &req.to) {
        return Err(Error::TargetExists);
    }
    root.rename(&from, &to).map_err(Error::Io)?;
    Ok(MoveResult {
        from: from_path.to_string_lossy().into_owned(),
        to: to_path.to_string_lossy().into_owned(),
        completed_at_unix_secs: unix_now_secs(),
    })
}

pub const PREPARE_OPERATION: &str = "site.prepareRoot";
pub const REMOVE_OPERATION: &str = "site.removeRoot";
pub const RELEASE_OPERATION: &str = "site.releaseRoot";

/// Site identities are allocated from 10000 on a panel host; nothing below
/// 1000 is ever a tenant, so a request naming one is refused outright.
const MIN_SITE_ID: u32 = 1000;
const MAX_SITE_ID: u32 = u32::MAX - 2;
const MAX_RELATIVE_COMPONENTS: usize = 8;
/// A tree larger or deeper than this is not a site this engine created.
const MAX_REMOVE_ENTRIES: usize = 2_000_000;
const MAX_REMOVE_DEPTH: usize = 64;
/// Engine release trees (`sites/<site id>/...`) live beside the per-domain
/// directories, so a domain may not take this name.
const RELEASE_TREES_DIR: &str = "sites";
const INTERMEDIATE_MODE: u32 = 0o755;
const ROOT_MODE: u32 = 0o700;

/// Directories the engine never manages sites in, even if a content root is
/// misconfigured to one of them (exact match: `/var/www` is fine, `/var` is
/// not).
const SYSTEM_DIRS: &[&str] = &[
    "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib32", "/lib64", "/media", "/mnt",
    "/opt", "/proc", "/root", "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/var", "/var/lib",
    "/var/log", "/var/run",
];

fn parse_domain(value: &str) -> Result<Domain, RequestError> {
    let domain = Domain::parse(value).map_err(|_| RequestError::InvalidDomain)?;
    if domain.as_str() == RELEASE_TREES_DIR {
        return Err(RequestError::ReservedDomain);
    }
    Ok(domain)
}

fn parse_relative_root(relative_root: Option<&str>) -> Result<Vec<SiteRelativePath>, RequestError> {
    let mut components = Vec::new();
    if let Some(relative) = relative_root.filter(|relative| !relative.is_empty()) {
        let parsed =
            SiteRelativePath::parse(relative).map_err(|_| RequestError::InvalidRelativeRoot)?;
        for component in parsed.as_path().components() {
            components.push(
                SiteRelativePath::parse(component.as_os_str())
                    .map_err(|_| RequestError::InvalidRelativeRoot)?,
            );
        }
        if components.len() > MAX_RELATIVE_COMPONENTS {
            return Err(RequestError::InvalidRelativeRoot);
        }
    }
    Ok(components)
}

fn parse_ids(
    request_id: &str,
    key: Option<&str>,
) -> Result<(RequestId, Option<IdempotencyKey>), RequestError> {
    let request_id = RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?;
    let key = key
        .map(IdempotencyKey::parse)
        .transpose()
        .map_err(|_| RequestError::InvalidIdempotencyKey)?;
    Ok((request_id, key))
}

/// What `prepareRoot` does with a final directory that already exists and
/// holds content owned by someone else.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExistingPolicy {
    /// Refuse (the default): nothing is changed.
    Refuse,
    /// Hand over the directory itself only; the files inside keep their
    /// owners.
    AdoptDirectory,
    /// Hand over the directory and everything below it, as one safe
    /// descriptor walk (no symlink is followed or changed, nothing on
    /// another filesystem is touched). Not reverted if it fails part-way.
    AdoptTree,
}

impl ExistingPolicy {
    fn parse(value: Option<&str>) -> Result<Self, RequestError> {
        match value {
            None | Some("refuse") => Ok(Self::Refuse),
            Some("adopt-directory") => Ok(Self::AdoptDirectory),
            Some("adopt-tree") => Ok(Self::AdoptTree),
            Some(_) => Err(RequestError::InvalidExistingPolicy),
        }
    }
}

/// Creates (or adopts) `<content root>/<domain>/<relative root>` for a new
/// site and hands it to the site identity.
pub struct PrepareRequest {
    pub domain: Domain,
    /// The directories below the site directory, one component each; empty
    /// means the site directory itself is the root.
    relative_root: Vec<SiteRelativePath>,
    pub uid: u32,
    pub gid: u32,
    pub existing: ExistingPolicy,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl PrepareRequest {
    pub fn parse(
        domain: &str,
        relative_root: Option<&str>,
        uid: u32,
        gid: u32,
        existing: Option<&str>,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let domain = parse_domain(domain)?;
        let existing = ExistingPolicy::parse(existing)?;
        let components = parse_relative_root(relative_root)?;
        for id in [uid, gid] {
            if !(MIN_SITE_ID..=MAX_SITE_ID).contains(&id) {
                return Err(RequestError::InvalidIdentity);
            }
        }
        let (request_id, idempotency_key) = parse_ids(request_id, key)?;
        Ok(Self {
            domain,
            relative_root: components,
            uid,
            gid,
            existing,
            request_id,
            idempotency_key,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareResult {
    /// The prepared root directory.
    pub path: String,
    /// Whether this request created the root directory (false when it
    /// already existed and was only adopted or already correct).
    pub created: bool,
    pub uid: u32,
    pub gid: u32,
    pub mode: String,
    pub completed_at_unix_secs: u64,
}

/// Removes a site's directory (and, when `site_id` is given, its engine
/// release tree).
pub struct RemoveRequest {
    pub domain: Domain,
    /// Directories below the site directory to remove instead of the whole
    /// site directory; the site directory and the levels between are then
    /// removed too, but only while they are left empty.
    relative_root: Vec<SiteRelativePath>,
    pub site_id: Option<SiteId>,
    /// The caller confirms that deleting a non-empty directory is intended.
    pub confirm_contents: bool,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl RemoveRequest {
    pub fn parse(
        domain: &str,
        relative_root: Option<&str>,
        site_id: Option<&str>,
        confirm_contents: bool,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let domain = parse_domain(domain)?;
        let relative_root = parse_relative_root(relative_root)?;
        let site_id = site_id
            .map(SiteId::parse)
            .transpose()
            .map_err(|_| RequestError::InvalidSiteId)?;
        let (request_id, idempotency_key) = parse_ids(request_id, key)?;
        Ok(Self {
            domain,
            relative_root,
            site_id,
            confirm_contents,
            request_id,
            idempotency_key,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveResult {
    /// The directories this request removed (empty when nothing existed).
    pub removed: Vec<String>,
    pub entries_removed: u64,
    pub completed_at_unix_secs: u64,
}

/// Hands a deleted site's leftover content to root.
pub struct ReleaseRequest {
    pub domain: Domain,
    pub site_id: Option<SiteId>,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl ReleaseRequest {
    pub fn parse(
        domain: &str,
        site_id: Option<&str>,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let RemoveRequest {
            domain,
            site_id,
            request_id,
            idempotency_key,
            ..
        } = RemoveRequest::parse(domain, None, site_id, false, request_id, key)?;
        Ok(Self {
            domain,
            site_id,
            request_id,
            idempotency_key,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseResult {
    /// The directories whose tree is now owned by root:root.
    pub released: Vec<String>,
    pub repaired_entries: u64,
    pub completed_at_unix_secs: u64,
}

/// Runs `body` as one recorded operation: resource locks on every path in
/// `lock_paths`, idempotency admission, a transaction record and an audit
/// entry in the `site-root` scope.
fn transact<T, F>(
    engine_state: &ManagedRoot,
    operation: &'static str,
    request_id: RequestId,
    key: Option<&IdempotencyKey>,
    lock_paths: &[&Path],
    body: F,
) -> Result<T, Error>
where
    T: Serialize + DeserializeOwned,
    F: FnOnce() -> Result<T, Error>,
{
    transact_in(
        SCOPE,
        engine_state,
        operation,
        request_id,
        key,
        lock_paths,
        body,
    )
}

/// `transact` in a named scope, for the file operations of `site_file`
/// (`site-file`), which share this scaffolding and error type.
pub(crate) fn transact_in<T, F>(
    scope_name: &'static str,
    engine_state: &ManagedRoot,
    operation: &'static str,
    request_id: RequestId,
    key: Option<&IdempotencyKey>,
    lock_paths: &[&Path],
    body: F,
) -> Result<T, Error>
where
    T: Serialize + DeserializeOwned,
    F: FnOnce() -> Result<T, Error>,
{
    let scope = open_named_scope(engine_state, scope_name).map_err(Error::Io)?;
    let _resource_locks = resource_lock::acquire_many(engine_state, lock_paths, request_id)
        .map_err(|_| Error::ResourceBusy)?;

    let admitted =
        match preflight::run(&scope, request_id, key, operation).map_err(Error::Preflight)? {
            preflight::Outcome::Replay(original) => return replay(&scope, original, operation),
            preflight::Outcome::Proceed(admitted) => admitted,
        };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path = transaction_path(request_id);
    let audit_path = rel("audit/events.jsonl");

    let value = match body() {
        Ok(value) => value,
        Err(error) => return Err(fail(&scope, &state_path, &audit_path, state, error)),
    };

    let encoded = serde_json::to_value(&value).expect("operation results always serialize");
    state
        .mark_committed(encoded.clone())
        .expect("state is always InProgress at this point");
    if state::save(&scope, &state_path, &state).is_err() {
        drop(lock);
        return Err(Error::PostCommit(encoded));
    }
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(request_id, true, None),
    );
    drop(lock);
    Ok(value)
}

/// The content root a request addresses: the first one that already has an
/// entry named after any of `names`, else the first configured one.
fn pick_content_root<'a>(
    content_roots: &'a [TrustedRoot],
    names: &[PathBuf],
) -> Result<&'a TrustedRoot, Error> {
    content_roots
        .iter()
        .find(|root| {
            names
                .iter()
                .any(|name| std::fs::symlink_metadata(root.as_path().join(name)).is_ok())
        })
        .or_else(|| content_roots.first())
        .ok_or_else(|| Error::Io(io::Error::other("no content root is configured")))
}

pub(crate) fn refuse_system_dir(content_root: &TrustedRoot) -> Result<(), Error> {
    if SYSTEM_DIRS
        .iter()
        .any(|dir| content_root.as_path() == Path::new(dir))
    {
        return Err(Error::UnsafeContentRoot);
    }
    Ok(())
}

/// `ELOOP`/`ENOTDIR` from a no-follow directory open mean the entry is a
/// symlink or not a directory.
pub(crate) fn open_error(error: io::Error) -> Error {
    match error.raw_os_error() {
        Some(code) if code == libc::ELOOP || code == libc::ENOTDIR => Error::UnsafePath,
        _ => Error::Io(error),
    }
}

/// Creates `<content root>/<domain>[/<relative root>]` and gives the final
/// directory to `uid:gid` with mode 0700.
///
/// Every level is looked at with `lstat` and opened with `O_NOFOLLOW`
/// through the previous level's descriptor, so a symlink (or a path that
/// leaves the content root by any other means) is refused, never followed.
/// Directories the request creates are root-owned 0755 (the site directory
/// and anything between it and the root); only the final directory is
/// handed to the site identity, and only that one directory is touched:
/// nothing is ever changed recursively.
///
/// An existing final directory is adopted when it is empty or already owned
/// by the requested identity (so a replay without an idempotency key is a
/// no-op); a non-empty directory owned by anyone else is refused with
/// nothing changed unless the request opts in with an `ExistingPolicy`. Any failure removes the directories this request
/// created and restores an adopted directory's previous owner and mode.
pub fn prepare_root(
    engine_state: &ManagedRoot,
    content_roots: &[TrustedRoot],
    req: &PrepareRequest,
) -> Result<PrepareResult, Error> {
    let content_root = pick_content_root(content_roots, &[PathBuf::from(req.domain.as_str())])?;
    let site_path = content_root.as_path().join(req.domain.as_str());
    transact(
        engine_state,
        PREPARE_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        &[site_path.as_path()],
        || prepare(content_root, &site_path, req),
    )
}

fn prepare(
    content_root: &TrustedRoot,
    site_path: &Path,
    req: &PrepareRequest,
) -> Result<PrepareResult, Error> {
    refuse_system_dir(content_root)?;
    let mut names = vec![domain_rel(&req.domain)];
    names.extend(req.relative_root.iter().cloned());

    // `handles[level]` is the directory `names[level]` lives in.
    let mut handles = vec![ManagedRoot::open(content_root).map_err(Error::Io)?];
    let mut created: Vec<(usize, SiteRelativePath)> = Vec::new();
    let mut previous = None;
    match walk_and_own(&names, req, &mut handles, &mut created, &mut previous) {
        Ok(final_created) => {
            let mut path = site_path.to_path_buf();
            for component in &req.relative_root {
                path.push(component.as_path());
            }
            Ok(PrepareResult {
                path: path.to_string_lossy().into_owned(),
                created: final_created,
                uid: req.uid,
                gid: req.gid,
                mode: format!("{ROOT_MODE:04o}"),
                completed_at_unix_secs: unix_now_secs(),
            })
        }
        Err(error) => {
            // Undo, innermost first. `remove_dir` is non-recursive: a
            // directory that somehow gained content is left in place.
            if let (Some((uid, gid, mode)), Some(final_dir)) = (previous, handles.last()) {
                let _ = final_dir.chown_self(uid, gid);
                let _ = final_dir.set_own_mode(mode);
            }
            for (level, name) in created.iter().rev() {
                let _ = handles[*level].remove_dir(name);
            }
            Err(error)
        }
    }
}

/// Walks (creating as needed) every level of `names`, then hands the final
/// directory to the requested identity. Returns whether the final directory
/// was created by this request.
fn walk_and_own(
    names: &[SiteRelativePath],
    req: &PrepareRequest,
    handles: &mut Vec<ManagedRoot>,
    created: &mut Vec<(usize, SiteRelativePath)>,
    previous: &mut Option<(u32, u32, u32)>,
) -> Result<bool, Error> {
    let mut final_created = false;
    for (level, name) in names.iter().enumerate() {
        let parent = &handles[level];
        let made = match parent.symlink_metadata(name) {
            Ok(metadata) if metadata.is_dir() => false,
            Ok(_) => return Err(Error::UnsafePath),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                parent.create_dir(name).map_err(Error::Io)?;
                created.push((level, name.clone()));
                true
            }
            Err(error) => return Err(Error::Io(error)),
        };
        let child = parent.open_child_dir_nofollow(name).map_err(open_error)?;
        if made {
            // Independent of the process umask.
            child.set_own_mode(INTERMEDIATE_MODE).map_err(Error::Io)?;
        }
        final_created = made;
        handles.push(child);
    }

    let final_dir = handles.last().expect("the site directory level exists");
    let metadata = final_dir.own_metadata().map_err(Error::Io)?;
    if !final_created
        && req.existing == ExistingPolicy::Refuse
        && (metadata.uid() != req.uid || metadata.gid() != req.gid)
        && !final_dir.child_entries().map_err(Error::Io)?.is_empty()
    {
        return Err(Error::ExistingContent);
    }
    if !final_created {
        *previous = Some((metadata.uid(), metadata.gid(), metadata.mode() & 0o7777));
    }
    if !final_created && req.existing == ExistingPolicy::AdoptTree {
        let fd = final_dir.try_clone_fd().map_err(Error::Io)?;
        crate::permissions::execute::repair_open_directory(&fd, req.uid, req.gid, &[])
            .map_err(Error::Io)?;
    } else {
        final_dir.chown_self(req.uid, req.gid).map_err(Error::Io)?;
    }
    final_dir.set_own_mode(ROOT_MODE).map_err(Error::Io)?;
    Ok(final_created)
}

/// One directory a removal or release will act on.
struct Target {
    /// `parents[level]` is the directory `names[level]` lives in.
    parents: Vec<ManagedRoot>,
    names: Vec<SiteRelativePath>,
    dir: ManagedRoot,
    path: PathBuf,
    /// Entries below it that are not directories (files, symlinks, ...):
    /// a tree of empty directories holds no content.
    contents: usize,
    /// Remove the ancestors named by `names[..len - 1]` too, while empty.
    prune: bool,
}

/// Removes `<content root>/<domain>` and, when the request names a site id,
/// the engine release tree `<content root>/sites/<site id>`.
///
/// Bounded and refusing before anything is deleted: each directory must be
/// a real directory (never a symlink), owned by root or a site identity
/// (uid 1000 or higher), and its whole tree must be within the entry and
/// depth bounds and on one filesystem. A release tree is only removed when
/// the engine manifest for the id names this domain. A tree holding
/// anything but empty directories is refused unless the request confirms
/// deleting its contents. Entries are removed bottom-up through
/// descriptors without following a symlink (a link is unlinked, never its
/// target). Removal is not reversible; a request that fails part-way is
/// safe to repeat, and a directory that is already gone is a success with
/// nothing removed.
pub fn remove_root(
    engine_state: &ManagedRoot,
    content_roots: &[TrustedRoot],
    manifests_dir: &Path,
    manifest_owner_uid: u32,
    req: &RemoveRequest,
) -> Result<RemoveResult, Error> {
    let (content_root, lock_paths) = locate(content_roots, &req.domain, req.site_id.as_ref())?;
    let lock_refs: Vec<&Path> = lock_paths.iter().map(PathBuf::as_path).collect();
    transact(
        engine_state,
        REMOVE_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        &lock_refs,
        || remove(content_root, manifests_dir, manifest_owner_uid, req),
    )
}

/// The content root a domain (and optional release tree) lives in and the
/// paths that need a resource lock.
fn locate<'a>(
    content_roots: &'a [TrustedRoot],
    domain: &Domain,
    site_id: Option<&SiteId>,
) -> Result<(&'a TrustedRoot, Vec<PathBuf>), Error> {
    let mut names = vec![PathBuf::from(domain.as_str())];
    if let Some(id) = site_id {
        names.push(Path::new(RELEASE_TREES_DIR).join(id.to_string()));
    }
    let content_root = pick_content_root(content_roots, &names)?;
    let lock_paths = names
        .iter()
        .map(|name| content_root.as_path().join(name))
        .collect();
    Ok((content_root, lock_paths))
}

/// Gives everything below `<content root>/<domain>` (and the manifest-
/// verified release tree of `site_id`) to root:root, so that numeric uid of
/// a deleted site identity, which the next site may be handed, does not
/// keep access to the leftover tenant files. The same descriptor-relative
/// walk as `permissions.fixOwnership`: a symlink is neither followed nor
/// changed and nothing on another filesystem is touched. A missing
/// directory is skipped.
pub fn release_root(
    engine_state: &ManagedRoot,
    content_roots: &[TrustedRoot],
    manifests_dir: &Path,
    manifest_owner_uid: u32,
    req: &ReleaseRequest,
) -> Result<ReleaseResult, Error> {
    let (content_root, lock_paths) = locate(content_roots, &req.domain, req.site_id.as_ref())?;
    let lock_refs: Vec<&Path> = lock_paths.iter().map(PathBuf::as_path).collect();
    transact(
        engine_state,
        RELEASE_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        &lock_refs,
        || {
            let targets = resolve_targets(
                content_root,
                manifests_dir,
                manifest_owner_uid,
                &req.domain,
                &[],
                req.site_id.as_ref(),
            )?;
            let mut released = Vec::new();
            let mut repaired_entries = 0;
            for target in &targets {
                repaired_entries +=
                    crate::permissions::execute::repair_tree(&target.path, 0, 0, &[])
                        .map_err(Error::Io)?;
                released.push(target.path.to_string_lossy().into_owned());
            }
            Ok(ReleaseResult {
                released,
                repaired_entries,
                completed_at_unix_secs: unix_now_secs(),
            })
        },
    )
}

fn remove(
    content_root: &TrustedRoot,
    manifests_dir: &Path,
    manifest_owner_uid: u32,
    req: &RemoveRequest,
) -> Result<RemoveResult, Error> {
    let targets = resolve_targets(
        content_root,
        manifests_dir,
        manifest_owner_uid,
        &req.domain,
        &req.relative_root,
        req.site_id.as_ref(),
    )?;
    if !req.confirm_contents && targets.iter().any(|target| target.contents > 0) {
        return Err(Error::NotEmpty);
    }

    // Everything above is checked before the first deletion.
    let mut removed = Vec::new();
    let mut entries_removed = 0u64;
    for target in &targets {
        let mut remaining = MAX_REMOVE_ENTRIES;
        empty_dir(&target.dir, 0, &mut remaining)?;
        let last = target.names.len() - 1;
        target.parents[last]
            .remove_dir(&target.names[last])
            .map_err(Error::Io)?;
        if target.prune {
            // Best effort: stops at the first level that is not empty.
            for level in (0..last).rev() {
                if target.parents[level]
                    .remove_dir(&target.names[level])
                    .is_err()
                {
                    break;
                }
            }
        }
        removed.push(target.path.to_string_lossy().into_owned());
        entries_removed += (MAX_REMOVE_ENTRIES - remaining) as u64;
    }
    Ok(RemoveResult {
        removed,
        entries_removed,
        completed_at_unix_secs: unix_now_secs(),
    })
}

/// The directories a request acts on, each already checked: the site
/// directory and (with a site id, only when the engine manifest names this
/// domain) the release tree. Missing directories are skipped.
fn resolve_targets(
    content_root: &TrustedRoot,
    manifests_dir: &Path,
    manifest_owner_uid: u32,
    domain: &Domain,
    relative_root: &[SiteRelativePath],
    site_id: Option<&SiteId>,
) -> Result<Vec<Target>, Error> {
    refuse_system_dir(content_root)?;
    let mut targets = Vec::new();

    let mut names = vec![domain_rel(domain)];
    names.extend(relative_root.iter().cloned());
    let mut path = content_root.as_path().join(domain.as_str());
    for component in relative_root {
        path.push(component.as_path());
    }
    let base = ManagedRoot::open(content_root).map_err(Error::Io)?;
    if let Some(target) = open_target(base, names, path, !relative_root.is_empty())? {
        targets.push(target);
    }

    if let Some(id) = site_id {
        let names = vec![rel(RELEASE_TREES_DIR), rel(&id.to_string())];
        let path = content_root
            .as_path()
            .join(RELEASE_TREES_DIR)
            .join(id.to_string());
        let base = ManagedRoot::open(content_root).map_err(Error::Io)?;
        if let Some(target) = open_target(base, names, path, false)? {
            let manifest_path = manifests_dir.join(format!("{id}.json"));
            let manifest = SiteManifest::load_owned_by(&manifest_path, manifest_owner_uid, *id)
                .map_err(|_| Error::ManifestMismatch)?;
            if manifest.domain != domain.as_str() {
                return Err(Error::ManifestMismatch);
            }
            targets.push(target);
        }
    }
    Ok(targets)
}

/// Walks `names` down from `base` without following a symlink and returns
/// the last directory as a target, or `None` when any level does not exist.
/// Applies every refusal that does not need the other target.
fn open_target(
    base: ManagedRoot,
    names: Vec<SiteRelativePath>,
    path: PathBuf,
    prune: bool,
) -> Result<Option<Target>, Error> {
    let mut parents = vec![base];
    let mut dir = None;
    for (level, name) in names.iter().enumerate() {
        let parent = &parents[level];
        match parent.symlink_metadata(name) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => return Err(Error::UnsafePath),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(Error::Io(error)),
        }
        let child = parent.open_child_dir_nofollow(name).map_err(open_error)?;
        if level + 1 == names.len() {
            dir = Some(child);
        } else {
            parents.push(child);
        }
    }
    let dir = dir.expect("a target has at least one name");
    let metadata = dir.own_metadata().map_err(Error::Io)?;
    if !owner_allowed(metadata.uid()) {
        return Err(Error::UnknownOwner);
    }
    let mut counts = Counts::default();
    scan(&dir, metadata.dev(), 0, &mut counts)?;
    Ok(Some(Target {
        parents,
        names,
        dir,
        path,
        contents: counts.contents,
        prune,
    }))
}

/// Root, the engine's own user (the same thing in production) or a site
/// identity; never another system account.
fn owner_allowed(uid: u32) -> bool {
    // SAFETY: `geteuid` has no preconditions.
    uid == 0 || uid >= MIN_SITE_ID || uid == unsafe { libc::geteuid() }
}

fn entry_name(name: &OsString) -> Result<SiteRelativePath, Error> {
    SiteRelativePath::parse(name).map_err(|_| Error::UnsafePath)
}

#[derive(Default)]
struct Counts {
    entries: usize,
    contents: usize,
}

/// Counts the entries below `dir`, refusing a tree that is too deep, too
/// large, or crosses onto another filesystem.
fn scan(dir: &ManagedRoot, dev: u64, depth: usize, counts: &mut Counts) -> Result<(), Error> {
    if depth > MAX_REMOVE_DEPTH {
        return Err(Error::OutOfBounds);
    }
    for entry in dir.child_entries().map_err(Error::Io)? {
        counts.entries += 1;
        if counts.entries > MAX_REMOVE_ENTRIES {
            return Err(Error::OutOfBounds);
        }
        if entry.is_dir {
            let child = dir
                .open_child_dir_nofollow(&entry_name(&entry.name)?)
                .map_err(open_error)?;
            if child.own_metadata().map_err(Error::Io)?.dev() != dev {
                return Err(Error::OutOfBounds);
            }
            scan(&child, dev, depth + 1, counts)?;
        } else {
            counts.contents += 1;
        }
    }
    Ok(())
}

/// Removes everything below `dir`, bottom-up, never following a symlink.
/// `remaining` is the entry budget left (the scan already proved it
/// sufficient; this only guards a tree that grew since).
fn empty_dir(dir: &ManagedRoot, depth: usize, remaining: &mut usize) -> Result<(), Error> {
    if depth > MAX_REMOVE_DEPTH {
        return Err(Error::OutOfBounds);
    }
    for entry in dir.child_entries().map_err(Error::Io)? {
        *remaining = remaining.checked_sub(1).ok_or(Error::OutOfBounds)?;
        let name = entry_name(&entry.name)?;
        let result = if entry.is_dir {
            let child = dir.open_child_dir_nofollow(&name).map_err(open_error)?;
            empty_dir(&child, depth + 1, remaining)?;
            dir.remove_dir(&name)
        } else {
            dir.remove_file(&name)
        };
        match result {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(Error::Io(error)),
        }
    }
    Ok(())
}

/// A real directory (not a symlink to one) named `domain` directly under
/// `root`.
fn is_real_dir(root: &TrustedRoot, domain: &Domain) -> bool {
    std::fs::symlink_metadata(root.as_path().join(domain.as_str()))
        .is_ok_and(|metadata| metadata.file_type().is_dir())
}

/// Anything at all named `domain` directly under `root`, including a
/// dangling symlink (`symlink_metadata` does not follow it).
fn entry_exists(root: &TrustedRoot, domain: &Domain) -> bool {
    std::fs::symlink_metadata(root.as_path().join(domain.as_str())).is_ok()
}

fn domain_rel(domain: &Domain) -> SiteRelativePath {
    SiteRelativePath::parse(domain.as_str()).expect("a validated domain is one path component")
}

fn open_scope(engine_state: &ManagedRoot) -> io::Result<ManagedRoot> {
    open_named_scope(engine_state, SCOPE)
}

fn open_named_scope(engine_state: &ManagedRoot, name: &str) -> io::Result<ManagedRoot> {
    engine_state.create_dir_all(&rel(name))?;
    let scope = engine_state.open_managed_dir(&rel(name))?;
    for child in ["locks", "transactions", "audit"] {
        scope.create_dir_all(&rel(child))?;
    }
    Ok(scope)
}

fn replay<T: DeserializeOwned>(
    scope: &ManagedRoot,
    original: RequestId,
    operation: &str,
) -> Result<T, Error> {
    let loaded = state::load(scope, &transaction_path(original))
        .map_err(|error| Error::Io(io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != operation {
        return Err(Error::Io(io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => loaded
            .outcome
            .and_then(|outcome| outcome.result)
            .ok_or_else(|| Error::Io(io::Error::other("committed outcome has no result")))
            .and_then(|value| {
                serde_json::from_value(value).map_err(|error| Error::Io(io::Error::other(error)))
            }),
        TransactionStatus::Failed => {
            let outcome = loaded
                .outcome
                .expect("a failed transaction always has an outcome");
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
    mut state: TransactionState,
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

fn transaction_path(request_id: RequestId) -> SiteRelativePath {
    rel(&format!("transactions/{request_id}.json"))
}

pub(crate) fn rel(path: &str) -> SiteRelativePath {
    SiteRelativePath::parse(path).expect("literal path is valid")
}

pub(crate) fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::symlink};

    use super::*;

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const OTHER_ID: &str = "123e4567-e89b-12d3-a456-426614174001";
    const THIRD_ID: &str = "123e4567-e89b-12d3-a456-426614174002";

    struct Fixture {
        _dir: tempfile::TempDir,
        state: ManagedRoot,
        content: TrustedRoot,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path().canonicalize().unwrap();
            fs::create_dir(base.join("state")).unwrap();
            fs::create_dir(base.join("www")).unwrap();
            Self {
                state: ManagedRoot::open(&TrustedRoot::parse(base.join("state")).unwrap()).unwrap(),
                content: TrustedRoot::parse(base.join("www")).unwrap(),
                _dir: dir,
            }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.content.as_path().join(name)
        }

        fn site(&self, name: &str) {
            fs::create_dir(self.path(name)).unwrap();
            fs::write(self.path(name).join("index.php"), "<?php").unwrap();
        }

        fn run(&self, req: &MoveRequest) -> Result<MoveResult, Error> {
            move_root(&self.state, std::slice::from_ref(&self.content), req)
        }
    }

    fn req(from: &str, to: &str, id: &str, key: Option<&str>) -> MoveRequest {
        MoveRequest::parse(from, to, id, key).unwrap()
    }

    #[test]
    fn moves_the_directory_with_its_contents_and_replays() {
        let fixture = Fixture::new();
        fixture.site("old.test");

        let result = fixture
            .run(&req("old.test", "new.test", ID, Some("mv-1")))
            .unwrap();
        assert_eq!(result.to, fixture.path("new.test").to_string_lossy());
        assert!(!fixture.path("old.test").exists());
        assert!(fixture.path("new.test/index.php").exists());

        // The same key replays the committed outcome instead of failing on
        // the now-missing source.
        let replayed = fixture
            .run(&req("old.test", "new.test", ID, Some("mv-1")))
            .unwrap_or_else(|error| panic!("{error:?}"));
        assert_eq!(replayed.from, result.from);
    }

    #[test]
    fn swapping_the_domains_rolls_the_move_back() {
        let fixture = Fixture::new();
        fixture.site("old.test");
        fixture.run(&req("old.test", "new.test", ID, None)).unwrap();
        fixture
            .run(&req("new.test", "old.test", OTHER_ID, None))
            .unwrap();
        assert!(fixture.path("old.test/index.php").exists());
        assert!(!fixture.path("new.test").exists());
    }

    #[test]
    fn refuses_an_existing_target_and_moves_nothing() {
        let fixture = Fixture::new();
        fixture.site("old.test");
        fixture.site("new.test");

        let error = fixture
            .run(&req("old.test", "new.test", ID, None))
            .unwrap_err();
        assert!(matches!(error, Error::TargetExists));
        assert!(fixture.path("old.test/index.php").exists());
    }

    #[test]
    fn refuses_a_dangling_symlink_at_the_target() {
        let fixture = Fixture::new();
        fixture.site("old.test");
        symlink("/nonexistent", fixture.path("new.test")).unwrap();

        let error = fixture
            .run(&req("old.test", "new.test", ID, None))
            .unwrap_err();
        assert!(matches!(error, Error::TargetExists));
    }

    #[test]
    fn refuses_a_missing_file_or_symlinked_source() {
        let fixture = Fixture::new();
        assert!(matches!(
            fixture.run(&req("old.test", "new.test", ID, None)),
            Err(Error::SourceMissing)
        ));

        fs::write(fixture.path("file.test"), "x").unwrap();
        assert!(matches!(
            fixture.run(&req("file.test", "new.test", OTHER_ID, None)),
            Err(Error::SourceMissing)
        ));

        fixture.site("real.test");
        symlink(fixture.path("real.test"), fixture.path("link.test")).unwrap();
        assert!(matches!(
            fixture.run(&req("link.test", "new.test", THIRD_ID, None)),
            Err(Error::SourceMissing)
        ));
        assert!(fixture.path("real.test/index.php").exists());
    }

    #[test]
    fn a_held_resource_lock_on_either_side_blocks_the_move() {
        let fixture = Fixture::new();
        fixture.site("old.test");
        for held in ["old.test", "new.test"] {
            let _held = resource_lock::acquire(
                &fixture.state,
                &fixture.path(held),
                RequestId::parse(OTHER_ID).unwrap(),
            )
            .unwrap();
            assert!(matches!(
                fixture.run(&req("old.test", "new.test", ID, None)),
                Err(Error::ResourceBusy)
            ));
        }
        assert!(fixture.path("old.test/index.php").exists());
    }

    #[test]
    fn rejects_malformed_requests() {
        assert_eq!(
            MoveRequest::parse("../etc", "new.test", ID, None).err(),
            Some(RequestError::InvalidDomain)
        );
        assert_eq!(
            MoveRequest::parse("old.test", "a/b", ID, None).err(),
            Some(RequestError::InvalidDomain)
        );
        assert_eq!(
            MoveRequest::parse("same.test", "same.test", ID, None).err(),
            Some(RequestError::SameDomain)
        );
        assert_eq!(
            MoveRequest::parse("old.test", "new.test", "not-a-uuid", None).err(),
            Some(RequestError::InvalidRequestId)
        );
    }

    // ---- site.prepareRoot / site.removeRoot (milestone 061) ----

    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    fn me() -> (u32, u32) {
        // SAFETY: `getuid`/`getgid` have no preconditions.
        unsafe { (libc::getuid(), libc::getgid()) }
    }

    fn is_root() -> bool {
        me().0 == 0
    }

    /// Built directly: `parse` refuses ids below 1000, which an unprivileged
    /// test user cannot be expected to have.
    fn prep(domain: &str, relative: &[&str], uid: u32, gid: u32, id: &str) -> PrepareRequest {
        PrepareRequest {
            domain: Domain::parse(domain).unwrap(),
            relative_root: relative
                .iter()
                .map(|part| SiteRelativePath::parse(part).unwrap())
                .collect(),
            uid,
            gid,
            existing: ExistingPolicy::Refuse,
            request_id: RequestId::parse(id).unwrap(),
            idempotency_key: None,
        }
    }

    fn mode_of(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }

    impl Fixture {
        fn prepare(&self, req: &PrepareRequest) -> Result<PrepareResult, Error> {
            prepare_root(&self.state, std::slice::from_ref(&self.content), req)
        }

        fn sites_dir(&self) -> PathBuf {
            self.content.as_path().parent().unwrap().join("manifests")
        }

        fn remove(&self, req: &RemoveRequest) -> Result<RemoveResult, Error> {
            fs::create_dir_all(self.sites_dir()).unwrap();
            remove_root(
                &self.state,
                std::slice::from_ref(&self.content),
                &self.sites_dir(),
                me().0,
                req,
            )
        }

        fn manifest(&self, site: &str, domain: &str) {
            fs::create_dir_all(self.sites_dir()).unwrap();
            let json = serde_json::json!({
                "schemaVersion": 1,
                "siteId": site,
                "domain": domain,
                "contentRoot": format!("sites/{site}/current"),
                "siteUser": "old_test",
                "repository": {
                    "url": "git@example.com:r.git",
                    "allowedBranches": ["main"],
                    "credentialId": site,
                },
            });
            let path = self.sites_dir().join(format!("{site}.json"));
            fs::write(&path, json.to_string()).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        }
    }

    fn rm(domain: &str, site: Option<&str>, confirm: bool, id: &str) -> RemoveRequest {
        RemoveRequest::parse(domain, None, site, confirm, id, None).unwrap()
    }

    const SITE: &str = "550e8400-e29b-41d4-a716-446655440000";

    #[test]
    fn prepare_creates_the_site_directory_and_a_private_root() {
        let fixture = Fixture::new();
        let (uid, gid) = me();
        let mut req = prep("a.test", &["public"], uid, gid, ID);
        req.idempotency_key = Some(IdempotencyKey::parse("prep-1").unwrap());

        let result = fixture.prepare(&req).unwrap();
        assert_eq!(result.path, fixture.path("a.test/public").to_string_lossy());
        assert!(result.created);
        assert_eq!(mode_of(&fixture.path("a.test")), 0o755);
        assert_eq!(mode_of(&fixture.path("a.test/public")), 0o700);
        let owner = fs::metadata(fixture.path("a.test/public")).unwrap();
        assert_eq!((owner.uid(), owner.gid()), (uid, gid));

        // The same key replays the recorded outcome.
        let replayed = fixture.prepare(&req).unwrap();
        assert_eq!(replayed.path, result.path);
        assert!(replayed.created);

        // A new request for the finished root is a no-op, not an error.
        let again = fixture
            .prepare(&prep("a.test", &["public"], uid, gid, OTHER_ID))
            .unwrap();
        assert!(!again.created);
        assert_eq!(mode_of(&fixture.path("a.test/public")), 0o700);
    }

    #[test]
    fn prepare_without_a_relative_root_hands_over_the_site_directory() {
        let fixture = Fixture::new();
        let (uid, gid) = me();
        let result = fixture.prepare(&prep("b.test", &[], uid, gid, ID)).unwrap();
        assert_eq!(result.path, fixture.path("b.test").to_string_lossy());
        assert_eq!(mode_of(&fixture.path("b.test")), 0o700);
    }

    #[test]
    fn prepare_never_follows_a_symlink_at_any_level() {
        let fixture = Fixture::new();
        let (uid, gid) = me();
        let outside = fixture.content.as_path().parent().unwrap().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o755)).unwrap();

        symlink(&outside, fixture.path("link.test")).unwrap();
        assert!(matches!(
            fixture.prepare(&prep("link.test", &["public"], uid, gid, ID)),
            Err(Error::UnsafePath)
        ));

        fs::create_dir(fixture.path("real.test")).unwrap();
        symlink(&outside, fixture.path("real.test/public")).unwrap();
        assert!(matches!(
            fixture.prepare(&prep("real.test", &["public"], uid, gid, OTHER_ID)),
            Err(Error::UnsafePath)
        ));

        fs::write(fixture.path("file.test"), "x").unwrap();
        assert!(matches!(
            fixture.prepare(&prep("file.test", &[], uid, gid, THIRD_ID)),
            Err(Error::UnsafePath)
        ));

        assert_eq!(mode_of(&outside), 0o755);
        assert_eq!(fs::metadata(&outside).unwrap().uid(), uid);
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    }

    #[test]
    fn prepare_refuses_foreign_content_and_changes_nothing() {
        let fixture = Fixture::new();
        let (uid, gid) = me();
        fixture.site("c.test");
        fs::set_permissions(fixture.path("c.test"), fs::Permissions::from_mode(0o755)).unwrap();

        // Owned by the test user, requested for a different identity.
        let error = fixture
            .prepare(&prep("c.test", &[], uid + 1, gid, ID))
            .unwrap_err();
        assert!(matches!(error, Error::ExistingContent));
        assert_eq!(mode_of(&fixture.path("c.test")), 0o755);
        assert!(fixture.path("c.test/index.php").exists());

        // Already owned by the requested identity: adopted, mode fixed.
        fixture
            .prepare(&prep("c.test", &[], uid, gid, OTHER_ID))
            .unwrap();
        assert_eq!(mode_of(&fixture.path("c.test")), 0o700);
        assert!(fixture.path("c.test/index.php").exists());
    }

    #[test]
    fn prepare_failure_removes_what_it_created_and_restores_what_it_adopted() {
        if is_root() {
            return; // chown to another user succeeds for root
        }
        let fixture = Fixture::new();
        let (uid, gid) = me();

        // A fresh tree: the chown to another user is refused, so nothing
        // may remain.
        let error = fixture
            .prepare(&prep("d.test", &["public"], uid + 1, gid, ID))
            .unwrap_err();
        assert!(matches!(error, Error::Io(_)));
        assert!(!fixture.path("d.test").exists());

        // An adopted empty directory keeps its previous mode.
        fs::create_dir(fixture.path("e.test")).unwrap();
        fs::set_permissions(fixture.path("e.test"), fs::Permissions::from_mode(0o750)).unwrap();
        assert!(
            fixture
                .prepare(&prep("e.test", &[], uid + 1, gid, OTHER_ID))
                .is_err()
        );
        assert_eq!(mode_of(&fixture.path("e.test")), 0o750);

        // The failure is recorded: a retry under the same key replays it.
        let mut req = prep("d.test", &["public"], uid + 1, gid, THIRD_ID);
        req.idempotency_key = Some(IdempotencyKey::parse("prep-fail").unwrap());
        assert!(fixture.prepare(&req).is_err());
        assert!(matches!(fixture.prepare(&req), Err(Error::Replayed { .. })));
    }

    #[test]
    fn prepare_assigns_the_requested_identity_when_run_as_root() {
        if !is_root() {
            return;
        }
        let fixture = Fixture::new();
        fixture
            .prepare(&prep("f.test", &["public"], 12345, 23456, ID))
            .unwrap();
        let root = fs::metadata(fixture.path("f.test/public")).unwrap();
        assert_eq!((root.uid(), root.gid()), (12345, 23456));
        assert_eq!(mode_of(&fixture.path("f.test/public")), 0o700);
        let site = fs::metadata(fixture.path("f.test")).unwrap();
        assert_eq!((site.uid(), site.gid()), (0, 0));
        assert_eq!(mode_of(&fixture.path("f.test")), 0o755);
    }

    #[test]
    fn prepare_and_remove_refuse_a_system_directory_as_content_root() {
        let fixture = Fixture::new();
        let (uid, gid) = me();
        let etc = TrustedRoot::parse("/etc").unwrap();
        let error = prepare_root(
            &fixture.state,
            std::slice::from_ref(&etc),
            &prep("zzz-engine-test.invalid", &["public"], uid, gid, ID),
        )
        .unwrap_err();
        assert!(matches!(error, Error::UnsafeContentRoot));
        assert!(!Path::new("/etc/zzz-engine-test.invalid").exists());

        let error = remove_root(
            &fixture.state,
            std::slice::from_ref(&etc),
            &fixture.sites_dir(),
            0,
            &rm("zzz-engine-test.invalid", None, true, OTHER_ID),
        )
        .unwrap_err();
        assert!(matches!(error, Error::UnsafeContentRoot));
    }

    #[test]
    fn prepare_and_remove_are_blocked_by_a_held_resource_lock() {
        let fixture = Fixture::new();
        let (uid, gid) = me();
        fixture.site("g.test");
        let _held = resource_lock::acquire(
            &fixture.state,
            &fixture.path("g.test"),
            RequestId::parse(OTHER_ID).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            fixture.prepare(&prep("g.test", &["public"], uid, gid, ID)),
            Err(Error::ResourceBusy)
        ));
        assert!(matches!(
            fixture.remove(&rm("g.test", None, true, THIRD_ID)),
            Err(Error::ResourceBusy)
        ));
        assert!(fixture.path("g.test/index.php").exists());
    }

    #[test]
    fn prepare_and_remove_reject_malformed_requests() {
        let parse = |domain: &str, rel: Option<&str>, uid: u32, gid: u32| {
            PrepareRequest::parse(domain, rel, uid, gid, None, ID, None).err()
        };
        assert_eq!(
            parse("sites", None, 10000, 10000),
            Some(RequestError::ReservedDomain)
        );
        assert_eq!(
            parse("../etc", None, 10000, 10000),
            Some(RequestError::InvalidDomain)
        );
        assert_eq!(
            parse("a.test", Some("../x"), 10000, 10000),
            Some(RequestError::InvalidRelativeRoot)
        );
        assert_eq!(
            parse("a.test", Some("/etc"), 10000, 10000),
            Some(RequestError::InvalidRelativeRoot)
        );
        assert_eq!(
            parse("a.test", Some("a//b"), 10000, 10000),
            Some(RequestError::InvalidRelativeRoot)
        );
        assert_eq!(
            parse("a.test", Some("a/b/c/d/e/f/g/h/i"), 10000, 10000),
            Some(RequestError::InvalidRelativeRoot)
        );
        assert_eq!(
            parse("a.test", None, 0, 10000),
            Some(RequestError::InvalidIdentity)
        );
        assert_eq!(
            parse("a.test", None, 10000, 999),
            Some(RequestError::InvalidIdentity)
        );
        assert_eq!(
            parse("a.test", None, u32::MAX, 10000),
            Some(RequestError::InvalidIdentity)
        );
        assert!(parse("a.test", Some("public/html"), 10000, 10000).is_none());
        assert!(parse("a.test", Some(""), 10000, 10000).is_none());

        assert_eq!(
            RemoveRequest::parse("sites", None, None, true, ID, None).err(),
            Some(RequestError::ReservedDomain)
        );
        assert_eq!(
            RemoveRequest::parse("a.test", None, Some("not-a-uuid"), true, ID, None).err(),
            Some(RequestError::InvalidSiteId)
        );
        assert_eq!(
            MoveRequest::parse("sites", "new.test", ID, None).err(),
            Some(RequestError::ReservedDomain)
        );
    }

    #[test]
    fn remove_deletes_the_tree_and_unlinks_symlinks_without_following_them() {
        let fixture = Fixture::new();
        let outside = fixture.content.as_path().parent().unwrap().join("keep");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("precious"), "data").unwrap();

        fixture.site("h.test");
        fs::create_dir_all(fixture.path("h.test/public/wp-content/uploads")).unwrap();
        fs::write(fixture.path("h.test/public/wp-content/uploads/a.jpg"), "x").unwrap();
        symlink(&outside, fixture.path("h.test/public/outside")).unwrap();
        symlink("/nonexistent", fixture.path("h.test/dangling")).unwrap();

        let result = fixture.remove(&rm("h.test", None, true, ID)).unwrap();
        assert_eq!(
            result.removed,
            vec![fixture.path("h.test").to_string_lossy()]
        );
        assert!(result.entries_removed >= 7);
        assert!(!fixture.path("h.test").exists());
        assert_eq!(
            fs::read_to_string(outside.join("precious")).unwrap(),
            "data"
        );
    }

    #[test]
    fn remove_refuses_unconfirmed_contents_but_takes_an_empty_directory() {
        let fixture = Fixture::new();
        fixture.site("i.test");
        assert!(matches!(
            fixture.remove(&rm("i.test", None, false, ID)),
            Err(Error::NotEmpty)
        ));
        assert!(fixture.path("i.test/index.php").exists());

        fs::create_dir(fixture.path("empty.test")).unwrap();
        fixture
            .remove(&rm("empty.test", None, false, OTHER_ID))
            .unwrap();
        assert!(!fixture.path("empty.test").exists());
    }

    #[test]
    fn remove_of_a_missing_site_succeeds_with_nothing_removed() {
        let fixture = Fixture::new();
        let result = fixture.remove(&rm("gone.test", None, true, ID)).unwrap();
        assert!(result.removed.is_empty());
        assert_eq!(result.entries_removed, 0);
    }

    #[test]
    fn remove_refuses_a_symlink_or_file_in_place_of_the_site_directory() {
        let fixture = Fixture::new();
        let outside = fixture.content.as_path().parent().unwrap().join("keep");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("precious"), "data").unwrap();
        symlink(&outside, fixture.path("link.test")).unwrap();
        assert!(matches!(
            fixture.remove(&rm("link.test", None, true, ID)),
            Err(Error::UnsafePath)
        ));
        fs::write(fixture.path("file.test"), "x").unwrap();
        assert!(matches!(
            fixture.remove(&rm("file.test", None, true, OTHER_ID)),
            Err(Error::UnsafePath)
        ));
        assert!(outside.join("precious").exists());
        assert!(fixture.path("link.test").symlink_metadata().is_ok());
    }

    #[test]
    fn remove_refuses_a_system_owned_directory_when_run_as_root() {
        if !is_root() {
            return;
        }
        let fixture = Fixture::new();
        fixture.site("j.test");
        std::os::unix::fs::chown(fixture.path("j.test"), Some(33), Some(33)).unwrap();
        assert!(matches!(
            fixture.remove(&rm("j.test", None, true, ID)),
            Err(Error::UnknownOwner)
        ));
        assert!(fixture.path("j.test/index.php").exists());
    }

    #[test]
    fn remove_takes_the_release_tree_only_when_the_manifest_names_the_domain() {
        let fixture = Fixture::new();
        fixture.site("k.test");
        fs::create_dir_all(fixture.path(&format!("sites/{SITE}/releases/r1"))).unwrap();
        symlink(
            "releases/r1",
            fixture.path(&format!("sites/{SITE}/current")),
        )
        .unwrap();

        // No manifest, or one for another domain: nothing at all is removed.
        assert!(matches!(
            fixture.remove(&rm("k.test", Some(SITE), true, ID)),
            Err(Error::ManifestMismatch)
        ));
        fixture.manifest(SITE, "other.test");
        assert!(matches!(
            fixture.remove(&rm("k.test", Some(SITE), true, OTHER_ID)),
            Err(Error::ManifestMismatch)
        ));
        assert!(fixture.path("k.test/index.php").exists());
        assert!(fixture.path(&format!("sites/{SITE}/releases/r1")).exists());

        fixture.manifest(SITE, "k.test");
        let result = fixture
            .remove(&rm("k.test", Some(SITE), true, THIRD_ID))
            .unwrap();
        assert_eq!(result.removed.len(), 2);
        assert!(!fixture.path("k.test").exists());
        assert!(!fixture.path(&format!("sites/{SITE}")).exists());
        // The shared `sites` directory itself stays.
        assert!(fixture.path("sites").is_dir());
    }

    #[test]
    fn remove_refuses_a_tree_deeper_than_the_bound_and_keeps_it() {
        let fixture = Fixture::new();
        fixture.site("l.test");
        let mut deep = fixture.path("l.test");
        for _ in 0..(MAX_REMOVE_DEPTH + 2) {
            deep.push("d");
        }
        fs::create_dir_all(&deep).unwrap();
        assert!(matches!(
            fixture.remove(&rm("l.test", None, true, ID)),
            Err(Error::OutOfBounds)
        ));
        assert!(fixture.path("l.test/index.php").exists());
    }

    #[test]
    fn remove_replays_a_recorded_outcome_for_the_same_key() {
        let fixture = Fixture::new();
        fixture.site("m.test");
        let mut req = rm("m.test", None, true, ID);
        req.idempotency_key = Some(IdempotencyKey::parse("rm-1").unwrap());
        let first = fixture.remove(&req).unwrap();
        let replayed = fixture.remove(&req).unwrap();
        assert_eq!(first.removed, replayed.removed);
    }

    #[test]
    fn remove_takes_a_tree_of_empty_directories_without_confirmation() {
        let fixture = Fixture::new();
        fs::create_dir_all(fixture.path("n.test/public/nested")).unwrap();
        let result = fixture.remove(&rm("n.test", None, false, ID)).unwrap();
        assert_eq!(result.removed.len(), 1);
        assert!(!fixture.path("n.test").exists());
    }

    fn release(domain: &str, site: Option<&str>, id: &str) -> ReleaseRequest {
        ReleaseRequest::parse(domain, site, id, None).unwrap()
    }

    #[test]
    fn release_skips_a_missing_site_and_checks_the_manifest() {
        let fixture = Fixture::new();
        let run = |req: &ReleaseRequest| {
            fs::create_dir_all(fixture.sites_dir()).unwrap();
            release_root(
                &fixture.state,
                std::slice::from_ref(&fixture.content),
                &fixture.sites_dir(),
                me().0,
                req,
            )
        };
        let result = run(&release("gone.test", None, ID)).unwrap();
        assert!(result.released.is_empty());

        fs::create_dir_all(fixture.path(&format!("sites/{SITE}"))).unwrap();
        assert!(matches!(
            run(&release("o.test", Some(SITE), OTHER_ID)),
            Err(Error::ManifestMismatch)
        ));
    }

    #[test]
    fn release_hands_the_tree_to_root_without_following_symlinks_when_run_as_root() {
        if !is_root() {
            return;
        }
        let fixture = Fixture::new();
        fixture.site("p.test");
        fs::create_dir_all(fixture.path("p.test/public")).unwrap();
        fs::write(fixture.path("p.test/public/a.php"), "x").unwrap();
        let outside = fixture.content.as_path().parent().unwrap().join("keep");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("precious"), "data").unwrap();
        symlink(&outside, fixture.path("p.test/public/out")).unwrap();
        for path in [
            "p.test",
            "p.test/index.php",
            "p.test/public",
            "p.test/public/a.php",
        ] {
            std::os::unix::fs::chown(fixture.path(path), Some(12345), Some(12345)).unwrap();
        }
        std::os::unix::fs::chown(&outside, Some(777), Some(777)).unwrap();

        let result = release_root(
            &fixture.state,
            std::slice::from_ref(&fixture.content),
            &fixture.sites_dir(),
            0,
            &release("p.test", None, ID),
        )
        .unwrap();
        assert_eq!(
            result.released,
            vec![fixture.path("p.test").to_string_lossy()]
        );
        for path in [
            "p.test",
            "p.test/index.php",
            "p.test/public",
            "p.test/public/a.php",
        ] {
            let metadata = fs::symlink_metadata(fixture.path(path)).unwrap();
            assert_eq!((metadata.uid(), metadata.gid()), (0, 0), "{path}");
        }
        assert_eq!(fs::metadata(&outside).unwrap().uid(), 777);
    }

    #[test]
    fn prepare_parses_the_existing_policy() {
        let parse = |existing: Option<&str>| {
            PrepareRequest::parse("a.test", None, 10000, 10000, existing, ID, None)
                .map(|req| req.existing)
        };
        assert_eq!(parse(None).unwrap(), ExistingPolicy::Refuse);
        assert_eq!(parse(Some("refuse")).unwrap(), ExistingPolicy::Refuse);
        assert_eq!(
            parse(Some("adopt-directory")).unwrap(),
            ExistingPolicy::AdoptDirectory
        );
        assert_eq!(
            parse(Some("adopt-tree")).unwrap(),
            ExistingPolicy::AdoptTree
        );
        assert_eq!(
            parse(Some("recursive")).err(),
            Some(RequestError::InvalidExistingPolicy)
        );
    }

    #[test]
    fn prepare_adopts_existing_content_only_when_asked_when_run_as_root() {
        if !is_root() {
            return;
        }
        let fixture = Fixture::new();
        let outside = fixture.content.as_path().parent().unwrap().join("keep");
        fs::create_dir(&outside).unwrap();
        std::os::unix::fs::chown(&outside, Some(777), Some(777)).unwrap();
        let build = |site: &str| {
            fixture.site(site);
            fs::create_dir_all(fixture.path(&format!("{site}/sub"))).unwrap();
            fs::write(fixture.path(&format!("{site}/sub/f.php")), "x").unwrap();
            symlink(&outside, fixture.path(&format!("{site}/sub/out"))).unwrap();
            for path in ["", "/index.php", "/sub", "/sub/f.php"] {
                std::os::unix::fs::chown(
                    fixture.path(&format!("{site}{path}")),
                    Some(500),
                    Some(500),
                )
                .unwrap();
            }
        };
        let owner = |path: String| fs::symlink_metadata(fixture.path(&path)).unwrap().uid();

        build("q.test");
        assert!(matches!(
            fixture.prepare(&prep("q.test", &[], 12345, 12345, ID)),
            Err(Error::ExistingContent)
        ));
        assert_eq!(owner("q.test".into()), 500);

        let mut req = prep("q.test", &[], 12345, 12345, OTHER_ID);
        req.existing = ExistingPolicy::AdoptDirectory;
        fixture.prepare(&req).unwrap();
        assert_eq!(owner("q.test".into()), 12345);
        assert_eq!(owner("q.test/index.php".into()), 500);
        assert_eq!(mode_of(&fixture.path("q.test")), 0o700);

        build("r.test");
        let mut req = prep("r.test", &[], 12345, 12345, THIRD_ID);
        req.existing = ExistingPolicy::AdoptTree;
        fixture.prepare(&req).unwrap();
        for path in [
            "r.test",
            "r.test/index.php",
            "r.test/sub",
            "r.test/sub/f.php",
        ] {
            assert_eq!(owner(path.into()), 12345, "{path}");
        }
        // The symlink was neither followed nor changed.
        assert_eq!(fs::metadata(&outside).unwrap().uid(), 777);
    }

    #[test]
    fn remove_with_a_relative_root_takes_only_that_directory_and_prunes_empty_parents() {
        let fixture = Fixture::new();
        let remove = |domain: &str, id: &str| {
            fixture
                .remove(
                    &RemoveRequest::parse(domain, Some("public"), None, true, id, None).unwrap(),
                )
                .unwrap()
        };

        // Only the root goes; the site directory stays while it holds
        // anything else.
        fs::create_dir_all(fixture.path("s.test/public")).unwrap();
        fs::write(fixture.path("s.test/public/index.php"), "x").unwrap();
        fs::write(fixture.path("s.test/notes.txt"), "keep").unwrap();
        let result = remove("s.test", ID);
        assert_eq!(
            result.removed,
            vec![fixture.path("s.test/public").to_string_lossy()]
        );
        assert!(!fixture.path("s.test/public").exists());
        assert!(fixture.path("s.test/notes.txt").exists());

        // An otherwise empty site directory is removed with its root.
        fs::create_dir_all(fixture.path("t.test/public")).unwrap();
        remove("t.test", OTHER_ID);
        assert!(!fixture.path("t.test").exists());

        // A missing root is a no-op.
        assert!(remove("u.test", THIRD_ID).removed.is_empty());
    }
}
