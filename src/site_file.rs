//! `site.writeEnvFile` and `site.quarantineFile` (milestone 072): the two
//! single-file operations on a site's content directory that the control
//! panel used to run as a raw `base64 -d > path` (`env_write`) and a raw
//! `sudo mv` into `/var/quarantine` (`malware_quarantine`).
//!
//! Both name a file by absolute path, but the engine only acts on a path
//! below one of its configured content roots. Every directory between the
//! root and the file is looked at with `lstat` and opened with
//! `O_NOFOLLOW` through the previous level's descriptor, so a symlink a
//! tenant swapped in is refused, never followed, and the final file must be
//! a regular file. Both take the resource lock of the site directory (the
//! first path component below the root, the same lock `site.moveRoot` and
//! the WordPress operations use) and record a transaction and an audit entry
//! in the `site-file` scope.
//!
//! # `site.writeEnvFile`
//!
//! The file name must be `.env`, `*.env` or `.env.*`. The new content goes
//! through a same-directory temp file and a rename, so a reader never sees a
//! half-written secret file. An existing file keeps its owner, group and mode
//! (a site's `.env` is read by the site's own identity, so a root-owned
//! replacement would break the site); a new file is created `0600` and handed
//! to the owner of its directory. The temp file is `0600` from the moment it
//! is created. With `expectedHash` the write is refused (`CONFIG_HASH_MISMATCH`)
//! unless the current content has that SHA-256, which is what stops one editor
//! overwriting another's save; without it the write is unconditional.
//!
//! The content arrives in a staged, root-owned request file, never in argv.
//!
//! # `site.quarantineFile`
//!
//! The file is streamed into `<state root>/site-file/quarantine` as
//! `<unix seconds>-<sha256>.quarantine` (root-owned, `0600`, in a `0700`
//! directory) with a `.json` manifest beside it: original path, SHA-256, size,
//! owner, group, mode and mtime. Nothing is overwritten (two files with the
//! same name no longer clobber each other, as they did in `/var/quarantine`)
//! and a restore stays possible from the manifest. The original is removed
//! only after the copy is complete and the source is seen unchanged (device,
//! inode, size and mtime); if the removal fails the copy is taken back out. A
//! file larger than 512 MiB is refused.

use std::{
    ffi::OsStr,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use cap_std::fs::MetadataExt as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    filesystem::ManagedRoot,
    ingress::{ConfigHash, MAX_CONTENT_BYTES},
    site::{SiteRelativePath, TrustedRoot},
    site_root::{Error, open_error, rel, transact_in, unix_now_secs},
    transaction::{IdempotencyKey, RequestId},
};

pub const ENV_OPERATION: &str = "site.writeEnvFile";
pub const QUARANTINE_OPERATION: &str = "site.quarantineFile";

const SCOPE: &str = "site-file";
const QUARANTINE_DIR: &str = "site-file/quarantine";
const MAX_PATH_BYTES: usize = 4096;
/// A file is `<domain dir>/<...>/<file>`; deeper than this is not a site file.
const MAX_COMPONENTS: usize = 16;
const MAX_QUARANTINE_BYTES: u64 = 512 * 1024 * 1024;
const COPY_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestError {
    InvalidRequest,
    InvalidPath,
    InvalidFileName,
    InvalidContent,
    InvalidHash,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl RequestError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidRequest => "the request file is not a valid writeEnvFile request",
            Self::InvalidPath => "path must be an absolute path without '..' or empty segments",
            Self::InvalidFileName => "the file name must be .env, *.env or .env.*",
            Self::InvalidContent => "content must be at most 256 KiB and contain no NUL",
            Self::InvalidHash => "expectedHash must be 64 hexadecimal digits",
            Self::InvalidRequestId => "request-id must be a canonical UUID",
            Self::InvalidIdempotencyKey => "idempotency-key is invalid",
        }
    }
}

/// `.env`, `*.env` (at least one character before the suffix) or `.env.*`
/// (at least one character after it).
pub fn is_env_file_name(name: &str) -> bool {
    name == ".env"
        || (name.len() > ".env".len() && name.ends_with(".env"))
        || (name.len() > ".env.".len() && name.starts_with(".env."))
}

fn parse_path(path: &str) -> Result<&Path, RequestError> {
    if path.is_empty() || path.len() > MAX_PATH_BYTES || path.contains('\0') {
        return Err(RequestError::InvalidPath);
    }
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err(RequestError::InvalidPath);
    }
    Ok(path)
}

fn parse_ids(
    request_id: &str,
    key: Option<&str>,
) -> Result<(RequestId, Option<IdempotencyKey>), RequestError> {
    Ok((
        RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
        key.map(IdempotencyKey::parse)
            .transpose()
            .map_err(|_| RequestError::InvalidIdempotencyKey)?,
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawEnvRequest {
    path: String,
    content: String,
    #[serde(default)]
    expected_hash: Option<String>,
}

pub struct EnvRequest {
    pub path: PathBuf,
    content: Vec<u8>,
    pub expected_hash: Option<ConfigHash>,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl std::fmt::Debug for EnvRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvRequest")
            .field("path", &self.path)
            .field("content", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl EnvRequest {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let raw: RawEnvRequest =
            serde_json::from_str(json).map_err(|_| RequestError::InvalidRequest)?;
        let path = parse_path(&raw.path)?;
        let name = path
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or(RequestError::InvalidPath)?;
        if !is_env_file_name(name) {
            return Err(RequestError::InvalidFileName);
        }
        if raw.content.len() > MAX_CONTENT_BYTES || raw.content.contains('\0') {
            return Err(RequestError::InvalidContent);
        }
        let expected_hash = raw
            .expected_hash
            .as_deref()
            .map(ConfigHash::parse)
            .transpose()
            .map_err(|_| RequestError::InvalidHash)?;
        let (request_id, idempotency_key) = parse_ids(request_id, key)?;
        Ok(Self {
            path: path.to_owned(),
            content: raw.content.into_bytes(),
            expected_hash,
            request_id,
            idempotency_key,
        })
    }
}

#[derive(Debug)]
pub struct QuarantineRequest {
    pub path: PathBuf,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl QuarantineRequest {
    pub fn parse(path: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let path = parse_path(path)?;
        path.file_name().ok_or(RequestError::InvalidPath)?;
        let (request_id, idempotency_key) = parse_ids(request_id, key)?;
        Ok(Self {
            path: path.to_owned(),
            request_id,
            idempotency_key,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvResult {
    pub path: String,
    /// The file did not exist before.
    pub created: bool,
    pub bytes: u64,
    /// SHA-256 of the content now in the file.
    pub sha256: String,
    /// SHA-256 of the content that was replaced.
    pub previous_sha256: Option<String>,
    pub mode: u32,
    pub completed_at_unix_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineResult {
    pub original_path: String,
    /// The copy's file name inside `<state root>/site-file/quarantine`; the
    /// manifest beside it has the same stem and a `.json` extension.
    pub quarantine_file: String,
    pub sha256: String,
    pub size: u64,
    pub completed_at_unix_secs: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct QuarantineManifest<'a> {
    original_path: &'a str,
    sha256: &'a str,
    size: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    mtime_unix_secs: i64,
    quarantined_at_unix_secs: u64,
    request_id: String,
}

/// The content root a path is below and its components beneath it, which
/// must be a site directory and at least one more level.
fn split_path<'a>(
    content_roots: &'a [TrustedRoot],
    path: &Path,
) -> Result<(&'a TrustedRoot, Vec<SiteRelativePath>), Error> {
    for root in content_roots {
        let Ok(rest) = path.strip_prefix(root.as_path()) else {
            continue;
        };
        let mut names = Vec::new();
        for component in rest.components() {
            let std::path::Component::Normal(name) = component else {
                return Err(Error::OutsideContentRoot);
            };
            names.push(SiteRelativePath::parse(name).map_err(|_| Error::OutsideContentRoot)?);
        }
        if names.len() < 2 || names.len() > MAX_COMPONENTS {
            return Err(Error::OutsideContentRoot);
        }
        return Ok((root, names));
    }
    Err(Error::OutsideContentRoot)
}

/// Walks to the directory holding the file without following a symlink and
/// returns it with the file's name.
fn open_parent(
    content_root: &TrustedRoot,
    names: &[SiteRelativePath],
) -> Result<(ManagedRoot, SiteRelativePath), Error> {
    crate::site_root::refuse_system_dir(content_root)?;
    let (file, dirs) = names.split_last().expect("at least two components");
    let mut dir = ManagedRoot::open(content_root).map_err(Error::Io)?;
    for name in dirs {
        match dir.symlink_metadata(name) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => return Err(Error::UnsafePath),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(Error::FileMissing);
            }
            Err(error) => return Err(Error::Io(error)),
        }
        dir = dir.open_child_dir_nofollow(name).map_err(open_error)?;
    }
    Ok((dir, file.clone()))
}

fn hex(digest: &[u8]) -> String {
    use std::fmt::Write as _;
    digest.iter().fold(String::with_capacity(64), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// Writes `request.content` to the env file, replacing it atomically.
pub fn write_env_file(
    engine_state: &ManagedRoot,
    content_roots: &[TrustedRoot],
    req: &EnvRequest,
) -> Result<EnvResult, Error> {
    let (content_root, names) = split_path(content_roots, &req.path)?;
    let lock = content_root.as_path().join(names[0].as_path());
    transact_in(
        SCOPE,
        engine_state,
        ENV_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        &[lock.as_path()],
        || write_env(content_root, &names, req),
    )
}

fn write_env(
    content_root: &TrustedRoot,
    names: &[SiteRelativePath],
    req: &EnvRequest,
) -> Result<EnvResult, Error> {
    let (parent, name) = open_parent(content_root, names)?;
    let text_name = name.as_path().to_string_lossy().into_owned();
    if !is_env_file_name(&text_name) {
        return Err(Error::OutsideContentRoot);
    }

    // What is there now: nothing, or a regular file whose owner, group and
    // mode the replacement keeps.
    let existing = match parent.symlink_metadata(&name) {
        Ok(metadata) if metadata.is_file() => Some(metadata),
        Ok(metadata) if metadata.file_type().is_symlink() => return Err(Error::UnsafePath),
        Ok(_) => return Err(Error::NotRegularFile),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(Error::Io(error)),
    };
    let previous = match &existing {
        Some(_) => Some(ConfigHash::of(
            &parent.read_bytes(&name).map_err(Error::Io)?,
        )),
        None => None,
    };
    if let Some(expected) = &req.expected_hash {
        if previous.as_ref() != Some(expected) {
            return Err(Error::HashMismatch);
        }
    }
    let (uid, gid, mode) = match &existing {
        Some(metadata) => (metadata.uid(), metadata.gid(), metadata.mode() & 0o777),
        None => {
            let directory = parent.own_metadata().map_err(Error::Io)?;
            (directory.uid(), directory.gid(), 0o600)
        }
    };

    let temp = SiteRelativePath::parse(format!(".{text_name}.wcp-{}.tmp", req.request_id))
        .map_err(|_| Error::Io(io::Error::other("invalid temporary file name")))?;
    let staged = (|| -> io::Result<()> {
        let mut file = parent.create_new_file_with_mode(&temp, 0o600)?;
        file.write_all(&req.content)?;
        file.sync_all()?;
        drop(file);
        parent.chown(&temp, uid, gid)?;
        parent.set_mode(&temp, mode)?;
        parent.rename(&temp, &name)
    })();
    if let Err(error) = staged {
        let _ = parent.remove_file(&temp);
        return Err(Error::Io(error));
    }

    Ok(EnvResult {
        path: req.path.to_string_lossy().into_owned(),
        created: existing.is_none(),
        bytes: req.content.len() as u64,
        sha256: ConfigHash::of(&req.content).to_string(),
        previous_sha256: previous.map(|hash| hash.to_string()),
        mode,
        completed_at_unix_secs: unix_now_secs(),
    })
}

/// Moves the file into the engine's quarantine directory.
pub fn quarantine_file(
    engine_state: &ManagedRoot,
    content_roots: &[TrustedRoot],
    req: &QuarantineRequest,
) -> Result<QuarantineResult, Error> {
    quarantine_file_bounded(engine_state, content_roots, req, MAX_QUARANTINE_BYTES)
}

fn quarantine_file_bounded(
    engine_state: &ManagedRoot,
    content_roots: &[TrustedRoot],
    req: &QuarantineRequest,
    max_bytes: u64,
) -> Result<QuarantineResult, Error> {
    let (content_root, names) = split_path(content_roots, &req.path)?;
    let lock = content_root.as_path().join(names[0].as_path());
    transact_in(
        SCOPE,
        engine_state,
        QUARANTINE_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        &[lock.as_path()],
        || quarantine(engine_state, content_root, &names, req, max_bytes),
    )
}

fn quarantine(
    engine_state: &ManagedRoot,
    content_root: &TrustedRoot,
    names: &[SiteRelativePath],
    req: &QuarantineRequest,
    max_bytes: u64,
) -> Result<QuarantineResult, Error> {
    let (parent, name) = open_parent(content_root, names)?;
    let metadata = match parent.symlink_metadata(&name) {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(metadata) if metadata.file_type().is_symlink() => return Err(Error::UnsafePath),
        Ok(_) => return Err(Error::NotRegularFile),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(Error::FileMissing),
        Err(error) => return Err(Error::Io(error)),
    };
    if metadata.size() > max_bytes {
        return Err(Error::FileTooLarge);
    }

    engine_state
        .create_dir_all(&rel(QUARANTINE_DIR))
        .map_err(Error::Io)?;
    let quarantine = engine_state
        .open_managed_dir(&rel(QUARANTINE_DIR))
        .map_err(Error::Io)?;
    quarantine.set_own_mode(0o700).map_err(Error::Io)?;

    let incoming = rel(&format!(".incoming-{}", req.request_id));
    let copied = copy_and_hash(&parent, &name, &quarantine, &incoming, max_bytes);
    let (sha256, size, before) = match copied {
        Ok(copied) => copied,
        Err(error) => {
            let _ = quarantine.remove_file(&incoming);
            return Err(error);
        }
    };

    // The copy is only the file's content if the file was not swapped or
    // edited while it was being read.
    let unchanged = parent.symlink_metadata(&name).is_ok_and(|after| {
        after.is_file()
            && after.dev() == before.dev()
            && after.ino() == before.ino()
            && after.size() == before.size()
            && after.mtime() == before.mtime()
            && after.mtime_nsec() == before.mtime_nsec()
    });
    if !unchanged {
        let _ = quarantine.remove_file(&incoming);
        return Err(Error::FileChanged);
    }

    let now = unix_now_secs();
    let stem = format!("{now}-{sha256}");
    let data = rel(&format!("{stem}.quarantine"));
    let manifest = rel(&format!("{stem}.json"));
    let original = req.path.to_string_lossy().into_owned();
    let manifest_json = serde_json::to_vec_pretty(&QuarantineManifest {
        original_path: &original,
        sha256: &sha256,
        size,
        uid: before.uid(),
        gid: before.gid(),
        mode: before.mode() & 0o7777,
        mtime_unix_secs: before.mtime(),
        quarantined_at_unix_secs: now,
        request_id: req.request_id.to_string(),
    })
    .expect("a manifest always serializes");

    let placed = quarantine
        .rename(&incoming, &data)
        .and_then(|()| quarantine.write_atomic_private(&manifest, &manifest_json))
        .and_then(|()| parent.remove_file(&name));
    if let Err(error) = placed {
        let _ = quarantine.remove_file(&incoming);
        let _ = quarantine.remove_file(&data);
        let _ = quarantine.remove_file(&manifest);
        return Err(Error::Io(error));
    }

    Ok(QuarantineResult {
        original_path: original,
        quarantine_file: format!("{stem}.quarantine"),
        sha256,
        size,
        completed_at_unix_secs: now,
    })
}

type CopyOutcome = (String, u64, cap_std::fs::Metadata);

/// Streams `name` into `incoming` (created `0600`) while hashing it.
fn copy_and_hash(
    parent: &ManagedRoot,
    name: &SiteRelativePath,
    quarantine: &ManagedRoot,
    incoming: &SiteRelativePath,
    max_bytes: u64,
) -> Result<CopyOutcome, Error> {
    let mut source = parent.open_read(name).map_err(Error::Io)?;
    let before = parent.symlink_metadata(name).map_err(Error::Io)?;
    let mut target = quarantine
        .create_new_file_with_mode(incoming, 0o600)
        .map_err(Error::Io)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; COPY_BUFFER_BYTES];
    let mut total = 0u64;
    loop {
        let read = source.read(&mut buffer).map_err(Error::Io)?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > max_bytes {
            return Err(Error::FileTooLarge);
        }
        hasher.update(&buffer[..read]);
        target.write_all(&buffer[..read]).map_err(Error::Io)?;
    }
    target.sync_all().map_err(Error::Io)?;
    Ok((hex(&hasher.finalize()), total, before))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::transaction::resource_lock;
    use std::os::unix::fs::MetadataExt as _;
    use std::{fs, os::unix::fs::PermissionsExt, os::unix::fs::symlink};

    const ID1: &str = "123e4567-e89b-12d3-a456-426614174001";
    const ID2: &str = "123e4567-e89b-12d3-a456-426614174002";
    const ID3: &str = "123e4567-e89b-12d3-a456-426614174003";
    const ID4: &str = "123e4567-e89b-12d3-a456-426614174004";

    struct Fixture {
        dir: tempfile::TempDir,
        roots: Vec<TrustedRoot>,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            fs::create_dir_all(dir.path().join("www/site-a/sub")).unwrap();
            fs::create_dir_all(dir.path().join("www/site-b")).unwrap();
            fs::create_dir_all(dir.path().join("state")).unwrap();
            fs::create_dir_all(dir.path().join("elsewhere")).unwrap();
            let roots = vec![TrustedRoot::parse(dir.path().join("www")).unwrap()];
            Self { dir, roots }
        }

        fn state(&self) -> ManagedRoot {
            ManagedRoot::open(&TrustedRoot::parse(self.dir.path().join("state")).unwrap()).unwrap()
        }

        fn www(&self, rest: &str) -> PathBuf {
            self.dir.path().join("www").join(rest)
        }

        fn quarantine_dir(&self) -> PathBuf {
            self.dir.path().join("state").join(QUARANTINE_DIR)
        }
    }

    fn env_request(
        path: &Path,
        content: &str,
        hash: Option<&str>,
        id: &str,
        key: Option<&str>,
    ) -> EnvRequest {
        let mut json = serde_json::json!({ "path": path, "content": content });
        if let Some(hash) = hash {
            json["expectedHash"] = hash.into();
        }
        EnvRequest::parse(&json.to_string(), id, key).unwrap()
    }

    fn write(f: &Fixture, req: &EnvRequest) -> Result<EnvResult, Error> {
        write_env_file(&f.state(), &f.roots, req)
    }

    fn quarantine(f: &Fixture, path: &Path, id: &str) -> Result<QuarantineResult, Error> {
        quarantine_file(
            &f.state(),
            &f.roots,
            &QuarantineRequest::parse(path.to_str().unwrap(), id, None).unwrap(),
        )
    }

    #[test]
    fn env_file_names() {
        for ok in [".env", "app.env", ".env.production", ".env.local", "a.env"] {
            assert!(is_env_file_name(ok), "{ok}");
        }
        for bad in [
            "env",
            ".envx",
            "x.envx",
            ".env.",
            "foo",
            "config.php",
            ".environment",
            "",
        ] {
            assert!(!is_env_file_name(bad), "{bad}");
        }
    }

    #[test]
    fn env_request_validation() {
        let parse =
            |json: serde_json::Value| EnvRequest::parse(&json.to_string(), ID1, None).map(|_| ());
        assert_eq!(
            parse(serde_json::json!({"path": "/var/www/a/.env", "content": "A=1"})),
            Ok(())
        );
        assert_eq!(
            parse(serde_json::json!({"path": "relative/.env", "content": ""})),
            Err(RequestError::InvalidPath)
        );
        assert_eq!(
            parse(serde_json::json!({"path": "/var/www/a/config.php", "content": ""})),
            Err(RequestError::InvalidFileName)
        );
        assert_eq!(
            parse(serde_json::json!({"path": "/var/www/a/.env", "content": "a\0b"})),
            Err(RequestError::InvalidContent)
        );
        assert_eq!(
            parse(
                serde_json::json!({"path": "/var/www/a/.env", "content": "x".repeat(MAX_CONTENT_BYTES + 1)})
            ),
            Err(RequestError::InvalidContent)
        );
        assert_eq!(
            parse(
                serde_json::json!({"path": "/var/www/a/.env", "content": "", "expectedHash": "abc"})
            ),
            Err(RequestError::InvalidHash)
        );
        assert_eq!(
            parse(serde_json::json!({"path": "/var/www/a/.env", "content": "", "other": 1})),
            Err(RequestError::InvalidRequest)
        );
        assert_eq!(
            EnvRequest::parse("{\"path\":\"/a/.env\",\"content\":\"\"}", "nope", None).unwrap_err(),
            RequestError::InvalidRequestId
        );
        assert_eq!(
            QuarantineRequest::parse("relative", ID1, None).unwrap_err(),
            RequestError::InvalidPath
        );
        assert_eq!(
            QuarantineRequest::parse("/", ID1, None).unwrap_err(),
            RequestError::InvalidPath
        );
    }

    #[test]
    fn a_new_env_file_is_private_and_belongs_to_its_directory() {
        let f = Fixture::new();
        let path = f.www("site-a/.env");
        let done = write(&f, &env_request(&path, "APP_KEY=secret\n", None, ID1, None)).unwrap();
        assert!(done.created);
        assert_eq!(done.previous_sha256, None);
        assert_eq!(done.mode, 0o600);
        assert_eq!(done.sha256, ConfigHash::of(b"APP_KEY=secret\n").to_string());
        assert_eq!(fs::read_to_string(&path).unwrap(), "APP_KEY=secret\n");
        let meta = fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let dir = fs::metadata(f.www("site-a")).unwrap();
        assert_eq!((meta.uid(), meta.gid()), (dir.uid(), dir.gid()));
        let leftovers: Vec<_> = fs::read_dir(f.www("site-a"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(leftovers.contains(&".env".to_owned()), "{leftovers:?}");
        assert!(
            !leftovers.iter().any(|n| n.ends_with(".tmp")),
            "{leftovers:?}"
        );
    }

    #[test]
    fn replacing_an_env_file_keeps_its_mode_and_reports_both_hashes() {
        let f = Fixture::new();
        let path = f.www("site-a/sub/prod.env");
        fs::write(&path, "OLD=1\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let done = write(&f, &env_request(&path, "NEW=2\n", None, ID1, None)).unwrap();
        assert!(!done.created);
        assert_eq!(done.mode, 0o640);
        assert_eq!(
            done.previous_sha256,
            Some(ConfigHash::of(b"OLD=1\n").to_string())
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), "NEW=2\n");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    #[test]
    fn expected_hash_guards_against_a_concurrent_edit() {
        let f = Fixture::new();
        let path = f.www("site-a/.env");
        fs::write(&path, "A=1\n").unwrap();
        let current = ConfigHash::of(b"A=1\n").to_string();
        let stale = ConfigHash::of(b"A=0\n").to_string();

        let err = write(&f, &env_request(&path, "B=2\n", Some(&stale), ID1, None)).unwrap_err();
        assert!(matches!(err, Error::HashMismatch));
        assert_eq!(
            err.protocol().0,
            crate::error::ErrorCode::ConfigHashMismatch
        );
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "A=1\n",
            "a refused write changes nothing"
        );

        write(
            &f,
            &env_request(&path, "B=2\n", Some(&current.to_uppercase()), ID2, None),
        )
        .unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "B=2\n");

        // A hash for a file that is not there is a mismatch too.
        let missing = f.www("site-b/.env");
        let err = write(
            &f,
            &env_request(&missing, "X=1\n", Some(&current), ID3, None),
        )
        .unwrap_err();
        assert!(matches!(err, Error::HashMismatch));
        assert!(!missing.exists());
    }

    #[test]
    fn env_write_replays_without_writing_again() {
        let f = Fixture::new();
        let path = f.www("site-a/.env");
        let req = env_request(&path, "A=1\n", None, ID1, Some("key-1"));
        let first = write(&f, &req).unwrap();
        fs::write(&path, "EDITED=elsewhere\n").unwrap();
        let again = write(&f, &req).unwrap();
        assert_eq!(again.completed_at_unix_secs, first.completed_at_unix_secs);
        assert_eq!(fs::read_to_string(&path).unwrap(), "EDITED=elsewhere\n");
    }

    #[test]
    fn symlinks_directories_and_paths_outside_the_roots_are_refused() {
        let f = Fixture::new();
        // A symlinked directory below the site directory.
        symlink(f.dir.path().join("elsewhere"), f.www("site-a/link")).unwrap();
        let err = write(
            &f,
            &env_request(&f.www("site-a/link/.env"), "A=1\n", None, ID1, None),
        )
        .unwrap_err();
        assert!(matches!(err, Error::UnsafePath));
        assert!(!f.dir.path().join("elsewhere/.env").exists());
        // A symlinked site directory.
        symlink(f.dir.path().join("elsewhere"), f.www("site-c")).unwrap();
        let err = write(
            &f,
            &env_request(&f.www("site-c/.env"), "A=1\n", None, ID2, None),
        )
        .unwrap_err();
        assert!(matches!(err, Error::UnsafePath));
        // A symlink as the file itself.
        fs::write(f.dir.path().join("elsewhere/target"), "keep").unwrap();
        symlink(f.dir.path().join("elsewhere/target"), f.www("site-a/.env")).unwrap();
        let err = write(
            &f,
            &env_request(&f.www("site-a/.env"), "A=1\n", None, ID3, None),
        )
        .unwrap_err();
        assert!(matches!(err, Error::UnsafePath));
        assert_eq!(
            fs::read_to_string(f.dir.path().join("elsewhere/target")).unwrap(),
            "keep"
        );
        // A directory named like an env file.
        fs::create_dir(f.www("site-b/.env")).unwrap();
        let err = write(
            &f,
            &env_request(&f.www("site-b/.env"), "A=1\n", None, ID4, None),
        )
        .unwrap_err();
        assert!(matches!(err, Error::NotRegularFile));
        // Outside the content roots, directly in a root, and with '..'.
        for (i, path) in [
            PathBuf::from("/etc/site/.env"),
            f.www(".env"),
            f.www("site-a/../../elsewhere/.env"),
            f.dir.path().join("elsewhere/.env"),
        ]
        .into_iter()
        .enumerate()
        {
            let id = format!("123e4567-e89b-12d3-a456-4266141740{:02}", 10 + i);
            let err = write(&f, &env_request(&path, "A=1\n", None, &id, None)).unwrap_err();
            assert!(
                matches!(err, Error::OutsideContentRoot),
                "{path:?}: {err:?}"
            );
        }
        // A missing directory is a missing file, not a created tree.
        let err = write(
            &f,
            &env_request(
                &f.www("site-a/nope/.env"),
                "A=1\n",
                None,
                "123e4567-e89b-12d3-a456-426614174030",
                Some("k"),
            ),
        )
        .unwrap_err();
        assert!(matches!(err, Error::FileMissing));
        assert!(!f.www("site-a/nope").exists());
    }

    #[test]
    fn a_busy_site_directory_is_a_conflict() {
        let f = Fixture::new();
        let state = f.state();
        let lock_path = f.www("site-a");
        let held = resource_lock::acquire_many(
            &state,
            &[lock_path.as_path()],
            RequestId::parse(ID3).unwrap(),
        )
        .map_err(|_| ())
        .unwrap();
        let err = write(
            &f,
            &env_request(&f.www("site-a/.env"), "A=1\n", None, ID1, None),
        )
        .unwrap_err();
        assert!(matches!(err, Error::ResourceBusy));
        assert!(!f.www("site-a/.env").exists());
        // Another site is not affected.
        write(
            &f,
            &env_request(&f.www("site-b/.env"), "A=1\n", None, ID2, None),
        )
        .unwrap();
        drop(held);
        write(
            &f,
            &env_request(&f.www("site-a/.env"), "A=1\n", None, ID4, None),
        )
        .unwrap();
    }

    #[test]
    fn quarantine_moves_the_file_and_records_a_manifest() {
        let f = Fixture::new();
        let path = f.www("site-a/sub/shell.php");
        fs::write(&path, "<?php evil();").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let done = quarantine(&f, &path, ID1).unwrap();
        assert!(!path.exists(), "the original is gone");
        assert_eq!(done.size, 13);
        let sha = ConfigHash::of(b"<?php evil();").to_string();
        assert_eq!(done.sha256, sha);
        assert!(
            done.quarantine_file
                .ends_with(&format!("-{sha}.quarantine"))
        );
        let stored = f.quarantine_dir().join(&done.quarantine_file);
        assert_eq!(fs::read(&stored).unwrap(), b"<?php evil();");
        assert_eq!(
            fs::metadata(&stored).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(f.quarantine_dir())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let manifest: serde_json::Value = serde_json::from_slice(
            &fs::read(
                f.quarantine_dir()
                    .join(done.quarantine_file.replace(".quarantine", ".json")),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(manifest["originalPath"], path.to_string_lossy().as_ref());
        assert_eq!(manifest["sha256"], sha.as_str());
        assert_eq!(manifest["size"], 13);
        assert_eq!(manifest["mode"], 0o644);
        assert_eq!(manifest["requestId"], ID1);
        let leftovers: Vec<_> = fs::read_dir(f.quarantine_dir())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".incoming"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn files_with_the_same_name_do_not_overwrite_each_other() {
        let f = Fixture::new();
        let a = f.www("site-a/index.php");
        let b = f.www("site-b/index.php");
        fs::write(&a, "first").unwrap();
        fs::write(&b, "second").unwrap();
        let first = quarantine(&f, &a, ID1).unwrap();
        let second = quarantine(&f, &b, ID2).unwrap();
        assert_ne!(first.quarantine_file, second.quarantine_file);
        assert_eq!(
            fs::read(f.quarantine_dir().join(&first.quarantine_file)).unwrap(),
            b"first"
        );
        assert_eq!(
            fs::read(f.quarantine_dir().join(&second.quarantine_file)).unwrap(),
            b"second"
        );
    }

    #[test]
    fn quarantine_refuses_what_it_should_not_touch() {
        let f = Fixture::new();
        fs::write(f.dir.path().join("elsewhere/target"), "keep").unwrap();
        symlink(
            f.dir.path().join("elsewhere/target"),
            f.www("site-a/link.php"),
        )
        .unwrap();
        let err = quarantine(&f, &f.www("site-a/link.php"), ID1).unwrap_err();
        assert!(matches!(err, Error::UnsafePath));
        assert_eq!(
            fs::read_to_string(f.dir.path().join("elsewhere/target")).unwrap(),
            "keep"
        );
        let err = quarantine(&f, &f.www("site-a/sub"), ID2).unwrap_err();
        assert!(matches!(err, Error::NotRegularFile));
        let err = quarantine(&f, &f.www("site-a/missing.php"), ID3).unwrap_err();
        assert!(matches!(err, Error::FileMissing));
        assert_eq!(err.protocol().0, crate::error::ErrorCode::NotFound);
        let err = quarantine(&f, Path::new("/etc/passwd"), ID4).unwrap_err();
        assert!(matches!(err, Error::OutsideContentRoot));
        assert!(
            !f.quarantine_dir().exists()
                || fs::read_dir(f.quarantine_dir()).unwrap().next().is_none()
        );
    }

    #[test]
    fn an_oversized_file_is_left_in_place() {
        let f = Fixture::new();
        let path = f.www("site-a/big.bin");
        fs::write(&path, "0123456789").unwrap();
        let req = QuarantineRequest::parse(path.to_str().unwrap(), ID1, None).unwrap();
        let err = quarantine_file_bounded(&f.state(), &f.roots, &req, 4).unwrap_err();
        assert!(matches!(err, Error::FileTooLarge));
        assert_eq!(fs::read_to_string(&path).unwrap(), "0123456789");
        assert!(
            !f.quarantine_dir().exists(),
            "a refused file creates no quarantine state"
        );
    }

    #[test]
    fn quarantine_replays_after_the_file_is_gone() {
        let f = Fixture::new();
        let path = f.www("site-a/shell.php");
        fs::write(&path, "x").unwrap();
        let req = QuarantineRequest::parse(path.to_str().unwrap(), ID1, Some("k")).unwrap();
        let first = quarantine_file(&f.state(), &f.roots, &req).unwrap();
        let again = quarantine_file(&f.state(), &f.roots, &req).unwrap();
        assert_eq!(first.quarantine_file, again.quarantine_file);
    }
}
