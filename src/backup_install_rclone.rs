//! `backup.installRclone`: installs a pinned, SHA-256-verified rclone
//! release binary as `/usr/bin/rclone`. Replaces the panel's
//! `curl -fsSL https://rclone.org/install.sh | bash`, which executed an
//! unpinned remote script as root.
//!
//! Nothing downloaded is trusted until the whole release zip hashes to the
//! digest compiled into this file (cross-checked against both
//! `downloads.rclone.org/<version>/SHA256SUMS` and the GitHub release
//! assets when the pin was set). Only the one `rclone` entry is extracted —
//! bounded in size and CRC-checked — and nothing else in the archive is
//! written or executed. The binary is activated with a same-directory
//! atomic rename and must then answer `rclone version`; otherwise it is
//! removed again.
//!
//! An rclone already present at any well-known path is left untouched
//! (`installed: false`), exactly like the previous `command -v rclone`
//! guard: this operation never upgrades or replaces an operator's rclone.

use crate::{
    engine::fetch,
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination},
    site::SiteRelativePath,
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        commit::PreCommit,
        state::{self, TransactionStatus},
    },
};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const OPERATION: &str = "backup.installRclone";
pub const BIN_DIR: &str = "/usr/bin";
/// Paths where an existing rclone means "already installed".
pub const EXISTING_PATHS: &[&str] = &[
    "/usr/bin/rclone",
    "/usr/local/bin/rclone",
    "/bin/rclone",
    "/snap/bin/rclone",
];
pub const RCLONE_VERSION: &str = "v1.75.1";
/// The release zips are ~30 MiB; the extracted binary is ~85 MiB.
pub const MAX_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_BINARY_BYTES: u64 = 256 * 1024 * 1024;
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const BINARY_NAME: &str = "rclone";

/// One pinned release asset.
#[derive(Clone, Debug)]
pub struct Artifact {
    pub version: String,
    pub url: String,
    pub sha256: String,
    /// The zip entry holding the binary, e.g.
    /// `rclone-v1.75.1-linux-amd64/rclone`.
    pub entry: String,
}

/// The pinned artifact for the architecture this engine binary was built
/// for (and therefore runs on), or `None` where rclone is not pinned.
pub fn pinned_artifact() -> Option<Artifact> {
    let (arch, sha256) = if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        (
            "amd64",
            "982b5aa772841168f8e380f139e9e787b2a105403e32b94da8676a0e1c0a13ab",
        )
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        (
            "arm64",
            "03f2504174034b6d004152ed7369251c9a9ec1f7e0836eda420f5c7a5ec0dff9",
        )
    } else {
        return None;
    };
    let stem = format!("rclone-{RCLONE_VERSION}-linux-{arch}");
    Some(Artifact {
        version: RCLONE_VERSION.to_owned(),
        url: format!("https://downloads.rclone.org/{RCLONE_VERSION}/{stem}.zip"),
        sha256: sha256.to_owned(),
        entry: format!("{stem}/{BINARY_NAME}"),
    })
}

pub struct Request {
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug)]
pub enum RequestError {
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl Request {
    pub fn parse(request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        Ok(Self {
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallResult {
    /// `false` when an rclone was already present and left untouched.
    pub installed: bool,
    pub path: String,
    /// The pinned version, when this request installed it.
    pub version: Option<String>,
    pub completed_at_unix_secs: u64,
}

pub type Fetcher<'a> = &'a dyn Fn(&str) -> Result<Vec<u8>, fetch::Error>;

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    /// Opened on [`BIN_DIR`]; only its `rclone` entry is written.
    pub bin_dir: &'a ManagedRoot,
    /// Absolute path of `bin_dir`, used to run the installed binary.
    pub bin_dir_path: &'a Path,
    pub existing_paths: &'a [&'a Path],
    pub artifact: &'a Artifact,
    pub fetch: Fetcher<'a>,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Cancelled,
    Fetch(fetch::Error),
    DigestMismatch,
    Archive(&'static str),
    Write(io::Error),
    /// The installed binary did not answer `rclone version`; it was removed.
    NotRunnable,
    /// The binary did not run and could not be removed again.
    RollbackFailed,
    PostCommit {
        result: InstallResult,
    },
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another rclone installation is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before rclone was installed".into(),
            ),
            Self::Fetch(fetch::Error::Timeout) => (
                ErrorCode::Timeout,
                "timed out downloading the rclone release".into(),
            ),
            Self::Fetch(_) => (
                ErrorCode::ArtifactFetchFailed,
                "could not download the rclone release".into(),
            ),
            Self::DigestMismatch => (
                ErrorCode::ArtifactVerificationFailed,
                "the downloaded rclone release does not match its pinned SHA-256".into(),
            ),
            Self::Archive(reason) => (
                ErrorCode::ArtifactVerificationFailed,
                format!("the rclone release archive is invalid: {reason}"),
            ),
            Self::Write(_) => (
                ErrorCode::Internal,
                "could not install the rclone binary".into(),
            ),
            Self::NotRunnable => (
                ErrorCode::ArtifactNotRunnable,
                "the installed rclone binary did not run on this host and was removed".into(),
            ),
            Self::RollbackFailed => (
                ErrorCode::Internal,
                "the installed rclone binary did not run on this host and could not be removed"
                    .into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit { .. } => (
                ErrorCode::Internal,
                "internal rclone installation error".into(),
            ),
        }
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 15) as usize] as char);
    }
    out
}

// ── zip ──────────────────────────────────────────────────────────────────────
//
// A deliberately minimal reader: the archive is already SHA-256-pinned, so
// this only has to locate one entry through the central directory, with
// every offset bounds-checked, and inflate it with a size cap and CRC check.
// Zip64, encryption and multi-disk archives are rejected.

const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
const LOCAL_SIGNATURE: u32 = 0x0403_4b50;
const EOCD_LEN: usize = 22;
const MAX_COMMENT_LEN: usize = 0xFFFF;

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

pub fn extract_entry(archive: &[u8], name: &str, max_bytes: u64) -> Result<Vec<u8>, Error> {
    let bad = Error::Archive;
    let search_from = archive.len().saturating_sub(EOCD_LEN + MAX_COMMENT_LEN);
    let eocd = (search_from..=archive.len().saturating_sub(EOCD_LEN))
        .rev()
        .find(|&at| u32_at(archive, at) == Some(EOCD_SIGNATURE))
        .ok_or(bad("no end-of-central-directory record"))?;
    if u16_at(archive, eocd + 4) != Some(0) || u16_at(archive, eocd + 6) != Some(0) {
        return Err(bad("multi-disk archives are not supported"));
    }
    let entries = u16_at(archive, eocd + 10).ok_or(bad("truncated directory"))?;
    let directory_offset = u32_at(archive, eocd + 16).ok_or(bad("truncated directory"))?;
    if directory_offset == u32::MAX {
        return Err(bad("zip64 archives are not supported"));
    }

    let mut at = directory_offset as usize;
    for _ in 0..entries {
        if u32_at(archive, at) != Some(CENTRAL_SIGNATURE) {
            return Err(bad("corrupt central directory"));
        }
        let field = |offset: usize| u16_at(archive, at + offset).ok_or(bad("truncated entry"));
        let flags = field(8)?;
        let method = field(10)?;
        let name_len = field(28)? as usize;
        let extra_len = field(30)? as usize;
        let comment_len = field(32)? as usize;
        let crc = u32_at(archive, at + 16).ok_or(bad("truncated entry"))?;
        let compressed = u32_at(archive, at + 20).ok_or(bad("truncated entry"))?;
        let size = u32_at(archive, at + 24).ok_or(bad("truncated entry"))?;
        let local = u32_at(archive, at + 42).ok_or(bad("truncated entry"))? as usize;
        let entry_name = archive
            .get(at + 46..at + 46 + name_len)
            .ok_or(bad("truncated entry"))?;
        at += 46 + name_len + extra_len + comment_len;
        if entry_name != name.as_bytes() {
            continue;
        }

        if flags & 0x1 != 0 {
            return Err(bad("encrypted entries are not supported"));
        }
        if compressed == u32::MAX || size == u32::MAX || local == u32::MAX as usize {
            return Err(bad("zip64 entries are not supported"));
        }
        if u64::from(size) > max_bytes {
            return Err(bad("the binary exceeds the size limit"));
        }
        if u32_at(archive, local) != Some(LOCAL_SIGNATURE) {
            return Err(bad("corrupt local header"));
        }
        let local_name = u16_at(archive, local + 26).ok_or(bad("truncated local header"))?;
        let local_extra = u16_at(archive, local + 28).ok_or(bad("truncated local header"))?;
        let start = local + 30 + local_name as usize + local_extra as usize;
        let data = archive
            .get(start..start + compressed as usize)
            .ok_or(bad("entry data is out of bounds"))?;

        let contents = match method {
            0 => data.to_vec(),
            8 => {
                let mut out = Vec::with_capacity(size as usize);
                flate2::read::DeflateDecoder::new(data)
                    .take(u64::from(size) + 1)
                    .read_to_end(&mut out)
                    .map_err(|_| bad("the binary could not be inflated"))?;
                out
            }
            _ => return Err(bad("unsupported compression method")),
        };
        if contents.len() != size as usize {
            return Err(bad("the binary has the wrong size"));
        }
        let mut checksum = flate2::Crc::new();
        checksum.update(&contents);
        if checksum.sum() != crc {
            return Err(bad("the binary fails its CRC-32 check"));
        }
        return Ok(contents);
    }
    Err(bad("the archive does not contain the rclone binary"))
}

// ── install ──────────────────────────────────────────────────────────────────

fn existing(ctx: &Context<'_>) -> Option<String> {
    ctx.existing_paths
        .iter()
        .find(|path| path.exists())
        .map(|path| path.to_string_lossy().into_owned())
}

fn runs(binary: &Path) -> bool {
    process::run(
        &ProcessRequest::new(binary).args(["version"]),
        &ProcessLimits {
            timeout: Duration::from_secs(30),
            max_stdout_bytes: 64 * 1024,
            max_stderr_bytes: 64 * 1024,
        },
        &CancellationToken::default(),
    )
    .is_ok_and(|output| {
        matches!(
            output.termination,
            ProcessTermination::Exited { success: true, .. }
        )
    })
}

fn install(ctx: &Context<'_>, pre_commit: PreCommit) -> Result<InstallResult, Error> {
    if let Some(path) = existing(ctx) {
        return Ok(result(false, path, None));
    }
    let archive = (ctx.fetch)(&ctx.artifact.url).map_err(Error::Fetch)?;
    if hex_digest(&Sha256::digest(&archive)) != ctx.artifact.sha256 {
        return Err(Error::DigestMismatch);
    }
    let binary = extract_entry(&archive, &ctx.artifact.entry, MAX_BINARY_BYTES)?;
    drop(archive);

    pre_commit.check().map_err(|_| Error::Cancelled)?;
    let _post_commit = pre_commit.commit();

    let target = SiteRelativePath::parse(BINARY_NAME).unwrap();
    ctx.bin_dir
        .write_new_executable(&target, &binary)
        .map_err(Error::Write)?;
    let installed = ctx.bin_dir_path.join(BINARY_NAME);
    if !runs(&installed) {
        return Err(match ctx.bin_dir.remove_file(&target) {
            Ok(()) => Error::NotRunnable,
            Err(_) => Error::RollbackFailed,
        });
    }
    Ok(result(
        true,
        installed.to_string_lossy().into_owned(),
        Some(ctx.artifact.version.clone()),
    ))
}

fn result(installed: bool, path: String, version: Option<String>) -> InstallResult {
    InstallResult {
        installed,
        path,
        version,
        completed_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    }
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<InstallResult, Error> {
    let scope_path = SiteRelativePath::parse("backup-rclone").unwrap();
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

    let result = match install(ctx, PreCommit::new(cancel.clone())) {
        Ok(value) => value,
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

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<InstallResult, Error> {
    let path = SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap();
    let loaded = state::load(scope, &path)
        .map_err(|error| Error::Io(io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != OPERATION {
        return Err(Error::Io(io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => {
            serde_json::from_value(loaded.outcome.unwrap().result.unwrap())
                .map_err(|error| Error::Io(io::Error::other(error)))
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
    use std::{cell::Cell, fs, io::Write, os::unix::fs::PermissionsExt, path::PathBuf};

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const ID_2: &str = "123e4567-e89b-12d3-a456-426614174001";
    const ENTRY: &str = "rclone-v0.0.0-linux-test/rclone";

    fn managed(directory: &Path) -> ManagedRoot {
        ManagedRoot::open(&crate::site::TrustedRoot::parse(directory).unwrap()).unwrap()
    }

    /// Builds a zip with the given `(name, contents, deflate)` entries —
    /// the same local-header/central-directory layout rclone's release
    /// archives use.
    fn zip(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, contents, deflate) in entries {
            let data = if *deflate {
                let mut encoder =
                    flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(contents).unwrap();
                encoder.finish().unwrap()
            } else {
                contents.to_vec()
            };
            let mut crc = flate2::Crc::new();
            crc.update(contents);
            let method: u16 = if *deflate { 8 } else { 0 };
            let offset = out.len() as u32;
            let common = |buf: &mut Vec<u8>| {
                buf.extend_from_slice(&0u16.to_le_bytes()); // flags
                buf.extend_from_slice(&method.to_le_bytes());
                buf.extend_from_slice(&[0; 4]); // time/date
                buf.extend_from_slice(&crc.sum().to_le_bytes());
                buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
                buf.extend_from_slice(&(contents.len() as u32).to_le_bytes());
                buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
                buf.extend_from_slice(&0u16.to_le_bytes()); // extra
            };
            out.extend_from_slice(&LOCAL_SIGNATURE.to_le_bytes());
            out.extend_from_slice(&20u16.to_le_bytes());
            common(&mut out);
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&data);

            central.extend_from_slice(&CENTRAL_SIGNATURE.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes()); // made by
            central.extend_from_slice(&20u16.to_le_bytes()); // needed
            common(&mut central);
            central.extend_from_slice(&[0; 6]); // comment len, disk, internal attrs
            central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let directory_offset = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(&EOCD_SIGNATURE.to_le_bytes());
        out.extend_from_slice(&[0; 4]); // disk numbers
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&directory_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    fn release(binary_script: &str) -> Vec<u8> {
        zip(&[
            ("rclone-v0.0.0-linux-test/README.txt", b"readme", true),
            (ENTRY, binary_script.as_bytes(), true),
        ])
    }

    struct Host {
        dir: tempfile::TempDir,
    }

    impl Host {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            for sub in ["state", "bin", "other"] {
                fs::create_dir(dir.path().join(sub)).unwrap();
            }
            Self { dir }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.dir.path().join(name)
        }

        fn run(
            &self,
            archive: &[u8],
            sha256: Option<&str>,
            id: &str,
            key: Option<&str>,
            fetches: &Cell<u32>,
        ) -> Result<InstallResult, Error> {
            let state = managed(&self.path("state"));
            let bin = managed(&self.path("bin"));
            let bin_path = self.path("bin");
            let existing_bin = self.path("bin/rclone");
            let existing_other = self.path("other/rclone");
            let existing = [existing_bin.as_path(), existing_other.as_path()];
            let artifact = Artifact {
                version: "v0.0.0".into(),
                url: "https://downloads.example.test/rclone.zip".into(),
                sha256: sha256
                    .map(str::to_owned)
                    .unwrap_or_else(|| hex_digest(&Sha256::digest(archive))),
                entry: ENTRY.into(),
            };
            let fetch = |_: &str| {
                fetches.set(fetches.get() + 1);
                Ok(archive.to_vec())
            };
            let ctx = Context {
                engine_state: &state,
                bin_dir: &bin,
                bin_dir_path: &bin_path,
                existing_paths: &existing,
                artifact: &artifact,
                fetch: &fetch,
            };
            execute(
                &ctx,
                &Request::parse(id, key).unwrap(),
                &CancellationToken::default(),
            )
        }
    }

    #[test]
    fn the_pinned_artifact_is_well_formed_where_one_exists() {
        if let Some(artifact) = pinned_artifact() {
            assert_eq!(artifact.sha256.len(), 64);
            assert!(artifact.sha256.bytes().all(|c| c.is_ascii_hexdigit()));
            let stem = artifact.entry.strip_suffix("/rclone").unwrap();
            assert_eq!(
                artifact.url,
                format!("https://downloads.rclone.org/{RCLONE_VERSION}/{stem}.zip")
            );
        }
    }

    #[test]
    fn installs_the_verified_binary_executable_then_replays() {
        let host = Host::new();
        let archive = release("#!/bin/sh\necho 'rclone v0.0.0'\n");
        let fetches = Cell::new(0);

        let first = host
            .run(&archive, None, ID, Some("rclone-key"), &fetches)
            .unwrap();
        let second = host
            .run(&archive, None, ID_2, Some("rclone-key"), &fetches)
            .unwrap();

        assert!(first.installed);
        assert_eq!(first.version.as_deref(), Some("v0.0.0"));
        assert_eq!(first.completed_at_unix_secs, second.completed_at_unix_secs);
        assert_eq!(fetches.get(), 1);
        let installed = host.path("bin/rclone");
        assert_eq!(
            fs::read_to_string(&installed).unwrap(),
            "#!/bin/sh\necho 'rclone v0.0.0'\n"
        );
        assert_eq!(
            fs::metadata(&installed).unwrap().permissions().mode() & 0o777,
            0o755
        );
        // README.txt and the rest of the archive are never written.
        assert_eq!(fs::read_dir(host.path("bin")).unwrap().count(), 1);
    }

    #[test]
    fn an_existing_rclone_is_left_untouched_without_downloading() {
        let host = Host::new();
        fs::write(host.path("other/rclone"), "operator's rclone").unwrap();
        let fetches = Cell::new(0);

        let result = host
            .run(&release("#!/bin/sh\n"), None, ID, None, &fetches)
            .unwrap();

        assert!(!result.installed);
        assert_eq!(result.path, host.path("other/rclone").to_string_lossy());
        assert_eq!(fetches.get(), 0);
        assert!(!host.path("bin/rclone").exists());
    }

    #[test]
    fn a_digest_mismatch_installs_nothing() {
        let host = Host::new();
        let error = host
            .run(
                &release("#!/bin/sh\n"),
                Some(&"0".repeat(64)),
                ID,
                None,
                &Cell::new(0),
            )
            .unwrap_err();

        assert!(matches!(error, Error::DigestMismatch));
        assert_eq!(error.protocol().0, ErrorCode::ArtifactVerificationFailed);
        assert!(!host.path("bin/rclone").exists());
    }

    #[test]
    fn a_binary_that_does_not_run_is_removed_again() {
        let host = Host::new();
        let error = host
            .run(
                &release("#!/bin/sh\nexit 3\n"),
                None,
                ID,
                None,
                &Cell::new(0),
            )
            .unwrap_err();

        assert!(matches!(error, Error::NotRunnable));
        assert_eq!(error.protocol().0, ErrorCode::ArtifactNotRunnable);
        assert!(!host.path("bin/rclone").exists());
    }

    #[test]
    fn a_failed_request_replays_its_recorded_error() {
        let host = Host::new();
        let archive = release("#!/bin/sh\n");
        let fetches = Cell::new(0);
        let wrong = "0".repeat(64);
        host.run(&archive, Some(&wrong), ID, Some("k"), &fetches)
            .unwrap_err();
        let second = host
            .run(&archive, Some(&wrong), ID_2, Some("k"), &fetches)
            .unwrap_err();

        assert!(matches!(
            second,
            Error::Replayed {
                code: ErrorCode::ArtifactVerificationFailed,
                ..
            }
        ));
        assert_eq!(fetches.get(), 1);
    }

    #[test]
    fn extracts_stored_and_deflated_entries() {
        let archive = zip(&[("a", b"stored", false), ("b/rclone", b"deflated!", true)]);
        assert_eq!(extract_entry(&archive, "a", 1024).unwrap(), b"stored");
        assert_eq!(
            extract_entry(&archive, "b/rclone", 1024).unwrap(),
            b"deflated!"
        );
    }

    #[test]
    fn rejects_missing_oversized_corrupt_and_truncated_entries() {
        let archive = zip(&[(ENTRY, b"binary contents", true)]);
        assert!(matches!(
            extract_entry(&archive, "other", 1024),
            Err(Error::Archive(_))
        ));
        assert!(matches!(
            extract_entry(&archive, ENTRY, 4),
            Err(Error::Archive("the binary exceeds the size limit"))
        ));

        // Flip one byte of the stored CRC in the central directory.
        let mut corrupt = zip(&[(ENTRY, b"binary contents", false)]);
        let central = corrupt
            .windows(4)
            .position(|window| window == CENTRAL_SIGNATURE.to_le_bytes())
            .unwrap();
        corrupt[central + 16] ^= 0xFF;
        assert!(matches!(
            extract_entry(&corrupt, ENTRY, 1024),
            Err(Error::Archive("the binary fails its CRC-32 check"))
        ));

        for len in [0, 10, archive.len() / 2, archive.len() - 1] {
            assert!(extract_entry(&archive[..len], ENTRY, 1024).is_err());
        }
    }
}
