//! Download one remote backup artifact into the fixed imports directory and
//! verify its declared SHA-256 before publishing it. The caller verifies the
//! snapshot manifest and supplies the digest; this operation owns the mutation.

use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{self, CancellationToken, ProcessLimits, ProcessRequest},
    site::SiteRelativePath,
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        state::{self, TransactionStatus},
    },
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::Path, time::Duration};

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 15) as usize] as char);
    }
    out
}

pub const OPERATION: &str = "backup.importRemote";
pub const IMPORT_ROOT: &str = "/root/db-backups/imports";
pub const RCLONE_CONFIG: &str = "/root/.wcp/rclone.conf";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    remote_name: String,
    bucket: String,
    prefix: String,
    filename: String,
    sha256: String,
}

pub struct Request {
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
    remote_path: String,
    basename: String,
    digest: String,
}

impl Request {
    pub fn parse(json: &str, id: &str, key: Option<&str>) -> Result<Self, &'static str> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| "invalid request JSON")?;
        let remote = &plan.remote_name;
        let bucket = &plan.bucket;
        if remote.is_empty()
            || remote.len() > 64
            || !remote
                .bytes()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric())
            || !remote
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
            || bucket.is_empty()
            || bucket.len() > 63
            || !bucket
                .bytes()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric())
            || !bucket
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
        {
            return Err("invalid remote or bucket");
        }
        fn safe_path(path: &str, allow_empty: bool) -> bool {
            if allow_empty && path.is_empty() {
                return true;
            }
            (allow_empty || !path.is_empty())
                && !path.starts_with('/')
                && !path.ends_with('/')
                && path.len() <= 1024
                && path.split('/').all(|part| {
                    !part.is_empty()
                        && part != "."
                        && part != ".."
                        && !part.contains('\\')
                        && !part.chars().any(char::is_control)
                })
        }
        if !safe_path(&plan.prefix, true) || !safe_path(&plan.filename, false) {
            return Err("invalid remote path");
        }
        if plan.sha256.len() != 64 || !plan.sha256.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err("invalid SHA-256 digest");
        }
        let basename = plan
            .filename
            .rsplit('/')
            .next()
            .ok_or("invalid filename")?
            .to_owned();
        let path = if plan.prefix.is_empty() {
            format!("{remote}:{bucket}/{}", plan.filename)
        } else {
            format!("{remote}:{bucket}/{}/{}", plan.prefix, plan.filename)
        };
        Ok(Self {
            request_id: RequestId::parse(id).map_err(|_| "invalid request ID")?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| "invalid idempotency key")?,
            remote_path: path,
            basename,
            digest: plan.sha256.to_ascii_lowercase(),
        })
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    pub file_path: String,
    pub sha256: String,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub import_root: &'a Path,
    pub rclone_config: &'a Path,
    pub rclone_program: &'a str,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Run(process::ProcessRunError),
    Rejected(ErrorCode),
    DigestMismatch,
    Replayed { code: ErrorCode, message: String },
    PostCommit { result: ImportResult },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) | Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "remote import is already in progress".into(),
            ),
            Self::Run(error) => (
                process::spawn_error_code(error),
                "remote download could not start".into(),
            ),
            Self::Rejected(code) => (*code, "remote download failed".into()),
            Self::DigestMismatch => (
                ErrorCode::InvalidInput,
                "remote artifact SHA-256 did not match".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            _ => (
                ErrorCode::Internal,
                "remote import could not complete".into(),
            ),
        }
    }
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<ImportResult, Error> {
    let scope_path = SiteRelativePath::parse("backup-import-remote").unwrap();
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
    let result = download(ctx, req, cancel);
    let result = match result {
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

fn download(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<ImportResult, Error> {
    fs::create_dir_all(ctx.import_root).map_err(Error::Io)?;
    let destination = ctx
        .import_root
        .join(format!("{}_{}", req.request_id, req.basename));
    let partial = destination.with_extension(format!(
        "{}.partial",
        destination
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("file")
    ));
    // A request ID names one destination. Do not let a replay or a pre-existing
    // path overwrite an import, including through a symlink.
    if destination.symlink_metadata().is_ok() || partial.symlink_metadata().is_ok() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "import path exists",
        )));
    }
    let output = process::run(
        &ProcessRequest::new(ctx.rclone_program).args([
            "--config",
            ctx.rclone_config.to_str().unwrap_or(RCLONE_CONFIG),
            "copyto",
            &req.remote_path,
            partial
                .to_str()
                .ok_or_else(|| Error::Io(std::io::Error::other("invalid import path")))?,
        ]),
        &ProcessLimits {
            timeout: Duration::from_secs(6 * 60 * 60),
            max_stdout_bytes: 16 * 1024,
            max_stderr_bytes: 16 * 1024,
        },
        cancel,
    );
    let output = match output {
        Ok(value) => value,
        Err(error) => {
            let _ = fs::remove_file(&partial);
            return Err(Error::Run(error));
        }
    };
    if let Some(code) = process::error_code(&output.termination) {
        let _ = fs::remove_file(&partial);
        return Err(Error::Rejected(code));
    }
    let verified = (|| -> Result<String, Error> {
        let metadata = partial.symlink_metadata().map_err(Error::Io)?;
        if !metadata.file_type().is_file() {
            return Err(Error::Io(std::io::Error::other(
                "remote import is not a regular file",
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&partial, fs::Permissions::from_mode(0o600)).map_err(Error::Io)?;
        }
        let mut file = fs::File::open(&partial).map_err(Error::Io)?;
        let mut hasher = Sha256::new();
        let mut chunk = [0u8; 64 * 1024];
        loop {
            let count = file.read(&mut chunk).map_err(Error::Io)?;
            if count == 0 {
                break;
            }
            hasher.update(&chunk[..count]);
        }
        let actual = hex_digest(&hasher.finalize());
        if actual != req.digest {
            return Err(Error::DigestMismatch);
        }
        Ok(actual)
    })();
    let actual = match verified {
        Ok(value) => value,
        Err(error) => {
            let _ = fs::remove_file(&partial);
            return Err(error);
        }
    };
    fs::rename(&partial, &destination).map_err(|error| {
        let _ = fs::remove_file(&partial);
        Error::Io(error)
    })?;
    Ok(ImportResult {
        file_path: destination.to_string_lossy().into_owned(),
        sha256: actual,
    })
}

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<ImportResult, Error> {
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
    use std::os::unix::fs::PermissionsExt;
    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    fn fixture(
        script: &str,
    ) -> (
        tempfile::TempDir,
        ManagedRoot,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state");
        fs::create_dir(&state_path).unwrap();
        let state =
            ManagedRoot::open(&crate::site::TrustedRoot::parse(&state_path).unwrap()).unwrap();
        let imports = dir.path().join("imports");
        let rclone = dir.path().join("rclone.sh");
        fs::write(&rclone, script).unwrap();
        fs::set_permissions(&rclone, fs::Permissions::from_mode(0o700)).unwrap();
        (dir, state, imports, rclone)
    }

    fn request(hash: String) -> Request {
        Request::parse(&serde_json::json!({"remoteName":"remote","bucket":"bucket","prefix":"daily","filename":"dump.sql.gz","sha256":hash}).to_string(), ID, Some("same-key")).unwrap()
    }

    #[test]
    fn downloads_verified_artifact_once_then_replays() {
        let (dir, state, imports, rclone) = fixture("#!/bin/sh\nprintf 'hello' > \"$5\"\n");
        let context = Context {
            engine_state: &state,
            import_root: &imports,
            rclone_config: dir.path(),
            rclone_program: rclone.to_str().unwrap(),
        };
        let hash = hex_digest(&Sha256::digest(b"hello"));
        let req = request(hash);
        let first = execute(&context, &req, &CancellationToken::default()).unwrap();
        assert_eq!(fs::read(&first.file_path).unwrap(), b"hello");
        assert_eq!(
            fs::metadata(&first.file_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let second = execute(&context, &req, &CancellationToken::default()).unwrap();
        assert_eq!(first.file_path, second.file_path);
    }

    #[test]
    fn digest_mismatch_removes_partial_and_records_failure() {
        let (dir, state, imports, rclone) = fixture("#!/bin/sh\nprintf 'wrong' > \"$5\"\n");
        let context = Context {
            engine_state: &state,
            import_root: &imports,
            rclone_config: dir.path(),
            rclone_program: rclone.to_str().unwrap(),
        };
        let error = execute(
            &context,
            &request("a".repeat(64)),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::DigestMismatch));
        assert_eq!(fs::read_dir(imports).unwrap().count(), 0);
    }

    #[test]
    fn rejects_traversal_before_running() {
        let json = serde_json::json!({"remoteName":"remote","bucket":"bucket","prefix":"daily","filename":"../secret.sql","sha256":"a".repeat(64)}).to_string();
        assert!(Request::parse(&json, ID, None).is_err());
        let empty_prefix = serde_json::json!({"remoteName":"remote","bucket":"bucket","prefix":"","filename":"dump.sql.gz","sha256":"a".repeat(64)}).to_string();
        assert!(Request::parse(&empty_prefix, ID, None).is_ok());
    }
}
