//! Bounded WXR import. The panel stages a root-owned artifact; the engine
//! verifies its size and digest, then runs only fixed Docker/WP-CLI argv.
//! Import changes WordPress data and has no automatic rollback.

use crate::{
    db_restore::ContainerName,
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{
        self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination,
        SubprocessDiagnostics,
    },
    site::SiteRelativePath,
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        resource_lock,
        state::{self, TransactionStatus},
    },
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};
#[cfg(unix)]
use std::{
    fs::OpenOptions,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
};

pub const OPERATION: &str = "wordpress.import";
pub const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;

fn hex_digest(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut hex, "{byte:02x}").unwrap();
    }
    hex
}

#[derive(Debug)]
pub enum RequestError {
    Invalid,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    container: String,
    root: String,
    uid: u32,
    gid: u32,
    sha256: String,
    byte_length: u64,
}

#[derive(Debug)]
pub struct Request {
    container: ContainerName,
    root: PathBuf,
    uid: u32,
    gid: u32,
    sha256: String,
    byte_length: u64,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl Request {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError::Invalid)?;
        let root = PathBuf::from(plan.root);
        if !root.is_absolute()
            || root.as_os_str().len() > 4096
            || root
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(RequestError::Invalid);
        }
        if plan.byte_length == 0
            || plan.byte_length > MAX_ARTIFACT_BYTES
            || plan.sha256.len() != 64
            || !plan.sha256.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(RequestError::Invalid);
        }
        Ok(Self {
            container: ContainerName::parse(&plan.container).map_err(|_| RequestError::Invalid)?,
            root,
            uid: plan.uid,
            gid: plan.gid,
            sha256: plan.sha256.to_ascii_lowercase(),
            byte_length: plan.byte_length,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::Invalid)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::Invalid)?,
        })
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    pub output: String,
    pub output_truncated: bool,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub artifact_dir: &'a Path,
    pub artifact_owner_uid: u32,
    pub docker_program: &'a str,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ResourceBusy,
    ReplayInProgress,
    InvalidArtifact,
    Run(process::ProcessRunError),
    Rejected(SubprocessDiagnostics),
    PostCommit { result: ImportResult },
    Replayed { code: ErrorCode, message: String },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) | Self::ResourceBusy => (
                ErrorCode::Conflict,
                "another WordPress operation is in progress for this site".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original import is still in progress".into(),
            ),
            Self::InvalidArtifact => (
                ErrorCode::InvalidInput,
                "WXR artifact is missing, unsafe, too large, or does not match its SHA-256 digest"
                    .into(),
            ),
            Self::Run(e) => (
                process::spawn_error_code(e),
                "could not run the WordPress import step".into(),
            ),
            Self::Rejected(d) => (
                if d.timed_out {
                    ErrorCode::Timeout
                } else if d.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::SubprocessFailed
                },
                "WordPress import step failed".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit { .. } => (
                ErrorCode::Internal,
                "internal WordPress import error".into(),
            ),
        }
    }
}

fn artifact_path(ctx: &Context<'_>, req: &Request) -> PathBuf {
    ctx.artifact_dir
        .join(format!("{}.import.xml", req.request_id))
}

fn verify_artifact(ctx: &Context<'_>, req: &Request) -> Result<PathBuf, Error> {
    let path = artifact_path(ctx, req);
    #[cfg(unix)]
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|_| Error::InvalidArtifact)?;
    #[cfg(not(unix))]
    let mut file = std::fs::File::open(&path).map_err(|_| Error::InvalidArtifact)?;
    let meta = file.metadata().map_err(|_| Error::InvalidArtifact)?;
    if !meta.is_file() || meta.len() != req.byte_length {
        return Err(Error::InvalidArtifact);
    }
    #[cfg(unix)]
    if meta.uid() != ctx.artifact_owner_uid || meta.nlink() != 1 || meta.mode() & 0o777 != 0o600 {
        return Err(Error::InvalidArtifact);
    }
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buf = [0_u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|_| Error::InvalidArtifact)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > MAX_ARTIFACT_BYTES {
            return Err(Error::InvalidArtifact);
        }
        digest.update(&buf[..n]);
    }
    let computed = hex_digest(&digest.finalize());
    if total != req.byte_length || computed != req.sha256 {
        return Err(Error::InvalidArtifact);
    }
    Ok(path)
}

fn run(
    ctx: &Context<'_>,
    args: Vec<String>,
    cancel: &CancellationToken,
) -> Result<process::ProcessOutput, Error> {
    let output = process::run(
        &ProcessRequest::new(ctx.docker_program).args(args),
        &ProcessLimits {
            timeout: Duration::from_secs(30 * 60),
            max_stdout_bytes: 64 * 1024,
            max_stderr_bytes: 64 * 1024,
        },
        cancel,
    )
    .map_err(Error::Run)?;
    if !matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        return Err(Error::Rejected(SubprocessDiagnostics::from_output(
            ctx.docker_program,
            &output,
        )));
    }
    Ok(output)
}

fn wp_args(req: &Request, tail: &[&str]) -> Vec<String> {
    let mut args = vec![
        "exec".into(),
        "-i".into(),
        "--user".into(),
        format!("{}:{}", req.uid, req.gid),
        req.container.as_str().into(),
        "wp".into(),
        format!("--path={}", req.root.display()),
        "--allow-root".into(),
    ];
    args.extend(tail.iter().map(|s| (*s).to_owned()));
    args
}

fn perform(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<ImportResult, Error> {
    let artifact = verify_artifact(ctx, req)?;
    let container_path = format!("/tmp/wp-import-{}.xml", req.request_id);
    let target = format!("{}:{container_path}", req.container.as_str());
    run(
        ctx,
        vec!["cp".into(), artifact.to_string_lossy().into_owned(), target],
        cancel,
    )?;
    let _ = fs::remove_file(&artifact);
    let result = (|| {
        run(
            ctx,
            vec![
                "exec".into(),
                req.container.as_str().into(),
                "chown".into(),
                format!("{}:{}", req.uid, req.gid),
                container_path.clone(),
            ],
            cancel,
        )?;
        // WP-CLI returns nonzero when the plugin is already installed. Activation is authoritative.
        let _ = run(
            ctx,
            wp_args(
                req,
                &["plugin", "install", "wordpress-importer", "--activate"],
            ),
            cancel,
        );
        run(
            ctx,
            wp_args(req, &["plugin", "activate", "wordpress-importer"]),
            cancel,
        )?;
        let output = run(
            ctx,
            wp_args(req, &["import", &container_path, "--authors=create"]),
            cancel,
        )?;
        let (bytes, truncated) = if output.stdout.bytes.is_empty() {
            (output.stderr.bytes, output.stderr.truncated)
        } else {
            (output.stdout.bytes, output.stdout.truncated)
        };
        Ok(ImportResult {
            output: String::from_utf8_lossy(&bytes).into_owned(),
            output_truncated: truncated,
        })
    })();
    let _ = run(
        ctx,
        vec![
            "exec".into(),
            req.container.as_str().into(),
            "rm".into(),
            "-f".into(),
            container_path,
        ],
        &CancellationToken::default(),
    );
    result
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<ImportResult, Error> {
    let hash = resource_lock::canonical_hash(&req.root);
    let scope_path = SiteRelativePath::parse(format!("wordpress-import/{hash}")).unwrap();
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
    let _resource_lock = resource_lock::acquire(ctx.engine_state, &req.root, req.request_id)
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
    let result = match perform(ctx, req, cancel) {
        Ok(v) => v,
        Err(e) => return Err(fail(&scope, &state_path, &audit_path, state, e)),
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

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<ImportResult, Error> {
    let path = SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap();
    let loaded = state::load(scope, &path)
        .map_err(|e| Error::Io(std::io::Error::other(format!("{e:?}"))))?;
    if loaded.operation != OPERATION {
        return Err(Error::Io(std::io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => {
            serde_json::from_value(loaded.outcome.unwrap().result.unwrap())
                .map_err(|e| Error::Io(std::io::Error::other(e)))
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

    fn fixture(import_fails: bool) -> (tempfile::TempDir, String, Request) {
        let dir = tempfile::tempdir().unwrap();
        let artifact = dir.path().join(format!("{ID}.import.xml"));
        fs::write(&artifact, b"<wxr></wxr>").unwrap();
        fs::set_permissions(&artifact, fs::Permissions::from_mode(0o600)).unwrap();
        let hash = hex_digest(&Sha256::digest(b"<wxr></wxr>"));
        let plan = serde_json::json!({
            "container":"site-php", "root":dir.path(), "uid":1000, "gid":1000,
            "sha256":hash, "byteLength":11,
        });
        let req = Request::parse(&plan.to_string(), ID, Some("import-once")).unwrap();
        let script = dir.path().join("fake-docker");
        let code = if import_fails {
            "case \" $* \" in *\" import \"*) exit 17;; esac"
        } else {
            ""
        };
        fs::write(
            &script,
            format!(
                "#!/bin/sh\necho \"$*\" >> '{}'\n{code}\necho Imported\n",
                dir.path().join("calls.log").display()
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        (dir, script.to_string_lossy().into_owned(), req)
    }

    fn managed(dir: &Path) -> ManagedRoot {
        ManagedRoot::open(&crate::site::TrustedRoot::parse(dir).unwrap()).unwrap()
    }

    #[test]
    fn imports_once_then_replays_without_needing_the_artifact() {
        let (dir, docker, req) = fixture(false);
        let state = managed(dir.path());
        let ctx = Context {
            engine_state: &state,
            artifact_dir: dir.path(),
            artifact_owner_uid: unsafe { libc::geteuid() },
            docker_program: &docker,
        };
        let first = execute(&ctx, &req, &CancellationToken::default()).unwrap();
        assert_eq!(first.output.trim(), "Imported");
        assert!(!dir.path().join(format!("{ID}.import.xml")).exists());
        let replayed = execute(&ctx, &req, &CancellationToken::default()).unwrap();
        assert_eq!(replayed.output, first.output);
        let calls = fs::read_to_string(dir.path().join("calls.log")).unwrap();
        assert_eq!(calls.lines().count(), 6);
        assert!(calls.contains("plugin activate wordpress-importer"));
        assert!(calls.contains("import /tmp/wp-import-"));
    }

    #[test]
    fn rejects_a_wrong_digest_before_running_docker_and_replays_failure() {
        let (dir, docker, mut req) = fixture(false);
        req.sha256 = "0".repeat(64);
        let state = managed(dir.path());
        let ctx = Context {
            engine_state: &state,
            artifact_dir: dir.path(),
            artifact_owner_uid: unsafe { libc::geteuid() },
            docker_program: &docker,
        };
        assert!(matches!(
            execute(&ctx, &req, &CancellationToken::default()),
            Err(Error::InvalidArtifact)
        ));
        assert!(matches!(
            execute(&ctx, &req, &CancellationToken::default()),
            Err(Error::Replayed { .. })
        ));
        assert!(!dir.path().join("calls.log").exists());
    }

    #[test]
    fn a_failed_wp_import_still_cleans_the_container_artifact() {
        let (dir, docker, req) = fixture(true);
        let state = managed(dir.path());
        let ctx = Context {
            engine_state: &state,
            artifact_dir: dir.path(),
            artifact_owner_uid: unsafe { libc::geteuid() },
            docker_program: &docker,
        };
        assert!(matches!(
            execute(&ctx, &req, &CancellationToken::default()),
            Err(Error::Rejected(_))
        ));
        let calls = fs::read_to_string(dir.path().join("calls.log")).unwrap();
        assert!(
            calls
                .lines()
                .last()
                .unwrap()
                .contains("rm -f /tmp/wp-import-")
        );
    }
}
