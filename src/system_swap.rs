//! Host swap-file lifecycle (`system.createSwap`, `system.deleteSwap`,
//! `system.resizeSwap`) under one host-wide `system-swap` lock/idempotency/
//! transaction/audit scope. Replaces the panel's raw
//! `fallocate && mkswap && swapon && echo >> /etc/fstab` shell chains, in
//! particular its resize, which was two independent SSH calls (delete, then
//! create) that could leave the host with no swap and a dangling fstab
//! entry if the second call failed or the connection dropped between them.
//!
//! The engine owns exactly one path, [`SWAP_PATH`], and the fstab entry for
//! it. There is no caller-supplied path or command; the only input is a
//! bounded size. Every external tool runs as a fixed argv without a shell.
//! Each operation compensates what it already changed when a later step
//! fails, and reports `RollbackFailed` — never a silent partial state — when
//! that compensation itself fails.

use crate::{
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
        commit::PreCommit,
        state::{self, TransactionStatus},
    },
};
use std::{
    fs, io,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const CREATE_OPERATION: &str = "system.createSwap";
pub const DELETE_OPERATION: &str = "system.deleteSwap";
pub const RESIZE_OPERATION: &str = "system.resizeSwap";
pub const SWAP_PATH: &str = "/swapfile";
pub const ETC_DIR: &str = "/etc";
pub const PROC_SWAPS: &str = "/proc/swaps";
pub const MIN_SIZE_MB: u32 = 256;
pub const MAX_SIZE_MB: u32 = 32 * 1024;
const FSTAB_FILE: &str = "fstab";
const DEFAULT_FSTAB_MODE: u32 = 0o644;
const MIB: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Create { size_mb: u32 },
    Delete,
    Resize { size_mb: u32 },
}

impl Action {
    pub const fn operation(self) -> &'static str {
        match self {
            Self::Create { .. } => CREATE_OPERATION,
            Self::Delete => DELETE_OPERATION,
            Self::Resize { .. } => RESIZE_OPERATION,
        }
    }
}

pub struct Request {
    pub action: Action,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidSize,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl Request {
    pub fn parse(
        action: Action,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        if let Action::Create { size_mb } | Action::Resize { size_mb } = action {
            if !(MIN_SIZE_MB..=MAX_SIZE_MB).contains(&size_mb) {
                return Err(RequestError::InvalidSize);
            }
        }
        Ok(Self {
            action,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    Allocate,
    Format,
    Enable,
    Disable,
    Persist,
    Remove,
}

impl Stage {
    fn message(self) -> &'static str {
        match self {
            Self::Allocate => "could not allocate the swap file",
            Self::Format => "could not format the swap file",
            Self::Enable => "could not enable the swap file",
            Self::Disable => "could not disable the active swap file",
            Self::Persist => "could not update /etc/fstab",
            Self::Remove => "could not remove the swap file",
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SwapResult {
    /// The managed swap file's size after the operation; `None` once it
    /// has been deleted.
    pub size_mb: Option<u32>,
    /// `false` when the host was already in the requested state.
    pub changed: bool,
    pub completed_at_unix_secs: u64,
}

pub struct Tools<'a> {
    pub fallocate: &'a str,
    pub mkswap: &'a str,
    pub swapon: &'a str,
    pub swapoff: &'a str,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    /// Opened on [`ETC_DIR`]; only its `fstab` entry is read or replaced.
    pub etc_dir: &'a ManagedRoot,
    pub swap_path: &'a str,
    pub proc_swaps: &'a Path,
    pub tools: Tools<'a>,
    /// Bytes available to an unprivileged-reserve-respecting writer on the
    /// filesystem holding `swap_path` (production: `statvfs`).
    pub available_bytes: fn(&Path) -> io::Result<u64>,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Cancelled,
    /// `create` found something already at the swap path. Nothing changed.
    AlreadyExists,
    /// The swap path is a symlink, directory or other non-regular file.
    /// Nothing changed.
    UnsafeSwapPath,
    /// The filesystem cannot hold the requested size. Nothing changed.
    InsufficientSpace,
    Run(Stage, process::ProcessRunError),
    Rejected(Stage, SubprocessDiagnostics),
    Filesystem(Stage, io::Error),
    /// A step failed and restoring the previous swap state also failed.
    /// The host may have no swap, an inactive leftover file, or an fstab
    /// entry that disagrees with the file; only an operator (or a follow-up
    /// request after inspection) resolves that, never an automatic retry.
    RollbackFailed(Stage),
    PostCommit {
        result: SwapResult,
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
                "another swap operation is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before the swap configuration was changed".into(),
            ),
            Self::AlreadyExists => (
                ErrorCode::Conflict,
                format!("{SWAP_PATH} already exists; resize or delete it instead"),
            ),
            Self::UnsafeSwapPath => (
                ErrorCode::Conflict,
                format!("{SWAP_PATH} is not a regular file; refusing to manage it"),
            ),
            Self::InsufficientSpace => (
                ErrorCode::InvalidInput,
                "not enough free disk space for the requested swap size".into(),
            ),
            Self::Run(stage, error) => (process::spawn_error_code(error), stage.message().into()),
            Self::Rejected(stage, diagnostics) => (
                if diagnostics.timed_out {
                    ErrorCode::Timeout
                } else if diagnostics.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::SubprocessFailed
                },
                stage.message().into(),
            ),
            Self::Filesystem(stage, _) => (ErrorCode::Internal, stage.message().into()),
            Self::RollbackFailed(stage) => (
                ErrorCode::Internal,
                format!(
                    "{}, and restoring the previous swap state also failed; check `swapon \
                     --show` and /etc/fstab before retrying",
                    stage.message()
                ),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit { .. } => {
                (ErrorCode::Internal, "internal swap operation error".into())
            }
        }
    }
}

// ── host inspection ──────────────────────────────────────────────────────────

enum SwapFile {
    Absent,
    Present { len: u64, allocated: u64 },
}

fn inspect(ctx: &Context<'_>) -> Result<SwapFile, Error> {
    match fs::symlink_metadata(ctx.swap_path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(SwapFile::Absent),
        Err(error) => Err(Error::Io(error)),
        Ok(meta) if !meta.file_type().is_file() => Err(Error::UnsafeSwapPath),
        Ok(meta) => Ok(SwapFile::Present {
            len: meta.len(),
            allocated: meta.blocks() * 512,
        }),
    }
}

fn is_active(ctx: &Context<'_>) -> Result<bool, Error> {
    let swaps = fs::read_to_string(ctx.proc_swaps).map_err(Error::Io)?;
    Ok(swaps
        .lines()
        .skip(1)
        .any(|line| line.split_whitespace().next() == Some(ctx.swap_path)))
}

fn swap_parent<'a>(ctx: &Context<'a>) -> &'a Path {
    Path::new(ctx.swap_path)
        .parent()
        .unwrap_or_else(|| Path::new("/"))
}

// ── fstab ────────────────────────────────────────────────────────────────────

struct Fstab {
    original: String,
    mode: u32,
}

fn fstab_path() -> SiteRelativePath {
    SiteRelativePath::parse(FSTAB_FILE).unwrap()
}

fn is_swap_entry(line: &str, swap_path: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') {
        return false;
    }
    let mut fields = trimmed.split_whitespace();
    fields.next() == Some(swap_path) && fields.nth(1) == Some("swap")
}

fn read_fstab(ctx: &Context<'_>) -> Result<Fstab, Error> {
    let path = fstab_path();
    match ctx.etc_dir.read_to_string(&path) {
        Ok(original) => Ok(Fstab {
            original,
            mode: ctx.etc_dir.mode(&path).map_err(Error::Io)?,
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Fstab {
            original: String::new(),
            mode: DEFAULT_FSTAB_MODE,
        }),
        Err(error) => Err(Error::Io(error)),
    }
}

/// `None` when the entry is already present.
fn with_entry(fstab: &str, swap_path: &str) -> Option<String> {
    if fstab.lines().any(|line| is_swap_entry(line, swap_path)) {
        return None;
    }
    let mut updated = fstab.to_owned();
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(&format!("{swap_path} none swap sw 0 0\n"));
    Some(updated)
}

/// `None` when there is no entry to remove.
fn without_entry(fstab: &str, swap_path: &str) -> Option<String> {
    let kept: String = fstab
        .split_inclusive('\n')
        .filter(|line| !is_swap_entry(line, swap_path))
        .collect();
    (kept.len() != fstab.len()).then_some(kept)
}

fn write_fstab(ctx: &Context<'_>, contents: &str, mode: u32) -> io::Result<()> {
    let path = fstab_path();
    ctx.etc_dir.write_atomic(&path, contents.as_bytes())?;
    ctx.etc_dir.set_mode(&path, mode)
}

// ── swap file primitives ─────────────────────────────────────────────────────

fn run_tool(
    program: &str,
    args: &[&str],
    stage: Stage,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    // `swapoff` has to page everything back in (or into another swap area),
    // which on a loaded host legitimately takes minutes.
    let timeout = match stage {
        Stage::Disable => Duration::from_secs(10 * 60),
        _ => Duration::from_secs(2 * 60),
    };
    let output = process::run(
        &ProcessRequest::new(program).args(args),
        &ProcessLimits {
            timeout,
            max_stdout_bytes: 64 * 1024,
            max_stderr_bytes: 64 * 1024,
        },
        cancel,
    )
    .map_err(|error| Error::Run(stage, error))?;
    if !matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        return Err(Error::Rejected(
            stage,
            SubprocessDiagnostics::from_output(program, &output),
        ));
    }
    Ok(())
}

fn swapon(ctx: &Context<'_>) -> Result<(), Error> {
    run_tool(
        ctx.tools.swapon,
        &[ctx.swap_path],
        Stage::Enable,
        &CancellationToken::default(),
    )
}

fn swapoff(ctx: &Context<'_>) -> Result<(), Error> {
    run_tool(
        ctx.tools.swapoff,
        &[ctx.swap_path],
        Stage::Disable,
        &CancellationToken::default(),
    )
}

fn remove_swap_file(ctx: &Context<'_>) -> io::Result<()> {
    match fs::remove_file(ctx.swap_path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// Creates, formats and (when `enable`) activates a new swap file of
/// `bytes`. The file is created `O_EXCL` with mode `0600`, so it never
/// adopts a pre-existing file or symlink and is never briefly readable by
/// other users. Any failure removes the partial file again; if even that
/// fails the error becomes `RollbackFailed`.
fn build_swap(ctx: &Context<'_>, bytes: u64, enable: bool) -> Result<(), Error> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(ctx.swap_path)
        .map_err(|error| Error::Filesystem(Stage::Allocate, error))?;
    let size = bytes.to_string();
    let cancel = CancellationToken::default();
    let mut steps = vec![
        (
            ctx.tools.fallocate,
            vec!["-l", size.as_str(), ctx.swap_path],
            Stage::Allocate,
        ),
        (ctx.tools.mkswap, vec![ctx.swap_path], Stage::Format),
    ];
    if enable {
        steps.push((ctx.tools.swapon, vec![ctx.swap_path], Stage::Enable));
    }
    for (program, args, stage) in steps {
        if let Err(error) = run_tool(program, &args, stage, &cancel) {
            return Err(match remove_swap_file(ctx) {
                Ok(()) => error,
                Err(_) => Error::RollbackFailed(stage),
            });
        }
    }
    Ok(())
}

// ── operations ───────────────────────────────────────────────────────────────

fn create(ctx: &Context<'_>, size_mb: u32, pre_commit: PreCommit) -> Result<SwapResult, Error> {
    if !matches!(inspect(ctx)?, SwapFile::Absent) {
        return Err(Error::AlreadyExists);
    }
    let bytes = u64::from(size_mb) * MIB;
    if (ctx.available_bytes)(swap_parent(ctx)).map_err(Error::Io)? < bytes {
        return Err(Error::InsufficientSpace);
    }
    let fstab = read_fstab(ctx)?;
    pre_commit.check().map_err(|_| Error::Cancelled)?;
    let _post_commit = pre_commit.commit();

    build_swap(ctx, bytes, true)?;
    if let Some(updated) = with_entry(&fstab.original, ctx.swap_path) {
        if let Err(error) = write_fstab(ctx, &updated, fstab.mode) {
            let undone = swapoff(ctx).is_ok() && remove_swap_file(ctx).is_ok();
            return Err(if undone {
                Error::Filesystem(Stage::Persist, error)
            } else {
                Error::RollbackFailed(Stage::Persist)
            });
        }
    }
    Ok(result(Some(size_mb), true))
}

fn delete(ctx: &Context<'_>, pre_commit: PreCommit) -> Result<SwapResult, Error> {
    let exists = matches!(inspect(ctx)?, SwapFile::Present { .. });
    let active = is_active(ctx)?;
    let fstab = read_fstab(ctx)?;
    let pruned = without_entry(&fstab.original, ctx.swap_path);
    if !exists && !active && pruned.is_none() {
        return Ok(result(None, false));
    }
    pre_commit.check().map_err(|_| Error::Cancelled)?;
    let _post_commit = pre_commit.commit();

    // A failed swapoff (typically: not enough RAM to page the swap back in)
    // leaves everything exactly as it was.
    if active {
        swapoff(ctx)?;
    }
    let reenable = |error: Error| -> Error {
        if active && swapon(ctx).is_err() {
            Error::RollbackFailed(stage_of(&error))
        } else {
            error
        }
    };
    if let Some(pruned) = &pruned {
        if let Err(error) = write_fstab(ctx, pruned, fstab.mode) {
            return Err(reenable(Error::Filesystem(Stage::Persist, error)));
        }
    }
    if let Err(error) = remove_swap_file(ctx) {
        if pruned.is_some() && write_fstab(ctx, &fstab.original, fstab.mode).is_err() {
            return Err(Error::RollbackFailed(Stage::Remove));
        }
        return Err(reenable(Error::Filesystem(Stage::Remove, error)));
    }
    Ok(result(None, true))
}

fn resize(ctx: &Context<'_>, size_mb: u32, pre_commit: PreCommit) -> Result<SwapResult, Error> {
    // With no managed swap file, resize is a create — exactly what the
    // panel's previous delete-then-create sequence did in that case.
    let SwapFile::Present { len, allocated } = inspect(ctx)? else {
        return create(ctx, size_mb, pre_commit);
    };
    let bytes = u64::from(size_mb) * MIB;
    let active = is_active(ctx)?;
    let fstab = read_fstab(ctx)?;
    let entry = with_entry(&fstab.original, ctx.swap_path);
    if len == bytes && active && entry.is_none() {
        return Ok(result(Some(size_mb), false));
    }
    // The old file's blocks are freed before the new one is allocated, so
    // they count toward the space the new file may use.
    let available = (ctx.available_bytes)(swap_parent(ctx)).map_err(Error::Io)?;
    if available.saturating_add(allocated) < bytes {
        return Err(Error::InsufficientSpace);
    }
    pre_commit.check().map_err(|_| Error::Cancelled)?;
    let _post_commit = pre_commit.commit();

    // Make the fstab entry correct first: every later step keeps the same
    // path, so whether the resize succeeds or is rolled back, a reboot
    // brings back whatever swap file ends up at that path.
    if let Some(updated) = &entry {
        write_fstab(ctx, updated, fstab.mode)
            .map_err(|error| Error::Filesystem(Stage::Persist, error))?;
    }
    let restore_fstab = || entry.is_none() || write_fstab(ctx, &fstab.original, fstab.mode).is_ok();

    if active {
        if let Err(error) = swapoff(ctx) {
            return Err(if restore_fstab() {
                error
            } else {
                Error::RollbackFailed(Stage::Disable)
            });
        }
    }
    if let Err(error) = remove_swap_file(ctx) {
        let restored = (!active || swapon(ctx).is_ok()) && restore_fstab();
        return Err(if restored {
            Error::Filesystem(Stage::Remove, error)
        } else {
            Error::RollbackFailed(Stage::Remove)
        });
    }
    if let Err(error) = build_swap(ctx, bytes, true) {
        let stage = stage_of(&error);
        // Put the previous swap file back at its previous size (and state).
        // If that fails too, drop the fstab entry so the next boot does not
        // wait on a swap file that no longer exists.
        if matches!(error, Error::RollbackFailed(_)) || build_swap(ctx, len, active).is_err() {
            if let Some(pruned) = without_entry(&fstab.original, ctx.swap_path) {
                let _ = write_fstab(ctx, &pruned, fstab.mode);
            }
            return Err(Error::RollbackFailed(stage));
        }
        return Err(if restore_fstab() {
            error
        } else {
            Error::RollbackFailed(stage)
        });
    }
    Ok(result(Some(size_mb), true))
}

fn stage_of(error: &Error) -> Stage {
    match error {
        Error::Run(stage, _)
        | Error::Rejected(stage, _)
        | Error::Filesystem(stage, _)
        | Error::RollbackFailed(stage) => *stage,
        _ => Stage::Allocate,
    }
}

fn result(size_mb: Option<u32>, changed: bool) -> SwapResult {
    SwapResult {
        size_mb,
        changed,
        completed_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    }
}

/// `statvfs(2)` on `path`: blocks available to non-root writers times the
/// fragment size, so the root reserve is never counted as usable.
pub fn statvfs_available_bytes(path: &Path) -> io::Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c_path` is a valid NUL-terminated string and `stat` is a
    // properly sized, writable out-parameter for the duration of the call.
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    #[allow(clippy::unnecessary_cast)]
    Ok((stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64))
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<SwapResult, Error> {
    let operation = req.action.operation();
    let scope_path = SiteRelativePath::parse("system-swap").unwrap();
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
        operation,
    )
    .map_err(Error::Preflight)?
    {
        preflight::Outcome::Replay(id) => return replay(&scope, id, operation),
        preflight::Outcome::Proceed(value) => value,
    };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path =
        SiteRelativePath::parse(format!("transactions/{}.json", req.request_id)).unwrap();
    let audit_path = SiteRelativePath::parse("audit/events.jsonl").unwrap();
    let pre_commit = PreCommit::new(cancel.clone());

    let outcome = match req.action {
        Action::Create { size_mb } => create(ctx, size_mb, pre_commit),
        Action::Delete => delete(ctx, pre_commit),
        Action::Resize { size_mb } => resize(ctx, size_mb, pre_commit),
    };
    let result = match outcome {
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

fn replay(scope: &ManagedRoot, id: RequestId, operation: &str) -> Result<SwapResult, Error> {
    let path = SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap();
    let loaded = state::load(scope, &path)
        .map_err(|error| Error::Io(io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != operation {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::unix::fs::PermissionsExt, path::PathBuf};

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const ID_2: &str = "123e4567-e89b-12d3-a456-426614174001";

    fn managed(directory: &Path) -> ManagedRoot {
        ManagedRoot::open(&crate::site::TrustedRoot::parse(directory).unwrap()).unwrap()
    }

    fn plenty(_: &Path) -> io::Result<u64> {
        Ok(u64::MAX / 2)
    }

    fn none_free(_: &Path) -> io::Result<u64> {
        Ok(0)
    }

    /// A fake host: fake tools record each call to `calls.log`; `swapon`
    /// and `swapoff` also maintain a fake `/proc/swaps`. Any tool whose
    /// name is listed in `failing` exits 1 instead.
    struct Host {
        dir: tempfile::TempDir,
        swap_path: String,
        tools: [String; 4],
    }

    impl Host {
        fn new(failing: &[&str]) -> Self {
            let dir = tempfile::tempdir().unwrap();
            for sub in ["state", "etc"] {
                fs::create_dir(dir.path().join(sub)).unwrap();
            }
            let swap_path = dir.path().join("swapfile").to_string_lossy().into_owned();
            let proc_swaps = dir.path().join("proc-swaps");
            fs::write(&proc_swaps, "Filename Type Size Used Priority\n").unwrap();
            let log = dir.path().join("calls.log");
            let names = ["fallocate", "mkswap", "swapon", "swapoff"];
            let tools = names.map(|name| {
                let path = dir.path().join(format!("fake-{name}"));
                let effect = match name {
                    "swapon" => format!("echo \"$1 file 0 0 -2\" >> '{}'", proc_swaps.display()),
                    "swapoff" => format!(
                        "grep -v \"^$1 \" '{0}' > '{0}.tmp'; mv '{0}.tmp' '{0}'",
                        proc_swaps.display()
                    ),
                    // Make the fake allocation visible as the file's length.
                    "fallocate" => "truncate -s \"$2\" \"$3\"".to_owned(),
                    _ => String::new(),
                };
                let body = if failing.contains(&name) {
                    "exit 1".to_owned()
                } else {
                    effect
                };
                fs::write(
                    &path,
                    format!(
                        "#!/bin/sh\necho \"{name} $*\" >> '{}'\n{body}\n",
                        log.display()
                    ),
                )
                .unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
                path.to_string_lossy().into_owned()
            });
            Self {
                dir,
                swap_path,
                tools,
            }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.dir.path().join(name)
        }

        fn fstab(&self) -> String {
            fs::read_to_string(self.path("etc/fstab")).unwrap_or_default()
        }

        fn active(&self) -> bool {
            fs::read_to_string(self.path("proc-swaps"))
                .unwrap()
                .lines()
                .any(|line| line.starts_with(&format!("{} ", self.swap_path)))
        }

        fn calls(&self) -> String {
            fs::read_to_string(self.path("calls.log")).unwrap_or_default()
        }

        /// Seeds an active managed swap file of `size_mb` with its fstab
        /// entry, as a previous successful create would have left it.
        fn seed(&self, size_mb: u64) {
            let file = fs::File::create(&self.swap_path).unwrap();
            file.set_len(size_mb * MIB).unwrap();
            fs::write(
                self.path("proc-swaps"),
                format!(
                    "Filename Type Size Used Priority\n{} file 0 0 -2\n",
                    self.swap_path
                ),
            )
            .unwrap();
            fs::write(
                self.path("etc/fstab"),
                format!(
                    "UUID=abc / ext4 defaults 0 1\n{} none swap sw 0 0\n",
                    self.swap_path
                ),
            )
            .unwrap();
        }

        fn run(
            &self,
            action: Action,
            id: &str,
            key: Option<&str>,
            available: fn(&Path) -> io::Result<u64>,
        ) -> Result<SwapResult, Error> {
            let state = managed(&self.path("state"));
            let etc = managed(&self.path("etc"));
            let proc_swaps = self.path("proc-swaps");
            let ctx = Context {
                engine_state: &state,
                etc_dir: &etc,
                swap_path: &self.swap_path,
                proc_swaps: &proc_swaps,
                tools: Tools {
                    fallocate: &self.tools[0],
                    mkswap: &self.tools[1],
                    swapon: &self.tools[2],
                    swapoff: &self.tools[3],
                },
                available_bytes: available,
            };
            let req = Request::parse(action, id, key).unwrap();
            execute(&ctx, &req, &CancellationToken::default())
        }

        fn swap_len(&self) -> Option<u64> {
            fs::metadata(&self.swap_path).ok().map(|meta| meta.len())
        }
    }

    #[test]
    fn rejects_sizes_outside_the_bounded_range() {
        for size_mb in [0, MIN_SIZE_MB - 1, MAX_SIZE_MB + 1] {
            for action in [Action::Create { size_mb }, Action::Resize { size_mb }] {
                assert_eq!(
                    Request::parse(action, ID, None).err(),
                    Some(RequestError::InvalidSize)
                );
            }
        }
        assert!(
            Request::parse(
                Action::Create {
                    size_mb: MIN_SIZE_MB
                },
                ID,
                None
            )
            .is_ok()
        );
        assert!(
            Request::parse(
                Action::Resize {
                    size_mb: MAX_SIZE_MB
                },
                ID,
                None
            )
            .is_ok()
        );
    }

    #[test]
    fn create_builds_a_private_active_swap_file_with_one_fstab_entry_then_replays() {
        let host = Host::new(&[]);
        fs::write(host.path("etc/fstab"), "UUID=abc / ext4 defaults 0 1").unwrap();

        let first = host
            .run(
                Action::Create { size_mb: 512 },
                ID,
                Some("swap-key"),
                plenty,
            )
            .unwrap();
        let second = host
            .run(
                Action::Create { size_mb: 512 },
                ID_2,
                Some("swap-key"),
                plenty,
            )
            .unwrap();

        assert_eq!(first.size_mb, Some(512));
        assert!(first.changed);
        assert_eq!(first.completed_at_unix_secs, second.completed_at_unix_secs);
        assert!(host.active());
        assert_eq!(host.swap_len(), Some(512 * MIB));
        assert_eq!(
            fs::metadata(&host.swap_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            host.fstab(),
            format!(
                "UUID=abc / ext4 defaults 0 1\n{} none swap sw 0 0\n",
                host.swap_path
            )
        );
        // The replayed request never touched the host again.
        assert_eq!(host.calls().matches("fallocate").count(), 1);
    }

    #[test]
    fn create_refuses_an_existing_path_and_insufficient_space_without_changes() {
        let host = Host::new(&[]);
        fs::write(&host.swap_path, "").unwrap();
        assert!(matches!(
            host.run(Action::Create { size_mb: 512 }, ID, None, plenty),
            Err(Error::AlreadyExists)
        ));

        let host = Host::new(&[]);
        std::os::unix::fs::symlink("/etc/passwd", &host.swap_path).unwrap();
        for (action, id) in [
            (Action::Create { size_mb: 512 }, ID),
            (Action::Delete, ID_2),
            (
                Action::Resize { size_mb: 512 },
                "123e4567-e89b-12d3-a456-426614174002",
            ),
        ] {
            assert!(matches!(
                host.run(action, id, None, plenty),
                Err(Error::UnsafeSwapPath)
            ));
        }
        assert!(host.calls().is_empty());

        let host = Host::new(&[]);
        assert!(matches!(
            host.run(Action::Create { size_mb: 512 }, ID, None, none_free),
            Err(Error::InsufficientSpace)
        ));
        assert!(host.calls().is_empty());
        assert_eq!(host.swap_len(), None);
    }

    #[test]
    fn create_removes_the_partial_file_when_mkswap_fails() {
        let host = Host::new(&["mkswap"]);
        let error = host
            .run(Action::Create { size_mb: 512 }, ID, None, plenty)
            .unwrap_err();

        assert!(matches!(error, Error::Rejected(Stage::Format, _)));
        assert_eq!(host.swap_len(), None);
        assert!(!host.active());
        assert_eq!(host.fstab(), "");
    }

    #[test]
    fn create_undoes_activation_when_fstab_cannot_be_written() {
        // Root ignores directory permissions, so this failure cannot be
        // provoked that way when the suite runs as root.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let host = Host::new(&[]);
        fs::write(host.path("etc/fstab"), "UUID=abc / ext4 defaults 0 1\n").unwrap();
        // fstab stays readable, but its directory refuses the atomic
        // replacement's temp file.
        fs::set_permissions(host.path("etc"), fs::Permissions::from_mode(0o555)).unwrap();

        let error = host
            .run(Action::Create { size_mb: 512 }, ID, None, plenty)
            .unwrap_err();
        fs::set_permissions(host.path("etc"), fs::Permissions::from_mode(0o755)).unwrap();

        assert!(matches!(error, Error::Filesystem(Stage::Persist, _)));
        assert_eq!(host.swap_len(), None);
        assert!(!host.active());
        assert_eq!(host.fstab(), "UUID=abc / ext4 defaults 0 1\n");
    }

    #[test]
    fn delete_disables_removes_and_drops_only_the_managed_fstab_entry() {
        let host = Host::new(&[]);
        host.seed(512);

        let result = host.run(Action::Delete, ID, None, plenty).unwrap();

        assert!(result.changed);
        assert_eq!(result.size_mb, None);
        assert_eq!(host.swap_len(), None);
        assert!(!host.active());
        assert_eq!(host.fstab(), "UUID=abc / ext4 defaults 0 1\n");
    }

    #[test]
    fn delete_is_a_no_op_when_nothing_is_managed() {
        let host = Host::new(&[]);
        let result = host.run(Action::Delete, ID, None, plenty).unwrap();
        assert!(!result.changed);
        assert!(host.calls().is_empty());
    }

    #[test]
    fn delete_changes_nothing_when_swapoff_fails() {
        let host = Host::new(&["swapoff"]);
        host.seed(512);
        let fstab = host.fstab();

        let error = host.run(Action::Delete, ID, None, plenty).unwrap_err();

        assert!(matches!(error, Error::Rejected(Stage::Disable, _)));
        assert!(host.active());
        assert_eq!(host.swap_len(), Some(512 * MIB));
        assert_eq!(host.fstab(), fstab);
    }

    #[test]
    fn resize_replaces_the_swap_file_at_the_same_path() {
        let host = Host::new(&[]);
        host.seed(512);
        let fstab = host.fstab();

        let result = host
            .run(Action::Resize { size_mb: 1024 }, ID, None, plenty)
            .unwrap();

        assert_eq!(result.size_mb, Some(1024));
        assert!(result.changed);
        assert!(host.active());
        assert_eq!(host.swap_len(), Some(1024 * MIB));
        assert_eq!(host.fstab(), fstab);
    }

    #[test]
    fn resize_to_the_current_size_is_a_no_op() {
        let host = Host::new(&[]);
        host.seed(512);
        let result = host
            .run(Action::Resize { size_mb: 512 }, ID, None, plenty)
            .unwrap();
        assert!(!result.changed);
        assert!(host.calls().is_empty());
    }

    #[test]
    fn resize_without_a_managed_file_creates_one() {
        let host = Host::new(&[]);
        let result = host
            .run(Action::Resize { size_mb: 768 }, ID, None, plenty)
            .unwrap();
        assert!(result.changed);
        assert_eq!(host.swap_len(), Some(768 * MIB));
        assert!(host.active());
    }

    #[test]
    fn resize_refuses_insufficient_space_before_touching_the_active_swap() {
        let host = Host::new(&[]);
        host.seed(512);
        // Only the freed 512 MiB would be available — not enough for 1024.
        assert!(matches!(
            host.run(Action::Resize { size_mb: 1024 }, ID, None, none_free),
            Err(Error::InsufficientSpace)
        ));
        assert!(host.calls().is_empty());
        assert!(host.active());
    }

    #[test]
    fn resize_keeps_the_old_swap_active_when_swapoff_fails() {
        let host = Host::new(&["swapoff"]);
        host.seed(512);

        let error = host
            .run(Action::Resize { size_mb: 1024 }, ID, None, plenty)
            .unwrap_err();

        assert!(matches!(error, Error::Rejected(Stage::Disable, _)));
        assert!(host.active());
        assert_eq!(host.swap_len(), Some(512 * MIB));
    }

    #[test]
    fn resize_that_cannot_allocate_and_cannot_restore_reports_rollback_failed() {
        // fallocate fails for both the new size and the restore attempt,
        // so the host is left without the file; the fstab entry is dropped
        // so boot does not wait on it.
        let host = Host::new(&["fallocate"]);
        host.seed(512);

        let error = host
            .run(Action::Resize { size_mb: 1024 }, ID, None, plenty)
            .unwrap_err();

        assert!(matches!(error, Error::RollbackFailed(Stage::Allocate)));
        assert_eq!(host.swap_len(), None);
        assert_eq!(host.fstab(), "UUID=abc / ext4 defaults 0 1\n");
        let (code, message) = error.protocol();
        assert_eq!(code, ErrorCode::Internal);
        assert!(message.contains("restoring the previous swap state also failed"));
    }

    #[test]
    fn resize_restores_the_previous_size_when_the_new_file_cannot_be_enabled() {
        // swapon fails for the new file; the restore rebuilds the old size
        // and tries to enable it too, which also fails with this fake —
        // so the outcome must be RollbackFailed, never a silent success.
        let host = Host::new(&["swapon"]);
        host.seed(512);

        let error = host
            .run(Action::Resize { size_mb: 1024 }, ID, None, plenty)
            .unwrap_err();

        assert!(matches!(error, Error::RollbackFailed(Stage::Enable)));
    }

    #[test]
    fn a_failed_request_replays_its_recorded_error() {
        let host = Host::new(&["swapoff"]);
        host.seed(512);
        let first = host
            .run(Action::Delete, ID, Some("delete-key"), plenty)
            .unwrap_err();
        let second = host
            .run(Action::Delete, ID_2, Some("delete-key"), plenty)
            .unwrap_err();

        assert_eq!(first.protocol().0, ErrorCode::SubprocessFailed);
        assert!(matches!(
            second,
            Error::Replayed {
                code: ErrorCode::SubprocessFailed,
                ..
            }
        ));
        assert_eq!(host.calls().matches("swapoff").count(), 1);
    }

    #[test]
    fn fstab_edits_ignore_comments_and_other_swap_areas() {
        let fstab = "# /swapfile none swap sw 0 0\n/swap.img none swap sw 0 0\n";
        let added = with_entry(fstab, "/swapfile").unwrap();
        assert!(added.ends_with("/swapfile none swap sw 0 0\n"));
        assert_eq!(without_entry(&added, "/swapfile").unwrap(), fstab);
        assert_eq!(without_entry(fstab, "/swapfile"), None);
    }
}
