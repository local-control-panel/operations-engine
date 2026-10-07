//! `docker.network`, `docker.imagePull`, `docker.imageRemove` and
//! `docker.volumeRemove`: the Docker resource verbs the control panel's
//! Images, Networks and Volumes tabs offer, as typed, audited, transactional
//! operations instead of raw `docker` over SSH.
//!
//! Decisions (milestone 070):
//!
//! - Fixed argv, no shell. Every name is validated before any state is
//!   written, and every destructive verb resolves the resource with `docker
//!   inspect` first, so the caller's string never reaches `rm`/`rmi` unless
//!   Docker confirmed it names exactly that resource (a network is matched by
//!   exact name, never by id prefix; an image is resolved to its full
//!   `sha256:` id, which must start with what the caller sent).
//! - The managed stack is never touched. A network labelled
//!   `com.docker.compose.project=wcp` and the built-in `bridge`, `host` and
//!   `none` networks cannot be removed; an image that any `wcp` container
//!   (running or not, since the next `up -d` would need it) was created from
//!   cannot be removed; a volume carrying the `wcp` label, or attached to any
//!   container, cannot be removed. Refusals are `INVALID_INPUT` and recorded.
//! - Destructive verbs need their exact confirmation token: `NETWORK_REMOVE`,
//!   `IMAGE_REMOVE`, `IMAGE_REMOVE_FORCE` (`--force` is an explicit flag with
//!   a token of its own) and `VOLUME_REMOVE`. Creating a network and pulling
//!   an image are additive and need none.
//! - `volumeRemove` has no `force`: for a volume `-f` only silences "no such
//!   volume", it never frees one that is in use, so the flag would be a
//!   promise the engine could not keep.
//! - `imagePull` pulls from a fixed registry allowlist (Docker Hub, `ghcr.io`,
//!   `quay.io`, `gcr.io`, `mcr.microsoft.com`, `registry.k8s.io`, `lscr.io`,
//!   `public.ecr.aws`, `registry.gitlab.com`) and refuses to start with less
//!   than 2 GiB free under Docker's root directory.
//! - `imageRemove` takes the shared `stacks/wcp` lock (the "is a managed
//!   container using it" check would otherwise race `stack.deploy`'s `up
//!   -d`); the other three take none. All four share one scope
//!   (`docker-resource`); lock, idempotency key, transaction record and audit
//!   entry come from `mutation::preflight`.

use crate::{
    docker_container::{Error, MANAGED_PROJECT, Stage, fail, now_secs, rel, replay, run_docker},
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{
        self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination,
        SubprocessDiagnostics,
    },
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        state::{self},
    },
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::time::Duration;

pub const NETWORK_OPERATION: &str = "docker.network";
pub const PULL_OPERATION: &str = "docker.imagePull";
pub const IMAGE_REMOVE_OPERATION: &str = "docker.imageRemove";
pub const VOLUME_REMOVE_OPERATION: &str = "docker.volumeRemove";
const SCOPE: &str = "docker-resource";
const PROJECT_LABEL: &str = "com.docker.compose.project";

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(30);
const ACTION_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const PULL_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// An image pull is refused below this much free space.
pub const MIN_FREE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Most of `docker pull`'s progress output returned to the caller.
const PULL_OUTPUT_LIMIT: usize = 16 * 1024;

const NETWORK_DRIVERS: &[&str] = &["bridge", "overlay", "host", "macvlan", "none"];
const BUILTIN_NETWORKS: &[&str] = &["bridge", "host", "none"];
const REGISTRIES: &[&str] = &[
    "docker.io",
    "ghcr.io",
    "quay.io",
    "gcr.io",
    "mcr.microsoft.com",
    "registry.k8s.io",
    "lscr.io",
    "public.ecr.aws",
    "registry.gitlab.com",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidAction,
    InvalidName,
    InvalidDriver,
    InvalidReference,
    RegistryNotAllowed,
    InvalidImageId,
    InvalidConfirmation,
    /// `--force` was given where it does not apply.
    ForceNotApplicable,
    InvalidRequestId,
    InvalidIdempotencyKey,
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

fn check_token(expected: Option<&str>, given: Option<&str>) -> Result<(), RequestError> {
    match expected {
        Some(token) if given != Some(token) => Err(RequestError::InvalidConfirmation),
        _ => Ok(()),
    }
}

/// A Docker network or volume name: an ASCII alphanumeric, then letters,
/// digits, `_`, `.` or `-`, at most 128 bytes (what the panel always allowed).
fn valid_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    (1..=128).contains(&value.len())
        && bytes.next().is_some_and(|b| b.is_ascii_alphanumeric())
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkAction {
    Create { driver: String },
    Remove,
}

#[derive(Debug)]
pub struct NetworkRequest {
    pub name: String,
    pub action: NetworkAction,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl NetworkRequest {
    pub const REMOVE_TOKEN: &'static str = "NETWORK_REMOVE";

    pub fn parse(
        action: &str,
        name: &str,
        driver: Option<&str>,
        confirmation: Option<&str>,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        if !valid_name(name) {
            return Err(RequestError::InvalidName);
        }
        let action = match action {
            "create" => {
                let driver = driver.filter(|d| !d.is_empty()).unwrap_or("bridge");
                if !NETWORK_DRIVERS.contains(&driver) {
                    return Err(RequestError::InvalidDriver);
                }
                NetworkAction::Create {
                    driver: driver.to_owned(),
                }
            }
            "remove" => {
                if driver.is_some_and(|d| !d.is_empty()) {
                    return Err(RequestError::InvalidDriver);
                }
                check_token(Some(Self::REMOVE_TOKEN), confirmation)?;
                NetworkAction::Remove
            }
            _ => return Err(RequestError::InvalidAction),
        };
        let (request_id, idempotency_key) = parse_ids(request_id, key)?;
        Ok(Self {
            name: name.to_owned(),
            action,
            request_id,
            idempotency_key,
        })
    }
}

/// An image reference the engine will pull: `[registry/]path[:tag][@sha256:...]`
/// from an allowlisted registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageReference(String);

impl ImageReference {
    pub fn parse(value: &str) -> Result<Self, RequestError> {
        if value.is_empty()
            || value.len() > 255
            || !value.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/' | b':' | b'@')
            })
        {
            return Err(RequestError::InvalidReference);
        }
        let (name, digest) = match value.split_once('@') {
            Some((name, digest)) => (name, Some(digest)),
            None => (value, None),
        };
        if let Some(digest) = digest {
            let hex = digest
                .strip_prefix("sha256:")
                .ok_or(RequestError::InvalidReference)?;
            if hex.len() != 64 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                return Err(RequestError::InvalidReference);
            }
        }
        // A `:` after the last `/` starts the tag; before it, a registry port.
        let last_slash = name.rfind('/');
        let (path, tag) = match name.rfind(':') {
            Some(colon) if last_slash.is_none_or(|slash| colon > slash) => {
                (&name[..colon], Some(&name[colon + 1..]))
            }
            _ => (name, None),
        };
        if let Some(tag) = tag {
            let mut bytes = tag.bytes();
            let ok = (1..=128).contains(&tag.len())
                && bytes
                    .next()
                    .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_')
                && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
            if !ok {
                return Err(RequestError::InvalidReference);
            }
        }
        let mut parts: Vec<&str> = path.split('/').collect();
        let registry = if parts.len() > 1
            && (parts[0].contains('.') || parts[0].contains(':') || parts[0] == "localhost")
        {
            Some(parts.remove(0))
        } else {
            None
        };
        if let Some(registry) = registry {
            if !REGISTRIES.contains(&registry) {
                return Err(RequestError::RegistryNotAllowed);
            }
        }
        let component_ok = |part: &&str| {
            let mut bytes = part.bytes();
            bytes
                .next()
                .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                && bytes.all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
                })
        };
        if parts.is_empty() || !parts.iter().all(component_ok) {
            return Err(RequestError::InvalidReference);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug)]
pub struct PullRequest {
    pub reference: ImageReference,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl PullRequest {
    pub fn parse(
        reference: &str,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let reference = ImageReference::parse(reference)?;
        let (request_id, idempotency_key) = parse_ids(request_id, key)?;
        Ok(Self {
            reference,
            request_id,
            idempotency_key,
        })
    }
}

/// A 12-64 digit lowercase hex image id, as `docker images` prints it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageId(String);

impl ImageId {
    pub fn parse(value: &str) -> Option<Self> {
        let ok = (12..=64).contains(&value.len())
            && value
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        ok.then(|| Self(value.to_owned()))
    }
}

#[derive(Debug)]
pub struct ImageRemoveRequest {
    pub image_id: ImageId,
    pub force: bool,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl ImageRemoveRequest {
    pub const fn token(force: bool) -> &'static str {
        if force {
            "IMAGE_REMOVE_FORCE"
        } else {
            "IMAGE_REMOVE"
        }
    }

    pub fn parse(
        image_id: &str,
        force: bool,
        confirmation: Option<&str>,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let image_id = ImageId::parse(image_id).ok_or(RequestError::InvalidImageId)?;
        check_token(Some(Self::token(force)), confirmation)?;
        let (request_id, idempotency_key) = parse_ids(request_id, key)?;
        Ok(Self {
            image_id,
            force,
            request_id,
            idempotency_key,
        })
    }
}

#[derive(Debug)]
pub struct VolumeRemoveRequest {
    pub name: String,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl VolumeRemoveRequest {
    pub const TOKEN: &'static str = "VOLUME_REMOVE";

    pub fn parse(
        name: &str,
        confirmation: Option<&str>,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        if !valid_name(name) {
            return Err(RequestError::InvalidName);
        }
        check_token(Some(Self::TOKEN), confirmation)?;
        let (request_id, idempotency_key) = parse_ids(request_id, key)?;
        Ok(Self {
            name: name.to_owned(),
            request_id,
            idempotency_key,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkResult {
    /// `create` or `remove`.
    pub action: String,
    pub name: String,
    pub driver: Option<String>,
    pub completed_at_unix_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PullResult {
    pub reference: String,
    /// The tail of `docker pull`'s output (layer progress and the digest).
    pub output: String,
    pub output_truncated: bool,
    pub completed_at_unix_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageRemoveResult {
    /// The full `sha256:` id that was removed.
    pub image_id: String,
    pub force: bool,
    pub completed_at_unix_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VolumeRemoveResult {
    pub name: String,
    pub completed_at_unix_secs: u64,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub docker_program: &'a str,
    /// Free bytes available to unprivileged writers on the filesystem
    /// holding the given directory.
    pub free_bytes: fn(&str) -> std::io::Result<u64>,
}

/// Free space on the filesystem holding `path`, through `statvfs`.
#[cfg(unix)]
pub fn statvfs_free_bytes(path: &str) -> std::io::Result<u64> {
    use std::{ffi::CString, mem::MaybeUninit};
    let path = CString::new(path).map_err(std::io::Error::other)?;
    let mut stat = MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `path` is a valid NUL-terminated string and `stat` is a valid
    // out-pointer; the struct is only read after the call reports success.
    let rc = unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `statvfs` returned 0, so it initialised the struct.
    let stat = unsafe { stat.assume_init() };
    // The field widths differ between platforms (u32 on macOS, u64 on Linux),
    // so the widening is a no-op on some targets.
    #[allow(clippy::useless_conversion)]
    let free = u64::from(stat.f_bavail).saturating_mul(u64::from(stat.f_frsize));
    Ok(free)
}

fn open_scope(engine_state: &ManagedRoot) -> std::io::Result<ManagedRoot> {
    engine_state.create_dir_all(&rel(SCOPE))?;
    let scope = engine_state.open_managed_dir(&rel(SCOPE))?;
    for child in ["locks", "transactions", "audit"] {
        scope.create_dir_all(&rel(child))?;
    }
    Ok(scope)
}

/// Lock, preflight and the transaction scaffolding common to the four
/// operations. `body` runs with the transaction `InProgress`.
fn run_transaction<T, F>(
    ctx: &Context<'_>,
    request_id: RequestId,
    key: Option<&IdempotencyKey>,
    operation: &'static str,
    take_stack_lock: bool,
    body: F,
) -> Result<T, Error>
where
    T: Serialize + DeserializeOwned,
    F: FnOnce() -> Result<T, Error>,
{
    let scope = open_scope(ctx.engine_state).map_err(Error::Io)?;
    let stack_scope = crate::stack_deploy::open_scope(ctx.engine_state).map_err(Error::Io)?;
    let _stack_lock = if take_stack_lock {
        Some(
            crate::stack_deploy::acquire_stack_lock(&stack_scope, request_id)
                .map_err(|_| Error::StackBusy)?,
        )
    } else {
        None
    };
    let admitted =
        match preflight::run(&scope, request_id, key, operation).map_err(Error::Preflight)? {
            preflight::Outcome::Replay(id) => return replay(&scope, id, operation),
            preflight::Outcome::Proceed(value) => value,
        };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path =
        crate::site::SiteRelativePath::parse(format!("transactions/{request_id}.json")).unwrap();
    let audit_path = rel("audit/events.jsonl");

    let result = match body() {
        Ok(result) => result,
        Err(error) => return Err(fail(&scope, &state_path, &audit_path, state, error)),
    };
    let value = serde_json::to_value(&result).expect("results always serialize");
    state.mark_committed(value.clone()).unwrap();
    if state::save(&scope, &state_path, &state).is_err() {
        drop(lock);
        return Err(Error::PostCommit { result: value });
    }
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(request_id, true, None),
    );
    drop(lock);
    Ok(result)
}

/// stdout of a read-only `docker` call, or `None` when Docker answered "No
/// such ..." (the resource is not there).
fn lookup(
    ctx: &Context<'_>,
    argv: &[String],
    cancel: &CancellationToken,
) -> Result<Option<String>, Error> {
    let output = process::run(
        &ProcessRequest::new(ctx.docker_program).args(argv),
        &ProcessLimits {
            timeout: LOOKUP_TIMEOUT,
            max_stdout_bytes: 64 * 1024,
            max_stderr_bytes: 16 * 1024,
        },
        cancel,
    )
    .map_err(|e| Error::Run(Stage::Lookup, e))?;
    match output.termination {
        ProcessTermination::Exited { success: true, .. } => Ok(Some(
            String::from_utf8_lossy(&output.stdout.bytes).into_owned(),
        )),
        ProcessTermination::Exited { .. }
            if String::from_utf8_lossy(&output.stderr.bytes).contains("No such") =>
        {
            Ok(None)
        }
        _ => Err(Error::Rejected(
            Stage::Lookup,
            SubprocessDiagnostics::from_output(ctx.docker_program, &output),
        )),
    }
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|p| (*p).to_owned()).collect()
}

fn label_format(prefix: &str) -> String {
    // The label goes last: it is free text and may contain spaces.
    format!("{prefix} {{{{index .Labels \"{PROJECT_LABEL}\"}}}}")
}

pub fn execute_network(
    ctx: &Context<'_>,
    req: &NetworkRequest,
    cancel: &CancellationToken,
) -> Result<NetworkResult, Error> {
    run_transaction(
        ctx,
        req.request_id,
        req.idempotency_key.as_ref(),
        NETWORK_OPERATION,
        false,
        || match &req.action {
            NetworkAction::Create { driver } => {
                run_docker(
                    ctx.docker_program,
                    Stage::NetworkCreate,
                    &argv(&["network", "create", "--driver", driver, &req.name]),
                    ACTION_TIMEOUT,
                    cancel,
                )?;
                Ok(NetworkResult {
                    action: "create".into(),
                    name: req.name.clone(),
                    driver: Some(driver.clone()),
                    completed_at_unix_secs: now_secs(),
                })
            }
            NetworkAction::Remove => {
                if BUILTIN_NETWORKS.contains(&req.name.as_str()) {
                    return Err(Error::Refused(
                        "the built-in Docker networks cannot be removed",
                    ));
                }
                let stdout = lookup(
                    ctx,
                    &argv(&[
                        "network",
                        "inspect",
                        "--format",
                        &label_format("{{.Id}} {{.Name}}"),
                        &req.name,
                    ]),
                    cancel,
                )?
                .ok_or(Error::NotFound)?;
                let line = stdout.lines().next().unwrap_or("");
                let mut fields = line.splitn(3, ' ');
                let id = fields.next().unwrap_or("");
                let name = fields.next().unwrap_or("");
                let project = fields.next().unwrap_or("");
                let id_ok = id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit());
                if !id_ok || name != req.name {
                    // Docker matched an id prefix, not the name.
                    return Err(Error::NotFound);
                }
                if project == MANAGED_PROJECT {
                    return Err(Error::Refused(
                        "networks of the managed wcp stack cannot be removed",
                    ));
                }
                run_docker(
                    ctx.docker_program,
                    Stage::NetworkRemove,
                    &argv(&["network", "rm", id]),
                    ACTION_TIMEOUT,
                    cancel,
                )?;
                Ok(NetworkResult {
                    action: "remove".into(),
                    name: req.name.clone(),
                    driver: None,
                    completed_at_unix_secs: now_secs(),
                })
            }
        },
    )
}

pub fn execute_pull(
    ctx: &Context<'_>,
    req: &PullRequest,
    cancel: &CancellationToken,
) -> Result<PullResult, Error> {
    run_transaction(
        ctx,
        req.request_id,
        req.idempotency_key.as_ref(),
        PULL_OPERATION,
        false,
        || {
            let root = lookup(
                ctx,
                &argv(&["info", "--format", "{{.DockerRootDir}}"]),
                cancel,
            )?
            .unwrap_or_default();
            let root = root.lines().next().unwrap_or("").trim();
            if !root.starts_with('/') {
                return Err(Error::DiskLow);
            }
            match (ctx.free_bytes)(root) {
                Ok(free) if free >= MIN_FREE_BYTES => {}
                _ => return Err(Error::DiskLow),
            }
            let output = process::run(
                &ProcessRequest::new(ctx.docker_program)
                    .args(argv(&["pull", req.reference.as_str()])),
                &ProcessLimits {
                    timeout: PULL_TIMEOUT,
                    max_stdout_bytes: 1024 * 1024,
                    max_stderr_bytes: 64 * 1024,
                },
                cancel,
            )
            .map_err(|e| Error::Run(Stage::ImagePull, e))?;
            if !matches!(
                output.termination,
                ProcessTermination::Exited { success: true, .. }
            ) {
                return Err(Error::Rejected(
                    Stage::ImagePull,
                    SubprocessDiagnostics::from_output(ctx.docker_program, &output),
                ));
            }
            let text = String::from_utf8_lossy(&output.stdout.bytes);
            let (tail, truncated) = tail_of(&text, PULL_OUTPUT_LIMIT);
            Ok(PullResult {
                reference: req.reference.as_str().to_owned(),
                output: tail,
                output_truncated: truncated || output.stdout.truncated,
                completed_at_unix_secs: now_secs(),
            })
        },
    )
}

/// The last `limit` bytes of `text`, cut at a character boundary.
fn tail_of(text: &str, limit: usize) -> (String, bool) {
    if text.len() <= limit {
        return (text.to_owned(), false);
    }
    let mut start = text.len() - limit;
    while !text.is_char_boundary(start) {
        start += 1;
    }
    (text[start..].to_owned(), true)
}

pub fn execute_image_remove(
    ctx: &Context<'_>,
    req: &ImageRemoveRequest,
    cancel: &CancellationToken,
) -> Result<ImageRemoveResult, Error> {
    run_transaction(
        ctx,
        req.request_id,
        req.idempotency_key.as_ref(),
        IMAGE_REMOVE_OPERATION,
        true,
        || {
            let stdout = lookup(
                ctx,
                &argv(&["image", "inspect", "--format", "{{.Id}}", &req.image_id.0]),
                cancel,
            )?
            .ok_or(Error::NotFound)?;
            let id = stdout.lines().next().unwrap_or("").trim();
            let digest_ok = id.strip_prefix("sha256:").is_some_and(|hex| {
                hex.len() == 64
                    && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                    && hex.starts_with(&req.image_id.0)
            });
            if !digest_ok {
                return Err(Error::NotFound);
            }
            let users = lookup(
                ctx,
                &argv(&[
                    "ps",
                    "-a",
                    "--no-trunc",
                    "--filter",
                    &format!("ancestor={id}"),
                    "--filter",
                    &format!("label={PROJECT_LABEL}={MANAGED_PROJECT}"),
                    "--format",
                    "{{.ID}}",
                ]),
                cancel,
            )?
            .unwrap_or_default();
            if !users.trim().is_empty() {
                return Err(Error::Refused(
                    "the image is used by a container of the managed wcp stack",
                ));
            }
            let mut rmi = vec!["rmi".to_owned()];
            if req.force {
                rmi.push("-f".into());
            }
            rmi.push(id.to_owned());
            run_docker(
                ctx.docker_program,
                Stage::ImageRemove,
                &rmi,
                ACTION_TIMEOUT,
                cancel,
            )?;
            Ok(ImageRemoveResult {
                image_id: id.to_owned(),
                force: req.force,
                completed_at_unix_secs: now_secs(),
            })
        },
    )
}

pub fn execute_volume_remove(
    ctx: &Context<'_>,
    req: &VolumeRemoveRequest,
    cancel: &CancellationToken,
) -> Result<VolumeRemoveResult, Error> {
    run_transaction(
        ctx,
        req.request_id,
        req.idempotency_key.as_ref(),
        VOLUME_REMOVE_OPERATION,
        false,
        || {
            let stdout = lookup(
                ctx,
                &argv(&[
                    "volume",
                    "inspect",
                    "--format",
                    &label_format("{{.Name}}"),
                    &req.name,
                ]),
                cancel,
            )?
            .ok_or(Error::NotFound)?;
            let line = stdout.lines().next().unwrap_or("");
            let mut fields = line.splitn(2, ' ');
            if fields.next() != Some(req.name.as_str()) {
                return Err(Error::NotFound);
            }
            if fields.next().unwrap_or("") == MANAGED_PROJECT {
                return Err(Error::Refused(
                    "volumes of the managed wcp stack cannot be removed",
                ));
            }
            let attached = lookup(
                ctx,
                &argv(&[
                    "ps",
                    "-a",
                    "--no-trunc",
                    "--filter",
                    &format!("volume={}", req.name),
                    "--format",
                    "{{.ID}}",
                ]),
                cancel,
            )?
            .unwrap_or_default();
            if !attached.trim().is_empty() {
                return Err(Error::Refused(
                    "the volume is attached to a container; remove the container first",
                ));
            }
            run_docker(
                ctx.docker_program,
                Stage::VolumeRemove,
                &argv(&["volume", "rm", &req.name]),
                ACTION_TIMEOUT,
                cancel,
            )?;
            Ok(VolumeRemoveResult {
                name: req.name.clone(),
                completed_at_unix_secs: now_secs(),
            })
        },
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::error::ErrorCode;
    use std::{fs, os::unix::fs::PermissionsExt, sync::Mutex};
    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const ID2: &str = "123e4567-e89b-12d3-a456-426614174001";
    const ID3: &str = "123e4567-e89b-12d3-a456-426614174002";
    const NET_ID: &str = "aaaaaaaaaaaa0000000000000000000000000000000000000000000000000000";
    const IMG: &str = "cccccccccccc";
    const IMG_FULL: &str =
        "sha256:cccccccccccc0000000000000000000000000000000000000000000000000000";

    static SERIAL: Mutex<()> = Mutex::new(());

    /// A fake `docker` that records its argv and answers the lookups for a
    /// handful of known resources.
    struct Fixture {
        dir: tempfile::TempDir,
        docker: String,
    }

    impl Fixture {
        fn new(verb_exit: i32) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let log = dir.path().join("calls.log");
            let script = dir.path().join("docker");
            fs::write(
                &script,
                format!(
                    "#!/bin/sh\necho \"$*\" >> '{log}'\n\
                     last=; for a; do last=$a; done\n\
                     case \"$1 $2\" in\n\
                       'network inspect') case \"$last\" in\n\
                         plain) echo '{NET_ID} plain ';;\n\
                         managed_default) echo '{NET_ID} managed_default wcp';;\n\
                         other) echo '{NET_ID} other-x ';;\n\
                         *) echo 'Error: No such network: '\"$last\" >&2; exit 1;; esac; exit 0;;\n\
                       'image inspect') case \"$last\" in\n\
                         {IMG}) echo '{IMG_FULL}';;\n\
                         dddddddddddd) echo 'sha256:eeeeeeeeeeee0000000000000000000000000000000000000000000000000000';;\n\
                         *) echo 'Error: No such image: '\"$last\" >&2; exit 1;; esac; exit 0;;\n\
                       'volume inspect') case \"$last\" in\n\
                         data) echo 'data ';;\n\
                         used) echo 'used ';;\n\
                         wcp_db) echo 'wcp_db wcp';;\n\
                         *) echo 'Error: No such volume: '\"$last\" >&2; exit 1;; esac; exit 0;;\n\
                       'info --format') echo '{root}'; exit 0;;\n\
                     esac\n\
                     if [ \"$1\" = ps ]; then\n\
                       case \"$*\" in\n\
                         *ancestor={IMG_FULL}*) case \"$*\" in *label=com.docker.compose.project=wcp*) test -f '{managed}' && echo bbbb;; esac;;\n\
                         *volume=used*) echo cccc;;\n\
                       esac\n\
                       exit 0\n\
                     fi\n\
                     exit {verb_exit}\n",
                    log = log.display(),
                    root = dir.path().display(),
                    managed = dir.path().join("image-in-use").display(),
                ),
            )
            .unwrap();
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
            let docker = script.to_string_lossy().into_owned();
            Self { dir, docker }
        }

        fn state(&self) -> ManagedRoot {
            let root = self.dir.path().join("state");
            fs::create_dir_all(&root).unwrap();
            ManagedRoot::open(&crate::site::TrustedRoot::parse(&root).unwrap()).unwrap()
        }

        fn calls(&self) -> Vec<String> {
            fs::read_to_string(self.dir.path().join("calls.log"))
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect()
        }

        fn mutating_calls(&self) -> Vec<String> {
            self.calls()
                .into_iter()
                .filter(|l| {
                    ["network create", "network rm", "rmi", "volume rm", "pull"]
                        .iter()
                        .any(|p| l.starts_with(p))
                })
                .collect()
        }

        fn image_in_use_by_wcp(&self) {
            fs::write(self.dir.path().join("image-in-use"), "").unwrap();
        }
    }

    fn ctx<'a>(
        f: &'a Fixture,
        state: &'a ManagedRoot,
        free: fn(&str) -> std::io::Result<u64>,
    ) -> Context<'a> {
        Context {
            engine_state: state,
            docker_program: &f.docker,
            free_bytes: free,
        }
    }

    fn plenty(_: &str) -> std::io::Result<u64> {
        Ok(MIN_FREE_BYTES)
    }

    fn scarce(_: &str) -> std::io::Result<u64> {
        Ok(MIN_FREE_BYTES - 1)
    }

    fn cancel() -> CancellationToken {
        CancellationToken::default()
    }

    fn remove_network(name: &str, request: &str) -> NetworkRequest {
        NetworkRequest::parse(
            "remove",
            name,
            None,
            Some("NETWORK_REMOVE"),
            request,
            Some(&format!("key-{request}")),
        )
        .unwrap()
    }

    #[test]
    fn destructive_verbs_need_their_exact_token() {
        for wrong in [
            None,
            Some(""),
            Some("network_remove"),
            Some("VOLUME_REMOVE"),
        ] {
            assert_eq!(
                NetworkRequest::parse("remove", "plain", None, wrong, ID, None).unwrap_err(),
                RequestError::InvalidConfirmation
            );
        }
        assert!(NetworkRequest::parse("create", "plain", None, None, ID, None).is_ok());
        for (force, token) in [(false, "IMAGE_REMOVE"), (true, "IMAGE_REMOVE_FORCE")] {
            assert!(ImageRemoveRequest::parse(IMG, force, Some(token), ID, None).is_ok());
        }
        // The plain token never authorises a forced removal.
        assert_eq!(
            ImageRemoveRequest::parse(IMG, true, Some("IMAGE_REMOVE"), ID, None).unwrap_err(),
            RequestError::InvalidConfirmation
        );
        assert_eq!(
            VolumeRemoveRequest::parse("data", Some("IMAGE_REMOVE"), ID, None).unwrap_err(),
            RequestError::InvalidConfirmation
        );
        assert!(VolumeRemoveRequest::parse("data", Some("VOLUME_REMOVE"), ID, None).is_ok());
    }

    #[test]
    fn request_validation() {
        for bad in ["", "-x", "a b", "a;b", "a/b", "../x", &"a".repeat(129)] {
            assert_eq!(
                NetworkRequest::parse("create", bad, None, None, ID, None).unwrap_err(),
                RequestError::InvalidName,
                "{bad:?}"
            );
            assert_eq!(
                VolumeRemoveRequest::parse(bad, Some("VOLUME_REMOVE"), ID, None).unwrap_err(),
                RequestError::InvalidName,
                "{bad:?}"
            );
        }
        assert_eq!(
            NetworkRequest::parse("create", "n", Some("weave"), None, ID, None).unwrap_err(),
            RequestError::InvalidDriver
        );
        assert_eq!(
            NetworkRequest::parse(
                "remove",
                "n",
                Some("bridge"),
                Some("NETWORK_REMOVE"),
                ID,
                None
            )
            .unwrap_err(),
            RequestError::InvalidDriver
        );
        assert_eq!(
            NetworkRequest::parse("prune", "n", None, None, ID, None).unwrap_err(),
            RequestError::InvalidAction
        );
        for bad in [
            "short",
            "UPPERCASE1234",
            "cccccccccccc;ls",
            "--all",
            "sha256:cccccccccccc",
        ] {
            assert_eq!(
                ImageRemoveRequest::parse(bad, false, Some("IMAGE_REMOVE"), ID, None).unwrap_err(),
                RequestError::InvalidImageId,
                "{bad}"
            );
        }
    }

    #[test]
    fn image_references_and_the_registry_allowlist() {
        for ok in [
            "nginx",
            "nginx:1.27",
            "library/nginx:1.27-alpine",
            "ghcr.io/local-control-panel/frankenphp:latest",
            "docker.io/library/redis@sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "quay.io/prometheus/node-exporter:v1.8.2",
            "mcr.microsoft.com/dotnet/runtime:8.0",
        ] {
            assert!(ImageReference::parse(ok).is_ok(), "{ok}");
        }
        for (bad, why) in [
            ("", RequestError::InvalidReference),
            ("-nginx", RequestError::InvalidReference),
            ("nginx latest", RequestError::InvalidReference),
            ("nginx;ls", RequestError::InvalidReference),
            ("Nginx", RequestError::InvalidReference),
            ("nginx:", RequestError::InvalidReference),
            ("nginx:-x", RequestError::InvalidReference),
            ("a//b", RequestError::InvalidReference),
            ("nginx@sha256:abc", RequestError::InvalidReference),
            ("nginx@md5:00", RequestError::InvalidReference),
            ("evil.example.com/x/y:1", RequestError::RegistryNotAllowed),
            ("localhost/x", RequestError::RegistryNotAllowed),
            ("localhost:5000/x", RequestError::RegistryNotAllowed),
            ("ghcr.io.evil.com/x", RequestError::RegistryNotAllowed),
        ] {
            assert_eq!(ImageReference::parse(bad).unwrap_err(), why, "{bad:?}");
        }
    }

    #[test]
    fn network_create_runs_the_fixed_argv_and_replays() {
        let _g = SERIAL.lock().unwrap();
        let f = Fixture::new(0);
        let state = f.state();
        let c = ctx(&f, &state, plenty);
        let req = NetworkRequest::parse("create", "app_net", Some("macvlan"), None, ID, Some("k"))
            .unwrap();
        let first = execute_network(&c, &req, &cancel()).unwrap();
        assert_eq!(first.driver.as_deref(), Some("macvlan"));
        assert_eq!(
            f.mutating_calls(),
            ["network create --driver macvlan app_net"]
        );
        let again = execute_network(&c, &req, &cancel()).unwrap();
        assert_eq!(again.completed_at_unix_secs, first.completed_at_unix_secs);
        assert_eq!(
            f.mutating_calls().len(),
            1,
            "a replay must not run docker again"
        );
        // Default driver.
        let req = NetworkRequest::parse("create", "n2", None, None, ID2, None).unwrap();
        execute_network(&c, &req, &cancel()).unwrap();
        assert_eq!(f.mutating_calls()[1], "network create --driver bridge n2");
    }

    #[test]
    fn network_remove_resolves_the_exact_name_and_runs_against_the_id() {
        let _g = SERIAL.lock().unwrap();
        let f = Fixture::new(0);
        let state = f.state();
        let c = ctx(&f, &state, plenty);
        execute_network(&c, &remove_network("plain", ID), &cancel()).unwrap();
        assert_eq!(f.mutating_calls(), [format!("network rm {NET_ID}")]);
        // Docker answering for another network (an id-prefix match) is a miss.
        let err = execute_network(&c, &remove_network("other", ID2), &cancel()).unwrap_err();
        assert!(matches!(err, Error::NotFound));
        let err = execute_network(&c, &remove_network("ghost", ID3), &cancel()).unwrap_err();
        assert!(matches!(err, Error::NotFound));
        assert_eq!(f.mutating_calls().len(), 1);
    }

    #[test]
    fn built_in_and_managed_networks_are_refused() {
        let _g = SERIAL.lock().unwrap();
        let f = Fixture::new(0);
        let state = f.state();
        let c = ctx(&f, &state, plenty);
        for (i, name) in ["bridge", "host", "none", "managed_default"]
            .iter()
            .enumerate()
        {
            let id = format!("123e4567-e89b-12d3-a456-4266141740{:02}", 10 + i);
            let err = execute_network(&c, &remove_network(name, &id), &cancel()).unwrap_err();
            assert!(matches!(err, Error::Refused(_)), "{name}");
            assert_eq!(err.protocol().0, ErrorCode::InvalidInput);
        }
        assert!(f.mutating_calls().is_empty());
    }

    #[test]
    fn a_rejected_docker_call_is_recorded_and_replayed() {
        let _g = SERIAL.lock().unwrap();
        let f = Fixture::new(1);
        let state = f.state();
        let c = ctx(&f, &state, plenty);
        let req = remove_network("plain", ID);
        let first = execute_network(&c, &req, &cancel()).unwrap_err();
        assert_eq!(first.protocol().0, ErrorCode::SubprocessFailed);
        let calls = f.calls().len();
        let again = execute_network(&c, &req, &cancel()).unwrap_err();
        assert!(matches!(again, Error::Replayed { .. }));
        assert_eq!(f.calls().len(), calls, "a replay must not call docker");
    }

    #[test]
    fn image_remove_uses_the_full_id_and_the_force_flag() {
        let _g = SERIAL.lock().unwrap();
        let f = Fixture::new(0);
        let state = f.state();
        let c = ctx(&f, &state, plenty);
        let plain = ImageRemoveRequest::parse(IMG, false, Some("IMAGE_REMOVE"), ID, None).unwrap();
        let done = execute_image_remove(&c, &plain, &cancel()).unwrap();
        assert_eq!(done.image_id, IMG_FULL);
        let forced =
            ImageRemoveRequest::parse(IMG, true, Some("IMAGE_REMOVE_FORCE"), ID2, None).unwrap();
        execute_image_remove(&c, &forced, &cancel()).unwrap();
        assert_eq!(
            f.mutating_calls(),
            [format!("rmi {IMG_FULL}"), format!("rmi -f {IMG_FULL}")]
        );
    }

    #[test]
    fn an_image_used_by_the_managed_stack_is_refused() {
        let _g = SERIAL.lock().unwrap();
        let f = Fixture::new(0);
        f.image_in_use_by_wcp();
        let state = f.state();
        let c = ctx(&f, &state, plenty);
        let req =
            ImageRemoveRequest::parse(IMG, true, Some("IMAGE_REMOVE_FORCE"), ID, None).unwrap();
        let err = execute_image_remove(&c, &req, &cancel()).unwrap_err();
        assert!(matches!(err, Error::Refused(_)));
        assert!(f.mutating_calls().is_empty());
    }

    #[test]
    fn unknown_or_mismatched_images_are_not_found() {
        let _g = SERIAL.lock().unwrap();
        let f = Fixture::new(0);
        let state = f.state();
        let c = ctx(&f, &state, plenty);
        for (i, id) in ["bbbbbbbbbbbb", "dddddddddddd"].iter().enumerate() {
            let request = format!("123e4567-e89b-12d3-a456-4266141740{:02}", 20 + i);
            let req =
                ImageRemoveRequest::parse(id, false, Some("IMAGE_REMOVE"), &request, None).unwrap();
            assert!(matches!(
                execute_image_remove(&c, &req, &cancel()).unwrap_err(),
                Error::NotFound
            ));
        }
        assert!(f.mutating_calls().is_empty());
    }

    #[test]
    fn image_remove_takes_the_stack_lock() {
        let _g = SERIAL.lock().unwrap();
        let f = Fixture::new(0);
        let state = f.state();
        let c = ctx(&f, &state, plenty);
        let stack_scope = crate::stack_deploy::open_scope(&state).unwrap();
        let held =
            crate::stack_deploy::acquire_stack_lock(&stack_scope, RequestId::parse(ID3).unwrap())
                .map_err(|_| ())
                .unwrap();
        let req =
            ImageRemoveRequest::parse(IMG, false, Some("IMAGE_REMOVE"), ID, Some("k")).unwrap();
        let err = execute_image_remove(&c, &req, &cancel()).unwrap_err();
        assert!(matches!(err, Error::StackBusy));
        assert_eq!(err.protocol().0, ErrorCode::Conflict);
        assert!(f.calls().is_empty());
        drop(held);
        // A busy stack was not a recorded transaction: the same key now runs.
        execute_image_remove(&c, &req, &cancel()).unwrap();
        // The other operations never wait for the stack.
        let held =
            crate::stack_deploy::acquire_stack_lock(&stack_scope, RequestId::parse(ID3).unwrap())
                .map_err(|_| ())
                .unwrap();
        execute_network(&c, &remove_network("plain", ID2), &cancel()).unwrap();
        drop(held);
    }

    #[test]
    fn volume_remove_refuses_attached_and_managed_volumes() {
        let _g = SERIAL.lock().unwrap();
        let f = Fixture::new(0);
        let state = f.state();
        let c = ctx(&f, &state, plenty);
        let remove = |name: &str, request: &str| {
            execute_volume_remove(
                &c,
                &VolumeRemoveRequest::parse(name, Some("VOLUME_REMOVE"), request, None).unwrap(),
                &cancel(),
            )
        };
        assert!(matches!(remove("used", ID).unwrap_err(), Error::Refused(_)));
        assert!(matches!(
            remove("wcp_db", ID2).unwrap_err(),
            Error::Refused(_)
        ));
        assert!(matches!(remove("ghost", ID3).unwrap_err(), Error::NotFound));
        assert!(f.mutating_calls().is_empty());
        remove("data", "123e4567-e89b-12d3-a456-426614174009").unwrap();
        assert_eq!(f.mutating_calls(), ["volume rm data"]);
    }

    #[test]
    fn pull_checks_free_space_first() {
        let _g = SERIAL.lock().unwrap();
        let f = Fixture::new(0);
        let state = f.state();
        let req = PullRequest::parse("nginx:1.27", ID, Some("k")).unwrap();
        let err = execute_pull(&ctx(&f, &state, scarce), &req, &cancel()).unwrap_err();
        assert!(matches!(err, Error::DiskLow));
        assert_eq!(err.protocol().0, ErrorCode::DependencyUnavailable);
        assert!(f.mutating_calls().is_empty());
        // The failure is recorded; a new request id runs once there is space.
        let req = PullRequest::parse("nginx:1.27", ID2, Some("k2")).unwrap();
        let done = execute_pull(&ctx(&f, &state, plenty), &req, &cancel()).unwrap();
        assert_eq!(done.reference, "nginx:1.27");
        assert_eq!(f.mutating_calls(), ["pull nginx:1.27"]);
    }

    #[test]
    fn pull_returns_only_the_tail_of_a_long_output() {
        let long = format!("{}\nDigest: sha256:abc\n", "layer\n".repeat(10_000));
        let (tail, truncated) = tail_of(&long, PULL_OUTPUT_LIMIT);
        assert!(truncated);
        assert!(tail.len() <= PULL_OUTPUT_LIMIT);
        assert!(tail.ends_with("Digest: sha256:abc\n"));
        assert_eq!(tail_of("short", 100), ("short".to_owned(), false));
        // A cut inside a multi-byte character moves forward.
        let (tail, _) = tail_of("ééééé", 3);
        assert!(tail.chars().all(|c| c == 'é'));
    }

    #[cfg(unix)]
    #[test]
    fn statvfs_reports_free_space_for_a_real_directory() {
        let free = statvfs_free_bytes("/").unwrap();
        assert!(free > 0);
        assert!(statvfs_free_bytes("/definitely/not/here").is_err());
    }
}
