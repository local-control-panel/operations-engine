//! `journal.append` and `journal.list`: the server-side change journal
//! ("who changed what on which site, when, with which result").
//!
//! The engine is the source of truth; the panel reads it and may keep its
//! own copy. The journal is deliberately **not** a transaction: it has its
//! own small lock, records only bounded identifiers and a short redacted
//! summary, and never carries secrets, one-time login links or request
//! bodies. For a one-time admin login only the fact (`cms.adminLogin`) and
//! the admin user (`target`) are recorded, never the link.
//!
//! Storage (below the engine state root, root-owned):
//!
//! ```text
//! journal/                      0700
//!   journal.lock                0600  flock target, serializes append/list/rotation
//!   events.jsonl                0600  active segment, one JSON object per line
//!   events.<lastSeq:020>.jsonl  0600  rotated segments, named by their last `seq`
//! ```
//!
//! - **Append-only JSON Lines**, written with one `write` under the lock. A
//!   crash can leave a torn last line; the next append starts on a fresh
//!   line and every reader skips (and counts) lines it cannot parse.
//! - **Bounded**: a segment rotates at [`MAX_SEGMENT_BYTES`], at most
//!   [`MAX_SEGMENTS`] rotated segments are kept and a rotated segment older
//!   than [`RETENTION`] is removed, so the journal never exceeds roughly
//!   `(MAX_SEGMENTS + 1) * MAX_SEGMENT_BYTES`.
//! - **`seq`** is a gap-tolerant, strictly increasing counter assigned under
//!   the lock (recovered from the newest valid line); it is the pagination
//!   cursor.
//! - **Idempotency**: the request id is the entry id. A retry carrying the
//!   same request id (or the same idempotency key) as an entry in the recent
//!   tail of the active segment returns that entry with `replayed: true`
//!   instead of writing a second one.
//!
//! Validation is closed, not best-effort: every field has a charset and a
//! length bound, `action` is a namespaced name from a closed set of
//! namespaces, and the only free-text field (`summary`) is rejected (never
//! silently rewritten, never echoed back) when it looks like a URL, a
//! `key=value` secret, a bearer/authorization value or a long opaque token.

use std::{
    io::{self, Read, Seek, SeekFrom, Write},
    os::fd::AsRawFd,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{
    filesystem::ManagedRoot,
    site::SiteRelativePath,
    transaction::{IdempotencyKey, RequestId},
};

pub const APPEND_OPERATION: &str = "journal.append";
pub const LIST_OPERATION: &str = "journal.list";

pub const SCHEMA_VERSION: u32 = 1;
const DIR: &str = "journal";
const ACTIVE: &str = "events.jsonl";
const LOCK: &str = "journal.lock";
const ROTATED_PREFIX: &str = "events.";
const ROTATED_SUFFIX: &str = ".jsonl";

/// A segment is rotated before an append that would grow it past this.
pub const MAX_SEGMENT_BYTES: u64 = 2 * 1024 * 1024;
/// Rotated segments kept besides the active one.
pub const MAX_SEGMENTS: usize = 10;
/// A rotated segment not written for this long is removed.
pub const RETENTION: Duration = Duration::from_secs(400 * 24 * 60 * 60);
/// One serialized entry never exceeds this (the field bounds make it
/// unreachable; the check keeps `write` atomic by construction).
pub const MAX_LINE_BYTES: usize = 2048;
/// How much of the active segment's end an append inspects for the last
/// `seq` and for a replayed request.
const TAIL_BYTES: u64 = 256 * 1024;
const LOCK_WAIT: Duration = Duration::from_secs(3);

pub const LIST_DEFAULT_LIMIT: usize = 50;
pub const LIST_MAX_LIMIT: usize = 200;

pub const MAX_ACTOR_LEN: usize = 64;
pub const MAX_ACTION_LEN: usize = 64;
pub const MAX_SITE_LEN: usize = 64;
pub const MAX_OPERATION_ID_LEN: usize = 64;
pub const MAX_TARGET_LEN: usize = 64;
pub const MAX_ERROR_CODE_LEN: usize = 48;
pub const MAX_SUMMARY_CHARS: usize = 200;

/// First `action` segment. Closed on purpose: a new area of the product adds
/// its namespace here (and in `docs/protocol.md`), a typo is rejected.
pub const ACTION_NAMESPACES: &[&str] = &[
    "agent",
    "auth",
    "backup",
    "cms",
    "compose",
    "cron",
    "db",
    "docker",
    "drupal",
    "engine",
    "file",
    "ingress",
    "joomla",
    "panel",
    "runtime",
    "site",
    "stack",
    "system",
    "tool",
    "wordpress",
];

/// Whether an entry was supplied through `journal.append` or written by the
/// engine itself for one of its own operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Api,
    Engine,
}

impl Source {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "api" => Some(Self::Api),
            "engine" => Some(Self::Engine),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JournalResult {
    Ok,
    Failed,
    Denied,
    Cancelled,
}

impl JournalResult {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "ok" => Some(Self::Ok),
            "failed" => Some(Self::Failed),
            "denied" => Some(Self::Denied),
            "cancelled" => Some(Self::Cancelled),
            _ => None,
        }
    }
}

/// A rejected field. The message names the field only, never the value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rejected(pub &'static str);

impl Rejected {
    pub fn message(&self) -> &'static str {
        self.0
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum JournalError {
    /// The journal lock stayed busy for [`LOCK_WAIT`].
    Busy,
    Io,
}

/// Unvalidated `journal.append` fields.
#[derive(Clone, Copy, Debug, Default)]
pub struct RawEntry<'a> {
    pub actor: &'a str,
    pub action: &'a str,
    pub result: &'a str,
    pub site: Option<&'a str>,
    pub operation_id: Option<&'a str>,
    pub target: Option<&'a str>,
    pub error_code: Option<&'a str>,
    pub summary: Option<&'a str>,
}

/// A validated entry body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewEntry {
    actor: String,
    action: String,
    result: JournalResult,
    site: Option<String>,
    operation_id: Option<String>,
    target: Option<String>,
    error_code: Option<String>,
    summary: Option<String>,
}

impl NewEntry {
    pub fn parse(raw: RawEntry<'_>) -> Result<Self, Rejected> {
        let actor = token(
            raw.actor,
            MAX_ACTOR_LEN,
            "@:+",
            Rejected("actor is invalid"),
        )?;
        let action = action_name(raw.action)?;
        let result = JournalResult::parse(raw.result).ok_or(Rejected("result is invalid"))?;
        let site = raw
            .site
            .map(|v| token(v, MAX_SITE_LEN, "", Rejected("site is invalid")))
            .transpose()?;
        let operation_id = raw
            .operation_id
            .map(|v| {
                token(
                    v,
                    MAX_OPERATION_ID_LEN,
                    ":",
                    Rejected("operation-id is invalid"),
                )
            })
            .transpose()?;
        let target = raw
            .target
            .map(|v| token(v, MAX_TARGET_LEN, "@:+", Rejected("target is invalid")))
            .transpose()?;
        let error_code = raw.error_code.map(error_code).transpose()?;
        let summary = raw.summary.map(summary).transpose()?;
        Ok(Self {
            actor,
            action,
            result,
            site,
            operation_id,
            target,
            error_code,
            summary,
        })
    }
}

/// Characters allowed in every identifier-like field besides the extra set.
fn token(value: &str, max: usize, extra: &str, rejected: Rejected) -> Result<String, Rejected> {
    if value.is_empty()
        || value.len() > max
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') || extra.contains(c))
        || longest_opaque_run(value) >= 40
    {
        return Err(rejected);
    }
    Ok(value.to_owned())
}

fn error_code(value: &str) -> Result<String, Rejected> {
    if value.is_empty()
        || value.len() > MAX_ERROR_CODE_LEN
        || !value
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err(Rejected("error-code is invalid"));
    }
    Ok(value.to_owned())
}

/// `namespace.name[.name[.name]]`: a closed namespace, then camelCase
/// segments (`cms.adminLogin`, `wordpress.updateCore`, `site.deploy`).
fn action_name(value: &str) -> Result<String, Rejected> {
    let rejected = Rejected("action is invalid");
    if value.len() > MAX_ACTION_LEN {
        return Err(rejected);
    }
    let segments: Vec<&str> = value.split('.').collect();
    if !(2..=4).contains(&segments.len()) || !ACTION_NAMESPACES.contains(&segments[0]) {
        return Err(rejected);
    }
    for segment in &segments {
        let mut chars = segment.chars();
        let first_ok = chars.next().is_some_and(|c| c.is_ascii_lowercase());
        if !first_ok || segment.len() > 24 || !chars.all(|c| c.is_ascii_alphanumeric()) {
            return Err(rejected);
        }
    }
    Ok(value.to_owned())
}

/// Length of the longest run of base64/hex-looking characters.
fn longest_opaque_run(value: &str) -> usize {
    let mut longest = 0;
    let mut current = 0;
    for c in value.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=') {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 0;
        }
    }
    longest
}

const SECRET_WORDS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "api_key",
    "api-key",
    "authorization",
    "cookie",
    "credential",
    "private key",
    "privatekey",
    "nonce",
    "signature",
];

const SECRET_PREFIXES: &[&str] = &[
    "eyj",
    "akia",
    "ghp_",
    "gho_",
    "github_pat_",
    "xoxb-",
    "xoxp-",
];

/// Rejects free text that could carry a secret or a link with credentials.
fn summary(value: &str) -> Result<String, Rejected> {
    let rejected = Rejected("summary is not allowed");
    if value.is_empty()
        || value.chars().count() > MAX_SUMMARY_CHARS
        || value.chars().any(char::is_control)
    {
        return Err(rejected);
    }
    let lower = value.to_ascii_lowercase();
    if lower.contains("://")
        || lower.contains("www.")
        || lower.contains("bearer ")
        || lower.contains("-----begin")
        || longest_opaque_run(value) >= 32
        || has_query_pair(&lower)
        || has_secret_assignment(&lower)
        || lower
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
            .any(|word| SECRET_PREFIXES.iter().any(|p| word.starts_with(p)))
    {
        return Err(rejected);
    }
    Ok(value.to_owned())
}

/// `?name=` or `&name=`: a URL query string.
fn has_query_pair(lower: &str) -> bool {
    let bytes = lower.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(byte, b'?' | b'&') {
            let rest = &bytes[index + 1..];
            let name = rest
                .iter()
                .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
                .count();
            if name > 0 && rest.get(name) == Some(&b'=') {
                return true;
            }
        }
    }
    false
}

/// A secret-looking word followed by `=` or `:` (`password=…`, `token: …`).
fn has_secret_assignment(lower: &str) -> bool {
    SECRET_WORDS.iter().any(|word| {
        lower.match_indices(word).any(|(index, _)| {
            lower[index + word.len()..]
                .trim_start_matches([' ', '"', '\''])
                .starts_with(['=', ':'])
        })
    })
}

/// One stored journal line.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub schema_version: u32,
    pub seq: u64,
    /// The request id of the `journal.append` call (or of the engine
    /// operation, for [`Source::Engine`] entries).
    pub id: RequestId,
    pub at_unix_secs: u64,
    pub source: Source,
    pub actor: String,
    pub action: String,
    pub result: JournalResult,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppendOutcome {
    pub entry: Entry,
    /// True when the request had already been recorded and nothing was
    /// written.
    pub replayed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListOutcome {
    pub entries: Vec<Entry>,
    /// Pass as `--before-seq` to get the next (older) page; absent on the
    /// last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<u64>,
    /// Lines that exist but could not be parsed; never silently dropped.
    pub skipped: usize,
}

fn rel(path: impl AsRef<std::path::Path>) -> SiteRelativePath {
    SiteRelativePath::parse(path).expect("journal paths are fixed and valid")
}

pub fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn rotated_name(last_seq: u64) -> String {
    format!("{ROTATED_PREFIX}{last_seq:020}{ROTATED_SUFFIX}")
}

fn rotated_seq(name: &str) -> Option<u64> {
    let digits = name
        .strip_prefix(ROTATED_PREFIX)?
        .strip_suffix(ROTATED_SUFFIX)?;
    (digits.len() == 20 && digits.bytes().all(|b| b.is_ascii_digit()))
        .then(|| digits.parse().ok())
        .flatten()
}

/// Rotated segment names with their last `seq`, oldest first.
fn rotated_segments(dir: &ManagedRoot) -> io::Result<Vec<(u64, String)>> {
    let mut segments: Vec<(u64, String)> = dir
        .file_names()?
        .into_iter()
        .filter_map(|name| rotated_seq(&name).map(|seq| (seq, name)))
        .collect();
    segments.sort();
    Ok(segments)
}

struct LockGuard(std::fs::File);

impl Drop for LockGuard {
    fn drop(&mut self) {
        // SAFETY: the descriptor is open until this returns.
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn lock(dir: &ManagedRoot) -> Result<LockGuard, JournalError> {
    create_private(dir, &rel(LOCK))?;
    let file = dir
        .open_or_create_file(&rel(LOCK))
        .map_err(|_| JournalError::Io)?;
    let started = Instant::now();
    loop {
        // SAFETY: the descriptor is open for the duration of the call.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            return Ok(LockGuard(file));
        }
        if io::Error::last_os_error().kind() != io::ErrorKind::WouldBlock {
            return Err(JournalError::Io);
        }
        if started.elapsed() >= LOCK_WAIT {
            return Err(JournalError::Busy);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Creates `path` with mode 0600 when missing and makes sure an existing
/// file is not readable by anyone else.
fn create_private(dir: &ManagedRoot, path: &SiteRelativePath) -> Result<(), JournalError> {
    match dir.create_new_file_with_mode(path, 0o600) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if dir.mode(path).map_err(|_| JournalError::Io)? != 0o600 {
                dir.set_mode(path, 0o600).map_err(|_| JournalError::Io)?;
            }
        }
        Err(_) => return Err(JournalError::Io),
    }
    Ok(())
}

/// Opens (creating, 0700) the journal directory below the state root.
fn open_dir(state: &ManagedRoot, create: bool) -> Result<Option<ManagedRoot>, JournalError> {
    let path = rel(DIR);
    if create {
        state.create_dir_all(&path).map_err(|_| JournalError::Io)?;
        if state.mode(&path).map_err(|_| JournalError::Io)? != 0o700 {
            state.set_mode(&path, 0o700).map_err(|_| JournalError::Io)?;
        }
    }
    match state.open_managed_dir(&path) {
        Ok(dir) => Ok(Some(dir)),
        Err(error) if error.kind() == io::ErrorKind::NotFound && !create => Ok(None),
        Err(_) => Err(JournalError::Io),
    }
}

/// Reads at most the last `max` bytes of `file`. When the start was cut off,
/// the first (partial) line is dropped.
fn read_tail(file: &mut std::fs::File, max: u64) -> io::Result<Vec<u8>> {
    let len = file.metadata()?.len();
    let start = len.saturating_sub(max);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::with_capacity((len - start) as usize);
    file.take(max).read_to_end(&mut bytes)?;
    if start > 0 {
        match bytes.iter().position(|b| *b == b'\n') {
            Some(index) => {
                bytes.drain(..=index);
            }
            None => bytes.clear(),
        }
    }
    Ok(bytes)
}

fn parse_lines(bytes: &[u8]) -> (Vec<Entry>, usize) {
    let mut entries = Vec::new();
    let mut skipped = 0;
    for line in bytes.split(|b| *b == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        match serde_json::from_slice::<Entry>(line) {
            Ok(entry) if entry.schema_version >= 1 => entries.push(entry),
            _ => skipped += 1,
        }
    }
    (entries, skipped)
}

/// Appends one entry. `now` is the engine clock; callers cannot choose it.
pub fn append(
    state: &ManagedRoot,
    entry: &NewEntry,
    request_id: RequestId,
    idempotency_key: Option<&IdempotencyKey>,
    source: Source,
    now: u64,
) -> Result<AppendOutcome, JournalError> {
    append_with(
        state,
        entry,
        request_id,
        idempotency_key,
        source,
        now,
        &Limits::DEFAULT,
    )
}

/// Rotation limits; tests shrink them.
pub struct Limits {
    pub segment_bytes: u64,
    pub segments: usize,
}

impl Limits {
    pub const DEFAULT: Self = Self {
        segment_bytes: MAX_SEGMENT_BYTES,
        segments: MAX_SEGMENTS,
    };
}

pub fn append_with(
    state: &ManagedRoot,
    entry: &NewEntry,
    request_id: RequestId,
    idempotency_key: Option<&IdempotencyKey>,
    source: Source,
    now: u64,
    limits: &Limits,
) -> Result<AppendOutcome, JournalError> {
    let dir = open_dir(state, true)?.ok_or(JournalError::Io)?;
    let _guard = lock(&dir)?;
    let active = rel(ACTIVE);
    create_private(&dir, &active)?;
    let mut file = dir
        .open_or_create_file(&active)
        .map_err(|_| JournalError::Io)?;
    let len = file.metadata().map_err(|_| JournalError::Io)?.len();
    let tail = read_tail(&mut file, TAIL_BYTES).map_err(|_| JournalError::Io)?;
    let (recent, _) = parse_lines(&tail);

    let key = idempotency_key.map(IdempotencyKey::as_str);
    if let Some(existing) = recent
        .iter()
        .rev()
        .find(|e| e.id == request_id || (key.is_some() && e.idempotency_key.as_deref() == key))
    {
        return Ok(AppendOutcome {
            entry: existing.clone(),
            replayed: true,
        });
    }

    let rotated = rotated_segments(&dir).map_err(|_| JournalError::Io)?;
    let last_seq = recent
        .iter()
        .map(|e| e.seq)
        .chain(rotated.last().map(|(seq, _)| *seq))
        .max()
        .unwrap_or(0);
    let stored = Entry {
        schema_version: SCHEMA_VERSION,
        seq: last_seq + 1,
        id: request_id,
        at_unix_secs: now,
        source,
        actor: entry.actor.clone(),
        action: entry.action.clone(),
        result: entry.result,
        site: entry.site.clone(),
        operation_id: entry.operation_id.clone(),
        target: entry.target.clone(),
        error_code: entry.error_code.clone(),
        summary: entry.summary.clone(),
        idempotency_key: key.map(str::to_owned),
    };
    let mut line = serde_json::to_vec(&stored).map_err(|_| JournalError::Io)?;
    line.push(b'\n');
    if line.len() > MAX_LINE_BYTES {
        return Err(JournalError::Io);
    }
    // A torn last line (crash mid-write) must not swallow this entry.
    let mut buffer = Vec::with_capacity(line.len() + 1);
    let torn = len > 0 && tail.last().is_some_and(|b| *b != b'\n');
    if torn {
        buffer.push(b'\n');
    }
    buffer.extend_from_slice(&line);

    if len > 0 && len + buffer.len() as u64 > limits.segment_bytes {
        let target = rel(rotated_name(last_seq));
        if !dir.exists(&target) {
            drop(file);
            dir.rename(&active, &target).map_err(|_| JournalError::Io)?;
            create_private(&dir, &active)?;
            file = dir
                .open_or_create_file(&active)
                .map_err(|_| JournalError::Io)?;
            // The torn-line guard belongs to the old segment.
            if torn {
                buffer.remove(0);
            }
            prune(&dir, now, limits.segments);
        }
    }

    file.seek(SeekFrom::End(0)).map_err(|_| JournalError::Io)?;
    file.write_all(&buffer).map_err(|_| JournalError::Io)?;
    file.sync_data().map_err(|_| JournalError::Io)?;
    Ok(AppendOutcome {
        entry: stored,
        replayed: false,
    })
}

/// Best-effort retention: oldest segments beyond the count cap and
/// segments past the age cap.
fn prune(dir: &ManagedRoot, now: u64, max_segments: usize) {
    let Ok(mut segments) = rotated_segments(dir) else {
        return;
    };
    while segments.len() > max_segments {
        let (_, name) = segments.remove(0);
        let _ = dir.remove_file(&rel(name));
    }
    for (_, name) in segments {
        let path = rel(&name);
        let old = dir
            .modified(&path)
            .ok()
            .and_then(|m| m.duration_since(UNIX_EPOCH).ok())
            .is_some_and(|m| m.as_secs().saturating_add(RETENTION.as_secs()) < now);
        if old {
            let _ = dir.remove_file(&path);
        }
    }
}

/// `journal.list` filters. All are optional; a page is newest first.
#[derive(Clone, Debug, Default)]
pub struct Query {
    pub site: Option<String>,
    pub since_unix_secs: Option<u64>,
    pub action_prefix: Option<String>,
    pub result: Option<JournalResult>,
    pub source: Option<Source>,
    pub limit: Option<usize>,
    /// Only entries with a smaller `seq` (the previous page's `nextCursor`).
    pub before_seq: Option<u64>,
}

impl Query {
    pub fn validate(&self) -> Result<(), Rejected> {
        if let Some(site) = &self.site {
            token(site, MAX_SITE_LEN, "", Rejected("site is invalid"))?;
        }
        if let Some(prefix) = &self.action_prefix {
            if prefix.is_empty()
                || prefix.len() > MAX_ACTION_LEN
                || !prefix
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.')
            {
                return Err(Rejected("action-prefix is invalid"));
            }
        }
        Ok(())
    }

    fn matches(&self, entry: &Entry) -> bool {
        self.site
            .as_deref()
            .is_none_or(|s| entry.site.as_deref() == Some(s))
            && self.since_unix_secs.is_none_or(|t| entry.at_unix_secs >= t)
            && self
                .action_prefix
                .as_deref()
                .is_none_or(|p| entry.action.starts_with(p))
            && self.result.is_none_or(|r| entry.result == r)
            && self.source.is_none_or(|s| entry.source == s)
            && self.before_seq.is_none_or(|b| entry.seq < b)
    }
}

/// Newest-first page of entries. Reads under the journal lock so a rotation
/// cannot move a segment mid-read. A journal that was never written is an
/// empty list and creates nothing.
pub fn list(state: &ManagedRoot, query: &Query) -> Result<ListOutcome, JournalError> {
    let empty = ListOutcome {
        entries: Vec::new(),
        next_cursor: None,
        skipped: 0,
    };
    let Some(dir) = open_dir(state, false)? else {
        return Ok(empty);
    };
    let _guard = lock(&dir)?;
    let limit = query
        .limit
        .unwrap_or(LIST_DEFAULT_LIMIT)
        .clamp(1, LIST_MAX_LIMIT);

    let rotated = rotated_segments(&dir).map_err(|_| JournalError::Io)?;
    // Newest first: the active segment, then rotated ones descending. Each
    // segment's smallest possible `seq` is its predecessor's last + 1.
    let mut order: Vec<(String, u64)> = Vec::new();
    let newest_rotated = rotated.last().map_or(0, |(seq, _)| *seq);
    order.push((ACTIVE.to_owned(), newest_rotated));
    for (index, (_, name)) in rotated.iter().enumerate().rev() {
        let previous = index.checked_sub(1).map_or(0, |i| rotated[i].0);
        order.push((name.clone(), previous));
    }

    let mut out = Vec::new();
    let mut skipped = 0;
    let mut more = false;
    'segments: for (name, previous_last) in order {
        if query
            .before_seq
            .is_some_and(|before| previous_last.saturating_add(1) >= before)
        {
            continue;
        }
        let path = rel(&name);
        if let (true, Some(since)) = (name != ACTIVE, query.since_unix_secs) {
            let modified = dir
                .modified(&path)
                .ok()
                .and_then(|m| m.duration_since(UNIX_EPOCH).ok())
                .map(|m| m.as_secs());
            if modified.is_some_and(|m| m < since) {
                break;
            }
        }
        let mut file = match dir.open_read(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => return Err(JournalError::Io),
        };
        let bytes = read_tail(&mut file, MAX_SEGMENT_BYTES * 2).map_err(|_| JournalError::Io)?;
        let (mut entries, bad) = parse_lines(&bytes);
        skipped += bad;
        entries.sort_by_key(|e| std::cmp::Reverse(e.seq));
        entries.dedup_by_key(|e| e.seq);
        for entry in entries {
            if !query.matches(&entry) {
                continue;
            }
            if out.len() == limit {
                more = true;
                break 'segments;
            }
            out.push(entry);
        }
    }
    let next_cursor = more.then(|| out.last().map(|e| e.seq)).flatten();
    Ok(ListOutcome {
        entries: out,
        next_cursor,
        skipped,
    })
}

pub mod auto;

#[cfg(test)]
mod tests;
