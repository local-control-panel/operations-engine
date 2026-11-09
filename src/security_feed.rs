//! Consumer of the public security feed (`/feed/v1/index.json` and the
//! manifest it points to), check only: it fetches, validates and records
//! what the publisher announced. It never runs a fix, downloads a payload or
//! decides that a machine is affected or safe.
//!
//! Nothing leaves the machine unless the server policy is `checkOnly`
//! (default `off`). One refresh is at most two plain GETs of the configured
//! origin, with `User-Agent: ops-engine` and no identifier, cookie or result.
//!
//! The validation follows the publisher's feed contract: the production HTTPS
//! origin only (no redirect is followed; a plain-HTTP loopback origin is
//! accepted for tests), bounded sizes, SHA-256 of the exact manifest bytes
//! before they are parsed, a strictly checked manifest path, consistent
//! `sequence` and times between index and manifest, a persisted highest
//! `sequence` with its manifest hash (a lower sequence, or another hash at the
//! same sequence, is a replay/tamper error that never moves the accepted
//! state), and an `expiresAt` that a `304` does not extend. An expired feed or
//! an unreachable origin means freshness is unknown, never that the machine
//! is safe.

use crate::{
    filesystem::ManagedRoot,
    site::SiteRelativePath,
    transaction::{RequestId, resource_lock},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub const REFRESH: &str = "security.refresh";
pub const STATUS: &str = "security.status";
pub const HISTORY: &str = "security.history";
pub const SET_POLICY: &str = "security.setPolicy";

pub const DEFAULT_ORIGIN: &str = "https://updates.orbden.com";
pub const ORIGIN_ENV: &str = "ORBDEN_UPDATES_URL";
const INDEX_PATH: &str = "/feed/v1/index.json";
pub const USER_AGENT: &str = "ops-engine";

const MAX_INDEX_BYTES: u64 = 16 * 1024;
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
/// A clock this early is not a clock: fail closed.
const MIN_PLAUSIBLE_UNIX: i64 = 1_704_067_200; // 2024-01-01
const FUTURE_TOLERANCE_SECS: i64 = 300;
/// The publisher renews at most 31 days ahead; a little slack, no more.
const MAX_VALIDITY_SECS: i64 = 32 * 24 * 3600;
const MAX_ADVISORIES: usize = 500;

const DIR: &str = "security-updates";
const POLICY_FILE: &str = "security-updates/policy.json";
const STATE_FILE: &str = "security-updates/state.json";
const HISTORY_FILE: &str = "security-updates/history.jsonl";
const MAX_HISTORY_ENTRIES: usize = 200;
const MAX_HISTORY_AGE_SECS: i64 = 90 * 24 * 3600;
/// A history file larger than this is not read (it is never this big unless changed by hand).
const MAX_HISTORY_BYTES: usize = 1024 * 1024;
pub const DEFAULT_HISTORY_LIMIT: u32 = 50;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Mode {
    Off,
    CheckOnly,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Policy {
    schema_version: u32,
    mode: Mode,
}

/// What the stored policy says. An unreadable or unknown policy is reported,
/// never read as permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PolicyState {
    Off,
    CheckOnly,
    Invalid,
}

fn rel(path: &str) -> SiteRelativePath {
    SiteRelativePath::parse(path).unwrap()
}

pub fn read_policy(state: &ManagedRoot) -> PolicyState {
    let path = rel(POLICY_FILE);
    if !state.exists(&path) {
        return PolicyState::Off;
    }
    match state
        .read_to_string(&path)
        .ok()
        .and_then(|text| serde_json::from_str::<Policy>(&text).ok())
    {
        Some(Policy {
            schema_version: 1,
            mode: Mode::Off,
        }) => PolicyState::Off,
        Some(Policy {
            schema_version: 1,
            mode: Mode::CheckOnly,
        }) => PolicyState::CheckOnly,
        _ => PolicyState::Invalid,
    }
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Busy,
    PolicyNotEnabled,
}

impl Error {
    pub fn protocol(&self) -> (crate::error::ErrorCode, String) {
        use crate::error::ErrorCode;
        match self {
            Self::Busy => (
                ErrorCode::Conflict,
                "another security feed operation is in progress".into(),
            ),
            Self::PolicyNotEnabled => (
                ErrorCode::InvalidInput,
                "the security updates policy is not checkOnly; nothing was fetched".into(),
            ),
            Self::Io(_) => (ErrorCode::Internal, "internal security feed error".into()),
        }
    }
}

fn lock(
    state: &ManagedRoot,
    holder: RequestId,
) -> Result<crate::transaction::lock::SiteLockGuard<'_>, Error> {
    resource_lock::acquire(state, Path::new("/security-updates"), holder).map_err(|_| Error::Busy)
}

/// Writes the policy. The only mutation of this module; idempotent.
pub fn set_policy(state: &ManagedRoot, mode: Mode, holder: RequestId) -> Result<(), Error> {
    let _guard = lock(state, holder)?;
    state.create_dir_all(&rel(DIR)).map_err(Error::Io)?;
    let body = serde_json::to_vec_pretty(&Policy {
        schema_version: 1,
        mode,
    })
    .unwrap();
    state
        .write_atomic(&rel(POLICY_FILE), &body)
        .map_err(Error::Io)
}

// ---- time -----------------------------------------------------------------

/// `YYYY-MM-DDTHH:MM:SSZ` (UTC, no fractions or offsets) as Unix seconds.
fn parse_utc(value: &str) -> Option<i64> {
    let b = value.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<i64> {
        let part = &value[from..to];
        part.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| part.parse().ok())
            .flatten()
    };
    let (year, month, day) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hour, minute, second) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    // Days from civil (Howard Hinnant's algorithm).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hour * 3600 + minute * 60 + second)
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

// ---- fetching ---------------------------------------------------------------

#[derive(Debug, Eq, PartialEq)]
pub enum FetchError {
    Unreachable,
    TooLarge,
    Redirect,
    Status(u16),
}

pub enum Fetched {
    NotModified,
    Body {
        bytes: Vec<u8>,
        etag: Option<String>,
    },
}

pub trait Fetch {
    fn get(&self, url: &str, max_bytes: u64, etag: Option<&str>) -> Result<Fetched, FetchError>;
}

/// The HTTP fetcher: no proxy from the environment, no redirect followed
/// (a 3xx is an error), HTTPS only (plain HTTP only on loopback, for tests),
/// bounded time and size.
pub struct Http;

impl Fetch for Http {
    fn get(&self, url: &str, max_bytes: u64, etag: Option<&str>) -> Result<Fetched, FetchError> {
        use std::time::Duration;
        let loopback = crate::engine::fetch::is_plain_http_loopback(url);
        let config = ureq::config::Config::builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .timeout_connect(Some(Duration::from_secs(10)))
            .proxy(None)
            .max_redirects(0)
            .https_only(!loopback)
            .http_status_as_error(false)
            .user_agent(USER_AGENT)
            .build();
        let agent = ureq::Agent::new_with_config(config);
        let mut request = agent.get(url);
        if let Some(etag) = etag {
            request = request.header("If-None-Match", etag);
        }
        let mut response = request.call().map_err(|_| FetchError::Unreachable)?;
        match response.status().as_u16() {
            304 => Ok(Fetched::NotModified),
            200 => {
                let etag = response
                    .headers()
                    .get("etag")
                    .and_then(|v| v.to_str().ok())
                    .filter(|v| v.len() <= 256 && v.is_ascii())
                    .map(str::to_owned);
                let bytes = response
                    .body_mut()
                    .with_config()
                    .limit(max_bytes + 1)
                    .read_to_vec()
                    .map_err(|_| FetchError::Unreachable)?;
                if bytes.len() as u64 > max_bytes {
                    return Err(FetchError::TooLarge);
                }
                Ok(Fetched::Body { bytes, etag })
            }
            300..=399 => Err(FetchError::Redirect),
            other => Err(FetchError::Status(other)),
        }
    }
}

// ---- documents ---------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Index {
    schema_version: u32,
    sequence: u64,
    published_at: String,
    expires_at: String,
    manifest: ManifestRef,
}

#[derive(Deserialize)]
struct ManifestRef {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    schema_version: u32,
    sequence: u64,
    published_at: String,
    expires_at: String,
    advisories: Vec<Advisory>,
    revoked: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct Advisory {
    id: String,
    title: String,
    severity: String,
    status: String,
}

/// A path under the origin: `/releases/...json`, plain characters, no
/// traversal, no empty segment, no query or fragment.
fn manifest_path_ok(path: &str) -> bool {
    path.starts_with("/releases/")
        && path.ends_with(".json")
        && path.len() <= 200
        && !path.contains("//")
        && path
            .split('/')
            .skip(1)
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'/' | b'-' | b'_'))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

// ---- state ---------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdvisorySummary {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub status: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Accepted {
    pub sequence: u64,
    pub manifest_sha256: String,
    pub published_at_unix: i64,
    pub expires_at_unix: i64,
    pub advisories: Vec<AdvisorySummary>,
    pub revoked_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index_etag: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LastCheck {
    pub at_unix: i64,
    /// `updated`, `unchanged`, `expired`, `unreachable`, `invalid`, `replay`
    /// or `clockUnreliable`.
    pub result: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct State {
    #[serde(default)]
    pub accepted: Option<Accepted>,
    #[serde(default)]
    pub last_check: Option<LastCheck>,
}

fn load_state(root: &ManagedRoot) -> State {
    root.read_to_string(&rel(STATE_FILE))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

fn save_state(root: &ManagedRoot, state: &State) -> Result<(), Error> {
    root.create_dir_all(&rel(DIR)).map_err(Error::Io)?;
    root.write_atomic(&rel(STATE_FILE), &serde_json::to_vec_pretty(state).unwrap())
        .map_err(Error::Io)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Freshness {
    /// An accepted feed that has not expired.
    Fresh,
    /// An accepted feed past its `expiresAt`.
    Expired,
    /// Nothing accepted yet.
    Unknown,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub policy: PolicyState,
    pub freshness: Freshness,
    pub accepted: Option<Accepted>,
    pub last_check: Option<LastCheck>,
}

pub fn status(state: &ManagedRoot, now: i64) -> Status {
    let stored = load_state(state);
    let freshness = match &stored.accepted {
        Some(accepted) if accepted.expires_at_unix > now => Freshness::Fresh,
        Some(_) => Freshness::Expired,
        None => Freshness::Unknown,
    };
    Status {
        policy: read_policy(state),
        freshness,
        accepted: stored.accepted,
        last_check: stored.last_check,
    }
}

// ---- history -----------------------------------------------------------------------

/// One check, as kept in `history.jsonl`. No URL, body or error text: the
/// result word, the accepted revision at that time and the start of its hash.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryEntry {
    pub at_unix: i64,
    pub result: String,
    pub sequence: Option<u64>,
    pub manifest_prefix: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct History {
    /// `false` when the file exists but cannot be read; then nothing is claimed.
    pub available: bool,
    /// Newest first.
    pub entries: Vec<HistoryEntry>,
    /// Lines that could not be parsed (skipped, never guessed).
    pub unreadable_lines: u32,
}

/// Parses the file text: valid entries in file order and the count of lines
/// that were not valid.
fn parse_history(text: &str) -> (Vec<HistoryEntry>, u32) {
    let mut entries = Vec::new();
    let mut unreadable = 0u32;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        match serde_json::from_str::<HistoryEntry>(line) {
            Ok(entry) => entries.push(entry),
            Err(_) => unreadable = unreadable.saturating_add(1),
        }
    }
    (entries, unreadable)
}

fn read_history_file(root: &ManagedRoot) -> Option<String> {
    match root.read_to_string(&rel(HISTORY_FILE)) {
        Ok(text) if text.len() <= MAX_HISTORY_BYTES => Some(text),
        Ok(_) => None,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(String::new()),
        Err(_) => None,
    }
}

/// Appends one entry and trims to the newest [`MAX_HISTORY_ENTRIES`] within
/// [`MAX_HISTORY_AGE_SECS`]. Best effort: history never decides whether a
/// check succeeded. Invalid lines are dropped when the file is rewritten.
fn record_history(root: &ManagedRoot, entry: HistoryEntry, now: i64) {
    let Some(text) = read_history_file(root) else {
        return;
    };
    let (mut entries, _) = parse_history(&text);
    entries.push(entry);
    entries.retain(|e| e.at_unix >= now - MAX_HISTORY_AGE_SECS);
    let start = entries.len().saturating_sub(MAX_HISTORY_ENTRIES);
    let mut out = String::new();
    for e in &entries[start..] {
        if let Ok(line) = serde_json::to_string(e) {
            out.push_str(&line);
            out.push('\n');
        }
    }
    let _ = root.create_dir_all(&rel(DIR));
    let _ = root.write_atomic_private(&rel(HISTORY_FILE), out.as_bytes());
}

/// The newest `limit` checks (1..=200), newest first. Read-only.
pub fn history(root: &ManagedRoot, limit: u32) -> History {
    let limit = limit.clamp(1, MAX_HISTORY_ENTRIES as u32) as usize;
    let Some(text) = read_history_file(root) else {
        return History {
            available: false,
            entries: Vec::new(),
            unreadable_lines: 0,
        };
    };
    let (mut entries, unreadable_lines) = parse_history(&text);
    entries.reverse();
    entries.truncate(limit);
    History {
        available: true,
        entries,
        unreadable_lines,
    }
}

// ---- refresh -----------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshResult {
    pub result: String,
    pub freshness: Freshness,
    pub sequence: Option<u64>,
}

/// One check. `origin` has no trailing slash. Only called with the policy
/// `checkOnly`; see [`refresh`].
fn check(
    fetch: &dyn Fetch,
    origin: &str,
    now: i64,
    stored: &mut State,
) -> Result<&'static str, &'static str> {
    if now < MIN_PLAUSIBLE_UNIX {
        return Err("clockUnreliable");
    }
    let etag = stored
        .accepted
        .as_ref()
        .and_then(|a| a.index_etag.as_deref());
    let index_bytes = match fetch.get(&format!("{origin}{INDEX_PATH}"), MAX_INDEX_BYTES, etag) {
        Ok(Fetched::NotModified) => {
            // A 304 only says the cached bytes are still current; it does not
            // extend `expiresAt`, which is judged by the status.
            return if stored.accepted.is_some() {
                Ok("unchanged")
            } else {
                Err("invalid")
            };
        }
        Ok(Fetched::Body { bytes, etag }) => (bytes, etag),
        Err(_) => return Err("unreachable"),
    };
    let (bytes, new_etag) = index_bytes;
    let index: Index = serde_json::from_slice(&bytes).map_err(|_| "invalid")?;
    let (published, expires) = match (parse_utc(&index.published_at), parse_utc(&index.expires_at))
    {
        (Some(p), Some(e)) => (p, e),
        _ => return Err("invalid"),
    };
    if index.schema_version != 1
        || index.sequence == 0
        || index.manifest.sha256.len() != 64
        || !index
            .manifest
            .sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || index.manifest.bytes == 0
        || index.manifest.bytes > MAX_MANIFEST_BYTES
        || !manifest_path_ok(&index.manifest.path)
        || expires <= published
        || expires - published > MAX_VALIDITY_SECS
    {
        return Err("invalid");
    }
    if published > now + FUTURE_TOLERANCE_SECS {
        return Err("clockUnreliable");
    }
    // Replay and tamper: judged before the feed's age, so an old signed-looking
    // index can never roll the accepted state back.
    if let Some(accepted) = &stored.accepted {
        if index.sequence < accepted.sequence
            || (index.sequence == accepted.sequence
                && index.manifest.sha256 != accepted.manifest_sha256)
        {
            return Err("replay");
        }
        if index.sequence == accepted.sequence {
            if let Some(accepted) = stored.accepted.as_mut() {
                accepted.index_etag = new_etag;
            }
            return Ok("unchanged");
        }
    }
    if expires <= now {
        return Err("expired");
    }
    let manifest_bytes = match fetch.get(
        &format!("{origin}{}", index.manifest.path),
        index.manifest.bytes,
        None,
    ) {
        Ok(Fetched::Body { bytes, .. }) => bytes,
        Ok(Fetched::NotModified) => return Err("invalid"),
        Err(_) => return Err("unreachable"),
    };
    if manifest_bytes.len() as u64 != index.manifest.bytes
        || hex(&Sha256::digest(&manifest_bytes)) != index.manifest.sha256
    {
        return Err("invalid");
    }
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes).map_err(|_| "invalid")?;
    if manifest.schema_version != 1
        || manifest.sequence != index.sequence
        || manifest.published_at != index.published_at
        || manifest.expires_at != index.expires_at
        || manifest.advisories.len() > MAX_ADVISORIES
        || manifest
            .advisories
            .iter()
            .any(|a| a.id.is_empty() || a.id.len() > 128 || a.title.len() > 512)
    {
        return Err("invalid");
    }
    stored.accepted = Some(Accepted {
        sequence: index.sequence,
        manifest_sha256: index.manifest.sha256,
        published_at_unix: published,
        expires_at_unix: expires,
        advisories: manifest
            .advisories
            .into_iter()
            .map(|a| AdvisorySummary {
                id: a.id,
                title: a.title,
                severity: a.severity,
                status: a.status,
            })
            .collect(),
        revoked_count: u32::try_from(manifest.revoked.len()).unwrap_or(u32::MAX),
        index_etag: new_etag,
    });
    Ok("updated")
}

/// The configured origin: `ORBDEN_UPDATES_URL` when set to a non-empty value,
/// else the production origin; trailing slashes are dropped. Anything that is
/// not an HTTPS origin (or plain-HTTP loopback) with no path is refused.
pub fn origin_from_env() -> String {
    std::env::var(ORIGIN_ENV)
        .ok()
        .map(|v| v.trim().trim_end_matches('/').to_owned())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_ORIGIN.to_owned())
}

fn origin_ok(origin: &str) -> bool {
    let rest = origin.strip_prefix("https://").or_else(|| {
        crate::engine::fetch::is_plain_http_loopback(origin)
            .then(|| origin.strip_prefix("http://"))
            .flatten()
    });
    rest.is_some_and(|rest| {
        !rest.is_empty() && !rest.contains(['/', '?', '#', '@', '\\']) && rest.is_ascii()
    })
}

/// Runs one check and records it. Refuses, before any request, unless the
/// policy is `checkOnly`.
pub fn refresh(
    state: &ManagedRoot,
    fetch: &dyn Fetch,
    origin: &str,
    now: i64,
    holder: RequestId,
) -> Result<RefreshResult, Error> {
    let _guard = lock(state, holder)?;
    if read_policy(state) != PolicyState::CheckOnly {
        return Err(Error::PolicyNotEnabled);
    }
    let mut stored = load_state(state);
    let outcome = if origin_ok(origin) {
        check(fetch, origin, now, &mut stored)
    } else {
        Err("invalid")
    };
    let result = match outcome {
        Ok(result) | Err(result) => result,
    };
    stored.last_check = Some(LastCheck {
        at_unix: now,
        result: result.to_owned(),
    });
    save_state(state, &stored)?;
    record_history(
        state,
        HistoryEntry {
            at_unix: now,
            result: result.to_owned(),
            sequence: stored.accepted.as_ref().map(|a| a.sequence),
            manifest_prefix: stored
                .accepted
                .as_ref()
                .map(|a| a.manifest_sha256.chars().take(12).collect()),
        },
        now,
    );
    let freshness = match &stored.accepted {
        Some(accepted) if accepted.expires_at_unix > now => Freshness::Fresh,
        Some(_) => Freshness::Expired,
        None => Freshness::Unknown,
    };
    Ok(RefreshResult {
        result: result.to_owned(),
        freshness,
        sequence: stored.accepted.as_ref().map(|a| a.sequence),
    })
}

#[cfg(all(test, unix))]
mod tests;
