//! `drupal.watchdog`: a bounded, read-only, redacted view of Drupal's
//! database log (`drush watchdog:show`).
//!
//! The Drush argv is fixed: `watchdog:show --format=json --count=N` plus an
//! optional `--severity=<level name>` (or `--severity-min=`) and `--type=<channel>`. The only
//! caller-controlled values are a count (1..=100), one of eight severity
//! names and a short channel name from a closed charset; each is a single
//! argv element and nothing goes through a shell. Drush runs as the site
//! user in the site's runtime container, from the project root.
//!
//! Log messages are free text written by modules and visitors and can carry
//! URLs with query strings, e-mail addresses, tokens and `password=...`
//! pairs. Every message is therefore **redacted before it leaves the
//! engine** ([`redact_message`]), stripped of markup and control characters
//! and cut at [`MAX_MESSAGE_CHARS`]. Hostnames, user names, referers and
//! locations are not returned at all: an entry is
//! `{id, date, type, severity, message}`.
//!
//! In a multisite project the request names the site with `site`
//! (`{"host", "directory"}`). The engine resolves the host from the static
//! `sites.php` map ([`drupal_site`]), requires the named directory to be the
//! mapped one, runs Drush with `--uri=<host>` and refuses unless Drush reports
//! that same `sites/<directory>` with a connected database whose name agrees
//! with `sql:conf`. There is no fallback to `default`. The answer carries the
//! verified host, directory, database name and table prefix, never a
//! credential.
//!
//! Nothing is written: no transaction, no lock, no audit record.

use crate::{
    db_restore::{ContainerName, RestoreRequestError},
    drupal_site::{self, DrupalSiteIdentity},
    error::ErrorCode,
    process::{
        self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination,
        SubprocessDiagnostics,
    },
};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Duration};

pub const OPERATION: &str = "drupal.watchdog";

pub const DEFAULT_COUNT: u32 = 50;
pub const MAX_COUNT: u32 = 200;
pub const MAX_MESSAGE_CHARS: usize = 500;
const MAX_TYPE_LEN: usize = 64;
const TIMEOUT: Duration = Duration::from_secs(60);
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
/// Exit status of the Drush selector when no Drush exists.
const DRUSH_ABSENT: i32 = 97;

/// The eight RFC 5424 levels Drupal logs with.
pub const SEVERITIES: &[&str] = &[
    "emergency",
    "alert",
    "critical",
    "error",
    "warning",
    "notice",
    "info",
    "debug",
];

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    container: String,
    project_root: String,
    document_root: String,
    uid: u32,
    gid: u32,
    count: Option<u32>,
    severity: Option<String>,
    /// At least this severe (`--severity-min`); exclusive with `severity`.
    severity_min: Option<String>,
    #[serde(rename = "type")]
    channel: Option<String>,
    site: Option<SitePlan>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SitePlan {
    host: String,
    directory: String,
}

/// The site of a multisite project a request is about.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SiteSelector {
    host: String,
    directory: String,
}

#[derive(Debug)]
pub struct Request {
    container: ContainerName,
    project_root: PathBuf,
    document_root: PathBuf,
    uid: u32,
    gid: u32,
    count: u32,
    severity: Option<&'static str>,
    severity_min: Option<&'static str>,
    channel: Option<String>,
    site: Option<SiteSelector>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    InvalidRoot,
    InvalidContainer,
    InvalidCount,
    InvalidSeverity,
    InvalidType,
    InvalidSite,
}

impl RequestError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidJson => "request-file is not a valid Drupal watchdog plan",
            Self::InvalidRoot => {
                "projectRoot and documentRoot must be plain absolute paths, documentRoot inside projectRoot"
            }
            Self::InvalidContainer => "container is not a valid container name",
            Self::InvalidCount => "count must be between 1 and 200",
            Self::InvalidSeverity => {
                "severity and severityMin must each be one of emergency, alert, critical, error, warning, notice, info, debug, and not both"
            }
            Self::InvalidType => {
                "type must be 1-64 characters of letters, digits, space, dot, underscore or hyphen"
            }
            Self::InvalidSite => {
                "site must name a host (letters, digits, dot, hyphen) and a directory under sites/"
            }
        }
    }
}

fn plain_absolute_path(value: &str) -> Option<PathBuf> {
    let path = PathBuf::from(value);
    (path.is_absolute()
        && value.len() <= 4096
        && !value.chars().any(char::is_control)
        && !path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir)))
    .then_some(path)
}

fn valid_channel(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TYPE_LEN
        && !value.starts_with(' ')
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | '-'))
}

impl Request {
    pub fn parse(json: &str) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        let project_root =
            plain_absolute_path(&plan.project_root).ok_or(RequestError::InvalidRoot)?;
        let document_root =
            plain_absolute_path(&plan.document_root).ok_or(RequestError::InvalidRoot)?;
        if !document_root.starts_with(&project_root) {
            return Err(RequestError::InvalidRoot);
        }
        let count = plan.count.unwrap_or(DEFAULT_COUNT);
        if !(1..=MAX_COUNT).contains(&count) {
            return Err(RequestError::InvalidCount);
        }
        let level = |value: Option<&str>| -> Result<Option<&'static str>, RequestError> {
            match value {
                None => Ok(None),
                Some(value) => SEVERITIES
                    .iter()
                    .copied()
                    .find(|level| *level == value)
                    .map(Some)
                    .ok_or(RequestError::InvalidSeverity),
            }
        };
        let severity = level(plan.severity.as_deref())?;
        let severity_min = level(plan.severity_min.as_deref())?;
        if severity.is_some() && severity_min.is_some() {
            return Err(RequestError::InvalidSeverity);
        }
        if plan.channel.as_deref().is_some_and(|v| !valid_channel(v)) {
            return Err(RequestError::InvalidType);
        }
        let site = match plan.site {
            None => None,
            Some(site) => {
                drupal_site::check_host(&site.host).map_err(|_| RequestError::InvalidSite)?;
                drupal_site::check_directory(&site.directory)
                    .map_err(|_| RequestError::InvalidSite)?;
                Some(SiteSelector {
                    host: site.host,
                    directory: site.directory,
                })
            }
        };
        Ok(Self {
            container: ContainerName::parse(&plan.container)
                .map_err(|_: RestoreRequestError| RequestError::InvalidContainer)?,
            project_root,
            document_root,
            uid: plan.uid,
            gid: plan.gid,
            count,
            severity,
            severity_min,
            channel: plan.channel,
            site,
        })
    }

    pub fn root(&self) -> &std::path::Path {
        &self.project_root
    }

    fn drush_args(&self) -> Vec<String> {
        let mut args = vec![
            "watchdog:show".to_owned(),
            "--format=json".to_owned(),
            format!("--count={}", self.count),
        ];
        if let Some(level) = self.severity {
            // Drush compares against Drupal's capitalised level labels
            // (`Error`), not the lowercase names the request uses; a
            // numeric 0 (emergency) would be treated as "no filter".
            let mut label = level.to_owned();
            label[..1].make_ascii_uppercase();
            args.push(format!("--severity={label}"));
        }
        if let Some(level) = self.severity_min {
            let mut label = level.to_owned();
            label[..1].make_ascii_uppercase();
            args.push(format!("--severity-min={label}"));
        }
        if let Some(channel) = &self.channel {
            args.push(format!("--type={channel}"));
        }
        args
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub id: u64,
    pub date: String,
    #[serde(rename = "type")]
    pub channel: String,
    pub severity: String,
    pub message: String,
    /// Present (and `true`) only when the message was cut at
    /// [`MAX_MESSAGE_CHARS`].
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchdogResult {
    /// Newest first.
    pub entries: Vec<Entry>,
    /// The site the entries belong to; present only for a multisite request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site: Option<VerifiedSite>,
}

/// A site whose identity the engine checked against `sites.php` and Drush.
/// No credential is part of it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedSite {
    pub host: String,
    pub directory: String,
    pub database: String,
    /// `None` when Drush did not report a usable prefix.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table_prefix: Option<String>,
}

/// Why a multisite request was refused. Nothing was read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SiteError {
    /// `sites.php` is dynamic, too large or not a plain file.
    MapUnsupported,
    NotMapped,
    /// The requested directory is not the one `sites.php` maps the host to.
    DirectoryMismatch,
    DirectoryNotUsable,
    /// Drush bootstrapped a different site than `sites.php` names.
    DrushSelectedOther,
    DatabaseNotReady,
    DatabaseMismatch,
}

impl SiteError {
    const fn message(self) -> &'static str {
        match self {
            Self::MapUnsupported => {
                "sites.php is not a plain list of $sites['host'] = 'directory'; assignments, so multisite requests are not supported for this project; nothing was read"
            }
            Self::NotMapped => "the host is not mapped in sites.php; nothing was read",
            Self::DirectoryMismatch => {
                "the requested directory is not the one sites.php maps the host to; nothing was read"
            }
            Self::DirectoryNotUsable => {
                "the site directory is missing, a symlink or outside sites/; nothing was read"
            }
            Self::DrushSelectedOther => {
                "Drush selected a different site than sites.php names for this host; nothing was read"
            }
            Self::DatabaseNotReady => {
                "the selected site's database is not connected; nothing was read"
            }
            Self::DatabaseMismatch => {
                "the selected site's database settings disagree; nothing was read"
            }
        }
    }
}

impl From<drupal_site::Error> for SiteError {
    fn from(error: drupal_site::Error) -> Self {
        match error {
            drupal_site::Error::MapTooLarge | drupal_site::Error::DynamicMap => {
                Self::MapUnsupported
            }
            drupal_site::Error::NotMapped
            | drupal_site::Error::InvalidHost
            | drupal_site::Error::InvalidDirectory => Self::NotMapped,
            drupal_site::Error::DirectoryNotUsable => Self::DirectoryNotUsable,
        }
    }
}

pub struct Context<'a> {
    pub docker_program: &'a str,
}

#[derive(Debug)]
pub enum Error {
    Run(process::ProcessRunError),
    Rejected(SubprocessDiagnostics),
    /// Drush is not installed for this site (`drupal.installDrush`).
    DrushMissing,
    TooLarge,
    BadOutput,
    Site(SiteError),
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Run(error) => (
                process::spawn_error_code(error),
                "could not run Drush".into(),
            ),
            Self::Rejected(diagnostics) => {
                let code = if diagnostics.timed_out {
                    ErrorCode::Timeout
                } else if diagnostics.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::SubprocessFailed
                };
                (
                    code,
                    "Drush could not read the log (is the Database Logging module enabled?)".into(),
                )
            }
            Self::DrushMissing => (
                ErrorCode::DependencyUnavailable,
                "Drush is not installed for this site; run drupal.installDrush first".into(),
            ),
            Self::Site(error) => (ErrorCode::InvalidInput, error.message().into()),
            Self::TooLarge | Self::BadOutput => (
                ErrorCode::Internal,
                "Drush returned an unexpected answer".into(),
            ),
        }
    }
}

// ---------------------------------------------------------------- redaction

const SECRET_KEY_PARTS: &[&str] = &[
    "pass",
    "pwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "api-key",
    "authorization",
    "cookie",
    "session",
    "credential",
    "signature",
    "nonce",
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

const REDACTED: &str = "[redacted]";

fn is_secret_key(key: &str) -> bool {
    let lower = key
        .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
        .to_ascii_lowercase();
    !lower.is_empty() && SECRET_KEY_PARTS.iter().any(|part| lower.contains(part))
}

fn longest_opaque_run(word: &str) -> usize {
    let (mut longest, mut current) = (0, 0);
    for c in word.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '+' | '=') {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 0;
        }
    }
    longest
}

fn looks_like_email(word: &str) -> bool {
    word.split_once('@')
        .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'))
}

/// `scheme://[user:pass@]host/path[?query][#fragment]` keeps scheme, host
/// and path; credentials, query and fragment go.
fn redact_url(word: &str) -> String {
    let Some(start) = word.find("://") else {
        return word.to_owned();
    };
    let (scheme, rest) = word.split_at(start + 3);
    let cut = rest.find(['?', '#']);
    let (authority_and_path, had_extra) = match cut {
        Some(index) => (&rest[..index], true),
        None => (rest, false),
    };
    let authority_end = authority_and_path
        .find('/')
        .unwrap_or(authority_and_path.len());
    let (authority, path) = authority_and_path.split_at(authority_end);
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let mut out = format!("{scheme}{host}{path}");
    if had_extra {
        out.push_str("?[redacted]");
    }
    out
}

fn strip_markup(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_tag = false;
    for c in text.chars() {
        match c {
            '<' => in_tag = true,
            '>' if in_tag => {
                in_tag = false;
                out.push(' ');
            }
            _ if in_tag => {}
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// Removes everything that could be a credential from one log message and
/// cuts it at [`MAX_MESSAGE_CHARS`]. Returns the text and whether it was
/// cut. Whitespace is collapsed to single spaces.
pub fn redact_message(raw: &str) -> (String, bool) {
    let text = strip_markup(raw);
    if text.to_ascii_lowercase().contains("-----begin") {
        return (REDACTED.to_owned(), false);
    }
    let mut words: Vec<String> = Vec::new();
    // The previous word named a secret (`password:` / `token =`): the next
    // word is its value.
    let mut redact_next = false;
    // The previous word was a bare secret name (`api_key`): a following
    // `=`/`:` word makes the word after that a value.
    let mut key_seen = false;
    for word in text.split_whitespace() {
        let lower = word.to_ascii_lowercase();
        let after_key = std::mem::take(&mut key_seen);
        if matches!(word, "=" | ":") {
            redact_next = redact_next || after_key;
            words.push(word.to_owned());
            continue;
        }
        if redact_next && !matches!(lower.as_str(), "bearer" | "basic") {
            redact_next = false;
            words.push(REDACTED.to_owned());
            continue;
        }
        if lower == "bearer" || lower == "basic" {
            words.push(word.to_owned());
            redact_next = true;
            continue;
        }
        if word.contains("://") {
            words.push(redact_url(word));
            continue;
        }
        if let Some(index) = word.find('?') {
            let after = &word[index + 1..];
            if after
                .split_once('=')
                .is_some_and(|(name, _)| !name.is_empty())
            {
                words.push(format!("{}?[redacted]", &word[..index]));
                continue;
            }
        }
        if let Some(index) = word.find(['=', ':']) {
            let (key, value) = (&word[..index], &word[index + 1..]);
            if is_secret_key(key) {
                if value.is_empty() {
                    redact_next = true;
                    words.push(word.to_owned());
                } else {
                    words.push(format!("{}{REDACTED}", &word[..=index]));
                }
                continue;
            }
        }
        if is_secret_key(word) && word.len() <= 24 {
            // A bare name such as `api_key` is not itself secret.
            key_seen = true;
            words.push(word.to_owned());
            continue;
        }
        if SECRET_PREFIXES.iter().any(|p| lower.starts_with(p)) || longest_opaque_run(word) >= 32 {
            words.push(REDACTED.to_owned());
            continue;
        }
        if looks_like_email(word) {
            words.push("[email]".to_owned());
            continue;
        }
        words.push(word.to_owned());
    }
    let joined = words.join(" ");
    if joined.chars().count() > MAX_MESSAGE_CHARS {
        let cut: String = joined.chars().take(MAX_MESSAGE_CHARS).collect();
        (cut, true)
    } else {
        (joined, false)
    }
}

// ------------------------------------------------------------------- parsing

fn short(value: Option<&serde_json::Value>, max: usize) -> String {
    let text = match value {
        Some(serde_json::Value::String(s)) => s.as_str(),
        _ => "",
    };
    strip_markup(text)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(max)
        .collect()
}

fn entry_id(value: Option<&serde_json::Value>) -> Option<u64> {
    match value? {
        serde_json::Value::Number(n) => n.as_u64(),
        serde_json::Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Parses `drush watchdog:show --format=json`: an object keyed by log id or
/// a list, after any leading notices.
pub fn parse_output(bytes: &[u8], limit: usize) -> Result<Vec<Entry>, Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::BadOutput)?;
    let start = text.find(['{', '[']).ok_or(Error::BadOutput)?;
    let value: serde_json::Value =
        serde_json::from_str(text[start..].trim()).map_err(|_| Error::BadOutput)?;
    let rows: Vec<&serde_json::Value> = match &value {
        serde_json::Value::Object(map) => map.values().collect(),
        serde_json::Value::Array(list) => list.iter().collect(),
        _ => return Err(Error::BadOutput),
    };
    let mut entries = Vec::new();
    for row in rows {
        let id = entry_id(row.get("wid").or_else(|| row.get("id"))).ok_or(Error::BadOutput)?;
        let raw_message = match row.get("message") {
            Some(serde_json::Value::String(s)) => s.as_str(),
            _ => "",
        };
        let (message, truncated) = redact_message(raw_message);
        entries.push(Entry {
            id,
            date: short(row.get("date"), 32),
            channel: short(row.get("type"), MAX_TYPE_LEN),
            severity: short(row.get("severity"), 16).to_ascii_lowercase(),
            message,
            truncated,
        });
    }
    entries.sort_by(|a, b| b.id.cmp(&a.id));
    entries.truncate(limit);
    Ok(entries)
}

// ----------------------------------------------------------------- execution

/// Runs `drush` as the site user in the project root with `--root` (and
/// `--uri` for a multisite request) and returns its standard output.
fn run_drush(
    ctx: &Context<'_>,
    req: &Request,
    drush_args: &[String],
    cancel: &CancellationToken,
) -> Result<Vec<u8>, Error> {
    let mut args: Vec<String> = vec![
        "exec".into(),
        "--user".into(),
        format!("{}:{}", req.uid, req.gid),
        "-w".into(),
        req.project_root.display().to_string(),
        req.container.as_str().to_owned(),
        "sh".into(),
        "-c".into(),
        format!(
            "if [ -x ./vendor/bin/drush ]; then exec ./vendor/bin/drush \"$@\"; elif command -v drush >/dev/null 2>&1; then exec drush \"$@\"; else exit {DRUSH_ABSENT}; fi"
        ),
        "drush".into(),
        format!("--root={}", req.document_root.display()),
        "--no-interaction".into(),
    ];
    if let Some(site) = &req.site {
        args.push(format!("--uri={}", site.host));
    }
    args.extend(drush_args.iter().cloned());
    let output = process::run(
        &ProcessRequest::new(ctx.docker_program).args(args),
        &ProcessLimits {
            timeout: TIMEOUT,
            max_stdout_bytes: MAX_OUTPUT_BYTES,
            max_stderr_bytes: MAX_OUTPUT_BYTES,
        },
        cancel,
    )
    .map_err(Error::Run)?;
    match output.termination {
        ProcessTermination::Exited { success: true, .. } => {}
        ProcessTermination::Exited {
            code: Some(DRUSH_ABSENT),
            ..
        } => return Err(Error::DrushMissing),
        _ => {
            return Err(Error::Rejected(SubprocessDiagnostics::from_output(
                ctx.docker_program,
                &output,
            )));
        }
    }
    if output.stdout.truncated || output.stderr.truncated {
        return Err(Error::TooLarge);
    }
    Ok(output.stdout.bytes)
}

/// The first JSON object in Drush output, after any leading notices.
fn json_object(bytes: &[u8]) -> Option<serde_json::Value> {
    let text = std::str::from_utf8(bytes).ok()?;
    let value: serde_json::Value = serde_json::from_str(text[text.find('{')?..].trim()).ok()?;
    value.is_object().then_some(value)
}

/// A table prefix Drupal would accept in a name: letters, digits, underscore.
fn usable_prefix(value: &str) -> Option<String> {
    (value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_'))
    .then(|| value.to_owned())
}

/// Checks Drush's answers against the identity `sites.php` gave. Pure, so the
/// refusals are tested without a server.
///
/// `status` is `drush status --fields=site,db-name,db-status --format=json`
/// and `conf` is `drush sql:conf --format=json` (credentials in it are never
/// read).
pub fn verify_drush(
    identity: &DrupalSiteIdentity,
    status: &[u8],
    conf: &[u8],
) -> Result<VerifiedSite, SiteError> {
    let status = json_object(status).ok_or(SiteError::DrushSelectedOther)?;
    let text = |value: &serde_json::Value, key: &str| {
        value.get(key).and_then(|v| v.as_str()).map(str::to_owned)
    };
    let selected = text(&status, "site").ok_or(SiteError::DrushSelectedOther)?;
    let selected = selected.trim_end_matches('/');
    let wanted = format!("sites/{}", identity.directory());
    if selected != wanted && !selected.ends_with(&format!("/{wanted}")) {
        return Err(SiteError::DrushSelectedOther);
    }
    if text(&status, "db-status").as_deref() != Some("Connected") {
        return Err(SiteError::DatabaseNotReady);
    }
    let database = text(&status, "db-name")
        .filter(|name| !name.is_empty())
        .ok_or(SiteError::DatabaseNotReady)?;
    let conf = json_object(conf).ok_or(SiteError::DatabaseMismatch)?;
    // Some Drush versions nest the spec under `database.default.default`.
    let spec = conf
        .get("database")
        .filter(|inner| inner.is_object())
        .and_then(|inner| inner.get("default").and_then(|d| d.get("default")))
        .unwrap_or(&conf);
    if text(spec, "database").as_deref() != Some(database.as_str()) {
        return Err(SiteError::DatabaseMismatch);
    }
    let table_prefix = match spec.get("prefix") {
        Some(serde_json::Value::String(prefix)) => usable_prefix(prefix),
        Some(serde_json::Value::Object(map)) => map
            .get("default")
            .and_then(|v| v.as_str())
            .and_then(usable_prefix),
        _ => None,
    };
    Ok(VerifiedSite {
        host: identity.host().to_owned(),
        directory: identity.directory().to_owned(),
        database,
        table_prefix,
    })
}

fn verify_site(
    ctx: &Context<'_>,
    req: &Request,
    selector: &SiteSelector,
    cancel: &CancellationToken,
) -> Result<VerifiedSite, Error> {
    let map = drupal_site::read_sites_map(&req.document_root).map_err(SiteError::from)?;
    let identity = DrupalSiteIdentity::resolve(&req.document_root, &map, &selector.host)
        .map_err(SiteError::from)?;
    if identity.directory() != selector.directory {
        return Err(SiteError::DirectoryMismatch.into());
    }
    let status = run_drush(
        ctx,
        req,
        &[
            "status".into(),
            "--fields=site,db-name,db-status".into(),
            "--format=json".into(),
        ],
        cancel,
    )?;
    let conf = run_drush(
        ctx,
        req,
        &["sql:conf".into(), "--format=json".into()],
        cancel,
    )?;
    Ok(verify_drush(&identity, &status, &conf)?)
}

impl From<SiteError> for Error {
    fn from(error: SiteError) -> Self {
        Self::Site(error)
    }
}

pub fn read(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<WatchdogResult, Error> {
    let site = match &req.site {
        None => None,
        Some(selector) => Some(verify_site(ctx, req, selector, cancel)?),
    };
    let stdout = run_drush(ctx, req, &req.drush_args(), cancel)?;
    let text = String::from_utf8_lossy(&stdout);
    // An empty log prints nothing or `[]`.
    if text.trim().is_empty() {
        return Ok(WatchdogResult {
            entries: vec![],
            site,
        });
    }
    Ok(WatchdogResult {
        entries: parse_output(text.as_bytes(), req.count as usize)?,
        site,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt, path::Path};

    const PLAN: &str = r#"{"container":"runtime-1","projectRoot":"/var/www/site","documentRoot":"/var/www/site/web","uid":1000,"gid":1001}"#;

    fn plan_with(extra: &str) -> String {
        PLAN.replacen('}', &format!(",{extra}}}"), 1)
    }

    fn redacted(text: &str) -> String {
        redact_message(text).0
    }

    #[test]
    fn requests_are_validated_and_bounded() {
        let ok = Request::parse(PLAN).unwrap();
        assert_eq!(ok.count, 50);
        assert_eq!(
            ok.drush_args(),
            ["watchdog:show", "--format=json", "--count=50"]
        );
        let full = Request::parse(&plan_with(
            r#""count":200,"severity":"error","type":"access denied""#,
        ))
        .unwrap();
        assert_eq!(
            full.drush_args(),
            [
                "watchdog:show",
                "--format=json",
                "--count=200",
                "--severity=Error",
                "--type=access denied"
            ]
        );
        let check = |extra: &str, expected: RequestError| {
            assert_eq!(
                Request::parse(&plan_with(extra)).unwrap_err(),
                expected,
                "{extra}"
            );
        };
        check(r#""count":0"#, RequestError::InvalidCount);
        check(r#""count":201"#, RequestError::InvalidCount);
        check(
            r#""severity":"error","severityMin":"warning""#,
            RequestError::InvalidSeverity,
        );
        check(r#""severityMin":"Warning""#, RequestError::InvalidSeverity);
        let min = Request::parse(&plan_with(r#""severityMin":"warning""#)).unwrap();
        assert_eq!(
            min.drush_args(),
            [
                "watchdog:show",
                "--format=json",
                "--count=50",
                "--severity-min=Warning"
            ]
        );
        check(r#""severity":"Error""#, RequestError::InvalidSeverity);
        check(r#""severity":"--root=/""#, RequestError::InvalidSeverity);
        check(r#""type":"""#, RequestError::InvalidType);
        check(r#""type":"a;b""#, RequestError::InvalidType);
        check(r#""type":"--uri=x/""#, RequestError::InvalidType);
        check(r#""type":" lead""#, RequestError::InvalidType);
        check(r#""command":"x""#, RequestError::InvalidJson);
        let long = format!(r#""type":"{}""#, "a".repeat(65));
        check(&long, RequestError::InvalidType);
        for (project, document, expected) in [
            ("var/www", "/var/www/web", RequestError::InvalidRoot),
            ("/var/www/site", "/var/www/other", RequestError::InvalidRoot),
            (
                "/var/www/site",
                "/var/www/site/../x",
                RequestError::InvalidRoot,
            ),
        ] {
            let json = format!(
                r#"{{"container":"runtime-1","projectRoot":"{project}","documentRoot":"{document}","uid":1,"gid":1}}"#
            );
            assert_eq!(Request::parse(&json).unwrap_err(), expected, "{project}");
        }
        let json = PLAN.replace("runtime-1", "a b");
        assert_eq!(
            Request::parse(&json).unwrap_err(),
            RequestError::InvalidContainer
        );
    }

    #[test]
    fn urls_lose_credentials_query_and_fragment() {
        assert_eq!(
            redacted("GET https://user:pw@example.com/path/x?token=abc&a=b#frag failed"),
            "GET https://example.com/path/x?[redacted] failed"
        );
        assert_eq!(
            redacted("see http://example.com/plain/path ok"),
            "see http://example.com/plain/path ok"
        );
        assert_eq!(
            redacted("/user/reset?pass-reset-token=zzz"),
            "/user/reset?[redacted]"
        );
        assert_eq!(redacted("What? Done."), "What? Done.");
    }

    #[test]
    fn secret_pairs_bearer_tokens_and_blobs_are_redacted() {
        assert_eq!(redacted("password=hunter2 ok"), "password=[redacted] ok");
        assert_eq!(redacted("Password: hunter2 ok"), "Password: [redacted] ok");
        assert_eq!(redacted("api_key = abc ok"), "api_key = [redacted] ok");
        assert_eq!(redacted("token:abc"), "token:[redacted]");
        assert_eq!(
            redacted("Authorization: Bearer abc.def"),
            "Authorization: Bearer [redacted]"
        );
        assert_eq!(redacted("Bearer abc"), "Bearer [redacted]");
        assert_eq!(redacted("cookie=SESS123=abc"), "cookie=[redacted]");
        assert_eq!(
            redacted(&format!("hash {} end", "a1".repeat(16))),
            "hash [redacted] end"
        );
        assert_eq!(
            redacted("key eyJhbGciOiJIUzI1NiJ9 end"),
            "key [redacted] end"
        );
        assert_eq!(redacted("AKIAABCDEFGHIJKLMNOP"), "[redacted]");
        assert_eq!(
            redacted("-----BEGIN PRIVATE KEY----- MIIE -----END PRIVATE KEY-----"),
            "[redacted]"
        );
    }

    #[test]
    fn emails_markup_and_control_characters_are_removed() {
        assert_eq!(
            redacted("Session opened for admin@example.com."),
            "Session opened for [email]"
        );
        assert_eq!(
            redacted("<em>Notice</em>: <a href=\"/x?t=1\">link</a>\u{7}\nbreak"),
            "Notice : link break"
        );
        assert_eq!(redacted("a   b\t\tc"), "a b c");
        // Ordinary text and paths survive.
        assert_eq!(
            redacted("Page not found: /node/12 (Drupal 10.4.1)"),
            "Page not found: /node/12 (Drupal 10.4.1)"
        );
    }

    #[test]
    fn long_messages_are_cut_on_characters() {
        let (short, cut) = redact_message("ok");
        assert_eq!((short.as_str(), cut), ("ok", false));
        let wide = "é ".repeat(400);
        let (text, cut) = redact_message(&wide);
        assert!(cut);
        assert_eq!(text.chars().count(), MAX_MESSAGE_CHARS);
        let exact = format!("{} x", "é".repeat(MAX_MESSAGE_CHARS - 2));
        assert_eq!(exact.chars().count(), MAX_MESSAGE_CHARS);
        assert!(!redact_message(&exact).1);
    }

    #[test]
    fn drush_output_is_parsed_sorted_bounded_and_stripped_of_extras() {
        let out = br#"Deprecated: noise
{
  "7": {"wid":"7","type":"php","message":"Oops password=x","severity":"Error","date":"2026-10-12 10:00:00","hostname":"203.0.113.9","username":"alice","location":"https://x/?t=1"},
  "9": {"wid":9,"type":"cron","message":"Cron run completed.","severity":"Notice","date":"2026-10-12 11:00:00"},
  "8": {"wid":"8","type":"user","message":"b","severity":"Warning","date":"d"}
}"#;
        let entries = parse_output(out, 2).unwrap();
        assert_eq!(entries.iter().map(|e| e.id).collect::<Vec<_>>(), [9, 8]);
        assert_eq!(entries[0].severity, "notice");
        assert_eq!(entries[0].channel, "cron");
        let all = parse_output(out, 10).unwrap();
        assert_eq!(all[2].message, "Oops password=[redacted]");
        let json = serde_json::to_string(&all).unwrap();
        assert!(!json.contains("203.0.113.9") && !json.contains("alice") && !json.contains("t=1"));
        assert!(!json.contains("truncated"));
        // A list works too; garbage and a missing id are errors.
        assert_eq!(
            parse_output(br#"[{"wid":1,"message":"m"}]"#, 5)
                .unwrap()
                .len(),
            1
        );
        assert!(matches!(parse_output(b"nothing", 5), Err(Error::BadOutput)));
        assert!(matches!(
            parse_output(br#"[{"message":"m"}]"#, 5),
            Err(Error::BadOutput)
        ));
        assert!(matches!(
            parse_output(br#"{"1":{"wid":"x"}}"#, 5),
            Err(Error::BadOutput)
        ));
    }

    fn fake_docker(directory: &Path, script: &str) -> String {
        let path = directory.join("fake-docker");
        fs::write(&path, script).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn reading_runs_fixed_drush_arguments_as_the_site_user() {
        let work = tempfile::tempdir().unwrap();
        let docker = fake_docker(
            work.path(),
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{d}/argv'\necho '{{\"1\":{{\"wid\":\"1\",\"type\":\"php\",\"message\":\"boom\",\"severity\":\"Error\",\"date\":\"d\"}}}}'\n",
                d = work.path().display()
            ),
        );
        let request = Request::parse(&plan_with(r#""count":5,"severity":"error""#)).unwrap();
        let result = read(
            &Context {
                docker_program: &docker,
            },
            &request,
            &CancellationToken::default(),
        )
        .unwrap();
        assert_eq!(result.entries.len(), 1);
        let argv = fs::read_to_string(work.path().join("argv")).unwrap();
        assert!(argv.starts_with("exec\n--user\n1000:1001\n-w\n/var/www/site\nruntime-1\nsh\n"));
        assert!(argv.contains("--root=/var/www/site/web\n--no-interaction\nwatchdog:show\n--format=json\n--count=5\n--severity=Error\n"));
    }

    #[test]
    fn an_empty_log_and_failures_map_to_stable_errors() {
        let work = tempfile::tempdir().unwrap();
        let request = Request::parse(PLAN).unwrap();
        let run = |script: &str| {
            let docker = fake_docker(work.path(), script);
            read(
                &Context {
                    docker_program: &docker,
                },
                &request,
                &CancellationToken::default(),
            )
        };
        assert!(run("#!/bin/sh\nexit 0\n").unwrap().entries.is_empty());
        assert!(run("#!/bin/sh\necho '[]'\n").unwrap().entries.is_empty());
        let missing = run("#!/bin/sh\nexit 97\n").unwrap_err();
        assert_eq!(missing.protocol().0, ErrorCode::DependencyUnavailable);
        let failed = run("#!/bin/sh\necho 'secret=zzz' >&2\nexit 1\n").unwrap_err();
        let (code, message) = failed.protocol();
        assert_eq!(code, ErrorCode::SubprocessFailed);
        assert!(!message.contains("zzz"));
        let garbage = run("#!/bin/sh\necho 'not json'\n").unwrap_err();
        assert_eq!(garbage.protocol().0, ErrorCode::Internal);
    }

    // ------------------------------------------------------------ multisite

    fn identity(host: &str, directory: &str) -> (tempfile::TempDir, DrupalSiteIdentity) {
        let docroot = tempfile::tempdir().unwrap();
        fs::create_dir_all(docroot.path().join("sites").join(directory)).unwrap();
        let map =
            drupal_site::SitesMap::parse(&format!("$sites['{host}'] = '{directory}';")).unwrap();
        let identity = DrupalSiteIdentity::resolve(docroot.path(), &map, host).unwrap();
        (docroot, identity)
    }

    const STATUS: &str = r#"{"site":"sites/shop","db-name":"shop_db","db-status":"Connected"}"#;
    const CONF: &str =
        r#"{"driver":"mysql","host":"db","database":"shop_db","prefix":"shop_","username":"u"}"#;

    #[test]
    fn a_site_request_is_validated() {
        let ok = Request::parse(&plan_with(
            r#""site":{"host":"shop.example.com","directory":"shop"}"#,
        ))
        .unwrap();
        assert_eq!(ok.site.as_ref().unwrap().host, "shop.example.com");
        for bad in [
            r#""site":{"host":"","directory":"shop"}"#,
            r#""site":{"host":"a.com","directory":"../x"}"#,
            r#""site":{"host":"a.com","directory":"all"}"#,
            r#""site":{"host":"a b","directory":"shop"}"#,
            r#""site":{"host":"a.com"}"#,
            r#""site":{"host":"a.com","directory":"shop","uri":"x"}"#,
        ] {
            assert!(Request::parse(&plan_with(bad)).is_err(), "{bad}");
        }
        assert!(Request::parse(PLAN).unwrap().site.is_none());
    }

    #[test]
    fn the_verified_site_is_the_one_drush_selected() {
        let (_docroot, id) = identity("shop.example.com", "shop");
        let verified = verify_drush(&id, STATUS.as_bytes(), CONF.as_bytes()).unwrap();
        assert_eq!(
            verified,
            VerifiedSite {
                host: "shop.example.com".into(),
                directory: "shop".into(),
                database: "shop_db".into(),
                table_prefix: Some("shop_".into()),
            }
        );
        // A path with a prefix and the nested spec of some Drush versions.
        let nested = r#"{"database":{"default":{"default":{"database":"shop_db","prefix":{"default":"p_"}}}}}"#;
        let status = r#"Notice\n{"site":"/var/www/s/web/sites/shop/","db-name":"shop_db","db-status":"Connected"}"#;
        let again = verify_drush(&id, status.as_bytes(), nested.as_bytes()).unwrap();
        assert_eq!(again.table_prefix.as_deref(), Some("p_"));
    }

    #[test]
    fn drift_and_database_problems_are_refused() {
        let (_docroot, id) = identity("shop.example.com", "shop");
        let refused = |status: &str, conf: &str| {
            verify_drush(&id, status.as_bytes(), conf.as_bytes()).unwrap_err()
        };
        // Drush fell back to another site (map drift, or the default site).
        assert_eq!(
            refused(
                r#"{"site":"sites/default","db-name":"d","db-status":"Connected"}"#,
                CONF
            ),
            SiteError::DrushSelectedOther
        );
        assert_eq!(
            refused(
                r#"{"site":"sites/shop2","db-name":"d","db-status":"Connected"}"#,
                CONF
            ),
            SiteError::DrushSelectedOther
        );
        assert_eq!(refused("not json", CONF), SiteError::DrushSelectedOther);
        assert_eq!(
            refused(r#"{"site":"sites/shop","db-name":"shop_db"}"#, CONF),
            SiteError::DatabaseNotReady
        );
        assert_eq!(
            refused(
                r#"{"site":"sites/shop","db-name":"shop_db","db-status":"Not connected"}"#,
                CONF
            ),
            SiteError::DatabaseNotReady
        );
        // The two Drush answers name different databases.
        assert_eq!(
            refused(STATUS, r#"{"database":"other_db"}"#),
            SiteError::DatabaseMismatch
        );
        assert_eq!(refused(STATUS, "nope"), SiteError::DatabaseMismatch);
    }

    #[test]
    fn an_unusable_prefix_is_unknown_not_a_refusal() {
        let (_docroot, id) = identity("shop.example.com", "shop");
        let conf = r#"{"database":"shop_db","prefix":"a b;"}"#;
        let verified = verify_drush(&id, STATUS.as_bytes(), conf.as_bytes()).unwrap();
        assert_eq!(verified.table_prefix, None);
    }

    #[test]
    fn the_answer_carries_no_credential_and_single_site_answers_are_unchanged() {
        let (_docroot, id) = identity("shop.example.com", "shop");
        let verified = verify_drush(&id, STATUS.as_bytes(), CONF.as_bytes()).unwrap();
        let json = serde_json::to_string(&WatchdogResult {
            entries: vec![],
            site: Some(verified),
        })
        .unwrap();
        assert!(!json.contains("username") && !json.contains("password"));
        assert_eq!(
            serde_json::to_string(&WatchdogResult {
                entries: vec![],
                site: None
            })
            .unwrap(),
            r#"{"entries":[]}"#
        );
    }

    #[test]
    fn site_errors_say_nothing_was_read() {
        for error in [
            SiteError::MapUnsupported,
            SiteError::NotMapped,
            SiteError::DirectoryMismatch,
            SiteError::DirectoryNotUsable,
            SiteError::DrushSelectedOther,
            SiteError::DatabaseNotReady,
            SiteError::DatabaseMismatch,
        ] {
            let (code, message) = Error::Site(error).protocol();
            assert_eq!(code, ErrorCode::InvalidInput);
            assert!(message.ends_with("nothing was read"), "{message}");
        }
    }
}
