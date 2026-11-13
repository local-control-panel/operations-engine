//! `agent.validate`: the rules an `agent.toml` and its script must meet before
//! the agent can be released, in one place.
//!
//! The agents repository parses its `agent.toml` (TOML syntax is the caller's
//! job), hands the table over as JSON next to the agent's directory, and prints
//! what this module answers. The engine's installer shares the helpers that
//! live here (`author_text_ok`, `parse_semver`, `valid_script_name`,
//! `valid_script_text`), so a manifest this module accepts is not refused for
//! those reasons on a server.
//!
//! Read-only: it reads the two named inputs and nothing else, writes nothing
//! and never echoes a manifest value other than a closed set of names (helper
//! groups, tools, key names that were checked first). A manifest it cannot
//! judge (not an object, a script it cannot read) is a problem, never a pass.

use std::{
    collections::BTreeSet,
    io::Read,
    path::{Path, PathBuf},
};

use serde::Serialize;
use serde_json::Value;

use crate::{
    agent_lifecycle::{AGENT_HELPERS, valid_agent_name},
    agent_registry::{MAX_SCRIPT_BYTES, MAX_WRITABLE_PATHS},
    agent_systemd,
    backup_schedule::Schedule,
};

pub const OPERATION: &str = "agent.validate";
/// The largest manifest (as JSON) the command reads.
pub const MAX_MANIFEST_BYTES: u64 = 64 * 1024;

const AUTHOR_MAX: usize = 100;
const REQUIRES_MAX: usize = 32;
const CONFIG_KEYS_MAX: usize = 64;
const NETWORK_MAX: usize = 32;
/// `official` and `community` are published; `example` never reaches a
/// registry (the generator skips it).
const TIERS: [&str; 3] = ["official", "community", "example"];
const SCHEDULES: [&str; 3] = ["fixed", "configurable", "none"];
/// Tools `requires_tools` can name (`agent tool status`).
const KNOWN_TOOLS: [&str; 3] = ["wp-cli", "rclone", "docker"];
/// Helper groups `heartbeat`, `lock` and `log` follow from `min_engine`.
const IMPLIED_HELPERS: [&str; 3] = ["heartbeat", "lock", "log"];
/// Groups whose use in a script must be declared in `requires_helpers`.
const DECLARED_HELPERS: [&str; 5] = ["result", "config", "site", "tool", "version"];
const REQUIRED_KEYS: [&str; 10] = [
    "name",
    "version",
    "tier",
    "author",
    "script",
    "schedule",
    "default_schedule",
    "min_engine",
    "description",
    "paths",
];
const OPTIONAL_KEYS: [&str; 7] = [
    "isolation",
    "writable_paths",
    "requires_ops",
    "requires_helpers",
    "requires_tools",
    "config_keys",
    "network",
];

/// The text rules for who wrote an agent, as shown to operators and written
/// into the manifest. An empty name passes here: the installer treats a missing
/// author as unknown (third-party). A manifest must still give one.
pub fn author_text_ok(author: &str) -> bool {
    author.chars().count() <= AUTHOR_MAX
        && !author.chars().any(char::is_control)
        && author == author.trim()
}

/// `x.y.z`, digits only (no sign, no spaces).
pub fn parse_semver(text: &str) -> Option<(u64, u64, u64)> {
    let mut parts = text.split('.');
    let mut next = || {
        let part = parts.next()?;
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        part.parse().ok()
    };
    let triple = (next()?, next()?, next()?);
    parts.next().is_none().then_some(triple)
}

/// A plain file name inside the agent's directory.
pub fn valid_script_name(script: &str) -> bool {
    !script.is_empty() && !script.contains(['/', '\\']) && !script.starts_with('.')
}

/// What a script must be to be installed: text that starts with `#!`.
pub fn valid_script_text(script: &str) -> bool {
    !script.contains('\0') && script.starts_with("#!")
}

#[derive(Debug, Serialize, Eq, PartialEq)]
pub struct Finding {
    /// A stable identifier, such as `invalid_version`.
    pub code: &'static str,
    /// The manifest key it is about, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<&'static str>,
    pub message: String,
}

fn finding(code: &'static str, field: Option<&'static str>, message: impl Into<String>) -> Finding {
    Finding {
        code,
        field,
        message: message.into(),
    }
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub valid: bool,
    /// The agent's name when the manifest has a usable one.
    pub agent: Option<String>,
    pub problems: Vec<Finding>,
    /// Contract points that are not (yet) errors.
    pub warnings: Vec<Finding>,
}

/// Why the inputs could not be read at all. The caller must treat it as
/// "not validated".
#[derive(Debug, Eq, PartialEq)]
pub enum InputError {
    ManifestUnreadable,
    ManifestTooLarge,
    ManifestNotJson,
    DirectoryUnusable,
}

impl InputError {
    pub const fn message(&self) -> &'static str {
        match self {
            Self::ManifestUnreadable => "manifest-file cannot be read as a regular file",
            Self::ManifestTooLarge => "manifest-file is too large",
            Self::ManifestNotJson => "manifest-file is not valid JSON",
            Self::DirectoryUnusable => "directory must name an existing directory",
        }
    }
}

fn read_bounded(path: &Path, max: u64) -> std::io::Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(max + 1)
        .read_to_end(&mut bytes)?;
    Ok((bytes.len() as u64 <= max).then_some(bytes))
}

/// Reads the inputs and validates them.
pub fn validate_paths(directory: &Path, manifest_file: &Path) -> Result<Report, InputError> {
    if !directory.is_dir() {
        return Err(InputError::DirectoryUnusable);
    }
    let meta =
        std::fs::symlink_metadata(manifest_file).map_err(|_| InputError::ManifestUnreadable)?;
    if !meta.is_file() {
        return Err(InputError::ManifestUnreadable);
    }
    let bytes = read_bounded(manifest_file, MAX_MANIFEST_BYTES)
        .map_err(|_| InputError::ManifestUnreadable)?
        .ok_or(InputError::ManifestTooLarge)?;
    let manifest: Value =
        serde_json::from_slice(&bytes).map_err(|_| InputError::ManifestNotJson)?;
    let directory_name = std::fs::canonicalize(directory)
        .ok()
        .and_then(|path| path.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_default();
    Ok(validate(&manifest, &directory_name, &|script| {
        read_script(directory, script)
    }))
}

pub enum Script {
    Text(String),
    Problem(Finding),
}

fn read_script(directory: &Path, script: &str) -> Script {
    let path: PathBuf = directory.join(script);
    let missing = || {
        Script::Problem(finding(
            "script_missing",
            Some("script"),
            "script is not a file in the agent's directory",
        ))
    };
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_file() => {}
        _ => return missing(),
    }
    match read_bounded(&path, MAX_SCRIPT_BYTES) {
        Ok(Some(bytes)) => match String::from_utf8(bytes) {
            Ok(text) => Script::Text(text),
            Err(_) => Script::Problem(finding(
                "script_not_text",
                Some("script"),
                "script must be UTF-8 text",
            )),
        },
        Ok(None) => Script::Problem(finding(
            "script_too_large",
            Some("script"),
            format!("script is larger than {MAX_SCRIPT_BYTES} bytes"),
        )),
        Err(_) => missing(),
    }
}

/// Validates one manifest. `directory_name` is the agent's directory (the name
/// must equal it); `script` reads the script the manifest names, only after
/// the name was checked to be a plain file name.
pub fn validate(manifest: &Value, directory_name: &str, script: &dyn Fn(&str) -> Script) -> Report {
    let mut problems = Vec::new();
    let mut warnings = Vec::new();
    let agent = manifest
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| valid_agent_name(name))
        .map(str::to_owned);
    let Some(table) = manifest.as_object() else {
        problems.push(finding(
            "manifest_not_an_object",
            None,
            "the manifest must be a table of keys",
        ));
        return Report {
            valid: false,
            agent,
            problems,
            warnings,
        };
    };
    for key in REQUIRED_KEYS {
        if !table.contains_key(key) {
            problems.push(finding(
                "missing_key",
                Some(key),
                format!("missing key {key}"),
            ));
        }
    }
    if !problems.is_empty() {
        return Report {
            valid: false,
            agent,
            problems,
            warnings,
        };
    }
    for key in table.keys() {
        if !REQUIRED_KEYS.contains(&key.as_str()) && !OPTIONAL_KEYS.contains(&key.as_str()) {
            warnings.push(finding(
                "unknown_key",
                None,
                "a key the engine does not read; check the spelling against the reference",
            ));
        }
    }
    let text = |key: &'static str| table.get(key).and_then(Value::as_str);
    for key in [
        "name",
        "version",
        "tier",
        "author",
        "script",
        "schedule",
        "default_schedule",
        "min_engine",
        "description",
    ] {
        if text(key).is_none() {
            problems.push(finding(
                "wrong_type",
                Some(key),
                format!("{key} must be a string"),
            ));
        }
    }
    if !problems.is_empty() {
        return Report {
            valid: false,
            agent,
            problems,
            warnings,
        };
    }
    let name = text("name").unwrap_or_default();
    let author = text("author").unwrap_or_default();
    if author.is_empty() || !author_text_ok(author) {
        problems.push(finding(
            "invalid_author",
            Some("author"),
            format!(
                "author must be a non-empty name of at most {AUTHOR_MAX} characters, without \
                 surrounding spaces or control characters"
            ),
        ));
    }
    if name != directory_name || !valid_agent_name(name) {
        problems.push(finding(
            "invalid_name",
            Some("name"),
            "name must equal the directory and match a-z0-9-",
        ));
    }
    for key in ["version", "min_engine"] {
        if parse_semver(text(key).unwrap_or_default()).is_none() {
            problems.push(finding(
                "invalid_version",
                Some(key),
                format!("{key} must be x.y.z"),
            ));
        }
    }
    let tier = text("tier").unwrap_or_default();
    if !TIERS.contains(&tier) {
        problems.push(finding(
            "unknown_tier",
            Some("tier"),
            format!("tier must be one of {TIERS:?}"),
        ));
    }
    let schedule = text("schedule").unwrap_or_default();
    let default_schedule = text("default_schedule").unwrap_or_default();
    if !SCHEDULES.contains(&schedule) {
        problems.push(finding(
            "unknown_schedule",
            Some("schedule"),
            format!("schedule must be one of {SCHEDULES:?}"),
        ));
    } else if schedule == "none" {
        if !default_schedule.is_empty() {
            problems.push(finding(
                "schedule_not_empty",
                Some("default_schedule"),
                "default_schedule must be empty when schedule = none",
            ));
        }
    } else if Schedule::parse(default_schedule).is_err()
        || matches!(default_schedule, "@midnight" | "@annually")
    {
        // The installer also accepts the `@midnight` and `@annually` aliases;
        // published agents use the canonical `@daily` and `@yearly`.
        problems.push(finding(
            "invalid_default_schedule",
            Some("default_schedule"),
            "default_schedule is not a cron expression",
        ));
    }
    let script_name = text("script").unwrap_or_default();
    let script_text = if valid_script_name(script_name) {
        match script(script_name) {
            Script::Text(text) => Some(text),
            Script::Problem(problem) => {
                problems.push(problem);
                None
            }
        }
    } else {
        problems.push(finding(
            "invalid_script_name",
            Some("script"),
            "script must be a plain file name in the agent's directory",
        ));
        None
    };
    if script_text
        .as_deref()
        .is_some_and(|t| !valid_script_text(t))
    {
        problems.push(finding(
            "script_not_text",
            Some("script"),
            "script must be text starting with #!",
        ));
    }
    check_paths(table, &mut problems);
    check_isolation(table, schedule, &mut problems);
    check_lists(table, &mut problems);
    if let Some(text) = &script_text {
        check_script(table, text, &mut problems, &mut warnings);
    }
    Report {
        valid: problems.is_empty(),
        agent,
        problems,
        warnings,
    }
}

fn check_paths(table: &serde_json::Map<String, Value>, problems: &mut Vec<Finding>) {
    let paths = table.get("paths").and_then(Value::as_array);
    let all_absolute = paths.is_some_and(|list| {
        list.iter()
            .all(|p| p.as_str().is_some_and(|p| p.starts_with('/')))
    });
    if !all_absolute {
        problems.push(finding(
            "invalid_paths",
            Some("paths"),
            "paths must be a list of absolute paths",
        ));
    } else if paths.is_some_and(|list| {
        list.iter()
            .any(|p| p.as_str().is_some_and(|p| p.split('/').any(|c| c == "..")))
    }) {
        problems.push(finding(
            "invalid_paths",
            Some("paths"),
            "paths must not contain ..",
        ));
    }
}

fn check_isolation(
    table: &serde_json::Map<String, Value>,
    schedule: &str,
    problems: &mut Vec<Finding>,
) {
    let isolation = match table.get("isolation") {
        None => "cron",
        Some(value) => value.as_str().unwrap_or("?"),
    };
    let writable = table.get("writable_paths");
    match isolation {
        "cron" => {
            if writable.is_some() {
                problems.push(finding(
                    "writable_paths_without_systemd",
                    Some("writable_paths"),
                    "writable_paths only applies to isolation = systemd",
                ));
            }
        }
        "systemd" => {
            let valid = writable.and_then(Value::as_array).is_some_and(|list| {
                list.len() <= MAX_WRITABLE_PATHS
                    && list
                        .iter()
                        .all(|p| p.as_str().is_some_and(agent_systemd::valid_writable_path))
            });
            if !valid {
                problems.push(finding(
                    "invalid_writable_paths",
                    Some("writable_paths"),
                    format!(
                        "a systemd agent needs writable_paths, a list of at most \
                         {MAX_WRITABLE_PATHS} absolute paths below /root/.wcp, /var/log, \
                         /var/www or /var/lib/wcp-agent, using only A-Za-z0-9._-"
                    ),
                ));
            }
            if schedule == "none" {
                problems.push(finding(
                    "systemd_without_schedule",
                    Some("isolation"),
                    "a systemd agent needs a schedule (the engine installs a timer)",
                ));
            }
        }
        _ => problems.push(finding(
            "unknown_isolation",
            Some("isolation"),
            "isolation must be one of [\"cron\", \"systemd\"]",
        )),
    }
}

/// A list of strings that are each valid, distinct, and at most `max` long.
fn list_of(value: &Value, max: usize, valid: &dyn Fn(&str) -> bool) -> bool {
    let Some(list) = value.as_array() else {
        return false;
    };
    let mut seen = BTreeSet::new();
    list.len() <= max
        && list
            .iter()
            .all(|v| v.as_str().is_some_and(|s| valid(s) && seen.insert(s)))
}

/// A `requires_*` key, its name check and what it expects, for the message.
type Rule<'a> = (&'static str, &'a dyn Fn(&str) -> bool, String);

fn check_lists(table: &serde_json::Map<String, Value>, problems: &mut Vec<Finding>) {
    let known_helper = |s: &str| IMPLIED_HELPERS.contains(&s) || DECLARED_HELPERS.contains(&s);
    let rules: [Rule<'_>; 3] = [
        (
            "requires_ops",
            &|s: &str| {
                !s.is_empty()
                    && s.len() <= 64
                    && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.')
            },
            "engine operation names such as site.list".into(),
        ),
        (
            "requires_helpers",
            &known_helper,
            format!("helper groups from {AGENT_HELPERS:?}"),
        ),
        (
            "requires_tools",
            &|s: &str| KNOWN_TOOLS.contains(&s),
            format!("tools from {KNOWN_TOOLS:?}"),
        ),
    ];
    for (key, valid, expected) in rules {
        if table
            .get(key)
            .is_some_and(|value| !list_of(value, REQUIRES_MAX, valid))
        {
            problems.push(finding(
                "invalid_requires",
                Some(key),
                format!("{key} must be a list of at most {REQUIRES_MAX} distinct {expected}"),
            ));
        }
    }
    if table
        .get("config_keys")
        .is_some_and(|value| !list_of(value, CONFIG_KEYS_MAX, &valid_config_key))
    {
        problems.push(finding(
            "invalid_config_keys",
            Some("config_keys"),
            format!(
                "config_keys must be a list of at most {CONFIG_KEYS_MAX} distinct names \
                 (letters, digits, '_', not starting with a digit)"
            ),
        ));
    }
    if table
        .get("network")
        .is_some_and(|value| !list_of(value, NETWORK_MAX, &valid_host))
    {
        problems.push(finding(
            "invalid_network",
            Some("network"),
            format!(
                "network must be a list of at most {NETWORK_MAX} distinct host names \
                 (no scheme, port or path)"
            ),
        ));
    }
}

fn valid_config_key(key: &str) -> bool {
    let mut bytes = key.bytes();
    key.len() <= 64
        && bytes
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn valid_host(host: &str) -> bool {
    let bytes = host.as_bytes();
    let edge = |b: u8| b.is_ascii_alphanumeric();
    !bytes.is_empty()
        && bytes.len() <= 253
        && edge(bytes[0])
        && edge(bytes[bytes.len() - 1])
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
}

fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Positions where `word` occurs delimited by non-word characters on both
/// sides.
fn words<'a>(text: &'a str, word: &'a str) -> impl Iterator<Item = usize> + 'a {
    let bytes = text.as_bytes();
    text.match_indices(word)
        .map(|(at, _)| at)
        .filter(move |&at| {
            (at == 0 || !is_word(bytes[at - 1]))
                && bytes.get(at + word.len()).is_none_or(|&b| !is_word(b))
        })
}

fn lines_starting<'a>(text: &'a str, prefix: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    text.lines()
        .filter_map(move |line| line.strip_prefix(prefix))
}

/// The value of a `# key: value` header line (the first one).
fn header<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("# {key}: ");
    text.lines()
        .filter_map(|line| line.strip_prefix(prefix.as_str()))
        .find(|rest| !rest.is_empty() && !rest.contains(char::is_whitespace))
}

/// After `agent`, whitespace (at least one), then a word: the group names.
fn agent_group_after(text: &str, from: usize, end: usize) -> Option<&'static str> {
    let bytes = text.as_bytes();
    for at in words(&text[from..end], "agent") {
        let mut i = from + at + "agent".len();
        let start = i;
        while bytes.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
            i += 1;
        }
        if i == start {
            continue;
        }
        for group in DECLARED_HELPERS {
            if text[i..].starts_with(group)
                && bytes.get(i + group.len()).is_none_or(|&b| !is_word(b))
            {
                return Some(group);
            }
        }
    }
    None
}

/// The helper groups beyond the implied three that the script calls, through
/// `$OPS agent <group>`, `ops-engine agent <group>` or `"agent", "<group>"`.
pub fn used_helpers(text: &str) -> BTreeSet<&'static str> {
    let mut used = BTreeSet::new();
    for marker in ["$OPS", "${OPS", "ops-engine", "OPS_ENGINE"] {
        for (at, _) in text.match_indices(marker) {
            let after = at + marker.len();
            // `$OPS` and `${OPS` must end on a word boundary.
            if marker.starts_with('$') && text.as_bytes().get(after).is_some_and(|&b| is_word(b)) {
                continue;
            }
            let line_end = text[after..].find('\n').map_or(text.len(), |n| after + n);
            if let Some(group) = agent_group_after(text, after, line_end) {
                used.insert(group);
            }
        }
    }
    // The argv form: "agent", "result" (either quote, whitespace between).
    let bytes = text.as_bytes();
    for (at, _) in text.match_indices("agent") {
        let (Some(open), Some(&close)) = (at.checked_sub(1), bytes.get(at + 5)) else {
            continue;
        };
        if !matches!(bytes[open], b'"' | b'\'') || !matches!(close, b'"' | b'\'') {
            continue;
        }
        let mut i = at + 6;
        if bytes.get(i) != Some(&b',') {
            continue;
        }
        i += 1;
        while bytes.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
            i += 1;
        }
        let Some(&quote) = bytes.get(i).filter(|b| matches!(b, b'"' | b'\'')) else {
            continue;
        };
        for group in DECLARED_HELPERS {
            let end = i + 1 + group.len();
            if text[i + 1..].starts_with(group) && bytes.get(end) == Some(&quote) {
                used.insert(group);
            }
        }
    }
    used
}

/// Contract rule 4: a second start while one runs must do nothing. The plain
/// `flock -n N`, the engine helper `agent lock`, and a non-blocking
/// `fcntl.flock` all count.
fn takes_lock(text: &str) -> bool {
    let plain = text.lines().any(|line| {
        line.trim_start()
            .strip_prefix("flock -n ")
            .is_some_and(|rest| rest.bytes().next().is_some_and(|b| b.is_ascii_digit()))
    });
    let helper = words(text, "agent").any(|at| {
        let rest = &text[at + 5..];
        let trimmed = rest.trim_start();
        trimmed.len() < rest.len()
            && trimmed.starts_with("lock")
            && trimmed.as_bytes().get(4).is_none_or(|&b| !is_word(b))
    });
    let python = words(text, "fcntl").any(|at| {
        text[at..]
            .lines()
            .next()
            .is_some_and(|line| line.starts_with("fcntl.flock(") && line.contains("LOCK_NB"))
    });
    plain || helper || python
}

fn check_script(
    table: &serde_json::Map<String, Value>,
    text: &str,
    problems: &mut Vec<Finding>,
    warnings: &mut Vec<Finding>,
) {
    let name = table
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let version = table
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if header(text, "wcp-agent-version") != Some(version) {
        problems.push(finding(
            "header_version_mismatch",
            Some("version"),
            "'# wcp-agent-version' must equal version in agent.toml",
        ));
    }
    if text.contains("b64decode") {
        problems.push(finding(
            "embedded_library",
            None,
            "no base64 blobs; import wcp_agent_lib from the installed file",
        ));
    }
    let imports_library = lines_starting(text, "from wcp_agent_lib import ")
        .next()
        .is_some();
    if words(text, "wcp_agent_lib").next().is_some() && !imports_library {
        problems.push(finding(
            "library_import_form",
            None,
            "use 'from wcp_agent_lib import ...'",
        ));
    }
    let path_line = |line: &str| {
        line.strip_prefix("sys.path.insert(0, ")
            .and_then(|rest| rest.strip_suffix(')'))
            .is_some_and(|middle| middle.contains("agents"))
    };
    if imports_library && !text.lines().any(path_line) {
        problems.push(finding(
            "library_path_missing",
            None,
            "put the agents directory on sys.path before importing wcp_agent_lib",
        ));
    }
    if let Some(declared) = table.get("requires_helpers").and_then(Value::as_array) {
        let declared: BTreeSet<&str> = declared.iter().filter_map(Value::as_str).collect();
        for group in used_helpers(text).difference(&declared) {
            problems.push(finding(
                "undeclared_helper",
                Some("requires_helpers"),
                format!(
                    "the script calls 'agent {group}' but requires_helpers does not list \
                     \"{group}\" (the engine checks it at install)"
                ),
            ));
        }
    } else if table.get("requires_helpers").is_none() {
        for group in used_helpers(text) {
            problems.push(finding(
                "undeclared_helper",
                Some("requires_helpers"),
                format!(
                    "the script calls 'agent {group}' but requires_helpers does not list \
                     \"{group}\" (the engine checks it at install)"
                ),
            ));
        }
    }
    if header(text, "wcp-agent") != Some(name) {
        problems.push(finding(
            "header_name_mismatch",
            Some("name"),
            "'# wcp-agent' must equal name in agent.toml",
        ));
    }
    if !takes_lock(text) {
        problems.push(finding(
            "no_lock",
            None,
            "no lock taken with 'flock -n' or 'ops-engine agent lock' (contract rule 4)",
        ));
    }
    if !text.contains("heartbeat") {
        warnings.push(finding(
            "no_heartbeat",
            None,
            "no heartbeat written on exit (contract rule 3)",
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const LOCK: &str = "exec 9>\"$WCP_DIR/agents/demo.lock\"\nflock -n 9 || exit 0\n";

    fn script(version: &str) -> String {
        format!("#!/usr/bin/env bash\n# wcp-agent: demo\n# wcp-agent-version: {version}\n{LOCK}")
    }

    fn manifest() -> Value {
        json!({"name": "demo", "version": "1.0.0", "tier": "official", "author": "Ada",
               "script": "agent.sh", "schedule": "none", "default_schedule": "",
               "min_engine": "0.1.0", "description": "d", "paths": ["/root/.wcp"]})
    }

    fn check(manifest: &Value, script_text: &str) -> Report {
        validate(manifest, "demo", &|_| Script::Text(script_text.to_owned()))
    }

    fn codes(report: &Report) -> Vec<&'static str> {
        report.problems.iter().map(|p| p.code).collect()
    }

    #[test]
    fn a_complete_agent_is_valid() {
        let report = check(&manifest(), &script("1.0.0"));
        assert!(report.valid, "{:?}", report.problems);
        assert_eq!(report.agent.as_deref(), Some("demo"));
        assert_eq!(codes(&report), Vec::<&str>::new());
    }

    #[test]
    fn missing_keys_are_each_named_and_nothing_else_is_judged() {
        let mut m = manifest();
        m.as_object_mut().unwrap().remove("author");
        m.as_object_mut().unwrap().remove("paths");
        let report = check(&m, "");
        assert!(!report.valid);
        assert_eq!(codes(&report), ["missing_key", "missing_key"]);
    }

    #[test]
    fn a_manifest_that_is_not_a_table_is_invalid() {
        let report = check(&json!(["x"]), &script("1.0.0"));
        assert!(!report.valid);
        assert_eq!(codes(&report), ["manifest_not_an_object"]);
    }

    #[test]
    fn wrong_types_are_reported_not_guessed() {
        let mut m = manifest();
        m["version"] = json!(1);
        assert_eq!(codes(&check(&m, "")), ["wrong_type"]);
    }

    #[test]
    fn author_name_version_tier_and_schedule_rules() {
        let mut m = manifest();
        m["author"] = json!(" Ada");
        m["name"] = json!("Other");
        m["version"] = json!("+1.0.0");
        m["min_engine"] = json!("1.0");
        m["tier"] = json!("gold");
        m["schedule"] = json!("daily");
        let report = check(&m, &script("1.0.0"));
        let found = codes(&report);
        for code in [
            "invalid_author",
            "invalid_name",
            "invalid_version",
            "unknown_tier",
            "unknown_schedule",
        ] {
            assert!(found.contains(&code), "{code} in {found:?}");
        }
    }

    #[test]
    fn schedules_follow_the_engine_cron_rules() {
        let mut m = manifest();
        m["schedule"] = json!("configurable");
        m["default_schedule"] = json!("17 3 * * *");
        assert!(check(&m, &script("1.0.0")).valid);
        m["default_schedule"] = json!("@hourly");
        assert!(check(&m, &script("1.0.0")).valid);
        m["default_schedule"] = json!("@midnight");
        assert_eq!(
            codes(&check(&m, &script("1.0.0"))),
            ["invalid_default_schedule"]
        );
        m["default_schedule"] = json!("1 2 3 4 ?");
        assert_eq!(
            codes(&check(&m, &script("1.0.0"))),
            ["invalid_default_schedule"]
        );
        m["schedule"] = json!("none");
        m["default_schedule"] = json!("@daily");
        assert_eq!(codes(&check(&m, &script("1.0.0"))), ["schedule_not_empty"]);
    }

    #[test]
    fn the_script_must_be_a_plain_name_and_start_with_a_shebang() {
        let mut m = manifest();
        m["script"] = json!("../agent.sh");
        assert_eq!(codes(&check(&m, &script("1.0.0"))), ["invalid_script_name"]);
        let report = check(&manifest(), &script("1.0.0").replacen("#!", "# ", 1));
        assert_eq!(codes(&report), ["script_not_text"]);
    }

    #[test]
    fn a_missing_script_is_a_problem_not_a_pass() {
        let report = validate(&manifest(), "demo", &|_| {
            Script::Problem(finding("script_missing", Some("script"), "x"))
        });
        assert!(!report.valid);
        assert_eq!(codes(&report), ["script_missing"]);
    }

    #[test]
    fn paths_must_be_absolute_and_without_dotdot() {
        let mut m = manifest();
        m["paths"] = json!(["relative"]);
        assert_eq!(codes(&check(&m, &script("1.0.0"))), ["invalid_paths"]);
        m["paths"] = json!(["/var/www/../etc"]);
        assert_eq!(codes(&check(&m, &script("1.0.0"))), ["invalid_paths"]);
    }

    #[test]
    fn isolation_follows_the_installer() {
        let mut m = manifest();
        m["writable_paths"] = json!(["/var/log/x"]);
        assert_eq!(
            codes(&check(&m, &script("1.0.0"))),
            ["writable_paths_without_systemd"]
        );
        m["isolation"] = json!("systemd");
        assert_eq!(
            codes(&check(&m, &script("1.0.0"))),
            ["systemd_without_schedule"]
        );
        m["schedule"] = json!("fixed");
        m["default_schedule"] = json!("@daily");
        assert!(check(&m, &script("1.0.0")).valid);
        m["writable_paths"] = json!(["/etc/passwd"]);
        assert_eq!(
            codes(&check(&m, &script("1.0.0"))),
            ["invalid_writable_paths"]
        );
        m["writable_paths"] = json!(vec!["/var/log/x"; 17]);
        assert_eq!(
            codes(&check(&m, &script("1.0.0"))),
            ["invalid_writable_paths"]
        );
        m["isolation"] = json!("docker");
        assert_eq!(codes(&check(&m, &script("1.0.0"))), ["unknown_isolation"]);
    }

    #[test]
    fn requirement_lists_are_closed_and_distinct() {
        let mut m = manifest();
        m["requires_tools"] = json!(["rclone", "rclone"]);
        m["requires_helpers"] = json!(["nope"]);
        m["requires_ops"] = json!(["site list"]);
        m["config_keys"] = json!(["1BAD"]);
        m["network"] = json!(["https://example.com"]);
        let found = codes(&check(&m, &script("1.0.0")));
        for code in ["invalid_requires", "invalid_config_keys", "invalid_network"] {
            assert!(found.contains(&code), "{code} in {found:?}");
        }
        assert_eq!(
            found.iter().filter(|c| **c == "invalid_requires").count(),
            3
        );
        m["requires_tools"] = json!(["rclone"]);
        m["requires_helpers"] = json!(["result"]);
        m["requires_ops"] = json!(["site.list"]);
        m["config_keys"] = json!(["WEBHOOK_URL"]);
        m["network"] = json!(["hooks.example.com"]);
        assert!(check(&m, &script("1.0.0")).valid);
    }

    #[test]
    fn script_header_must_agree_with_the_manifest() {
        let report = check(&manifest(), &script("1.0.1"));
        assert_eq!(codes(&report), ["header_version_mismatch"]);
        let other = script("1.0.0").replace("# wcp-agent: demo", "# wcp-agent: other");
        assert_eq!(codes(&check(&manifest(), &other)), ["header_name_mismatch"]);
    }

    #[test]
    fn the_shared_library_is_imported_never_embedded() {
        let base = script("1.0.0");
        let blob = format!("{base}exec(base64.b64decode('QQ=='))\n");
        assert_eq!(codes(&check(&manifest(), &blob)), ["embedded_library"]);
        let bare = format!("{base}import wcp_agent_lib\n");
        assert_eq!(codes(&check(&manifest(), &bare)), ["library_import_form"]);
        let no_path = format!("{base}from wcp_agent_lib import run\n");
        assert_eq!(
            codes(&check(&manifest(), &no_path)),
            ["library_path_missing"]
        );
        let with_path = format!(
            "{base}sys.path.insert(0, os.path.join(WCP_DIR, \"agents\"))\nfrom wcp_agent_lib import run\n"
        );
        assert!(check(&manifest(), &with_path).valid);
    }

    #[test]
    fn a_used_helper_group_must_be_declared() {
        let base = script("1.0.0");
        for call in [
            "\"$OPS\" agent result emit demo\n",
            "${OPS} agent site list\n",
            "/usr/local/bin/ops-engine agent tool status rclone\n",
            "subprocess.run([ENGINE, \"agent\", \"config\", \"get\"])\n",
            "OPS_ENGINE agent version\n",
        ] {
            let report = check(&manifest(), &format!("{base}{call}"));
            assert_eq!(codes(&report), ["undeclared_helper"], "{call}");
        }
        let mut m = manifest();
        m["requires_helpers"] = json!(["result"]);
        let ok = format!("{base}\"$OPS\" agent result emit demo\n");
        assert!(check(&m, &ok).valid);
        // The implied helpers and unrelated words need no declaration.
        let implied =
            format!("{base}\"$OPS\" agent heartbeat demo\n\"$OPS\" agent lock demo -- true\n");
        assert!(check(&manifest(), &implied).valid);
        assert!(check(&manifest(), &format!("{base}# agent resulting\n")).valid);
    }

    #[test]
    fn a_script_without_a_lock_is_invalid_and_each_lock_form_counts() {
        let bare = "#!/bin/sh\n# wcp-agent: demo\n# wcp-agent-version: 1.0.0\n";
        assert_eq!(codes(&check(&manifest(), bare)), ["no_lock"]);
        for lock in [
            "flock -n 9 || exit 0\n",
            "  flock -n 200\n",
            "\"$OPS\" agent lock demo -- run\n",
            "fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)\n",
        ] {
            let text = format!("{bare}{lock}");
            assert!(
                !codes(&check(&manifest(), &text)).contains(&"no_lock"),
                "{lock}"
            );
        }
        let blocking = format!("{bare}flock 9\nfcntl.flock(fh, fcntl.LOCK_EX)\n");
        assert_eq!(codes(&check(&manifest(), &blocking)), ["no_lock"]);
    }

    #[test]
    fn a_missing_heartbeat_is_a_warning_not_a_problem() {
        let report = check(&manifest(), &script("1.0.0"));
        assert!(report.valid);
        assert_eq!(report.warnings[0].code, "no_heartbeat");
        let with = format!("{}trap 'agent heartbeat demo' EXIT\n", script("1.0.0"));
        assert!(check(&manifest(), &with).warnings.is_empty());
    }

    #[test]
    fn an_unknown_key_is_a_warning() {
        let mut m = manifest();
        m["requires_helper"] = json!(["result"]);
        let report = check(&m, &script("1.0.0"));
        assert!(report.valid);
        assert!(report.warnings.iter().any(|w| w.code == "unknown_key"));
    }

    #[test]
    fn semver_is_digits_only() {
        assert_eq!(parse_semver("1.20.3"), Some((1, 20, 3)));
        for bad in [
            "+1.0.0", "1.0", "1.0.0.0", "1..0", "a.b.c", " 1.0.0", "1.0.-1",
        ] {
            assert_eq!(parse_semver(bad), None, "{bad}");
        }
    }

    #[test]
    fn findings_never_carry_manifest_values() {
        let mut m = manifest();
        m["author"] = json!("secret-token \u{7}");
        m["description"] = json!("secret-token");
        let report = check(&m, &script("1.0.0"));
        assert!(
            !serde_json::to_string(&report)
                .unwrap()
                .contains("secret-token")
        );
    }
}
