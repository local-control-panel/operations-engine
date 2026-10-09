//! The bundled host agents (`/root/.wcp/agents/*.sh`), installed, removed and
//! unbanned by the engine instead of by SFTP writes and `sudo` one-liners.
//!
//! Three operations share one design:
//!
//! - `agent.install` writes the agent's script and shared library atomically,
//!   records it in `manifest.json` and only then commits the cron line, so a
//!   failure at any step restores the previous files and leaves the crontab as
//!   it was. The scripts are compiled into the engine: the caller names an
//!   agent, it never supplies code. Installing again is the update path; the
//!   schedule the operator chose is kept.
//! - `agent.remove` takes the cron line out first (cron never runs a missing
//!   file), then the manifest entry and the script.
//! - `agent.bruteforceUnban` drops one IP from the active-ban file, then runs
//!   the installed guard with `--apply-only`, which hands the remaining list to
//!   `ingress.applyBans`.
//!
//! Install and remove hold the same per-user cron lock scope as
//! `cron.installTab` (`cron/root`), so the panel's generic cron writes cannot
//! interleave with them.

use crate::{
    backup_schedule::Schedule,
    transaction::{IdempotencyKey, RequestId},
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[cfg(unix)]
pub mod execute;

pub const INSTALL_OPERATION: &str = "agent.install";
pub const REMOVE_OPERATION: &str = "agent.remove";
pub const UNBAN_OPERATION: &str = "agent.bruteforceUnban";

pub const ROOT: &str = crate::agent_config::ROOT;
pub const AGENTS_DIR: &str = "agents";
pub const MANIFEST_FILE: &str = "manifest.json";
pub const LIBRARY_FILE: &str = "wcp_agent_lib.py";
pub const BANS_FILE: &str = "bruteforce-active-bans.txt";
pub const EVENTS_FILE: &str = "bruteforce-events.jsonl";
pub const GUARD_NAME: &str = "bruteforce-guard";
/// Comment tag that marks a cron line as an agent's, shared with the panel's
/// pre-engine format.
pub const TAG: &str = "[wcp-agent]";
const MAX_TAB_BYTES: usize = 256 * 1024;

const LIBRARY: &str = include_str!("../resources/agents/wcp_agent_lib.py");

/// One agent the engine can install. The panel keeps the human-readable
/// description; everything that decides what runs as root lives here.
pub struct Agent {
    pub name: &'static str,
    pub version: &'static str,
    /// Cron schedule registered at install time, or none for an agent that is
    /// started by something else.
    pub default_schedule: Option<&'static str>,
    /// Whether the caller may pick the schedule. False for the tight
    /// monitoring loops, which keep their fixed cadence.
    pub configurable_schedule: bool,
    script: &'static str,
    /// Built-in agents inline the shared library. An agent installed from the
    /// registry is self-contained and is written exactly as it was verified.
    pub bundled: bool,
}

/// Lowercase letters, digits and `-`, starting with a letter or digit.
pub fn valid_agent_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    name.len() <= 64
        && bytes
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl Agent {
    /// An agent that was verified against the registry. The engine is a
    /// one-shot process per request, so the few strings are leaked instead of
    /// threading a lifetime through every pipeline.
    pub fn from_registry(
        name: String,
        version: String,
        default_schedule: Option<String>,
        configurable_schedule: bool,
        script: String,
    ) -> &'static Agent {
        Box::leak(Box::new(Agent {
            name: Box::leak(name.into_boxed_str()),
            version: Box::leak(version.into_boxed_str()),
            default_schedule: default_schedule.map(|text| &*Box::leak(text.into_boxed_str())),
            configurable_schedule,
            script: Box::leak(script.into_boxed_str()),
            bundled: false,
        }))
    }

    /// Only a name, for removing an agent the registry installed: removal
    /// needs the name and nothing else.
    fn named(name: String) -> &'static Agent {
        Self::from_registry(name, String::new(), None, false, String::new())
    }

    /// The file that is written to disk: the script with the shared library
    /// inlined, because the scripts run their Python from a heredoc, where
    /// `import wcp_agent_lib` cannot find a file next to the script.
    pub fn installed_script(&self) -> String {
        if self.bundled {
            bundle(self.script)
        } else {
            self.script.to_owned()
        }
    }

    pub fn relative_script_path(&self) -> String {
        format!("{AGENTS_DIR}/{}.sh", self.name)
    }

    pub fn absolute_script_path(&self) -> String {
        format!("{ROOT}/{AGENTS_DIR}/{}.sh", self.name)
    }
}

pub static AGENTS: [Agent; 7] = [
    Agent {
        name: "metrics-agent",
        version: "1.1.0",
        default_schedule: Some("* * * * *"),
        configurable_schedule: false,
        script: include_str!("../resources/agents/metrics-agent.sh"),
        bundled: true,
    },
    Agent {
        name: "resource-alert",
        version: "1.0.0",
        default_schedule: Some("*/5 * * * *"),
        configurable_schedule: false,
        script: include_str!("../resources/agents/resource-alert.sh"),
        bundled: true,
    },
    Agent {
        name: "backup-agent",
        version: "1.1.0",
        default_schedule: None,
        configurable_schedule: false,
        script: include_str!("../resources/agents/backup-agent.sh"),
        bundled: true,
    },
    Agent {
        name: GUARD_NAME,
        version: "1.0.0",
        default_schedule: Some("* * * * *"),
        configurable_schedule: false,
        script: include_str!("../resources/agents/bruteforce-guard.sh"),
        bundled: true,
    },
    Agent {
        name: "backup-restore-drill",
        version: "1.1.0",
        default_schedule: Some("0 3 * * *"),
        configurable_schedule: true,
        script: include_str!("../resources/agents/backup-restore-drill.sh"),
        bundled: true,
    },
    Agent {
        name: "error-log-digest",
        version: "1.0.0",
        default_schedule: Some("0 8 * * *"),
        configurable_schedule: true,
        script: include_str!("../resources/agents/error-log-digest.sh"),
        bundled: true,
    },
    Agent {
        name: "cache-warmup",
        version: "1.0.0",
        default_schedule: Some("0 4 * * *"),
        configurable_schedule: true,
        script: include_str!("../resources/agents/cache-warmup.sh"),
        bundled: true,
    },
];

pub fn find(name: &str) -> Option<&'static Agent> {
    AGENTS.iter().find(|agent| agent.name == name)
}

pub fn library() -> &'static str {
    LIBRARY
}

/// Byte-for-byte what the panel's `bundle_agent_script` produced, so an agent
/// installed by the engine behaves exactly like one installed over SFTP.
pub fn bundle(script: &str) -> String {
    let library = base64(LIBRARY.as_bytes());
    script.replace(
        "from wcp_agent_lib import",
        &format!(
            "import base64, types\n_agent_lib = types.ModuleType('wcp_agent_lib')\nexec(base64.b64decode('{library}'), _agent_lib.__dict__)\nsys.modules['wcp_agent_lib'] = _agent_lib\nfrom wcp_agent_lib import"
        ),
    )
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(char::from(ALPHABET[(n >> 18) as usize & 63]));
        out.push(char::from(ALPHABET[(n >> 12) as usize & 63]));
        out.push(if chunk.len() > 1 {
            char::from(ALPHABET[(n >> 6) as usize & 63])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(ALPHABET[n as usize & 63])
        } else {
            '='
        });
    }
    out
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    UnknownAgent,
    InvalidSchedule,
    ScheduleNotConfigurable,
    InvalidIp,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

fn ids(
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
struct InstallPlan {
    name: String,
    schedule: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RemovePlan {
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UnbanPlan {
    ip: String,
}

pub struct InstallRequest {
    pub agent: &'static Agent,
    /// Only ever present for an agent whose schedule is configurable.
    pub schedule: Option<Schedule>,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl InstallRequest {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: InstallPlan =
            serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        let agent = find(&plan.name).ok_or(RequestError::UnknownAgent)?;
        let schedule = match plan.schedule {
            None => None,
            Some(_) if !agent.configurable_schedule => {
                return Err(RequestError::ScheduleNotConfigurable);
            }
            Some(value) => {
                Some(Schedule::parse(&value).map_err(|_| RequestError::InvalidSchedule)?)
            }
        };
        let (request_id, idempotency_key) = ids(request_id, key)?;
        Ok(Self {
            agent,
            schedule,
            request_id,
            idempotency_key,
        })
    }
}

pub struct RemoveRequest {
    pub agent: &'static Agent,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl RemoveRequest {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: RemovePlan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        let agent = find(&plan.name)
            .or_else(|| valid_agent_name(&plan.name).then(|| Agent::named(plan.name.clone())))
            .ok_or(RequestError::UnknownAgent)?;
        let (request_id, idempotency_key) = ids(request_id, key)?;
        Ok(Self {
            agent,
            request_id,
            idempotency_key,
        })
    }
}

pub struct UnbanRequest {
    pub ip: IpAddr,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl UnbanRequest {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: UnbanPlan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        let ip = plan.ip.parse().map_err(|_| RequestError::InvalidIp)?;
        let (request_id, idempotency_key) = ids(request_id, key)?;
        Ok(Self {
            ip,
            request_id,
            idempotency_key,
        })
    }
}

pub fn tab_too_large(tab: &str) -> bool {
    tab.len() > MAX_TAB_BYTES
}

fn render(lines: Vec<String>) -> String {
    if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    }
}

/// Whether `line` carries this agent's tag. The name must end at a word
/// boundary so one agent's name can never match a longer one.
fn is_agent_line(line: &str, name: &str) -> bool {
    let tag = format!("{TAG} {name}");
    line.match_indices(&tag).any(|(at, _)| {
        line[at + tag.len()..]
            .chars()
            .next()
            .is_none_or(char::is_whitespace)
    })
}

/// The schedule of the first (enabled or disabled) line for `name`.
pub fn current_schedule(tab: &str, name: &str) -> Option<Schedule> {
    let line = tab.lines().find(|line| is_agent_line(line, name))?;
    let mut fields = line.trim().trim_start_matches('#').split_whitespace();
    let first = fields.next()?;
    let text = if first.starts_with('@') {
        first.to_owned()
    } else {
        std::iter::once(first)
            .chain(fields.by_ref().take(4))
            .collect::<Vec<_>>()
            .join(" ")
    };
    Schedule::parse(&text).ok()
}

/// The cron line that runs `agent` on `schedule`.
pub fn cron_line(agent: &Agent, schedule: &Schedule) -> String {
    format!(
        "{} bash '{}' # {TAG} {}",
        schedule.as_str(),
        agent.absolute_script_path(),
        agent.name
    )
}

/// The tab with every line of `agent` replaced by one line on `schedule`
/// (or by none), plus how many lines were replaced. Other lines are kept.
pub fn with_agent(tab: &str, agent: &Agent, schedule: Option<&Schedule>) -> (String, usize) {
    let mut replaced = 0;
    let mut lines: Vec<String> = tab
        .lines()
        .filter(|line| {
            let hit = is_agent_line(line, agent.name);
            replaced += usize::from(hit);
            !hit
        })
        .map(str::to_owned)
        .collect();
    if let Some(schedule) = schedule {
        lines.push(cron_line(agent, schedule));
    }
    (render(lines), replaced)
}

/// The tab without `agent`'s lines, plus how many were removed.
pub fn without_agent(tab: &str, agent: &Agent) -> (String, usize) {
    with_agent(tab, agent, None)
}

/// `manifest.json` after setting (`Some`) or dropping (`None`) one entry.
/// Unreadable or non-object content counts as an empty manifest, as it did
/// when the panel rewrote it; entries of other agents are kept untouched.
pub fn manifest_with(
    current: Option<&str>,
    name: &str,
    entry: Option<serde_json::Value>,
) -> String {
    let mut manifest = match current.and_then(|text| serde_json::from_str(text).ok()) {
        Some(serde_json::Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    };
    match entry {
        Some(value) => {
            manifest.insert(name.to_owned(), value);
        }
        None => {
            manifest.remove(name);
        }
    }
    serde_json::to_string_pretty(&serde_json::Value::Object(manifest))
        .expect("a JSON object serializes")
}

/// The `installed_at` of an entry, when `current` has one for `name`.
pub fn manifest_entry(current: Option<&str>, name: &str) -> Option<serde_json::Value> {
    match serde_json::from_str(current?).ok()? {
        serde_json::Value::Object(mut map) => map.remove(name),
        _ => None,
    }
}

/// The ban file without the lines for `ip`, plus how many were removed. A
/// line matches when its first field *is* that address, whatever spelling it
/// was written in; everything else, including malformed lines, is kept.
pub fn without_ban(bans: &str, ip: IpAddr) -> (String, usize) {
    let mut removed = 0;
    let mut kept = String::with_capacity(bans.len());
    for line in bans.split_inclusive('\n') {
        let hit = line
            .split_whitespace()
            .next()
            .and_then(|first| first.parse::<IpAddr>().ok())
            == Some(ip);
        removed += usize::from(hit);
        if !hit {
            kept.push_str(line);
        }
    }
    (kept, removed)
}

/// The JSONL event the guard's own log uses for a manual unban.
pub fn unban_event(ip: IpAddr, ts: u64) -> String {
    format!("{{\"ts\":{ts},\"action\":\"unban\",\"ip\":\"{ip}\",\"jail\":\"manual\"}}\n")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallResult {
    pub name: String,
    pub version: String,
    /// The schedule now in the crontab, or none for an unscheduled agent.
    pub schedule: Option<String>,
    /// False when the files and the crontab already matched.
    pub changed: bool,
    pub replaced_cron_lines: u32,
    /// SHA-256 of the installed script file.
    pub script_sha256: String,
    pub installed_at_unix_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveResult {
    pub name: String,
    /// False when there was nothing of this agent to remove.
    pub removed: bool,
    pub removed_cron_lines: u32,
    pub removed_at_unix_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnbanResult {
    pub ip: String,
    pub removed_bans: u32,
    /// Whether the guard ran `--apply-only`. False when it is not installed,
    /// in which case there is no Caddyfile block to take out either.
    pub applied: bool,
    pub unbanned_at_unix_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    /// SHA-256 of every installed script (bundled with the library). The panel
    /// pins the same values, so a script edited on one side only fails a test
    /// on that side.
    pub const PINNED: [(&str, &str); 7] = [
        (
            "metrics-agent",
            "ffe4396a1a3a1de9289509ea43fdcbea6806524222d4acdd91cd5e3ae2baf883",
        ),
        (
            "resource-alert",
            "efb4916b100782f781922d44cbd0e12a94753579622c38bac2aa35674ecb3b9f",
        ),
        (
            "backup-agent",
            "4e11c76d30c28e5e3139441d8ea7f2c2a0f9e7bc704465e682c395f39def259b",
        ),
        (
            "bruteforce-guard",
            "57ef84978e6a5c9e37d319f1a35fb20256b615572061135ecb164f88eec0e962",
        ),
        (
            "backup-restore-drill",
            "6cd1563d4865a282fa06d0c00cba7cbbfa384154ecf0d3578509509de7d9c4e5",
        ),
        (
            "error-log-digest",
            "a5d475708c2718b05f7dda7335d050e340a46fb06e701d1945b9bc173631c015",
        ),
        (
            "cache-warmup",
            "f85f9c8a5b23980e2e2f3dd11a8386991f74c9bd5e3b4d48c41bdf3f35e06eec",
        ),
    ];

    fn digest(text: &str) -> String {
        crate::ingress::ConfigHash::of(text.as_bytes())
            .as_str()
            .to_owned()
    }

    #[test]
    fn base64_matches_the_standard_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn every_script_inlines_the_library_once_and_is_pinned() {
        for (agent, (name, pin)) in AGENTS.iter().zip(PINNED) {
            assert_eq!(agent.name, name);
            let installed = agent.installed_script();
            assert_eq!(
                installed.matches("_agent_lib.__dict__").count(),
                1,
                "{name}"
            );
            assert_eq!(
                digest(&installed),
                pin,
                "{name} drifted from the pinned digest"
            );
        }
    }

    #[test]
    fn the_guard_applies_bans_through_the_engine_and_never_edits_routes() {
        let script = find(GUARD_NAME).unwrap().installed_script();
        assert!(script.contains("\"ingress\", \"apply-bans\""));
        for forbidden in [
            "docker",
            "frankenphp",
            "Caddyfile.d",
            "caddy reload",
            ".caddyfile",
        ] {
            assert!(
                !script.contains(forbidden),
                "the guard must not reference {forbidden:?}"
            );
        }
    }

    #[test]
    fn install_request_takes_a_name_and_only_a_configurable_schedule() {
        let ok = InstallRequest::parse(
            r#"{"name":"cache-warmup","schedule":"0 5 * * 1"}"#,
            ID,
            Some("k"),
        )
        .unwrap();
        assert_eq!(ok.schedule.unwrap().as_str(), "0 5 * * 1");
        assert!(
            InstallRequest::parse(r#"{"name":"cache-warmup"}"#, ID, None)
                .unwrap()
                .schedule
                .is_none()
        );
        let reject = |json: &str| InstallRequest::parse(json, ID, None).err().unwrap();
        assert_eq!(reject(r#"{"name":"nope"}"#), RequestError::UnknownAgent);
        assert_eq!(reject(r#"{"name":"../x"}"#), RequestError::UnknownAgent);
        assert_eq!(
            reject(r#"{"name":"metrics-agent","schedule":"0 5 * * *"}"#),
            RequestError::ScheduleNotConfigurable
        );
        assert_eq!(
            reject(r#"{"name":"cache-warmup","schedule":"0 5 * * *; rm -rf /"}"#),
            RequestError::InvalidSchedule
        );
        assert_eq!(
            reject(r#"{"name":"cache-warmup","script":"x"}"#),
            RequestError::InvalidJson
        );
        assert_eq!(reject("nope"), RequestError::InvalidJson);
        assert_eq!(
            InstallRequest::parse(r#"{"name":"cache-warmup"}"#, "x", None)
                .err()
                .unwrap(),
            RequestError::InvalidRequestId
        );
    }

    #[test]
    fn remove_and_unban_requests_are_strict() {
        assert!(RemoveRequest::parse(r#"{"name":"backup-agent"}"#, ID, None).is_ok());
        // A name outside the catalog may belong to a registry agent.
        assert!(RemoveRequest::parse(r#"{"name":"disk-report"}"#, ID, None).is_ok());
        for name in ["../x", "X", "a b", "", "-x", "a;b"] {
            assert_eq!(
                RemoveRequest::parse(&format!(r#"{{"name":"{name}"}}"#), ID, None)
                    .err()
                    .unwrap(),
                RequestError::UnknownAgent,
                "{name:?}"
            );
        }
        assert!(UnbanRequest::parse(r#"{"ip":"203.0.113.7"}"#, ID, None).is_ok());
        assert!(UnbanRequest::parse(r#"{"ip":"::1"}"#, ID, None).is_ok());
        for ip in ["1.2.3.4; rm -rf /", "not-an-ip", "", "1.2.3.4 ", "1.2.3"] {
            assert_eq!(
                UnbanRequest::parse(&format!(r#"{{"ip":"{ip}"}}"#), ID, None)
                    .err()
                    .unwrap(),
                RequestError::InvalidIp,
                "{ip:?}"
            );
        }
    }

    #[test]
    fn the_cron_line_has_the_shape_the_panel_wrote() {
        let agent = find("cache-warmup").unwrap();
        let schedule = Schedule::parse("0 4 * * *").unwrap();
        assert_eq!(
            cron_line(agent, &schedule),
            "0 4 * * * bash '/root/.wcp/agents/cache-warmup.sh' # [wcp-agent] cache-warmup"
        );
    }

    #[test]
    fn tab_edits_replace_only_this_agents_lines() {
        let agent = find("backup-agent").unwrap();
        let other = find("backup-restore-drill").unwrap();
        let tab = format!(
            "MAILTO=x\n{}\n{}\n# [wcp-agent] backup-agent-extra\n0 1 * * * true # [wcp-agent] backup-agent\n",
            cron_line(other, &Schedule::parse("0 3 * * *").unwrap()),
            "5 5 * * * echo hi",
        );
        let (without, removed) = without_agent(&tab, agent);
        assert_eq!(removed, 1);
        assert!(without.contains("backup-restore-drill"));
        assert!(without.contains("backup-agent-extra"));
        assert!(without.contains("MAILTO=x\n"));
        assert!(!without.contains("true # [wcp-agent] backup-agent"));
        assert_eq!(without_agent(&without, agent).1, 0);
    }

    #[test]
    fn with_agent_is_idempotent_and_keeps_the_schedule() {
        let agent = find("cache-warmup").unwrap();
        let weekly = Schedule::parse("0 5 * * 1").unwrap();
        let (first, replaced) = with_agent("", agent, Some(&weekly));
        assert_eq!(replaced, 0);
        let kept = current_schedule(&first, agent.name).unwrap();
        assert_eq!(kept.as_str(), "0 5 * * 1");
        let (again, replaced) = with_agent(&first, agent, Some(&kept));
        assert_eq!((again, replaced), (first, 1));
        assert_eq!(
            with_agent("x\n", find("backup-agent").unwrap(), None).0,
            "x\n"
        );
    }

    #[test]
    fn schedule_is_read_from_keyword_and_disabled_lines() {
        assert_eq!(
            current_schedule(
                "@daily bash 'x' # [wcp-agent] cache-warmup\n",
                "cache-warmup"
            )
            .unwrap()
            .as_str(),
            "@daily"
        );
        assert_eq!(
            current_schedule(
                "#0 6 * * * bash 'x' # [wcp-agent] cache-warmup\n",
                "cache-warmup"
            )
            .unwrap()
            .as_str(),
            "0 6 * * *"
        );
        assert!(current_schedule("0 6 * * * x # [wcp-agent] other\n", "cache-warmup").is_none());
    }

    #[test]
    fn manifest_edits_keep_other_entries_and_survive_garbage() {
        let entry = serde_json::json!({"version": "1.0.0", "installed_at": 5});
        let one = manifest_with(None, "a", Some(entry.clone()));
        let two = manifest_with(Some(&one), "b", Some(entry.clone()));
        assert_eq!(manifest_entry(Some(&two), "a"), Some(entry.clone()));
        let dropped = manifest_with(Some(&two), "a", None);
        assert!(manifest_entry(Some(&dropped), "a").is_none());
        assert!(manifest_entry(Some(&dropped), "b").is_some());
        assert!(manifest_with(Some("{broken"), "a", None).starts_with('{'));
        assert_eq!(manifest_with(Some("[1]"), "a", None), "{}");
    }

    #[test]
    fn unban_matches_the_address_not_its_spelling() {
        let bans = "203.0.113.7 caddy 1 2\n2001:db8::1 wp_login 1 2\n203.0.113.70 caddy 1 2\ngarbage\n2001:0db8:0:0:0:0:0:1 caddy 3 4\n";
        let (rest, removed) = without_ban(bans, "2001:db8::1".parse().unwrap());
        assert_eq!(removed, 2);
        assert_eq!(
            rest,
            "203.0.113.7 caddy 1 2\n203.0.113.70 caddy 1 2\ngarbage\n"
        );
        let (rest, removed) = without_ban(bans, "203.0.113.7".parse().unwrap());
        assert_eq!(removed, 1);
        assert!(rest.contains("203.0.113.70"));
        assert_eq!(without_ban("", "::1".parse().unwrap()), (String::new(), 0));
    }

    #[test]
    fn unban_event_is_one_json_line() {
        let line = unban_event("203.0.113.7".parse().unwrap(), 7);
        let value: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(value["action"], "unban");
        assert_eq!(value["ip"], "203.0.113.7");
        assert_eq!(value["jail"], "manual");
        assert!(line.ends_with('\n'));
    }
}
