//! `agent.installFromRegistry` and `agent.approve`: agents that live in the
//! open `local-control-panel/agents` repository instead of in this binary.
//!
//! The caller never supplies code or an address. A request names an agent, the
//! release tag it was published in and the SHA-256 of the agent's script. The
//! engine downloads `registry.json` of that release and the script from the
//! repository address compiled into this file, and installs only when
//!
//! - the registry is schema 1, belongs to the requested release and lists the
//!   agent with a `scripts` entry inside `agents/<name>/`;
//! - the version is not in the registry's `revoked` list and this engine is at
//!   least the agent's `minEngine`;
//! - the downloaded script hashes to the registry's value **and** to the value
//!   the caller supplied (so what the operator reviewed is what runs);
//! - a `community` agent was approved for exactly that hash on this host
//!   (`agent.approve`).
//!
//! The install itself is the existing `agent.install` pipeline: atomic files,
//! the cron line last, rollback on failure. Built-in agents keep their names;
//! the registry cannot replace one.

use crate::{
    agent_lifecycle::{self, Agent, valid_agent_name},
    agent_systemd,
    backup_schedule::Schedule,
    engine::fetch,
    error::ErrorCode,
    ingress::ConfigHash,
};
use serde::Deserialize;
use std::{collections::BTreeMap, time::Duration};

pub const INSTALL_OPERATION: &str = "agent.installFromRegistry";
pub const APPROVE_OPERATION: &str = "agent.approve";
pub const UNAPPROVE_OPERATION: &str = "agent.unapprove";

/// Where releases are published. These are the only addresses the engine
/// fetches agents from; no request can change them.
pub const RELEASES_BASE: &str = "https://github.com/local-control-panel/agents/releases/download";
pub const RAW_BASE: &str = "https://raw.githubusercontent.com/local-control-panel/agents";

pub const MAX_REGISTRY_BYTES: u64 = 1024 * 1024;
pub const MAX_WRITABLE_PATHS: usize = 16;
pub const MAX_SCRIPT_BYTES: u64 = 256 * 1024;
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(60);

pub const APPROVALS_DIR: &str = "agent-approvals";

/// The two addresses, so tests can point at a local server.
#[derive(Clone, Debug)]
pub struct Source {
    pub releases_base: String,
    pub raw_base: String,
}

impl Default for Source {
    fn default() -> Self {
        Self {
            releases_base: RELEASES_BASE.to_owned(),
            raw_base: RAW_BASE.to_owned(),
        }
    }
}

pub type Fetcher<'a> = &'a dyn Fn(&str, u64) -> Result<Vec<u8>, fetch::Error>;

/// The fetcher production uses.
pub fn network_fetch(url: &str, max_bytes: u64) -> Result<Vec<u8>, fetch::Error> {
    fetch::fetch_bytes_bounded(url, max_bytes, FETCH_TIMEOUT)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    InvalidName,
    InvalidRelease,
    InvalidHash,
    InvalidSchedule,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

fn is_hash(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_release(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty() && part.len() <= 9 && part.bytes().all(|b| b.is_ascii_digit())
        })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InstallPlan {
    name: String,
    release: String,
    sha256: String,
    schedule: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApprovePlan {
    name: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UnapprovePlan {
    name: String,
    sha256: Option<String>,
}

#[derive(Debug)]
pub struct InstallRequest {
    pub name: String,
    pub release: String,
    pub sha256: String,
    pub schedule: Option<Schedule>,
}

impl InstallRequest {
    pub fn parse(json: &str) -> Result<Self, RequestError> {
        let plan: InstallPlan =
            serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        if !valid_agent_name(&plan.name) {
            return Err(RequestError::InvalidName);
        }
        if !is_release(&plan.release) {
            return Err(RequestError::InvalidRelease);
        }
        if !is_hash(&plan.sha256) {
            return Err(RequestError::InvalidHash);
        }
        let schedule = plan
            .schedule
            .map(|value| Schedule::parse(&value).map_err(|_| RequestError::InvalidSchedule))
            .transpose()?;
        Ok(Self {
            name: plan.name,
            release: plan.release,
            sha256: plan.sha256,
            schedule,
        })
    }
}

#[derive(Debug)]
pub struct ApproveRequest {
    pub name: String,
    pub sha256: String,
}

impl ApproveRequest {
    pub fn parse(json: &str) -> Result<Self, RequestError> {
        let plan: ApprovePlan =
            serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        if !valid_agent_name(&plan.name) {
            return Err(RequestError::InvalidName);
        }
        if !is_hash(&plan.sha256) {
            return Err(RequestError::InvalidHash);
        }
        Ok(Self {
            name: plan.name,
            sha256: plan.sha256,
        })
    }
}

/// Withdraws approvals: the one for `sha256`, or every approval of the agent
/// when no hash is given.
#[derive(Debug)]
pub struct UnapproveRequest {
    pub name: String,
    pub sha256: Option<String>,
}

impl UnapproveRequest {
    pub fn parse(json: &str) -> Result<Self, RequestError> {
        let plan: UnapprovePlan =
            serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        if !valid_agent_name(&plan.name) {
            return Err(RequestError::InvalidName);
        }
        if plan.sha256.as_deref().is_some_and(|hash| !is_hash(hash)) {
            return Err(RequestError::InvalidHash);
        }
        Ok(Self {
            name: plan.name,
            sha256: plan.sha256,
        })
    }

    /// Whether the marker file `file` (a name in `APPROVALS_DIR`) is one this
    /// request withdraws. Agent names may contain `-`, so the hash is split
    /// off the end rather than the name off the front.
    pub fn matches(&self, file: &str) -> bool {
        let Some((name, hash)) = file.rsplit_once('-') else {
            return false;
        };
        name == self.name && is_hash(hash) && self.sha256.as_deref().is_none_or(|h| h == hash)
    }
}

/// The name of the marker file that records an approval: one file per agent
/// and hash, so approving needs no read-modify-write.
pub fn approval_file(name: &str, sha256: &str) -> String {
    format!("{APPROVALS_DIR}/{name}-{sha256}")
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Registry {
    schema: u32,
    release: String,
    agents: BTreeMap<String, RegistryAgent>,
    #[serde(default)]
    revoked: Vec<Revoked>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegistryAgent {
    version: String,
    tier: String,
    schedule: String,
    default_schedule: String,
    min_engine: String,
    /// `cron` (the default) or `systemd`.
    #[serde(default)]
    isolation: String,
    #[serde(default)]
    writable_paths: Vec<String>,
    script: String,
    files: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct Revoked {
    name: String,
    version: String,
}

#[derive(Debug)]
pub enum Error {
    Fetch(fetch::Error),
    BadRegistry(&'static str),
    UnknownAgent,
    BuiltIn,
    Revoked,
    EngineTooOld,
    HashMismatch,
    NotApproved,
    ScheduleNotConfigurable,
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Fetch(fetch::Error::Timeout) => (
                ErrorCode::Timeout,
                "the agent registry did not answer in time".into(),
            ),
            Self::Fetch(_) => (
                ErrorCode::ArtifactFetchFailed,
                "could not download the agent from the registry".into(),
            ),
            Self::BadRegistry(why) => (
                ErrorCode::ArtifactVerificationFailed,
                format!("the registry is not usable: {why}"),
            ),
            Self::UnknownAgent => (
                ErrorCode::NotFound,
                "the release does not contain this agent".into(),
            ),
            Self::BuiltIn => (
                ErrorCode::InvalidInput,
                "this name belongs to a built-in agent".into(),
            ),
            Self::Revoked => (
                ErrorCode::InvalidInput,
                "this agent version has been revoked".into(),
            ),
            Self::EngineTooOld => (
                ErrorCode::InvalidInput,
                "this agent needs a newer engine".into(),
            ),
            Self::HashMismatch => (
                ErrorCode::ArtifactVerificationFailed,
                "the script does not match the registry or the reviewed hash".into(),
            ),
            Self::NotApproved => (
                ErrorCode::InvalidInput,
                "a community agent must be approved for this exact hash first".into(),
            ),
            Self::ScheduleNotConfigurable => (
                ErrorCode::InvalidInput,
                "this agent runs on a fixed schedule".into(),
            ),
        }
    }
}

/// An agent whose script was downloaded and checked.
pub struct Verified {
    pub agent: &'static Agent,
    pub tier: Tier,
    pub script_sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tier {
    Official,
    Community,
}

fn sha256(bytes: &[u8]) -> String {
    ConfigHash::of(bytes).as_str().to_owned()
}

fn parse_semver(text: &str) -> Option<(u64, u64, u64)> {
    let mut parts = text.split('.');
    let triple = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    );
    parts.next().is_none().then_some(triple)
}

/// Downloads and verifies one agent. Approval of a community agent is checked
/// by the caller with `approved`, so this stays free of filesystem access.
pub fn fetch_verified(
    source: &Source,
    fetch: Fetcher<'_>,
    request: &InstallRequest,
    engine_version: &str,
    approved: &dyn Fn(&str, &str) -> bool,
) -> Result<Verified, Error> {
    if agent_lifecycle::find(&request.name).is_some() {
        return Err(Error::BuiltIn);
    }
    let registry_url = format!(
        "{}/{}/registry.json",
        source.releases_base.trim_end_matches('/'),
        request.release
    );
    let registry: Registry =
        serde_json::from_slice(&fetch(&registry_url, MAX_REGISTRY_BYTES).map_err(Error::Fetch)?)
            .map_err(|_| Error::BadRegistry("not valid JSON"))?;
    if registry.schema != 1 {
        return Err(Error::BadRegistry("unsupported schema"));
    }
    if registry.release != request.release {
        return Err(Error::BadRegistry("belongs to another release"));
    }
    let entry = registry
        .agents
        .get(&request.name)
        .ok_or(Error::UnknownAgent)?;
    if registry
        .revoked
        .iter()
        .any(|r| r.name == request.name && r.version == entry.version)
    {
        return Err(Error::Revoked);
    }
    let tier = match entry.tier.as_str() {
        "official" => Tier::Official,
        "community" => Tier::Community,
        _ => return Err(Error::BadRegistry("unknown tier")),
    };
    let (Some(needed), Some(have)) = (
        parse_semver(&entry.min_engine),
        parse_semver(engine_version),
    ) else {
        return Err(Error::BadRegistry("version is not x.y.z"));
    };
    if have < needed {
        return Err(Error::EngineTooOld);
    }
    if parse_semver(&entry.version).is_none() {
        return Err(Error::BadRegistry("version is not x.y.z"));
    }
    let (configurable, default_schedule) = match entry.schedule.as_str() {
        "none" => (false, None),
        "fixed" | "configurable" => {
            if Schedule::parse(&entry.default_schedule).is_err() {
                return Err(Error::BadRegistry("default schedule is invalid"));
            }
            (
                entry.schedule == "configurable",
                Some(entry.default_schedule.clone()),
            )
        }
        _ => return Err(Error::BadRegistry("unknown schedule kind")),
    };
    let systemd_writable = match entry.isolation.as_str() {
        "" | "cron" if entry.writable_paths.is_empty() => None,
        "systemd"
            if default_schedule.is_some()
                && entry.writable_paths.len() <= MAX_WRITABLE_PATHS
                && entry
                    .writable_paths
                    .iter()
                    .all(|path| agent_systemd::valid_writable_path(path)) =>
        {
            Some(entry.writable_paths.clone())
        }
        _ => return Err(Error::BadRegistry("isolation settings are not valid")),
    };
    if request.schedule.is_some() && !configurable {
        return Err(Error::ScheduleNotConfigurable);
    }
    if entry.script.is_empty()
        || entry.script.contains(['/', '\\'])
        || entry.script.starts_with('.')
    {
        return Err(Error::BadRegistry("script name is not a plain file name"));
    }
    let path = format!("agents/{}/{}", request.name, entry.script);
    let listed = entry
        .files
        .get(&path)
        .ok_or(Error::BadRegistry("script is not listed in files"))?;
    if !is_hash(listed) {
        return Err(Error::BadRegistry("script hash is malformed"));
    }
    let script_url = format!(
        "{}/{}/{}",
        source.raw_base.trim_end_matches('/'),
        request.release,
        path
    );
    let bytes = fetch(&script_url, MAX_SCRIPT_BYTES).map_err(Error::Fetch)?;
    let actual = sha256(&bytes);
    if actual != *listed || actual != request.sha256 {
        return Err(Error::HashMismatch);
    }
    if tier == Tier::Community && !approved(&request.name, &actual) {
        return Err(Error::NotApproved);
    }
    let script = String::from_utf8(bytes).map_err(|_| Error::BadRegistry("script is not UTF-8"))?;
    if script.contains('\0') || !script.starts_with("#!") {
        return Err(Error::BadRegistry("script must be text starting with #!"));
    }
    let agent = Agent::from_registry(
        request.name.clone(),
        entry.version.clone(),
        default_schedule,
        configurable,
        script,
        systemd_writable,
    );
    Ok(Verified {
        agent,
        tier,
        script_sha256: actual,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn unapprove_matches_only_the_named_agent_and_hash() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let all = UnapproveRequest::parse(r#"{"name":"foo"}"#).unwrap();
        assert!(all.matches(&format!("foo-{a}")));
        assert!(all.matches(&format!("foo-{b}")));
        // A longer name that merely starts with `foo-` is another agent.
        assert!(!all.matches(&format!("foo-bar-{a}")));
        assert!(!all.matches("foo-notahash"));
        let one = UnapproveRequest::parse(&format!(r#"{{"name":"foo","sha256":"{a}"}}"#)).unwrap();
        assert!(one.matches(&format!("foo-{a}")));
        assert!(!one.matches(&format!("foo-{b}")));
        assert!(UnapproveRequest::parse(r#"{"name":"foo","sha256":"x"}"#).is_err());
    }

    use super::*;

    const GOOD: &str = "#!/usr/bin/env bash\necho hi\n";

    fn registry(tier: &str, schedule: &str, revoked: &str, hash: &str) -> String {
        format!(
            r#"{{"schema":1,"release":"1.0.0","commit":"c","revoked":{revoked},
"agents":{{"disk-report":{{"version":"1.2.0","tier":"{tier}","schedule":"{schedule}",
"defaultSchedule":"0 5 * * *","minEngine":"0.1.0","description":"d","paths":[],
"script":"agent.sh","files":{{"agents/disk-report/agent.sh":"{hash}"}}}}}}}}"#
        )
    }

    fn serve(
        registry_json: String,
        script: &'static str,
    ) -> impl Fn(&str, u64) -> Result<Vec<u8>, fetch::Error> {
        move |url, _| {
            if url.ends_with("/1.0.0/registry.json") {
                Ok(registry_json.clone().into_bytes())
            } else if url.ends_with("/1.0.0/agents/disk-report/agent.sh") {
                Ok(script.as_bytes().to_vec())
            } else {
                panic!("unexpected url {url}")
            }
        }
    }

    fn request(hash: &str, schedule: Option<&str>) -> InstallRequest {
        let schedule = schedule
            .map(|s| format!(r#","schedule":"{s}""#))
            .unwrap_or_default();
        InstallRequest::parse(&format!(
            r#"{{"name":"disk-report","release":"1.0.0","sha256":"{hash}"{schedule}}}"#
        ))
        .unwrap()
    }

    fn run(
        registry_json: String,
        script: &'static str,
        request: &InstallRequest,
        approved: bool,
    ) -> Result<Verified, Error> {
        fetch_verified(
            &Source::default(),
            &serve(registry_json, script),
            request,
            "0.1.0",
            &|_, _| approved,
        )
    }

    fn hash() -> String {
        sha256(GOOD.as_bytes())
    }

    #[test]
    fn an_official_agent_installs_without_approval() {
        let h = hash();
        let verified = run(
            registry("official", "configurable", "[]", &h),
            GOOD,
            &request(&h, None),
            false,
        )
        .unwrap();
        assert_eq!(verified.agent.name, "disk-report");
        assert_eq!(verified.agent.version, "1.2.0");
        assert_eq!(verified.agent.default_schedule, Some("0 5 * * *"));
        assert!(verified.agent.configurable_schedule);
        assert!(!verified.agent.bundled);
        assert_eq!(verified.agent.installed_script(), GOOD);
    }

    fn isolated(isolation: &str, paths: &str, schedule: &str) -> String {
        registry("official", schedule, "[]", &hash()).replace(
            r#""minEngine":"0.1.0""#,
            &format!(r#""minEngine":"0.1.0","isolation":"{isolation}","writablePaths":{paths}"#),
        )
    }

    #[test]
    fn a_systemd_agent_carries_its_validated_writable_paths() {
        let h = hash();
        let json = isolated(
            "systemd",
            r#"["/root/.wcp/agents","/root/.wcp/logs"]"#,
            "configurable",
        );
        let verified = run(json, GOOD, &request(&h, None), false).unwrap();
        assert_eq!(
            verified.agent.systemd_writable,
            Some(&["/root/.wcp/agents", "/root/.wcp/logs"][..])
        );
        // Cron stays the default.
        let plain = run(
            registry("official", "configurable", "[]", &h),
            GOOD,
            &request(&h, None),
            false,
        )
        .unwrap();
        assert!(plain.agent.systemd_writable.is_none());
    }

    #[test]
    fn unsafe_or_inconsistent_isolation_is_refused() {
        let h = hash();
        for json in [
            isolated("systemd", r#"["/etc"]"#, "configurable"),
            isolated("systemd", r#"["/root/.wcp/../.ssh"]"#, "configurable"),
            isolated("systemd", r#"["/root/.wcp/a b"]"#, "configurable"),
            // Nothing to schedule, so nothing for a timer to do.
            isolated("systemd", r#"["/root/.wcp/logs"]"#, "none"),
            isolated("docker", "[]", "configurable"),
            // Paths that mean nothing under cron are a mistake, not a hint.
            isolated("cron", r#"["/root/.wcp/logs"]"#, "configurable"),
        ] {
            assert!(
                matches!(
                    run(json.clone(), GOOD, &request(&h, None), false),
                    Err(Error::BadRegistry(_))
                ),
                "{json}"
            );
        }
    }

    #[test]
    fn a_community_agent_needs_an_approval_for_this_exact_hash() {
        let h = hash();
        let json = registry("community", "none", "[]", &h);
        assert!(matches!(
            run(json.clone(), GOOD, &request(&h, None), false),
            Err(Error::NotApproved)
        ));
        assert!(run(json, GOOD, &request(&h, None), true).is_ok());
    }

    #[test]
    fn a_script_that_differs_from_the_registry_or_the_reviewed_hash_is_refused() {
        let h = hash();
        // Registry lists another hash than the file has.
        assert!(matches!(
            run(
                registry("official", "none", "[]", &"0".repeat(64)),
                GOOD,
                &request(&h, None),
                true
            ),
            Err(Error::HashMismatch)
        ));
        // The operator reviewed another hash than the registry lists.
        assert!(matches!(
            run(
                registry("official", "none", "[]", &h),
                GOOD,
                &request(&"1".repeat(64), None),
                true
            ),
            Err(Error::HashMismatch)
        ));
    }

    #[test]
    fn a_revoked_version_is_refused() {
        let h = hash();
        let json = registry(
            "official",
            "none",
            r#"[{"name":"disk-report","version":"1.2.0"}]"#,
            &h,
        );
        assert!(matches!(
            run(json, GOOD, &request(&h, None), true),
            Err(Error::Revoked)
        ));
    }

    #[test]
    fn a_fixed_schedule_rejects_a_requested_one() {
        let h = hash();
        assert!(matches!(
            run(
                registry("official", "fixed", "[]", &h),
                GOOD,
                &request(&h, Some("0 1 * * *")),
                true
            ),
            Err(Error::ScheduleNotConfigurable)
        ));
    }

    #[test]
    fn a_built_in_name_cannot_come_from_the_registry() {
        let h = hash();
        let request = InstallRequest::parse(&format!(
            r#"{{"name":"metrics-agent","release":"1.0.0","sha256":"{h}"}}"#
        ))
        .unwrap();
        assert!(matches!(
            fetch_verified(
                &Source::default(),
                &|_, _| panic!("must not fetch"),
                &request,
                "0.1.0",
                &|_, _| true,
            ),
            Err(Error::BuiltIn)
        ));
    }

    #[test]
    fn an_engine_older_than_min_engine_refuses() {
        let h = hash();
        let json = registry("official", "none", "[]", &h)
            .replace(r#""minEngine":"0.1.0""#, r#""minEngine":"9.0.0""#);
        assert!(matches!(
            run(json, GOOD, &request(&h, None), true),
            Err(Error::EngineTooOld)
        ));
    }

    #[test]
    fn a_registry_for_another_release_or_schema_is_refused() {
        let h = hash();
        let other = registry("official", "none", "[]", &h)
            .replace(r#""release":"1.0.0""#, r#""release":"2.0.0""#);
        assert!(matches!(
            run(other, GOOD, &request(&h, None), true),
            Err(Error::BadRegistry(_))
        ));
        let schema =
            registry("official", "none", "[]", &h).replace(r#""schema":1"#, r#""schema":2"#);
        assert!(matches!(
            run(schema, GOOD, &request(&h, None), true),
            Err(Error::BadRegistry(_))
        ));
    }

    #[test]
    fn a_script_name_cannot_leave_the_agent_directory() {
        let h = hash();
        for bad in ["../x.sh", "a/b.sh", ".hidden", ""] {
            let json = registry("official", "none", "[]", &h)
                .replace(r#""script":"agent.sh""#, &format!(r#""script":"{bad}""#));
            assert!(
                matches!(
                    run(json, GOOD, &request(&h, None), true),
                    Err(Error::BadRegistry(_))
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_script_without_a_shebang_is_refused() {
        let text: &'static str = "echo no shebang\n";
        let h = sha256(text.as_bytes());
        assert!(matches!(
            run(
                registry("official", "none", "[]", &h),
                text,
                &request(&h, None),
                true
            ),
            Err(Error::BadRegistry(_))
        ));
    }

    #[test]
    fn requests_are_strict() {
        let h = hash();
        assert_eq!(
            InstallRequest::parse(r#"{"name":"x","release":"1.0.0","sha256":"abc"}"#).unwrap_err(),
            RequestError::InvalidHash
        );
        for bad_release in ["latest", "1.0", "1.0.0.0", "v1.0.0", "1.0.x"] {
            assert_eq!(
                InstallRequest::parse(&format!(
                    r#"{{"name":"x","release":"{bad_release}","sha256":"{h}"}}"#
                ))
                .unwrap_err(),
                RequestError::InvalidRelease
            );
        }
        assert_eq!(
            InstallRequest::parse(&format!(
                r#"{{"name":"../x","release":"1.0.0","sha256":"{h}"}}"#
            ))
            .unwrap_err(),
            RequestError::InvalidName
        );
        // An address or code cannot be smuggled in.
        assert_eq!(
            InstallRequest::parse(&format!(
                r#"{{"name":"x","release":"1.0.0","sha256":"{h}","url":"http://evil"}}"#
            ))
            .unwrap_err(),
            RequestError::InvalidJson
        );
        assert_eq!(
            ApproveRequest::parse(&format!(
                r#"{{"name":"x","sha256":"{}"}}"#,
                h.to_uppercase()
            ))
            .unwrap_err(),
            RequestError::InvalidHash
        );
    }

    #[test]
    fn approvals_are_one_file_per_agent_and_hash() {
        assert_eq!(
            approval_file("a", &"b".repeat(64)),
            format!("agent-approvals/a-{}", "b".repeat(64))
        );
    }
}
