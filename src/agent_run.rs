//! `agent.run`: start an installed agent once, now, and report what it left
//! behind (E7). For "try it" in the panel and for operators.
//!
//! An agent runs exactly as its scheduler would start it: the cron line's
//! `bash <script>` with `WCP_DIR`, `OPS_ENGINE` and `PATH` set (see
//! `agent_lifecycle::agent_environment`), or `systemctl start` of its own
//! sandboxed unit. Nothing about the agent is taken from the request except
//! its name, and the script is the one installed under `$WCP_DIR/agents`,
//! owned by the running user and not writable by others.
//!
//! `--dry-run` sets `WCP_DRY_RUN=1`: the helpers then write no heartbeat, log
//! or result line, and a cooperating agent changes nothing outside `$WCP_DIR`.
//! It is **not a sandbox**. A sandboxed (systemd) agent has no dry run, because
//! the unit's environment is fixed; asking for one is refused.
//!
//! The run is bounded: a timeout (default 300 seconds, at most 3600) after
//! which the script is killed; processes it started on its own may outlive it.
//! If the agent's lock is already held, nothing is started. A run is not
//! journaled by the engine; the agent's heartbeat and log are the record.

use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use serde_json::Value;

use crate::{
    agent_helper,
    agent_lifecycle::{agent_environment, valid_agent_name},
    agent_systemd,
    error::ErrorCode,
    process::{self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination},
};

pub const OPERATION: &str = "agent.run";
pub const DEFAULT_TIMEOUT_SECS: u64 = 300;
pub const MAX_TIMEOUT_SECS: u64 = 3600;
const OUTPUT_TAIL_BYTES: usize = 4096;
const CAPTURE_BYTES: usize = 256 * 1024;
const LOG_TAIL_BYTES: u64 = 256 * 1024;

pub struct Context<'a> {
    /// `$WCP_DIR`.
    pub dir: &'a Path,
    /// `bash` outside tests.
    pub shell: &'a str,
    /// Where sandboxed agents' units live (`/etc/systemd/system`).
    pub unit_dir: &'a Path,
    /// `Some("systemctl")` when systemd is the running init.
    pub systemctl: Option<&'a str>,
    /// The `OPS_ENGINE` the agent is told about.
    pub engine_binary: &'a str,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    InvalidName,
    InvalidTimeout,
    NotInstalled,
    ScriptNotTrusted,
    /// The agent's lock is held: another run is in progress.
    Busy,
    DryRunNotSupported,
    Spawn,
    Io,
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        let (code, message) = match self {
            Self::InvalidName => (
                ErrorCode::InvalidInput,
                "agent name must be lowercase letters, digits and '-' (at most 64)",
            ),
            Self::InvalidTimeout => (
                ErrorCode::InvalidInput,
                "timeout must be between 1 and 3600 seconds",
            ),
            Self::NotInstalled => (ErrorCode::NotFound, "this agent is not installed"),
            Self::ScriptNotTrusted => (
                ErrorCode::PermissionDenied,
                "the installed script is not a regular file owned by the engine's user and not writable by others",
            ),
            Self::Busy => (
                ErrorCode::Conflict,
                "the agent is already running (its lock is held)",
            ),
            Self::DryRunNotSupported => (
                ErrorCode::InvalidInput,
                "a dry run is not available for agents that run under systemd",
            ),
            Self::Spawn => (
                ErrorCode::DependencyUnavailable,
                "could not start the agent",
            ),
            Self::Io => (ErrorCode::Internal, "could not read the agent's state"),
        };
        (code, message.to_owned())
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunReport {
    pub agent: String,
    pub dry_run: bool,
    /// `cron` (the plain script) or `systemd`.
    pub scheduler: &'static str,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub duration_ms: u64,
    /// The heartbeat this run wrote; none in a dry run or when it wrote none.
    pub heartbeat: Option<Value>,
    /// The last result line this run wrote.
    pub result: Option<Value>,
    pub stdout: String,
    pub stderr: String,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn tail(bytes: &[u8]) -> String {
    let start = bytes.len().saturating_sub(OUTPUT_TAIL_BYTES);
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}

pub(crate) fn installed(dir: &Path, name: &str) -> bool {
    let Ok(text) = fs::read_to_string(dir.join("agents").join("manifest.json")) else {
        return false;
    };
    matches!(serde_json::from_str::<Value>(&text), Ok(Value::Object(map)) if map.contains_key(name))
}

fn trusted_script(path: &Path) -> Result<(), Error> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Error::NotInstalled
            } else {
                Error::ScriptNotTrusted
            }
        })?;
    let meta = file.metadata().map_err(|_| Error::Io)?;
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    if meta.is_file() && meta.uid() == uid && meta.permissions().mode() & 0o022 == 0 {
        Ok(())
    } else {
        Err(Error::ScriptNotTrusted)
    }
}

/// The last line of `log` newer than `since` that carries a `status` (the
/// result lines `agent result emit` writes).
fn last_result(log: &Path, since: u64) -> Option<Value> {
    let mut file = fs::File::open(log).ok()?;
    let len = file.metadata().ok()?.len();
    file.seek(SeekFrom::Start(len.saturating_sub(LOG_TAIL_BYTES)))
        .ok()?;
    let mut text = String::new();
    file.take(LOG_TAIL_BYTES).read_to_string(&mut text).ok()?;
    text.lines()
        .rev()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|entry| {
            entry.get("status").is_some() && entry["ts"].as_u64().is_some_and(|ts| ts >= since)
        })
}

fn fresh_heartbeat(dir: &Path, name: &str, since: u64) -> Option<Value> {
    let text = fs::read_to_string(agent_helper::heartbeat_path(dir, name)).ok()?;
    let beat: Value = serde_json::from_str(&text).ok()?;
    beat["ts"]
        .as_u64()
        .is_some_and(|ts| ts >= since)
        .then_some(beat)
}

pub fn run(
    ctx: &Context<'_>,
    name: &str,
    dry_run: bool,
    timeout: Duration,
) -> Result<RunReport, Error> {
    if !valid_agent_name(name) {
        return Err(Error::InvalidName);
    }
    if timeout.is_zero() || timeout.as_secs() > MAX_TIMEOUT_SECS {
        return Err(Error::InvalidTimeout);
    }
    if !installed(ctx.dir, name) {
        return Err(Error::NotInstalled);
    }
    let script: PathBuf = ctx.dir.join("agents").join(format!("{name}.sh"));
    trusted_script(&script)?;
    let unit = ctx
        .unit_dir
        .join(format!("{}{name}.service", agent_systemd::UNIT_PREFIX));
    let sandboxed = ctx.systemctl.is_some() && unit.is_file();
    if sandboxed && dry_run {
        return Err(Error::DryRunNotSupported);
    }
    // Same lock the agent takes; held means a run is in progress.
    match agent_helper::try_lock(ctx.dir, name) {
        Ok(Some(_free)) => {}
        Ok(None) => return Err(Error::Busy),
        Err(_) => return Err(Error::Io),
    }

    let mut request = if let (true, Some(systemctl)) = (sandboxed, ctx.systemctl) {
        ProcessRequest::new(systemctl).args([
            "start",
            &format!("{}{name}.service", agent_systemd::UNIT_PREFIX),
        ])
    } else {
        ProcessRequest::new(ctx.shell).args([script.as_os_str()])
    };
    if !sandboxed {
        for (key, value) in agent_environment() {
            let value = match key {
                "WCP_DIR" => ctx.dir.as_os_str().to_owned(),
                "OPS_ENGINE" => ctx.engine_binary.into(),
                _ => value.into(),
            };
            request = request.env(key, value);
        }
        request = request
            .env("WCP_DRY_RUN", if dry_run { "1" } else { "0" })
            // A lock inherited from the caller must not make the script skip its own.
            .env(agent_helper::LOCK_HELD_ENV, "");
    }
    let started_secs = now_secs();
    let started = Instant::now();
    let output = process::run(
        &request,
        &ProcessLimits {
            timeout,
            max_stdout_bytes: CAPTURE_BYTES,
            max_stderr_bytes: CAPTURE_BYTES,
        },
        &CancellationToken::default(),
    )
    .map_err(|_| Error::Spawn)?;
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let (exit_code, timed_out) = match output.termination {
        ProcessTermination::Exited { code, .. } => (code, false),
        ProcessTermination::TimedOut => (None, true),
        ProcessTermination::Cancelled => (None, false),
    };
    let (heartbeat, result) = if dry_run {
        (None, None)
    } else {
        (
            fresh_heartbeat(ctx.dir, name, started_secs),
            last_result(&agent_helper::log_path(ctx.dir, name), started_secs),
        )
    };
    Ok(RunReport {
        agent: name.to_owned(),
        dry_run,
        scheduler: if sandboxed { "systemd" } else { "cron" },
        exit_code,
        timed_out,
        duration_ms,
        heartbeat,
        result,
        stdout: tail(&output.stdout.bytes),
        stderr: tail(&output.stderr.bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        dir: tempfile::TempDir,
        units: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            fs::create_dir_all(dir.path().join("wcp/agents")).unwrap();
            let units = dir.path().join("units");
            fs::create_dir_all(&units).unwrap();
            Self { dir, units }
        }

        fn wcp(&self) -> PathBuf {
            self.dir.path().join("wcp")
        }

        fn install(&self, name: &str, script: &str) {
            let path = self.wcp().join("agents").join(format!("{name}.sh"));
            fs::write(&path, script).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            let manifest = self.wcp().join("agents/manifest.json");
            let mut map: serde_json::Map<String, Value> = fs::read_to_string(&manifest)
                .ok()
                .and_then(|text| serde_json::from_str(&text).ok())
                .unwrap_or_default();
            map.insert(name.to_owned(), serde_json::json!({"version": "1.0.0"}));
            fs::write(manifest, Value::Object(map).to_string()).unwrap();
        }

        fn ctx<'a>(&'a self, wcp: &'a Path, systemctl: Option<&'a str>) -> Context<'a> {
            Context {
                dir: wcp,
                shell: "bash",
                unit_dir: &self.units,
                systemctl,
                engine_binary: "/usr/local/bin/ops-engine",
            }
        }
    }

    const SECS: Duration = Duration::from_secs(20);

    const WELL_BEHAVED: &str = r#"#!/usr/bin/env bash
set -eu
echo "dir=$WCP_DIR engine=$OPS_ENGINE dry=$WCP_DRY_RUN held=[${WCP_LOCK_HELD:-}] path=$PATH"
mkdir -p "$WCP_DIR/agents"
if [ "$WCP_DRY_RUN" != "1" ]; then
  echo "{\"ts\":$(date +%s),\"exit_code\":0}" > "$WCP_DIR/agents/demo.heartbeat"
  mkdir -p "$WCP_DIR/logs"
  echo "{\"ts\":$(date +%s),\"agent\":\"demo\",\"status\":\"warn\",\"summary\":\"two things\",\"data\":{}}" >> "$WCP_DIR/logs/demo.log"
fi
echo "to stderr" >&2
"#;

    #[test]
    fn the_agent_starts_with_the_environment_cron_would_give_it() {
        let fixture = Fixture::new();
        fixture.install("demo", WELL_BEHAVED);
        let wcp = fixture.wcp();
        let report = run(&fixture.ctx(&wcp, None), "demo", false, SECS).unwrap();
        assert_eq!(report.exit_code, Some(0));
        assert!(!report.timed_out);
        assert_eq!(report.scheduler, "cron");
        assert!(report.stdout.contains(&format!("dir={}", wcp.display())));
        assert!(report.stdout.contains("engine=/usr/local/bin/ops-engine"));
        assert!(report.stdout.contains("dry=0"));
        assert!(report.stdout.contains("path=/usr/local/bin:"));
        assert_eq!(report.stderr.trim(), "to stderr");
        assert_eq!(report.heartbeat.unwrap()["exit_code"], 0);
        let result = report.result.unwrap();
        assert_eq!(result["status"], "warn");
        assert_eq!(result["summary"], "two things");
    }

    #[test]
    fn the_script_is_told_it_does_not_already_hold_the_lock() {
        let fixture = Fixture::new();
        fixture.install("demo", WELL_BEHAVED);
        let wcp = fixture.wcp();
        let report = run(&fixture.ctx(&wcp, None), "demo", false, SECS).unwrap();
        assert!(report.stdout.contains("held=[]"));
    }

    #[test]
    fn a_dry_run_sets_the_flag_and_reports_no_heartbeat_or_result() {
        let fixture = Fixture::new();
        fixture.install("demo", WELL_BEHAVED);
        let wcp = fixture.wcp();
        let report = run(&fixture.ctx(&wcp, None), "demo", true, SECS).unwrap();
        assert!(report.dry_run);
        assert!(report.stdout.contains("dry=1"));
        assert!(report.heartbeat.is_none());
        assert!(report.result.is_none());
        assert!(!wcp.join("agents/demo.heartbeat").exists());
        assert!(!wcp.join("logs").exists());
    }

    #[test]
    fn an_old_heartbeat_and_old_result_are_not_this_runs() {
        let fixture = Fixture::new();
        fixture.install("demo", "#!/usr/bin/env bash\nexit 3\n");
        let wcp = fixture.wcp();
        fs::write(
            wcp.join("agents/demo.heartbeat"),
            "{\"ts\":1,\"exit_code\":0}\n",
        )
        .unwrap();
        fs::create_dir_all(wcp.join("logs")).unwrap();
        fs::write(
            wcp.join("logs/demo.log"),
            "{\"ts\":1,\"agent\":\"demo\",\"status\":\"ok\",\"summary\":\"old\",\"data\":{}}\n",
        )
        .unwrap();
        let report = run(&fixture.ctx(&wcp, None), "demo", false, SECS).unwrap();
        assert_eq!(report.exit_code, Some(3));
        assert!(report.heartbeat.is_none());
        assert!(report.result.is_none());
    }

    #[test]
    fn a_runaway_agent_is_killed_at_the_timeout() {
        let fixture = Fixture::new();
        fixture.install("demo", "#!/usr/bin/env bash\nexec sleep 30\n");
        let wcp = fixture.wcp();
        let report = run(
            &fixture.ctx(&wcp, None),
            "demo",
            false,
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(report.timed_out);
        assert_eq!(report.exit_code, None);
        assert!(report.duration_ms < 10_000);
    }

    #[test]
    fn output_is_cut_to_its_tail() {
        let fixture = Fixture::new();
        fixture.install(
            "demo",
            "#!/usr/bin/env bash\nhead -c 20000 /dev/zero | tr '\\0' a\necho END\n",
        );
        let wcp = fixture.wcp();
        let report = run(&fixture.ctx(&wcp, None), "demo", false, SECS).unwrap();
        assert_eq!(report.stdout.len(), OUTPUT_TAIL_BYTES);
        assert!(report.stdout.trim_end().ends_with("END"));
    }

    #[test]
    fn a_held_lock_means_busy_and_nothing_starts() {
        let fixture = Fixture::new();
        fixture.install("demo", "#!/usr/bin/env bash\ntouch \"$WCP_DIR/started\"\n");
        let wcp = fixture.wcp();
        let _held = agent_helper::try_lock(&wcp, "demo").unwrap().unwrap();
        assert_eq!(
            run(&fixture.ctx(&wcp, None), "demo", false, SECS).unwrap_err(),
            Error::Busy
        );
        assert!(!wcp.join("started").exists());
    }

    #[test]
    fn unknown_unsafe_and_untrusted_agents_are_refused() {
        let fixture = Fixture::new();
        let wcp = fixture.wcp();
        let ctx = fixture.ctx(&wcp, None);
        for bad in ["", "../x", "A", "a b"] {
            assert_eq!(
                run(&ctx, bad, false, SECS).unwrap_err(),
                Error::InvalidName,
                "{bad}"
            );
        }
        assert_eq!(
            run(&ctx, "demo", false, SECS).unwrap_err(),
            Error::NotInstalled
        );
        // A script without a manifest entry is not an installed agent.
        let stray = wcp.join("agents/stray.sh");
        fs::write(&stray, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&stray, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            run(&ctx, "stray", false, SECS).unwrap_err(),
            Error::NotInstalled
        );
        // Listed, but writable by others.
        fixture.install("demo", "#!/bin/sh\n");
        let script = wcp.join("agents/demo.sh");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            run(&ctx, "demo", false, SECS).unwrap_err(),
            Error::ScriptNotTrusted
        );
        // Listed, but a symlink.
        fs::remove_file(&script).unwrap();
        let target = wcp.join("target.sh");
        fs::write(&target, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink(&target, &script).unwrap();
        assert_eq!(
            run(&ctx, "demo", false, SECS).unwrap_err(),
            Error::ScriptNotTrusted
        );
        // Timeout bounds.
        assert_eq!(
            run(&ctx, "demo", false, Duration::ZERO).unwrap_err(),
            Error::InvalidTimeout
        );
        assert_eq!(
            run(
                &ctx,
                "demo",
                false,
                Duration::from_secs(MAX_TIMEOUT_SECS + 1)
            )
            .unwrap_err(),
            Error::InvalidTimeout
        );
    }

    #[test]
    fn a_sandboxed_agent_runs_through_its_unit_and_has_no_dry_run() {
        let fixture = Fixture::new();
        fixture.install("demo", "#!/usr/bin/env bash\nexit 99\n");
        let wcp = fixture.wcp();
        fs::write(
            fixture.dir.path().join("units/wcp-agent-demo.service"),
            "[Service]\n",
        )
        .unwrap();
        let systemctl = fixture.dir.path().join("systemctl");
        fs::write(
            &systemctl,
            format!(
                "#!/bin/sh\necho \"$@\" > '{}'\nexit 0\n",
                fixture.dir.path().join("systemctl-calls").display()
            ),
        )
        .unwrap();
        fs::set_permissions(&systemctl, fs::Permissions::from_mode(0o755)).unwrap();
        let program = systemctl.to_str().unwrap();
        let ctx = fixture.ctx(&wcp, Some(program));
        assert_eq!(
            run(&ctx, "demo", true, SECS).unwrap_err(),
            Error::DryRunNotSupported
        );
        let report = run(&ctx, "demo", false, SECS).unwrap();
        assert_eq!(report.scheduler, "systemd");
        assert_eq!(report.exit_code, Some(0));
        let calls = fs::read_to_string(fixture.dir.path().join("systemctl-calls")).unwrap();
        assert_eq!(calls.trim(), "start wcp-agent-demo.service");
        // The script itself (which would exit 99) was not run directly.
    }

    #[test]
    fn without_systemd_a_unit_file_alone_does_not_change_how_it_runs() {
        let fixture = Fixture::new();
        fixture.install("demo", "#!/usr/bin/env bash\nexit 0\n");
        fs::write(fixture.dir.path().join("units/wcp-agent-demo.service"), "x").unwrap();
        let wcp = fixture.wcp();
        let report = run(&fixture.ctx(&wcp, None), "demo", true, SECS).unwrap();
        assert_eq!(report.scheduler, "cron");
    }

    #[test]
    fn the_failure_codes_are_stable() {
        assert_eq!(Error::NotInstalled.protocol().0, ErrorCode::NotFound);
        assert_eq!(Error::Busy.protocol().0, ErrorCode::Conflict);
        assert_eq!(Error::InvalidName.protocol().0, ErrorCode::InvalidInput);
        assert_eq!(
            Error::ScriptNotTrusted.protocol().0,
            ErrorCode::PermissionDenied
        );
        assert_eq!(Error::Spawn.protocol().0, ErrorCode::DependencyUnavailable);
    }
}
