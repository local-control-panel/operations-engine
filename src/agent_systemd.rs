//! systemd units for a sandboxed registry agent, instead of a cron line.
//!
//! An agent opts in with `isolation = "systemd"` and a list of
//! `writable_paths` in its `agent.toml`. The engine then writes a `oneshot`
//! service and a timer from the fixed templates below. The registry supplies
//! only the agent name, the schedule and the writable paths, and all three are
//! validated here; no directive ever comes from the registry. Everything the
//! sandbox does not mention stays readable, exactly as under cron.
//!
//! The sandbox restricts **writes** (and privilege gain), not reads and not
//! the network. It does not protect a sibling agent's script when the agent is
//! granted `/root/.wcp/agents` (heartbeat and lock files live there). The
//! shared Python library in that directory is mounted read-only for the
//! service, because the unsandboxed agents import it as root.

use crate::{agent_lifecycle::Agent, backup_schedule::Schedule};

pub const UNIT_DIR: &str = "/etc/systemd/system";
/// Present only while systemd is the running init.
pub const RUN_DIR: &str = "/run/systemd/system";
pub const UNIT_PREFIX: &str = "wcp-agent-";
/// A comment in the timer, so the operator's cron schedule survives a round
/// trip through `OnCalendar=`.
const SCHEDULE_COMMENT: &str = "# wcp-agent-schedule: ";

/// Directories a sandboxed agent may be granted write access to (strictly
/// below them). The engine state, `/etc` and the systemd directories are not
/// on the list.
const WRITABLE_PREFIXES: [&str; 4] = [
    "/root/.wcp/",
    "/var/log/",
    "/var/www/",
    "/var/lib/wcp-agent/",
];

pub fn service_name(agent: &Agent) -> String {
    format!("{UNIT_PREFIX}{}.service", agent.name)
}

pub fn timer_name(agent: &Agent) -> String {
    format!("{UNIT_PREFIX}{}.timer", agent.name)
}

/// Whether `path` may be granted to a sandboxed agent as writable.
pub fn valid_writable_path(path: &str) -> bool {
    WRITABLE_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
        && path.len() <= 200
        && path.split('/').skip(1).all(|part| {
            !part.is_empty()
                && part != ".."
                && part != "."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        })
}

/// Whether no component of `path` below its allowed directory is a symlink.
/// `ReadWritePaths=` follows links, so a link planted under `/var/www` would
/// make the sandbox grant write access to wherever it points. The check runs
/// at install time; a link created later is not covered.
pub fn has_no_symlink(path: &str) -> bool {
    let Some(prefix) = WRITABLE_PREFIXES.iter().find(|p| path.starts_with(**p)) else {
        return false;
    };
    no_symlink_below(std::path::Path::new(prefix), &path[prefix.len()..])
}

fn no_symlink_below(base: &std::path::Path, rest: &str) -> bool {
    let mut current = base.to_path_buf();
    rest.split('/').all(|part| {
        current.push(part);
        !std::fs::symlink_metadata(&current).is_ok_and(|meta| meta.file_type().is_symlink())
    })
}

fn expand(field: &str, min: u32, max: u32) -> Option<Vec<u32>> {
    let mut values = Vec::new();
    for part in field.split(',') {
        let (range, step) = match part.split_once('/') {
            Some((range, step)) => (range, step.parse::<u32>().ok().filter(|s| *s > 0)?),
            None => (part, 1),
        };
        let (low, high) = if range == "*" {
            (min, max)
        } else if let Some((low, high)) = range.split_once('-') {
            (low.parse().ok()?, high.parse().ok()?)
        } else if part.contains('/') {
            return None;
        } else {
            let value = range.parse().ok()?;
            (value, value)
        };
        if low < min || high > max || low > high {
            return None;
        }
        values.extend((low..=high).step_by(step as usize));
    }
    values.sort_unstable();
    values.dedup();
    Some(values)
}

fn list(values: &[u32], min: u32, max: u32, width: usize) -> String {
    if values.len() as u32 == max - min + 1 {
        return "*".to_owned();
    }
    values
        .iter()
        .map(|value| format!("{value:0width$}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// The `OnCalendar=` value with the same firing times as the cron schedule,
/// or none when it cannot be said exactly. Month and weekday names, and a
/// line that restricts both the day of the month and the weekday (cron fires
/// on either, systemd on both), stay on cron.
pub fn on_calendar(schedule: &Schedule) -> Option<String> {
    let text = match schedule.as_str() {
        "@hourly" => "0 * * * *",
        "@daily" | "@midnight" => "0 0 * * *",
        "@weekly" => "0 0 * * 0",
        "@monthly" => "0 0 1 * *",
        "@yearly" | "@annually" => "0 0 1 1 *",
        other => other,
    };
    let fields: Vec<&str> = text.split_whitespace().collect();
    let [minute, hour, day, month, weekday] = fields.as_slice() else {
        return None;
    };
    if *day != "*" && *weekday != "*" {
        return None;
    }
    let minutes = expand(minute, 0, 59)?;
    let hours = expand(hour, 0, 23)?;
    let days = expand(day, 1, 31)?;
    let months = expand(month, 1, 12)?;
    let weekdays = expand(weekday, 0, 7)?;
    const NAMES: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    let mut week: Vec<u32> = weekdays.iter().map(|d| d % 7).collect();
    week.sort_unstable();
    week.dedup();
    let weekday = if week.len() == 7 {
        String::new()
    } else {
        format!(
            "{} ",
            week.iter()
                .map(|d| NAMES[*d as usize])
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    Some(format!(
        "{weekday}*-{}-{} {}:{}:00",
        list(&months, 1, 12, 2),
        list(&days, 1, 31, 2),
        list(&hours, 0, 23, 2),
        list(&minutes, 0, 59, 2),
    ))
}

/// The service unit. Fixed directives only; `writable` has been validated.
pub fn service_unit(agent: &Agent, writable: &[&str]) -> String {
    let paths: Vec<String> = writable.iter().map(|path| format!("-{path}")).collect();
    let library_path = format!(
        "{}/{}/{}",
        crate::agent_lifecycle::ROOT,
        crate::agent_lifecycle::AGENTS_DIR,
        crate::agent_lifecycle::LIBRARY_FILE
    );
    format!(
        "# Managed by the operations engine ({TAG}). Do not edit.\n\
         [Unit]\n\
         Description=WCP agent {name}\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         Environment=WCP_DIR={wcp_dir}\n\
         Environment=OPS_ENGINE={engine}\n\
         Environment=PATH={path}\n\
         ExecStart=/usr/bin/env bash '{script}'\n\
         NoNewPrivileges=yes\n\
         PrivateTmp=yes\n\
         PrivateDevices=yes\n\
         ProtectSystem=strict\n\
         ProtectHome=read-only\n\
         ProtectKernelTunables=yes\n\
         ProtectKernelModules=yes\n\
         ProtectKernelLogs=yes\n\
         ProtectControlGroups=yes\n\
         ProtectClock=yes\n\
         RestrictSUIDSGID=yes\n\
         RestrictRealtime=yes\n\
         LockPersonality=yes\n\
         ReadWritePaths={paths}\n\
         ReadOnlyPaths=-{library}\n",
        TAG = crate::agent_lifecycle::TAG,
        name = agent.name,
        wcp_dir = crate::agent_lifecycle::ROOT,
        engine = crate::backup_schedule::ENGINE_BINARY,
        path = crate::agent_lifecycle::AGENT_PATH,
        script = agent.absolute_script_path(),
        paths = paths.join(" "),
        library = library_path,
    )
}

/// The timer unit. `AccuracySec=1s` because systemd otherwise may delay a
/// firing by up to a minute, which would stretch the per-minute agents.
pub fn timer_unit(agent: &Agent, schedule: &Schedule, calendar: &str) -> String {
    format!(
        "# Managed by the operations engine ({TAG}). Do not edit.\n\
         {SCHEDULE_COMMENT}{cron}\n\
         [Unit]\n\
         Description=WCP agent {name} schedule\n\
         \n\
         [Timer]\n\
         OnCalendar={calendar}\n\
         AccuracySec=1s\n\
         Persistent=false\n\
         Unit={service}\n\
         \n\
         [Install]\n\
         WantedBy=timers.target\n",
        TAG = crate::agent_lifecycle::TAG,
        cron = schedule.as_str(),
        name = agent.name,
        service = service_name(agent),
    )
}

/// The cron schedule recorded in a timer written by `timer_unit`.
pub fn schedule_from_timer(text: &str) -> Option<Schedule> {
    let line = text
        .lines()
        .find_map(|line| line.strip_prefix(SCHEDULE_COMMENT))?;
    Schedule::parse(line).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cal(text: &str) -> Option<String> {
        on_calendar(&Schedule::parse(text).unwrap())
    }

    fn agent() -> &'static Agent {
        Agent::from_registry(
            "disk-report".into(),
            "1.0.0".into(),
            Some("0 5 * * *".into()),
            true,
            "#!/bin/sh\n".into(),
            Some(vec!["/root/.wcp/logs".into()]),
        )
    }

    #[test]
    fn common_cron_schedules_become_exact_calendars() {
        assert_eq!(cal("* * * * *").unwrap(), "*-*-* *:*:00");
        assert_eq!(cal("0 4 * * *").unwrap(), "*-*-* 04:00:00");
        assert_eq!(
            cal("*/5 * * * *").unwrap(),
            "*-*-* *:00,05,10,15,20,25,30,35,40,45,50,55:00"
        );
        assert_eq!(cal("30 2 1 * *").unwrap(), "*-*-01 02:30:00");
        assert_eq!(cal("0 5 * * 1").unwrap(), "Mon *-*-* 05:00:00");
        assert_eq!(
            cal("0 5 * * 1-5").unwrap(),
            "Mon,Tue,Wed,Thu,Fri *-*-* 05:00:00"
        );
        assert_eq!(cal("0 5 * * 0,7").unwrap(), "Sun *-*-* 05:00:00");
        assert_eq!(cal("0 0 * 6-8 *").unwrap(), "*-06,07,08-* 00:00:00");
        assert_eq!(cal("0 9-17/4 * * *").unwrap(), "*-*-* 09,13,17:00:00");
    }

    #[test]
    fn keywords_match_what_cron_means_by_them() {
        assert_eq!(cal("@hourly").unwrap(), "*-*-* *:00:00");
        assert_eq!(cal("@daily").unwrap(), "*-*-* 00:00:00");
        assert_eq!(cal("@weekly").unwrap(), "Sun *-*-* 00:00:00");
        assert_eq!(cal("@monthly").unwrap(), "*-*-01 00:00:00");
        assert_eq!(cal("@yearly").unwrap(), "*-01-01 00:00:00");
    }

    #[test]
    fn what_systemd_would_read_differently_stays_on_cron() {
        // Names, out of range values, a zero step, and day-of-month plus
        // weekday (cron ORs them, systemd ANDs them).
        for text in [
            "0 5 * * MON",
            "0 5 * JAN *",
            "60 * * * *",
            "0 24 * * *",
            "*/0 * * * *",
            "0 5 1 * 1",
            "5/2 * * * *",
            "0 0 0 * *",
        ] {
            assert_eq!(cal(text), None, "{text}");
        }
    }

    #[test]
    fn only_paths_below_the_allowed_directories_may_be_writable() {
        for ok in [
            "/root/.wcp/logs",
            "/var/log/wcp",
            "/var/www/shop/cache",
            "/var/lib/wcp-agent/x",
        ] {
            assert!(valid_writable_path(ok), "{ok}");
        }
        for bad in [
            "/",
            "/etc",
            "/etc/cron.d",
            "/root",
            "/root/.wcp",
            "/root/.wcp/",
            "/root/.ssh",
            "/root/.wcp/../.ssh",
            "/root/.wcp/a b",
            "/root/.wcp/a\"b",
            "/var/lib/operations-engine",
            "/var/log",
            "/var/log/a\nb",
            "relative",
            "/var/www//x",
            "/etc/systemd/system",
        ] {
            assert!(!valid_writable_path(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_symlink_below_the_allowed_directory_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, dir.path().join("link")).unwrap();
        assert!(!no_symlink_below(dir.path(), "link"));
        assert!(!no_symlink_below(dir.path(), "link/inner"));
        assert!(no_symlink_below(dir.path(), "real/inner"));
        assert!(has_no_symlink("/root/.wcp/does-not-exist"));
    }

    #[test]
    fn the_service_is_the_fixed_template_with_only_the_declared_paths() {
        let unit = service_unit(agent(), &["/root/.wcp/agents", "/root/.wcp/logs"]);
        assert!(unit.contains("ExecStart=/usr/bin/env bash '/root/.wcp/agents/disk-report.sh'\n"));
        assert!(unit.contains("Environment=WCP_DIR=/root/.wcp\n"));
        assert!(unit.contains("Environment=OPS_ENGINE=/usr/local/bin/ops-engine\n"));
        assert!(unit.contains("Environment=PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"));
        assert!(unit.contains("ProtectSystem=strict\n"));
        assert!(unit.contains("NoNewPrivileges=yes\n"));
        assert!(unit.contains("ReadWritePaths=-/root/.wcp/agents -/root/.wcp/logs\n"));
        assert_eq!(unit.matches("ReadWritePaths").count(), 1);
        // The shared library stays read-only even inside a writable agents
        // directory: every unsandboxed agent imports it as root.
        assert!(unit.contains("ReadOnlyPaths=-/root/.wcp/agents/wcp_agent_lib.py\n"));
    }

    #[test]
    fn the_timer_keeps_the_cron_schedule_for_the_next_update() {
        let schedule = Schedule::parse("0 5 * * 1").unwrap();
        let timer = timer_unit(agent(), &schedule, &on_calendar(&schedule).unwrap());
        assert!(timer.contains("OnCalendar=Mon *-*-* 05:00:00\n"));
        assert!(timer.contains("AccuracySec=1s\n"));
        assert!(timer.contains("Unit=wcp-agent-disk-report.service\n"));
        assert_eq!(schedule_from_timer(&timer).unwrap().as_str(), "0 5 * * 1");
        assert!(schedule_from_timer("[Timer]\n").is_none());
    }
}
