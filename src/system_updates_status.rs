//! `system.updatesStatus`: what the host's apt would upgrade, whether a reboot
//! is pending and when the package lists were last refreshed. Read-only and
//! local: the pending set comes from a simulated `apt-get dist-upgrade`
//! (`-s`, no lock, nothing installed) over the package lists already on disk.
//!
//! A fact that cannot be read is `unknown`, never "none pending" or "no reboot
//! needed". An absent `reboot-required` file is a real answer only when its
//! directory can be read.

use crate::process::{self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination};
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const OPERATION: &str = "system.updatesStatus";
pub const REBOOT_REQUIRED: &str = "/var/run/reboot-required";
pub const REBOOT_REQUIRED_PKGS: &str = "/var/run/reboot-required.pkgs";
pub const UPDATE_STAMP: &str = "/var/lib/apt/periodic/update-success-stamp";
pub const APT_HISTORY: &str = "/var/log/apt/history.log";
pub const UNATTENDED_LOG: &str = "/var/log/unattended-upgrades/unattended-upgrades.log";
pub const BOOT_DIR: &str = "/boot";
pub const OSRELEASE: &str = "/proc/sys/kernel/osrelease";
/// Days of `unattended-upgrades` history counted as attempts.
pub const ATTEMPT_WINDOW_DAYS: u64 = 30;
const TIMEOUT: Duration = Duration::from_secs(60);
const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PACKAGES: usize = 500;
const MAX_REBOOT_PACKAGES: usize = 50;
/// Newest `unattended-upgrades` runs reported in the history.
pub const HISTORY_RUNS: usize = 10;
const MAX_RUN_PACKAGES: usize = 30;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Package {
    pub name: String,
    pub installed: Option<String>,
    pub candidate: String,
    /// The candidate comes from a `-security` pocket.
    pub security: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", tag = "state")]
pub enum Pending {
    Known {
        packages: Vec<Package>,
        /// More packages were pending than are listed.
        truncated: bool,
    },
    Unknown {
        reason: &'static str,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", tag = "state")]
pub enum Reboot {
    Required { packages: Vec<String> },
    NotRequired,
    Unknown,
}

/// Runs of `unattended-upgrades` in the current log file within the window.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", tag = "state")]
pub enum Attempts {
    Known {
        window_days: u64,
        /// Runs that started (`Starting unattended upgrades script`).
        runs: u32,
        /// Runs during which the script logged an error.
        failed: u32,
        /// First day (`YYYY-MM-DD`) the counted log covers; rotated logs are
        /// not read, so this can be later than the window start.
        since: Option<String>,
    },
    Unknown {
        reason: &'static str,
    },
}

/// How one `unattended-upgrades` run ended, as its log says.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RunResult {
    /// `All upgrades installed`.
    Installed,
    /// `No packages found that can be upgraded unattended`.
    NothingToDo,
    /// An `ERROR` line followed the start.
    Failed,
    /// No recognised end line (still running, or a line this reader does not know).
    Unknown,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Run {
    /// Server-local `YYYY-MM-DD HH:MM:SS` of the start line.
    pub started_local: String,
    pub result: RunResult,
    /// Packages the run announced (`Packages that will be upgraded:`), at most 30.
    pub packages: Vec<String>,
    /// How many packages were announced, also past the listed ones.
    pub package_count: u32,
}

/// The newest runs in the current `unattended-upgrades` log, newest first.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", tag = "state")]
pub enum History {
    Known {
        runs: Vec<Run>,
        /// Older runs exist in the current log than are listed.
        truncated: bool,
    },
    Unknown {
        reason: &'static str,
    },
}

/// The running kernel against the newest one installed in `/boot`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", tag = "state")]
pub enum Kernel {
    Known {
        running: String,
        /// Newest installed kernel of the same flavour; `None` when `/boot`
        /// lists none (the running one cannot be compared).
        newest_installed: Option<String>,
        /// A newer kernel is installed than the one running.
        behind: bool,
    },
    Unknown {
        reason: &'static str,
    },
}

/// Whether `unattended-upgrades` is allowed to install from a `-security` pocket.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", tag = "state")]
pub enum SecurityUpdates {
    Known { enabled: bool },
    Unknown { reason: &'static str },
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpdatesStatus {
    pub attempts: Attempts,
    pub history: History,
    pub kernel: Kernel,
    pub security_updates: SecurityUpdates,
    pub pending: Pending,
    pub reboot: Reboot,
    /// Unix seconds of the last successful `apt-get update`; `None` when unknown.
    pub lists_updated_at: Option<u64>,
    /// Server-local `End-Date` of the newest apt run that upgraded packages,
    /// exactly as apt logged it (`YYYY-MM-DD  HH:MM:SS`); `None` when unknown.
    pub last_upgrade_local: Option<String>,
}

pub struct Context<'a> {
    pub apt_get: &'a str,
    pub reboot_required: &'a Path,
    pub reboot_required_pkgs: &'a Path,
    pub update_stamp: &'a Path,
    pub apt_history: &'a Path,
    pub unattended_log: &'a Path,
    pub boot_dir: &'a Path,
    pub osrelease: &'a Path,
    pub apt_config: &'a str,
    /// Unix seconds "now", for the attempts window.
    pub now: u64,
}

impl Context<'static> {
    pub fn system() -> Self {
        Self {
            apt_get: "apt-get",
            reboot_required: Path::new(REBOOT_REQUIRED),
            reboot_required_pkgs: Path::new(REBOOT_REQUIRED_PKGS),
            update_stamp: Path::new(UPDATE_STAMP),
            apt_history: Path::new(APT_HISTORY),
            unattended_log: Path::new(UNATTENDED_LOG),
            boot_dir: Path::new(BOOT_DIR),
            osrelease: Path::new(OSRELEASE),
            apt_config: "apt-config",
            now: now_unix(),
        }
    }
}

pub fn status(ctx: &Context<'_>, cancellation: &CancellationToken) -> UpdatesStatus {
    UpdatesStatus {
        attempts: attempts(ctx),
        history: history(ctx),
        kernel: kernel(ctx),
        security_updates: security_updates(ctx, cancellation),
        pending: pending(ctx, cancellation),
        reboot: reboot(ctx),
        lists_updated_at: mtime_secs(ctx.update_stamp),
        last_upgrade_local: last_upgrade(ctx.apt_history),
    }
}

pub(crate) fn pending(ctx: &Context<'_>, cancellation: &CancellationToken) -> Pending {
    let request = ProcessRequest::new(ctx.apt_get)
        .args([
            "-s",
            "-o",
            "Debug::NoLocking=1",
            "-o",
            "APT::Get::Show-User-Simulation-Note=0",
            "dist-upgrade",
        ])
        .env("LC_ALL", "C");
    let limits = ProcessLimits {
        timeout: TIMEOUT,
        max_stdout_bytes: MAX_OUTPUT_BYTES,
        max_stderr_bytes: 64 * 1024,
    };
    let Ok(output) = process::run(&request, &limits, cancellation) else {
        return Pending::Unknown {
            reason: "apt-get could not be started",
        };
    };
    if !matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        return Pending::Unknown {
            reason: "apt-get did not finish successfully",
        };
    }
    if output.stdout.truncated {
        return Pending::Unknown {
            reason: "apt-get output was too large",
        };
    }
    let Ok(text) = String::from_utf8(output.stdout.bytes) else {
        return Pending::Unknown {
            reason: "apt-get output was not text",
        };
    };
    let mut packages: Vec<Package> = text.lines().filter_map(parse_inst).collect();
    packages.sort_by(|a, b| a.name.cmp(&b.name));
    let truncated = packages.len() > MAX_PACKAGES;
    packages.truncate(MAX_PACKAGES);
    Pending::Known {
        packages,
        truncated,
    }
}

/// `Inst libc6 [2.39-0ubuntu8.3] (2.39-0ubuntu8.4 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])`
/// or, for a new dependency, `Inst pkg (1.0 Ubuntu:24.04/noble [amd64])`.
fn parse_inst(line: &str) -> Option<Package> {
    let rest = line.strip_prefix("Inst ")?;
    let (name, rest) = rest.split_once(' ')?;
    if !package_name_ok(name) {
        return None;
    }
    let (installed, rest) = match rest.strip_prefix('[') {
        Some(after) => {
            let (old, tail) = after.split_once("] ")?;
            (Some(old.to_string()), tail)
        }
        None => (None, rest),
    };
    let inner = rest.strip_prefix('(')?;
    let inner = inner.split_once(')')?.0;
    let (candidate, origins) = inner.split_once(' ')?;
    if candidate.is_empty() || candidate.len() > 128 {
        return None;
    }
    Some(Package {
        name: name.to_string(),
        installed,
        candidate: candidate.to_string(),
        security: origins.contains("-security"),
    })
}

pub(crate) fn package_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-' | b':'))
}

pub(crate) fn reboot(ctx: &Context<'_>) -> Reboot {
    match std::fs::symlink_metadata(ctx.reboot_required) {
        Ok(_) => {
            let packages = read_small(ctx.reboot_required_pkgs)
                .map(|text| {
                    let mut names: Vec<String> = text
                        .lines()
                        .map(str::trim)
                        .filter(|name| package_name_ok(name))
                        .map(str::to_string)
                        .collect();
                    names.sort();
                    names.dedup();
                    names.truncate(MAX_REBOOT_PACKAGES);
                    names
                })
                .unwrap_or_default();
            Reboot::Required { packages }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // The file is only meaningful when its directory is readable.
            match ctx.reboot_required.parent().map(std::fs::read_dir) {
                Some(Ok(_)) => Reboot::NotRequired,
                _ => Reboot::Unknown,
            }
        }
        Err(_) => Reboot::Unknown,
    }
}

fn read_small(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE_BYTES {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

fn mtime_secs(path: &Path) -> Option<u64> {
    std::fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// `End-Date` of the newest block in apt's history that has an `Upgrade:` line.
fn last_upgrade(path: &Path) -> Option<String> {
    let text = read_small(path)?;
    let mut newest = None;
    for block in text.split("\n\n") {
        if !block.lines().any(|l| l.starts_with("Upgrade: ")) {
            continue;
        }
        if let Some(end) = block.lines().find_map(|l| l.strip_prefix("End-Date: ")) {
            let end = end.trim();
            if end.len() <= 32
                && end
                    .bytes()
                    .all(|b| b.is_ascii_digit() || matches!(b, b'-' | b':' | b' '))
            {
                newest = Some(end.to_string());
            }
        }
    }
    newest
}

/// Days since 1970-01-01 of a civil date (proleptic Gregorian).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `YYYY-MM-DD` at the start of a log line, as days since the epoch.
fn line_day(line: &str) -> Option<(i64, &str)> {
    let date = line.get(..10)?;
    let mut parts = date.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let day: i64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some((days_from_civil(year, month, day), date))
}

/// Counts runs and failed runs in the current `unattended-upgrades` log. A run
/// starts at `Starting unattended upgrades script`; it failed when an `ERROR`
/// line follows before the next start. An unreadable log is unknown; a log with
/// no run inside the window is a real `0`.
fn attempts(ctx: &Context<'_>) -> Attempts {
    let Some(text) = read_small(ctx.unattended_log) else {
        return Attempts::Unknown {
            reason: "the unattended-upgrades log could not be read",
        };
    };
    let first_day = (ctx.now / 86_400).saturating_sub(ATTEMPT_WINDOW_DAYS) as i64;
    let (mut runs, mut failed) = (0u32, 0u32);
    let (mut in_run, mut run_failed) = (false, false);
    let mut since: Option<&str> = None;
    for line in text.lines() {
        let Some((day, date)) = line_day(line) else {
            continue;
        };
        if day < first_day {
            continue;
        }
        if line.contains(" INFO Starting unattended upgrades script") {
            if in_run && run_failed {
                failed += 1;
            }
            in_run = true;
            run_failed = false;
            runs += 1;
            since = since.or(Some(date));
        } else if in_run && line.contains(" ERROR ") {
            run_failed = true;
        }
    }
    if in_run && run_failed {
        failed += 1;
    }
    Attempts::Known {
        window_days: ATTEMPT_WINDOW_DAYS,
        runs,
        failed,
        since: since.map(str::to_string),
    }
}

/// The newest [`HISTORY_RUNS`] runs of the current log. Only the start,
/// package-list and result lines are read; configuration lines (allowed
/// origins, blacklists) and everything unrecognised are ignored, and a run
/// without a recognised result is `unknown`. Rotated logs are not read.
fn history(ctx: &Context<'_>) -> History {
    let Some(text) = read_small(ctx.unattended_log) else {
        return History::Unknown {
            reason: "the unattended-upgrades log could not be read",
        };
    };
    let mut runs: Vec<Run> = Vec::new();
    let mut current: Option<Run> = None;
    let mut failed = false;
    let finish = |current: &mut Option<Run>, failed: bool, runs: &mut Vec<Run>| {
        if let Some(mut run) = current.take() {
            if failed && run.result == RunResult::Unknown {
                run.result = RunResult::Failed;
            }
            runs.push(run);
        }
    };
    for line in text.lines() {
        let Some(stamp) = line.get(..19).filter(|s| timestamp_ok(s)) else {
            continue;
        };
        if line.contains(" INFO Starting unattended upgrades script") {
            finish(&mut current, failed, &mut runs);
            failed = false;
            current = Some(Run {
                started_local: stamp.to_string(),
                result: RunResult::Unknown,
                packages: Vec::new(),
                package_count: 0,
            });
            continue;
        }
        let Some(run) = current.as_mut() else {
            continue;
        };
        if let Some(list) = line.split_once(" INFO Packages that will be upgraded:") {
            for name in list.1.split_whitespace().filter(|n| package_name_ok(n)) {
                run.package_count = run.package_count.saturating_add(1);
                if run.packages.len() < MAX_RUN_PACKAGES {
                    run.packages.push(name.to_string());
                }
            }
        } else if line.contains(" INFO All upgrades installed") {
            run.result = RunResult::Installed;
        } else if line.contains(" INFO No packages found that can be upgraded unattended") {
            run.result = RunResult::NothingToDo;
        } else if line.contains(" ERROR ") {
            failed = true;
        }
    }
    finish(&mut current, failed, &mut runs);
    let truncated = runs.len() > HISTORY_RUNS;
    runs.reverse();
    runs.truncate(HISTORY_RUNS);
    History::Known { runs, truncated }
}

/// `YYYY-MM-DD HH:MM:SS`.
fn timestamp_ok(s: &str) -> bool {
    s.len() == 19
        && s.bytes().enumerate().all(|(i, b)| match i {
            4 | 7 => b == b'-',
            10 => b == b' ',
            13 | 16 => b == b':',
            _ => b.is_ascii_digit(),
        })
}

/// Numeric parts of `6.8.0-100-generic` without the flavour: `[6, 8, 0, 100]`.
fn kernel_key(release: &str) -> Option<(Vec<u64>, &str)> {
    let (version, flavour) = release.rsplit_once('-')?;
    let numbers: Option<Vec<u64>> = version
        .split(['.', '-'])
        .map(|part| part.parse().ok())
        .collect();
    let numbers = numbers?;
    (!numbers.is_empty() && !flavour.is_empty()).then_some((numbers, flavour))
}

fn kernel(ctx: &Context<'_>) -> Kernel {
    let Some(running) = read_small(ctx.osrelease).map(|s| s.trim().to_string()) else {
        return Kernel::Unknown {
            reason: "the running kernel could not be read",
        };
    };
    let Some((running_key, flavour)) = kernel_key(&running) else {
        return Kernel::Unknown {
            reason: "the running kernel version was not understood",
        };
    };
    let Ok(entries) = std::fs::read_dir(ctx.boot_dir) else {
        return Kernel::Unknown {
            reason: "/boot could not be read",
        };
    };
    let mut newest: Option<(Vec<u64>, String)> = None;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(release) = name.strip_prefix("vmlinuz-") else {
            continue;
        };
        let Some((key, entry_flavour)) = kernel_key(release) else {
            continue;
        };
        if entry_flavour == flavour && newest.as_ref().is_none_or(|(best, _)| key > *best) {
            newest = Some((key, release.to_string()));
        }
    }
    Kernel::Known {
        running,
        behind: newest.as_ref().is_some_and(|(key, _)| *key > running_key),
        newest_installed: newest.map(|(_, release)| release),
    }
}

fn security_updates(ctx: &Context<'_>, cancellation: &CancellationToken) -> SecurityUpdates {
    let request = ProcessRequest::new(ctx.apt_config)
        .args(["dump", "Unattended-Upgrade::Allowed-Origins"])
        .env("LC_ALL", "C");
    let limits = ProcessLimits {
        timeout: Duration::from_secs(15),
        max_stdout_bytes: 64 * 1024,
        max_stderr_bytes: 16 * 1024,
    };
    let Ok(output) = process::run(&request, &limits, cancellation) else {
        return SecurityUpdates::Unknown {
            reason: "apt-config could not be started",
        };
    };
    if !matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) || output.stdout.truncated
    {
        return SecurityUpdates::Unknown {
            reason: "apt-config did not finish successfully",
        };
    }
    let text = String::from_utf8_lossy(&output.stdout.bytes);
    // `Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}-security";`
    let enabled = text.lines().any(|line| {
        line.trim_end()
            .trim_end_matches(';')
            .trim_end_matches('"')
            .ends_with("-security")
    });
    SecurityUpdates::Known { enabled }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// 2026-11-11 12:00:00 UTC.
    const NOW: u64 = 1_794_398_400;

    fn fake_apt(dir: &Path, script: &str) -> String {
        let path = dir.join("apt-get");
        std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.to_str().unwrap().to_string()
    }

    fn ctx<'a>(dir: &'a Path, apt: &'a str) -> Context<'a> {
        Context {
            apt_get: apt,
            reboot_required: Box::leak(dir.join("reboot-required").into_boxed_path()),
            reboot_required_pkgs: Box::leak(dir.join("reboot-required.pkgs").into_boxed_path()),
            update_stamp: Box::leak(dir.join("stamp").into_boxed_path()),
            apt_history: Box::leak(dir.join("history.log").into_boxed_path()),
            unattended_log: Box::leak(dir.join("unattended.log").into_boxed_path()),
            boot_dir: Box::leak(dir.join("boot").into_boxed_path()),
            osrelease: Box::leak(dir.join("osrelease").into_boxed_path()),
            apt_config: "/nonexistent/apt-config",
            now: NOW,
        }
    }

    #[test]
    fn parses_upgrade_and_new_dependency_lines() {
        let p = parse_inst("Inst libc6 [2.39-0ubuntu8.3] (2.39-0ubuntu8.4 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])").unwrap();
        assert_eq!(p.name, "libc6");
        assert_eq!(p.installed.as_deref(), Some("2.39-0ubuntu8.3"));
        assert_eq!(p.candidate, "2.39-0ubuntu8.4");
        assert!(p.security);
        let n = parse_inst(
            "Inst linux-image-6.8.0-149 (6.8.0-149.149 Ubuntu:24.04/noble-updates [amd64])",
        )
        .unwrap();
        assert_eq!(n.installed, None);
        assert!(!n.security);
        assert!(parse_inst("Conf libc6 (2.39 Ubuntu [amd64])").is_none());
        assert!(parse_inst("Inst bad;name [1] (2 x [a])").is_none());
    }

    #[test]
    fn lists_pending_sorted_and_reports_reboot() {
        let dir = tempfile::tempdir().unwrap();
        let apt = fake_apt(
            dir.path(),
            "echo 'Inst zlib1g [1] (2 Ubuntu/noble-security [amd64])'\necho 'Conf zlib1g (2 Ubuntu [amd64])'\necho 'Inst apparmor [1] (2 Ubuntu/noble-updates [amd64])'",
        );
        std::fs::write(
            dir.path().join("reboot-required"),
            "*** System restart required ***\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("reboot-required.pkgs"),
            "linux-image-6.8\nlinux-image-6.8\nbad name\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("stamp"), "").unwrap();
        std::fs::write(
            dir.path().join("history.log"),
            "Start-Date: 2026-10-01  03:00:00\nUpgrade: a:amd64 (1, 2)\nEnd-Date: 2026-10-01  03:01:00\n\nStart-Date: 2026-11-01  09:00:00\nUpgrade: b:amd64 (1, 2)\nEnd-Date: 2026-11-01  09:03:11\n\nStart-Date: 2026-11-02  09:00:00\nInstall: c:amd64 (1)\nEnd-Date: 2026-11-02  09:01:00\n",
        )
        .unwrap();
        let status = status(&ctx(dir.path(), &apt), &CancellationToken::default());
        let Pending::Known {
            packages,
            truncated,
        } = status.pending
        else {
            panic!("pending must be known");
        };
        assert!(!truncated);
        assert_eq!(
            packages.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            ["apparmor", "zlib1g"]
        );
        assert!(packages[1].security && !packages[0].security);
        assert_eq!(
            status.reboot,
            Reboot::Required {
                packages: vec!["linux-image-6.8".into()]
            }
        );
        assert!(status.lists_updated_at.is_some());
        assert_eq!(
            status.last_upgrade_local.as_deref(),
            Some("2026-11-01  09:03:11")
        );
    }

    #[test]
    fn failures_are_unknown_not_empty() {
        let dir = tempfile::tempdir().unwrap();
        let apt = fake_apt(dir.path(), "echo boom >&2; exit 100");
        let status = status(&ctx(dir.path(), &apt), &CancellationToken::default());
        assert!(matches!(status.pending, Pending::Unknown { .. }));
        assert_eq!(status.reboot, Reboot::NotRequired);
        assert_eq!(status.lists_updated_at, None);
        assert_eq!(status.last_upgrade_local, None);

        let missing = dir.path().join("nope").join("apt-get");
        let status = status_with_missing_dir(missing.to_str().unwrap(), dir.path());
        assert!(matches!(status.pending, Pending::Unknown { .. }));
        assert_eq!(status.reboot, Reboot::Unknown);
    }

    fn status_with_missing_dir(apt: &str, dir: &Path) -> UpdatesStatus {
        let gone = dir.join("gone");
        let ctx = Context {
            apt_get: apt,
            reboot_required: Box::leak(gone.join("reboot-required").into_boxed_path()),
            reboot_required_pkgs: Box::leak(gone.join("pkgs").into_boxed_path()),
            update_stamp: Box::leak(gone.join("stamp").into_boxed_path()),
            apt_history: Box::leak(gone.join("history").into_boxed_path()),
            unattended_log: Box::leak(gone.join("unattended.log").into_boxed_path()),
            boot_dir: Box::leak(gone.join("boot").into_boxed_path()),
            osrelease: Box::leak(gone.join("osrelease").into_boxed_path()),
            apt_config: "/nonexistent/apt-config",
            now: NOW,
        };
        status(&ctx, &CancellationToken::default())
    }

    fn write_log(dir: &Path, text: &str) {
        std::fs::write(dir.join("unattended.log"), text).unwrap();
    }

    #[test]
    fn counts_runs_and_failed_runs_inside_the_window_only() {
        let dir = tempfile::tempdir().unwrap();
        write_log(
            dir.path(),
            "2026-09-01 06:00:00,000 INFO Starting unattended upgrades script\n\
2026-09-01 06:00:01,000 ERROR too old to count\n\
2026-11-01 06:00:00,000 INFO Starting unattended upgrades script\n\
2026-11-01 06:01:00,000 INFO All upgrades installed\n\
2026-11-05 06:00:00,000 INFO Starting unattended upgrades script\n\
2026-11-05 06:00:30,000 ERROR Installing the upgrades failed!\n\
2026-11-05 06:00:31,000 ERROR Lock could not be acquired\n\
2026-11-09 06:00:00,000 INFO Starting unattended upgrades script\n\
2026-11-09 06:00:10,000 WARNING Could not figure out development release\n\
a line with no date\n",
        );
        let attempts = attempts(&ctx(dir.path(), "unused"));
        assert_eq!(
            attempts,
            Attempts::Known {
                window_days: 30,
                runs: 3,
                failed: 1,
                since: Some("2026-11-01".into())
            }
        );
    }

    #[test]
    fn history_lists_newest_runs_with_packages_and_results() {
        let dir = tempfile::tempdir().unwrap();
        write_log(
            dir.path(),
            "2026-11-01 06:00:00,000 INFO Starting unattended upgrades script\n\
2026-11-01 06:00:01,000 INFO Allowed origins are: o=Ubuntu,a=noble-security\n\
2026-11-01 06:00:02,000 INFO Packages that will be upgraded: libc6 libc-bin bad;name\n\
2026-11-01 06:01:00,000 INFO All upgrades installed\n\
2026-11-05 06:00:00,000 INFO Starting unattended upgrades script\n\
2026-11-05 06:00:02,000 INFO Packages that will be upgraded: openssl\n\
2026-11-05 06:00:30,000 ERROR Installing the upgrades failed!\n\
2026-11-09 06:00:00,000 INFO Starting unattended upgrades script\n\
2026-11-09 06:00:05,000 INFO No packages found that can be upgraded unattended and no pending auto-removals\n\
2026-11-10 06:00:00,000 INFO Starting unattended upgrades script\n\
garbage line\n",
        );
        let History::Known { runs, truncated } = history(&ctx(dir.path(), "unused")) else {
            panic!("expected known");
        };
        assert!(!truncated);
        let results: Vec<RunResult> = runs.iter().map(|r| r.result).collect();
        assert_eq!(
            results,
            [
                RunResult::Unknown,
                RunResult::NothingToDo,
                RunResult::Failed,
                RunResult::Installed
            ]
        );
        assert_eq!(runs[0].started_local, "2026-11-10 06:00:00");
        assert_eq!(runs[2].packages, ["openssl"]);
        assert_eq!(runs[3].packages, ["libc6", "libc-bin"]);
        assert_eq!(runs[3].package_count, 2);
    }

    #[test]
    fn history_is_capped_and_an_unreadable_log_is_unknown() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            history(&ctx(dir.path(), "unused")),
            History::Unknown { .. }
        ));
        let mut text = String::new();
        for day in 1..=12 {
            text.push_str(&format!(
                "2026-10-{day:02} 06:00:00,000 INFO Starting unattended upgrades script\n"
            ));
        }
        write_log(dir.path(), &text);
        let History::Known { runs, truncated } = history(&ctx(dir.path(), "unused")) else {
            panic!("expected known");
        };
        assert!(truncated);
        assert_eq!(runs.len(), HISTORY_RUNS);
        assert_eq!(runs[0].started_local, "2026-10-12 06:00:00");
    }

    #[test]
    fn an_empty_window_is_zero_but_an_unreadable_log_is_unknown() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            attempts(&ctx(dir.path(), "unused")),
            Attempts::Unknown { .. }
        ));
        write_log(
            dir.path(),
            "2026-01-01 06:00:00,000 INFO Starting unattended upgrades script\n",
        );
        assert_eq!(
            attempts(&ctx(dir.path(), "unused")),
            Attempts::Known {
                window_days: 30,
                runs: 0,
                failed: 0,
                since: None
            }
        );
    }

    #[test]
    fn days_from_civil_matches_known_dates() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2026, 11, 11), (NOW / 86_400) as i64);
    }

    fn boot(dir: &Path, running: &str, installed: &[&str]) {
        std::fs::write(dir.join("osrelease"), format!("{running}\n")).unwrap();
        std::fs::create_dir_all(dir.join("boot")).unwrap();
        for release in installed {
            std::fs::write(dir.join("boot").join(format!("vmlinuz-{release}")), "").unwrap();
        }
    }

    #[test]
    fn kernel_behind_compares_numbers_not_text_and_ignores_other_flavours() {
        let dir = tempfile::tempdir().unwrap();
        boot(
            dir.path(),
            "6.8.0-9-generic",
            &["6.8.0-9-generic", "6.8.0-100-generic", "6.9.0-1-aws"],
        );
        assert_eq!(
            kernel(&ctx(dir.path(), "unused")),
            Kernel::Known {
                running: "6.8.0-9-generic".into(),
                newest_installed: Some("6.8.0-100-generic".into()),
                behind: true
            }
        );
        let dir = tempfile::tempdir().unwrap();
        boot(
            dir.path(),
            "6.8.0-100-generic",
            &["6.8.0-9-generic", "6.8.0-100-generic"],
        );
        assert!(matches!(
            kernel(&ctx(dir.path(), "unused")),
            Kernel::Known { behind: false, .. }
        ));
    }

    #[test]
    fn an_unreadable_kernel_fact_is_unknown() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            kernel(&ctx(dir.path(), "unused")),
            Kernel::Unknown { .. }
        ));
        std::fs::write(dir.path().join("osrelease"), "6.8.0-1-generic\n").unwrap();
        assert!(matches!(
            kernel(&ctx(dir.path(), "unused")),
            Kernel::Unknown { reason } if reason.contains("/boot")
        ));
        std::fs::write(dir.path().join("osrelease"), "weird\n").unwrap();
        assert!(matches!(
            kernel(&ctx(dir.path(), "unused")),
            Kernel::Unknown { .. }
        ));
    }

    fn fake_apt_config(dir: &Path, script: &str) -> String {
        let path = dir.join("apt-config");
        std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.to_str().unwrap().to_string()
    }

    #[test]
    fn security_origin_is_detected_and_a_failure_is_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = ctx(dir.path(), "unused");
        let on = fake_apt_config(
            dir.path(),
            "echo 'Unattended-Upgrade::Allowed-Origins:: \"${distro_id}:${distro_codename}\";'\necho 'Unattended-Upgrade::Allowed-Origins:: \"${distro_id}:${distro_codename}-security\";'",
        );
        c.apt_config = &on;
        assert_eq!(
            security_updates(&c, &CancellationToken::default()),
            SecurityUpdates::Known { enabled: true }
        );
        let off = fake_apt_config(
            dir.path(),
            "echo 'Unattended-Upgrade::Allowed-Origins:: \"${distro_id}:${distro_codename}-updates\";'",
        );
        c.apt_config = &off;
        assert_eq!(
            security_updates(&c, &CancellationToken::default()),
            SecurityUpdates::Known { enabled: false }
        );
        let broken = fake_apt_config(dir.path(), "exit 1");
        c.apt_config = &broken;
        assert!(matches!(
            security_updates(&c, &CancellationToken::default()),
            SecurityUpdates::Unknown { .. }
        ));
    }
}
