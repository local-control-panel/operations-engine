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
const TIMEOUT: Duration = Duration::from_secs(60);
const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PACKAGES: usize = 500;
const MAX_REBOOT_PACKAGES: usize = 50;

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

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpdatesStatus {
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
}

impl Context<'static> {
    pub fn system() -> Self {
        Self {
            apt_get: "apt-get",
            reboot_required: Path::new(REBOOT_REQUIRED),
            reboot_required_pkgs: Path::new(REBOOT_REQUIRED_PKGS),
            update_stamp: Path::new(UPDATE_STAMP),
            apt_history: Path::new(APT_HISTORY),
        }
    }
}

pub fn status(ctx: &Context<'_>, cancellation: &CancellationToken) -> UpdatesStatus {
    UpdatesStatus {
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

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

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
        };
        status(&ctx, &CancellationToken::default())
    }
}
