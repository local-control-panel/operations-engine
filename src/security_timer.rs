//! The hourly schedule of the security feed check: a systemd `oneshot`
//! service and a timer written from the fixed templates below. Installed when
//! the policy becomes `checkOnly`, removed when it becomes `off`; nothing in
//! them comes from the feed or the caller. Without systemd as the running init
//! the schedule is `unavailable` and only manual refreshes happen.

use crate::process::{self, CancellationToken, ProcessLimits, ProcessRequest};
use std::{path::Path, time::Duration};

pub const UNIT_DIR: &str = "/etc/systemd/system";
pub const RUN_DIR: &str = "/run/systemd/system";
const NAME: &str = "wcp-security-refresh";

/// Fresh request id for every run; the engine binary is at its fixed path.
const SERVICE: &str = "[Unit]\n\
Description=OrbDen security feed check (check only)\n\
\n\
[Service]\n\
Type=oneshot\n\
ExecStart=/bin/sh -c 'exec /usr/local/bin/ops-engine security refresh --request-id \"$(cat /proc/sys/kernel/random/uuid)\"'\n\
TimeoutStartSec=120\n\
NoNewPrivileges=yes\n\
";

/// About hourly, spread over ten minutes so servers do not hit the origin together.
const TIMER: &str = "[Unit]\n\
Description=OrbDen security feed check, hourly\n\
\n\
[Timer]\n\
OnBootSec=10min\n\
OnUnitActiveSec=1h\n\
RandomizedDelaySec=10min\n\
Persistent=true\n\
\n\
[Install]\n\
WantedBy=timers.target\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Timer {
    Installed,
    Removed,
    Unavailable,
}

impl Timer {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Installed => "installed",
            Self::Removed => "removed",
            Self::Unavailable => "unavailable",
        }
    }
}

fn systemctl(program: &str, args: &[&str]) -> bool {
    let request = ProcessRequest::new(program).args(args.iter().copied());
    process::run(
        &request,
        &ProcessLimits {
            timeout: Duration::from_secs(60),
            max_stdout_bytes: 16 * 1024,
            max_stderr_bytes: 16 * 1024,
        },
        &CancellationToken::default(),
    )
    .is_ok_and(|output| process::error_code(&output.termination).is_none())
}

/// Brings the schedule in line with `enabled`. `Unavailable` when systemd is
/// not the running init or `systemctl` refuses.
pub fn sync(enabled: bool, unit_dir: &Path, run_dir: &Path, program: &str) -> Timer {
    if !run_dir.is_dir() {
        return Timer::Unavailable;
    }
    let service = unit_dir.join(format!("{NAME}.service"));
    let timer = unit_dir.join(format!("{NAME}.timer"));
    let unit = format!("{NAME}.timer");
    if enabled {
        if std::fs::write(&service, SERVICE).is_err() || std::fs::write(&timer, TIMER).is_err() {
            return Timer::Unavailable;
        }
        if systemctl(program, &["daemon-reload"]) && systemctl(program, &["enable", "--now", &unit])
        {
            Timer::Installed
        } else {
            Timer::Unavailable
        }
    } else {
        let _ = systemctl(program, &["disable", "--now", &unit]);
        let _ = std::fs::remove_file(&timer);
        let _ = std::fs::remove_file(&service);
        let _ = systemctl(program, &["daemon-reload"]);
        Timer::Removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fake(dir: &Path) -> String {
        let path = dir.join("fake-systemctl");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\necho \"$*\" >> '{}'\nexit 0\n",
                dir.join("calls").display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn enabling_writes_the_fixed_units_and_disabling_removes_them() {
        let dir = tempfile::tempdir().unwrap();
        let units = dir.path().join("units");
        let run = dir.path().join("run");
        std::fs::create_dir_all(&units).unwrap();
        std::fs::create_dir_all(&run).unwrap();
        let program = fake(dir.path());
        assert_eq!(sync(true, &units, &run, &program), Timer::Installed);
        let timer = std::fs::read_to_string(units.join("wcp-security-refresh.timer")).unwrap();
        assert!(timer.contains("OnUnitActiveSec=1h") && timer.contains("RandomizedDelaySec=10min"));
        let service = std::fs::read_to_string(units.join("wcp-security-refresh.service")).unwrap();
        assert!(service.contains("security refresh --request-id"));
        let calls = std::fs::read_to_string(dir.path().join("calls")).unwrap();
        assert!(
            calls.contains("enable --now wcp-security-refresh.timer"),
            "{calls}"
        );
        assert_eq!(sync(false, &units, &run, &program), Timer::Removed);
        assert!(!units.join("wcp-security-refresh.timer").exists());
        assert!(!units.join("wcp-security-refresh.service").exists());
        // Idempotent.
        assert_eq!(sync(false, &units, &run, &program), Timer::Removed);
    }

    #[test]
    fn without_systemd_as_init_nothing_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let program = fake(dir.path());
        assert_eq!(
            sync(true, dir.path(), &dir.path().join("no-run"), &program),
            Timer::Unavailable
        );
        assert!(!dir.path().join("wcp-security-refresh.timer").exists());
    }
}
