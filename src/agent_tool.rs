//! `ops-engine agent tool status|ensure`: the programs an agent may depend on,
//! on top of the installers the engine already has.
//!
//! The list is closed and compiled in: `wp-cli` (the engine-managed catalog,
//! `tool.install`), `rclone` (`backup.installRclone`) and `docker`
//! (`system.installDocker`). Nothing here can name a URL, a package or a path;
//! `ensure` only runs one of those three operations, which keep their own
//! pinning, verification, locking and audit.
//!
//! `status` is read-only. `ensure` changes the host only when the **operator**
//! allowed it (the tool is listed in `$WCP_DIR/allow-tool-ensure`, a file owned
//! by the running user and not writable by others) and `WCP_DRY_RUN` is not 1;
//! otherwise it reports what it would do, or why it will not.

use std::{
    ffi::OsString,
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use serde::Serialize;
use serde_json::Value;

use crate::{
    process::{self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination},
    tool_manage,
};

/// The file that lists, one name per line, the tools `ensure` may install.
pub const ALLOW_FILE: &str = "allow-tool-ensure";
const VERSION_TIMEOUT: Duration = Duration::from_secs(10);
const INSTALL_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const MAX_ALLOW_BYTES: u64 = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentTool {
    WpCli,
    Rclone,
    Docker,
}

impl AgentTool {
    pub const ALL: [Self; 3] = [Self::WpCli, Self::Rclone, Self::Docker];

    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tool| tool.name() == name)
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::WpCli => "wp-cli",
            Self::Rclone => "rclone",
            Self::Docker => "docker",
        }
    }

    /// The protocol operation that installs it.
    pub const fn installer(self) -> &'static str {
        match self {
            Self::WpCli => "tool.install",
            Self::Rclone => "backup.installRclone",
            Self::Docker => "system.installDocker",
        }
    }

    /// The engine arguments (before `--request-id`) that run the installer.
    fn install_args(self) -> Vec<String> {
        let words: &[&str] = match self {
            Self::WpCli => &["tool", "install", "--tool", "wp-cli"],
            Self::Rclone => &["backup", "install-rclone"],
            Self::Docker => &["system", "install-docker"],
        };
        words.iter().map(|word| (*word).to_owned()).collect()
    }
}

/// Where tools are looked for. `production()` is the real host; tests build
/// their own.
#[derive(Clone, Debug)]
pub struct Host {
    pub tools_dir: PathBuf,
    pub rclone: Vec<PathBuf>,
    pub docker: Vec<PathBuf>,
}

impl Host {
    /// The real locations, or the directories in `WCP_TOOL_BIN_DIRS`
    /// (colon-separated, a development and test hook that only changes where
    /// `status` looks) and `WCP_TOOLS_DIR`.
    pub fn production() -> Self {
        let from_env = |name: &str| std::env::var_os(name).filter(|value| !value.is_empty());
        let tools_dir = from_env("WCP_TOOLS_DIR")
            .map_or_else(|| PathBuf::from(tool_manage::TOOLS_DIR), PathBuf::from);
        let (rclone, docker) = match from_env("WCP_TOOL_BIN_DIRS") {
            Some(dirs) => {
                let dirs: Vec<PathBuf> = std::env::split_paths(&dirs).collect();
                (
                    dirs.iter().map(|dir| dir.join("rclone")).collect(),
                    dirs.iter().map(|dir| dir.join("docker")).collect(),
                )
            }
            None => (
                crate::backup_install_rclone::EXISTING_PATHS
                    .iter()
                    .map(PathBuf::from)
                    .collect(),
                crate::system_install_docker::CLI_BINARIES
                    .iter()
                    .chain(crate::system_install_docker::UNOWNED_BINARIES)
                    .map(PathBuf::from)
                    .collect(),
            ),
        };
        Self {
            tools_dir,
            rclone,
            docker,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolState {
    pub tool: &'static str,
    pub present: bool,
    pub version: Option<String>,
    pub path: Option<String>,
    pub installer: &'static str,
}

fn is_executable(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

/// The first word of `output` that looks like a version, after `prefix` words.
fn version_in(output: &str, skip_words: usize) -> Option<String> {
    let word = output
        .lines()
        .next()?
        .split_whitespace()
        .nth(skip_words)?
        .trim_end_matches(',');
    let word = word.strip_prefix('v').unwrap_or(word);
    (!word.is_empty()
        && word.len() <= 64
        && word.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+' | b'_' | b':' | b'~')
        }))
    .then(|| word.to_owned())
}

fn probe_version(binary: &Path, argument: &str, skip_words: usize) -> Option<String> {
    let output = process::run(
        &ProcessRequest::new(binary).args([argument]),
        &ProcessLimits {
            timeout: VERSION_TIMEOUT,
            max_stdout_bytes: 16 * 1024,
            max_stderr_bytes: 4 * 1024,
        },
        &CancellationToken::default(),
    )
    .ok()?;
    match output.termination {
        ProcessTermination::Exited { success: true, .. } => {
            version_in(&String::from_utf8_lossy(&output.stdout.bytes), skip_words)
        }
        _ => None,
    }
}

pub fn status(host: &Host, tool: AgentTool) -> ToolState {
    let absent = ToolState {
        tool: tool.name(),
        present: false,
        version: None,
        path: None,
        installer: tool.installer(),
    };
    match tool {
        AgentTool::WpCli => {
            let current = host.tools_dir.join("wp-cli").join("current");
            let Some(version) = fs::read_link(&current)
                .ok()
                .and_then(|target| target.to_str().map(str::to_owned))
                .filter(|name| !name.is_empty() && !name.contains('/') && !name.starts_with('.'))
            else {
                return absent;
            };
            let file = current.join("wp.phar");
            if !file.is_file() {
                return absent;
            }
            ToolState {
                present: true,
                version: Some(version),
                path: Some(file.to_string_lossy().into_owned()),
                ..absent
            }
        }
        AgentTool::Rclone | AgentTool::Docker => {
            let (candidates, argument, skip) = if tool == AgentTool::Rclone {
                (&host.rclone, "version", 1)
            } else {
                (&host.docker, "--version", 2)
            };
            let Some(binary) = candidates.iter().find(|path| is_executable(path)) else {
                return absent;
            };
            ToolState {
                present: true,
                version: probe_version(binary, argument, skip),
                path: Some(binary.to_string_lossy().into_owned()),
                ..absent
            }
        }
    }
}

/// Whether the operator listed `tool` in `<dir>/allow-tool-ensure`. A file
/// that is missing, a symlink, not a regular file, owned by someone else or
/// writable by group or others allows nothing.
pub fn allowed(dir: &Path, tool: AgentTool, required_uid: u32) -> bool {
    let Ok(mut file) = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dir.join(ALLOW_FILE))
    else {
        return false;
    };
    let Ok(meta) = file.metadata() else {
        return false;
    };
    if !meta.is_file()
        || meta.uid() != required_uid
        || meta.permissions().mode() & 0o022 != 0
        || meta.len() > MAX_ALLOW_BYTES
    {
        return false;
    }
    let mut text = String::new();
    if file
        .by_ref()
        .take(MAX_ALLOW_BYTES)
        .read_to_string(&mut text)
        .is_err()
    {
        return false;
    }
    text.lines().map(str::trim).any(|line| line == tool.name())
}

/// How `ensure` ended.
#[derive(Debug, Eq, PartialEq)]
pub enum Ensure {
    /// Already there; nothing done.
    Present(ToolState),
    /// Installed now.
    Installed(ToolState),
    /// A dry run: this is what would be done.
    WouldInstall(ToolState),
    /// Missing and the operator did not allow `ensure` for it.
    NotAllowed(ToolState),
    /// The installer ran and failed, or the tool is still missing after it.
    Failed(ToolState, String),
}

impl Ensure {
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Present(_) | Self::Installed(_) | Self::WouldInstall(_) => 0,
            Self::NotAllowed(_) | Self::Failed(..) => 1,
        }
    }
}

/// Runs the installer with these engine arguments; `Err` carries one line.
pub type Installer<'a> = &'a dyn Fn(&[String]) -> Result<(), String>;

pub fn ensure(
    host: &Host,
    tool: AgentTool,
    allowed: bool,
    dry_run: bool,
    install: Installer<'_>,
    request_id: &str,
) -> Ensure {
    let state = status(host, tool);
    if state.present {
        return Ensure::Present(state);
    }
    if !allowed {
        return Ensure::NotAllowed(state);
    }
    if dry_run {
        return Ensure::WouldInstall(state);
    }
    let mut args = tool.install_args();
    args.extend(["--request-id".to_owned(), request_id.to_owned()]);
    if let Err(message) = install(&args) {
        return Ensure::Failed(state, message);
    }
    let after = status(host, tool);
    if after.present {
        Ensure::Installed(after)
    } else {
        Ensure::Failed(
            after,
            "the installer finished but the tool is still missing".into(),
        )
    }
}

/// Runs this same engine binary with `args` and reads the envelope it prints.
pub fn run_self(args: &[String]) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|_| "cannot find the engine binary".to_owned())?;
    run_program(&exe, args)
}

fn run_program(exe: &Path, args: &[String]) -> Result<(), String> {
    let exe: OsString = exe.as_os_str().to_owned();
    let output = process::run(
        &ProcessRequest::new(exe).args(args),
        &ProcessLimits {
            timeout: INSTALL_TIMEOUT,
            max_stdout_bytes: 256 * 1024,
            max_stderr_bytes: 16 * 1024,
        },
        &CancellationToken::default(),
    )
    .map_err(|_| "could not run the installer".to_owned())?;
    match output.termination {
        ProcessTermination::TimedOut => return Err("the installer timed out".into()),
        ProcessTermination::Cancelled => return Err("the installer was cancelled".into()),
        ProcessTermination::Exited { .. } => {}
    }
    let envelope: Value = serde_json::from_slice(&output.stdout.bytes)
        .map_err(|_| "the installer printed no answer".to_owned())?;
    if envelope["ok"] == true {
        return Ok(());
    }
    let message = envelope["error"]["message"].as_str().unwrap_or("it failed");
    let code = envelope["error"]["code"].as_str().unwrap_or("ERROR");
    Err(format!(
        "{code}: {}",
        message.chars().take(200).collect::<String>()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn script(path: &Path, body: &str) {
        fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn host(root: &Path) -> Host {
        Host {
            tools_dir: root.join("tools"),
            rclone: vec![root.join("bin/rclone"), root.join("bin2/rclone")],
            docker: vec![root.join("bin/docker")],
        }
    }

    fn uid() -> u32 {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() }
    }

    #[test]
    fn the_names_are_a_closed_list() {
        assert_eq!(AgentTool::parse("rclone"), Some(AgentTool::Rclone));
        assert_eq!(AgentTool::parse("wp-cli"), Some(AgentTool::WpCli));
        assert_eq!(AgentTool::parse("docker"), Some(AgentTool::Docker));
        for bad in ["", "curl", "../rclone", "RCLONE", "rclone ", "tool.install"] {
            assert_eq!(AgentTool::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn missing_tools_are_reported_absent() {
        let root = tempfile::tempdir().unwrap();
        let host = host(root.path());
        for tool in AgentTool::ALL {
            let state = status(&host, tool);
            assert!(!state.present, "{tool:?}");
            assert_eq!(state.version, None);
            assert_eq!(state.path, None);
        }
    }

    #[test]
    fn rclone_and_docker_report_the_version_their_binary_prints() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("bin")).unwrap();
        script(
            &root.path().join("bin/rclone"),
            "echo 'rclone v1.75.1'; echo '- os/version: debian 12'",
        );
        script(
            &root.path().join("bin/docker"),
            "echo 'Docker version 27.3.1, build ce12230'",
        );
        let host = host(root.path());
        let rclone = status(&host, AgentTool::Rclone);
        assert!(rclone.present);
        assert_eq!(rclone.version.as_deref(), Some("1.75.1"));
        assert!(rclone.path.unwrap().ends_with("bin/rclone"));
        let docker = status(&host, AgentTool::Docker);
        assert_eq!(docker.version.as_deref(), Some("27.3.1"));
        assert_eq!(docker.installer, "system.installDocker");
    }

    #[test]
    fn a_binary_that_fails_or_prints_junk_is_present_without_a_version() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("bin")).unwrap();
        script(&root.path().join("bin/rclone"), "exit 3");
        script(
            &root.path().join("bin/docker"),
            "echo 'weird $(rm -rf) output here'",
        );
        let host = host(root.path());
        let rclone = status(&host, AgentTool::Rclone);
        assert!(rclone.present);
        assert_eq!(rclone.version, None);
        assert_eq!(status(&host, AgentTool::Docker).version, None);
    }

    #[test]
    fn a_file_that_is_not_executable_is_not_a_tool() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("bin")).unwrap();
        fs::write(root.path().join("bin/rclone"), "x").unwrap();
        assert!(!status(&host(root.path()), AgentTool::Rclone).present);
    }

    #[test]
    fn wp_cli_is_present_when_current_points_at_a_version_with_the_phar() {
        let root = tempfile::tempdir().unwrap();
        let tool = root.path().join("tools/wp-cli");
        fs::create_dir_all(tool.join("2.12.0")).unwrap();
        std::os::unix::fs::symlink("2.12.0", tool.join("current")).unwrap();
        let host = host(root.path());
        assert!(!status(&host, AgentTool::WpCli).present, "no phar yet");
        fs::write(tool.join("2.12.0/wp.phar"), "x").unwrap();
        let state = status(&host, AgentTool::WpCli);
        assert!(state.present);
        assert_eq!(state.version.as_deref(), Some("2.12.0"));
        assert_eq!(state.installer, "tool.install");
    }

    #[test]
    fn a_current_link_that_leaves_the_tool_directory_is_ignored() {
        let root = tempfile::tempdir().unwrap();
        let tool = root.path().join("tools/wp-cli");
        fs::create_dir_all(&tool).unwrap();
        std::os::unix::fs::symlink("../../elsewhere", tool.join("current")).unwrap();
        assert!(!status(&host(root.path()), AgentTool::WpCli).present);
    }

    #[test]
    fn only_a_trusted_allow_file_allows_a_listed_tool() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(ALLOW_FILE);
        assert!(!allowed(root.path(), AgentTool::Rclone, uid()));
        fs::write(&path, "# operator\nrclone\n  docker  \n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(allowed(root.path(), AgentTool::Rclone, uid()));
        assert!(allowed(root.path(), AgentTool::Docker, uid()));
        assert!(!allowed(root.path(), AgentTool::WpCli, uid()));
        assert!(!allowed(root.path(), AgentTool::Rclone, uid() + 1));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(!allowed(root.path(), AgentTool::Rclone, uid()));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(&path, "rclone-extra\nxrclone\n").unwrap();
        assert!(
            !allowed(root.path(), AgentTool::Rclone, uid()),
            "whole lines only"
        );
    }

    #[test]
    fn a_symlinked_allow_file_allows_nothing() {
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real");
        fs::write(&real, "rclone\n").unwrap();
        std::os::unix::fs::symlink(&real, root.path().join(ALLOW_FILE)).unwrap();
        assert!(!allowed(root.path(), AgentTool::Rclone, uid()));
    }

    #[test]
    fn ensure_does_nothing_when_the_tool_is_there() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("bin")).unwrap();
        script(&root.path().join("bin/rclone"), "echo 'rclone v1.2.3'");
        let never = |_: &[String]| -> Result<(), String> { panic!("must not install") };
        let outcome = ensure(
            &host(root.path()),
            AgentTool::Rclone,
            true,
            false,
            &never,
            "id",
        );
        assert!(matches!(outcome, Ensure::Present(_)));
        assert_eq!(outcome.exit_code(), 0);
    }

    #[test]
    fn ensure_refuses_unless_the_operator_allowed_it_and_never_installs_in_a_dry_run() {
        let root = tempfile::tempdir().unwrap();
        let never = |_: &[String]| -> Result<(), String> { panic!("must not install") };
        let host = host(root.path());
        let refused = ensure(&host, AgentTool::Rclone, false, false, &never, "id");
        assert!(matches!(refused, Ensure::NotAllowed(_)));
        assert_eq!(refused.exit_code(), 1);
        let refused_dry = ensure(&host, AgentTool::Rclone, false, true, &never, "id");
        assert!(matches!(refused_dry, Ensure::NotAllowed(_)));
        let dry = ensure(&host, AgentTool::Rclone, true, true, &never, "id");
        assert!(matches!(dry, Ensure::WouldInstall(_)));
        assert_eq!(dry.exit_code(), 0);
    }

    #[test]
    fn ensure_runs_exactly_the_documented_installer_once() {
        let expected = [
            (
                AgentTool::WpCli,
                vec!["tool", "install", "--tool", "wp-cli"],
            ),
            (AgentTool::Rclone, vec!["backup", "install-rclone"]),
            (AgentTool::Docker, vec!["system", "install-docker"]),
        ];
        for (tool, words) in expected {
            let root = tempfile::tempdir().unwrap();
            let host = host(root.path());
            let calls = RefCell::new(Vec::new());
            let install = |args: &[String]| -> Result<(), String> {
                calls.borrow_mut().push(args.to_vec());
                // The installer "works": put the tool where status looks.
                match tool {
                    AgentTool::WpCli => {
                        let dir = host.tools_dir.join("wp-cli");
                        fs::create_dir_all(dir.join("2.12.0")).unwrap();
                        fs::write(dir.join("2.12.0/wp.phar"), "x").unwrap();
                        std::os::unix::fs::symlink("2.12.0", dir.join("current")).unwrap();
                    }
                    AgentTool::Rclone => {
                        fs::create_dir_all(root.path().join("bin")).unwrap();
                        script(&root.path().join("bin/rclone"), "echo 'rclone v1.0.0'");
                    }
                    AgentTool::Docker => {
                        fs::create_dir_all(root.path().join("bin")).unwrap();
                        script(
                            &root.path().join("bin/docker"),
                            "echo 'Docker version 1.0.0, build x'",
                        );
                    }
                }
                Ok(())
            };
            let outcome = ensure(
                &host,
                tool,
                true,
                false,
                &install,
                "11111111-1111-4111-8111-111111111111",
            );
            assert!(
                matches!(outcome, Ensure::Installed(_)),
                "{tool:?}: {outcome:?}"
            );
            let calls = calls.borrow();
            assert_eq!(calls.len(), 1);
            let mut want: Vec<String> = words.iter().map(|w| (*w).to_owned()).collect();
            want.extend([
                "--request-id".into(),
                "11111111-1111-4111-8111-111111111111".into(),
            ]);
            assert_eq!(calls[0], want);
        }
    }

    #[test]
    fn a_failed_installer_and_a_lying_installer_both_fail() {
        let root = tempfile::tempdir().unwrap();
        let host = host(root.path());
        let failing = |_: &[String]| -> Result<(), String> { Err("TIMEOUT: slow".into()) };
        let outcome = ensure(&host, AgentTool::Rclone, true, false, &failing, "id");
        assert!(matches!(&outcome, Ensure::Failed(_, message) if message == "TIMEOUT: slow"));
        assert_eq!(outcome.exit_code(), 1);
        let lying = |_: &[String]| -> Result<(), String> { Ok(()) };
        let outcome = ensure(&host, AgentTool::Rclone, true, false, &lying, "id");
        assert!(matches!(outcome, Ensure::Failed(..)));
    }

    #[test]
    fn the_installer_envelope_decides_success() {
        let root = tempfile::tempdir().unwrap();
        let ok = root.path().join("ok");
        script(&ok, r#"echo '{"ok":true,"result":{}}'"#);
        assert_eq!(run_program(&ok, &[]), Ok(()));
        let bad = root.path().join("bad");
        script(
            &bad,
            r#"echo '{"ok":false,"error":{"code":"ARTIFACT_FETCH_FAILED","message":"could not download"}}'; exit 1"#,
        );
        assert_eq!(
            run_program(&bad, &[]),
            Err("ARTIFACT_FETCH_FAILED: could not download".to_owned())
        );
        let silent = root.path().join("silent");
        script(&silent, "exit 1");
        assert!(run_program(&silent, &[]).is_err());
        assert!(run_program(&root.path().join("missing"), &[]).is_err());
        let echo = root.path().join("echo");
        script(&echo, r#"echo "{\"ok\":true,\"args\":\"$*\"}""#);
        assert_eq!(
            run_program(&echo, &["tool".into(), "install".into()]),
            Ok(())
        );
    }

    #[test]
    fn version_parsing_takes_the_expected_word_and_nothing_odd() {
        assert_eq!(
            version_in("rclone v1.75.1\nmore", 1).as_deref(),
            Some("1.75.1")
        );
        assert_eq!(
            version_in("Docker version 27.3.1, build x", 2).as_deref(),
            Some("27.3.1")
        );
        assert_eq!(version_in("", 1), None);
        assert_eq!(version_in("rclone", 1), None);
        assert_eq!(version_in("rclone $(id)", 1), None);
        assert_eq!(version_in(&format!("x {}", "9".repeat(65)), 1), None);
    }
}
