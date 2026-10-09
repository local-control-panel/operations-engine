//! The transactional pipelines for installing and removing a bundled agent and
//! for the manual brute-force unban. See the parent module for the design.
//!
//! Install and remove hold the `cron/root` lock scope that `cron.installTab`
//! and the scheduled-backup operations use, so no other crontab writer can
//! interleave with their read-modify-write; a final re-read of the tab before
//! the install also catches writers that do not take the lock. The unban has
//! a scope of its own.

use super::{
    AGENTS_DIR, BANS_FILE, EVENTS_FILE, GUARD_NAME, INSTALL_OPERATION, InstallRequest,
    InstallResult, LIBRARY_FILE, MANIFEST_FILE, REMOVE_OPERATION, RemoveRequest, RemoveResult,
    UNBAN_OPERATION, UnbanRequest, UnbanResult, current_schedule, find, library, manifest_entry,
    manifest_with, tab_too_large, unban_event, with_agent, without_ban,
};
use crate::{
    backup_schedule::Schedule,
    cron::execute::{InstallFailure, open_cron_state, read_current_tab},
    error::ErrorCode,
    filesystem::ManagedRoot,
    ingress::ConfigHash,
    mutation::preflight,
    process::{self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination},
    site::{SiteRelativePath, TrustedRoot},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        commit::PreCommit,
        state::{self, TransactionState, TransactionStatus},
    },
};
use serde::{Serialize, de::DeserializeOwned};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The cron user whose crontab holds agent lines.
const CRON_USER: &str = "root";
/// The guard re-applies the ban list and reloads Caddy in a container.
const APPLY_TIMEOUT: Duration = Duration::from_secs(120);

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub state_root: &'a TrustedRoot,
    /// The agent root (`/root/.wcp`).
    pub root: &'a ManagedRoot,
    pub crontab_program: &'a str,
    /// What runs the guard script; `bash` outside tests.
    pub shell_program: &'a str,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    State(state::StateError),
    ReplayInProgress,
    Read(process::ProcessRunError),
    NotUtf8,
    TooLarge,
    TabChanged,
    Install(InstallFailure),
    Cancelled,
    ApplyFailed(Option<ErrorCode>),
    Replayed { code: ErrorCode, message: String },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Io(_) | Self::State(_) => {
                (ErrorCode::Internal, "internal agent operation error".into())
            }
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another agent or crontab change is already in progress".into(),
            ),
            Self::Preflight(_) => (ErrorCode::Internal, "preflight failed".into()),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Read(error) => (
                process::spawn_error_code(error),
                "could not read the current crontab".into(),
            ),
            Self::NotUtf8 => (
                ErrorCode::Internal,
                "the current crontab is not valid UTF-8".into(),
            ),
            Self::TooLarge => (
                ErrorCode::InvalidInput,
                "the resulting crontab exceeds the maximum size".into(),
            ),
            Self::TabChanged => (
                ErrorCode::ConfigHashMismatch,
                "the crontab changed while it was being edited - retry".into(),
            ),
            Self::Install(InstallFailure::Run(error)) => (
                process::spawn_error_code(error),
                "could not run crontab".into(),
            ),
            Self::Install(InstallFailure::Rejected(diagnostics)) => (
                if diagnostics.timed_out {
                    ErrorCode::Timeout
                } else {
                    ErrorCode::ConfigValidationFailed
                },
                "the submitted crontab was rejected".into(),
            ),
            Self::Cancelled => (ErrorCode::Cancelled, "cancelled before the commit".into()),
            Self::ApplyFailed(code) => (
                code.unwrap_or(ErrorCode::SubprocessFailed),
                "the brute-force guard could not apply the ban list; the ban was kept".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
        }
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn rel(path: &str) -> SiteRelativePath {
    SiteRelativePath::parse(path).expect("literal or validated path")
}

fn state_path(id: RequestId) -> SiteRelativePath {
    rel(&format!("transactions/{id}.json"))
}

fn read_tab(program: &str) -> Result<String, Error> {
    let bytes = read_current_tab(program, None)
        .map_err(Error::Read)?
        .unwrap_or_default();
    String::from_utf8(bytes).map_err(|_| Error::NotUtf8)
}

fn sha256(bytes: &[u8]) -> String {
    ConfigHash::of(bytes).as_str().to_owned()
}

/// Installs `content` unless the tab changed since `before` was read.
fn install_guarded(ctx: &Context<'_>, before: &str, content: &str) -> Result<(), Error> {
    if tab_too_large(content) {
        return Err(Error::TooLarge);
    }
    if read_tab(ctx.crontab_program)? != before {
        return Err(Error::TabChanged);
    }
    if before == content {
        return Ok(());
    }
    crate::cron::execute::install(ctx.state_root, ctx.crontab_program, content, None)
        .map_err(Error::Install)
}

/// Opens (creating if necessary) the state scope of the unban.
fn open_unban_scope(engine_state: &ManagedRoot) -> std::io::Result<ManagedRoot> {
    let relative = rel("agent/bruteforce");
    engine_state.create_dir_all(&relative)?;
    let scoped = engine_state.open_managed_dir(&relative)?;
    for sub in ["locks", "transactions", "audit"] {
        scoped.create_dir_all(&rel(sub))?;
    }
    Ok(scoped)
}

fn transactional<T: Serialize + DeserializeOwned>(
    scope: &ManagedRoot,
    request_id: RequestId,
    key: Option<&IdempotencyKey>,
    operation: &'static str,
    cancel: &CancellationToken,
    body: impl FnOnce() -> Result<T, Error>,
) -> Result<T, Error> {
    let admitted =
        match preflight::run(scope, request_id, key, operation).map_err(Error::Preflight)? {
            preflight::Outcome::Replay(original) => return replay(scope, original, operation),
            preflight::Outcome::Proceed(admitted) => admitted,
        };
    let preflight::Admitted { lock, mut state } = admitted;
    let path = state_path(request_id);
    let audit_path = rel("audit/events.jsonl");
    let pre_commit = PreCommit::new(cancel.clone());
    let outcome = if pre_commit.check().is_err() {
        Err(Error::Cancelled)
    } else {
        body()
    };
    match outcome {
        Err(error) => Err(fail(scope, &path, &audit_path, state, error)),
        Ok(result) => {
            let _ = pre_commit.commit();
            state
                .mark_committed(serde_json::to_value(&result).expect("results serialize"))
                .expect("state is in progress");
            let saved = state::save(scope, &path, &state);
            let _ = audit::append(
                scope,
                &audit_path,
                &AuditRecord::result(request_id, true, None),
            );
            drop(lock);
            // The change is already live; a missing record only costs
            // replayability, so report success.
            let _ = saved;
            Ok(result)
        }
    }
}

fn replay<T: DeserializeOwned>(
    scope: &ManagedRoot,
    original: RequestId,
    operation: &'static str,
) -> Result<T, Error> {
    let loaded = state::load(scope, &state_path(original)).map_err(Error::State)?;
    if loaded.operation != operation {
        return Err(Error::State(state::StateError::Corrupt));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => {
            let value = loaded
                .outcome
                .and_then(|outcome| outcome.result)
                .ok_or(Error::State(state::StateError::Corrupt))?;
            serde_json::from_value(value).map_err(|_| Error::State(state::StateError::Corrupt))
        }
        TransactionStatus::Failed => {
            let outcome = loaded
                .outcome
                .ok_or(Error::State(state::StateError::Corrupt))?;
            Err(Error::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}

fn fail(
    scope: &ManagedRoot,
    path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut state: TransactionState,
    error: Error,
) -> Error {
    let (code, message) = error.protocol();
    let _ = state.mark_failed(code, message);
    let _ = state::save(scope, path, &state);
    let _ = audit::append(
        scope,
        audit_path,
        &AuditRecord::result(state.request_id, false, Some(code)),
    );
    error
}

/// How a file is written and restored: scripts are executable, everything
/// else is private to root.
#[derive(Clone, Copy)]
enum Kind {
    Executable,
    Private,
}

fn write(
    root: &ManagedRoot,
    path: &SiteRelativePath,
    bytes: &[u8],
    kind: Kind,
) -> std::io::Result<()> {
    match kind {
        Kind::Executable => root.write_new_executable(path, bytes),
        Kind::Private => root.write_atomic_private(path, bytes),
    }
}

/// Puts a file back as it was: its old bytes, or gone if it did not exist.
fn restore(root: &ManagedRoot, path: &SiteRelativePath, previous: &Option<Vec<u8>>, kind: Kind) {
    let _ = match previous {
        Some(bytes) => write(root, path, bytes, kind),
        None => root.remove_file(path).or_else(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(error)
            }
        }),
    };
}

fn read_optional(root: &ManagedRoot, path: &SiteRelativePath) -> Option<Vec<u8>> {
    root.read_bytes(path).ok()
}

fn is_executable(root: &ManagedRoot, path: &SiteRelativePath) -> bool {
    root.mode(path).is_ok_and(|mode| mode & 0o777 == 0o755)
}

pub fn install(
    ctx: &Context<'_>,
    request: &InstallRequest,
    cancel: &CancellationToken,
) -> Result<InstallResult, Error> {
    let scope = open_cron_state(ctx.engine_state, Some(CRON_USER)).map_err(Error::Io)?;
    transactional(
        &scope,
        request.request_id,
        request.idempotency_key.as_ref(),
        INSTALL_OPERATION,
        cancel,
        || {
            let agent = request.agent;
            let before = read_tab(ctx.crontab_program)?;
            let schedule: Option<Schedule> = if agent.configurable_schedule {
                request
                    .schedule
                    .clone()
                    .or_else(|| current_schedule(&before, agent.name))
            } else {
                None
            }
            .or_else(|| {
                agent
                    .default_schedule
                    .map(|text| Schedule::parse(text).expect("catalog schedules are valid"))
            });
            let (content, replaced) = with_agent(&before, agent, schedule.as_ref());

            let agents_dir = rel(AGENTS_DIR);
            let script_path = rel(&agent.relative_script_path());
            let library_path = rel(&format!("{AGENTS_DIR}/{LIBRARY_FILE}"));
            let manifest_path = rel(MANIFEST_FILE);
            let script = agent.installed_script();
            let previous_script = read_optional(ctx.root, &script_path);
            let previous_library = read_optional(ctx.root, &library_path);
            let previous_manifest = read_optional(ctx.root, &manifest_path);
            let previous_manifest_text = previous_manifest
                .as_deref()
                .and_then(|bytes| std::str::from_utf8(bytes).ok());
            let previous_entry = manifest_entry(previous_manifest_text, agent.name);

            let files_current = previous_script.as_deref() == Some(script.as_bytes())
                && (!agent.bundled || previous_library.as_deref() == Some(library().as_bytes()))
                && is_executable(ctx.root, &script_path)
                && previous_entry
                    .as_ref()
                    .and_then(|entry| entry.get("version"))
                    .and_then(|version| version.as_str())
                    == Some(agent.version);
            let installed_at = previous_entry
                .as_ref()
                .filter(|_| files_current)
                .and_then(|entry| entry.get("installed_at"))
                .and_then(|value| value.as_u64())
                .unwrap_or_else(now);
            let manifest = manifest_with(
                previous_manifest_text,
                agent.name,
                Some(serde_json::json!({
                    "version": agent.version,
                    "installed_at": installed_at,
                })),
            );

            if !files_current {
                ctx.root.create_dir_all(&agents_dir).map_err(Error::Io)?;
                ctx.root.set_mode(&agents_dir, 0o700).map_err(Error::Io)?;
                let written = (|| -> std::io::Result<()> {
                    if agent.bundled {
                        write(ctx.root, &library_path, library().as_bytes(), Kind::Private)?;
                    }
                    write(ctx.root, &script_path, script.as_bytes(), Kind::Executable)?;
                    write(ctx.root, &manifest_path, manifest.as_bytes(), Kind::Private)
                })();
                let committed = written
                    .map_err(Error::Io)
                    .and_then(|()| install_guarded(ctx, &before, &content));
                if let Err(error) = committed {
                    // The crontab line never became live; put the files back.
                    restore(ctx.root, &manifest_path, &previous_manifest, Kind::Private);
                    restore(ctx.root, &script_path, &previous_script, Kind::Executable);
                    if agent.bundled {
                        restore(ctx.root, &library_path, &previous_library, Kind::Private);
                    }
                    return Err(error);
                }
            } else {
                install_guarded(ctx, &before, &content)?;
            }
            Ok(InstallResult {
                name: agent.name.to_owned(),
                version: agent.version.to_owned(),
                schedule: schedule.map(|value| value.as_str().to_owned()),
                changed: !files_current || before != content,
                replaced_cron_lines: replaced as u32,
                script_sha256: sha256(script.as_bytes()),
                installed_at_unix_secs: installed_at,
            })
        },
    )
}

pub fn remove(
    ctx: &Context<'_>,
    request: &RemoveRequest,
    cancel: &CancellationToken,
) -> Result<RemoveResult, Error> {
    let scope = open_cron_state(ctx.engine_state, Some(CRON_USER)).map_err(Error::Io)?;
    transactional(
        &scope,
        request.request_id,
        request.idempotency_key.as_ref(),
        REMOVE_OPERATION,
        cancel,
        || {
            let agent = request.agent;
            let before = read_tab(ctx.crontab_program)?;
            let (content, removed_lines) = with_agent(&before, agent, None);
            let script_path = rel(&agent.relative_script_path());
            let manifest_path = rel(MANIFEST_FILE);
            let previous_script = read_optional(ctx.root, &script_path);
            let previous_manifest = read_optional(ctx.root, &manifest_path);
            let previous_manifest_text = previous_manifest
                .as_deref()
                .and_then(|bytes| std::str::from_utf8(bytes).ok());
            let had_entry = manifest_entry(previous_manifest_text, agent.name).is_some();
            let removed = removed_lines > 0 || previous_script.is_some() || had_entry;

            // The line goes first, so cron never runs a missing script.
            install_guarded(ctx, &before, &content)?;
            let undo_tab = |error: Error| {
                let _ = crate::cron::execute::install(
                    ctx.state_root,
                    ctx.crontab_program,
                    &before,
                    None,
                );
                error
            };
            if had_entry {
                let manifest = manifest_with(previous_manifest_text, agent.name, None);
                write(ctx.root, &manifest_path, manifest.as_bytes(), Kind::Private)
                    .map_err(|error| undo_tab(Error::Io(error)))?;
            }
            if previous_script.is_some() {
                if let Err(error) = ctx.root.remove_file(&script_path) {
                    restore(ctx.root, &manifest_path, &previous_manifest, Kind::Private);
                    return Err(undo_tab(Error::Io(error)));
                }
            }
            // The shared library goes with the last agent; the scripts carry
            // their own inlined copy, so nothing needs it once none is left.
            if had_entry
                && manifest_is_empty(&manifest_with(previous_manifest_text, agent.name, None))
            {
                let _ = ctx
                    .root
                    .remove_file(&rel(&format!("{AGENTS_DIR}/{LIBRARY_FILE}")));
            }
            // The last-run record of a removed agent would keep showing in
            // the list; it is a log, so a failure here changes nothing.
            let _ = ctx
                .root
                .remove_file(&rel(&format!("{AGENTS_DIR}/{}.heartbeat", agent.name)));
            Ok(RemoveResult {
                name: agent.name.to_owned(),
                removed,
                removed_cron_lines: removed_lines as u32,
                removed_at_unix_secs: now(),
            })
        },
    )
}

/// Whether a manifest lists no agent.
fn manifest_is_empty(text: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|value| value.as_object().map(serde_json::Map::is_empty))
        .unwrap_or(false)
}

pub fn bruteforce_unban(
    ctx: &Context<'_>,
    request: &UnbanRequest,
    cancel: &CancellationToken,
) -> Result<UnbanResult, Error> {
    let scope = open_unban_scope(ctx.engine_state).map_err(Error::Io)?;
    transactional(
        &scope,
        request.request_id,
        request.idempotency_key.as_ref(),
        UNBAN_OPERATION,
        cancel,
        || {
            let bans_path = rel(BANS_FILE);
            let events_path = rel(EVENTS_FILE);
            let previous = read_optional(ctx.root, &bans_path);
            let text = previous
                .as_deref()
                .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                .unwrap_or_default();
            let (remaining, removed) = without_ban(&text, request.ip);
            if removed > 0 {
                write(ctx.root, &bans_path, remaining.as_bytes(), Kind::Private)
                    .map_err(Error::Io)?;
            }
            let guard = find(GUARD_NAME).expect("the guard is in the catalog");
            let applied = if ctx.root.exists(&rel(&guard.relative_script_path())) {
                let output = process::run(
                    &ProcessRequest::new(ctx.shell_program)
                        .args([guard.absolute_script_path().as_str(), "--apply-only"]),
                    &ProcessLimits {
                        timeout: APPLY_TIMEOUT,
                        ..ProcessLimits::default()
                    },
                    &CancellationToken::default(),
                );
                let failure = match output {
                    Ok(output) => match output.termination {
                        ProcessTermination::Exited { success: true, .. } => None,
                        other => Some(process::error_code(&other)),
                    },
                    Err(error) => Some(Some(process::spawn_error_code(&error))),
                };
                if let Some(code) = failure {
                    // Keep the ban list consistent with what is live.
                    if removed > 0 {
                        restore(ctx.root, &bans_path, &previous, Kind::Private);
                    }
                    return Err(Error::ApplyFailed(code));
                }
                true
            } else {
                false
            };
            // A log line is history, not state: a failed append must not
            // turn a completed unban into an error.
            let _ = ctx
                .root
                .append(&events_path, unban_event(request.ip, now()).as_bytes());
            Ok(UnbanResult {
                ip: request.ip.to_string(),
                removed_bans: removed as u32,
                applied,
                unbanned_at_unix_secs: now(),
            })
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const A: &str = "123e4567-e89b-12d3-a456-426614174001";
    const B: &str = "123e4567-e89b-12d3-a456-426614174002";
    const C: &str = "123e4567-e89b-12d3-a456-426614174003";

    struct Host {
        dir: tempfile::TempDir,
        engine_state: ManagedRoot,
        state_root: TrustedRoot,
        root: ManagedRoot,
        crontab: String,
        shell: String,
    }

    fn script(dir: &std::path::Path, name: &str, body: &str) -> String {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    /// `crontab_body` replaces the fake crontab's behavior when given.
    fn host_with(initial: Option<&str>, crontab_body: Option<&str>) -> Host {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let root = dir.path().join("wcp");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        let tab = dir.path().join("tab");
        if let Some(initial) = initial {
            std::fs::write(&tab, initial).unwrap();
        }
        let default = format!(
            "TAB='{tab}'\nif [ \"$1\" = \"-l\" ]; then [ -f \"$TAB\" ] && cat \"$TAB\" || exit 1; else cp \"$1\" \"$TAB\"; fi",
            tab = tab.display()
        );
        let crontab = script(dir.path(), "crontab", crontab_body.unwrap_or(&default));
        let shell = script(
            dir.path(),
            "shell",
            &format!(
                "echo \"$@\" >> '{}'",
                dir.path().join("guard-calls").display()
            ),
        );
        let state_root = TrustedRoot::parse(&state).unwrap();
        Host {
            engine_state: ManagedRoot::open(&state_root).unwrap(),
            root: ManagedRoot::open(&TrustedRoot::parse(&root).unwrap()).unwrap(),
            state_root,
            crontab,
            shell,
            dir,
        }
    }

    fn host(initial: Option<&str>) -> Host {
        host_with(initial, None)
    }

    impl Host {
        fn ctx(&self) -> Context<'_> {
            Context {
                engine_state: &self.engine_state,
                state_root: &self.state_root,
                root: &self.root,
                crontab_program: &self.crontab,
                shell_program: &self.shell,
            }
        }
        fn tab(&self) -> String {
            std::fs::read_to_string(self.dir.path().join("tab")).unwrap_or_default()
        }
        fn file(&self, relative: &str) -> Option<String> {
            std::fs::read_to_string(self.dir.path().join("wcp").join(relative)).ok()
        }
        fn mode(&self, relative: &str) -> u32 {
            std::fs::metadata(self.dir.path().join("wcp").join(relative))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        }
        fn guard_calls(&self) -> Option<String> {
            std::fs::read_to_string(self.dir.path().join("guard-calls")).ok()
        }
    }

    fn install_request(json: &str, id: &str, key: Option<&str>) -> InstallRequest {
        InstallRequest::parse(json, id, key).unwrap()
    }

    fn cancel() -> CancellationToken {
        CancellationToken::default()
    }

    #[test]
    fn a_registry_agent_is_written_as_verified_without_the_library_and_removed_by_name() {
        let host = host(Some("MAILTO=x\n"));
        let script = "#!/usr/bin/env bash\necho from the registry\n".to_owned();
        let agent = crate::agent_lifecycle::Agent::from_registry(
            "disk-report".into(),
            "1.2.0".into(),
            Some("0 5 * * *".into()),
            true,
            script.clone(),
        );
        let request = InstallRequest {
            agent,
            schedule: None,
            request_id: RequestId::parse(A).unwrap(),
            idempotency_key: None,
        };
        let result = install(&host.ctx(), &request, &cancel()).unwrap();
        assert_eq!(result.version, "1.2.0");
        assert_eq!(result.script_sha256, sha256(script.as_bytes()));
        assert_eq!(host.file("agents/disk-report.sh").unwrap(), script);
        assert_eq!(host.mode("agents/disk-report.sh"), 0o755);
        assert!(host.file("agents/wcp_agent_lib.py").is_none());
        assert_eq!(
            host.tab(),
            "MAILTO=x\n0 5 * * * bash '/root/.wcp/agents/disk-report.sh' # [wcp-agent] disk-report\n"
        );
        let manifest: serde_json::Value =
            serde_json::from_str(&host.file("manifest.json").unwrap()).unwrap();
        assert_eq!(manifest["disk-report"]["version"], "1.2.0");

        // An unchanged reinstall does nothing.
        let again = InstallRequest {
            request_id: RequestId::parse(B).unwrap(),
            ..request
        };
        assert!(!install(&host.ctx(), &again, &cancel()).unwrap().changed);

        // Removal works for a name that is not in the built-in catalog.
        let removed = remove(
            &host.ctx(),
            &RemoveRequest::parse(r#"{"name":"disk-report"}"#, C, None).unwrap(),
            &cancel(),
        )
        .unwrap();
        assert!(removed.removed);
        assert_eq!(host.tab(), "MAILTO=x\n");
        assert!(host.file("agents/disk-report.sh").is_none());
    }

    #[test]
    fn install_writes_files_manifest_and_the_cron_line_last() {
        let host = host(Some("MAILTO=x\n"));
        let result = install(
            &host.ctx(),
            &install_request(r#"{"name":"cache-warmup"}"#, A, None),
            &cancel(),
        )
        .unwrap();
        assert!(result.changed);
        assert_eq!(result.schedule.as_deref(), Some("0 4 * * *"));
        assert_eq!(result.script_sha256.len(), 64);
        assert_eq!(
            host.file("agents/cache-warmup.sh").unwrap(),
            find("cache-warmup").unwrap().installed_script()
        );
        assert_eq!(host.mode("agents/cache-warmup.sh"), 0o755);
        assert_eq!(host.mode("agents"), 0o700);
        assert_eq!(host.mode("agents/wcp_agent_lib.py"), 0o600);
        assert_eq!(host.mode("manifest.json"), 0o600);
        let manifest: serde_json::Value =
            serde_json::from_str(&host.file("manifest.json").unwrap()).unwrap();
        assert_eq!(manifest["cache-warmup"]["version"], "1.0.0");
        assert_eq!(
            host.tab(),
            "MAILTO=x\n0 4 * * * bash '/root/.wcp/agents/cache-warmup.sh' # [wcp-agent] cache-warmup\n"
        );
        let leftovers: Vec<_> = std::fs::read_dir(host.dir.path().join("wcp/agents"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(leftovers.len(), 2, "temp files left behind: {leftovers:?}");
    }

    #[test]
    fn reinstall_is_idempotent_and_keeps_a_custom_schedule() {
        let host = host(None);
        let first = install(
            &host.ctx(),
            &install_request(r#"{"name":"cache-warmup","schedule":"0 6 * * 1"}"#, A, None),
            &cancel(),
        )
        .unwrap();
        let tab = host.tab();
        let second = install(
            &host.ctx(),
            &install_request(r#"{"name":"cache-warmup"}"#, B, None),
            &cancel(),
        )
        .unwrap();
        assert!(first.changed && !second.changed);
        assert_eq!(second.schedule.as_deref(), Some("0 6 * * 1"));
        assert_eq!(second.installed_at_unix_secs, first.installed_at_unix_secs);
        assert_eq!(host.tab(), tab);
        assert_eq!(second.replaced_cron_lines, 1);
    }

    #[test]
    fn an_unscheduled_agent_gets_files_but_no_cron_line() {
        let host = host(Some("1 1 * * * true # [wcp-agent] backup-agent\n"));
        let result = install(
            &host.ctx(),
            &install_request(r#"{"name":"backup-agent"}"#, A, None),
            &cancel(),
        )
        .unwrap();
        assert_eq!(result.schedule, None);
        assert_eq!(host.tab(), "");
        assert!(host.file("agents/backup-agent.sh").is_some());
    }

    #[test]
    fn a_fixed_cadence_agent_ignores_a_stale_custom_line() {
        let host = host(Some("*/9 * * * * bash 'x' # [wcp-agent] metrics-agent\n"));
        let result = install(
            &host.ctx(),
            &install_request(r#"{"name":"metrics-agent"}"#, A, None),
            &cancel(),
        )
        .unwrap();
        assert_eq!(result.schedule.as_deref(), Some("* * * * *"));
        assert!(!host.tab().contains("*/9"));
    }

    #[test]
    fn a_rejected_crontab_restores_the_previous_files() {
        let host = host_with(
            Some("0 4 * * * old\n"),
            Some("if [ \"$1\" = \"-l\" ]; then echo '0 4 * * * old'; else exit 1; fi"),
        );
        // A previous install of an older script, library and manifest.
        std::fs::create_dir_all(host.dir.path().join("wcp/agents")).unwrap();
        std::fs::write(
            host.dir.path().join("wcp/agents/cache-warmup.sh"),
            "old script",
        )
        .unwrap();
        std::fs::write(
            host.dir.path().join("wcp/agents/wcp_agent_lib.py"),
            "old lib",
        )
        .unwrap();
        std::fs::write(host.dir.path().join("wcp/manifest.json"), "{\"x\":1}").unwrap();
        let error = install(
            &host.ctx(),
            &install_request(r#"{"name":"cache-warmup"}"#, A, None),
            &cancel(),
        )
        .unwrap_err();
        assert_eq!(error.protocol().0, ErrorCode::ConfigValidationFailed);
        assert_eq!(host.file("agents/cache-warmup.sh").unwrap(), "old script");
        assert_eq!(host.file("agents/wcp_agent_lib.py").unwrap(), "old lib");
        assert_eq!(host.file("manifest.json").unwrap(), "{\"x\":1}");
    }

    #[test]
    fn a_first_install_that_fails_leaves_no_files() {
        let host = host_with(
            None,
            Some("if [ \"$1\" = \"-l\" ]; then exit 1; else exit 1; fi"),
        );
        assert!(
            install(
                &host.ctx(),
                &install_request(r#"{"name":"cache-warmup"}"#, A, None),
                &cancel(),
            )
            .is_err()
        );
        assert!(host.file("agents/cache-warmup.sh").is_none());
        assert!(host.file("agents/wcp_agent_lib.py").is_none());
        assert!(host.file("manifest.json").is_none());
    }

    #[test]
    fn retry_with_the_same_key_replays_without_a_second_write() {
        let host = host(None);
        let request = |id| install_request(r#"{"name":"cache-warmup"}"#, id, Some("k1"));
        let first = install(&host.ctx(), &request(A), &cancel()).unwrap();
        std::fs::remove_file(host.dir.path().join("wcp/agents/cache-warmup.sh")).unwrap();
        let second = install(&host.ctx(), &request(B), &cancel()).unwrap();
        assert_eq!(first.installed_at_unix_secs, second.installed_at_unix_secs);
        assert!(
            host.file("agents/cache-warmup.sh").is_none(),
            "a replay must not write"
        );
    }

    #[test]
    fn remove_takes_line_manifest_entry_and_script_and_keeps_the_rest() {
        let host = host(Some("MAILTO=x\n"));
        install(
            &host.ctx(),
            &install_request(r#"{"name":"cache-warmup"}"#, A, None),
            &cancel(),
        )
        .unwrap();
        install(
            &host.ctx(),
            &install_request(r#"{"name":"error-log-digest"}"#, B, None),
            &cancel(),
        )
        .unwrap();
        let result = remove(
            &host.ctx(),
            &RemoveRequest::parse(r#"{"name":"cache-warmup"}"#, C, None).unwrap(),
            &cancel(),
        )
        .unwrap();
        assert!(result.removed);
        assert_eq!(result.removed_cron_lines, 1);
        assert!(host.file("agents/cache-warmup.sh").is_none());
        assert!(host.file("agents/cache-warmup.heartbeat").is_none());
        assert!(host.file("agents/error-log-digest.sh").is_some());
        let manifest: serde_json::Value =
            serde_json::from_str(&host.file("manifest.json").unwrap()).unwrap();
        assert!(manifest.get("cache-warmup").is_none());
        assert!(manifest.get("error-log-digest").is_some());
        assert!(host.tab().contains("MAILTO=x"));
        assert!(host.tab().contains("error-log-digest"));
        assert!(!host.tab().contains("cache-warmup"));
        // Another agent is still installed, so the shared library stays.
        assert!(host.file("agents/wcp_agent_lib.py").is_some());
        remove(
            &host.ctx(),
            &RemoveRequest::parse(
                r#"{"name":"error-log-digest"}"#,
                "123e4567-e89b-12d3-a456-426614174004",
                None,
            )
            .unwrap(),
            &cancel(),
        )
        .unwrap();
        // The last one takes the library with it.
        assert!(host.file("agents/wcp_agent_lib.py").is_none());
        assert!(host.file("agents/error-log-digest.sh").is_none());
        assert_eq!(host.file("manifest.json").unwrap().trim(), "{}");
    }

    #[test]
    fn removing_an_agent_that_is_not_installed_is_a_no_op() {
        let host = host(Some("MAILTO=x\n"));
        let result = remove(
            &host.ctx(),
            &RemoveRequest::parse(r#"{"name":"cache-warmup"}"#, A, None).unwrap(),
            &cancel(),
        )
        .unwrap();
        assert!(!result.removed);
        assert_eq!(host.tab(), "MAILTO=x\n");
        assert!(host.file("manifest.json").is_none());
    }

    #[test]
    fn a_rejected_crontab_on_remove_changes_nothing() {
        let tab = "0 4 * * * bash 'x' # [wcp-agent] cache-warmup\n";
        let host = host_with(
            Some(tab),
            Some(
                "if [ \"$1\" = \"-l\" ]; then echo '0 4 * * * bash '\"'x'\"' # [wcp-agent] cache-warmup'; else exit 1; fi",
            ),
        );
        std::fs::create_dir_all(host.dir.path().join("wcp/agents")).unwrap();
        std::fs::write(host.dir.path().join("wcp/agents/cache-warmup.sh"), "s").unwrap();
        std::fs::write(
            host.dir.path().join("wcp/manifest.json"),
            "{\"cache-warmup\":{\"version\":\"1.0.0\"}}",
        )
        .unwrap();
        let error = remove(
            &host.ctx(),
            &RemoveRequest::parse(r#"{"name":"cache-warmup"}"#, B, None).unwrap(),
            &cancel(),
        )
        .unwrap_err();
        assert_eq!(error.protocol().0, ErrorCode::ConfigValidationFailed);
        assert_eq!(host.file("agents/cache-warmup.sh").unwrap(), "s");
        assert!(host.file("manifest.json").unwrap().contains("cache-warmup"));
    }

    fn unban(host: &Host, ip: &str, id: &str) -> Result<UnbanResult, Error> {
        bruteforce_unban(
            &host.ctx(),
            &UnbanRequest::parse(&format!(r#"{{"ip":"{ip}"}}"#), id, None).unwrap(),
            &cancel(),
        )
    }

    #[test]
    fn unban_drops_the_address_logs_the_event_and_reapplies_the_guard() {
        let host = host(None);
        std::fs::write(
            host.dir.path().join("wcp/bruteforce-active-bans.txt"),
            "203.0.113.7 caddy 1 2\n203.0.113.70 caddy 1 2\n",
        )
        .unwrap();
        let guard = find(GUARD_NAME).unwrap();
        std::fs::create_dir_all(host.dir.path().join("wcp/agents")).unwrap();
        std::fs::write(host.dir.path().join("wcp/agents/bruteforce-guard.sh"), "x").unwrap();
        let result = unban(&host, "203.0.113.7", A).unwrap();
        assert_eq!((result.removed_bans, result.applied), (1, true));
        assert_eq!(
            host.file("bruteforce-active-bans.txt").unwrap(),
            "203.0.113.70 caddy 1 2\n"
        );
        let events = host.file("bruteforce-events.jsonl").unwrap();
        assert!(events.contains(r#""action":"unban""#) && events.contains("203.0.113.7"));
        assert_eq!(
            host.guard_calls().unwrap().trim(),
            format!("{} --apply-only", guard.absolute_script_path())
        );
    }

    #[test]
    fn unban_without_an_installed_guard_edits_the_list_but_applies_nothing() {
        let host = host(None);
        std::fs::write(
            host.dir.path().join("wcp/bruteforce-active-bans.txt"),
            "::1 caddy 1 2\n",
        )
        .unwrap();
        let result = unban(&host, "::1", A).unwrap();
        assert_eq!((result.removed_bans, result.applied), (1, false));
        assert_eq!(host.file("bruteforce-active-bans.txt").unwrap(), "");
        assert!(host.guard_calls().is_none());
    }

    #[test]
    fn a_failing_guard_restores_the_ban_list() {
        let mut host = host(None);
        host.shell = script(host.dir.path(), "failing-shell", "exit 3");
        std::fs::write(
            host.dir.path().join("wcp/bruteforce-active-bans.txt"),
            "203.0.113.7 caddy 1 2\n",
        )
        .unwrap();
        std::fs::create_dir_all(host.dir.path().join("wcp/agents")).unwrap();
        std::fs::write(host.dir.path().join("wcp/agents/bruteforce-guard.sh"), "x").unwrap();
        let error = unban(&host, "203.0.113.7", A).unwrap_err();
        assert_eq!(error.protocol().0, ErrorCode::SubprocessFailed);
        assert_eq!(
            host.file("bruteforce-active-bans.txt").unwrap(),
            "203.0.113.7 caddy 1 2\n"
        );
        assert!(host.file("bruteforce-events.jsonl").is_none());
    }

    #[test]
    fn unban_of_an_unknown_address_with_no_ban_file_is_still_a_success() {
        let host = host(None);
        let result = unban(&host, "198.51.100.1", A).unwrap();
        assert_eq!(result.removed_bans, 0);
        assert!(host.file("bruteforce-active-bans.txt").is_none());
    }

    #[test]
    fn every_catalog_schedule_parses() {
        for agent in &super::super::AGENTS {
            if let Some(text) = agent.default_schedule {
                assert!(Schedule::parse(text).is_ok(), "{}", agent.name);
            }
        }
    }
}
