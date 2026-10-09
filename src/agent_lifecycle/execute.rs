//! The transactional pipelines for installing and removing a bundled agent and
//! for the manual brute-force unban. See the parent module for the design.
//!
//! Install and remove hold the `cron/root` lock scope that `cron.installTab`
//! and the scheduled-backup operations use, so no other crontab writer can
//! interleave with their read-modify-write; a final re-read of the tab before
//! the install also catches writers that do not take the lock. The unban has
//! a scope of its own.

use super::{
    AGENTS_DIR, Agent, BANS_FILE, EVENTS_FILE, GUARD_NAME, INSTALL_OPERATION, InstallRequest,
    InstallResult, LIBRARY_FILE, MANIFEST_FILE, REMOVE_OPERATION, ROOT, RemoveRequest,
    RemoveResult, UNBAN_OPERATION, UnbanRequest, UnbanResult, current_schedule, find, library,
    manifest_entry, manifest_with, tab_too_large, unban_event, with_agent, without_ban,
};
use crate::{
    agent_systemd,
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
const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(60);

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub state_root: &'a TrustedRoot,
    /// The agent root (`/root/.wcp`).
    pub root: &'a ManagedRoot,
    pub crontab_program: &'a str,
    /// What runs the guard script; `bash` outside tests.
    pub shell_program: &'a str,
    /// Where sandboxed agents get their units. None when systemd is not the
    /// init of this host; such agents then run from cron like any other.
    pub systemd: Option<Systemd<'a>>,
}

#[derive(Clone, Copy)]
pub struct Systemd<'a> {
    /// `/etc/systemd/system`.
    pub units: &'a ManagedRoot,
    pub systemctl_program: &'a str,
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
    Systemd(Option<ErrorCode>),
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
            Self::Systemd(code) => (
                code.unwrap_or(ErrorCode::SubprocessFailed),
                "systemctl could not set up the agent's timer; nothing was changed".into(),
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

/// What a sandboxed install will leave on the host.
struct UnitsPlan {
    service: String,
    timer: String,
    writable: &'static [&'static str],
}

fn unit_path(name: String) -> SiteRelativePath {
    rel(&name)
}

fn systemctl(sd: &Systemd<'_>, args: &[&str]) -> Result<(), Error> {
    let output = process::run(
        &ProcessRequest::new(sd.systemctl_program).args(args),
        &ProcessLimits {
            timeout: SYSTEMCTL_TIMEOUT,
            ..ProcessLimits::default()
        },
        &CancellationToken::default(),
    );
    match output {
        Ok(output) => match process::error_code(&output.termination) {
            None => Ok(()),
            code => Err(Error::Systemd(code)),
        },
        Err(error) => Err(Error::Systemd(Some(process::spawn_error_code(&error)))),
    }
}

fn read_unit(sd: &Systemd<'_>, name: String) -> Option<Vec<u8>> {
    sd.units.read_bytes(&unit_path(name)).ok()
}

fn write_unit(sd: &Systemd<'_>, name: String, bytes: &[u8]) -> std::io::Result<()> {
    let path = unit_path(name);
    sd.units.write_atomic(&path, bytes)?;
    // systemd warns about world-inaccessible units, and the umask is not ours.
    sd.units.set_mode(&path, 0o644)
}

/// Puts the units back as they were (`None` = absent) and tells systemd.
/// Best effort: this runs on a failure path that is already reporting.
fn restore_units(sd: &Systemd<'_>, agent: &Agent, previous: &(Option<Vec<u8>>, Option<Vec<u8>>)) {
    let timer = agent_systemd::timer_name(agent);
    let service = agent_systemd::service_name(agent);
    if previous.1.is_none() {
        let _ = systemctl(sd, &["disable", "--now", &timer]);
    }
    for (name, bytes) in [(service, &previous.0), (timer.clone(), &previous.1)] {
        let _ = match bytes {
            Some(bytes) => write_unit(sd, name, bytes),
            None => sd.units.remove_file(&unit_path(name)).or_else(|error| {
                (error.kind() == std::io::ErrorKind::NotFound)
                    .then_some(())
                    .ok_or(error)
            }),
        };
    }
    let _ = systemctl(sd, &["daemon-reload"]);
    if previous.1.is_some() {
        let _ = systemctl(sd, &["restart", &timer]);
    }
}

/// Takes the agent's timer and units out. Returns whether there were any.
fn remove_units(sd: &Systemd<'_>, agent: &Agent) -> Result<bool, Error> {
    let timer = agent_systemd::timer_name(agent);
    let service = agent_systemd::service_name(agent);
    let previous = (read_unit(sd, service.clone()), read_unit(sd, timer.clone()));
    if previous.0.is_none() && previous.1.is_none() {
        return Ok(false);
    }
    if previous.1.is_some() {
        systemctl(sd, &["disable", "--now", &timer])?;
    }
    // A run that is already going finishes under its own terms; stopping the
    // service is only about not leaving a stale unit behind.
    let _ = systemctl(sd, &["stop", &service]);
    for name in [service, timer] {
        if let Err(error) = sd.units.remove_file(&unit_path(name)) {
            if error.kind() != std::io::ErrorKind::NotFound {
                restore_units(sd, agent, &previous);
                return Err(Error::Io(error));
            }
        }
    }
    systemctl(sd, &["daemon-reload"])?;
    Ok(true)
}

/// The crontab (and, for a sandboxed agent, the timer) goes live last.
///
/// Sandboxed: units first, then the cron line is dropped, so a failure at the
/// crontab leaves the cron line running and the units are removed again.
/// Otherwise: the cron line, and any units a previous sandboxed install left
/// are taken out so the agent does not run twice.
fn activate(
    ctx: &Context<'_>,
    agent: &Agent,
    plan: Option<&UnitsPlan>,
    before: &str,
    content: &str,
) -> Result<(), Error> {
    let (Some(plan), Some(sd)) = (plan, ctx.systemd.as_ref()) else {
        install_guarded(ctx, before, content)?;
        if let Some(sd) = ctx.systemd.as_ref() {
            if let Err(error) = remove_units(sd, agent) {
                // The new cron line must not stay live next to a timer while
                // the caller puts the old files back.
                let _ = crate::cron::execute::install(
                    ctx.state_root,
                    ctx.crontab_program,
                    before,
                    None,
                );
                return Err(error);
            }
        }
        return Ok(());
    };
    let previous = (
        read_unit(sd, agent_systemd::service_name(agent)),
        read_unit(sd, agent_systemd::timer_name(agent)),
    );
    let changed = previous.0.as_deref() != Some(plan.service.as_bytes())
        || previous.1.as_deref() != Some(plan.timer.as_bytes());
    let timer = agent_systemd::timer_name(agent);
    let go_live = || -> Result<(), Error> {
        for path in plan.writable {
            if !agent_systemd::has_no_symlink(path) {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "a writable path goes through a symlink",
                )));
            }
            // Only the agent root is ours to create; other paths must exist
            // (a missing one is skipped by the leading `-` in the unit).
            if let Some(inside) = path.strip_prefix(&format!("{ROOT}/")) {
                let inside = rel(inside);
                ctx.root.create_dir_all(&inside).map_err(Error::Io)?;
                ctx.root.set_mode(&inside, 0o700).map_err(Error::Io)?;
            }
        }
        if changed {
            write_unit(
                sd,
                agent_systemd::service_name(agent),
                plan.service.as_bytes(),
            )
            .and_then(|()| write_unit(sd, timer.clone(), plan.timer.as_bytes()))
            .map_err(Error::Io)?;
            systemctl(sd, &["daemon-reload"])?;
        }
        systemctl(sd, &["enable", &timer])?;
        systemctl(sd, &[if changed { "restart" } else { "start" }, &timer])
    };
    if let Err(error) = go_live() {
        if changed {
            restore_units(sd, agent, &previous);
        }
        return Err(error);
    }
    if let Err(error) = install_guarded(ctx, before, content) {
        if changed {
            restore_units(sd, agent, &previous);
        } else if previous.1.is_none() {
            let _ = systemctl(sd, &["disable", "--now", &timer]);
        }
        return Err(error);
    }
    Ok(())
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
                    .or_else(|| {
                        let sd = ctx.systemd.as_ref()?;
                        let timer = read_unit(sd, agent_systemd::timer_name(agent))?;
                        agent_systemd::schedule_from_timer(&String::from_utf8_lossy(&timer))
                    })
            } else {
                None
            }
            .or_else(|| {
                agent
                    .default_schedule
                    .map(|text| Schedule::parse(text).expect("catalog schedules are valid"))
            });
            // A sandboxed agent gets a timer when this host has systemd and
            // cron's schedule has an exact OnCalendar equivalent; otherwise it
            // stays on cron.
            let units = match (agent.systemd_writable, ctx.systemd.as_ref(), &schedule) {
                (Some(writable), Some(_), Some(schedule)) => agent_systemd::on_calendar(schedule)
                    .map(|calendar| UnitsPlan {
                        service: agent_systemd::service_unit(agent, writable),
                        timer: agent_systemd::timer_unit(agent, schedule, &calendar),
                        writable,
                    }),
                _ => None,
            };
            let unit_drift = match (&units, ctx.systemd.as_ref()) {
                (Some(plan), Some(sd)) => {
                    read_unit(sd, agent_systemd::service_name(agent)).as_deref()
                        != Some(plan.service.as_bytes())
                        || read_unit(sd, agent_systemd::timer_name(agent)).as_deref()
                            != Some(plan.timer.as_bytes())
                }
                _ => false,
            };
            let (content, replaced) = with_agent(
                &before,
                agent,
                schedule.as_ref().filter(|_| units.is_none()),
            );

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
                && previous_library.as_deref() == Some(library().as_bytes())
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
                    write(ctx.root, &library_path, library().as_bytes(), Kind::Private)?;
                    write(ctx.root, &script_path, script.as_bytes(), Kind::Executable)?;
                    write(ctx.root, &manifest_path, manifest.as_bytes(), Kind::Private)
                })();
                let committed = written
                    .map_err(Error::Io)
                    .and_then(|()| activate(ctx, agent, units.as_ref(), &before, &content));
                if let Err(error) = committed {
                    // The crontab line never became live; put the files back.
                    restore(ctx.root, &manifest_path, &previous_manifest, Kind::Private);
                    restore(ctx.root, &script_path, &previous_script, Kind::Executable);
                    restore(ctx.root, &library_path, &previous_library, Kind::Private);
                    return Err(error);
                }
            } else {
                activate(ctx, agent, units.as_ref(), &before, &content)?;
            }
            let on_systemd = units.is_some();
            Ok(InstallResult {
                name: agent.name.to_owned(),
                version: agent.version.to_owned(),
                schedule: schedule.map(|value| value.as_str().to_owned()),
                changed: !files_current || before != content || unit_drift,
                replaced_cron_lines: replaced as u32,
                scheduler: if on_systemd { "systemd" } else { "cron" }.to_owned(),
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
            let units_present = ctx.systemd.as_ref().is_some_and(|sd| {
                read_unit(sd, agent_systemd::service_name(agent)).is_some()
                    || read_unit(sd, agent_systemd::timer_name(agent)).is_some()
            });
            let removed =
                removed_lines > 0 || previous_script.is_some() || had_entry || units_present;

            // The schedule goes first, so nothing runs a missing script. A
            // timer is stopped before the crontab is touched; if that fails,
            // it comes back.
            let previous_units = ctx.systemd.as_ref().map(|sd| {
                (
                    read_unit(sd, agent_systemd::service_name(agent)),
                    read_unit(sd, agent_systemd::timer_name(agent)),
                )
            });
            if let Some(sd) = ctx.systemd.as_ref() {
                remove_units(sd, agent)?;
            }
            if let Err(error) = install_guarded(ctx, &before, &content) {
                if let (Some(sd), Some(previous)) = (ctx.systemd.as_ref(), previous_units.as_ref())
                {
                    if units_present {
                        restore_units(sd, agent, previous);
                        let _ = systemctl(sd, &["enable", &agent_systemd::timer_name(agent)]);
                    }
                }
                return Err(error);
            }
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
            // The shared library goes with the last agent: the scripts import
            // it from that file, so nothing needs it once none is left.
            if had_entry
                && manifest_is_empty(&manifest_with(previous_manifest_text, agent.name, None))
            {
                let _ = ctx
                    .root
                    .remove_file(&rel(&format!("{AGENTS_DIR}/{LIBRARY_FILE}")));
            }
            // The last-run record of a removed agent would keep showing in
            // the list; it is a log, so a failure here changes nothing.
            for suffix in ["heartbeat", "lock"] {
                let _ = ctx
                    .root
                    .remove_file(&rel(&format!("{AGENTS_DIR}/{}.{suffix}", agent.name)));
            }
            Ok(RemoveResult {
                name: agent.name.to_owned(),
                removed,
                removed_cron_lines: removed_lines as u32,
                removed_systemd_units: units_present,
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
        units: ManagedRoot,
        systemctl: String,
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
        std::fs::create_dir_all(dir.path().join("units")).unwrap();
        // Logs every call; `systemctl-fail` names a subcommand that fails.
        let systemctl = script(
            dir.path(),
            "systemctl",
            &format!(
                "D='{d}'\necho \"$@\" >> \"$D/systemctl-calls\"\n[ \"$1\" = \"$(cat \"$D/systemctl-fail\" 2>/dev/null)\" ] && exit 1\nexit 0",
                d = dir.path().display()
            ),
        );
        Host {
            units: ManagedRoot::open(&TrustedRoot::parse(dir.path().join("units")).unwrap())
                .unwrap(),
            systemctl,
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
                systemd: None,
            }
        }
        fn sd_ctx(&self) -> Context<'_> {
            Context {
                systemd: Some(Systemd {
                    units: &self.units,
                    systemctl_program: &self.systemctl,
                }),
                ..self.ctx()
            }
        }
        fn unit(&self, name: &str) -> Option<String> {
            std::fs::read_to_string(self.dir.path().join("units").join(name)).ok()
        }
        fn systemctl_calls(&self) -> Vec<String> {
            std::fs::read_to_string(self.dir.path().join("systemctl-calls"))
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect()
        }
        fn fail_systemctl(&self, subcommand: &str) {
            std::fs::write(self.dir.path().join("systemctl-fail"), subcommand).unwrap();
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
    fn a_registry_agent_is_written_as_verified_with_the_library_and_removed_by_name() {
        let host = host(Some("MAILTO=x\n"));
        let script = "#!/usr/bin/env bash\necho from the registry\n".to_owned();
        let agent = crate::agent_lifecycle::Agent::from_registry(
            "disk-report".into(),
            "1.2.0".into(),
            Some("0 5 * * *".into()),
            true,
            script.clone(),
            None,
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
        assert_eq!(host.file("agents/wcp_agent_lib.py").unwrap(), library());
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
        host.ctx()
            .root
            .write_atomic(&rel("agents/cache-warmup.lock"), b"")
            .unwrap();
        let result = remove(
            &host.ctx(),
            &RemoveRequest::parse(r#"{"name":"cache-warmup"}"#, C, None).unwrap(),
            &cancel(),
        )
        .unwrap();
        assert!(result.removed);
        assert_eq!(result.removed_cron_lines, 1);
        assert!(host.file("agents/cache-warmup.lock").is_none());
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

    fn sandboxed(schedule: &str, writable: &[&str]) -> &'static crate::agent_lifecycle::Agent {
        crate::agent_lifecycle::Agent::from_registry(
            "disk-report".into(),
            "1.0.0".into(),
            Some(schedule.into()),
            true,
            "#!/usr/bin/env bash\necho hi\n".into(),
            Some(writable.iter().map(|p| (*p).to_owned()).collect()),
        )
    }

    fn install_agent(
        host: &Host,
        agent: &'static crate::agent_lifecycle::Agent,
        schedule: Option<&str>,
        id: &str,
        with_systemd: bool,
    ) -> Result<InstallResult, Error> {
        let request = InstallRequest {
            agent,
            schedule: schedule.map(|s| Schedule::parse(s).unwrap()),
            request_id: RequestId::parse(id).unwrap(),
            idempotency_key: None,
        };
        let ctx = if with_systemd {
            host.sd_ctx()
        } else {
            host.ctx()
        };
        install(&ctx, &request, &cancel())
    }

    const WRITABLE: [&str; 2] = ["/root/.wcp/agents", "/root/.wcp/logs"];

    #[test]
    fn a_sandboxed_agent_gets_a_timer_and_no_cron_line() {
        let host = host(Some("MAILTO=x\n"));
        let agent = sandboxed("0 5 * * *", &WRITABLE);
        let result = install_agent(&host, agent, None, A, true).unwrap();
        assert_eq!(result.scheduler, "systemd");
        assert_eq!(result.schedule.as_deref(), Some("0 5 * * *"));
        assert_eq!(host.tab(), "MAILTO=x\n");
        let service = host.unit("wcp-agent-disk-report.service").unwrap();
        assert!(service.contains("ProtectSystem=strict\n"));
        assert!(service.contains("ReadWritePaths=-/root/.wcp/agents -/root/.wcp/logs\n"));
        let timer = host.unit("wcp-agent-disk-report.timer").unwrap();
        assert!(timer.contains("OnCalendar=*-*-* 05:00:00\n"));
        assert_eq!(
            host.systemctl_calls(),
            [
                "daemon-reload",
                "enable wcp-agent-disk-report.timer",
                "restart wcp-agent-disk-report.timer"
            ]
        );
        assert!(host.dir.path().join("wcp/logs").is_dir());
        assert_eq!(host.mode("logs"), 0o700);
        let mode = std::fs::metadata(host.dir.path().join("units/wcp-agent-disk-report.timer"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o644);
    }

    #[test]
    fn an_existing_cron_install_migrates_to_a_timer_and_keeps_its_schedule() {
        let host = host(Some(
            "MAILTO=x\n0 7 * * 1 bash '/root/.wcp/agents/disk-report.sh' # [wcp-agent] disk-report\n5 5 * * * echo hi\n",
        ));
        let agent = sandboxed("0 5 * * *", &WRITABLE);
        let result = install_agent(&host, agent, None, A, true).unwrap();
        assert_eq!(result.scheduler, "systemd");
        assert_eq!(result.replaced_cron_lines, 1);
        assert_eq!(host.tab(), "MAILTO=x\n5 5 * * * echo hi\n");
        assert!(
            host.unit("wcp-agent-disk-report.timer")
                .unwrap()
                .contains("OnCalendar=Mon *-*-* 07:00:00\n")
        );
        // An update keeps the schedule that now lives in the timer.
        let again = install_agent(&host, sandboxed("0 5 * * *", &WRITABLE), None, B, true).unwrap();
        assert_eq!(again.schedule.as_deref(), Some("0 7 * * 1"));
        assert!(!again.changed);
    }

    #[test]
    fn an_unchanged_sandboxed_reinstall_only_starts_the_timer() {
        let host = host(None);
        let agent = sandboxed("0 5 * * *", &WRITABLE);
        install_agent(&host, agent, None, A, true).unwrap();
        let before = host.systemctl_calls().len();
        let again = install_agent(&host, agent, None, B, true).unwrap();
        assert!(!again.changed);
        assert_eq!(
            host.systemctl_calls()[before..],
            [
                "enable wcp-agent-disk-report.timer",
                "start wcp-agent-disk-report.timer"
            ]
        );
    }

    #[test]
    fn a_failing_systemctl_leaves_the_cron_line_and_no_units() {
        let cron = "0 7 * * 1 bash '/root/.wcp/agents/disk-report.sh' # [wcp-agent] disk-report\n";
        let host = host(Some(cron));
        host.fail_systemctl("enable");
        let error =
            install_agent(&host, sandboxed("0 5 * * *", &WRITABLE), None, A, true).unwrap_err();
        assert_eq!(error.protocol().0, ErrorCode::SubprocessFailed);
        assert_eq!(host.tab(), cron);
        assert!(host.unit("wcp-agent-disk-report.timer").is_none());
        assert!(host.unit("wcp-agent-disk-report.service").is_none());
        assert!(host.file("agents/disk-report.sh").is_none());
        assert!(host.file("manifest.json").is_none());
        assert!(
            host.systemctl_calls()
                .iter()
                .any(|c| c.starts_with("disable --now"))
        );
    }

    #[test]
    fn a_failing_crontab_write_takes_the_new_units_out_again() {
        let host = host_with(
            Some("0 7 * * 1 bash '/root/.wcp/agents/disk-report.sh' # [wcp-agent] disk-report\n"),
            Some("if [ \"$1\" = \"-l\" ]; then cat \"$0.tab\"; else exit 1; fi"),
        );
        std::fs::write(
            format!("{}.tab", host.crontab),
            "0 7 * * 1 bash '/root/.wcp/agents/disk-report.sh' # [wcp-agent] disk-report\n",
        )
        .unwrap();
        let error =
            install_agent(&host, sandboxed("0 5 * * *", &WRITABLE), None, A, true).unwrap_err();
        assert!(matches!(error, Error::Install(_)));
        assert!(host.unit("wcp-agent-disk-report.timer").is_none());
        assert!(host.file("agents/disk-report.sh").is_none());
    }

    #[test]
    fn a_schedule_without_an_exact_calendar_stays_on_cron() {
        let host = host(None);
        let agent = sandboxed("0 5 * * *", &WRITABLE);
        // Day of month and weekday together: cron ORs them, systemd would AND.
        let result = install_agent(&host, agent, Some("0 5 1 * 1"), A, true).unwrap();
        assert_eq!(result.scheduler, "cron");
        assert!(host.tab().contains("0 5 1 * 1 bash"));
        assert!(host.unit("wcp-agent-disk-report.timer").is_none());
    }

    #[test]
    fn without_systemd_a_sandboxed_agent_runs_from_cron() {
        let host = host(None);
        let result =
            install_agent(&host, sandboxed("0 5 * * *", &WRITABLE), None, A, false).unwrap();
        assert_eq!(result.scheduler, "cron");
        assert!(host.tab().contains("disk-report"));
        assert!(host.systemctl_calls().is_empty());
    }

    #[test]
    fn going_back_to_cron_removes_the_timer_so_the_agent_never_runs_twice() {
        let host = host(None);
        install_agent(&host, sandboxed("0 5 * * *", &WRITABLE), None, A, true).unwrap();
        let result = install_agent(
            &host,
            sandboxed("0 5 * * *", &WRITABLE),
            Some("0 5 1 * 1"),
            B,
            true,
        )
        .unwrap();
        assert_eq!(result.scheduler, "cron");
        assert!(host.unit("wcp-agent-disk-report.timer").is_none());
        assert!(host.tab().contains("0 5 1 * 1 bash"));
    }

    #[test]
    fn removing_a_sandboxed_agent_stops_the_timer_and_deletes_the_units() {
        let host = host(Some("MAILTO=x\n"));
        install_agent(&host, sandboxed("0 5 * * *", &WRITABLE), None, A, true).unwrap();
        let request = RemoveRequest::parse(r#"{"name":"disk-report"}"#, B, None).unwrap();
        let result = remove(&host.sd_ctx(), &request, &cancel()).unwrap();
        assert!(result.removed && result.removed_systemd_units);
        assert!(host.unit("wcp-agent-disk-report.timer").is_none());
        assert!(host.unit("wcp-agent-disk-report.service").is_none());
        assert!(host.file("agents/disk-report.sh").is_none());
        let calls = host.systemctl_calls();
        assert!(calls.contains(&"disable --now wcp-agent-disk-report.timer".to_owned()));
        assert_eq!(calls.last().unwrap(), "daemon-reload");
    }

    /// Real systemd, real `/etc/systemd/system`, real `/root/.wcp`: run as
    /// root in a VM with `cargo test real_systemd -- --ignored`.
    #[test]
    #[ignore = "needs root and a systemd host; run in the Lima VM"]
    fn real_systemd_runs_the_agent_inside_the_sandbox() {
        use std::process::Command;
        let sh = |cmd: &str| {
            let out = Command::new("sh").arg("-c").arg(cmd).output().unwrap();
            (
                out.status.success(),
                String::from_utf8_lossy(&out.stdout).trim().to_owned(),
            )
        };
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        let state_root = TrustedRoot::parse(&state).unwrap();
        std::fs::create_dir_all(ROOT).unwrap();
        let root = ManagedRoot::open(&TrustedRoot::parse(ROOT).unwrap()).unwrap();
        let units = ManagedRoot::open(&TrustedRoot::parse(super::agent_systemd::UNIT_DIR).unwrap())
            .unwrap();
        let ctx = Context {
            engine_state: &ManagedRoot::open(&state_root).unwrap(),
            state_root: &state_root,
            root: &root,
            crontab_program: "crontab",
            shell_program: "bash",
            systemd: Some(Systemd {
                units: &units,
                systemctl_program: "systemctl",
            }),
        };
        let script = "#!/usr/bin/env bash\n\
            r=\n\
            echo x > /root/.wcp/logs/allowed 2>/dev/null && r=\"$r allowed=written\" || r=\"$r allowed=BLOCKED\"\n\
            echo x > /root/.wcp/outside 2>/dev/null && r=\"$r root=WRITTEN\" || r=\"$r root=blocked\"\n\
            echo x > /etc/wcp-outside 2>/dev/null && r=\"$r etc=WRITTEN\" || r=\"$r etc=blocked\"\n\
            echo x >> /root/.wcp/agents/wcp_agent_lib.py 2>/dev/null && r=\"$r lib=WRITTEN\" || r=\"$r lib=blocked\"\n\
            rm -f /root/.wcp/agents/wcp_agent_lib.py 2>/dev/null && r=\"$r libdel=DELETED\" || r=\"$r libdel=blocked\"\n\
            echo x > /tmp/wcp-private-probe && r=\"$r tmp=private\"\n\
            echo \"$r\" > /root/.wcp/logs/result\n";
        let agent = crate::agent_lifecycle::Agent::from_registry(
            "wcp-sandbox-probe".into(),
            "1.0.0".into(),
            Some("* * * * *".into()),
            true,
            script.into(),
            Some(vec!["/root/.wcp/agents".into(), "/root/.wcp/logs".into()]),
        );
        let _ = sh("crontab -l > /tmp/wcp-test-crontab.bak 2>/dev/null; true");
        let request = InstallRequest {
            agent,
            schedule: None,
            request_id: RequestId::parse(A).unwrap(),
            idempotency_key: None,
        };
        let result = install(&ctx, &request, &cancel()).unwrap();
        assert_eq!(result.scheduler, "systemd");
        let (_, active) = sh("systemctl is-active wcp-agent-wcp-sandbox-probe.timer");
        assert_eq!(active, "active");
        let (_, enabled) = sh("systemctl is-enabled wcp-agent-wcp-sandbox-probe.timer");
        assert_eq!(enabled, "enabled");
        let (verified, report) = sh(
            "systemd-analyze verify /etc/systemd/system/wcp-agent-wcp-sandbox-probe.service /etc/systemd/system/wcp-agent-wcp-sandbox-probe.timer 2>&1; echo $?",
        );
        assert!(verified && report.ends_with('0'), "{report}");
        // The timer itself must fire (every minute) and run the service.
        let started = std::time::Instant::now();
        while !std::path::Path::new("/root/.wcp/logs/result").exists() {
            assert!(
                started.elapsed() < std::time::Duration::from_secs(100),
                "the timer never ran the service"
            );
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
        let (_, outcome) = sh("cat /root/.wcp/logs/result");
        assert_eq!(
            outcome,
            "allowed=written root=blocked etc=blocked lib=blocked libdel=blocked tmp=private"
        );
        assert_eq!(
            std::fs::read_to_string("/root/.wcp/agents/wcp_agent_lib.py").unwrap(),
            library()
        );
        assert!(!std::path::Path::new("/tmp/wcp-private-probe").exists());
        assert!(!std::path::Path::new("/root/.wcp/outside").exists());
        assert!(!std::path::Path::new("/etc/wcp-outside").exists());

        let request = RemoveRequest::parse(r#"{"name":"wcp-sandbox-probe"}"#, B, None).unwrap();
        let removed = remove(&ctx, &request, &cancel()).unwrap();
        assert!(removed.removed_systemd_units);
        let (_, after) =
            sh("systemctl list-unit-files 'wcp-agent-wcp-sandbox-probe*' --no-legend | wc -l");
        assert_eq!(after, "0");
        let _ = sh("rm -rf /root/.wcp/logs/result /root/.wcp/logs/allowed");
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
