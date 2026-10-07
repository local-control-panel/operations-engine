//! The transactional pipeline for scheduling, unscheduling, listing and
//! running database backups. See the parent module for the design.
//!
//! Scheduling and unscheduling hold the same per-user cron lock scope that
//! `cron.installTab` uses (`cron/root`), so the panel's generic cron writes
//! cannot interleave with this read-modify-write; a final re-read of the tab
//! before the install also catches writers that do not take the lock.

use super::{
    Credentials, ListResult, RunRequest, SCHEDULE_OPERATION, ScheduleRequest, Target,
    UNSCHEDULE_OPERATION, UnscheduleRequest, list_jobs, needs_credentials, tab_too_large, with_job,
    without_job,
};
use crate::{
    backup_create,
    cron::execute::{InstallFailure, open_cron_state, read_current_tab},
    error::ErrorCode,
    filesystem::ManagedRoot,
    ingress::ConfigHash,
    mutation::preflight,
    process::{self, CancellationToken},
    site::{SiteRelativePath, TrustedRoot},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        commit::PreCommit,
        state::{self, TransactionState, TransactionStatus},
    },
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::time::{SystemTime, UNIX_EPOCH};

/// The cron user whose crontab holds backup jobs. Backups are written under
/// `/root/db-backups` and run `docker`, so the jobs belong to root.
const CRON_USER: &str = "root";

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub state_root: &'a TrustedRoot,
    /// The `db-backup` directory of the credential root (mode `0700`).
    pub credentials: &'a ManagedRoot,
    pub crontab_program: &'a str,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduleResult {
    /// Existing lines for the same database and schedule that were replaced
    /// (a legacy line with an embedded password counts).
    pub replaced_jobs: u32,
    pub crontab_sha256: ConfigHash,
    pub activated_at_unix_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnscheduleResult {
    pub removed_jobs: u32,
    pub credentials_removed: bool,
    pub crontab_sha256: ConfigHash,
    pub activated_at_unix_secs: u64,
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
    CredentialsMissing,
    CredentialsInsecure,
    CredentialsInvalid,
    Backup(backup_create::TransactionError),
    PostCommit,
    Replayed { code: ErrorCode, message: String },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Io(_) | Self::State(_) | Self::PostCommit => (
                ErrorCode::Internal,
                "internal scheduled backup error".into(),
            ),
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another crontab change is already in progress".into(),
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
            Self::CredentialsMissing => (
                ErrorCode::NotFound,
                "no stored credentials for this scheduled backup - schedule it again".into(),
            ),
            Self::CredentialsInsecure => (
                ErrorCode::Internal,
                "the stored backup credentials are not private to root".into(),
            ),
            Self::CredentialsInvalid => (
                ErrorCode::Internal,
                "the stored backup credentials are unreadable - schedule it again".into(),
            ),
            Self::Backup(error) => error.protocol(),
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

fn credential_path(target: &Target) -> SiteRelativePath {
    rel(&target.credential_file())
}

/// Opens the `db-backup` credential directory beneath the credential root,
/// creating it as `0700` when missing.
pub fn open_credentials(root: &ManagedRoot) -> std::io::Result<ManagedRoot> {
    let relative = rel(super::CREDENTIAL_DIR);
    root.create_dir_all(&relative)?;
    let directory = root.open_managed_dir(&relative)?;
    directory.set_own_mode(0o700)?;
    Ok(directory)
}

fn read_tab(program: &str) -> Result<String, Error> {
    let bytes = read_current_tab(program, None)
        .map_err(Error::Read)?
        .unwrap_or_default();
    String::from_utf8(bytes).map_err(|_| Error::NotUtf8)
}

fn hash(tab: &str) -> ConfigHash {
    ConfigHash::of(tab.as_bytes())
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

fn transactional<T: Serialize + DeserializeOwned>(
    ctx: &Context<'_>,
    request_id: RequestId,
    key: Option<&IdempotencyKey>,
    operation: &'static str,
    cancel: &CancellationToken,
    body: impl FnOnce() -> Result<T, Error>,
) -> Result<T, Error> {
    let scope = open_cron_state(ctx.engine_state, Some(CRON_USER)).map_err(Error::Io)?;
    let admitted =
        match preflight::run(&scope, request_id, key, operation).map_err(Error::Preflight)? {
            preflight::Outcome::Replay(original) => return replay(&scope, original, operation),
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
        Err(error) => Err(fail(&scope, &path, &audit_path, state, error)),
        Ok(result) => {
            let _ = pre_commit.commit();
            state
                .mark_committed(serde_json::to_value(&result).expect("results serialize"))
                .expect("state is in progress");
            let saved = state::save(&scope, &path, &state);
            let _ = audit::append(
                &scope,
                &audit_path,
                &AuditRecord::result(request_id, true, None),
            );
            drop(lock);
            // The crontab is already installed; a missing record only costs
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

pub fn schedule(
    ctx: &Context<'_>,
    request: &ScheduleRequest,
    cancel: &CancellationToken,
) -> Result<ScheduleResult, Error> {
    transactional(
        ctx,
        request.request_id,
        request.idempotency_key.as_ref(),
        SCHEDULE_OPERATION,
        cancel,
        || {
            let before = read_tab(ctx.crontab_program)?;
            let (content, replaced) = with_job(
                &before,
                &request.target,
                &request.schedule,
                request.retention_days,
            );
            let path = credential_path(&request.target);
            let previous = ctx.credentials.read_to_string(&path).ok();
            let credentials = serde_json::to_vec(&Credentials {
                container: request.container.as_str().to_owned(),
                root_password: request.root_password.clone(),
            })
            .expect("credentials serialize");
            ctx.credentials
                .write_atomic_private(&path, &credentials)
                .map_err(Error::Io)?;
            if let Err(error) = install_guarded(ctx, &before, &content) {
                // The new line never became live; put the old secret back.
                let _ = match &previous {
                    Some(old) => ctx.credentials.write_atomic_private(&path, old.as_bytes()),
                    None => ctx.credentials.remove_file(&path),
                };
                return Err(error);
            }
            Ok(ScheduleResult {
                replaced_jobs: replaced as u32,
                crontab_sha256: hash(&content),
                activated_at_unix_secs: now(),
            })
        },
    )
}

pub fn unschedule(
    ctx: &Context<'_>,
    request: &UnscheduleRequest,
    cancel: &CancellationToken,
) -> Result<UnscheduleResult, Error> {
    transactional(
        ctx,
        request.request_id,
        request.idempotency_key.as_ref(),
        UNSCHEDULE_OPERATION,
        cancel,
        || {
            let before = read_tab(ctx.crontab_program)?;
            let (content, removed) = without_job(&before, &request.target, &request.schedule);
            install_guarded(ctx, &before, &content)?;
            // Only after the lines are gone: a leftover file is harmless, a
            // missing one under a live line would break the job.
            let credentials_removed = !needs_credentials(&content, &request.target)
                && ctx
                    .credentials
                    .remove_file(&credential_path(&request.target))
                    .is_ok();
            Ok(UnscheduleResult {
                removed_jobs: removed as u32,
                credentials_removed,
                crontab_sha256: hash(&content),
                activated_at_unix_secs: now(),
            })
        },
    )
}

/// Read-only: the tagged jobs of the root crontab, redacted.
pub fn list(crontab_program: &str) -> Result<ListResult, Error> {
    Ok(ListResult {
        jobs: list_jobs(&read_tab(crontab_program)?),
    })
}

/// What cron runs. Loads the credential file, then takes exactly the path
/// `backup.createDatabase` takes (lock, transaction, atomic publish, retention).
pub fn run(
    credentials: &ManagedRoot,
    request: &RunRequest,
    engine_state: &ManagedRoot,
    backup_root: &ManagedRoot,
    docker_program: &str,
    cancel: &CancellationToken,
) -> Result<backup_create::CreateResult, Error> {
    let path = credential_path(&request.target);
    let mode = credentials.mode(&path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            Error::CredentialsMissing
        } else {
            Error::Io(error)
        }
    })?;
    if mode & 0o077 != 0 {
        return Err(Error::CredentialsInsecure);
    }
    let stored: Credentials = serde_json::from_str(
        &credentials
            .read_to_string(&path)
            .map_err(|_| Error::CredentialsInvalid)?,
    )
    .map_err(|_| Error::CredentialsInvalid)?;
    let plan = serde_json::json!({
        "dbType": request.target.db_type_str(),
        "database": request.target.database.as_str(),
        "container": stored.container,
        "rootPassword": stored.root_password,
        "retentionDays": request.retention_days,
    });
    let create = backup_create::Request::parse(
        &plan.to_string(),
        &uuid::Uuid::new_v4().hyphenated().to_string(),
        None,
    )
    .map_err(|_| Error::CredentialsInvalid)?;
    backup_create::execute_transactional(&create, engine_state, backup_root, docker_program, cancel)
        .map_err(Error::Backup)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::backup_schedule::{Schedule, engine_line};
    use std::{fs, os::unix::fs::PermissionsExt};

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const ID2: &str = "223e4567-e89b-12d3-a456-426614174000";
    const LEGACY: &str = "0 2 * * * docker exec 'db-1' mariadb-dump -uroot -p'sekret' 'wp' > /x.sql && find /x -mtime +7 -delete # [db-backup] mariadb:wp";

    struct Host {
        dir: tempfile::TempDir,
        state_root: TrustedRoot,
        engine_state: ManagedRoot,
        credentials: ManagedRoot,
        crontab: String,
        tab: std::path::PathBuf,
    }

    fn host(initial: Option<&str>) -> Host {
        let dir = tempfile::tempdir().unwrap();
        for sub in ["state", "creds"] {
            fs::create_dir(dir.path().join(sub)).unwrap();
        }
        let tab = dir.path().join("installed.tab");
        if let Some(initial) = initial {
            fs::write(&tab, initial).unwrap();
        }
        let fake = dir.path().join("fake-crontab");
        fs::write(
            &fake,
            format!(
                "#!/bin/sh\nTAB='{tab}'\nif [ \"$1\" = \"-l\" ]; then [ -f \"$TAB\" ] && cat \"$TAB\" || exit 1; exit $?; fi\n[ -e '{reject}' ] && exit 1\ncp \"$1\" \"$TAB\"\n",
                tab = tab.display(),
                reject = dir.path().join("REJECT").display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
        let state_root = TrustedRoot::parse(dir.path().join("state")).unwrap();
        let engine_state = ManagedRoot::open(&state_root).unwrap();
        let creds_root =
            ManagedRoot::open(&TrustedRoot::parse(dir.path().join("creds")).unwrap()).unwrap();
        let credentials = open_credentials(&creds_root).unwrap();
        Host {
            crontab: fake.to_string_lossy().into_owned(),
            dir,
            state_root,
            engine_state,
            credentials,
            tab,
        }
    }

    impl Host {
        fn ctx(&self) -> Context<'_> {
            Context {
                engine_state: &self.engine_state,
                state_root: &self.state_root,
                credentials: &self.credentials,
                crontab_program: &self.crontab,
            }
        }
        fn tab(&self) -> String {
            fs::read_to_string(&self.tab).unwrap_or_default()
        }
        fn cred_path(&self, name: &str) -> std::path::PathBuf {
            self.dir
                .path()
                .join("creds")
                .join(super::super::CREDENTIAL_DIR)
                .join(name)
        }
    }

    fn schedule_request(
        id: &str,
        key: Option<&str>,
        schedule: &str,
        password: &str,
    ) -> ScheduleRequest {
        ScheduleRequest::parse(
            &serde_json::json!({
                "dbType":"mariadb","database":"wp","container":"db-1",
                "rootPassword":password,"schedule":schedule,"retentionDays":7
            })
            .to_string(),
            id,
            key,
        )
        .unwrap()
    }

    fn unschedule_request(id: &str, schedule: &str) -> UnscheduleRequest {
        UnscheduleRequest::parse(
            &serde_json::json!({"dbType":"mariadb","database":"wp","schedule":schedule})
                .to_string(),
            id,
            None,
        )
        .unwrap()
    }

    #[test]
    fn schedule_keeps_the_password_out_of_the_crontab_and_in_a_private_file() {
        let host = host(Some("MAILTO=root\n"));
        let result = schedule(
            &host.ctx(),
            &schedule_request(ID, None, "0 2 * * *", "p'w d"),
            &CancellationToken::default(),
        )
        .unwrap();
        let tab = host.tab();
        assert!(!tab.contains("p'w d"), "{tab}");
        assert!(
            tab.starts_with(
                "MAILTO=root\n0 2 * * * /usr/local/bin/ops-engine backup run-scheduled"
            )
        );
        assert_eq!(result.replaced_jobs, 0);
        let file = host.cred_path("mariadb_wp.json");
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(file.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let stored: Credentials = serde_json::from_str(&fs::read_to_string(file).unwrap()).unwrap();
        assert_eq!(stored.root_password, "p'w d");
        assert_eq!(stored.container, "db-1");
    }

    #[test]
    fn rescheduling_replaces_a_legacy_line_and_leaves_other_jobs() {
        let host = host(Some(&format!("{LEGACY}\n5 5 * * * /usr/bin/true\n")));
        let result = schedule(
            &host.ctx(),
            &schedule_request(ID, None, "0 2 * * *", "new"),
            &CancellationToken::default(),
        )
        .unwrap();
        assert_eq!(result.replaced_jobs, 1);
        let tab = host.tab();
        assert!(!tab.contains("sekret") && !tab.contains("mariadb-dump"));
        assert!(tab.contains("5 5 * * * /usr/bin/true"));
        // The legacy line for a different schedule survives untouched.
        let host2 = host2_with_legacy();
        schedule(
            &host2.ctx(),
            &schedule_request(ID, None, "0 9 * * *", "new"),
            &CancellationToken::default(),
        )
        .unwrap();
        assert!(host2.tab().contains("mariadb-dump -uroot -p'sekret'"));
    }

    fn host2_with_legacy() -> Host {
        host(Some(&format!("{LEGACY}\n")))
    }

    #[test]
    fn rejected_crontab_restores_the_previous_credentials() {
        let host = host(None);
        schedule(
            &host.ctx(),
            &schedule_request(ID, None, "0 2 * * *", "first"),
            &CancellationToken::default(),
        )
        .unwrap();
        fs::write(host.dir.path().join("REJECT"), "").unwrap();
        let error = schedule(
            &host.ctx(),
            &schedule_request(ID2, None, "0 3 * * *", "second"),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::Install(_)));
        let stored: Credentials =
            serde_json::from_str(&fs::read_to_string(host.cred_path("mariadb_wp.json")).unwrap())
                .unwrap();
        assert_eq!(stored.root_password, "first");
        assert!(!host.tab().contains("0 3 * * *"));
    }

    #[test]
    fn first_time_failure_leaves_no_credential_file() {
        let host = host(None);
        fs::write(host.dir.path().join("REJECT"), "").unwrap();
        assert!(
            schedule(
                &host.ctx(),
                &schedule_request(ID, None, "0 2 * * *", "x"),
                &CancellationToken::default(),
            )
            .is_err()
        );
        assert!(!host.cred_path("mariadb_wp.json").exists());
    }

    #[test]
    fn retry_with_the_same_key_replays_without_a_second_write() {
        let host = host(None);
        let first = schedule(
            &host.ctx(),
            &schedule_request(ID, Some("k1"), "0 2 * * *", "x"),
            &CancellationToken::default(),
        )
        .unwrap();
        let before = host.tab();
        let again = schedule(
            &host.ctx(),
            &schedule_request(ID2, Some("k1"), "0 2 * * *", "x"),
            &CancellationToken::default(),
        )
        .unwrap();
        assert_eq!(first.activated_at_unix_secs, again.activated_at_unix_secs);
        assert_eq!(before, host.tab());
    }

    #[test]
    fn unschedule_removes_lines_then_the_credentials_when_unused() {
        let host = host(None);
        for (id, when) in [(ID, "0 2 * * *"), (ID2, "0 9 * * *")] {
            schedule(
                &host.ctx(),
                &schedule_request(id, None, when, "x"),
                &CancellationToken::default(),
            )
            .unwrap();
        }
        let first = unschedule(
            &host.ctx(),
            &unschedule_request("323e4567-e89b-12d3-a456-426614174000", "0 2 * * *"),
            &CancellationToken::default(),
        )
        .unwrap();
        assert_eq!((first.removed_jobs, first.credentials_removed), (1, false));
        assert!(host.cred_path("mariadb_wp.json").exists());
        let last = unschedule(
            &host.ctx(),
            &unschedule_request("423e4567-e89b-12d3-a456-426614174000", "0 9 * * *"),
            &CancellationToken::default(),
        )
        .unwrap();
        assert_eq!((last.removed_jobs, last.credentials_removed), (1, true));
        assert!(!host.cred_path("mariadb_wp.json").exists());
        assert_eq!(host.tab(), "");
    }

    #[test]
    fn list_redacts_legacy_passwords() {
        let host = host(Some(&format!(
            "{LEGACY}\n{}\n",
            engine_line(
                &Target {
                    db_type: crate::db_restore::DbType::Mariadb,
                    database: crate::db_restore::DatabaseName::parse("other").unwrap()
                },
                &Schedule::parse("@daily").unwrap(),
                3
            )
        )));
        let listed = list(&host.crontab).unwrap();
        assert_eq!(listed.jobs.len(), 2);
        let serialized = serde_json::to_string(&listed).unwrap();
        assert!(!serialized.contains("sekret"));
        assert!(listed.jobs[0].secret_in_crontab);
        assert!(!listed.jobs[1].secret_in_crontab);
    }

    #[test]
    fn run_requires_private_credentials_and_takes_the_create_database_path() {
        let host = host(None);
        let docker = host.dir.path().join("fake-docker");
        fs::write(
            &docker,
            "#!/bin/sh\n[ \"$MYSQL_PWD\" = \"pw\" ] || exit 9\nprintf 'CREATE TABLE t;\\n'\n",
        )
        .unwrap();
        fs::set_permissions(&docker, fs::Permissions::from_mode(0o755)).unwrap();
        let backups_dir = host.dir.path().join("backups");
        fs::create_dir(&backups_dir).unwrap();
        let backups = ManagedRoot::open(&TrustedRoot::parse(&backups_dir).unwrap()).unwrap();
        let request = RunRequest::parse("mariadb", "wp", 0).unwrap();
        let run_it = || {
            run(
                &host.credentials,
                &request,
                &host.engine_state,
                &backups,
                docker.to_str().unwrap(),
                &CancellationToken::default(),
            )
        };
        assert!(matches!(run_it(), Err(Error::CredentialsMissing)));
        schedule(
            &host.ctx(),
            &schedule_request(ID, None, "0 2 * * *", "pw"),
            &CancellationToken::default(),
        )
        .unwrap();
        let result = run_it().unwrap();
        let name = result.file_path.rsplit('/').next().unwrap();
        assert_eq!(
            fs::read_to_string(backups_dir.join(name)).unwrap(),
            "CREATE TABLE t;\n"
        );
        let file = host.cred_path("mariadb_wp.json");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(run_it(), Err(Error::CredentialsInsecure)));
    }
}
