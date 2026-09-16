use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    maria_slow_log::{ClearResult, OPERATION, Request},
    mutation::preflight,
    process::{
        self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination,
        SubprocessDiagnostics,
    },
    site::SiteRelativePath,
    transaction::{
        audit::{self, AuditRecord},
        commit::PreCommit,
        state::{self, TransactionStatus},
    },
};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub docker_program: &'a str,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Run(process::ProcessRunError),
    Rejected(SubprocessDiagnostics),
    InvalidStatus,
    InvalidLogPath,
    Cancelled,
    PostCommit { result: ClearResult },
    Replayed { code: ErrorCode, message: String },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another MariaDB slow-log clear is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Run(error) => (
                process::spawn_error_code(error),
                "could not run MariaDB slow-log clear".into(),
            ),
            Self::Rejected(details) => (
                if details.timed_out {
                    ErrorCode::Timeout
                } else if details.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::SubprocessFailed
                },
                "MariaDB slow-log clear failed".into(),
            ),
            Self::InvalidStatus | Self::InvalidLogPath => (
                ErrorCode::InvalidInput,
                "MariaDB returned an unsafe slow-log configuration".into(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before MariaDB slow-log clear ran".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            _ => (
                ErrorCode::Internal,
                "internal MariaDB slow-log clear error".into(),
            ),
        }
    }
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<ClearResult, Error> {
    let scope = open(ctx.engine_state, req.container.as_str()).map_err(Error::Io)?;
    let admitted = match preflight::run(
        &scope,
        req.request_id,
        req.idempotency_key.as_ref(),
        OPERATION,
    )
    .map_err(Error::Preflight)?
    {
        preflight::Outcome::Replay(id) => return replay(&scope, id),
        preflight::Outcome::Proceed(value) => value,
    };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path = state_path(req.request_id);
    let audit_path = audit_path();
    let pre_commit = PreCommit::new(cancel.clone());
    if pre_commit.check().is_err() {
        return Err(fail(
            &scope,
            &state_path,
            &audit_path,
            state,
            Error::Cancelled,
        ));
    }

    let status = run_mariadb(
        ctx,
        req,
        "SELECT CONCAT(@@GLOBAL.slow_query_log, '\\t', @@GLOBAL.slow_query_log_file);",
        cancel,
    )
    .map_err(|error| fail(&scope, &state_path, &audit_path, state.clone(), error))?;
    let (enabled, log_path) = parse_status(&status)
        .map_err(|error| fail(&scope, &state_path, &audit_path, state.clone(), error))?;
    run_mariadb(ctx, req, "SET GLOBAL slow_query_log = OFF;", cancel)
        .map_err(|error| fail(&scope, &state_path, &audit_path, state.clone(), error))?;

    let truncate = run_fixed(
        ctx,
        [
            "exec",
            req.container.as_str(),
            "truncate",
            "-s",
            "0",
            log_path,
        ],
        cancel,
    );
    if let Err(error) = truncate {
        if enabled {
            let _ = run_mariadb(ctx, req, "SET GLOBAL slow_query_log = ON;", cancel);
        }
        return Err(fail(&scope, &state_path, &audit_path, state, error));
    }
    if enabled {
        run_mariadb(ctx, req, "SET GLOBAL slow_query_log = ON;", cancel)
            .map_err(|error| fail(&scope, &state_path, &audit_path, state.clone(), error))?;
    }

    let _ = pre_commit.commit();
    let result = ClearResult {
        restored_enabled_state: enabled,
        completed_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    state
        .mark_committed(serde_json::to_value(&result).unwrap())
        .unwrap();
    if state::save(&scope, &state_path, &state).is_err() {
        drop(lock);
        return Err(Error::PostCommit { result });
    }
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(req.request_id, true, None),
    );
    drop(lock);
    Ok(result)
}

fn run_mariadb(
    ctx: &Context<'_>,
    req: &Request,
    sql: &str,
    cancel: &CancellationToken,
) -> Result<String, Error> {
    let password = format!("-p{}", req.root_password);
    let args = [
        "exec",
        req.container.as_str(),
        "mariadb",
        "-uroot",
        password.as_str(),
        "-Nse",
        sql,
    ];
    let output = run_fixed(ctx, args, cancel)?;
    String::from_utf8(output.stdout.bytes).map_err(|_| Error::InvalidStatus)
}

fn run_fixed<I, S>(
    ctx: &Context<'_>,
    args: I,
    cancel: &CancellationToken,
) -> Result<process::ProcessOutput, Error>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let output = process::run(
        &ProcessRequest::new(ctx.docker_program).args(args),
        &ProcessLimits::default(),
        cancel,
    )
    .map_err(Error::Run)?;
    if !matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        return Err(Error::Rejected(SubprocessDiagnostics::from_output(
            ctx.docker_program,
            &output,
        )));
    }
    Ok(output)
}

fn parse_status(value: &str) -> Result<(bool, &str), Error> {
    let (enabled, path) = value.trim().split_once('\t').ok_or(Error::InvalidStatus)?;
    let enabled = match enabled {
        "0" | "OFF" => false,
        "1" | "ON" => true,
        _ => return Err(Error::InvalidStatus),
    };
    if path.is_empty()
        || path.len() > 4096
        || !path.starts_with('/')
        || path.bytes().any(|b| b == 0 || b == b'\n' || b == b'\r')
    {
        return Err(Error::InvalidLogPath);
    }
    Ok((enabled, path))
}

fn open(root: &ManagedRoot, container: &str) -> std::io::Result<ManagedRoot> {
    let path = SiteRelativePath::parse(format!("maria-slow-log/{container}")).unwrap();
    root.create_dir_all(&path)?;
    let scope = root.open_managed_dir(&path)?;
    for child in ["locks", "transactions", "audit"] {
        scope.create_dir_all(&SiteRelativePath::parse(child).unwrap())?;
    }
    Ok(scope)
}
fn state_path(id: crate::transaction::RequestId) -> SiteRelativePath {
    SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap()
}
fn audit_path() -> SiteRelativePath {
    SiteRelativePath::parse("audit/events.jsonl").unwrap()
}
fn replay(scope: &ManagedRoot, id: crate::transaction::RequestId) -> Result<ClearResult, Error> {
    let loaded = state::load(scope, &state_path(id))
        .map_err(|error| Error::Io(std::io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != OPERATION {
        return Err(Error::Io(std::io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => {
            serde_json::from_value(loaded.outcome.unwrap().result.unwrap())
                .map_err(|error| Error::Io(std::io::Error::other(error)))
        }
        TransactionStatus::Failed => {
            let outcome = loaded.outcome.unwrap();
            Err(Error::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}
fn fail(
    scope: &ManagedRoot,
    state_path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut state: crate::transaction::state::TransactionState,
    error: Error,
) -> Error {
    let (code, message) = error.protocol();
    let _ = state.mark_failed(code, message);
    let _ = state::save(scope, state_path, &state);
    let _ = audit::append(
        scope,
        audit_path,
        &AuditRecord::result(state.request_id, false, Some(code)),
    );
    error
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    #[test]
    fn status_parser_accepts_only_absolute_single_line_paths() {
        assert_eq!(
            parse_status("1\t/var/lib/mysql/slow.log\n").unwrap(),
            (true, "/var/lib/mysql/slow.log")
        );
        assert!(parse_status("1\trelative.log").is_err());
        assert!(parse_status("2\t/var/lib/mysql/slow.log").is_err());
    }

    #[test]
    fn clears_with_fixed_argv_and_restores_the_enabled_state() {
        let directory = tempfile::tempdir().unwrap();
        let state_path = directory.path().join("state");
        fs::create_dir(&state_path).unwrap();
        let calls = directory.path().join("calls");
        let docker = directory.path().join("docker");
        fs::write(
            &docker,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"$*\" in *SELECT*) printf '1\\t/var/lib/mysql/slow.log\\n';; esac\n",
                calls.display()
            ),
        )
        .unwrap();
        let mut permissions = fs::metadata(&docker).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&docker, permissions).unwrap();
        let state =
            ManagedRoot::open(&crate::site::TrustedRoot::parse(&state_path).unwrap()).unwrap();
        let request = Request::parse(
            r#"{"container":"mariadb-11","rootPassword":"secret"}"#,
            "123e4567-e89b-12d3-a456-426614174000",
            Some("clear-slow-log"),
        )
        .unwrap();
        let result = execute(
            &Context {
                engine_state: &state,
                docker_program: docker.to_str().unwrap(),
            },
            &request,
            &CancellationToken::default(),
        )
        .unwrap();
        assert!(result.restored_enabled_state);
        let calls = fs::read_to_string(calls).unwrap();
        assert!(calls.contains("exec mariadb-11 truncate -s 0 /var/lib/mysql/slow.log"));
        assert!(calls.contains("SET GLOBAL slow_query_log = OFF;"));
        assert!(calls.contains("SET GLOBAL slow_query_log = ON;"));
        assert!(!calls.contains("sh -c"));
    }
}
