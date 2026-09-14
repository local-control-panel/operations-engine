use crate::{
    compose,
    db_tool::{REMOVE_OPERATION, RemoveRequest, RemoveResult, Tool},
    error::ErrorCode,
    filesystem::ManagedRoot,
    ingress::{self, activate},
    mutation::preflight,
    process::{
        self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination,
        SubprocessDiagnostics,
    },
    site::{SiteRelativePath, TrustedRoot},
    transaction::{
        audit::{self, AuditRecord},
        state::{self, TransactionStatus},
    },
};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub ingress_root: &'a TrustedRoot,
    pub docker_program: &'a str,
    pub compose: &'a compose::Access,
}
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Run(process::ProcessRunError),
    Rejected(SubprocessDiagnostics),
    Config,
    Recovery,
    PostCommit { result: RemoveResult },
    Replayed { code: ErrorCode, message: String },
}
impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another lifecycle request for this tool is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Run(e) => (
                process::spawn_error_code(e),
                "could not remove database tool".into(),
            ),
            Self::Rejected(d) => (
                if d.timed_out {
                    ErrorCode::Timeout
                } else if d.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::SubprocessFailed
                },
                "database tool removal was rejected".into(),
            ),
            Self::Config => (
                ErrorCode::ConfigReloadFailed,
                "database tool route could not be reloaded".into(),
            ),
            Self::Recovery => (
                ErrorCode::ConfigRecoveryFailed,
                "database tool removal failed and route recovery did not complete".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            _ => (
                ErrorCode::Internal,
                "internal database tool removal error".into(),
            ),
        }
    }
}

pub fn execute(
    ctx: &Context<'_>,
    req: &RemoveRequest,
    cancel: &CancellationToken,
) -> Result<RemoveResult, Error> {
    let scope = open(ctx.engine_state, req.name()).map_err(Error::Io)?;
    let admitted = match preflight::run(
        &scope,
        req.request_id,
        req.idempotency_key.as_ref(),
        REMOVE_OPERATION,
    )
    .map_err(Error::Preflight)?
    {
        preflight::Outcome::Replay(id) => return replay(&scope, id),
        preflight::Outcome::Proceed(v) => v,
    };
    let preflight::Admitted { lock, mut state } = admitted;
    let sp = state_path(req.request_id);
    let ap = audit_path();
    if let Err(e) = run(ctx, req, cancel) {
        return Err(fail(&scope, &sp, &ap, state, e));
    }
    let result = RemoveResult {
        tool: match req.tool {
            Tool::PhpMyAdmin => "phpMyAdmin",
            Tool::Adminer => "adminer",
        }
        .into(),
        removed: true,
        completed_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    state
        .mark_committed(serde_json::to_value(&result).unwrap())
        .unwrap();
    if state::save(&scope, &sp, &state).is_err() {
        drop(lock);
        return Err(Error::PostCommit { result });
    }
    let _ = audit::append(
        &scope,
        &ap,
        &AuditRecord::result(req.request_id, true, None),
    );
    drop(lock);
    Ok(result)
}
fn run(ctx: &Context<'_>, req: &RemoveRequest, cancel: &CancellationToken) -> Result<(), Error> {
    let root = ManagedRoot::open(ctx.ingress_root).map_err(Error::Io)?;
    let mut moved = None;
    if let Some(domain) = &req.domain {
        let live = ingress::route_path(domain);
        match root.read_bytes(&live) {
            Ok(_) => {
                let backup = SiteRelativePath::parse(format!(
                    "{}.removing-{}",
                    domain.as_str(),
                    req.request_id
                ))
                .unwrap();
                root.rename(&live, &backup).map_err(Error::Io)?;
                if activate::validate(ctx.compose, ingress::LIVE_CONFIG_PATH).is_err()
                    || activate::reload(ctx.compose).is_err()
                {
                    let _ = root.rename(&backup, &live);
                    let _ = activate::reload(ctx.compose);
                    return Err(Error::Config);
                }
                moved = Some((live, backup));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(Error::Io(error)),
        }
    }
    let out = process::run(
        &ProcessRequest::new(ctx.docker_program).args(["rm", "-f", req.name()]),
        &ProcessLimits::default(),
        cancel,
    )
    .map_err(Error::Run)?;
    if !matches!(
        out.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        if let Some((live, backup)) = &moved {
            if root.rename(backup, live).is_err() || activate::reload(ctx.compose).is_err() {
                return Err(Error::Recovery);
            }
        }
        return Err(Error::Rejected(SubprocessDiagnostics::from_output(
            ctx.docker_program,
            &out,
        )));
    }
    if let Some((_, backup)) = moved {
        let _ = root.remove_file(&backup);
    }
    Ok(())
}
fn open(root: &ManagedRoot, name: &str) -> std::io::Result<ManagedRoot> {
    let p = SiteRelativePath::parse(format!("db-tools/{name}")).unwrap();
    root.create_dir_all(&p)?;
    let s = root.open_managed_dir(&p)?;
    for d in ["locks", "transactions", "audit"] {
        s.create_dir_all(&SiteRelativePath::parse(d).unwrap())?;
    }
    Ok(s)
}
fn state_path(id: crate::transaction::RequestId) -> SiteRelativePath {
    SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap()
}
fn audit_path() -> SiteRelativePath {
    SiteRelativePath::parse("audit/events.jsonl").unwrap()
}
fn replay(s: &ManagedRoot, id: crate::transaction::RequestId) -> Result<RemoveResult, Error> {
    let l = state::load(s, &state_path(id))
        .map_err(|e| Error::Io(std::io::Error::other(format!("{e:?}"))))?;
    if l.operation != REMOVE_OPERATION {
        return Err(Error::Replayed {
            code: ErrorCode::Conflict,
            message: "idempotency key belongs to another operation".into(),
        });
    }
    match l.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => serde_json::from_value(l.outcome.unwrap().result.unwrap())
            .map_err(|e| Error::Io(std::io::Error::other(e))),
        TransactionStatus::Failed => {
            let o = l.outcome.unwrap();
            Err(Error::Replayed {
                code: o.error_code.unwrap_or(ErrorCode::Internal),
                message: o.error_message.unwrap_or_default(),
            })
        }
    }
}
fn fail(
    s: &ManagedRoot,
    sp: &SiteRelativePath,
    ap: &SiteRelativePath,
    mut st: crate::transaction::state::TransactionState,
    e: Error,
) -> Error {
    let (c, m) = e.protocol();
    let _ = st.mark_failed(c, m);
    let _ = state::save(s, sp, &st);
    let _ = audit::append(s, ap, &AuditRecord::result(st.request_id, false, Some(c)));
    e
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    struct Fixture {
        _dir: tempfile::TempDir,
        state: ManagedRoot,
        ingress: TrustedRoot,
        docker: String,
        access: compose::Access,
    }
    impl Fixture {
        fn new(fail_rm: bool) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let state_path = dir.path().join("state");
            let ingress_path = dir.path().join("ingress");
            let bin = dir.path().join("bin");
            fs::create_dir_all(&state_path).unwrap();
            fs::create_dir_all(&ingress_path).unwrap();
            fs::create_dir_all(&bin).unwrap();
            let docker = bin.join("docker");
            fs::write(
                &docker,
                format!(
                    "#!/bin/sh\nif [ \"$1\" = rm ]; then exit {}; fi\nexit 0\n",
                    if fail_rm { 1 } else { 0 }
                ),
            )
            .unwrap();
            let mut mode = fs::metadata(&docker).unwrap().permissions();
            mode.set_mode(0o755);
            fs::set_permissions(&docker, mode).unwrap();
            let state_root = TrustedRoot::parse(&state_path).unwrap();
            let ingress = TrustedRoot::parse(&ingress_path).unwrap();
            let state = ManagedRoot::open(&state_root).unwrap();
            let access = compose::Access::default()
                .stack_dir(dir.path())
                .docker_path(&bin);
            Self {
                _dir: dir,
                state,
                ingress,
                docker: docker.to_string_lossy().into(),
                access,
            }
        }
        fn request(&self) -> RemoveRequest {
            RemoveRequest::parse(
                r#"{"tool":"adminer","domain":"db.example.com"}"#,
                "123e4567-e89b-12d3-a456-426614174000",
                None,
            )
            .unwrap()
        }
        fn route(&self) -> std::path::PathBuf {
            self.ingress.as_path().join("db.example.com.caddyfile")
        }
        fn context(&self) -> Context<'_> {
            Context {
                engine_state: &self.state,
                ingress_root: &self.ingress,
                docker_program: &self.docker,
                compose: &self.access,
            }
        }
    }
    #[test]
    fn removes_route_and_container_transactionally() {
        let f = Fixture::new(false);
        fs::write(f.route(), "route").unwrap();
        execute(&f.context(), &f.request(), &CancellationToken::default()).unwrap();
        assert!(!f.route().exists());
    }
    #[test]
    fn restores_route_when_container_removal_fails() {
        let f = Fixture::new(true);
        fs::write(f.route(), "route").unwrap();
        assert!(matches!(
            execute(&f.context(), &f.request(), &CancellationToken::default()),
            Err(Error::Rejected(_))
        ));
        assert_eq!(fs::read_to_string(f.route()).unwrap(), "route");
    }
}
