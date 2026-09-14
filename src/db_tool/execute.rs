use crate::{
    db_tool::{
        ADMINER_IMAGE, Action, DatabaseType, OPERATION, PMA_IMAGE, Request, Tool, ToolResult,
    },
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{
        self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination,
        SubprocessDiagnostics,
    },
    site::SiteRelativePath,
    transaction::{
        audit::{self, AuditRecord},
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
    PostCommit { result: ToolResult },
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
                "could not run database tool lifecycle".into(),
            ),
            Self::Rejected(d) => (
                if d.timed_out {
                    ErrorCode::Timeout
                } else if d.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::SubprocessFailed
                },
                "database tool lifecycle was rejected".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            _ => (
                ErrorCode::Internal,
                "internal database tool lifecycle error".into(),
            ),
        }
    }
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> std::result::Result<ToolResult, Error> {
    let scope = open(ctx.engine_state, req.name()).map_err(Error::Io)?;
    let admitted = match preflight::run(
        &scope,
        req.request_id,
        req.idempotency_key.as_ref(),
        OPERATION,
    )
    .map_err(Error::Preflight)?
    {
        preflight::Outcome::Replay(id) => return replay(&scope, id),
        preflight::Outcome::Proceed(v) => v,
    };
    let preflight::Admitted { lock, mut state } = admitted;
    let sp = state_path(req.request_id);
    let ap = audit_path();
    let run = run(ctx, req, cancel);
    if let Err(e) = run {
        return Err(fail(&scope, &sp, &ap, state, e));
    }
    let result = ToolResult {
        tool: match req.tool {
            Tool::PhpMyAdmin => "phpMyAdmin",
            Tool::Adminer => "adminer",
        }
        .into(),
        action: format!("{:?}", req.action).to_ascii_lowercase(),
        running: req.action != Action::Stop,
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
fn run(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> std::result::Result<(), Error> {
    let commands = commands(req);
    for (index, args) in commands.into_iter().enumerate() {
        let out = process::run(
            &ProcessRequest::new(ctx.docker_program).args(args),
            &ProcessLimits::default(),
            cancel,
        )
        .map_err(Error::Run)?;
        if !matches!(
            out.termination,
            ProcessTermination::Exited { success: true, .. }
        ) {
            if req.action == Action::Install && index == 0 {
                continue;
            }
            if req.action == Action::Install {
                let _ = process::run(
                    &ProcessRequest::new(ctx.docker_program).args(["rm", "-f", req.name()]),
                    &ProcessLimits::default(),
                    &CancellationToken::default(),
                );
            }
            return Err(Error::Rejected(SubprocessDiagnostics::from_output(
                ctx.docker_program,
                &out,
            )));
        }
    }
    Ok(())
}
fn commands(req: &Request) -> Vec<Vec<String>> {
    match req.action {
        Action::Start => vec![vec!["start".into(), req.name().into()]],
        Action::Stop => vec![vec!["stop".into(), req.name().into()]],
        Action::Install => {
            let domain = req.domain.as_ref().unwrap().as_str();
            let (image, port_env, labels) = match req.tool {
                Tool::PhpMyAdmin => (
                    PMA_IMAGE,
                    vec!["-e", "PMA_HOST=mariadb-11", "-e", "PMA_PORT=3306"],
                    vec![format!("wcp.pma.domain={domain}")],
                ),
                Tool::Adminer => {
                    let db = req.database_type.unwrap_or(DatabaseType::Mariadb);
                    let server = if db == DatabaseType::Postgresql {
                        "postgres-17"
                    } else {
                        "mariadb-11"
                    };
                    (
                        ADMINER_IMAGE,
                        vec![
                            "-e",
                            if server == "postgres-17" {
                                "ADMINER_DEFAULT_SERVER=postgres-17"
                            } else {
                                "ADMINER_DEFAULT_SERVER=mariadb-11"
                            },
                        ],
                        vec![
                            format!("wcp.adminer.domain={domain}"),
                            format!(
                                "wcp.adminer.database-type={}",
                                if db == DatabaseType::Postgresql {
                                    "postgresql"
                                } else {
                                    "mariadb"
                                }
                            ),
                        ],
                    )
                }
            };
            let mut run = vec![
                "run".into(),
                "-d".into(),
                "--name".into(),
                req.name().into(),
                "--network".into(),
                "wcp_backend".into(),
                "--restart".into(),
                "unless-stopped".into(),
                "--security-opt".into(),
                "no-new-privileges:true".into(),
            ];
            for l in labels {
                run.extend(["--label".into(), l]);
            }
            for v in port_env {
                run.push(v.into());
            }
            run.push(image.into());
            vec![
                vec!["rm".into(), "-f".into(), req.name().into()],
                run,
                vec![
                    "network".into(),
                    "connect".into(),
                    "wcp_edge".into(),
                    req.name().into(),
                ],
            ]
        }
    }
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
fn replay(
    s: &ManagedRoot,
    id: crate::transaction::RequestId,
) -> std::result::Result<ToolResult, Error> {
    let l = state::load(s, &state_path(id))
        .map_err(|e| Error::Io(std::io::Error::other(format!("{e:?}"))))?;
    if l.operation != OPERATION {
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn install_argv_is_fixed_and_pinned() {
        let r=Request::parse(r#"{"tool":"phpMyAdmin","action":"install","domain":"db.example.com","databaseType":"mariadb"}"#,"123e4567-e89b-12d3-a456-426614174000",None).unwrap();
        let c = commands(&r);
        assert!(c[1].contains(&PMA_IMAGE.to_string()));
        assert!(!c.iter().flatten().any(|v| v.contains(';')));
    }
}
