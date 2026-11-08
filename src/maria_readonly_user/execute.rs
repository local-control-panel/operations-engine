use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    maria_readonly_user::{
        ENSURE_OPERATION, HOST, MAX_QUERIES_PER_HOUR, MAX_UPDATES_PER_HOUR, MAX_USER_CONNECTIONS,
        REVOKE_OPERATION, Request, ensure_statements, revoke_statements,
    },
    mutation::preflight,
    process::{
        self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination,
        SubprocessDiagnostics,
    },
    secret_result::SecretResult,
    site::SiteRelativePath,
    transaction::{
        RequestId,
        audit::{self, AuditRecord},
        state::{self, TransactionState, TransactionStatus},
    },
};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

const PASSWORD_LEN: usize = 32;

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub docker_program: &'a str,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Limits {
    pub max_queries_per_hour: u32,
    pub max_updates_per_hour: u32,
    pub max_user_connections: u32,
}

const LIMITS: Limits = Limits {
    max_queries_per_hour: MAX_QUERIES_PER_HOUR,
    max_updates_per_hour: MAX_UPDATES_PER_HOUR,
    max_user_connections: MAX_USER_CONNECTIONS,
};

/// The part of an ensure result that is safe to keep and to replay.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnsurePublic {
    pub username: String,
    pub host: String,
    pub database: String,
    /// The account did not exist before this request.
    pub created: bool,
    /// A new password was set and returned in this response.
    pub password_issued: bool,
    pub limits: Limits,
    pub completed_at_unix_secs: u64,
}

/// The one-time part.
#[derive(Serialize)]
pub struct EnsureSecret {
    pub password: String,
}

#[derive(Debug)]
pub enum Ensured {
    /// A password was set; it is in the secret half.
    Issued(Box<SecretResult<EnsurePublic, EnsureSecret>>),
    /// The account exists and no rotation was requested: no password.
    Existing(EnsurePublic),
    /// An idempotent replay: the public record only.
    AlreadyIssued(serde_json::Value),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeResult {
    pub username: String,
    pub host: String,
    pub database: String,
    /// `false` when the account did not exist (still a success).
    pub revoked: bool,
    pub completed_at_unix_secs: u64,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Run(process::ProcessRunError),
    Rejected(SubprocessDiagnostics),
    MalformedOutput,
    Cancelled,
    Entropy,
    DatabaseMissing,
    PostCommitEnsure(Box<Ensured>),
    PostCommitRevoke(RevokeResult),
    Replayed { code: ErrorCode, message: String },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another read-only MariaDB user request is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Run(error) => (
                process::spawn_error_code(error),
                "could not run the read-only MariaDB user request".into(),
            ),
            Self::Rejected(diagnostics) => (
                if diagnostics.timed_out {
                    ErrorCode::Timeout
                } else if diagnostics.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::SubprocessFailed
                },
                "MariaDB rejected the read-only user request".into(),
            ),
            Self::MalformedOutput => (
                ErrorCode::SubprocessFailed,
                "MariaDB answered the read-only user request unexpectedly".into(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before the read-only user request ran".into(),
            ),
            Self::DatabaseMissing => (
                ErrorCode::InvalidInput,
                "the database does not exist".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            _ => (
                ErrorCode::Internal,
                "internal read-only MariaDB user error".into(),
            ),
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// 32 alphanumeric characters from the kernel's random source.
fn new_password() -> Result<String, Error> {
    use std::io::Read;
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut urandom = std::fs::File::open("/dev/urandom").map_err(|_| Error::Entropy)?;
    let mut out = String::with_capacity(PASSWORD_LEN);
    let mut byte = [0u8; 1];
    while out.len() < PASSWORD_LEN {
        urandom.read_exact(&mut byte).map_err(|_| Error::Entropy)?;
        // 248 = 62 * 4: rejecting the rest keeps every character equally likely.
        if byte[0] < 248 {
            out.push(ALPHABET[usize::from(byte[0]) % ALPHABET.len()] as char);
        }
    }
    Ok(out)
}

/// Runs SQL through the client in the container. The root password is the
/// first stdin line (read into `MYSQL_PWD` by the wrapper), the SQL follows;
/// nothing secret is in argv.
fn sql(
    ctx: &Context<'_>,
    req: &Request,
    statements: &[String],
    query: bool,
    cancel: &CancellationToken,
) -> Result<Vec<u8>, Error> {
    let script = if query {
        "IFS= read -r MYSQL_PWD; export MYSQL_PWD; exec mariadb -u root --batch --skip-column-names"
    } else {
        "IFS= read -r MYSQL_PWD; export MYSQL_PWD; exec mariadb -u root --batch"
    };
    let args = ["exec", "-i", req.container.as_str(), "sh", "-c", script];
    let mut input = format!("{}\n", req.root_password);
    for statement in statements {
        input.push_str(statement);
        input.push('\n');
    }
    let output = process::run_with_stdin_bytes(
        &ProcessRequest::new(ctx.docker_program).args(args),
        input.as_bytes(),
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
    Ok(output.stdout.bytes)
}

/// `(account exists, database exists)`.
fn probe(
    ctx: &Context<'_>,
    req: &Request,
    user: &str,
    cancel: &CancellationToken,
) -> Result<(bool, bool), Error> {
    let query = format!(
        "SELECT (SELECT COUNT(*) FROM mysql.user WHERE User='{user}' AND Host='{HOST}'), (SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name='{}');",
        req.database.as_str()
    );
    let reply = sql(ctx, req, &[query], true, cancel)?;
    let text = std::str::from_utf8(&reply).map_err(|_| Error::MalformedOutput)?;
    let mut parts = text.trim().split('\t');
    let flag = |part: Option<&str>| match part {
        Some("0") => Ok(false),
        Some("1") => Ok(true),
        _ => Err(Error::MalformedOutput),
    };
    let user_exists = flag(parts.next())?;
    let database_exists = flag(parts.next())?;
    if parts.next().is_some() {
        return Err(Error::MalformedOutput);
    }
    Ok((user_exists, database_exists))
}

struct Begun<'a> {
    scope: &'a ManagedRoot,
    state: TransactionState,
    lock: crate::transaction::lock::SiteLockGuard<'a>,
    state_path: SiteRelativePath,
    audit_path: SiteRelativePath,
}

enum Admission<'a> {
    Run(Box<Begun<'a>>),
    Replay(serde_json::Value),
}

/// One scope per container and account, shared by ensure and revoke so the
/// two never run at the same time on the same account.
fn open_scope(root: &ManagedRoot, req: &Request) -> Result<ManagedRoot, Error> {
    let path = SiteRelativePath::parse(format!(
        "maria-readonly-user/{}/{}",
        req.container.as_str(),
        req.username()
    ))
    .unwrap();
    root.create_dir_all(&path).map_err(Error::Io)?;
    let scope = root.open_managed_dir(&path).map_err(Error::Io)?;
    for child in ["locks", "transactions", "audit"] {
        scope
            .create_dir_all(&SiteRelativePath::parse(child).unwrap())
            .map_err(Error::Io)?;
    }
    Ok(scope)
}

fn begin<'a>(
    scope: &'a ManagedRoot,
    req: &Request,
    operation: &'static str,
) -> Result<Admission<'a>, Error> {
    match preflight::run(
        scope,
        req.request_id,
        req.idempotency_key.as_ref(),
        operation,
    )
    .map_err(Error::Preflight)?
    {
        preflight::Outcome::Replay(id) => {
            let loaded = state::load(
                scope,
                &SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap(),
            )
            .map_err(|error| Error::Io(std::io::Error::other(format!("{error:?}"))))?;
            if loaded.operation != operation {
                return Err(Error::Io(std::io::Error::other(
                    "transaction operation mismatch",
                )));
            }
            match loaded.status {
                TransactionStatus::InProgress => Err(Error::ReplayInProgress),
                TransactionStatus::Committed => Ok(Admission::Replay(
                    loaded
                        .outcome
                        .and_then(|outcome| outcome.result)
                        .unwrap_or_default(),
                )),
                TransactionStatus::Failed => {
                    let outcome = loaded.outcome.unwrap();
                    Err(Error::Replayed {
                        code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                        message: outcome.error_message.unwrap_or_default(),
                    })
                }
            }
        }
        preflight::Outcome::Proceed(preflight::Admitted { lock, state }) => {
            Ok(Admission::Run(Box::new(Begun {
                scope,
                state,
                lock,
                state_path: SiteRelativePath::parse(format!(
                    "transactions/{}.json",
                    req.request_id
                ))
                .unwrap(),
                audit_path: SiteRelativePath::parse("audit/events.jsonl").unwrap(),
            })))
        }
    }
}

fn abort(begun: &Begun<'_>, error: Error) -> Error {
    let (code, message) = error.protocol();
    let mut state = begun.state.clone();
    let _ = state.mark_failed(code, message);
    let _ = state::save(begun.scope, &begun.state_path, &state);
    let _ = audit::append(
        begun.scope,
        &begun.audit_path,
        &AuditRecord::result(state.request_id, false, Some(code)),
    );
    error
}

/// Records the commit with the public value; `false` when the state could not
/// be saved.
fn commit(begun: &mut Begun<'_>, public: serde_json::Value, request_id: RequestId) -> bool {
    begun.state.mark_committed(public).unwrap();
    if state::save(begun.scope, &begun.state_path, &begun.state).is_err() {
        return false;
    }
    let _ = audit::append(
        begun.scope,
        &begun.audit_path,
        &AuditRecord::result(request_id, true, None),
    );
    true
}

pub fn ensure(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<Ensured, Error> {
    let scope = open_scope(ctx.engine_state, req)?;
    let mut begun = match begin(&scope, req, ENSURE_OPERATION)? {
        Admission::Replay(public) => return Ok(Ensured::AlreadyIssued(public)),
        Admission::Run(begun) => begun,
    };
    if cancel.is_cancelled() {
        return Err(abort(&begun, Error::Cancelled));
    }
    let user = req.username();
    let (existed, database_exists) = match probe(ctx, req, &user, cancel) {
        Ok(value) => value,
        Err(error) => return Err(abort(&begun, error)),
    };
    if !database_exists {
        return Err(abort(&begun, Error::DatabaseMissing));
    }
    let password = if !existed || req.rotate {
        match new_password() {
            Ok(value) => Some(value),
            Err(error) => return Err(abort(&begun, error)),
        }
    } else {
        None
    };
    let statements = ensure_statements(&user, &req.database, password.as_deref());
    if let Err(error) = sql(ctx, req, &statements, false, cancel) {
        if !existed {
            // Do not leave a half-configured account behind; best effort.
            let _ = sql(ctx, req, &revoke_statements(&user), false, cancel);
        }
        return Err(abort(&begun, error));
    }
    let public = EnsurePublic {
        username: user,
        host: HOST.to_owned(),
        database: req.database.as_str().to_owned(),
        created: !existed,
        password_issued: password.is_some(),
        limits: LIMITS,
        completed_at_unix_secs: now_secs(),
    };
    let ensured = match password {
        Some(password) => Ensured::Issued(Box::new(SecretResult::new(
            public,
            EnsureSecret { password },
        ))),
        None => Ensured::Existing(public),
    };
    // Only the public half is ever handed to storage.
    let stored = match &ensured {
        Ensured::Issued(result) => result.public_value().ok(),
        Ensured::Existing(public) => serde_json::to_value(public).ok(),
        Ensured::AlreadyIssued(_) => None,
    };
    let Some(stored) = stored else {
        drop(begun.lock);
        return Err(Error::Io(std::io::Error::other(
            "result could not be encoded",
        )));
    };
    if !commit(&mut begun, stored, req.request_id) {
        drop(begun.lock);
        return Err(Error::PostCommitEnsure(Box::new(ensured)));
    }
    drop(begun.lock);
    Ok(ensured)
}

pub fn revoke(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<RevokeResult, Error> {
    let scope = open_scope(ctx.engine_state, req)?;
    let mut begun = match begin(&scope, req, REVOKE_OPERATION)? {
        Admission::Replay(value) => {
            return serde_json::from_value(value)
                .map_err(|error| Error::Io(std::io::Error::other(error)));
        }
        Admission::Run(begun) => begun,
    };
    if cancel.is_cancelled() {
        return Err(abort(&begun, Error::Cancelled));
    }
    let user = req.username();
    let steps = (|| {
        // The database may already be gone; only the account matters here.
        let (existed, _) = probe(ctx, req, &user, cancel)?;
        sql(ctx, req, &revoke_statements(&user), false, cancel)?;
        Ok(existed)
    })();
    let revoked = match steps {
        Ok(value) => value,
        Err(error) => return Err(abort(&begun, error)),
    };
    let result = RevokeResult {
        username: user,
        host: HOST.to_owned(),
        database: req.database.as_str().to_owned(),
        revoked,
        completed_at_unix_secs: now_secs(),
    };
    if !commit(
        &mut begun,
        serde_json::to_value(&result).unwrap(),
        req.request_id,
    ) {
        drop(begun.lock);
        return Err(Error::PostCommitRevoke(result));
    }
    drop(begun.lock);
    Ok(result)
}

#[cfg(all(test, unix))]
mod tests;
