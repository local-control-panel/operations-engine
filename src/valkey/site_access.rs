//! Per-site access to the shared Valkey instance (Valkey 9). Valkey runs with
//! its `default` user off; each site gets its own ACL user and its own numbered
//! database. The user can read and write only that database (ACL `db=<n>`), may
//! `FLUSHDB` and `SCAN` it, and cannot select another database or run
//! administrative commands (`FLUSHALL`, `KEYS`, `CONFIG`, `ACL`, ...).
//!
//! Three operations, all through the administrator wrapper of the Valkey
//! image (see [`crate::valkey::ADMIN_CLI`]):
//!
//! - `db.provisionValkeySite` creates the site's user, or replaces its
//!   password. The password is generated here, goes to Valkey only as a
//!   SHA-256 hash, and comes back once as a secret result; it is never
//!   stored, logged or replayed.
//! - `db.revokeValkeySite` empties the site's database and removes its user.
//! - `db.flushValkeySite` empties the site's database only.
//!
//! The database of a site is read from its ACL user, never from the caller of
//! flush or revoke, so a wrong request cannot empty another site's database.
//!
//! Users are persisted with `ACL SAVE` into the ACL file the image keeps on
//! its data volume, so they survive a restart.

use crate::{
    db_restore::ContainerName,
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{
        self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination,
        SubprocessDiagnostics,
    },
    secret_result::SecretResult,
    site::{Domain, SiteRelativePath},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        state::{self, TransactionStatus},
    },
    valkey::ADMIN_CLI,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub const PROVISION_OPERATION: &str = "db.provisionValkeySite";
pub const REVOKE_OPERATION: &str = "db.revokeValkeySite";
pub const FLUSH_OPERATION: &str = "db.flushValkeySite";

const PASSWORD_LEN: usize = 32;

/// Site databases are 1..=MAX_DATABASE; 0 stays with the administrator. The
/// image sets `databases 256`.
pub const MAX_DATABASE: u16 = 255;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    container: String,
    domain: String,
    /// Only `db.provisionValkeySite` takes it; the others read it from the user.
    #[serde(default)]
    database: Option<u16>,
}

#[derive(Debug)]
pub struct SiteRequest {
    pub container: ContainerName,
    pub domain: Domain,
    /// The site's database (provisioning only).
    pub database: Option<u16>,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    InvalidContainer,
    InvalidDomain,
    InvalidDatabase,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl SiteRequest {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        Ok(Self {
            container: ContainerName::parse(&plan.container)
                .map_err(|_| RequestError::InvalidContainer)?,
            domain: Domain::parse(&plan.domain).map_err(|_| RequestError::InvalidDomain)?,
            database: match plan.database {
                Some(n) if (1..=MAX_DATABASE).contains(&n) => Some(n),
                Some(_) => return Err(RequestError::InvalidDatabase),
                None => None,
            },
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }

    fn username(&self) -> String {
        format!("site_{}", self.domain)
    }
}

/// The part of a provisioning result that is safe to keep and to replay.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisionPublic {
    pub username: String,
    pub database: u16,
    pub completed_at_unix_secs: u64,
}

/// The one-time part.
#[derive(Serialize)]
pub struct ProvisionSecret {
    pub password: String,
}

pub type ProvisionResult = SecretResult<ProvisionPublic, ProvisionSecret>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlushSiteResult {
    pub database: u16,
    pub keys_removed: u64,
    pub completed_at_unix_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeResult {
    /// `false` when the site had no user (the operation is still a success).
    pub revoked: bool,
    pub keys_removed: u64,
    pub completed_at_unix_secs: u64,
}

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
    MalformedOutput,
    Cancelled,
    Entropy,
    /// The site has no Valkey user (or one without exactly one database).
    NotProvisioned,
    /// Provisioning needs a database number.
    MissingDatabase,
    PostCommitProvision(Box<ProvisionResult>),
    PostCommitFlush(FlushSiteResult),
    PostCommitRevoke(RevokeResult),
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another Valkey site operation is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Run(error) => (
                process::spawn_error_code(error),
                "could not run the Valkey site operation".into(),
            ),
            Self::Rejected(diagnostics) => (
                if diagnostics.timed_out {
                    ErrorCode::Timeout
                } else if diagnostics.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::SubprocessFailed
                },
                "Valkey rejected the site operation".into(),
            ),
            Self::MalformedOutput => (
                ErrorCode::SubprocessFailed,
                "Valkey answered the site operation unexpectedly".into(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before the Valkey site operation ran".into(),
            ),
            Self::NotProvisioned => (
                ErrorCode::InvalidInput,
                "the site has no Valkey user with exactly one database".into(),
            ),
            Self::MissingDatabase => (
                ErrorCode::InvalidInput,
                "a database number from 1 to 255 is required".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            _ => (
                ErrorCode::Internal,
                "internal Valkey site operation error".into(),
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

fn sha256_hex(value: &str) -> String {
    use std::fmt::Write;
    Sha256::digest(value.as_bytes())
        .iter()
        .fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// The ACL rules of a site user, as separate arguments. Only the hash of the
/// password is here. `db=<n>` limits every command, `SELECT` included, to the
/// site's own database; `FLUSHDB` is allowed back after `-@dangerous` because
/// in that database it only empties the site's own data. No channels: the
/// object caches do not use Pub/Sub. Scripts are allowed because Valkey checks
/// every command inside them against this same user.
fn acl_rules(username: &str, database: u16, password_hash: &str) -> Vec<String> {
    let mut args: Vec<String> = ["ACL", "SETUSER", username, "reset", "on"]
        .map(String::from)
        .to_vec();
    args.push(format!("#{password_hash}"));
    args.extend(
        ["resetkeys", "~*", "resetchannels"]
            .map(String::from)
            .into_iter()
            .chain([format!("db={database}")]),
    );
    args.extend(
        [
            "-@all",
            "+@read",
            "+@write",
            "+@keyspace",
            "+@hash",
            "+@list",
            "+@set",
            "+@sortedset",
            "+@string",
            "+@transaction",
            "+@connection",
            "-@dangerous",
            "-@admin",
            "+flushdb",
            "+eval",
            "+evalsha",
            "+eval_ro",
            "+evalsha_ro",
            "+script|load",
            "+script|exists",
        ]
        .map(String::from),
    );
    args
}

/// The single database a site user is limited to, from `ACL GETUSER`'s reply
/// (`... databases` followed by a line such as `db=3`). `None` for a missing
/// user, no database, several databases or anything unexpected.
fn parse_user_database(reply: &[u8]) -> Option<u16> {
    let text = std::str::from_utf8(reply).ok()?;
    let mut lines = text.lines().map(str::trim);
    lines.find(|line| *line == "databases")?;
    let value = lines.next()?.strip_prefix("db=")?;
    if value.contains(',') || value.contains('-') {
        return None;
    }
    value
        .parse()
        .ok()
        .filter(|n| (1..=MAX_DATABASE).contains(n))
}

/// One administrator command; the standard output of a successful run.
fn admin(
    ctx: &Context<'_>,
    container: &ContainerName,
    tail: &[String],
    cancel: &CancellationToken,
) -> Result<Vec<u8>, Error> {
    let mut args: Vec<String> = vec![
        "exec".into(),
        container.as_str().into(),
        "sh".into(),
        ADMIN_CLI.into(),
    ];
    args.extend(tail.iter().cloned());
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
    Ok(output.stdout.bytes)
}

fn expect_ok(output: &[u8]) -> Result<(), Error> {
    if matches!(output, b"OK\n" | b"OK\r\n") {
        Ok(())
    } else {
        Err(Error::MalformedOutput)
    }
}

fn expect_count(output: &[u8]) -> Result<u64, Error> {
    std::str::from_utf8(output)
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .ok_or(Error::MalformedOutput)
}

/// Empties the database of the site's user and returns how many keys it held.
/// The database comes from the user, never from the request.
fn empty_database(
    ctx: &Context<'_>,
    req: &SiteRequest,
    cancel: &CancellationToken,
) -> Result<(u16, u64), Error> {
    let reply = admin(
        ctx,
        &req.container,
        &["ACL".into(), "GETUSER".into(), req.username()],
        cancel,
    )?;
    let database = parse_user_database(&reply).ok_or(Error::NotProvisioned)?;
    let select = ["-n".to_owned(), database.to_string()];
    let count = |command: &[&str]| -> Vec<String> {
        select
            .iter()
            .cloned()
            .chain(command.iter().map(|part| (*part).to_owned()))
            .collect()
    };
    let keys = expect_count(&admin(ctx, &req.container, &count(&["DBSIZE"]), cancel)?)?;
    expect_ok(&admin(
        ctx,
        &req.container,
        &count(&["FLUSHDB", "ASYNC"]),
        cancel,
    )?)?;
    Ok((database, keys))
}

/// What an operation needs from the transaction machinery.
struct Begun<'a> {
    scope: &'a ManagedRoot,
    state: crate::transaction::state::TransactionState,
    lock: crate::transaction::lock::SiteLockGuard<'a>,
    state_path: SiteRelativePath,
    audit_path: SiteRelativePath,
}

enum Admission<'a> {
    Run(Box<Begun<'a>>),
    Replay(serde_json::Value),
}

/// The per-container scope that holds this kind of operation's state.
fn open_scope(
    ctx: &Context<'_>,
    req: &SiteRequest,
    scope_name: &str,
) -> Result<ManagedRoot, Error> {
    let path = SiteRelativePath::parse(format!("{scope_name}/{}", req.container.as_str())).unwrap();
    ctx.engine_state.create_dir_all(&path).map_err(Error::Io)?;
    let scope = ctx
        .engine_state
        .open_managed_dir(&path)
        .map_err(Error::Io)?;
    for child in ["locks", "transactions", "audit"] {
        scope
            .create_dir_all(&SiteRelativePath::parse(child).unwrap())
            .map_err(Error::Io)?;
    }
    Ok(scope)
}

fn begin<'a>(
    scope: &'a ManagedRoot,
    req: &SiteRequest,
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

/// Records the commit; `false` when the state could not be saved.
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

/// The outcome of `db.provisionValkeySite`.
#[derive(Debug)]
pub enum Provisioned {
    New(Box<ProvisionResult>),
    /// An idempotent replay: the public record only; the password was never
    /// stored and cannot be returned again.
    AlreadyIssued(serde_json::Value),
}

pub fn provision(
    ctx: &Context<'_>,
    req: &SiteRequest,
    cancel: &CancellationToken,
) -> Result<Provisioned, Error> {
    let scope = open_scope(ctx, req, "valkey-site-provision")?;
    let mut begun = match begin(&scope, req, PROVISION_OPERATION)? {
        Admission::Replay(public) => return Ok(Provisioned::AlreadyIssued(public)),
        Admission::Run(begun) => begun,
    };
    if cancel.is_cancelled() {
        return Err(abort(&begun, Error::Cancelled));
    }
    let Some(database) = req.database else {
        return Err(abort(&begun, Error::MissingDatabase));
    };
    let password = match new_password() {
        Ok(value) => value,
        Err(error) => return Err(abort(&begun, error)),
    };
    let steps = (|| {
        // The rules go as separate arguments of one ACL SETUSER.
        let rules = acl_rules(&req.username(), database, &sha256_hex(&password));
        expect_ok(&admin(ctx, &req.container, &rules, cancel)?)?;
        expect_ok(&admin(
            ctx,
            &req.container,
            &["ACL".into(), "SAVE".into()],
            cancel,
        )?)
    })();
    if let Err(error) = steps {
        return Err(abort(&begun, error));
    }
    let result = SecretResult::new(
        ProvisionPublic {
            username: req.username(),
            database,
            completed_at_unix_secs: now_secs(),
        },
        ProvisionSecret { password },
    );
    // Only the public half is ever handed to storage.
    let public = result
        .public_value()
        .map_err(|_| Error::Io(std::io::Error::other("result could not be encoded")))?;
    if !commit(&mut begun, public, req.request_id) {
        drop(begun.lock);
        return Err(Error::PostCommitProvision(Box::new(result)));
    }
    drop(begun.lock);
    Ok(Provisioned::New(Box::new(result)))
}

pub fn flush(
    ctx: &Context<'_>,
    req: &SiteRequest,
    cancel: &CancellationToken,
) -> Result<FlushSiteResult, Error> {
    let scope = open_scope(ctx, req, "valkey-site-flush")?;
    let mut begun = match begin(&scope, req, FLUSH_OPERATION)? {
        Admission::Replay(value) => {
            return serde_json::from_value(value)
                .map_err(|error| Error::Io(std::io::Error::other(error)));
        }
        Admission::Run(begun) => begun,
    };
    if cancel.is_cancelled() {
        return Err(abort(&begun, Error::Cancelled));
    }
    let (database, keys_removed) = match empty_database(ctx, req, cancel) {
        Ok(value) => value,
        Err(error) => return Err(abort(&begun, error)),
    };
    let result = FlushSiteResult {
        database,
        keys_removed,
        completed_at_unix_secs: now_secs(),
    };
    if !commit(
        &mut begun,
        serde_json::to_value(&result).unwrap(),
        req.request_id,
    ) {
        drop(begun.lock);
        return Err(Error::PostCommitFlush(result));
    }
    drop(begun.lock);
    Ok(result)
}

pub fn revoke(
    ctx: &Context<'_>,
    req: &SiteRequest,
    cancel: &CancellationToken,
) -> Result<RevokeResult, Error> {
    let scope = open_scope(ctx, req, "valkey-site-revoke")?;
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
    let steps = (|| {
        // A site that has no user has nothing to empty; the revoke is a success.
        let keys_removed = match empty_database(ctx, req, cancel) {
            Ok((_, keys)) => keys,
            Err(Error::NotProvisioned) => 0,
            Err(error) => return Err(error),
        };
        // DELUSER also drops the user's open connections.
        let deleted = expect_count(&admin(
            ctx,
            &req.container,
            &["ACL".into(), "DELUSER".into(), req.username()],
            cancel,
        )?)?;
        expect_ok(&admin(
            ctx,
            &req.container,
            &["ACL".into(), "SAVE".into()],
            cancel,
        )?)?;
        Ok::<_, Error>((keys_removed, deleted > 0))
    })();
    let (keys_removed, revoked) = match steps {
        Ok(value) => value,
        Err(error) => return Err(abort(&begun, error)),
    };
    let result = RevokeResult {
        revoked,
        keys_removed,
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
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const ID2: &str = "123e4567-e89b-12d3-a456-426614174001";

    fn plan(domain: &str) -> String {
        serde_json::json!({"container":"valkey-9","domain":domain}).to_string()
    }

    fn plan_with_database(domain: &str, database: u64) -> String {
        serde_json::json!({"container":"valkey-9","domain":domain,"database":database}).to_string()
    }

    struct Fixture {
        directory: tempfile::TempDir,
        state: ManagedRoot,
        docker: PathBuf,
    }

    impl Fixture {
        /// Logs every call as one line; answers like Valkey does. Marker files
        /// make single steps fail or change an answer.
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let state_path = directory.path().join("state");
            fs::create_dir(&state_path).unwrap();
            let docker = directory.path().join("docker");
            fs::write(
                &docker,
                r#"#!/bin/sh
base="$(dirname "$0")"
printf '%s\n' "$*" >> "$base/calls.log"
case "$*" in
  *"ACL SETUSER"*) test -f "$base/REJECT_SETUSER" && exit 1; echo OK ;;
  *"ACL SAVE"*) test -f "$base/REJECT_SAVE" && exit 1; echo OK ;;
  *"ACL DELUSER"*) cat "$base/DELUSER_REPLY" 2>/dev/null || echo 1 ;;
  *"ACL GETUSER"*)
    if test -f "$base/NO_USER"; then echo; else
      printf 'flags\non\npasswords\nabc\ncommands\n-@all\nkeys\n~*\nchannels\n\ndatabases\n%s\nselectors\n' "$(cat "$base/USER_DB" 2>/dev/null || echo db=7)"
    fi ;;
  *" DBSIZE"*) cat "$base/DBSIZE_REPLY" 2>/dev/null || echo 3 ;;
  *"FLUSHDB ASYNC"*) test -f "$base/REJECT_FLUSH" && exit 1; echo OK ;;
  *) exit 2 ;;
esac
"#,
            )
            .unwrap();
            let mut permissions = fs::metadata(&docker).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&docker, permissions).unwrap();
            let state =
                ManagedRoot::open(&crate::site::TrustedRoot::parse(&state_path).unwrap()).unwrap();
            Self {
                directory,
                state,
                docker,
            }
        }

        fn context(&self) -> Context<'_> {
            Context {
                engine_state: &self.state,
                docker_program: self.docker.to_str().unwrap(),
            }
        }

        fn calls(&self) -> Vec<String> {
            fs::read_to_string(self.directory.path().join("calls.log"))
                .map(|text| text.lines().map(str::to_owned).collect())
                .unwrap_or_default()
        }

        fn mark(&self, name: &str, content: &str) {
            fs::write(self.directory.path().join(name), content).unwrap();
        }

        /// Everything the engine wrote under its state root.
        fn state_text(&self) -> String {
            fn walk(path: &std::path::Path, out: &mut String) {
                for entry in fs::read_dir(path).unwrap().flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        walk(&path, out);
                    } else if let Ok(text) = fs::read_to_string(&path) {
                        out.push_str(&text);
                    }
                }
            }
            let mut out = String::new();
            walk(&self.directory.path().join("state"), &mut out);
            out
        }
    }

    fn req(domain: &str, id: &str, key: Option<&str>) -> SiteRequest {
        SiteRequest::parse(&plan(domain), id, key).unwrap()
    }

    fn provisioning(domain: &str, database: u64, id: &str, key: &str) -> SiteRequest {
        SiteRequest::parse(&plan_with_database(domain, database), id, Some(key)).unwrap()
    }

    #[test]
    fn requests_accept_only_a_container_a_plain_domain_and_a_site_database() {
        assert!(SiteRequest::parse(&plan("a.example.com"), ID, None).is_ok());
        for domain in [
            "",
            "A.example.com",
            "a.example.com\n",
            "*.example.com",
            "a b.test",
            "a:b.test",
            "a/b",
        ] {
            assert_eq!(
                SiteRequest::parse(&plan(domain), ID, None).unwrap_err(),
                RequestError::InvalidDomain,
                "{domain:?}"
            );
        }
        let extra = r#"{"container":"valkey-9","domain":"a.test","password":"x"}"#;
        assert_eq!(
            SiteRequest::parse(extra, ID, None).unwrap_err(),
            RequestError::InvalidJson
        );
        let bad = r#"{"container":"bad;name","domain":"a.test"}"#;
        assert_eq!(
            SiteRequest::parse(bad, ID, None).unwrap_err(),
            RequestError::InvalidContainer
        );
        for database in [0u64, 256, 1000, 70000] {
            assert!(
                SiteRequest::parse(&plan_with_database("a.test", database), ID, None).is_err(),
                "{database}"
            );
        }
        for database in [1u64, 15, 255] {
            assert_eq!(
                SiteRequest::parse(&plan_with_database("a.test", database), ID, None)
                    .unwrap()
                    .database,
                Some(database as u16)
            );
        }
    }

    #[test]
    fn the_site_user_is_limited_to_its_database_and_gets_only_a_hash() {
        let rules = acl_rules("site_a.test", 7, &sha256_hex("pw"));
        let text = rules.join(" ");
        assert!(text.starts_with("ACL SETUSER site_a.test reset on #"));
        assert!(text.contains(" resetkeys ~* resetchannels db=7 -@all "));
        for denied in ["-@dangerous", "-@admin"] {
            assert!(rules.iter().any(|rule| rule == denied), "{denied}");
        }
        for never in [
            "+@all",
            "+@admin",
            "+@dangerous",
            "allkeys",
            "nopass",
            "alldbs",
            "+@pubsub",
            "+flushall",
            "+keys",
            "+config",
            "+acl",
        ] {
            assert!(!rules.iter().any(|rule| rule == never), "{never}");
        }
        // Exactly one database rule.
        assert_eq!(rules.iter().filter(|r| r.starts_with("db=")).count(), 1);
        // FLUSHDB comes back after the broad deny, so it is allowed.
        let position = |rule: &str| rules.iter().position(|r| r == rule).unwrap();
        assert!(position("-@dangerous") < position("+flushdb"));
        assert!(position("+@write") < position("-@dangerous"));
        assert!(!text.contains("pw"));
    }

    #[test]
    fn the_database_is_read_from_the_user_and_only_when_it_is_exactly_one() {
        let reply = |db: &str| {
            format!(
                "flags\non\ncommands\n-@all\nkeys\n~*\nchannels\n\ndatabases\n{db}\nselectors\n"
            )
        };
        assert_eq!(parse_user_database(reply("db=7").as_bytes()), Some(7));
        assert_eq!(parse_user_database(reply("db=255").as_bytes()), Some(255));
        for bad in ["db=0", "db=256", "db=3,4", "db=3-5", "alldbs", "", "db=x"] {
            assert_eq!(parse_user_database(reply(bad).as_bytes()), None, "{bad}");
        }
        assert_eq!(parse_user_database(b"\n"), None, "a missing user");
        assert_eq!(parse_user_database(b""), None);
        assert_eq!(
            parse_user_database(b"flags\non\n"),
            None,
            "no databases section"
        );
    }

    #[test]
    fn provisioning_creates_the_user_saves_it_and_returns_the_password_once() {
        let fx = Fixture::new();
        let request = provisioning("a.test", 7, ID, "key-1");
        let Provisioned::New(result) =
            provision(&fx.context(), &request, &CancellationToken::default()).unwrap()
        else {
            panic!("expected a new result");
        };
        let calls = fx.calls();
        assert_eq!(calls.len(), 2);
        assert!(calls[0].starts_with(
            "exec valkey-9 sh /etc/valkey/wcp-valkey-cli.sh ACL SETUSER site_a.test reset on #"
        ));
        assert!(calls[0].contains(" db=7 "));
        assert_eq!(
            calls[1],
            "exec valkey-9 sh /etc/valkey/wcp-valkey-cli.sh ACL SAVE"
        );

        let response = result.public_value().unwrap();
        assert_eq!(response["username"], "site_a.test");
        assert_eq!(response["database"], 7);
        // The password is in the secret half only; Valkey got just its hash.
        let secret = (*result).into_response_value().unwrap();
        let password = secret["password"].as_str().unwrap().to_owned();
        assert_eq!(password.len(), PASSWORD_LEN);
        assert!(calls.iter().all(|call| !call.contains(&password)));
        assert!(calls[0].contains(&sha256_hex(&password)));
        assert!(
            !fx.state_text().contains(&password),
            "the password is never stored"
        );
    }

    #[test]
    fn provisioning_without_a_database_is_refused_before_anything_runs() {
        let fx = Fixture::new();
        let request = SiteRequest::parse(&plan("a.test"), ID, Some("key-1")).unwrap();
        let result = provision(&fx.context(), &request, &CancellationToken::default());
        assert!(matches!(result, Err(Error::MissingDatabase)));
        assert!(fx.calls().is_empty());
    }

    #[test]
    fn a_replay_returns_the_public_record_and_no_password_and_runs_nothing() {
        let fx = Fixture::new();
        provision(
            &fx.context(),
            &provisioning("a.test", 7, ID, "key-1"),
            &CancellationToken::default(),
        )
        .unwrap();
        let again = provisioning("a.test", 7, ID2, "key-1");
        match provision(&fx.context(), &again, &CancellationToken::default()).unwrap() {
            Provisioned::AlreadyIssued(public) => {
                assert_eq!(public["username"], "site_a.test");
                assert!(public.get("password").is_none());
            }
            Provisioned::New(_) => panic!("a replay must not issue a new password"),
        }
        assert_eq!(fx.calls().len(), 2, "no second ACL SETUSER");
    }

    #[test]
    fn a_new_request_rotates_the_password() {
        let fx = Fixture::new();
        for (id, key) in [(ID, "key-1"), (ID2, "key-2")] {
            provision(
                &fx.context(),
                &provisioning("a.test", 7, id, key),
                &CancellationToken::default(),
            )
            .unwrap();
        }
        let calls = fx.calls();
        let set: Vec<&String> = calls.iter().filter(|c| c.contains("SETUSER")).collect();
        assert_eq!(set.len(), 2);
        assert_ne!(set[0], set[1], "a different hash each time");
    }

    #[test]
    fn a_rejected_step_fails_the_request_and_returns_no_secret() {
        for marker in ["REJECT_SETUSER", "REJECT_SAVE"] {
            let fx = Fixture::new();
            fx.mark(marker, "");
            let result = provision(
                &fx.context(),
                &provisioning("a.test", 7, ID, "key-1"),
                &CancellationToken::default(),
            );
            assert!(matches!(result, Err(Error::Rejected(_))), "{marker}");
        }
    }

    #[test]
    fn flushing_empties_the_database_the_user_is_limited_to_and_no_other() {
        let fx = Fixture::new();
        fx.mark("USER_DB", "db=12");
        fx.mark("DBSIZE_REPLY", "42\n");
        let result = flush(
            &fx.context(),
            &req("a.test", ID, None),
            &CancellationToken::default(),
        )
        .unwrap();
        assert_eq!((result.database, result.keys_removed), (12, 42));
        let calls = fx.calls();
        assert_eq!(calls.len(), 3);
        assert!(calls[0].ends_with("ACL GETUSER site_a.test"));
        assert!(calls[1].ends_with("-n 12 DBSIZE"));
        assert!(calls[2].ends_with("-n 12 FLUSHDB ASYNC"));
        assert!(
            calls.iter().all(|c| !c.contains("FLUSHALL")),
            "never the whole instance"
        );
    }

    #[test]
    fn a_request_cannot_aim_a_flush_at_another_database() {
        // A caller-supplied number is ignored: the user's own database is used.
        let fx = Fixture::new();
        fx.mark("USER_DB", "db=5");
        let request = SiteRequest::parse(&plan_with_database("a.test", 9), ID, None).unwrap();
        let result = flush(&fx.context(), &request, &CancellationToken::default()).unwrap();
        assert_eq!(result.database, 5);
        assert!(fx.calls().iter().all(|c| !c.contains("-n 9")));
    }

    #[test]
    fn flushing_a_site_without_a_user_is_an_error_and_touches_nothing() {
        let fx = Fixture::new();
        fx.mark("NO_USER", "");
        let result = flush(
            &fx.context(),
            &req("a.test", ID, None),
            &CancellationToken::default(),
        );
        assert!(matches!(result, Err(Error::NotProvisioned)));
        assert_eq!(fx.calls().len(), 1, "only the lookup ran");
    }

    #[test]
    fn a_user_limited_to_several_databases_is_not_flushed() {
        let fx = Fixture::new();
        fx.mark("USER_DB", "db=3,4");
        let result = flush(
            &fx.context(),
            &req("a.test", ID, None),
            &CancellationToken::default(),
        );
        assert!(matches!(result, Err(Error::NotProvisioned)));
        assert_eq!(fx.calls().len(), 1);
    }

    #[test]
    fn revoking_empties_the_database_then_removes_the_user_then_saves() {
        let fx = Fixture::new();
        let result = revoke(
            &fx.context(),
            &req("a.test", ID, None),
            &CancellationToken::default(),
        )
        .unwrap();
        assert!(result.revoked);
        assert_eq!(result.keys_removed, 3);
        let calls = fx.calls();
        assert_eq!(calls.len(), 5);
        assert!(calls[0].ends_with("ACL GETUSER site_a.test"));
        assert!(calls[2].ends_with("-n 7 FLUSHDB ASYNC"));
        assert!(calls[3].ends_with("ACL DELUSER site_a.test"));
        assert!(calls[4].ends_with("ACL SAVE"));
    }

    #[test]
    fn revoking_a_site_that_has_no_user_still_succeeds_and_flushes_nothing() {
        let fx = Fixture::new();
        fx.mark("NO_USER", "");
        fx.mark("DELUSER_REPLY", "0\n");
        let result = revoke(
            &fx.context(),
            &req("a.test", ID, None),
            &CancellationToken::default(),
        )
        .unwrap();
        assert!(!result.revoked);
        assert_eq!(result.keys_removed, 0);
        assert!(fx.calls().iter().all(|c| !c.contains("FLUSHDB")));
    }

    #[test]
    fn an_unexpected_answer_is_an_error_not_a_guess() {
        let fx = Fixture::new();
        fx.mark("DBSIZE_REPLY", "not a number\n");
        let result = flush(
            &fx.context(),
            &req("a.test", ID, None),
            &CancellationToken::default(),
        );
        assert!(matches!(result, Err(Error::MalformedOutput)));
    }

    #[test]
    fn passwords_are_random_alphanumeric_and_not_repeated() {
        let a = new_password().unwrap();
        let b = new_password().unwrap();
        assert_eq!(a.len(), PASSWORD_LEN);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_ne!(a, b);
    }
}
