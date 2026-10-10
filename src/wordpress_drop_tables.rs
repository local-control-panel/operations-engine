//! Drops an explicit list of orphaned WordPress tables under one
//! lock/idempotency/transaction/audit-backed request. Replaces the idea of
//! the panel sending a raw `wp db query "DROP TABLE ..."`: the engine owns
//! the safety rules, so a table is only dropped when, at execution time, it
//! (a) carries the site's `table_prefix`, (b) still exists in a freshly read
//! `wp db tables --all-tables-with-prefix` listing, and (c) is *not* in the
//! set WordPress registers (`wp db tables --scope=all`, `--network` on a
//! multisite). Core and registered tables are therefore always refused, and
//! every name is checked for identifier syntax before it reaches SQL.
//! The result lists each requested table as `dropped` or `refused`
//! (with a reason); a retried request carrying the same idempotency key
//! replays that outcome instead of dropping again.

use crate::{
    db_restore::{ContainerName, RestoreRequestError},
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{
        self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination,
        SubprocessDiagnostics,
    },
    site::SiteRelativePath,
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        resource_lock,
        state::{self, TransactionStatus},
    },
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const OPERATION: &str = "wordpress.dropTables";

/// Upper bound on tables per request; a site rarely has more orphans and a
/// bound keeps the transaction record and the audit trail small.
const MAX_TABLES: usize = 200;
/// MariaDB identifier length limit.
const MAX_TABLE_NAME: usize = 64;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    container: String,
    root: String,
    uid: u32,
    gid: u32,
    tables: Vec<String>,
}

#[derive(Debug)]
pub struct Request {
    container: ContainerName,
    root: PathBuf,
    uid: u32,
    gid: u32,
    tables: Vec<String>,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    InvalidTables,
    InvalidRoot,
    InvalidContainer,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

fn valid_table_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_TABLE_NAME
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'$')
}

impl Request {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        let unique: BTreeSet<&String> = plan.tables.iter().collect();
        if plan.tables.is_empty()
            || plan.tables.len() > MAX_TABLES
            || unique.len() != plan.tables.len()
            || !plan.tables.iter().all(|name| valid_table_name(name))
        {
            return Err(RequestError::InvalidTables);
        }
        let root = PathBuf::from(plan.root);
        if !root.is_absolute()
            || root.as_os_str().len() > 4096
            || root
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(RequestError::InvalidRoot);
        }
        Ok(Self {
            container: ContainerName::parse(&plan.container)
                .map_err(|_: RestoreRequestError| RequestError::InvalidContainer)?,
            root,
            uid: plan.uid,
            gid: plan.gid,
            tables: plan.tables,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }

    pub fn root(&self) -> &std::path::Path {
        &self.root
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TableStatus {
    Dropped,
    Refused,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TableResult {
    pub name: String,
    pub status: TableStatus,
    /// Why a table was refused: `wrongPrefix`, `notFound`, `registered` or
    /// `dropFailed`. Absent for dropped tables.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DropTablesResult {
    pub tables: Vec<TableResult>,
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
    ResourceBusy,
    Cancelled,
    Run(process::ProcessRunError),
    Rejected(SubprocessDiagnostics),
    /// A read-only WP-CLI listing returned something unusable; nothing was
    /// dropped.
    UnexpectedListing(&'static str),
    PostCommit {
        result: DropTablesResult,
    },
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
                "another drop-tables operation for this site is in progress".into(),
            ),
            Self::ResourceBusy => (
                ErrorCode::Conflict,
                "another WordPress operation is already in progress for this site".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before the tables were dropped".into(),
            ),
            Self::Run(error) => (
                process::spawn_error_code(error),
                "could not run the WordPress table command".into(),
            ),
            Self::Rejected(diagnostics) => (
                if diagnostics.timed_out {
                    ErrorCode::Timeout
                } else if diagnostics.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::SubprocessFailed
                },
                "WordPress could not list the site's tables".into(),
            ),
            Self::UnexpectedListing(message) => (ErrorCode::SubprocessFailed, (*message).into()),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit { .. } => {
                (ErrorCode::Internal, "internal drop-tables error".into())
            }
        }
    }
}

struct WpRunner<'a> {
    ctx: &'a Context<'a>,
    req: &'a Request,
    cancel: &'a CancellationToken,
}

impl WpRunner<'_> {
    /// Runs one `wp ...` command as the site user and returns its stdout, or
    /// the diagnostics of a non-zero exit.
    fn run(&self, wp_args: &[String], limit: usize) -> Result<Vec<u8>, Error> {
        let mut args = vec![
            "exec".to_owned(),
            "-i".to_owned(),
            "--user".to_owned(),
            format!("{}:{}", self.req.uid, self.req.gid),
            self.req.container.as_str().to_owned(),
            "wp".to_owned(),
            format!("--path={}", self.req.root.display()),
            "--allow-root".to_owned(),
        ];
        args.extend(wp_args.iter().cloned());
        let output = process::run(
            &ProcessRequest::new(self.ctx.docker_program).args(args),
            &ProcessLimits {
                timeout: Duration::from_secs(2 * 60),
                max_stdout_bytes: limit,
                max_stderr_bytes: 64 * 1024,
            },
            self.cancel,
        )
        .map_err(Error::Run)?;
        if !matches!(
            output.termination,
            ProcessTermination::Exited { success: true, .. }
        ) {
            return Err(Error::Rejected(SubprocessDiagnostics::from_output(
                self.ctx.docker_program,
                &output,
            )));
        }
        if output.stdout.truncated {
            return Err(Error::UnexpectedListing("table listing was too large"));
        }
        Ok(output.stdout.bytes)
    }
}

fn names(bytes: &[u8]) -> BTreeSet<String> {
    String::from_utf8_lossy(bytes)
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|name| valid_table_name(name))
        .map(str::to_owned)
        .collect()
}

/// Pure decision for one requested table against the fresh listings.
fn decide(
    name: &str,
    prefix: &str,
    all_with_prefix: &BTreeSet<String>,
    registered: &BTreeSet<String>,
) -> Option<&'static str> {
    if !name.starts_with(prefix) {
        Some("wrongPrefix")
    } else if registered.contains(name) {
        Some("registered")
    } else if !all_with_prefix.contains(name) {
        Some("notFound")
    } else {
        None
    }
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<DropTablesResult, Error> {
    let hash = resource_lock::canonical_hash(&req.root);
    let scope_path = SiteRelativePath::parse(format!("wordpress-drop-tables/{hash}")).unwrap();
    ctx.engine_state
        .create_dir_all(&scope_path)
        .map_err(Error::Io)?;
    let scope = ctx
        .engine_state
        .open_managed_dir(&scope_path)
        .map_err(Error::Io)?;
    for child in ["locks", "transactions", "audit"] {
        scope
            .create_dir_all(&SiteRelativePath::parse(child).unwrap())
            .map_err(Error::Io)?;
    }
    let _resource_lock = resource_lock::acquire(ctx.engine_state, &req.root, req.request_id)
        .map_err(|_| Error::ResourceBusy)?;

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
    let state_path =
        SiteRelativePath::parse(format!("transactions/{}.json", req.request_id)).unwrap();
    let audit_path = SiteRelativePath::parse("audit/events.jsonl").unwrap();

    if cancel.is_cancelled() {
        return Err(fail(
            &scope,
            &state_path,
            &audit_path,
            state,
            Error::Cancelled,
        ));
    }

    let outcome = drop_tables(ctx, req, cancel);
    let tables = match outcome {
        Ok(tables) => tables,
        Err(error) => return Err(fail(&scope, &state_path, &audit_path, state, error)),
    };

    let result = DropTablesResult {
        tables,
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

fn drop_tables(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<Vec<TableResult>, Error> {
    let wp = WpRunner { ctx, req, cancel };
    let multisite = wp
        .run(
            &[
                "config".into(),
                "get".into(),
                "MULTISITE".into(),
                "--format=json".into(),
            ],
            4 * 1024,
        )
        .map(|bytes| String::from_utf8_lossy(&bytes).trim() == "true")
        // An undefined MULTISITE constant makes `wp config get` fail.
        .unwrap_or(false);
    let prefix_bytes = wp.run(
        &["config".into(), "get".into(), "table_prefix".into()],
        4 * 1024,
    )?;
    let prefix = String::from_utf8_lossy(&prefix_bytes).trim().to_owned();
    if prefix.is_empty() || !valid_table_name(&prefix) {
        return Err(Error::UnexpectedListing(
            "could not determine the table prefix",
        ));
    }
    let all = names(&wp.run(
        &[
            "db".into(),
            "tables".into(),
            "--all-tables-with-prefix".into(),
        ],
        1024 * 1024,
    )?);
    let mut registered_args = vec!["db".into(), "tables".into(), "--scope=all".into()];
    if multisite {
        registered_args.push("--network".into());
    }
    let registered = names(&wp.run(&registered_args, 1024 * 1024)?);
    // A registered listing that does not even contain the core options
    // table means the read was wrong; with it empty every table would look
    // orphaned, so refuse to proceed rather than guess.
    if !registered.contains(&format!("{prefix}options")) {
        return Err(Error::UnexpectedListing(
            "registered table listing is incomplete",
        ));
    }

    let mut results = Vec::with_capacity(req.tables.len());
    for name in &req.tables {
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        if let Some(reason) = decide(name, &prefix, &all, &registered) {
            results.push(TableResult {
                name: name.clone(),
                status: TableStatus::Refused,
                reason: Some(reason.into()),
            });
            continue;
        }
        // `name` passed `valid_table_name`, so backtick quoting is safe.
        let sql = format!("DROP TABLE IF EXISTS `{name}`");
        match wp.run(&["db".into(), "query".into(), sql], 64 * 1024) {
            Ok(_) => results.push(TableResult {
                name: name.clone(),
                status: TableStatus::Dropped,
                reason: None,
            }),
            Err(Error::Cancelled) => return Err(Error::Cancelled),
            Err(_) => results.push(TableResult {
                name: name.clone(),
                status: TableStatus::Refused,
                reason: Some("dropFailed".into()),
            }),
        }
    }
    Ok(results)
}

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<DropTablesResult, Error> {
    let path = SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap();
    let loaded = state::load(scope, &path)
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const ID2: &str = "123e4567-e89b-12d3-a456-426614174001";

    fn managed(directory: &std::path::Path) -> ManagedRoot {
        ManagedRoot::open(&crate::site::TrustedRoot::parse(directory).unwrap()).unwrap()
    }

    fn request(tables: &str, id: &str, key: Option<&str>) -> Request {
        Request::parse(
            &format!(
                r#"{{"container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1000,"tables":{tables}}}"#
            ),
            id,
            key,
        )
        .unwrap()
    }

    /// A stand-in for `docker exec ... wp ...` that answers the listing
    /// commands and records every `db query` it receives.
    fn fake_docker(directory: &std::path::Path, fail_drop: bool) -> String {
        let log = directory.join("queries.log");
        let path = directory.join("fake-docker");
        let drop_exit = if fail_drop { 1 } else { 0 };
        fs::write(
            &path,
            format!(
                r#"#!/bin/sh
case "$*" in
  *"config get MULTISITE"*) echo false ;;
  *"config get table_prefix"*) echo wp_ ;;
  *"--all-tables-with-prefix"*) printf 'wp_options\nwp_posts\nwp_old_plugin\nwp_extra\n' ;;
  *"db tables --scope=all"*) printf 'wp_options\nwp_posts\n' ;;
  *"db query"*) printf '%s\n' "$*" >> '{}'; exit {} ;;
esac
exit 0
"#,
                log.display(),
                drop_exit
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn rejects_invalid_plans() {
        for bad in [
            "[]",
            r#"["wp_a","wp_a"]"#,
            r#"["wp_a; DROP TABLE x"]"#,
            r#"["wp_`a"]"#,
            r#"[""]"#,
        ] {
            assert_eq!(
                Request::parse(
                    &format!(
                        r#"{{"container":"runtime-1","root":"/var/www/site","uid":1,"gid":1,"tables":{bad}}}"#
                    ),
                    ID,
                    None
                )
                .unwrap_err(),
                RequestError::InvalidTables,
                "{bad}"
            );
        }
        assert_eq!(
            Request::parse(
                r#"{"container":"runtime-1","root":"../escape","uid":1,"gid":1,"tables":["wp_a"]}"#,
                ID,
                None
            )
            .unwrap_err(),
            RequestError::InvalidRoot
        );
    }

    #[test]
    fn decide_refuses_core_registered_foreign_and_missing_tables() {
        let all: BTreeSet<String> = ["wp_options", "wp_x"].map(String::from).into();
        let registered: BTreeSet<String> = ["wp_options"].map(String::from).into();
        assert_eq!(
            decide("wp_options", "wp_", &all, &registered),
            Some("registered")
        );
        assert_eq!(
            decide("other_x", "wp_", &all, &registered),
            Some("wrongPrefix")
        );
        assert_eq!(
            decide("wp_gone", "wp_", &all, &registered),
            Some("notFound")
        );
        assert_eq!(decide("wp_x", "wp_", &all, &registered), None);
    }

    #[test]
    fn drops_only_orphans_and_replays() {
        let state_dir = tempfile::tempdir().unwrap();
        let docker = fake_docker(state_dir.path(), false);
        let state = managed(state_dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };
        let req = request(
            r#"["wp_old_plugin","wp_posts","wp_nope","foreign_t"]"#,
            ID,
            Some("drop-tables-key"),
        );

        let first = execute(&ctx, &req, &CancellationToken::default()).unwrap();
        let by_name = |n: &str| first.tables.iter().find(|t| t.name == n).unwrap();
        assert_eq!(by_name("wp_old_plugin").status, TableStatus::Dropped);
        assert_eq!(by_name("wp_posts").reason.as_deref(), Some("registered"));
        assert_eq!(by_name("wp_nope").reason.as_deref(), Some("notFound"));
        assert_eq!(by_name("foreign_t").reason.as_deref(), Some("wrongPrefix"));

        let log = fs::read_to_string(state_dir.path().join("queries.log")).unwrap();
        assert_eq!(log.lines().count(), 1, "{log}");
        assert!(log.contains("DROP TABLE IF EXISTS `wp_old_plugin`"));

        // Same key + same request: replayed, no second DROP.
        let second = execute(&ctx, &req, &CancellationToken::default()).unwrap();
        assert_eq!(first.completed_at_unix_secs, second.completed_at_unix_secs);
        let log = fs::read_to_string(state_dir.path().join("queries.log")).unwrap();
        assert_eq!(log.lines().count(), 1);
    }

    #[test]
    fn a_failing_drop_is_reported_per_table() {
        let state_dir = tempfile::tempdir().unwrap();
        let docker = fake_docker(state_dir.path(), true);
        let state = managed(state_dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };
        let req = request(r#"["wp_extra"]"#, ID2, None);
        let result = execute(&ctx, &req, &CancellationToken::default()).unwrap();
        assert_eq!(result.tables[0].status, TableStatus::Refused);
        assert_eq!(result.tables[0].reason.as_deref(), Some("dropFailed"));
    }

    #[test]
    fn an_incomplete_registered_listing_aborts_without_dropping() {
        let state_dir = tempfile::tempdir().unwrap();
        let path = state_dir.path().join("fake-docker");
        fs::write(
            &path,
            "#!/bin/sh\ncase \"$*\" in\n  *\"config get table_prefix\"*) echo wp_ ;;\n  *\"--all-tables-with-prefix\"*) echo wp_x ;;\nesac\nexit 0\n",
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        let docker = path.to_string_lossy().into_owned();
        let state = managed(state_dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };
        let req = request(r#"["wp_x"]"#, ID, None);
        assert!(matches!(
            execute(&ctx, &req, &CancellationToken::default()),
            Err(Error::UnexpectedListing(_))
        ));
    }

    /// Real-host check against a live WP-CLI container; run manually with
    /// `WCP_DROP_TABLES_E2E_CONTAINER=<name> WCP_DROP_TABLES_E2E_ROOT=<wp root>
    /// WCP_DROP_TABLES_E2E_UID=<uid> cargo test -- --ignored drop_tables_e2e`.
    /// The site must already contain `{prefix}orphan_a` and `{prefix}orphan_b`.
    #[test]
    #[ignore = "needs a live WordPress container"]
    fn drop_tables_e2e() {
        let (Ok(container), Ok(root), Ok(uid)) = (
            std::env::var("WCP_DROP_TABLES_E2E_CONTAINER"),
            std::env::var("WCP_DROP_TABLES_E2E_ROOT"),
            std::env::var("WCP_DROP_TABLES_E2E_UID"),
        ) else {
            return;
        };
        let docker = std::env::var("WCP_DROP_TABLES_E2E_DOCKER").unwrap_or("docker".into());
        let state_dir = tempfile::tempdir().unwrap();
        let state = managed(state_dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };
        let req = Request::parse(
            &format!(
                r#"{{"container":"{container}","root":"{root}","uid":{uid},"gid":{uid},"tables":["wp_orphan_a","wp_options","wp_orphan_b","wp_missing","other_orphan"]}}"#
            ),
            ID,
            Some("e2e-drop-key"),
        )
        .unwrap();
        let result = execute(&ctx, &req, &CancellationToken::default()).unwrap();
        println!("{result:#?}");
        let status = |n: &str| result.tables.iter().find(|t| t.name == n).unwrap().status;
        assert_eq!(status("wp_orphan_a"), TableStatus::Dropped);
        assert_eq!(status("wp_orphan_b"), TableStatus::Dropped);
        assert_eq!(status("wp_options"), TableStatus::Refused);
        assert_eq!(status("wp_missing"), TableStatus::Refused);
        assert_eq!(status("other_orphan"), TableStatus::Refused);
        let again = execute(&ctx, &req, &CancellationToken::default()).unwrap();
        assert_eq!(again.completed_at_unix_secs, result.completed_at_unix_secs);
    }
}
