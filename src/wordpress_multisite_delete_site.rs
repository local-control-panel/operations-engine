//! Deletes one subsite from a WordPress multisite network
//! (`wp site delete <id> --yes`) under one lock/idempotency/transaction/
//! audit-backed request. Replaces the panel's raw, unvalidated
//! `docker exec ... wp site delete {blog_id} --yes` call, which accepted
//! any `i64` including `1` (the network's own primary site, never a valid
//! deletion target) and had no idempotency story: a lost response left the
//! caller unable to tell whether the delete happened without re-running it
//! and risking a confusing "site not found" WP-CLI error on the retry.
//! This operation cannot make the underlying WP-CLI delete itself
//! idempotent — a real second delete of an already-gone site is still a WP-
//! CLI failure — but a retried request carrying the *same* idempotency key
//! now replays the original outcome instead of re-issuing the call.

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
use serde::Deserialize;
use std::{
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const OPERATION: &str = "wordpress.multisiteDeleteSite";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    container: String,
    root: String,
    uid: u32,
    gid: u32,
    blog_id: u32,
}

#[derive(Debug)]
pub struct Request {
    container: ContainerName,
    root: PathBuf,
    uid: u32,
    gid: u32,
    blog_id: u32,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    InvalidBlogId,
    InvalidRoot,
    InvalidContainer,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl Request {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        // Blog ID 1 is always the network's own primary site; a multisite
        // "delete a subsite" action can never legitimately target it.
        if plan.blog_id <= 1 {
            return Err(RequestError::InvalidBlogId);
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
            blog_id: plan.blog_id,
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

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteSiteResult {
    pub blog_id: u32,
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
    PostCommit { result: DeleteSiteResult },
    Replayed { code: ErrorCode, message: String },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another multisite operation for this site is in progress".into(),
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
                "cancelled before the subsite was deleted".into(),
            ),
            Self::Run(error) => (
                process::spawn_error_code(error),
                "could not run the multisite delete command".into(),
            ),
            Self::Rejected(diagnostics) => (
                if diagnostics.timed_out {
                    ErrorCode::Timeout
                } else if diagnostics.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::SubprocessFailed
                },
                "WordPress rejected the multisite delete".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit { .. } => (
                ErrorCode::Internal,
                "internal multisite delete error".into(),
            ),
        }
    }
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<DeleteSiteResult, Error> {
    let hash = resource_lock::canonical_hash(&req.root);
    let scope_path =
        SiteRelativePath::parse(format!("wordpress-multisite-delete-site/{hash}")).unwrap();
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

    let args = [
        "exec".to_owned(),
        "-i".to_owned(),
        "--user".to_owned(),
        format!("{}:{}", req.uid, req.gid),
        req.container.as_str().to_owned(),
        "wp".to_owned(),
        format!("--path={}", req.root.display()),
        "--allow-root".to_owned(),
        "site".to_owned(),
        "delete".to_owned(),
        req.blog_id.to_string(),
        "--yes".to_owned(),
    ];
    let output = match process::run(
        &ProcessRequest::new(ctx.docker_program).args(args),
        &ProcessLimits {
            timeout: Duration::from_secs(5 * 60),
            max_stdout_bytes: 64 * 1024,
            max_stderr_bytes: 64 * 1024,
        },
        cancel,
    ) {
        Ok(value) => value,
        Err(error) => {
            return Err(fail(
                &scope,
                &state_path,
                &audit_path,
                state,
                Error::Run(error),
            ));
        }
    };
    if !matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        return Err(fail(
            &scope,
            &state_path,
            &audit_path,
            state,
            Error::Rejected(SubprocessDiagnostics::from_output(
                ctx.docker_program,
                &output,
            )),
        ));
    }

    let result = DeleteSiteResult {
        blog_id: req.blog_id,
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

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<DeleteSiteResult, Error> {
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

    fn managed(directory: &std::path::Path) -> ManagedRoot {
        ManagedRoot::open(&crate::site::TrustedRoot::parse(directory).unwrap()).unwrap()
    }

    fn request(root: &str, id: &str, key: Option<&str>) -> Request {
        Request::parse(
            &format!(
                r#"{{"container":"runtime-1","root":"{root}","uid":1000,"gid":1000,"blogId":3}}"#
            ),
            id,
            key,
        )
        .unwrap()
    }

    fn fake_docker(directory: &std::path::Path, exit: i32) -> String {
        let path = directory.join("fake-docker");
        fs::write(
            &path,
            format!("#!/bin/sh\nprintf '%s\\n' \"$@\"\nexit {exit}\n"),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn rejects_blog_id_one_and_other_invalid_plans() {
        assert_eq!(
            Request::parse(
                r#"{"container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1000,"blogId":1}"#,
                ID,
                None,
            )
            .unwrap_err(),
            RequestError::InvalidBlogId
        );
        assert_eq!(
            Request::parse(
                r#"{"container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1000,"blogId":0}"#,
                ID,
                None,
            )
            .unwrap_err(),
            RequestError::InvalidBlogId
        );
        assert_eq!(
            Request::parse(
                r#"{"container":"runtime-1","root":"../escape","uid":1000,"gid":1000,"blogId":2}"#,
                ID,
                None,
            )
            .unwrap_err(),
            RequestError::InvalidRoot
        );
    }

    #[test]
    fn deletes_the_subsite_then_replays() {
        let state_dir = tempfile::tempdir().unwrap();
        let docker = fake_docker(state_dir.path(), 0);
        let state = managed(state_dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };
        let req = request("/var/www/site", ID, Some("multisite-delete-key"));

        let first = execute(&ctx, &req, &CancellationToken::default()).unwrap();
        let second = execute(&ctx, &req, &CancellationToken::default()).unwrap();
        assert_eq!(first.blog_id, 3);
        assert_eq!(first.completed_at_unix_secs, second.completed_at_unix_secs);
    }

    #[test]
    fn a_rejected_delete_is_reported_and_can_be_retried() {
        let state_dir = tempfile::tempdir().unwrap();
        let docker = fake_docker(state_dir.path(), 1);
        let state = managed(state_dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };
        let req = request("/var/www/site", ID, None);

        let result = execute(&ctx, &req, &CancellationToken::default());
        assert!(matches!(result, Err(Error::Rejected(_))));
    }
}
