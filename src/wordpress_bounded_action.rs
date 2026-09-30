//! The `wordpress.boundedAction` operation: a small, fixed set of one-shot
//! WordPress mutations that each previously ran as an unvalidated raw
//! `docker exec ... wp ...` call from `website-control-panel` - creating a
//! subsite in a multisite network, flipping a multisite network between
//! subdomain and subdirectory mode, and clearing all WooCommerce
//! transients. None of the three has enough independent shape to justify
//! its own operation module (unlike, say, `wordpress.multisiteDeleteSite`,
//! which has a real destructive-boundary invariant to enforce on `blogId`),
//! so they share one lock/idempotency/transaction/audit-backed request with
//! an internal `action.kind` discriminator instead. A future bounded action
//! with its own nontrivial validation or recovery story should get its own
//! operation module rather than growing the match arm here.

use crate::{
    db_restore::{ContainerName, RestoreRequestError},
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{
        self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination,
        SubprocessDiagnostics,
    },
    site::{Domain, SiteRelativePath},
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

pub const OPERATION: &str = "wordpress.boundedAction";

const MAX_TITLE_BYTES: usize = 200;
const MAX_EMAIL_BYTES: usize = 254;
/// A subdirectory-network slug becomes both a URL path segment and a
/// filesystem directory name; bounded to the same per-label length WP-CLI's
/// own multisite defaults tolerate comfortably.
const MAX_SLUG_BYTES: usize = 63;
const STEP_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_STEP_OUTPUT_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    container: String,
    root: String,
    uid: u32,
    gid: u32,
    action: ActionPlan,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
enum ActionPlan {
    MultisiteCreateSite {
        title: String,
        email: String,
        slug: Option<String>,
        url: Option<String>,
    },
    MultisiteSetMode {
        subdomain: bool,
    },
    WooClearTransients {},
}

#[derive(Clone, Debug)]
enum Action {
    MultisiteCreateSite {
        title: String,
        email: String,
        target: CreateSiteTarget,
    },
    MultisiteSetMode {
        subdomain: bool,
    },
    WooClearTransients,
}

#[derive(Clone, Debug)]
enum CreateSiteTarget {
    Slug(String),
    Url(Domain),
}

#[derive(Debug)]
pub struct Request {
    container: ContainerName,
    root: PathBuf,
    uid: u32,
    gid: u32,
    action: Action,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    InvalidRoot,
    InvalidContainer,
    InvalidRequestId,
    InvalidIdempotencyKey,
    InvalidAction,
}

/// A permissive structural email check - one `@`, non-empty local/domain
/// parts, no whitespace or NUL - not a full RFC 5322 validator. `wp site
/// create` itself is the authority on whether the address is actually
/// usable; this only keeps obviously-malformed input from ever reaching
/// argv.
fn validate_email(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_EMAIL_BYTES
        || value.bytes().any(|b| b == 0 || b.is_ascii_whitespace())
    {
        return false;
    }
    let mut parts = value.splitn(2, '@');
    matches!(
        (parts.next(), parts.next()),
        (Some(local), Some(domain))
            if !local.is_empty() && !domain.is_empty() && !domain.contains('@')
    )
}

fn validate_title(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TITLE_BYTES && !value.bytes().any(|b| b == 0)
}

/// Lowercase ASCII letters, digits, or hyphens; never starting or ending
/// with a hyphen; 1-63 bytes - the same per-label character class
/// `site::Domain` enforces. This is what rejects a slug such as `--evil`,
/// which is otherwise a plausible-looking bare word: leading `-` is exactly
/// the byte this excludes, closing off any confusion with a WP-CLI flag
/// even though the slug is always passed as one `--slug=<value>` argv
/// element rather than a bare word.
fn validate_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SLUG_BYTES
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl ActionPlan {
    fn validate(self) -> Result<Action, RequestError> {
        match self {
            Self::MultisiteCreateSite {
                title,
                email,
                slug,
                url,
            } => {
                if !validate_title(&title) || !validate_email(&email) {
                    return Err(RequestError::InvalidAction);
                }
                let target = match (slug, url) {
                    (Some(slug), None) if validate_slug(&slug) => CreateSiteTarget::Slug(slug),
                    (None, Some(url)) => CreateSiteTarget::Url(
                        Domain::parse(&url).map_err(|_| RequestError::InvalidAction)?,
                    ),
                    _ => return Err(RequestError::InvalidAction),
                };
                Ok(Action::MultisiteCreateSite {
                    title,
                    email,
                    target,
                })
            }
            Self::MultisiteSetMode { subdomain } => Ok(Action::MultisiteSetMode { subdomain }),
            Self::WooClearTransients {} => Ok(Action::WooClearTransients),
        }
    }
}

impl Request {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        let root = PathBuf::from(plan.root);
        if !root.is_absolute()
            || root.as_os_str().len() > 4096
            || root
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(RequestError::InvalidRoot);
        }
        let action = plan.action.validate()?;
        Ok(Self {
            container: ContainerName::parse(&plan.container)
                .map_err(|_: RestoreRequestError| RequestError::InvalidContainer)?,
            root,
            uid: plan.uid,
            gid: plan.gid,
            action,
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

    fn argv(&self) -> Vec<String> {
        let mut args = vec![
            "exec".to_owned(),
            "-i".to_owned(),
            "--user".to_owned(),
            format!("{}:{}", self.uid, self.gid),
            self.container.as_str().to_owned(),
            "wp".to_owned(),
            format!("--path={}", self.root.display()),
            "--allow-root".to_owned(),
        ];
        match &self.action {
            Action::MultisiteCreateSite {
                title,
                email,
                target,
            } => {
                args.push("site".to_owned());
                args.push("create".to_owned());
                match target {
                    CreateSiteTarget::Slug(slug) => args.push(format!("--slug={slug}")),
                    CreateSiteTarget::Url(url) => args.push(format!("--url={url}")),
                }
                args.push(format!("--title={title}"));
                args.push(format!("--email={email}"));
            }
            Action::MultisiteSetMode { subdomain } => {
                args.push("config".to_owned());
                args.push("set".to_owned());
                args.push("SUBDOMAIN_INSTALL".to_owned());
                args.push(if *subdomain { "1" } else { "0" }.to_owned());
                args.push("--raw".to_owned());
            }
            Action::WooClearTransients => {
                args.push("transient".to_owned());
                args.push("delete".to_owned());
                args.push("--all".to_owned());
            }
        }
        args
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BoundedActionResult {
    pub output: String,
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
    TooLarge,
    InvalidUtf8,
    PostCommit { result: BoundedActionResult },
    Replayed { code: ErrorCode, message: String },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another WordPress bounded action for this site is in progress".into(),
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
                "cancelled before the bounded action ran".into(),
            ),
            Self::Run(error) => (
                process::spawn_error_code(error),
                "could not run the WordPress bounded action".into(),
            ),
            Self::Rejected(diagnostics) => (
                if diagnostics.timed_out {
                    ErrorCode::Timeout
                } else if diagnostics.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::SubprocessFailed
                },
                "WordPress rejected the bounded action".into(),
            ),
            Self::TooLarge => (
                ErrorCode::Internal,
                "WordPress bounded action output exceeded its limit".into(),
            ),
            Self::InvalidUtf8 => (
                ErrorCode::Internal,
                "WordPress bounded action output was not valid UTF-8".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit { .. } => (
                ErrorCode::Internal,
                "internal WordPress bounded action error".into(),
            ),
        }
    }
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<BoundedActionResult, Error> {
    let hash = resource_lock::canonical_hash(&req.root);
    let scope_path = SiteRelativePath::parse(format!("wordpress-bounded-action/{hash}")).unwrap();
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

    let output = match process::run(
        &ProcessRequest::new(ctx.docker_program).args(req.argv()),
        &ProcessLimits {
            timeout: STEP_TIMEOUT,
            max_stdout_bytes: MAX_STEP_OUTPUT_BYTES,
            max_stderr_bytes: MAX_STEP_OUTPUT_BYTES,
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
    if output.stdout.truncated || output.stderr.truncated {
        return Err(fail(
            &scope,
            &state_path,
            &audit_path,
            state,
            Error::TooLarge,
        ));
    }
    let bytes = if output.stdout.bytes.is_empty() {
        output.stderr.bytes
    } else {
        output.stdout.bytes
    };
    let output = match String::from_utf8(bytes) {
        Ok(value) => value,
        Err(_) => {
            return Err(fail(
                &scope,
                &state_path,
                &audit_path,
                state,
                Error::InvalidUtf8,
            ));
        }
    };

    let result = BoundedActionResult {
        output,
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

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<BoundedActionResult, Error> {
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
    fn rejects_a_slug_that_looks_like_a_flag() {
        assert_eq!(
            Request::parse(
                r#"{"container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1000,
                    "action":{"kind":"multisiteCreateSite","title":"T","email":"a@b.com","slug":"--evil"}}"#,
                ID,
                None,
            )
            .unwrap_err(),
            RequestError::InvalidAction
        );
    }

    #[test]
    fn rejects_both_slug_and_url_or_neither() {
        assert_eq!(
            Request::parse(
                r#"{"container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1000,
                    "action":{"kind":"multisiteCreateSite","title":"T","email":"a@b.com"}}"#,
                ID,
                None,
            )
            .unwrap_err(),
            RequestError::InvalidAction
        );
        assert_eq!(
            Request::parse(
                r#"{"container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1000,
                    "action":{"kind":"multisiteCreateSite","title":"T","email":"a@b.com",
                    "slug":"news","url":"news.example.com"}}"#,
                ID,
                None,
            )
            .unwrap_err(),
            RequestError::InvalidAction
        );
    }

    #[test]
    fn rejects_a_malformed_email_and_an_escaping_root() {
        assert_eq!(
            Request::parse(
                r#"{"container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1000,
                    "action":{"kind":"multisiteCreateSite","title":"T","email":"not-an-email","slug":"news"}}"#,
                ID,
                None,
            )
            .unwrap_err(),
            RequestError::InvalidAction
        );
        assert_eq!(
            Request::parse(
                r#"{"container":"runtime-1","root":"../escape","uid":1000,"gid":1000,
                    "action":{"kind":"wooClearTransients"}}"#,
                ID,
                None,
            )
            .unwrap_err(),
            RequestError::InvalidRoot
        );
    }

    #[test]
    fn creates_a_site_by_slug_then_replays() {
        let state_dir = tempfile::tempdir().unwrap();
        let docker = fake_docker(state_dir.path(), 0);
        let state = managed(state_dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };
        let req = Request::parse(
            r#"{"container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1000,
                "action":{"kind":"multisiteCreateSite","title":"News","email":"a@b.com","slug":"news"}}"#,
            ID,
            Some("create-key"),
        )
        .unwrap();

        let first = execute(&ctx, &req, &CancellationToken::default()).unwrap();
        let second = execute(&ctx, &req, &CancellationToken::default()).unwrap();
        assert!(first.output.contains("--slug=news"));
        assert!(first.output.contains("--title=News"));
        assert!(first.output.contains("--email=a@b.com"));
        assert_eq!(first.completed_at_unix_secs, second.completed_at_unix_secs);
    }

    #[test]
    fn sets_multisite_mode() {
        let state_dir = tempfile::tempdir().unwrap();
        let docker = fake_docker(state_dir.path(), 0);
        let state = managed(state_dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };
        let req = Request::parse(
            r#"{"container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1000,
                "action":{"kind":"multisiteSetMode","subdomain":true}}"#,
            ID,
            None,
        )
        .unwrap();

        let result = execute(&ctx, &req, &CancellationToken::default()).unwrap();
        assert!(result.output.contains("SUBDOMAIN_INSTALL"));
        assert!(result.output.contains("--raw"));
        let lines: Vec<_> = result.output.lines().collect();
        assert_eq!(lines[lines.len() - 2], "1");
    }

    #[test]
    fn clears_woocommerce_transients() {
        let state_dir = tempfile::tempdir().unwrap();
        let docker = fake_docker(state_dir.path(), 0);
        let state = managed(state_dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };
        let req = Request::parse(
            r#"{"container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1000,
                "action":{"kind":"wooClearTransients"}}"#,
            ID,
            None,
        )
        .unwrap();

        let result = execute(&ctx, &req, &CancellationToken::default()).unwrap();
        assert!(result.output.contains("transient"));
        assert!(result.output.contains("delete"));
        assert!(result.output.contains("--all"));
    }

    #[test]
    fn a_rejected_action_is_reported_and_can_be_retried() {
        let state_dir = tempfile::tempdir().unwrap();
        let docker = fake_docker(state_dir.path(), 1);
        let state = managed(state_dir.path());
        let ctx = Context {
            engine_state: &state,
            docker_program: &docker,
        };
        let req = Request::parse(
            r#"{"container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1000,
                "action":{"kind":"wooClearTransients"}}"#,
            ID,
            None,
        )
        .unwrap();

        let result = execute(&ctx, &req, &CancellationToken::default());
        assert!(matches!(result, Err(Error::Rejected(_))));
    }
}
