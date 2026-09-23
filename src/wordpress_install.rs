//! The `wordpress.install` operation: site-content half of standing up a new
//! WordPress site (`docs/site-model.md`'s trusted-root model, per-site
//! lock/idempotency/transaction/audit — the same shape as
//! `wordpress_update`). Database provisioning is deliberately out of scope
//! here: `website-control-panel`'s `wp_install` calls `db.provisionMariaDb`
//! itself before this operation runs, and passes the resulting credentials
//! in as plain fields.
//!
//! The site's own directory is *not* created (or removed on failure) by
//! this operation. By the time this runs, `website-control-panel`'s
//! `create_site` (`runtime_pool.rs`) has already created it, chowned it to
//! the site's own numeric UID/GID, and written its `.user.ini` — a
//! separate, still-raw-shell step this migration does not touch. This
//! operation only requires that the directory already exists beneath a
//! configured content root and does not escape it through a symlink
//! (`TrustedRoot::resolve_existing`); it never deletes that directory,
//! since it did not create it and doing so on a WP-CLI failure would
//! destroy `create_site`'s own prior work. See `PLAN.md`'s Phase 8 decision
//! log for why this deviates from this operation's original milestone doc.

use crate::{
    db_restore::{ContainerName, DatabaseName, RestoreRequestError},
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{
        self, CancellationToken, ProcessLimits, ProcessOutput, ProcessRequest, ProcessRunError,
    },
    site::{Domain, SiteRelativePath, TrustedRoot},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        state::{self, TransactionStatus},
    },
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fmt::Write as _,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const OPERATION: &str = "wordpress.install";

const MAX_TITLE_BYTES: usize = 200;
const MAX_ADMIN_USER_BYTES: usize = 60;
const MAX_ADMIN_PASSWORD_BYTES: usize = 256;
const MAX_EMAIL_BYTES: usize = 254;
const MAX_DB_PASSWORD_BYTES: usize = 256;
/// Fixed WP-CLI download timeout/output bounds shared by every step below -
/// generous enough for a full core download over a slow link, still a hard
/// ceiling.
const STEP_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_STEP_OUTPUT_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    container: String,
    root: String,
    uid: u32,
    gid: u32,
    domain: String,
    site_title: String,
    admin_user: String,
    admin_password: String,
    admin_email: String,
    db_name: String,
    db_user: String,
    db_password: String,
    db_host: String,
    cache_host: String,
}

pub struct Request {
    container: ContainerName,
    root: PathBuf,
    uid: u32,
    gid: u32,
    domain: Domain,
    site_title: String,
    admin_user: String,
    admin_password: String,
    admin_email: String,
    db_name: DatabaseName,
    db_user: DatabaseName,
    db_password: String,
    db_host: ContainerName,
    cache_host: ContainerName,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug)]
pub struct RequestError;

fn validate_bounded(value: &str, max: usize) -> Result<(), RequestError> {
    if value.is_empty() || value.len() > max || value.as_bytes().contains(&0) {
        return Err(RequestError);
    }
    Ok(())
}

/// A permissive structural email check - one `@`, non-empty local/domain
/// parts, no whitespace or NUL - not a full RFC 5322 validator. `wp core
/// install` itself is the authority on whether the address is actually
/// usable; this only keeps obviously-malformed input from ever reaching
/// argv.
fn validate_email(value: &str) -> Result<(), RequestError> {
    if value.is_empty()
        || value.len() > MAX_EMAIL_BYTES
        || value.bytes().any(|b| b == 0 || b.is_ascii_whitespace())
    {
        return Err(RequestError);
    }
    let mut parts = value.splitn(2, '@');
    match (parts.next(), parts.next()) {
        (Some(local), Some(domain))
            if !local.is_empty() && !domain.is_empty() && !domain.contains('@') => {}
        _ => return Err(RequestError),
    }
    Ok(())
}

/// Mirrors `website-control-panel`'s own `validate_db_credentials`: no NUL,
/// CR or LF. Unlike the DB name/user, a password is not restricted to
/// `DatabaseName`'s alphanumeric/underscore charset.
fn validate_db_password(value: &str) -> Result<(), RequestError> {
    if value.is_empty()
        || value.len() > MAX_DB_PASSWORD_BYTES
        || value.bytes().any(|b| matches!(b, 0 | b'\n' | b'\r'))
    {
        return Err(RequestError);
    }
    Ok(())
}

impl Request {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError)?;
        let root = PathBuf::from(plan.root);
        if !root.is_absolute()
            || root.as_os_str().len() > 4096
            || root
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(RequestError);
        }
        validate_bounded(&plan.site_title, MAX_TITLE_BYTES)?;
        validate_bounded(&plan.admin_user, MAX_ADMIN_USER_BYTES)?;
        validate_bounded(&plan.admin_password, MAX_ADMIN_PASSWORD_BYTES)?;
        validate_email(&plan.admin_email)?;
        validate_db_password(&plan.db_password)?;

        Ok(Self {
            container: ContainerName::parse(&plan.container)
                .map_err(|_: RestoreRequestError| RequestError)?,
            root,
            uid: plan.uid,
            gid: plan.gid,
            domain: Domain::parse(&plan.domain).map_err(|_| RequestError)?,
            site_title: plan.site_title,
            admin_user: plan.admin_user,
            admin_password: plan.admin_password,
            admin_email: plan.admin_email,
            db_name: DatabaseName::parse(&plan.db_name)
                .map_err(|_: RestoreRequestError| RequestError)?,
            db_user: DatabaseName::parse(&plan.db_user)
                .map_err(|_: RestoreRequestError| RequestError)?,
            db_password: plan.db_password,
            db_host: ContainerName::parse(&plan.db_host)
                .map_err(|_: RestoreRequestError| RequestError)?,
            cache_host: ContainerName::parse(&plan.cache_host)
                .map_err(|_: RestoreRequestError| RequestError)?,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError)?,
        })
    }

    pub fn root(&self) -> &std::path::Path {
        &self.root
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallResult {
    pub admin_url: String,
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
    Run(ProcessRunError),
    Rejected(ErrorCode),
    RootUnavailable,
    PostCommit { result: InstallResult },
    Replayed { code: ErrorCode, message: String },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another WordPress install is in progress for this site".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Run(error) => (
                process::spawn_error_code(error),
                "could not run a WordPress install prerequisite".into(),
            ),
            Self::Rejected(code) => (
                *code,
                "WordPress core download, configuration or install failed".into(),
            ),
            Self::RootUnavailable => (
                ErrorCode::InvalidInput,
                "WordPress root does not exist or is outside the configured content root".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            _ => (
                ErrorCode::Internal,
                "internal WordPress install error".into(),
            ),
        }
    }
}

pub fn execute(
    ctx: &Context<'_>,
    content_root: &TrustedRoot,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<InstallResult, Error> {
    let digest = Sha256::digest(req.root.as_os_str().as_encoded_bytes());
    let mut hash = String::new();
    for byte in digest {
        write!(&mut hash, "{byte:02x}").unwrap();
    }
    let scope_path = SiteRelativePath::parse(format!("wordpress-install/{hash}")).unwrap();
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

    let relative = match req.root.strip_prefix(content_root.as_path()) {
        Ok(value) if !value.as_os_str().is_empty() => value,
        _ => {
            return Err(fail(
                &scope,
                &state_path,
                &audit_path,
                state,
                Error::RootUnavailable,
            ));
        }
    };
    let relative = match SiteRelativePath::parse(relative) {
        Ok(value) => value,
        Err(_) => {
            return Err(fail(
                &scope,
                &state_path,
                &audit_path,
                state,
                Error::RootUnavailable,
            ));
        }
    };
    let root_path = match content_root.resolve_existing(&relative) {
        Ok(value) => value,
        Err(_) => {
            return Err(fail(
                &scope,
                &state_path,
                &audit_path,
                state,
                Error::RootUnavailable,
            ));
        }
    };
    let root_str = match root_path.to_str() {
        Some(value) => value,
        None => {
            return Err(fail(
                &scope,
                &state_path,
                &audit_path,
                state,
                Error::RootUnavailable,
            ));
        }
    };

    // ── Critical path: core download (with a fixed bg_BG/en_US fallback,
    // matching the raw-shell behavior this replaces), wp-config.php, and
    // `wp core install`. Any failure here fails the whole request. ──
    let primary_download = run_wp(
        ctx,
        req,
        root_str,
        &["core", "download", "--locale=bg_BG", "--skip-content"],
        cancel,
    );
    if step_failed(&primary_download) {
        let fallback_download = run_wp(
            ctx,
            req,
            root_str,
            &["core", "download", "--locale=en_US", "--skip-content"],
            cancel,
        );
        if let Err(error) = critical(fallback_download) {
            return Err(fail(&scope, &state_path, &audit_path, state, error));
        }
    }

    let db_password_flag = format!("--dbpass={}", req.db_password);
    let config_create = run_wp(
        ctx,
        req,
        root_str,
        &[
            "config",
            "create",
            &format!("--dbname={}", req.db_name.as_str()),
            &format!("--dbuser={}", req.db_user.as_str()),
            &db_password_flag,
            &format!("--dbhost={}", req.db_host.as_str()),
            "--skip-check",
        ],
        cancel,
    );
    if let Err(error) = critical(config_create) {
        return Err(fail(&scope, &state_path, &audit_path, state, error));
    }

    // ── Best-effort from here: object-cache wiring, the cache plugin and
    // disabling native WP-Cron. Matches the raw-shell code this replaces,
    // which never checked their output either - a site with a broken cache
    // plugin is still a successfully installed site. ──
    let _ = run_wp(
        ctx,
        req,
        root_str,
        &["config", "set", "WP_REDIS_HOST", req.cache_host.as_str()],
        cancel,
    );
    let _ = run_wp(
        ctx,
        req,
        root_str,
        &["config", "set", "WP_REDIS_PORT", "6379", "--raw"],
        cancel,
    );
    let _ = run_wp(
        ctx,
        req,
        root_str,
        &["config", "set", "WP_CACHE", "true", "--raw"],
        cancel,
    );

    let url_flag = format!("--url=https://{}", req.domain.as_str());
    let title_flag = format!("--title={}", req.site_title);
    let admin_user_flag = format!("--admin_user={}", req.admin_user);
    let admin_password_flag = format!("--admin_password={}", req.admin_password);
    let admin_email_flag = format!("--admin_email={}", req.admin_email);
    let core_install = run_wp(
        ctx,
        req,
        root_str,
        &[
            "core",
            "install",
            &url_flag,
            &title_flag,
            &admin_user_flag,
            &admin_password_flag,
            &admin_email_flag,
            "--skip-email",
        ],
        cancel,
    );
    if let Err(error) = critical(core_install) {
        return Err(fail(&scope, &state_path, &audit_path, state, error));
    }

    let _ = run_wp(
        ctx,
        req,
        root_str,
        &["plugin", "install", "redis-cache", "--activate"],
        cancel,
    );
    let _ = run_wp(ctx, req, root_str, &["redis", "enable"], cancel);
    let _ = run_wp(
        ctx,
        req,
        root_str,
        &["config", "set", "DISABLE_WP_CRON", "true", "--raw"],
        cancel,
    );

    let result = InstallResult {
        admin_url: format!("https://{}/wp-admin", req.domain.as_str()),
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

fn wp_args(req: &Request, root: &str, tail: &[&str]) -> Vec<String> {
    let mut args = vec![
        "exec".to_owned(),
        "-i".to_owned(),
        "--user".to_owned(),
        format!("{}:{}", req.uid, req.gid),
        req.container.as_str().to_owned(),
        "wp".to_owned(),
        format!("--path={root}"),
        "--allow-root".to_owned(),
    ];
    args.extend(tail.iter().map(|value| (*value).to_owned()));
    args
}

fn run_wp(
    ctx: &Context<'_>,
    req: &Request,
    root: &str,
    tail: &[&str],
    cancel: &CancellationToken,
) -> Result<ProcessOutput, ProcessRunError> {
    process::run(
        &ProcessRequest::new(ctx.docker_program).args(wp_args(req, root, tail)),
        &ProcessLimits {
            timeout: STEP_TIMEOUT,
            max_stdout_bytes: MAX_STEP_OUTPUT_BYTES,
            max_stderr_bytes: MAX_STEP_OUTPUT_BYTES,
        },
        cancel,
    )
}

fn step_failed(output: &Result<ProcessOutput, ProcessRunError>) -> bool {
    match output {
        Ok(value) => process::error_code(&value.termination).is_some(),
        Err(_) => true,
    }
}

fn critical(output: Result<ProcessOutput, ProcessRunError>) -> Result<(), Error> {
    let output = output.map_err(Error::Run)?;
    if let Some(code) = process::error_code(&output.termination) {
        return Err(Error::Rejected(code));
    }
    Ok(())
}

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<InstallResult, Error> {
    let loaded = state::load(
        scope,
        &SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap(),
    )
    .map_err(|e| Error::Io(std::io::Error::other(format!("{e:?}"))))?;
    if loaded.operation != OPERATION {
        return Err(Error::Io(std::io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => {
            serde_json::from_value(loaded.outcome.unwrap().result.unwrap())
                .map_err(|e| Error::Io(std::io::Error::other(e)))
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
    path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut state: crate::transaction::state::TransactionState,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    const REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    fn valid_json() -> String {
        r#"{
            "container": "runtime-1",
            "root": "/var/www/example.com",
            "uid": 1000,
            "gid": 1000,
            "domain": "example.com",
            "siteTitle": "Example Site",
            "adminUser": "admin",
            "adminPassword": "correct-horse-battery",
            "adminEmail": "admin@example.com",
            "dbName": "site_db",
            "dbUser": "site_user",
            "dbPassword": "s3cret",
            "dbHost": "mariadb",
            "cacheHost": "valkey"
        }"#
        .to_owned()
    }

    #[test]
    fn parses_a_well_formed_plan() {
        let request = Request::parse(&valid_json(), REQUEST_ID, None).expect("should parse");
        assert_eq!(request.root(), std::path::Path::new("/var/www/example.com"));
    }

    #[test]
    fn rejects_a_relative_root() {
        let json = valid_json().replace("/var/www/example.com", "var/www/example.com");
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn rejects_an_invalid_domain() {
        let json = valid_json().replace("\"domain\": \"example.com\"", "\"domain\": \"-bad-\"");
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn rejects_db_name_outside_the_allowlisted_charset() {
        let json = valid_json().replace(
            "\"dbName\": \"site_db\"",
            "\"dbName\": \"site; drop table x\"",
        );
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn rejects_a_malformed_admin_email() {
        let json = valid_json().replace(
            "\"adminEmail\": \"admin@example.com\"",
            "\"adminEmail\": \"not-an-email\"",
        );
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn rejects_a_db_password_containing_control_bytes() {
        let json = valid_json().replace(
            "\"dbPassword\": \"s3cret\"",
            "\"dbPassword\": \"line1\\nline2\"",
        );
        assert!(Request::parse(&json, REQUEST_ID, None).is_err());
    }

    #[test]
    fn wp_args_places_identity_and_path_before_the_tail() {
        let request = Request::parse(&valid_json(), REQUEST_ID, None).expect("should parse");
        let args = wp_args(&request, "/var/www/example.com", &["core", "install"]);
        assert_eq!(
            args,
            vec![
                "exec",
                "-i",
                "--user",
                "1000:1000",
                "runtime-1",
                "wp",
                "--path=/var/www/example.com",
                "--allow-root",
                "core",
                "install",
            ]
        );
    }

    // ── `execute` integration tests: a fake `docker` shell script stands in
    // for the real binary, logging every invocation's argv to a sibling
    // `calls.log` so the fixed WP-CLI sequence (and which steps are
    // critical vs. best-effort) can be asserted directly. ──

    fn write_script(directory: &std::path::Path, name: &str, body: &str) -> PathBuf {
        let path = directory.join(name);
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// Builds a fixture with a content root containing a pre-existing
    /// `example.com` site directory (mirroring `create_site` having already
    /// run), a fresh engine state root, and a fake `docker` whose behavior
    /// is driven entirely by `script_body`.
    struct Fixture {
        _directory: tempfile::TempDir,
        content_root: TrustedRoot,
        state: ManagedRoot,
        docker: PathBuf,
        site_root: PathBuf,
    }

    fn fixture(script_body: &str) -> Fixture {
        let directory = tempfile::tempdir().unwrap();
        let content_dir = directory.path().join("content");
        let state_dir = directory.path().join("state");
        fs::create_dir_all(content_dir.join("example.com")).unwrap();
        fs::create_dir_all(&state_dir).unwrap();
        let content_root = TrustedRoot::parse(&content_dir).unwrap();
        let state = ManagedRoot::open(&TrustedRoot::parse(&state_dir).unwrap()).unwrap();
        let docker = write_script(directory.path(), "fake-docker", script_body);
        let site_root = content_dir.join("example.com");
        Fixture {
            _directory: directory,
            content_root,
            state,
            docker,
            site_root,
        }
    }

    fn request_for(root: &std::path::Path, request_id: &str, key: Option<&str>) -> Request {
        let json = valid_json().replace(
            "\"root\": \"/var/www/example.com\"",
            &format!("\"root\": \"{}\"", root.display()),
        );
        Request::parse(&json, request_id, key).expect("request should parse")
    }

    fn calls_log(fixture: &Fixture) -> Vec<String> {
        let log_path = fixture.docker.parent().unwrap().join("calls.log");
        match fs::read_to_string(log_path) {
            Ok(contents) => contents.lines().map(str::to_owned).collect(),
            Err(_) => Vec::new(),
        }
    }

    const ALWAYS_SUCCEED: &str =
        "#!/bin/sh\necho \"$@\" >> \"$(dirname \"$0\")/calls.log\"\nexit 0\n";

    #[test]
    fn succeeds_end_to_end_and_runs_the_full_fixed_wp_cli_sequence() {
        let fx = fixture(ALWAYS_SUCCEED);
        let request = request_for(&fx.site_root, REQUEST_ID, None);
        let context = Context {
            engine_state: &fx.state,
            docker_program: fx.docker.to_str().unwrap(),
        };

        let result = execute(
            &context,
            &fx.content_root,
            &request,
            &CancellationToken::default(),
        )
        .expect("install should succeed");
        assert_eq!(result.admin_url, "https://example.com/wp-admin");

        let calls = calls_log(&fx);
        assert_eq!(calls.len(), 9, "unexpected call sequence: {calls:#?}");
        assert!(calls[0].contains("core download") && calls[0].contains("--locale=bg_BG"));
        assert!(calls[1].contains("config create") && calls[1].contains("--dbname=site_db"));
        assert!(calls[2].contains("WP_REDIS_HOST"));
        assert!(calls[3].contains("WP_REDIS_PORT"));
        assert!(calls[4].contains("WP_CACHE"));
        assert!(
            calls[5].contains("core install") && calls[5].contains("--url=https://example.com")
        );
        assert!(calls[6].contains("redis-cache"));
        assert!(calls[7].contains("redis enable"));
        assert!(calls[8].contains("DISABLE_WP_CRON"));
    }

    #[test]
    fn falls_back_to_en_us_locale_when_bg_bg_download_fails() {
        let script = "#!/bin/sh\necho \"$@\" >> \"$(dirname \"$0\")/calls.log\"\ncase \"$*\" in\n  *\"--locale=bg_BG\"*) exit 1;;\nesac\nexit 0\n";
        let fx = fixture(script);
        let request = request_for(&fx.site_root, REQUEST_ID, None);
        let context = Context {
            engine_state: &fx.state,
            docker_program: fx.docker.to_str().unwrap(),
        };

        let result = execute(
            &context,
            &fx.content_root,
            &request,
            &CancellationToken::default(),
        )
        .expect("install should still succeed via the en_US fallback");
        assert_eq!(result.admin_url, "https://example.com/wp-admin");

        let calls = calls_log(&fx);
        assert!(calls[0].contains("--locale=bg_BG"));
        assert!(calls[1].contains("--locale=en_US"));
        assert_eq!(
            calls.len(),
            10,
            "expected one extra call for the fallback: {calls:#?}"
        );
    }

    #[test]
    fn fails_closed_and_stops_immediately_when_both_locale_downloads_fail() {
        let script = "#!/bin/sh\necho \"$@\" >> \"$(dirname \"$0\")/calls.log\"\ncase \"$*\" in\n  *\"core download\"*) exit 1;;\nesac\nexit 0\n";
        let fx = fixture(script);
        let request = request_for(&fx.site_root, REQUEST_ID, None);
        let context = Context {
            engine_state: &fx.state,
            docker_program: fx.docker.to_str().unwrap(),
        };

        let error = execute(
            &context,
            &fx.content_root,
            &request,
            &CancellationToken::default(),
        )
        .expect_err("both locale attempts failing should fail the whole request");
        assert_eq!(error.protocol().0, ErrorCode::SubprocessFailed);

        // Neither `wp config create` nor anything after it ran.
        let calls = calls_log(&fx);
        assert_eq!(
            calls.len(),
            2,
            "only the two locale attempts should have run: {calls:#?}"
        );
    }

    #[test]
    fn fails_closed_when_wp_config_create_fails_without_running_core_install() {
        let script = "#!/bin/sh\necho \"$@\" >> \"$(dirname \"$0\")/calls.log\"\ncase \"$*\" in\n  *\"config create\"*) exit 1;;\nesac\nexit 0\n";
        let fx = fixture(script);
        let request = request_for(&fx.site_root, REQUEST_ID, None);
        let context = Context {
            engine_state: &fx.state,
            docker_program: fx.docker.to_str().unwrap(),
        };

        let error = execute(
            &context,
            &fx.content_root,
            &request,
            &CancellationToken::default(),
        )
        .expect_err("a failed wp-config write should fail the whole request");
        assert_eq!(error.protocol().0, ErrorCode::SubprocessFailed);

        let calls = calls_log(&fx);
        assert_eq!(
            calls.len(),
            2,
            "download then the failed config create: {calls:#?}"
        );
        assert!(!calls.iter().any(|c| c.contains("core install")));
    }

    #[test]
    fn rejects_a_root_that_does_not_exist_beneath_the_content_root() {
        let fx = fixture(ALWAYS_SUCCEED);
        let missing = fx.content_root.as_path().join("never-created.example.com");
        let request = request_for(&missing, REQUEST_ID, None);
        let context = Context {
            engine_state: &fx.state,
            docker_program: fx.docker.to_str().unwrap(),
        };

        let error = execute(
            &context,
            &fx.content_root,
            &request,
            &CancellationToken::default(),
        )
        .expect_err("a root that was never created should be rejected");
        assert_eq!(error.protocol().0, ErrorCode::InvalidInput);
        assert!(calls_log(&fx).is_empty(), "no WP-CLI step should have run");
    }

    #[test]
    fn replaying_the_same_idempotency_key_returns_the_original_result_without_rerunning_wp_cli() {
        let fx = fixture(ALWAYS_SUCCEED);
        let first = request_for(&fx.site_root, REQUEST_ID, Some("install-once"));
        let context = Context {
            engine_state: &fx.state,
            docker_program: fx.docker.to_str().unwrap(),
        };
        let first_result = execute(
            &context,
            &fx.content_root,
            &first,
            &CancellationToken::default(),
        )
        .expect("first attempt should succeed");
        let calls_after_first = calls_log(&fx).len();
        assert!(calls_after_first > 0);

        let second_request_id = "223e4567-e89b-12d3-a456-426614174000";
        let second = request_for(&fx.site_root, second_request_id, Some("install-once"));
        let second_result = execute(
            &context,
            &fx.content_root,
            &second,
            &CancellationToken::default(),
        )
        .expect("replay should return the recorded result, not fail");

        assert_eq!(first_result.admin_url, second_result.admin_url);
        assert_eq!(
            calls_log(&fx).len(),
            calls_after_first,
            "a replayed idempotency key must not run WP-CLI again"
        );
    }
}
