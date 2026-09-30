//! `wordpress.setSmtpRelay`: installs/activates WP Mail SMTP and writes its
//! eight `WPMS_*` relay constants into `wp-config.php` as one
//! lock/idempotency/transaction/audit-backed request.
//!
//! Replaces the panel's nine separate raw-SSH `docker exec … wp` calls,
//! which put the SMTP password on a remote command line and could leave
//! `wp-config.php` half-configured (host set, password not) if any call
//! failed or the connection dropped between them.
//!
//! - The plan (including the password) arrives in a root-owned request
//!   file and reaches the container only over stdin; every argv is fixed.
//! - All file access runs inside the site container as the site UID, never
//!   as host root inside a site-owned directory.
//! - The constants are applied with WP-CLI's own `WPConfigTransformer`
//!   (the class behind `wp config set`) to a private copy of
//!   `wp-config.php` in the same directory, which then replaces the
//!   original with one `rename`. The live file is therefore either fully
//!   the previous version or fully the new one, never in between.
//!   `locate_wp_config()` resolves symlinks, so a symlinked `wp-config.php`
//!   has its target replaced in the target's own directory. That is no
//!   escalation: the script runs as the site UID inside the site
//!   container, so it can only write what the site user already can.
//! - The plugin install runs first and changes nothing in `wp-config.php`;
//!   if the config write then fails, the active-but-unconfigured plugin
//!   falls back to its own defaults, as it did before.

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
        commit::PreCommit,
        resource_lock,
        state::{self, TransactionStatus},
    },
};
use serde::Deserialize;
use std::{
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const OPERATION: &str = "wordpress.setSmtpRelay";
pub const PLUGIN: &str = "wp-mail-smtp";
const MAX_SECRET_LEN: usize = 1024;
const MAX_USERNAME_LEN: usize = 320;

/// Applies the stdin plan to a private copy of `wp-config.php` and swaps it
/// in with one rename. Fixed text: nothing request-specific is interpolated.
pub const APPLY_PHP: &str = r#"umask(0077);
$plan = json_decode(stream_get_contents(STDIN), true);
if (!is_array($plan) || !isset($plan['constants']) || !is_array($plan['constants'])) { fwrite(STDERR, "invalid plan\n"); exit(2); }
if (!class_exists('WPConfigTransformer')) { fwrite(STDERR, "WPConfigTransformer is unavailable\n"); exit(3); }
$config = \WP_CLI\Utils\locate_wp_config();
if (!$config || !is_file($config)) { fwrite(STDERR, "wp-config.php was not found\n"); exit(4); }
$tmp = dirname($config) . '/.wp-config.wcp-' . bin2hex(random_bytes(8)) . '.php';
if (!@copy($config, $tmp)) { fwrite(STDERR, "could not stage wp-config.php\n"); exit(5); }
try {
    @chmod($tmp, fileperms($config) & 0777);
    $transformer = new WPConfigTransformer($tmp);
    foreach ($plan['constants'] as $constant) {
        $transformer->update('constant', (string) $constant['name'], (string) $constant['value'], array('raw' => (bool) $constant['raw'], 'normalize' => false));
    }
    if (!@rename($tmp, $config)) { throw new RuntimeException('rename failed'); }
} catch (Throwable $error) {
    @unlink($tmp);
    fwrite(STDERR, "could not update wp-config.php\n");
    exit(6);
}
echo "ok\n";"#;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    container: String,
    root: String,
    uid: u32,
    gid: u32,
    host: String,
    port: u32,
    username: String,
    password: String,
    encryption: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Encryption {
    Tls,
    Ssl,
    None,
}

pub struct Request {
    container: ContainerName,
    root: PathBuf,
    uid: u32,
    gid: u32,
    host: String,
    port: u16,
    username: String,
    password: String,
    encryption: Encryption,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestError;

fn valid_text(value: &str, max_len: usize) -> bool {
    value.len() <= max_len && !value.chars().any(char::is_control)
}

/// A DNS name or an IPv4/IPv6 literal: no whitespace, quotes or anything a
/// PHP string or mail transport would treat specially.
fn valid_host(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
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
        let host = plan.host.trim().to_owned();
        if !valid_host(&host)
            || !valid_text(&plan.username, MAX_USERNAME_LEN)
            || !valid_text(&plan.password, MAX_SECRET_LEN)
        {
            return Err(RequestError);
        }
        let port = u16::try_from(plan.port)
            .ok()
            .filter(|port| *port > 0)
            .ok_or(RequestError)?;
        let encryption = match plan.encryption.as_str() {
            "tls" => Encryption::Tls,
            "ssl" => Encryption::Ssl,
            "none" => Encryption::None,
            _ => return Err(RequestError),
        };
        Ok(Self {
            container: ContainerName::parse(&plan.container)
                .map_err(|_: RestoreRequestError| RequestError)?,
            root,
            uid: plan.uid,
            gid: plan.gid,
            host,
            port,
            username: plan.username,
            password: plan.password,
            encryption,
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

    /// The constants WP Mail SMTP reads, in the order the panel used to
    /// write them (https://wpmailsmtp.com/docs/how-to-set-smtp-constants-in-wp-config-php-file/).
    fn constants(&self) -> serde_json::Value {
        let ssl = match self.encryption {
            Encryption::Tls => "tls",
            Encryption::Ssl => "ssl",
            Encryption::None => "",
        };
        let constant = |name: &str, value: &str, raw: bool| serde_json::json!({ "name": name, "value": value, "raw": raw });
        serde_json::json!({
            "constants": [
                constant("WPMS_ON", "true", true),
                constant("WPMS_MAILER", "smtp", false),
                constant("WPMS_SMTP_HOST", &self.host, false),
                constant("WPMS_SMTP_PORT", &self.port.to_string(), true),
                constant("WPMS_SSL", ssl, false),
                constant("WPMS_SMTP_AUTH", "true", true),
                constant("WPMS_SMTP_USER", &self.username, false),
                constant("WPMS_SMTP_PASS", &self.password, false),
            ]
        })
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmtpRelayResult {
    pub plugin: String,
    pub completed_at_unix_secs: u64,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub docker_program: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    InstallPlugin,
    WriteConfig,
}

impl Stage {
    fn message(self) -> &'static str {
        match self {
            Self::InstallPlugin => "could not install and activate WP Mail SMTP",
            Self::WriteConfig => {
                "could not write the SMTP relay settings to wp-config.php; it was left unchanged"
            }
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    ResourceBusy,
    Preflight(preflight::Error),
    ReplayInProgress,
    Cancelled,
    Run(Stage, process::ProcessRunError),
    Rejected(Stage, SubprocessDiagnostics),
    PostCommit { result: SmtpRelayResult },
    Replayed { code: ErrorCode, message: String },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::ResourceBusy => (
                ErrorCode::Conflict,
                "another operation on this WordPress site is in progress".into(),
            ),
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another SMTP relay change for this site is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Cancelled => (
                ErrorCode::Cancelled,
                "cancelled before wp-config.php was changed".into(),
            ),
            Self::Run(stage, error) => (process::spawn_error_code(error), stage.message().into()),
            Self::Rejected(stage, diagnostics) => (
                if diagnostics.timed_out {
                    ErrorCode::Timeout
                } else if diagnostics.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::SubprocessFailed
                },
                stage.message().into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit { .. } => (
                ErrorCode::Internal,
                "internal SMTP relay configuration error".into(),
            ),
        }
    }
}

fn wp_args<I, S>(req: &Request, tail: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut args = vec![
        "exec".to_owned(),
        "-i".to_owned(),
        "--user".to_owned(),
        format!("{}:{}", req.uid, req.gid),
        req.container.as_str().to_owned(),
        "wp".to_owned(),
        format!("--path={}", req.root.display()),
        "--allow-root".to_owned(),
    ];
    args.extend(tail.into_iter().map(|v| v.as_ref().to_owned()));
    args
}

fn check(
    ctx: &Context<'_>,
    stage: Stage,
    result: Result<process::ProcessOutput, process::ProcessRunError>,
) -> Result<(), Error> {
    let output = result.map_err(|e| Error::Run(stage, e))?;
    if !matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        return Err(Error::Rejected(
            stage,
            SubprocessDiagnostics::from_output(ctx.docker_program, &output),
        ));
    }
    Ok(())
}

fn install_plugin(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    // The plugin download is the slow part; `--activate` is a no-op when it
    // is already active, and `install` of an installed plugin only warns.
    let result = process::run(
        &ProcessRequest::new(ctx.docker_program)
            .args(wp_args(req, ["plugin", "install", PLUGIN, "--activate"])),
        &ProcessLimits {
            timeout: Duration::from_secs(3 * 60),
            ..ProcessLimits::default()
        },
        cancel,
    );
    check(ctx, Stage::InstallPlugin, result)
}

fn write_config(ctx: &Context<'_>, req: &Request) -> Result<(), Error> {
    let plan = req.constants().to_string();
    // Past the commit point: never cancelled mid-write.
    let result = process::run_with_stdin_bytes(
        &ProcessRequest::new(ctx.docker_program)
            .args(wp_args(req, ["--skip-wordpress", "eval", APPLY_PHP])),
        plan.as_bytes(),
        &ProcessLimits::default(),
        &CancellationToken::default(),
    );
    check(ctx, Stage::WriteConfig, result)
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<SmtpRelayResult, Error> {
    let hash = resource_lock::canonical_hash(&req.root);
    let scope_path = SiteRelativePath::parse(format!("wordpress-smtp-relay/{hash}")).unwrap();
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
    let pre_commit = PreCommit::new(cancel.clone());

    if let Err(error) = install_plugin(ctx, req, cancel) {
        return Err(fail(&scope, &state_path, &audit_path, state, error));
    }
    if pre_commit.check().is_err() {
        return Err(fail(
            &scope,
            &state_path,
            &audit_path,
            state,
            Error::Cancelled,
        ));
    }
    let _post_commit = pre_commit.commit();
    if let Err(error) = write_config(ctx, req) {
        return Err(fail(&scope, &state_path, &audit_path, state, error));
    }

    let result = SmtpRelayResult {
        plugin: PLUGIN.to_owned(),
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

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<SmtpRelayResult, Error> {
    let loaded = state::load(
        scope,
        &SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap(),
    )
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
    const ID_2: &str = "123e4567-e89b-12d3-a456-426614174001";
    const SECRET: &str = "s3cr3t 'quoted\" $pass";

    fn plan_json(root: &str, overrides: &[(&str, serde_json::Value)]) -> String {
        let mut plan = serde_json::json!({
            "container": "site-php", "root": root, "uid": 1000, "gid": 1000,
            "host": "smtp.example.com", "port": 587, "username": "mailer@example.com",
            "password": SECRET, "encryption": "tls",
        });
        for (key, value) in overrides {
            plan[*key] = value.clone();
        }
        plan.to_string()
    }

    fn managed(directory: &std::path::Path) -> ManagedRoot {
        ManagedRoot::open(&crate::site::TrustedRoot::parse(directory).unwrap()).unwrap()
    }

    /// A fake `docker` logging every argv line and every stdin byte, failing
    /// a chosen stage when a marker file exists next to it.
    fn fake_docker(directory: &std::path::Path) -> String {
        let script = directory.join("docker");
        fs::write(
            &script,
            r#"#!/bin/sh
DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
printf '%s\n' "$*" >> "$DIR/argv.log"
case "$*" in
  *"plugin install wp-mail-smtp --activate"*)
    [ -f "$DIR/fail_plugin" ] && exit 5
    exit 0
    ;;
  *"--skip-wordpress eval"*)
    { cat; printf '\n'; } >> "$DIR/stdin.log"
    [ -f "$DIR/fail_config" ] && exit 6
    exit 0
    ;;
esac
exit 0
"#,
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        script.to_string_lossy().into_owned()
    }

    struct Harness {
        dir: tempfile::TempDir,
        docker: String,
    }

    impl Harness {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            for sub in ["state", "content"] {
                fs::create_dir(dir.path().join(sub)).unwrap();
            }
            let docker = fake_docker(dir.path());
            Self { dir, docker }
        }

        fn run(&self, id: &str, key: Option<&str>) -> Result<SmtpRelayResult, Error> {
            let root = self.dir.path().join("content");
            let req = Request::parse(&plan_json(root.to_str().unwrap(), &[]), id, key).unwrap();
            let state = managed(&self.dir.path().join("state"));
            let ctx = Context {
                engine_state: &state,
                docker_program: &self.docker,
            };
            execute(&ctx, &req, &CancellationToken::default())
        }

        fn log(&self, name: &str) -> String {
            fs::read_to_string(self.dir.path().join(name)).unwrap_or_default()
        }

        fn mark(&self, name: &str) {
            fs::write(self.dir.path().join(name), "").unwrap();
        }
    }

    #[test]
    fn parses_a_well_formed_plan_and_rejects_invalid_fields() {
        assert!(Request::parse(&plan_json("/srv/site", &[]), ID, None).is_ok());
        for (key, value) in [
            ("root", serde_json::json!("relative/site")),
            ("root", serde_json::json!("/srv/../etc")),
            ("host", serde_json::json!("")),
            ("host", serde_json::json!("smtp.example.com; rm -rf /")),
            ("host", serde_json::json!("smtp.example.com'")),
            ("port", serde_json::json!(0)),
            ("port", serde_json::json!(65_536)),
            ("encryption", serde_json::json!("starttls")),
            ("password", serde_json::json!("line\nbreak")),
            ("username", serde_json::json!("nul\u{0}")),
            ("container", serde_json::json!("bad name")),
        ] {
            assert_eq!(
                Request::parse(&plan_json("/srv/site", &[(key, value.clone())]), ID, None).err(),
                Some(RequestError),
                "{key} = {value}"
            );
        }
        let mut extra: serde_json::Value =
            serde_json::from_str(&plan_json("/srv/site", &[])).unwrap();
        extra["command"] = serde_json::json!("eval");
        assert!(Request::parse(&extra.to_string(), ID, None).is_err());
    }

    #[test]
    fn plans_the_eight_constants_with_raw_literals_only_where_needed() {
        let req = Request::parse(
            &plan_json("/srv/site", &[("encryption", serde_json::json!("none"))]),
            ID,
            None,
        )
        .unwrap();
        let constants = req.constants();
        let list = constants["constants"].as_array().unwrap();
        let names: Vec<_> = list.iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert_eq!(
            names,
            [
                "WPMS_ON",
                "WPMS_MAILER",
                "WPMS_SMTP_HOST",
                "WPMS_SMTP_PORT",
                "WPMS_SSL",
                "WPMS_SMTP_AUTH",
                "WPMS_SMTP_USER",
                "WPMS_SMTP_PASS"
            ]
        );
        let raw: Vec<_> = list
            .iter()
            .filter(|c| c["raw"] == true)
            .map(|c| c["name"].as_str().unwrap())
            .collect();
        assert_eq!(raw, ["WPMS_ON", "WPMS_SMTP_PORT", "WPMS_SMTP_AUTH"]);
        assert_eq!(list[4]["value"], "");
        assert_eq!(list[7]["value"], SECRET);
    }

    #[test]
    fn installs_then_writes_config_with_the_secret_only_on_stdin_then_replays() {
        let harness = Harness::new();
        let first = harness.run(ID, Some("smtp-key")).unwrap();
        let second = harness.run(ID_2, Some("smtp-key")).unwrap();

        assert_eq!(first.plugin, PLUGIN);
        assert_eq!(first.completed_at_unix_secs, second.completed_at_unix_secs);
        let argv = harness.log("argv.log");
        // The eval argv carries the multi-line script, so count calls by
        // their fixed markers rather than by lines.
        assert_eq!(
            argv.matches("plugin install").count(),
            1,
            "replay must not run docker again"
        );
        assert_eq!(argv.matches("--skip-wordpress eval").count(), 1);
        assert!(
            argv.lines()
                .next()
                .unwrap()
                .contains("plugin install wp-mail-smtp --activate")
        );
        assert!(argv.contains("--user 1000:1000 site-php wp --path="));
        assert!(!argv.contains("s3cr3t"));
        assert!(!argv.contains("mailer@example.com"));
        let stdin = harness.log("stdin.log");
        let plan: serde_json::Value = serde_json::from_str(stdin.trim()).unwrap();
        assert_eq!(plan["constants"][7]["value"], SECRET);
    }

    #[test]
    fn a_failed_plugin_install_never_touches_wp_config() {
        let harness = Harness::new();
        harness.mark("fail_plugin");

        let error = harness.run(ID, None).unwrap_err();

        assert!(matches!(error, Error::Rejected(Stage::InstallPlugin, _)));
        assert!(!harness.log("argv.log").contains("eval"));
        assert!(harness.log("stdin.log").is_empty());
    }

    #[test]
    fn a_failed_config_write_is_reported_and_replayed() {
        let harness = Harness::new();
        harness.mark("fail_config");

        let first = harness.run(ID, Some("k")).unwrap_err();
        let second = harness.run(ID_2, Some("k")).unwrap_err();

        assert!(matches!(first, Error::Rejected(Stage::WriteConfig, _)));
        assert!(first.protocol().1.contains("left unchanged"));
        assert!(matches!(
            second,
            Error::Replayed {
                code: ErrorCode::SubprocessFailed,
                ..
            }
        ));
    }

    #[test]
    fn the_apply_script_contains_no_request_specific_text() {
        assert!(!APPLY_PHP.contains("WPMS_"));
        assert!(APPLY_PHP.contains("stream_get_contents(STDIN)"));
        assert!(APPLY_PHP.contains("rename($tmp, $config)"));
    }
}
