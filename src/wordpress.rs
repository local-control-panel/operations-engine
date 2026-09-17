use crate::{
    db_restore::{ContainerName, RestoreRequestError},
    error::ErrorCode,
    process::{
        self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination,
        SubprocessDiagnostics,
    },
};
use serde::Deserialize;
use std::{path::PathBuf, time::Duration};

pub const OPERATION: &str = "wordpress.cleanup";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Action {
    Revisions,
    WcSessions,
    ScheduledActions,
    PaymentTransients,
}

impl Action {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "revisions" => Some(Self::Revisions),
            "wc_sessions" => Some(Self::WcSessions),
            "action_scheduler" => Some(Self::ScheduledActions),
            "payment_transients" => Some(Self::PaymentTransients),
            _ => None,
        }
    }
    fn php(self) -> &'static str {
        match self {
            Self::Revisions => {
                r#"global $wpdb; $n = $wpdb->query("DELETE FROM {$wpdb->posts} WHERE post_type = 'revision'"); echo "Deleted {$n} revision(s).\n";"#
            }
            Self::WcSessions => {
                r#"global $wpdb; $n = $wpdb->query("DELETE FROM {$wpdb->prefix}woocommerce_sessions WHERE session_expiry < " . time()); echo "Deleted {$n} expired session(s).\n";"#
            }
            Self::ScheduledActions => {
                r#"global $wpdb; $n = $wpdb->query("DELETE FROM {$wpdb->prefix}actionscheduler_actions WHERE status = 'complete' AND scheduled_date_gmt < DATE_SUB(NOW(), INTERVAL 1 DAY)"); echo "Deleted {$n} completed action(s).\n";"#
            }
            Self::PaymentTransients => {
                r#"global $wpdb; $n = $wpdb->query("DELETE FROM {$wpdb->prefix}options WHERE option_name REGEXP '_transient_(timeout_)?(stripe|paypal|wc_braintree|wc_paypal)'"); echo "Deleted {$n} transient(s).\n";"#
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    action: String,
    container: String,
    root: String,
    uid: u32,
    gid: u32,
}

pub struct Request {
    action: Action,
    container: ContainerName,
    root: PathBuf,
    uid: u32,
    gid: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct RequestError;

impl Request {
    pub fn parse(json: &str) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError)?;
        let root = PathBuf::from(plan.root);
        if !root.is_absolute()
            || root.as_os_str().len() > 4096
            || root
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(RequestError);
        }
        Ok(Self {
            action: Action::parse(&plan.action).ok_or(RequestError)?,
            container: ContainerName::parse(&plan.container)
                .map_err(|_: RestoreRequestError| RequestError)?,
            root,
            uid: plan.uid,
            gid: plan.gid,
        })
    }

    pub fn root(&self) -> &std::path::Path {
        &self.root
    }
}

#[derive(Debug, serde::Serialize)]
pub struct CleanupResult {
    pub output: String,
}

#[derive(Debug)]
pub enum ExecuteError {
    Run(process::ProcessRunError),
    Rejected(SubprocessDiagnostics),
    TooLarge,
    InvalidUtf8,
}
impl ExecuteError {
    pub fn protocol(&self) -> (ErrorCode, &'static str) {
        match self {
            Self::Run(e) => (
                process::spawn_error_code(e),
                "could not run WordPress cleanup",
            ),
            Self::Rejected(d) if d.timed_out => (ErrorCode::Timeout, "WordPress cleanup timed out"),
            Self::Rejected(_) => (ErrorCode::SubprocessFailed, "WordPress cleanup failed"),
            Self::TooLarge => (
                ErrorCode::Internal,
                "WordPress cleanup output exceeded its limit",
            ),
            Self::InvalidUtf8 => (
                ErrorCode::Internal,
                "WordPress cleanup output was not valid UTF-8",
            ),
        }
    }
}

pub fn execute(request: &Request, docker: &str) -> Result<CleanupResult, ExecuteError> {
    let args = [
        "exec".to_owned(),
        "-i".to_owned(),
        "--user".to_owned(),
        format!("{}:{}", request.uid, request.gid),
        request.container.as_str().to_owned(),
        "wp".to_owned(),
        format!("--path={}", request.root.display()),
        "--allow-root".to_owned(),
        "eval".to_owned(),
        request.action.php().to_owned(),
    ];
    let output = process::run(
        &ProcessRequest::new(docker).args(args),
        &ProcessLimits {
            timeout: Duration::from_secs(120),
            max_stdout_bytes: 64 * 1024,
            max_stderr_bytes: 64 * 1024,
        },
        &CancellationToken::default(),
    )
    .map_err(ExecuteError::Run)?;
    if !matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        return Err(ExecuteError::Rejected(SubprocessDiagnostics::from_output(
            docker, &output,
        )));
    }
    if output.stdout.truncated || output.stderr.truncated {
        return Err(ExecuteError::TooLarge);
    }
    let bytes = if output.stdout.bytes.is_empty() {
        output.stderr.bytes
    } else {
        output.stdout.bytes
    };
    String::from_utf8(bytes)
        .map(|output| CleanupResult { output })
        .map_err(|_| ExecuteError::InvalidUtf8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    #[test]
    fn accepts_only_known_actions_and_safe_identifiers() {
        assert!(Request::parse(r#"{"action":"revisions","container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1000}"#).is_ok());
        assert!(Request::parse(r#"{"action":"shell","container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1000}"#).is_err());
        assert!(Request::parse(r#"{"action":"revisions","container":"bad;name","root":"/var/www/site","uid":1000,"gid":1000}"#).is_err());
    }

    #[test]
    fn passes_the_fixed_php_as_one_argv_element() {
        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("fake-docker");
        fs::write(&script, "#!/bin/sh\nprintf '%s\\n' \"$@\"\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let request = Request::parse(r#"{"action":"revisions","container":"runtime-1","root":"/var/www/site","uid":1000,"gid":1001}"#).unwrap();

        let result = execute(&request, script.to_str().unwrap()).unwrap();

        let args: Vec<_> = result.output.lines().collect();
        assert_eq!(
            &args[..8],
            [
                "exec",
                "-i",
                "--user",
                "1000:1001",
                "runtime-1",
                "wp",
                "--path=/var/www/site",
                "--allow-root"
            ]
        );
        assert_eq!(args[8], "eval");
        assert!(args[9].contains("post_type = 'revision'"));
        assert_eq!(args.len(), 10);
    }
}
