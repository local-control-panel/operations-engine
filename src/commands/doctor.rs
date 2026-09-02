use std::time::Duration;

use serde::Serialize;

use crate::{
    error::WarningCode,
    process::{
        CancellationToken, ProcessLimits, ProcessRequest, ProcessRunError, ProcessTermination,
        run as run_process,
    },
    protocol::{Response, ResponseBuildError, Warning},
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DoctorResult {
    ready: bool,
    platform: Platform,
    dependencies: Vec<Dependency>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Platform {
    os: &'static str,
    architecture: &'static str,
    supported: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Dependency {
    name: &'static str,
    available: bool,
    version: Option<String>,
    required_for: &'static [&'static str],
    check: CheckStatus,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
enum CheckStatus {
    Passed,
    Missing,
    Failed,
    TimedOut,
}

pub fn run() -> Result<Response, ResponseBuildError> {
    let supported = cfg!(target_os = "linux");
    let mut warnings = if supported {
        Vec::new()
    } else {
        vec![Warning {
            code: WarningCode::UnsupportedPlatform,
            message: format!(
                "Operations Engine targets Linux; this binary is running on {}",
                std::env::consts::OS
            ),
        }]
    };

    let limits = ProcessLimits {
        timeout: Duration::from_secs(2),
        max_stdout_bytes: 16 * 1024,
        max_stderr_bytes: 16 * 1024,
    };
    let cancellation = CancellationToken::default();
    let dependencies = vec![
        inspect_dependency(
            "git",
            &["--version"],
            &["site.deploy", "site.rollback"],
            &limits,
            &cancellation,
        ),
        inspect_dependency(
            "docker",
            &["--version"],
            &["stack", "site"],
            &limits,
            &cancellation,
        ),
        inspect_dependency(
            "caddy",
            &["version"],
            &["site.configure"],
            &limits,
            &cancellation,
        ),
    ];

    warnings.extend(
        dependencies
            .iter()
            .filter(|dependency| !dependency.available)
            .map(|dependency| Warning {
                code: WarningCode::DependencyUnavailable,
                message: format!("{} is unavailable", dependency.name),
            }),
    );

    let result = DoctorResult {
        ready: supported && dependencies.iter().all(|dependency| dependency.available),
        platform: Platform {
            os: std::env::consts::OS,
            architecture: std::env::consts::ARCH,
            supported,
        },
        dependencies,
    };

    Response::success("doctor", result).map(|response| response.with_warnings(warnings))
}

fn inspect_dependency(
    name: &'static str,
    args: &[&str],
    required_for: &'static [&'static str],
    limits: &ProcessLimits,
    cancellation: &CancellationToken,
) -> Dependency {
    let output = run_process(&ProcessRequest::new(name).args(args), limits, cancellation);

    match output {
        Ok(output)
            if matches!(
                output.termination,
                ProcessTermination::Exited { success: true, .. }
            ) =>
        {
            Dependency {
                name,
                available: true,
                version: first_nonempty_line(&output.stdout.bytes)
                    .or_else(|| first_nonempty_line(&output.stderr.bytes)),
                required_for,
                check: CheckStatus::Passed,
            }
        }
        Ok(output) => Dependency {
            name,
            available: false,
            version: None,
            required_for,
            check: match output.termination {
                ProcessTermination::TimedOut => CheckStatus::TimedOut,
                ProcessTermination::Exited { .. } | ProcessTermination::Cancelled => {
                    CheckStatus::Failed
                }
            },
        },
        Err(ProcessRunError::Spawn(_)) => Dependency {
            name,
            available: false,
            version: None,
            required_for,
            check: CheckStatus::Missing,
        },
        Err(_) => Dependency {
            name,
            available: false,
            version: None,
            required_for,
            check: CheckStatus::Failed,
        },
    }
}

fn first_nonempty_line(bytes: &[u8]) -> Option<String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::first_nonempty_line;

    #[test]
    fn extracts_first_nonempty_line() {
        assert_eq!(
            first_nonempty_line(b"\n  git version 2.50.0  \nignored"),
            Some("git version 2.50.0".to_owned())
        );
    }

    #[test]
    fn returns_none_for_empty_output() {
        assert_eq!(first_nonempty_line(b" \n\t"), None);
    }
}
