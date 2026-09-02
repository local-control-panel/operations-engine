use std::process::Command;

use serde::Serialize;

use crate::protocol::{Response, Warning};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DoctorResult {
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
}

pub fn run() -> Response {
    let supported = cfg!(target_os = "linux");
    let warnings = if supported {
        Vec::new()
    } else {
        vec![Warning {
            code: "UNSUPPORTED_PLATFORM",
            message: format!(
                "Operations Engine targets Linux; this binary is running on {}",
                std::env::consts::OS
            ),
        }]
    };

    let result = DoctorResult {
        platform: Platform {
            os: std::env::consts::OS,
            architecture: std::env::consts::ARCH,
            supported,
        },
        dependencies: vec![
            inspect_dependency("git", &["--version"], &["site.deploy", "site.rollback"]),
            inspect_dependency("docker", &["--version"], &["stack", "site"]),
            inspect_dependency("caddy", &["version"], &["site.configure"]),
        ],
    };

    Response::success("doctor", result).with_warnings(warnings)
}

fn inspect_dependency(
    name: &'static str,
    args: &[&str],
    required_for: &'static [&'static str],
) -> Dependency {
    let output = Command::new(name).args(args).output();

    match output {
        Ok(output) if output.status.success() => Dependency {
            name,
            available: true,
            version: first_nonempty_line(&output.stdout)
                .or_else(|| first_nonempty_line(&output.stderr)),
            required_for,
        },
        _ => Dependency {
            name,
            available: false,
            version: None,
            required_for,
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
