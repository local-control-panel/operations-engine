use serde::Serialize;

use crate::protocol::{PROTOCOL_VERSION, Response, ResponseBuildError};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VersionResult {
    engine_version: &'static str,
    protocol_version: u32,
    build: Build,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Build {
    target_os: &'static str,
    target_architecture: &'static str,
    git_commit: Option<&'static str>,
}

pub fn run() -> Result<Response, ResponseBuildError> {
    Response::success(
        "version",
        VersionResult {
            engine_version: env!("CARGO_PKG_VERSION"),
            protocol_version: PROTOCOL_VERSION,
            build: Build {
                target_os: std::env::consts::OS,
                target_architecture: std::env::consts::ARCH,
                git_commit: option_env!("OPS_ENGINE_GIT_COMMIT"),
            },
        },
    )
}
