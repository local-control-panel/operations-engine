use serde::Serialize;

use crate::protocol::{Response, ResponseBuildError};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CapabilitiesResult {
    operations: [&'static str; 7],
    output_formats: [&'static str; 1],
    features: Features,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Features {
    json_lines_progress: bool,
    cancellation: bool,
    mutations: bool,
}

pub fn run() -> Result<Response, ResponseBuildError> {
    Response::success(
        "capabilities",
        CapabilitiesResult {
            operations: [
                "version",
                "capabilities",
                "doctor",
                "site.deploy",
                "site.rollback",
                "engine.install",
                "engine.rollback",
            ],
            output_formats: ["json"],
            features: Features {
                json_lines_progress: false,
                cancellation: false,
                mutations: true,
            },
        },
    )
}
