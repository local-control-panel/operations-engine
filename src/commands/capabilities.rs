use serde::Serialize;

use crate::protocol::Response;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CapabilitiesResult {
    operations: [&'static str; 3],
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

pub fn run() -> Response {
    Response::success(
        "capabilities",
        CapabilitiesResult {
            operations: ["version", "capabilities", "doctor"],
            output_formats: ["json"],
            features: Features {
                json_lines_progress: false,
                cancellation: false,
                mutations: false,
            },
        },
    )
}
