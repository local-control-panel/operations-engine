use serde::Serialize;

use crate::protocol::{PROTOCOL_VERSION, Response};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VersionResult {
    engine_version: &'static str,
    protocol_version: u32,
}

pub fn run() -> Response {
    Response::success(
        "version",
        VersionResult {
            engine_version: env!("CARGO_PKG_VERSION"),
            protocol_version: PROTOCOL_VERSION,
        },
    )
}
