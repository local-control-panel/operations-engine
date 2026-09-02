use serde::Serialize;
use serde_json::Value;

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    pub protocol_version: u32,
    pub operation: &'static str,
    pub ok: bool,
    pub result: Option<Value>,
    pub warnings: Vec<Warning>,
    pub error: Option<ProtocolError>,
}

impl Response {
    pub fn success<T: Serialize>(operation: &'static str, result: T) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            operation,
            ok: true,
            result: Some(serde_json::to_value(result).expect("result must be serializable")),
            warnings: Vec::new(),
            error: None,
        }
    }

    pub fn with_warnings(mut self, warnings: Vec<Warning>) -> Self {
        self.warnings = warnings;
        self
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Warning {
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolError {
    pub code: String,
    pub message: String,
    pub details: Option<Value>,
}
