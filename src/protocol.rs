use serde::Serialize;
use serde_json::Value;

use crate::error::{ErrorCode, WarningCode};

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
    pub fn success<T: Serialize>(
        operation: &'static str,
        result: T,
    ) -> Result<Self, ResponseBuildError> {
        let result = serde_json::to_value(result).map_err(|_| ResponseBuildError)?;

        Ok(Self {
            protocol_version: PROTOCOL_VERSION,
            operation,
            ok: true,
            result: Some(result),
            warnings: Vec::new(),
            error: None,
        })
    }

    pub fn failure(operation: &'static str, code: ErrorCode, message: &str) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            operation,
            ok: false,
            result: None,
            warnings: Vec::new(),
            error: Some(ProtocolError {
                code,
                message: message.to_owned(),
                details: None,
            }),
        }
    }

    pub fn with_warnings(mut self, warnings: Vec<Warning>) -> Self {
        self.warnings = warnings;
        self
    }
}

#[derive(Debug)]
pub struct ResponseBuildError;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Warning {
    pub code: WarningCode,
    pub message: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolError {
    pub code: ErrorCode,
    pub message: String,
    pub details: Option<Value>,
}

#[cfg(test)]
mod tests {
    use serde::{Serialize, Serializer};

    use crate::error::ErrorCode;

    use super::Response;

    struct FailingResult;

    impl Serialize for FailingResult {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            Err(serde::ser::Error::custom("intentional test failure"))
        }
    }

    #[test]
    fn result_serialization_failure_is_returned_instead_of_panicking() {
        assert!(Response::success("test", FailingResult).is_err());
    }

    #[test]
    fn failure_response_has_no_partial_result() {
        let response = Response::failure("test", ErrorCode::Internal, "safe message");

        assert!(!response.ok);
        assert!(response.result.is_none());
        assert_eq!(
            response.error.expect("error must exist").code,
            ErrorCode::Internal
        );
    }
}
