use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    Internal,
    InternalSerializationError,
    InvalidInput,
    UnsupportedPlatform,
    DependencyUnavailable,
    Conflict,
    Timeout,
    Cancelled,
    SubprocessFailed,
    ArtifactFetchFailed,
    ArtifactVerificationFailed,
}

impl ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Internal => "INTERNAL",
            Self::InternalSerializationError => "INTERNAL_SERIALIZATION_ERROR",
            Self::InvalidInput => "INVALID_INPUT",
            Self::UnsupportedPlatform => "UNSUPPORTED_PLATFORM",
            Self::DependencyUnavailable => "DEPENDENCY_UNAVAILABLE",
            Self::Conflict => "CONFLICT",
            Self::Timeout => "TIMEOUT",
            Self::Cancelled => "CANCELLED",
            Self::SubprocessFailed => "SUBPROCESS_FAILED",
            Self::ArtifactFetchFailed => "ARTIFACT_FETCH_FAILED",
            Self::ArtifactVerificationFailed => "ARTIFACT_VERIFICATION_FAILED",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WarningCode {
    UnsupportedPlatform,
    DependencyUnavailable,
    /// A mutation completed — the state it reports actually changed — but
    /// its transaction record could not be persisted afterward. The
    /// result is genuine; only the durable bookkeeping is in question.
    TransactionRecordIncomplete,
}

#[cfg(test)]
mod tests {
    use super::{ErrorCode, WarningCode};

    #[test]
    fn error_codes_have_stable_protocol_values() {
        assert_eq!(
            serde_json::to_string(&ErrorCode::InternalSerializationError)
                .expect("code should serialize"),
            "\"INTERNAL_SERIALIZATION_ERROR\""
        );
        assert_eq!(ErrorCode::Timeout.as_str(), "TIMEOUT");
    }

    #[test]
    fn warning_codes_have_stable_protocol_values() {
        assert_eq!(
            serde_json::to_string(&WarningCode::DependencyUnavailable)
                .expect("code should serialize"),
            "\"DEPENDENCY_UNAVAILABLE\""
        );
    }

    #[test]
    fn new_artifact_error_codes_have_stable_protocol_values() {
        assert_eq!(
            serde_json::to_string(&ErrorCode::ArtifactFetchFailed).expect("code should serialize"),
            "\"ARTIFACT_FETCH_FAILED\""
        );
        assert_eq!(
            serde_json::to_string(&ErrorCode::ArtifactVerificationFailed)
                .expect("code should serialize"),
            "\"ARTIFACT_VERIFICATION_FAILED\""
        );
    }
}
