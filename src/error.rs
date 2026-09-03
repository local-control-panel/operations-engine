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
    /// A verified artifact could not be proven to run on this host, so it
    /// was rejected before anything was activated.
    ArtifactNotRunnable,
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
            Self::ArtifactNotRunnable => "ARTIFACT_NOT_RUNNABLE",
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
    /// An `engine.install`/`engine.rollback` completed — the binary at
    /// `/usr/local/bin/ops-engine` really was switched — but the
    /// `install.state` record naming the active and rollback-able
    /// versions could not be written afterward. Unlike a missing
    /// transaction record this is operationally significant: until it is
    /// repaired, `engine rollback` would restore the version named by the
    /// stale record rather than the one just replaced.
    InstallStateRecordIncomplete,
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
        assert_eq!(
            serde_json::to_string(&WarningCode::InstallStateRecordIncomplete)
                .expect("code should serialize"),
            "\"INSTALL_STATE_RECORD_INCOMPLETE\""
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
        assert_eq!(
            serde_json::to_string(&ErrorCode::ArtifactNotRunnable).expect("code should serialize"),
            "\"ARTIFACT_NOT_RUNNABLE\""
        );
        assert_eq!(
            ErrorCode::ArtifactNotRunnable.as_str(),
            "ARTIFACT_NOT_RUNNABLE"
        );
    }
}
