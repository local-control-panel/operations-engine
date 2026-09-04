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
    /// The file the caller intended to replace no longer hashes to the
    /// value it supplied as `expectedPriorHash` — something else wrote to
    /// it between the caller's read and this request. Nothing was written.
    /// Distinct from `CONFIG_VALIDATION_FAILED` on purpose: the client's
    /// response is to re-read, re-apply its edit, and retry, not to fix
    /// the config it sent.
    ConfigHashMismatch,
    /// The submitted configuration was rejected by the service that has to
    /// run it (`caddy validate`), before anything reached the live path.
    /// The live configuration is untouched.
    ConfigValidationFailed,
    /// A live reload failed — typically a conflict with some other
    /// already-live config file that standalone validation cannot see. In
    /// every case this code is used, *this request wrote nothing that
    /// survived it*: nothing needs undoing and a retry is safe. What it
    /// does **not** uniformly promise is what the running server is on,
    /// because it has two producers with different guarantees:
    ///
    /// - `ReloadFailedAndRestored` — the submitted config was activated,
    ///   its reload failed, and the previous file was then put back *and*
    ///   successfully reloaded. Here what is live is exactly what was live
    ///   before this request. (The one exception is a reload that timed
    ///   out rather than returning a verdict: the engine stops waiting but
    ///   cannot kill the command inside the container, so it says so in
    ///   the message instead of claiming the restore is live.)
    /// - `ReloadFailedUnchanged` — the file already held the submitted
    ///   content, so nothing was written, and the reload that exists to
    ///   converge the running server onto it failed. Nothing on disk
    ///   changed, but the running server is on something the engine could
    ///   not identify — quite possibly not this file, since that
    ///   divergence is the reason the converging reload runs at all.
    ///
    /// So: safe to retry in both cases, but only the first lets a client
    /// assume the live configuration is the previous one. The response
    /// message distinguishes them; treat this code alone as "the reload
    /// did not take", not as "the previous config is live".
    ConfigReloadFailed,
    /// A reload failed *and* the recovery that follows it did not
    /// complete: either the previous file could not be put back or, once
    /// back, it could not be reloaded either. Unlike every other code
    /// here, this one means the live configuration may be neither what the
    /// caller asked for nor what was there before — it needs an operator,
    /// not a retry.
    ConfigRecoveryFailed,
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
            Self::ConfigHashMismatch => "CONFIG_HASH_MISMATCH",
            Self::ConfigValidationFailed => "CONFIG_VALIDATION_FAILED",
            Self::ConfigReloadFailed => "CONFIG_RELOAD_FAILED",
            Self::ConfigRecoveryFailed => "CONFIG_RECOVERY_FAILED",
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

    /// The four ingress-activation codes exist to be told apart by a
    /// client, so assert every one of them separately rather than
    /// spot-checking one.
    #[test]
    fn new_config_activation_error_codes_have_stable_distinct_protocol_values() {
        let codes = [
            (ErrorCode::ConfigHashMismatch, "CONFIG_HASH_MISMATCH"),
            (
                ErrorCode::ConfigValidationFailed,
                "CONFIG_VALIDATION_FAILED",
            ),
            (ErrorCode::ConfigReloadFailed, "CONFIG_RELOAD_FAILED"),
            (ErrorCode::ConfigRecoveryFailed, "CONFIG_RECOVERY_FAILED"),
        ];
        for (code, expected) in codes {
            assert_eq!(code.as_str(), expected);
            assert_eq!(
                serde_json::to_string(&code).expect("code should serialize"),
                format!("\"{expected}\"")
            );
        }
    }
}
