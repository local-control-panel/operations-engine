//! Why a `composer update` failed, as a closed set the panel can explain.
//!
//! Composer's text never leaves the engine. The output is matched against a
//! few fixed phrases (taken from Composer 2.10, the version the engine
//! manages) and only the resulting reason is returned.

use crate::process::{ProcessOutput, SubprocessDiagnostics};

/// How much of each stream is looked at.
const MAX_SCAN_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComposerReason {
    /// Composer refuses a version that has a security advisory.
    AdvisoryBlocked,
    /// The constraints in `composer.json` cannot be satisfied.
    ResolutionConflict,
    /// The package registry could not be reached.
    RegistryUnreachable,
    DiskOrPermission,
    Timeout,
    Other,
}

impl ComposerReason {
    pub fn classify(diagnostics: &SubprocessDiagnostics, output: &ProcessOutput) -> Self {
        if diagnostics.timed_out {
            return Self::Timeout;
        }
        let text = scan_text(output);
        if has(
            &text,
            &[
                "no space left on device",
                "permission denied",
                "is not writable",
                "disk quota",
            ],
        ) {
            return Self::DiskOrPermission;
        }
        if has(&text, &["curl error", "you are offline"]) {
            return Self::RegistryUnreachable;
        }
        // Composer exits with 2 when the dependency solver finds no solution.
        if diagnostics.exit_code == Some(2) {
            return if has(&text, &["affected by security advisories"]) {
                Self::AdvisoryBlocked
            } else {
                Self::ResolutionConflict
            };
        }
        Self::Other
    }

    /// Stable token the panel maps to its own wording.
    pub fn token(self) -> &'static str {
        match self {
            Self::AdvisoryBlocked => "advisoryBlocked",
            Self::ResolutionConflict => "resolutionConflict",
            Self::RegistryUnreachable => "registryUnreachable",
            Self::DiskOrPermission => "diskOrPermission",
            Self::Timeout => "timeout",
            Self::Other => "other",
        }
    }

    pub fn sentence(self) -> &'static str {
        match self {
            Self::AdvisoryBlocked => "Composer refuses a version that has a security advisory",
            Self::ResolutionConflict => {
                "the version constraints in composer.json do not allow this update"
            }
            Self::RegistryUnreachable => "the package registry could not be reached",
            Self::DiskOrPermission => "Composer ran out of disk space or lacks permission",
            Self::Timeout => "Composer took too long",
            Self::Other => "Composer failed for another reason",
        }
    }
}

fn scan_text(output: &ProcessOutput) -> String {
    let mut text = String::new();
    for stream in [&output.stderr, &output.stdout] {
        let end = stream.bytes.len().min(MAX_SCAN_BYTES);
        text.push_str(&String::from_utf8_lossy(&stream.bytes[..end]));
        text.push('\n');
    }
    text.to_ascii_lowercase()
}

fn has(text: &str, phrases: &[&str]) -> bool {
    phrases.iter().any(|phrase| text.contains(phrase))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::{CapturedOutput, ProcessTermination};

    fn output(code: i32, stderr: &str) -> (SubprocessDiagnostics, ProcessOutput) {
        let output = ProcessOutput {
            termination: ProcessTermination::Exited {
                code: Some(code),
                success: code == 0,
            },
            stdout: CapturedOutput {
                bytes: Vec::new(),
                truncated: false,
            },
            stderr: CapturedOutput {
                bytes: stderr.as_bytes().to_vec(),
                truncated: false,
            },
        };
        (
            SubprocessDiagnostics::from_output("docker", &output),
            output,
        )
    }

    fn reason(code: i32, stderr: &str) -> ComposerReason {
        let (diagnostics, output) = output(code, stderr);
        ComposerReason::classify(&diagnostics, &output)
    }

    // The samples below are the output of Composer 2.10.3 on a Lima host.
    #[test]
    fn a_blocked_advisory_is_told_apart_from_a_conflict() {
        let advisory = "Your requirements could not be resolved to an installable set of packages.\n\n  \
            Problem 1\n    - Root composer.json requires symfony/http-foundation 5.4.0, found \
            symfony/http-foundation[v5.4.0] but these were not loaded, because they are affected by \
            security advisories (\"PKSA-x\").";
        assert_eq!(reason(2, advisory), ComposerReason::AdvisoryBlocked);
        let conflict = "Your requirements could not be resolved to an installable set of packages.\n\n  \
            Problem 1\n    - monolog/monolog[3.0.0] require psr/log ^2.0 || ^3.0 -> it conflicts with \
            your root composer.json require (^1.0).";
        assert_eq!(reason(2, conflict), ComposerReason::ResolutionConflict);
    }

    #[test]
    fn an_unreachable_registry_is_recognised() {
        let text = "The following exception probably indicates you are offline or have misconfigured \
            DNS resolver(s)\nIn CurlDownloader.php line 407:\n  curl error 6 while downloading \
            https://repo.packagist.org/packages.json";
        assert_eq!(reason(100, text), ComposerReason::RegistryUnreachable);
    }

    #[test]
    fn disk_and_permission_problems_win_over_the_exit_code() {
        assert_eq!(
            reason(
                1,
                "file_put_contents(vendor/x): Failed to open stream: No space left on device"
            ),
            ComposerReason::DiskOrPermission
        );
    }

    #[test]
    fn invalid_json_and_unknown_failures_are_other() {
        assert_eq!(
            reason(1, "\"./composer.json\" does not contain valid JSON"),
            ComposerReason::Other
        );
        assert_eq!(reason(7, ""), ComposerReason::Other);
    }

    #[test]
    fn a_timeout_is_a_timeout() {
        let output = ProcessOutput {
            termination: ProcessTermination::TimedOut,
            stdout: CapturedOutput {
                bytes: Vec::new(),
                truncated: false,
            },
            stderr: CapturedOutput {
                bytes: Vec::new(),
                truncated: false,
            },
        };
        let diagnostics = SubprocessDiagnostics::from_output("docker", &output);
        assert_eq!(
            ComposerReason::classify(&diagnostics, &output),
            ComposerReason::Timeout
        );
    }

    #[test]
    fn the_sentence_never_carries_tool_output() {
        for reason in [
            ComposerReason::AdvisoryBlocked,
            ComposerReason::ResolutionConflict,
            ComposerReason::RegistryUnreachable,
            ComposerReason::DiskOrPermission,
            ComposerReason::Timeout,
            ComposerReason::Other,
        ] {
            assert!(!reason.sentence().contains("PKSA"));
            assert!(reason.token().chars().all(|c| c.is_ascii_alphabetic()));
        }
    }
}
