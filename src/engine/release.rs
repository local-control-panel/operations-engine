//! A validated release version string, and the GitHub Releases URL shape
//! every `engine install` fetch is built from — never a caller-supplied
//! URL (see the design spec's "no ambient discovery" rule). `base_url` is
//! a parameter, not a hardcoded constant, purely so tests can point it at
//! a local fixture server; every production call site passes the one
//! `GITHUB_RELEASES_BASE` constant in `commands/engine.rs`.

use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineVersion(String);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidVersion;

impl EngineVersion {
    /// Accepts only `MAJOR.MINOR.PATCH` (no `v` prefix, no pre-release or
    /// build metadata) — the exact shape the release workflow tags and
    /// publishes. Rejecting anything else keeps this string safe to embed
    /// directly into a URL path segment and a filesystem path segment
    /// without further escaping.
    pub fn parse(value: &str) -> Result<Self, InvalidVersion> {
        let parts: Vec<&str> = value.split('.').collect();
        if parts.len() != 3
            || parts
                .iter()
                .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
        {
            return Err(InvalidVersion);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EngineVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// This host's architecture, mapped to the target-triple suffix the
/// release workflow names its binaries with. `None` means this build has
/// no published artifact for the running host — `engine install` must
/// fail rather than guess.
pub fn target_triple() -> Option<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Some("x86_64-unknown-linux-gnu"),
        "aarch64" => Some("aarch64-unknown-linux-gnu"),
        _ => None,
    }
}

pub fn binary_asset_name(version: &EngineVersion, target_triple: &str) -> String {
    format!("ops-engine-{version}-{target_triple}")
}

pub fn sha256sums_url(base_url: &str, version: &EngineVersion) -> String {
    format!("{base_url}/v{version}/SHA256SUMS")
}

pub fn sha256sums_minisig_url(base_url: &str, version: &EngineVersion) -> String {
    format!("{base_url}/v{version}/SHA256SUMS.minisig")
}

pub fn binary_url(base_url: &str, version: &EngineVersion, target_triple: &str) -> String {
    format!(
        "{base_url}/v{version}/{}",
        binary_asset_name(version, target_triple)
    )
}

#[cfg(test)]
mod tests {
    use super::{
        EngineVersion, binary_asset_name, binary_url, sha256sums_minisig_url, sha256sums_url,
    };

    #[test]
    fn version_accepts_major_minor_patch() {
        let version = EngineVersion::parse("0.5.0").expect("version should parse");
        assert_eq!(version.as_str(), "0.5.0");
        assert_eq!(version.to_string(), "0.5.0");
    }

    #[test]
    fn version_rejects_anything_else() {
        assert!(EngineVersion::parse("v0.5.0").is_err());
        assert!(EngineVersion::parse("0.5").is_err());
        assert!(EngineVersion::parse("0.5.0-rc1").is_err());
        assert!(EngineVersion::parse("0.5.x").is_err());
        assert!(EngineVersion::parse("../../etc").is_err());
        assert!(EngineVersion::parse("").is_err());
    }

    #[test]
    fn urls_are_built_from_the_given_base_and_version() {
        let version = EngineVersion::parse("0.5.0").expect("version should parse");
        assert_eq!(
            sha256sums_url("https://example.test/releases", &version),
            "https://example.test/releases/v0.5.0/SHA256SUMS"
        );
        assert_eq!(
            sha256sums_minisig_url("https://example.test/releases", &version),
            "https://example.test/releases/v0.5.0/SHA256SUMS.minisig"
        );
        assert_eq!(
            binary_url(
                "https://example.test/releases",
                &version,
                "x86_64-unknown-linux-gnu"
            ),
            "https://example.test/releases/v0.5.0/ops-engine-0.5.0-x86_64-unknown-linux-gnu"
        );
        assert_eq!(
            binary_asset_name(&version, "aarch64-unknown-linux-gnu"),
            "ops-engine-0.5.0-aarch64-unknown-linux-gnu"
        );
    }
}
