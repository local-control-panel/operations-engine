use std::{fs::File, io::Read, path::Path};

use serde::Deserialize;

use crate::site::{SiteId, SiteRelativePath, TrustedRoot, ValidationError};

pub const CONFIG_SCHEMA_VERSION: u32 = 1;
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;

#[derive(Debug)]
pub struct EngineConfig {
    pub content_roots: Vec<TrustedRoot>,
    pub state_root: TrustedRoot,
    pub credential_root: TrustedRoot,
}

impl EngineConfig {
    pub fn from_json(json: &str) -> Result<Self, ConfigError> {
        let raw: RawEngineConfig =
            serde_json::from_str(json).map_err(|_| ConfigError::InvalidJson)?;
        if raw.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(ConfigError::UnsupportedSchema);
        }
        if raw.content_roots.is_empty() {
            return Err(ConfigError::EmptyContentRoots);
        }

        let content_roots = raw
            .content_roots
            .iter()
            .map(TrustedRoot::parse)
            .collect::<Result<Vec<_>, _>>()?;
        for (index, root) in content_roots.iter().enumerate() {
            if content_roots[..index]
                .iter()
                .any(|previous| roots_overlap(previous, root))
            {
                return Err(ConfigError::OverlappingContentRoots);
            }
        }

        let state_root = TrustedRoot::parse(raw.state_root)?;
        let credential_root = TrustedRoot::parse(raw.credential_root)?;
        if content_roots.iter().any(|content| {
            roots_overlap(content, &state_root) || roots_overlap(content, &credential_root)
        }) {
            return Err(ConfigError::PrivilegedRootOverlapsContent);
        }

        Ok(Self {
            content_roots,
            state_root,
            credential_root,
        })
    }

    #[cfg(unix)]
    pub fn load_root_owned(path: &Path) -> Result<Self, ConfigError> {
        Self::load_owned_by(path, 0)
    }

    #[cfg(unix)]
    fn load_owned_by(path: &Path, required_uid: u32) -> Result<Self, ConfigError> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let mut file = File::open(path).map_err(|_| ConfigError::Io)?;
        let metadata = file.metadata().map_err(|_| ConfigError::Io)?;
        if metadata.uid() != required_uid {
            return Err(ConfigError::InsecureOwner);
        }
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(ConfigError::InsecureMode);
        }

        let mut json = String::new();
        file.read_to_string(&mut json)
            .map_err(|_| ConfigError::Io)?;
        Self::from_json(&json)
    }
}

#[derive(Debug)]
pub struct SiteManifest {
    pub site_id: SiteId,
    pub domain: String,
    pub content_root: SiteRelativePath,
    pub site_user: String,
    pub repository: RepositoryPolicy,
}

impl SiteManifest {
    #[cfg(unix)]
    pub fn load_root_owned(path: &Path, expected: SiteId) -> Result<Self, ConfigError> {
        let json = read_owned_by(path, 0)?;
        Self::from_json_for_site(&json, expected)
    }

    pub fn from_json_for_site(json: &str, expected: SiteId) -> Result<Self, ConfigError> {
        let raw: RawSiteManifest =
            serde_json::from_str(json).map_err(|_| ConfigError::InvalidJson)?;
        if raw.schema_version != MANIFEST_SCHEMA_VERSION {
            return Err(ConfigError::UnsupportedSchema);
        }

        let site_id = SiteId::parse(&raw.site_id).map_err(|_| ConfigError::InvalidSiteId)?;
        if site_id != expected {
            return Err(ConfigError::SiteIdMismatch);
        }
        validate_domain(&raw.domain)?;
        validate_site_user(&raw.site_user)?;
        validate_bounded_text(&raw.repository.url, 2048)?;
        if raw.repository.allowed_branches.is_empty() {
            return Err(ConfigError::EmptyBranchPolicy);
        }
        for branch in &raw.repository.allowed_branches {
            validate_bounded_text(branch, 255)?;
        }

        Ok(Self {
            site_id,
            domain: raw.domain,
            content_root: SiteRelativePath::parse(raw.content_root)?,
            site_user: raw.site_user,
            repository: RepositoryPolicy {
                url: raw.repository.url,
                allowed_branches: raw.repository.allowed_branches,
                credential_id: SiteId::parse(&raw.repository.credential_id)
                    .map_err(|_| ConfigError::InvalidCredentialId)?,
            },
        })
    }
}

#[derive(Debug)]
pub struct RepositoryPolicy {
    pub url: String,
    pub allowed_branches: Vec<String>,
    pub credential_id: SiteId,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawEngineConfig {
    schema_version: u32,
    content_roots: Vec<String>,
    state_root: String,
    credential_root: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawSiteManifest {
    schema_version: u32,
    site_id: String,
    domain: String,
    content_root: String,
    site_user: String,
    repository: RawRepositoryPolicy,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawRepositoryPolicy {
    url: String,
    allowed_branches: Vec<String>,
    credential_id: String,
}

fn roots_overlap(left: &TrustedRoot, right: &TrustedRoot) -> bool {
    left.as_path().starts_with(right.as_path()) || right.as_path().starts_with(left.as_path())
}

fn validate_domain(value: &str) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > 253
        || value.starts_with('.')
        || value.ends_with('.')
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        return Err(ConfigError::InvalidDomain);
    }
    Ok(())
}

#[cfg(unix)]
fn read_owned_by(path: &Path, required_uid: u32) -> Result<String, ConfigError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let mut file = File::open(path).map_err(|_| ConfigError::Io)?;
    let metadata = file.metadata().map_err(|_| ConfigError::Io)?;
    if metadata.uid() != required_uid {
        return Err(ConfigError::InsecureOwner);
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(ConfigError::InsecureMode);
    }
    let mut json = String::new();
    file.read_to_string(&mut json)
        .map_err(|_| ConfigError::Io)?;
    Ok(json)
}

fn validate_site_user(value: &str) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > 32
        || !value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'_' | b'-'))
        })
    {
        return Err(ConfigError::InvalidSiteUser);
    }
    Ok(())
}

fn validate_bounded_text(value: &str, max: usize) -> Result<(), ConfigError> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(ConfigError::InvalidPolicyValue);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    InvalidJson,
    UnsupportedSchema,
    EmptyContentRoots,
    InvalidPath,
    OverlappingContentRoots,
    PrivilegedRootOverlapsContent,
    InvalidSiteId,
    InvalidCredentialId,
    SiteIdMismatch,
    InvalidDomain,
    InvalidSiteUser,
    EmptyBranchPolicy,
    InvalidPolicyValue,
    InsecureOwner,
    InsecureMode,
    Io,
}

impl From<ValidationError> for ConfigError {
    fn from(_: ValidationError) -> Self {
        Self::InvalidPath
    }
}

#[cfg(test)]
mod tests {
    use super::{ConfigError, EngineConfig, SiteManifest};
    use crate::site::SiteId;

    const SITE_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn config_json() -> &'static str {
        r#"{
          "schemaVersion": 1,
          "contentRoots": ["/var/www"],
          "stateRoot": "/var/lib/operations-engine",
          "credentialRoot": "/var/lib/operations-engine-credentials"
        }"#
    }

    fn manifest_json() -> String {
        format!(
            r#"{{
              "schemaVersion": 1,
              "siteId": "{SITE_ID}",
              "domain": "example.com",
              "contentRoot": "sites/{SITE_ID}",
              "siteUser": "site-example",
              "repository": {{
                "url": "git@github.com:example/site.git",
                "allowedBranches": ["main"],
                "credentialId": "{SITE_ID}"
              }}
            }}"#
        )
    }

    #[test]
    fn parses_valid_engine_config() {
        let config = EngineConfig::from_json(config_json()).expect("config should be valid");
        assert_eq!(config.content_roots[0].as_path().to_str(), Some("/var/www"));
    }

    #[test]
    fn rejects_overlapping_and_unknown_config() {
        let overlapping =
            config_json().replace("[\"/var/www\"]", "[\"/var/www\", \"/var/www/sites\"]");
        assert_eq!(
            EngineConfig::from_json(&overlapping).unwrap_err(),
            ConfigError::OverlappingContentRoots
        );
        let unknown = config_json().replace("\"schemaVersion\"", "\"unknown\"");
        assert_eq!(
            EngineConfig::from_json(&unknown).unwrap_err(),
            ConfigError::InvalidJson
        );
    }

    #[test]
    fn privileged_roots_must_not_overlap_content() {
        let overlapping = config_json().replace(
            "\"/var/lib/operations-engine\"",
            "\"/var/www/engine-state\"",
        );
        assert_eq!(
            EngineConfig::from_json(&overlapping).unwrap_err(),
            ConfigError::PrivilegedRootOverlapsContent
        );
    }

    #[test]
    fn manifest_must_match_requested_site() {
        let expected = SiteId::parse(SITE_ID).expect("site ID should be valid");
        let manifest = SiteManifest::from_json_for_site(&manifest_json(), expected)
            .expect("manifest should be valid");
        assert_eq!(manifest.site_id, expected);

        let other = SiteId::parse("123e4567-e89b-12d3-a456-426614174000")
            .expect("other site ID should be valid");
        assert_eq!(
            SiteManifest::from_json_for_site(&manifest_json(), other).unwrap_err(),
            ConfigError::SiteIdMismatch
        );
    }

    #[cfg(unix)]
    #[test]
    fn secure_loader_rejects_group_writable_config() {
        use std::{
            fs,
            os::unix::fs::{MetadataExt, PermissionsExt},
        };

        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let path = directory.path().join("config.json");
        fs::write(&path, config_json()).expect("config should be written");
        let uid = fs::metadata(&path).expect("metadata should exist").uid();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o664))
            .expect("permissions should change");

        assert_eq!(
            EngineConfig::load_owned_by(&path, uid).unwrap_err(),
            ConfigError::InsecureMode
        );
    }

    #[cfg(unix)]
    #[test]
    fn secure_loader_rejects_unexpected_owner() {
        use std::{fs, os::unix::fs::MetadataExt};

        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let path = directory.path().join("config.json");
        fs::write(&path, config_json()).expect("config should be written");
        let actual_uid = fs::metadata(&path).expect("metadata should exist").uid();

        assert_eq!(
            EngineConfig::load_owned_by(&path, actual_uid.saturating_add(1)).unwrap_err(),
            ConfigError::InsecureOwner
        );
    }

    #[test]
    fn manifest_rejects_invalid_domain_labels_and_credential_id() {
        let expected = SiteId::parse(SITE_ID).expect("site ID should be valid");
        let invalid_domain = manifest_json().replace("example.com", "-example..com");
        assert_eq!(
            SiteManifest::from_json_for_site(&invalid_domain, expected).unwrap_err(),
            ConfigError::InvalidDomain
        );

        let invalid_credential = manifest_json().replace(
            &format!("\"credentialId\": \"{SITE_ID}\""),
            "\"credentialId\": \"not-a-uuid\"",
        );
        assert_eq!(
            SiteManifest::from_json_for_site(&invalid_credential, expected).unwrap_err(),
            ConfigError::InvalidCredentialId
        );
    }
}
