use std::{
    fmt,
    path::{Component, Path, PathBuf},
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SiteId(Uuid);

impl SiteId {
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        let uuid = Uuid::parse_str(value).map_err(|_| ValidationError::InvalidSiteId)?;
        if uuid.is_nil() || value != uuid.hyphenated().to_string() {
            return Err(ValidationError::InvalidSiteId);
        }
        Ok(Self(uuid))
    }
}

impl fmt::Display for SiteId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.hyphenated().fmt(formatter)
    }
}

impl FromStr for SiteId {
    type Err = ValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// A validated DNS hostname. The rules are exactly the ones `config.rs`
/// already applied to a site manifest's `domain` field (which now parses
/// through this type, so the two cannot drift apart): 1-253 bytes, no
/// leading or trailing dot, and every dot-separated label 1-63 bytes of
/// lowercase ASCII letters, digits, or hyphens, never starting or ending
/// with a hyphen.
///
/// That character set is also what makes a `Domain` safe to interpolate
/// into a single path segment — `<domain>.caddyfile` for the ingress route
/// file named after it. `/`, `\0`, `.`-only segments, and every other
/// component-splitting or traversal byte are already excluded above, so
/// the resulting name is always one `Component::Normal`. `SiteRelativePath`
/// still re-checks it; this only means that check can never be the thing
/// standing between a request and a path escape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Domain(String);

impl Domain {
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        if value.is_empty()
            || value.len() > 253
            || value.starts_with('.')
            || value.ends_with('.')
            || value.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
        {
            return Err(ValidationError::InvalidDomain);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A validated runtime-pool identifier (`website-control-panel`'s
/// `runtime_id`, e.g. `fp1-php83`) — 1-64 bytes of lowercase ASCII letters,
/// digits, or hyphens, never starting or ending with a hyphen. The same
/// per-label character-class rule `Domain::parse` applies to each of its
/// dot-separated labels, applied here to the whole string once, since a
/// runtime id has no dots at all.
///
/// That character set is what makes a `RuntimeId` safe to interpolate into
/// a single path segment (`runtime_config::route_path`'s `{runtime_id}/`
/// prefix) exactly the way `Domain`'s own doc comment argues for
/// `<domain>.caddyfile`: `/`, `\0`, and every other component-splitting or
/// traversal byte are already excluded above, so the resulting segment is
/// always one `Component::Normal`. `SiteRelativePath` still re-checks it;
/// this only means that check can never be the thing standing between a
/// request and a path escape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeId(String);

impl RuntimeId {
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        if value.is_empty()
            || value.len() > 64
            || value.starts_with('-')
            || value.ends_with('-')
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(ValidationError::InvalidRuntimeId);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RuntimeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A validated Docker Compose stack identifier (`website-control-panel`'s
/// `stack_name`) — mirrors that client's own `is_valid_stack_name`: 1-64
/// bytes, first byte ASCII alphanumeric, every subsequent byte ASCII
/// alphanumeric or one of `_`, `.`, `-`, and never exactly `.` or `..`.
/// Wider than `RuntimeId`'s charset (mixed case and `_`/`.` allowed) because
/// it has to accept whatever the client already accepts, not invent a
/// stricter rule the client doesn't enforce. The leading-alphanumeric rule
/// alone already rules out a leading `.`/`-`/`/`, and the explicit `.`/`..`
/// rejection closes the one remaining traversal-segment case that rule
/// doesn't - `compose::route_path`'s `{stack_name}/docker-compose.yml`
/// prefix is always one `Component::Normal` for the same reason
/// `RuntimeId`'s doc comment argues for its own path safety.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StackName(String);

impl StackName {
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        if value.is_empty() || value.len() > 64 || value == "." || value == ".." {
            return Err(ValidationError::InvalidStackName);
        }
        let mut bytes = value.bytes();
        match bytes.next() {
            Some(byte) if byte.is_ascii_alphanumeric() => {}
            _ => return Err(ValidationError::InvalidStackName),
        }
        if !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')) {
            return Err(ValidationError::InvalidStackName);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StackName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedRoot(PathBuf);

impl TrustedRoot {
    pub fn parse(path: impl AsRef<Path>) -> Result<Self, ValidationError> {
        let path = path.as_ref();
        validate_absolute_normal_path(path)?;
        if path.parent().is_none() {
            return Err(ValidationError::RootFilesystemNotAllowed);
        }
        Ok(Self(path.to_owned()))
    }

    pub fn as_path(&self) -> &Path {
        &self.0
    }

    pub fn join(&self, relative: &SiteRelativePath) -> PathBuf {
        self.0.join(relative.as_path())
    }

    pub fn resolve_existing(
        &self,
        relative: &SiteRelativePath,
    ) -> Result<PathBuf, ValidationError> {
        let canonical_root = self
            .0
            .canonicalize()
            .map_err(|_| ValidationError::PathResolutionFailed)?;
        let canonical_candidate = self
            .join(relative)
            .canonicalize()
            .map_err(|_| ValidationError::PathResolutionFailed)?;

        if !canonical_candidate.starts_with(&canonical_root) {
            return Err(ValidationError::PathEscapesTrustedRoot);
        }
        Ok(canonical_candidate)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SiteRelativePath(PathBuf);

impl SiteRelativePath {
    pub fn parse(path: impl AsRef<Path>) -> Result<Self, ValidationError> {
        let path = path.as_ref();
        if path.as_os_str().is_empty()
            || path.is_absolute()
            || has_noncanonical_separators(path, false)
        {
            return Err(ValidationError::InvalidRelativePath);
        }
        if has_forbidden_raw_segment(path)
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(ValidationError::InvalidRelativePath);
        }
        Ok(Self(path.to_owned()))
    }

    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GitCommitSha(String);

impl GitCommitSha {
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        if !matches!(value.len(), 40 | 64) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ValidationError::InvalidCommitSha);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for GitCommitSha {
    type Err = ValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

fn validate_absolute_normal_path(path: &Path) -> Result<(), ValidationError> {
    if !path.is_absolute()
        || has_forbidden_raw_segment(path)
        || has_noncanonical_separators(path, true)
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(ValidationError::InvalidTrustedRoot);
    }
    Ok(())
}

fn has_noncanonical_separators(path: &Path, absolute: bool) -> bool {
    let bytes = path.as_os_str().as_encoded_bytes();
    (bytes.len() > usize::from(absolute) && bytes.last() == Some(&b'/'))
        || bytes.windows(2).any(|window| window == b"//")
}

fn has_forbidden_raw_segment(path: &Path) -> bool {
    path.as_os_str()
        .as_encoded_bytes()
        .split(|byte| *byte == b'/')
        .any(|segment| segment == b"." || segment == b".." || segment.contains(&0))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    InvalidSiteId,
    InvalidDomain,
    InvalidRuntimeId,
    InvalidStackName,
    InvalidTrustedRoot,
    RootFilesystemNotAllowed,
    InvalidRelativePath,
    InvalidCommitSha,
    PathResolutionFailed,
    PathEscapesTrustedRoot,
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use super::{
        Domain, GitCommitSha, RuntimeId, SiteId, SiteRelativePath, StackName, TrustedRoot,
        ValidationError,
    };

    #[test]
    fn domain_accepts_only_lowercase_label_syntax() {
        assert_eq!(
            Domain::parse("example.com")
                .expect("a plain hostname should parse")
                .as_str(),
            "example.com"
        );
        assert!(Domain::parse("a-b.sub.example.com").is_ok());
        assert!(Domain::parse("").is_err());
        assert!(Domain::parse("Example.com").is_err());
        assert!(Domain::parse(".example.com").is_err());
        assert!(Domain::parse("example.com.").is_err());
        assert!(Domain::parse("example..com").is_err());
        assert!(Domain::parse("-example.com").is_err());
        assert!(Domain::parse("example-.com").is_err());
        assert!(Domain::parse(&"a".repeat(254)).is_err());
        assert_eq!(
            Domain::parse("ex ample.com").unwrap_err(),
            ValidationError::InvalidDomain
        );
    }

    /// The property the ingress route file name depends on: nothing a
    /// `Domain` can hold makes `<domain>.caddyfile` anything other than one
    /// ordinary path component.
    #[test]
    fn domain_never_contains_a_path_separator_or_traversal_segment() {
        for hostile in [
            "../etc/passwd",
            "a/b.com",
            "..",
            ".",
            "a\0b.com",
            "/absolute.com",
        ] {
            assert!(
                Domain::parse(hostile).is_err(),
                "{hostile} must not parse as a domain"
            );
        }
        let domain = Domain::parse("example.com").expect("domain should parse");
        let relative = SiteRelativePath::parse(format!("{domain}.caddyfile"))
            .expect("a domain-derived route name should always be a valid relative path");
        assert_eq!(relative.as_path().components().count(), 1);
    }

    #[test]
    fn runtime_id_accepts_only_lowercase_hyphenated_syntax() {
        assert_eq!(
            RuntimeId::parse("fp1-php83")
                .expect("a plain runtime id should parse")
                .as_str(),
            "fp1-php83"
        );
        assert!(RuntimeId::parse("").is_err());
        assert!(RuntimeId::parse("FP1-PHP83").is_err());
        assert!(RuntimeId::parse("-fp1-php83").is_err());
        assert!(RuntimeId::parse("fp1-php83-").is_err());
        assert!(RuntimeId::parse("fp1_php83").is_err());
        assert!(RuntimeId::parse(&"a".repeat(65)).is_err());
        assert!(RuntimeId::parse(&"a".repeat(64)).is_ok());
        assert_eq!(
            RuntimeId::parse("fp1 php83").unwrap_err(),
            ValidationError::InvalidRuntimeId
        );
    }

    /// The property `runtime_config::route_path`'s `{runtime_id}/` prefix
    /// depends on: nothing a `RuntimeId` can hold makes that path segment
    /// anything other than one ordinary path component.
    #[test]
    fn runtime_id_never_contains_a_path_separator_or_traversal_segment() {
        for hostile in ["../etc/passwd", "a/b", "..", ".", "a\0b", "/absolute"] {
            assert!(
                RuntimeId::parse(hostile).is_err(),
                "{hostile} must not parse as a runtime id"
            );
        }
        let runtime_id = RuntimeId::parse("fp1-php83").expect("runtime id should parse");
        let relative = SiteRelativePath::parse(format!("{runtime_id}/example.com.caddyfile"))
            .expect("a runtime-id-derived path should always be a valid relative path");
        assert_eq!(relative.as_path().components().count(), 2);
    }

    #[test]
    fn stack_name_accepts_mixed_case_and_dots_but_not_bare_dot_segments() {
        assert_eq!(
            StackName::parse("wp-stack_1.prod")
                .expect("a mixed-charset stack name should parse")
                .as_str(),
            "wp-stack_1.prod"
        );
        assert!(StackName::parse("").is_err());
        assert!(StackName::parse(".").is_err());
        assert!(StackName::parse("..").is_err());
        assert!(StackName::parse("-leading-hyphen").is_err());
        assert!(StackName::parse(".leading-dot").is_err());
        assert!(StackName::parse(&"a".repeat(65)).is_err());
        assert!(StackName::parse(&"a".repeat(64)).is_ok());
        assert_eq!(
            StackName::parse("has space").unwrap_err(),
            ValidationError::InvalidStackName
        );
    }

    #[test]
    fn stack_name_never_contains_a_path_separator_or_traversal_segment() {
        for hostile in ["../etc/passwd", "a/b", "/absolute", "a\0b"] {
            assert!(
                StackName::parse(hostile).is_err(),
                "{hostile} must not parse as a stack name"
            );
        }
        let stack_name = StackName::parse("wp-stack").expect("stack name should parse");
        let relative = SiteRelativePath::parse(format!("{stack_name}/docker-compose.yml"))
            .expect("a stack-name-derived path should always be a valid relative path");
        assert_eq!(relative.as_path().components().count(), 2);
    }

    #[test]
    fn site_id_requires_canonical_lowercase_hyphenated_uuid() {
        let id = SiteId::parse("550e8400-e29b-41d4-a716-446655440000")
            .expect("canonical UUID should be accepted");
        assert_eq!(id.to_string(), "550e8400-e29b-41d4-a716-446655440000");
        assert!(SiteId::parse("550E8400-E29B-41D4-A716-446655440000").is_err());
        assert!(SiteId::parse("550e8400e29b41d4a716446655440000").is_err());
        assert!(SiteId::parse("00000000-0000-0000-0000-000000000000").is_err());
        assert!(SiteId::parse("example.com").is_err());
    }

    #[test]
    fn trusted_root_rejects_root_relative_and_lexical_traversal() {
        assert_eq!(
            TrustedRoot::parse("/").unwrap_err(),
            ValidationError::RootFilesystemNotAllowed
        );
        assert!(TrustedRoot::parse("var/www").is_err());
        assert!(TrustedRoot::parse("/var/www/../etc").is_err());
        assert!(TrustedRoot::parse("/var//www").is_err());
        assert!(TrustedRoot::parse("/var/www/").is_err());
        assert!(TrustedRoot::parse("/var/www\0/etc").is_err());
        assert!(TrustedRoot::parse("/var/www").is_ok());
    }

    #[test]
    fn relative_path_accepts_only_normal_components() {
        assert!(SiteRelativePath::parse("sites/site.json").is_ok());
        assert!(SiteRelativePath::parse("").is_err());
        assert!(SiteRelativePath::parse("/etc/passwd").is_err());
        assert!(SiteRelativePath::parse("../etc/passwd").is_err());
        assert!(SiteRelativePath::parse("sites//site.json").is_err());
        assert!(SiteRelativePath::parse("sites/").is_err());
        assert!(SiteRelativePath::parse("sites/./site.json").is_err());
        assert!(SiteRelativePath::parse("sites\0/site.json").is_err());
    }

    #[test]
    fn commit_sha_is_full_length_hex_and_normalized() {
        let sha = GitCommitSha::parse("ABCDEF0123456789ABCDEF0123456789ABCDEF01")
            .expect("full SHA-1 should be accepted");
        assert_eq!(sha.as_str(), "abcdef0123456789abcdef0123456789abcdef01");
        assert!(GitCommitSha::parse("abc123").is_err());
        assert!(GitCommitSha::parse(&"g".repeat(40)).is_err());
        assert!(GitCommitSha::parse(&"a".repeat(64)).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn existing_path_resolution_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temporary root should exist");
        let root_path = directory.path().join("managed");
        let outside_path = directory.path().join("outside");
        fs::create_dir_all(&root_path).expect("managed root should be created");
        fs::create_dir_all(&outside_path).expect("outside root should be created");
        fs::write(outside_path.join("secret"), "not managed")
            .expect("outside file should be created");
        symlink(&outside_path, root_path.join("escape")).expect("symlink should be created");

        let root = TrustedRoot::parse(&root_path).expect("root should be valid");
        let relative = SiteRelativePath::parse(Path::new("escape/secret"))
            .expect("relative path should be valid lexically");
        assert_eq!(
            root.resolve_existing(&relative).unwrap_err(),
            ValidationError::PathEscapesTrustedRoot
        );
    }
}
