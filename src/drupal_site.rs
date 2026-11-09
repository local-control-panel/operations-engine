//! Which Drupal site a request is about, in a Drupal multisite project.
//!
//! A multisite project keeps one directory per site under `sites/`, and a
//! `sites.php` that maps host names to those directories. The directory is
//! not always the host name, and several hosts may share one directory.
//!
//! This module only *describes and checks* an identity; no operation uses it
//! yet. It never runs `sites.php`: the file is read as text and accepted only
//! when every line is a plain `$sites['host'] = 'directory';` assignment.
//! Anything else (a function call, an `include`, a variable, a multi-line
//! statement) is a dynamic map and is refused, because evaluating it would
//! run site code as root. There is no fallback to `default`: a host that is
//! not mapped has no identity.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

const MAX_MAP_BYTES: usize = 64 * 1024;
const MAX_MAP_ENTRIES: usize = 1024;
const MAX_HOST_LEN: usize = 253;
const MAX_DIR_LEN: usize = 128;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The map is too large, or has more entries than allowed.
    MapTooLarge,
    /// The map contains something other than plain assignments.
    DynamicMap,
    InvalidHost,
    InvalidDirectory,
    /// The host has no entry in the map.
    NotMapped,
    /// `sites/<dir>` is missing, not a directory, a symlink, or outside the root.
    DirectoryNotUsable,
}

/// `host -> sites/<directory>` as written in `sites.php`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SitesMap(BTreeMap<String, String>);

impl SitesMap {
    /// Parses the text of a `sites.php`. An empty or comment-only file is an
    /// empty map.
    pub fn parse(text: &str) -> Result<Self, Error> {
        if text.len() > MAX_MAP_BYTES {
            return Err(Error::MapTooLarge);
        }
        let mut entries = BTreeMap::new();
        let mut in_block_comment = false;
        for raw in text.lines() {
            let mut line = raw.trim();
            if in_block_comment {
                match line.find("*/") {
                    Some(end) => {
                        line = line[end + 2..].trim();
                        in_block_comment = false;
                    }
                    None => continue,
                }
            }
            if line.is_empty() || line == "<?php" || line.starts_with("//") || line.starts_with('#')
            {
                continue;
            }
            if line.starts_with("/*") {
                if !line.contains("*/") {
                    in_block_comment = true;
                }
                continue;
            }
            let (host, dir) = assignment(line).ok_or(Error::DynamicMap)?;
            check_host(host)?;
            check_directory(dir)?;
            entries.insert(host.to_owned(), dir.to_owned());
            if entries.len() > MAX_MAP_ENTRIES {
                return Err(Error::MapTooLarge);
            }
        }
        if in_block_comment {
            return Err(Error::DynamicMap);
        }
        Ok(Self(entries))
    }

    /// The directory for exactly this host. No parent-domain search and no
    /// `default`.
    pub fn directory(&self, host: &str) -> Result<&str, Error> {
        self.0.get(host).map(String::as_str).ok_or(Error::NotMapped)
    }
}

/// `$sites['host'] = 'dir';`, optionally followed by a `//` comment. Returns
/// the two quoted strings, or `None` for any other shape.
fn assignment(line: &str) -> Option<(&str, &str)> {
    let rest = line.strip_prefix("$sites[")?;
    let (host, rest) = quoted(rest)?;
    let rest = rest.trim_start().strip_prefix(']')?;
    let rest = rest.trim_start().strip_prefix('=')?;
    let (dir, rest) = quoted(rest.trim_start())?;
    let rest = rest.trim_start().strip_prefix(';')?.trim();
    (rest.is_empty() || rest.starts_with("//") || rest.starts_with('#')).then_some((host, dir))
}

/// A single- or double-quoted string without escapes or interpolation.
fn quoted(text: &str) -> Option<(&str, &str)> {
    let quote = text.chars().next().filter(|c| *c == '\'' || *c == '"')?;
    let body = &text[1..];
    let end = body.find(quote)?;
    let value = &body[..end];
    if value.contains('\\') || (quote == '"' && value.contains(['$', '{'])) {
        return None;
    }
    Some((value, &body[end + 1..]))
}

fn check_host(host: &str) -> Result<(), Error> {
    let ok = !host.is_empty()
        && host.len() <= MAX_HOST_LEN
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && !host.starts_with(['.', '-'])
        && !host.ends_with(['.', '-'])
        && !host.contains("..");
    ok.then_some(()).ok_or(Error::InvalidHost)
}

/// One path component under `sites/`: no separators, no dot names, not the
/// shared `all` directory.
fn check_directory(dir: &str) -> Result<(), Error> {
    let ok = !dir.is_empty()
        && dir.len() <= MAX_DIR_LEN
        && dir
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        && !dir.starts_with('.')
        && !dir.contains("..")
        && dir != "all";
    ok.then_some(()).ok_or(Error::InvalidDirectory)
}

/// One site of a project: where the project is, which host asked, and which
/// `sites/<directory>` it maps to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrupalSiteIdentity {
    project_root: PathBuf,
    host: String,
    directory: String,
}

impl DrupalSiteIdentity {
    /// Builds an identity for `host` from the project's map and checks that
    /// `sites/<directory>` is a real directory inside the project root.
    pub fn resolve(project_root: &Path, map: &SitesMap, host: &str) -> Result<Self, Error> {
        check_host(host)?;
        let directory = map.directory(host)?.to_owned();
        let project_root = project_root
            .canonicalize()
            .map_err(|_| Error::DirectoryNotUsable)?;
        confirm_directory(&project_root, &directory)?;
        Ok(Self {
            project_root,
            host: host.to_owned(),
            directory,
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    /// `sites/<directory>`, relative to the project root.
    pub fn relative_path(&self) -> PathBuf {
        Path::new("sites").join(&self.directory)
    }

    pub fn project_root(&self) -> &Path {
        &self.project_root
    }
}

fn confirm_directory(root: &Path, directory: &str) -> Result<(), Error> {
    check_directory(directory)?;
    let path = root.join("sites").join(directory);
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| Error::DirectoryNotUsable)?;
    if !metadata.is_dir() {
        // Covers a symlink (even one that stays inside the root) and a file.
        return Err(Error::DirectoryNotUsable);
    }
    let real = path.canonicalize().map_err(|_| Error::DirectoryNotUsable)?;
    if real.starts_with(root.join("sites")) {
        Ok(())
    } else {
        Err(Error::DirectoryNotUsable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const MAP: &str = "<?php\n// comment\n$sites['example.com'] = 'main';\n$sites['www.example.com'] = 'main';\n$sites[\"shop.example.com\"] = \"shop_dir\"; // trailing\n/* block\n comment */\n";

    #[test]
    fn a_static_map_with_aliases_and_a_directory_that_is_not_the_host_parses() {
        let map = SitesMap::parse(MAP).unwrap();
        assert_eq!(map.directory("example.com"), Ok("main"));
        assert_eq!(map.directory("www.example.com"), Ok("main"));
        assert_eq!(map.directory("shop.example.com"), Ok("shop_dir"));
    }

    #[test]
    fn an_unmapped_host_has_no_identity_and_does_not_fall_back_to_default() {
        let map = SitesMap::parse(MAP).unwrap();
        assert_eq!(map.directory("other.example.com"), Err(Error::NotMapped));
        assert_eq!(map.directory("default"), Err(Error::NotMapped));
        assert_eq!(SitesMap::parse("").unwrap(), SitesMap::default());
    }

    #[test]
    fn anything_that_is_not_a_plain_assignment_is_a_dynamic_map() {
        for text in [
            "$sites['a.com'] = getenv('SITE');",
            "$sites['a.com'] = $dir;",
            "include 'more-sites.php';",
            "$sites = ['a.com' => 'a'];",
            "$sites['a.com'] =\n  'a';",
            "$sites['a.com'] = 'a'; $sites['b.com'] = 'b';",
            "$sites['a.com'] = \"$dir\";",
            "$sites['a.com'] = 'a\\'b';",
            "if (1) { $sites['a.com'] = 'a'; }",
            "/* never closed\n$sites['a.com'] = 'a';",
        ] {
            assert_eq!(SitesMap::parse(text), Err(Error::DynamicMap), "{text:?}");
        }
    }

    #[test]
    fn hosts_and_directories_are_single_safe_components() {
        for dir in ["..", "../x", "a/b", "/abs", ".hidden", "all", "", "a b"] {
            let text = format!("$sites['a.com'] = '{dir}';");
            assert_eq!(
                SitesMap::parse(&text),
                Err(Error::InvalidDirectory),
                "{dir:?}"
            );
        }
        for host in ["", "-a.com", "a..com", "a.com.", "A B", "a/b"] {
            let text = format!("$sites['{host}'] = 'a';");
            assert_eq!(SitesMap::parse(&text), Err(Error::InvalidHost), "{host:?}");
        }
    }

    #[test]
    fn size_limits_are_enforced() {
        assert_eq!(
            SitesMap::parse(&"x".repeat(MAX_MAP_BYTES + 1)),
            Err(Error::MapTooLarge)
        );
        let many: String = (0..=MAX_MAP_ENTRIES)
            .map(|i| format!("$sites['h{i}.com'] = 'd{i}';\n"))
            .collect();
        assert_eq!(SitesMap::parse(&many), Err(Error::MapTooLarge));
    }

    #[test]
    fn an_identity_needs_a_real_directory_inside_the_project() {
        let project = tempfile::tempdir().unwrap();
        fs::create_dir_all(project.path().join("sites/main")).unwrap();
        let map = SitesMap::parse("$sites['example.com'] = 'main';").unwrap();
        let identity = DrupalSiteIdentity::resolve(project.path(), &map, "example.com").unwrap();
        assert_eq!(identity.host(), "example.com");
        assert_eq!(identity.relative_path(), Path::new("sites/main"));
        assert_eq!(
            identity.project_root(),
            project.path().canonicalize().unwrap()
        );

        let missing = SitesMap::parse("$sites['gone.com'] = 'gone';").unwrap();
        assert_eq!(
            DrupalSiteIdentity::resolve(project.path(), &missing, "gone.com"),
            Err(Error::DirectoryNotUsable)
        );
        assert_eq!(
            DrupalSiteIdentity::resolve(project.path(), &map, "other.com"),
            Err(Error::NotMapped)
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_site_directory_is_refused_even_inside_the_project() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir_all(project.path().join("sites/real")).unwrap();
        fs::create_dir_all(project.path().join("sites")).unwrap();
        std::os::unix::fs::symlink(outside.path(), project.path().join("sites/escape")).unwrap();
        std::os::unix::fs::symlink(
            project.path().join("sites/real"),
            project.path().join("sites/alias"),
        )
        .unwrap();
        for dir in ["escape", "alias"] {
            let map = SitesMap::parse(&format!("$sites['a.com'] = '{dir}';")).unwrap();
            assert_eq!(
                DrupalSiteIdentity::resolve(project.path(), &map, "a.com"),
                Err(Error::DirectoryNotUsable),
                "{dir}"
            );
        }
    }
}
