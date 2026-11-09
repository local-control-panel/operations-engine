//! Which Drupal site a request is about, in a Drupal multisite project.
//!
//! A multisite project keeps one directory per site under `sites/`, and a
//! `sites.php` that maps host names to those directories. The directory is
//! not always the host name, and several hosts may share one directory.
//!
//! This module *describes and checks* an identity, and defines the lock
//! order a Drupal mutation takes ([`acquire_locks`]). It never runs `sites.php`: the file is read as text and accepted only
//! when every line is a plain `$sites['host'] = 'directory';` assignment.
//! Anything else (a function call, an `include`, a variable, a multi-line
//! statement) is a dynamic map and is refused, because evaluating it would
//! run site code as root. There is no fallback to `default`: a host that is
//! not mapped has no identity.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use crate::{
    filesystem::ManagedRoot,
    transaction::{RequestId, lock::SiteLockGuard, resource_lock},
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

/// Reads `<docroot>/sites/sites.php` as text, without following a symlink.
/// A missing file is an empty map (so every host is unmapped); anything that
/// is not a regular file, or is too large, is refused.
#[cfg(unix)]
pub fn read_sites_map(docroot: &Path) -> Result<SitesMap, Error> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let path = docroot.join("sites").join("sites.php");
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(SitesMap::default());
        }
        Err(_) => return Err(Error::DirectoryNotUsable),
    };
    if !file
        .metadata()
        .map_err(|_| Error::DirectoryNotUsable)?
        .is_file()
    {
        return Err(Error::DirectoryNotUsable);
    }
    let mut bytes = Vec::new();
    file.take(MAX_MAP_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::DirectoryNotUsable)?;
    let text = String::from_utf8(bytes).map_err(|_| Error::DynamicMap)?;
    SitesMap::parse(&text)
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

pub fn check_host(host: &str) -> Result<(), Error> {
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
pub fn check_directory(dir: &str) -> Result<(), Error> {
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

    /// The directory name under `sites/`.
    pub fn directory(&self) -> &str {
        &self.directory
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

/// Why [`acquire_locks`] did not hand out the locks.
#[derive(Debug, PartialEq, Eq)]
pub enum LockError {
    /// Another request holds the project or the site, or the lock state
    /// could not be used. Nothing stays locked.
    Busy,
    /// The identity belongs to another project root than the one asked for.
    RootMismatch,
}

/// The locks a Drupal mutation holds. Dropping releases the site lock first,
/// then the project lock (field order).
pub struct SiteLocks<'a> {
    _site: Option<SiteLockGuard<'a>>,
    _project: SiteLockGuard<'a>,
}

/// The lock order of a Drupal mutation: the project lock first, then, only
/// when the request names a site of a multisite project, a lock for that
/// `sites/<directory>`. The order is never inverted.
///
/// The project lock is the same lock every single-site Drupal operation takes
/// (`resource_lock` on the project root), so a multisite request and a
/// single-site-style request on the same project exclude each other, and
/// Composer/core changes cannot overlap with work on any site. With no
/// identity this is exactly `resource_lock::acquire(project_root)`.
///
/// Locks never wait: a busy lock fails at once, and a guard already taken is
/// released on the way out.
pub fn acquire_locks<'a>(
    engine_state: &'a ManagedRoot,
    project_root: &Path,
    identity: Option<&DrupalSiteIdentity>,
    holder: RequestId,
) -> Result<SiteLocks<'a>, LockError> {
    if let Some(identity) = identity {
        if identity.project_root() != project_root {
            return Err(LockError::RootMismatch);
        }
    }
    let project =
        resource_lock::acquire(engine_state, project_root, holder).map_err(|_| LockError::Busy)?;
    let site = match identity {
        Some(identity) => Some(
            resource_lock::acquire(
                engine_state,
                &project_root.join(identity.relative_path()),
                holder,
            )
            .map_err(|_| LockError::Busy)?,
        ),
        None => None,
    };
    Ok(SiteLocks {
        _site: site,
        _project: project,
    })
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
        let mut many = String::new();
        for i in 0..=MAX_MAP_ENTRIES {
            many.push_str(&format!("$sites['h{i}.com'] = 'd{i}';\n"));
        }
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
    fn the_map_file_is_read_as_text_and_never_through_a_symlink() {
        let docroot = tempfile::tempdir().unwrap();
        fs::create_dir_all(docroot.path().join("sites")).unwrap();
        assert_eq!(read_sites_map(docroot.path()), Ok(SitesMap::default()));
        let file = docroot.path().join("sites/sites.php");
        fs::write(&file, "<?php\n$sites['a.com'] = 'a';\n").unwrap();
        assert_eq!(
            read_sites_map(docroot.path()).unwrap().directory("a.com"),
            Ok("a")
        );
        fs::remove_file(&file).unwrap();
        let elsewhere = docroot.path().join("elsewhere.php");
        fs::write(&elsewhere, "$sites['a.com'] = 'a';").unwrap();
        std::os::unix::fs::symlink(&elsewhere, &file).unwrap();
        assert_eq!(
            read_sites_map(docroot.path()),
            Err(Error::DirectoryNotUsable)
        );
        fs::remove_file(&file).unwrap();
        fs::write(&file, "$sites['a.com'] = getenv('X');").unwrap();
        assert_eq!(read_sites_map(docroot.path()), Err(Error::DynamicMap));
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

    mod locks {
        use super::*;
        use crate::{site::TrustedRoot, transaction::lock::LockError as RawLockError};

        const FIRST: &str = "550e8400-e29b-41d4-a716-446655440000";
        const SECOND: &str = "123e4567-e89b-12d3-a456-426614174000";

        fn id(uuid: &str) -> RequestId {
            RequestId::parse(uuid).unwrap()
        }

        fn engine_state(dir: &Path) -> ManagedRoot {
            ManagedRoot::open(&TrustedRoot::parse(dir).unwrap()).unwrap()
        }

        /// A project with two sites, `a.example.com` and `b.example.com`.
        fn project() -> (tempfile::TempDir, DrupalSiteIdentity, DrupalSiteIdentity) {
            let project = tempfile::tempdir().unwrap();
            for dir in ["a", "b"] {
                fs::create_dir_all(project.path().join("sites").join(dir)).unwrap();
            }
            let map =
                SitesMap::parse("$sites['a.example.com'] = 'a';\n$sites['b.example.com'] = 'b';\n")
                    .unwrap();
            let a = DrupalSiteIdentity::resolve(project.path(), &map, "a.example.com").unwrap();
            let b = DrupalSiteIdentity::resolve(project.path(), &map, "b.example.com").unwrap();
            (project, a, b)
        }

        #[test]
        fn a_request_without_identity_takes_the_plain_project_lock() {
            let (project, ..) = project();
            let state = tempfile::tempdir().unwrap();
            let state = engine_state(state.path());
            let root = project.path().canonicalize().unwrap();
            let held = acquire_locks(&state, &root, None, id(FIRST)).unwrap();
            assert!(matches!(
                resource_lock::acquire(&state, &root, id(SECOND)),
                Err(RawLockError::Held { .. })
            ));
            assert_eq!(
                acquire_locks(&state, &root, None, id(SECOND)).err(),
                Some(LockError::Busy)
            );
            drop(held);
            assert!(acquire_locks(&state, &root, None, id(SECOND)).is_ok());
        }

        #[test]
        fn two_sites_of_one_project_exclude_each_other_on_the_project_lock() {
            let (_project, a, b) = project();
            let state = tempfile::tempdir().unwrap();
            let state = engine_state(state.path());
            let root = a.project_root().to_path_buf();
            let held = acquire_locks(&state, &root, Some(&a), id(FIRST)).unwrap();
            assert_eq!(
                acquire_locks(&state, &root, Some(&b), id(SECOND)).err(),
                Some(LockError::Busy)
            );
            // Not even a single-site style request gets in.
            assert_eq!(
                acquire_locks(&state, &root, None, id(SECOND)).err(),
                Some(LockError::Busy)
            );
            drop(held);
            assert!(acquire_locks(&state, &root, Some(&b), id(SECOND)).is_ok());
        }

        #[test]
        fn the_same_site_twice_conflicts() {
            let (_project, a, _b) = project();
            let state = tempfile::tempdir().unwrap();
            let state = engine_state(state.path());
            let root = a.project_root().to_path_buf();
            let _held = acquire_locks(&state, &root, Some(&a), id(FIRST)).unwrap();
            assert_eq!(
                acquire_locks(&state, &root, Some(&a), id(SECOND)).err(),
                Some(LockError::Busy)
            );
        }

        #[test]
        fn a_failed_attempt_leaves_nothing_locked() {
            let (_project, a, _b) = project();
            let state = tempfile::tempdir().unwrap();
            let state = engine_state(state.path());
            let root = a.project_root().to_path_buf();
            let site_path = root.join(a.relative_path());

            // The site lock is held by someone else: the project lock taken
            // on the way is released again.
            let stray = resource_lock::acquire(&state, &site_path, id(SECOND)).unwrap();
            assert_eq!(
                acquire_locks(&state, &root, Some(&a), id(FIRST)).err(),
                Some(LockError::Busy)
            );
            assert!(resource_lock::acquire(&state, &root, id(FIRST)).is_ok());
            drop(stray);

            // The project lock is held by someone else: the site lock is
            // never touched.
            let project_holder = resource_lock::acquire(&state, &root, id(SECOND)).unwrap();
            assert_eq!(
                acquire_locks(&state, &root, Some(&a), id(FIRST)).err(),
                Some(LockError::Busy)
            );
            assert!(resource_lock::acquire(&state, &site_path, id(FIRST)).is_ok());
            drop(project_holder);

            // Everything is free again.
            assert!(acquire_locks(&state, &root, Some(&a), id(FIRST)).is_ok());
        }

        #[test]
        fn the_site_lock_is_held_inside_the_project_lock_and_released_first() {
            let (_project, a, _b) = project();
            let state = tempfile::tempdir().unwrap();
            let state = engine_state(state.path());
            let root = a.project_root().to_path_buf();
            let site_path = root.join(a.relative_path());
            let held = acquire_locks(&state, &root, Some(&a), id(FIRST)).unwrap();
            for path in [&root, &site_path] {
                assert!(matches!(
                    resource_lock::acquire(&state, path, id(SECOND)),
                    Err(RawLockError::Held { .. })
                ));
            }
            drop(held);
            for path in [&root, &site_path] {
                assert!(resource_lock::acquire(&state, path, id(SECOND)).is_ok());
            }
        }

        #[test]
        fn an_identity_of_another_project_is_refused() {
            let (_project, a, _b) = project();
            let other = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();
            let state = engine_state(state.path());
            assert_eq!(
                acquire_locks(
                    &state,
                    &other.path().canonicalize().unwrap(),
                    Some(&a),
                    id(FIRST)
                )
                .err(),
                Some(LockError::RootMismatch)
            );
        }

        #[test]
        fn racing_requests_on_two_sites_let_exactly_one_through() {
            let (_project, a, b) = project();
            let state_dir = tempfile::tempdir().unwrap();
            let root = a.project_root().to_path_buf();
            let barrier = std::sync::Barrier::new(2);
            let outcomes: Vec<bool> = std::thread::scope(|scope| {
                let handles: Vec<_> = [(&a, FIRST), (&b, SECOND)]
                    .into_iter()
                    .map(|(identity, holder)| {
                        let (barrier, root, state_path) =
                            (&barrier, &root, state_dir.path().to_path_buf());
                        scope.spawn(move || {
                            let state = engine_state(&state_path);
                            barrier.wait();
                            let attempt = acquire_locks(&state, root, Some(identity), id(holder));
                            let won = attempt.is_ok();
                            // Hold the lock until both have tried.
                            barrier.wait();
                            won
                        })
                    })
                    .collect();
                handles.into_iter().map(|h| h.join().unwrap()).collect()
            });
            assert_eq!(
                outcomes.iter().filter(|won| **won).count(),
                1,
                "{outcomes:?}"
            );
        }
    }
}
