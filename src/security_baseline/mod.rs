//! PHP code baseline: `security.baselineCapture`, `security.baselineCompare`,
//! `security.baselineAccept` and `security.baselinePrune`.
//!
//! A baseline is a SHA-256 map of the application's code files (path ->
//! hash, nothing else) that the operator explicitly accepted. Comparing it to
//! the code on disk shows added, changed and deleted files. It does not prove
//! the first snapshot was clean and it is server-local: a root compromise is
//! outside what it guarantees.
//!
//! * Storage: `<state root>/security-baselines/<domain>/` (0700, files 0600),
//!   root-owned, outside every web root. `index.json` names the accepted and
//!   candidate generation; `gen-<n>.json` files are immutable once written.
//!   Every write is a temporary name plus `rename`. A generation file that
//!   the index does not name (an interrupted capture) is swept by the next
//!   mutation.
//! * Capture only ever writes a *candidate*; it never replaces the accepted
//!   generation. Accept is explicit (generation + digest), re-scans under the
//!   project lock and refuses when the code no longer matches the candidate.
//! * Compare takes the same project lock as deploy and CMS mutations, so a
//!   concurrent update gives `conflict`, not a torn comparison.
//! * An unreadable, unstable or over-limit scan is incomplete: it is reported
//!   as such and can never be accepted.

mod ops;
pub mod scan;
mod store;

pub use ops::{
    Context, Error, Op, PruneMode, Request, RequestError, accept, capture, compare, prune,
};

use std::path::PathBuf;

pub const CAPTURE: &str = "security.baselineCapture";
pub const COMPARE: &str = "security.baselineCompare";
pub const ACCEPT: &str = "security.baselineAccept";
pub const PRUNE: &str = "security.baselinePrune";

pub const SCHEMA_VERSION: u32 = 1;
pub const ALGORITHM: &str = "sha256";
/// Generations kept per site (accepted + candidate + history).
pub const RETAINED_GENERATIONS: usize = 3;
/// Paths listed per category in a result.
pub const MAX_LISTED_PATHS: usize = 100;

/// File extensions that count as application code (case-insensitive).
pub const EXTENSIONS: &[&str] = &["php", "phtml", "inc", "module", "install", "theme", "phar"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Wordpress,
    Drupal,
    Joomla,
    Laravel,
}

impl Kind {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "wordpress" => Some(Self::Wordpress),
            "drupal" => Some(Self::Drupal),
            "joomla" => Some(Self::Joomla),
            "laravel" => Some(Self::Laravel),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Wordpress => "wordpress",
            Self::Drupal => "drupal",
            Self::Joomla => "joomla",
            Self::Laravel => "laravel",
        }
    }

    /// Directory patterns that are not scanned. Anchored at the project root;
    /// `*` stands for exactly one path segment and a leading `**/` matches the
    /// directory name at any depth.
    pub const fn excludes(self) -> &'static [&'static str] {
        match self {
            Self::Wordpress => &[
                "wp-content/uploads",
                "wp-content/cache",
                "wp-content/upgrade",
                "**/node_modules",
            ],
            Self::Drupal => &[
                "sites/*/files",
                "sites/*/private",
                "**/node_modules",
                "vendor",
            ],
            Self::Joomla => &["cache", "tmp", "administrator/cache", "images"],
            Self::Laravel => &[
                "vendor",
                "storage",
                "bootstrap/cache",
                "**/node_modules",
                "public/storage",
            ],
        }
    }
}

/// What is scanned. Its text form is stored with a baseline: changing the
/// extensions or the excludes makes an older snapshot incomparable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Scope {
    kind: Kind,
}

impl Scope {
    pub const fn for_kind(kind: Kind) -> Self {
        Self { kind }
    }

    pub fn id(&self) -> String {
        format!(
            "v1;{};ext={};exclude={}",
            self.kind.name(),
            EXTENSIONS.join(","),
            self.kind.excludes().join(",")
        )
    }

    pub fn is_code_file(&self, name: &str) -> bool {
        name.rsplit_once('.').is_some_and(|(stem, ext)| {
            !stem.is_empty()
                && EXTENSIONS
                    .iter()
                    .any(|known| ext.eq_ignore_ascii_case(known))
        })
    }

    /// `rel` is the directory's path from the project root, `name` its last segment.
    pub fn is_excluded(&self, rel: &str, name: &str) -> bool {
        self.kind.excludes().iter().any(|pattern| {
            if let Some(any_depth) = pattern.strip_prefix("**/") {
                return name == any_depth;
            }
            let mut left = rel.split('/');
            let mut right = pattern.split('/');
            loop {
                match (left.next(), right.next()) {
                    (None, None) => return true,
                    (Some(a), Some(b)) if b == "*" || a == b => {}
                    _ => return false,
                }
            }
        })
    }
}

pub(crate) fn project_root_ok(root: &str) -> Option<PathBuf> {
    let path = PathBuf::from(root);
    if !path.is_absolute()
        || root.len() > 4096
        || root.chars().any(char::is_control)
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return None;
    }
    Some(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extensions_are_case_insensitive_and_need_a_stem() {
        let scope = Scope::for_kind(Kind::Wordpress);
        for name in [
            "a.php",
            "A.PHP",
            "x.phtml",
            "a.inc",
            "m.module",
            "i.install",
            "t.theme",
            "p.phar",
        ] {
            assert!(scope.is_code_file(name), "{name}");
        }
        for name in ["a.txt", "php", ".php", "a.php.jpg", "a.php5", "a.json"] {
            assert!(!scope.is_code_file(name), "{name}");
        }
    }

    #[test]
    fn excludes_are_anchored_except_node_modules() {
        let wp = Scope::for_kind(Kind::Wordpress);
        assert!(wp.is_excluded("wp-content/uploads", "uploads"));
        assert!(!wp.is_excluded("wp-content/plugins/uploads", "uploads"));
        assert!(!wp.is_excluded("wp-content/uploads/2026", "2026"));
        assert!(wp.is_excluded("wp-content/plugins/a/node_modules", "node_modules"));
        let drupal = Scope::for_kind(Kind::Drupal);
        assert!(drupal.is_excluded("sites/default/files", "files"));
        assert!(!drupal.is_excluded("sites/default", "default"));
        assert!(!drupal.is_excluded("modules/vendor", "vendor"));
        assert!(drupal.is_excluded("vendor", "vendor"));
        let joomla = Scope::for_kind(Kind::Joomla);
        assert!(joomla.is_excluded("administrator/cache", "cache"));
        assert!(!joomla.is_excluded("plugins/cache", "cache"));
    }

    #[test]
    fn scope_id_changes_with_the_kind() {
        assert_ne!(
            Scope::for_kind(Kind::Wordpress).id(),
            Scope::for_kind(Kind::Drupal).id()
        );
    }
}
