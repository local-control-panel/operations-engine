//! Phase 5, item 1: which release identifiers are eligible for rollback.
//!
//! Per `docs/site-model.md`, "rollback never trusts client-side history as
//! its authorization source" — a syntactically valid `ReleaseId` is not
//! itself authorization, exactly as a syntactically valid `GitCommitSha`
//! is not for deploy (see `deploy::resolve`). The only source of truth
//! here is the engine's own filesystem state: a `ReleaseId` is eligible if
//! and only if `sites/<siteId>/releases/<releaseId>/` already exists as a
//! directory this engine itself created. `deploy::cleanup::prune_old_releases`
//! is what decides which release directories still exist at all; this
//! module only checks presence, and never invents or reconstructs a
//! release that isn't already on disk.

use std::{io, path::PathBuf};

use crate::{
    deploy::ReleaseId,
    filesystem::ManagedRoot,
    site::{SiteId, SiteRelativePath, TrustedRoot, ValidationError},
};

#[derive(Debug)]
pub enum Error {
    /// No `releases/<releaseId>/` directory exists for this site. Covers
    /// both "never existed" and "already pruned by retention" — rollback
    /// cannot distinguish the two, and does not need to.
    NotFound,
    Io(io::Error),
}

/// Resolves `release_id` to its absolute, containment-checked path beneath
/// `content_root`, failing with `Error::NotFound` unless
/// `sites/<siteId>/releases/<releaseId>/` already exists as a real
/// directory. Never constructs or trusts a path from anything other than
/// this existence check.
pub fn resolve_retained_release(
    content_root: &TrustedRoot,
    site_id: SiteId,
    release_id: ReleaseId,
) -> Result<PathBuf, Error> {
    let managed = ManagedRoot::open(content_root).map_err(Error::Io)?;
    let relative = SiteRelativePath::parse(format!("sites/{site_id}/releases/{release_id}"))
        .expect("a canonical SiteId and ReleaseId always yield a valid relative path");
    if !managed.exists(&relative) {
        return Err(Error::NotFound);
    }

    match content_root.resolve_existing(&relative) {
        Ok(path) => Ok(path),
        // A pre-existing symlink escape is reported the same as "not
        // found" rather than distinguished — the caller only needs to know
        // this release is not a valid rollback target, not why.
        Err(ValidationError::PathEscapesTrustedRoot | ValidationError::PathResolutionFailed) => {
            Err(Error::NotFound)
        }
        Err(_) => Err(Error::NotFound),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::{Error, resolve_retained_release};
    use crate::{
        deploy::ReleaseId,
        filesystem::ManagedRoot,
        site::{SiteId, SiteRelativePath, TrustedRoot},
        transaction::RequestId,
    };

    const SITE_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
    const RELEASE_ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    fn site_id() -> SiteId {
        SiteId::parse(SITE_ID).expect("site id should be canonical")
    }

    fn release_id() -> ReleaseId {
        ReleaseId::from(RequestId::parse(RELEASE_ID).expect("test UUID should be canonical"))
    }

    #[test]
    fn resolves_an_existing_release_directory() {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let content_root = TrustedRoot::parse(directory.path()).expect("root should be valid");
        let managed = ManagedRoot::open(&content_root).expect("root should open");
        let relative = SiteRelativePath::parse(format!("sites/{SITE_ID}/releases/{RELEASE_ID}"))
            .expect("path should be valid");
        managed
            .create_dir_all(&relative)
            .expect("release directory should be created");

        let resolved = resolve_retained_release(&content_root, site_id(), release_id())
            .expect("existing release should resolve");
        assert_eq!(
            resolved,
            directory
                .path()
                .join(format!("sites/{SITE_ID}/releases/{RELEASE_ID}"))
                .canonicalize()
                .expect("expected path should canonicalize")
        );
    }

    #[test]
    fn reports_not_found_for_a_release_that_was_never_created() {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let content_root = TrustedRoot::parse(directory.path()).expect("root should be valid");

        let outcome = resolve_retained_release(&content_root, site_id(), release_id());
        assert!(matches!(outcome, Err(Error::NotFound)));
    }

    #[test]
    fn reports_not_found_for_a_release_that_was_already_pruned() {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let content_root = TrustedRoot::parse(directory.path()).expect("root should be valid");
        let managed = ManagedRoot::open(&content_root).expect("root should open");
        let relative = SiteRelativePath::parse(format!("sites/{SITE_ID}/releases/{RELEASE_ID}"))
            .expect("path should be valid");
        managed
            .create_dir_all(&relative)
            .expect("release directory should be created");
        managed
            .remove_dir_all(&relative)
            .expect("release directory should be removable");

        let outcome = resolve_retained_release(&content_root, site_id(), release_id());
        assert!(matches!(outcome, Err(Error::NotFound)));
    }
}
