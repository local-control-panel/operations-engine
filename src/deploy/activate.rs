//! Phase 4, item 1 (of the current list): the atomic switch — the one
//! commit point of a deploy. Per `docs/site-model.md`: a new relative
//! symlink is created under a unique temporary name and renamed over
//! `current` in the same directory; same-directory rename is atomic on
//! POSIX and is the single moment a deploy becomes visible.

use std::{
    ffi::OsStr,
    io,
    path::{Component, Path},
};

use crate::{
    deploy::ReleaseId,
    filesystem::ManagedRoot,
    site::{SiteId, SiteRelativePath, TrustedRoot},
};

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    /// `current` exists but does not point at a `releases/<releaseId>`
    /// this build recognizes. Refusing to guess is safer than silently
    /// reporting no previous release when one may well exist.
    UnrecognizedCurrentTarget,
}

/// Atomically switches `sites/<siteId>/current` to point at `release_id`,
/// returning the release it previously pointed at (`None` on a site's first
/// activation).
pub fn activate(
    content_root: &TrustedRoot,
    site_id: SiteId,
    release_id: ReleaseId,
) -> Result<Option<ReleaseId>, Error> {
    let managed = ManagedRoot::open(content_root).map_err(Error::Io)?;
    let site_dir = SiteRelativePath::parse(format!("sites/{site_id}"))
        .expect("a canonical SiteId always yields a valid relative path");
    managed.create_dir_all(&site_dir).map_err(Error::Io)?;

    let current = current_path(site_id);
    let previous = read_previous_release(&managed, &current)?;

    let target = SiteRelativePath::parse(format!("releases/{release_id}"))
        .expect("a canonical ReleaseId always yields a valid relative path");
    let temp = SiteRelativePath::parse(format!("sites/{site_id}/.current.tmp-{release_id}"))
        .expect("a canonical SiteId and ReleaseId always yield a valid relative path");

    managed.symlink(&temp, &target).map_err(Error::Io)?;
    // The commit point: everything before this line is still fully
    // abortable (the temp link can simply be left unreferenced); this
    // rename is the one moment `current` — and therefore what the runtime
    // serves — actually changes.
    managed.rename(&temp, &current).map_err(Error::Io)?;

    Ok(previous)
}

fn current_path(site_id: SiteId) -> SiteRelativePath {
    SiteRelativePath::parse(format!("sites/{site_id}/current"))
        .expect("a canonical SiteId always yields a valid relative path")
}

fn read_previous_release(
    managed: &ManagedRoot,
    current: &SiteRelativePath,
) -> Result<Option<ReleaseId>, Error> {
    let target = match managed.read_link(current) {
        Ok(target) => target,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(Error::Io(error)),
    };

    parse_release_symlink_target(&target)
        .map(Some)
        .ok_or(Error::UnrecognizedCurrentTarget)
}

/// Accepts only a target shaped exactly like `releases/<releaseId>` — two
/// normal components, nothing else — so a hand-edited or unexpected
/// `current` link is reported rather than partially trusted.
fn parse_release_symlink_target(target: &Path) -> Option<ReleaseId> {
    let mut components = target.components();
    match (components.next(), components.next(), components.next()) {
        (Some(Component::Normal(first)), Some(Component::Normal(second)), None)
            if first == OsStr::new("releases") =>
        {
            second.to_str().and_then(|id| ReleaseId::parse(id).ok())
        }
        _ => None,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::{Error, activate};
    use crate::{
        deploy::ReleaseId,
        filesystem::ManagedRoot,
        site::{SiteId, SiteRelativePath, TrustedRoot},
        transaction::RequestId,
    };

    const SITE_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
    const RELEASE_A: &str = "123e4567-e89b-12d3-a456-426614174000";
    const RELEASE_B: &str = "9b2f1c34-5678-4abc-9def-0123456789ab";

    fn release(uuid: &str) -> ReleaseId {
        ReleaseId::from(RequestId::parse(uuid).expect("test UUID should be canonical"))
    }

    fn site_id() -> SiteId {
        SiteId::parse(SITE_ID).expect("site id should be canonical")
    }

    #[test]
    fn a_sites_first_activation_reports_no_previous_release() {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let content_root = TrustedRoot::parse(directory.path()).expect("root should be valid");

        let previous = activate(&content_root, site_id(), release(RELEASE_A))
            .expect("first activation should succeed");
        assert_eq!(previous, None);

        let managed = ManagedRoot::open(&content_root).expect("root should open");
        let current = SiteRelativePath::parse(format!("sites/{SITE_ID}/current"))
            .expect("path should be valid");
        assert_eq!(
            managed.read_link(&current).unwrap(),
            std::path::Path::new(&format!("releases/{RELEASE_A}"))
        );
    }

    #[test]
    fn a_second_activation_reports_the_previous_release_and_switches_atomically() {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let content_root = TrustedRoot::parse(directory.path()).expect("root should be valid");

        activate(&content_root, site_id(), release(RELEASE_A)).expect("first activation");
        let previous = activate(&content_root, site_id(), release(RELEASE_B))
            .expect("second activation should succeed");
        assert_eq!(previous, Some(release(RELEASE_A)));

        let managed = ManagedRoot::open(&content_root).expect("root should open");
        let current = SiteRelativePath::parse(format!("sites/{SITE_ID}/current"))
            .expect("path should be valid");
        assert_eq!(
            managed.read_link(&current).unwrap(),
            std::path::Path::new(&format!("releases/{RELEASE_B}"))
        );
        assert!(
            !directory
                .path()
                .join(format!("sites/{SITE_ID}/.current.tmp-{RELEASE_B}"))
                .exists(),
            "the temporary link must not survive a successful activation"
        );
    }

    #[test]
    fn an_unrecognized_existing_current_target_is_reported_not_guessed() {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let content_root = TrustedRoot::parse(directory.path()).expect("root should be valid");
        let managed = ManagedRoot::open(&content_root).expect("root should open");
        let site_dir =
            SiteRelativePath::parse(format!("sites/{SITE_ID}")).expect("path should be valid");
        managed
            .create_dir_all(&site_dir)
            .expect("site dir should be created");
        let current = SiteRelativePath::parse(format!("sites/{SITE_ID}/current"))
            .expect("path should be valid");
        let elsewhere =
            SiteRelativePath::parse("shared/oops").expect("elsewhere path should be valid");
        managed
            .symlink(&current, &elsewhere)
            .expect("hand-edited link should be created");

        let outcome = activate(&content_root, site_id(), release(RELEASE_A));
        assert!(matches!(outcome, Err(Error::UnrecognizedCurrentTarget)));
    }
}
