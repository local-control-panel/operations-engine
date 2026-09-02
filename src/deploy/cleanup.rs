//! Phase 4, item 1 (of the current list): bounded retention for old
//! releases. Nothing frees `releases/<releaseId>/` directories on its own,
//! so without this a site's disk usage grows by one full checkout per
//! deploy forever.

use std::io;

use cap_std::time::SystemTime;

use crate::{
    deploy::ReleaseId,
    filesystem::ManagedRoot,
    site::{SiteId, SiteRelativePath, TrustedRoot},
};

/// How many releases a site keeps by default: the active one plus enough
/// history to roll back a few deploys without engine involvement.
pub const DEFAULT_RETAIN_COUNT: usize = 5;

/// Removes releases beyond the `retain` most recently created, always
/// keeping `active_release` regardless of its age or position. Age is the
/// release directory's filesystem modification time — an approximation
/// (something touching a file inside a release after staging would skew
/// it), not a cross-reference against `TransactionState.finishedAt`, which
/// would need this function to also hold the state root. Good enough for
/// "don't grow forever"; revisit if release ages ever need to be exact.
///
/// Best-effort per release: failing to remove one specific release is
/// skipped, not propagated, because cleanup must never turn an otherwise
/// successful deploy into a reported failure. Returns the releases that
/// were actually removed.
pub fn prune_old_releases(
    content_root: &TrustedRoot,
    site_id: SiteId,
    active_release: ReleaseId,
    retain: usize,
) -> io::Result<Vec<ReleaseId>> {
    let managed = ManagedRoot::open(content_root)?;
    let releases_relative = SiteRelativePath::parse(format!("sites/{site_id}/releases"))
        .expect("a canonical SiteId always yields a valid relative path");
    let releases_dir = match managed.open_dir(&releases_relative) {
        Ok(dir) => dir,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };

    let mut candidates: Vec<(ReleaseId, SystemTime)> = Vec::new();
    for entry in releases_dir.entries()? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(release_id) = ReleaseId::parse(&name) else {
            continue;
        };
        let modified = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .unwrap_or(SystemTime::from_std(std::time::UNIX_EPOCH));
        candidates.push((release_id, modified));
    }
    candidates.sort_by_key(|(_, modified)| std::cmp::Reverse(*modified));

    let mut removed = Vec::new();
    for (index, (release_id, _)) in candidates.iter().enumerate() {
        if *release_id == active_release || index < retain {
            continue;
        }
        let relative = SiteRelativePath::parse(format!("sites/{site_id}/releases/{release_id}"))
            .expect("a canonical SiteId and ReleaseId always yield a valid relative path");
        if managed.remove_dir_all(&relative).is_ok() {
            removed.push(*release_id);
        }
    }
    Ok(removed)
}

#[cfg(all(test, unix))]
mod tests {
    use std::{thread, time::Duration};

    use super::{DEFAULT_RETAIN_COUNT, prune_old_releases};
    use crate::{
        deploy::ReleaseId,
        filesystem::ManagedRoot,
        site::{SiteId, SiteRelativePath, TrustedRoot},
        transaction::RequestId,
    };

    const SITE_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn release(seed: u8) -> ReleaseId {
        let uuid = format!("123e4567-e89b-12d3-a456-42661417{seed:04x}");
        ReleaseId::from(RequestId::parse(&uuid).expect("test UUID should be canonical"))
    }

    fn site_id() -> SiteId {
        SiteId::parse(SITE_ID).expect("site id should be canonical")
    }

    /// Creates `count` release directories in order, sleeping briefly
    /// between each so their modification times are distinguishable, and
    /// returns them oldest-first.
    fn make_releases(content_root: &TrustedRoot, count: u8) -> Vec<ReleaseId> {
        let managed = ManagedRoot::open(content_root).expect("root should open");
        let mut releases = Vec::new();
        for seed in 0..count {
            let release_id = release(seed);
            let relative =
                SiteRelativePath::parse(format!("sites/{SITE_ID}/releases/{release_id}"))
                    .expect("path should be valid");
            managed
                .create_dir_all(&relative)
                .expect("release directory should be created");
            releases.push(release_id);
            thread::sleep(Duration::from_millis(10));
        }
        releases
    }

    #[test]
    fn keeps_only_the_most_recent_releases_plus_the_active_one() {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let content_root = TrustedRoot::parse(directory.path()).expect("root should be valid");
        // Oldest to newest: releases[0] .. releases[3].
        let releases = make_releases(&content_root, 4);
        let active = releases[3];

        // retain = 2 keeps the 2 most recent (releases[3], releases[2]);
        // the 2 oldest are removed.
        let removed =
            prune_old_releases(&content_root, site_id(), active, 2).expect("prune should succeed");

        assert_eq!(removed.len(), 2);
        assert!(removed.contains(&releases[0]));
        assert!(removed.contains(&releases[1]));
        for removed_id in &releases[..2] {
            assert!(
                !directory
                    .path()
                    .join(format!("sites/{SITE_ID}/releases/{removed_id}"))
                    .exists()
            );
        }
        for kept in &releases[2..] {
            assert!(
                directory
                    .path()
                    .join(format!("sites/{SITE_ID}/releases/{kept}"))
                    .exists()
            );
        }
    }

    #[test]
    fn never_removes_the_active_release_even_if_it_is_the_oldest() {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let content_root = TrustedRoot::parse(directory.path()).expect("root should be valid");
        let releases = make_releases(&content_root, 3);
        let active = releases[0];

        let removed =
            prune_old_releases(&content_root, site_id(), active, 1).expect("prune should succeed");

        assert!(!removed.contains(&active));
        assert!(
            directory
                .path()
                .join(format!("sites/{SITE_ID}/releases/{active}"))
                .exists()
        );
    }

    #[test]
    fn a_missing_releases_directory_is_treated_as_nothing_to_clean_up() {
        let directory = tempfile::tempdir().expect("temporary directory should exist");
        let content_root = TrustedRoot::parse(directory.path()).expect("root should be valid");

        let removed =
            prune_old_releases(&content_root, site_id(), release(0), DEFAULT_RETAIN_COUNT)
                .expect("prune should succeed even with no releases yet");
        assert!(removed.is_empty());
    }
}
