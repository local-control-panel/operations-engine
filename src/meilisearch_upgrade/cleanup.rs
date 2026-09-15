//! Expired recovery-artifact cleanup for committed Meilisearch upgrades.
//! Only engine-written manifests are considered, and the retained source
//! volume is removed only while the manifest's target volume is still live.

use crate::{
    filesystem::ManagedRoot, meilisearch_upgrade::execute::RetainedArtifact, site::SiteRelativePath,
};
use std::time::{SystemTime, UNIX_EPOCH};

pub trait Driver {
    type Error: std::fmt::Debug;
    fn active_volume(&mut self) -> Result<String, Self::Error>;
    fn remove_volume(&mut self, volume: &str) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanupResult {
    pub removed_source_volumes: Vec<String>,
    pub removed_backups: Vec<String>,
    pub skipped_manifests: u64,
}

pub fn cleanup_expired<D: Driver>(root: &ManagedRoot, now: u64, driver: &mut D) -> CleanupResult {
    let mut result = CleanupResult::default();
    let Ok(artifacts) = root.open_managed_dir(&path("artifacts")) else {
        return result;
    };
    let Ok(names) = artifacts.file_names() else {
        return result;
    };
    for name in names {
        if !name.ends_with(".json") {
            continue;
        }
        let manifest_path = path(&format!("artifacts/{name}"));
        let Ok(json) = root.read_to_string(&manifest_path) else {
            result.skipped_manifests += 1;
            continue;
        };
        let Ok(manifest) = serde_json::from_str::<RetainedArtifact>(&json) else {
            result.skipped_manifests += 1;
            continue;
        };
        if now < manifest.expires_at_unix_secs
            || manifest.source_volume == manifest.target_volume
            || !valid_name(&manifest.source_volume)
            || !valid_name(&manifest.target_volume)
            || !valid_name(&manifest.backup_id)
            || driver.active_volume().ok().as_deref() != Some(&manifest.target_volume)
        {
            result.skipped_manifests += 1;
            continue;
        }
        if driver.remove_volume(&manifest.source_volume).is_err() {
            result.skipped_manifests += 1;
            continue;
        }
        result.removed_source_volumes.push(manifest.source_volume);

        let backup = path(&format!(
            "backups/{}/{}.dump",
            manifest.upgrade_request_id, manifest.backup_id
        ));
        if root.exists(&backup) {
            if root.remove_file(&backup).is_err() {
                result.skipped_manifests += 1;
                continue;
            }
            result
                .removed_backups
                .push(backup.as_path().to_string_lossy().into_owned());
        }
        if root.remove_file(&manifest_path).is_err() {
            result.skipped_manifests += 1;
        }
    }
    result
}

pub fn cleanup_expired_now<D: Driver>(root: &ManagedRoot, driver: &mut D) -> CleanupResult {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    cleanup_expired(root, now, driver)
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn path(value: &str) -> SiteRelativePath {
    SiteRelativePath::parse(value).expect("validated static or engine-generated cleanup path")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        meilisearch_upgrade::execute::RECOVERY_RETENTION_SECS, site::TrustedRoot,
        transaction::RequestId,
    };

    #[derive(Default)]
    struct Fake {
        active: String,
        removed: Vec<String>,
    }
    impl Driver for Fake {
        type Error = ();
        fn active_volume(&mut self) -> Result<String, ()> {
            Ok(self.active.clone())
        }
        fn remove_volume(&mut self, volume: &str) -> Result<(), ()> {
            self.removed.push(volume.into());
            Ok(())
        }
    }

    fn fixture() -> (tempfile::TempDir, ManagedRoot, RetainedArtifact) {
        let dir = tempfile::tempdir().unwrap();
        let trusted = TrustedRoot::parse(dir.path()).unwrap();
        let root = ManagedRoot::open(&trusted).unwrap();
        for child in ["artifacts", "backups/123e4567-e89b-12d3-a456-426614174000"] {
            root.create_dir_all(&path(child)).unwrap();
        }
        let artifact = RetainedArtifact {
            upgrade_request_id: RequestId::parse("123e4567-e89b-12d3-a456-426614174000").unwrap(),
            source_volume: "source-volume".into(),
            target_volume: "target-volume".into(),
            backup_id: "dump-1".into(),
            retained_at_unix_secs: 100,
            expires_at_unix_secs: 100 + RECOVERY_RETENTION_SECS,
        };
        root.write_atomic(
            &path("artifacts/123e4567-e89b-12d3-a456-426614174000.json"),
            &serde_json::to_vec(&artifact).unwrap(),
        )
        .unwrap();
        root.write_atomic(
            &path("backups/123e4567-e89b-12d3-a456-426614174000/dump-1.dump"),
            b"dump",
        )
        .unwrap();
        (dir, root, artifact)
    }

    #[test]
    fn expired_artifacts_are_removed_only_when_the_target_is_still_active() {
        let (_dir, root, artifact) = fixture();
        let mut driver = Fake {
            active: "target-volume".into(),
            ..Fake::default()
        };
        let result = cleanup_expired(&root, artifact.expires_at_unix_secs, &mut driver);
        assert_eq!(result.removed_source_volumes, vec!["source-volume"]);
        assert_eq!(result.removed_backups.len(), 1);
        assert!(!root.exists(&path("artifacts/123e4567-e89b-12d3-a456-426614174000.json")));
    }

    #[test]
    fn recent_or_no_longer_active_targets_are_never_cleaned() {
        let (_dir, root, artifact) = fixture();
        let mut driver = Fake {
            active: "some-other-volume".into(),
            ..Fake::default()
        };
        assert_eq!(
            cleanup_expired(&root, artifact.expires_at_unix_secs, &mut driver).skipped_manifests,
            1
        );
        driver.active = "target-volume".into();
        assert_eq!(
            cleanup_expired(&root, artifact.expires_at_unix_secs - 1, &mut driver)
                .skipped_manifests,
            1
        );
        assert!(driver.removed.is_empty());
    }
}
