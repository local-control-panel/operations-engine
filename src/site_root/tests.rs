use std::{fs, os::unix::fs::symlink};

use super::*;

const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
const OTHER_ID: &str = "123e4567-e89b-12d3-a456-426614174001";
const THIRD_ID: &str = "123e4567-e89b-12d3-a456-426614174002";

struct Fixture {
    _dir: tempfile::TempDir,
    state: ManagedRoot,
    content: TrustedRoot,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        fs::create_dir(base.join("state")).unwrap();
        fs::create_dir(base.join("www")).unwrap();
        Self {
            state: ManagedRoot::open(&TrustedRoot::parse(base.join("state")).unwrap()).unwrap(),
            content: TrustedRoot::parse(base.join("www")).unwrap(),
            _dir: dir,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.content.as_path().join(name)
    }

    fn site(&self, name: &str) {
        fs::create_dir(self.path(name)).unwrap();
        fs::write(self.path(name).join("index.php"), "<?php").unwrap();
    }

    fn run(&self, req: &MoveRequest) -> Result<MoveResult, Error> {
        move_root(&self.state, std::slice::from_ref(&self.content), req)
    }
}

fn req(from: &str, to: &str, id: &str, key: Option<&str>) -> MoveRequest {
    MoveRequest::parse(from, to, id, key).unwrap()
}

#[test]
fn moves_the_directory_with_its_contents_and_replays() {
    let fixture = Fixture::new();
    fixture.site("old.test");

    let result = fixture
        .run(&req("old.test", "new.test", ID, Some("mv-1")))
        .unwrap();
    assert_eq!(result.to, fixture.path("new.test").to_string_lossy());
    assert!(!fixture.path("old.test").exists());
    assert!(fixture.path("new.test/index.php").exists());

    // The same key replays the committed outcome instead of failing on
    // the now-missing source.
    let replayed = fixture
        .run(&req("old.test", "new.test", ID, Some("mv-1")))
        .unwrap_or_else(|error| panic!("{error:?}"));
    assert_eq!(replayed.from, result.from);
}

#[test]
fn swapping_the_domains_rolls_the_move_back() {
    let fixture = Fixture::new();
    fixture.site("old.test");
    fixture.run(&req("old.test", "new.test", ID, None)).unwrap();
    fixture
        .run(&req("new.test", "old.test", OTHER_ID, None))
        .unwrap();
    assert!(fixture.path("old.test/index.php").exists());
    assert!(!fixture.path("new.test").exists());
}

#[test]
fn refuses_an_existing_target_and_moves_nothing() {
    let fixture = Fixture::new();
    fixture.site("old.test");
    fixture.site("new.test");

    let error = fixture
        .run(&req("old.test", "new.test", ID, None))
        .unwrap_err();
    assert!(matches!(error, Error::TargetExists));
    assert!(fixture.path("old.test/index.php").exists());
}

#[test]
fn refuses_a_dangling_symlink_at_the_target() {
    let fixture = Fixture::new();
    fixture.site("old.test");
    symlink("/nonexistent", fixture.path("new.test")).unwrap();

    let error = fixture
        .run(&req("old.test", "new.test", ID, None))
        .unwrap_err();
    assert!(matches!(error, Error::TargetExists));
}

#[test]
fn refuses_a_missing_file_or_symlinked_source() {
    let fixture = Fixture::new();
    assert!(matches!(
        fixture.run(&req("old.test", "new.test", ID, None)),
        Err(Error::SourceMissing)
    ));

    fs::write(fixture.path("file.test"), "x").unwrap();
    assert!(matches!(
        fixture.run(&req("file.test", "new.test", OTHER_ID, None)),
        Err(Error::SourceMissing)
    ));

    fixture.site("real.test");
    symlink(fixture.path("real.test"), fixture.path("link.test")).unwrap();
    assert!(matches!(
        fixture.run(&req("link.test", "new.test", THIRD_ID, None)),
        Err(Error::SourceMissing)
    ));
    assert!(fixture.path("real.test/index.php").exists());
}

#[test]
fn a_held_resource_lock_on_either_side_blocks_the_move() {
    let fixture = Fixture::new();
    fixture.site("old.test");
    for held in ["old.test", "new.test"] {
        let _held = resource_lock::acquire(
            &fixture.state,
            &fixture.path(held),
            RequestId::parse(OTHER_ID).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            fixture.run(&req("old.test", "new.test", ID, None)),
            Err(Error::ResourceBusy)
        ));
    }
    assert!(fixture.path("old.test/index.php").exists());
}

#[test]
fn rejects_malformed_requests() {
    assert_eq!(
        MoveRequest::parse("../etc", "new.test", ID, None).err(),
        Some(RequestError::InvalidDomain)
    );
    assert_eq!(
        MoveRequest::parse("old.test", "a/b", ID, None).err(),
        Some(RequestError::InvalidDomain)
    );
    assert_eq!(
        MoveRequest::parse("same.test", "same.test", ID, None).err(),
        Some(RequestError::SameDomain)
    );
    assert_eq!(
        MoveRequest::parse("old.test", "new.test", "not-a-uuid", None).err(),
        Some(RequestError::InvalidRequestId)
    );
}

// ---- site.prepareRoot / site.removeRoot (milestone 061) ----

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

fn me() -> (u32, u32) {
    // SAFETY: `getuid`/`getgid` have no preconditions.
    unsafe { (libc::getuid(), libc::getgid()) }
}

fn is_root() -> bool {
    me().0 == 0
}

/// Built directly: `parse` refuses ids below 1000, which an unprivileged
/// test user cannot be expected to have.
fn prep(domain: &str, relative: &[&str], uid: u32, gid: u32, id: &str) -> PrepareRequest {
    PrepareRequest {
        domain: Domain::parse(domain).unwrap(),
        relative_root: relative
            .iter()
            .map(|part| SiteRelativePath::parse(part).unwrap())
            .collect(),
        uid,
        gid,
        existing: ExistingPolicy::Refuse,
        require_absent: false,
        request_id: RequestId::parse(id).unwrap(),
        idempotency_key: None,
    }
}

fn mode_of(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
}

impl Fixture {
    fn prepare(&self, req: &PrepareRequest) -> Result<PrepareResult, Error> {
        prepare_root(&self.state, std::slice::from_ref(&self.content), req)
    }

    fn sites_dir(&self) -> PathBuf {
        self.content.as_path().parent().unwrap().join("manifests")
    }

    fn remove(&self, req: &RemoveRequest) -> Result<RemoveResult, Error> {
        fs::create_dir_all(self.sites_dir()).unwrap();
        remove_root(
            &self.state,
            std::slice::from_ref(&self.content),
            &self.sites_dir(),
            me().0,
            req,
        )
    }

    fn manifest(&self, site: &str, domain: &str) {
        fs::create_dir_all(self.sites_dir()).unwrap();
        let json = serde_json::json!({
            "schemaVersion": 1,
            "siteId": site,
            "domain": domain,
            "contentRoot": format!("sites/{site}/current"),
            "siteUser": "old_test",
            "repository": {
                "url": "git@example.com:r.git",
                "allowedBranches": ["main"],
                "credentialId": site,
            },
        });
        let path = self.sites_dir().join(format!("{site}.json"));
        fs::write(&path, json.to_string()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    }
}

fn rm(domain: &str, site: Option<&str>, confirm: bool, id: &str) -> RemoveRequest {
    RemoveRequest::parse(domain, None, site, confirm, id, None).unwrap()
}

const SITE: &str = "550e8400-e29b-41d4-a716-446655440000";

#[test]
fn guarded_empty_root_removal_preserves_a_different_owner() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.path("guarded.test")).unwrap();
    let mut req = rm("guarded.test", None, false, ID);
    req.expected_owner = Some((me().0.saturating_add(1), me().1));
    let error = remove_root(
        &fixture.state,
        std::slice::from_ref(&fixture.content),
        &fixture.sites_dir(),
        me().0,
        &req,
    )
    .unwrap_err();
    assert!(matches!(error, Error::UnknownOwner));
    assert!(fixture.path("guarded.test").is_dir());
}

#[test]
fn prepare_creates_the_site_directory_and_a_private_root() {
    let fixture = Fixture::new();
    let (uid, gid) = me();
    let mut req = prep("a.test", &["public"], uid, gid, ID);
    req.idempotency_key = Some(IdempotencyKey::parse("prep-1").unwrap());

    let result = fixture.prepare(&req).unwrap();
    assert_eq!(result.path, fixture.path("a.test/public").to_string_lossy());
    assert!(result.created);
    assert_eq!(mode_of(&fixture.path("a.test")), 0o755);
    assert_eq!(mode_of(&fixture.path("a.test/public")), 0o700);
    let owner = fs::metadata(fixture.path("a.test/public")).unwrap();
    assert_eq!((owner.uid(), owner.gid()), (uid, gid));

    // The same key replays the recorded outcome.
    let replayed = fixture.prepare(&req).unwrap();
    assert_eq!(replayed.path, result.path);
    assert!(replayed.created);

    // A new request for the finished root is a no-op, not an error.
    let again = fixture
        .prepare(&prep("a.test", &["public"], uid, gid, OTHER_ID))
        .unwrap();
    assert!(!again.created);
    assert_eq!(mode_of(&fixture.path("a.test/public")), 0o700);
}

#[test]
fn prepare_without_a_relative_root_hands_over_the_site_directory() {
    let fixture = Fixture::new();
    let (uid, gid) = me();
    let result = fixture.prepare(&prep("b.test", &[], uid, gid, ID)).unwrap();
    assert_eq!(result.path, fixture.path("b.test").to_string_lossy());
    assert_eq!(mode_of(&fixture.path("b.test")), 0o700);
}

#[test]
fn prepare_never_follows_a_symlink_at_any_level() {
    let fixture = Fixture::new();
    let (uid, gid) = me();
    let outside = fixture.content.as_path().parent().unwrap().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o755)).unwrap();

    symlink(&outside, fixture.path("link.test")).unwrap();
    assert!(matches!(
        fixture.prepare(&prep("link.test", &["public"], uid, gid, ID)),
        Err(Error::UnsafePath)
    ));

    fs::create_dir(fixture.path("real.test")).unwrap();
    symlink(&outside, fixture.path("real.test/public")).unwrap();
    assert!(matches!(
        fixture.prepare(&prep("real.test", &["public"], uid, gid, OTHER_ID)),
        Err(Error::UnsafePath)
    ));

    fs::write(fixture.path("file.test"), "x").unwrap();
    assert!(matches!(
        fixture.prepare(&prep("file.test", &[], uid, gid, THIRD_ID)),
        Err(Error::UnsafePath)
    ));

    assert_eq!(mode_of(&outside), 0o755);
    assert_eq!(fs::metadata(&outside).unwrap().uid(), uid);
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
}

#[test]
fn prepare_refuses_foreign_content_and_changes_nothing() {
    let fixture = Fixture::new();
    let (uid, gid) = me();
    fixture.site("c.test");
    fs::set_permissions(fixture.path("c.test"), fs::Permissions::from_mode(0o755)).unwrap();

    // Owned by the test user, requested for a different identity.
    let error = fixture
        .prepare(&prep("c.test", &[], uid + 1, gid, ID))
        .unwrap_err();
    assert!(matches!(error, Error::ExistingContent));
    assert_eq!(mode_of(&fixture.path("c.test")), 0o755);
    assert!(fixture.path("c.test/index.php").exists());

    // Already owned by the requested identity: adopted, mode fixed.
    fixture
        .prepare(&prep("c.test", &[], uid, gid, OTHER_ID))
        .unwrap();
    assert_eq!(mode_of(&fixture.path("c.test")), 0o700);
    assert!(fixture.path("c.test/index.php").exists());
}

#[test]
fn prepare_failure_removes_what_it_created_and_restores_what_it_adopted() {
    if is_root() {
        return; // chown to another user succeeds for root
    }
    let fixture = Fixture::new();
    let (uid, gid) = me();

    // A fresh tree: the chown to another user is refused, so nothing
    // may remain.
    let error = fixture
        .prepare(&prep("d.test", &["public"], uid + 1, gid, ID))
        .unwrap_err();
    assert!(matches!(error, Error::Io(_)));
    assert!(!fixture.path("d.test").exists());

    // An adopted empty directory keeps its previous mode.
    fs::create_dir(fixture.path("e.test")).unwrap();
    fs::set_permissions(fixture.path("e.test"), fs::Permissions::from_mode(0o750)).unwrap();
    assert!(
        fixture
            .prepare(&prep("e.test", &[], uid + 1, gid, OTHER_ID))
            .is_err()
    );
    assert_eq!(mode_of(&fixture.path("e.test")), 0o750);

    // The failure is recorded: a retry under the same key replays it.
    let mut req = prep("d.test", &["public"], uid + 1, gid, THIRD_ID);
    req.idempotency_key = Some(IdempotencyKey::parse("prep-fail").unwrap());
    assert!(fixture.prepare(&req).is_err());
    assert!(matches!(fixture.prepare(&req), Err(Error::Replayed { .. })));
}

#[test]
fn prepare_assigns_the_requested_identity_when_run_as_root() {
    if !is_root() {
        return;
    }
    let fixture = Fixture::new();
    fixture
        .prepare(&prep("f.test", &["public"], 12345, 23456, ID))
        .unwrap();
    let root = fs::metadata(fixture.path("f.test/public")).unwrap();
    assert_eq!((root.uid(), root.gid()), (12345, 23456));
    assert_eq!(mode_of(&fixture.path("f.test/public")), 0o700);
    let site = fs::metadata(fixture.path("f.test")).unwrap();
    assert_eq!((site.uid(), site.gid()), (0, 0));
    assert_eq!(mode_of(&fixture.path("f.test")), 0o755);
}

#[test]
fn prepare_and_remove_refuse_a_system_directory_as_content_root() {
    let fixture = Fixture::new();
    let (uid, gid) = me();
    let etc = TrustedRoot::parse("/etc").unwrap();
    let error = prepare_root(
        &fixture.state,
        std::slice::from_ref(&etc),
        &prep("zzz-engine-test.invalid", &["public"], uid, gid, ID),
    )
    .unwrap_err();
    assert!(matches!(error, Error::UnsafeContentRoot));
    assert!(!Path::new("/etc/zzz-engine-test.invalid").exists());

    let error = remove_root(
        &fixture.state,
        std::slice::from_ref(&etc),
        &fixture.sites_dir(),
        0,
        &rm("zzz-engine-test.invalid", None, true, OTHER_ID),
    )
    .unwrap_err();
    assert!(matches!(error, Error::UnsafeContentRoot));
}

#[test]
fn prepare_and_remove_are_blocked_by_a_held_resource_lock() {
    let fixture = Fixture::new();
    let (uid, gid) = me();
    fixture.site("g.test");
    let _held = resource_lock::acquire(
        &fixture.state,
        &fixture.path("g.test"),
        RequestId::parse(OTHER_ID).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        fixture.prepare(&prep("g.test", &["public"], uid, gid, ID)),
        Err(Error::ResourceBusy)
    ));
    assert!(matches!(
        fixture.remove(&rm("g.test", None, true, THIRD_ID)),
        Err(Error::ResourceBusy)
    ));
    assert!(fixture.path("g.test/index.php").exists());
}

#[test]
fn prepare_and_remove_reject_malformed_requests() {
    let parse = |domain: &str, rel: Option<&str>, uid: u32, gid: u32| {
        PrepareRequest::parse(domain, rel, uid, gid, None, ID, None).err()
    };
    assert_eq!(
        parse("sites", None, 10000, 10000),
        Some(RequestError::ReservedDomain)
    );
    assert_eq!(
        parse("../etc", None, 10000, 10000),
        Some(RequestError::InvalidDomain)
    );
    assert_eq!(
        parse("a.test", Some("../x"), 10000, 10000),
        Some(RequestError::InvalidRelativeRoot)
    );
    assert_eq!(
        parse("a.test", Some("/etc"), 10000, 10000),
        Some(RequestError::InvalidRelativeRoot)
    );
    assert_eq!(
        parse("a.test", Some("a//b"), 10000, 10000),
        Some(RequestError::InvalidRelativeRoot)
    );
    assert_eq!(
        parse("a.test", Some("a/b/c/d/e/f/g/h/i"), 10000, 10000),
        Some(RequestError::InvalidRelativeRoot)
    );
    assert_eq!(
        parse("a.test", None, 0, 10000),
        Some(RequestError::InvalidIdentity)
    );
    assert_eq!(
        parse("a.test", None, 10000, 999),
        Some(RequestError::InvalidIdentity)
    );
    assert_eq!(
        parse("a.test", None, u32::MAX, 10000),
        Some(RequestError::InvalidIdentity)
    );
    assert!(parse("a.test", Some("public/html"), 10000, 10000).is_none());
    assert!(parse("a.test", Some(""), 10000, 10000).is_none());

    assert_eq!(
        RemoveRequest::parse("sites", None, None, true, ID, None).err(),
        Some(RequestError::ReservedDomain)
    );
    assert_eq!(
        RemoveRequest::parse("a.test", None, Some("not-a-uuid"), true, ID, None).err(),
        Some(RequestError::InvalidSiteId)
    );
    assert_eq!(
        MoveRequest::parse("sites", "new.test", ID, None).err(),
        Some(RequestError::ReservedDomain)
    );
}

#[test]
fn remove_deletes_the_tree_and_unlinks_symlinks_without_following_them() {
    let fixture = Fixture::new();
    let outside = fixture.content.as_path().parent().unwrap().join("keep");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("precious"), "data").unwrap();

    fixture.site("h.test");
    fs::create_dir_all(fixture.path("h.test/public/wp-content/uploads")).unwrap();
    fs::write(fixture.path("h.test/public/wp-content/uploads/a.jpg"), "x").unwrap();
    symlink(&outside, fixture.path("h.test/public/outside")).unwrap();
    symlink("/nonexistent", fixture.path("h.test/dangling")).unwrap();

    let result = fixture.remove(&rm("h.test", None, true, ID)).unwrap();
    assert_eq!(
        result.removed,
        vec![fixture.path("h.test").to_string_lossy()]
    );
    assert!(result.entries_removed >= 7);
    assert!(!fixture.path("h.test").exists());
    assert_eq!(
        fs::read_to_string(outside.join("precious")).unwrap(),
        "data"
    );
}

#[test]
fn remove_refuses_unconfirmed_contents_but_takes_an_empty_directory() {
    let fixture = Fixture::new();
    fixture.site("i.test");
    assert!(matches!(
        fixture.remove(&rm("i.test", None, false, ID)),
        Err(Error::NotEmpty)
    ));
    assert!(fixture.path("i.test/index.php").exists());

    fs::create_dir(fixture.path("empty.test")).unwrap();
    fixture
        .remove(&rm("empty.test", None, false, OTHER_ID))
        .unwrap();
    assert!(!fixture.path("empty.test").exists());
}

#[test]
fn remove_of_a_missing_site_succeeds_with_nothing_removed() {
    let fixture = Fixture::new();
    let result = fixture.remove(&rm("gone.test", None, true, ID)).unwrap();
    assert!(result.removed.is_empty());
    assert_eq!(result.entries_removed, 0);
}

#[test]
fn remove_refuses_a_symlink_or_file_in_place_of_the_site_directory() {
    let fixture = Fixture::new();
    let outside = fixture.content.as_path().parent().unwrap().join("keep");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("precious"), "data").unwrap();
    symlink(&outside, fixture.path("link.test")).unwrap();
    assert!(matches!(
        fixture.remove(&rm("link.test", None, true, ID)),
        Err(Error::UnsafePath)
    ));
    fs::write(fixture.path("file.test"), "x").unwrap();
    assert!(matches!(
        fixture.remove(&rm("file.test", None, true, OTHER_ID)),
        Err(Error::UnsafePath)
    ));
    assert!(outside.join("precious").exists());
    assert!(fixture.path("link.test").symlink_metadata().is_ok());
}

#[test]
fn remove_refuses_a_system_owned_directory_when_run_as_root() {
    if !is_root() {
        return;
    }
    let fixture = Fixture::new();
    fixture.site("j.test");
    std::os::unix::fs::chown(fixture.path("j.test"), Some(33), Some(33)).unwrap();
    assert!(matches!(
        fixture.remove(&rm("j.test", None, true, ID)),
        Err(Error::UnknownOwner)
    ));
    assert!(fixture.path("j.test/index.php").exists());
}

#[test]
fn remove_takes_the_release_tree_only_when_the_manifest_names_the_domain() {
    let fixture = Fixture::new();
    fixture.site("k.test");
    fs::create_dir_all(fixture.path(&format!("sites/{SITE}/releases/r1"))).unwrap();
    symlink(
        "releases/r1",
        fixture.path(&format!("sites/{SITE}/current")),
    )
    .unwrap();

    // No manifest, or one for another domain: nothing at all is removed.
    assert!(matches!(
        fixture.remove(&rm("k.test", Some(SITE), true, ID)),
        Err(Error::ManifestMismatch)
    ));
    fixture.manifest(SITE, "other.test");
    assert!(matches!(
        fixture.remove(&rm("k.test", Some(SITE), true, OTHER_ID)),
        Err(Error::ManifestMismatch)
    ));
    assert!(fixture.path("k.test/index.php").exists());
    assert!(fixture.path(&format!("sites/{SITE}/releases/r1")).exists());

    fixture.manifest(SITE, "k.test");
    let result = fixture
        .remove(&rm("k.test", Some(SITE), true, THIRD_ID))
        .unwrap();
    assert_eq!(result.removed.len(), 2);
    assert!(!fixture.path("k.test").exists());
    assert!(!fixture.path(&format!("sites/{SITE}")).exists());
    // The shared `sites` directory itself stays.
    assert!(fixture.path("sites").is_dir());
}

#[test]
fn remove_refuses_a_tree_deeper_than_the_bound_and_keeps_it() {
    let fixture = Fixture::new();
    fixture.site("l.test");
    let mut deep = fixture.path("l.test");
    for _ in 0..(MAX_REMOVE_DEPTH + 2) {
        deep.push("d");
    }
    fs::create_dir_all(&deep).unwrap();
    assert!(matches!(
        fixture.remove(&rm("l.test", None, true, ID)),
        Err(Error::OutOfBounds)
    ));
    assert!(fixture.path("l.test/index.php").exists());
}

#[test]
fn remove_replays_a_recorded_outcome_for_the_same_key() {
    let fixture = Fixture::new();
    fixture.site("m.test");
    let mut req = rm("m.test", None, true, ID);
    req.idempotency_key = Some(IdempotencyKey::parse("rm-1").unwrap());
    let first = fixture.remove(&req).unwrap();
    let replayed = fixture.remove(&req).unwrap();
    assert_eq!(first.removed, replayed.removed);
}

#[test]
fn remove_takes_a_tree_of_empty_directories_without_confirmation() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.path("n.test/public/nested")).unwrap();
    let result = fixture.remove(&rm("n.test", None, false, ID)).unwrap();
    assert_eq!(result.removed.len(), 1);
    assert!(!fixture.path("n.test").exists());
}

fn release(domain: &str, site: Option<&str>, id: &str) -> ReleaseRequest {
    ReleaseRequest::parse(domain, site, id, None).unwrap()
}

#[test]
fn release_skips_a_missing_site_and_checks_the_manifest() {
    let fixture = Fixture::new();
    let run = |req: &ReleaseRequest| {
        fs::create_dir_all(fixture.sites_dir()).unwrap();
        release_root(
            &fixture.state,
            std::slice::from_ref(&fixture.content),
            &fixture.sites_dir(),
            me().0,
            req,
        )
    };
    let result = run(&release("gone.test", None, ID)).unwrap();
    assert!(result.released.is_empty());

    fs::create_dir_all(fixture.path(&format!("sites/{SITE}"))).unwrap();
    assert!(matches!(
        run(&release("o.test", Some(SITE), OTHER_ID)),
        Err(Error::ManifestMismatch)
    ));
}

#[test]
fn release_hands_the_tree_to_root_without_following_symlinks_when_run_as_root() {
    if !is_root() {
        return;
    }
    let fixture = Fixture::new();
    fixture.site("p.test");
    fs::create_dir_all(fixture.path("p.test/public")).unwrap();
    fs::write(fixture.path("p.test/public/a.php"), "x").unwrap();
    let outside = fixture.content.as_path().parent().unwrap().join("keep");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("precious"), "data").unwrap();
    symlink(&outside, fixture.path("p.test/public/out")).unwrap();
    for path in [
        "p.test",
        "p.test/index.php",
        "p.test/public",
        "p.test/public/a.php",
    ] {
        std::os::unix::fs::chown(fixture.path(path), Some(12345), Some(12345)).unwrap();
    }
    std::os::unix::fs::chown(&outside, Some(777), Some(777)).unwrap();

    let result = release_root(
        &fixture.state,
        std::slice::from_ref(&fixture.content),
        &fixture.sites_dir(),
        0,
        &release("p.test", None, ID),
    )
    .unwrap();
    assert_eq!(
        result.released,
        vec![fixture.path("p.test").to_string_lossy()]
    );
    for path in [
        "p.test",
        "p.test/index.php",
        "p.test/public",
        "p.test/public/a.php",
    ] {
        let metadata = fs::symlink_metadata(fixture.path(path)).unwrap();
        assert_eq!((metadata.uid(), metadata.gid()), (0, 0), "{path}");
    }
    assert_eq!(fs::metadata(&outside).unwrap().uid(), 777);
}

#[test]
fn prepare_parses_the_existing_policy() {
    let parse = |existing: Option<&str>| {
        PrepareRequest::parse("a.test", None, 10000, 10000, existing, ID, None)
            .map(|req| req.existing)
    };
    assert_eq!(parse(None).unwrap(), ExistingPolicy::Refuse);
    assert_eq!(parse(Some("refuse")).unwrap(), ExistingPolicy::Refuse);
    assert_eq!(
        parse(Some("adopt-directory")).unwrap(),
        ExistingPolicy::AdoptDirectory
    );
    assert_eq!(
        parse(Some("adopt-tree")).unwrap(),
        ExistingPolicy::AdoptTree
    );
    assert_eq!(
        parse(Some("recursive")).err(),
        Some(RequestError::InvalidExistingPolicy)
    );
}

#[test]
fn prepare_adopts_existing_content_only_when_asked_when_run_as_root() {
    if !is_root() {
        return;
    }
    let fixture = Fixture::new();
    let outside = fixture.content.as_path().parent().unwrap().join("keep");
    fs::create_dir(&outside).unwrap();
    std::os::unix::fs::chown(&outside, Some(777), Some(777)).unwrap();
    let build = |site: &str| {
        fixture.site(site);
        fs::create_dir_all(fixture.path(&format!("{site}/sub"))).unwrap();
        fs::write(fixture.path(&format!("{site}/sub/f.php")), "x").unwrap();
        symlink(&outside, fixture.path(&format!("{site}/sub/out"))).unwrap();
        for path in ["", "/index.php", "/sub", "/sub/f.php"] {
            std::os::unix::fs::chown(fixture.path(&format!("{site}{path}")), Some(500), Some(500))
                .unwrap();
        }
    };
    let owner = |path: String| fs::symlink_metadata(fixture.path(&path)).unwrap().uid();

    build("q.test");
    assert!(matches!(
        fixture.prepare(&prep("q.test", &[], 12345, 12345, ID)),
        Err(Error::ExistingContent)
    ));
    assert_eq!(owner("q.test".into()), 500);

    let mut req = prep("q.test", &[], 12345, 12345, OTHER_ID);
    req.existing = ExistingPolicy::AdoptDirectory;
    fixture.prepare(&req).unwrap();
    assert_eq!(owner("q.test".into()), 12345);
    assert_eq!(owner("q.test/index.php".into()), 500);
    assert_eq!(mode_of(&fixture.path("q.test")), 0o700);

    build("r.test");
    let mut req = prep("r.test", &[], 12345, 12345, THIRD_ID);
    req.existing = ExistingPolicy::AdoptTree;
    fixture.prepare(&req).unwrap();
    for path in [
        "r.test",
        "r.test/index.php",
        "r.test/sub",
        "r.test/sub/f.php",
    ] {
        assert_eq!(owner(path.into()), 12345, "{path}");
    }
    // The symlink was neither followed nor changed.
    assert_eq!(fs::metadata(&outside).unwrap().uid(), 777);
}

#[test]
fn remove_with_a_relative_root_takes_only_that_directory_and_prunes_empty_parents() {
    let fixture = Fixture::new();
    let remove = |domain: &str, id: &str| {
        fixture
            .remove(&RemoveRequest::parse(domain, Some("public"), None, true, id, None).unwrap())
            .unwrap()
    };

    // Only the root goes; the site directory stays while it holds
    // anything else.
    fs::create_dir_all(fixture.path("s.test/public")).unwrap();
    fs::write(fixture.path("s.test/public/index.php"), "x").unwrap();
    fs::write(fixture.path("s.test/notes.txt"), "keep").unwrap();
    let result = remove("s.test", ID);
    assert_eq!(
        result.removed,
        vec![fixture.path("s.test/public").to_string_lossy()]
    );
    assert!(!fixture.path("s.test/public").exists());
    assert!(fixture.path("s.test/notes.txt").exists());

    // An otherwise empty site directory is removed with its root.
    fs::create_dir_all(fixture.path("t.test/public")).unwrap();
    remove("t.test", OTHER_ID);
    assert!(!fixture.path("t.test").exists());

    // A missing root is a no-op.
    assert!(remove("u.test", THIRD_ID).removed.is_empty());
}
