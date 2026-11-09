use super::*;
use std::{fs, os::unix::fs::PermissionsExt};

const ID: &str = "123e4567-e89b-12d3-a456-426614174000";

fn managed(directory: &Path) -> ManagedRoot {
    ManagedRoot::open(&crate::site::TrustedRoot::parse(directory).unwrap()).unwrap()
}

fn plan(root: &str, extra: &str) -> String {
    format!(
        r#"{{"container":"runtime-1","projectRoot":"{root}","documentRoot":"{root}/web","uid":1000,"gid":1000{extra}}}"#
    )
}

#[test]
fn parse_accepts_each_kind_and_normalises_packages() {
    assert!(Request::parse("update-core", &plan("/var/www/s", ""), ID, None).is_ok());
    let req = Request::parse(
        "update-packages",
        &plan(
            "/var/www/s",
            r#","packages":["drupal/token","drupal/pathauto","drupal/token"]"#,
        ),
        ID,
        None,
    )
    .unwrap();
    assert_eq!(req.packages, ["drupal/pathauto", "drupal/token"]);
    assert!(
        Request::parse(
            "restore-update",
            &plan("/var/www/s", &format!(r#","recoveryId":"{ID}""#)),
            ID,
            None
        )
        .is_ok()
    );
}

#[test]
fn parse_refuses_what_is_not_a_bounded_package_or_the_wrong_shape() {
    let packages = |list: &str| {
        Request::parse(
            "update-packages",
            &plan("/var/www/s", &format!(r#","packages":{list}"#)),
            ID,
            None,
        )
        .err()
    };
    for bad in [
        r#"[]"#,
        r#"["drupal/core"]"#,
        r#"["drupal/core-recommended"]"#,
        r#"["token"]"#,
        r#"["Drupal/Token"]"#,
        r#"["drupal/token --no-scripts"]"#,
        r#"["drupal/*"]"#,
        r#"["-x/y"]"#,
        r#"["a/b/c"]"#,
    ] {
        assert_eq!(packages(bad), Some(RequestError::InvalidPackage), "{bad}");
    }
    let many = format!(
        "[{}]",
        (0..129)
            .map(|n| format!(r#""v/p{n}""#))
            .collect::<Vec<_>>()
            .join(",")
    );
    assert_eq!(packages(&many), Some(RequestError::InvalidPackage));
    // a version, a command or packages on the core operation are shape errors
    for (kind, extra) in [
        ("update-core", r#","packages":["drupal/token"]"#),
        ("update-core", r#","version":"10.3.1""#),
        ("update-packages", ""),
        ("restore-update", ""),
        ("restore-update", r#","recoveryId":"nope""#),
        ("run-composer", ""),
    ] {
        assert!(
            Request::parse(kind, &plan("/var/www/s", extra), ID, None).is_err(),
            "{kind} {extra}"
        );
    }
    assert!(Request::parse("update-core", &plan("web/../x", ""), ID, None).is_err());
}

struct Fixture {
    dir: tempfile::TempDir,
    root: PathBuf,
}

use std::path::PathBuf;

fn fixture(lock: &str, json: &str, multisite: bool) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("site");
    fs::create_dir_all(root.join("web")).unwrap();
    fs::write(root.join("composer.lock"), lock).unwrap();
    fs::write(root.join("composer.json"), json).unwrap();
    fs::create_dir_all(dir.path().join("composer/current")).unwrap();
    fs::write(dir.path().join("composer/current/composer.phar"), "").unwrap();
    let docker = dir.path().join("fake-docker");
    // Everything succeeds, except the multisite probe on a multisite site;
    // the log shows which mutating commands ran.
    fs::write(
        &docker,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{log}'\ncase \"$*\" in *sites.php*) {multi} ;; esac\nexit 0\n",
            log = dir.path().join("docker.log").display(),
            multi = if multisite { "exit 3" } else { "exit 0" },
        ),
    )
    .unwrap();
    fs::set_permissions(&docker, fs::Permissions::from_mode(0o755)).unwrap();
    Fixture { dir, root }
}

fn run_request(fx: &Fixture, kind: &str, extra: &str) -> Result<UpdateResult, Error> {
    run_request_as(fx, kind, extra, ID)
}

fn run_request_as(fx: &Fixture, kind: &str, extra: &str, id: &str) -> Result<UpdateResult, Error> {
    let state_dir = fx.dir.path().join("state");
    let backup_dir = fx.dir.path().join("backups");
    fs::create_dir_all(&state_dir).unwrap();
    fs::create_dir_all(&backup_dir).unwrap();
    let state = managed(&state_dir);
    let backups = managed(&backup_dir);
    let docker = fx.dir.path().join("fake-docker");
    let ctx = Context {
        engine_state: &state,
        docker_program: docker.to_str().unwrap(),
        tar_program: "tar",
        tools_dir: fx.dir.path(),
        backup_root: &backups,
        backup_path: &backup_dir,
    };
    let req = Request::parse(kind, &plan(fx.root.to_str().unwrap(), extra), id, None).unwrap();
    execute(&ctx, &req, &CancellationToken::default())
}

fn docker_log(fx: &Fixture) -> String {
    fs::read_to_string(fx.dir.path().join("docker.log")).unwrap_or_default()
}

const LOCK: &str = r#"{"packages":[{"name":"drupal/core","version":"10.3.1"},{"name":"drupal/token","version":"v1.14.0"}],"packages-dev":[]}"#;
const JSON: &str = r#"{"require":{"drupal/core-recommended":"^10.3","drupal/token":"^1.14"}}"#;

#[test]
fn a_multisite_project_is_refused_before_anything_changes() {
    let fx = fixture(LOCK, JSON, true);
    let error = run_request(&fx, "update-core", "").unwrap_err();
    assert!(matches!(error, Error::Multisite), "{error:?}");
    let log = docker_log(&fx);
    assert!(!log.contains("composer.phar"), "{log}");
    assert!(!log.contains("maintenance_mode 1"), "{log}");
    assert!(!fx.dir.path().join("backups/drupal-updates").exists());
}

#[test]
fn a_package_that_is_not_locked_is_refused() {
    let fx = fixture(LOCK, JSON, false);
    let error =
        run_request(&fx, "update-packages", r#","packages":["drupal/pathauto"]"#).unwrap_err();
    assert!(matches!(error, Error::PackageNotInstalled(name) if name == "drupal/pathauto"));
    assert!(docker_log(&fx).is_empty());
}

#[test]
fn core_needs_a_required_core_package_and_a_readable_lock() {
    let fx = fixture(LOCK, r#"{"require":{"drupal/token":"^1"}}"#, false);
    assert!(matches!(
        run_request(&fx, "update-core", "").unwrap_err(),
        Error::NoCorePackages
    ));
    let fx = fixture("not json", JSON, false);
    assert!(matches!(
        run_request(&fx, "update-core", "").unwrap_err(),
        Error::LockUnreadable
    ));
}

#[test]
fn restoring_without_a_bundle_or_with_a_tampered_one_changes_nothing() {
    let fx = fixture(LOCK, JSON, false);
    let extra = format!(r#","recoveryId":"{ID}""#);
    assert!(matches!(
        run_request(&fx, "restore-update", &extra).unwrap_err(),
        Error::BundleMissing
    ));
    // A manifest whose checksums do not match the files.
    let bundle = fx.dir.path().join("backups/drupal-updates").join(ID);
    fs::create_dir_all(&bundle).unwrap();
    fs::write(bundle.join("files.tar.gz"), "x").unwrap();
    fs::write(bundle.join("database.sql"), "y").unwrap();
    let manifest = Manifest {
        version: 1,
        operation: CORE.into(),
        request_id: ID.into(),
        project_root: fx.root.display().to_string(),
        document_root: format!("{}/web", fx.root.display()),
        created_at_unix_secs: 0,
        previous_maintenance_mode: false,
        versions_before: BTreeMap::new(),
        files_sha256: "0".repeat(64),
        database_sha256: "0".repeat(64),
    };
    fs::write(
        bundle.join("manifest.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    fs::write(fx.root.join("keep"), "mine").unwrap();
    assert!(matches!(
        run_request_as(
            &fx,
            "restore-update",
            &extra,
            "123e4567-e89b-12d3-a456-426614174001"
        )
        .unwrap_err(),
        Error::BundleCorrupt
    ));
    assert_eq!(fs::read_to_string(fx.root.join("keep")).unwrap(), "mine");
}

#[test]
fn locked_versions_strip_the_v_prefix() {
    let fx = fixture(LOCK, JSON, false);
    let versions = locked_versions(&fx.root).unwrap();
    assert_eq!(versions["drupal/token"], "1.14.0");
    assert_eq!(versions["drupal/core"], "10.3.1");
}

#[test]
fn bundles_older_than_a_week_are_pruned_and_fresh_ones_kept() {
    let fx = fixture(LOCK, JSON, false);
    let backups = fx.dir.path().join("backups");
    let old = backups.join("drupal-updates/old-one");
    let fresh = backups.join("drupal-updates/fresh-one");
    fs::create_dir_all(&old).unwrap();
    fs::create_dir_all(&fresh).unwrap();
    fs::write(old.join("files.tar.gz"), "x").unwrap();
    let eight_days = SystemTime::now() - std::time::Duration::from_secs(8 * 24 * 3600);
    fs::File::open(&old)
        .unwrap()
        .set_modified(eight_days)
        .unwrap();
    let managed = managed(&backups);
    let state_dir = fx.dir.path().join("state");
    fs::create_dir_all(&state_dir).unwrap();
    let state = self::managed(&state_dir);
    let ctx = Context {
        engine_state: &state,
        docker_program: "docker",
        tar_program: "tar",
        tools_dir: fx.dir.path(),
        backup_root: &managed,
        backup_path: &backups,
    };
    prune_bundles(&ctx, RequestId::parse(ID).unwrap());
    assert!(!old.exists());
    assert!(fresh.exists());
}

#[test]
fn a_read_only_default_site_is_unlocked_for_the_run_and_put_back() {
    let fx = fixture(LOCK, JSON, false);
    let default = fx.root.join("web/sites/default");
    fs::create_dir_all(&default).unwrap();
    fs::set_permissions(&default, fs::Permissions::from_mode(0o555)).unwrap();
    let req = Request::parse(
        "update-core",
        &plan(fx.root.to_str().unwrap(), ""),
        ID,
        None,
    )
    .unwrap();
    let saved = unlock_default_site(&req);
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&default), 0o755);
    relock_default_site(saved);
    assert_eq!(mode(&default), 0o555);
    // Already writable: nothing to restore.
    fs::set_permissions(&default, fs::Permissions::from_mode(0o775)).unwrap();
    assert!(unlock_default_site(&req).is_none());
    assert_eq!(mode(&default), 0o775);
}

#[test]
fn the_step_journal_is_appended_in_order_and_holds_only_step_names() {
    let dir = tempfile::tempdir().unwrap();
    let backups = dir.path().join("backups");
    let state_dir = dir.path().join("state");
    fs::create_dir_all(backups.join(format!("drupal-updates/{ID}"))).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    let (managed_backups, state) = (managed(&backups), managed(&state_dir));
    let ctx = Context {
        engine_state: &state,
        docker_program: "docker",
        tar_program: "tar",
        tools_dir: dir.path(),
        backup_root: &managed_backups,
        backup_path: &backups,
    };
    let id = RequestId::parse(ID).unwrap();
    record(&ctx, id, Step::Bundled);
    record(&ctx, id, Step::ComposerDone);
    let text = fs::read_to_string(backups.join(format!("drupal-updates/{ID}/steps.json"))).unwrap();
    let journal: steps::Journal = serde_json::from_str(&text).unwrap();
    let names: Vec<Step> = journal.steps.iter().map(|e| e.step).collect();
    assert_eq!(names, [Step::Bundled, Step::ComposerDone]);
    assert!(!text.contains('/'), "no paths in the journal: {text}");
}

const OLDER_ID: &str = "123e4567-e89b-12d3-a456-426614174009";

/// A fake docker that also answers the two Drush calls a rollback needs.
fn answering_docker(fx: &Fixture) {
    let docker = fx.dir.path().join("fake-docker");
    fs::write(
        &docker,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{log}'\ncase \"$*\" in\n\
             *sql:conf*) echo '{{\"driver\":\"mysql\",\"host\":\"db1\",\"username\":\"u\",\"password\":\"p\",\"database\":\"d\"}}' ;;\n\
             *status*) echo '{{\"bootstrap\":\"Successful\"}}' ;;\nesac\nexit 0\n",
            log = fx.dir.path().join("docker.log").display(),
        ),
    )
    .unwrap();
}

/// A complete bundle of the fixture project as it is now, with the given
/// steps in its journal and, if asked, an in-progress transaction.
fn bundle_of_now(fx: &Fixture, id: &str, steps: &[Step], transaction: bool) {
    let backups = fx.dir.path().join("backups");
    let bundle = backups.join("drupal-updates").join(id);
    fs::create_dir_all(&bundle).unwrap();
    let status = std::process::Command::new("tar")
        .args(["-C", fx.root.to_str().unwrap(), "-czf"])
        .arg(bundle.join("files.tar.gz"))
        .arg(".")
        .status()
        .unwrap();
    assert!(status.success());
    fs::write(bundle.join("database.sql"), "SELECT 1;").unwrap();
    let manifest = Manifest {
        version: 1,
        operation: CORE.into(),
        request_id: id.into(),
        project_root: fx.root.display().to_string(),
        document_root: format!("{}/web", fx.root.display()),
        created_at_unix_secs: 1,
        previous_maintenance_mode: false,
        versions_before: BTreeMap::new(),
        files_sha256: sha256_file(&bundle.join("files.tar.gz")).unwrap().1,
        database_sha256: sha256_file(&bundle.join("database.sql")).unwrap().1,
    };
    fs::write(
        bundle.join("manifest.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    let managed_backups = managed(&backups);
    let state = fx.dir.path().join("state");
    fs::create_dir_all(&state).unwrap();
    let ctx = Context {
        engine_state: &managed(&state),
        docker_program: "docker",
        tar_program: "tar",
        tools_dir: fx.dir.path(),
        backup_root: &managed_backups,
        backup_path: &backups,
    };
    let request_id = RequestId::parse(id).unwrap();
    for step in steps {
        record(&ctx, request_id, *step);
    }
    if transaction {
        let hash = crate::transaction::resource_lock::canonical_hash(&fx.root);
        let scope_dir = state.join(format!("drupal-update/{hash}"));
        for child in ["locks", "transactions", "audit"] {
            fs::create_dir_all(scope_dir.join(child)).unwrap();
        }
        let scope = managed(&scope_dir);
        let record = crate::transaction::state::TransactionState::start(request_id, None, CORE);
        state::create(
            &scope,
            &SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap(),
            &record,
        )
        .unwrap();
    }
}

fn last_step(fx: &Fixture, id: &str) -> String {
    let text = fs::read_to_string(
        fx.dir
            .path()
            .join(format!("backups/drupal-updates/{id}/steps.json")),
    )
    .unwrap();
    let journal: steps::Journal = serde_json::from_str(&text).unwrap();
    format!("{:?}", journal.last().unwrap())
}

fn transaction_status(fx: &Fixture, id: &str) -> TransactionStatus {
    let hash = crate::transaction::resource_lock::canonical_hash(&fx.root);
    let scope = managed(&fx.dir.path().join(format!("state/drupal-update/{hash}")));
    state::load(
        &scope,
        &SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap(),
    )
    .unwrap()
    .status
}

const NOT_LOCKED: &str = r#","packages":["drupal/not-locked"]"#;

#[test]
fn the_next_request_rolls_back_an_update_that_died_half_way() {
    let fx = fixture(LOCK, JSON, false);
    answering_docker(&fx);
    bundle_of_now(
        &fx,
        OLDER_ID,
        &[Step::Bundled, Step::MaintenanceOn, Step::ComposerDone],
        true,
    );
    // What the interrupted update did to the site.
    fs::write(fx.root.join("added-by-update"), "x").unwrap();

    let error = run_request(&fx, "update-packages", NOT_LOCKED).unwrap_err();
    assert!(matches!(error, Error::PackageNotInstalled(_)), "{error:?}");

    assert!(!fx.root.join("added-by-update").exists(), "files are back");
    assert!(fx.root.join("composer.lock").is_file());
    assert_eq!(last_step(&fx, OLDER_ID), "RolledBack");
    assert_eq!(transaction_status(&fx, OLDER_ID), TransactionStatus::Failed);
}

#[test]
fn a_finished_or_rolled_back_update_is_left_alone() {
    for last in [Step::Finished, Step::RolledBack] {
        let fx = fixture(LOCK, JSON, false);
        answering_docker(&fx);
        bundle_of_now(&fx, OLDER_ID, &[Step::Bundled, last], false);
        fs::write(fx.root.join("later-change"), "x").unwrap();
        run_request(&fx, "update-packages", NOT_LOCKED).unwrap_err();
        assert!(fx.root.join("later-change").exists(), "{last:?}");
    }
}

#[test]
fn an_update_without_a_journal_is_rolled_back_only_if_its_transaction_never_finished() {
    let fx = fixture(LOCK, JSON, false);
    answering_docker(&fx);
    bundle_of_now(&fx, OLDER_ID, &[], false);
    fs::write(fx.root.join("later-change"), "x").unwrap();
    run_request(&fx, "update-packages", NOT_LOCKED).unwrap_err();
    assert!(
        fx.root.join("later-change").exists(),
        "no transaction: left alone"
    );

    let fx = fixture(LOCK, JSON, false);
    answering_docker(&fx);
    bundle_of_now(&fx, OLDER_ID, &[], true);
    fs::write(fx.root.join("later-change"), "x").unwrap();
    run_request(&fx, "update-packages", NOT_LOCKED).unwrap_err();
    assert!(
        !fx.root.join("later-change").exists(),
        "interrupted: rolled back"
    );
}

#[test]
fn a_bundle_that_cannot_be_rolled_back_stops_the_request_and_changes_nothing() {
    let fx = fixture(LOCK, JSON, false);
    answering_docker(&fx);
    bundle_of_now(&fx, OLDER_ID, &[Step::Bundled, Step::ComposerDone], true);
    fs::write(
        fx.dir
            .path()
            .join(format!("backups/drupal-updates/{OLDER_ID}/database.sql")),
        "tampered",
    )
    .unwrap();
    fs::write(fx.root.join("keep"), "mine").unwrap();
    let error = run_request(&fx, "update-packages", NOT_LOCKED).unwrap_err();
    assert!(matches!(error, Error::RecoveryRequired(_)), "{error:?}");
    assert_eq!(fs::read_to_string(fx.root.join("keep")).unwrap(), "mine");
    assert_eq!(
        transaction_status(&fx, OLDER_ID),
        TransactionStatus::InProgress,
        "still open for the next attempt"
    );
}

#[test]
fn a_bundle_of_another_project_is_not_touched() {
    let fx = fixture(LOCK, JSON, false);
    answering_docker(&fx);
    bundle_of_now(&fx, OLDER_ID, &[Step::Bundled, Step::ComposerDone], false);
    let manifest_path = fx
        .dir
        .path()
        .join(format!("backups/drupal-updates/{OLDER_ID}/manifest.json"));
    let text = fs::read_to_string(&manifest_path)
        .unwrap()
        .replace(&fx.root.display().to_string(), "/var/www/other");
    fs::write(&manifest_path, text).unwrap();
    fs::write(fx.root.join("later-change"), "x").unwrap();
    run_request(&fx, "update-packages", NOT_LOCKED).unwrap_err();
    assert!(fx.root.join("later-change").exists());
    assert_eq!(last_step(&fx, OLDER_ID), "ComposerDone");
}
