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
