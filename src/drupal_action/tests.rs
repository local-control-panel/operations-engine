use super::*;
use std::{fs, os::unix::fs::PermissionsExt};

const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
const ID2: &str = "123e4567-e89b-12d3-a456-426614174001";

fn managed(directory: &std::path::Path) -> ManagedRoot {
    ManagedRoot::open(&crate::site::TrustedRoot::parse(directory).unwrap()).unwrap()
}

fn request(kind: &str, state: Option<&str>, id: &str, key: Option<&str>) -> Request {
    let state = state.map_or(String::new(), |s| format!(r#","state":"{s}""#));
    Request::parse(
        kind,
        &format!(
            r#"{{"container":"runtime-1","projectRoot":"/var/www/site","documentRoot":"/var/www/site/web","uid":1000,"gid":1000{state}}}"#
        ),
        id,
        key,
    )
    .unwrap()
}

/// A stand-in for `docker exec ... drush ...`: records every invocation
/// and keeps the maintenance flag in a file so a read-back works.
fn fake_docker(directory: &std::path::Path, fail_all: bool) -> String {
    let log = directory.join("drush.log");
    let flag = directory.join("flag");
    let path = directory.join("fake-docker");
    fs::write(
        &path,
        format!(
            r#"#!/bin/sh
printf '%s\n' "$*" >> '{log}'
{fail}
case "$*" in
  *"state:set system.maintenance_mode 1"*) echo 1 > '{flag}' ;;
  *"state:set system.maintenance_mode 0"*) echo 0 > '{flag}' ;;
  *"state:get system.maintenance_mode"*) cat '{flag}' ;;
esac
exit 0
"#,
            log = log.display(),
            flag = flag.display(),
            fail = if fail_all { "exit 1" } else { "" },
        ),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path.to_string_lossy().into_owned()
}

fn log(directory: &std::path::Path) -> String {
    fs::read_to_string(directory.join("drush.log")).unwrap_or_default()
}

#[test]
fn rejects_invalid_requests() {
    let base = |extra: &str| {
        format!(
            r#"{{"container":"runtime-1","projectRoot":"/var/www/site","documentRoot":"/var/www/site/web","uid":1,"gid":1{extra}}}"#
        )
    };
    // maintenance needs an explicit on/off; the others forbid a state
    assert_eq!(
        Request::parse("maintenance", &base(""), ID, None).unwrap_err(),
        RequestError::InvalidState
    );
    assert_eq!(
        Request::parse("maintenance", &base(r#","state":"maybe""#), ID, None).unwrap_err(),
        RequestError::InvalidState
    );
    assert_eq!(
        Request::parse("cache-rebuild", &base(r#","state":"on""#), ID, None).unwrap_err(),
        RequestError::InvalidState
    );
    assert_eq!(
        Request::parse("run-anything", &base(""), ID, None).unwrap_err(),
        RequestError::InvalidState
    );
    // unknown fields (a smuggled command) are refused
    assert_eq!(
        Request::parse("cron-run", &base(r#","command":"sql:cli""#), ID, None).unwrap_err(),
        RequestError::InvalidJson
    );
    // the document root must live inside the project root
    let outside = r#"{"container":"runtime-1","projectRoot":"/var/www/site","documentRoot":"/var/www/other","uid":1,"gid":1}"#;
    assert_eq!(
        Request::parse("cron-run", outside, ID, None).unwrap_err(),
        RequestError::InvalidRoot
    );
    let traversal = r#"{"container":"runtime-1","projectRoot":"/var/www/site","documentRoot":"/var/www/site/../etc","uid":1,"gid":1}"#;
    assert_eq!(
        Request::parse("cron-run", traversal, ID, None).unwrap_err(),
        RequestError::InvalidRoot
    );
    let relative = r#"{"container":"runtime-1","projectRoot":"site","documentRoot":"site/web","uid":1,"gid":1}"#;
    assert_eq!(
        Request::parse("cron-run", relative, ID, None).unwrap_err(),
        RequestError::InvalidRoot
    );
}

#[test]
fn runs_fixed_argv_as_the_site_user_and_replays() {
    let dir = tempfile::tempdir().unwrap();
    let docker = fake_docker(dir.path(), false);
    let state = managed(dir.path());
    let ctx = Context {
        engine_state: &state,
        docker_program: &docker,
        tools_dir: dir.path(),
        backup_root: &state,
    };
    let req = request("cache-rebuild", None, ID, Some("cache-key"));
    let first = execute(&ctx, &req, &CancellationToken::default()).unwrap();
    assert_eq!(first.action, "cacheRebuild");
    let recorded = log(dir.path());
    assert_eq!(recorded.lines().count(), 1, "{recorded}");
    assert!(recorded.contains("exec -i --user 1000:1000 -w /var/www/site runtime-1 sh -c"));
    assert!(recorded.contains("--root=/var/www/site/web --no-interaction cache:rebuild"));

    let second = execute(&ctx, &req, &CancellationToken::default()).unwrap();
    assert_eq!(first.completed_at_unix_secs, second.completed_at_unix_secs);
    assert_eq!(log(dir.path()).lines().count(), 1, "replay must not re-run");
}

#[test]
fn cron_run_uses_core_cron() {
    let dir = tempfile::tempdir().unwrap();
    let docker = fake_docker(dir.path(), false);
    let state = managed(dir.path());
    let ctx = Context {
        engine_state: &state,
        docker_program: &docker,
        tools_dir: dir.path(),
        backup_root: &state,
    };
    let req = request("cron-run", None, ID, None);
    let result = execute(&ctx, &req, &CancellationToken::default()).unwrap();
    assert_eq!(result.action, "cronRun");
    assert!(log(dir.path()).contains("core:cron"));
}

#[test]
fn maintenance_sets_rebuilds_and_reads_back() {
    let dir = tempfile::tempdir().unwrap();
    let docker = fake_docker(dir.path(), false);
    let state = managed(dir.path());
    let ctx = Context {
        engine_state: &state,
        docker_program: &docker,
        tools_dir: dir.path(),
        backup_root: &state,
    };
    let on = request("maintenance", Some("on"), ID, None);
    let result = execute(&ctx, &on, &CancellationToken::default()).unwrap();
    assert_eq!(result.maintenance_mode, Some(true));
    let recorded = log(dir.path());
    assert!(recorded.contains("state:set system.maintenance_mode 1 --input-format=integer"));
    assert!(recorded.contains("cache:rebuild"));
    assert!(recorded.contains("state:get system.maintenance_mode"));

    let off = request("maintenance", Some("off"), ID2, None);
    let result = execute(&ctx, &off, &CancellationToken::default()).unwrap();
    assert_eq!(result.maintenance_mode, Some(false));
}

#[test]
fn a_failing_drush_fails_the_request_and_is_replayed_as_failed() {
    let dir = tempfile::tempdir().unwrap();
    let docker = fake_docker(dir.path(), true);
    let state = managed(dir.path());
    let ctx = Context {
        engine_state: &state,
        docker_program: &docker,
        tools_dir: dir.path(),
        backup_root: &state,
    };
    let req = request("cache-rebuild", None, ID, Some("fail-key"));
    assert!(matches!(
        execute(&ctx, &req, &CancellationToken::default()),
        Err(Error::Rejected(_))
    ));
    let retry = request("cache-rebuild", None, ID2, Some("fail-key"));
    assert!(matches!(
        execute(&ctx, &retry, &CancellationToken::default()),
        Err(Error::Replayed { .. })
    ));
    assert_eq!(log(dir.path()).lines().count(), 1, "retry must not re-run");
}

/// `updatedb:status` lists `pending` entries until `updatedb` ran, then
/// none (or, with `sticky`, still the same after it).
fn fake_updatedb_docker(directory: &std::path::Path, pending: u32, sticky: bool) -> String {
    let log = directory.join("drush.log");
    let done = directory.join("updated");
    let path = directory.join("fake-docker");
    let list = (0..pending)
        .map(|n| format!(r#""hook_{n}":{{"module":"m"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    fs::write(
        &path,
        format!(
            r#"#!/bin/sh
printf '%s\n' "$*" >> '{log}'
case "$*" in
  *"sql:conf"*) if [ -e '{conf}' ]; then cat '{conf}'; else echo '{{"driver":"mysql","host":"db-1","username":"drupal","password":"s3cret-pw","database":"drupal"}}'; fi ;;
  *"updatedb:status"*)
if [ -e '{done}' ] && [ "{sticky}" = false ]; then echo '[]'; else echo '{{{list}}}'; fi ;;
  *" updatedb"*) touch '{done}' ;;
  *"state:set system.maintenance_mode 1"*) echo 1 > '{flag}' ;;
  *"state:set system.maintenance_mode 0"*) echo 0 > '{flag}' ;;
  *"state:get system.maintenance_mode"*) cat '{flag}' 2>/dev/null ;;
esac
exit 0
"#,
            log = log.display(),
            done = done.display(),
            flag = directory.join("flag").display(),
            sticky = sticky,
            conf = directory.join("conf").display(),
            list = list,
        ),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path.to_string_lossy().into_owned()
}

/// Like `fake_updatedb_docker` but also keeps the maintenance flag in a
/// file (starting at `start_flag`), dumps a marker for `mariadb-dump`/`sql:dump`, and
/// with `fail_update` makes `updatedb` exit 1.
fn fake_safe_docker(
    directory: &std::path::Path,
    start_flag: u8,
    fail_update: bool,
    fail_dump: bool,
) -> String {
    let log = directory.join("drush.log");
    let done = directory.join("updated");
    let flag = directory.join("flag");
    fs::write(&flag, start_flag.to_string()).unwrap();
    let path = directory.join("fake-docker");
    fs::write(
        &path,
        format!(
            r#"#!/bin/sh
printf '%s\n' "$*" >> '{log}'
case "$*" in
  *"sql:conf"*) if [ -e '{conf}' ]; then cat '{conf}'; else echo '{{"driver":"mysql","host":"db-1","username":"drupal","password":"s3cret-pw","database":"drupal"}}'; fi ;;
  *"updatedb:status"*)
if [ -e '{done}' ]; then echo '[]'; else echo '{{"hook_1":{{}}}}'; fi ;;
  *" updatedb"*) if [ "{fail_update}" = true ]; then exit 1; fi; touch '{done}' ;;
  *"sql:dump"*|*"mariadb-dump"*) if [ "{fail_dump}" = true ]; then echo partial; exit 1; fi; echo 'DUMP' ;;
  *"state:set system.maintenance_mode 1"*) echo 1 > '{flag}' ;;
  *"state:set system.maintenance_mode 0"*) echo 0 > '{flag}' ;;
  *"state:get system.maintenance_mode"*) cat '{flag}' ;;
esac
exit 0
"#,
            log = log.display(),
            done = done.display(),
            flag = flag.display(),
            conf = directory.join("conf").display(),
            fail_update = fail_update,
            fail_dump = fail_dump,
        ),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path.to_string_lossy().into_owned()
}

fn flag(directory: &std::path::Path) -> String {
    fs::read_to_string(directory.join("flag"))
        .unwrap()
        .trim()
        .to_owned()
}

#[test]
fn update_db_backs_up_then_wraps_the_run_in_maintenance_and_restores() {
    let dir = tempfile::tempdir().unwrap();
    let backups_dir = tempfile::tempdir().unwrap();
    let docker = fake_safe_docker(dir.path(), 0, false, false);
    let state = managed(dir.path());
    let backups = managed(backups_dir.path());
    let ctx = Context {
        engine_state: &state,
        docker_program: &docker,
        tools_dir: dir.path(),
        backup_root: &backups,
    };
    let result = execute(
        &ctx,
        &request("update-db", None, ID, None),
        &CancellationToken::default(),
    )
    .unwrap();
    assert_eq!(result.previous_maintenance_mode, Some(false));
    let file = result.backup_file.unwrap();
    assert_eq!(file, format!("drupal-updates/{ID}/database.sql"));
    assert_eq!(
        fs::read_to_string(backups_dir.path().join(&file)).unwrap(),
        "DUMP\n"
    );
    assert_eq!(flag(dir.path()), "0", "previous mode restored");
    let recorded = log(dir.path());
    let at = |needle: &str| {
        recorded
            .find(needle)
            .unwrap_or_else(|| panic!("{needle}: {recorded}"))
    };
    assert!(at("mariadb-dump") < at("maintenance_mode 1"));
    assert!(
        recorded.contains("exec -i -e MYSQL_PWD db-1 mariadb-dump -udrupal --single-transaction"),
        "{recorded}"
    );
    assert!(!recorded.contains("sql:dump"), "{recorded}");
    assert!(
        !recorded.contains("s3cret-pw"),
        "the password never reaches argv: {recorded}"
    );
    assert!(at("maintenance_mode 1") < at("--no-interaction updatedb\n"));
    assert!(at("--no-interaction updatedb\n") < at("maintenance_mode 0"));
}

#[test]
fn update_db_leaves_maintenance_on_when_it_was_on_before() {
    let dir = tempfile::tempdir().unwrap();
    let docker = fake_safe_docker(dir.path(), 1, false, false);
    let state = managed(dir.path());
    let ctx = Context {
        engine_state: &state,
        docker_program: &docker,
        tools_dir: dir.path(),
        backup_root: &state,
    };
    let result = execute(
        &ctx,
        &request("update-db", None, ID, None),
        &CancellationToken::default(),
    )
    .unwrap();
    assert_eq!(result.previous_maintenance_mode, Some(true));
    assert_eq!(flag(dir.path()), "1");
    assert!(!log(dir.path()).contains("state:set"), "never toggled");
}

#[test]
fn update_db_restores_maintenance_after_a_failed_update() {
    let dir = tempfile::tempdir().unwrap();
    let docker = fake_safe_docker(dir.path(), 0, true, false);
    let state = managed(dir.path());
    let ctx = Context {
        engine_state: &state,
        docker_program: &docker,
        tools_dir: dir.path(),
        backup_root: &state,
    };
    let error = execute(
        &ctx,
        &request("update-db", None, ID, None),
        &CancellationToken::default(),
    )
    .unwrap_err();
    assert!(matches!(error, Error::Rejected(_)), "{error:?}");
    assert_eq!(flag(dir.path()), "0", "restored although updatedb failed");
    assert!(log(dir.path()).contains("maintenance_mode 1"));
}

#[test]
fn update_db_runs_nothing_when_the_backup_fails() {
    let dir = tempfile::tempdir().unwrap();
    let docker = fake_safe_docker(dir.path(), 0, false, true);
    let state = managed(dir.path());
    let ctx = Context {
        engine_state: &state,
        docker_program: &docker,
        tools_dir: dir.path(),
        backup_root: &state,
    };
    let error = execute(
        &ctx,
        &request("update-db", None, ID, None),
        &CancellationToken::default(),
    )
    .unwrap_err();
    assert!(matches!(error, Error::BackupFailed(_)), "{error:?}");
    let recorded = log(dir.path());
    assert!(!recorded.contains("state:set"), "{recorded}");
    assert!(
        !recorded.contains("--no-interaction updatedb\n"),
        "{recorded}"
    );
    assert!(
        !dir.path()
            .join(format!("drupal-updates/{ID}/database.sql"))
            .exists(),
        "a partial dump is removed"
    );
}

#[test]
fn update_db_uses_drush_dump_for_another_driver_and_refuses_unreadable_config() {
    let dir = tempfile::tempdir().unwrap();
    let docker = fake_safe_docker(dir.path(), 0, false, false);
    let state = managed(dir.path());
    let ctx = Context {
        engine_state: &state,
        docker_program: &docker,
        tools_dir: dir.path(),
        backup_root: &state,
    };
    fs::write(
        dir.path().join("conf"),
        r#"{"driver":"sqlite","database":"x.db"}"#,
    )
    .unwrap();
    execute(
        &ctx,
        &request("update-db", None, ID, None),
        &CancellationToken::default(),
    )
    .unwrap();
    let recorded = log(dir.path());
    assert!(recorded.contains("sql:dump") && !recorded.contains("mariadb-dump"));

    let dir = tempfile::tempdir().unwrap();
    let docker = fake_safe_docker(dir.path(), 0, false, false);
    let state = managed(dir.path());
    let ctx = Context {
        engine_state: &state,
        docker_program: &docker,
        tools_dir: dir.path(),
        backup_root: &state,
    };
    for bad in [
        "not json",
        r#"{"driver":"mysql","host":"localhost","username":"u","password":"p","database":"d"}"#,
        r#"{"driver":"mysql","host":"db-1","username":"-x","password":"p","database":"d"}"#,
    ]
    .into_iter()
    .zip([
        "123e4567-e89b-12d3-a456-426614174010",
        "123e4567-e89b-12d3-a456-426614174011",
        "123e4567-e89b-12d3-a456-426614174012",
    ]) {
        let (bad, id) = bad;
        fs::write(dir.path().join("conf"), bad).unwrap();
        let error = execute(
            &ctx,
            &request("update-db", None, id, None),
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::BackupConfigUnreadable), "{error:?}");
    }
    let recorded = log(dir.path());
    assert!(!recorded.contains("state:set"), "{recorded}");
    assert!(
        !recorded.contains("--no-interaction updatedb\n"),
        "{recorded}"
    );
    assert!(!dir.path().join(format!("drupal-updates/{ID}")).exists());
}

#[test]
fn update_db_runs_updatedb_only_when_updates_are_pending() {
    let dir = tempfile::tempdir().unwrap();
    let docker = fake_updatedb_docker(dir.path(), 3, false);
    let state = managed(dir.path());
    let ctx = Context {
        engine_state: &state,
        docker_program: &docker,
        tools_dir: dir.path(),
        backup_root: &state,
    };
    let result = execute(
        &ctx,
        &request("update-db", None, ID, None),
        &CancellationToken::default(),
    )
    .unwrap();
    assert_eq!(result.action, "updateDb");
    assert_eq!(result.changed, Some(true));
    assert_eq!(result.updates_pending, Some(3));
    assert_eq!(result.updates_remaining, Some(0));
    let recorded = log(dir.path());
    assert!(recorded.contains("--no-interaction updatedb:status --format=json"));
    assert!(
        recorded.contains("--no-interaction updatedb\n"),
        "{recorded}"
    );
    assert!(
        recorded.contains("mariadb-dump") && recorded.contains("maintenance_mode 1"),
        "{recorded}"
    );

    // nothing pending now: status only, no mutation
    let again = execute(
        &ctx,
        &request("update-db", None, ID2, None),
        &CancellationToken::default(),
    )
    .unwrap();
    assert_eq!(again.changed, Some(false));
    assert_eq!(again.updates_pending, Some(0));
    let after = log(dir.path());
    assert_eq!(
        after.matches("mariadb-dump").count(),
        1,
        "no second dump: {after}"
    );
    assert_eq!(after.matches("--no-interaction updatedb\n").count(), 1);
}

#[test]
fn update_db_fails_when_updates_remain() {
    let dir = tempfile::tempdir().unwrap();
    let docker = fake_updatedb_docker(dir.path(), 2, true);
    let state = managed(dir.path());
    let ctx = Context {
        engine_state: &state,
        docker_program: &docker,
        tools_dir: dir.path(),
        backup_root: &state,
    };
    let error = execute(
        &ctx,
        &request("update-db", None, ID, None),
        &CancellationToken::default(),
    )
    .unwrap_err();
    assert!(matches!(error, Error::UpdatesRemain(2)));
    assert_eq!(error.protocol().0, ErrorCode::SubprocessFailed);
}

/// Keeps the interval in a file: `config:get` prints it, `config:set`
/// stores it. `missing` makes `config:get` fail like a site without the
/// automated_cron module.
fn fake_cron_docker(directory: &std::path::Path, start: u32, missing: bool) -> String {
    let log = directory.join("drush.log");
    let value = directory.join("interval");
    fs::write(&value, start.to_string()).unwrap();
    let path = directory.join("fake-docker");
    fs::write(
        &path,
        format!(
            r#"#!/bin/sh
printf '%s\n' "$*" >> '{log}'
case "$*" in
  *"config:get automated_cron.settings interval --format=json"*)
if [ "{missing}" = true ]; then exit 1; fi; printf '%s' '{{"automated_cron.settings:interval":'; cat '{value}'; printf '%s\n' '}}' ;;
  *"config:set"*"automated_cron.settings interval "*) printf '%s' "$(echo "$*" | sed 's/.*interval //')" > '{value}' ;;
esac
exit 0
"#,
            log = log.display(),
            value = value.display(),
            missing = missing,
        ),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path.to_string_lossy().into_owned()
}

fn cron_request(interval: Option<u32>, id: &str) -> Request {
    let extra = interval.map_or(String::new(), |n| format!(r#","interval":{n}"#));
    Request::parse(
        "automated-cron",
        &format!(
            r#"{{"container":"runtime-1","projectRoot":"/var/www/site","documentRoot":"/var/www/site/web","uid":1000,"gid":1000{extra}}}"#
        ),
        id,
        None,
    )
    .unwrap()
}

#[test]
fn automated_cron_switches_off_is_idempotent_and_restores() {
    let dir = tempfile::tempdir().unwrap();
    let docker = fake_cron_docker(dir.path(), 10800, false);
    let state = managed(dir.path());
    let ctx = Context {
        engine_state: &state,
        docker_program: &docker,
        tools_dir: dir.path(),
        backup_root: &state,
    };
    let cancel = CancellationToken::default();
    let off = execute(&ctx, &cron_request(None, ID), &cancel).unwrap();
    assert_eq!(off.action, "automatedCron");
    assert_eq!(
        (off.changed, off.previous_interval, off.interval),
        (Some(true), Some(10800), Some(0))
    );
    let recorded = log(dir.path());
    assert!(recorded.contains(
        "config:set --no-interaction --input-format=yaml automated_cron.settings interval 0"
    ));
    assert_eq!(recorded.lines().count(), 3, "get, set, get");

    let again = execute(&ctx, &cron_request(Some(0), ID2), &cancel).unwrap();
    assert_eq!(
        (again.changed, again.previous_interval, again.interval),
        (Some(false), Some(0), Some(0))
    );
    assert_eq!(log(dir.path()).lines().count(), 4, "repeat only reads");

    let back = execute(
        &ctx,
        &cron_request(Some(10800), "123e4567-e89b-12d3-a456-426614174002"),
        &cancel,
    )
    .unwrap();
    assert_eq!(
        (back.changed, back.previous_interval, back.interval),
        (Some(true), Some(0), Some(10800))
    );
}

#[test]
fn automated_cron_refuses_when_drupal_cannot_report_the_interval() {
    let dir = tempfile::tempdir().unwrap();
    let docker = fake_cron_docker(dir.path(), 10800, true);
    let state = managed(dir.path());
    let ctx = Context {
        engine_state: &state,
        docker_program: &docker,
        tools_dir: dir.path(),
        backup_root: &state,
    };
    assert!(matches!(
        execute(&ctx, &cron_request(None, ID), &CancellationToken::default()),
        Err(Error::Rejected(_))
    ));
    assert!(
        !log(dir.path()).contains("config:set"),
        "never writes blind"
    );
}

#[test]
fn automated_cron_request_validation_and_interval_parsing() {
    let base = |extra: &str| {
        format!(
            r#"{{"container":"runtime-1","projectRoot":"/var/www/site","documentRoot":"/var/www/site/web","uid":1,"gid":1{extra}}}"#
        )
    };
    assert_eq!(
        Request::parse("automated-cron", &base(r#","interval":99999999"#), ID, None).unwrap_err(),
        RequestError::InvalidInterval
    );
    assert_eq!(
        Request::parse("automated-cron", &base(r#","state":"on""#), ID, None).unwrap_err(),
        RequestError::InvalidState
    );
    assert_eq!(
        Request::parse("cron-run", &base(r#","interval":0"#), ID, None).unwrap_err(),
        RequestError::InvalidInterval
    );
    assert_eq!(cron_interval(b"10800\n"), Some(10800));
    assert_eq!(cron_interval(b"0"), Some(0));
    assert_eq!(cron_interval(b"null"), None);
    assert_eq!(cron_interval(b"\"abc\""), None);
    assert_eq!(cron_interval(b"-1"), None);
}

#[test]
fn cron_interval_accepts_only_the_requested_nonnegative_integer() {
    for bytes in [
        br#"{"automated_cron.settings:interval":3600}"#.as_slice(),
        b"3600\n",
    ] {
        assert_eq!(cron_interval(bytes), Some(3600));
    }
    assert_eq!(
        cron_interval(br#"{"automated_cron.settings:interval":0}"#),
        Some(0)
    );
    for bytes in [
        br#"{"interval":0}"#.as_slice(),
        br#"{"automated_cron.settings:interval":0,"other":0}"#,
        br#"{"automated_cron.settings:interval":null}"#,
        br#"{"automated_cron.settings:interval":"0"}"#,
        br#"{"automated_cron.settings:interval":-1}"#,
        br#"{"automated_cron.settings:interval":1.5}"#,
        b"4294967296",
        b"[]",
        b"{}",
        b"warning\n0",
    ] {
        assert_eq!(cron_interval(bytes), None, "{bytes:?}");
    }
}

#[test]
fn pending_updates_counts_entries_and_refuses_garbage() {
    assert_eq!(pending_updates(b""), Some(0));
    assert_eq!(pending_updates(b"  []\n"), Some(0));
    assert_eq!(pending_updates(b"{}"), Some(0));
    assert_eq!(pending_updates(br#"{"a":{},"b":{}}"#), Some(2));
    assert_eq!(pending_updates(br#"[{"a":1}]"#), Some(1));
    assert_eq!(pending_updates(b"No database updates required"), None);
    assert_eq!(pending_updates(b"7"), None);
}

/// A stand-in for the container: `test -x ./vendor/bin/drush` succeeds
/// once a Composer run created the marker; `composer.json` presence is
/// controlled by `has_composer_json`.
fn fake_composer_docker(directory: &std::path::Path, has_composer_json: bool) -> String {
    let log = directory.join("drush.log");
    let marker = directory.join("drush-installed");
    let path = directory.join("fake-docker");
    fs::write(
        &path,
        format!(
            r#"#!/bin/sh
printf '%s\n' "$*" >> '{log}'
case "$*" in
  *"test -x ./vendor/bin/drush"*) [ -e '{marker}' ]; exit $? ;;
  *"test -f ./composer.json"*) exit {json} ;;
  *"composer.phar require drush/drush"*) touch '{marker}'; exit 0 ;;
esac
exit 0
"#,
            log = log.display(),
            marker = marker.display(),
            json = if has_composer_json { 0 } else { 1 },
        ),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path.to_string_lossy().into_owned()
}

fn with_composer(dir: &std::path::Path) {
    let current = dir.join("tools/composer/current");
    fs::create_dir_all(&current).unwrap();
    fs::write(current.join("composer.phar"), b"x").unwrap();
}

#[test]
fn install_drush_requires_with_the_managed_composer_then_is_a_no_op() {
    let dir = tempfile::tempdir().unwrap();
    with_composer(dir.path());
    let docker = fake_composer_docker(dir.path(), true);
    let state = managed(dir.path());
    let tools = dir.path().join("tools");
    let ctx = Context {
        engine_state: &state,
        docker_program: &docker,
        tools_dir: &tools,
        backup_root: &state,
    };
    let first = execute(
        &ctx,
        &request("install-drush", None, ID, None),
        &CancellationToken::default(),
    )
    .unwrap();
    assert_eq!(first.action, "installDrush");
    assert_eq!(first.changed, Some(true));
    let recorded = log(dir.path());
    assert!(recorded.contains(
        "-e COMPOSER_HOME=/tmp/wcp-composer -e COMPOSER_CACHE_DIR=/tmp/wcp-composer/cache"
    ));
    assert!(recorded.contains(
        "runtime-1 php /opt/wcp-tools/composer/current/composer.phar require drush/drush"
    ));
    assert!(recorded.contains("--no-scripts"));
    assert!(recorded.contains("--version"), "verifies Drush runs");

    let second = execute(
        &ctx,
        &request("install-drush", None, ID2, None),
        &CancellationToken::default(),
    )
    .unwrap();
    assert_eq!(second.changed, Some(false));
    assert_eq!(recorded.matches("require drush/drush").count(), 1);
    assert_eq!(log(dir.path()).matches("require drush/drush").count(), 1);
}

/// Like `fake_composer_docker`, but the Composer run exits with `code`.
fn failing_composer_docker(directory: &std::path::Path, code: i32) -> String {
    let path = directory.join("fake-docker-failing");
    fs::write(
        &path,
        format!(
            r#"#!/bin/sh
case "$*" in
  *"test -x ./vendor/bin/drush"*) exit 1 ;;
  *"test -f ./composer.json"*) exit 0 ;;
  *"composer.phar require drush/drush"*) echo 'SECRET-TOKEN-IN-STDERR' >&2; exit {code} ;;
esac
exit 0
"#
        ),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path.to_string_lossy().into_owned()
}

#[test]
fn a_failing_composer_step_is_reported_as_composer_with_its_exit_code_and_no_output() {
    let dir = tempfile::tempdir().unwrap();
    with_composer(dir.path());
    let docker = failing_composer_docker(dir.path(), 3);
    let state = managed(dir.path());
    let tools = dir.path().join("tools");
    let ctx = Context {
        engine_state: &state,
        docker_program: &docker,
        tools_dir: &tools,
        backup_root: &state,
    };
    let error = execute(
        &ctx,
        &request("install-drush", None, ID, None),
        &CancellationToken::default(),
    )
    .unwrap_err();
    assert!(matches!(error, Error::ComposerFailed(_)), "{error:?}");
    let (code, message) = error.protocol();
    assert_eq!(code, ErrorCode::SubprocessFailed);
    assert!(message.starts_with("Composer could not add drush/drush"));
    assert!(message.contains("(exit code 3)"), "{message}");
    assert!(
        !message.contains("SECRET"),
        "what the child printed never reaches the message"
    );
}

#[test]
fn subprocess_outcomes_read_plainly() {
    let base = SubprocessDiagnostics {
        program: "docker".into(),
        exit_code: Some(2),
        timed_out: false,
        cancelled: false,
        stdout_truncated: false,
        stderr_truncated: false,
    };
    assert_eq!(outcome_suffix(&base), " (exit code 2)");
    let timed_out = SubprocessDiagnostics {
        exit_code: None,
        timed_out: true,
        ..base
    };
    assert_eq!(outcome_suffix(&timed_out), " (timed out)");
    assert_eq!(subprocess_code(&timed_out), ErrorCode::Timeout);
    let (_, message) = Error::DrushDoesNotRun(timed_out).protocol();
    assert_eq!(
        message,
        "Drush was added to the project but does not run (timed out)"
    );
}

#[test]
fn install_drush_refuses_without_composer_or_a_composer_project() {
    let dir = tempfile::tempdir().unwrap();
    let state = managed(dir.path());
    let tools = dir.path().join("tools");
    let ctx = Context {
        engine_state: &state,
        docker_program: &fake_composer_docker(dir.path(), true),
        tools_dir: &tools,
        backup_root: &state,
    };
    assert!(matches!(
        execute(
            &ctx,
            &request("install-drush", None, ID, None),
            &CancellationToken::default()
        ),
        Err(Error::ComposerMissing)
    ));
    let dir = tempfile::tempdir().unwrap();
    with_composer(dir.path());
    let state = managed(dir.path());
    let tools = dir.path().join("tools");
    let ctx = Context {
        engine_state: &state,
        docker_program: &fake_composer_docker(dir.path(), false),
        tools_dir: &tools,
        backup_root: &state,
    };
    assert!(matches!(
        execute(
            &ctx,
            &request("install-drush", None, ID, None),
            &CancellationToken::default()
        ),
        Err(Error::NotAComposerProject)
    ));
}

/// Real-host check against a live Drupal container; run manually with
/// `WCP_DRUPAL_E2E_CONTAINER=<name> WCP_DRUPAL_E2E_PROJECT=<project root>
/// WCP_DRUPAL_E2E_DOCROOT=<public root> WCP_DRUPAL_E2E_UID=<uid>
/// cargo test -- --ignored drupal_action_e2e`.
#[test]
#[ignore = "needs a live Drupal container"]
fn drupal_action_e2e() {
    let (Ok(container), Ok(project), Ok(docroot), Ok(uid)) = (
        std::env::var("WCP_DRUPAL_E2E_CONTAINER"),
        std::env::var("WCP_DRUPAL_E2E_PROJECT"),
        std::env::var("WCP_DRUPAL_E2E_DOCROOT"),
        std::env::var("WCP_DRUPAL_E2E_UID"),
    ) else {
        return;
    };
    let docker = std::env::var("WCP_DRUPAL_E2E_DOCKER").unwrap_or("docker".into());
    let dir = tempfile::tempdir().unwrap();
    let state = managed(dir.path());
    let ctx = Context {
        engine_state: &state,
        docker_program: &docker,
        tools_dir: dir.path(),
        backup_root: &state,
    };
    let make = |kind: &str, st: Option<&str>, id: &str| {
        let st = st.map_or(String::new(), |s| format!(r#","state":"{s}""#));
        Request::parse(
            kind,
            &format!(
                r#"{{"container":"{container}","projectRoot":"{project}","documentRoot":"{docroot}","uid":{uid},"gid":{uid}{st}}}"#
            ),
            id,
            None,
        )
        .unwrap()
    };
    let cancel = CancellationToken::default();
    println!(
        "{:?}",
        execute(&ctx, &make("cache-rebuild", None, ID), &cancel).unwrap()
    );
    println!(
        "{:?}",
        execute(&ctx, &make("cron-run", None, ID2), &cancel).unwrap()
    );
    let on = execute(
        &ctx,
        &make(
            "maintenance",
            Some("on"),
            "123e4567-e89b-12d3-a456-426614174002",
        ),
        &cancel,
    )
    .unwrap();
    assert_eq!(on.maintenance_mode, Some(true));
    let off = execute(
        &ctx,
        &make(
            "maintenance",
            Some("off"),
            "123e4567-e89b-12d3-a456-426614174003",
        ),
        &cancel,
    )
    .unwrap();
    assert_eq!(off.maintenance_mode, Some(false));
}
