//! The `ingress.removeRoute` operation: deleting a domain's route files
//! (live or disabled, plus its maintenance backup) as one hash-guarded,
//! transactional step, with the ingress reloaded so the domain stops being
//! served and every file put back if that reload fails.
//!
//! Replaces `delete_site`'s raw `sudo rm -f` of the three route files. The
//! files are renamed to `.rollback-<request-id>` siblings first (the
//! convention `ingress.reconcile` already recovers from) and only deleted
//! once the reload has accepted the removal.
//!
//! The engine refuses a domain whose live *and* disabled route both exist:
//! that is not a state any engine operation produces, and picking one of the
//! two to call "the route" would be a guess.

use crate::{
    filesystem::ManagedRoot,
    ingress::{
        ConfigHash, INGRESS_SERVICE, REMOVE_ROUTE_OPERATION, RemoveRouteRequest, RemoveRouteResult,
        backup_route_path, disabled_route_path,
        execute::ActivateContext,
        route_path,
        transition::{
            self, LifecycleError, Rename, read_optional, rollback_sibling, unix_now_secs,
        },
    },
    process::CancellationToken,
};

pub type RemoveRouteError = LifecycleError<RemoveRouteResult>;

pub fn execute(
    context: &ActivateContext<'_>,
    request: &RemoveRouteRequest,
    cancellation: &CancellationToken,
) -> Result<RemoveRouteResult, RemoveRouteError> {
    let op_state = crate::ingress::execute::open_ingress_state(context.engine_state)
        .map_err(LifecycleError::Io)?;
    transition::run(
        context.engine_state,
        &op_state,
        REMOVE_ROUTE_OPERATION,
        request.request_id,
        request.idempotency_key.as_ref(),
        cancellation,
        || remove(context, request),
    )
}

fn remove(
    context: &ActivateContext<'_>,
    request: &RemoveRouteRequest,
) -> Result<RemoveRouteResult, RemoveRouteError> {
    let root = ManagedRoot::open(context.ingress_root).map_err(LifecycleError::Io)?;
    let live = route_path(&request.domain);
    let disabled = disabled_route_path(&request.domain);
    let backup = backup_route_path(&request.domain);

    let live_bytes = read_optional(&root, &live).map_err(LifecycleError::Io)?;
    let disabled_bytes = read_optional(&root, &disabled).map_err(LifecycleError::Io)?;
    let backup_bytes = read_optional(&root, &backup).map_err(LifecycleError::Io)?;

    let (was_live, route_bytes) = match (live_bytes, disabled_bytes) {
        (Some(_), Some(_)) => {
            return Err(LifecycleError::Conflict(
                "both the live and the disabled route exist for this domain; resolve it manually",
            ));
        }
        (Some(bytes), None) => (true, bytes),
        (None, Some(bytes)) => (false, bytes),
        (None, None) => return Err(LifecycleError::NotFound),
    };
    if ConfigHash::of(&route_bytes) != request.expected_hash {
        return Err(LifecycleError::HashGuardMismatch);
    }
    // An omitted backup hash asserts that there is no backup.
    let backup_ok = match (&backup_bytes, &request.expected_backup_hash) {
        (None, None) => true,
        (Some(bytes), Some(expected)) => &ConfigHash::of(bytes) == expected,
        _ => false,
    };
    if !backup_ok {
        return Err(LifecycleError::HashGuardMismatch);
    }

    let suffix = request.request_id.to_string();
    let mut renames = Vec::new();
    let mut cleanup = Vec::new();
    let mut stage = |path: &crate::site::SiteRelativePath| {
        let aside = rollback_sibling(path, &suffix);
        renames.push(Rename {
            from: path.clone(),
            to: aside.clone(),
        });
        cleanup.push(aside);
    };
    stage(if was_live { &live } else { &disabled });
    if backup_bytes.is_some() {
        stage(&backup);
    }

    // Only a live route changes what the running server serves.
    let reload_service = was_live.then_some(INGRESS_SERVICE);
    transition::transition(&root, &renames, reload_service, &cleanup, context.compose)
        .map_err(LifecycleError::Transition)?;

    Ok(RemoveRouteResult {
        domain: request.domain.as_str().to_owned(),
        was_live,
        removed_maintenance_backup: backup_bytes.is_some(),
        content_sha256: ConfigHash::of(&route_bytes),
        removed_at_unix_secs: unix_now_secs(),
    })
}

#[cfg(all(test, unix))]
mod tests {
    use std::{fs, path::Path};

    use super::{RemoveRouteError, execute};
    use crate::{
        error::ErrorCode,
        filesystem::ManagedRoot,
        ingress::{
            ConfigHash, RemoveRouteRequest, RemoveRouteResult, execute::ActivateContext,
            fake_docker::FakeDocker,
        },
        process::CancellationToken,
        site::TrustedRoot,
    };

    const DOMAIN: &str = "example.com";
    const REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const RETRY_REQUEST_ID: &str = "9b2f1c34-5678-4abc-9def-0123456789ab";
    const ROUTE: &str = "example.com {\n  respond \"live\"\n}\n";
    const BACKUP: &str = "example.com {\n  respond \"before maintenance\"\n}\n";

    struct Host {
        state_dir: tempfile::TempDir,
        ingress_dir: tempfile::TempDir,
        ingress_root: TrustedRoot,
        engine_state: ManagedRoot,
    }

    fn host(files: &[(&str, &str)]) -> Host {
        let state_dir = tempfile::tempdir().expect("state root should be created");
        let ingress_dir = tempfile::tempdir().expect("ingress root should be created");
        for (name, contents) in files {
            fs::write(ingress_dir.path().join(name), contents).expect("file should be written");
        }
        let engine_state = ManagedRoot::open(
            &TrustedRoot::parse(state_dir.path()).expect("state root should be valid"),
        )
        .expect("state root should open");
        let ingress_root =
            TrustedRoot::parse(ingress_dir.path()).expect("ingress root should be valid");
        Host {
            state_dir,
            ingress_dir,
            ingress_root,
            engine_state,
        }
    }

    impl Host {
        fn read(&self, name: &str) -> Option<String> {
            fs::read_to_string(self.ingress_dir.path().join(name)).ok()
        }

        fn entries(&self) -> Vec<String> {
            let mut names: Vec<String> = fs::read_dir(Path::new(self.ingress_dir.path()))
                .expect("ingress root should list")
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        }

        fn transaction(&self, request_id: &str) -> serde_json::Value {
            let path = self
                .state_dir
                .path()
                .join(format!("ingress/transactions/{request_id}.json"));
            serde_json::from_str(&fs::read_to_string(path).expect("record should exist"))
                .expect("record should be JSON")
        }
    }

    fn request(
        route: &str,
        backup: Option<&str>,
        request_id: &str,
        key: Option<&str>,
    ) -> RemoveRouteRequest {
        RemoveRouteRequest::parse(
            DOMAIN,
            ConfigHash::of(route.as_bytes()).as_str(),
            backup
                .map(|backup| ConfigHash::of(backup.as_bytes()).as_str().to_owned())
                .as_deref(),
            request_id,
            key,
        )
        .expect("request should parse")
    }

    fn run(
        host: &Host,
        docker: &FakeDocker,
        request: &RemoveRouteRequest,
    ) -> Result<RemoveRouteResult, RemoveRouteError> {
        let access = docker.access();
        let context = ActivateContext {
            ingress_root: &host.ingress_root,
            engine_state: &host.engine_state,
            compose: &access,
        };
        execute(&context, request, &CancellationToken::default())
    }

    #[test]
    fn removing_a_live_route_deletes_it_with_its_backup_and_reloads() {
        let host = host(&[
            ("example.com.caddyfile", ROUTE),
            ("example.com.maintenance-backup", BACKUP),
        ]);
        let docker = FakeDocker::new();

        let result = run(
            &host,
            &docker,
            &request(ROUTE, Some(BACKUP), REQUEST_ID, None),
        )
        .expect("removal should succeed");

        assert!(result.was_live);
        assert!(result.removed_maintenance_backup);
        assert_eq!(result.content_sha256, ConfigHash::of(ROUTE.as_bytes()));
        assert!(
            host.entries().is_empty(),
            "no route or rollback file may remain: {:?}",
            host.entries()
        );
        assert_eq!(docker.calls("reload").len(), 1);
        let record = host.transaction(REQUEST_ID);
        assert_eq!(record["operation"], "ingress.removeRoute");
        assert_eq!(record["status"], "COMMITTED");
    }

    #[test]
    fn removing_a_disabled_route_does_not_reload() {
        let host = host(&[("example.com.caddyfile.disabled", ROUTE)]);
        let docker = FakeDocker::new();

        let result = run(&host, &docker, &request(ROUTE, None, REQUEST_ID, None))
            .expect("removal should succeed");

        assert!(!result.was_live);
        assert!(!result.removed_maintenance_backup);
        assert!(host.entries().is_empty());
        assert!(docker.calls("reload").is_empty());
    }

    #[test]
    fn a_stale_route_hash_removes_nothing() {
        let host = host(&[("example.com.caddyfile", ROUTE)]);
        let docker = FakeDocker::new();

        let error = run(
            &host,
            &docker,
            &request("something else", None, REQUEST_ID, None),
        )
        .expect_err("a stale hash must be refused");

        assert!(matches!(error, RemoveRouteError::HashGuardMismatch));
        assert_eq!(error.protocol().0, ErrorCode::ConfigHashMismatch);
        assert_eq!(host.read("example.com.caddyfile").as_deref(), Some(ROUTE));
        assert_eq!(host.transaction(REQUEST_ID)["status"], "FAILED");
    }

    #[test]
    fn an_unexpected_or_unclaimed_backup_removes_nothing() {
        let host = host(&[
            ("example.com.caddyfile", ROUTE),
            ("example.com.maintenance-backup", BACKUP),
        ]);
        let docker = FakeDocker::new();

        // The caller claims there is no backup, but there is one.
        let error = run(&host, &docker, &request(ROUTE, None, REQUEST_ID, None))
            .expect_err("an unclaimed backup must be refused");
        assert!(matches!(error, RemoveRouteError::HashGuardMismatch));

        // The caller claims a different backup.
        let error = run(
            &host,
            &docker,
            &request(ROUTE, Some("other"), RETRY_REQUEST_ID, None),
        )
        .expect_err("a stale backup hash must be refused");
        assert!(matches!(error, RemoveRouteError::HashGuardMismatch));
        assert_eq!(host.entries().len(), 2);
    }

    #[test]
    fn a_missing_route_is_not_found() {
        let host = host(&[]);
        let docker = FakeDocker::new();

        let error = run(&host, &docker, &request(ROUTE, None, REQUEST_ID, None))
            .expect_err("nothing to remove");

        assert!(matches!(error, RemoveRouteError::NotFound));
        assert_eq!(error.protocol().0, ErrorCode::NotFound);
    }

    #[test]
    fn live_and_disabled_routes_together_are_refused() {
        let host = host(&[
            ("example.com.caddyfile", ROUTE),
            ("example.com.caddyfile.disabled", ROUTE),
        ]);
        let docker = FakeDocker::new();

        let error = run(&host, &docker, &request(ROUTE, None, REQUEST_ID, None))
            .expect_err("an ambiguous state must be refused");

        assert!(matches!(error, RemoveRouteError::Conflict(_)));
        assert_eq!(host.entries().len(), 2);
    }

    #[test]
    fn a_reload_failure_puts_every_file_back() {
        let host = host(&[
            ("example.com.caddyfile", ROUTE),
            ("example.com.maintenance-backup", BACKUP),
        ]);
        let docker = FakeDocker::new().failing("reload", "1");

        let error = run(
            &host,
            &docker,
            &request(ROUTE, Some(BACKUP), REQUEST_ID, None),
        )
        .expect_err("a refused reload must fail the removal");

        assert_eq!(error.protocol().0, ErrorCode::ConfigReloadFailed);
        assert_eq!(host.read("example.com.caddyfile").as_deref(), Some(ROUTE));
        assert_eq!(
            host.read("example.com.maintenance-backup").as_deref(),
            Some(BACKUP)
        );
        assert_eq!(host.entries().len(), 2, "no rollback sibling may remain");
        assert_eq!(
            docker.calls("reload").len(),
            2,
            "the restored state is reloaded too"
        );
    }

    #[test]
    fn a_failed_restore_reload_reports_recovery_failure_and_keeps_the_files() {
        let host = host(&[("example.com.caddyfile", ROUTE)]);
        let docker = FakeDocker::new().failing("reload", "all");

        let error = run(&host, &docker, &request(ROUTE, None, REQUEST_ID, None))
            .expect_err("both reloads fail");

        assert_eq!(error.protocol().0, ErrorCode::ConfigRecoveryFailed);
        assert_eq!(host.read("example.com.caddyfile").as_deref(), Some(ROUTE));
    }

    #[test]
    fn a_retry_with_the_same_idempotency_key_replays_the_original_result() {
        let host = host(&[("example.com.caddyfile", ROUTE)]);
        let docker = FakeDocker::new();
        let first = run(
            &host,
            &docker,
            &request(ROUTE, None, REQUEST_ID, Some("delete-1")),
        )
        .expect("removal should succeed");

        let replay = run(
            &host,
            &docker,
            &request(ROUTE, None, RETRY_REQUEST_ID, Some("delete-1")),
        )
        .expect("a retry must replay, not fail with NotFound");

        assert_eq!(replay.removed_at_unix_secs, first.removed_at_unix_secs);
        assert_eq!(docker.calls("reload").len(), 1);
    }
}
