//! The `ingress.setEnabled` operation: enabling or disabling a domain by
//! renaming its route between `<domain>.caddyfile` and
//! `<domain>.caddyfile.disabled`, hash-guarded, with the ingress reloaded
//! and the rename reversed if the reload refuses it.
//!
//! Replaces `toggle_site`'s raw `sudo mv -f` and its hand-written
//! move-back-on-failure. Unlike `mv -f`, a destination that already exists
//! is refused rather than overwritten.
//!
//! Re-sending a request whose route is already in the requested state (the
//! source file is gone and the destination holds the expected content)
//! succeeds with `changed: false`, after reloading to confirm the server is
//! on it, so a lost response can be retried safely.

use crate::{
    filesystem::ManagedRoot,
    ingress::{
        ConfigHash, INGRESS_SERVICE, SET_ENABLED_OPERATION, SetEnabledRequest, SetEnabledResult,
        activate, disabled_route_path,
        execute::ActivateContext,
        route_path,
        transition::{self, LifecycleError, Rename, read_optional, unix_now_secs},
    },
    process::CancellationToken,
};

pub type SetEnabledError = LifecycleError<SetEnabledResult>;

pub fn execute(
    context: &ActivateContext<'_>,
    request: &SetEnabledRequest,
    cancellation: &CancellationToken,
) -> Result<SetEnabledResult, SetEnabledError> {
    let op_state = crate::ingress::execute::open_ingress_state(context.engine_state)
        .map_err(LifecycleError::Io)?;
    transition::run(
        context.engine_state,
        &op_state,
        SET_ENABLED_OPERATION,
        request.request_id,
        request.idempotency_key.as_ref(),
        cancellation,
        || set_enabled(context, request),
    )
}

fn set_enabled(
    context: &ActivateContext<'_>,
    request: &SetEnabledRequest,
) -> Result<SetEnabledResult, SetEnabledError> {
    let root = ManagedRoot::open(context.ingress_root).map_err(LifecycleError::Io)?;
    let (from, to) = if request.enabled {
        (
            disabled_route_path(&request.domain),
            route_path(&request.domain),
        )
    } else {
        (
            route_path(&request.domain),
            disabled_route_path(&request.domain),
        )
    };

    let source = read_optional(&root, &from).map_err(LifecycleError::Io)?;
    let destination = read_optional(&root, &to).map_err(LifecycleError::Io)?;
    let result = |changed: bool| SetEnabledResult {
        domain: request.domain.as_str().to_owned(),
        enabled: request.enabled,
        changed,
        content_sha256: request.expected_hash.clone(),
        changed_at_unix_secs: unix_now_secs(),
    };

    match (source, destination) {
        (Some(bytes), None) => {
            if ConfigHash::of(&bytes) != request.expected_hash {
                return Err(LifecycleError::HashGuardMismatch);
            }
            let renames = [Rename { from, to }];
            transition::transition(&root, &renames, Some(INGRESS_SERVICE), &[], context.compose)
                .map_err(LifecycleError::Transition)?;
            Ok(result(true))
        }
        (Some(_), Some(_)) => Err(LifecycleError::Conflict(
            "both the live and the disabled route exist for this domain; resolve it manually",
        )),
        (None, Some(bytes)) => {
            // Already in the requested state: converge, do not assume.
            if ConfigHash::of(&bytes) != request.expected_hash {
                return Err(LifecycleError::HashGuardMismatch);
            }
            transition::reload(context.compose, INGRESS_SERVICE).map_err(|failure| {
                LifecycleError::Transition(activate::Error::ReloadFailedUnchanged(failure))
            })?;
            Ok(result(false))
        }
        (None, None) => Err(LifecycleError::NotFound),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;

    use super::{SetEnabledError, execute};
    use crate::{
        error::ErrorCode,
        filesystem::ManagedRoot,
        ingress::{
            ConfigHash, SetEnabledRequest, SetEnabledResult, execute::ActivateContext,
            fake_docker::FakeDocker,
        },
        process::CancellationToken,
        site::TrustedRoot,
    };

    const DOMAIN: &str = "example.com";
    const REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const RETRY_REQUEST_ID: &str = "9b2f1c34-5678-4abc-9def-0123456789ab";
    const LIVE: &str = "example.com.caddyfile";
    const DISABLED: &str = "example.com.caddyfile.disabled";
    const ROUTE: &str = "example.com {\n  respond \"hello\"\n}\n";

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

        fn status(&self, request_id: &str) -> String {
            let path = self
                .state_dir
                .path()
                .join(format!("ingress/transactions/{request_id}.json"));
            let record: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(path).expect("record should exist"))
                    .expect("record should be JSON");
            record["status"].as_str().unwrap_or_default().to_owned()
        }
    }

    fn request(
        enabled: bool,
        hash_of: &str,
        request_id: &str,
        key: Option<&str>,
    ) -> SetEnabledRequest {
        SetEnabledRequest::parse(
            DOMAIN,
            enabled,
            ConfigHash::of(hash_of.as_bytes()).as_str(),
            request_id,
            key,
        )
        .expect("request should parse")
    }

    fn run(
        host: &Host,
        docker: &FakeDocker,
        request: &SetEnabledRequest,
    ) -> Result<SetEnabledResult, SetEnabledError> {
        let access = docker.access();
        let context = ActivateContext {
            ingress_root: &host.ingress_root,
            engine_state: &host.engine_state,
            compose: &access,
        };
        execute(&context, request, &CancellationToken::default())
    }

    #[test]
    fn disabling_renames_the_live_route_and_reloads() {
        let host = host(&[(LIVE, ROUTE)]);
        let docker = FakeDocker::new();

        let result = run(&host, &docker, &request(false, ROUTE, REQUEST_ID, None))
            .expect("disabling should succeed");

        assert!(result.changed && !result.enabled);
        assert!(host.read(LIVE).is_none());
        assert_eq!(host.read(DISABLED).as_deref(), Some(ROUTE));
        assert_eq!(docker.calls("reload").len(), 1);
        assert_eq!(host.status(REQUEST_ID), "COMMITTED");
    }

    #[test]
    fn enabling_renames_the_disabled_route_back() {
        let host = host(&[(DISABLED, ROUTE)]);
        let docker = FakeDocker::new();

        let result = run(&host, &docker, &request(true, ROUTE, REQUEST_ID, None))
            .expect("enabling should succeed");

        assert!(result.changed && result.enabled);
        assert_eq!(host.read(LIVE).as_deref(), Some(ROUTE));
        assert!(host.read(DISABLED).is_none());
    }

    #[test]
    fn a_stale_hash_moves_nothing() {
        let host = host(&[(LIVE, ROUTE)]);
        let docker = FakeDocker::new();

        let error = run(&host, &docker, &request(false, "other", REQUEST_ID, None))
            .expect_err("a stale hash must be refused");

        assert_eq!(error.protocol().0, ErrorCode::ConfigHashMismatch);
        assert_eq!(host.read(LIVE).as_deref(), Some(ROUTE));
        assert!(docker.calls("reload").is_empty());
    }

    #[test]
    fn a_reload_failure_renames_the_route_back_and_reloads_again() {
        let host = host(&[(LIVE, ROUTE)]);
        let docker = FakeDocker::new().failing("reload", "1");

        let error = run(&host, &docker, &request(false, ROUTE, REQUEST_ID, None))
            .expect_err("a refused reload must fail the toggle");

        assert_eq!(error.protocol().0, ErrorCode::ConfigReloadFailed);
        assert_eq!(host.read(LIVE).as_deref(), Some(ROUTE));
        assert!(host.read(DISABLED).is_none());
        assert_eq!(docker.calls("reload").len(), 2);
        assert_eq!(host.status(REQUEST_ID), "FAILED");
    }

    #[test]
    fn a_failed_restore_reload_reports_recovery_failure() {
        let host = host(&[(LIVE, ROUTE)]);
        let docker = FakeDocker::new().failing("reload", "all");

        let error = run(&host, &docker, &request(false, ROUTE, REQUEST_ID, None))
            .expect_err("both reloads fail");

        assert_eq!(error.protocol().0, ErrorCode::ConfigRecoveryFailed);
        assert_eq!(host.read(LIVE).as_deref(), Some(ROUTE));
    }

    #[test]
    fn an_occupied_destination_is_refused_not_overwritten() {
        let host = host(&[(LIVE, ROUTE), (DISABLED, "older")]);
        let docker = FakeDocker::new();

        let error = run(&host, &docker, &request(false, ROUTE, REQUEST_ID, None))
            .expect_err("mv -f's silent overwrite must be refused");

        assert_eq!(error.protocol().0, ErrorCode::Conflict);
        assert_eq!(host.read(DISABLED).as_deref(), Some("older"));
    }

    #[test]
    fn a_missing_route_is_not_found() {
        let host = host(&[]);
        let docker = FakeDocker::new();

        let error = run(&host, &docker, &request(true, ROUTE, REQUEST_ID, None))
            .expect_err("nothing to move");

        assert_eq!(error.protocol().0, ErrorCode::NotFound);
    }

    #[test]
    fn a_route_already_in_the_requested_state_converges_without_a_rename() {
        let host = host(&[(LIVE, ROUTE)]);
        let docker = FakeDocker::new();

        let result = run(&host, &docker, &request(true, ROUTE, REQUEST_ID, None))
            .expect("re-enabling an enabled route is a no-op success");

        assert!(!result.changed && result.enabled);
        assert_eq!(host.read(LIVE).as_deref(), Some(ROUTE));
        assert_eq!(
            docker.calls("reload").len(),
            1,
            "the server is reloaded to confirm"
        );
    }

    #[test]
    fn a_retry_with_the_same_idempotency_key_replays_the_original_result() {
        let host = host(&[(LIVE, ROUTE)]);
        let docker = FakeDocker::new();
        let first = run(
            &host,
            &docker,
            &request(false, ROUTE, REQUEST_ID, Some("toggle-1")),
        )
        .expect("disabling should succeed");

        let replay = run(
            &host,
            &docker,
            &request(false, ROUTE, RETRY_REQUEST_ID, Some("toggle-1")),
        )
        .expect("a retry must replay");

        assert_eq!(replay.changed_at_unix_secs, first.changed_at_unix_secs);
        assert_eq!(docker.calls("reload").len(), 1);
    }
}
