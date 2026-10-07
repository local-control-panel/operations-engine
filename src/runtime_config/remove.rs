//! The `runtime.removeConfig` operation: deleting one site's fragment from
//! one runtime pool, hash-guarded, with that pool's Caddy reloaded and the
//! fragment put back if the reload refuses the removal.
//!
//! Replaces the panel's `remove_runtime_config_checked` and the exec-config
//! half of `delete_site` (`sudo rm -f` of the fragment). The fragment is
//! renamed to a `.rollback-<request-id>` sibling first, which
//! `runtime.reconcile` recovers from, and only deleted once the reload has
//! accepted the removal. Stopping a pool that has become idle stays a
//! separate call (`stack.stopIdleRuntime`).

use crate::{
    filesystem::ManagedRoot,
    ingress::{
        ConfigHash,
        transition::{
            self, LifecycleError, Rename, read_optional, rollback_sibling, unix_now_secs,
        },
    },
    process::CancellationToken,
    runtime_config::{
        REMOVE_OPERATION, RuntimeRemoveConfigRequest, RuntimeRemoveConfigResult,
        execute::{RuntimeActivateContext, open_runtime_config_state},
        route_path,
    },
};

pub type RuntimeRemoveConfigError = LifecycleError<RuntimeRemoveConfigResult>;

pub fn execute(
    context: &RuntimeActivateContext<'_>,
    request: &RuntimeRemoveConfigRequest,
    cancellation: &CancellationToken,
) -> Result<RuntimeRemoveConfigResult, RuntimeRemoveConfigError> {
    let op_state = open_runtime_config_state(context.engine_state, &request.runtime_id)
        .map_err(LifecycleError::Io)?;
    transition::run(
        context.engine_state,
        &op_state,
        REMOVE_OPERATION,
        request.request_id,
        request.idempotency_key.as_ref(),
        cancellation,
        || remove(context, request),
    )
}

fn remove(
    context: &RuntimeActivateContext<'_>,
    request: &RuntimeRemoveConfigRequest,
) -> Result<RuntimeRemoveConfigResult, RuntimeRemoveConfigError> {
    let root = ManagedRoot::open(context.runtime_root).map_err(LifecycleError::Io)?;
    let live = route_path(&request.runtime_id, &request.domain);
    let Some(bytes) = read_optional(&root, &live).map_err(LifecycleError::Io)? else {
        return Err(LifecycleError::NotFound);
    };
    if ConfigHash::of(&bytes) != request.expected_hash {
        return Err(LifecycleError::HashGuardMismatch);
    }

    let aside = rollback_sibling(&live, &request.request_id.to_string());
    let renames = [Rename {
        from: live,
        to: aside.clone(),
    }];
    let service = format!("runtime-{}", request.runtime_id);
    transition::transition(&root, &renames, Some(&service), &[aside], context.compose)
        .map_err(LifecycleError::Transition)?;

    Ok(RuntimeRemoveConfigResult {
        runtime_id: request.runtime_id.as_str().to_owned(),
        domain: request.domain.as_str().to_owned(),
        content_sha256: ConfigHash::of(&bytes),
        removed_at_unix_secs: unix_now_secs(),
    })
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;

    use super::{RuntimeRemoveConfigError, execute};
    use crate::{
        error::ErrorCode,
        filesystem::ManagedRoot,
        ingress::{ConfigHash, fake_docker::FakeDocker},
        process::CancellationToken,
        runtime_config::{
            RuntimeRemoveConfigRequest, RuntimeRemoveConfigResult, execute::RuntimeActivateContext,
        },
        site::TrustedRoot,
    };

    const RUNTIME_ID: &str = "fp1-php83";
    const DOMAIN: &str = "example.com";
    const REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const FRAGMENT: &str = "example.com {\n  respond \"hello\"\n}\n";

    struct Host {
        _state_dir: tempfile::TempDir,
        runtime_dir: tempfile::TempDir,
        runtime_root: TrustedRoot,
        engine_state: ManagedRoot,
    }

    fn host(existing: Option<&str>) -> Host {
        let state_dir = tempfile::tempdir().expect("state root should be created");
        let runtime_dir = tempfile::tempdir().expect("runtime root should be created");
        if let Some(contents) = existing {
            let subdir = runtime_dir.path().join(RUNTIME_ID);
            fs::create_dir_all(&subdir).expect("subdirectory should be created");
            fs::write(subdir.join("example.com.caddyfile"), contents)
                .expect("fragment should be written");
        }
        let engine_state = ManagedRoot::open(
            &TrustedRoot::parse(state_dir.path()).expect("state root should be valid"),
        )
        .expect("state root should open");
        let runtime_root =
            TrustedRoot::parse(runtime_dir.path()).expect("runtime root should be valid");
        Host {
            _state_dir: state_dir,
            runtime_dir,
            runtime_root,
            engine_state,
        }
    }

    impl Host {
        fn entries(&self) -> Vec<String> {
            fs::read_dir(self.runtime_dir.path().join(RUNTIME_ID))
                .map(|dir| {
                    dir.map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                        .collect()
                })
                .unwrap_or_default()
        }
    }

    fn request(hash_of: &str) -> RuntimeRemoveConfigRequest {
        RuntimeRemoveConfigRequest::parse(
            RUNTIME_ID,
            DOMAIN,
            ConfigHash::of(hash_of.as_bytes()).as_str(),
            REQUEST_ID,
            None,
        )
        .expect("request should parse")
    }

    fn run(
        host: &Host,
        docker: &FakeDocker,
        request: &RuntimeRemoveConfigRequest,
    ) -> Result<RuntimeRemoveConfigResult, RuntimeRemoveConfigError> {
        let access = docker.access();
        let context = RuntimeActivateContext {
            runtime_root: &host.runtime_root,
            engine_state: &host.engine_state,
            compose: &access,
        };
        execute(&context, request, &CancellationToken::default())
    }

    #[test]
    fn removing_a_fragment_deletes_it_and_reloads_the_pool() {
        let host = host(Some(FRAGMENT));
        let docker = FakeDocker::new();

        let result = run(&host, &docker, &request(FRAGMENT)).expect("removal should succeed");

        assert_eq!(result.content_sha256, ConfigHash::of(FRAGMENT.as_bytes()));
        assert!(host.entries().is_empty(), "{:?}", host.entries());
        let reloads = docker.calls("reload");
        assert_eq!(reloads.len(), 1);
        assert!(reloads[0].contains("runtime-fp1-php83"), "{reloads:?}");
    }

    #[test]
    fn a_stale_hash_removes_nothing() {
        let host = host(Some(FRAGMENT));
        let docker = FakeDocker::new();

        let error = run(&host, &docker, &request("other")).expect_err("stale hash");

        assert_eq!(error.protocol().0, ErrorCode::ConfigHashMismatch);
        assert_eq!(host.entries(), vec!["example.com.caddyfile"]);
        assert!(docker.calls("reload").is_empty());
    }

    #[test]
    fn a_missing_fragment_is_not_found() {
        let host = host(None);
        let docker = FakeDocker::new();

        let error = run(&host, &docker, &request(FRAGMENT)).expect_err("nothing to remove");

        assert_eq!(error.protocol().0, ErrorCode::NotFound);
    }

    #[test]
    fn a_reload_failure_puts_the_fragment_back() {
        let host = host(Some(FRAGMENT));
        let docker = FakeDocker::new().failing("reload", "1");

        let error = run(&host, &docker, &request(FRAGMENT)).expect_err("refused reload");

        assert_eq!(error.protocol().0, ErrorCode::ConfigReloadFailed);
        assert_eq!(host.entries(), vec!["example.com.caddyfile"]);
        assert_eq!(docker.calls("reload").len(), 2);
    }
}
