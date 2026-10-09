//! The `ingress.applyBans` operation: the brute-force guard's ban list as one
//! file the ingress server imports into every route.
//!
//! Every route file carries `import /etc/wcp/ingress.d/bans/*.caddy` in its
//! site block. The guard no longer splices `remote_ip` blocks into each route
//! from a root cron job; it hands the full list of banned addresses to this
//! operation, which writes `bans/bans.caddy` under the same stack lock,
//! validate, swap, reload and restore path every other route change takes. A
//! glob import that matches nothing is valid Caddy, so a host without the file
//! (no bans, or the operation never ran) serves every route normally.
//!
//! The file is validated the way `ingress.activateConfig` validates a route:
//! the staged copy is imported by a throw-away site block next to the routes,
//! so `caddy validate` parses the real directives in a real site context. The
//! live file is replaced by renames, with the previous list kept as
//! `bans.caddy.rollback-<request id>` until the reload accepted the new one.
//! Neither the staged nor the rollback file matches the `*.caddy` import glob.
//! A crash between the two renames leaves no live list (fail-open until the
//! next apply); `ingress.reconcile` sweeps `bans/` and puts the rollback copy
//! back, so the previous list is enforced again.

use std::{net::IpAddr, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::{
    filesystem::ManagedRoot,
    ingress::{
        ConfigHash, INGRESS_SERVICE, activate,
        execute::ActivateContext,
        transition::{
            self, LifecycleError, Rename, read_optional, rollback_sibling, unix_now_secs,
        },
    },
    process::CancellationToken,
    site::SiteRelativePath,
    transaction::{IdempotencyKey, RequestId},
};

/// The stable protocol operation name.
pub const APPLY_BANS_OPERATION: &str = "ingress.applyBans";

/// Directory under `ingress_root` holding the ban file, and the glob every
/// route imports from it.
pub const BANS_DIR: &str = "bans";
pub const BANS_FILE: &str = "bans/bans.caddy";
/// The import line a route carries; the container sees the same path.
pub const BANS_IMPORT: &str = "import /etc/wcp/ingress.d/bans/*.caddy";

/// More addresses than a real guard bans; keeps the file and the request
/// bounded.
pub const MAX_BANS: usize = 10_000;

#[derive(Debug, Eq, PartialEq)]
pub struct ApplyBansRequest {
    /// Sorted, de-duplicated, canonical addresses.
    pub bans: Vec<IpAddr>,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyBansRequestError {
    InvalidJson,
    InvalidIp,
    TooManyBans,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    bans: Vec<String>,
}

impl ApplyBansRequest {
    pub fn parse(
        json: &str,
        request_id: &str,
        idempotency_key: Option<&str>,
    ) -> Result<Self, ApplyBansRequestError> {
        let plan: Plan =
            serde_json::from_str(json).map_err(|_| ApplyBansRequestError::InvalidJson)?;
        if plan.bans.len() > MAX_BANS {
            return Err(ApplyBansRequestError::TooManyBans);
        }
        let mut bans = plan
            .bans
            .iter()
            .map(|raw| IpAddr::from_str(raw).map_err(|_| ApplyBansRequestError::InvalidIp))
            .collect::<Result<Vec<_>, _>>()?;
        bans.sort();
        bans.dedup();
        Ok(Self {
            bans,
            request_id: RequestId::parse(request_id)
                .map_err(|_| ApplyBansRequestError::InvalidRequestId)?,
            idempotency_key: idempotency_key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| ApplyBansRequestError::InvalidIdempotencyKey)?,
        })
    }

    /// The exact bytes of `bans/bans.caddy`.
    pub fn content(&self) -> String {
        let mut content =
            String::from("# Managed by ingress.applyBans (brute-force guard). Do not edit.\n");
        if !self.bans.is_empty() {
            let ips: Vec<String> = self.bans.iter().map(ToString::to_string).collect();
            content.push_str(&format!("@bf_banned remote_ip {}\n", ips.join(" ")));
            content.push_str("respond @bf_banned 403\n");
        }
        content
    }
}

/// The `result` payload of a successful `ingress.applyBans` response.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyBansResult {
    pub ban_count: usize,
    /// `false` when the file already held this list (the ingress was still
    /// reloaded to confirm it).
    pub changed: bool,
    pub content_sha256: ConfigHash,
    pub applied_at_unix_secs: u64,
}

pub type ApplyBansError = LifecycleError<ApplyBansResult>;

pub fn execute(
    context: &ActivateContext<'_>,
    request: &ApplyBansRequest,
    cancellation: &CancellationToken,
) -> Result<ApplyBansResult, ApplyBansError> {
    let op_state = crate::ingress::execute::open_ingress_state(context.engine_state)
        .map_err(LifecycleError::Io)?;
    transition::run(
        context.engine_state,
        &op_state,
        APPLY_BANS_OPERATION,
        request.request_id,
        request.idempotency_key.as_ref(),
        cancellation,
        || apply(context, request),
    )
}

fn path(name: &str) -> SiteRelativePath {
    SiteRelativePath::parse(name).expect("literal path is valid")
}

fn apply(
    context: &ActivateContext<'_>,
    request: &ApplyBansRequest,
) -> Result<ApplyBansResult, ApplyBansError> {
    let root = ManagedRoot::open(context.ingress_root).map_err(LifecycleError::Io)?;
    root.create_dir_all(&path(BANS_DIR))
        .map_err(LifecycleError::Io)?;
    let live = path(BANS_FILE);
    let content = request.content();
    let result = |changed: bool| ApplyBansResult {
        ban_count: request.bans.len(),
        changed,
        content_sha256: ConfigHash::of(content.as_bytes()),
        applied_at_unix_secs: unix_now_secs(),
    };

    let current = read_optional(&root, &live).map_err(LifecycleError::Io)?;
    if current.as_deref() == Some(content.as_bytes()) {
        // Converge, do not assume: the file being right does not prove the
        // running server loaded it.
        transition::reload(context.compose, INGRESS_SERVICE).map_err(|failure| {
            LifecycleError::Transition(activate::Error::ReloadFailedUnchanged(failure))
        })?;
        return Ok(result(false));
    }

    let id = request.request_id.to_string();
    let staged = path(&format!("{BANS_FILE}.tmp"));
    let wrapper = path(&format!(".bans-validate-{id}.tmp"));
    let wrapper_text = |staged_path: &str| {
        format!("http://bans-validate.invalid {{\n    import {staged_path}\n    respond 200\n}}\n")
    };

    root.write_atomic(&staged, content.as_bytes())
        .map_err(LifecycleError::Io)?;
    let discard = |root: &ManagedRoot| {
        let _ = root.remove_file(&staged);
        let _ = root.remove_file(&wrapper);
    };
    let staged_abs = match context.ingress_root.resolve_existing(&staged) {
        Ok(p) => p,
        Err(error) => {
            discard(&root);
            return Err(LifecycleError::Transition(activate::Error::Path(error)));
        }
    };
    let Some(staged_abs) = staged_abs.to_str() else {
        discard(&root);
        return Err(LifecycleError::Transition(activate::Error::Path(
            crate::site::ValidationError::PathResolutionFailed,
        )));
    };
    if let Err(error) = root.write_atomic(&wrapper, wrapper_text(staged_abs).as_bytes()) {
        discard(&root);
        return Err(LifecycleError::Io(error));
    }
    let wrapper_abs = match context.ingress_root.resolve_existing(&wrapper) {
        Ok(p) => p,
        Err(error) => {
            discard(&root);
            return Err(LifecycleError::Transition(activate::Error::Path(error)));
        }
    };
    let Some(wrapper_abs) = wrapper_abs.to_str() else {
        discard(&root);
        return Err(LifecycleError::Transition(activate::Error::Path(
            crate::site::ValidationError::PathResolutionFailed,
        )));
    };
    let validated = activate::validate(context.compose, wrapper_abs);
    let _ = root.remove_file(&wrapper);
    if let Err(failure) = validated {
        discard(&root);
        return Err(LifecycleError::Transition(activate::Error::ValidateFailed(
            failure,
        )));
    }

    let rollback = rollback_sibling(&live, &id);
    let mut renames = Vec::new();
    let mut cleanup = Vec::new();
    if current.is_some() {
        renames.push(Rename {
            from: live.clone(),
            to: rollback.clone(),
        });
        cleanup.push(rollback);
    }
    renames.push(Rename {
        from: staged.clone(),
        to: live,
    });
    let outcome = transition::transition(
        &root,
        &renames,
        Some(INGRESS_SERVICE),
        &cleanup,
        context.compose,
    );
    discard(&root);
    outcome.map_err(LifecycleError::Transition)?;
    Ok(result(true))
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;

    use super::{
        ApplyBansError, ApplyBansRequest, ApplyBansRequestError, ApplyBansResult, execute,
    };
    use crate::{
        error::ErrorCode,
        filesystem::ManagedRoot,
        ingress::{execute::ActivateContext, fake_docker::FakeDocker},
        process::CancellationToken,
        site::TrustedRoot,
    };

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const RETRY_ID: &str = "9b2f1c34-5678-4abc-9def-0123456789ab";

    struct Host {
        state_dir: tempfile::TempDir,
        ingress_dir: tempfile::TempDir,
        ingress_root: TrustedRoot,
        engine_state: ManagedRoot,
    }

    fn host(bans_file: Option<&str>) -> Host {
        let state_dir = tempfile::tempdir().unwrap();
        let ingress_dir = tempfile::tempdir().unwrap();
        if let Some(text) = bans_file {
            fs::create_dir(ingress_dir.path().join("bans")).unwrap();
            fs::write(ingress_dir.path().join("bans/bans.caddy"), text).unwrap();
        }
        Host {
            engine_state: ManagedRoot::open(&TrustedRoot::parse(state_dir.path()).unwrap())
                .unwrap(),
            ingress_root: TrustedRoot::parse(ingress_dir.path()).unwrap(),
            state_dir,
            ingress_dir,
        }
    }

    impl Host {
        fn bans(&self) -> Option<String> {
            fs::read_to_string(self.ingress_dir.path().join("bans/bans.caddy")).ok()
        }

        fn leftovers(&self) -> Vec<String> {
            let mut names: Vec<String> = fs::read_dir(self.ingress_dir.path().join("bans"))
                .map(|dir| {
                    dir.map(|e| e.unwrap().file_name().into_string().unwrap())
                        .collect()
                })
                .unwrap_or_default();
            names.extend(
                fs::read_dir(self.ingress_dir.path())
                    .unwrap()
                    .map(|e| e.unwrap().file_name().into_string().unwrap())
                    .filter(|name| name.starts_with('.')),
            );
            names.retain(|name| name != "bans.caddy" && name != "bans");
            names
        }

        fn status(&self, id: &str) -> String {
            let path = self
                .state_dir
                .path()
                .join(format!("ingress/transactions/{id}.json"));
            let record: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
            record["status"].as_str().unwrap_or_default().to_owned()
        }
    }

    fn request(ips: &[&str], id: &str, key: Option<&str>) -> ApplyBansRequest {
        let json = serde_json::json!({ "bans": ips }).to_string();
        ApplyBansRequest::parse(&json, id, key).unwrap()
    }

    fn run(
        host: &Host,
        docker: &FakeDocker,
        request: &ApplyBansRequest,
    ) -> Result<ApplyBansResult, ApplyBansError> {
        let access = docker.access();
        let context = ActivateContext {
            ingress_root: &host.ingress_root,
            engine_state: &host.engine_state,
            compose: &access,
        };
        execute(&context, request, &CancellationToken::default())
    }

    #[test]
    fn the_request_is_sorted_deduplicated_and_canonical() {
        let req = request(
            &["10.0.0.2", "10.0.0.1", "10.0.0.2", "2001:0db8::1"],
            ID,
            None,
        );
        assert_eq!(
            req.content(),
            "# Managed by ingress.applyBans (brute-force guard). Do not edit.\n\
             @bf_banned remote_ip 10.0.0.1 10.0.0.2 2001:db8::1\n\
             respond @bf_banned 403\n"
        );
        assert!(!request(&[], ID, None).content().contains("remote_ip"));
    }

    #[test]
    fn requests_that_could_inject_caddy_are_refused() {
        for bad in [
            "1.2.3.4 respond 200",
            "1.2.3.4\nrespond 200",
            "{",
            "",
            "1.2.3",
            "a.b",
        ] {
            let json = serde_json::json!({ "bans": [bad] }).to_string();
            assert_eq!(
                ApplyBansRequest::parse(&json, ID, None).unwrap_err(),
                ApplyBansRequestError::InvalidIp,
                "{bad:?}"
            );
        }
        assert_eq!(
            ApplyBansRequest::parse("{\"bans\":[],\"extra\":1}", ID, None).unwrap_err(),
            ApplyBansRequestError::InvalidJson
        );
        assert_eq!(
            ApplyBansRequest::parse("{\"bans\":[]}", "nope", None).unwrap_err(),
            ApplyBansRequestError::InvalidRequestId
        );
    }

    #[test]
    fn a_first_apply_creates_the_file_after_validating_it() {
        let host = host(None);
        let docker = FakeDocker::new();
        let result = run(&host, &docker, &request(&["203.0.113.7"], ID, None)).unwrap();
        assert!(result.changed && result.ban_count == 1);
        assert!(host.bans().unwrap().contains("remote_ip 203.0.113.7"));
        assert_eq!(docker.calls("validate").len(), 1);
        assert_eq!(docker.calls("reload").len(), 1);
        assert_eq!(host.leftovers(), Vec::<String>::new());
        assert_eq!(host.status(ID), "COMMITTED");
    }

    #[test]
    fn the_validated_wrapper_imports_the_staged_file() {
        let host = host(None);
        let docker = FakeDocker::new();
        run(&host, &docker, &request(&["203.0.113.7"], ID, None)).unwrap();
        let call = &docker.calls("validate")[0];
        assert!(call.contains(".bans-validate-"), "{call}");
    }

    #[test]
    fn a_replacement_keeps_nothing_behind() {
        let host = host(Some("old\n"));
        let docker = FakeDocker::new();
        run(&host, &docker, &request(&["203.0.113.7"], ID, None)).unwrap();
        assert!(host.bans().unwrap().contains("203.0.113.7"));
        assert_eq!(host.leftovers(), Vec::<String>::new());
    }

    #[test]
    fn an_unchanged_list_reloads_to_confirm_and_reports_no_change() {
        let host = host(None);
        let docker = FakeDocker::new();
        run(&host, &docker, &request(&["203.0.113.7"], ID, None)).unwrap();
        let again = run(&host, &docker, &request(&["203.0.113.7"], RETRY_ID, None)).unwrap();
        assert!(!again.changed);
        assert_eq!(docker.calls("validate").len(), 1, "nothing new to validate");
        assert_eq!(docker.calls("reload").len(), 2);
    }

    #[test]
    fn a_rejected_validation_changes_nothing() {
        let host = host(Some("old\n"));
        let docker = FakeDocker::new().failing("validate", "all");
        let error = run(&host, &docker, &request(&["203.0.113.7"], ID, None)).unwrap_err();
        assert_eq!(error.protocol().0, ErrorCode::ConfigValidationFailed);
        assert_eq!(host.bans().as_deref(), Some("old\n"));
        assert!(docker.calls("reload").is_empty());
        assert_eq!(host.leftovers(), Vec::<String>::new());
        assert_eq!(host.status(ID), "FAILED");
    }

    #[test]
    fn a_refused_reload_puts_the_previous_list_back_and_reloads_again() {
        let host = host(Some("old\n"));
        let docker = FakeDocker::new().failing("reload", "1");
        let error = run(&host, &docker, &request(&["203.0.113.7"], ID, None)).unwrap_err();
        assert_eq!(error.protocol().0, ErrorCode::ConfigReloadFailed);
        assert_eq!(host.bans().as_deref(), Some("old\n"));
        assert_eq!(docker.calls("reload").len(), 2);
        assert_eq!(host.leftovers(), Vec::<String>::new());
    }

    #[test]
    fn a_refused_first_reload_removes_the_new_file() {
        let host = host(None);
        let docker = FakeDocker::new().failing("reload", "1");
        let error = run(&host, &docker, &request(&["203.0.113.7"], ID, None)).unwrap_err();
        assert_eq!(error.protocol().0, ErrorCode::ConfigReloadFailed);
        assert!(host.bans().is_none());
        assert_eq!(host.leftovers(), Vec::<String>::new());
    }

    #[test]
    fn a_failed_restore_reload_reports_recovery_failure() {
        let host = host(Some("old\n"));
        let docker = FakeDocker::new().failing("reload", "all");
        let error = run(&host, &docker, &request(&["203.0.113.7"], ID, None)).unwrap_err();
        assert_eq!(error.protocol().0, ErrorCode::ConfigRecoveryFailed);
        assert_eq!(host.bans().as_deref(), Some("old\n"));
    }

    #[test]
    fn a_retry_with_the_same_idempotency_key_replays() {
        let host = host(None);
        let docker = FakeDocker::new();
        let first = run(
            &host,
            &docker,
            &request(&["203.0.113.7"], ID, Some("bans-1")),
        )
        .unwrap();
        let replay = run(
            &host,
            &docker,
            &request(&["203.0.113.7"], RETRY_ID, Some("bans-1")),
        )
        .unwrap();
        assert_eq!(replay.applied_at_unix_secs, first.applied_at_unix_secs);
        assert_eq!(docker.calls("reload").len(), 1);
    }
}
