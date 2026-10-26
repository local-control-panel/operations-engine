//! Production adapter: all mutations reuse typed engine operations.
use crate::{
    error::ErrorCode,
    filesystem::ManagedRoot,
    ingress::{
        self, ActivateConfigRequest, ConfigHash, HashGuard, RouteTarget,
        execute::{ActivateConfigError, ActivateContext},
    },
    process::CancellationToken,
    site::SiteRelativePath,
    site_create::{Backend, Plan},
    site_identity,
    site_migrate_runtime::host::HostBackend,
    site_migrate_runtime::{Backend as _, Identity, StepError},
    site_root, stack_service,
    transaction::{
        RequestId,
        state::{self, TransactionStatus},
    },
};
fn rel(s: &str) -> SiteRelativePath {
    SiteRelativePath::parse(s).unwrap()
}
fn fresh() -> String {
    uuid::Uuid::new_v4().to_string()
}
fn failed(message: &str) -> StepError {
    StepError::new(ErrorCode::Internal, message)
}
fn conflict() -> StepError {
    StepError::new(
        ErrorCode::Conflict,
        "site artifacts already exist or changed; inspect them before retrying",
    )
}
fn map_protocol<T>(r: Result<T, site_root::Error>) -> Result<T, StepError> {
    r.map_err(|e| {
        let (c, m) = e.protocol();
        StepError::new(c, m)
    })
}
fn absent(root: &ManagedRoot, path: &SiteRelativePath) -> Result<(), StepError> {
    match root.symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(conflict()),
        Err(_) => Err(failed("cannot verify site artifacts")),
    }
}
impl Backend for HostBackend<'_> {
    fn check_available(&self, plan: &Plan) -> Result<String, StepError> {
        let (domain, _runtime) = plan.validate()?;
        let [content] = self.config.content_roots.as_slice() else {
            return Err(failed("site creation requires exactly one content root"));
        };
        let content_dir =
            ManagedRoot::open(content).map_err(|_| failed("content root is unavailable"))?;
        absent(&content_dir, &rel(&plan.domain))?;
        let ingress = ManagedRoot::open(&self.config.ingress_root)
            .map_err(|_| failed("ingress root is unavailable"))?;
        for suffix in ["caddyfile", "caddyfile.disabled", "maintenance-backup"] {
            absent(&ingress, &rel(&format!("{domain}.{suffix}")))?;
        }
        let runtimes = ManagedRoot::open(&self.config.runtime_root)
            .map_err(|_| failed("runtime root is unavailable"))?;
        for entry in runtimes
            .child_entries()
            .map_err(|_| failed("runtime inventory is unavailable"))?
        {
            if !entry.is_dir {
                continue;
            }
            let name = entry.name.to_str().ok_or_else(conflict)?;
            let dir = runtimes
                .open_child_dir_nofollow(&rel(name))
                .map_err(|_| conflict())?;
            for suffix in ["identity", "caddyfile"] {
                absent(&dir, &rel(&format!("{domain}.{suffix}")))?;
            }
        }
        let services = ManagedRoot::open(&self.config.site_services_root)
            .map_err(|_| failed("site services root is unavailable"))?;
        for entry in services
            .child_entries()
            .map_err(|_| failed("site service inventory is unavailable"))?
        {
            if !entry.is_dir {
                continue;
            }
            let name = entry.name.to_str().ok_or_else(conflict)?;
            absent(
                &services
                    .open_child_dir_nofollow(&rel(name))
                    .map_err(|_| conflict())?,
                &rel(&plan.domain),
            )?;
        }
        let mut root = content.as_path().join(&plan.domain);
        if let Some(relative) = &plan.relative_root {
            root.push(relative);
        }
        Ok(root.to_string_lossy().into_owned())
    }
    fn allocate_new(&self, plan: &Plan, root: &str, key: &str) -> Result<Identity, StepError> {
        let id = key.split(':').next().ok_or_else(conflict)?;
        let mut req = site_identity::AllocateRequest::parse(
            &plan.runtime_id,
            &plan.domain,
            None,
            root,
            plan.worker_mode,
            plan.worker_count,
            &self.config.content_roots,
            id,
            Some(key),
        )
        .map_err(|_| conflict())?;
        req.require_absent = true;
        let result = match site_identity::allocate(
            &self.identity_context(),
            &req,
            &CancellationToken::default(),
        ) {
            Ok(r) => r,
            Err(site_identity::Error::PostCommit(value)) => serde_json::from_value(value)
                .map_err(|_| failed("identity outcome requires recovery"))?,
            Err(e) => {
                let (c, m) = e.protocol();
                return Err(StepError::new(c, m));
            }
        };
        Ok(Identity {
            os_user: result.os_user,
            uid: result.uid,
            gid: result.gid,
            port: result.port,
            root: result.root,
            worker_mode: result.worker_mode,
            worker_count: result.worker_count,
        })
    }
    fn prepare_new_root(
        &self,
        plan: &Plan,
        identity: &Identity,
        key: &str,
    ) -> Result<(), StepError> {
        let mut req = site_root::PrepareRequest::parse(
            &plan.domain,
            plan.relative_root.as_deref(),
            identity.uid,
            identity.gid,
            None,
            key.split(':').next().ok_or_else(conflict)?,
            Some(key),
        )
        .map_err(|_| conflict())?;
        req.require_absent = true;
        map_protocol(site_root::prepare_root(
            self.engine_state,
            &self.config.content_roots,
            &req,
        ))
        .map(|_| ())
    }
    fn ensure_pool(&self, plan: &Plan) -> Result<(), StepError> {
        let req = stack_service::EnsureRequest::parse(
            &plan.runtime_id,
            plan.profile.as_deref(),
            &fresh(),
            None,
        )
        .map_err(|_| conflict())?;
        match stack_service::ensure_runtime(self.stack, &req, &CancellationToken::default()) {
            Ok(_) | Err(stack_service::Error::PostCommit(_)) => Ok(()),
            Err(e) => {
                let (c, m) = e.protocol();
                Err(StepError::new(c, m))
            }
        }
    }
    fn create_route(&self, plan: &Plan, content: &str) -> Result<(), StepError> {
        let req = ActivateConfigRequest::parse(
            &plan.domain,
            content,
            HashGuard::Absent,
            RouteTarget::Live,
            &fresh(),
            None,
        )
        .map_err(|_| conflict())?;
        let context = ActivateContext {
            ingress_root: &self.config.ingress_root,
            engine_state: self.engine_state,
            compose: self.compose,
        };
        match ingress::execute::execute(&context, &req, &CancellationToken::default()) {
            Ok(_) | Err(ActivateConfigError::PostCommitRecordFailed { .. }) => Ok(()),
            Err(e) => {
                let (c, m) = e.protocol();
                Err(StepError::new(c, m))
            }
        }
    }
    fn remove_created_route(&self, plan: &Plan, expected: &str) -> Result<(), StepError> {
        let root = ManagedRoot::open(&self.config.ingress_root)
            .map_err(|_| failed("ingress root is unavailable"))?;
        // A parked/disabled/modified route is not this attempt's route anymore.
        for suffix in ["maintenance-backup", "caddyfile.disabled"] {
            absent(&root, &rel(&format!("{}.{suffix}", plan.domain)))?;
        }
        let path = rel(&format!("{}.caddyfile", plan.domain));
        match root.read_to_string(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Ok(content) if content == expected => {}
            _ => return Err(conflict()),
        }
        let req = ingress::RemoveRouteRequest::parse(
            &plan.domain,
            ConfigHash::of(expected.as_bytes()).as_str(),
            None,
            &fresh(),
            None,
        )
        .map_err(|_| conflict())?;
        let context = ActivateContext {
            ingress_root: &self.config.ingress_root,
            engine_state: self.engine_state,
            compose: self.compose,
        };
        match ingress::remove::execute(&context, &req, &CancellationToken::default()) {
            Ok(_)
            | Err(ingress::transition::LifecycleError::NotFound)
            | Err(ingress::transition::LifecycleError::PostCommitRecordFailed { .. }) => Ok(()),
            Err(e) => {
                let (c, m) = e.protocol();
                Err(StepError::new(c, m))
            }
        }
    }
    fn remove_empty_root(&self, plan: &Plan, request_id: RequestId) -> Result<(), StepError> {
        let proof = self.creation_identity(plan, request_id)?;
        let mut req = site_root::RemoveRequest::parse(
            &plan.domain,
            plan.relative_root.as_deref(),
            None,
            false,
            &fresh(),
            None,
        )
        .map_err(|_| conflict())?;
        req.expected_owner = Some((proof.uid, proof.gid));
        map_protocol(site_root::remove_root(
            self.engine_state,
            &self.config.content_roots,
            std::path::Path::new("/etc/operations-engine/sites"),
            0,
            &req,
        ))
        .map(|_| ())
    }

    fn remove_created_exec(&self, plan: &Plan, request_id: RequestId) -> Result<(), StepError> {
        let proof = self.creation_identity(plan, request_id)?;
        let (domain, _runtime) = plan.validate()?;
        let expected =
            crate::site_migrate_runtime::pool_reverse_proxy_caddyfile(&domain, proof.port);
        let req = crate::runtime_config::RuntimeRemoveConfigRequest::parse(
            &plan.runtime_id,
            &plan.domain,
            ConfigHash::of(expected.as_bytes()).as_str(),
            &fresh(),
            None,
        )
        .map_err(|_| conflict())?;
        let context = crate::runtime_config::execute::RuntimeActivateContext {
            runtime_root: &self.config.runtime_root,
            engine_state: self.engine_state,
            compose: self.compose,
        };
        match crate::runtime_config::remove::execute(&context, &req, &CancellationToken::default())
        {
            Ok(_)
            | Err(ingress::transition::LifecycleError::NotFound)
            | Err(ingress::transition::LifecycleError::PostCommitRecordFailed { .. }) => Ok(()),
            Err(e) => {
                let (c, m) = e.protocol();
                Err(StepError::new(c, m))
            }
        }
    }
    fn remove_created_service(&self, plan: &Plan, request_id: RequestId) -> Result<(), StepError> {
        let proof = self.creation_identity(plan, request_id)?;
        let (domain, runtime) = plan.validate()?;
        let base = format!("{runtime}/{domain}");
        let cdir = format!("/etc/wcp/site-services/{domain}");
        let mut req = stack_service::RemoveSiteServiceRequest::parse(
            &plan.runtime_id,
            &plan.domain,
            &fresh(),
            None,
        )
        .map_err(|_| conflict())?;
        req.expected_files = Some(vec![
            (
                rel(&format!("{base}/run")),
                stack_service::site_run_script(proof.uid, proof.gid, &cdir),
            ),
            (
                rel(&format!("{base}/Caddyfile")),
                stack_service::site_process_caddyfile(
                    &domain,
                    &runtime,
                    proof.port,
                    &proof.root,
                    proof.worker_mode,
                    proof.worker_count,
                ),
            ),
            (
                rel(&format!("{base}/open-basedir.ini")),
                stack_service::site_open_basedir_ini(&proof.root),
            ),
        ]);
        match stack_service::remove_site_service(self.stack, &req, &CancellationToken::default()) {
            Ok(_) | Err(stack_service::Error::PostCommit(_)) => Ok(()),
            Err(e) => {
                let (c, m) = e.protocol();
                Err(StepError::new(c, m))
            }
        }
    }
    fn release_created_identity(
        &self,
        plan: &Plan,
        request_id: RequestId,
    ) -> Result<(), StepError> {
        let (domain, runtime) = plan.validate()?;
        // Ownership is proved by the nested allocation transaction, not merely
        // by the current existence of an identity with this domain name.
        let scope = self
            .engine_state
            .open_managed_dir(&rel("site-identity"))
            .map_err(|_| failed("identity allocation evidence is unavailable"))?;
        let nested = match state::load(&scope, &rel(&format!("transactions/{request_id}.json"))) {
            Err(state::StateError::NotFound) => {
                if self.read_identity(&runtime, &domain)?.is_none() {
                    return Ok(());
                }
                return Err(conflict());
            }
            Ok(record) => record,
            Err(_) => return Err(failed("identity allocation evidence is unreadable")),
        };
        if nested.status == TransactionStatus::Failed {
            if self.read_identity(&runtime, &domain)?.is_none() {
                return Ok(());
            }
            return Err(conflict());
        }
        if nested.status != TransactionStatus::Committed {
            return Err(failed(
                "interrupted identity allocation requires inspection",
            ));
        }
        if let Some(current) = self.read_identity(&runtime, &domain)? {
            let result = nested.outcome.and_then(|o| o.result).ok_or_else(conflict)?;
            if result["uid"].as_u64() != Some(u64::from(current.uid))
                || result["gid"].as_u64() != Some(u64::from(current.gid))
                || result["port"].as_u64() != Some(u64::from(current.port))
                || result["osUser"].as_str() != Some(current.os_user.as_str())
            {
                return Err(conflict());
            }
        } else {
            return Ok(());
        }
        let req = site_identity::ReleaseRequest::parse(
            &plan.runtime_id,
            &plan.domain,
            true,
            &fresh(),
            None,
        )
        .map_err(|_| conflict())?;
        match site_identity::release(
            &self.identity_context(),
            &req,
            &CancellationToken::default(),
        ) {
            Ok(_) | Err(site_identity::Error::PostCommit(_)) => Ok(()),
            Err(e) => {
                let (c, m) = e.protocol();
                Err(StepError::new(c, m))
            }
        }
    }
}

impl HostBackend<'_> {
    fn creation_identity(
        &self,
        plan: &Plan,
        id: RequestId,
    ) -> Result<site_identity::IdentityResult, StepError> {
        let scope = self
            .engine_state
            .open_managed_dir(&rel("site-identity"))
            .map_err(|_| conflict())?;
        let record = state::load(&scope, &rel(&format!("transactions/{id}.json")))
            .map_err(|_| conflict())?;
        if record.request_id != id
            || record.operation != site_identity::ALLOCATE_OPERATION
            || record.status != TransactionStatus::Committed
        {
            return Err(conflict());
        }
        let proof: site_identity::IdentityResult =
            serde_json::from_value(record.outcome.and_then(|o| o.result).ok_or_else(conflict)?)
                .map_err(|_| conflict())?;
        if proof.domain != plan.domain || proof.runtime_id != plan.runtime_id || !proof.user_created
        {
            return Err(conflict());
        }
        let (domain, runtime) = plan.validate()?;
        if let Some(current) = self.read_identity(&runtime, &domain)? {
            if current.uid != proof.uid
                || current.gid != proof.gid
                || current.port != proof.port
                || current.os_user != proof.os_user
                || current.root != proof.root
                || current.worker_mode != proof.worker_mode
                || current.worker_count != proof.worker_count
            {
                return Err(conflict());
            }
        }
        Ok(proof)
    }
}
