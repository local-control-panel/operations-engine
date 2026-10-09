//! The real [`Backend`]: each step calls the engine operation it is named
//! after, with a fresh request id, exactly as its own CLI command would.

use std::{path::Path, time::Duration};

use crate::{
    compose,
    config::EngineConfig,
    error::ErrorCode,
    filesystem::ManagedRoot,
    ingress::{
        ActivateConfigRequest, ConfigHash, HashGuard, RouteTarget,
        execute::{ActivateConfigError, ActivateContext, execute as execute_route},
    },
    process::CancellationToken,
    runtime_config::{
        RuntimeActivateConfigRequest, RuntimeRemoveConfigRequest,
        execute::{RuntimeActivateConfigError, RuntimeActivateContext, execute as execute_exec},
        remove::execute as execute_remove_exec,
    },
    site::{Domain, RuntimeId, SiteRelativePath},
    site_identity::{self, AllocateRequest, ReleaseRequest, UserTools},
    site_probe::{ProbeRequest, probe_site},
    stack_service::{self, RemoveSiteServiceRequest, Stage, StopRequest, WriteSiteServiceRequest},
    transaction::RequestId,
};

use super::{
    Backend, HealthCheck, Identity, PROBE_ATTEMPTS, PROBE_PAUSE, Route, RouteKind, StepError,
    check_health,
};

const LEGACY_UID_COUNTER: &str = "/etc/wcp/site-uid-counter";
const REMOVE_SERVICE_ATTEMPTS: u32 = 3;
const REMOVE_SERVICE_BACKOFF: Duration = Duration::from_millis(1500);
const HEALTH_TIMEOUT: Duration = Duration::from_secs(15);

pub struct HostBackend<'a> {
    pub config: &'a EngineConfig,
    pub engine_state: &'a ManagedRoot,
    pub stack: &'a stack_service::Context<'a>,
    pub compose: &'a compose::Access,
    pub passwd_file: &'a Path,
    pub group_file: &'a Path,
    pub legacy_uid_counter: Option<&'a Path>,
    pub tools: UserTools<'a>,
    /// Pause between probe attempts and service removals; zero in tests.
    pub pause: bool,
}

fn fresh_id() -> RequestId {
    RequestId::parse(&uuid::Uuid::new_v4().to_string()).expect("a v4 UUID is canonical")
}

fn invalid(message: &str) -> StepError {
    StepError::new(ErrorCode::InvalidInput, message)
}

fn io_error(what: &str, error: &std::io::Error) -> StepError {
    StepError::new(ErrorCode::Internal, format!("{what}: {error}"))
}

fn relative(path: &str) -> Result<SiteRelativePath, StepError> {
    SiteRelativePath::parse(path).map_err(|_| invalid("unsafe path"))
}

impl HostBackend<'_> {
    fn identity_context(&self) -> site_identity::Context<'_> {
        site_identity::Context {
            engine_state: self.engine_state,
            runtime_root: &self.config.runtime_root,
            site_services_root: &self.config.site_services_root,
            passwd_file: self.passwd_file,
            group_file: self.group_file,
            legacy_uid_counter: self.legacy_uid_counter,
            tools: UserTools {
                groupadd: self.tools.groupadd,
                useradd: self.tools.useradd,
                userdel: self.tools.userdel,
                groupdel: self.tools.groupdel,
            },
        }
    }

    fn runtime_context(&self) -> RuntimeActivateContext<'_> {
        RuntimeActivateContext {
            runtime_root: &self.config.runtime_root,
            engine_state: self.engine_state,
            compose: self.compose,
        }
    }

    fn read_optional(
        root: &ManagedRoot,
        path: &SiteRelativePath,
    ) -> Result<Option<String>, StepError> {
        match root.read_to_string(path) {
            Ok(text) => Ok(Some(text)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(io_error("read", &error)),
        }
    }

    fn health_probe(
        &self,
        service: &str,
        domain: &Domain,
        check: &HealthCheck,
    ) -> Result<(), StepError> {
        let marker = format!("__WCP_HEALTH_STATUS_{}__", uuid::Uuid::new_v4().simple());
        let tail = super::health_curl_args(service, domain, check, &marker);
        let args: Vec<&str> = tail.iter().map(String::as_str).collect();
        let output = stack_service::compose(
            self.stack,
            Stage::ApplicationProbe,
            &args,
            HEALTH_TIMEOUT,
            &CancellationToken::default(),
        )
        .map_err(|error| {
            let (code, message) = error.protocol();
            StepError::new(code, message)
        })?;
        check_health(&output, &marker, check)
            .map_err(|message| StepError::new(ErrorCode::SubprocessFailed, message))
    }

    fn probe_once(
        &self,
        service: &str,
        domain: &Domain,
        root: &str,
        health: Option<&HealthCheck>,
    ) -> Result<(), StepError> {
        if let Some(check) = health {
            return self.health_probe(service, domain, check);
        }
        let request = ProbeRequest::parse(
            "applicationToken",
            service,
            domain.as_str(),
            root,
            &self.config.content_roots,
            &fresh_id().to_string(),
            None,
        )
        .map_err(|error| invalid(error.message()))?;
        match probe_site(self.stack, &request, &CancellationToken::default()) {
            Ok(_) | Err(stack_service::Error::PostCommit(_)) => Ok(()),
            Err(error) => {
                let (code, message) = error.protocol();
                Err(StepError::new(code, message))
            }
        }
    }
}

fn stack_step<T>(result: Result<T, stack_service::Error>) -> Result<(), StepError> {
    match result {
        Ok(_) | Err(stack_service::Error::PostCommit(_)) => Ok(()),
        Err(error) => {
            let (code, message) = error.protocol();
            Err(StepError::new(code, message))
        }
    }
}

impl Backend for HostBackend<'_> {
    fn read_route(&self, domain: &Domain) -> Result<Route, StepError> {
        let root = ManagedRoot::open(&self.config.ingress_root)
            .map_err(|error| io_error("ingress root", &error))?;
        for (name, kind) in [
            (format!("{domain}.maintenance-backup"), RouteKind::Backup),
            (format!("{domain}.caddyfile"), RouteKind::Live),
        ] {
            if let Some(content) = Self::read_optional(&root, &relative(&name)?)? {
                return Ok(Route { kind, content });
            }
        }
        if root.exists(&relative(&format!("{domain}.caddyfile.disabled"))?) {
            return Err(invalid(
                "the site is disabled: enable it before moving it to another runtime",
            ));
        }
        Err(StepError::new(
            ErrorCode::NotFound,
            format!("{domain} has no ingress route to migrate"),
        ))
    }

    fn read_identity(
        &self,
        runtime: &RuntimeId,
        domain: &Domain,
    ) -> Result<Option<Identity>, StepError> {
        let root = ManagedRoot::open(&self.config.runtime_root)
            .map_err(|error| io_error("runtime root", &error))?;
        match site_identity::read_record(&root, runtime, domain) {
            Ok(record) => Ok(record.map(|r| Identity {
                os_user: r.os_user,
                uid: r.uid,
                gid: r.gid,
                port: r.port,
                root: r.settings.root,
                worker_mode: r.settings.worker_mode,
                worker_count: r.settings.worker_count,
            })),
            Err(error) => {
                let (code, message) = error.protocol();
                Err(StepError::new(code, message))
            }
        }
    }

    fn allocate_identity(
        &self,
        runtime: &RuntimeId,
        domain: &Domain,
        from: &Identity,
    ) -> Result<Identity, StepError> {
        let request = AllocateRequest::parse(
            runtime.as_str(),
            domain.as_str(),
            Some(&from.os_user),
            &from.root,
            from.worker_mode,
            from.worker_count,
            &self.config.content_roots,
            &fresh_id().to_string(),
            None,
        )
        .map_err(|error| invalid(error.message()))?;
        let result = match site_identity::allocate(
            &self.identity_context(),
            &request,
            &CancellationToken::default(),
        ) {
            Ok(result) => result,
            Err(site_identity::Error::PostCommit(value)) => {
                serde_json::from_value(value).map_err(|_| {
                    StepError::new(ErrorCode::Internal, "the identity result is unreadable")
                })?
            }
            Err(error) => {
                let (code, message) = error.protocol();
                return Err(StepError::new(code, message));
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

    fn write_service(
        &self,
        runtime: &RuntimeId,
        domain: &Domain,
        identity: &Identity,
    ) -> Result<(), StepError> {
        let request = WriteSiteServiceRequest::parse(
            runtime.as_str(),
            domain.as_str(),
            identity.uid,
            identity.gid,
            identity.port,
            identity.root.clone(),
            identity.worker_mode,
            identity.worker_count,
            &self.config.content_roots,
            &fresh_id().to_string(),
            None,
        )
        .map_err(|error| invalid(error.message()))?;
        stack_step(stack_service::write_site_service(
            self.stack,
            &request,
            &CancellationToken::default(),
        ))
    }

    fn activate_exec_config(
        &self,
        runtime: &RuntimeId,
        domain: &Domain,
        content: &str,
    ) -> Result<(), StepError> {
        let request = RuntimeActivateConfigRequest::parse(
            runtime.as_str(),
            domain.as_str(),
            content,
            HashGuard::Absent,
            &fresh_id().to_string(),
            None,
        )
        .map_err(|_| invalid("the runtime config is not valid"))?;
        match execute_exec(
            &self.runtime_context(),
            &request,
            &CancellationToken::default(),
        ) {
            Ok(_) | Err(RuntimeActivateConfigError::PostCommitRecordFailed { .. }) => Ok(()),
            Err(error) => {
                let (code, message) = error.protocol();
                Err(StepError::new(code, message))
            }
        }
    }

    fn probe(
        &self,
        service: &str,
        domain: &Domain,
        root: &str,
        health: Option<&HealthCheck>,
    ) -> Result<(), StepError> {
        let mut last = None;
        for attempt in 0..PROBE_ATTEMPTS {
            if attempt > 0 && self.pause {
                std::thread::sleep(PROBE_PAUSE);
            }
            match self.probe_once(service, domain, root, health) {
                Ok(()) => return Ok(()),
                Err(error) => last = Some(error),
            }
        }
        Err(last.expect("at least one attempt ran"))
    }

    fn activate_route(
        &self,
        domain: &Domain,
        kind: RouteKind,
        content: &str,
        expected: &ConfigHash,
    ) -> Result<(), StepError> {
        let request = ActivateConfigRequest::parse(
            domain.as_str(),
            content,
            HashGuard::Sha256(expected.clone()),
            match kind {
                RouteKind::Live => RouteTarget::Live,
                RouteKind::Backup => RouteTarget::Backup,
            },
            &fresh_id().to_string(),
            None,
        )
        .map_err(|_| invalid("the route is not valid"))?;
        let context = ActivateContext {
            ingress_root: &self.config.ingress_root,
            engine_state: self.engine_state,
            compose: self.compose,
        };
        match execute_route(&context, &request, &CancellationToken::default()) {
            Ok(_) | Err(ActivateConfigError::PostCommitRecordFailed { .. }) => Ok(()),
            Err(error) => {
                let (code, message) = error.protocol();
                Err(StepError::new(code, message))
            }
        }
    }

    fn remove_exec_config(&self, runtime: &RuntimeId, domain: &Domain) -> Result<(), StepError> {
        let root = ManagedRoot::open(&self.config.runtime_root)
            .map_err(|error| io_error("runtime root", &error))?;
        let path = relative(&format!("{runtime}/{domain}.caddyfile"))?;
        let Some(content) = Self::read_optional(&root, &path)? else {
            return Ok(());
        };
        let request = RuntimeRemoveConfigRequest::parse(
            runtime.as_str(),
            domain.as_str(),
            ConfigHash::of(content.as_bytes()).as_str(),
            &fresh_id().to_string(),
            None,
        )
        .map_err(|_| invalid("the runtime config cannot be removed"))?;
        match execute_remove_exec(
            &self.runtime_context(),
            &request,
            &CancellationToken::default(),
        ) {
            Ok(_)
            | Err(crate::ingress::transition::LifecycleError::PostCommitRecordFailed { .. })
            | Err(crate::ingress::transition::LifecycleError::NotFound) => Ok(()),
            Err(error) => {
                let (code, message) = error.protocol();
                Err(StepError::new(code, message))
            }
        }
    }

    fn remove_service(&self, runtime: &RuntimeId, domain: &Domain) -> Result<(), StepError> {
        let mut attempt = 1;
        loop {
            let request = RemoveSiteServiceRequest::parse(
                runtime.as_str(),
                domain.as_str(),
                &fresh_id().to_string(),
                None,
            )
            .map_err(|error| invalid(error.message()))?;
            // The service was started moments ago and may still be settling
            // under the supervisor: one transient refusal must not orphan it.
            match stack_step(stack_service::remove_site_service(
                self.stack,
                &request,
                &CancellationToken::default(),
            )) {
                Ok(()) => return Ok(()),
                Err(error) if attempt >= REMOVE_SERVICE_ATTEMPTS => return Err(error),
                Err(_) => {
                    if self.pause {
                        std::thread::sleep(REMOVE_SERVICE_BACKOFF * attempt);
                    }
                    attempt += 1;
                }
            }
        }
    }

    fn release_identity(&self, runtime: &RuntimeId, domain: &Domain) -> Result<(), StepError> {
        let request = ReleaseRequest::parse(
            runtime.as_str(),
            domain.as_str(),
            false,
            &fresh_id().to_string(),
            None,
        )
        .map_err(|error| invalid(error.message()))?;
        match site_identity::release(
            &self.identity_context(),
            &request,
            &CancellationToken::default(),
        ) {
            Ok(_) | Err(site_identity::Error::PostCommit(_)) => Ok(()),
            Err(error) => {
                let (code, message) = error.protocol();
                Err(StepError::new(code, message))
            }
        }
    }

    fn stop_idle_pool(&self, runtime: &RuntimeId) -> Result<(), StepError> {
        let request = StopRequest::parse(runtime.as_str(), &fresh_id().to_string(), None)
            .map_err(|error| invalid(error.message()))?;
        stack_step(stack_service::stop_idle_runtime(
            self.stack,
            &request,
            &CancellationToken::default(),
        ))
    }
}

pub const LEGACY_COUNTER_PATH: &str = LEGACY_UID_COUNTER;
