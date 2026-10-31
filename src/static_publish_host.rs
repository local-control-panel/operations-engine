//! Production boundary for static publishing. No application commands are run.
use crate::{
    config::EngineConfig,
    error::ErrorCode,
    filesystem::ManagedRoot,
    ingress::{self, ConfigHash, HashGuard, RouteTarget},
    process::{self, CancellationToken, ProcessLimits, ProcessRequest},
    protocol::{Response, ResponseBuildError},
    site::{SiteRelativePath, TrustedRoot},
    site_migrate_runtime::StepError,
    static_publish::{self, Backend, Plan},
    transaction::{IdempotencyKey, RequestId},
};
use std::{io::Read, path::Path, time::Duration};
const ROOT: &str = "/var/lib/wcp-static";
fn err(message: &str) -> StepError {
    StepError::new(ErrorCode::Conflict, message)
}
fn rel(p: &str) -> Result<SiteRelativePath, StepError> {
    SiteRelativePath::parse(p).map_err(|_| err("invalid static path"))
}
fn fresh() -> String {
    uuid::Uuid::new_v4().to_string()
}
struct Host<'a> {
    config: &'a EngineConfig,
    state: &'a ManagedRoot,
    compose: crate::compose::Access,
}
fn bounded(root: &ManagedRoot, path: &SiteRelativePath) -> Result<Option<String>, StepError> {
    let file = match root.open_regular_read(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(err("route unavailable")),
    };
    let mut value = String::new();
    file.take(262145)
        .read_to_string(&mut value)
        .map_err(|_| err("invalid route"))?;
    if value.len() > 262144 {
        return Err(err("route too large"));
    }
    Ok(Some(value))
}
impl Host<'_> {
    fn route(&self, p: &Plan) -> Result<Option<String>, StepError> {
        let root =
            ManagedRoot::open(&self.config.ingress_root).map_err(|_| err("ingress unavailable"))?;
        bounded(&root, &rel(&format!("{}.caddyfile", p.domain))?)
    }
    fn context(&self) -> ingress::execute::ActivateContext<'_> {
        ingress::execute::ActivateContext {
            ingress_root: &self.config.ingress_root,
            engine_state: self.state,
            compose: &self.compose,
        }
    }
    fn set(&self, p: &Plan, content: &str, previous: Option<&str>) -> Result<(), StepError> {
        let guard = previous
            .map(|s| HashGuard::Sha256(ConfigHash::of(s.as_bytes())))
            .unwrap_or(HashGuard::Absent);
        ingress::activate::activate(
            &self.config.ingress_root,
            &p.validate()?,
            content,
            &guard,
            RouteTarget::Live,
            &fresh(),
            &self.compose,
        )
        .map_err(|_| err("static route activation requires recovery"))?;
        Ok(())
    }
}
impl Backend for Host<'_> {
    fn check(&self, p: &Plan) -> Result<Option<String>, StepError> {
        p.validate()?;
        // Inspect the actual running container, not just a proposed compose file.
        let output = process::run(
            &ProcessRequest::new("docker").args([
                "inspect",
                "wcp-ingress-1",
                "--format",
                "{{json .Mounts}}",
            ]),
            &ProcessLimits {
                timeout: Duration::from_secs(15),
                ..Default::default()
            },
            &CancellationToken::default(),
        )
        .map_err(|_| err("cannot inspect ingress mounts"))?;
        if process::error_code(&output.termination).is_some() || output.stdout.truncated {
            return Err(err("cannot inspect ingress mounts"));
        }
        let mounts: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout.bytes)
            .map_err(|_| err("invalid ingress mounts"))?;
        let mut found = false;
        for m in mounts {
            let source = m["Source"].as_str().unwrap_or("");
            let target = m["Destination"].as_str().unwrap_or("");
            if target == "/srv/wcp-static" {
                if source != ROOT || m["RW"].as_bool() != Some(false) {
                    return Err(err(
                        "static publishing mount must be isolated and read-only",
                    ));
                }
                found = true;
            } else if target.starts_with("/srv/wcp-static/")
                || self.config.content_roots.iter().any(|r| {
                    Path::new(source).starts_with(r.as_path()) || r.as_path().starts_with(source)
                })
            {
                return Err(err("ingress exposes application content"));
            }
        }
        if !found {
            return Err(err("ingress static mount is unavailable"));
        }
        let root =
            ManagedRoot::open(&self.config.ingress_root).map_err(|_| err("ingress unavailable"))?;
        for suffix in ["caddyfile.disabled", "maintenance-backup"] {
            if bounded(&root, &rel(&format!("{}.{}", p.domain, suffix))?)?.is_some() {
                return Err(err("disabled or parked route cannot be published"));
            }
        }
        let previous = self.route(p)?;
        if let Some(s) = &previous {
            let domain = p.validate()?;
            if *s != crate::static_ingress::render(&domain, false)
                && *s != crate::static_ingress::render(&domain, true)
            {
                return Err(err("existing route is not managed static hosting"));
            }
        }
        Ok(previous)
    }
    fn activate_route(&self, p: &Plan, previous: Option<&str>) -> Result<(), StepError> {
        self.set(
            p,
            &crate::static_ingress::render(&p.validate()?, p.spa_fallback),
            previous,
        )
    }
    fn restore_route(&self, p: &Plan, previous: Option<&str>) -> Result<(), StepError> {
        let current = self.route(p)?;
        let generated = crate::static_ingress::render(&p.validate()?, p.spa_fallback);
        if current.as_deref() != Some(&generated) && current.as_deref() != previous {
            return Err(err("route changed during recovery"));
        }
        if let Some(old) = previous {
            return self.set(p, old, current.as_deref());
        }
        if let Some(current) = current {
            let req = ingress::RemoveRouteRequest::parse(
                &p.domain,
                ConfigHash::of(current.as_bytes()).as_str(),
                None,
                &fresh(),
                None,
            )
            .map_err(|_| err("invalid recovery route"))?;
            ingress::remove::remove(&self.context(), &req)
                .map_err(|_| err("route removal requires recovery"))?;
        }
        Ok(())
    }
    fn probe(&self, p: &Plan, release: Option<RequestId>) -> Result<(), StepError> {
        let resolve = format!("{}:443:127.0.0.1", p.domain);
        let url = format!("https://{}/wcp-release.txt", p.domain);
        let output = self
            .compose
            .exec(
                "ingress",
                &[
                    "curl",
                    "--silent",
                    "--show-error",
                    "--fail",
                    "--insecure",
                    "--max-time",
                    "10",
                    "--resolve",
                    &resolve,
                    &url,
                ],
            )
            .map_err(|_| err("static HTTP verification unavailable"))?;
        match release {
            Some(id)
                if process::error_code(&output.termination).is_none()
                    && !output.stdout.truncated
                    && output.stdout.bytes == id.to_string().as_bytes() =>
            {
                Ok(())
            }
            None if self.route(p)?.is_none()
                && process::error_code(&output.termination).is_some() =>
            {
                Ok(())
            }
            _ => Err(err("static HTTP verification failed")),
        }
    }
}
fn open_private(path: &Path) -> Result<ManagedRoot, StepError> {
    use std::os::unix::fs::MetadataExt;
    let mut cursor = std::path::PathBuf::from("/");
    for c in path.components() {
        if let std::path::Component::Normal(part) = c {
            cursor.push(part);
            let m = std::fs::symlink_metadata(&cursor)
                .map_err(|_| err("publishing root unavailable"))?;
            if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
                return Err(err(
                    "publishing root must be root-owned and not writable by other users",
                ));
            }
        }
    }
    ManagedRoot::open(&TrustedRoot::parse(path).map_err(|_| err("invalid root"))?)
        .map_err(|_| err("publishing root unavailable"))
}
fn source(config: &EngineConfig, path: &str) -> Result<ManagedRoot, StepError> {
    let path = Path::new(path);
    for root in &config.content_roots {
        if let Ok(relative) = path.strip_prefix(root.as_path()) {
            let mut dir = ManagedRoot::open(root).map_err(|_| err("source root unavailable"))?;
            for component in relative.components() {
                let std::path::Component::Normal(name) = component else {
                    return Err(err("invalid source path"));
                };
                dir = dir
                    .open_child_dir_nofollow(&rel(name
                        .to_str()
                        .ok_or_else(|| err("invalid source path"))?)?)
                    .map_err(|_| err("source must be a directory without symlinks"))?;
            }
            return Ok(dir);
        }
    }
    Err(err("source is outside configured content roots"))
}
fn dispatch<T: serde::Serialize>(
    op: &'static str,
    action: impl FnOnce(&EngineConfig, &ManagedRoot, &ManagedRoot, &Host<'_>) -> Result<T, StepError>,
) -> Result<Response, ResponseBuildError> {
    let result = (|| {
        let config = EngineConfig::load_root_owned(Path::new("/etc/operations-engine/config.json"))
            .map_err(|_| err("engine configuration unavailable"))?;
        let state =
            ManagedRoot::open(&config.state_root).map_err(|_| err("engine state unavailable"))?;
        let publishing = open_private(Path::new(ROOT))?;
        let host = Host {
            config: &config,
            state: &state,
            compose: Default::default(),
        };
        let stack_scope =
            crate::stack_deploy::open_scope(&state).map_err(|_| err("stack lock unavailable"))?;
        let ingress_scope = ingress::execute::open_ingress_state(&state)
            .map_err(|_| err("ingress lock unavailable"))?;
        let lock_id = RequestId::parse(&fresh()).map_err(|_| err("invalid lock identity"))?;
        let _stack_lock = if op != "site.staticStatus" {
            Some(
                crate::stack_deploy::acquire_stack_lock(&stack_scope, lock_id)
                    .map_err(|_| err("stack is busy"))?,
            )
        } else {
            None
        };
        let _ingress_lock = if op != "site.staticStatus" {
            Some(
                crate::transaction::lock::acquire(
                    &ingress_scope,
                    &crate::mutation::preflight::lock_path(),
                    lock_id,
                )
                .map_err(|_| err("ingress is busy"))?,
            )
        } else {
            None
        };
        action(&config, &state, &publishing, &host)
    })();
    match result {
        Ok(r) => Response::success(op, r),
        Err(e) => Ok(Response::failure(op, e.code, &e.message)),
    }
}
pub fn publish(path: &Path, id: &str, key: &str) -> Result<Response, ResponseBuildError> {
    dispatch("site.publishStatic", |config, state, publishing, host| {
        let json = crate::commands::read_root_owned_content_file_bounded(path, 16384)
            .map_err(|_| err("invalid root-owned static request"))?;
        let plan: Plan = serde_json::from_str(&json).map_err(|_| err("invalid static plan"))?;
        plan.validate()?;
        let source = source(config, &plan.source_path)?;
        static_publish::execute(
            state,
            publishing,
            &source,
            host,
            &plan,
            RequestId::parse(id).map_err(|_| err("invalid request ID"))?,
            &IdempotencyKey::parse(key).map_err(|_| err("invalid idempotency key"))?,
        )
    })
}
pub fn status(domain: &str, id: &str) -> Result<Response, ResponseBuildError> {
    dispatch("site.staticStatus", |_, state, _, _| {
        static_publish::status(
            state,
            domain,
            RequestId::parse(id).map_err(|_| err("invalid request ID"))?,
        )
    })
}
pub fn recover(domain: &str, id: &str) -> Result<Response, ResponseBuildError> {
    dispatch("site.recoverStatic", |_, state, publishing, host| {
        static_publish::recover(
            state,
            publishing,
            host,
            domain,
            RequestId::parse(id).map_err(|_| err("invalid request ID"))?,
        )
    })
}
