use super::*;

/// Writes (or overwrites) one site's s6 service directory — `run` script,
/// dedicated `Caddyfile` and `open-basedir.ini` — then makes the running
/// `s6-svscan` pick the directory up. No restart or readiness probe: this
/// is site creation/migration, where the process has not served yet.
pub fn write_site_service(
    ctx: &Context<'_>,
    req: &WriteSiteServiceRequest,
    cancel: &CancellationToken,
) -> Result<SiteServiceResult, Error> {
    run_admitted(
        ctx,
        WRITE_SITE_SERVICE_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        || {
            let root = ManagedRoot::open(ctx.site_services_root).map_err(Error::Io)?;
            root.create_dir_all(&service_rel(&req.runtime_id, &req.domain, ""))
                .map_err(Error::Io)?;
            let cdir = container_dir(&req.domain);
            root.write_new_executable(
                &service_rel(&req.runtime_id, &req.domain, "run"),
                site_run_script(req.uid, req.gid, &cdir).as_bytes(),
            )
            .or_else(|error| {
                // `write_new_executable` fails if `run` already exists
                // (create-new); a rewrite overwrites it atomically instead.
                if error.kind() == io::ErrorKind::AlreadyExists {
                    overwrite_executable(
                        &root,
                        &service_rel(&req.runtime_id, &req.domain, "run"),
                        site_run_script(req.uid, req.gid, &cdir).as_bytes(),
                    )
                } else {
                    Err(error)
                }
            })
            .map_err(Error::Io)?;
            root.write_atomic(
                &service_rel(&req.runtime_id, &req.domain, "open-basedir.ini"),
                site_open_basedir_ini(&req.config.root).as_bytes(),
            )
            .map_err(Error::Io)?;
            root.write_atomic(
                &service_rel(&req.runtime_id, &req.domain, "Caddyfile"),
                site_process_caddyfile(
                    &req.domain,
                    &req.runtime_id,
                    req.config.port,
                    &req.config.root,
                    req.config.worker_mode,
                    req.config.worker_count,
                )
                .as_bytes(),
            )
            .map_err(Error::Io)?;
            prepare_runtime_log(ctx, req)?;
            scan_services(ctx, &req.runtime_id, cancel)?;
            Ok(site_result(&req.runtime_id, &req.domain))
        },
    )
}

/// Pre-creates the site's own runtime log, `0600` and owned by the site
/// identity, before the service is registered: the site process runs as an
/// unprivileged uid and cannot create a file in the root-owned shared log
/// directory. The ingress log has a different name and stays root-owned.
/// The file is opened through the log directory's capability, must be a
/// regular file, and is changed through its own descriptor.
pub(super) fn prepare_runtime_log(
    ctx: &Context<'_>,
    req: &WriteSiteServiceRequest,
) -> Result<(), Error> {
    use std::os::unix::fs::{PermissionsExt, fchown};

    let logs = ManagedRoot::open(ctx.log_root).map_err(Error::Io)?;
    let name = rel(&format!("runtime-{}-{}.log", req.runtime_id, req.domain));
    let file = logs.open_or_create_file(&name).map_err(Error::Io)?;
    if !file.metadata().map_err(Error::Io)?.is_file() {
        return Err(Error::Io(io::Error::other(
            "runtime log is not a regular file",
        )));
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(Error::Io)?;
    if ctx.chown_logs {
        fchown(&file, Some(req.uid), Some(req.gid)).map_err(Error::Io)?;
    }
    Ok(())
}

/// Regenerates a site's `Caddyfile` (and `open-basedir.ini`) from typed
/// parameters, validates the new `Caddyfile` inside the pool, swaps it in
/// atomically, restarts the site process and waits for it to answer. If the
/// restarted process never becomes ready the previous files are restored and
/// the process is brought back up on them (brief decision 2).
pub fn activate_site_config(
    ctx: &Context<'_>,
    req: &ActivateSiteConfigRequest,
    cancel: &CancellationToken,
) -> Result<SiteServiceResult, Error> {
    run_admitted(
        ctx,
        ACTIVATE_SITE_CONFIG_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        || {
            activate_locked(
                ctx,
                &SiteActivation {
                    runtime_id: &req.runtime_id,
                    domain: &req.domain,
                    port: req.port,
                    root: &req.root,
                    caddyfile: &req.caddyfile,
                    guard: &req.guard,
                },
                cancel,
            )
        },
    )
}

/// What `activate_locked` swaps in. Borrowed from either
/// `stack.activateSiteConfig` or `site.setErrorPages`, which both run the
/// same validate, swap, restart, probe and roll back sequence.
pub(crate) struct SiteActivation<'a> {
    pub runtime_id: &'a RuntimeId,
    pub domain: &'a Domain,
    pub port: u16,
    pub root: &'a str,
    pub caddyfile: &'a str,
    pub guard: &'a HashGuard,
}

/// The activation itself, for a caller that already holds the `stacks/wcp`
/// lock (`run_admitted` is not reentrant).
pub(crate) fn activate_locked(
    ctx: &Context<'_>,
    activation: &SiteActivation<'_>,
    cancel: &CancellationToken,
) -> Result<SiteServiceResult, Error> {
    let root = ManagedRoot::open(ctx.site_services_root).map_err(Error::Io)?;
    let caddy_rel = service_rel(activation.runtime_id, activation.domain, "Caddyfile");
    let basedir_rel = service_rel(activation.runtime_id, activation.domain, "open-basedir.ini");
    let tmp_rel = service_rel(activation.runtime_id, activation.domain, "Caddyfile.tmp");

    // Hash-guard the file currently on disk before touching anything.
    let prior_caddy = read_optional(&root, &caddy_rel)?;
    if !activation.guard.is_satisfied_by(prior_caddy.as_deref()) {
        return Err(Error::HashMismatch);
    }
    let prior_basedir = read_optional(&root, &basedir_rel)?;

    // The Caddyfile is the caller's opaque, validated-in-container
    // content; open-basedir is derived from the root.
    let new_caddy = activation.caddyfile;
    let new_basedir = site_open_basedir_ini(activation.root);

    // Stage the new Caddyfile next to the live one and validate it
    // inside the pool before it can take effect. A `.tmp` sibling is
    // not loaded by the running process.
    root.write_atomic(&tmp_rel, new_caddy.as_bytes())
        .map_err(Error::Io)?;
    let cdir = container_dir(activation.domain);
    if let Err(error) = validate_site_config(ctx, activation.runtime_id, &cdir, cancel) {
        let _ = root.remove_file(&tmp_rel);
        return Err(error);
    }

    // Commit: swap the validated Caddyfile in and refresh the ini.
    root.rename(&tmp_rel, &caddy_rel).map_err(Error::Io)?;
    root.write_atomic(&basedir_rel, new_basedir.as_bytes())
        .map_err(Error::Io)?;

    // Restart the child and probe it. Any failure rolls both files
    // back to what was on disk and restarts on the old config.
    let outcome = restart_service(ctx, activation.runtime_id, &cdir, cancel)
        .and_then(|()| site_probe(ctx, activation.runtime_id, activation.port, cancel));
    match outcome {
        Ok(()) => Ok(site_result(activation.runtime_id, activation.domain)),
        Err(_down) => Err(restore_site(
            &root,
            ctx,
            activation.runtime_id,
            &caddy_rel,
            &basedir_rel,
            &cdir,
            prior_caddy.as_deref(),
            prior_basedir.as_deref(),
            cancel,
        )),
    }
}

/// The site process's current `Caddyfile`, if it has a service directory.
pub(crate) fn read_site_caddyfile(
    ctx: &Context<'_>,
    runtime_id: &RuntimeId,
    domain: &Domain,
) -> Result<Option<Vec<u8>>, Error> {
    let root = ManagedRoot::open(ctx.site_services_root).map_err(Error::Io)?;
    read_optional(&root, &service_rel(runtime_id, domain, "Caddyfile"))
}

pub struct RemoveSiteServiceRequest {
    pub runtime_id: RuntimeId,
    pub domain: Domain,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
    pub(crate) expected_files: Option<Vec<(SiteRelativePath, String)>>,
}

impl RemoveSiteServiceRequest {
    pub fn parse(
        runtime_id: &str,
        domain: &str,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let runtime_id =
            RuntimeId::parse(runtime_id).map_err(|_| RequestError::InvalidRuntimeId)?;
        let domain = Domain::parse(domain).map_err(|_| RequestError::InvalidDomain)?;
        let (request_id, idempotency_key) = parse_ids(request_id, key)?;
        Ok(Self {
            runtime_id,
            domain,
            request_id,
            idempotency_key,
            expected_files: None,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveSiteServiceResult {
    pub runtime_id: String,
    pub domain: String,
    /// `false` when there was no service directory to remove: a site whose
    /// service was never created (or is already gone) is a no-op, not an
    /// error, so cleanup paths can call this unconditionally.
    pub removed: bool,
    /// Whether the pool was running, i.e. whether a process could exist to
    /// be stopped and an `s6-svscan` to tell about the removal.
    pub pool_running: bool,
    pub completed_at_unix_secs: u64,
}

/// Tears down one site's s6 service: `s6-svc -d` stops its FrankenPHP
/// child, the service directory is removed, and `s6-svscanctl -a` drops
/// its supervisor. A failed stop changes nothing on disk (brief decision 3:
/// a visible `FAILED`, never a half-removed service reported as success).
/// A stopped pool has no process to stop, so only the directory goes.
pub fn remove_site_service(
    ctx: &Context<'_>,
    req: &RemoveSiteServiceRequest,
    cancel: &CancellationToken,
) -> Result<RemoveSiteServiceResult, Error> {
    run_admitted(
        ctx,
        REMOVE_SITE_SERVICE_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        || {
            let root = ManagedRoot::open(ctx.site_services_root).map_err(Error::Io)?;
            let dir_rel = service_rel(&req.runtime_id, &req.domain, "");
            let result = |removed, pool_running| RemoveSiteServiceResult {
                runtime_id: req.runtime_id.as_str().to_owned(),
                domain: req.domain.as_str().to_owned(),
                removed,
                pool_running,
                completed_at_unix_secs: unix_now_secs(),
            };
            if !root.exists(&dir_rel) {
                return Ok(result(false, false));
            }

            if let Some(expected) = &req.expected_files {
                for (path, content) in expected {
                    match root.read_to_string(path) {
                        Ok(actual) if actual == *content => {}
                        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                        _ => return Err(Error::HashMismatch),
                    }
                }
            }
            let service = runtime_service(&req.runtime_id);
            let running = !compose(
                ctx,
                Stage::Probe,
                &["ps", "-q", &service],
                PROBE_TIMEOUT,
                cancel,
            )?
            .trim()
            .is_empty();
            let cdir = container_dir(&req.domain);
            if running {
                let stop = compose(
                    ctx,
                    Stage::StopService,
                    &["exec", "-T", &service, "s6-svc", "-d", &cdir],
                    SIGNAL_TIMEOUT,
                    cancel,
                );
                // A directory written but never picked up by the scanner (a
                // rolled-back preparation) has no supervisor and nothing to
                // stop; any other failure keeps the service in place.
                if let Err(error) = stop {
                    if !has_no_supervisor(ctx, &service, &cdir, cancel) {
                        return Err(error);
                    }
                }
            }
            root.remove_dir_all(&dir_rel).map_err(Error::Io)?;
            if running {
                scan_services(ctx, &req.runtime_id, cancel)?;
            }
            Ok(result(true, running))
        },
    )
}
