use super::*;

/// Whether `s6-svstat` reports that no supervisor runs for the service
/// directory, i.e. there is no process to stop.
pub(super) fn has_no_supervisor(
    ctx: &Context<'_>,
    service: &str,
    container_dir: &str,
    cancel: &CancellationToken,
) -> bool {
    compose(
        ctx,
        Stage::StopService,
        &[
            "exec",
            "-T",
            service,
            "sh",
            "-c",
            "s6-svstat \"$1\" 2>&1 || true",
            "sh",
            container_dir,
        ],
        SIGNAL_TIMEOUT,
        cancel,
    )
    .is_ok_and(|out| {
        out.contains("s6-supervise not running") || out.contains("supervisor not listening")
    })
}

/// Overwrites an existing file atomically and marks it executable, matching
/// `write_new_executable`'s result for a path that already exists.
pub(super) fn overwrite_executable(
    root: &ManagedRoot,
    path: &SiteRelativePath,
    contents: &[u8],
) -> io::Result<()> {
    root.write_atomic(path, contents)?;
    root.set_mode(path, 0o755)
}

pub(super) fn read_optional(
    root: &ManagedRoot,
    path: &SiteRelativePath,
) -> Result<Option<Vec<u8>>, Error> {
    match root.read_bytes(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Error::Io(error)),
    }
}

/// `s6-svscanctl -a` with the same bounded retry the panel used: a freshly
/// started pool's nested `s6-svscan` may not have its control FIFO yet.
pub(super) fn scan_services(
    ctx: &Context<'_>,
    runtime_id: &RuntimeId,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let service = runtime_service(runtime_id);
    let script = format!(
        "i=0; while [ \"$i\" -lt 10 ]; do s6-svscanctl -a {SITE_SERVICES_CONTAINER_ROOT} && exit 0; i=$((i+1)); sleep 0.3; done; exit 1"
    );
    compose(
        ctx,
        Stage::ScanService,
        &["exec", "-T", &service, "sh", "-c", &script],
        SIGNAL_TIMEOUT,
        cancel,
    )?;
    Ok(())
}

pub(super) fn validate_site_config(
    ctx: &Context<'_>,
    runtime_id: &RuntimeId,
    container_dir: &str,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let service = runtime_service(runtime_id);
    let config = format!("{container_dir}/Caddyfile.tmp");
    compose(
        ctx,
        Stage::ValidateConfig,
        &[
            "exec",
            "-T",
            &service,
            "caddy",
            "validate",
            "--config",
            &config,
            "--adapter",
            "caddyfile",
        ],
        RELOAD_TIMEOUT,
        cancel,
    )?;
    Ok(())
}

/// `s6-svc -r <dir>`: restart the site's supervised FrankenPHP child so a
/// config change takes effect.
pub(super) fn restart_service(
    ctx: &Context<'_>,
    runtime_id: &RuntimeId,
    container_dir: &str,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let service = runtime_service(runtime_id);
    compose(
        ctx,
        Stage::RestartService,
        &["exec", "-T", &service, "s6-svc", "-r", container_dir],
        SIGNAL_TIMEOUT,
        cancel,
    )?;
    Ok(())
}

/// The readiness probe the panel ran: up to 20 one-second tries for any
/// HTTP status on the site's loopback port. Each `curl` is capped at 5 s,
/// so a process that accepts the connection but never answers cannot hold
/// the probe (and the stack lock) until the `compose exec` timeout.
pub(super) fn site_probe(
    ctx: &Context<'_>,
    runtime_id: &RuntimeId,
    port: u16,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let service = runtime_service(runtime_id);
    let probe = format!(
        "i=0; while [ \"$i\" -lt 20 ]; do code=$(curl -s --max-time 5 -o /dev/null -w '%{{http_code}}' -H 'Host: 127.0.0.1' http://127.0.0.1:{port}/ || true); [ \"$code\" != 000 ] && exit 0; i=$((i+1)); sleep 1; done; exit 1"
    );
    compose(
        ctx,
        Stage::SiteProbe,
        &["exec", "-T", &service, "sh", "-c", &probe],
        UP_TIMEOUT,
        cancel,
    )?;
    Ok(())
}

/// Restores the previous `Caddyfile`/`open-basedir.ini` (or removes a file
/// that had none) and restarts the child on the old config. Maps to
/// `SiteRolledBack` on success, `SiteRecoveryFailed` if the restore itself
/// fails.
#[allow(clippy::too_many_arguments)]
pub(super) fn restore_site(
    root: &ManagedRoot,
    ctx: &Context<'_>,
    runtime_id: &RuntimeId,
    caddy_rel: &SiteRelativePath,
    basedir_rel: &SiteRelativePath,
    container_dir: &str,
    prior_caddy: Option<&[u8]>,
    prior_basedir: Option<&[u8]>,
    cancel: &CancellationToken,
) -> Error {
    let restore = |path: &SiteRelativePath, prior: Option<&[u8]>| -> io::Result<()> {
        match prior {
            Some(bytes) => root.write_atomic(path, bytes),
            None => match root.remove_file(path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
            },
        }
    };
    if restore(caddy_rel, prior_caddy).is_err() || restore(basedir_rel, prior_basedir).is_err() {
        return Error::SiteRecoveryFailed;
    }
    // Only a prior config can be restarted into; a rolled-back first write
    // leaves nothing to run, so skip the restart there. No re-probe: the
    // restored config is the one that was serving before this request.
    if prior_caddy.is_some() && restart_service(ctx, runtime_id, container_dir, cancel).is_err() {
        return Error::SiteRecoveryFailed;
    }
    Error::SiteRolledBack
}
