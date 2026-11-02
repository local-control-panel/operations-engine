use super::*;

/// Polls `ps -q <service>` and the container's `.State.Health.Status` until
/// it reads `healthy`. A container that is not created yet, or has no health
/// status yet, is polled again rather than failed.
pub(super) fn wait_healthy(
    ctx: &Context<'_>,
    service: &str,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let deadline = std::time::Instant::now() + ctx.health.timeout;
    let mut last = None;
    loop {
        let id = compose(
            ctx,
            Stage::Probe,
            &["ps", "-q", service],
            PROBE_TIMEOUT,
            cancel,
        )?;
        let id = id.trim();
        if !id.is_empty() {
            let status = docker(
                ctx,
                Stage::Probe,
                &[
                    "inspect",
                    "-f",
                    "{{if .State.Health}}{{.State.Health.Status}}{{end}}",
                    id,
                ],
                PROBE_TIMEOUT,
                cancel,
            )?;
            let status = status.trim();
            if status == "healthy" {
                return Ok(());
            }
            if !status.is_empty() {
                last = Some(status.to_owned());
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(Error::Unhealthy(last));
        }
        std::thread::sleep(ctx.health.interval);
    }
}

/// Live exec configs in `runtime_root/<runtime id>/`. Staging and rollback
/// files (`.tmp`, `.rollback-*`) are not imported by the pool's Caddy and do
/// not count. A missing directory means no configs.
pub(super) fn count_site_configs(
    runtime_root: &TrustedRoot,
    runtime_id: &RuntimeId,
) -> Result<usize, Error> {
    let root = ManagedRoot::open(runtime_root).map_err(Error::Io)?;
    let relative = SiteRelativePath::parse(runtime_id.as_str())
        .expect("a validated RuntimeId is a valid relative path");
    let pool_dir = match root.open_managed_dir(&relative) {
        Ok(dir) => dir,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(Error::Io(error)),
    };
    let suffix = format!(".{ROUTE_EXTENSION}");
    Ok(pool_dir
        .file_names()
        .map_err(Error::Io)?
        .iter()
        .filter(|name| name.ends_with(&suffix) && name.len() > suffix.len())
        .count())
}
