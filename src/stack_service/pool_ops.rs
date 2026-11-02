use super::*;

pub fn reload(
    ctx: &Context<'_>,
    req: &ReloadRequest,
    cancel: &CancellationToken,
) -> Result<ReloadResult, Error> {
    run_admitted(
        ctx,
        RELOAD_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        || {
            let service = req.service.name();
            compose(
                ctx,
                Stage::Reload,
                &[
                    "exec",
                    "-T",
                    &service,
                    "caddy",
                    "reload",
                    "--config",
                    LIVE_CONFIG_PATH,
                    "--adapter",
                    "caddyfile",
                ],
                RELOAD_TIMEOUT,
                cancel,
            )?;
            Ok(ReloadResult {
                service,
                reloaded_at_unix_secs: unix_now_secs(),
            })
        },
    )
}

pub fn stop_idle_runtime(
    ctx: &Context<'_>,
    req: &StopRequest,
    cancel: &CancellationToken,
) -> Result<StopResult, Error> {
    run_admitted(
        ctx,
        STOP_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        || {
            let service = runtime_service(&req.runtime_id);
            let site_configs = count_site_configs(ctx.runtime_root, &req.runtime_id)?;
            if site_configs == 0 {
                compose(ctx, Stage::Stop, &["stop", &service], STOP_TIMEOUT, cancel)?;
            }
            Ok(StopResult {
                runtime_id: req.runtime_id.as_str().to_owned(),
                service,
                stopped: site_configs == 0,
                site_configs,
                completed_at_unix_secs: unix_now_secs(),
            })
        },
    )
}

pub fn ensure_runtime(
    ctx: &Context<'_>,
    req: &EnsureRequest,
    cancel: &CancellationToken,
) -> Result<EnsureResult, Error> {
    run_admitted(
        ctx,
        ENSURE_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        || {
            let service = runtime_service(&req.runtime_id);
            let mut tail = Vec::new();
            if let Some(profile) = &req.profile {
                tail.extend(["--profile", profile.as_str()]);
            }
            tail.extend(["up", "-d", service.as_str()]);
            compose(ctx, Stage::Up, &tail, UP_TIMEOUT, cancel)?;
            wait_healthy(ctx, &service, cancel)?;
            Ok(EnsureResult {
                runtime_id: req.runtime_id.as_str().to_owned(),
                service,
                healthy_at_unix_secs: unix_now_secs(),
            })
        },
    )
}

pub fn reload_workers(
    ctx: &Context<'_>,
    req: &RuntimeRequest,
    cancel: &CancellationToken,
) -> Result<RuntimeActionResult, Error> {
    runtime_action(
        ctx,
        RELOAD_WORKERS_OPERATION,
        Stage::ReloadWorkers,
        req,
        &["sh", "-c", RELOAD_WORKERS_SCRIPT],
        cancel,
    )
}

pub fn flush_fpc(
    ctx: &Context<'_>,
    req: &RuntimeRequest,
    cancel: &CancellationToken,
) -> Result<RuntimeActionResult, Error> {
    runtime_action(
        ctx,
        FLUSH_FPC_OPERATION,
        Stage::FlushFpc,
        req,
        &["sh", "-c", FLUSH_FPC_SCRIPT],
        cancel,
    )
}

/// `exec -T runtime-<id> <command>` under the stack lock.
pub(super) fn runtime_action(
    ctx: &Context<'_>,
    operation: &'static str,
    stage: Stage,
    req: &RuntimeRequest,
    command: &[&str],
    cancel: &CancellationToken,
) -> Result<RuntimeActionResult, Error> {
    run_admitted(
        ctx,
        operation,
        req.request_id,
        req.idempotency_key.as_ref(),
        || {
            let service = runtime_service(&req.runtime_id);
            let mut tail = vec!["exec", "-T", service.as_str()];
            tail.extend_from_slice(command);
            compose(ctx, stage, &tail, SIGNAL_TIMEOUT, cancel)?;
            Ok(RuntimeActionResult {
                runtime_id: req.runtime_id.as_str().to_owned(),
                service,
                completed_at_unix_secs: unix_now_secs(),
            })
        },
    )
}
