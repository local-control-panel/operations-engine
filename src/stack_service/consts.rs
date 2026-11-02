use super::*;

pub const RELOAD_OPERATION: &str = "stack.reloadCaddy";
pub const STOP_OPERATION: &str = "stack.stopIdleRuntime";
pub const ENSURE_OPERATION: &str = "stack.ensureRuntime";
pub const RELOAD_WORKERS_OPERATION: &str = "stack.reloadWorkers";
pub const FLUSH_FPC_OPERATION: &str = "stack.flushFpc";
pub const WRITE_SITE_SERVICE_OPERATION: &str = "stack.writeSiteService";
pub const ACTIVATE_SITE_CONFIG_OPERATION: &str = "stack.activateSiteConfig";
pub const REMOVE_SITE_SERVICE_OPERATION: &str = "stack.removeSiteService";

/// Where each pool sees its own `site_services_root/<runtime id>/` subtree,
/// bind-mounted bare so the path is the same inside every pool. A site's
/// own directory is `SITE_SERVICES_CONTAINER_ROOT/<domain>`; that is the
/// `--config` base its `run` script and every `s6-svc` target use, and the
/// directory `s6-svscanctl -a` rescans.
pub const SITE_SERVICES_CONTAINER_ROOT: &str = "/etc/wcp/site-services";

/// Engine-state scope for both operations. Separate from `stacks/wcp`,
/// whose own preflight lock *is* the shared stack lock.
pub(super) const SCOPE: &str = "stack-service";

/// The one ingress Compose service (`images/stack/docker-compose.v2.yml`).
pub const INGRESS_SERVICE: &str = "ingress";

/// Same bound `compose::exec` uses for an in-container `caddy reload`.
pub(super) const RELOAD_TIMEOUT: Duration = Duration::from_secs(30);

/// `docker compose stop` waits up to 10 s per container before it kills;
/// the rest is Compose's own start-up and the API round trips.
pub(super) const STOP_TIMEOUT: Duration = Duration::from_secs(60);

/// `docker compose up -d` for one service may pull nothing but still has to
/// create the container and its network attachments.
pub(super) const UP_TIMEOUT: Duration = Duration::from_secs(120);

/// One `ps -q` or `docker inspect` round trip during the health wait.
pub(super) const PROBE_TIMEOUT: Duration = Duration::from_secs(15);

/// `kill -USR2 1` and the cache purge are both instant inside the container.
pub(super) const SIGNAL_TIMEOUT: Duration = Duration::from_secs(30);

/// PHP workers run in each site's own FrankenPHP child process (`admin off`,
/// supervised by s6 under `/etc/wcp/site-services/<domain>`), not in the
/// pool's main Caddy, and pid 1 is `s6-svscan`. Reloading them means
/// restarting every site service that has a `run` script; a leftover
/// directory without one is skipped.
pub(super) const RELOAD_WORKERS_SCRIPT: &str = "for d in /etc/wcp/site-services/*/; do \
     [ -f \"${d}run\" ] || continue; s6-svc -r \"$d\" || exit 1; done";

/// Fixed in-container FPC purge: a `PURGE` to Souin plus a wipe of its
/// BadgerDB store, both best-effort, exactly what the panel ran before.
pub(super) const FLUSH_FPC_SCRIPT: &str =
    "curl -sf -X PURGE http://localhost/ 2>/dev/null; rm -rf /tmp/souin 2>/dev/null; echo ok";

pub(super) const MAX_OUTPUT_BYTES: usize = 64 * 1024;
