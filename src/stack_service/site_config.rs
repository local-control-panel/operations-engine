use super::*;

// ===================== site-service lifecycle (051) =====================
//
// `stack.writeSiteService` and `stack.activateSiteConfig`: the per-site s6
// service directory and its dedicated FrankenPHP child's config, which the
// control panel used to write and reload over raw SSH against the pool's
// Compose project (`runtime_pool::site_identity`/`activation`). Both reuse
// this module's shared `stacks/wcp` lock, `stack-service` scope, `compose`
// exec and the `Context` the pool operations already run under. File writes
// go through `site_services_root` (a `ManagedRoot`), the container-side
// `s6-svc`/`s6-svscanctl`/`caddy validate`/`curl` go through `compose`.

/// A site's own directory inside its pool (`SITE_SERVICES_CONTAINER_ROOT/
/// <domain>`): the `--config` base its `run` script and `s6-svc` targets
/// use, and what `s6-svscanctl -a` rescans.
pub(super) fn container_dir(domain: &Domain) -> String {
    format!("{SITE_SERVICES_CONTAINER_ROOT}/{domain}")
}

/// `site_services_root`-relative path of one of a site's service files, or
/// the directory itself when `file` is empty.
pub(super) fn service_rel(runtime_id: &RuntimeId, domain: &Domain, file: &str) -> SiteRelativePath {
    let path = if file.is_empty() {
        format!("{runtime_id}/{domain}")
    } else {
        format!("{runtime_id}/{domain}/{file}")
    };
    SiteRelativePath::parse(path).expect("validated runtime id and domain form a valid path")
}

/// Ported verbatim from the control panel's
/// `sites::build_site_process_caddyfile` so the engine, not the panel, is
/// the single generator of this file's bytes (brief decision 3).
pub(crate) fn site_process_caddyfile(
    domain: &Domain,
    runtime_id: &RuntimeId,
    port: u16,
    root: &str,
    worker_mode: bool,
    worker_count: i64,
) -> String {
    let mut lines: Vec<String> = vec![
        "{".into(),
        "    admin off".into(),
        "}".into(),
        String::new(),
    ];
    lines.push(format!("http://127.0.0.1:{port} {{"));
    lines.push(format!("    root * {root}"));
    lines.push("    encode zstd gzip".into());
    if worker_mode {
        lines.push("    frankenphp {".into());
        lines.push(format!("        worker {root}/index.php {worker_count}"));
        lines.push("    }".into());
    }
    lines.push(String::new());
    lines.push("    @static {".into());
    lines.push("        file".into());
    lines.push(
        "        path *.css *.js *.png *.jpg *.jpeg *.gif *.webp *.avif *.svg *.woff *.woff2 *.ico"
            .into(),
    );
    lines.push("    }".into());
    lines.push("    header @static Cache-Control \"public, max-age=31536000, immutable\"".into());
    lines.push("    header @static Vary Accept-Encoding".into());
    lines.push(String::new());
    lines.push("    php_server".into());
    lines.push(String::new());
    lines.push("    log {".into());
    lines.push(format!(
        "        output file /var/log/caddy/runtime-{runtime_id}-{domain}.log {{"
    ));
    lines.push("            mode 0600".into());
    lines.push("        }".into());
    lines.push("        format json".into());
    lines.push("    }".into());
    lines.push("    log_append request_id {http.request.header.X-Request-ID}".into());
    lines.push(format!("    log_append domain {domain}"));
    lines.push(format!("    log_append runtime_id {runtime_id}"));
    lines.push("}".into());
    lines.join("\n")
}

/// Ported from the panel's `build_site_run_script`: drops privileges to the
/// site's UID/GID and execs its own FrankenPHP child.
pub(crate) fn site_run_script(uid: u32, gid: u32, container_dir: &str) -> String {
    format!(
        "#!/bin/sh\nexport PHP_INI_SCAN_DIR=\"/usr/local/etc/php/conf.d:{container_dir}\"\nexec setpriv --reuid={uid} --regid={gid} --clear-groups \\\n    frankenphp run --config {container_dir}/Caddyfile --adapter caddyfile\n"
    )
}

/// Ported from the panel's `build_site_open_basedir_ini`.
pub(crate) fn site_open_basedir_ini(root: &str) -> String {
    format!(
        "; Managed by OrbDen - do not edit manually\nopen_basedir = {root}:/tmp:/var/tmp:/run/valkey/valkey.sock\n"
    )
}

/// The identity a site's config carries: its loopback port, document root
/// and FrankenPHP worker settings. Shared by both site operations.
pub struct SiteConfig {
    pub port: u16,
    pub root: String,
    pub worker_mode: bool,
    pub worker_count: i64,
}

/// The document root goes verbatim into a `Caddyfile` and an `open_basedir`
/// ini line, so it gets the validation `site.allocateIdentity` applies: plain
/// absolute path of path-safe characters, no dot segments, under a content
/// root. A rejected root never reaches a file.
pub(super) fn validate_site_root(
    root: &str,
    content_roots: &[TrustedRoot],
) -> Result<(), RequestError> {
    crate::site_identity::validate_root(root, content_roots).map_err(|_| RequestError::InvalidRoot)
}

pub(super) fn parse_site_config(
    port: u16,
    root: String,
    worker_mode: bool,
    worker_count: i64,
    content_roots: &[TrustedRoot],
) -> Result<SiteConfig, RequestError> {
    if port == 0 {
        return Err(RequestError::InvalidPort);
    }
    validate_site_root(&root, content_roots)?;
    Ok(SiteConfig {
        port,
        root,
        worker_mode,
        worker_count,
    })
}

/// The run script drops to this identity and the runtime log is handed to
/// it: never root or a system account. Checked at the command boundary.
pub fn validate_site_identity(uid: u32, gid: u32) -> Result<(), RequestError> {
    let minimum = crate::site_enroll::MIN_SITE_IDENTITY;
    if uid < minimum || gid < minimum {
        return Err(RequestError::InvalidIdentity);
    }
    Ok(())
}

pub struct WriteSiteServiceRequest {
    pub runtime_id: RuntimeId,
    pub domain: Domain,
    pub uid: u32,
    pub gid: u32,
    pub config: SiteConfig,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl WriteSiteServiceRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn parse(
        runtime_id: &str,
        domain: &str,
        uid: u32,
        gid: u32,
        port: u16,
        root: String,
        worker_mode: bool,
        worker_count: i64,
        content_roots: &[TrustedRoot],
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
            uid,
            gid,
            config: parse_site_config(port, root, worker_mode, worker_count, content_roots)?,
            request_id,
            idempotency_key,
        })
    }
}

pub struct ActivateSiteConfigRequest {
    pub runtime_id: RuntimeId,
    pub domain: Domain,
    /// The site process's loopback port, for the readiness probe.
    pub port: u16,
    /// The document root, for regenerating `open-basedir.ini` (which is
    /// never edited textually, only derived from the root).
    pub root: String,
    /// The complete new `Caddyfile`, opaque to the engine: the panel edits
    /// this file textually (error pages, PHP settings), so it cannot be
    /// regenerated from typed parameters. Validated inside the pool before
    /// it can take effect.
    pub caddyfile: String,
    /// The precondition the swap runs under: `Absent` for a first write,
    /// `Sha256` of what the caller last read otherwise.
    pub guard: HashGuard,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl ActivateSiteConfigRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn parse(
        runtime_id: &str,
        domain: &str,
        port: u16,
        root: String,
        caddyfile: String,
        expected_prior_hash: Option<&str>,
        content_roots: &[TrustedRoot],
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let runtime_id =
            RuntimeId::parse(runtime_id).map_err(|_| RequestError::InvalidRuntimeId)?;
        let domain = Domain::parse(domain).map_err(|_| RequestError::InvalidDomain)?;
        if port == 0 {
            return Err(RequestError::InvalidPort);
        }
        validate_site_root(&root, content_roots)?;
        let guard = match expected_prior_hash {
            None => HashGuard::Absent,
            Some(value) => HashGuard::Sha256(
                ConfigHash::parse(value).map_err(|_| RequestError::InvalidPriorHash)?,
            ),
        };
        let (request_id, idempotency_key) = parse_ids(request_id, key)?;
        Ok(Self {
            runtime_id,
            domain,
            port,
            root,
            caddyfile,
            guard,
            request_id,
            idempotency_key,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteServiceResult {
    pub runtime_id: String,
    pub domain: String,
    pub completed_at_unix_secs: u64,
}

pub(super) fn site_result(runtime_id: &RuntimeId, domain: &Domain) -> SiteServiceResult {
    SiteServiceResult {
        runtime_id: runtime_id.as_str().to_owned(),
        domain: domain.as_str().to_owned(),
        completed_at_unix_secs: unix_now_secs(),
    }
}
