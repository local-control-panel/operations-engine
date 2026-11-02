use std::path::PathBuf;

use clap::Subcommand;

#[derive(Debug, Subcommand)]
pub enum RuntimeCommand {
    /// Atomically replace one site's runtime-service Caddyfile fragment,
    /// validating the new content before it can reach the live path and
    /// restoring the previous content if the live reload rejects it.
    ActivateConfig {
        /// Which runtime pool's Caddyfile fragment is being replaced —
        /// selects both the `runtime-<id>` Compose service the write
        /// validates/reloads against and the `<id>/` subdirectory of the
        /// configured runtime root it lives under.
        #[arg(long = "runtime-id")]
        runtime_id: String,

        /// The site whose fragment this is. The engine derives the file
        /// name from it (`<domain>.caddyfile`).
        #[arg(long)]
        domain: String,

        /// Path to a file holding the complete new contents of the
        /// fragment. Whole-file replacement, not a patch: read the current
        /// file, transform it, and pass the result here.
        #[arg(long = "content-file")]
        content_file: PathBuf,

        /// The SHA-256 digest of the fragment's current contents, as an
        /// optimistic-concurrency precondition. Omit only when no fragment
        /// is expected to exist yet for this site on this runtime pool
        /// (asserts absence — fails if one is already there). To update an
        /// existing fragment, pass its current content hash.
        #[arg(long = "expected-hash")]
        expected_hash: Option<String>,

        /// Canonical UUID identifying this specific attempt. The caller
        /// mints this, not the engine — see `docs/site-model.md`.
        #[arg(long = "request-id")]
        request_id: String,

        /// Caller-supplied token so a retried request returns the original
        /// outcome instead of activating twice.
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },

    /// Deletes one site's fragment from one runtime pool and reloads that
    /// pool, putting the fragment back if the reload fails.
    RemoveConfig {
        /// Which runtime pool the fragment belongs to.
        #[arg(long = "runtime-id")]
        runtime_id: String,

        #[arg(long)]
        domain: String,

        /// SHA-256 digest of the fragment being removed.
        #[arg(long = "expected-hash")]
        expected_hash: String,

        /// Canonical UUID identifying this specific attempt.
        #[arg(long = "request-id")]
        request_id: String,

        /// Caller-supplied token so a retried request returns the original
        /// outcome instead of removing twice.
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },

    /// Sweeps one runtime pool's own subdirectory of the configured runtime
    /// root for `.tmp`/`.tmp-*` staging siblings and `.rollback-*` backup
    /// siblings left behind by an interrupted activate-config attempt,
    /// removing or restoring each. Takes `--runtime-id`, same as
    /// `activate-config` - see docs repo milestone `003-runtime-reconcile.md`
    /// for why this sweeps one named pool rather than every pool at once.
    Reconcile {
        /// Which runtime pool's subdirectory to sweep.
        #[arg(long = "runtime-id")]
        runtime_id: String,

        /// Canonical UUID identifying this specific attempt. The caller
        /// mints this, not the engine — see `docs/site-model.md`.
        #[arg(long = "request-id")]
        request_id: String,

        /// Caller-supplied token so a retried request returns the original
        /// outcome instead of sweeping twice.
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum StackCommand {
    /// Replace the managed WCP stack's files and converge its containers:
    /// staged validation, image policy and pull before any live change,
    /// then activation, a health gate and automatic rollback.
    Deploy {
        /// Root-owned JSON file holding every managed stack file's contents.
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Reload Caddy inside one service of the managed WCP stack (the
    /// ingress or one runtime pool) through a fixed argv, under the shared
    /// stack lock.
    ReloadCaddy {
        /// `ingress` or `runtime-<runtime id>`.
        #[arg(long = "service")]
        service: String,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Stop one runtime pool's service, but only if no site exec config is
    /// left under its runtime directory; otherwise leave it running.
    StopIdleRuntime {
        #[arg(long = "runtime-id")]
        runtime_id: String,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Start one runtime pool's service (`up -d`) and wait until its
    /// healthcheck reports `healthy`, under the shared stack lock.
    EnsureRuntime {
        #[arg(long = "runtime-id")]
        runtime_id: String,
        /// `php-<major>.<minor>` for a non-default pool gated behind a
        /// Compose profile; omitted for the default runtime.
        #[arg(long = "profile")]
        profile: Option<String>,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Restart every site process (and so its PHP workers) in one runtime
    /// pool through s6, under the shared stack lock.
    ReloadWorkers {
        #[arg(long = "runtime-id")]
        runtime_id: String,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Purge the Souin full-page cache inside one runtime pool, under the
    /// shared stack lock.
    FlushFpc {
        #[arg(long = "runtime-id")]
        runtime_id: String,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Write one site's s6 service directory (run script, dedicated
    /// Caddyfile and open-basedir.ini) under `siteServicesRoot` and
    /// register it with the pool's s6-svscan, under the shared stack lock.
    WriteSiteService {
        #[arg(long = "runtime-id")]
        runtime_id: String,
        #[arg(long = "domain")]
        domain: String,
        /// The site's dedicated UID the run script drops privileges to.
        #[arg(long = "uid")]
        uid: u32,
        #[arg(long = "gid")]
        gid: u32,
        /// The site process's loopback port.
        #[arg(long = "port")]
        port: u16,
        /// The site's document root inside the container.
        #[arg(long = "root")]
        root: String,
        /// Enable FrankenPHP worker mode for this site (`true`/`false`).
        #[arg(long = "worker-mode", action = clap::ArgAction::Set)]
        worker_mode: bool,
        #[arg(long = "worker-count", default_value_t = 0)]
        worker_count: i64,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Regenerate one site's Caddyfile (and open-basedir.ini) from typed
    /// parameters, validate it inside the pool, swap it in, restart the
    /// site process and probe it — restoring the previous config if the
    /// restarted process never becomes ready. Under the shared stack lock.
    ActivateSiteConfig {
        #[arg(long = "runtime-id")]
        runtime_id: String,
        #[arg(long = "domain")]
        domain: String,
        #[arg(long = "port")]
        port: u16,
        /// The document root, used to regenerate `open-basedir.ini`.
        #[arg(long = "root")]
        root: String,
        /// Root-owned file holding the complete new Caddyfile contents
        /// (the panel edits this file textually, so it is opaque here and
        /// validated inside the pool before it can take effect).
        #[arg(long = "content-file")]
        content_file: PathBuf,
        /// 64 hex digits the live Caddyfile must currently hash to; omit
        /// for a first write that must not overwrite an existing file.
        #[arg(long = "expected-prior-hash")]
        expected_prior_hash: Option<String>,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Run one fixed probe (`applicationToken`, `opcacheStatus` or
    /// `opcacheReset`) against a site through its runtime pool: a short-lived
    /// PHP file in the site's webroot is fetched with `curl` and removed.
    ProbeSite {
        #[arg(long)]
        kind: String,
        /// `ingress` or `runtime-<runtime id>`.
        #[arg(long)]
        service: String,
        #[arg(long)]
        domain: String,
        /// The site's document root, below a content root.
        #[arg(long)]
        root: String,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Stop one site's s6-supervised process, remove its service directory
    /// under `siteServicesRoot` and drop it from the pool's s6-svscan, under
    /// the shared stack lock. A site with no service directory is a no-op.
    RemoveSiteService {
        #[arg(long = "runtime-id")]
        runtime_id: String,
        #[arg(long = "domain")]
        domain: String,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Install (`enabled`) or take out a site's custom 404 and 5xx pages: the
    /// two HTML files in `<root>/.wcp-errors` and the marked block in the
    /// site's process Caddyfile, as one operation that puts the files back if
    /// the config does not activate. The request (including the HTML) comes
    /// from a root-owned request file.
    SetErrorPages {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
}

impl StackCommand {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::Deploy { .. } => "stack.deploy",
            Self::ReloadCaddy { .. } => "stack.reloadCaddy",
            Self::StopIdleRuntime { .. } => "stack.stopIdleRuntime",
            Self::EnsureRuntime { .. } => "stack.ensureRuntime",
            Self::ReloadWorkers { .. } => "stack.reloadWorkers",
            Self::FlushFpc { .. } => "stack.flushFpc",
            Self::WriteSiteService { .. } => "stack.writeSiteService",
            Self::ActivateSiteConfig { .. } => "stack.activateSiteConfig",
            Self::RemoveSiteService { .. } => "stack.removeSiteService",
            Self::ProbeSite { .. } => "site.probe",
            Self::SetErrorPages { .. } => "site.setErrorPages",
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum ComposeCommand {
    /// Atomically replace one Compose stack's `docker-compose.yml`,
    /// validating the new content (`docker compose config`) before it can
    /// reach the live path and bringing the stack up (`docker compose up
    /// -d`) - restoring the previous file and bringing it back up if that
    /// fails.
    ActivateConfig {
        /// Which stack's compose file is being replaced.
        #[arg(long = "stack-name")]
        stack_name: String,

        /// Path to a file holding the complete new contents of the compose
        /// file. Whole-file replacement, not a patch.
        #[arg(long = "content-file")]
        content_file: PathBuf,

        /// The SHA-256 digest of the compose file's current contents, as an
        /// optimistic-concurrency precondition. Omit only when no file is
        /// expected to exist yet for this stack (asserts absence - fails if
        /// one is already there).
        #[arg(long = "expected-hash")]
        expected_hash: Option<String>,

        /// Canonical UUID identifying this specific attempt.
        #[arg(long = "request-id")]
        request_id: String,

        /// Caller-supplied token so a retried request returns the original
        /// outcome instead of activating twice.
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Run one lifecycle verb (`up`, `down`, `restart`, `pull`) on a stack
    /// under `~/compose` with a fixed argv. `down` needs
    /// `--confirmation COMPOSE_DOWN` and is refused for the managed hosting
    /// stack.
    Action {
        #[arg(long = "stack-name")]
        stack_name: String,
        #[arg(long)]
        action: String,
        #[arg(long)]
        confirmation: Option<String>,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Take a stack down and delete its directory under `~/compose`. Needs
    /// `--confirmation COMPOSE_REMOVE`; refused for the managed hosting
    /// stack.
    Remove {
        #[arg(long = "stack-name")]
        stack_name: String,
        #[arg(long)]
        confirmation: String,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
}

impl ComposeCommand {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::ActivateConfig { .. } => "compose.activateConfig",
            Self::Action { .. } => "compose.action",
            Self::Remove { .. } => "compose.remove",
        }
    }
}

impl RuntimeCommand {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::ActivateConfig { .. } => "runtime.activateConfig",
            Self::RemoveConfig { .. } => "runtime.removeConfig",
            Self::Reconcile { .. } => "runtime.reconcile",
        }
    }
}
