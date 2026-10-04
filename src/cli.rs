use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(name = "ops-engine", version, about)]
pub struct Cli {
    #[arg(long, value_enum, default_value_t = OutputFormat::Json, global = true)]
    pub output: OutputFormat,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    Json,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Backup artifact operations.
    Backup {
        #[command(subcommand)]
        command: BackupCommand,
    },
    /// Print engine and protocol version information.
    Version,

    /// List the operations and protocol features supported by this build.
    Capabilities,

    /// Inspect whether the current host can run planned operations.
    Doctor,

    /// Read durable mutation state without retrying the mutation.
    Operation {
        #[command(subcommand)]
        command: OperationCommand,
    },

    /// Site-scoped mutation operations.
    Site {
        #[command(subcommand)]
        command: SiteCommand,
    },

    /// Engine binary install/rollback operations.
    Engine {
        #[command(subcommand)]
        command: EngineCommand,
    },

    /// Ingress route-configuration operations.
    Ingress {
        #[command(subcommand)]
        command: IngressCommand,
    },

    /// Per-site runtime-service configuration operations.
    Runtime {
        #[command(subcommand)]
        command: RuntimeCommand,
    },

    /// Host crontab operations.
    Cron {
        #[command(subcommand)]
        command: CronCommand,
    },

    /// Database restore operations.
    Db {
        #[command(subcommand)]
        command: DbCommand,
    },

    /// Docker Compose stack configuration operations.
    Compose {
        #[command(subcommand)]
        command: ComposeCommand,
    },

    /// Controlled Meilisearch lifecycle operations.
    Meilisearch {
        #[command(subcommand)]
        command: MeilisearchCommand,
    },

    /// Host content ownership repair operations.
    Permissions {
        #[command(subcommand)]
        command: PermissionsCommand,
    },

    /// Bounded WordPress application operations.
    Wordpress {
        #[command(subcommand)]
        command: WordpressCommand,
    },

    /// Configuration for bundled host agents.
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },

    /// Host-wide system configuration operations.
    System {
        #[command(subcommand)]
        command: SystemCommand,
    },

    /// Managed WCP Compose stack operations.
    Stack {
        #[command(subcommand)]
        command: StackCommand,
    },
}

impl Command {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::Version => "version",
            Self::Capabilities => "capabilities",
            Self::Doctor => "doctor",
            Self::Operation { command } => command.operation(),
            Self::Backup { command } => command.operation(),
            Self::Site { command } => command.operation(),
            Self::Engine { command } => command.operation(),
            Self::Ingress { command } => command.operation(),
            Self::Runtime { command } => command.operation(),
            Self::Cron { command } => command.operation(),
            Self::Db { command } => command.operation(),
            Self::Compose { command } => command.operation(),
            Self::Meilisearch { command } => command.operation(),
            Self::Permissions { command } => command.operation(),
            Self::Wordpress { command } => command.operation(),
            Self::Agent { command } => command.operation(),
            Self::System { command } => command.operation(),
            Self::Stack { command } => command.operation(),
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum SystemCommand {
    /// Atomically activate the paired `unattended-upgrades` apt
    /// configuration under one lock/idempotency/transaction/audit-backed
    /// request.
    ActivateAutoupdatesConfig {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },

    /// Install the `unattended-upgrades` apt package under one lock/
    /// idempotency/transaction/audit-backed request.
    InstallAutoupdates {
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Install Docker Engine and Compose v2 from the official Docker apt
    /// repository on an allowlisted Debian/Ubuntu host, refusing any
    /// Docker from another source.
    InstallDocker {
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Start the host Docker service through a fixed platform action.
    StartDocker {
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Create, format, enable and persist the managed `/swapfile`.
    CreateSwap {
        #[arg(long = "size-mb")]
        size_mb: u32,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Disable and remove the managed `/swapfile` and its fstab entry.
    DeleteSwap {
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Replace the managed `/swapfile` with one of a new size, restoring
    /// the previous file when the replacement fails.
    ResizeSwap {
        #[arg(long = "size-mb")]
        size_mb: u32,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
}

impl SystemCommand {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::ActivateAutoupdatesConfig { .. } => "system.activateAutoupdatesConfig",
            Self::InstallAutoupdates { .. } => "system.installAutoupdates",
            Self::InstallDocker { .. } => "system.installDocker",
            Self::StartDocker { .. } => "system.startDocker",
            Self::CreateSwap { .. } => "system.createSwap",
            Self::DeleteSwap { .. } => "system.deleteSwap",
            Self::ResizeSwap { .. } => "system.resizeSwap",
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum OperationCommand {
    /// Return the last durable state for one site-scoped request.
    Status {
        #[arg(long = "site-id")]
        site_id: Option<String>,

        #[arg(long)]
        database: Option<String>,

        #[arg(long = "backup-database")]
        backup_database: Option<String>,

        /// A managed Compose stack; only `wcp` exists.
        #[arg(long)]
        stack: Option<String>,

        #[arg(long = "request-id")]
        request_id: String,
    },
}

impl OperationCommand {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::Status { .. } => "operation.status",
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum AgentCommand {
    /// Atomically replace the typed brute-force guard configuration.
    ActivateBruteforceConfig {
        #[arg(long = "request-file")]
        request_file: PathBuf,
    },
}

impl AgentCommand {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::ActivateBruteforceConfig { .. } => "agent.activateBruteforceConfig",
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum WordpressCommand {
    /// Import a bounded, SHA-256-verified WXR artifact as the site UID.
    Import {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Run one developer-defined cleanup action as the site's container user.
    Cleanup {
        #[arg(long = "request-file")]
        request_file: PathBuf,
    },
    /// Create a new WordPress site's content: core download, wp-config.php,
    /// object-cache wiring and `wp core install`, under one lock/
    /// idempotency/transaction/audit-backed request. The site's own
    /// directory must already exist beneath a configured content root
    /// (`website-control-panel`'s `create_site` creates and owns it).
    Install {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Clone a WordPress site's content and database into a fresh staging
    /// directory on the same server: content copy, database export/import
    /// and an ownership fix, under one lock/idempotency/transaction/audit-
    /// backed request.
    Clone {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Export one WordPress site (database dump + files archive + SHA-256
    /// manifest) for a cross-server migration. Never changes the site.
    MigrateExport {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Remove one migration export directory (it holds a full DB dump).
    MigrateDiscard {
        #[arg(long = "export-id")]
        export_id: String,
        #[arg(long = "request-id")]
        request_id: String,
    },
    /// Snapshot and update WordPress core through fixed WP-CLI argv.
    UpdateCore {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Snapshot and update selected WordPress plugins (or all plugins).
    UpdatePlugins {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Snapshot and update selected WordPress themes (or all themes).
    UpdateThemes {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Rotate a WordPress site's MariaDB credentials under one lock/
    /// idempotency/transaction/audit-backed request: generates a new
    /// password, applies it to MariaDB and to `wp-config.php`, verifies
    /// database connectivity, and reverts both back to the prior password
    /// if the update or the verification fails.
    RotateCredentials {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Delete one subsite from a WordPress multisite network under one
    /// lock/idempotency/transaction/audit-backed request.
    MultisiteDeleteSite {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Run one of a small fixed set of bounded WordPress mutations
    /// (multisite create-site, multisite set-mode, WooCommerce clear
    /// transients) under one lock/idempotency/transaction/audit-backed
    /// request.
    BoundedAction {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Install WP Mail SMTP and atomically write its relay constants to
    /// wp-config.php; the password arrives only in the root-owned request.
    SetSmtpRelay {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
}

impl WordpressCommand {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::Import { .. } => "wordpress.import",
            Self::Cleanup { .. } => "wordpress.cleanup",
            Self::Install { .. } => "wordpress.install",
            Self::Clone { .. } => "wordpress.clone",
            Self::MigrateExport { .. } => "wordpress.migrateExport",
            Self::MigrateDiscard { .. } => "wordpress.migrateDiscard",
            Self::UpdateCore { .. } => "wordpress.updateCore",
            Self::UpdatePlugins { .. } => "wordpress.updatePlugins",
            Self::UpdateThemes { .. } => "wordpress.updateThemes",
            Self::RotateCredentials { .. } => "wordpress.rotateCredentials",
            Self::MultisiteDeleteSite { .. } => "wordpress.multisiteDeleteSite",
            Self::BoundedAction { .. } => "wordpress.boundedAction",
            Self::SetSmtpRelay { .. } => "wordpress.setSmtpRelay",
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum MeilisearchCommand {
    /// Export, validate and blue/green migrate the managed Meilisearch service.
    Upgrade {
        /// Root-owned JSON request containing the guarded source version,
        /// exact target image, API key and representative search probes.
        #[arg(long = "request-file")]
        request_file: PathBuf,

        #[arg(long = "request-id")]
        request_id: String,

        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },

    /// Remove expired dump/source-volume recovery artifacts after verifying
    /// that their corresponding target volume is still active.
    Cleanup,
}

impl MeilisearchCommand {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::Upgrade { .. } => "meilisearch.upgrade",
            Self::Cleanup => "meilisearch.cleanup",
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum BackupCommand {
    /// Install the pinned, SHA-256-verified rclone release binary.
    InstallRclone {
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Copy and verify one remote artifact into the fixed imports directory.
    ImportRemote {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Atomically activate the remote-backup configuration bundle.
    ActivateConfig {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Run the installed remote-backup agent immediately.
    TriggerNow {
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Stream a database dump into the managed backup root.
    CreateDatabase {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Delete one file constrained beneath the managed backup root.
    Delete {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
}

impl BackupCommand {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::InstallRclone { .. } => "backup.installRclone",
            Self::ImportRemote { .. } => "backup.importRemote",
            Self::ActivateConfig { .. } => "backup.activateConfig",
            Self::TriggerNow { .. } => "backup.triggerNow",
            Self::CreateDatabase { .. } => "backup.createDatabase",
            Self::Delete { .. } => "backup.delete",
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum PermissionsCommand {
    /// Restore the declared owner of each managed content tree.
    FixOwnership {
        /// Root-owned JSON file containing the typed ownership plan.
        #[arg(long = "owners-file")]
        owners_file: PathBuf,

        #[arg(long = "request-id")]
        request_id: String,

        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },

    /// Remove the world-writable bit from managed content.
    FixWorldWritable {
        /// Configured content root to harden.
        #[arg(long = "root")]
        root: PathBuf,

        #[arg(long = "request-id")]
        request_id: String,

        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
}

impl PermissionsCommand {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::FixOwnership { .. } => "permissions.fixOwnership",
            Self::FixWorldWritable { .. } => "permissions.fixWorldWritable",
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum SiteCommand {
    /// Deploy a resolved Git revision for one site.
    Deploy {
        #[arg(long = "site-id")]
        site_id: String,

        /// A full Git object ID already resolved from an allowed branch.
        #[arg(long)]
        revision: String,

        /// Canonical UUID identifying this specific attempt. The caller
        /// mints this, not the engine — see `docs/site-model.md`.
        #[arg(long = "request-id")]
        request_id: String,

        /// Caller-supplied token so a retried request returns the original
        /// outcome instead of deploying twice.
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },

    /// Switch a site back to a previously retained release.
    Rollback {
        #[arg(long = "site-id")]
        site_id: String,

        /// A retained release identifier previously returned by
        /// `site deploy` or `site rollback` as `releaseId`. Not trusted as
        /// authorization by itself — the engine only accepts a release it
        /// itself still retains for this site.
        #[arg(long)]
        release: String,

        /// Canonical UUID identifying this specific attempt. The caller
        /// mints this, not the engine — see `docs/site-model.md`.
        #[arg(long = "request-id")]
        request_id: String,

        /// Caller-supplied token so a retried request returns the original
        /// outcome instead of rolling back twice.
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },

    /// Rename a site's content directory from `<content root>/<from>` to
    /// `<content root>/<to>` (a single rename(2) inside one content root),
    /// refusing a missing source or an existing target.
    MoveRoot {
        #[arg(long = "from-domain")]
        from_domain: String,
        #[arg(long = "to-domain")]
        to_domain: String,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
}

impl SiteCommand {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::Deploy { .. } => "site.deploy",
            Self::Rollback { .. } => "site.rollback",
            Self::MoveRoot { .. } => "site.moveRoot",
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum EngineCommand {
    /// Fetch, verify, and atomically activate a specific published
    /// engine version.
    Install {
        #[arg(long)]
        version: String,

        /// Canonical UUID identifying this specific attempt. The caller
        /// mints this, not the engine — see `docs/site-model.md`.
        #[arg(long = "request-id")]
        request_id: String,

        /// Caller-supplied token so a retried request returns the
        /// original outcome instead of installing twice.
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },

    /// Atomically switch back to the one retained previous engine
    /// version, without a network call.
    Rollback {
        #[arg(long = "request-id")]
        request_id: String,

        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
}

impl EngineCommand {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::Install { .. } => "engine.install",
            Self::Rollback { .. } => "engine.rollback",
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum IngressCommand {
    /// Atomically replace one domain's live ingress route file, validating
    /// the new content before it can reach the live path and restoring the
    /// previous content if the live reload rejects it.
    ActivateConfig {
        /// The domain whose route file is being replaced. The engine
        /// derives the file name from it (`<domain>.caddyfile`).
        #[arg(long)]
        domain: String,

        /// Path to a file holding the complete new contents of the route
        /// file. Whole-file replacement, not a patch: read the current
        /// file, transform it, and pass the result here.
        #[arg(long = "content-file")]
        content_file: PathBuf,

        /// The SHA-256 digest of the route file's current live contents,
        /// as an optimistic-concurrency precondition. Omit only when no
        /// config is expected to exist yet for this domain (asserts
        /// absence — fails if one is already live). To update an existing
        /// config, pass its current content hash.
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

        /// Which of this domain's two route files to write: `live` (the
        /// imported, Caddy-validated Caddyfile — today's only behavior) or
        /// `backup` (the inert `.maintenance-backup` file a parked domain's
        /// pre-maintenance config is kept in; no validation or reload).
        #[arg(long, value_enum, default_value_t = IngressTarget::Live)]
        target: IngressTarget,
    },

    /// Snapshots a domain's live route file to its maintenance-backup and
    /// activates a maintenance page in its place.
    Park {
        #[arg(long)]
        domain: String,

        /// Path to a file holding the complete contents of the maintenance
        /// page route file to put live in place of the domain's current
        /// configuration.
        #[arg(long = "content-file")]
        content_file: PathBuf,

        /// Canonical UUID identifying this specific attempt. The caller
        /// mints this, not the engine — see `docs/site-model.md`.
        #[arg(long = "request-id")]
        request_id: String,

        /// Caller-supplied token so a retried request returns the original
        /// outcome instead of parking twice.
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },

    /// Restores a parked domain's route file from its maintenance-backup and
    /// removes the backup.
    Unpark {
        #[arg(long)]
        domain: String,

        /// Canonical UUID identifying this specific attempt. The caller
        /// mints this, not the engine — see `docs/site-model.md`.
        #[arg(long = "request-id")]
        request_id: String,

        /// Caller-supplied token so a retried request returns the original
        /// outcome instead of unparking twice.
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },

    /// Sweeps the whole configured ingress root for `.tmp`/`.tmp-*`
    /// staging siblings and `.rollback-*` backup siblings left behind by
    /// an interrupted activate/park/unpark attempt, removing or restoring
    /// each. No `--domain` - this is a whole-root sweep, not a per-site
    /// operation.
    Reconcile {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum IngressTarget {
    Live,
    Backup,
}

impl IngressCommand {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::ActivateConfig { .. } => "ingress.activateConfig",
            Self::Park { .. } => "ingress.park",
            Self::Unpark { .. } => "ingress.unpark",
            Self::Reconcile { .. } => "ingress.reconcile",
        }
    }
}

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
}

impl ComposeCommand {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::ActivateConfig { .. } => "compose.activateConfig",
        }
    }
}

impl RuntimeCommand {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::ActivateConfig { .. } => "runtime.activateConfig",
            Self::Reconcile { .. } => "runtime.reconcile",
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum CronCommand {
    /// Atomically replace the engine's own host user's crontab.
    InstallTab {
        /// Host user whose crontab is replaced. Omit for the engine user.
        #[arg(long = "user")]
        user: Option<String>,

        /// Path to a file holding the complete new crontab contents.
        #[arg(long = "content-file")]
        content_file: PathBuf,

        /// The SHA-256 digest of the crontab's current contents, as an
        /// optimistic-concurrency precondition. Omit only when no crontab
        /// is expected to exist yet (asserts absence).
        #[arg(long = "expected-hash")]
        expected_hash: Option<String>,

        /// Canonical UUID identifying this specific attempt.
        #[arg(long = "request-id")]
        request_id: String,

        /// Caller-supplied token so a retried request returns the original
        /// outcome instead of installing twice.
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
}

impl CronCommand {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::InstallTab { .. } => "cron.installTab",
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum DbCommand {
    /// Export a database through a fixed client invocation.
    Export {
        #[arg(long = "request-file")]
        request_file: PathBuf,
    },
    /// Converge a protected database administration tool container.
    ToolConverge {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Remove a protected database administration tool and its ingress route.
    ToolRemove {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Create or converge a MariaDB database and optional isolated user.
    ProvisionMariadb {
        /// Root-owned JSON request containing identifiers and credentials.
        #[arg(long = "request-file")]
        request_file: PathBuf,

        #[arg(long = "request-id")]
        request_id: String,

        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Drop a non-system MariaDB database through a fixed client invocation.
    DropMariadb {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Drop a non-system MariaDB account through a fixed client invocation.
    DropMariadbUser {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Clear the configured MariaDB slow-query log and restore its enabled state.
    ClearMariadbSlowLog {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Enable or disable MariaDB slow logging with an optional threshold.
    ConfigureMariadbSlowLog {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Delete one bounded Valkey key without placing it in process argv.
    DeleteValkeyKey {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Asynchronously flush the selected Valkey database after explicit confirmation.
    FlushValkeyDb {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Asynchronously flush every Valkey database after explicit confirmation.
    FlushAllValkey {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Create a PostgreSQL database through a fixed psql invocation.
    ProvisionPostgres {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Drop a non-system PostgreSQL database and force-close its sessions.
    DropPostgres {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Create a PostgreSQL login role and optionally grant database access.
    ProvisionPostgresUser {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Drop a non-system PostgreSQL role.
    DropPostgresUser {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },

    /// Runs a database client against an already-on-disk dump file.
    /// Audit-trail only - no snapshot, no rollback; the dump either
    /// imports cleanly or it doesn't, the same as the raw command this
    /// replaces.
    Restore {
        #[arg(long = "db-type", value_enum)]
        db_type: DbTypeArg,

        #[arg(long)]
        database: String,

        /// The Docker container/service running the database.
        #[arg(long)]
        container: String,

        /// Path to the dump file on this host - not staged or copied,
        /// read directly by the database client.
        #[arg(long = "file-path")]
        file_path: String,

        #[arg(long = "root-password")]
        root_password: String,

        /// Canonical UUID identifying this specific attempt.
        #[arg(long = "request-id")]
        request_id: String,

        /// Caller-supplied token so a retried request returns the original
        /// outcome instead of restoring twice.
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum DbTypeArg {
    Mariadb,
    Postgres,
}

impl DbCommand {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::Export { .. } => "db.export",
            Self::ToolConverge { .. } => "dbTool.converge",
            Self::ToolRemove { .. } => "dbTool.remove",
            Self::ProvisionMariadb { .. } => "db.provisionMariaDb",
            Self::DropMariadb { .. } => "db.dropMariaDb",
            Self::DropMariadbUser { .. } => "db.dropMariaDbUser",
            Self::ClearMariadbSlowLog { .. } => "db.clearMariaSlowLog",
            Self::ConfigureMariadbSlowLog { .. } => "db.configureMariaSlowLog",
            Self::DeleteValkeyKey { .. } => "db.deleteValkeyKey",
            Self::FlushValkeyDb { .. } => "db.flushValkeyDb",
            Self::FlushAllValkey { .. } => "db.flushAllValkey",
            Self::ProvisionPostgres { .. } => "db.provisionPostgres",
            Self::DropPostgres { .. } => "db.dropPostgres",
            Self::ProvisionPostgresUser { .. } => "db.provisionPostgresUser",
            Self::DropPostgresUser { .. } => "db.dropPostgresUser",
            Self::Restore { .. } => "db.restore",
        }
    }
}
