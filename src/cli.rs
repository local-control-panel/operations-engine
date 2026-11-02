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

    /// Typed Drupal application operations (Drush with a fixed argv).
    Drupal {
        #[command(subcommand)]
        command: DrupalCommand,
    },

    /// Typed Joomla application operations.
    Joomla {
        #[command(subcommand)]
        command: JoomlaCommand,
    },

    /// Typed CMS application operations that are not tied to one CMS's own
    /// command group.
    Cms {
        #[command(subcommand)]
        command: CmsCommand,
    },

    /// Host-managed tools (pinned, SHA-256-verified) mounted into runtime
    /// containers.
    Tool {
        #[command(subcommand)]
        command: ToolCommand,
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

    /// The server-side change journal (who changed what, when, with which
    /// result). Never carries secrets or one-time links.
    #[command(name = "change-log")]
    Journal {
        #[command(subcommand)]
        command: JournalCommand,
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
            Self::Drupal { command } => command.operation(),
            Self::Joomla { command } => command.operation(),
            Self::Cms { command } => command.operation(),
            Self::Tool { command } => command.operation(),
            Self::Agent { command } => command.operation(),
            Self::System { command } => command.operation(),
            Self::Stack { command } => command.operation(),
            Self::Journal { command } => command.operation(),
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum JournalCommand {
    /// Append one change event. The engine assigns `seq` and the time; the
    /// request id is the entry id, so a retry returns the original entry.
    Append {
        /// Who made the change (panel user id or email, 1-64 chars).
        #[arg(long)]
        actor: String,
        /// Namespaced action, e.g. `cms.adminLogin` or `wordpress.updateCore`.
        #[arg(long)]
        action: String,
        /// `ok`, `failed`, `denied` or `cancelled`.
        #[arg(long)]
        result: String,
        #[arg(long)]
        site: Option<String>,
        /// Network subsite (WordPress multisite and similar).
        #[arg(long)]
        subsite: Option<String>,
        /// `production`, `staging` or `development`.
        #[arg(long)]
        environment: Option<String>,
        /// The panel operation this event belongs to.
        #[arg(long = "operation-id")]
        operation_id: Option<String>,
        /// The thing acted on, e.g. an admin user name. Never a link.
        #[arg(long)]
        target: Option<String>,
        #[arg(long = "error-code")]
        error_code: Option<String>,
        /// Short redacted note (200 chars); rejected if it looks like a URL
        /// or a secret.
        #[arg(long, allow_hyphen_values = true)]
        summary: Option<String>,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// List change events, newest first (read-only).
    List {
        #[arg(long)]
        site: Option<String>,
        #[arg(long)]
        subsite: Option<String>,
        #[arg(long)]
        environment: Option<String>,
        /// Only events at or after this Unix time (seconds).
        #[arg(long)]
        since: Option<u64>,
        /// Only actions starting with this text, e.g. `cms.`.
        #[arg(long = "action-prefix")]
        action_prefix: Option<String>,
        #[arg(long)]
        result: Option<String>,
        /// `api` (site.changeLog.append) or `engine` (written by the engine).
        #[arg(long)]
        source: Option<String>,
        /// Page size; defaults to 50 and is clamped to 200.
        #[arg(long)]
        limit: Option<usize>,
        /// Only events older than this `seq` (the previous `nextCursor`).
        #[arg(long = "before-seq")]
        before_seq: Option<u64>,
    },
}

impl JournalCommand {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::Append { .. } => "site.changeLog.append",
            Self::List { .. } => "site.changeLog.list",
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum ToolCommand {
    /// Install the pinned release of a catalog tool (e.g. `wp-cli`).
    Install {
        #[arg(long)]
        tool: String,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Remove an installed catalog tool.
    Remove {
        #[arg(long)]
        tool: String,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Report every catalog tool: pinned/installed version, selection, integrity.
    Status,
}

impl ToolCommand {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::Install { .. } => "tool.install",
            Self::Remove { .. } => "tool.remove",
            Self::Status => "tool.status",
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum DrupalCommand {
    /// Run `drush cache:rebuild` as the site user under one
    /// lock/idempotency/transaction/audit-backed request.
    CacheRebuild {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Run Drupal cron (`drush core:cron`) as the site user under one
    /// lock/idempotency/transaction/audit-backed request.
    CronRun {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Set `automated_cron.settings:interval` through Drush `config:set`
    /// (default `0` = off, or the `interval` of the request to restore it);
    /// returns the previous and the new value and does nothing when equal.
    AutomatedCron {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Install Drush into the site's Composer project
    /// (`composer require drush/drush` with the engine-managed Composer) as
    /// the site user.
    InstallDrush {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Apply pending database updates (`drush updatedb`) when
    /// `updatedb:status` lists any, and verify none remain.
    UpdateDb {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Turn maintenance mode on or off (explicit `state` in the request)
    /// and verify the mode Drupal reports afterwards.
    Maintenance {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Read the newest entries of Drupal's database log
    /// (`drush watchdog:show`): bounded, optionally filtered by severity and
    /// type, with messages redacted (read-only).
    Watchdog {
        #[arg(long = "request-file")]
        request_file: PathBuf,
    },
    /// Clone a Drupal site's files and database into a staging directory on
    /// the same server, with its own database credentials, a new hash salt
    /// and the chosen safety defaults, under one lock/idempotency/
    /// transaction/audit-backed request.
    Clone {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
}

impl DrupalCommand {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::CacheRebuild { .. } => "drupal.cacheRebuild",
            Self::CronRun { .. } => "drupal.cronRun",
            Self::AutomatedCron { .. } => "drupal.automatedCron",
            Self::Maintenance { .. } => "drupal.maintenance",
            Self::InstallDrush { .. } => "drupal.installDrush",
            Self::UpdateDb { .. } => "drupal.updateDb",
            Self::Watchdog { .. } => "drupal.watchdog",
            Self::Clone { .. } => "drupal.clone",
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum JoomlaCommand {
    /// Clone a Joomla 4+ site's files and database into a staging directory
    /// on the same server, with its own database credentials, a new secret
    /// and the chosen safety defaults, under one lock/idempotency/
    /// transaction/audit-backed request.
    Clone {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
}

impl JoomlaCommand {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::Clone { .. } => "joomla.clone",
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum CmsCommand {
    /// Clear the application caches of a Laravel project with artisan's
    /// own `optimize:clear` (fixed argv, site user).
    ClearCache {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Turn maintenance mode on or off for a Joomla (`site:down`/`site:up`)
    /// or Laravel (`artisan down --secret`/`up`) project; explicit `state`
    /// in the request.
    Maintenance {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Safe mode ("disable all extensions") for WordPress (all plugins off,
    /// saved list, exact restore) and Drupal (maintenance on, module list
    /// only); `state` is `on`, `off` or `status` in the request.
    SafeMode {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
}

impl CmsCommand {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::ClearCache { .. } => "cms.clearCache",
            Self::Maintenance { .. } => "cms.maintenance",
            Self::SafeMode { .. } => "cms.safeMode",
        }
    }
}

mod agent;
mod data;
mod ingress;
mod site;
mod stack;
mod system;
mod wordpress;

pub use agent::*;
pub use data::*;
pub use ingress::*;
pub use site::*;
pub use stack::*;
pub use system::*;
pub use wordpress::*;
