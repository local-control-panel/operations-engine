use std::path::PathBuf;

use clap::Subcommand;

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
    /// (`orbden`'s `create_site` creates and owns it).
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
    /// Import a migration export (verified against its manifest) into a
    /// destination site, snapshotting and restoring it on failure.
    MigrateImport {
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
    /// Drop an explicit list of orphaned tables, each re-validated against
    /// the site's prefix and the set WordPress registers, under one
    /// lock/idempotency/transaction/audit-backed request.
    DropTables {
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
    /// Rotate `wp-content/debug.log` (rename-based, bounded copies, fresh
    /// file with the same owner and mode) without reading its contents.
    RotateDebugLog {
        #[arg(long)]
        path: String,
        #[arg(long)]
        keep: Option<u32>,
        /// Gzip the rotated copy to `debug.log.1.gz` (the plain copy is kept
        /// if compression fails).
        #[arg(long)]
        compress: bool,
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
            Self::MigrateImport { .. } => "wordpress.migrateImport",
            Self::UpdateCore { .. } => "wordpress.updateCore",
            Self::UpdatePlugins { .. } => "wordpress.updatePlugins",
            Self::UpdateThemes { .. } => "wordpress.updateThemes",
            Self::RotateCredentials { .. } => "wordpress.rotateCredentials",
            Self::MultisiteDeleteSite { .. } => "wordpress.multisiteDeleteSite",
            Self::DropTables { .. } => "wordpress.dropTables",
            Self::BoundedAction { .. } => "wordpress.boundedAction",
            Self::SetSmtpRelay { .. } => "wordpress.setSmtpRelay",
            Self::RotateDebugLog { .. } => "wordpress.rotateDebugLog",
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
    /// Schedule a database backup without a secret in the crontab.
    ScheduleDatabase {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Remove a scheduled database backup and its stored credentials.
    UnscheduleDatabase {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// List scheduled database backups with passwords redacted.
    ListScheduled,
    /// Run one scheduled database backup. Invoked by cron, not by a client.
    RunScheduled {
        #[arg(long = "db-type")]
        db_type: String,
        #[arg(long)]
        database: String,
        #[arg(long = "retention-days")]
        retention_days: u16,
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
            Self::ScheduleDatabase { .. } => "backup.scheduleDatabase",
            Self::UnscheduleDatabase { .. } => "backup.unscheduleDatabase",
            Self::ListScheduled => "backup.listScheduledDatabase",
            Self::RunScheduled { .. } => "backup.runScheduledDatabase",
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
