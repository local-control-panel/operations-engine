use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};

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
    /// Move the databases and accounts to another MariaDB line's service and
    /// give that server the old service name.
    MigrateMariadbLine {
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
    /// Create a site's Valkey user (or give it a new password). The password
    /// is returned once as a secret result.
    ProvisionValkeySite {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: String,
    },
    /// Remove a site's Valkey keys and its user.
    RevokeValkeySite {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Move a site's Valkey user to a new domain name: same database, same
    /// password, new user name.
    RenameValkeySite {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Remove a site's Valkey keys (the user stays).
    FlushValkeySite {
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

    /// Read bounded recovery metadata for an original protected restore.
    RestoreRecoveryInfo {
        #[arg(long)]
        database: String,
        #[arg(long = "original-request-id")]
        original_request_id: String,
    },
    /// Offline restore with a private snapshot and compensation on a rejected import.
    RestoreProtected {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: String,
    },
    /// Recover a protected restore only after the original client has stopped.
    RecoverRestore {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: String,
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
            Self::MigrateMariadbLine { .. } => "db.migrateMariadbLine",
            Self::DropMariadb { .. } => "db.dropMariaDb",
            Self::DropMariadbUser { .. } => "db.dropMariaDbUser",
            Self::ClearMariadbSlowLog { .. } => "db.clearMariaSlowLog",
            Self::ConfigureMariadbSlowLog { .. } => "db.configureMariaSlowLog",
            Self::DeleteValkeyKey { .. } => "db.deleteValkeyKey",
            Self::FlushValkeyDb { .. } => "db.flushValkeyDb",
            Self::FlushAllValkey { .. } => "db.flushAllValkey",
            Self::ProvisionValkeySite { .. } => "db.provisionValkeySite",
            Self::RevokeValkeySite { .. } => "db.revokeValkeySite",
            Self::FlushValkeySite { .. } => "db.flushValkeySite",
            Self::RenameValkeySite { .. } => "db.renameValkeySite",
            Self::ProvisionPostgres { .. } => "db.provisionPostgres",
            Self::DropPostgres { .. } => "db.dropPostgres",
            Self::ProvisionPostgresUser { .. } => "db.provisionPostgresUser",
            Self::DropPostgresUser { .. } => "db.dropPostgresUser",
            Self::Restore { .. } => "db.restore",
            Self::RestoreRecoveryInfo { .. } => "db.restoreRecoveryInfo",
            Self::RestoreProtected { .. } => "db.restoreProtected",
            Self::RecoverRestore { .. } => "db.recoverRestore",
        }
    }
}
