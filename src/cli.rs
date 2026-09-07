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
    /// Print engine and protocol version information.
    Version,

    /// List the operations and protocol features supported by this build.
    Capabilities,

    /// Inspect whether the current host can run planned operations.
    Doctor,

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
}

impl Command {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::Version => "version",
            Self::Capabilities => "capabilities",
            Self::Doctor => "doctor",
            Self::Site { command } => command.operation(),
            Self::Engine { command } => command.operation(),
            Self::Ingress { command } => command.operation(),
            Self::Runtime { command } => command.operation(),
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
}

impl SiteCommand {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::Deploy { .. } => "site.deploy",
            Self::Rollback { .. } => "site.rollback",
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
}

impl RuntimeCommand {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::ActivateConfig { .. } => "runtime.activateConfig",
        }
    }
}
