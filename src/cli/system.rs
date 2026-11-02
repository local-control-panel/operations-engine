use std::path::PathBuf;

use clap::Subcommand;

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
    /// Prune unused Docker resources of one kind (`image`, `volume` or
    /// `system`) under a fixed argv, after the kind's exact confirmation
    /// token. The engine-managed `wcp` stack is never a candidate.
    PruneDocker {
        #[arg(long)]
        kind: String,
        #[arg(long)]
        confirmation: String,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Run one lifecycle verb (`start`, `stop`, `restart`, `pause`, `unpause`,
    /// `remove`) on a container named by hex id. Containers of the managed
    /// `wcp` stack take the stack lock and cannot be removed; `stop`,
    /// `restart` and `remove` need their exact confirmation token.
    ContainerAction {
        #[arg(long = "container-id")]
        container_id: String,
        #[arg(long)]
        action: String,
        /// Force removal of a running container (`remove` only). Takes an
        /// explicit value (`--force true`) so that every argument is a
        /// name/value pair, as the panel's argv builder emits them.
        #[arg(long, action = clap::ArgAction::Set, default_value_t = false)]
        force: bool,
        #[arg(long)]
        confirmation: Option<String>,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Set the runtime CPU, memory and restart-policy limits of a container,
    /// bound by the host's cores and RAM. Runtime-only: lost when Compose
    /// recreates the container.
    SetContainerLimits {
        #[arg(long = "container-id")]
        container_id: String,
        /// CPU count; `0` clears the limit.
        #[arg(long)]
        cpus: f64,
        /// Memory in bytes; `0` clears the limit.
        #[arg(long = "memory-bytes")]
        memory_bytes: u64,
        #[arg(long = "restart-policy")]
        restart_policy: Option<String>,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Create or remove a Docker network. Removal needs its confirmation
    /// token and refuses the built-in networks and the managed `wcp` stack's.
    DockerNetwork {
        /// `create` or `remove`.
        #[arg(long)]
        action: String,
        #[arg(long)]
        name: String,
        /// `bridge` (default), `overlay`, `host`, `macvlan` or `none`;
        /// `create` only.
        #[arg(long)]
        driver: Option<String>,
        #[arg(long)]
        confirmation: Option<String>,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Pull an image from an allowlisted registry, refusing to start with
    /// little free space under Docker's root directory.
    PullImage {
        #[arg(long)]
        reference: String,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Remove an image named by hex id, refusing one that a container of the
    /// managed `wcp` stack was created from.
    RemoveImage {
        #[arg(long = "image-id")]
        image_id: String,
        /// Explicit value (`--force true`), as every argument is a pair.
        #[arg(long, action = clap::ArgAction::Set, default_value_t = false)]
        force: bool,
        #[arg(long)]
        confirmation: Option<String>,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Remove a Docker volume, refusing one that is attached to a container
    /// or belongs to the managed `wcp` stack.
    RemoveVolume {
        #[arg(long = "volume-name")]
        volume_name: String,
        #[arg(long)]
        confirmation: Option<String>,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Start or restart the `netdata` or `docker` systemd unit and verify it
    /// is active afterwards.
    Service {
        #[arg(long)]
        unit: String,
        #[arg(long)]
        action: String,
        #[arg(long)]
        confirmation: Option<String>,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Send one allowlisted signal to a verified, non-protected process.
    SignalProcess {
        #[arg(long)]
        pid: u32,
        /// `TERM` (default), `KILL`, `HUP` or `INT`.
        #[arg(long)]
        signal: Option<String>,
        /// Refuse unless the process still has this `comm` name.
        #[arg(long = "expect-comm")]
        expect_comm: Option<String>,
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
            Self::PruneDocker { .. } => "docker.prune",
            Self::ContainerAction { .. } => "docker.containerAction",
            Self::SetContainerLimits { .. } => "docker.setLimits",
            Self::DockerNetwork { .. } => "docker.network",
            Self::PullImage { .. } => "docker.imagePull",
            Self::RemoveImage { .. } => "docker.imageRemove",
            Self::RemoveVolume { .. } => "docker.volumeRemove",
            Self::Service { .. } => "system.service",
            Self::SignalProcess { .. } => "system.signalProcess",
            Self::CreateSwap { .. } => "system.createSwap",
            Self::DeleteSwap { .. } => "system.deleteSwap",
            Self::ResizeSwap { .. } => "system.resizeSwap",
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum OperationCommand {
    /// Read one known operation family's durable record without executing it.
    ResourceStatus {
        #[arg(long = "resource-operation")]
        resource_operation: String,
        #[arg(long)]
        resource: String,
        #[arg(long = "request-id")]
        request_id: String,
    },
    /// Return the last durable state for one site-scoped request.
    Status {
        #[arg(long = "site-id")]
        site_id: Option<String>,
        #[arg(long = "create-domain")]
        create_domain: Option<String>,

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
    /// Find interrupted transactions and recovery markers in every scope.
    Incomplete,
    /// List the newest durable transactions of one scope, redacted.
    List {
        #[arg(long = "site-id")]
        site_id: Option<String>,
        #[arg(long = "create-domain")]
        create_domain: Option<String>,

        #[arg(long)]
        database: Option<String>,

        #[arg(long = "backup-database")]
        backup_database: Option<String>,

        /// A managed Compose stack; only `wcp` exists.
        #[arg(long)]
        stack: Option<String>,

        /// Page size; defaults to 20 and is clamped to 100.
        #[arg(long)]
        limit: Option<usize>,
    },
}

impl OperationCommand {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::Status { .. } => "operation.status",
            Self::ResourceStatus { .. } => "operation.resourceStatus",
            Self::List { .. } => "operation.list",
            Self::Incomplete => "operation.incomplete",
        }
    }
}
