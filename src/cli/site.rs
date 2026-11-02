use std::path::PathBuf;

use clap::Subcommand;

#[derive(Debug, Subcommand)]
pub enum SiteCommand {
    /// List the sites on this server (read-only).
    List,
    /// List a site's administrators (ids and logins, at most 50; read-only).
    AdminUsers {
        #[arg(long = "request-file")]
        request_file: PathBuf,
    },
    /// Issue a short-lived, single-use login link for one administrator. The
    /// link is returned once (`secretResult`) and is never stored.
    AdminLogin {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        /// Required: a replay returns "already issued", never the link.
        #[arg(long = "idempotency-key")]
        idempotency_key: String,
    },
    /// Resolve an interrupted deploy/rollback without repeating the mutation.
    RecoverDeployment {
        #[arg(long = "site-id")]
        site_id: String,
        #[arg(long = "request-id")]
        request_id: String,
    },
    /// Publish a prebuilt static directory without running build scripts.
    PublishStatic {
        #[arg(long)]
        request_file: PathBuf,
        #[arg(long)]
        request_id: String,
        #[arg(long)]
        idempotency_key: String,
    },
    StaticStatus {
        #[arg(long)]
        domain: String,
        #[arg(long)]
        request_id: String,
    },
    RecoverStatic {
        #[arg(long)]
        domain: String,
        #[arg(long)]
        request_id: String,
    },
    /// Create a PHP site as one server-owned, recoverable operation.
    Create {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: String,
    },
    /// Compensate an interrupted site creation, or record its verified success.
    RecoverCreate {
        #[arg(long)]
        domain: String,
        #[arg(long = "request-id")]
        request_id: String,
    },
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

    /// Create a new site's content directory
    /// `<content root>/<domain>[/<relative root>]` and give the final
    /// directory to the site identity (mode 0700). Refuses symlinks,
    /// system uids/gids and an existing non-empty directory owned by
    /// anyone else; nothing is changed recursively.
    PrepareRoot {
        #[arg(long)]
        domain: String,
        /// Directory below the site directory that becomes the root, e.g.
        /// `public`. Omit for the site directory itself.
        #[arg(long = "relative-root")]
        relative_root: Option<String>,
        #[arg(long)]
        uid: u32,
        #[arg(long)]
        gid: u32,
        /// What to do with an existing non-empty directory owned by
        /// someone else: `refuse` (default), `adopt-directory` (hand over
        /// the directory only) or `adopt-tree` (hand over everything below
        /// it too, without following symlinks).
        #[arg(long)]
        existing: Option<String>,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },

    /// Replace an environment file (`.env`, `*.env`, `.env.*`) below a site
    /// directory of a content root, atomically, keeping an existing file's
    /// owner and mode. The content comes from a root-owned request file.
    WriteEnvFile {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Start or end a phpinfo session in a site directory: a
    /// `_phpinfo_<token>.php` page that expires and deletes itself.
    PhpInfoSession {
        /// `enable` or `disable`.
        #[arg(long)]
        action: String,
        /// Absolute path of a site directory below a content root.
        #[arg(long)]
        directory: String,
        /// Lifetime for `enable`, 1 to 240 minutes.
        #[arg(long = "ttl-minutes")]
        ttl_minutes: Option<u32>,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Move a file below a site directory of a content root into the
    /// engine's quarantine directory, with a manifest.
    QuarantineFile {
        #[arg(long)]
        path: String,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },

    /// Delete a site's directory `<content root>/<domain>` and, with
    /// `--site-id`, its engine release tree. Refuses symlinks, system-owned
    /// directories, oversized trees and (without `--confirm-contents true`)
    /// non-empty directories.
    RemoveRoot {
        #[arg(long)]
        domain: String,
        /// Remove only this directory below the site directory (and the
        /// site directory itself if that leaves it empty). Omit to remove
        /// the whole site directory.
        #[arg(long = "relative-root")]
        relative_root: Option<String>,
        #[arg(long = "site-id")]
        site_id: Option<String>,
        /// Confirm that deleting a non-empty directory is intended
        /// (`true`/`false`).
        #[arg(long = "confirm-contents", action = clap::ArgAction::Set)]
        confirm_contents: bool,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },

    /// Give everything left in a deleted site's directory (and, with
    /// `--site-id`, its release tree) to root:root, so a freed numeric uid
    /// keeps no access. Same safe walk as `permissions fix-ownership`.
    ReleaseRoot {
        #[arg(long)]
        domain: String,
        #[arg(long = "site-id")]
        site_id: Option<String>,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },

    /// Point a site's engine manifest at its new domain after a panel
    /// rename. Only `domain` changes; a repeat for the same domain is a
    /// no-op and the result names the previous domain for a rollback.
    RenameManifest {
        #[arg(long = "site-id")]
        site_id: String,
        #[arg(long)]
        domain: String,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Write a git-deploy site's engine manifest and deploy key from a
    /// staged, root-owned request file (the key never travels as an
    /// argument). A repeat with identical content is a no-op.
    Enroll {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Remove a site's engine manifest and deploy key. Missing files are
    /// success.
    Unenroll {
        #[arg(long = "site-id")]
        site_id: String,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Make sure a site has its Unix account, a loopback port in the pool
    /// and an identity record. Creates the account with the next id from a
    /// monotonic counter that never reuses an id, or reuses the site's
    /// existing managed account (`--os-user`, for a runtime migration).
    /// Under the shared stack lock; idempotent.
    AllocateIdentity {
        #[arg(long = "runtime-id")]
        runtime_id: String,
        #[arg(long)]
        domain: String,
        /// An existing `wcp-site-<16 hex>` account to reuse instead of the
        /// one derived from the domain.
        #[arg(long = "os-user")]
        os_user: Option<String>,
        /// The site's document root, under a content root.
        #[arg(long)]
        root: String,
        /// FrankenPHP worker mode (`true`/`false`).
        #[arg(long = "worker-mode", action = clap::ArgAction::Set)]
        worker_mode: bool,
        #[arg(long = "worker-count")]
        worker_count: i64,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Remove a site's identity record from a pool and, with
    /// `--remove-user true`, its account when no other record uses it and
    /// its service directory is gone. A missing record is success.
    ReleaseIdentity {
        #[arg(long = "runtime-id")]
        runtime_id: String,
        #[arg(long)]
        domain: String,
        #[arg(long = "remove-user", action = clap::ArgAction::Set)]
        remove_user: bool,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Archive one site root (SHA-256 manifest) for a server-to-server sync.
    /// Never changes the site.
    ExportArchive {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Replace a site root with a verified archive, keeping the previous state
    /// as a snapshot and restoring it on failure.
    ImportArchive {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Remove one site archive export, one destination snapshot, or all stale
    /// exports.
    DiscardArchive {
        /// `export`, `snapshot`, or `stale` (every export past 24 hours).
        #[arg(long)]
        kind: String,
        #[arg(long = "archive-id")]
        archive_id: Option<String>,
        #[arg(long = "request-id")]
        request_id: String,
    },
    /// Roll back `site.importArchive`, `wordpress.migrateImport` and
    /// `wordpress.clone` runs that a killed engine left half done.
    RecoverContent {
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: String,
        #[arg(long = "request-file")]
        request_file: PathBuf,
    },
    Reconcile {
        #[arg(long = "request-id")]
        request_id: String,
        /// Optional root-owned JSON file `{"mariadbRootPasswords": {"<container>": "<password>"}}`;
        /// needed only to replay the database snapshot of a migration or clone.
        #[arg(long = "request-file")]
        request_file: Option<PathBuf>,
    },
    /// Move a site to another runtime pool: identity, service and exec config
    /// on the target, route cutover, check through the ingress, cleanup of the
    /// old pool, with the previous state restored on failure. The target pool
    /// must be running.
    MigrateRuntime {
        #[arg(long)]
        domain: String,
        #[arg(long = "target-runtime-id")]
        target_runtime_id: String,
        /// Check this path instead of the control-token probe.
        #[arg(long = "health-path")]
        health_path: Option<String>,
        /// Expected HTTP status of the health path (default 200).
        #[arg(long = "health-status")]
        health_status: Option<u16>,
        /// Exact expected body of the health path.
        #[arg(long = "health-body")]
        health_body: Option<String>,
        /// Stop the old pool when its last site left (`true`/`false`). Pass
        /// `false` for the base install's default pool.
        #[arg(long = "stop-idle-source", action = clap::ArgAction::Set, default_value_t = false)]
        stop_idle_source: bool,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Change the document root of a site's identity record.
    UpdateIdentity {
        #[arg(long = "runtime-id")]
        runtime_id: String,
        #[arg(long)]
        domain: String,
        #[arg(long)]
        root: String,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Move a site's identity record to its new domain (and root) after a
    /// rename, keeping the account and port.
    RenameIdentity {
        #[arg(long = "runtime-id")]
        runtime_id: String,
        #[arg(long = "from-domain")]
        from_domain: String,
        #[arg(long = "to-domain")]
        to_domain: String,
        #[arg(long)]
        root: String,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
}

impl SiteCommand {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::List => "site.list",
            Self::AdminUsers { .. } => "site.adminUsers",
            Self::AdminLogin { .. } => "site.adminLogin",
            Self::PublishStatic { .. } => "site.publishStatic",
            Self::StaticStatus { .. } => "site.staticStatus",
            Self::RecoverStatic { .. } => "site.recoverStatic",
            Self::Create { .. } => "site.create",
            Self::RecoverCreate { .. } => "site.recoverCreate",
            Self::RecoverDeployment { .. } => "site.recoverDeployment",
            Self::Deploy { .. } => "site.deploy",
            Self::Rollback { .. } => "site.rollback",
            Self::MoveRoot { .. } => "site.moveRoot",
            Self::PrepareRoot { .. } => "site.prepareRoot",
            Self::RemoveRoot { .. } => "site.removeRoot",
            Self::WriteEnvFile { .. } => "site.writeEnvFile",
            Self::QuarantineFile { .. } => "site.quarantineFile",
            Self::PhpInfoSession { .. } => "site.phpInfoSession",
            Self::ReleaseRoot { .. } => "site.releaseRoot",
            Self::RenameManifest { .. } => "site.renameManifest",
            Self::Enroll { .. } => "site.enroll",
            Self::Unenroll { .. } => "site.unenroll",
            Self::AllocateIdentity { .. } => "site.allocateIdentity",
            Self::ReleaseIdentity { .. } => "site.releaseIdentity",
            Self::UpdateIdentity { .. } => "site.updateIdentity",
            Self::RenameIdentity { .. } => "site.renameIdentity",
            Self::ExportArchive { .. } => "site.exportArchive",
            Self::ImportArchive { .. } => "site.importArchive",
            Self::DiscardArchive { .. } => "site.discardArchive",
            Self::RecoverContent { .. } => "site.recoverContent",
            Self::Reconcile { .. } => "site.reconcile",
            Self::MigrateRuntime { .. } => "site.migrateRuntime",
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
