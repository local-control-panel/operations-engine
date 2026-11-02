use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};

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

    /// Deletes a domain's route files (live or disabled, plus any
    /// maintenance backup) and reloads the ingress, putting every file back
    /// if the reload fails.
    RemoveRoute {
        #[arg(long)]
        domain: String,

        /// SHA-256 digest of the route being removed: the live file, or the
        /// disabled file when there is no live one.
        #[arg(long = "expected-hash")]
        expected_hash: String,

        /// SHA-256 digest of the domain's `.maintenance-backup`. Omit to
        /// assert that the domain has none.
        #[arg(long = "expected-backup-hash")]
        expected_backup_hash: Option<String>,

        /// Canonical UUID identifying this specific attempt.
        #[arg(long = "request-id")]
        request_id: String,

        /// Caller-supplied token so a retried request returns the original
        /// outcome instead of removing twice.
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },

    /// Enables or disables a domain by renaming its route between
    /// `<domain>.caddyfile` and `<domain>.caddyfile.disabled`, reloading the
    /// ingress and renaming back if the reload fails.
    SetEnabled {
        #[arg(long)]
        domain: String,

        /// `true` to move the disabled route live, `false` to disable the
        /// live route.
        #[arg(long, action = clap::ArgAction::Set)]
        enabled: bool,

        /// SHA-256 digest of the route file being moved (the disabled file
        /// when enabling, the live file when disabling).
        #[arg(long = "expected-hash")]
        expected_hash: String,

        /// Canonical UUID identifying this specific attempt.
        #[arg(long = "request-id")]
        request_id: String,

        /// Caller-supplied token so a retried request returns the original
        /// outcome instead of toggling twice.
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },

    /// Replaces the brute-force guard's ban list, `bans/bans.caddy`, that
    /// every route imports: validated, swapped in, reloaded, and put back if
    /// the reload refuses it. The request file is `{"bans":["<ip>",...]}`.
    ApplyBans {
        /// Root-owned JSON request file.
        #[arg(long = "request-file")]
        request_file: PathBuf,

        /// Canonical UUID identifying this specific attempt.
        #[arg(long = "request-id")]
        request_id: String,

        /// Caller-supplied token so a retried request returns the original
        /// outcome instead of applying twice.
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },

    /// Restricts one domain's sensitive admin paths (from a closed per-kind
    /// catalog) to an IP allowlist or to Basic auth, or removes the
    /// restriction. Writes `bans/admin-<domain>.caddy`, validated, reloaded
    /// and put back if the reload refuses it. The request file is
    /// `{"domain":"..","restriction":null|{"kind","paths","mode",...}}`.
    ApplyAdminPaths {
        /// Root-owned JSON request file.
        #[arg(long = "request-file")]
        request_file: PathBuf,

        /// Canonical UUID identifying this specific attempt.
        #[arg(long = "request-id")]
        request_id: String,

        /// Caller-supplied token so a retried request returns the original
        /// outcome instead of applying twice.
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
            Self::RemoveRoute { .. } => "ingress.removeRoute",
            Self::SetEnabled { .. } => "ingress.setEnabled",
            Self::ApplyBans { .. } => "ingress.applyBans",
            Self::ApplyAdminPaths { .. } => "ingress.applyAdminPaths",
            Self::Reconcile { .. } => "ingress.reconcile",
        }
    }
}
