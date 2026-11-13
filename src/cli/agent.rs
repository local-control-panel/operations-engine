use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};

#[derive(Debug, Subcommand)]
pub enum AgentCommand {
    /// Atomically replace the typed brute-force guard configuration.
    ActivateBruteforceConfig {
        #[arg(long = "request-file")]
        request_file: PathBuf,
    },
    /// Install or update a bundled agent: script, manifest entry and cron line.
    Install {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Install an agent from the open agents repository, verified against the
    /// release's registry.json.
    InstallFromRegistry {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Record that the operator reviewed one exact script hash of a community
    /// agent.
    Approve {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Withdraw the approval of a community agent's script hash (all hashes
    /// of the agent when none is given).
    Unapprove {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Remove a bundled agent: cron line, manifest entry and script.
    Remove {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Drop one IP from the brute-force ban list and re-apply the guard.
    BruteforceUnban {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    /// Start an installed agent once, now, the way its scheduler would, and
    /// report its exit code, heartbeat and last result line. `--dry-run` sets
    /// `WCP_DRY_RUN=1` (not a sandbox).
    Run {
        name: String,
        #[arg(long = "dry-run")]
        dry_run: bool,
        /// Kill the agent after this many seconds (1 to 3600).
        #[arg(long = "timeout-seconds", default_value_t = 300)]
        timeout_seconds: u64,
    },
    /// Write one agent's own configuration (`$WCP_DIR/agents/NAME.conf`, mode
    /// 0600) from a staged request file; values never appear in the answer.
    Configure {
        #[arg(long = "request-file")]
        request_file: PathBuf,
    },
    /// Check an agent's manifest and script against the rules the engine
    /// installs by. Read-only. `--manifest-file` is the agent's `agent.toml`
    /// as JSON; the script is read from `--directory`. The answer is
    /// `{valid, agent, problems[], warnings[]}`; a manifest that cannot be
    /// read or parsed is an `INVALID_INPUT` failure, never `valid`.
    Validate {
        /// The agent's directory (its name must equal the manifest's `name`).
        #[arg(long)]
        directory: PathBuf,
        /// The agent's `agent.toml` converted to JSON.
        #[arg(long = "manifest-file")]
        manifest_file: PathBuf,
    },
    /// Helper for agent scripts: write `$WCP_DIR/agents/NAME.heartbeat`
    /// atomically. Silent on success; exit 0, or 1 on I/O failure, 2 on a bad
    /// name. Skipped under `WCP_DRY_RUN=1`.
    Heartbeat {
        name: String,
        /// The exit status to record (use `$?` in an EXIT trap).
        #[arg(long = "exit-code", default_value_t = 0, allow_hyphen_values = true)]
        exit_code: i32,
        /// Print one protocol envelope on stdout.
        #[arg(long)]
        json: bool,
    },
    /// Helper for agent scripts: take the agent's non-blocking lock
    /// (`$WCP_DIR/agents/NAME.lock`) and run `-- CMD...` while holding it.
    /// When another run holds it, CMD is not started and the exit code is 0
    /// (`--held-exit-code`). `--check` only probes: 0 free, 75 held.
    Lock {
        name: String,
        /// Probe without running anything.
        #[arg(long)]
        check: bool,
        /// Exit code when the lock is already held.
        #[arg(long = "held-exit-code", default_value_t = 0)]
        held_exit_code: u8,
        /// Print one protocol envelope on stdout when the command is not run.
        #[arg(long)]
        json: bool,
        /// The command to run under the lock; replaces this process, so its
        /// exit status is the exit status.
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Helper for agent scripts: append one JSON line to
    /// `$WCP_DIR/logs/NAME.log` and keep the file bounded. The message comes
    /// from the arguments, or from standard input when none (or `-`) is given.
    Log {
        name: String,
        #[arg(long, value_enum, default_value_t = LogLevel::Info)]
        level: LogLevel,
        /// Keep at most this many lines.
        #[arg(long = "max-lines", default_value_t = 2000)]
        max_lines: usize,
        /// Print one protocol envelope on stdout.
        #[arg(long)]
        json: bool,
        message: Vec<String>,
    },
    /// Helper for agent scripts: record what the run found (the result line
    /// the panel shows).
    #[command(name = "result")]
    ResultCmd {
        #[command(subcommand)]
        command: AgentResultCommand,
    },
    /// Helper for agent scripts: read the agent's own configuration
    /// (`$WCP_DIR/agents/NAME.conf`).
    #[command(name = "config")]
    ConfigCmd {
        #[command(subcommand)]
        command: AgentConfigCommand,
    },
    /// Helper for agent scripts: read-only facts about this server.
    #[command(name = "site")]
    SiteCmd {
        #[command(subcommand)]
        command: AgentSiteCommand,
    },
    /// Helper for agent scripts: is a program the agent needs installed, and
    /// (only when the operator allowed it) install it.
    #[command(name = "tool")]
    ToolCmd {
        #[command(subcommand)]
        command: AgentToolCommand,
    },
    /// Helper for agent scripts: which helper commands this engine has.
    Version {
        /// Print one protocol envelope on stdout.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum AgentResultCommand {
    /// Append the result line `{"ts","agent","status","summary","data"}` to
    /// `$WCP_DIR/logs/NAME.log`. Nothing is written under `WCP_DRY_RUN=1`.
    Emit {
        name: String,
        #[arg(long, value_enum)]
        status: ResultStatus,
        /// What happened, in one sentence (cut at 500 characters).
        #[arg(long)]
        summary: String,
        /// A `KEY=VALUE` pair for the result's `data` object (repeatable).
        #[arg(long = "data")]
        data: Vec<String>,
        /// A JSON object merged into `data` (before the `--data` pairs).
        #[arg(long = "data-json")]
        data_json: Option<String>,
        /// Keep at most this many lines in the log.
        #[arg(long = "max-lines", default_value_t = 2000)]
        max_lines: usize,
        /// Print one protocol envelope on stdout.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum AgentConfigCommand {
    /// Print the value of KEY from `$WCP_DIR/agents/NAME.conf`. Exit 1 when
    /// the key is missing and there is no `--default`.
    Get {
        name: String,
        key: String,
        #[arg(long)]
        default: Option<String>,
        /// Print one protocol envelope on stdout (it contains the value).
        #[arg(long)]
        json: bool,
    },
    /// Print the key names (never the values), one per line.
    List {
        name: String,
        /// Print one protocol envelope on stdout.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum AgentToolCommand {
    /// Whether NAME (`wp-cli`, `rclone` or `docker`) is installed and at what
    /// version. Prints the version (or nothing); exit 0 present, 1 missing,
    /// 2 unknown name. Read-only.
    Status {
        name: String,
        /// Print one protocol envelope on stdout.
        #[arg(long)]
        json: bool,
    },
    /// Install NAME with the engine's own installer, but only when the
    /// operator listed it in `$WCP_DIR/allow-tool-ensure`; under
    /// `WCP_DRY_RUN=1` only report. Exit 0 present or installed, 1 refused or
    /// failed, 2 unknown name.
    Ensure {
        name: String,
        /// Print one protocol envelope on stdout.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum AgentSiteCommand {
    /// The sites on this server, one domain per line.
    List {
        /// Print one protocol envelope on stdout with the full records.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ResultStatus {
    Ok,
    Warn,
    Fail,
    Skipped,
}

impl ResultStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
            Self::Skipped => "skipped",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

impl AgentCommand {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::ActivateBruteforceConfig { .. } => "agent.activateBruteforceConfig",
            Self::Install { .. } => "agent.install",
            Self::InstallFromRegistry { .. } => "agent.installFromRegistry",
            Self::Approve { .. } => "agent.approve",
            Self::Unapprove { .. } => "agent.unapprove",
            Self::Remove { .. } => "agent.remove",
            Self::BruteforceUnban { .. } => "agent.bruteforceUnban",
            Self::Run { .. } => "agent.run",
            Self::Configure { .. } => "agent.configure",
            Self::Validate { .. } => "agent.validate",
            Self::Heartbeat { .. } => "agent.heartbeat",
            Self::Lock { .. } => "agent.lock",
            Self::Log { .. } => "agent.log",
            Self::ResultCmd { .. } => "agent.result.emit",
            Self::ConfigCmd { command } => match command {
                AgentConfigCommand::Get { .. } => "agent.config.get",
                AgentConfigCommand::List { .. } => "agent.config.list",
            },
            Self::SiteCmd { .. } => "agent.site.list",
            Self::ToolCmd { command } => match command {
                AgentToolCommand::Status { .. } => "agent.tool.status",
                AgentToolCommand::Ensure { .. } => "agent.tool.ensure",
            },
            Self::Version { .. } => "agent.version",
        }
    }

    /// Whether this is a helper for agent scripts (exit code is the contract,
    /// no envelope unless `--json`) rather than a protocol operation.
    pub const fn is_helper(&self) -> bool {
        matches!(
            self,
            Self::Heartbeat { .. }
                | Self::Lock { .. }
                | Self::Log { .. }
                | Self::ResultCmd { .. }
                | Self::ConfigCmd { .. }
                | Self::SiteCmd { .. }
                | Self::ToolCmd { .. }
                | Self::Version { .. }
        )
    }
}
