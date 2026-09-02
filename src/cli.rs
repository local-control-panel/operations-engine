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
}

impl Command {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::Version => "version",
            Self::Capabilities => "capabilities",
            Self::Doctor => "doctor",
        }
    }
}
