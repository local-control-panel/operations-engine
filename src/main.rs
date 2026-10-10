use std::process::ExitCode;

use clap::Parser;
use operations_engine::{cli::Cli, execute};

fn main() -> ExitCode {
    let cli = Cli::parse();

    // The agent helpers (`agent heartbeat|lock|log`) are commands for scripts:
    // their exit code is the contract, not a protocol envelope.
    #[cfg(unix)]
    if let operations_engine::cli::Command::Agent { command } = &cli.command {
        if operations_engine::agent_helper::is_helper(command) {
            let code = operations_engine::agent_helper::run(command);
            return ExitCode::from(u8::try_from(code).unwrap_or(1));
        }
    }

    let response = execute(cli);

    match serde_json::to_string(&response) {
        Ok(json) => {
            println!("{json}");
            if response.ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("failed to serialize protocol response: {error}");
            ExitCode::FAILURE
        }
    }
}
