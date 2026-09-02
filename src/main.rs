use std::process::ExitCode;

use clap::Parser;
use operations_engine::{cli::Cli, execute};

fn main() -> ExitCode {
    let response = execute(Cli::parse());

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
