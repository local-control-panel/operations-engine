pub mod cli;
pub mod commands;
pub mod compose;
pub mod config;
pub mod deploy;
pub mod engine;
pub mod error;
pub mod filesystem;
pub mod ingress;
pub mod mutation;
pub mod process;
pub mod protocol;
pub mod rollback;
pub mod site;
pub mod transaction;

use cli::{Cli, Command};
use error::ErrorCode;
use protocol::{Response, ResponseBuildError};

pub fn execute(cli: Cli) -> Response {
    let operation = cli.command.operation();
    let response = match cli.command {
        Command::Version => commands::version::run(),
        Command::Capabilities => commands::capabilities::run(),
        Command::Doctor => commands::doctor::run(),
        Command::Site { command } => commands::site::run(command),
        Command::Engine { command } => commands::engine::run(command),
    };

    response.unwrap_or_else(|error| internal_error(operation, error))
}

fn internal_error(operation: &'static str, _error: ResponseBuildError) -> Response {
    Response::failure(
        operation,
        ErrorCode::InternalSerializationError,
        "The operation result could not be encoded safely",
    )
}
