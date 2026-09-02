pub mod cli;
pub mod commands;
pub mod error;
pub mod process;
pub mod protocol;
pub mod site;

use cli::{Cli, Command};
use error::ErrorCode;
use protocol::{Response, ResponseBuildError};

pub fn execute(cli: Cli) -> Response {
    let operation = cli.command.operation();
    let response = match cli.command {
        Command::Version => commands::version::run(),
        Command::Capabilities => commands::capabilities::run(),
        Command::Doctor => commands::doctor::run(),
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
