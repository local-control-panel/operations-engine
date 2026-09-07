pub mod cli;
pub mod commands;
pub mod compose;
pub mod compose_config;
pub mod config;
pub mod cron;
pub mod db_restore;
pub mod deploy;
pub mod engine;
pub mod error;
pub mod filesystem;
pub mod ingress;
pub mod mutation;
pub mod process;
pub mod protocol;
pub mod rollback;
pub mod runtime_config;
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
        Command::Ingress { command } => commands::ingress::run(command),
        Command::Runtime { command } => commands::runtime_config::run(command),
        Command::Cron { command } => commands::cron::run(command),
        Command::Db { command } => commands::db_restore::run(command),
        Command::Compose { command } => commands::compose_config::run(command),
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
