pub mod cli;
pub mod commands;
pub mod protocol;

use cli::{Cli, Command};
use protocol::Response;

pub fn execute(cli: Cli) -> Response {
    match cli.command {
        Command::Version => commands::version::run(),
        Command::Capabilities => commands::capabilities::run(),
        Command::Doctor => commands::doctor::run(),
    }
}
