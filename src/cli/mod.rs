//! CLI module
//! Command-line interface and subcommand implementation

pub mod commands;

use crate::error::Result;
use commands::{CliParser, CommandExecutor};

/// Run CLI
pub fn run() -> Result<()> {
    let cmd = CliParser::parse();
    CommandExecutor::execute(cmd)
}
