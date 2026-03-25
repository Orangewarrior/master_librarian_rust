//! CLI parsing types.

use std::path::PathBuf;

use clap::Parser;

use crate::formatter::OutputMode;

/// Raw CLI structure parsed by clap.
#[derive(Debug, Parser)]
#[command(
    name = "master-librarian-rust",
    about = "Search public vulnerabilities related to local pkg-config packages"
)]
pub struct RawCli {
    /// Output mode.
    #[arg(short = 't', long = "type", value_enum, default_value_t = OutputMode::Txt)]
    pub output_mode: OutputMode,

    /// Maximum number of records to request per package.
    #[arg(short = 'l', long = "limit", default_value_t = 3)]
    pub limit: usize,

    /// Output file used when CSV mode is selected.
    #[arg(long = "csv-output", default_value = "librarian_log.csv")]
    pub csv_output: PathBuf,
}
