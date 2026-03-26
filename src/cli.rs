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
    #[arg(short = 'l', long = "limit", default_value_t = 10)]
    pub limit: usize,

    /// Output file used when CSV mode is selected.
    #[arg(long = "csv-output", default_value = "librarian_log.csv")]
    pub csv_output: PathBuf,

    /// Output file used when JSON mode is selected.
    #[arg(long = "json-output", default_value = "librarian_log.json")]
    pub json_output: PathBuf,

    /// Number of worker threads used for NVD requests.
    #[arg(long = "threads", default_value_t = 4)]
    pub thread_count: usize,

    /// Minimum delay in milliseconds between NVD requests across all workers.
    #[arg(long = "rate-limit-ms", default_value_t = 250)]
    pub rate_limit_ms: u64,
}
