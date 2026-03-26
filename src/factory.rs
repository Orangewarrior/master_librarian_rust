//! Factory-based assembly for CLI configuration and output strategies.

use clap::Parser;

use crate::cli::RawCli;
use crate::config::{AppConfig, AppConfigBuilder};
use crate::formatter::{OutputFormatter, OutputFormatterFactory};

/// Factory trait for building application configuration from CLI input.
pub trait GetoptFactory {
    /// Parse process arguments and build a validated configuration.
    fn build_config(&self) -> anyhow::Result<AppConfig>;
}

/// Clap-backed CLI factory.
pub struct ClapGetoptFactory;

impl GetoptFactory for ClapGetoptFactory {
    fn build_config(&self) -> anyhow::Result<AppConfig> {
        let cli = RawCli::parse();
        AppConfigBuilder::new()
            .output_mode(cli.output_mode)
            .limit(cli.limit)
            .csv_output(cli.csv_output)
            .json_output(cli.json_output)
            .thread_count(cli.thread_count)
            .rate_limit_ms(cli.rate_limit_ms)
            .build()
    }
}

/// Factory trait for output formatter creation.
pub trait FormatterFactory {
    /// Build the formatter instance matching the selected mode.
    fn build_formatter(&self, config: &AppConfig) -> anyhow::Result<Box<dyn OutputFormatter>>;
}

/// Default formatter factory.
pub struct DefaultFormatterFactory;

impl FormatterFactory for DefaultFormatterFactory {
    fn build_formatter(&self, config: &AppConfig) -> anyhow::Result<Box<dyn OutputFormatter>> {
        OutputFormatterFactory::create(config)
    }
}
