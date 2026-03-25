//! Application orchestration with a builder-based assembly model.

use std::collections::BTreeSet;

use anyhow::Context;

use crate::config::AppConfig;
use crate::formatter::{OutputFormatter, OutputMode};
use crate::models::VulnerabilityRecord;
use crate::nvd::NvdClient;
use crate::pkgconfig;

/// Builder for the main application object.
#[derive(Default)]
pub struct MasterLibrarianBuilder {
    config: Option<AppConfig>,
    formatter: Option<Box<dyn OutputFormatter>>,
    nvd_client: Option<NvdClient>,
}

impl MasterLibrarianBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inject the validated configuration.
    #[must_use]
    pub fn config(mut self, config: AppConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Inject the chosen formatter.
    #[must_use]
    pub fn formatter(mut self, formatter: Box<dyn OutputFormatter>) -> Self {
        self.formatter = Some(formatter);
        self
    }

    /// Inject a custom NVD client.
    #[must_use]
    pub fn nvd_client(mut self, nvd_client: NvdClient) -> Self {
        self.nvd_client = Some(nvd_client);
        self
    }

    /// Build the final application instance.
    pub fn build(self) -> anyhow::Result<MasterLibrarian> {
        Ok(MasterLibrarian {
            config: self.config.context("missing app config")?,
            formatter: self.formatter.context("missing formatter")?,
            nvd_client: self.nvd_client.context("missing NVD client")?,
        })
    }
}

/// Main application.
pub struct MasterLibrarian {
    config: AppConfig,
    formatter: Box<dyn OutputFormatter>,
    nvd_client: NvdClient,
}

impl MasterLibrarian {
    /// Run the end-to-end workflow.
    pub fn run(mut self) -> anyhow::Result<()> {
        print_banner(&self.config);
        let packages = pkgconfig::collect_packages()?;

        for package in packages {
            let mut results = self
                .nvd_client
                .search_by_keyword(&package.lookup_term, self.config.limit.get())?;

            dedup_records(&mut results);

            if results.is_empty() {
                continue;
            }

            self.formatter.begin_package(&package)?;
            for record in &results {
                self.formatter.write_record(&package, record)?;
            }
        }

        self.formatter.finish()?;
        Ok(())
    }
}

fn dedup_records(records: &mut Vec<VulnerabilityRecord>) {
    records.sort_by(|a, b| {
        a.cve_id
            .cmp(&b.cve_id)
            .then_with(|| a.published.cmp(&b.published))
            .then_with(|| a.url.cmp(&b.url))
    });

    let mut seen = BTreeSet::new();
    records.retain(|record| {
        seen.insert((
            record.cve_id.clone(),
            record.published.clone(),
            record.url.clone(),
        ))
    });
}

fn print_banner(config: &AppConfig) {
    println!("Librarian audit v0.3 ");
    println!("Tool to search public vulnerabilities on local libraries");
    println!("by Orangewarrior");
    println!("Output mode: {}", config.output_mode.as_str());
    println!("Limit per package: {}", config.limit);

    if matches!(config.output_mode, OutputMode::Csv) {
        println!("CSV output: {}", config.csv_output.display());
    }

    println!();
}
