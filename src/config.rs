//! Configuration types and builder for the application.

use std::num::NonZeroUsize;
use std::path::PathBuf;

use crate::formatter::OutputMode;

/// Immutable runtime configuration for the application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppConfig {
    /// Output format selected by the user.
    pub output_mode: OutputMode,
    /// Maximum number of vulnerability records requested per package.
    pub limit: NonZeroUsize,
    /// Output path used when CSV mode is selected.
    pub csv_output: PathBuf,
    /// Output path used when JSON mode is selected.
    pub json_output: PathBuf,
    /// Number of parallel workers for remote requests.
    pub thread_count: NonZeroUsize,
    /// Global minimum delay between requests in milliseconds.
    pub rate_limit_ms: u64,
}

/// Builder for [`AppConfig`].
#[derive(Debug, Default)]
pub struct AppConfigBuilder {
    output_mode: Option<OutputMode>,
    limit: Option<usize>,
    csv_output: Option<PathBuf>,
    json_output: Option<PathBuf>,
    thread_count: Option<usize>,
    rate_limit_ms: Option<u64>,
}

impl AppConfigBuilder {
    /// Create a new empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the output mode.
    #[must_use]
    pub fn output_mode(mut self, output_mode: OutputMode) -> Self {
        self.output_mode = Some(output_mode);
        self
    }

    /// Set the record limit.
    #[must_use]
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set the CSV output path.
    #[must_use]
    pub fn csv_output<P: Into<PathBuf>>(mut self, csv_output: P) -> Self {
        self.csv_output = Some(csv_output.into());
        self
    }

    /// Set the JSON output path.
    #[must_use]
    pub fn json_output<P: Into<PathBuf>>(mut self, json_output: P) -> Self {
        self.json_output = Some(json_output.into());
        self
    }

    /// Set the rayon thread count.
    #[must_use]
    pub fn thread_count(mut self, thread_count: usize) -> Self {
        self.thread_count = Some(thread_count);
        self
    }

    /// Set the global request delay.
    #[must_use]
    pub fn rate_limit_ms(mut self, rate_limit_ms: u64) -> Self {
        self.rate_limit_ms = Some(rate_limit_ms);
        self
    }

    /// Validate and build the final configuration.
    pub fn build(self) -> anyhow::Result<AppConfig> {
        let output_mode = self
            .output_mode
            .ok_or_else(|| anyhow::anyhow!("missing output mode"))?;
        let limit = NonZeroUsize::new(self.limit.unwrap_or(10))
            .ok_or_else(|| anyhow::anyhow!("limit must be greater than zero"))?;
        let thread_count = NonZeroUsize::new(self.thread_count.unwrap_or(4))
            .ok_or_else(|| anyhow::anyhow!("thread count must be greater than zero"))?;
        let csv_output = self
            .csv_output
            .unwrap_or_else(|| PathBuf::from("librarian_log.csv"));
        let json_output = self
            .json_output
            .unwrap_or_else(|| PathBuf::from("librarian_log.json"));

        Ok(AppConfig {
            output_mode,
            limit,
            csv_output,
            json_output,
            thread_count,
            rate_limit_ms: self.rate_limit_ms.unwrap_or(250),
        })
    }
}
