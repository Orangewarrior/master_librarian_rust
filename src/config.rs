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
    /// Optional CSV output path.
    pub csv_output: PathBuf,
}

/// Builder for [`AppConfig`].
#[derive(Debug, Default)]
pub struct AppConfigBuilder {
    output_mode: Option<OutputMode>,
    limit: Option<usize>,
    csv_output: Option<PathBuf>,
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

    /// Validate and build the final configuration.
    pub fn build(self) -> anyhow::Result<AppConfig> {
        let output_mode = self
            .output_mode
            .ok_or_else(|| anyhow::anyhow!("missing output mode"))?;
        let limit = self.limit.unwrap_or(3);
        let limit = NonZeroUsize::new(limit)
            .ok_or_else(|| anyhow::anyhow!("limit must be greater than zero"))?;
        let csv_output = self
            .csv_output
            .unwrap_or_else(|| PathBuf::from("librarian_log.csv"));

        Ok(AppConfig {
            output_mode,
            limit,
            csv_output,
        })
    }
}
