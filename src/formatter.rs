//! Output formatting abstractions.

use std::fs::File;
use std::io::BufWriter;

use anyhow::{Context, Result};
use clap::ValueEnum;
use csv::WriterBuilder;

use crate::config::AppConfig;
use crate::models::{CsvRow, PackageInfo, VulnerabilityRecord};

/// Supported output modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputMode {
    /// Human-readable terminal output.
    Txt,
    /// RFC-compliant CSV output.
    Csv,
}

impl OutputMode {
    /// Stable lowercase label for UI output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Txt => "text",
            Self::Csv => "csv",
        }
    }
}

/// Interface used by the application to emit records.
pub trait OutputFormatter: Send {
    /// Emit the package header or context marker.
    fn begin_package(&mut self, package: &PackageInfo) -> Result<()>;

    /// Emit a single vulnerability record.
    fn write_record(&mut self, package: &PackageInfo, record: &VulnerabilityRecord) -> Result<()>;

    /// Emit a final footer if necessary.
    fn finish(&mut self) -> Result<()>;
}

/// Factory for creating concrete output formatters.
pub struct OutputFormatterFactory;

impl OutputFormatterFactory {
    /// Create a boxed formatter for the selected mode.
    pub fn create(config: &AppConfig) -> Result<Box<dyn OutputFormatter>> {
        match config.output_mode {
            OutputMode::Txt => Ok(Box::new(TextFormatter::default())),
            OutputMode::Csv => CsvFormatter::new(&config.csv_output)
                .map(|f| Box::new(f) as Box<dyn OutputFormatter>),
        }
    }
}

/// Plain text formatter.
#[derive(Default)]
pub struct TextFormatter;

impl OutputFormatter for TextFormatter {
    fn begin_package(&mut self, package: &PackageInfo) -> Result<()> {
        let libs = package.libs_display();
        let includes = package.includes_display();

        println!();
        print!("{}", package.display_label());

        if !libs.is_empty() {
            print!(" [libs: {libs}]");
        }

        if !includes.is_empty() {
            print!(" [includes: {includes}]");
        }

        println!();
        Ok(())
    }

    fn write_record(&mut self, _package: &PackageInfo, record: &VulnerabilityRecord) -> Result<()> {
        println!("\tCVE: {}", record.cve_id);
        println!("\tURL: {}", record.url);
        println!("\tDate: {}", record.published);
        println!("\tDescription: {}", record.description);
        println!("\tSeverity V2: {}", colorize_optional_severity(record.severity_v2.as_deref()));
        println!("\tSeverity V3: {}", colorize_optional_severity(record.severity_v3.as_deref()));
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Robust CSV formatter backed by the `csv` crate.
pub struct CsvFormatter {
    writer: csv::Writer<BufWriter<File>>,
}

impl CsvFormatter {
    fn new(path: &std::path::Path) -> Result<Self> {
        let file = File::create(path)
            .with_context(|| format!("failed to create CSV output file: {}", path.display()))?;
        let writer = WriterBuilder::new()
            .has_headers(true)
            .from_writer(BufWriter::new(file));

        Ok(Self { writer })
    }
}

impl OutputFormatter for CsvFormatter {
    fn begin_package(&mut self, _package: &PackageInfo) -> Result<()> {
        Ok(())
    }

    fn write_record(&mut self, package: &PackageInfo, record: &VulnerabilityRecord) -> Result<()> {
        let row = CsvRow::from_package_and_record(package, record);
        self.writer
            .serialize(row)
            .context("failed to write CSV record")
    }

    fn finish(&mut self) -> Result<()> {
        self.writer.flush().context("failed to flush CSV writer")
    }
}

fn colorize_optional_severity(severity: Option<&str>) -> String {
    match severity {
        Some(value) => colorize_severity(value),
        None => "NULL".to_owned(),
    }
}

fn colorize_severity(severity: &str) -> String {
    let normalized = severity.trim().to_ascii_uppercase();

    match normalized.as_str() {
        "LOW" => ansi_wrap(severity, "33"),
        "MEDIUM" => ansi_wrap(severity, "38;5;208"),
        "HIGH" => ansi_wrap(severity, "31"),
        "CRITICAL" => ansi_wrap(severity, "5;31"),
        _ => severity.to_owned(),
    }
}

fn ansi_wrap(text: &str, code: &str) -> String {
    format!("\x1b[{code}m{text}\x1b[0m")
}

#[cfg(test)]
mod tests {
    use super::colorize_severity;

    #[test]
    fn low_is_yellow() {
        assert_eq!(colorize_severity("LOW"), "\x1b[33mLOW\x1b[0m");
    }

    #[test]
    fn medium_is_orange_256() {
        assert_eq!(colorize_severity("MEDIUM"), "\x1b[38;5;208mMEDIUM\x1b[0m");
    }

    #[test]
    fn high_is_red() {
        assert_eq!(colorize_severity("HIGH"), "\x1b[31mHIGH\x1b[0m");
    }

    #[test]
    fn critical_is_blinking_red() {
        assert_eq!(colorize_severity("CRITICAL"), "\x1b[5;31mCRITICAL\x1b[0m");
    }
}
