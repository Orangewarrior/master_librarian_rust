//! Output formatting abstractions.

use std::fs::File;
use std::io::BufWriter;

use anyhow::{Context, Result};
use clap::ValueEnum;
use csv::WriterBuilder;

use crate::config::AppConfig;
use crate::models::{CsvRow, JsonPackageReport, PackageInfo, VulnerabilityRecord};

/// Supported output modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputMode {
    /// Human-readable terminal output.
    Txt,
    /// RFC-compliant CSV output.
    Csv,
    /// Structured JSON output.
    Json,
}

impl OutputMode {
    /// Stable lowercase label for UI output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Txt => "text",
            Self::Csv => "csv",
            Self::Json => "json",
        }
    }
}

/// Interface used by the application to emit records.
pub trait OutputFormatter: Send {
    fn begin_package(&mut self, package: &PackageInfo) -> Result<()>;
    fn write_record(&mut self, package: &PackageInfo, record: &VulnerabilityRecord) -> Result<()>;
    fn finish(&mut self) -> Result<()>;
}

pub struct OutputFormatterFactory;

impl OutputFormatterFactory {
    pub fn create(config: &AppConfig) -> Result<Box<dyn OutputFormatter>> {
        match config.output_mode {
            OutputMode::Txt => Ok(Box::new(TextFormatter::default())),
            OutputMode::Csv => CsvFormatter::new(&config.csv_output)
                .map(|f| Box::new(f) as Box<dyn OutputFormatter>),
            OutputMode::Json => JsonFormatter::new(&config.json_output)
                .map(|f| Box::new(f) as Box<dyn OutputFormatter>),
        }
    }
}

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
        self.writer.serialize(row).context("failed to write CSV record")
    }

    fn finish(&mut self) -> Result<()> {
        self.writer.flush().context("failed to flush CSV writer")
    }
}

pub struct JsonFormatter {
    writer: BufWriter<File>,
    current: Option<JsonPackageReport>,
    reports: Vec<JsonPackageReport>,
}

impl JsonFormatter {
    fn new(path: &std::path::Path) -> Result<Self> {
        let file = File::create(path)
            .with_context(|| format!("failed to create JSON output file: {}", path.display()))?;
        Ok(Self {
            writer: BufWriter::new(file),
            current: None,
            reports: Vec::new(),
        })
    }

    fn flush_current(&mut self) {
        if let Some(current) = self.current.take() {
            self.reports.push(current);
        }
    }
}

impl OutputFormatter for JsonFormatter {
    fn begin_package(&mut self, package: &PackageInfo) -> Result<()> {
        self.flush_current();
        self.current = Some(JsonPackageReport {
            package: package.clone(),
            vulnerabilities: Vec::new(),
        });
        Ok(())
    }

    fn write_record(&mut self, _package: &PackageInfo, record: &VulnerabilityRecord) -> Result<()> {
        if let Some(current) = self.current.as_mut() {
            current.vulnerabilities.push(record.clone());
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        self.flush_current();
        serde_json::to_writer_pretty(&mut self.writer, &self.reports)
            .context("failed to write JSON output")
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
