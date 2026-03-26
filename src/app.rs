//! Application orchestration with a builder-based assembly model.
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;
use rayon::prelude::*;
use rayon::ThreadPoolBuilder;

use crate::config::AppConfig;
use crate::formatter::{OutputFormatter, OutputMode};
use crate::models::{PackageInfo, VulnerabilityRecord};
use crate::nvd::NvdClient;
use crate::pkgconfig;

#[derive(Default)]
pub struct MasterLibrarianBuilder {
    config: Option<AppConfig>,
    formatter: Option<Box<dyn OutputFormatter>>,
    nvd_client: Option<NvdClient>,
}

impl MasterLibrarianBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn config(mut self, config: AppConfig) -> Self {
        self.config = Some(config);
        self
    }

    #[must_use]
    pub fn formatter(mut self, formatter: Box<dyn OutputFormatter>) -> Self {
        self.formatter = Some(formatter);
        self
    }

    #[must_use]
    pub fn nvd_client(mut self, nvd_client: NvdClient) -> Self {
        self.nvd_client = Some(nvd_client);
        self
    }

    pub fn build(self) -> anyhow::Result<MasterLibrarian> {
        Ok(MasterLibrarian {
            config: self.config.context("missing app config")?,
            formatter: self.formatter.context("missing formatter")?,
            nvd_client: self.nvd_client.context("missing NVD client")?,
        })
    }
}

pub struct MasterLibrarian {
    config: AppConfig,
    formatter: Box<dyn OutputFormatter>,
    nvd_client: NvdClient,
}

impl MasterLibrarian {
    pub fn run(mut self) -> anyhow::Result<()> {
        print_banner(&self.config);
        let packages = pkgconfig::collect_packages()?;
        let throttle = Arc::new(Mutex::new(Instant::now() - Duration::from_millis(self.config.rate_limit_ms)));
        let client = self.nvd_client.clone();
        let config = self.config.clone();

        let pool = ThreadPoolBuilder::new()
            .num_threads(config.thread_count.get())
            .build()
            .context("failed to build rayon thread pool")?;

        let mut reports = pool.install(|| {
            packages
                .into_par_iter()
                .filter_map(|package| {
                    throttle_request(&throttle, config.rate_limit_ms);

                    let raw = client
                        .search_by_keyword(&package.lookup_term, config.limit.get())
                        .ok()?;

                    let mut filtered = filter_records_for_package(&package, raw);
                    dedup_records(&mut filtered);

                    if filtered.is_empty() {
                        None
                    } else {
                        Some((package, filtered))
                    }
                })
                .collect::<Vec<_>>()
        });

        reports.sort_by(|a, b| a.0.lookup_term.cmp(&b.0.lookup_term));

        for (package, records) in reports {
            self.formatter.begin_package(&package)?;
            for record in &records {
                self.formatter.write_record(&package, record)?;
            }
        }

        self.formatter.finish()?;
        Ok(())
    }
}

fn throttle_request(last_request: &Mutex<Instant>, rate_limit_ms: u64) {
    if rate_limit_ms == 0 {
        return;
    }

    let mut guard = match last_request.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    let min_gap = Duration::from_millis(rate_limit_ms);
    let now = Instant::now();
    let elapsed = now.saturating_duration_since(*guard);

    if elapsed < min_gap {
        std::thread::sleep(min_gap - elapsed);
    }

    *guard = Instant::now();
}

fn filter_records_for_package(package: &PackageInfo, records: Vec<VulnerabilityRecord>) -> Vec<VulnerabilityRecord> {
    let tokens = package
        .relevance_tokens()
        .into_iter()
        .map(|token| token.to_ascii_lowercase())
        .collect::<Vec<_>>();

    let version = package.version.as_deref().map(str::to_ascii_lowercase);

    records
        .into_iter()
        .filter(|record| record_relevant(record, &tokens, version.as_deref()))
        .collect()
}

fn record_relevant(record: &VulnerabilityRecord, tokens: &[String], version: Option<&str>) -> bool {
    let haystack = format!(
        "{} {} {}",
        record.cve_id,
        record.url,
        record.description
    );

    let words = tokenize(&haystack);
    let has_token = tokens.iter().any(|token| words.contains(token));

    let version_ok = version.map_or(true, |version| words.contains(version));

    has_token && version_ok
}

fn tokenize(input: &str) -> BTreeSet<String> {
    input
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .map(|part| part.to_ascii_lowercase())
        .collect()
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
    println!("Master Librarian v0.4");
    println!("Tool to search public vulnerabilities on local libraries");
    println!("by Orangewarrior");
    println!("Output mode: {}", config.output_mode.as_str());
    println!("Limit per package: {}", config.limit);
    println!("Worker threads: {}", config.thread_count);
    println!("Rate limit: {} ms", config.rate_limit_ms);

    if matches!(config.output_mode, OutputMode::Csv) {
        println!("CSV output: {}", config.csv_output.display());
    }

    if matches!(config.output_mode, OutputMode::Json) {
        println!("JSON output: {}", config.json_output.display());
    }

    println!();
}

#[cfg(test)]
mod tests {
    use super::{record_relevant, tokenize};
    use crate::models::VulnerabilityRecord;

    fn mk(desc: &str) -> VulnerabilityRecord {
        VulnerabilityRecord {
            cve_id: "CVE-TEST".to_owned(),
            published: "2024-01-01".to_owned(),
            url: "https://example.invalid".to_owned(),
            description: desc.to_owned(),
            severity_v2: None,
            severity_v3: None,
        }
    }

    #[test]
    fn tokenization_splits_hyphenated_words() {
        let tokens = tokenize("Crypto-C Micro Edition");
        assert!(tokens.contains("crypto"));
        assert!(tokens.contains("c"));
        assert!(!tokens.contains("crypt"));
    }

    #[test]
    fn crypt_does_not_match_crypto_c_false_positive() {
        let rec = mk("Dell BSAFE Crypto-C Micro Edition before 4.1.5.");
        assert!(!record_relevant(&rec, &[String::from("crypt")], Some("4.5.2")));
    }

    #[test]
    fn ssl_record_with_exact_token_matches() {
        let rec = mk("A flaw in SSL certificate validation allows spoofing.");
        assert!(record_relevant(&rec, &[String::from("ssl")], None));
    }
}
