//! NVD API client.

use std::collections::BTreeSet;

use anyhow::Context;
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, HeaderMap, HeaderValue, USER_AGENT};
use serde::Deserialize;

use crate::models::VulnerabilityRecord;

/// Small blocking client for the NVD CVE API.
#[derive(Clone)]
pub struct NvdClient {
    client: Client,
}

impl NvdClient {
    /// Build a hardened blocking client with timeouts and a stable user-agent.
    pub fn new() -> anyhow::Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static("Master_librarian_rust/0.3 (+https://example.invalid)"),
        );

        let client = Client::builder()
            .default_headers(headers)
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(20))
            .https_only(true)
            .build()
            .context("failed to build HTTP client")?;

        Ok(Self { client })
    }

    /// Query NVD by keyword.
    pub fn search_by_keyword(
        &self,
        keyword: &str,
        results_per_page: usize,
    ) -> anyhow::Result<Vec<VulnerabilityRecord>> {
        let response = self
            .client
            .get("https://services.nvd.nist.gov/rest/json/cves/2.0")
            .query(&[("keywordSearch", keyword), ("resultsPerPage", &results_per_page.to_string())])
            .send()
            .with_context(|| format!("failed to query NVD for keyword '{keyword}'"))?
            .error_for_status()
            .context("NVD returned an error status")?;

        let body: NvdResponse = response.json().context("failed to parse NVD JSON response")?;

        let mut seen = BTreeSet::new();
        let mut records = Vec::new();

        for item in body.vulnerabilities {
            let record = item.into_record();
            let key = (
                record.cve_id.clone(),
                record.published.clone(),
                record.url.clone(),
            );

            if seen.insert(key) {
                records.push(record);
            }
        }

        Ok(records)
    }
}

#[derive(Debug, Deserialize)]
struct NvdResponse {
    #[serde(default)]
    vulnerabilities: Vec<NvdVulnerabilityItem>,
}

#[derive(Debug, Deserialize)]
struct NvdVulnerabilityItem {
    cve: NvdCve,
}

impl NvdVulnerabilityItem {
    fn into_record(self) -> VulnerabilityRecord {
        let cve_id = self.cve.id;
        let url = format!("https://nvd.nist.gov/vuln/detail/{cve_id}");
        let descriptions = self.cve.descriptions;
        let description = descriptions
            .iter()
            .find(|d| d.lang.eq_ignore_ascii_case("en"))
            .or_else(|| descriptions.first())
            .map(|d| normalize_description(&d.value))
            .unwrap_or_else(|| "No description available".to_owned());

        let severity_v3 = self
            .cve
            .metrics
            .as_ref()
            .and_then(|m| m.cvss_metric_v31.as_ref().or(m.cvss_metric_v30.as_ref()))
            .and_then(|entries| entries.first())
            .map(|entry| entry.cvss_data.base_severity.clone());

        let severity_v2 = self
            .cve
            .metrics
            .as_ref()
            .and_then(|m| m.cvss_metric_v2.as_ref())
            .and_then(|entries| entries.first())
            .map(|entry| entry.base_severity.clone());

        VulnerabilityRecord {
            cve_id,
            published: self.cve.published,
            url,
            description,
            severity_v2,
            severity_v3,
        }
    }
}

fn normalize_description(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[derive(Debug, Deserialize)]
struct NvdCve {
    #[serde(rename = "id")]
    id: String,
    #[serde(rename = "published")]
    published: String,
    #[serde(default)]
    descriptions: Vec<NvdDescription>,
    #[serde(default)]
    metrics: Option<NvdMetrics>,
}

#[derive(Debug, Deserialize)]
struct NvdDescription {
    lang: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct NvdMetrics {
    #[serde(rename = "cvssMetricV2")]
    cvss_metric_v2: Option<Vec<NvdCvssV2Entry>>,
    #[serde(rename = "cvssMetricV30")]
    cvss_metric_v30: Option<Vec<NvdCvssV3Entry>>,
    #[serde(rename = "cvssMetricV31")]
    cvss_metric_v31: Option<Vec<NvdCvssV3Entry>>,
}

#[derive(Debug, Deserialize)]
struct NvdCvssV2Entry {
    #[serde(rename = "baseSeverity")]
    base_severity: String,
}

#[derive(Debug, Deserialize)]
struct NvdCvssV3Entry {
    #[serde(rename = "cvssData")]
    cvss_data: NvdCvssV3Data,
}

#[derive(Debug, Deserialize)]
struct NvdCvssV3Data {
    #[serde(rename = "baseSeverity")]
    base_severity: String,
}
