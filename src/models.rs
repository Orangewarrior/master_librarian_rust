//! Domain models used by the application.

use serde::Serialize;

/// Parsed vulnerability information returned by the NVD client.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VulnerabilityRecord {
    /// CVE identifier.
    pub cve_id: String,
    /// Published date from NVD.
    pub published: String,
    /// Full detail URL.
    pub url: String,
    /// Free-form description.
    pub description: String,
    /// Optional CVSS v2 severity.
    pub severity_v2: Option<String>,
    /// Optional CVSS v3 or v4 severity.
    pub severity_v3: Option<String>,
}


/// Metadata collected for one local pkg-config package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageInfo {
    /// Canonical package token reported by `pkg-config --list-all`.
    pub package_name: String,
    /// Name or alias used as the NVD lookup term.
    pub lookup_term: String,
    /// Optional pkg-config reported version.
    pub version: Option<String>,
    /// Link library names discovered by pkg-config.
    pub libs: Vec<String>,
    /// Include paths discovered by pkg-config.
    pub include_paths: Vec<String>,
}

impl PackageInfo {
    /// Human-readable package label used in terminal output.
    #[must_use]
    pub fn display_label(&self) -> String {
        match self.version.as_deref() {
            Some(version) if !version.is_empty() => {
                format!("{} (version {})", self.lookup_term, version)
            }
            _ => self.lookup_term.clone(),
        }
    }


    /// Return the linked library list in a stable display format.
    #[must_use]
    pub fn libs_display(&self) -> String {
        if self.libs.is_empty() {
            String::new()
        } else {
            self.libs.join(", ")
        }
    }

    /// Return include paths in a stable display format.
    #[must_use]
    pub fn includes_display(&self) -> String {
        if self.include_paths.is_empty() {
            String::new()
        } else {
            self.include_paths.join(", ")
        }
    }

    /// Merge alias metadata from another package that resolves to the same
    /// lookup term.
    pub fn merge_from(&mut self, other: Self) {
        if self.version.is_none() {
            self.version = other.version;
        }

        self.libs.extend(other.libs);
        self.libs.sort();
        self.libs.dedup();

        self.include_paths.extend(other.include_paths);
        self.include_paths.sort();
        self.include_paths.dedup();
    }
}

/// Serialized CSV output row.
///
/// Using a dedicated row type keeps formatting deterministic and easier to audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CsvRow {
    pub package_name: String,
    pub lookup_term: String,
    pub package_version: String,
    pub linked_libraries: String,
    pub include_paths: String,
    pub cve_id: String,
    pub published: String,
    pub url: String,
    pub severity_v2: String,
    pub severity_v3: String,
    pub description: String,
}

impl CsvRow {
    /// Build one CSV row from package metadata plus one vulnerability record.
    #[must_use]
    pub fn from_package_and_record(package: &PackageInfo, record: &VulnerabilityRecord) -> Self {
        Self {
            package_name: package.package_name.clone(),
            lookup_term: package.lookup_term.clone(),
            package_version: package.version.clone().unwrap_or_default(),
            linked_libraries: package.libs.join(","),
            include_paths: package.include_paths.join(","),
            cve_id: record.cve_id.clone(),
            published: record.published.clone(),
            url: record.url.clone(),
            severity_v2: record.severity_v2.clone().unwrap_or_default(),
            severity_v3: record.severity_v3.clone().unwrap_or_default(),
            description: record.description.clone(),
        }
    }
}
