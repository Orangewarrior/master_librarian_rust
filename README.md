![Crates.io](https://img.shields.io/crates/v/master_librarian_rust)
![Downloads](https://img.shields.io/crates/d/master_librarian_rust)
![License](https://img.shields.io/crates/l/master_librarian_rust)
![Rust Version](https://img.shields.io/badge/rust-1.75%2B-orange)
![Build](https://img.shields.io/github/actions/workflow/status/Orangewarrior/master_librarian_rust/ci.yml)
![Last Commit](https://img.shields.io/github/last-commit/Orangewarrior/master_librarian_rust)
![Repo Size](https://img.shields.io/github/repo-size/Orangewarrior/master_librarian_rust)

# 📚 Librarian audit 

A low-level, security-focused tool to enumerate system libraries via pkg-config and correlate them with public vulnerabilities (CVE) from the NVD.

> 🔥 Designed for developers, AppSec engineers, and systems programmers who want visibility into native dependencies.

---

## 🧠 Overview

**Master Librarian** inspects local C/C++ libraries using `pkg-config`, extracts metadata, and queries the NVD API to identify known vulnerabilities.

It provides:

- 📦 system-wide library discovery
- 🔎 CVE correlation via NVD
- 🎨 colored severity output (terminal)
- 📊 structured CSV export
- 🛡️ hardened Rust implementation (no unsafe, input validation)

---

## ⚙️ Features

### 🔍 Library Discovery
- Uses `pkg-config` to enumerate installed libraries
- Extracts:
  - versions
  - linked libs
  - include paths
- deduplicates aliases and overlaps

---

### 🧬 Vulnerability Correlation
- Queries the **NVD (National Vulnerability Database)**
- Matches packages using normalized lookup terms
- Deduplicates CVEs across multiple aliases

---

### 🎨 Severity Highlighting (Console)

| Severity | Color |
|----------|------|
| LOW      | 🟡 Yellow |
| MEDIUM   | 🟠 Orange |
| HIGH     | 🔴 Red |
| CRITICAL | 🔴 Blinking Red |

---

### 📊 CSV Export

- RFC-compliant CSV (via `csv` crate)
- Safe escaping
- Includes:
  - package metadata
  - CVE ID
  - severity
  - description

---

### 🔐 Security Design

- strict input validation (pkg names)
- no shell injection
- no unsafe Rust
- bounded network timeouts
- deduplication to avoid noisy results

---

## 🚀 Usage

### Build

```bash
cargo build --release
```

---

### Run (console output)

```bash
./target/release/master_librarian_rust --type txt --limit 10
```

---

### Run (CSV output)

```bash
./target/release/master_librarian_rust   --type csv   --limit 20   --csv-output report.csv
```

---

## 📌 Example Output

```text
ssl 3.5.4 (version 3.5.4) [libs: ssl, crypto]

    CVE: CVE-2015-3455
    URL: https://nvd.nist.gov/vuln/detail/CVE-2015-3455
    Date: 2015-05-18
    Description: ...
    Severity V2: LOW
    Severity V3: NULL
```

---

## 🧱 Architecture

- Factory Pattern
  - CLI parsing
  - Output formatter

- Builder Pattern
  - application assembly

- Modules:
  - `pkgconfig` → system discovery
  - `nvd` → API client
  - `formatter` → output layer
  - `models` → domain types
  - `app` → orchestration

---

## 🧠 Why this project?

This tool was built to:

- understand native dependency exposure
- explore low-level system introspection
- bridge Dev + AppSec workflows

It is especially useful for:

- Linux environments
- C/C++ heavy systems
- auditing legacy stacks

---

## ⚠️ Limitations

- depends on `pkg-config`
- relies on keyword matching (not perfect)
- requires internet access (NVD API)

---

## 🧑‍💻 Author

**Orangewarrior**

---

## 🧠 Future Improvements

- local CVE cache
- severity filtering
- parallel queries
- SBOM export (CycloneDX / SPDX)
- integration with container scanning
