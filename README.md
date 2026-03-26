![Rust](https://img.shields.io/badge/language-Rust-orange)
![Security](https://img.shields.io/badge/focus-AppSec-red)
![Unsafe](https://img.shields.io/badge/unsafe-none-success)
![pkg-config](https://img.shields.io/badge/integration-pkg--config-blue)
![NVD](https://img.shields.io/badge/data-NVD-critical)

# 📚 Master librarian 

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

### Run (TXT|JSON|CSV output)

```bash
./target/release/master_librarian_rust --type txt --limit 10 --threads 8 --rate-limit-ms 250
./target/release/master_librarian_rust --type json --limit 10 --threads 8 --rate-limit-ms 250 --json-output report.json
./target/release/master_librarian_rust --type csv --limit 10 --threads 8 --rate-limit-ms 250 --csv-output report.csv
```

---

## 📌 Example Output

```textMaster Librarian v0.4
Tool to search public vulnerabilities on local libraries
by Orangewarrior
Output mode: text
Limit per package: 10
Worker threads: 8
Rate limit: 250 ms


systemd 249 (version 249)
	CVE: CVE-2026-29111
	URL: https://nvd.nist.gov/vuln/detail/CVE-2026-29111
	Date: 2026-03-23T22:16:26.267
	Description: systemd, a system and service manager, (as PID 1) hits an assert and freezes execution when an unprivileged IPC API call is made with spurious data. On version v249 and older the effect is not an assert, but stack overwriting, with the attacker controlled content. From version v250 and newer this is not possible as the safety check causes an assert instead. This IPC call was added in v239, so versions older than that are not affected. Versions 260-rc1, 259.2, 258.5, and 257.11 contain patches. No known workarounds are available.
	Severity V2: NULL
	Severity V3: MEDIUM

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
## 🔍 How this differs from other vulnerability scanners

Tools such as **Trivy**, **Grype**, and similar scanners operate using a fundamentally different model.

### 🧱 Traditional scanners (Trivy, Grype, osv-scanner)

These tools typically:

- analyze:
  - containers
  - filesystems
  - SBOMs
  - package manager databases (apt, rpm, npm, etc.)
- rely on:
  - pre-built vulnerability databases
  - package metadata (not runtime resolution)

👉 They **do NOT inspect native libraries via `pkg-config`**.

---

### 🔥 Master Librarian approach

This tool takes a different path:

- uses `pkg-config` to enumerate **real, installed native libraries**
- extracts:
  - actual linked libraries (`-l`)
  - include paths
  - resolved versions
- queries the **NVD API in real time**
- correlates vulnerabilities directly with:
  - system-level C/C++ dependencies

---

### ⚠️ Why this matters

Many environments rely heavily on:

- system libraries
- manually compiled dependencies
- non-package-managed software

In these cases:

- traditional scanners may **miss exposure**
- dependencies resolved at runtime may **not appear in SBOMs**

---

### 🧠 Summary

| Feature | Master Librarian | Trivy / Grype |
|--------|----------------|--------------|
| pkg-config integration | ✅ | ❌ |
| native C/C++ libs discovery | ✅ | ❌ |
| SBOM-based scanning | ❌ | ✅ |
| container scanning | ❌ | ✅ |
| runtime system introspection | ✅ | ❌ |

---

### 💡 Positioning

> Master Librarian is best understood as a **native library introspection tool with vulnerability correlation**, rather than a traditional vulnerability scanner.


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
