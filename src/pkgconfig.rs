//! Safe package discovery plus structured probing with the `pkg-config` crate.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, bail};

use crate::models::PackageInfo;

pub fn collect_packages() -> anyhow::Result<Vec<PackageInfo>> {
    let output = Command::new("pkg-config")
        .arg("--list-all")
        .output()
        .context("failed to execute pkg-config --list-all")?;

    if !output.status.success() {
        bail!("pkg-config --list-all failed with status {}", output.status);
    }

    let stdout = String::from_utf8(output.stdout).context("pkg-config output was not valid UTF-8")?;
    let mut merged: BTreeMap<(String, Option<String>), PackageInfo> = BTreeMap::new();

    for line in stdout.lines().filter(|line| !line.trim().is_empty()) {
        let package_name = line
            .split_whitespace()
            .next()
            .map(str::to_owned)
            .ok_or_else(|| anyhow::anyhow!("malformed pkg-config output line: {line}"))?;

        if !is_safe_pkg_name(&package_name) {
            continue;
        }

        let probe = pkg_config::Config::new()
            .cargo_metadata(false)
            .env_metadata(false)
            .print_system_cflags(false)
            .print_system_libs(false)
            .probe(&package_name);

        let info = match probe {
            Ok(lib) => {
                let mut libs = lib.libs;
                libs.sort();
                libs.dedup();

                let mut include_paths = path_vec_to_strings(lib.include_paths);
                include_paths.sort();
                include_paths.dedup();

                let version = non_empty_opt(lib.version);
                let lookup_term = build_lookup_term(&package_name, version.as_deref(), &libs);

                PackageInfo {
                    package_name,
                    lookup_term,
                    version,
                    libs,
                    include_paths,
                }
            }
            Err(_) => PackageInfo {
                lookup_term: package_name.clone(),
                package_name,
                version: None,
                libs: Vec::new(),
                include_paths: Vec::new(),
            },
        };

        let key = (info.lookup_term.clone(), info.version.clone());

        match merged.get_mut(&key) {
            Some(existing) => existing.merge_from(info),
            None => {
                merged.insert(key, info);
            }
        }
    }

    Ok(merged.into_values().collect())
}

fn path_vec_to_strings(paths: Vec<PathBuf>) -> Vec<String> {
    paths
        .into_iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect()
}

fn non_empty_opt(value: String) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

fn build_lookup_term(package_name: &str, version: Option<&str>, libs: &[String]) -> String {
    let anchor = libs
        .first()
        .filter(|s| !s.trim().is_empty())
        .map(String::as_str)
        .unwrap_or(package_name);

    match version {
        Some(version) if !version.trim().is_empty() => format!("{anchor} {version}"),
        _ => anchor.to_owned(),
    }
}

fn is_safe_pkg_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'+'))
}
