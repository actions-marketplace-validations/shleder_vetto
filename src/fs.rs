//! Filesystem helpers and lightweight credential scanning.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Determines if a directory name should be skipped during recursive traversal.
pub fn is_ignored_directory(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | "node_modules"
            | "target"
            | "vendor"
            | ".venv"
            | "venv"
            | "dist"
            | "build"
            | "__pycache__"
            | ".vetto"
            | ".vetto-reports"
            | ".cargo"
            | ".rustup"
    )
}

#[derive(Debug, Clone)]
pub struct SecretScanOptions {
    pub max_file_size_bytes: u64,
    pub max_files: usize,
    pub timeout: Duration,
}

impl Default for SecretScanOptions {
    fn default() -> Self {
        Self {
            max_file_size_bytes: 1024 * 1024,
            max_files: 5_000,
            timeout: Duration::from_secs(3),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretFinding {
    pub path: PathBuf,
    pub line: usize,
    pub rule: String,
    pub preview: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretScanResult {
    pub findings: Vec<SecretFinding>,
    pub files_scanned: usize,
    pub bytes_scanned: u64,
    pub timed_out: bool,
}

impl SecretScanResult {
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    pub fn unique_paths(&self) -> Vec<PathBuf> {
        let mut paths: Vec<PathBuf> = self.findings.iter().map(|f| f.path.clone()).collect();
        paths.sort();
        paths.dedup();
        paths
    }
}

fn check_line_for_secret(line: &str) -> Option<(&'static str, String)> {
    let trimmed = line.trim();
    if trimmed.contains("AKIA") {
        return Some(("AWS Access Key ID", "AKIA***".to_string()));
    }
    if trimmed.contains("-----BEGIN") && trimmed.contains("PRIVATE KEY") {
        return Some((
            "Private Key Header",
            "-----BEGIN...PRIVATE KEY-----".to_string(),
        ));
    }
    if trimmed.contains("ghp_") || trimmed.contains("github_pat_") {
        return Some(("GitHub Token", "ghp_***".to_string()));
    }
    None
}

pub fn scan_file(path: &Path, max_size: u64) -> Vec<SecretFinding> {
    let mut findings = Vec::new();
    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let lower_name = filename.to_ascii_lowercase();
    if lower_name.ends_with(".env") || lower_name.contains(".env") {
        findings.push(SecretFinding {
            path: path.to_path_buf(),
            line: 1,
            rule: "Environment file (.env)".to_string(),
            preview: filename.to_string(),
        });
    }

    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return findings,
    };
    if meta.len() > max_size {
        return findings;
    }

    if let Ok(content) = std::fs::read_to_string(path) {
        for (idx, line) in content.lines().enumerate() {
            if let Some((rule, preview)) = check_line_for_secret(line) {
                findings.push(SecretFinding {
                    path: path.to_path_buf(),
                    line: idx + 1,
                    rule: rule.to_string(),
                    preview,
                });
            }
        }
    }
    findings
}

pub fn scan_directory(root: &Path, options: &SecretScanOptions) -> SecretScanResult {
    let mut result = SecretScanResult::default();
    let mut queue = vec![root.to_path_buf()];

    while let Some(dir) = queue.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();
            if path.is_dir() {
                if !is_ignored_directory(&name_str) {
                    queue.push(path);
                }
            } else if path.is_file() {
                result.files_scanned += 1;
                if let Ok(m) = entry.metadata() {
                    result.bytes_scanned += m.len();
                }
                result
                    .findings
                    .extend(scan_file(&path, options.max_file_size_bytes));
                if result.files_scanned >= options.max_files {
                    result.timed_out = true;
                    return result;
                }
            }
        }
    }
    result
}
