//! SARIF 2.1.0 report renderer.
//!
//! Exports security denials and policy violations in OASIS SARIF 2.1.0 standard
//! format for seamless GitHub Code Scanning and CodeQL action integration.

use super::{clean, stats::SessionStats};

/// Normalizes an artifact file path for GitHub Code Scanning:
/// Converts absolute host paths to clean relative paths anchored to `%SRCROOT%`.
fn normalize_path(raw_path: &str) -> String {
    let sanitized = crate::sanitizer::sanitize_line(raw_path);
    let cleaned = clean(&sanitized).replace(['\r', '\n'], " ");
    let p = std::path::Path::new(&cleaned);

    // If path is inside current working directory, strip prefix to get repo-relative path
    if let Ok(cwd) = std::env::current_dir() {
        if let Ok(rel) = p.strip_prefix(&cwd) {
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            if !rel_str.is_empty() {
                return rel_str;
            }
        }
        if let Ok(canonical_cwd) = cwd.canonicalize() {
            if let Ok(rel) = p.strip_prefix(&canonical_cwd) {
                let rel_str = rel.to_string_lossy().replace('\\', "/");
                if !rel_str.is_empty() {
                    return rel_str;
                }
            }
        }
    }

    // Strip leading root slashes / Windows drive letters to make path relative to %SRCROOT%
    let s = cleaned.as_str();
    #[cfg(windows)]
    let s = if s.len() >= 2 && s.as_bytes()[1] == b':' {
        &s[2..]
    } else {
        s
    };
    let s = s.trim_start_matches(['/', '\\']);
    let normalized = s.replace('\\', "/");

    if normalized.is_empty() {
        ".vetto/policy.toml".to_string()
    } else {
        normalized
    }
}

pub fn render(stats: &SessionStats) -> String {
    let mut results = Vec::new();

    // VETTO-FS-001: Filesystem denial
    for blocked in &stats.blocked_attempts {
        let uri = normalize_path(&blocked.path);
        let comm = clean(&crate::sanitizer::sanitize_line(&blocked.comm));
        let source = clean(&crate::sanitizer::sanitize_line(&blocked.source));

        results.push(serde_json::json!({
            "ruleId": "VETTO-FS-001",
            "ruleIndex": 0,
            "level": "error",
            "message": {
                "text": format!(
                    "Blocked filesystem access attempt by {comm} from {source} ({} occurrence(s))",
                    blocked.count
                )
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": uri,
                        "uriBaseId": "%SRCROOT%"
                    }
                }
            }],
            "properties": {
                "count": blocked.count,
                "process": comm,
                "source": source
            }
        }));
    }

    // VETTO-NET-001: Denied network egress
    for request in stats.net_requests.iter().filter(|request| !request.allowed) {
        let host = clean(&crate::sanitizer::sanitize_line(&request.host));
        results.push(serde_json::json!({
            "ruleId": "VETTO-NET-001",
            "ruleIndex": 1,
            "level": "error",
            "message": {
                "text": format!("Denied network CONNECT attempt to {host}:{}", request.port)
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": ".vetto/policy.toml",
                        "uriBaseId": "%SRCROOT%"
                    }
                }
            }],
            "properties": {
                "host": host,
                "port": request.port,
                "allowed": false
            }
        }));
    }

    // VETTO-SYS-001: Suspicious security signal / heuristic
    for signal in &stats.suspicious_signals {
        let category = clean(&crate::sanitizer::sanitize_line(&signal.category));
        let severity = clean(&crate::sanitizer::sanitize_line(&signal.severity));
        let subject = clean(&crate::sanitizer::sanitize_line(&signal.subject));
        let reason = clean(&crate::sanitizer::sanitize_line(&signal.reason));

        results.push(serde_json::json!({
            "ruleId": "VETTO-SYS-001",
            "ruleIndex": 2,
            "level": match severity.as_str() {
                "high" => "warning",
                _ => "note",
            },
            "message": {
                "text": format!(
                    "Suspicious signal intercepted: {reason} ({subject}, {} occurrence(s))",
                    signal.count
                )
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": ".vetto/policy.toml",
                        "uriBaseId": "%SRCROOT%"
                    }
                }
            }],
            "properties": {
                "category": category,
                "severity": severity,
                "subject": subject,
                "count": signal.count,
                "advisoryOnly": true
            }
        }));
    }

    let payload = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "vetto",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/shleder/vetto",
                    "rules": [
                        {
                            "id": "VETTO-FS-001",
                            "name": "FilesystemAccessViolation",
                            "shortDescription": { "text": "Filesystem access attempt blocked by sandbox security policy." },
                            "fullDescription": { "text": "The agent process attempted to access, read, or modify a filesystem path restricted by Landlock LSM or sandbox mount policies." },
                            "help": {
                                "text": "Review the accessed path in policy.toml and explicitly allow it with 'vetto allow <path>' if the access was intended.",
                                "markdown": "Review the accessed path in `policy.toml` and explicitly allow it with `vetto allow <path>` if the access was intended."
                            },
                            "defaultConfiguration": { "level": "error" }
                        },
                        {
                            "id": "VETTO-NET-001",
                            "name": "NetworkEgressViolation",
                            "shortDescription": { "text": "Outbound network CONNECT denied by security policy." },
                            "fullDescription": { "text": "The agent attempted an outbound TCP connection to a domain or port not permitted by policy.toml or preset allowlists." },
                            "help": {
                                "text": "Review the destination domain and permit it with 'vetto allow --net <domain>' if legitimate.",
                                "markdown": "Review the destination domain and permit it with `vetto allow --net <domain>` if legitimate."
                            },
                            "defaultConfiguration": { "level": "error" }
                        },
                        {
                            "id": "VETTO-SYS-001",
                            "name": "SecurityHeuristicViolation",
                            "shortDescription": { "text": "Security heuristic or suspicious syscall intercepted." },
                            "fullDescription": { "text": "A potentially dangerous syscall or anomalous process behavior pattern was detected by runtime observability." },
                            "help": {
                                "text": "Inspect the event details in ~/.vetto/history.jsonl to confirm whether this indicates an exploit attempt.",
                                "markdown": "Inspect the event details in `~/.vetto/history.jsonl` to confirm whether this indicates an exploit attempt."
                            },
                            "defaultConfiguration": { "level": "warning" }
                        }
                    ]
                }
            },
            "originalUriBaseIds": {
                "%SRCROOT%": {
                    "uri": "file:///"
                }
            },
            "results": results,
            "properties": {
                "tier": clean(&stats.tier),
                "networkMode": clean(&stats.net_mode),
                "profile": clean(&stats.profile),
                "exitCode": stats.exit_code,
                "durationSecs": stats.duration_secs,
                "eventsTotal": stats.events_total,
                "fileReads": stats.file_reads,
                "fileWrites": stats.file_writes,
                "blockedAttempts": stats.blocked_attempts.iter().map(|record| record.count).sum::<u64>(),
                "networkDenied": stats.net_requests.iter().filter(|request| !request.allowed).count() as u64,
                "suspiciousSignals": stats.suspicious_signals.iter().map(|record| record.count).sum::<u64>()
            }
        }]
    });
    serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}\n".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::stats::{BlockedRecord, NetRecord, SuspiciousRecord};

    #[test]
    fn emits_sarif_findings_for_blocked_records() {
        let stats = SessionStats {
            blocked_attempts: vec![BlockedRecord {
                path: "/tmp/secret\nvalue".into(),
                comm: "agent".into(),
                source: "landlock".into(),
                count: 2,
            }],
            net_requests: vec![NetRecord {
                host: "example.test".into(),
                port: 22,
                allowed: false,
            }],
            suspicious_signals: vec![SuspiciousRecord {
                category: "syscall".into(),
                severity: "high".into(),
                subject: "ptrace".into(),
                reason: "unauthorized tracing attempt".into(),
                count: 1,
            }],
            ..SessionStats::default()
        };
        let value: serde_json::Value = serde_json::from_str(&render(&stats)).expect("SARIF JSON");
        assert_eq!(value["version"], "2.1.0");
        let results = value["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 3);

        // Result 0: VETTO-FS-001
        assert_eq!(results[0]["ruleId"], "VETTO-FS-001");
        assert_eq!(results[0]["ruleIndex"], 0);
        assert_eq!(results[0]["level"], "error");
        assert!(results[0]["message"]["text"]
            .as_str()
            .unwrap()
            .contains("2 occurrence"));
        let loc0 = &results[0]["locations"][0]["physicalLocation"]["artifactLocation"];
        assert_eq!(loc0["uri"], "tmp/secret value");
        assert_eq!(loc0["uriBaseId"], "%SRCROOT%");

        // Result 1: VETTO-NET-001
        assert_eq!(results[1]["ruleId"], "VETTO-NET-001");
        assert_eq!(results[1]["ruleIndex"], 1);
        assert_eq!(results[1]["level"], "error");
        let loc1 = &results[1]["locations"][0]["physicalLocation"]["artifactLocation"];
        assert_eq!(loc1["uri"], ".vetto/policy.toml");
        assert_eq!(loc1["uriBaseId"], "%SRCROOT%");

        // Result 2: VETTO-SYS-001
        assert_eq!(results[2]["ruleId"], "VETTO-SYS-001");
        assert_eq!(results[2]["ruleIndex"], 2);
        assert_eq!(results[2]["level"], "warning");
        let loc2 = &results[2]["locations"][0]["physicalLocation"]["artifactLocation"];
        assert_eq!(loc2["uri"], ".vetto/policy.toml");
        assert_eq!(loc2["uriBaseId"], "%SRCROOT%");

        // Verify originalUriBaseIds
        assert!(value["runs"][0]["originalUriBaseIds"]["%SRCROOT%"].is_object());
    }

    #[test]
    fn path_normalization_handles_cwd_and_absolute_paths() {
        if let Ok(cwd) = std::env::current_dir() {
            let child = cwd.join("src").join("report").join("sarif.rs");
            assert_eq!(
                normalize_path(&child.to_string_lossy()),
                "src/report/sarif.rs"
            );
        }
        assert_eq!(normalize_path("/etc/passwd"), "etc/passwd");
        assert_eq!(normalize_path("src/lib.rs"), "src/lib.rs");
        assert_eq!(normalize_path("/"), ".vetto/policy.toml");
    }
}
