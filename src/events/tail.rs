//! `vetto events <session>` subcommand (Feature 38).
//!
//! Tail and filter JSONL session event logs:
//! - `--filter deny` (blocked attempts, network denies)
//! - `--filter net` (network requests)
//! - `--filter files` (file observations)
//! - `--filter exec` (process executions)
//! - `--follow` / `-f` (streaming tail)
//! - `--json` or formatted table output

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};

use super::types::{Event, FileAccess};
use crate::sanitizer;

/// Filter predicate for events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventTailFilter {
    All,
    Deny,
    Network,
    Files,
    Exec,
    Notice,
    Custom(String),
}

impl EventTailFilter {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "all" | "" => Self::All,
            "deny" | "blocked" => Self::Deny,
            "net" | "network" => Self::Network,
            "file" | "files" => Self::Files,
            "exec" | "process" | "procs" => Self::Exec,
            "notice" | "notices" => Self::Notice,
            other => Self::Custom(other.to_string()),
        }
    }

    pub fn matches(&self, event: &Event) -> bool {
        match self {
            Self::All => true,
            Self::Deny => {
                matches!(event, Event::BlockedAttempt { .. })
                    || matches!(event, Event::NetRequest { allowed: false, .. })
                    || matches!(event, Event::NetQuotaExceeded { .. })
            }
            Self::Network => matches!(
                event,
                Event::NetRequest { .. }
                    | Event::DnsResolved { .. }
                    | Event::NetEgress { .. }
                    | Event::NetQuotaExceeded { .. }
            ),
            Self::Files => {
                matches!(
                    event,
                    Event::FileObserved { .. } | Event::SecretMasked { .. }
                )
            }
            Self::Exec => matches!(event, Event::ExecObserved { .. }),
            Self::Notice => matches!(event, Event::Notice { .. } | Event::SessionTimeout { .. }),
            Self::Custom(query) => {
                let q = query.to_ascii_lowercase();
                let kind_match = event.kind().to_ascii_lowercase().contains(&q);
                let path_match = event
                    .path()
                    .is_some_and(|p| p.to_ascii_lowercase().contains(&q));
                let net_match = event
                    .network_target()
                    .is_some_and(|(h, _, _)| h.to_ascii_lowercase().contains(&q));
                kind_match || path_match || net_match
            }
        }
    }
}

/// Format an event as a clean table row.
pub fn format_event_row(event: &Event) -> String {
    let t = event.ts().format("%H:%M:%S").to_string();
    let kind = event.kind();
    match event {
        Event::SessionStarted {
            pid, tier, profile, ..
        } => {
            format!(
                "{:<10}  {:<16}  pid={:<6}  profile={} tier={}",
                t, kind, pid, profile, tier
            )
        }
        Event::SessionEnded {
            exit_code,
            duration_secs,
            ..
        } => {
            format!(
                "{:<10}  {:<16}  exit={:<5}  duration={}s",
                t, kind, exit_code, duration_secs
            )
        }
        Event::FileObserved {
            comm,
            pid,
            path,
            access,
            ..
        } => {
            let a = match access {
                FileAccess::Read => "read",
                FileAccess::Write => "write",
                FileAccess::Unknown => "open",
            };
            format!(
                "{:<10}  {:<16}  {}[{}]  {} ({})",
                t, kind, comm, pid, path, a
            )
        }
        Event::ExecObserved { pid, argv, .. } => {
            let cmd = sanitizer::sanitize_line(&argv.join(" "));
            format!("{:<10}  {:<16}  pid={:<6}  exec: {}", t, kind, pid, cmd)
        }
        Event::BlockedAttempt {
            comm,
            pid,
            path,
            source,
            ..
        } => {
            format!(
                "{:<10}  {:<16}  {}[{}]  BLOCKED {} [{}]",
                t, "BLOCKED", comm, pid, path, source
            )
        }
        Event::NetRequest {
            host,
            port,
            allowed,
            ..
        } => {
            let status = if *allowed { "ALLOW" } else { "DENIED" };
            format!(
                "{:<10}  {:<16}  {:<10}  {}:{}",
                t, "net_request", status, host, port
            )
        }
        Event::DnsResolved { host, ips, .. } => {
            format!(
                "{:<10}  {:<16}  {:<10}  {} -> {:?}",
                t, "dns_resolved", "DNS", host, ips
            )
        }
        Event::NetEgress {
            host,
            ip,
            port,
            bytes_tx,
            bytes_rx,
            ..
        } => {
            format!(
                "{:<10}  {:<16}  {:<10}  {}:{} (tx={} rx={})",
                t, "net_egress", ip, host, port, bytes_tx, bytes_rx
            )
        }
        Event::NetQuotaExceeded {
            host,
            limit_bytes,
            used_bytes,
            ..
        } => {
            format!(
                "{:<10}  {:<16}  {:<10}  {} (limit={} used={})",
                t, "net_quota", "EXCEEDED", host, limit_bytes, used_bytes
            )
        }
        Event::SecretMasked { path, .. } => {
            format!(
                "{:<10}  {:<16}  {:<10}  masked: {}",
                t, kind, "MASKED", path
            )
        }
        Event::Notice { message, .. } => {
            format!("{:<10}  {:<16}  {:<10}  {}", t, kind, "NOTICE", message)
        }
        Event::SessionTimeout { .. } => {
            format!(
                "{:<10}  {:<16}  {:<10}  sandbox killed (timeout)",
                t, kind, "TIMEOUT"
            )
        }
    }
}

/// Resolves session JSONL path from file path or session ID.
pub fn resolve_session_path(session_arg: &Path) -> Result<PathBuf> {
    if session_arg.is_file() {
        return Ok(session_arg.to_path_buf());
    }
    // Check if appending .jsonl finds it
    let with_ext = session_arg.with_extension("jsonl");
    if with_ext.is_file() {
        return Ok(with_ext);
    }

    let session_str = session_arg.to_string_lossy();
    let raw = session_str.trim_end_matches(".jsonl");
    let stripped = raw.strip_prefix("session-").unwrap_or(raw);

    // Check in ~/.vetto/logs/ and ~/.vetto/
    if let Some(home) = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
    {
        let logs_dir = home.join(".vetto").join("logs");

        // 1. ~/.vetto/logs/<session>.jsonl
        let direct_log = logs_dir.join(format!("{raw}.jsonl"));
        if direct_log.is_file() {
            return Ok(direct_log);
        }

        // 2. ~/.vetto/logs/session-<session>.jsonl
        let session_log = logs_dir.join(format!("session-{raw}.jsonl"));
        if session_log.is_file() {
            return Ok(session_log);
        }

        // If session was already prefixed with "session-", check the stripped variant too
        let stripped_log = logs_dir.join(format!("{stripped}.jsonl"));
        if stripped_log.is_file() {
            return Ok(stripped_log);
        }
        let stripped_session_log = logs_dir.join(format!("session-{stripped}.jsonl"));
        if stripped_session_log.is_file() {
            return Ok(stripped_session_log);
        }

        let in_logs = logs_dir.join(session_arg);
        if in_logs.is_file() {
            return Ok(in_logs);
        }

        // Check in ~/.vetto/reports/
        let in_reports = home.join(".vetto").join("reports").join(session_arg);
        if in_reports.is_file() {
            return Ok(in_reports);
        }
        let in_reports_ext = home.join(".vetto").join("reports").join(&with_ext);
        if in_reports_ext.is_file() {
            return Ok(in_reports_ext);
        }
        let in_reports_sub = home
            .join(".vetto")
            .join("reports")
            .join(raw)
            .join(format!("{raw}.jsonl"));
        if in_reports_sub.is_file() {
            return Ok(in_reports_sub);
        }

        // Check in ~/.vetto/
        let in_home = home.join(".vetto").join(session_arg);
        if in_home.is_file() {
            return Ok(in_home);
        }
        let in_home_ext = home.join(".vetto").join(&with_ext);
        if in_home_ext.is_file() {
            return Ok(in_home_ext);
        }
    }

    let in_dot_vetto = Path::new(".vetto").join("reports").join(session_arg);
    if in_dot_vetto.is_file() {
        return Ok(in_dot_vetto);
    }
    let in_dot_vetto_ext = Path::new(".vetto").join("reports").join(&with_ext);
    if in_dot_vetto_ext.is_file() {
        return Ok(in_dot_vetto_ext);
    }

    Ok(session_arg.to_path_buf())
}

/// Execute the `vetto events` command.
pub fn run_events(
    session_arg: &Path,
    filter_str: Option<&str>,
    follow: bool,
    json_output: bool,
) -> Result<()> {
    let path = resolve_session_path(session_arg)?;
    if !path.exists() {
        anyhow::bail!("session log file '{}' does not exist", path.display());
    }

    let filter = filter_str
        .map(EventTailFilter::parse)
        .unwrap_or(EventTailFilter::All);
    let file = File::open(&path).with_context(|| format!("open {}", path.display()))?;
    let mut reader = BufReader::new(file);

    let mut line = String::new();
    let mut printed_header = false;

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                if !follow {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                // Skip sink metadata line
                if trimmed.contains("\"_vetto\":") {
                    continue;
                }
                if let Ok(event) = serde_json::from_str::<Event>(trimmed) {
                    if filter.matches(&event) {
                        if json_output {
                            println!("{}", serde_json::to_string(&event)?);
                        } else {
                            if !printed_header {
                                println!(
                                    "{:<10}  {:<16}  {:<10}  DETAILS",
                                    "TIME", "EVENT", "TARGET/PID"
                                );
                                println!("{:-<10}  {:-<16}  {:-<10}  {:-<30}", "", "", "", "");
                                printed_header = true;
                            }
                            println!("{}", format_event_row(&event));
                        }
                    }
                }
            }
            Err(e) => {
                if !follow {
                    return Err(e).context("read error");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn filter_matches_correct_events() {
        let blocked = Event::BlockedAttempt {
            ts: Utc::now(),
            pid: 1,
            comm: "cat".into(),
            path: "/etc/shadow".into(),
            source: "landlock".into(),
        };
        let file_obs = Event::FileObserved {
            ts: Utc::now(),
            pid: 1,
            comm: "python".into(),
            path: "/tmp/foo.py".into(),
            access: FileAccess::Read,
        };
        let net_obs = Event::NetRequest {
            ts: Utc::now(),
            host: "example.com".into(),
            port: 443,
            allowed: true,
        };

        assert!(EventTailFilter::Deny.matches(&blocked));
        assert!(!EventTailFilter::Deny.matches(&file_obs));
        assert!(!EventTailFilter::Deny.matches(&net_obs));

        assert!(EventTailFilter::Files.matches(&file_obs));
        assert!(!EventTailFilter::Files.matches(&net_obs));

        assert!(EventTailFilter::Network.matches(&net_obs));
        assert!(!EventTailFilter::Network.matches(&file_obs));

        let custom = EventTailFilter::Custom("shadow".into());
        assert!(custom.matches(&blocked));
        assert!(!custom.matches(&file_obs));
    }

    #[test]
    fn test_resolve_session_path_direct_file() {
        let temp_dir = std::env::temp_dir().join(format!("vetto-tail-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let file_path = temp_dir.join("direct_session.jsonl");
        std::fs::write(&file_path, b"{}\n").expect("write test file");

        let resolved = resolve_session_path(&file_path).expect("resolve direct file");
        assert_eq!(resolved, file_path);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_resolve_session_path_in_logs_dir() {
        if let Some(home) = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
        {
            let logs_dir = home.join(".vetto").join("logs");
            if std::fs::create_dir_all(&logs_dir).is_err() {
                return;
            }

            // Test <session>.jsonl
            let s1 = format!("test-tail-unit-{}", std::process::id());
            let log1 = logs_dir.join(format!("{s1}.jsonl"));
            if std::fs::write(&log1, b"{}\n").is_err() {
                return;
            }

            let res1 = resolve_session_path(Path::new(&s1)).expect("resolve s1");
            assert_eq!(res1, log1);

            // Test session-<session>.jsonl
            let s2 = format!("test-tail-sup-{}", std::process::id());
            let log2 = logs_dir.join(format!("session-{s2}.jsonl"));
            if std::fs::write(&log2, b"{}\n").is_err() {
                let _ = std::fs::remove_file(log1);
                return;
            }

            let res2 = resolve_session_path(Path::new(&s2)).expect("resolve s2");
            assert_eq!(res2, log2);

            let res2_prefixed = resolve_session_path(Path::new(&format!("session-{s2}")))
                .expect("resolve prefixed");
            assert_eq!(res2_prefixed, log2);

            let _ = std::fs::remove_file(log1);
            let _ = std::fs::remove_file(log2);
        }
    }

    #[test]
    fn test_filter_matches_additional_categories() {
        let exec_ev = Event::ExecObserved {
            ts: Utc::now(),
            pid: 10,
            argv: vec!["cargo".into(), "test".into()],
        };
        let notice_ev = Event::Notice {
            ts: Utc::now(),
            message: "hello notice".into(),
        };
        let timeout_ev = Event::SessionTimeout { ts: Utc::now() };
        let quota_ev = Event::NetQuotaExceeded {
            ts: Utc::now(),
            host: "api.anthropic.com".into(),
            limit_bytes: 1000,
            used_bytes: 2000,
        };
        let dns_ev = Event::DnsResolved {
            ts: Utc::now(),
            host: "api.openai.com".into(),
            ips: vec!["1.1.1.1".into()],
        };

        assert!(EventTailFilter::Exec.matches(&exec_ev));
        assert!(!EventTailFilter::Exec.matches(&notice_ev));

        assert!(EventTailFilter::Notice.matches(&notice_ev));
        assert!(EventTailFilter::Notice.matches(&timeout_ev));

        assert!(EventTailFilter::Deny.matches(&quota_ev));
        assert!(EventTailFilter::Network.matches(&quota_ev));
        assert!(EventTailFilter::Network.matches(&dns_ev));

        assert_eq!(EventTailFilter::parse("procs"), EventTailFilter::Exec);
        assert_eq!(EventTailFilter::parse("network"), EventTailFilter::Network);
        assert_eq!(EventTailFilter::parse("blocked"), EventTailFilter::Deny);
    }

    #[test]
    fn test_format_event_row_outputs() {
        let ev = Event::Notice {
            ts: Utc::now(),
            message: "recap complete".into(),
        };
        let row = format_event_row(&ev);
        assert!(row.contains("NOTICE"));
        assert!(row.contains("recap complete"));
    }
}
