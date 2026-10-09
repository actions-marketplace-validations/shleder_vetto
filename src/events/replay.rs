//! Sandbox session event replay (`vetto replay <session>`) (Feature 45).
//!
//! Replays the chronological sequence of sandbox observation and security enforcement
//! events from a session JSONL log with optional speed-scaling (`--speed 1.0` for real-time).
//!
//! NOTE: This replays sandbox events (file opens, network connections, blocked attempts,
//! process spawns), NOT interactive user terminal keystrokes.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};

use super::tail::resolve_session_path;
use super::types::{Event, FileAccess};
use crate::sanitizer;

pub fn run_replay(session_arg: &Path, speed: Option<f64>, json_output: bool) -> Result<()> {
    let path = resolve_session_path(session_arg)?;
    if !path.exists() {
        anyhow::bail!("session log file '{}' does not exist", path.display());
    }

    let file = File::open(&path).with_context(|| format!("open {}", path.display()))?;
    let reader = BufReader::new(file);

    let mut events = Vec::new();
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.contains("\"_vetto\":") {
            continue;
        }
        if let Ok(event) = serde_json::from_str::<Event>(trimmed) {
            events.push(event);
        }
    }

    if events.is_empty() {
        println!("No recorded events found in {}.", path.display());
        return Ok(());
    }

    // Sort by timestamp
    events.sort_by_key(|e| e.ts());

    let speed_factor = speed.unwrap_or(0.0);
    let start_ts = events[0].ts();
    let mut prev_ts = start_ts;

    if !json_output {
        println!("=== vetto sandbox session replay: {} ===", path.display());
        println!(
            "Events: {} | Speed: {}",
            events.len(),
            if speed_factor > 0.0 {
                format!("{speed_factor}x")
            } else {
                "instant".into()
            }
        );
        println!("NOTE: Replaying sandbox security & observation telemetry, not terminal input.\n");
        println!("{:<12}  {:<8}  {:<16}  DETAILS", "OFFSET", "DELTA", "EVENT");
        println!("{:-<12}  {:-<8}  {:-<16}  {:-<40}", "", "", "", "");
    }

    for event in &events {
        let cur_ts = event.ts();
        let offset_ms = cur_ts
            .signed_duration_since(start_ts)
            .num_milliseconds()
            .max(0);
        let delta_ms = cur_ts
            .signed_duration_since(prev_ts)
            .num_milliseconds()
            .max(0);

        if speed_factor > 0.0 && delta_ms > 0 {
            let sleep_ms = ((delta_ms as f64) / speed_factor).min(5000.0) as u64;
            if sleep_ms > 0 {
                std::thread::sleep(Duration::from_millis(sleep_ms));
            }
        }
        prev_ts = cur_ts;

        if json_output {
            println!("{}", serde_json::to_string(event)?);
        } else {
            let offset_str = format_millis_offset(offset_ms as u64);
            let delta_str = format!("+{:.3}s", (delta_ms as f64) / 1000.0);
            let kind = event.kind();
            let details = describe_replay_event(event);
            println!(
                "{:<12}  {:<8}  {:<16}  {}",
                offset_str, delta_str, kind, details
            );
        }
    }

    if !json_output {
        println!("\n=== Replay complete ===");
    }

    Ok(())
}

fn format_millis_offset(ms: u64) -> String {
    let total_secs = ms / 1000;
    let millis = ms % 1000;
    let mins = total_secs / 60;
    let secs = total_secs % 60;
    format!("{mins:02}:{secs:02}.{millis:03}")
}

fn describe_replay_event(event: &Event) -> String {
    match event {
        Event::SessionStarted {
            pid,
            tier,
            net_mode,
            profile,
            ..
        } => {
            format!("pid={pid} tier={tier} net={net_mode} profile={profile}")
        }
        Event::SessionEnded {
            exit_code,
            duration_secs,
            ..
        } => {
            format!("exit_code={exit_code} duration={duration_secs}s")
        }
        Event::FileObserved {
            comm,
            pid,
            path,
            access,
            ..
        } => {
            let acc = match access {
                FileAccess::Read => "read",
                FileAccess::Write => "write",
                FileAccess::Unknown => "open",
            };
            format!("{comm}[{pid}] {acc} {path}")
        }
        Event::ExecObserved { pid, argv, .. } => {
            format!(
                "pid={pid} exec: {}",
                sanitizer::sanitize_line(&argv.join(" "))
            )
        }
        Event::BlockedAttempt {
            comm,
            pid,
            path,
            source,
            ..
        } => {
            format!("{comm}[{pid}] BLOCKED '{path}' via {source}")
        }
        Event::NetRequest {
            host,
            port,
            allowed,
            ..
        } => {
            format!(
                "{}:{} -> {}",
                host,
                port,
                if *allowed { "ALLOW" } else { "DENIED" }
            )
        }
        Event::DnsResolved { host, ips, .. } => {
            format!("dns {host} -> {:?}", ips)
        }
        Event::NetEgress {
            host,
            ip,
            port,
            bytes_tx,
            bytes_rx,
            ..
        } => {
            format!("net {host} ({ip}:{port}) tx={bytes_tx} rx={bytes_rx}")
        }
        Event::NetQuotaExceeded {
            host,
            limit_bytes,
            used_bytes,
            ..
        } => {
            format!("quota exceeded {host}: {used_bytes}/{limit_bytes} bytes")
        }
        Event::SecretMasked { path, .. } => {
            format!("masked secret mount: {path}")
        }
        Event::Notice { message, .. } => message.clone(),
        Event::SessionTimeout { .. } => "session deadline reached, sandbox torn down".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn format_millis_offset_renders_correctly() {
        assert_eq!(format_millis_offset(0), "00:00.000");
        assert_eq!(format_millis_offset(1500), "00:01.500");
        assert_eq!(format_millis_offset(65432), "01:05.432");
    }

    #[test]
    fn describe_replay_event_formats_all_types() {
        let blocked = Event::BlockedAttempt {
            ts: Utc::now(),
            pid: 42,
            comm: "cat".into(),
            path: "/etc/shadow".into(),
            source: "landlock".into(),
        };
        let desc = describe_replay_event(&blocked);
        assert!(desc.contains("BLOCKED"));
        assert!(desc.contains("/etc/shadow"));
    }

    #[test]
    fn events_are_sorted_chronologically() {
        let now = Utc::now();
        let e1 = Event::Notice {
            ts: now + chrono::Duration::seconds(10),
            message: "third".into(),
        };
        let e2 = Event::Notice {
            ts: now,
            message: "first".into(),
        };
        let e3 = Event::Notice {
            ts: now + chrono::Duration::seconds(5),
            message: "second".into(),
        };
        let mut events = [e1, e2, e3];
        events.sort_by_key(|e| e.ts());

        let messages: Vec<&str> = events
            .iter()
            .map(|e| match e {
                Event::Notice { message, .. } => message.as_str(),
                _ => "",
            })
            .collect();
        assert_eq!(messages, vec!["first", "second", "third"]);
    }

    #[test]
    fn speed_scaling_computes_expected_delays() {
        let delta_ms = 1000u64;

        // 1.0x speed
        let speed_1x = 1.0f64;
        let sleep_1x = ((delta_ms as f64) / speed_1x).min(5000.0) as u64;
        assert_eq!(sleep_1x, 1000);

        // 2.0x speed
        let speed_2x = 2.0f64;
        let sleep_2x = ((delta_ms as f64) / speed_2x).min(5000.0) as u64;
        assert_eq!(sleep_2x, 500);

        // 0.5x speed
        let speed_half = 0.5f64;
        let sleep_half = ((delta_ms as f64) / speed_half).min(5000.0) as u64;
        assert_eq!(sleep_half, 2000);

        // Max cap at 5000ms
        let large_delta = 60_000u64;
        let sleep_capped = ((large_delta as f64) / speed_1x).min(5000.0) as u64;
        assert_eq!(sleep_capped, 5000);
    }

    #[test]
    fn describe_replay_event_covers_all_event_types() {
        let now = Utc::now();
        let evs = vec![
            Event::SessionStarted {
                ts: now,
                pid: 100,
                tier: "full".into(),
                net_mode: "off".into(),
                profile: "strict".into(),
                shadow: false,
            },
            Event::SessionEnded {
                ts: now,
                exit_code: 0,
                duration_secs: 5,
            },
            Event::FileObserved {
                ts: now,
                pid: 100,
                comm: "sh".into(),
                path: "/tmp/foo".into(),
                access: FileAccess::Write,
            },
            Event::ExecObserved {
                ts: now,
                pid: 100,
                argv: vec!["ls".into(), "-la".into()],
            },
            Event::NetRequest {
                ts: now,
                host: "api.anthropic.com".into(),
                port: 443,
                allowed: true,
            },
            Event::DnsResolved {
                ts: now,
                host: "example.com".into(),
                ips: vec!["93.184.216.34".into()],
            },
            Event::NetEgress {
                ts: now,
                host: "example.com".into(),
                ip: "93.184.216.34".into(),
                port: 443,
                bytes_tx: 50,
                bytes_rx: 200,
            },
            Event::NetQuotaExceeded {
                ts: now,
                host: "example.com".into(),
                limit_bytes: 100,
                used_bytes: 150,
            },
            Event::SecretMasked {
                ts: now,
                path: "~/.ssh/id_rsa".into(),
            },
            Event::Notice {
                ts: now,
                message: "system notice".into(),
            },
            Event::SessionTimeout { ts: now },
        ];

        for ev in &evs {
            let desc = describe_replay_event(ev);
            assert!(!desc.is_empty(), "description for {:?} was empty", ev);
        }
    }
}
