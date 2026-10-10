//! Session history tracking and automated timeout estimation (`--timeout auto`).
//!
//! Consolidated into [`crate::audit::history`]. Re-exported here for backwards compatibility.

pub use crate::audit::history::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::Duration;

    #[test]
    fn calculates_p95_timeout_with_floor() {
        let temp = std::env::temp_dir().join(format!("vetto-hist-{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).unwrap();

        // 1. Empty history returns None
        assert_eq!(compute_auto_timeout(&temp, "codex"), None);

        // 2. Short durations hit the 5-minute floor (300s)
        for d in [10, 20, 30, 40, 50] {
            append_session_history(
                &temp,
                &SessionHistoryRecord {
                    agent: "codex".into(),
                    duration_secs: d,
                    ts: "".into(),
                    exit_code: 0,
                },
            )
            .unwrap();
        }
        let timeout = compute_auto_timeout(&temp, "codex").unwrap();
        assert_eq!(timeout, Duration::from_secs(300));

        // 3. Long durations scale properly (p95 * 2)
        for d in 1..=100 {
            append_session_history(
                &temp,
                &SessionHistoryRecord {
                    agent: "heavy-agent".into(),
                    duration_secs: d * 10, // 10s to 1000s, p95 ~ 950s
                    ts: "".into(),
                    exit_code: 0,
                },
            )
            .unwrap();
        }
        let heavy_timeout = compute_auto_timeout(&temp, "heavy-agent").unwrap();
        assert!(heavy_timeout.as_secs() >= 1800);

        let _ = fs::remove_dir_all(&temp);
    }
}
