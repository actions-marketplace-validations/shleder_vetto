//! CLI-only reporting/completion tests; these do not require a sandbox tier.

use crate::common::*;
use std::process::Command;

#[test]
fn completions_are_available_for_all_requested_shells() {
    for shell in ["bash", "zsh", "fish", "powershell", "elvish"] {
        let output = Command::new(vetto_bin())
            .args(["completions", shell])
            .output()
            .expect("spawn completion command");
        assert!(
            output.status.success(),
            "completion failed for {shell}: {}",
            stderr(&output)
        );
        assert!(
            !output.stdout.is_empty(),
            "completion output empty for {shell}"
        );
    }
}

#[test]
fn typo_subcommands_fail_with_clap_error_not_workspace_profile() {
    for typo in [
        "rn",
        "stauts",
        "verify-ng",
        "profiles",
        "profile",
        "watch",
        "digest",
    ] {
        let output = Command::new(vetto_bin())
            .arg(typo)
            .output()
            .expect("spawn subcommand");
        assert!(!output.status.success(), "subcommand '{typo}' must fail");
        let err = stderr(&output);
        assert!(
            err.contains("unrecognized subcommand") || err.contains("unexpected"),
            "stderr for '{typo}' must be a clap error: {err}"
        );
        assert!(
            !err.contains("workspace profile"),
            "stderr for '{typo}' must not mention workspace profile: {err}"
        );
    }
}

#[test]
fn diff_cli_stat_and_json_flags() {
    let project = TempProject::new("cli-reporting-diff");
    let custom_home = TempProject::new("cli-diff-home");
    let home_path = custom_home.path().to_str().expect("valid home path");
    let test_file = project.path().join("tracked_doc.md");
    write_file(&test_file, "# Initial Title\nLine 1\n");

    // 1. diff --stat with no snapshot
    let out_stat = run_vetto_env_in(
        project.path(),
        &["diff", "--stat"],
        &[("HOME", home_path), ("USERPROFILE", home_path)],
    );
    assert!(
        out_stat.status.success(),
        "diff --stat must succeed even when no prior snapshot exists: {}",
        stderr(&out_stat)
    );
    let out_stat_str = stdout(&out_stat);
    assert!(
        out_stat_str.contains("no snapshot found")
            || out_stat_str.contains("diff")
            || out_stat_str.contains("Session Review"),
        "expected diff status notice in: {out_stat_str}"
    );

    // 2. diff --json with no snapshot
    let out_json = run_vetto_env_in(
        project.path(),
        &["diff", "--json"],
        &[("HOME", home_path), ("USERPROFILE", home_path)],
    );
    assert!(
        out_json.status.success(),
        "diff --json must succeed: {}",
        stderr(&out_json)
    );
    let json_val: serde_json::Value =
        serde_json::from_str(&stdout(&out_json)).expect("valid JSON review output");
    assert!(
        json_val.get("session_id").is_some(),
        "JSON review must contain session_id field: {json_val}"
    );
    assert!(
        json_val.get("files").is_some(),
        "JSON review must contain files section: {json_val}"
    );
    assert!(
        json_val.get("security").is_some(),
        "JSON review must contain security section: {json_val}"
    );
    assert_eq!(
        json_val["security"]["blocked_file_reads"].as_u64(),
        Some(0),
        "expected zero blocked file reads in empty diff"
    );
    assert_eq!(
        json_val["files"]["total_changed"].as_u64(),
        Some(0),
        "expected zero changed files in empty review with no snapshot"
    );
}

#[test]
fn audit_cli_latest_and_json_flags() {
    let project = TempProject::new("cli-reporting-audit");
    let custom_home = TempProject::new("cli-audit-home");
    let home_path = custom_home.path().to_str().expect("valid home path");

    // 1. In empty home, audit --latest must fail with actionable message
    let out_empty_latest = run_vetto_env_in(
        project.path(),
        &["audit", "--latest"],
        &[("HOME", home_path)],
    );
    assert!(
        !out_empty_latest.status.success(),
        "audit --latest must return non-zero exit code when no sessions exist"
    );
    let err_msg = stderr(&out_empty_latest);
    assert!(
        err_msg.contains("no past session logs or history found"),
        "expected no past sessions error message in: {err_msg}"
    );

    // 2. In empty home, audit --json returns empty array
    let out_empty_json =
        run_vetto_env_in(project.path(), &["audit", "--json"], &[("HOME", home_path)]);
    assert!(
        out_empty_json.status.success(),
        "audit --json must succeed: {}",
        stderr(&out_empty_json)
    );
    let json_arr: serde_json::Value =
        serde_json::from_str(stdout(&out_empty_json).trim()).expect("valid JSON array");
    assert!(
        json_arr.is_array(),
        "audit --json must return a JSON array: {json_arr}"
    );
    assert_eq!(json_arr.as_array().map(|a| a.len()), Some(0));

    // 3. Write a synthetic session into custom_home/.vetto/logs/ and history.jsonl
    let logs_dir = custom_home.path().join(".vetto").join("logs");
    std::fs::create_dir_all(&logs_dir).expect("create logs dir");
    let session_log = logs_dir.join("session-cli-test-01.jsonl");
    let log_content = concat!(
        r#"{"ts":"2026-10-10T12:00:00Z","pid":4242,"tier":"fs-only","net_mode":"off","profile":"default","event":"session_started"}"#,
        "\n",
        r#"{"ts":"2026-10-10T12:00:00Z","pid":4242,"argv":["test-agent"],"event":"exec_observed"}"#,
        "\n",
        r#"{"ts":"2026-10-10T12:00:01Z","pid":4242,"path":"/etc/shadow","source":"landlock","comm":"test-agent","event":"blocked_attempt"}"#,
        "\n",
        r#"{"ts":"2026-10-10T12:00:02Z","pid":4242,"exit_code":0,"duration_secs":2,"event":"session_ended"}"#,
        "\n"
    );
    write_file(&session_log, log_content);

    let history_file = custom_home.path().join(".vetto").join("history.jsonl");
    let history_record = serde_json::json!({
        "ts": "2026-10-10T12:00:00Z",
        "session_id": "session-cli-test-01",
        "agent": "test-agent",
        "command": "sh -c test",
        "profile": "default",
        "exit_code": 0,
        "duration_secs": 2,
        "tier": "fs-only",
        "net_mode": "off",
        "blocked_count": 1,
        "events_total": 3,
        "log_path": session_log.to_str().unwrap()
    });
    write_file(&history_file, &format!("{}\n", history_record));

    // 4. Now audit --latest must succeed and display session details
    let out_latest = run_vetto_env_in(
        project.path(),
        &["audit", "--latest"],
        &[("HOME", home_path)],
    );
    assert!(
        out_latest.status.success(),
        "audit --latest must succeed with existing session: {}",
        stderr(&out_latest)
    );
    let latest_text = stdout(&out_latest);
    assert!(
        latest_text.contains("session-cli-test-01") || latest_text.contains("/etc/shadow"),
        "expected session details in: {latest_text}"
    );

    // 5. audit --latest --json must return structured SessionAuditDetail JSON
    let out_latest_json = run_vetto_env_in(
        project.path(),
        &["audit", "--latest", "--json"],
        &[("HOME", home_path)],
    );
    assert!(
        out_latest_json.status.success(),
        "audit --latest --json must succeed: {}",
        stderr(&out_latest_json)
    );
    let detail: serde_json::Value =
        serde_json::from_str(&stdout(&out_latest_json)).expect("valid JSON detail");
    assert_eq!(detail["session_id"].as_str(), Some("session-cli-test-01"));
    assert_eq!(detail["violations_total"].as_u64(), Some(1));
    assert_eq!(detail["agent"].as_str(), Some("test-agent"));

    // 6. audit --json must now return an array with 1 record
    let out_json_populated =
        run_vetto_env_in(project.path(), &["audit", "--json"], &[("HOME", home_path)]);
    assert!(out_json_populated.status.success());
    let records: Vec<serde_json::Value> =
        serde_json::from_str(&stdout(&out_json_populated)).expect("valid JSON array");
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0]["session_id"].as_str(),
        Some("session-cli-test-01")
    );
}

#[test]
fn diff_sessions_cli_nonexistent_and_json_flags() {
    let project = TempProject::new("cli-reporting-diff-sessions");

    // 1. diff-sessions with non-existent session IDs must fail with clear error
    let out = run_vetto_in(
        project.path(),
        &["diff-sessions", "nonexistent_a", "nonexistent_b", "--json"],
    );
    assert!(
        !out.status.success(),
        "diff-sessions nonexistent_a nonexistent_b must fail"
    );
    let err = stderr(&out);
    assert!(
        err.contains("inspect session A")
            || err.contains("not found")
            || err.contains("nonexistent_a"),
        "stderr must report missing session A: {err}"
    );

    // 2. diff-sessions with real sessions must output structured JSON diff
    let custom_home = TempProject::new("cli-diff-sessions-home");
    let home_path = custom_home.path().to_str().expect("valid home path");
    let logs_dir = custom_home.path().join(".vetto").join("logs");
    std::fs::create_dir_all(&logs_dir).expect("create logs dir");

    let log_a = logs_dir.join("sess-a.jsonl");
    let log_b = logs_dir.join("sess-b.jsonl");

    let content_a = concat!(
        r#"{"ts":"2026-10-10T10:00:00Z","pid":1001,"tier":"full","net_mode":"off","profile":"default","event":"session_started"}"#,
        "\n",
        r#"{"ts":"2026-10-10T10:00:01Z","pid":1001,"path":"/etc/shadow","source":"landlock","comm":"agent-a","event":"blocked_attempt"}"#,
        "\n",
        r#"{"ts":"2026-10-10T10:00:02Z","pid":1001,"exit_code":0,"duration_secs":2,"event":"session_ended"}"#,
        "\n"
    );
    let content_b = concat!(
        r#"{"ts":"2026-10-10T11:00:00Z","pid":1002,"tier":"full","net_mode":"off","profile":"default","event":"session_started"}"#,
        "\n",
        r#"{"ts":"2026-10-10T11:00:01Z","pid":1002,"path":"/etc/passwd","source":"landlock","comm":"agent-b","event":"blocked_attempt"}"#,
        "\n",
        r#"{"ts":"2026-10-10T11:00:02Z","pid":1002,"exit_code":0,"duration_secs":2,"event":"session_ended"}"#,
        "\n"
    );
    write_file(&log_a, content_a);
    write_file(&log_b, content_b);

    let out_diff = run_vetto_env_in(
        project.path(),
        &["diff-sessions", "sess-a", "sess-b", "--json"],
        &[("HOME", home_path)],
    );
    assert!(
        out_diff.status.success(),
        "diff-sessions between real sessions must succeed: {}",
        stderr(&out_diff)
    );
    let diff_json: serde_json::Value =
        serde_json::from_str(&stdout(&out_diff)).expect("valid JSON diff");
    assert!(
        diff_json.get("policy_diff").is_some(),
        "diff JSON must have policy_diff: {diff_json}"
    );
    assert!(
        diff_json.get("blocks_diff").is_some(),
        "diff JSON must have blocks_diff: {diff_json}"
    );
    assert_eq!(
        diff_json["blocks_diff"]["a_only_paths"],
        serde_json::json!(["/etc/shadow"])
    );
    assert_eq!(
        diff_json["blocks_diff"]["b_only_paths"],
        serde_json::json!(["/etc/passwd"])
    );
}
