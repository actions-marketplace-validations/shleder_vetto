//! Multi-agent fleet concurrency and swarm orchestration integration tests.
//!
//! Validates `vetto fleet status`, `vetto fleet verify`, `vetto fleet spawn`, and `vetto fleet kill`.

use crate::common::*;
use std::sync::Mutex;

static FLEET_TEST_LOCK: Mutex<()> = Mutex::new(());

/// 1) `test_fleet_status_and_verify_json`:
/// - Executes `vetto fleet status --json` -> asserts exit 0 and valid JSON with
///   `active_count: 0`, `max_agents: 64`, `cpu_weight: 100`, `memory_limit_bytes: 2147483648`,
///   `pids_max: 128`, `ipc_isolation: true`, `base_port: 49201`, `workers: []`.
/// - Executes `vetto fleet verify --workers 8 --json` -> asserts exit 0 and valid JSON with
///   `workers_checked: 8`, `pairs_verified: 28`, `verdict: "PASS"`, `disjoint_ports: true`,
///   `disjoint_cow_branches: true`, `disjoint_cgroup_scopes: true`, `ipc_isolated: true`,
///   `pid_isolated: true`.
#[test]
fn test_fleet_status_and_verify_json() {
    let _guard = FLEET_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let proj = TempProject::new("fleet-status-verify");

    // Clean up any stale state first
    let _ = run_vetto_in(proj.path(), &["fleet", "kill", "--all"]);

    // 1. Check `vetto fleet status --json`
    let out_status = run_vetto_in(proj.path(), &["fleet", "status", "--json"]);
    assert!(
        out_status.status.success(),
        "fleet status --json failed with exit code {:?}: stderr={}",
        out_status.status.code(),
        stderr(&out_status)
    );

    let status_json: serde_json::Value =
        serde_json::from_str(&stdout(&out_status)).expect("valid JSON from fleet status");

    assert_eq!(status_json["active_count"], 0);
    assert_eq!(status_json["max_agents"], 64);
    assert_eq!(status_json["cpu_weight"], 100);
    assert_eq!(status_json["memory_limit_bytes"], 2147483648u64);
    assert_eq!(status_json["pids_max"], 128);
    assert_eq!(status_json["ipc_isolation"], true);
    assert_eq!(status_json["base_port"], 49201);
    assert_eq!(
        status_json["workers"]
            .as_array()
            .expect("workers array")
            .len(),
        0
    );

    // 2. Check `vetto fleet verify --workers 8 --json`
    let out_verify = run_vetto_in(
        proj.path(),
        &["fleet", "verify", "--workers", "8", "--json"],
    );
    assert!(
        out_verify.status.success(),
        "fleet verify --workers 8 --json failed with exit code {:?}: stderr={}",
        out_verify.status.code(),
        stderr(&out_verify)
    );

    let verify_json: serde_json::Value =
        serde_json::from_str(&stdout(&out_verify)).expect("valid JSON from fleet verify");

    assert_eq!(verify_json["workers_checked"], 8);
    assert_eq!(verify_json["pairs_verified"], 28);
    assert_eq!(verify_json["verdict"], "PASS");
    assert_eq!(verify_json["disjoint_ports"], true);
    assert_eq!(verify_json["disjoint_cow_branches"], true);
    assert_eq!(verify_json["disjoint_cgroup_scopes"], true);
    assert_eq!(verify_json["ipc_isolated"], true);
    assert_eq!(verify_json["pid_isolated"], true);
}

/// 2) `test_fleet_spawn_concurrent_workers`:
/// - Executes `vetto fleet spawn --count 3 -- sh -c "echo worker"` (or `true`).
/// - Asserts exit 0, and asserts subsequent `vetto fleet status --json` has 0 active workers (zero leaked slots).
#[test]
fn test_fleet_spawn_concurrent_workers() {
    let _guard = FLEET_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let proj = TempProject::new("fleet-spawn-concurrent");

    // Clean up any stale state first
    let _ = run_vetto_in(proj.path(), &["fleet", "kill", "--all"]);

    #[cfg(unix)]
    let spawn_args = &["fleet", "spawn", "--count", "3", "--", "true"];
    #[cfg(windows)]
    let spawn_args = &[
        "fleet", "spawn", "--count", "3", "--", "cmd.exe", "/c", "exit 0",
    ];

    let out_spawn = run_vetto_in(proj.path(), spawn_args);
    assert!(
        out_spawn.status.success(),
        "fleet spawn --count 3 failed with exit code {:?}: stdout={}, stderr={}",
        out_spawn.status.code(),
        stdout(&out_spawn),
        stderr(&out_spawn)
    );

    let out_status = run_vetto_in(proj.path(), &["fleet", "status", "--json"]);
    assert!(
        out_status.status.success(),
        "fleet status --json failed with exit code {:?}: stderr={}",
        out_status.status.code(),
        stderr(&out_status)
    );

    let status_json: serde_json::Value =
        serde_json::from_str(&stdout(&out_status)).expect("valid JSON from fleet status");

    assert_eq!(
        status_json["active_count"], 0,
        "Expected active_count == 0 after spawn completion, got: {}",
        status_json["active_count"]
    );
    let workers = status_json["workers"].as_array().expect("workers array");
    assert_eq!(
        workers.len(),
        0,
        "Zero leaked slots expected after session completion, but found: {:?}",
        workers
    );
}

/// 3) `test_fleet_lifecycle_and_kill_all`:
/// - Sets up mock worker in `$HOME/.vetto/fleet/workers.json` inside isolated `test_home()`.
/// - Runs `vetto fleet status --json` asserting active worker is listed.
/// - Runs `vetto fleet kill --all` asserting exit 0.
/// - Runs `vetto fleet status --json` asserting active count is 0.
#[test]
fn test_fleet_lifecycle_and_kill_all() {
    let _guard = FLEET_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let proj = TempProject::new("fleet-lifecycle-kill");

    let fleet_dir = test_home().join(".vetto").join("fleet");
    std::fs::create_dir_all(&fleet_dir).expect("create test fleet directory");
    let workers_file = fleet_dir.join("workers.json");

    let mock_worker = serde_json::json!({
        "active_count": 1,
        "max_agents": 64,
        "cpu_weight": 100,
        "memory_limit_bytes": 2147483648u64,
        "pids_max": 128,
        "ipc_isolation": true,
        "base_port": 49201,
        "workers": [
            {
                "worker_id": "agent-01",
                "agent_name": "claude",
                "scope_path": "/sys/fs/cgroup/vetto-fleet/agent-01.scope",
                "cow_branch_name": "agent-01",
                "ephemeral_port": 49201,
                "cpu_weight": 100,
                "memory_limit_bytes": 2147483648u64,
                "pids_max": 128,
                "ipc_isolated": true,
                "allocated_at": chrono::Utc::now().to_rfc3339(),
                "pid": null,
                "status": "allocated",
                "workspace_dir": ""
            }
        ]
    });

    std::fs::write(
        &workers_file,
        serde_json::to_string_pretty(&mock_worker).unwrap(),
    )
    .expect("write mock workers file");

    // Runs `vetto fleet status --json` asserting active worker is listed.
    let out_status = run_vetto_in(proj.path(), &["fleet", "status", "--json"]);
    assert!(
        out_status.status.success(),
        "fleet status --json failed with exit code {:?}: stderr={}",
        out_status.status.code(),
        stderr(&out_status)
    );
    let status_json: serde_json::Value =
        serde_json::from_str(&stdout(&out_status)).expect("valid JSON from fleet status");
    assert_eq!(status_json["active_count"], 1);
    let workers = status_json["workers"].as_array().expect("workers array");
    assert_eq!(workers.len(), 1);
    assert_eq!(workers[0]["worker_id"], "agent-01");

    // Runs `vetto fleet kill --all` asserting exit 0.
    let out_kill = run_vetto_in(proj.path(), &["fleet", "kill", "--all"]);
    assert!(
        out_kill.status.success(),
        "fleet kill --all failed with exit code {:?}: stderr={}",
        out_kill.status.code(),
        stderr(&out_kill)
    );

    // Runs `vetto fleet status --json` asserting active count is 0.
    let out_after = run_vetto_in(proj.path(), &["fleet", "status", "--json"]);
    assert!(
        out_after.status.success(),
        "fleet status after kill failed with exit code {:?}: stderr={}",
        out_after.status.code(),
        stderr(&out_after)
    );
    let after_json: serde_json::Value =
        serde_json::from_str(&stdout(&out_after)).expect("valid JSON from fleet status");
    assert_eq!(after_json["active_count"], 0);
    let workers_after = after_json["workers"].as_array().expect("workers array");
    assert_eq!(workers_after.len(), 0);
}
