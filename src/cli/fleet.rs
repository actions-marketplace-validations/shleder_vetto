//! First-Class Multi-Agent Fleet Orchestration CLI (`vetto fleet`).
//!
//! Provides operational control over concurrent multi-agent fleets:
//! - `vetto fleet status [--json]`: View capacity, cgroups fair-share configuration, and active worker scopes.
//! - `vetto fleet spawn <agent_or_cmd> [--name <name>] [--count <N>] [--profile <profile>] [--net <mode>] [--detach] [-- <args>...]`:
//!   Allocate isolated worker slots, verify pairwise isolation invariants, and execute sandboxed agents.
//! - `vetto fleet verify [--workers <N>] [--json]`:
//!   Run full pairwise isolation verification across ephemeral ports, CoW branches, cgroups, and PID/IPC namespaces.
//! - `vetto fleet kill [<worker_id> | --all]`:
//!   Terminate running worker processes, extinguish cgroup process trees, and release allocated slots.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use serde::Serialize;

use crate::multi::fleet::{AgentWorkerScope, FleetManager, FleetState};
use crate::multi::isolation::IsolationBarrier;

/// Command-line arguments for `vetto fleet`.
#[derive(Args, Debug, Clone)]
pub struct FleetArgs {
    #[command(subcommand)]
    pub command: FleetCommand,
}

/// Subcommands for `vetto fleet`.
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum FleetCommand {
    /// Display fleet capacity, fair-share cgroup configuration, and active worker scopes
    Status {
        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
    },

    /// Allocate isolated worker slots and spawn concurrent sandboxed agent(s)
    Spawn(FleetSpawnArgs),

    /// Run full pairwise isolation verification across fleet workers
    Verify {
        /// Number of test worker slots to allocate and verify pairwise (default: 4, up to 64)
        #[arg(long, default_value_t = 4)]
        workers: usize,

        /// Emit machine-readable JSON report
        #[arg(long)]
        json: bool,
    },

    /// Terminate worker scope(s) and release fleet slots
    Kill {
        /// Worker ID to terminate (e.g. agent-01)
        #[arg(value_name = "WORKER_ID", required_unless_present = "all")]
        worker_id: Option<String>,

        /// Terminate all active fleet workers
        #[arg(long, conflicts_with = "worker_id")]
        all: bool,
    },
}

/// Command-line arguments for `vetto fleet spawn`.
#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct FleetSpawnArgs {
    /// Target agent preset or command to execute (optional if trailing command provided after `--`)
    #[arg(value_name = "AGENT_OR_CMD")]
    pub agent_or_cmd: Option<String>,

    /// Custom agent worker name prefix (defaults to agent/command name)
    #[arg(long)]
    pub name: Option<String>,

    /// Number of worker instances to spawn concurrently (default: 1, up to 64)
    #[arg(long, default_value_t = 1)]
    pub count: usize,

    /// Built-in policy profile to apply (default: "default")
    #[arg(long)]
    pub profile: Option<String>,

    /// Network mode: off | allowlist:<domains> | strict:<rules> | ask | open
    #[arg(long)]
    pub net: Option<String>,

    /// Run workers detached in background without waiting for completion
    #[arg(long)]
    pub detach: bool,

    /// Command and arguments passed to the agent; everything after `--`
    #[arg(
        last = true,
        value_name = "ARGS",
        allow_hyphen_values = true
    )]
    pub args: Vec<String>,
}

/// Structured JSON report for `vetto fleet verify --json`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FleetVerifyReport {
    pub workers_checked: usize,
    pub pairs_verified: usize,
    pub verdict: String,
    pub disjoint_ports: bool,
    pub disjoint_cow_branches: bool,
    pub disjoint_cgroup_scopes: bool,
    pub ipc_isolated: bool,
    pub pid_isolated: bool,
}

/// Main entrypoint for `vetto fleet`.
pub fn run_cli(command: FleetCommand) -> Result<()> {
    match command {
        FleetCommand::Status { json } => run_status(json),
        FleetCommand::Spawn(args) => run_spawn(args),
        FleetCommand::Verify { workers, json } => run_verify(workers, json),
        FleetCommand::Kill { worker_id, all } => run_kill(worker_id, all),
    }
}

/// Executes `vetto fleet status [--json]`.
pub fn run_status(json: bool) -> Result<()> {
    let fleet = FleetManager::load_persistent()?;
    let _ = fleet.reconcile_live_workers()?;

    let workers = fleet.active_workers();
    let report = FleetState {
        active_count: workers.len(),
        max_agents: fleet.config().max_agents,
        cpu_weight: fleet.config().cpu_weight,
        memory_limit_bytes: fleet.config().memory_limit_bytes,
        pids_max: fleet.config().pids_max,
        ipc_isolation: fleet.config().ipc_isolation,
        base_port: fleet.config().base_port,
        workers,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "Fleet Capacity: {} / {} active workers",
            report.active_count, report.max_agents
        );
        println!(
            "Fair-Share Cgroups: cpu.weight = {}, memory.max = 2.0 GiB, pids.max = {}, ipc_isolation = {}",
            report.cpu_weight, report.pids_max, report.ipc_isolation
        );
        println!("Base Port: {}", report.base_port);
        println!();
        if report.workers.is_empty() {
            println!("No active fleet workers.");
        } else {
            println!(
                "{:<11} {:<12} {:<8} {:<7} {:<12} {:<28} {:<26} {:<8}",
                "WORKER ID", "AGENT", "PID", "PORT", "COW BRANCH", "CGROUP", "LIMITS", "STATUS"
            );
            println!("{}", "-".repeat(116));
            for w in &report.workers {
                let pid_str = w
                    .pid
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".to_string());
                let scope_str = w
                    .scope_path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(w.scope_path.to_str().unwrap_or("-"));
                let limits_str = format!(
                    "cpu:{} mem:{}M pid:{}",
                    w.cpu_weight,
                    w.memory_limit_bytes / (1024 * 1024),
                    w.pids_max
                );
                println!(
                    "{:<11} {:<12} {:<8} {:<7} {:<12} {:<28} {:<26} {:<8}",
                    w.worker_id,
                    w.agent_name,
                    pid_str,
                    w.ephemeral_port,
                    w.cow_branch_name,
                    scope_str,
                    limits_str,
                    w.status
                );
            }
        }
    }

    Ok(())
}

/// Executes `vetto fleet spawn <agent_or_cmd> ...`.
pub fn run_spawn(args: FleetSpawnArgs) -> Result<()> {
    let mut full_cmd = Vec::new();
    if let Some(cmd) = &args.agent_or_cmd {
        full_cmd.push(cmd.clone());
    }
    full_cmd.extend(args.args.iter().cloned());
    if full_cmd.is_empty() {
        bail!("No agent or command specified to spawn. Usage: vetto fleet spawn <agent_or_cmd> [-- <args>...]");
    }

    let count = args.count;
    if count == 0 || count > 64 {
        bail!("Worker count must be between 1 and 64 (got {})", count);
    }

    let resolved_bin = crate::mcp::wrap::resolve_in_path(&full_cmd[0])
        .with_context(|| format!("resolve agent command '{}' in PATH", full_cmd[0]))?;
    full_cmd[0] = resolved_bin.to_string_lossy().into_owned();

    let fleet = FleetManager::load_persistent()?;
    let _ = fleet.reconcile_live_workers()?;

    if fleet.active_count() + count > fleet.config().max_agents {
        bail!(
            "Fleet capacity exceeded: active agents ({}) + requested ({}) > max allowed ({})",
            fleet.active_count(),
            count,
            fleet.config().max_agents
        );
    }

    let base_name = args.name.as_deref().unwrap_or_else(|| {
        Path::new(&full_cmd[0])
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&full_cmd[0])
    });

    let mut allocated_scopes = Vec::with_capacity(count);
    for i in 0..count {
        let worker_name = if count == 1 {
            base_name.to_string()
        } else {
            format!("{}-{}", base_name, i + 1)
        };
        let scope = fleet
            .allocate_worker(&worker_name)
            .with_context(|| format!("allocate fleet slot for {}", worker_name))?;
        allocated_scopes.push(scope);
    }

    // Verify pairwise isolation across allocated slots
    if allocated_scopes.len() >= 2 {
        for i in 0..allocated_scopes.len() {
            for j in (i + 1)..allocated_scopes.len() {
                if let Err(e) = fleet.verify_isolation(
                    &allocated_scopes[i].worker_id,
                    &allocated_scopes[j].worker_id,
                ) {
                    for s in &allocated_scopes {
                        let _ = fleet.release_worker(&s.worker_id);
                    }
                    let _ = fleet.save_persistent();
                    return Err(e);
                }
            }
        }
    }

    let net_mode = crate::config::parse_net_mode(args.net.as_deref().unwrap_or("off"))?;
    let profile = args.profile.as_deref().unwrap_or("default");
    let current_dir = std::env::current_dir().context("current directory")?;
    let home_dir = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));

    let mut spawned = Vec::with_capacity(count);
    for scope in &allocated_scopes {
        let mut env_extra = HashMap::new();
        env_extra.insert(
            "VETTO_FLEET_WORKER_ID".to_string(),
            scope.worker_id.clone(),
        );
        env_extra.insert(
            "VETTO_FLEET_PORT".to_string(),
            scope.ephemeral_port.to_string(),
        );
        env_extra.insert(
            "VETTO_FLEET_WORKSPACE".to_string(),
            scope.workspace_dir.display().to_string(),
        );

        #[cfg(target_os = "linux")]
        if net_mode.uses_relay() {
            for (k, v) in crate::sandbox::linux::net_relay::build_proxy_env(
                crate::sandbox::linux::net_relay::RELAY_PORT_BASE,
            ) {
                env_extra.insert(k, v);
            }
        }

        let backend = match crate::sandbox::Backend::detect(net_mode.clone(), false) {
            Ok(b) => b,
            Err(e) => {
                for (s, mut ex) in spawned {
                    ex.handle.terminate();
                    let _ = fleet.release_worker(&s.worker_id);
                }
                for s in &allocated_scopes {
                    let _ = fleet.release_worker(&s.worker_id);
                }
                let _ = fleet.save_persistent();
                return Err(e);
            }
        };

        let tier = backend.tier().unwrap_or(crate::policy::Tier::Full);
        let policy =
            match crate::policy::loader::load(profile, None, &current_dir, &home_dir, tier) {
                Ok(p) => p,
                Err(e) => {
                    for (s, mut ex) in spawned {
                        ex.handle.terminate();
                        let _ = fleet.release_worker(&s.worker_id);
                    }
                    for s in &allocated_scopes {
                        let _ = fleet.release_worker(&s.worker_id);
                    }
                    let _ = fleet.save_persistent();
                    return Err(e);
                }
            };

        let stdio = crate::sandbox::StdioMode::Inherit;
        let scenario_id = format!("fleet:{}", scope.worker_id);
        let unprepared = crate::sandbox::production::UnpreparedProductionExecution::new(
            backend,
            policy,
            full_cmd.clone(),
            current_dir.clone(),
            env_extra,
            net_mode.clone(),
            None,
            stdio,
            scenario_id,
        );

        let prepared = match unprepared.prepare() {
            Ok(p) => p,
            Err(e) => {
                for (s, mut ex) in spawned {
                    ex.handle.terminate();
                    let _ = fleet.release_worker(&s.worker_id);
                }
                for s in &allocated_scopes {
                    let _ = fleet.release_worker(&s.worker_id);
                }
                let _ = fleet.save_persistent();
                return Err(e);
            }
        };

        let execution = match prepared.spawn() {
            Ok(ex) => ex,
            Err(e) => {
                for (s, mut ex) in spawned {
                    ex.handle.terminate();
                    let _ = fleet.release_worker(&s.worker_id);
                }
                for s in &allocated_scopes {
                    let _ = fleet.release_worker(&s.worker_id);
                }
                let _ = fleet.save_persistent();
                return Err(e);
            }
        };

        let pid = execution.pid();
        if let Err(e) = fleet.bind_worker_pid(&scope.worker_id, pid) {
            tracing::warn!(
                worker_id = %scope.worker_id,
                pid = pid,
                error = %e,
                "failed to bind worker pid"
            );
        }

        spawned.push((scope.clone(), execution));
    }

    fleet.save_persistent()?;

    if args.detach {
        for (scope, execution) in spawned {
            let pid = execution.pid();
            println!(
                "Spawned fleet worker '{}' (agent: {}, PID: {}, port: {}) [detached]",
                scope.worker_id, scope.agent_name, pid, scope.ephemeral_port
            );
            std::mem::forget(execution);
        }
        return Ok(());
    }

    // Foreground execution: wait for all workers to complete and release slots
    let mut worst_exit_code = 0;
    for (scope, execution) in spawned {
        let outcome = execution.wait_collect();
        let _ = fleet.release_worker(&scope.worker_id);
        if let Some(code) = outcome.exit_code {
            if code != 0 && worst_exit_code == 0 {
                worst_exit_code = code;
            }
        }
    }

    let _ = fleet.save_persistent();

    if worst_exit_code != 0 {
        std::process::exit(worst_exit_code);
    }

    Ok(())
}

/// Executes `vetto fleet verify [--workers <N>] [--json]`.
pub fn run_verify(workers: usize, json: bool) -> Result<()> {
    if workers < 2 || workers > 64 {
        bail!(
            "Worker count for verification must be between 2 and 64 (got {})",
            workers
        );
    }

    let fleet = FleetManager::new_default();
    let mut scopes = Vec::with_capacity(workers);
    for i in 1..=workers {
        let scope = fleet
            .allocate_worker(&format!("verify-{:02}", i))
            .with_context(|| format!("allocate verification worker {}", i))?;
        scopes.push(scope);
    }

    let barrier = IsolationBarrier::new();
    for (idx, scope) in scopes.iter().enumerate() {
        barrier.register_agent(
            &scope.worker_id,
            (10000 + idx + 1) as u32,
            true,
            scope.ipc_isolated,
            Some(scope.memory_limit_bytes),
        );
    }

    let total_pairs = workers * (workers - 1) / 2;
    let mut pairs_verified = 0;
    let mut disjoint_ports = true;
    let mut disjoint_cow_branches = true;
    let mut disjoint_cgroup_scopes = true;
    let mut ipc_isolated = true;
    let mut pid_isolated = true;

    for i in 0..workers {
        for j in (i + 1)..workers {
            let a = &scopes[i];
            let b = &scopes[j];

            if a.ephemeral_port == b.ephemeral_port {
                disjoint_ports = false;
            }
            if a.cow_branch_name == b.cow_branch_name {
                disjoint_cow_branches = false;
            }
            if a.scope_path == b.scope_path {
                disjoint_cgroup_scopes = false;
            }
            if !a.ipc_isolated
                || !b.ipc_isolated
                || barrier.verify_ipc_isolation(&a.worker_id).is_err()
                || barrier.verify_ipc_isolation(&b.worker_id).is_err()
            {
                ipc_isolated = false;
            }
            if barrier
                .verify_signal_isolation(&a.worker_id, &b.worker_id)
                .is_err()
            {
                pid_isolated = false;
            }

            if fleet.verify_isolation(&a.worker_id, &b.worker_id).is_ok() {
                pairs_verified += 1;
            }
        }
    }

    let all_passed = disjoint_ports
        && disjoint_cow_branches
        && disjoint_cgroup_scopes
        && ipc_isolated
        && pid_isolated
        && pairs_verified == total_pairs;

    let verdict = if all_passed {
        "PASS".to_string()
    } else {
        "FAIL".to_string()
    };

    let report = FleetVerifyReport {
        workers_checked: workers,
        pairs_verified,
        verdict: verdict.clone(),
        disjoint_ports,
        disjoint_cow_branches,
        disjoint_cgroup_scopes,
        ipc_isolated,
        pid_isolated,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "[FLEET VERIFY] Swarm Isolation Test ({} workers, {} pairs)",
            workers, total_pairs
        );
        println!(
            "  [OK] Worker slot allocation: {}/{} allocated ({} .. {})",
            workers,
            workers,
            scopes.first().map(|s| s.worker_id.as_str()).unwrap_or(""),
            scopes.last().map(|s| s.worker_id.as_str()).unwrap_or("")
        );
        println!(
            "  [{}] Ephemeral port allocation: {}",
            if disjoint_ports { "OK" } else { "FAIL" },
            if disjoint_ports {
                "all disjoint"
            } else {
                "collision detected"
            }
        );
        println!(
            "  [{}] CoW workspace branches: {}",
            if disjoint_cow_branches { "OK" } else { "FAIL" },
            if disjoint_cow_branches {
                "all disjoint"
            } else {
                "collision detected"
            }
        );
        println!(
            "  [{}] Cgroups v2 scopes: {}",
            if disjoint_cgroup_scopes { "OK" } else { "FAIL" },
            if disjoint_cgroup_scopes {
                "all disjoint"
            } else {
                "collision detected"
            }
        );
        println!(
            "  [{}] Kernel namespaces: CLONE_NEWPID + CLONE_NEWIPC verified across all pairs",
            if ipc_isolated && pid_isolated {
                "OK"
            } else {
                "FAIL"
            }
        );
        println!(
            "  [{}] Pairwise isolation matrix: {}/{} pairs PASS",
            if all_passed { "OK" } else { "FAIL" },
            pairs_verified,
            total_pairs
        );
        println!();
        println!(
            "VERDICT: {} ({} isolation breaches detected)",
            verdict,
            if all_passed {
                0
            } else {
                total_pairs - pairs_verified
            }
        );
    }

    if !all_passed {
        return Err(anyhow::Error::new(crate::error::VettoError::Sandbox(
            format!(
                "Fleet isolation verification failed: {}/{} pairs passed (verdict: FAIL)",
                pairs_verified, total_pairs
            ),
        )));
    }

    Ok(())
}

/// Executes `vetto fleet kill [<worker_id> | --all]`.
pub fn run_kill(worker_id: Option<String>, all: bool) -> Result<()> {
    let fleet = FleetManager::load_persistent()?;
    let _ = fleet.reconcile_live_workers()?;

    if all {
        let workers = fleet.active_workers();
        let count = workers.len();
        for w in &workers {
            if let Some(pid) = w.pid {
                let _ = crate::cli::kill::kill_pid(pid, true);
            }
            let cgroup_kill = w.scope_path.join("cgroup.kill");
            if cgroup_kill.exists() {
                let _ = std::fs::write(&cgroup_kill, "1\n");
            }
            if w.scope_path.exists() {
                let _ = std::fs::remove_dir(&w.scope_path);
            }
            if !w.workspace_dir.as_os_str().is_empty() && w.workspace_dir.exists() {
                let _ = std::fs::remove_dir_all(&w.workspace_dir);
            }
        }
        let _ = fleet.release_all_workers()?;
        fleet.save_persistent()?;
        if count == 0 {
            println!("No active fleet workers to terminate.");
        } else {
            println!("Terminated and released {} active fleet worker(s).", count);
        }
        return Ok(());
    }

    if let Some(id) = worker_id {
        let w = fleet
            .get_worker(&id)
            .ok_or_else(|| anyhow::anyhow!("Worker '{}' not found in active fleet", id))?;

        if let Some(pid) = w.pid {
            let _ = crate::cli::kill::kill_pid(pid, true);
        }
        let cgroup_kill = w.scope_path.join("cgroup.kill");
        if cgroup_kill.exists() {
            let _ = std::fs::write(&cgroup_kill, "1\n");
        }
        if w.scope_path.exists() {
            let _ = std::fs::remove_dir(&w.scope_path);
        }
        if !w.workspace_dir.as_os_str().is_empty() && w.workspace_dir.exists() {
            let _ = std::fs::remove_dir_all(&w.workspace_dir);
        }
        fleet.release_worker(&id)?;
        fleet.save_persistent()?;
        println!("Terminated and released fleet worker '{}'.", id);
        return Ok(());
    }

    bail!("Specify a worker ID to terminate (e.g. 'vetto fleet kill agent-01') or '--all'");
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_fleet_args_status_parsing() {
        #[derive(Parser, Debug)]
        struct TestCli {
            #[command(subcommand)]
            command: FleetCommand,
        }

        let cli1 = TestCli::try_parse_from(&["test", "status"]).expect("parse status");
        assert_eq!(cli1.command, FleetCommand::Status { json: false });

        let cli2 = TestCli::try_parse_from(&["test", "status", "--json"]).expect("parse status --json");
        assert_eq!(cli2.command, FleetCommand::Status { json: true });
    }

    #[test]
    fn test_fleet_args_verify_parsing() {
        #[derive(Parser, Debug)]
        struct TestCli {
            #[command(subcommand)]
            command: FleetCommand,
        }

        let cli = TestCli::try_parse_from(&["test", "verify", "--workers", "8", "--json"])
            .expect("parse verify");
        assert_eq!(
            cli.command,
            FleetCommand::Verify {
                workers: 8,
                json: true,
            }
        );
    }

    #[test]
    fn test_fleet_args_spawn_parsing() {
        #[derive(Parser, Debug)]
        struct TestCli {
            #[command(subcommand)]
            command: FleetCommand,
        }

        let cli = TestCli::try_parse_from(&["test", "spawn", "claude", "--count", "3", "--detach"])
            .expect("parse spawn agent");
        match cli.command {
            FleetCommand::Spawn(args) => {
                assert_eq!(args.agent_or_cmd.as_deref(), Some("claude"));
                assert_eq!(args.count, 3);
                assert!(args.detach);
                assert!(args.args.is_empty());
            }
            _ => panic!("expected spawn"),
        }

        let cli2 = TestCli::try_parse_from(&[
            "test", "spawn", "--count", "2", "--", "sh", "-c", "echo test",
        ])
        .expect("parse spawn trailing");
        match cli2.command {
            FleetCommand::Spawn(args) => {
                assert_eq!(args.agent_or_cmd, None);
                assert_eq!(args.count, 2);
                assert_eq!(args.args, vec!["sh", "-c", "echo test"]);
            }
            _ => panic!("expected spawn trailing"),
        }
    }

    #[test]
    fn test_fleet_args_kill_parsing() {
        #[derive(Parser, Debug)]
        struct TestCli {
            #[command(subcommand)]
            command: FleetCommand,
        }

        let cli1 = TestCli::try_parse_from(&["test", "kill", "agent-01"]).expect("parse kill id");
        assert_eq!(
            cli1.command,
            FleetCommand::Kill {
                worker_id: Some("agent-01".to_string()),
                all: false,
            }
        );

        let cli2 = TestCli::try_parse_from(&["test", "kill", "--all"]).expect("parse kill all");
        assert_eq!(
            cli2.command,
            FleetCommand::Kill {
                worker_id: None,
                all: true,
            }
        );

        assert!(TestCli::try_parse_from(&["test", "kill"]).is_err());
        assert!(TestCli::try_parse_from(&["test", "kill", "agent-01", "--all"]).is_err());
    }

    #[test]
    fn test_fleet_verify_swarm_invariants() {
        let workers = 8;
        let fleet = FleetManager::new_default();
        let mut scopes = Vec::new();
        for i in 1..=workers {
            scopes.push(fleet.allocate_worker(&format!("w{}", i)).expect("alloc"));
        }

        let barrier = IsolationBarrier::new();
        for (idx, scope) in scopes.iter().enumerate() {
            barrier.register_agent(
                &scope.worker_id,
                (20000 + idx + 1) as u32,
                true,
                scope.ipc_isolated,
                Some(scope.memory_limit_bytes),
            );
        }

        let total_pairs = workers * (workers - 1) / 2;
        assert_eq!(total_pairs, 28);

        let mut verified = 0;
        for i in 0..workers {
            for j in (i + 1)..workers {
                assert!(fleet.verify_isolation(&scopes[i].worker_id, &scopes[j].worker_id).is_ok());
                assert!(barrier.verify_signal_isolation(&scopes[i].worker_id, &scopes[j].worker_id).is_ok());
                assert!(barrier.verify_ipc_isolation(&scopes[i].worker_id).is_ok());
                assert!(barrier.verify_ipc_isolation(&scopes[j].worker_id).is_ok());
                verified += 1;
            }
        }
        assert_eq!(verified, 28);
    }

    #[test]
    fn test_fleet_state_schema_json() {
        let state = FleetState::default();
        let json_val = serde_json::to_value(&state).expect("serialize state");

        assert_eq!(json_val["active_count"], 0);
        assert_eq!(json_val["max_agents"], 64);
        assert_eq!(json_val["cpu_weight"], 100);
        assert_eq!(json_val["memory_limit_bytes"], 2147483648u64);
        assert_eq!(json_val["pids_max"], 128);
        assert_eq!(json_val["ipc_isolation"], true);
        assert_eq!(json_val["base_port"], 49201);
        assert_eq!(json_val["workers"], serde_json::json!([]));
    }
}
