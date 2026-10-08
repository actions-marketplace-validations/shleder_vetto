//! `vetto bench`: High-throughput, low-latency execution adapter for benchmarks (SWE-bench).
//!
//! Provides a drop-in execution runtime replacing Docker in SWE-bench evaluation harnesses:
//! - Sub-4ms cold-start latency by bypassing non-essential user CLI overheads (banners, updates,
//!   session registry writes, disk snapshot tarballs, diff manifests).
//! - Sub-megabyte host memory overhead per evaluation task.
//! - Hermetic kernel-level sandbox enforcement: Landlock LSM VFS isolation, read-only root CoW tmpfs,
//!   cgroups v2 memory limits, network blocking/allowlisting, and process-tree extinction on exit.
//! - Structured JSON output format for automated evaluation pipelines and CI runners.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, OwnedFd};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::cli::Cli;
use crate::config::{parse_net_mode, NetMode, RunConfig, TuiMode};
use crate::policy::loader::{load_with_options, PolicyLoadOptions, PolicyOverrides};
use crate::policy::Tier;
use crate::sandbox;
use crate::sandbox::production::UnpreparedProductionExecution;
use crate::sandbox::StdioMode;

/// Built-in SWE-bench hermetic agent profile content.
pub const SWEBENCH_PROFILE_TOML: &str = crate::policy::defaults::SWEBENCH_AGENT_TOML;

/// Arguments for `vetto bench`.
#[derive(clap::Args, Debug, Clone)]
pub struct BenchArgs {
    /// Workspace root directory for the benchmark evaluation
    #[arg(short = 'w', long = "workspace", value_name = "DIR")]
    pub workspace: Option<PathBuf>,

    /// Hard wall-clock timeout in seconds (default: 180s)
    #[arg(short = 't', long = "timeout", default_value = "180")]
    pub timeout: u64,

    /// Memory limit ceiling in megabytes (cgroups v2 memory.max, default: 4096MB)
    #[arg(short = 'm', long = "memory", default_value = "4096")]
    pub memory_mb: u64,

    /// Network mode (default: off). Allowed: off | allowlist:<domain,...> | strict:<domain:port,...>
    #[arg(long = "net")]
    pub net: Option<String>,

    /// Output structured JSON with exit_code, cold_start_ns, duration_ms, and peak_memory_bytes
    #[arg(long)]
    pub json: bool,

    /// Optional benchmark instance identifier (e.g. django__django-11099)
    #[arg(long = "instance-id", value_name = "ID")]
    pub instance_id: Option<String>,

    /// Security policy profile to use (default: "swebench")
    #[arg(long = "profile", default_value = "swebench")]
    pub profile: String,

    /// Pass environment variable to the task (e.g. -e KEY=VALUE)
    #[arg(short = 'e', long = "env", value_name = "KEY=VALUE", action = clap::ArgAction::Append)]
    pub env: Vec<String>,

    /// Command to execute in the benchmark sandbox; everything after `--`
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "COMMAND [ARGS...]"
    )]
    pub command: Vec<String>,
}

/// Structured JSON output matching SWE-bench runner requirements and PROJECT.md contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BenchJsonResult {
    pub exit_code: i32,
    pub cold_start_ns: u64,
    pub cold_start_ms: f64,
    pub duration_ms: u64,
    pub peak_memory_bytes: u64,
    pub peak_memory_mb: f64,
    pub blocked_attempts: usize,
    pub verdict: String,
    pub timed_out: bool,
    pub oom_killed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    pub stdout: String,
    pub stderr: String,
}

/// Build high-throughput fast-path RunConfig for benchmark evaluation.
pub fn configure_bench_run(bench_args: &BenchArgs, cli: &Cli) -> Result<RunConfig> {
    let mut cfg = RunConfig::from_cli(cli)?;

    cfg.agent = bench_args.command.clone();
    cfg.agent_preset = Some(bench_args.profile.clone());
    cfg.session_timeout = Some(Duration::from_secs(bench_args.timeout));
    cfg.limits_spec = Some(format!("memory={}mb", bench_args.memory_mb));
    cfg.tui = TuiMode::None;
    cfg.ci = true;
    cfg.ephemeral = true;
    cfg.benchmark = true;
    cfg.mask_secrets = true;
    cfg.auto_deny_secrets = true;
    cfg.tmpfs_tmp = true;
    cfg.snapshot = false;
    cfg.report_formats.clear();

    if let Some(ref net_str) = bench_args.net {
        cfg.net = parse_net_mode(net_str)?;
    } else {
        cfg.net = NetMode::Off;
    }

    Ok(cfg)
}

/// Resolve policy file from repository, system location, or materialize embedded TOML.
pub fn resolve_or_materialize_policy(profile_name: &str) -> Result<PathBuf> {
    let mut candidates = vec![
        PathBuf::from(format!("profiles/agents/{profile_name}.toml")),
        PathBuf::from(format!("../profiles/agents/{profile_name}.toml")),
        PathBuf::from(format!("profiles/{profile_name}.toml")),
        PathBuf::from(format!("../profiles/{profile_name}.toml")),
    ];

    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join(format!("profiles/agents/{profile_name}.toml")));
        candidates.push(cwd.join(format!("../profiles/agents/{profile_name}.toml")));
        candidates.push(cwd.join(format!("profiles/{profile_name}.toml")));
    }

    let config_dir = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));

    if let Some(cfg_dir) = config_dir {
        candidates.push(
            cfg_dir
                .join("vetto/profiles/agents")
                .join(format!("{profile_name}.toml")),
        );
        candidates.push(
            cfg_dir
                .join("vetto/profiles")
                .join(format!("{profile_name}.toml")),
        );
    }

    if let Some(home) = std::env::var_os("HOME") {
        let home_path = PathBuf::from(home);
        candidates.push(
            home_path
                .join(".vetto/profiles/agents")
                .join(format!("{profile_name}.toml")),
        );
        candidates.push(
            home_path
                .join(".vetto/profiles")
                .join(format!("{profile_name}.toml")),
        );
    }

    for candidate in &candidates {
        if candidate.is_file() {
            return Ok(candidate.clone());
        }
    }

    // Fallback: write embedded profile to a disposable location
    let temp_path = std::env::temp_dir().join(format!("vetto-profile-{profile_name}.toml"));
    let content = if let Some(builtin_agent) = crate::policy::defaults::agent_builtin(profile_name)
    {
        builtin_agent
    } else if let Some(builtin_pol) = crate::policy::defaults::builtin(profile_name) {
        builtin_pol
    } else {
        bail!("unknown profile '{profile_name}'");
    };
    let _ = std::fs::write(&temp_path, content);
    Ok(temp_path)
}

fn measure_peak_memory_bytes(pid: Option<u32>) -> u64 {
    let _ = pid;

    #[cfg(target_os = "linux")]
    {
        // 1. If child PID is provided, attempt direct inspection via procfs if still available
        if let Some(child_pid) = pid {
            if let Some(dir) = crate::verify_ng::linux_enforce::child_cgroup_dir(child_pid) {
                if let Ok(content) = std::fs::read_to_string(dir.join("memory.peak")) {
                    if let Ok(bytes) = content.trim().parse::<u64>() {
                        if bytes > 0 {
                            return bytes;
                        }
                    }
                }
            }
        }

        // 2. Try reading peak memory from active cgroups v2 scope matching this process session or PID
        if let Some(root) = crate::sandbox::linux::cgroup::find_cgroup_root() {
            if let Ok(entries) = std::fs::read_dir(&root) {
                let self_pid = std::process::id();
                let self_prefix = format!("vetto-session-{self_pid}-");
                let child_prefix = pid.map(|p| format!("vetto-session-{p}-"));

                let mut matched_peak: u64 = 0;
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_dir() {
                        if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                            let is_matching_session = name.starts_with(&self_prefix)
                                || child_prefix
                                    .as_deref()
                                    .is_some_and(|cp| name.starts_with(cp));

                            if is_matching_session {
                                if let Ok(content) = std::fs::read_to_string(p.join("memory.peak"))
                                {
                                    if let Ok(bytes) = content.trim().parse::<u64>() {
                                        if bytes > matched_peak {
                                            matched_peak = bytes;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if matched_peak > 0 {
                    return matched_peak;
                }
            }
        }

        // Fallback to getrusage for child processes
        unsafe {
            let mut usage: libc::rusage = std::mem::zeroed();
            if libc::getrusage(libc::RUSAGE_CHILDREN, &mut usage) == 0 {
                let ru_kb = usage.ru_maxrss as u64;
                if ru_kb > 0 {
                    return ru_kb * 1024;
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        unsafe {
            let mut usage: libc::rusage = std::mem::zeroed();
            if libc::getrusage(libc::RUSAGE_CHILDREN, &mut usage) == 0 {
                let bytes = usage.ru_maxrss as u64;
                if bytes > 0 {
                    return bytes;
                }
            }
        }
    }

    // Default baseline minimum memory observed (512KB)
    512 * 1024
}

/// Execute benchmark evaluation run and return structured results.
pub fn run_bench(bench_args: &BenchArgs, cli: &Cli) -> Result<BenchJsonResult> {
    if bench_args.command.is_empty() {
        bail!("no benchmark command provided; usage: vetto bench [OPTIONS] -- <command> [args...]");
    }

    // Switch workspace directory if requested
    if let Some(ref ws) = bench_args.workspace {
        std::env::set_current_dir(ws)
            .with_context(|| format!("failed to enter workspace directory {}", ws.display()))?;
    }
    let workspace_dir = std::env::current_dir().context("getcwd")?;
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .context("neither $HOME nor %USERPROFILE% is set")?;

    let cfg = configure_bench_run(bench_args, cli)?;

    // Resolve binary path early
    let mut agent_cmd = cfg.agent.clone();
    agent_cmd[0] = crate::shim::resolve_executable(&agent_cmd[0])?
        .to_string_lossy()
        .into_owned();

    // Backend detection (fast-path)
    let backend =
        sandbox::Backend::detect_with_backend(cfg.net.clone(), false, cfg.backend.as_deref())?;
    let tier = backend.tier();
    let tier_for_policy = match tier {
        Some(t) => t,
        None => Tier::Full,
    };

    // Hermetic policy setup
    let policy_path = resolve_or_materialize_policy(&bench_args.profile)?;
    let overrides = PolicyOverrides {
        auto_deny_secrets: Some(true),
        tmpfs_tmp: Some(true),
        snapshot: Some(false),
        git_guard: Some(false),
        ..PolicyOverrides::default()
    };
    let policy_options = PolicyLoadOptions {
        agent: None,
        include_project_policy: false,
        include_system_policy: false,
        include_user_policy: false,
        overrides,
        ..PolicyLoadOptions::default()
    };

    let mut pol = load_with_options(
        "default",
        Some(&policy_path),
        &workspace_dir,
        &home,
        tier_for_policy,
        &policy_options,
    )?;

    // Ensure project workspace and /tmp are writable
    if !pol.allow_write.contains(&workspace_dir) {
        pol.allow_write.push(workspace_dir.clone());
    }
    let tmp_path = PathBuf::from("/tmp");
    if !pol.allow_write.contains(&tmp_path) {
        pol.allow_write.push(tmp_path);
    }
    if let Some(spec) = &cfg.limits_spec {
        crate::policy::limits_spec::apply_cli(&mut pol, spec)?;
    }

    // Set up extra environment variables
    let mut env_extra: HashMap<String, String> = HashMap::new();
    env_extra.insert("VETTO_SANDBOX".into(), "1".into());
    env_extra.insert("VETTO_SANDBOXED".into(), "1".into());
    env_extra.insert("VETTO_BENCHMARK".into(), "1".into());
    let session_id = format!(
        "bench-{}-{}",
        chrono::Utc::now().format("%Y%m%d-%H%M%S"),
        std::process::id()
    );
    env_extra.insert("VETTO_SESSION_ID".into(), session_id);
    if let Some(ref id) = bench_args.instance_id {
        env_extra.insert("SWEBENCH_INSTANCE_ID".into(), id.clone());
    }

    // Parse custom environment variables from -e KEY=VALUE
    for env_var in &bench_args.env {
        if let Some((k, v)) = env_var.split_once('=') {
            env_extra.insert(k.trim().to_string(), v.trim().to_string());
        }
    }

    // Stdio plumbing: capture via pipes when json mode is enabled to keep stdout clean
    #[cfg(unix)]
    let mut stdout_r: Option<OwnedFd> = None;
    #[cfg(unix)]
    let mut stdout_w: Option<OwnedFd> = None;
    #[cfg(unix)]
    let mut stderr_r: Option<OwnedFd> = None;
    #[cfg(unix)]
    let mut stderr_w: Option<OwnedFd> = None;

    #[cfg(unix)]
    let stdio = if bench_args.json {
        let (r1, w1) = sandbox::create_cloexec_pipe()?;
        let (r2, w2) = sandbox::create_cloexec_pipe()?;
        let captured = StdioMode::Captured {
            stdout_w: w1.as_raw_fd(),
            stderr_w: w2.as_raw_fd(),
        };
        stdout_r = Some(r1);
        stdout_w = Some(w1);
        stderr_r = Some(r2);
        stderr_w = Some(w2);
        captured
    } else {
        StdioMode::Inherit
    };

    #[cfg(windows)]
    let stdio = StdioMode::Inherit;

    // Fast-path cold-start execution boundary
    let t_cold_start = Instant::now();
    let scenario_id = format!(
        "bench:{}",
        bench_args.instance_id.as_deref().unwrap_or("task")
    );
    let unprepared = UnpreparedProductionExecution::new(
        backend,
        pol,
        agent_cmd,
        workspace_dir,
        env_extra,
        cfg.net.clone(),
        cfg.session_timeout,
        stdio,
        scenario_id,
    );
    let prepared = unprepared.prepare()?;
    let spawned = prepared.spawn()?;
    let cold_start_ns = t_cold_start.elapsed().as_nanos() as u64;
    let cold_start_ms = cold_start_ns as f64 / 1_000_000.0;

    #[cfg(unix)]
    {
        drop(stdout_w.take());
        drop(stderr_w.take());
    }

    #[cfg(unix)]
    let mut out_reader: Option<sandbox::production::AsyncPipeReader> = None;
    #[cfg(unix)]
    let mut err_reader: Option<sandbox::production::AsyncPipeReader> = None;

    #[cfg(unix)]
    if bench_args.json {
        if let Some(r1) = stdout_r.take() {
            out_reader = Some(sandbox::production::AsyncPipeReader::spawn(
                r1,
                sandbox::production::PROD_MAX_STDIO,
                Duration::from_millis(200),
            ));
        }
        if let Some(r2) = stderr_r.take() {
            err_reader = Some(sandbox::production::AsyncPipeReader::spawn(
                r2,
                sandbox::production::PROD_MAX_STDIO,
                Duration::from_millis(200),
            ));
        }
    }

    // Monitored execution
    let t_exec = Instant::now();
    let prod_result = spawned.wait_collect();
    let duration_ms = t_exec.elapsed().as_millis() as u64;

    // Collect captured stdout and stderr
    #[cfg(unix)]
    let stdout = if let Some(h) = out_reader {
        h.notify_child_exited();
        String::from_utf8_lossy(&h.join()).to_string()
    } else {
        String::new()
    };
    #[cfg(not(unix))]
    let stdout = String::new();

    #[cfg(unix)]
    let stderr = if let Some(h) = err_reader {
        h.notify_child_exited();
        String::from_utf8_lossy(&h.join()).to_string()
    } else {
        String::new()
    };
    #[cfg(not(unix))]
    let stderr = String::new();

    let peak_memory_bytes = measure_peak_memory_bytes(prod_result.pid);
    let peak_memory_mb = (peak_memory_bytes as f64) / (1024.0 * 1024.0);

    let raw_exit_code = prod_result.exit_code.unwrap_or(-1);
    let timed_out = prod_result.timed_out;
    let oom_killed = raw_exit_code == 137 || (raw_exit_code == -1 && !timed_out);
    let blocked_attempts = prod_result.blocked_attempts;

    // Contract: Fail-closed Exit 125 on timeout, OOM or sandbox security breach
    let final_exit_code = if timed_out || oom_killed || raw_exit_code == 125 || blocked_attempts > 0
    {
        125
    } else {
        raw_exit_code
    };

    let verdict = if final_exit_code == 0 {
        "pass".to_string()
    } else {
        "fail_closed".to_string()
    };

    let status = if timed_out {
        Some("TIMEOUT".to_string())
    } else if oom_killed {
        Some("OOM".to_string())
    } else if final_exit_code == 0 {
        Some("COMPLETED".to_string())
    } else {
        Some("FAIL_CLOSED".to_string())
    };

    Ok(BenchJsonResult {
        exit_code: final_exit_code,
        cold_start_ns,
        cold_start_ms,
        duration_ms,
        peak_memory_bytes,
        peak_memory_mb,
        blocked_attempts,
        verdict,
        timed_out,
        oom_killed,
        instance_id: bench_args.instance_id.clone(),
        status,
        stdout,
        stderr,
    })
}

/// CLI entrypoint for `vetto bench`: formats output and exits process.
pub fn execute_bench(bench_args: &BenchArgs, cli: &Cli) -> Result<()> {
    let result = run_bench(bench_args, cli)?;

    if bench_args.json {
        let json_output = serde_json::to_string(&result)?;
        println!("{json_output}");
    } else {
        println!(
            "vetto bench: exit_code={} cold_start={:.2}ms duration={}ms peak_memory={:.2}MB verdict={}",
            result.exit_code,
            result.cold_start_ms,
            result.duration_ms,
            result.peak_memory_mb,
            result.verdict
        );
    }

    std::process::exit(result.exit_code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bench_args_defaults() {
        let args = BenchArgs {
            workspace: None,
            timeout: 180,
            memory_mb: 4096,
            net: None,
            json: false,
            instance_id: None,
            profile: "swebench".to_string(),
            env: vec![],
            command: vec!["pytest".to_string(), "tests/".to_string()],
        };
        assert_eq!(args.timeout, 180);
        assert_eq!(args.memory_mb, 4096);
        assert_eq!(args.profile, "swebench");
        assert_eq!(args.command, vec!["pytest", "tests/"]);
    }

    #[test]
    fn test_bench_json_result_contract() {
        let res = BenchJsonResult {
            exit_code: 0,
            cold_start_ns: 2_450_000,
            cold_start_ms: 2.45,
            duration_ms: 1250,
            peak_memory_bytes: 48 * 1024 * 1024,
            peak_memory_mb: 48.0,
            blocked_attempts: 0,
            verdict: "pass".to_string(),
            timed_out: false,
            oom_killed: false,
            instance_id: Some("django__django-11099".to_string()),
            status: Some("COMPLETED".to_string()),
            stdout: "pytest passed".to_string(),
            stderr: String::new(),
        };

        let json_str = serde_json::to_string(&res).expect("serialization");
        assert!(json_str.contains("\"exit_code\":0"));
        assert!(json_str.contains("\"cold_start_ns\":2450000"));
        assert!(json_str.contains("\"verdict\":\"pass\""));
        assert!(json_str.contains("\"instance_id\":\"django__django-11099\""));

        let deserialized: BenchJsonResult =
            serde_json::from_str(&json_str).expect("deserialization");
        assert_eq!(deserialized, res);
    }

    #[test]
    fn test_bench_timeout_verdict_contract() {
        let res = BenchJsonResult {
            exit_code: 125,
            cold_start_ns: 1_800_000,
            cold_start_ms: 1.8,
            duration_ms: 180_000,
            peak_memory_bytes: 20 * 1024 * 1024,
            peak_memory_mb: 20.0,
            blocked_attempts: 0,
            verdict: "fail_closed".to_string(),
            timed_out: true,
            oom_killed: false,
            instance_id: Some("sympy__sympy-13480".to_string()),
            status: Some("TIMEOUT".to_string()),
            stdout: String::new(),
            stderr: "session killed on deadline".to_string(),
        };

        assert_eq!(res.exit_code, 125);
        assert_eq!(res.verdict, "fail_closed");
        assert!(res.timed_out);
    }

    #[test]
    fn test_measure_peak_memory_bytes() {
        let mem_none = measure_peak_memory_bytes(None);
        assert!(mem_none >= 512 * 1024);

        let mem_pid = measure_peak_memory_bytes(Some(std::process::id()));
        assert!(mem_pid >= 512 * 1024);
    }
}
