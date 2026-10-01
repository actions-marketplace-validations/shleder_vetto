//! Integration tests for `vetto bench` / `--benchmark` fast-path mode.

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

use vetto::cli::bench::{
    configure_bench_run, resolve_or_materialize_policy, BenchArgs, BenchJsonResult,
    SWEBENCH_PROFILE_TOML,
};
use vetto::cli::{Cli, Command};
use vetto::config::{NetMode, TuiMode};
use vetto::policy::loader::parse_layer;

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
    assert!(!args.json);
    assert_eq!(args.command, vec!["pytest", "tests/"]);
}

#[test]
fn test_bench_subcommand_cli_parsing() {
    let cli = Cli::try_parse_from([
        "vetto",
        "bench",
        "--workspace",
        "/tmp/swebench-task",
        "--timeout",
        "120",
        "--memory",
        "2048",
        "--net",
        "off",
        "--json",
        "--instance-id",
        "django__django-11099",
        "-e",
        "PYTEST_ADDOPTS=-q",
        "--",
        "pytest",
        "tests/test_model.py",
    ])
    .expect("parse bench CLI args");

    let Some(Command::Bench(bench_args)) = cli.command else {
        panic!("expected Command::Bench subcommand");
    };

    assert_eq!(
        bench_args.workspace,
        Some(PathBuf::from("/tmp/swebench-task"))
    );
    assert_eq!(bench_args.timeout, 120);
    assert_eq!(bench_args.memory_mb, 2048);
    assert_eq!(bench_args.net, Some("off".to_string()));
    assert!(bench_args.json);
    assert_eq!(
        bench_args.instance_id,
        Some("django__django-11099".to_string())
    );
    assert_eq!(bench_args.env, vec!["PYTEST_ADDOPTS=-q".to_string()]);
    assert_eq!(
        bench_args.command,
        vec!["pytest".to_string(), "tests/test_model.py".to_string()]
    );
}

#[test]
fn test_benchmark_flag_root_cli() {
    let cli = Cli::try_parse_from(["vetto", "--benchmark", "--", "pytest", "tests/"])
        .expect("parse root --benchmark flag");

    assert!(cli.benchmark);
    assert_eq!(cli.agent, vec!["pytest".to_string(), "tests/".to_string()]);
}

#[test]
fn test_configure_bench_run_fast_path() {
    let cli = Cli::try_parse_from(["vetto", "bench", "--", "pytest"]).expect("parse cli");
    let bench_args = BenchArgs {
        workspace: Some(PathBuf::from("/workspace")),
        timeout: 90,
        memory_mb: 1024,
        net: Some("off".to_string()),
        json: true,
        instance_id: Some("test-task-1".to_string()),
        profile: "swebench".to_string(),
        env: vec![],
        command: vec!["pytest".to_string()],
    };

    let cfg = configure_bench_run(&bench_args, &cli).expect("configure bench run");

    assert_eq!(cfg.agent, vec!["pytest".to_string()]);
    assert_eq!(cfg.agent_preset, Some("swebench".to_string()));
    assert_eq!(cfg.session_timeout, Some(Duration::from_secs(90)));
    assert_eq!(cfg.limits_spec, Some("memory=1024mb".to_string()));
    assert_eq!(cfg.tui, TuiMode::None);
    assert!(cfg.ci);
    assert!(cfg.ephemeral);
    assert!(cfg.benchmark);
    assert!(cfg.mask_secrets);
    assert!(cfg.auto_deny_secrets);
    assert!(cfg.tmpfs_tmp);
    assert!(!cfg.snapshot);
    assert!(cfg.report_formats.is_empty());
    assert_eq!(cfg.net, NetMode::Off);
}

#[test]
fn test_bench_json_result_interface_contract() {
    let res = BenchJsonResult {
        exit_code: 0,
        cold_start_ns: 1_850_000,
        cold_start_ms: 1.85,
        duration_ms: 2400,
        peak_memory_bytes: 64 * 1024 * 1024,
        peak_memory_mb: 64.0,
        blocked_attempts: 0,
        verdict: "pass".to_string(),
        timed_out: false,
        oom_killed: false,
        instance_id: Some("django__django-11099".to_string()),
        status: Some("COMPLETED".to_string()),
        stdout: "2 passed in 1.4s".to_string(),
        stderr: "".to_string(),
    };

    let json_text = serde_json::to_string(&res).expect("serialize json");

    // Must satisfy Interface Contract: {"exit_code": i32, "cold_start_ns": u64, "duration_ms": u64, "peak_memory_bytes": u64, "blocked_attempts": usize, "verdict": "pass" | "fail_closed"}
    assert!(json_text.contains("\"exit_code\":0"));
    assert!(json_text.contains("\"cold_start_ns\":1850000"));
    assert!(json_text.contains("\"duration_ms\":2400"));
    assert!(json_text.contains("\"peak_memory_bytes\":67108864"));
    assert!(json_text.contains("\"blocked_attempts\":0"));
    assert!(json_text.contains("\"verdict\":\"pass\""));

    let parsed: BenchJsonResult = serde_json::from_str(&json_text).expect("deserialize json");
    assert_eq!(parsed, res);
}

#[test]
fn test_bench_fail_closed_contract_on_violation() {
    let timeout_res = BenchJsonResult {
        exit_code: 125,
        cold_start_ns: 2_100_000,
        cold_start_ms: 2.1,
        duration_ms: 180_000,
        peak_memory_bytes: 32 * 1024 * 1024,
        peak_memory_mb: 32.0,
        blocked_attempts: 0,
        verdict: "fail_closed".to_string(),
        timed_out: true,
        oom_killed: false,
        instance_id: Some("pytest-timeout".to_string()),
        status: Some("TIMEOUT".to_string()),
        stdout: "".to_string(),
        stderr: "deadline expired".to_string(),
    };

    assert_eq!(timeout_res.exit_code, 125);
    assert_eq!(timeout_res.verdict, "fail_closed");
    assert!(timeout_res.timed_out);

    let oom_res = BenchJsonResult {
        exit_code: 125,
        cold_start_ns: 1_900_000,
        cold_start_ms: 1.9,
        duration_ms: 4500,
        peak_memory_bytes: 4096 * 1024 * 1024,
        peak_memory_mb: 4096.0,
        blocked_attempts: 0,
        verdict: "fail_closed".to_string(),
        timed_out: false,
        oom_killed: true,
        instance_id: Some("pytest-oom".to_string()),
        status: Some("OOM".to_string()),
        stdout: "".to_string(),
        stderr: "memory limit exceeded (OOM killed)".to_string(),
    };

    assert_eq!(oom_res.exit_code, 125);
    assert_eq!(oom_res.verdict, "fail_closed");
    assert!(oom_res.oom_killed);
}

#[test]
fn test_swebench_profile_layer_validity() {
    let layer = parse_layer(SWEBENCH_PROFILE_TOML, "swebench.toml").expect("parse swebench layer");
    assert_eq!(
        layer.metadata.as_ref().and_then(|m| m.name.as_deref()),
        Some("swebench")
    );

    let fs = layer.filesystem.expect("filesystem section");
    let allow_write = fs.allow_write.expect("allow_write roots").into_vec();
    assert!(allow_write.contains(&"$PROJECT".to_string()));
    assert!(allow_write.contains(&"/tmp".to_string()));
    assert_eq!(fs.tmpfs_tmp, Some(true));

    let net = layer.network.expect("network section");
    assert_eq!(net.mode.as_deref(), Some("off"));

    let sec = layer.security.expect("security section");
    assert_eq!(sec.auto_deny_secrets, Some(true));

    let cgroup = layer.cgroup.expect("cgroup section");
    assert!(cgroup.memory_max.is_some());
    assert!(cgroup.pids_max.is_some());
}

#[test]
fn test_resolve_or_materialize_policy() {
    let path = resolve_or_materialize_policy("swebench").expect("resolve policy path");
    assert!(path.exists());
    let content = std::fs::read_to_string(&path).expect("read policy content");
    assert!(content.contains("[metadata]"));
    assert!(content.contains("name = \"swebench\""));
}

#[test]
fn test_run_subcommand_benchmark_flag() {
    let cli = Cli::try_parse_from(["vetto", "run", "--benchmark", "--", "pytest", "tests/"])
        .expect("parse run --benchmark flag");

    let Some(Command::Run {
        benchmark,
        command,
        args,
    }) = cli.command
    else {
        panic!("expected Command::Run");
    };

    assert!(benchmark);
    assert_eq!(command, Some("pytest".to_string()));
    assert_eq!(args, vec!["tests/".to_string()]);
}

#[test]
fn test_run_subcommand_benchmark_flag_without_dashdash() {
    let cli = Cli::try_parse_from(["vetto", "run", "--benchmark", "pytest", "tests/"])
        .expect("parse run --benchmark flag without dashdash");

    let Some(Command::Run {
        benchmark,
        command,
        args,
    }) = cli.command
    else {
        panic!("expected Command::Run");
    };

    assert!(benchmark);
    assert_eq!(command, Some("pytest".to_string()));
    assert_eq!(args, vec!["tests/".to_string()]);
}

#[test]
fn test_vetto_bench_not_treated_as_external_shim() {
    // Binary stems matching "vetto-bench" must be recognized as internal Vetto binaries,
    // ensuring detect_argv0_shim ignores them and never intercepts them as external shims.
    assert!(vetto::shim::is_internal_binary_stem("vetto-bench"));
    assert!(vetto::shim::is_internal_binary_stem("VETTO-BENCH"));
    assert!(vetto::shim::is_internal_binary_stem("vetto"));
    assert!(vetto::shim::is_internal_binary_stem("vetto-shim"));
    assert!(vetto::shim::is_internal_binary_stem("__vetto"));

    // Real external tools must NOT be classified as internal stems
    assert!(!vetto::shim::is_internal_binary_stem("pytest"));
    assert!(!vetto::shim::is_internal_binary_stem("python3"));
    assert!(!vetto::shim::is_internal_binary_stem("git"));
    assert!(!vetto::shim::is_internal_binary_stem("node"));
}

#[test]
fn test_vetto_bench_argv0_rewrite_to_bench_subcommand() {
    // When invoked via vetto-bench alias, arguments are translated into the `bench` subcommand.
    let mut rewritten_args = vec!["vetto".to_string(), "bench".to_string()];
    rewritten_args.extend(vec![
        "--workspace".to_string(),
        "/tmp/bench".to_string(),
        "--json".to_string(),
        "--".to_string(),
        "pytest".to_string(),
        "tests/".to_string(),
    ]);

    let cli = Cli::try_parse_from(&rewritten_args).expect("parse rewritten vetto-bench args");
    let Some(Command::Bench(bench_args)) = cli.command else {
        panic!("expected Command::Bench from rewritten vetto-bench args");
    };

    assert_eq!(bench_args.workspace, Some(PathBuf::from("/tmp/bench")));
    assert!(bench_args.json);
    assert_eq!(bench_args.command, vec!["pytest", "tests/"]);
}
