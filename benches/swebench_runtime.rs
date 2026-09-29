//! Criterion micro-benchmarks for SWE-bench runtime adapter primitives.
//!
//! Measures hot paths of the benchmark execution adapter:
//! - CLI argument parsing for fast-path bench mode
//! - High-throughput RunConfig construction
//! - SWE-bench hermetic policy parsing and validation
//! - Telemetry JSON serialization and deserialization

#![allow(clippy::all)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use vetto::cli::bench::{
    configure_bench_run, resolve_or_materialize_policy, BenchArgs, BenchJsonResult,
    SWEBENCH_PROFILE_TOML,
};
use vetto::cli::Cli;
use vetto::policy::loader::parse_layer;

fn bench_args_parsing(c: &mut Criterion) {
    let argv = [
        "vetto",
        "bench",
        "--workspace",
        "/tmp/swebench-task",
        "--timeout",
        "180",
        "--memory",
        "4096",
        "--net",
        "off",
        "--json",
        "--instance-id",
        "django__django-11099",
        "-e",
        "PYTHONPATH=/repo",
        "--",
        "pytest",
        "tests/test_model.py",
    ];

    c.bench_function("swebench_cli_args_parsing", |b| {
        b.iter(|| {
            use clap::Parser;
            let cli = Cli::try_parse_from(black_box(&argv)).expect("parse bench args");
            black_box(cli)
        });
    });
}

fn bench_configure_run_config(c: &mut Criterion) {
    use clap::Parser;
    let cli = Cli::try_parse_from(["vetto", "bench", "--", "pytest"]).expect("parse cli");
    let bench_args = BenchArgs {
        workspace: None,
        timeout: 180,
        memory_mb: 4096,
        net: Some("off".to_string()),
        json: true,
        instance_id: Some("django__django-11099".to_string()),
        profile: "swebench".to_string(),
        env: vec!["PYTHONPATH=/repo".to_string()],
        command: vec!["pytest".to_string(), "tests/test_model.py".to_string()],
    };

    c.bench_function("swebench_configure_run_config", |b| {
        b.iter(|| {
            let cfg = configure_bench_run(black_box(&bench_args), black_box(&cli))
                .expect("configure bench run");
            black_box(cfg)
        });
    });
}

fn bench_swebench_policy_layer_parsing(c: &mut Criterion) {
    c.bench_function("swebench_policy_parse_layer", |b| {
        b.iter(|| {
            let layer = parse_layer(black_box(SWEBENCH_PROFILE_TOML), black_box("swebench.toml"))
                .expect("parse swebench layer");
            black_box(layer)
        });
    });
}

fn bench_json_telemetry_roundtrip(c: &mut Criterion) {
    let res = BenchJsonResult {
        exit_code: 0,
        cold_start_ns: 1_820_000,
        cold_start_ms: 1.82,
        duration_ms: 3100,
        peak_memory_bytes: 48 * 1024 * 1024,
        peak_memory_mb: 48.0,
        blocked_attempts: 0,
        verdict: "pass".to_string(),
        timed_out: false,
        oom_killed: false,
        instance_id: Some("django__django-11099".to_string()),
        status: Some("COMPLETED".to_string()),
        stdout: "2 passed in 0.8s".to_string(),
        stderr: "".to_string(),
    };

    c.bench_function("swebench_json_serialize", |b| {
        b.iter(|| {
            let text = serde_json::to_string(black_box(&res)).expect("serialize");
            black_box(text)
        });
    });

    let json_text = serde_json::to_string(&res).expect("serialize baseline");
    c.bench_function("swebench_json_deserialize", |b| {
        b.iter(|| {
            let parsed: BenchJsonResult =
                serde_json::from_str(black_box(&json_text)).expect("deserialize");
            black_box(parsed)
        });
    });
}

fn bench_resolve_policy(c: &mut Criterion) {
    c.bench_function("swebench_resolve_policy_path", |b| {
        b.iter(|| {
            let path =
                resolve_or_materialize_policy(black_box("swebench")).expect("resolve policy");
            black_box(path)
        });
    });
}

criterion_group!(
    benches,
    bench_args_parsing,
    bench_configure_run_config,
    bench_swebench_policy_layer_parsing,
    bench_json_telemetry_roundtrip,
    bench_resolve_policy,
);
criterion_main!(benches);
