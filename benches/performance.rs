//! Criterion measurements for the hot paths that can be isolated safely.
//!
//! Benchmarks intentionally measure construction, observation, and rendering
//! primitives. They do not install a Landlock sandbox, enable seccomp for the
//! benchmark process, or claim a product overhead percentage.

#![allow(clippy::all)]
#![allow(warnings)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

mod bench_support;
use bench_support::session_stats;
#[cfg(target_os = "linux")]
use bench_support::{policy_inputs, PolicyInputs};
use vetto::report;

#[cfg(target_os = "linux")]
fn ensure_policy_paths(inputs: &PolicyInputs) {
    for path in inputs.allow_write.iter().chain(inputs.allow_read.iter()) {
        std::fs::create_dir_all(path).expect("create benchmark policy path");
    }
}

#[cfg(target_os = "linux")]
fn bench_landlock_ruleset_preparation(c: &mut Criterion) {
    use vetto::sandbox::linux::landlock;

    let mut group = c.benchmark_group("landlock-ruleset-construction-no-install");
    for rule_count in [1usize, 8, 32, 128] {
        let inputs = policy_inputs(rule_count);
        ensure_policy_paths(&inputs);
        group.bench_with_input(
            BenchmarkId::new("rules", rule_count),
            &inputs,
            |bench, inputs| {
                bench.iter(|| {
                    let prepared = landlock::prepare_ruleset_for_abi(
                        3,
                        black_box(&inputs.allow_write),
                        black_box(&inputs.allow_read),
                        false,
                    );
                    black_box((prepared.abi(), prepared.len(), prepared.rules().len()))
                });
            },
        );
    }
    group.finish();
}

#[cfg(not(target_os = "linux"))]
fn bench_landlock_ruleset_preparation(_c: &mut Criterion) {}

#[cfg(target_os = "linux")]
fn bench_visibility_scan(c: &mut Criterion) {
    use vetto::sandbox::linux::visibility::{self, PathCache};

    let pid = std::process::id();
    let mut group = c.benchmark_group("visibility-process-fd-scan");
    group.bench_function("process-tree", |bench| {
        bench.iter(|| black_box(visibility::collect_subtree(black_box(&[pid]))));
    });
    group.bench_function("fd-scan-cold", |bench| {
        let mut cache = PathCache::default();
        bench.iter(|| {
            cache.clear();
            black_box(visibility::scan_process_fds(pid, &mut cache).len())
        });
    });
    group.bench_function("fd-scan-warm", |bench| {
        let mut cache = PathCache::default();
        let _ = visibility::scan_process_fds(pid, &mut cache);
        bench.iter(|| black_box(visibility::scan_process_fds(pid, &mut cache).len()));
    });
    group.finish();
}

#[cfg(not(target_os = "linux"))]
fn bench_visibility_scan(_c: &mut Criterion) {}

#[allow(dead_code)]
fn bench_observe_seccomp(_c: &mut Criterion) {}

#[cfg(unix)]
fn bench_pty_passthrough(c: &mut Criterion) {
    use std::fs::OpenOptions;
    use std::os::fd::AsRawFd;
    use vetto::pty::{self, Pty};

    let Ok(pair) = Pty::open(24, 80) else {
        return;
    };
    let Ok(sink) = OpenOptions::new().write(true).open("/dev/null") else {
        return;
    };
    let master = pair.master.as_raw_fd();
    let slave = pair.slave.as_raw_fd();
    let sink_fd = sink.as_raw_fd();
    let _ = pty::set_nonblocking(master, true);
    let payload = vec![b'v'; 512];
    let mut group = c.benchmark_group("pty-byte-passthrough");
    group.bench_function("one-ready-chunk", |bench| {
        let mut buffer = vec![0u8; payload.len()];
        bench.iter(|| {
            pty::write_all_fd(slave, black_box(&payload));
            black_box(pty::passthrough_once(master, sink_fd, &mut buffer))
        });
    });
    group.finish();
}

#[cfg(not(unix))]
fn bench_pty_passthrough(_c: &mut Criterion) {}

fn bench_report_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("report-rendering");
    for record_count in [0usize, 4, 32, 128] {
        let stats = session_stats(record_count);
        group.bench_with_input(
            BenchmarkId::new("markdown", record_count),
            &stats,
            |bench, stats| bench.iter(|| black_box(report::markdown::render(black_box(stats)))),
        );
        group.bench_with_input(
            BenchmarkId::new("json", record_count),
            &stats,
            |bench, stats| bench.iter(|| black_box(report::json::render(black_box(stats)))),
        );
        group.bench_with_input(
            BenchmarkId::new("sarif", record_count),
            &stats,
            |bench, stats| bench.iter(|| black_box(report::sarif::render(black_box(stats)))),
        );
    }
    group.finish();
}

criterion_group!(
    performance,
    bench_landlock_ruleset_preparation,
    bench_visibility_scan,
    bench_observe_seccomp,
    bench_pty_passthrough,
    bench_report_generation
);
criterion_main!(performance);
