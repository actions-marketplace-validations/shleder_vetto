# SWE-bench High-Throughput Runtime Adapter

Technical reference and benchmark measurements for the Vetto SWE-bench execution adapter (`vetto bench`).

---

## 1. Overview & Threat Model

Evaluation harnesses such as SWE-bench evaluate coding agents by running test suites (`pytest`, `unittest`) against modified codebases across thousands of tasks. Standard harness implementations rely on Docker containers to achieve isolation:
- Launching containers introduces 1.5 to 5.0 seconds of cold-start latency per task.
- `dockerd` and `containerd` maintain persistent background memory footprints (~250 MB) and spawn individual `containerd-shim` processes (~14 MB per container).
- Running 32–64 parallel workers frequently encounters Docker daemon socket lock contention, overlay driver exhaustion, or runaway orphaned containers.

Vetto provides a drop-in execution runtime replacing Docker with direct kernel-level isolation:
- **Cold-Start Latency**: <4ms cold start from invocation to task execution.
- **Daemon-less Footprint**: 0 MB resident daemon overhead; sub-megabyte memory cost per task.
- **Rootless Operation**: Runs entirely in unprivileged user space via unprivileged user namespaces (`CLONE_NEWUSER`).
- **Mathematical Process Extinction**: Automatic process tree termination via `CLONE_NEWPID` and `cgroup.kill`, proven dead within 500ms (INV-20).

---

## 2. Architecture Comparison

| Architectural Dimension | Docker Container Runtime | Vetto Benchmark Adapter (`vetto bench`) |
|---|---|---|
| **Daemon Requirement** | Mandatory (`dockerd`, `containerd`) | **None** (daemon-less, single static ELF binary) |
| **Privilege Model** | Requires root or access to `/var/run/docker.sock` | **Rootless** (`CLONE_NEWUSER`, unprivileged) |
| **Startup Path** | REST API call -> containerd -> shim -> runc -> namespace/veth -> execve | Direct `fork` -> `unshare` -> Landlock LSM -> `execve` |
| **Startup Latency** | 1,500 – 5,000 ms | **<4 ms** |
| **Per-Task Shim RSS** | 10 – 15 MB (`containerd-shim`) | **<0.5 MB** (native supervisor stack) |
| **Filesystem Isolation** | Overlay2 storage driver with graph driver locking | Landlock LSM ABI 1–6 with ephemeral tmpfs CoW |
| **Process Tree Cleanup** | Asynchronous `docker stop` / `docker rm -f` | In-kernel `CLONE_NEWPID` exit + `cgroup.kill` (INV-20) |
| **Memory Ceiling Enforcement** | cgroups v1 / v2 via daemon configuration | cgroups v2 (`memory.max`) with fail-closed Exit 125 |
| **Network Default** | Bridge network (requires network teardown) | Interface-less netns (`CLONE_NEWNET`) / `NetMode::Off` |

---

## 3. Kernel Isolation Primitives

Vetto enforces hermetic task execution using five Linux kernel subsystems without requiring elevated privileges:

1. **Landlock LSM (ABI 1–6)**:
   - Restricts filesystem access to the designated `--workspace` directory and `/tmp`.
   - Denies read and write access to parent directories and user configuration roots (`~/.ssh`, `~/.aws`, `~/.gnupg`).
   - Attached to directory file descriptors using `LANDLOCK_RULE_PATH_BENEATH`, preventing time-of-check to time-of-use (TOCTOU) symlink races.

2. **Namespaces (`unshare`)**:
   - `CLONE_NEWNS`: Mount namespace isolation with private root mount (`MS_PRIVATE | MS_REC`).
   - `CLONE_NEWPID`: Process namespace isolation where task process runs as PID 1; terminating PID 1 causes the Linux scheduler to immediately send `SIGKILL` to all descendants.
   - `CLONE_NEWNET`: Network namespace isolation without external interfaces; disables raw, TCP, and UDP sockets when `--net=off` is active.
   - `CLONE_NEWUSER`: UID/GID mapping allowing unprivileged sandbox initialization.

3. **cgroups v2 Resource Ceiling**:
   - Writes memory limit ceiling directly to delegated cgroup scope: `memory.max = <LIMIT>MB`.
   - Sets swap limit: `memory.swap.max = 0`.
   - Sets PID explosion ceiling: `pids.max = 256`.
   - If the task exceeds memory limits, the kernel cgroup OOM killer terminates the task without impacting the parent test runner.

4. **Ephemeral CoW Overlays**:
   - Root filesystem is mounted read-only.
   - All ephemeral file modifications are routed to a transient in-memory tmpfs upper layer.
   - Post-execution teardown discards modified inodes instantly without disk I/O wear.

5. **Process-Tree Extinction (Theorem §12.1)**:
   - Bounded monotonic watchdog enforces hard execution deadlines.
   - Extinction verifier proves zero surviving descendant processes within 500ms post-completion.

---

## 4. CLI Interface & Exit Code Contracts

### 4.1. Command Syntax

```bash
vetto bench [OPTIONS] -- <COMMAND> [ARGS...]
```

### 4.2. Options

| Option | Type | Default | Description |
|---|---|---|---|
| `-w, --workspace <DIR>` | Path | Current directory | Root workspace directory of the evaluation repository |
| `-t, --timeout <SEC>` | Integer | `180` | Hard wall-clock timeout in seconds |
| `-m, --memory <MB>` | Integer | `4096` | Memory limit ceiling in megabytes (`cgroups v2 memory.max`) |
| `--net <MODE>` | String | `off` | Network mode: `off`, `allowlist:<domains>`, or `strict:<domain:port>` |
| `--json` | Flag | `false` | Emit pure JSON telemetry to standard output (capturing child stdout/stderr) |
| `--instance-id <ID>` | String | None | SWE-bench instance identifier (e.g. `django__django-11099`) |
| `--profile <NAME>` | String | `swebench` | Policy profile to enforce (`profiles/agents/swebench.toml`) |
| `-e, --env <KEY=VALUE>` | String | Empty | Environment variable override passed into the sandboxed task |

### 4.3. Exit Code Contract

- **`0`**: Evaluation task completed successfully (child returned 0, no sandbox breach, no timeout).
- **`1 – 124`**: Natural child process exit code (e.g. `pytest` reporting failed tests returns 1).
- **`125`**: Fail-closed security boundary triggered:
  - Task execution timed out at deadline.
  - Task exceeded memory limit and was killed by cgroups OOM.
  - Landlock or seccomp blocked unauthorized access outside workspace.
  - Process tree failed extinction verification.

### 4.4. JSON Telemetry Contract

When `--json` is supplied, child process stdout and stderr are captured into JSON fields to prevent standard output stream corruption:

```json
{
  "exit_code": 0,
  "cold_start_ns": 1820450,
  "cold_start_ms": 1.82,
  "duration_ms": 1420,
  "peak_memory_bytes": 50331648,
  "peak_memory_mb": 48.0,
  "blocked_attempts": 0,
  "verdict": "pass",
  "timed_out": false,
  "oom_killed": false,
  "instance_id": "django__django-11099",
  "status": "COMPLETED",
  "stdout": "================ 2 passed in 0.84s ================\n",
  "stderr": ""
}
```

---

## 5. Python Adapter Integration (SWE-bench Harness)

The Python adapter `tools/swebench/vetto_adapter.py` provides drop-in compatibility with the SWE-bench evaluation harness:

```python
from tools.swebench.vetto_adapter import VettoTaskRunner

# Initialize runner pointing to local checkout
runner = VettoTaskRunner(
    workspace="/path/to/repo/django",
    timeout=180,
    memory_limit_mb=4096,
    net="off",
)

# Execute test suite inside kernel-isolated sandbox
result = runner.run_command(
    cmd=["pytest", "tests/model_fields/test_charfield.py"],
    instance_id="django__django-11099",
)

print(f"Verdict: {result.verdict}")
print(f"Cold Start: {result.cold_start_ms:.2f} ms")
print(f"Peak RAM: {result.peak_memory_mb:.1f} MB")
print(f"Exit Code: {result.exit_code}")
```

### Docker SDK Compatibility Shim

For legacy harnesses interacting directly with `docker.models.containers.Container`:

```python
container = runner.as_docker_container()
exit_code, output = container.exec_run("pytest tests/test_core.py")
```

---

## 6. Reproducible Benchmark Measurements

Measurements conducted on reference hardware (AMD EPYC 7763, Linux 6.8.0, NVMe storage):

| Benchmark Metric | Docker 26.1 (containerd 1.7) | Vetto Runtime Adapter | Measurement Method |
|---|---|---|---|
| **Cold-Start Latency (Median)** | 1,640.0 ms | **1.82 ms** | 100 iterations of empty interpreter spawn |
| **Cold-Start Latency (p99)** | 2,120.0 ms | **3.45 ms** | 100 iterations tail latency |
| **Daemon RSS Memory Overhead** | 245.0 MB | **0.0 MB** | Host memory RSS of runtime daemons |
| **Per-Task Runtime Memory** | 14.5 MB | **<0.5 MB** | Process table memory allocated per worker |
| **Single Test Suite Execution** | 4.82 s | **3.19 s** | Standard arithmetic/JSON test suite |
| **Process Tree Extinction** | Asynchronous | **<500 ms (proven)** | Kernel PID namespace termination verification |

### Running the Criterion Benchmarks

```bash
cargo bench --bench swebench_runtime
```

### Running the Comparative Benchmark Script

```bash
python3 tools/benchmarks/compare_docker.py --iterations 10
```
