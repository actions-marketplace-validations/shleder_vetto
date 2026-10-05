# SWE-bench Kernel Sandbox vs Docker Runtime Benchmark

Technical reference, empirical comparative benchmarks, and execution guide for running SWE-bench agent evaluations using the Vetto native Linux kernel sandbox (`vetto bench`) instead of Docker.

---

## 1. Architectural Rationale: Kernel Sandbox vs Container Daemon

SWE-bench and similar AI coding benchmarks evaluate models by executing thousands of iterative test suites (`pytest`, `unittest`) against repository checkouts. Standard harness implementations rely on Docker containers to achieve isolation:
- Launching containers introduces 1,500 to 5,000 ms of cold-start latency per task.
- `dockerd` and `containerd` maintain persistent background memory footprints (~250 MB RSS) and spawn individual `containerd-shim` processes (~14.5 MB RSS per task).
- Running 32–64 concurrent evaluation workers frequently encounters Docker socket lock contention, overlay2 driver exhaustion, or orphaned container leaks.
- Running Docker inside CI/CD requires Docker-in-Docker (DinD), privileged runners, or mounted host Docker sockets (`/var/run/docker.sock`), compromising runner security.

Vetto replaces the Docker daemon with direct Linux kernel isolation injected between `fork()` and `execve()`:
- **Zero Daemon Overhead**: Runs as a single static ELF binary with 0 MB background RSS.
- **Microsecond Cold Start**: Sub-millisecond isolation handshake (~0.2 ms kernel boundary setup, <2 ms total interpreter spawn) without container daemon roundtrips.
- **Rootless & Unprivileged**: Executes entirely in unprivileged user space via user namespaces (`CLONE_NEWUSER`) and Landlock LSM (ABI 1–6).
- **Atomic Process Extinction**: Automatic process tree termination via `CLONE_NEWPID` and cgroups v2 `cgroup.kill`, mathematically verified extinct within 500 ms (Theorem §12.1).

---

## 2. Comparative Metrics Summary

Measurements conducted on reference hardware (AMD EPYC 7763, Linux 6.8.0, NVMe storage) using `tools/benchmarks/compare_docker.py`:

| Metric | Vetto (`vetto bench`) | Docker (`docker run`) | Kernel / Runtime Mechanism |
|---|---|---|---|
| **Isolation Cold Start** | **~0.2 ms** (`fork()` -> `execve()`) | **~1,600 ms** | Landlock LSM + user namespaces vs containerd + runc setup |
| **Background Daemon Memory (RSS)** | **0 MB** (no daemon) | **~250 MB** (`dockerd` + `containerd`) | Single standalone process vs persistent supervisor daemons |
| **Per-Task Runtime Overhead** | **<0.5 MB** | **~14.5 MB** | Direct supervisor stack vs `containerd-shim` + veth interfaces |
| **Privilege Model** | **Unprivileged user** | **Root daemon** | `CLONE_NEWUSER` + Landlock vs root socket `/var/run/docker.sock` |
| **Lingering Process Extinction** | **Atomic `cgroup.kill`** (cgroups v2, <500 ms) | Asynchronous / orphaned containers | In-kernel cgroup tree wipe vs external container teardown |
| **Test Suite Execution (Wall Clock)** | **3.19 s** | **4.82 s** | Direct host VFS execution vs container overlay2 driver overhead |

---

## 3. Architecture Comparison

| Dimension | Docker Container Runtime | Vetto Benchmark Adapter (`vetto bench`) |
|---|---|---|
| **Daemon Requirement** | Mandatory (`dockerd`, `containerd`) | **None** (daemon-less, single static ELF binary) |
| **Privilege Model** | Requires root or access to `/var/run/docker.sock` | **Rootless** (`CLONE_NEWUSER`, unprivileged user) |
| **Startup Path** | REST API call -> containerd -> shim -> runc -> veth -> execve | Direct `fork()` -> `unshare()` -> Landlock LSM -> `execve()` |
| **Startup Latency** | 1,500 – 5,000 ms | **<4 ms** (<0.2 ms kernel boundary setup) |
| **Per-Task Shim RSS** | 10 – 15 MB (`containerd-shim`) | **<0.5 MB** (native supervisor stack) |
| **Filesystem Isolation** | Overlay2 storage driver with graph driver locking | Landlock LSM ABI 1–6 with ephemeral tmpfs CoW |
| **Process Tree Cleanup** | Asynchronous `docker stop` / `docker rm -f` | In-kernel `CLONE_NEWPID` exit + `cgroup.kill` (INV-20) |
| **Memory Ceiling Enforcement** | cgroups v1 / v2 via daemon configuration | cgroups v2 (`memory.max`) with fail-closed Exit 125 |
| **Network Default** | Bridge network (requires network teardown) | Interface-less netns (`CLONE_NEWNET`) / `NetMode::Off` |

---

## 4. Kernel Isolation Primitives

Vetto enforces hermetic task execution using native Linux kernel subsystems without requiring elevated privileges:

1. **Landlock LSM (ABI 1–6)**:
   - Restricts filesystem access to the designated `--workspace` directory and `/tmp`.
   - Denies read and write access to parent directories and user configuration roots (`~/.ssh`, `~/.aws`, `~/.gnupg`).
   - Attached to directory file descriptors using `LANDLOCK_RULE_PATH_BENEATH`, preventing time-of-check to time-of-use (TOCTOU) symlink races.

2. **Namespaces (`unshare`)**:
   - `CLONE_NEWNS`: Mount namespace isolation with private root mount (`MS_PRIVATE | MS_REC`).
   - `CLONE_NEWPID`: Process namespace isolation where the task process runs as PID 1; terminating PID 1 causes the Linux scheduler to immediately send `SIGKILL` to all descendants.
   - `CLONE_NEWNET`: Network namespace isolation without external interfaces; disables raw, TCP, and UDP sockets when `--net=off` is active.
   - `CLONE_NEWUSER`: UID/GID mapping allowing unprivileged sandbox initialization.

3. **cgroups v2 Resource Ceilings**:
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

## 5. CLI Interface & Protocol Contracts

### 5.1. Command Syntax

```bash
vetto bench [OPTIONS] -- <COMMAND> [ARGS...]
```

### 5.2. Options

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

### 5.3. Exit Code Contract

- **`0`**: Evaluation task completed successfully (child returned 0, no sandbox breach, no timeout).
- **`1 – 124`**: Natural child process exit code (e.g. `pytest` reporting failed tests returns 1).
- **`125`**: Fail-closed security boundary triggered:
  - Task execution timed out at deadline.
  - Task exceeded memory limit and was killed by cgroups OOM.
  - Landlock or seccomp blocked unauthorized access outside workspace.
  - Process tree failed extinction verification.

### 5.4. JSON Telemetry Schema

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

## 6. Python Adapter Integration (`tools/swebench/vetto_adapter.py`)

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

For legacy harnesses expecting `docker.models.containers.Container`:

```python
container = runner.as_docker_container()
exit_code, output = container.exec_run("pytest tests/test_core.py")
```

---

## 7. Reproducible Step-by-Step Guide: Local & CI/CD Execution (No Docker)

### Step 1: Verify Host Kernel Prerequisites

Vetto requires Linux kernel >= 5.13 with unprivileged user namespaces enabled. Verify the host system using the preflight doctor:

```bash
vetto doctor --preflight
```

Expected output confirms Landlock LSM ABI (version 1–6), user namespaces, and cgroups v2 controller delegation:

```text
[OK] Landlock LSM: ABI v3 detected
[OK] User Namespaces: unprivileged clone permitted
[OK] Cgroups v2: memory and pids controllers delegated
```

### Step 2: Direct Single-Task Run via `vetto bench`

To evaluate a single task directly inside the target repository without Docker:

```bash
vetto bench \
  --workspace /path/to/repo \
  --timeout 120 \
  --memory 4096 \
  --net off \
  --json \
  --instance-id "sympy__sympy-13480" \
  -- pytest sympy/core/tests/test_expr.py
```

### Step 3: Run SWE-bench Instances via the Python Adapter

The adapter `tools/swebench/vetto_adapter.py` handles patch application, test execution, and clean workspace rollback:

```bash
# Direct CLI invocation:
python3 tools/swebench/vetto_adapter.py \
  --workspace /path/to/repo \
  --timeout 180 \
  --memory 4096 \
  --instance-id "astropy__astropy-12907" \
  -- pytest astropy/tests/test_units.py
```

### Step 4: Run the Comparative Benchmark Suite

To measure live cold-start latency and compare with Docker reference metrics on your host:

```bash
python3 tools/benchmarks/compare_docker.py --iterations 10
```

To emit machine-readable JSON:

```bash
python3 tools/benchmarks/compare_docker.py --iterations 10 --json > benchmark_report.json
```

### Step 5: Headless CI/CD Pipeline (GitHub Actions without Docker)

Unlike standard SWE-bench evaluation workflows that require Docker setup, DinD, or privileged runners, Vetto runs directly on standard GitHub Actions `ubuntu-latest` runners:

```yaml
name: SWE-bench Evaluation

on: [push, pull_request]

jobs:
  evaluate:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install Dependencies
        run: pip install pytest

      - name: Install Vetto
        run: |
          npm install -g @shledery/vetto

      - name: Verify Sandbox Preflight
        run: vetto doctor --preflight

      - name: Run SWE-bench Task under Kernel Isolation
        run: |
          python3 tools/swebench/vetto_adapter.py \
            --workspace . \
            --timeout 120 \
            --instance-id "ci-eval-test" \
            -- pytest tests/
```
