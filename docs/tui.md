# Mission Control TUI Guide

Vetto includes an interactive Terminal User Interface (TUI) Mission Control dashboard built with Ratatui and Crossterm. It provides real-time visibility into your sandboxed AI coding fleet, active VFS isolation policies, live kernel LSM probes, and session lifecycle controls.

---

## Launching Mission Control

In any interactive terminal (TTY), run bare `vetto` with no subcommands:

```bash
vetto
```

Non-interactive scripts, CI environments, and Unix pipelines automatically bypass the TUI with zero overhead.

---

## Keybindings & Navigation

| Key | Action | Description |
| :--- | :--- | :--- |
| `1` – `6` | **Switch Tab** | Jump directly to Agents (1), Sandbox VFS (2), Kernel Doctor (3), Sessions (4), Security Stream (5), or Fleet Swarm (6) |
| `Tab` / `Shift+Tab` | **Cycle Tabs** | Move sequentially between all 6 tabs |
| `↑` / `k`, `↓` / `j` | **Select Item** | Navigate agents, sessions, or fleet workers in the active list |
| `Space` | **Toggle Shim** | Enable or disable transparent PATH-shim (`~/.vetto/shims/`) |
| `Enter` | **Launch Sandbox** | Execute selected agent inside an isolated kernel sandbox |
| `v` | **Verify Probe** | Run live 4-worker isolation verification probe on Fleet tab (`6`) |
| `x` | **Terminate Worker** | Terminate selected worker process and release slot on Fleet tab (`6`) |
| `u` | **Instant Undo** | Roll back workspace to the pre-session clean state |
| `t` | **Toggle Theme** | Switch between Arasaka Cyber-Red and Cyber Circuit |
| `r` | **Refresh** | Re-scan `$PATH`, running processes, fleet state, and kernel status |
| `q` / `Esc` | **Quit** | Exit Mission Control cleanly and restore terminal |

---

## Dashboard Views (Tabs)

### 1. `[1: AGENTS]` — Fleet Control
- **Dynamic Fleet Detection**: Automatically queries `$PATH` for known coding agents (`claude`, `codex`, `antigravity`, `opencode`, `cursor`, `aider`, `cline`, `windsurf`, `goose`, `openhands`, `devin`, `copilot`, `smolagents`, `omp`, `zcode`, `kimi`, `grok`). Agents not installed on your system are cleanly omitted from the list.
- **Process Status**: Displays whether an agent is currently running, its PID, and whether transparent PATH-shims are active (`CONFINED`) or inactive (`UNCONFINED`).
- **Interactive Controls**: Press `Space` to toggle transparent shims, or `Enter` to spawn an isolated sandbox.

### 2. `[2: SANDBOX VFS]` — Secret Isolation Matrix
- Visualizes real-time inode-level secret masking.
- Proves `mode=0000` tmpfs masking for sensitive host paths:
  - `~/.ssh` (id_rsa, id_ed25519, config)
  - `~/.aws` (credentials, config)
  - `~/.gnupg`
  - `.env`, `.env.*`
- Shows allowed project workspace roots and read-only system mounts (`/usr`, `/lib`, `/bin`).

### 3. `[3: KERNEL DOCTOR]` — Live Preflight Diagnostics
- **Landlock LSM ABI Probe**: Verifies available ABI (v1 through v6) and active capability rights (file execution, truncation, reparenting, socket binding).
- **User Namespaces**: Probes `unshare(CLONE_NEWUSER)` to confirm rootless containerization without `sudo`.
- **Cgroups v2 & Process Extinction**: Audits `cgroup.kill` and memory controllers.
- **Seccomp-BPF**: Confirms filter compilation and syscall restrictions.

### 4. `[4: SESSIONS]` — Session Auditing & Rollback
- Lists active and past sandboxed agent sessions.
- Displays recorded syscall denials, blocked network attempts, and modified files.
- Press `u` on any session to perform an instant, byte-level workspace rollback to the pre-session snapshot.

### 5. `[5: SECURITY STREAM]` — Real-Time Policy Interception
- **Real-Time Security Event Stream**: Captures and renders runtime kernel policy violations, unauthorized filesystem accesses, and blocked network attempts as they happen.
- **Interception Counters**: Displays aggregate statistics of total filesystem denials, dropped egress attempts, and prevented syscall anomalies.

### 6. `[6: FLEET SWARM]` — Fleet Concurrency & Swarm Telemetry
- **4 Metric Cards**:
  - **Active Fleet Workers**: Real-time counter of provisioned worker slots against maximum capacity (`active / 64`).
  - **Fair-Share CPU Weight**: Current cgroups v2 `cpu.weight` balance factor (`100`).
  - **Memory Ceiling per Worker**: Hard cgroup `memory.max` resource limit per agent (`2.0 GiB`).
  - **IPC / PID Isolation Status**: Live kernel namespace guarantees (`CLONE_NEWIPC + CLONE_NEWPID`).
- **Live Fleet Worker Allocation Table**:
  - 8-column real-time allocation grid: `WORKER ID`, `AGENT`, `PID`, `PORT`, `COW BRANCH`, `CGROUP SCOPE`, `LIMITS`, and `STATUS`.
  - Visual cursor (`▶ `) and theme-aware row highlighting for active selection.
- **Interactive Swarm Operations**:
  - Press `v` to run a live 4-worker pairwise isolation verification probe validating disjoint ephemeral ports, CoW branches, cgroups, and IPC/PID namespaces.
  - Press `x` to terminate the selected worker process (`SIGKILL` + `cgroup.kill`) and immediately release its slot.
  - Press `j` / `k` (or `↓` / `↑`) to navigate between active fleet workers.

---

## Visual Themes

- **Arasaka Cyber-Red** (Default): Deep obsidian background (`#08080c`) with vibrant neon crimson borders (`#ff003c`) and emerald indicators (`#00ff66`).
- **Cyber Circuit**: Classic amber-phosphor CRT terminal theme (`#ffaa00` with `#00f0ff` cyan accents).
- Toggle anytime by pressing `t`.

---

## Terminal Safety & Lifecycle

Mission Control installs a non-blocking panic hook on startup. If an unexpected error occurs, terminal alternate screen mode and raw input mode are guaranteed to be disabled immediately, restoring standard terminal settings without leaving artifacts or broken terminal states.
