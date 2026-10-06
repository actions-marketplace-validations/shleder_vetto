<div align="center">

```text
██╗   ██╗███████╗████████╗████████╗ ██████╗ 
██║   ██║██╔════╝╚══██╔══╝╚══██╔══╝██╔═══██╗
██║   ██║█████╗     ██║      ██║   ██║   ██║
╚██╗ ██╔╝██╔══╝     ██║      ██║   ██║   ██║
 ╚████╔╝ ███████╗   ██║      ██║   ╚██████╔╝
  ╚═══╝  ╚══════╝   ╚═╝      ╚═╝    ╚═════╝ 
```

# VETTO

<p align="center">
  <b>Sub-Millisecond Linux Kernel Sandbox for AI Coding Agents</b>
</p>

[![CI](https://img.shields.io/github/actions/workflow/status/shleder/vetto/ci.yml?branch=main&label=CI&style=flat-square)](https://github.com/shleder/vetto/actions)
[![Release](https://img.shields.io/github/v/release/shleder/vetto?label=release&color=blue&style=flat-square)](https://github.com/shleder/vetto/releases)
[![npm version](https://img.shields.io/badge/npm-v0.6.1-CB3837?logo=npm&logoColor=white&style=flat-square)](https://www.npmjs.com/package/@shledery/vetto)
[![crates.io](https://img.shields.io/badge/crates.io-v0.6.1-orange?logo=rust&logoColor=white&style=flat-square)](https://crates.io/crates/vetto)
[![Platforms](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square)](https://github.com/shleder/vetto)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-green?style=flat-square)](LICENSE)

<p align="center">
  <a href="README.md"><b>English</b></a> |
  <a href="docs/README.ru.md">Русский</a> |
  <a href="docs/README.zh.md">简体中文</a> |
  <a href="docs/README.ja.md">日本語</a> |
  <a href="docs/README.es.md">Español</a> |
  <a href="docs/README.de.md">Deutsch</a>
</p>

</div>

Vetto is an unprivileged sandbox for AI coding CLI agents such as Claude Code, OpenAI Codex, Cursor, OpenCode, and Aider. It isolates filesystem access, network sockets, and child processes between `fork()` and `execve()` using native kernel facilities on Linux and macOS without running a background daemon or requiring root privileges.

---

## Kernel boundary enforcement

AI coding agents run generated shell commands and build scripts. If an agent tries to read private credentials, open raw network sockets, or spawn untracked background processes, Vetto blocks the operation at the kernel layer:

```text
> Reading ~/.ssh/id_rsa...         BLOCKED (secret mask, EACCES)
> Opening raw socket...             BLOCKED (net namespace, EAFNOSUPPORT)
> Spawning detached daemon...       TERMINATED (process tree extinction, exit 125)
```

### Fail-closed execution (exit 125)

When an agent violates policy or when the host kernel lacks a required isolation mechanism, Vetto exits immediately with code 125. Descendant processes and background workers are terminated synchronously through cgroups v2 `cgroup.kill`. If the host operating system cannot enforce a configured rule, Vetto reports the missing capability and halts instead of running with reduced security.

---

## Quick Start

### 1. Installation

Via standard package managers:

```bash
# npm (cross-platform global binary)
npm install -g @shledery/vetto

# Homebrew (macOS & Linux)
brew install shleder/tap/vetto

# Cargo (crates.io)
cargo install vetto
```

Or via standalone curl installer:

```bash
curl -fsSL https://raw.githubusercontent.com/shleder/vetto/main/install.sh | sh
```

### 2. Transparent agent wrapping

Wrap installed AI coding agents without modifying shell configurations or aliases:

```bash
vetto enable --all
```

Vetto searches `$PATH` for supported agent binaries (`claude`, `codex`, `cursor`, `opencode`, `aider`, `antigravity`, and others) and places interceptor shims in `~/.vetto/shims`.

After enabling, run the agent normally:

```bash
claude                # runs sandboxed under kernel LSM policies
cursor                # runs with protected credentials and restricted network egress
```

To manage individual agents:

```bash
vetto enable claude    # wrap claude only
vetto disable claude   # restore direct execution without sandboxing
```

### Comparison with Docker

AI coding agents need local compilers, existing package caches, and interactive terminal handling. Running them inside Docker requires heavy container setup, whereas Vetto applies kernel sandboxing directly to host processes:

| Dimension | Docker / DinD | Vetto |
| :--- | :--- | :--- |
| Startup overhead | 500ms to 2000ms container creation | Under 4ms cold start between `fork()` and `execve()` |
| Memory footprint | Background `dockerd` process | 0 MB background memory (no daemon) |
| Privilege model | Requires `root` or `docker` group membership | Unprivileged user namespaces, Landlock LSM, and cgroups v2 |
| Toolchains | Requires rebuilding container images | Direct access to host `cargo`, `npm`, `pip`, and `uv` |
| Package caches | Volume mounts or repeated downloads | Reuses host package caches directly |
| Process cleanup | Can leave orphaned containers | Synchronous process tree termination via cgroups v2 `cgroup.kill` |

For empirical performance measurements and adapter setup, see the [SWE-bench vs Docker Benchmark](docs/benchmarks/swe-bench.md).

### 3. Direct execution

Run arbitrary commands or scripts inside the sandbox:

```bash
vetto run -- python script.py
vetto -- npm test
```

### 4. Workspace snapshot rollback

Vetto takes a copy-on-write snapshot of the project directory before the agent starts work:

```bash
vetto diff        # show files modified, added, or removed by the agent
vetto undo        # revert the workspace back to its pre-execution state
```

### 5. Host diagnostics

Check which kernel isolation features are available on the current machine:

```bash
vetto doctor --preflight          # inspect Landlock ABI, namespaces, and cgroups v2
vetto doctor --preflight --json   # output diagnostic report as JSON
```

---

## GitHub Actions integration

Run AI coding agents securely inside your CI pipelines without Docker or root privileges using the official `shleder/vetto` action:

```yaml
- name: Run Sandboxed Agent
  uses: shleder/vetto@v0.6.1
  with:
    command: 'npx @anthropic-ai/claude-code -p "Fix linter errors"'
    agent: 'claude'
    profile: 'strict'
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

See the [CI/CD integration guide](docs/ci-cd.md) for full configuration options, multi-step workflows, and SARIF security reporting.

---

## Terminal handling and statusline

Interactive agents such as Claude Code and Codex manage their own terminal state (PTY). Vetto preserves direct terminal input and output while showing sandbox status:

- **Statusline overlay (`--tui=statusline`)**: Default for non-interactive commands. Shows active filesystem and network policies in the bottom line of the terminal.
- **Headless mode (`--tui=none` / `--ci`)**: Disables terminal UI rendering. Use this flag in CI environments, shell scripts, or when piping standard streams.

---

## Platform support

Vetto uses the unprivileged isolation features provided by each operating system:

| Platform | Filesystem isolation | Network isolation | Process lifecycle | Tier |
| :--- | :--- | :--- | :--- | :--- |
| **Linux (Native)** | **Landlock LSM (ABI 1 to 6)**<br>Tmpfs masking over `~/.ssh`, `~/.aws`, `.env` | **Network namespaces (`CLONE_NEWNET`)**<br>Loopback isolation with local TCP/TLS proxy | **PID namespaces (`CLONE_NEWPID`)**<br>Process tree cleanup via cgroups v2 `cgroup.kill` | Tier 1 (Full) |
| **Linux (WSL2)** | **Landlock LSM via WSL2 kernel**<br>Path access restrictions | **Network namespaces in VM**<br>Filtered outbound connections | **PID namespaces and `/proc` sweep**<br>Full tree termination | Tier 1 (Full) |
| **macOS (Darwin)** | **Seatbelt (`libsandbox.1.dylib`)**<br>Restricts writes to project directory and `/tmp` | **Network restriction**<br>`--net=off` blocks IP egress; `--net=allowlist` uses local loopback proxy | **Process supervision**<br>Watchdog tracking child process groups | Tier 2 (Target Tier 1.5) |
| **Windows Native** | **AppContainer and LPAC**<br>Token-based access control | **Capability restrictions**<br>Restricted network SIDs | **Job Objects**<br>`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` | Tier 3 (Guardrail) |

### Note on macOS Seatbelt

macOS does not offer unprivileged network namespaces. Vetto uses Apple's native Seatbelt framework (`libsandbox.1.dylib`) to restrict filesystem write access and protect user credentials. When `--net=off` is set, network traffic and IPC to `mDNSResponder` are blocked. When `--net=allowlist` is set, Vetto runs an ephemeral loopback proxy on `127.0.0.1` and restricts outgoing TCP traffic to that port. Read restrictions on macOS are scoped broadly to account for system dyld cache behavior.

---

## Supported AI agents

Vetto includes pre-configured profiles for more than 25 AI coding tools. Each profile scopes network egress to known provider endpoints and protects host credentials while keeping package caches available:

| Agent | Binary / Preset | Network endpoints | Protected configs and caches |
| :--- | :--- | :--- | :--- |
| **Claude Code** | `claude` | `api.anthropic.com`, `claude.ai` | `~/.claude`, `~/.config/claude`, plugins |
| **OpenAI Codex** | `codex` | `api.openai.com`, ChatGPT OAuth | `~/.codex`, `~/.config/codex`, plugins |
| **Cursor** | `cursor` | Cursor backend, extension marketplace | VS Code IPC sockets, `~/.cursor` |
| **Aider** | `aider` | Configured LLM provider endpoints | Git repository root, history caches |

For the complete list of supported agents, network scopes, and path rules, see the [Agent compatibility registry](docs/agents.md).

---

## Verification and integrity

Releases are built via automated GitHub Actions workflows with public cryptographic verification:

- **SLSA Level 3 Provenance**: In-toto build attestations generated for release binaries.
- **Minisign Signatures**: Published with each release archive under public key `75ECEC9B5080C590`.
- **SHA-256 Checksums**: Verified automatically by installation scripts.

---

## Documentation

- [Platform backends and isolation specs](docs/platform-backends.md)
- [Agent presets and configuration](docs/agents.md)
- [SWE-bench vs Docker runtime benchmark](docs/benchmarks/swe-bench.md)
- [Threat model and security boundaries](docs/threat-model.md)
- [CI/CD integration and GitHub Actions](docs/ci-cd.md)
- [Exit codes and failure modes](docs/exit-codes.md)
- [Security policy and vulnerability reporting](SECURITY.md)

---

## Contributing

Contributions are welcome. Please open pull requests against the `main` branch. All boundary assertions must include corresponding validation tests. Pull requests run against Linux, macOS, and Windows runners in GitHub Actions CI.

---

## License

Licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE)).
