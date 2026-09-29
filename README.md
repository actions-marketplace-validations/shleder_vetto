![vetto - a kernel wall between the AI agent and your machine](assets/readme/hero.png)

<p align="center">
  <a href="https://github.com/shleder/vetto/actions"><img src="https://img.shields.io/github/actions/workflow/status/shleder/vetto/ci.yml?branch=main&label=CI&style=flat-square" alt="CI"></a>
  <a href="https://github.com/shleder/vetto/releases/tag/v0.5.11"><img src="https://img.shields.io/badge/version-0.5.11-blue?style=flat-square" alt="Version"></a>
  <a href="https://www.npmjs.com/package/@shledery/vetto"><img src="https://img.shields.io/badge/npm-v0.5.11-CB3837?logo=npm&logoColor=white&style=flat-square" alt="npm"></a>
  <a href="https://crates.io/crates/vetto"><img src="https://img.shields.io/badge/crates.io-v0.5.11-orange?logo=rust&logoColor=white&style=flat-square" alt="crates.io"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-green?style=flat-square" alt="License"></a>
</p>

<p align="center">
  <a href="README.md"><b>English</b></a> |
  <a href="docs/README.ru.md">Русский</a> |
  <a href="docs/README.zh.md">简体中文</a> |
  <a href="docs/README.ja.md">日本語</a> |
  <a href="docs/README.es.md">Español</a> |
  <a href="docs/README.de.md">Deutsch</a>
</p>

Rootless, daemon-less kernel-level sandbox and policy enforcement runtime for AI coding CLI agents (**Claude Code**, **OpenAI Codex**, **Cursor**, **OpenCode**, **Aider**, **Antigravity**, **OMP**, **ZCode**, **Kimi**, **Grok**). Vetto injects immutable security boundaries directly between `fork()` and `execve()` with sub-4ms startup latency and zero Docker overhead.

---

## Proof Before Promises

Autonomous agents execute non-deterministic code. Untrusted dependency hooks, prompt injections, or hallucinated bash commands can compromise host credentials (`~/.ssh`, `~/.aws`, `.env`) or leak runaway background servers. Under Vetto, unauthorized system calls are blocked deterministically:

```text
> Reading ~/.ssh/id_rsa...         BLOCKED (secret mask, EACCES)
> Opening raw socket...             BLOCKED (net namespace, EAFNOSUPPORT)
> Spawning detached daemon...       TERMINATED (process tree extinction, exit 125)
```

### Fail-Closed Contract (Exit 125)

If an isolation boundary is violated or if required kernel primitives cannot be enforced, execution is terminated immediately with **exit code 125**. Descendant process trees and orphaned subprocesses are reaped synchronously via cgroups v2 `cgroup.kill`. Guarantees that the underlying OS cannot enforce are reported as unsupported; security is never silently downgraded.

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

### 2. Wrap All AI Coding Agents in 5 Seconds (Primary Adoption)

Wrap every installed AI coding agent on your system in a single command without modifying configs or aliases:

```bash
vetto enable --all
```

Vetto scans `$PATH` for recognized coding agent executables (`claude`, `codex`, `cursor`, `opencode`, `aider`, `antigravity`, `omp`, `zcode`, `kimi`, `grok`, and 15 others), discovers their real binaries, and installs non-destructive interception shims into `~/.vetto/shims`.

Once enabled, invoke your agent normally. Execution is confined at the kernel LSM boundary with zero friction:

```bash
claude                # runs normally, fully sandboxed at the kernel boundary
cursor                # launched with protected credentials and scoped network
```

#### Selective Single-Agent Management

To selectively wrap or unwrap specific agents instead of all:

```bash
vetto enable claude    # wrap only claude
vetto disable claude   # unwrap and restore native unconfined execution
```

#### The Containerless Advantage over Docker

AI coding agents require real compilers, local package managers, and low latency. Running them inside Docker introduces friction that Vetto completely eliminates:

| Dimension | Docker / DinD | Vetto Containerless Runtime |
| :--- | :--- | :--- |
| **Startup Overhead** | 500ms–2000ms container creation | **<4ms** cold start between `fork()` and `execve()` |
| **Background Footprint** | `dockerd` daemon consuming 500MB+ RAM | **0MB** in RAM (daemon-less, pure kernel enforcement) |
| **Privilege Model** | Requires `root` or `docker` group (escalation risk) | **Rootless** unprivileged Landlock LSM + cgroups v2 |
| **Host Toolchains** | Requires rebuilding massive images with compilers | **Native**: direct access to host `cargo`, `npm`, `pip`, `uv` |
| **Package Caches** | Isolated or slow volume bind mounts | **Host speed**: native package caches preserved |
| **Process Cleanup** | Orphaned containers and leaked host processes | **Synchronous extinction** via `cgroups v2` (`cgroup.kill`) |

### 3. Direct Execution & Disposable Eval

Execute standalone scripts under strict default isolation:

```bash
vetto run -- python script.py
vetto -- npm test
```

Safely evaluate code snippets with cgroups v2 memory ceilings and monotonic hardware timeouts:

```bash
vetto eval --python -c "print(1 + 1)" --timeout 5 --memory 256
```

### 4. Instant Snapshot Rollback

Vetto takes automatic, copy-on-write workspace snapshots before agent execution:

```bash
vetto diff        # inspect exact file modifications made by the agent
vetto undo        # roll back workspace to the pre-execution clean state
```

### 5. Diagnostics & Preflight Probe

Audit host kernel isolation capabilities and container limits:

```bash
vetto doctor --preflight          # audit Landlock ABI, namespaces, and cgroups v2
vetto doctor --preflight --json   # machine-readable capability payload
```

### 6. Multi-Agent Fleet Concurrency (`vetto fleet`)

Orchestrate swarms of isolated AI coding agents with fair-share cgroups v2 resource quotas, pairwise namespace isolation, and ephemeral CoW branches:

```bash
# Inspect fleet capacity, fair-share limits, and active worker scopes
vetto fleet status
vetto fleet status --json

# Concurrently spawn isolated worker agents with fair-share cgroups
vetto fleet spawn claude --count 3
vetto fleet spawn --count 4 -- sh -c "python agent.py"

# Run automated pairwise isolation verification across N workers (28 checks for N=8)
vetto fleet verify --workers 8 --json

# Terminate worker or clean up entire fleet swarm
vetto fleet kill agent-01
vetto fleet kill --all
```

---

## CI/CD: Zero-Docker GitHub Actions Integration

Running AI coding agents in CI pipelines commonly relies on Docker-in-Docker (DinD). DinD introduces 30–120 second base image pull delays, requires insecure `--privileged` flags that expose the host runner, and lacks native support on macOS and Windows runner VMs.

Vetto provides a standard, zero-Docker replacement published on GitHub Marketplace (`shleder/vetto`):

- **Sub-4ms Cold Start**: Pre-compiled binaries (<15MB) with SHA-256 integrity verification install in under 1 second without container image pulls.
- **Rootless Kernel Sandboxing**: Enforces Landlock LSM and cgroups v2 boundaries on standard Ubuntu runners without `--privileged` flags or root access.
- **Host Toolchain & Cache Access**: Directly executes against `$GITHUB_WORKSPACE` and runner caching layers (`actions/cache`, `actions/setup-node`, `actions/setup-python`), avoiding costly container rebuilds.
- **Deterministic Process Reaping**: Eliminates orphaned background workers and fork-bombs via cgroups v2 (`cgroup.kill`).
- **Cross-Platform Support**: Operates consistently across `ubuntu-latest` (Landlock LSM), `macos-latest` (Seatbelt SBPL), and `windows-latest` (Job Objects).

### Option A: Universal Marketplace Action (`shleder/vetto`)

Execute a sandboxed agent command with automatic preset allowlisting, audit logs, and CodeQL SARIF reporting:

```yaml
name: Agent Security Gate
on: [pull_request]

jobs:
  verify:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write # Required for upload-sarif
    steps:
      - uses: actions/checkout@v4

      - name: Run Sandboxed Agent
        uses: shleder/vetto@v0.5.11
        with:
          command: 'npx @anthropic-ai/claude-code -p "Run linter and fix basic formatting"'
          agent: 'claude'
          profile: 'strict'
          fail-on-block: '1'
          upload-sarif: 'true'
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

### Option B: Setup Mode for Multi-Step Workflows

When `command` is omitted, `shleder/vetto` verifies and installs the standalone `vetto` binary into `$GITHUB_PATH`:

```yaml
      - name: Setup Vetto
        uses: shleder/vetto@v0.5.11
        with:
          version: 'latest'

      - name: Run Sandboxed Commands
        run: |
          vetto doctor --preflight
          vetto run -- aider --message "Refactor parser error handling"
```

---

## Interactive TUI Mission Control

Launch the interactive Mission Control dashboard by running `vetto` in any interactive terminal:

```bash
vetto
```

Features live AI agent fleet detection, one-touch PATH-shim toggling, real-time VFS secret matrix auditing, kernel preflight diagnostics, zero-loss snapshot rollbacks, real-time policy interception streaming (`[5: SECURITY STREAM]`), and multi-agent swarm orchestration (`[6: FLEET SWARM]`).

For keybindings, detailed views, and theme configuration, see the [Mission Control TUI Guide](docs/tui.md).

---

## Platform Guarantees

Vetto enforces an immutable three-tier boundary model based on kernel capabilities available to unprivileged userspace:

| Platform / Tier | Filesystem Isolation | Network Isolation | Process Lifecycle | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Linux (Native)**<br>Tier 1 | **Landlock LSM (ABI 1–6)**<br>Inode-level VFS masking over `~/.ssh`, `~/.aws`, `.env` (mode 0000 tmpfs) | **Network Namespaces (`CLONE_NEWNET`)**<br>Loopback isolation + local TCP/TLS broker with SNI inspection | **PID Namespaces (`CLONE_NEWPID`)**<br>Deterministic process tree extinction via `cgroups v2` | Production |
| **Linux (WSL2)**<br>Tier 1 | **Landlock LSM via WSL2 kernel**<br>Full inode restriction | **Network Namespaces inside VM**<br>Isolated broker egress | **PID Namespaces + `/proc` sweep**<br>Full tree extinction | Production (Recommended for Windows) |
| **macOS (Darwin)**<br>Tier 2 | **Seatbelt (`libsandbox.1.dylib`)**<br>Write confinement to `$PROJECT` and `/tmp` | **Network Lockdown**<br>`--net=off` via `(deny network*)` rules | **Process Group Sweeping**<br>`pidfd` / kqueue watchdog supervision | Standard (Requires Full Disk Access for `~/Documents`) |
| **Windows Native**<br>Tier 3 | **AppContainer & LPAC**<br>DACL token restriction | **Capability Lockdown**<br>Restricted network SIDs | **Job Objects**<br>`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` | Guardrail (Use WSL2 for Tier 1 kernel namespaces) |

---

## Multi-Agent Compatibility Roster

Vetto includes dedicated out-of-the-box profiles (`profiles/agents/*.toml`), zero-config network allowlists, dynamic package manager cache mounts (`npm`, `uv`, `bun`), and Computer Use display pass-through for 24 leading agent runtimes:

| Agent | Binary / Preset | Automatic Network Presets | Custom Plugins & Caches |
| :--- | :--- | :--- | :--- |
| **Claude Code** | `claude` | `api.anthropic.com`, `claude.ai` | `~/.claude`, `~/.config/claude`, plugins |
| **OpenAI Codex** | `codex` | `api.openai.com`, ChatGPT OAuth | `~/.codex`, `~/.config/codex`, plugins |
| **OpenCode** | `opencode` | Dynamic JSONC endpoints (AIHubMix, Nvidia) | `~/.local/share/opencode`, `~/.config/opencode` |
| **Antigravity** | `agy`, `antigravity` | Google APIs, Google CDN, telemetry | `~/.gemini/antigravity`, plugins, skills |
| **OMP** | `omp` | `omp.sh`, Anthropic, OpenAI, Google, OpenRouter | `~/.config/omp`, `~/.omp`, project local `.omp` |
| **ZCode** | `zcode` | `z.ai`, `api.z.ai`, `glm.z.ai`, OpenAI | `~/.zcode`, `~/.config/zcode` |
| **Kimi Code** | `kimi` | `code.kimi.com`, `api.moonshot.cn`, `api.moonshot.ai` | `~/.kimi`, `~/.config/kimi` |
| **Grok Build** | `grok` | `x.ai`, `api.x.ai`, `grok.com` | `~/.grok`, `~/.config/grok` |
| **Cursor** | `cursor` | Cursor backend, extension marketplace | VS Code IPC sockets, `~/.cursor` |
| **Aider** | `aider` | Configured LLM provider endpoints | Git repo root, history caches |
| **Cline** | `cline` | `api.cline.bot`, `data.cline.bot` | VS Code extension host, browser caches |
| **Windsurf** | `windsurf` | `api.codeium.com`, `windsurf.codeium.com` | `~/.windsurf`, Cascade state |
| **Goose** | `goose` | Block API, Anthropic, Databricks | `~/.config/goose`, extensions |
| **OpenHands** | `openhands` | Configured model endpoints | Docker-less local execution |
| **Devin** | `devin` | `api.devin.ai`, `cognition.ai` | `~/.devin`, `~/.config/devin` |
| **GitHub Copilot** | `copilot` | `api.github.com`, Copilot endpoints | `~/.config/github-copilot` |
| **Smolagents** | `smolagents` | `huggingface.co`, `hf.co` | `~/.cache/huggingface`, PyTorch caches |
| **Hermes Agent** | `hermes` | `nousresearch.com`, Together, OpenAI, Anthropic | `~/.hermes`, `~/.config/hermes` |
| **Kilo Code** | `kilo` | `api.kilo.ai`, OpenAI, Anthropic, OpenRouter | `~/.kilo`, `~/.config/kilo` |
| **pi** | `pi` | `api.groq.com`, OpenAI, Anthropic, OpenRouter | `~/.pi`, `~/.config/pi` |
| **Command Code** | `command_code` | `api.cohere.com`, Cohere AI, OpenAI, Anthropic | `~/.command-code`, `~/.config/command-code` |
| **Freebuff** | `freebuff` | `api.deepseek.com`, OpenAI, Anthropic | `~/.freebuff`, `~/.config/freebuff` |
| **DeepSeek Harness** | `deepseek_harness` | `api.deepseek.com`, OpenAI, Anthropic | `~/.deepseek`, `~/.config/deepseek` |
| **Omnigent** | `omnigent` | `api.omnigent.ai`, OpenAI, Anthropic | `~/.omnigent`, `~/.config/omnigent` |

---

## Active Upstream Integrations & Ecosystem PRs

Vetto engineering maintains native upstream isolation adapters across open-source AI agent frameworks, replacing heavy Docker daemon dependencies and unprotected subprocesses with unprivileged kernel LSM fencing:

| Framework | Target Issue | Integration PR | Isolation Architecture |
| :--- | :--- | :--- | :--- |
| **Hugging Face smolagents** | [#2845](https://github.com/huggingface/smolagents/issues/2845) | [PR #2860](https://github.com/huggingface/smolagents/pull/2860) | `ProcessIsolatedExecutor` with monotonic wall-clock timeout and process group extinction (`os.killpg(SIGKILL)`). |
| **browser-use** | [#5879](https://github.com/browser-use/browser-use/issues/5879) | [PR #5929](https://github.com/browser-use/browser-use/pull/5929) | Pre-flight DNS watchdog blocking loopback, RFC 1918, CGNAT, and AWS/GCP instance metadata. |
| **OpenHands** | [#4266](https://github.com/OpenHands/software-agent-sdk/issues/4266) | [PR #5344](https://github.com/OpenHands/software-agent-sdk/pull/5344) | `LandlockWorkspace` containerless backend with dynamic Linux Landlock ABI (1–6) detection and rootless path bounding. |
| **Block goose** | [#12522](https://github.com/aaif-goose/goose/issues/12522) | [PR #12545](https://github.com/aaif-goose/goose/pull/12545) | `SubprocessExt` containerless process fencer with `PR_SET_PDEATHSIG`, subreaper, and namespace sandboxing. |
| **Block goose (ACP)** | [#12513](https://github.com/aaif-goose/goose/issues/12513) | [PR #12563](https://github.com/aaif-goose/goose/pull/12563) | ACP local shell execution policy (`GOOSE_ACP_CLIENT_TERMINAL`) and automatic sandbox confinement detection. |
| **Cline** | [#14544](https://github.com/cline/cline/issues/14544) | [PR #14583](https://github.com/cline/cline/pull/14583) | Multi-tier terminal sandbox execution and secret masking (`~/.ssh`, `.env`) in `ClineIgnoreController`. |
| **Qwen Code** | [#12856](https://github.com/QwenLM/qwen-code/issues/12856) | [PR #12953](https://github.com/QwenLM/qwen-code/pull/12953) | Credential egress scrubbing across 8 surfaces and workspace tombstones (`splitAuxModelSelector`). |
| **Claude Code History Viewer** | [#509](https://github.com/jhlee0409/claude-code-history-viewer/issues/509) | [PR #595](https://github.com/jhlee0409/claude-code-history-viewer/pull/595) | Session resume CLI flags and shell-metacharacter validation in Tauri backend. |

---

## Binary Integrity & Attestation

Releases are built via automated GitHub Actions workflows with public cryptographic verification:

- **SLSA Level 3 Provenance**: In-toto build attestations generated for all release binaries.
- **Minisign Signatures**: Published with each release archive under public key `75ECEC9B5080C590`.
- **Cryptographic Checksums**: Standalone SHA-256 hashes generated and verified during installation.

---

## Documentation

- [Platform Backends & Boundary Specs](docs/platform-backends.md)
- [Agent Presets & Registry](docs/agents.md)
- [Threat Model & Security Assumptions](docs/threat-model.md)
- [Diagnostic Preflight Verification](docs/architecture/verify-ng.md)
- [Exit Codes & Failure Modes](docs/exit-codes.md)
- [Vulnerability Reporting (SECURITY.md)](SECURITY.md)

---

## Contributing

Contributions are welcome. Please branch from `main`. All boundary assertions must include corresponding kernel validation test cases. Pull requests are validated against Linux, macOS, and Windows kernel runners in GitHub Actions CI.

---

## License

Licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE)).
