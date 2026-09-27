![vetto — a kernel wall between the AI agent and your machine](assets/readme/hero.png)

<p align="center">
  <a href="https://github.com/shleder/vetto/actions"><img src="https://img.shields.io/github/actions/workflow/status/shleder/vetto/ci.yml?branch=main&label=CI&style=flat-square" alt="CI"></a>
  <a href="https://github.com/shleder/vetto/releases/tag/v0.5.2"><img src="https://img.shields.io/badge/version-0.5.2-blue?style=flat-square" alt="Version"></a>
  <a href="https://www.npmjs.com/package/@shledery/vetto"><img src="https://img.shields.io/badge/npm-v0.5.2-CB3837?logo=npm&logoColor=white&style=flat-square" alt="npm"></a>
  <a href="https://crates.io/crates/vetto"><img src="https://img.shields.io/badge/crates.io-v0.5.2-orange?logo=rust&logoColor=white&style=flat-square" alt="crates.io"></a>
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

## Interactive TUI Mission Control

Launch the interactive Mission Control dashboard by simply running `vetto` in any interactive terminal:

```bash
vetto
```

Features live AI agent fleet detection, one-touch PATH-shim toggling, real-time VFS secret matrix auditing, kernel preflight diagnostics, and zero-loss snapshot rollbacks.

For keybindings, detailed views, and theme configuration, see the [Mission Control TUI Guide](docs/tui.md).

---

## Proof Before Promises

Autonomous agents execute non-deterministic code. Untrusted dependency hooks, prompt injections, or hallucinated bash commands can compromise host credentials (`~/.ssh`, `~/.aws`, `.env`) or leak runaway background servers. Under Vetto, unauthorized system calls are blocked deterministically:

```text
> Reading ~/.ssh/id_rsa...         BLOCKED (secret mask, EACCES)
> Opening raw socket...             BLOCKED (net namespace, EAFNOSUPPORT)
> Spawning detached daemon...       TERMINATED (process tree extinction, exit 125)
```

![Blocked exfiltration attempt under vetto](assets/demo.svg)

### Fail-Closed Contract (Exit 125)

If an isolation boundary is violated or if required kernel primitives cannot be enforced, execution is terminated immediately with **exit code 125**. Descendant process trees and orphaned subprocesses are reaped synchronously via cgroups v2 `cgroup.kill`. Guarantees that the underlying OS cannot enforce are reported as unsupported—security is never silently downgraded.

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

### 2. Transparent Agent Sandboxing (PATH-Shims)

Enable zero-configuration sandboxing for your coding agent once. Vetto installs a non-destructive shim in `~/.vetto/shims` with priority in `PATH`:

```bash
vetto enable claude   # supports codex, opencode, cursor, aider, antigravity, and 18 profiles
claude                # runs normally — fully sandboxed at the kernel boundary
```

To unwrap and restore native execution:

```bash
vetto disable claude
```

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

Vetto includes dedicated out-of-the-box profiles (`profiles/agents/*.toml`), zero-config network allowlists, dynamic package manager cache mounts (`npm`, `uv`, `bun`), and Computer Use display pass-through for 18 leading agent runtimes:

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
