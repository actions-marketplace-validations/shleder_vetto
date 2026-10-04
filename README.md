![vetto - a kernel wall between the AI agent and your machine](assets/readme/hero.png)

<p align="center">
  <a href="https://github.com/shleder/vetto/actions"><img src="https://img.shields.io/github/actions/workflow/status/shleder/vetto/ci.yml?branch=main&label=CI&style=flat-square" alt="CI"></a>
  <a href="https://github.com/shleder/vetto/releases/tag/v0.5.15"><img src="https://img.shields.io/badge/version-0.5.15-blue?style=flat-square" alt="Version"></a>
  <a href="https://www.npmjs.com/package/@shledery/vetto"><img src="https://img.shields.io/badge/npm-v0.5.15-CB3837?logo=npm&logoColor=white&style=flat-square" alt="npm"></a>
  <a href="https://crates.io/crates/vetto"><img src="https://img.shields.io/badge/crates.io-v0.5.15-orange?logo=rust&logoColor=white&style=flat-square" alt="crates.io"></a>
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

Running AI coding agents in CI usually involves Docker-in-Docker, which adds image pull overhead, often requires privileged runners, and is not portable across non-Linux VMs.

The `shleder/vetto` action runs agents on standard GitHub Actions runners without Docker:

- Cold start under 4ms with standalone binary verification.
- Rootless Landlock LSM and cgroups v2 enforcement on standard Ubuntu runners.
- Direct access to `$GITHUB_WORKSPACE` and action caches (`actions/cache`, `actions/setup-node`, `actions/setup-python`).
- Clean teardown of all subprocesses via `cgroup.kill`.
- Multi-platform support on Ubuntu, macOS, and Windows runners.

### Option A: Run a sandboxed agent step

Run an agent with policy allowlisting and optional SARIF audit output:

```yaml
name: Agent Security Gate
on: [pull_request]

jobs:
  verify:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Run Sandboxed Agent
        uses: shleder/vetto@v0.5.15
        with:
          command: 'npx @anthropic-ai/claude-code -p "Run linter and fix basic formatting"'
          agent: 'claude'
          profile: 'strict'
          fail-on-block: '1'
          upload-sarif: 'true'
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

### Option B: Install Vetto for multi-step workflows

Omit the `command` input to install the `vetto` binary into `$GITHUB_PATH`:

```yaml
      - name: Setup Vetto
        uses: shleder/vetto@v0.5.15
        with:
          version: 'latest'

      - name: Run Sandboxed Commands
        run: |
          vetto doctor --preflight
          vetto run -- aider --message "Refactor parser error handling"
```

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

## Python SDK (`vetto-python`)

The Python package in `sdk/python/` provides bindings to run sandboxed commands and isolate agent steps:

```python
from vetto import VettoSandbox, VettoSecurityError, VettoTimeoutError

sandbox = VettoSandbox(
    project_dir=".",
    network="allowlist:api.anthropic.com,api.openai.com",
    profile="default",
    timeout_secs=60,
)

# Runs command inside the sandbox. Raises VettoSecurityError on policy violation (exit 125).
result = sandbox.run(["pytest", "tests/"])
```

### LangGraph integration

The package includes `VettoToolNode` to isolate tool execution inside LangGraph workflows:

```python
from vetto.langgraph import VettoToolNode

tool_node = VettoToolNode(
    tools=[search_tool, execute_code_tool],
    network="off",
    timeout_secs=30,
)
```

---

## Upstream integrations

Vetto provides containerless process isolation pull requests for several open-source agent frameworks:

| Framework | Issue | Pull request | Details |
| :--- | :--- | :--- | :--- |
| **CrewAI** | [#7830](https://github.com/crewAIInc/crewAI/issues/7830) | [PR #7831](https://github.com/crewAIInc/crewAI/pull/7831) | `VettoExecTool` and `VettoPythonTool` unprivileged process isolation with workspace boundary fencing and timeout handling. |
| **Microsoft AutoGen** | [#8298](https://github.com/microsoft/autogen/issues/8298) | [PR #8299](https://github.com/microsoft/autogen/pull/8299) | `VettoCommandLineCodeExecutor` containerless sandbox in `autogen-ext`. |
| **OpenClaw** | [#160522](https://github.com/openclaw/openclaw/issues/160522) | [PR #161125](https://github.com/openclaw/openclaw/pull/161125) | Memory containment and heap threshold controls under `--max-old-space-size`. |
| **Hugging Face smolagents** | [#2845](https://github.com/huggingface/smolagents/issues/2845) | [PR #2860](https://github.com/huggingface/smolagents/pull/2860) | `ProcessIsolatedExecutor` with wall-clock timeout and process group termination. |
| **browser-use** | [#5879](https://github.com/browser-use/browser-use/issues/5879) | [PR #5929](https://github.com/browser-use/browser-use/pull/5929) | DNS preflight check blocking loopback, RFC 1918, CGNAT, and cloud metadata addresses. |
| **OpenHands** | [#4266](https://github.com/OpenHands/software-agent-sdk/issues/4266) | [PR #5344](https://github.com/OpenHands/software-agent-sdk/pull/5344) | `LandlockWorkspace` backend using Linux Landlock ABI 1 to 6 detection. |
| **Block goose** | [#12522](https://github.com/aaif-goose/goose/issues/12522) | [PR #12545](https://github.com/aaif-goose/goose/pull/12545) | `SubprocessExt` containerless process fencer with subreaper tracking and namespace sandboxing. |
| **Block goose (ACP)** | [#12513](https://github.com/aaif-goose/goose/issues/12513) | [PR #12563](https://github.com/aaif-goose/goose/pull/12563) | Shell execution policy (`GOOSE_ACP_CLIENT_TERMINAL`) with sandbox detection. |
| **Cline** | [#14544](https://github.com/cline/cline/issues/14544) | [PR #14583](https://github.com/cline/cline/pull/14583) | Terminal sandbox execution and secret masking (`~/.ssh`, `.env`) in `ClineIgnoreController`. |
| **Qwen Code** | [#12856](https://github.com/QwenLM/qwen-code/issues/12856) | [PR #12953](https://github.com/QwenLM/qwen-code/pull/12953) | Credential egress scrubbing and workspace protection. |
| **Claude Code History Viewer** | [#509](https://github.com/jhlee0409/claude-code-history-viewer/issues/509) | [PR #595](https://github.com/jhlee0409/claude-code-history-viewer/pull/595) | Session resume flags and input validation. |

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
- [Threat model and security boundaries](docs/threat-model.md)
- [Preflight diagnostic checks](docs/architecture/verify-ng.md)
- [Exit codes and failure modes](docs/exit-codes.md)
- [Security policy and vulnerability reporting](SECURITY.md)

---

## Contributing

Contributions are welcome. Please open pull requests against the `main` branch. All boundary assertions must include corresponding validation tests. Pull requests run against Linux, macOS, and Windows runners in GitHub Actions CI.

---

## License

Licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE)).
