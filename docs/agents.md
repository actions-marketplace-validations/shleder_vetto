# Agent compatibility registry

This registry describes the outer vetto integration contract. Built-in agent
sandbox behavior changes independently, so an agent preset may add required
read paths or environment names but must never weaken vetto's enforcement.
`Last tested` is intentionally explicit; `not in CI` means compatibility is
unproven rather than assumed.

| Agent | Typical command | Built-in isolation | Recommended mode | Preset | Network notes | Last tested |
|---|---|---|---|---|---|---|
| OpenAI Codex CLI | `codex`, `codex exec` | Yes; platform/config dependent | statusline for interactive, full/none for `exec` | `codex` | Provider and Git endpoints must be explicitly allowed | not in CI |
| Claude Code | `claude`, `claude -p` | Optional/tool-specific | statusline for interactive, full/none for `-p` | `claude` | Provider and package endpoints depend on the task | not in CI |
| OpenCode | `opencode` | permission model is not treated as an OS boundary | statusline | `opencode` | Provider-specific | not in CI |
| Antigravity | `antigravity`, `agy` | Google internal boundary | statusline or full | `antigravity` | Google Cloud & APIs | not in CI |
| OMP | `omp` | Stencil Labs isolation boundary | statusline | `omp` | `omp.sh`, Anthropic, OpenAI, Google, OpenRouter | not in CI |
| ZCode | `zcode`, `zcode-cli` | Z.ai internal boundary | statusline | `zcode` | `z.ai`, `api.z.ai`, `glm.z.ai`, OpenAI | not in CI |
| Kimi Code | `kimi` | Moonshot AI boundary | statusline | `kimi` | `code.kimi.com`, Moonshot API | not in CI |
| Grok Build | `grok`, `grok-build` | xAI boundary | statusline | `grok` | `x.ai`, `api.x.ai`, `grok.com` | not in CI |
| Cursor Agent | `cursor-agent` | Implementation/version dependent | full | `cursor` | Treat endpoints as untrusted configuration | not in CI |
| Aider | `aider` | No uniform OS boundary assumed | statusline | `aider` | Model provider plus optional Git endpoints | not in CI |
| Cline | user-configured CLI/extension command | unknown | full | `cline` | Do not infer endpoints from the preset | not in CI |
| GitHub Copilot CLI | `copilot` | implementation/version dependent | statusline | `copilot` | GitHub endpoints only when needed | not in CI |
| Windsurf | `windsurf` | Codeium Cascade boundary | statusline | `windsurf` | Codeium API endpoints | not in CI |
| Block Goose AI | `goose` | Implementation dependent | statusline or full | `goose` | Model provider endpoints | not in CI |
| OpenHands | `openhands` | Containerized or local | statusline or none | `openhands` | Model endpoints | not in CI |
| Cognition Devin | `devin` | Cloud agent CLI | statusline | `devin` | Devin API endpoints | not in CI |
| Hugging Face smolagents | `smolagents`, `vetto eval` | No OS isolation (threads) | none / full | `smolagents` | Hugging Face Hub + model providers | covered in CI |
| Hermes Agent (#1 Leaderboard) | `hermes`, `hermes-agent` | Unbounded Python runtime | statusline or full | `hermes` | Model provider + target repo write boundary | first-class preset |
| Kilo Code (#3 Leaderboard) | `kilo`, `kilo-code` | Extension/CLI boundary | full | `kilo` | Workspace root containment & tmpfs secret overlay | first-class preset |
| pi (#5 Leaderboard) | `pi` | Minimalist terminal runtime | statusline | `pi` | Model provider endpoints | first-class preset |
| Command Code (#8 Leaderboard) | `command-code` | Autonomous loop | full | `command_code` | Strict timeout & process group eviction | first-class preset |
| Freebuff (#9 Leaderboard) | `freebuff` | Multi-model agent runtime | statusline | `freebuff` | L7 proxy SNI filtering | first-class preset |
| DeepSeek Harness (#10 Leaderboard) | `deepseek-harness` | Batch benchmark runner | none or statusline | `deepseek_harness` | Fair-share cgroups v2 fleet containment | first-class preset |
| Omnigent AI | `omnigent`, `omnigent-cli` | Agent runtime | statusline or full | `omnigent` | Model provider + target repo write boundary | first-class preset |
| CrewAI Multi-Agent | `crewai` | Python runtime | statusline or full | `crewai` | Model providers + CrewAI Cloud + search APIs | first-class preset |
| Microsoft AutoGen | `autogen`, `autogenstudio` | Python runtime | statusline or full | `autogen` | Model providers + AutoGen Studio local state | first-class preset |
| Custom process | any executable | unknown | statusline or none | `custom` | Default remains `off` | process contract covered |

## High-Volume Token Leaderboard Presets
The production token leaderboard (September 2026) tracks massive usage across emerging autonomous runtimes. Vetto provides native zero-config sandbox profiles (`profiles/agents/*.toml`), automatic network allowlists, dynamic package manager cache mounts (`npm`, `uv`, `bun`), and Computer Use display pass-through (sub-4ms cold start, Landlock LSM ABI 1-6, tmpfs secret masking, cgroups v2 tree extinction) for these high-throughput agents:
- **Hermes Agent** (1.7T tokens) — Autonomous tool-use loop fencer.
- **Kilo Code** (793B tokens) — Workspace containment and secret masking.
- **pi** (397B tokens) — Minimalist terminal sandbox with stdio buffer protection.
- **Command Code** (281B tokens) — Autonomous loop watchdog.
- **Freebuff** (279B tokens) — L7 TLS SNI filtering and credential masking.
- **DeepSeek Harness** (201B tokens) — Large-scale evaluation runner with cgroups memory/CPU quotas.
- **Omnigent** — Autonomous agent framework with Landlock/seccomp process sandboxing.
- **CrewAI** - Multi-agent orchestration framework with tool isolation and API egress control.
- **Microsoft AutoGen** - Multi-agent conversation and Studio runtime with containerless sandbox.


## Compatibility rules

1. The command must be executable from the policy's read scope.
2. Interactive programs use a PTY; headless programs should use `--tui=full`
   or `--tui=none`.
3. Credential variables are stripped unless a project policy explicitly opts
   into each name.
4. An agent's own sandbox is defense in depth. vetto does not detect it and
   then remove outer restrictions.
5. `doctor --check-agent` reports observed version/output only. It must not say
   “no conflicts” unless that exact version is covered by an automated test.
