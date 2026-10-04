# Agent compatibility registry

Vetto bundles pre-configured profiles in `profiles/agents/` that define network allowlists, filesystem paths, and cache directories for common coding agents. The sandbox enforces these policies automatically when an agent is invoked through `vetto run` or its transparent shim in `~/.vetto/shims`.

## Supported agent profiles

| Agent | Binary / Preset | Network endpoints | Protected configs and caches |
| :--- | :--- | :--- | :--- |
| **Claude Code** | `claude` | `api.anthropic.com`, `claude.ai` | `~/.claude`, `~/.config/claude`, plugins |
| **OpenAI Codex** | `codex` | `api.openai.com`, ChatGPT OAuth | `~/.codex`, `~/.config/codex`, plugins |
| **OpenCode** | `opencode` | Configured provider endpoints | `~/.local/share/opencode`, `~/.config/opencode` |
| **Antigravity** | `agy`, `antigravity` | Google APIs, Google CDN | `~/.gemini/antigravity`, plugins, skills |
| **OMP** | `omp` | `omp.sh`, Anthropic, OpenAI, Google, OpenRouter | `~/.config/omp`, `~/.omp` |
| **ZCode** | `zcode` | `z.ai`, `api.z.ai`, `glm.z.ai`, OpenAI | `~/.zcode`, `~/.config/zcode` |
| **Kimi Code** | `kimi` | `code.kimi.com`, `api.moonshot.cn`, `api.moonshot.ai` | `~/.kimi`, `~/.config/kimi` |
| **Grok Build** | `grok` | `x.ai`, `api.x.ai`, `grok.com` | `~/.grok`, `~/.config/grok` |
| **Cursor** | `cursor` | Cursor backend, extension marketplace | VS Code IPC sockets, `~/.cursor` |
| **Aider** | `aider` | Configured LLM provider endpoints | Git repository root, history caches |
| **Cline** | `cline` | `api.cline.bot`, `data.cline.bot` | VS Code extension host, browser caches |
| **Windsurf** | `windsurf` | `api.codeium.com`, `windsurf.codeium.com` | `~/.windsurf`, Cascade state |
| **Goose** | `goose` | Block API, Anthropic, Databricks | `~/.config/goose`, extensions |
| **OpenHands** | `openhands` | Configured model endpoints | Local execution directories |
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
| **CrewAI** | `crewai` | `app.crewai.com`, `telemetry.crewai.com`, LLM endpoints | `~/.crewai`, `~/.config/crewai` |
| **Microsoft AutoGen** | `autogen` | Model endpoints for OpenAI, Anthropic, Gemini | `~/.autogen`, `~/.config/autogen` |
| **Sourcegraph Amp** | `amp` | `ampcode.com`, `sourcegraph.com`, Anthropic, OpenAI | `~/.config/amp`, `~/.local/share/amp` |

## Integration rules

1. The target agent command must be executable from the policy read scope.
2. Interactive agents preserve standard terminal PTY access. Non-interactive or batch commands can disable the UI with `--tui=none`.
3. Secret host variables (such as AWS and SSH credentials) are stripped unless explicitly allowed in project policy.
4. An agent's built-in sandbox acts as defense in depth. Vetto enforces its own kernel boundaries independently.
5. The command `vetto doctor --check-agent <name>` probes the agent binary with a bounded `--version` check to verify invocation.
