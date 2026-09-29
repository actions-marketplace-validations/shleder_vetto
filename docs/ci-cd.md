# CI/CD Integration Guide

Vetto provides a rootless, kernel-enforced security boundary for executing AI coding agents (Claude Code, Aider, Codex, Cursor) in CI/CD pipelines. It replaces Docker-in-Docker (DinD) with direct Landlock LSM and cgroups v2 isolation.

## Comparison: Vetto vs Docker-in-Docker (DinD)

| Dimension | Docker-in-Docker (DinD) | Vetto Sandbox |
|---|---|---|
| **Cold Start Overhead** | 30–120s (image pull + daemon init) | <4ms (kernel-native Landlock LSM) |
| **Privilege Requirement** | Requires `--privileged` or root Docker socket | 100% unprivileged / rootless user namespaces |
| **Runner Caching** | Isolated filesystem; cannot share `actions/cache` | Native access to `$GITHUB_WORKSPACE` and runner toolchains |
| **Process Extinction** | Orphaned containers can leak across steps | Guaranteed tree termination via cgroups v2 (`cgroup.kill`) |
| **Security Audit** | Container exit code only (coarse-grained) | Inode-level violation logs and SARIF 2.1.0 CodeQL annotations |
| **OS Support** | Linux VM runners only | Linux (Landlock), macOS (Seatbelt SBPL), Windows (Job Objects) |

## GitHub Actions Marketplace Action

The canonical action is published on GitHub Marketplace as `shleder/vetto`. It operates in two modes: **Setup Mode** and **Execute Mode**.

### Mode 1: Execute Mode (Single-Step Runner)

Execute a sandboxed agent command, generate audit reports, and optionally upload findings to GitHub Code Scanning:

```yaml
name: Agent Security Gate
on: [pull_request]

permissions:
  contents: read
  security-events: write # Required when upload-sarif is true

jobs:
  agent-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Aider in Sandbox
        uses: shleder/vetto@v0.5.11
        with:
          command: 'aider --yes-always --no-git --message "Review PR changes"'
          agent: 'aider'
          profile: 'strict'
          fail-on-block: '1'
          upload-sarif: 'true'
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

### Mode 2: Setup Mode (Multi-Step Workflows)

When `command` is omitted, the action verifies and installs the standalone `vetto` binary into `$GITHUB_PATH`:

```yaml
      - name: Setup Vetto Sandbox
        uses: shleder/vetto@v0.5.11
        with:
          version: 'latest'

      - name: Run Sandboxed Commands
        run: |
          vetto doctor --preflight
          vetto run -- aider --message "Refactor parser error handling"
```

## Binary Integrity & Verification

The action downloads official pre-compiled release binaries from GitHub Releases and cryptographically verifies the SHA-256 hash against the release `.sha256` sidecar file before extraction. Unverified binaries are rejected fail-closed.

## Action Inputs Reference

| Input | Type | Default | Description |
|---|---|---|---|
| `command` | String | `""` | Agent command to execute. If omitted, runs in Setup Mode. |
| `agent` | String | `""` | Agent preset (`aider`, `claude`, `codex`, `cursor`, `opencode`). Auto-configures profile and network allowlists. |
| `version` | String | `'latest'` | Target Vetto release version (e.g. `'0.5.11'` or `'latest'`). |
| `profile` | String | `'strict'` | Built-in policy profile: `strict`, `default`, `permissive`, `audit`. |
| `net` | String | `""` | Network mode: `off`, `allowlist:<domains>`, `strict:<domains>`. If omitted with `agent`, auto-resolves provider domains. Defaults to `off` if neither is specified. |
| `policy` | String | `""` | Path to custom TOML policy file. |
| `report` | String | `'json,sarif'` | Comma-separated report formats: `json`, `sarif`, `md`, `html`. |
| `report-dir` | String | `'.vetto/reports'` | Output directory for audit and security reports. |
| `fail-on-block` | String | `'false'` | Fail step if blocked attempts occur. `'true'` or integer threshold (e.g. `'1'`). |
| `upload-sarif` | String | `'false'` | Upload SARIF report to GitHub Code Scanning via `github/codeql-action/upload-sarif@v3`. |
| `telemetry` | String | `'false'` | Opt-in anonymous telemetry. |
| `github-token` | String | `""` | GitHub token for authenticated release resolution when rate-limited. |

## Action Outputs

| Output | Description |
|---|---|
| `vetto-version` | Installed Vetto version string (e.g. `0.5.11`). |
| `vetto-path` | Absolute path to the installed executable. |
| `exit-code` | Process return code from the sandboxed agent command. |
| `sarif-path` | Absolute path to the generated SARIF report file. |

## Audit Engine & Exit Codes

Vetto enforces deterministic exit codes:
- **`0`**: Command succeeded and zero policy violations were triggered.
- **`124`**: Command execution timed out.
- **`125` (`EXIT_FAIL_CLOSED`)**: Contract violation or security boundary breach (unauthorized filesystem write, secret traversal to `~/.ssh` or `.env`, or denied network egress).
- Non-zero status codes from the target agent process are preserved when no sandbox violation occurs.

## Code Scanning Annotations (SARIF 2.1.0)

When `upload-sarif: 'true'` is configured:
1. Vetto compiles blocked filesystem and network events into a standard SARIF 2.1.0 artifact in `report-dir`.
2. The SARIF payload includes exact violation categories:
   - `vetto.blocked-attempt`: Filesystem access blocked by Landlock LSM.
   - `vetto.network-denied`: Outbound socket connection rejected by network broker.
   - `vetto.suspicious-signal`: Suspicious system access heuristic.
3. GitHub Actions renders inline annotations on the Pull Request "Files Changed" tab pointing to the specific paths the agent attempted to access.

## Non-GitHub CI Systems (GitLab, Jenkins, CircleCI)

The standalone CLI operates identically in other CI runners:

```bash
vetto --ci --profile=strict --net=allowlist:api.anthropic.com \
  --report=json,sarif --report-dir=.vetto/reports \
  --fail-on-block=1 -- aider --message "Run tests"
```

Collect `.vetto/reports/*.sarif` as a job artifact and feed it into the platform's security dashboard.
