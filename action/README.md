# Vetto GitHub Action (`vetto-action`)

Run untrusted AI agent commands and build pipelines inside the **Vetto daemon-less sandbox** directly in your GitHub Actions workflows.

Vetto provides a standard, 10-50x faster, zero-Docker replacement for Docker-in-Docker (DinD) in CI agent pipelines:
- **Sub-4ms Cold Start**: Injects security boundaries directly between `fork()` and `execve()`, eliminating the 30-120 second image pull and container boot overhead typical of Docker-in-Docker.
- **Zero Daemon Overhead**: Fully rootless, unprivileged kernel sandboxing via Landlock LSM (ABI 1-6) and cgroups v2. Requires no `dockerd` daemon, no root privileges, and no `--privileged` container flags that compromise the runner host.
- **Preserves Runner Toolchains & Caches**: Runs directly against host compilers, runtimes, and local package caches (`actions/cache`, `npm`, `pip`, `cargo`), avoiding custom container image rebuilds.
- **Deterministic Extinction**: Terminates runaway agent subprocesses, daemons, and fork bombs synchronously via cgroups v2 `cgroup.kill` on job exit or timeout.
- **Cross-Platform Parity**: Runs natively across `ubuntu-latest` (Landlock LSM), `macos-latest` (Seatbelt SBPL), and `windows-latest` (Job Objects).

---

## Action Flavors

1. **`shleder/vetto/action@v0.5.14`** (`vetto-action`): Composite execution action that wraps a single agent command, produces audit logs, and uploads SARIF security reports.
2. **`shleder/vetto@v0.5.14`** (`Setup Vetto`): Root action that installs the standalone `vetto` CLI binary onto the runner and configures `$GITHUB_PATH` for multi-step workflows.

---

## Usage Examples

### 1. Basic Agent Execution (`vetto-action`)

```yaml
name: Agent Task
on: [push, pull_request]

jobs:
  agent-run:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4

      - name: Run Sandboxed Agent
        uses: shleder/vetto/action@v0.5.14
        with:
          command: 'npx claude-code -p "Run linter and fix basic formatting"'
```

---

### 2. Custom Policy & Network Allowlist

```yaml
      - name: Run Python Agent with PyPI Egress
        uses: shleder/vetto/action@v0.5.14
        with:
          policy: 'policies/community/python-dev.toml'
          net: 'allowlist:pypi.org,files.pythonhosted.org,github.com'
          command: 'pytest tests/'
```

---

### 3. Fail-On-Block Security Gate + CodeQL SARIF Upload

When enabling `upload-sarif: 'true'`, the job must declare `permissions: security-events: write` so GitHub Code Scanning accepts the SARIF upload:

```yaml
name: Agent Audit Gate
on: [pull_request]

jobs:
  audit-gate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write # Required for upload-sarif
    steps:
      - uses: actions/checkout@v4

      - name: Strict Security Verification
        uses: shleder/vetto/action@v0.5.14
        with:
          profile: 'strict'
          fail-on-block: '1' # Fails CI if agent attempts to read secrets or escape sandbox
          upload-sarif: 'true'
          command: 'make test'
```

---

### 4. Setup Vetto CLI for Multi-Step Workflows

```yaml
      - name: Setup Vetto
        uses: shleder/vetto@v0.5.14
        with:
          version: 'latest'

      - name: Execute with Vetto
        run: |
          vetto doctor --preflight
          vetto run -- aider --message "Refactor parser"
```

---

## Action Inputs (`vetto-action`)

| Input | Description | Default | Required |
|---|---|---|---|
| `command` | Agent or shell command to execute in sandbox (if omitted, runs in setup-only mode) | `""` | No |
| `policy` | Path to custom policy TOML or community policy | `""` | No |
| `net` | Network mode (`off`, `allowlist:...`, `strict:...`) | `off` | No |
| `profile` | Built-in profile (`strict`, `default`, `audit`, `permissive`) | `strict` | No |
| `report` | Report formats (`json,sarif`, `html`, `md`) | `json,sarif` | No |
| `report-dir` | Directory for audit reports | `.vetto/reports` | No |
| `version` | Vetto release version or `latest` | `latest` | No |
| `fail-on-block` | Gate CI on blocked security events (`true`, `false`, `N`) | `false` | No |
| `upload-sarif` | Upload generated SARIF report to GitHub Code Scanning (requires `permissions: security-events: write`) | `false` | No |

## Action Outputs (`vetto-action`)

| Output | Description |
|---|---|
| `vetto-version` | Installed Vetto version |
| `vetto-path` | Path to the installed vetto binary |
| `exit-code` | Exit code of the sandboxed command (when command is provided) |
| `sarif-path` | Path to the generated SARIF report file (when command is provided) |
