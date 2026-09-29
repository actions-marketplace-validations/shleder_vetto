# Tutorial: Securing AI Agents in GitHub Actions CI

This tutorial demonstrates how to run AI coding agents (such as Aider CLI or Claude Code) inside GitHub Actions with kernel-level isolation, zero root privileges, and automatic security annotations.

Estimated completion time: 10 minutes.

---

## 1. Prerequisites

- A GitHub repository with GitHub Actions enabled.
- API credentials for your chosen model provider (e.g. `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`) stored in **Repository Secrets** (`Settings -> Secrets and variables -> Actions`).
- GitHub Code Scanning permissions enabled for PR annotations (`permissions: security-events: write`).

---

## 2. Basic Setup: Running Aider in a Sandbox

Create `.github/workflows/agent-gate.yml` in your repository:

```yaml
name: Agent Review Gate

on:
  pull_request:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: 'pip'

      - name: Install Aider
        run: pip install --upgrade aider-chat

      - name: Run Aider under Vetto Sandbox
        uses: shleder/vetto@v0.5.11
        with:
          command: 'aider --yes-always --no-git --message "Review diff for obvious bugs"'
          agent: 'aider'
          profile: 'strict'
          fail-on-block: '1'
          upload-sarif: 'true'
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

### What Happens During Execution

1. **Binary Verification**: `shleder/vetto` downloads the pre-compiled native binary for Linux x86_64, fetches the `.sha256` sidecar, and verifies the cryptographic digest before unpacking.
2. **Preset Allowlisting**: The `agent: 'aider'` preset configures outbound network access specifically for known model providers (`api.anthropic.com`, `api.openai.com`, `openrouter.ai`) while blocking raw internet access.
3. **Filesystem Masking**: Inodes corresponding to `~/.ssh`, `~/.aws`, `.env`, and git configuration files are masked. Workspace files are granted read-write access.
4. **Kernel Enforcement**: Landlock LSM restricts unauthorized filesystem traversal. Any attempt to write outside the workspace or read host credentials returns `EACCES`/`EPERM`.

---

## 3. Testing Fail-Closed Security (Simulating an Attack)

To verify that the security boundary actively blocks unauthorized actions, test a command that attempts to exfiltrate host credentials:

```yaml
      - name: Malicious Agent Simulation
        id: attack_test
        uses: shleder/vetto@v0.5.11
        continue-on-error: true
        with:
          command: 'cat ~/.ssh/id_rsa || cat /etc/shadow'
          profile: 'strict'
          fail-on-block: '1'
          upload-sarif: 'true'

      - name: Verify Failure Verdict
        run: |
          echo "Exit code: ${{ steps.attack_test.outputs.exit-code }}"
          if [ "${{ steps.attack_test.outputs.exit-code }}" != "125" ]; then
            echo "Expected exit code 125 (fail-closed), got ${{ steps.attack_test.outputs.exit-code }}"
            exit 1
          fi
          echo "Attack was blocked fail-closed with code 125."
```

### Expected Behavior

- Landlock LSM traps the read attempt immediately.
- Vetto records a `vetto.blocked-attempt` event in the audit trail.
- The process terminates with exit code `125` (`EXIT_FAIL_CLOSED`), blocking the pull request merge.
- The SARIF generator exports the violation with URI details to `.vetto/reports/`.

---

## 4. Reviewing Findings in GitHub Code Scanning

When `upload-sarif: 'true'` is active:
1. Open the **Security** tab of your repository on GitHub.
2. Select **Code scanning alerts**.
3. Filter by tool `vetto`.
4. Each blocked event appears as an alert indicating:
   - Rule ID: `vetto.blocked-attempt` or `vetto.network-denied`.
   - File path or destination host targeted.
   - Calling process name and invocation timestamp.
   - Severity level (`error` for filesystem blocks, `warning` for heuristics).

---

## 5. Multi-Step Workflows (Setup Mode)

If you require multiple sandbox commands within a single job, use Setup Mode:

```yaml
      - name: Setup Vetto
        uses: shleder/vetto@v0.5.11
        with:
          version: 'latest'

      - name: Run Diagnostics
        run: vetto doctor --preflight

      - name: Run Hermetic Unit Tests
        run: |
          vetto --net=off --profile=strict -- \
            pytest tests/unit
```

---

## 6. Security Invariants & Best Practices

1. **Prompt Sanitization**: Treat pull request text and user comments as untrusted data. Never interpolate `${{ github.event.comment.body }}` directly into shell command strings without escaping.
2. **Secret Masking**: Store API tokens in GitHub Secrets and pass them via the job step's `env:` block. Vetto masks secrets from process environments that do not require them.
3. **Deterministic Fail-Closed**: Always set `fail-on-block: '1'` in PR validation gates to ensure malicious code modifications prevent merging automatically.
