# Vetto field testing

This checklist is for testing a published Vetto npm package on a real local
machine. It is intentionally npm-only: testers do not need Rust, a checkout of
the repository, or a build from `main`.

The supported npm package name is the scoped package
`@shledery/vetto`. The unscoped `vetto` name is not the installation path.

## Install one published build

Use the `latest` tag for the current stable release and record the exact version printed by
the first command. Do not paste an npm token into an issue and do not install
from a Git URL.

```console
npm install --global @shledery/vetto
vetto --version
vetto doctor --preflight
```

The package contains the native executable for the host platform in the current `0.5.15` package.
It does not need a Rust toolchain or an install-time binary download. If npm reports an
unsupported platform, record the platform and architecture and stop; do not
work around the package selector by copying a binary from another platform.

For a repeatable test, pin the version shown by `vetto --version` in the issue
and reinstall that exact version when reproducing. The `latest` tag can move
between releases.

## What is supported

Support is a claim about the tested surface, not about the vendor application
as a whole:

| Surface | Current claim | Safe test path |
| --- | --- | --- |
| Codex CLI | `protected` when launched through Vetto | Wrap `codex` with `vetto enable codex` or `vetto -- codex exec ...` |
| Claude Code CLI | `protected` when launched through Vetto | Wrap `claude` with `vetto enable claude` or `vetto -- claude ...` |
| Aider, OpenCode, Cursor, or another CLI | `protected` for processes launched by Vetto | Use transparent shims (`vetto enable <agent>`) or `vetto -- <command> [args...]` |
| Codex/Claude/Cursor/Antigravity desktop GUI | `observe-only` or `unavailable` | Vetto intercepts child processes and CLI tools, not pre-existing external GUI windows |

`integrated` is not a blanket claim for a provider. An unavailable
desktop integration is an honest result, not a failed workaround to hide.

## Baseline commands

Run these from a disposable project directory. The commands only launch a
process through Vetto or inspect state read-only:

```console
vetto doctor
vetto doctor --preflight
vetto doctor --probe

# Codex CLI, headless smoke test
vetto --profile strict --net off --tui none -- codex exec "print one short test line"

# Claude Code CLI, headless smoke test
vetto --profile strict --net off --tui none -- claude -p "print one short test line"
```

Use the same wrapper for another local CLI, for example:

```console
vetto --profile strict --net off --tui none -- aider --version
```

If the agent needs network access for a test, state the exact allowlist in the
issue. Keep the default `--net off` for the first run. Never pass a secret
through the environment just to make a smoke test pass; Vetto rebuilds the
child environment from an allowlist.

On Windows PowerShell, the same commands work. A desktop application that has
no CLI cannot be wrapped by typing its name into this command: an already
running GUI process is outside this support claim.

## Transparent shim testing

Verify that transparent shims intercept commands without breaking terminal workflows:

```console
# Enable wrapping for target agent
vetto enable claude
vetto status

# Verify the shim resolves first in PATH
which claude

# Run agent normally
claude --version

# Restore unconfined execution
vetto disable claude
```

## Workspace snapshot and diff verification

Test copy-on-write snapshot and rollback capabilities:

```console
# Inspect changes made by the sandboxed agent
vetto diff

# Revert workspace to pre-session state
vetto undo
```

## Audit and failure verification

Inspect audit events and verify fail-closed enforcement:

```console
# Inspect the most recent session events and violations
vetto audit --latest

# Verify fail-closed exit code 125 on unauthorized access
vetto --profile strict --net off --tui none -- cat ~/.ssh/id_rsa
# Expect exit code 125 (EXIT_FAIL_CLOSED)
```

## Report a result safely

Open the closest issue form:

- **Compatibility test** for a protected CLI launch or environment test;
- **Sanitized diagnostic report** for a cross-cutting doctor, environment, or
  support-level result.

Include only the following, after review:

- Vetto version from `vetto --version` and the agent name/version;
- OS family, OS version, architecture, and whether the run was native or WSL;
- the exact command with project names, usernames, hostnames, and secrets
  replaced by placeholders;
- expected result, actual result, exit code, and a short reproduction;
- sanitized `vetto doctor` output and, when relevant, sanitized `--json` output;
- the selected support level (`protected`, `observe-only`, or `unsupported`).

The sanitizer is best-effort, not a guarantee. Inspect every line before
posting. In particular, replace paths even when they look harmless:

```text
C:\Users\alice\project        -> <PROJECT>
/home/alice/.codex             -> <CODEX_HOME>
https://api.example.test/key   -> <URL>
```

Never attach or paste any of the following:

- raw agent internal databases or copied state directories;
- `auth.json`, `config.toml`, `.env`, shell history, SSH keys, certificates,
  cookies, access tokens, API keys, npm credentials, or cloud credentials;
- prompts, tool arguments, repository source, diffs, private project names, or
  unreviewed home-directory paths;
- a full environment dump, a full command transcript, or an unredacted report;
- a security vulnerability proof-of-concept in a public issue.

If a report may expose a vulnerability or a bypass, stop and use the private
security reporting link in the repository instead of a public issue. Do not
publish a working exploit while asking for a compatibility review.

## Triage expectations

One issue should describe one host, one Vetto version, one agent version, and
one primary failure. Separate unrelated platform results. A result from a
desktop GUI is not evidence that the corresponding CLI is broken.

Maintainers may request a synthetic fixture or a second run with explicit
flags. They should never request raw vendor state or credentials. A missing
capability, a moving session, and an unsupported desktop surface are valid
bounded outcomes and should remain visible in the report.

## Release gate

The release line advances only after the scoped change has a green cross-platform
CI run, focused regression coverage, and a documented limitation. Field tests
can provide evidence, but they do not turn an unverified provider or desktop
integration into a support claim.
