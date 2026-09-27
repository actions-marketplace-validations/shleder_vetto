# verify-ng — Adversarial Security Verification

> Implementation Status (0.5.2, verified): Stage 2 correction — non-self-authorizing
> challenge-response for `Aux`-pipeline scenarios on unix: host buffers
> fresh 128-bit challenge in host-downlink pre-spawn and provides NOTHING
> PASS-capable in env; child must read challenge and return rotation
> (`challenge`+nonce, last 8 characters moved to front) to host-uplink.
> Only the exact rotated response mints `VerifiedControl` → `HOST_FACT
> control` with provenance (`ExecutionIdentity`: scenario + session nonce +
> registry + frozen). Echo/challenge/nonce/stale/duplicates are rejected.
> Oracle is pure (zero IO): provenance == current identity, otherwise INCONCLUSIVE.
> Covered: `POSITIVE/ECHO/SELF-AUTH/FORGE/REPLAY/WRONG-SCENARIO/
> WRONG-REGISTRY/DUPLICATE-001`, `TEST-HOST-EVIDENCE-REPLAY-001`,
> `CONTROL-SPLIT-001` (A behavior → PASS, B forged file → INCONCLUSIVE),
> violation-dominates (→ FAIL), blocker-ceiling (→ INCONCLUSIVE).
> Blockers on direct-exec remain INCONCLUSIVE/FAIL (containment is not
> proven, direct is not a sandbox); non-Unix — control-unobserved.
> `vetto verify-ng --lint` without spawning; CLI still does not execute
> registry-suite; backend-wired suites are next stage. Everything below
> regarding blocker PASS-verdicts describes design, not current CLI behavior.

Measurement harness on top of sandbox backends. Enforcement remains in
`src/sandbox/*`; this module only measures and reports. Not a part of
the security boundary.

## Two Axes

- `Verdict`: `PASS` / `FAIL` / `INCONCLUSIVE` / `NOT_APPLICABLE`
  (`src/verify_ng/model.rs`). Fail-closed: non-PASS in blocker category
  blocks release. `NOT_APPLICABLE` requires probe evidence of missing
  capability, otherwise blocks as `N/A-without-evidence`.
- `ClaimStrength`: `STRONG` / `PARTIAL` / `UNSUPPORTED` — static property
  of the (scenario, platform-tier) pair in the registry. There is no
  "Partial-PASS": reports carry both axes.

## Evidence Tiers

1. `HOST_FACT` — observed by trusted host after wait (post-mortem stat,
   wait-status, sweep, canary comparison, spec-hash, verified
   challenge-response). The only tier capable of supporting PASS.
   Positive control requires provenance exactly matching current
   `ExecutionIdentity`, plus correctly executed behavior (rotation of
   fresh challenge, not echo): otherwise oracle yields INCONCLUSIVE
   (echo/replay/wrong-scenario/wrong-registry are rejected).
2. `CONSTRAINED` — narrow nonce-bound signal from inside (errno class + nonce).
   Supports FAIL, never PASS alone.
3. `SELF_REPORT` — stdout markers of attack. Triage hint only.

## Nonce Binding (FM-02)

Engine generates session nonce. Negative probe and positive control must
use it; host verifies match. Discrepancy yields INCONCLUSIVE.
Traps `ORACLE-DECEIT-001` / `CONTROL-SPLIT-001` are permanent regressions.

## FrozenSpec (FM-03)

One `detect` per scenario; hash is computed once from the same `&Policy` reference
passed to `Backend::spawn`; canonical serialization (sorting, `NetMode::label`,
tier, backend-describe, argv/env/cwd, nonce, registry hash, plus `policy_bytes` —
canonical rendering of entire `Policy`, not just decomposed path lists).
Re-freeze before spawn must match (`verify_spec_continuity`).

## Spawn Contract (FM-09)

All `Backend::spawn` under `SPAWN_SERIAL` from detect to fork-return.
Blocking `wait()` in runner is forbidden; only `try_wait`-poll +
`kill_on_deadline` + deadline-aware drain (`collector::drain_with_deadline`).

## Cleanup Matrix (FM-05)

- Linux FULL — Strong (PIDns teardown).
- Windows Job — Strong (kill-on-close).
- Linux FS-ONLY / macOS — BestEffort (group-kill + sweep budget 2s);
  destructive suites only in disposable VM.

## Fixture (FM-06)

One spawn — one scenario. Payload hash before/after; mutation yields INCONCLUSIVE.
HOME is isolated per run. `env_extra` is engine-controlled.

## Redaction (FM-07)

All detail strings pass through `redact_text`: secrets → `[REDACTED]`, control bytes
stripped, `MAX_DETAIL` limit. HOME prefix masked.

## Diagnostic Env (FM-08)

`VETTO_SEATBELT_MODE`, `VETTO_NO_MAC_LIMITS`, `VETTO_CHILD_TRACE` (and
`VETTO_FORCE_TIER` outside tier-differential job) — poison: FAIL on
blockers, INCONCLUSIVE on aux. Detected before spawn.

## Gate (FM-12)

`exit::evaluate_gate`: canaries (`VFS-TRAV-001`, `ENV-LEAK-001`, `PROC-ESC-001`)
must PASS; zero INCONCLUSIVE in I1–I6; NOT_APPLICABLE only with evidence;
minimum PASS for each blocker category. Empty suite yields gate FAIL
(`GATE-VACUUM-001`).

> Iteration 2: gate minimum for `fs-write` is satisfied by scenario
> `VFS-WRITE-001` (blocker, `linux-full`/`linux-fsonly` STRONG). Without its PASS
> gate remains red under the per-category minimum rule — write vacuum
> is impossible.

## Iteration 2 Suites (Prompt 01 Coverage Map)

Linux suite (complete, fail-closed/escape/exfil priority):

- `VFS-WRITE-001` (blocker, fs-write) — STRONG on full/fs-only. Closes
  empty blocker category `fs-write` and gate-minimum rule.
- `VFS-PROC-001` (blocker, fs-read) — `/proc|/sys|/dev`/fd injections.
- `NET-EXFIL-001` (blocker, net, quorum 3) — multi-vector exfiltration:
  curl, python-socket, native TCP4/6, DNS, alt-HTTP, UDS/IPC, raw syscall.
- `SHELL-ESC-001` (blocker, spawn) — alt-shell/interpreter/PATH confusion.
- `ENV-SECRETS-001` (blocker, secrets) — env/fd/argv/SSH-Git-cloud canary.
- `PROC-TREE-001` (blocker, proc) — sibling/detached/handles escape.
- `RACE-TOCTOU-001` (blocker, spawn, quorum 3) — freeze-spawn + symlink-swap
  TOCTOU, median ≥3 runs.
- `SEC-BLOCKS-001` (blocker, spawn) — seccomp/syscall denial on native ABI
  (ptrace/process_vm/pidfd, mount/pivot, io_uring, userfaultfd, bpf/perf).
- `RES-EXHAUST-001` (high, proc) — fork/pids/IO/disk/mem; full variant
  only in disposable VM.
- `STRESS-SWEEP-001` (high, proc) — stress/race contract: median, quorum,
  sweep budgets.
- `FUZZ-CORPUS-001` (high, spawn) — fuzz corpus contract (path/env/argv/cwd/
  symlink mutations) and oracle rules without production-fuzz code.
- `TIER-DIFF-001` (high, spawn) — differential full vs fs-only vs seccomp:
  divergence strictly toward documented weaker side, no silent
  downgrade.

Windows suite (host-fact-only):

- `WIN-ESC-001` (blocker, proc) — PowerShell/cmd/API, token, integrity, Job,
  ACL; evidence strictly host-fact-only (pipe-drain stub yields not-EOF →
  INCONCLUSIVE, never PASS).
- `WIN-NET-001` (blocker, net) — `--net=off` via AppContainer capabilities
  (PARTIAL); per-domain without admin is UNPROVABLE and must fail-closed.
- `WIN-UNC-001` (high, fs-read) — PARTIAL/advisory until alias mapping.
- `WIN-WSL-001` (high, fs-read) — UNSUPPORTED baseline; any PASS is a bug.

macOS suite (MAC-SHAPE ceiling):

- `MAC-ESC-001` (high, fs-read) — Shape-A + tail-deny byte-for-byte; read outside
  tail-deny succeeds by design (confirmation of PARTIAL ceiling, not FAIL).
- `MAC-PROC-001` (high, proc) — kqueue watchdog + group-kill + sweep 2s
  (BestEffort); destructive only in VM.
- `MAC-SHAPE-001` — byte-for-byte profile gate.

Execution tiers: smoke (small quotas/seed sets, local) → core → platform
→ destructive/adversarial (disposable VM/CI-runner only) → stress/race
(median) → regression (traps) → release-gate. Without elevated privileges
only smoke/core on Strong tiers run locally; all destructive,
full RES-EXHAUST, and full fuzz corpus run on CI-runner/VM.

## Race/Stress Strategy

`RACE-TOCTOU-001` + `STRESS-SWEEP-001`: median ≥3 (in practice runs=5),
quorum of vectors per run, sweep budget 2s on BestEffort tiers, retries do
not turn FAIL into PASS, run divergence yields INCONCLUSIVE (blocks gate
in I1–I6 via zero-INCONCLUSIVE rule). Parallel spawns only via
`SPAWN_SERIAL` (detect→fork-return); preparation and judging are parallelized.

## Fuzzing Strategy

`FUZZ-CORPUS-001` establishes contract: deterministic seeds in CI, mutation
corpus for path/env/argv0/cwd/locale/symlink-forest, fail-closed oracle rule
(any violation of host-fact boundary yields FAIL/INCONCLUSIVE).
Findings must become new vectors/quorum in registry; fuzzer itself is outside
verify-ng (not production enforcement code).

## Differential Testing Strategy

`TIER-DIFF-001` + `SEC-BLOCKS-001[not_applicable]` + `WIN-*/MAC-*` N/A sections:
full vs fs-only vs seccomp must match or weaken strictly according to
documentation; `VETTO_FORCE_TIER` is permitted only in tier-differential
CI job. Cross-OS differential is handled via N/A with probe evidence, without
silent skips (otherwise `N/A-without-evidence` blocks the gate).

## Quorum and Retries (FM-13)

Multivector scenarios require ≥quorum independent agreeing vectors,
otherwise INCONCLUSIVE. Stress requires median of ≥3 runs. Retries never
turn FAIL into PASS.

## Platform Ceilings (FM-11)

- macOS `VFS-READ` — maximum PARTIAL (Shape-A + tail-deny; `MAC-SHAPE-001`
  verifies profile byte-for-byte). Strong read secrecy requires Linux VM.
- Windows per-domain egress without admin — UNPROVABLE (WFP requires elevation).
- `WIN-WSL-001` — UNSUPPORTED baseline; any PASS is an oracle bug.
- Windows evidence — host-fact-only until HANDLE-capture exists in backend
  (requires dedicated backend review, out of scope for this plan).

## Pipeline (FM-14)

`Engine` is the sole owner of `SandboxHandle`:
Engine → Killer → Collector / HostEvidence → Oracle (pure function,
zero IO) → Reporter. Oracle does not manage collection or interact with OS:
all IO resides in runner/collector/host-evidence, oracle judges ready structures.
Host-owned control (Stage 2 correction, unix): `ControlChannel` creates
downlink+uplink prior to spawn and buffers fresh challenge; env receives only
FIFO paths, zero PASS value. Bound nonces + quorum from verified response
are collected only for `Aux` pipeline scenarios. Echo verifier material
(challenge/nonce/env/stale/duplicates) and child-writable paths
(`control.txt`, HOME files, stdout, exit code) are NOT evidence.
Without verified Aux response `probe_nonce`/`control_nonce` are empty and
oracle structurally yields INCONCLUSIVE/FAIL; blockers on direct-exec are
always INCONCLUSIVE/FAIL (protocol execution is observed, containment is not).
Suite-level ownership (`SuiteRunner`, one scenario at most one execution)
is mandatory for any future backend-wired suite.

## What Still Cannot Be Proven

See Prompt-01 §20 and self-review §E: TLS payload to allowed APIs, internal
`$PROJECT` integrity, side channels, kernel zero-days, log completeness, hash
binding to a live process (continuity of ownership proven only up to fork),
sweep completeness under SIGKILL on FS-ONLY/macOS, UDS/IPC exfiltration on
macOS/Windows, CI timing statistics.

## Stage 3C — Production Integration (Verified, Proven by Tests Only)

Single production path: `src/sandbox/production.rs` (`ProductionRunner`).
Production spawns (`src/main.rs supervise`, `src/multi/runtime.rs`,
`src/mcp/wrap.rs`) execute exclusively via `spawn_authoritative` /
`execute_simple` / `execute_with_backend`; direct `Backend::spawn` outside
`production.rs` does not exist in production code. Timeout uses only verified
killer path (deadline → kill → bounded re-wait → nonce sweep), no raw
blocking `wait()` without subsequent printer-friendly sweep cleanup.
Reporting strictly uses typed `EnforcementState`, never `sandboxed/secure`.

### PROVEN IN PRODUCTION (via real production runner, Linux, net=off)

Filesystem (Landlock allowlist, deny/symlink/proc-root/dotdot/root-escape),
network off (seccomp UnixOnly, TCP connect + namespace-escape), process
(pgroup + NO_NEW_PRIVS, host-verified via /proc), tree (group-kill +
nonce sub-reaper sweep, grandchild/reaped, deadline tree-kill),
resources (RLIMIT_AS/NPROC/CPU/FSIZE, host-verified via /proc/limits),
syscalls (seccomp hardening deny ptrace), fail-closed (preparation failure
→ spawn_count==0), no-direct-bypass (backend entered exactly once),
identity (policy cwd == FrozenSpec cwd == exec_root == child cwd, nonce
is unique, env does not reintroduce secrets).

### VERIFY-NG ONLY (Harness proves, production does not claim parity)

Relay allowlist/strict/ask: production preserves existing relay architecture
(netns+broker); 3B `UnixOnly` does not pretend to be allowlist relay; through
3B boundary network is honestly `unsupported`. Full-tier namespaces/mounts/pidns
reside in existing `Backend::spawn` (not weakened); 3B provides reporting +
verification + sweep on top.

### UNSUPPORTED

macOS/Windows enforcement across 3B boundary (placeholders, all
`Unsupported`); cgroups/PID/user/mount namespaces were not added as new
3C primitives; daemon/root/containers/VM/new policy language were not introduced.
