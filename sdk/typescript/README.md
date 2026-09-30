# @vetto/sdk

Official TypeScript and Node.js SDK for the Vetto sandbox runtime.

Vetto injects rootless kernel security boundaries between `fork()` and `execve()` using Linux Landlock LSM (ABI 1–6), mount/PID/network namespaces, and seccomp-BPF filters with sub-4ms cold-start latency.

## Installation

```bash
npm install @vetto/sdk
```

Requires `vetto` binary installed on the host system:
```bash
npm install -g @shledery/vetto
# or
cargo install vetto
```

## Quickstart

```typescript
import { VettoSandbox, VettoSecurityError, VettoTimeoutError } from "@vetto/sdk";

// Initialize sandbox with configured boundaries
const sandbox = new VettoSandbox({
  profile: "default",
  allowWrite: ["./workspace"],
  allowRead: ["/usr", "/lib"],
  net: "off",
  timeoutSeconds: 30,
});

// Run commands asynchronously
const result = await sandbox.run(["node", "-e", "console.log('sandboxed!')"]);
console.log(result.exitCode);   // 0
console.log(result.stdout);     // sandboxed!
console.log(result.durationMs);

// Enforce strict fail-closed Exit 125 error handling
try {
  await sandbox.run(["rm", "-rf", "/etc/hosts"], { raiseOnError: true });
} catch (err) {
  if (err instanceof VettoSecurityError) {
    console.error(`Blocked by kernel policy (Exit 125): ${err.result.stderr}`);
  }
}
```

## Exit Code Semantics

The SDK strictly enforces Vetto kernel-level exit codes:

| Exit Code | Meaning | Result Field | Thrown Exception |
|-----------|---------|--------------|------------------|
| `0` | Success | `result.success === true` | None |
| `124` | Wall-clock execution timeout | `result.timedOut === true` | `VettoTimeoutError` |
| `125` | Fail-closed security boundary breach | `result.violated === true` | `VettoSecurityError` |
| `1..123` | Child process failure | `result.exitCode > 0` | Generic `Error` |

## Synchronous Execution

```typescript
const result = sandbox.runSync(["python3", "-c", "print(1 + 1)"]);
console.log(result.stdout.trim()); // 2
```

## API Reference

### `new VettoSandbox(options?: VettoSandboxOptions)`
- `profile`: Built-in profile (`default`, `strict`, `audit`, `permissive`). Default: `default`.
- `allowWrite`: Array of paths granted write permission.
- `allowRead`: Array of paths granted read permission.
- `net`: Network egress mode (`off`, `allowlist`, `host`). Default: `off`.
- `allowedDomains`: Domain allowlist when `net: "allowlist"`.
- `timeoutSeconds`: Hard execution timeout in seconds. Default: `120`.
- `envPass`: Pass-through environment variable names.
- `memoryLimit`: Memory quota (e.g. `"512MB"`, `"2GB"`).
- `workingDir`: Workspace directory for execution.
- `binaryPath`: Explicit path to `vetto` binary.
- `policyPath`: Explicit path to external `policy.toml`.
- `allowFallback`: Fall back to uncontained execution if binary is missing. Default: `false`.
- `failOnBlock`: Fail with exit 125 on policy blocks. Default: `true`.
