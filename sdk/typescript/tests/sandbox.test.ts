import assert from "node:assert";
import test, { describe, it } from "node:test";
import * as path from "node:path";
import {
  VettoSandbox,
  VettoNotFoundError,
  VettoSecurityError,
  VettoTimeoutError,
  type VettoExecutionResult,
} from "../src/index.ts";


describe("VettoSandbox TypeScript SDK", () => {
  const dummyBin = "/mock/bin/vetto";

  it("should build command arguments correctly", () => {
    const sandbox = new VettoSandbox({
      binaryPath: dummyBin,
      profile: "strict",
      allowWrite: ["/tmp/build"],
      allowRead: ["/opt/lib"],
      net: "allowlist",
      allowedDomains: ["api.anthropic.com", "registry.npmjs.org"],
      timeoutSeconds: 60,
      memoryLimit: "2GB",
      policyPath: "/etc/vetto/policy.toml",
      failOnBlock: true,
      tui: "none",
    });

    // Mock binary resolution
    sandbox.resolveBinary = () => dummyBin;

    const cmd = sandbox.buildCommand(["npm", "test"], { cwd: "/workspace" });

    assert.strictEqual(cmd[0], dummyBin);
    assert.strictEqual(cmd[1], "run");
    assert.ok(cmd.includes("--profile"));
    assert.strictEqual(cmd[cmd.indexOf("--profile") + 1], "strict");
    assert.ok(cmd.includes("--policy"));
    assert.strictEqual(cmd[cmd.indexOf("--policy") + 1], "/etc/vetto/policy.toml");
    assert.ok(cmd.includes("--net"));
    assert.strictEqual(
      cmd[cmd.indexOf("--net") + 1],
      "allowlist:api.anthropic.com,registry.npmjs.org"
    );
    assert.ok(cmd.includes("--timeout"));
    assert.strictEqual(cmd[cmd.indexOf("--timeout") + 1], "60s");
    assert.ok(cmd.includes("--limits"));
    assert.strictEqual(cmd[cmd.indexOf("--limits") + 1], "as=2GB");
    assert.ok(cmd.includes("--fail-on-block"));
    assert.ok(cmd.includes("--tui"));
    assert.strictEqual(cmd[cmd.indexOf("--tui") + 1], "none");
    assert.ok(cmd.includes("--"));
    const dashIdx = cmd.indexOf("--");
    assert.deepStrictEqual(cmd.slice(dashIdx + 1), ["npm", "test"]);
  });

  it("should fail when binary is missing and fallback is disabled", () => {
    const sandbox = new VettoSandbox({ allowFallback: false });
    sandbox.resolveBinary = () => null;

    assert.throws(
      () => sandbox.buildCommand(["ls"]),
      (err: any) => err instanceof VettoNotFoundError
    );
  });

  it("should return raw command when binary is missing and fallback is enabled", () => {
    const sandbox = new VettoSandbox({ allowFallback: true });
    sandbox.resolveBinary = () => null;

    const cmd = sandbox.buildCommand(["echo", "hello"]);
    assert.deepStrictEqual(cmd, ["echo", "hello"]);
  });

  it("should execute synchronous command with fallback", () => {
    const sandbox = new VettoSandbox({ allowFallback: true });
    sandbox.resolveBinary = () => null;

    const result = sandbox.runSync(["node", "-e", "process.stdout.write('hello-sync')"]);
    assert.strictEqual(result.exitCode, 0);
    assert.strictEqual(result.stdout, "hello-sync");
    assert.strictEqual(result.success, true);
    assert.strictEqual(result.violated, false);
    assert.strictEqual(result.timedOut, false);
    assert.ok(result.durationMs >= 0);
  });

  it("should execute asynchronous command with fallback", async () => {
    const sandbox = new VettoSandbox({ allowFallback: true });
    sandbox.resolveBinary = () => null;

    const result = await sandbox.run(["node", "-e", "process.stdout.write('hello-async')"]);
    assert.strictEqual(result.exitCode, 0);
    assert.strictEqual(result.stdout, "hello-async");
    assert.strictEqual(result.success, true);
    assert.strictEqual(result.violated, false);
    assert.strictEqual(result.timedOut, false);
    assert.ok(result.durationMs >= 0);
  });

  it("should handle Exit 125 fail-closed semantics", () => {
    const sandbox = new VettoSandbox({ allowFallback: true });
    sandbox.resolveBinary = () => null;

    // Simulate Exit 125 exit code
    const result = sandbox.runSync(["node", "-e", "process.exit(125)"]);
    assert.strictEqual(result.exitCode, 125);
    assert.strictEqual(result.violated, true);
    assert.strictEqual(result.success, false);

    assert.throws(
      () => sandbox.runSync(["node", "-e", "process.exit(125)"], { raiseOnError: true }),
      (err: any) => {
        assert.ok(err instanceof VettoSecurityError);
        assert.strictEqual(err.result.exitCode, 125);
        assert.strictEqual(err.result.violated, true);
        return true;
      }
    );
  });

  it("should handle Exit 124 timeout semantics", () => {
    const sandbox = new VettoSandbox({ allowFallback: true });
    sandbox.resolveBinary = () => null;

    const result = sandbox.runSync(["node", "-e", "process.exit(124)"]);
    assert.strictEqual(result.exitCode, 124);
    assert.strictEqual(result.timedOut, true);
    assert.strictEqual(result.success, false);

    assert.throws(
      () => sandbox.runSync(["node", "-e", "process.exit(124)"], { raiseOnError: true }),
      (err: any) => {
        assert.ok(err instanceof VettoTimeoutError);
        assert.strictEqual(err.result.exitCode, 124);
        assert.strictEqual(err.result.timedOut, true);
        return true;
      }
    );
  });

  it("should handle async timeout correctly", async () => {
    const sandbox = new VettoSandbox({ allowFallback: true });
    sandbox.resolveBinary = () => null;

    // Command that sleeps for 2 seconds with 0.1s timeout
    const result = await sandbox.run(
      ["node", "-e", "setTimeout(() => {}, 2000)"],
      { timeoutSeconds: 0.1 }
    );

    assert.strictEqual(result.exitCode, 124);
    assert.strictEqual(result.timedOut, true);
    assert.strictEqual(result.success, false);
  });
});
