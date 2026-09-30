import * as childProcess from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

/**
 * Configuration options for initializing a VettoSandbox instance.
 */
export interface VettoSandboxOptions {
  /** Built-in policy profile name (default: 'default', 'strict', 'audit', 'permissive'). */
  profile?: string;
  /** Filesystem paths permitted for write access. */
  allowWrite?: string[];
  /** Filesystem paths permitted for read-only access. */
  allowRead?: string[];
  /** Network egress mode ('off', 'allowlist', 'host'). Default: 'off'. */
  net?: "off" | "allowlist" | "host" | "strict" | string;
  /** Permitted domain names when net is 'allowlist'. */
  allowedDomains?: string[];
  /** Hard execution wall-clock timeout in seconds. Default: 120. */
  timeoutSeconds?: number;
  /** Environment variable names permitted through the boundary. */
  envPass?: string[];
  /** Optional cgroup memory limit string (e.g. '512MB', '1GB'). */
  memoryLimit?: string;
  /** Default working directory for sandboxed command execution. */
  workingDir?: string;
  /** Explicit path to the vetto binary. Auto-located if not specified. */
  binaryPath?: string;
  /** Explicit path to an external policy.toml file. */
  policyPath?: string;
  /** Fall back to uncontained execution if the vetto binary is not found. Default: false. */
  allowFallback?: boolean;
  /** Terminal UI mode (default: 'none' for API/SDK usage). */
  tui?: "none" | "statusline" | "full" | string;
  /** Exit with code 125 (fail-closed) on blocked operations. Default: true. */
  failOnBlock?: boolean;
}

/**
 * Per-execution options overriding sandbox defaults.
 */
export interface VettoRunOptions {
  /** Working directory override for this execution. */
  cwd?: string;
  /** Custom environment variables to expose. */
  env?: Record<string, string>;
  /** Timeout in seconds override for this execution. */
  timeoutSeconds?: number;
  /** Additional paths permitted for write access. */
  extraAllowWrite?: string[];
  /** Additional paths permitted for read-only access. */
  extraAllowRead?: string[];
  /** If true, throws VettoSecurityError or VettoTimeoutError on failure. */
  raiseOnError?: boolean;
  /** Optional stdin data piped to the process. */
  stdin?: string | Buffer;
}

/**
 * Typed result returned after sandboxed process execution.
 */
export interface VettoExecutionResult {
  /** Numeric exit status code (0 = success, 124 = timeout, 125 = security violation). */
  exitCode: number;
  /** Captured stdout stream. */
  stdout: string;
  /** Captured stderr stream. */
  stderr: string;
  /** Total wall-clock duration in milliseconds. */
  durationMs: number;
  /** True if the operation was blocked by a kernel security boundary (Exit 125). */
  violated: boolean;
  /** True if execution exceeded the timeout deadline (Exit 124). */
  timedOut: boolean;
  /** True if the process completed with exit code 0. */
  success: boolean;
  /** Full argument vector executed. */
  command: string[];
}

/** Base exception for all Vetto SDK errors. */
export class VettoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VettoError";
  }
}

/** Thrown when the vetto binary cannot be located on the host. */
export class VettoNotFoundError extends VettoError {
  constructor(message?: string) {
    super(
      message ||
        "Vetto binary not found. Install via 'npm install -g @shledery/vetto' " +
          "or 'cargo install vetto', set VETTO_PATH, or configure allowFallback: true."
    );
    this.name = "VettoNotFoundError";
  }
}

/** Thrown when an execution violates sandbox boundaries (Exit 125 fail-closed). */
export class VettoSecurityError extends VettoError {
  public readonly result: VettoExecutionResult;

  constructor(message: string, result: VettoExecutionResult) {
    super(message);
    this.name = "VettoSecurityError";
    this.result = result;
  }
}

/** Thrown when execution exceeds the configured wall-clock timeout (Exit 124). */
export class VettoTimeoutError extends VettoError {
  public readonly result: VettoExecutionResult;

  constructor(message: string, result: VettoExecutionResult) {
    super(message);
    this.name = "VettoTimeoutError";
    this.result = result;
  }
}

/**
 * Vetto programmatic sandbox wrapper.
 */
export class VettoSandbox {
  public readonly profile: string;
  public readonly allowWrite: string[];
  public readonly allowRead: string[];
  public readonly net: string;
  public readonly allowedDomains: string[];
  public readonly timeoutSeconds: number;
  public readonly envPass: string[];
  public readonly memoryLimit?: string;
  public readonly workingDir?: string;
  public readonly binaryPath?: string;
  public readonly policyPath?: string;
  public readonly allowFallback: boolean;
  public readonly tui: string;
  public readonly failOnBlock: boolean;

  constructor(options: VettoSandboxOptions = {}) {
    this.profile = options.profile ?? "default";
    this.allowWrite = (options.allowWrite || []).map((p) => path.resolve(p));
    this.allowRead = (options.allowRead || []).map((p) => path.resolve(p));
    this.net = options.net ?? "off";
    this.allowedDomains = options.allowedDomains ? [...options.allowedDomains] : [];
    this.timeoutSeconds = options.timeoutSeconds ?? 120;
    this.envPass = options.envPass ? [...options.envPass] : [];
    this.memoryLimit = options.memoryLimit;
    this.workingDir = options.workingDir ? path.resolve(options.workingDir) : undefined;
    this.binaryPath = options.binaryPath ? path.resolve(options.binaryPath) : undefined;
    this.policyPath = options.policyPath ? path.resolve(options.policyPath) : undefined;
    this.allowFallback = options.allowFallback ?? false;
    this.tui = options.tui ?? "none";
    this.failOnBlock = options.failOnBlock ?? true;
  }

  /**
   * Resolve the path to the vetto binary on the host machine.
   */
  public resolveBinary(): string | null {
    if (this.binaryPath) {
      try {
        fs.accessSync(this.binaryPath, fs.constants.X_OK);
        return this.binaryPath;
      } catch {
        // Fall through to other checks
      }
    }

    const envPath = process.env.VETTO_PATH;
    if (envPath) {
      try {
        fs.accessSync(envPath, fs.constants.X_OK);
        return envPath;
      } catch {
        // Fall through
      }
    }

    // Check system PATH
    const pathDirs = (process.env.PATH || "").split(path.delimiter);
    for (const dir of pathDirs) {
      const candidate = path.join(dir, "vetto");
      try {
        fs.accessSync(candidate, fs.constants.X_OK);
        return candidate;
      } catch {
        // Ignore
      }
    }

    // Common standard locations
    const standardCandidates = [
      path.join(os.homedir(), ".cargo", "bin", "vetto"),
      "/usr/local/bin/vetto",
      "/usr/bin/vetto",
      path.join(os.homedir(), ".vetto", "bin", "vetto"),
      path.join(os.homedir(), ".local", "bin", "vetto"),
    ];

    for (const candidate of standardCandidates) {
      try {
        fs.accessSync(candidate, fs.constants.X_OK);
        return candidate;
      } catch {
        // Ignore
      }
    }

    return null;
  }

  /**
   * Build the complete command array prefixed with vetto CLI parameters.
   */
  public buildCommand(
    command: string | string[],
    options: VettoRunOptions = {}
  ): string[] {
    const cmdArgs = Array.isArray(command) ? command : [command];
    const vettoBin = this.resolveBinary();

    if (!vettoBin) {
      if (!this.allowFallback) {
        throw new VettoNotFoundError();
      }
      return cmdArgs;
    }

    const runArgs: string[] = [vettoBin, "run"];

    if (this.profile) {
      runArgs.push("--profile", this.profile);
    }

    if (this.policyPath) {
      runArgs.push("--policy", this.policyPath);
    }

    if (this.net === "allowlist" && this.allowedDomains.length > 0) {
      runArgs.push("--net", `allowlist:${this.allowedDomains.join(",")}`);
    } else {
      runArgs.push("--net", this.net);
    }

    const effectiveTimeout =
      options.timeoutSeconds !== undefined ? options.timeoutSeconds : this.timeoutSeconds;
    if (effectiveTimeout > 0) {
      runArgs.push("--timeout", `${Math.floor(effectiveTimeout)}s`);
    }

    if (this.tui) {
      runArgs.push("--tui", this.tui);
    }

    if (this.memoryLimit) {
      runArgs.push("--limits", `as=${this.memoryLimit}`);
    }

    if (this.failOnBlock) {
      runArgs.push("--fail-on-block");
    }

    // Workspace and write paths
    const targetCwd = path.resolve(options.cwd || this.workingDir || process.cwd());
    const writes = new Set<string>(this.allowWrite);
    if (options.extraAllowWrite) {
      for (const p of options.extraAllowWrite) {
        writes.add(path.resolve(p));
      }
    }
    writes.add(targetCwd);

    for (const w of writes) {
      runArgs.push("--allow-write", w);
    }

    const reads = new Set<string>(this.allowRead);
    if (options.extraAllowRead) {
      for (const p of options.extraAllowRead) {
        reads.add(path.resolve(p));
      }
    }
    for (const r of reads) {
      runArgs.push("--allow-read", r);
    }

    runArgs.push("--");
    runArgs.push(...cmdArgs);

    return runArgs;
  }

  /**
   * Run a sandboxed command asynchronously.
   */
  public async run(
    command: string | string[],
    options: VettoRunOptions = {}
  ): Promise<VettoExecutionResult> {
    const fullCommand = this.buildCommand(command, options);
    const targetCwd = path.resolve(options.cwd || this.workingDir || process.cwd());
    const effectiveTimeout =
      options.timeoutSeconds !== undefined ? options.timeoutSeconds : this.timeoutSeconds;

    const execEnv: Record<string, string> = { ...process.env } as Record<string, string>;
    if (this.envPass.length > 0) {
      const filtered: Record<string, string> = {};
      for (const k of this.envPass) {
        if (execEnv[k] !== undefined) {
          filtered[k] = execEnv[k];
        }
      }
      for (const essential of ["PATH", "HOME", "USER", "TERM", "LANG", "LC_ALL"]) {
        if (execEnv[essential] !== undefined && filtered[essential] === undefined) {
          filtered[essential] = execEnv[essential];
        }
      }
      Object.assign(execEnv, filtered);
    }

    if (options.env) {
      Object.assign(execEnv, options.env);
    }

    const startTime = performance.now();

    return new Promise<VettoExecutionResult>((resolve, reject) => {
      const [bin, ...args] = fullCommand;
      let timedOut = false;
      let timer: NodeJS.Timeout | undefined;

      const child = childProcess.spawn(bin, args, {
        cwd: targetCwd,
        env: execEnv,
        stdio: ["pipe", "pipe", "pipe"],
        detached: true,
      });

      const stdoutChunks: Buffer[] = [];
      const stderrChunks: Buffer[] = [];

      child.stdout.on("data", (chunk: Buffer) => stdoutChunks.push(chunk));
      child.stderr.on("data", (chunk: Buffer) => stderrChunks.push(chunk));

      if (options.stdin) {
        child.stdin.write(options.stdin);
        child.stdin.end();
      }

      if (effectiveTimeout > 0) {
        timer = setTimeout(() => {
          timedOut = true;
          try {
            if (process.platform !== "win32" && child.pid) {
              process.kill(-child.pid, "SIGKILL");
            } else {
              child.kill("SIGKILL");
            }
          } catch {
            child.kill("SIGKILL");
          }
        }, effectiveTimeout * 1000);
      }

      child.on("error", (err: Error) => {
        if (timer) clearTimeout(timer);
        const durationMs = Math.round(performance.now() - startTime);
        const res: VettoExecutionResult = {
          exitCode: 125,
          stdout: "",
          stderr: err.message,
          durationMs,
          violated: true,
          timedOut: false,
          success: false,
          command: fullCommand,
        };
        if (options.raiseOnError) {
          reject(new VettoSecurityError(`Command failed closed: ${err.message}`, res));
        } else {
          resolve(res);
        }
      });

      child.on("close", (code: number | null) => {
        if (timer) clearTimeout(timer);
        const durationMs = Math.round(performance.now() - startTime);
        const stdoutStr = Buffer.concat(stdoutChunks).toString("utf-8");
        let stderrStr = Buffer.concat(stderrChunks).toString("utf-8");

        let exitCode = code ?? 0;
        if (timedOut) {
          exitCode = 124;
          if (!stderrStr) {
            stderrStr = `Execution timed out after ${effectiveTimeout} seconds`;
          }
        }

        const violated =
          exitCode === 125 || stderrStr.toLowerCase().includes("blocked by policy");
        const isTimeout = exitCode === 124 || timedOut;

        const res: VettoExecutionResult = {
          exitCode,
          stdout: stdoutStr,
          stderr: stderrStr,
          durationMs,
          violated,
          timedOut: isTimeout,
          success: exitCode === 0,
          command: fullCommand,
        };

        if (options.raiseOnError) {
          if (isTimeout) {
            reject(new VettoTimeoutError(`Command timed out (Exit 124): ${stderrStr}`, res));
            return;
          }
          if (violated) {
            reject(
              new VettoSecurityError(
                `Command failed closed on security violation (Exit 125): ${stderrStr}`,
                res
              )
            );
            return;
          }
          if (exitCode !== 0) {
            reject(
              new Error(`Command failed with exit code ${exitCode}: ${stderrStr}`)
            );
            return;
          }
        }

        resolve(res);
      });
    });
  }

  /**
   * Run a sandboxed command synchronously.
   */
  public runSync(
    command: string | string[],
    options: VettoRunOptions = {}
  ): VettoExecutionResult {
    const fullCommand = this.buildCommand(command, options);
    const targetCwd = path.resolve(options.cwd || this.workingDir || process.cwd());
    const effectiveTimeout =
      options.timeoutSeconds !== undefined ? options.timeoutSeconds : this.timeoutSeconds;

    const execEnv: Record<string, string> = { ...process.env } as Record<string, string>;
    if (this.envPass.length > 0) {
      const filtered: Record<string, string> = {};
      for (const k of this.envPass) {
        if (execEnv[k] !== undefined) {
          filtered[k] = execEnv[k];
        }
      }
      for (const essential of ["PATH", "HOME", "USER", "TERM", "LANG", "LC_ALL"]) {
        if (execEnv[essential] !== undefined && filtered[essential] === undefined) {
          filtered[essential] = execEnv[essential];
        }
      }
      Object.assign(execEnv, filtered);
    }

    if (options.env) {
      Object.assign(execEnv, options.env);
    }

    const startTime = performance.now();
    const [bin, ...args] = fullCommand;

    const proc = childProcess.spawnSync(bin, args, {
      cwd: targetCwd,
      env: execEnv,
      input: options.stdin,
      timeout: effectiveTimeout > 0 ? effectiveTimeout * 1000 : undefined,
      encoding: "utf-8",
    });

    const durationMs = Math.round(performance.now() - startTime);
    const timedOut = proc.error !== undefined && (proc.error as any).code === "ETIMEDOUT";

    let exitCode = proc.status ?? (timedOut ? 124 : 125);
    if (timedOut) {
      exitCode = 124;
    }

    const stdout = proc.stdout ? proc.stdout.toString() : "";
    let stderr = proc.stderr ? proc.stderr.toString() : "";
    if (timedOut && !stderr) {
      stderr = `Execution timed out after ${effectiveTimeout} seconds`;
    }
    if (proc.error && !timedOut) {
      stderr = proc.error.message;
    }

    const violated =
      exitCode === 125 || stderr.toLowerCase().includes("blocked by policy");
    const isTimeout = exitCode === 124 || timedOut;

    const res: VettoExecutionResult = {
      exitCode,
      stdout,
      stderr,
      durationMs,
      violated,
      timedOut: isTimeout,
      success: exitCode === 0,
      command: fullCommand,
    };

    if (options.raiseOnError) {
      if (isTimeout) {
        throw new VettoTimeoutError(`Command timed out (Exit 124): ${stderr}`, res);
      }
      if (violated) {
        throw new VettoSecurityError(
          `Command failed closed on security violation (Exit 125): ${stderr}`,
          res
        );
      }
      if (exitCode !== 0) {
        throw new Error(`Command failed with exit code ${exitCode}: ${stderr}`);
      }
    }

    return res;
  }
}
