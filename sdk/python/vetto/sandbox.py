"""Vetto sandbox execution engine and result definitions."""

from __future__ import annotations

import asyncio
import os
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence, Union


class VettoError(Exception):
    """Base exception for all Vetto sandbox errors."""


class VettoNotFoundError(VettoError):
    """Raised when the Vetto binary cannot be located and fallback is disabled."""


class VettoSecurityError(VettoError):
    """Raised when an operation violates security boundaries (Exit 125 fail-closed)."""

    def __init__(self, message: str, result: VettoResult):
        super().__init__(message)
        self.result = result


class VettoTimeoutError(VettoError):
    """Raised when a sandboxed execution exceeds the allotted timeout (Exit 124)."""

    def __init__(self, message: str, result: VettoResult):
        super().__init__(message)
        self.result = result


@dataclass
class VettoResult:
    """Execution outcome produced by Vetto sandbox enforcement."""

    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float
    violated: bool = False
    timed_out: bool = False
    session_id: Optional[str] = None
    command: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        """True if the process terminated normally with exit code 0."""
        return self.exit_code == 0


class VettoSandbox:
    """Configurable execution sandbox enforcing kernel-level boundaries via Vetto CLI."""

    def __init__(
        self,
        profile: Optional[str] = "default",
        allow_write: Optional[Sequence[Union[str, Path]]] = None,
        allow_read: Optional[Sequence[Union[str, Path]]] = None,
        net: str = "off",
        allowed_domains: Optional[Sequence[str]] = None,
        timeout_seconds: Optional[float] = 120.0,
        env_pass: Optional[Sequence[str]] = None,
        memory_limit: Optional[str] = None,
        working_dir: Optional[Union[str, Path]] = None,
        binary_path: Optional[Union[str, Path]] = None,
        policy_path: Optional[Union[str, Path]] = None,
        allow_fallback: bool = False,
        tui: str = "none",
        fail_on_block: bool = True,
    ) -> None:
        """Initialize sandbox execution parameters.

        Args:
            profile: Built-in policy profile name (default, strict, audit, etc.).
            allow_write: List of filesystem paths permitted for write access.
            allow_read: List of filesystem paths permitted for read-only access.
            net: Network isolation mode ('off', 'allowlist', 'host').
            allowed_domains: Permitted domains when net='allowlist'.
            timeout_seconds: Hard execution wall-clock timeout in seconds.
            env_pass: Environment variable names permitted through the boundary.
            memory_limit: Cgroup memory limit string (e.g. '512MB', '2GB').
            working_dir: Root workspace directory for execution.
            binary_path: Explicit override path to the vetto binary.
            policy_path: Explicit path to an external policy.toml file.
            allow_fallback: Fallback to uncontained execution if binary is missing.
            tui: Terminal UI mode (default 'none' for API/SDK usage).
            fail_on_block: If True, blocks exit with Exit 125 fail-closed.
        """
        self.profile = profile
        self.allow_write = [str(Path(p).resolve()) for p in (allow_write or [])]
        self.allow_read = [str(Path(p).resolve()) for p in (allow_read or [])]
        self.net = net
        self.allowed_domains = list(allowed_domains or [])
        self.timeout_seconds = timeout_seconds
        self.env_pass = list(env_pass or [])
        self.memory_limit = memory_limit
        self.working_dir = Path(working_dir).resolve() if working_dir else None
        self.binary_path = Path(binary_path).resolve() if binary_path else None
        self.policy_path = Path(policy_path).resolve() if policy_path else None
        self.allow_fallback = allow_fallback
        self.tui = tui
        self.fail_on_block = fail_on_block

    def resolve_binary(self) -> Optional[str]:
        """Locate the vetto executable on the host system.

        Returns:
            Resolved executable path string or None if not found.
        """
        if self.binary_path and self.binary_path.is_file() and os.access(self.binary_path, os.X_OK):
            return str(self.binary_path)

        env_path = os.getenv("VETTO_PATH")
        if env_path:
            p = Path(env_path).expanduser()
            if p.is_file() and os.access(p, os.X_OK):
                return str(p)

        which_path = shutil.which("vetto")
        if which_path:
            return which_path

        candidates = [
            Path.home() / ".cargo" / "bin" / "vetto",
            Path("/usr/local/bin/vetto"),
            Path("/usr/bin/vetto"),
            Path.home() / ".vetto" / "bin" / "vetto",
            Path.home() / ".local" / "bin" / "vetto",
        ]
        for candidate in candidates:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)

        return None

    def build_command(
        self,
        command: Union[str, Sequence[str]],
        cwd: Optional[Union[str, Path]] = None,
        timeout: Optional[float] = None,
        extra_allow_write: Optional[Sequence[Union[str, Path]]] = None,
        extra_allow_read: Optional[Sequence[Union[str, Path]]] = None,
    ) -> list[str]:
        """Construct the argument vector for sandboxed execution.

        Args:
            command: Command string or argument list to execute.
            cwd: Working directory override.
            timeout: Timeout override in seconds.
            extra_allow_write: Additional writable paths.
            extra_allow_read: Additional readable paths.

        Returns:
            Command list prefixed with vetto CLI parameters.
        """
        cmd_args = [command] if isinstance(command, str) else list(command)

        vetto_bin = self.resolve_binary()
        if not vetto_bin:
            if not self.allow_fallback:
                raise VettoNotFoundError(
                    "Vetto binary not found. Install via 'cargo install vetto' "
                    "or 'npm install -g @shledery/vetto', set VETTO_PATH, or "
                    "configure allow_fallback=True."
                )
            return cmd_args

        run_args = [vetto_bin, "run"]

        if self.profile:
            run_args.extend(["--profile", self.profile])

        if self.policy_path:
            run_args.extend(["--policy", str(self.policy_path)])

        if self.net == "allowlist" and self.allowed_domains:
            run_args.extend(["--net", f"allowlist:{','.join(self.allowed_domains)}"])
        else:
            run_args.extend(["--net", self.net])

        eff_timeout = timeout if timeout is not None else self.timeout_seconds
        if eff_timeout and eff_timeout > 0:
            run_args.extend(["--timeout", f"{int(eff_timeout)}s"])

        if self.tui:
            run_args.extend(["--tui", self.tui])

        if self.memory_limit:
            run_args.extend(["--limits", f"as={self.memory_limit}"])

        if self.fail_on_block:
            run_args.append("--fail-on-block")

        # Filesystem write rules
        target_cwd = Path(cwd or self.working_dir or os.getcwd()).resolve()
        writes = list(self.allow_write)
        if extra_allow_write:
            writes.extend(str(Path(p).resolve()) for p in extra_allow_write)
        if str(target_cwd) not in writes:
            writes.append(str(target_cwd))

        for w in writes:
            run_args.extend(["--allow-write", w])

        reads = list(self.allow_read)
        if extra_allow_read:
            reads.extend(str(Path(p).resolve()) for p in extra_allow_read)

        for r in reads:
            run_args.extend(["--allow-read", r])

        run_args.append("--")
        run_args.extend(cmd_args)
        return run_args

    def run(
        self,
        command: Union[str, Sequence[str]],
        cwd: Optional[Union[str, Path]] = None,
        env: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
        raise_on_error: bool = False,
        extra_allow_write: Optional[Sequence[Union[str, Path]]] = None,
        extra_allow_read: Optional[Sequence[Union[str, Path]]] = None,
    ) -> VettoResult:
        """Execute a command synchronously within the Vetto sandbox.

        Args:
            command: Shell command string or argument sequence.
            cwd: Working directory for process execution.
            env: Environment variables to expose.
            timeout: Execution timeout in seconds override.
            raise_on_error: If True, raises VettoSecurityError or VettoTimeoutError.
            extra_allow_write: Additional writable paths for this run.
            extra_allow_read: Additional readable paths for this run.

        Returns:
            VettoResult instance with exit_code, stdout, stderr, and metadata.
        """
        full_command = self.build_command(
            command,
            cwd=cwd,
            timeout=timeout,
            extra_allow_write=extra_allow_write,
            extra_allow_read=extra_allow_read,
        )
        target_cwd = str(Path(cwd or self.working_dir or os.getcwd()).resolve())
        eff_timeout = timeout if timeout is not None else self.timeout_seconds

        exec_env = os.environ.copy()
        if self.env_pass:
            # Filter environment if explicit pass-through is configured
            filtered = {k: exec_env[k] for k in self.env_pass if k in exec_env}
            # Always preserve minimal runtime variables
            for essential in ("PATH", "HOME", "USER", "TERM", "LANG", "LC_ALL"):
                if essential in exec_env and essential not in filtered:
                    filtered[essential] = exec_env[essential]
            exec_env = filtered

        if env:
            exec_env.update(env)

        kwargs: dict[str, Any] = {
            "cwd": target_cwd,
            "env": exec_env,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
        }

        # Isolate child into a new process group for clean tree reaping
        if hasattr(os, "setsid"):
            kwargs["preexec_fn"] = os.setsid

        start_time = time.monotonic()
        try:
            proc = subprocess.Popen(full_command, **kwargs)
            try:
                stdout_bytes, stderr_bytes = proc.communicate(timeout=eff_timeout)
                duration_ms = round((time.monotonic() - start_time) * 1000.0, 2)
                exit_code = proc.returncode
                stdout_str = stdout_bytes.decode("utf-8", errors="replace")
                stderr_str = stderr_bytes.decode("utf-8", errors="replace")

                violated = exit_code == 125 or "blocked by policy" in stderr_str.lower()
                timed_out = exit_code == 124

                res = VettoResult(
                    exit_code=exit_code,
                    stdout=stdout_str,
                    stderr=stderr_str,
                    duration_ms=duration_ms,
                    violated=violated,
                    timed_out=timed_out,
                    command=full_command,
                )
            except subprocess.TimeoutExpired:
                # Terminate entire process tree
                self._terminate_process(proc)
                stdout_bytes, stderr_bytes = proc.communicate()
                duration_ms = round((time.monotonic() - start_time) * 1000.0, 2)
                stdout_str = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
                stderr_str = (
                    stderr_bytes.decode("utf-8", errors="replace")
                    if stderr_bytes
                    else f"Execution timed out after {eff_timeout} seconds"
                )
                res = VettoResult(
                    exit_code=124,
                    stdout=stdout_str,
                    stderr=stderr_str,
                    duration_ms=duration_ms,
                    violated=False,
                    timed_out=True,
                    command=full_command,
                )
        except VettoNotFoundError:
            raise
        except Exception as exc:
            duration_ms = round((time.monotonic() - start_time) * 1000.0, 2)
            res = VettoResult(
                exit_code=125,
                stdout="",
                stderr=str(exc),
                duration_ms=duration_ms,
                violated=True,
                timed_out=False,
                command=full_command,
            )

        if raise_on_error:
            if res.timed_out:
                raise VettoTimeoutError(f"Command timed out (Exit 124): {res.stderr}", res)
            if res.violated:
                raise VettoSecurityError(
                    f"Command failed closed on security violation (Exit 125): {res.stderr}", res
                )
            if not res.success:
                raise RuntimeError(f"Command failed with exit code {res.exit_code}: {res.stderr}")

        return res

    async def run_async(
        self,
        command: Union[str, Sequence[str]],
        cwd: Optional[Union[str, Path]] = None,
        env: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
        raise_on_error: bool = False,
        extra_allow_write: Optional[Sequence[Union[str, Path]]] = None,
        extra_allow_read: Optional[Sequence[Union[str, Path]]] = None,
    ) -> VettoResult:
        """Execute a command asynchronously within the Vetto sandbox.

        Args:
            command: Shell command string or argument sequence.
            cwd: Working directory for process execution.
            env: Environment variables to expose.
            timeout: Execution timeout in seconds override.
            raise_on_error: If True, raises VettoSecurityError or VettoTimeoutError.
            extra_allow_write: Additional writable paths for this run.
            extra_allow_read: Additional readable paths for this run.

        Returns:
            VettoResult instance with execution outcome.
        """
        full_command = self.build_command(
            command,
            cwd=cwd,
            timeout=timeout,
            extra_allow_write=extra_allow_write,
            extra_allow_read=extra_allow_read,
        )
        target_cwd = str(Path(cwd or self.working_dir or os.getcwd()).resolve())
        eff_timeout = timeout if timeout is not None else self.timeout_seconds

        exec_env = os.environ.copy()
        if self.env_pass:
            filtered = {k: exec_env[k] for k in self.env_pass if k in exec_env}
            for essential in ("PATH", "HOME", "USER", "TERM", "LANG", "LC_ALL"):
                if essential in exec_env and essential not in filtered:
                    filtered[essential] = exec_env[essential]
            exec_env = filtered

        if env:
            exec_env.update(env)

        start_time = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                full_command[0],
                *full_command[1:],
                cwd=target_cwd,
                env=exec_env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                if eff_timeout and eff_timeout > 0:
                    stdout_bytes, stderr_bytes = await asyncio.wait_for(
                        proc.communicate(), timeout=eff_timeout
                    )
                else:
                    stdout_bytes, stderr_bytes = await proc.communicate()

                duration_ms = round((time.monotonic() - start_time) * 1000.0, 2)
                exit_code = proc.returncode or 0
                stdout_str = stdout_bytes.decode("utf-8", errors="replace")
                stderr_str = stderr_bytes.decode("utf-8", errors="replace")

                violated = exit_code == 125 or "blocked by policy" in stderr_str.lower()
                timed_out = exit_code == 124

                res = VettoResult(
                    exit_code=exit_code,
                    stdout=stdout_str,
                    stderr=stderr_str,
                    duration_ms=duration_ms,
                    violated=violated,
                    timed_out=timed_out,
                    command=full_command,
                )
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                stdout_bytes, stderr_bytes = await proc.communicate()
                duration_ms = round((time.monotonic() - start_time) * 1000.0, 2)
                stdout_str = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
                stderr_str = (
                    stderr_bytes.decode("utf-8", errors="replace")
                    if stderr_bytes
                    else f"Execution timed out after {eff_timeout} seconds"
                )
                res = VettoResult(
                    exit_code=124,
                    stdout=stdout_str,
                    stderr=stderr_str,
                    duration_ms=duration_ms,
                    violated=False,
                    timed_out=True,
                    command=full_command,
                )
        except VettoNotFoundError:
            raise
        except Exception as exc:
            duration_ms = round((time.monotonic() - start_time) * 1000.0, 2)
            res = VettoResult(
                exit_code=125,
                stdout="",
                stderr=str(exc),
                duration_ms=duration_ms,
                violated=True,
                timed_out=False,
                command=full_command,
            )

        if raise_on_error:
            if res.timed_out:
                raise VettoTimeoutError(f"Command timed out (Exit 124): {res.stderr}", res)
            if res.violated:
                raise VettoSecurityError(
                    f"Command failed closed on security violation (Exit 125): {res.stderr}", res
                )
            if not res.success:
                raise RuntimeError(f"Command failed with exit code {res.exit_code}: {res.stderr}")

        return res

    def _terminate_process(self, proc: subprocess.Popen[Any]) -> None:
        """Deterministically terminate a process and its child tree."""
        if hasattr(os, "killpg") and hasattr(os, "getpgid"):
            try:
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGKILL)
                return
            except OSError:
                pass
        try:
            proc.kill()
        except OSError:
            pass
