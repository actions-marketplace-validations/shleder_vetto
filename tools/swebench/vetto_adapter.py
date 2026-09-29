#!/usr/bin/env python3
"""
Vetto SWE-bench Runtime Adapter (tools/swebench/vetto_adapter.py)

Drop-in execution runner replacing Docker in SWE-bench evaluation harnesses.
Executes test suites and agent patches with <4ms cold-start latency, sub-megabyte
host memory overhead, and strict kernel-enforced sandboxing (Landlock LSM,
namespaces, cgroups v2, read-only root CoW, process-tree extinction).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union


@dataclass
class VettoExecResult:
    """Standardized execution result matching SWE-bench evaluation schema."""
    exit_code: int
    stdout: str
    stderr: str
    cold_start_ns: int
    cold_start_ms: float
    duration_ms: int
    peak_memory_bytes: int
    peak_memory_mb: float
    blocked_attempts: int
    verdict: str
    timed_out: bool
    oom_killed: bool
    status: str
    instance_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class VettoContainer:
    """
    Docker SDK Container compatibility shim.
    Provides container.exec_run() and container.stop()/remove() methods
    for legacy harnesses expecting docker.models.containers.Container.
    """

    def __init__(self, runner: "VettoTaskRunner", workdir: Optional[Path] = None):
        self.runner = runner
        self.workdir = workdir or runner.workspace
        self.id = f"vetto-shim-{os.getpid()}-{int(time.time())}"

    def exec_run(
        self,
        cmd: Union[str, List[str]],
        workdir: Optional[Union[str, Path]] = None,
        environment: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> Tuple[int, bytes]:
        """
        Emulate docker container.exec_run.
        Returns tuple of (exit_code, combined_output_bytes).
        """
        cwd = Path(workdir) if workdir else self.workdir
        result = self.runner.run_command(
            cmd=cmd,
            cwd=cwd,
            timeout=timeout,
            env=environment,
        )
        combined_output = (result.stdout + "\n" + result.stderr).encode("utf-8", errors="replace")
        return result.exit_code, combined_output

    def stop(self, timeout: int = 10) -> None:
        """No-op: Vetto is daemon-less and automatically terminates process trees."""
        pass

    def remove(self, force: bool = True) -> None:
        """No-op: Vetto resources are cleaned up deterministically upon exit."""
        pass


class VettoTaskRunner:
    """
    High-throughput task runner for SWE-bench benchmarks.
    Replaces Docker daemon execution with Vetto kernel-level sandbox.
    """

    def __init__(
        self,
        workspace: Optional[Union[str, Path]] = None,
        timeout: int = 180,
        memory_limit_mb: int = 4096,
        vetto_bin: Optional[str] = None,
        profile: str = "swebench",
        net: str = "off",
    ):
        self.workspace = Path(workspace).resolve() if workspace else Path.cwd()
        self.timeout = timeout
        self.memory_limit_mb = memory_limit_mb
        self.profile = profile
        self.net = net
        self.vetto_bin = self._find_vetto_binary(vetto_bin)

    @staticmethod
    def _find_vetto_binary(custom_bin: Optional[str] = None) -> str:
        """Locate usable vetto executable."""
        if custom_bin and (Path(custom_bin).is_file() or shutil.which(custom_bin)):
            return custom_bin

        env_bin = os.environ.get("VETTO_BIN")
        if env_bin and Path(env_bin).is_file():
            return env_bin

        # Check in PATH
        which_path = shutil.which("vetto")
        if which_path:
            return which_path

        # Check repository target directories
        repo_roots = [
            Path("/home/shleder/prod/vetto"),
            Path(__file__).resolve().parent.parent.parent,
            Path.cwd(),
        ]
        for root in repo_roots:
            for profile in ["release", "debug"]:
                candidate = root / "target" / profile / "vetto"
                if candidate.is_file():
                    return str(candidate)

        return "vetto"

    def run_command(
        self,
        cmd: Union[str, List[str]],
        cwd: Optional[Union[str, Path]] = None,
        timeout: Optional[int] = None,
        env: Optional[Dict[str, str]] = None,
        instance_id: Optional[str] = None,
    ) -> VettoExecResult:
        """
        Execute command inside hermetic Vetto sandbox with JSON telemetry.
        """
        target_cwd = Path(cwd).resolve() if cwd else self.workspace
        exec_timeout = timeout or self.timeout

        cmd_list = [cmd] if isinstance(cmd, str) else list(cmd)
        if len(cmd_list) == 1 and (" " in cmd_list[0] or ";" in cmd_list[0]):
            cmd_args = ["/bin/sh", "-c", cmd_list[0]]
        else:
            cmd_args = cmd_list

        argv = [
            self.vetto_bin,
            "bench",
            "--workspace",
            str(target_cwd),
            "--timeout",
            str(exec_timeout),
            "--memory",
            str(self.memory_limit_mb),
            "--profile",
            self.profile,
            "--net",
            self.net,
            "--json",
        ]

        if instance_id:
            argv.extend(["--instance-id", instance_id])

        if env:
            for k, v in env.items():
                argv.extend(["-e", f"{k}={v}"])

        argv.append("--")
        argv.extend(cmd_args)

        t_start = time.perf_counter()
        try:
            proc = subprocess.run(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            wall_time_ms = int((time.perf_counter() - t_start) * 1000)
            raw_stdout = proc.stdout.strip()

            if proc.returncode == 0 or raw_stdout.startswith("{"):
                try:
                    data = json.loads(raw_stdout)
                    return VettoExecResult(
                        exit_code=data.get("exit_code", proc.returncode),
                        stdout=data.get("stdout", ""),
                        stderr=data.get("stderr", proc.stderr),
                        cold_start_ns=data.get("cold_start_ns", 0),
                        cold_start_ms=data.get("cold_start_ms", 0.0),
                        duration_ms=data.get("duration_ms", wall_time_ms),
                        peak_memory_bytes=data.get("peak_memory_bytes", 0),
                        peak_memory_mb=data.get("peak_memory_mb", 0.0),
                        blocked_attempts=data.get("blocked_attempts", 0),
                        verdict=data.get("verdict", "pass" if proc.returncode == 0 else "fail_closed"),
                        timed_out=data.get("timed_out", False),
                        oom_killed=data.get("oom_killed", False),
                        status=data.get("status", "COMPLETED" if proc.returncode == 0 else "FAIL_CLOSED"),
                        instance_id=data.get("instance_id", instance_id),
                    )
                except json.JSONDecodeError:
                    pass

            return VettoExecResult(
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                cold_start_ns=0,
                cold_start_ms=0.0,
                duration_ms=wall_time_ms,
                peak_memory_bytes=0,
                peak_memory_mb=0.0,
                blocked_attempts=0,
                verdict="pass" if proc.returncode == 0 else "fail_closed",
                timed_out=proc.returncode in (124, 125),
                oom_killed=proc.returncode == 137,
                status="COMPLETED" if proc.returncode == 0 else "FAIL_CLOSED",
                instance_id=instance_id,
            )

        except Exception as e:
            wall_time_ms = int((time.perf_counter() - t_start) * 1000)
            return VettoExecResult(
                exit_code=125,
                stdout="",
                stderr=f"vetto execution failed: {e}",
                cold_start_ns=0,
                cold_start_ms=0.0,
                duration_ms=wall_time_ms,
                peak_memory_bytes=0,
                peak_memory_mb=0.0,
                blocked_attempts=0,
                verdict="fail_closed",
                timed_out=False,
                oom_killed=False,
                status="FAIL_CLOSED",
                instance_id=instance_id,
            )

    def apply_patch(self, patch_content: str, workspace: Optional[Path] = None) -> bool:
        """Apply unified diff patch using git apply within the repository."""
        target_ws = workspace or self.workspace
        with tempfile.NamedTemporaryFile(mode="w", suffix=".patch", delete=False) as tf:
            tf.write(patch_content)
            patch_file = Path(tf.name)

        try:
            cmd = ["git", "apply", "-v", str(patch_file)]
            res = subprocess.run(
                cmd,
                cwd=target_ws,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            return res.returncode == 0
        finally:
            if patch_file.exists():
                patch_file.unlink()

    def run_instance(
        self,
        instance: Dict[str, Any],
        test_patch: Optional[str] = None,
        test_command: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate a single SWE-bench instance.
        1. Apply test_patch if provided
        2. Run test_command inside Vetto sandbox
        3. Collect execution metrics and logs
        4. Revert workspace changes cleanly
        """
        instance_id = instance.get("instance_id", "unknown_instance")
        patch_applied = False

        if test_patch:
            patch_applied = self.apply_patch(test_patch)

        cmd = test_command or instance.get("test_cmd", "pytest")
        result = self.run_command(
            cmd=cmd,
            instance_id=instance_id,
        )

        # Rollback workspace changes to ensure isolation between tasks
        subprocess.run(
            ["git", "checkout", "."],
            cwd=self.workspace,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        subprocess.run(
            ["git", "clean", "-fd"],
            cwd=self.workspace,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )

        return {
            "instance_id": instance_id,
            "patch_applied": patch_applied,
            "test_result": result.to_dict(),
        }

    def as_docker_container(self) -> VettoContainer:
        """Return Docker Container compatibility object."""
        return VettoContainer(runner=self, workdir=self.workspace)


def main() -> None:
    """CLI entrypoint for testing adapter directly."""
    import argparse

    parser = argparse.ArgumentParser(description="Vetto SWE-bench execution adapter")
    parser.add_argument("--workspace", "-w", type=str, default=".", help="Workspace path")
    parser.add_argument("--timeout", "-t", type=int, default=180, help="Timeout in seconds")
    parser.add_argument("--memory", "-m", type=int, default=4096, help="Memory limit in MB")
    parser.add_argument("--instance-id", type=str, default=None, help="SWE-bench instance ID")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Command to run")

    args = parser.parse_args()
    cmd = args.command
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]

    if not cmd:
        print("Error: no command specified", file=sys.stderr)
        sys.exit(1)

    runner = VettoTaskRunner(
        workspace=args.workspace,
        timeout=args.timeout,
        memory_limit_mb=args.memory,
    )
    result = runner.run_command(cmd, instance_id=args.instance_id)
    print(json.dumps(result.to_dict(), indent=2))
    sys.exit(result.exit_code)


if __name__ == "__main__":
    main()
