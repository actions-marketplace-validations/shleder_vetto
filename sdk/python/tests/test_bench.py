"""Unit tests for Vetto SWE-bench task runner and container adapter."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from vetto.bench import VettoContainer, VettoExecResult, VettoTaskRunner


class TestVettoBenchAdapter(unittest.TestCase):
    """Test suite for VettoTaskRunner, VettoContainer, and VettoExecResult."""

    def setUp(self) -> None:
        self.dummy_bin = "/usr/bin/vetto"

    def test_runner_initialization_defaults(self) -> None:
        with patch.object(VettoTaskRunner, "_find_vetto_binary", return_value=self.dummy_bin):
            runner = VettoTaskRunner()
            self.assertEqual(runner.timeout, 180)
            self.assertEqual(runner.memory_mb, 4096)
            self.assertEqual(runner.net, "off")
            self.assertEqual(runner.profile, "swebench")
            self.assertEqual(runner.vetto_bin, self.dummy_bin)

    def test_runner_initialization_custom(self) -> None:
        with patch.object(VettoTaskRunner, "_find_vetto_binary", return_value=self.dummy_bin):
            runner = VettoTaskRunner(
                workspace="/custom/workspace",
                timeout=300,
                memory_mb=8192,
                net=False,
                profile="custom_profile",
            )
            self.assertEqual(runner.workspace, Path("/custom/workspace").resolve())
            self.assertEqual(runner.timeout, 300)
            self.assertEqual(runner.memory_mb, 8192)
            self.assertEqual(runner.net, "off")
            self.assertEqual(runner.profile, "custom_profile")

    def test_run_command_success(self) -> None:
        mock_output = {
            "exit_code": 0,
            "stdout": "tests passed",
            "stderr": "",
            "cold_start_ns": 1500000,
            "cold_start_ms": 1.5,
            "duration_ms": 250,
            "peak_memory_bytes": 10485760,
            "peak_memory_mb": 10.0,
            "blocked_attempts": 0,
            "verdict": "pass",
            "timed_out": False,
            "oom_killed": False,
            "status": "COMPLETED",
            "instance_id": "task-42",
        }

        with patch.object(VettoTaskRunner, "_find_vetto_binary", return_value=self.dummy_bin), patch(
            "subprocess.run"
        ) as mock_run:
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.stdout = json.dumps(mock_output)
            mock_proc.stderr = ""
            mock_run.return_value = mock_proc

            runner = VettoTaskRunner(workspace="/tmp/test_workspace")
            result = runner.run_command(["pytest", "tests/"], instance_id="task-42")

            self.assertIsInstance(result, VettoExecResult)
            self.assertEqual(result.exit_code, 0)
            self.assertEqual(result.stdout, "tests passed")
            self.assertEqual(result.cold_start_ms, 1.5)
            self.assertEqual(result.verdict, "pass")
            self.assertEqual(result.instance_id, "task-42")

            # Check that command args were passed properly
            args, kwargs = mock_run.call_args
            cmd_args = args[0]
            self.assertEqual(cmd_args[0], self.dummy_bin)
            self.assertEqual(cmd_args[1], "bench")
            self.assertIn("--workspace", cmd_args)
            self.assertIn("--json", cmd_args)
            self.assertIn("--instance-id", cmd_args)
            self.assertIn("--", cmd_args)
            self.assertIn("pytest", cmd_args)

    def test_container_exec_run_shim(self) -> None:
        mock_result = VettoExecResult(
            exit_code=0,
            stdout="hello from container",
            stderr="",
            cold_start_ns=1000000,
            cold_start_ms=1.0,
            duration_ms=100,
            peak_memory_bytes=1024,
            peak_memory_mb=0.1,
            blocked_attempts=0,
            verdict="pass",
            timed_out=False,
            oom_killed=False,
            status="COMPLETED",
        )

        with patch.object(VettoTaskRunner, "_find_vetto_binary", return_value=self.dummy_bin), patch.object(
            VettoTaskRunner, "run_command", return_value=mock_result
        ):
            runner = VettoTaskRunner(workspace="/tmp/ws")
            container = runner.as_docker_container()

            exit_code, output = container.exec_run(["echo", "hello"])
            self.assertEqual(exit_code, 0)
            self.assertIn(b"hello from container", output)

            # Test no-ops
            container.stop()
            container.remove()


if __name__ == "__main__":
    unittest.main()
