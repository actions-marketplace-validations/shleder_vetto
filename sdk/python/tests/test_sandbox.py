"""Unit tests for VettoSandbox execution wrapper and exit code semantics."""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from vetto.sandbox import (
    VettoNotFoundError,
    VettoResult,
    VettoSandbox,
    VettoSecurityError,
    VettoTimeoutError,
)


class TestVettoSandbox(unittest.TestCase):
    """Test suite for VettoSandbox command construction and execution semantics."""

    def setUp(self) -> None:
        self.dummy_bin = "/mock/bin/vetto"

    def test_binary_resolution_explicit(self) -> None:
        # Fake file with execute permission
        with patch.object(Path, "is_file", return_value=True), patch("os.access", return_value=True):
            sandbox = VettoSandbox(binary_path="/custom/path/vetto")
            self.assertEqual(sandbox.resolve_binary(), "/custom/path/vetto")

    def test_binary_resolution_env(self) -> None:
        with patch.dict(os.environ, {"VETTO_PATH": "/env/vetto"}), patch.object(
            Path, "is_file", return_value=True
        ), patch("os.access", return_value=True):
            sandbox = VettoSandbox()
            self.assertEqual(sandbox.resolve_binary(), "/env/vetto")

    def test_binary_resolution_not_found(self) -> None:
        with patch.dict(os.environ, {}, clear=True), patch(
            "shutil.which", return_value=None
        ), patch.object(Path, "is_file", return_value=False):
            sandbox = VettoSandbox(allow_fallback=False)
            with self.assertRaises(VettoNotFoundError):
                sandbox.build_command(["ls"])

    def test_binary_resolution_fallback(self) -> None:
        with patch.dict(os.environ, {}, clear=True), patch(
            "shutil.which", return_value=None
        ), patch.object(Path, "is_file", return_value=False):
            sandbox = VettoSandbox(allow_fallback=True)
            cmd = sandbox.build_command(["python3", "script.py"])
            self.assertEqual(cmd, ["python3", "script.py"])

    def test_build_command_full_arguments(self) -> None:
        with patch.object(VettoSandbox, "resolve_binary", return_value=self.dummy_bin):
            sandbox = VettoSandbox(
                profile="strict",
                allow_write=["/tmp/write_dir"],
                allow_read=["/opt/read_dir"],
                net="allowlist",
                allowed_domains=["api.anthropic.com", "pypi.org"],
                timeout_seconds=45.0,
                memory_limit="1GB",
                policy_path="/etc/vetto/policy.toml",
                tui="none",
                fail_on_block=True,
            )

            cmd = sandbox.build_command(["bash", "-c", "echo test"], cwd="/workspace")

            self.assertEqual(cmd[0], self.dummy_bin)
            self.assertEqual(cmd[1], "run")
            self.assertIn("--profile", cmd)
            self.assertEqual(cmd[cmd.index("--profile") + 1], "strict")
            self.assertIn("--policy", cmd)
            self.assertEqual(cmd[cmd.index("--policy") + 1], "/etc/vetto/policy.toml")
            self.assertIn("--net", cmd)
            self.assertEqual(
                cmd[cmd.index("--net") + 1], "allowlist:api.anthropic.com,pypi.org"
            )
            self.assertIn("--timeout", cmd)
            self.assertEqual(cmd[cmd.index("--timeout") + 1], "45s")
            self.assertIn("--tui", cmd)
            self.assertEqual(cmd[cmd.index("--tui") + 1], "none")
            self.assertIn("--limits", cmd)
            self.assertEqual(cmd[cmd.index("--limits") + 1], "as=1GB")
            self.assertIn("--fail-on-block", cmd)
            self.assertIn("--allow-write", cmd)
            self.assertIn("--allow-read", cmd)
            self.assertIn("--", cmd)
            dash_idx = cmd.index("--")
            self.assertEqual(cmd[dash_idx + 1 :], ["bash", "-c", "echo test"])

    def test_result_success_semantics(self) -> None:
        res = VettoResult(
            exit_code=0,
            stdout="operation completed\n",
            stderr="",
            duration_ms=12.5,
        )
        self.assertTrue(res.success)
        self.assertFalse(res.violated)
        self.assertFalse(res.timed_out)

    def test_result_timeout_exit_124_semantics(self) -> None:
        res = VettoResult(
            exit_code=124,
            stdout="",
            stderr="process killed after 30s deadline",
            duration_ms=30005.0,
            timed_out=True,
        )
        self.assertFalse(res.success)
        self.assertTrue(res.timed_out)
        self.assertFalse(res.violated)

    def test_result_security_violation_exit_125_semantics(self) -> None:
        res = VettoResult(
            exit_code=125,
            stdout="",
            stderr="vetto: permission denied: path /etc/shadow blocked by policy",
            duration_ms=3.2,
            violated=True,
        )
        self.assertFalse(res.success)
        self.assertTrue(res.violated)
        self.assertFalse(res.timed_out)

    def test_run_with_raise_on_error_timeout(self) -> None:
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (b"", b"Timeout exceeded")
        mock_proc.returncode = 124

        with patch.object(VettoSandbox, "resolve_binary", return_value=self.dummy_bin), patch(
            "subprocess.Popen", return_value=mock_proc
        ):
            sandbox = VettoSandbox()
            with self.assertRaises(VettoTimeoutError) as ctx:
                sandbox.run(["long_task"], raise_on_error=True)
            self.assertEqual(ctx.exception.result.exit_code, 124)
            self.assertTrue(ctx.exception.result.timed_out)

    def test_run_with_raise_on_error_security_violation(self) -> None:
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (b"", b"Denied by landlock LSM")
        mock_proc.returncode = 125

        with patch.object(VettoSandbox, "resolve_binary", return_value=self.dummy_bin), patch(
            "subprocess.Popen", return_value=mock_proc
        ):
            sandbox = VettoSandbox()
            with self.assertRaises(VettoSecurityError) as ctx:
                sandbox.run(["cat", "/etc/shadow"], raise_on_error=True)
            self.assertEqual(ctx.exception.result.exit_code, 125)
            self.assertTrue(ctx.exception.result.violated)

    def test_run_fallback_execution(self) -> None:
        # When fallback is allowed, runs direct command using system python
        sandbox = VettoSandbox(allow_fallback=True)
        with patch.object(VettoSandbox, "resolve_binary", return_value=None):
            result = sandbox.run([sys.executable, "-c", "import sys; sys.stdout.write('hello')"])
            self.assertEqual(result.exit_code, 0)
            self.assertEqual(result.stdout, "hello")
            self.assertGreater(result.duration_ms, 0)


class TestVettoSandboxAsync(unittest.IsolatedAsyncioTestCase):
    """Asynchronous test cases for VettoSandbox."""

    async def test_run_async_fallback_execution(self) -> None:
        sandbox = VettoSandbox(allow_fallback=True)
        with patch.object(VettoSandbox, "resolve_binary", return_value=None):
            result = await sandbox.run_async(
                [sys.executable, "-c", "import sys; sys.stdout.write('async_hello')"]
            )
            self.assertEqual(result.exit_code, 0)
            self.assertEqual(result.stdout, "async_hello")
            self.assertGreater(result.duration_ms, 0)


if __name__ == "__main__":
    unittest.main()


