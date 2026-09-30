"""Unit tests for PolicyBuilder and TOML serialization."""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

from vetto.policy import PolicyBuilder


class TestPolicyBuilder(unittest.TestCase):
    """Test suite for PolicyBuilder TOML generation and compliance."""

    def test_basic_policy_serialization(self) -> None:
        builder = (
            PolicyBuilder(name="test-policy", description="Test policy description")
            .allow_write("/tmp/out", "/var/log")
            .allow_read("/usr", "/lib")
            .deny_write(".git", "config.json")
            .deny_read("~/.ssh", "~/.aws")
            .set_network(
                mode="allowlist",
                allowlist=["pypi.org", "github.com"],
                deny_network=["169.254.169.254"],
                allow_tcp_bind=[8080],
                allow_tcp_connect=[443, 8080],
            )
            .set_limits(processes=128, open_files=1024, memory_max="2G", cpu_max="1.5")
            .pass_env("PATH", "HOME", "API_KEY")
        )

        toml_text = builder.to_toml()
        data = tomllib.loads(toml_text)

        self.assertEqual(data["metadata"]["name"], "test-policy")
        self.assertEqual(data["metadata"]["description"], "Test policy description")
        self.assertEqual(data["filesystem"]["allow_write"], ["/tmp/out", "/var/log"])
        self.assertEqual(data["filesystem"]["allow_read"], ["/usr", "/lib"])
        self.assertEqual(data["filesystem"]["deny_write"], [".git", "config.json"])
        self.assertEqual(data["filesystem"]["deny_read"], ["~/.ssh", "~/.aws"])
        self.assertEqual(data["network"]["mode"], "allowlist")
        self.assertEqual(data["network"]["allowlist"], ["pypi.org", "github.com"])
        self.assertEqual(data["network"]["deny_network"], ["169.254.169.254"])
        self.assertEqual(data["network"]["allow_tcp_bind"], [8080])
        self.assertEqual(data["network"]["allow_tcp_connect"], [443, 8080])
        self.assertEqual(data["limits"]["processes"], 128)
        self.assertEqual(data["limits"]["open_files"], 1024)
        self.assertEqual(data["cgroup"]["memory_max"], "2G")
        self.assertEqual(data["cgroup"]["cpu_max"], "1.5")
        self.assertEqual(data["environment"]["pass_through"], ["PATH", "HOME", "API_KEY"])

    def test_temp_file_creation(self) -> None:
        builder = PolicyBuilder("temp-test").allow_write("/tmp")
        temp_path = builder.create_temp_file()
        try:
            self.assertTrue(temp_path.is_file())
            content = temp_path.read_text(encoding="utf-8")
            data = tomllib.loads(content)
            self.assertEqual(data["metadata"]["name"], "temp-test")
        finally:
            if temp_path.is_file():
                temp_path.unlink()


if __name__ == "__main__":
    unittest.main()
