"""Policy builder and serializer for Vetto Policy-as-Code definitions."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Optional, Sequence, Union


class PolicyBuilder:
    """Builder for constructing Vetto TOML policies programmatically."""

    def __init__(self, name: str = "custom", description: str = "") -> None:
        self.name = name
        self.description = description
        self._allow_write: list[str] = []
        self._allow_read: list[str] = []
        self._deny_write: list[str] = []
        self._deny_read: list[str] = []
        self._net_mode: str = "allowlist"
        self._net_allowlist: list[str] = []
        self._net_deny: list[str] = []
        self._tcp_bind: list[int] = []
        self._tcp_connect: list[int] = []
        self._pass_through: list[str] = []
        self._unix_sockets_allow: list[str] = []
        self._limits: dict[str, int] = {}
        self._cgroup: dict[str, str] = {}

    def set_metadata(self, name: str, description: str = "") -> PolicyBuilder:
        self.name = name
        self.description = description
        return self

    def allow_write(self, *paths: Union[str, Path]) -> PolicyBuilder:
        for p in paths:
            self._allow_write.append(str(p))
        return self

    def allow_read(self, *paths: Union[str, Path]) -> PolicyBuilder:
        for p in paths:
            self._allow_read.append(str(p))
        return self

    def deny_write(self, *paths: Union[str, Path]) -> PolicyBuilder:
        for p in paths:
            self._deny_write.append(str(p))
        return self

    def deny_read(self, *paths: Union[str, Path]) -> PolicyBuilder:
        for p in paths:
            self._deny_read.append(str(p))
        return self

    def allow_unix_socket(self, *patterns: str) -> PolicyBuilder:
        for pat in patterns:
            self._unix_sockets_allow.append(pat)
        return self

    def set_network(
        self,
        mode: str = "allowlist",
        allowlist: Optional[Sequence[str]] = None,
        deny_network: Optional[Sequence[str]] = None,
        allow_tcp_bind: Optional[Sequence[int]] = None,
        allow_tcp_connect: Optional[Sequence[int]] = None,
    ) -> PolicyBuilder:
        self._net_mode = mode
        if allowlist:
            self._net_allowlist.extend(allowlist)
        if deny_network:
            self._net_deny.extend(deny_network)
        if allow_tcp_bind:
            self._tcp_bind.extend(allow_tcp_bind)
        if allow_tcp_connect:
            self._tcp_connect.extend(allow_tcp_connect)
        return self

    def pass_env(self, *variables: str) -> PolicyBuilder:
        for v in variables:
            self._pass_through.append(v)
        return self

    def set_limits(
        self,
        processes: Optional[int] = None,
        open_files: Optional[int] = None,
        memory_max: Optional[str] = None,
        pids_max: Optional[str] = None,
        cpu_max: Optional[str] = None,
    ) -> PolicyBuilder:
        if processes is not None:
            self._limits["processes"] = processes
        if open_files is not None:
            self._limits["open_files"] = open_files
        if memory_max is not None:
            self._cgroup["memory_max"] = memory_max
        if pids_max is not None:
            self._cgroup["pids_max"] = pids_max
        if cpu_max is not None:
            self._cgroup["cpu_max"] = cpu_max
        return self

    def to_toml(self) -> str:
        """Serialize current policy state to a valid Vetto TOML string."""
        lines = ["[metadata]"]
        lines.append(f'name = "{self.name}"')
        if self.description:
            lines.append(f'description = "{self.description}"')
        lines.append("")

        lines.append("[filesystem]")
        if self._allow_write:
            lines.append("allow_write = [")
            for w in self._allow_write:
                lines.append(f'    "{w}",')
            lines.append("]")
        if self._allow_read:
            lines.append("allow_read = [")
            for r in self._allow_read:
                lines.append(f'    "{r}",')
            lines.append("]")
        if self._deny_write:
            lines.append("deny_write = [")
            for dw in self._deny_write:
                lines.append(f'    "{dw}",')
            lines.append("]")
        if self._deny_read:
            lines.append("deny_read = [")
            for dr in self._deny_read:
                lines.append(f'    "{dr}",')
            lines.append("]")
        lines.append("")

        if self._unix_sockets_allow:
            lines.append("[unix_sockets]")
            lines.append("allow = [")
            for s in self._unix_sockets_allow:
                lines.append(f'    "{s}",')
            lines.append("]")
            lines.append("")

        lines.append("[network]")
        lines.append(f'mode = "{self._net_mode}"')
        if self._net_allowlist:
            lines.append("allowlist = [")
            for a in self._net_allowlist:
                lines.append(f'    "{a}",')
            lines.append("]")
        if self._net_deny:
            lines.append("deny_network = [")
            for d in self._net_deny:
                lines.append(f'    "{d}",')
            lines.append("]")
        if self._tcp_bind:
            lines.append(f"allow_tcp_bind = {list(self._tcp_bind)}")
        if self._tcp_connect:
            lines.append(f"allow_tcp_connect = {list(self._tcp_connect)}")
        lines.append("")

        if self._limits:
            lines.append("[limits]")
            for k, v in self._limits.items():
                lines.append(f"{k} = {v}")
            lines.append("")

        if self._cgroup:
            lines.append("[cgroup]")
            for k, v in self._cgroup.items():
                lines.append(f'{k} = "{v}"')
            lines.append("")

        if self._pass_through:
            lines.append("[environment]")
            lines.append("pass_through = [")
            for env_var in self._pass_through:
                lines.append(f'    "{env_var}",')
            lines.append("]")
            lines.append("")

        return "\n".join(lines)

    def write_to_file(self, path: Union[str, Path]) -> Path:
        """Write the policy TOML to a destination file path."""
        p = Path(path).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.to_toml(), encoding="utf-8")
        return p

    def create_temp_file(self) -> Path:
        """Write the policy to a temporary file and return the Path."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".toml", prefix="vetto_policy_", delete=False
        ) as f:
            f.write(self.to_toml())
            return Path(f.name)
