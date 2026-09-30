"""LangGraph and LangChain execution adapters for Vetto sandbox containment."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional, Sequence, Union

from vetto.sandbox import VettoResult, VettoSandbox, VettoSecurityError, VettoTimeoutError

# Optional import of langchain_core with graceful fallback
try:
    from langchain_core.messages import ToolMessage
except ImportError:

    @dataclass
    class ToolMessage:  # type: ignore[no-redef]
        """Fallback ToolMessage compatible with LangGraph state graphs."""

        content: str
        tool_call_id: str
        name: Optional[str] = None
        status: str = "success"

        def to_dict(self) -> dict[str, Any]:
            return {
                "type": "tool",
                "content": self.content,
                "tool_call_id": self.tool_call_id,
                "name": self.name,
                "status": self.status,
            }


class VettoExecutionTool:
    """Drop-in tool runner executing commands inside a Vetto kernel sandbox."""

    name: str = "vetto_sandbox_execute"
    description: str = (
        "Execute a system command or script inside the rootless Vetto security sandbox. "
        "Enforces kernel Landlock LSM, seccomp-BPF filters, and process isolation. "
        "Returns stdout, stderr, exit_code, and violation metadata."
    )

    def __init__(
        self,
        sandbox: Optional[VettoSandbox] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        working_dir: Optional[str] = None,
    ) -> None:
        """Initialize the Vetto execution tool.

        Args:
            sandbox: Configured VettoSandbox instance or default.
            name: Custom tool name override.
            description: Custom tool description override.
            working_dir: Root execution directory.
        """
        self.sandbox = sandbox or VettoSandbox(working_dir=working_dir)
        if name:
            self.name = name
        if description:
            self.description = description

    def __call__(self, command: Union[str, Sequence[str]], **kwargs: Any) -> dict[str, Any]:
        return self.invoke(command, **kwargs)

    def invoke(
        self,
        input: Union[str, Mapping[str, Any]],
        config: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Execute command synchronously within the sandbox.

        Args:
            input: Command string or dict containing 'command' / 'cmd'.
            config: Optional LangChain runtime config.

        Returns:
            Dictionary containing execution outcome.
        """
        cmd: Union[str, Sequence[str]]
        cwd: Optional[str] = None
        timeout: Optional[float] = None

        if isinstance(input, str):
            cmd = input
        elif isinstance(input, Mapping):
            cmd = input.get("command") or input.get("cmd") or input.get("args") or []
            cwd = input.get("cwd") or input.get("working_dir")
            timeout = input.get("timeout")
        else:
            cmd = str(input)

        result: VettoResult = self.sandbox.run(
            command=cmd,
            cwd=cwd,
            timeout=timeout,
            raise_on_error=False,
        )

        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.exit_code,
            "duration_ms": result.duration_ms,
            "violated": result.violated,
            "timed_out": result.timed_out,
            "success": result.success,
        }

    async def ainvoke(
        self,
        input: Union[str, Mapping[str, Any]],
        config: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Execute command asynchronously within the sandbox."""
        cmd: Union[str, Sequence[str]]
        cwd: Optional[str] = None
        timeout: Optional[float] = None

        if isinstance(input, str):
            cmd = input
        elif isinstance(input, Mapping):
            cmd = input.get("command") or input.get("cmd") or input.get("args") or []
            cwd = input.get("cwd") or input.get("working_dir")
            timeout = input.get("timeout")
        else:
            cmd = str(input)

        result: VettoResult = await self.sandbox.run_async(
            command=cmd,
            cwd=cwd,
            timeout=timeout,
            raise_on_error=False,
        )

        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.exit_code,
            "duration_ms": result.duration_ms,
            "violated": result.violated,
            "timed_out": result.timed_out,
            "success": result.success,
        }


class VettoToolNode:
    """Drop-in LangGraph ToolNode wrapper enforcing Vetto containment on tool calls."""

    def __init__(
        self,
        tools: Sequence[Any],
        sandbox: Optional[VettoSandbox] = None,
        handle_tool_errors: bool = True,
        messages_key: str = "messages",
    ) -> None:
        """Initialize the LangGraph VettoToolNode.

        Args:
            tools: Sequence of callable tools or LangChain tools.
            sandbox: Shared VettoSandbox instance for execution.
            handle_tool_errors: Catch Exit 124/125 and return structured error messages.
            messages_key: State dictionary key storing conversation messages.
        """
        self.sandbox = sandbox or VettoSandbox()
        self.handle_tool_errors = handle_tool_errors
        self.messages_key = messages_key
        self.tools_by_name: dict[str, Any] = {}

        for tool in tools:
            name = getattr(tool, "name", None) or getattr(tool, "__name__", str(tool))
            self.tools_by_name[name] = tool

        # If no execution tool registered, register default vetto_sandbox_execute
        if "vetto_sandbox_execute" not in self.tools_by_name:
            default_exec = VettoExecutionTool(sandbox=self.sandbox)
            self.tools_by_name[default_exec.name] = default_exec

    def __call__(self, state: Union[dict[str, Any], list[Any]], **kwargs: Any) -> dict[str, Any]:
        return self.invoke(state, **kwargs)

    def invoke(self, state: Union[dict[str, Any], list[Any]], **kwargs: Any) -> dict[str, Any]:
        """Process incoming LangGraph state, executing tool calls under sandbox boundaries.

        Args:
            state: State dict or list of messages.

        Returns:
            State update dictionary with resulting ToolMessage instances.
        """
        messages = state.get(self.messages_key, []) if isinstance(state, dict) else state
        if not messages:
            return {self.messages_key: []}

        last_message = messages[-1]
        tool_calls = getattr(last_message, "tool_calls", None)
        if not tool_calls and isinstance(last_message, dict):
            tool_calls = last_message.get("tool_calls", [])

        if not tool_calls:
            return {self.messages_key: []}

        output_messages: list[Any] = []
        for call in tool_calls:
            tool_id = call.get("id") or call.get("tool_call_id") or ""
            name = call.get("name") or ""
            args = call.get("args") or {}

            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    args = {"command": args}

            tool = self.tools_by_name.get(name)
            if not tool:
                msg = ToolMessage(
                    content=f"Error: Tool '{name}' not found in VettoToolNode registry.",
                    tool_call_id=tool_id,
                    name=name,
                    status="error",
                )
                output_messages.append(msg)
                continue

            try:
                # Execute tool
                if hasattr(tool, "invoke"):
                    raw_out = tool.invoke(args)
                elif callable(tool):
                    raw_out = tool(**args) if isinstance(args, dict) else tool(args)
                else:
                    raw_out = str(tool)

                content_str = (
                    json.dumps(raw_out, default=str)
                    if isinstance(raw_out, (dict, list))
                    else str(raw_out)
                )

                # Check for Vetto violation in structured output
                if isinstance(raw_out, dict):
                    if raw_out.get("violated") or raw_out.get("exit_code") == 125:
                        output_messages.append(
                            ToolMessage(
                                content=(
                                    f"[Vetto Security Violation: Exit 125] Action blocked by kernel sandbox policy.\n"
                                    f"Stderr: {raw_out.get('stderr', '')}"
                                ),
                                tool_call_id=tool_id,
                                name=name,
                                status="error",
                            )
                        )
                        continue
                    if raw_out.get("timed_out") or raw_out.get("exit_code") == 124:
                        output_messages.append(
                            ToolMessage(
                                content=(
                                    f"[Vetto Timeout: Exit 124] Execution exceeded deadline.\n"
                                    f"Stderr: {raw_out.get('stderr', '')}"
                                ),
                                tool_call_id=tool_id,
                                name=name,
                                status="error",
                            )
                        )
                        continue

                output_messages.append(
                    ToolMessage(
                        content=content_str,
                        tool_call_id=tool_id,
                        name=name,
                        status="success",
                    )
                )
            except VettoSecurityError as sec_err:
                if self.handle_tool_errors:
                    output_messages.append(
                        ToolMessage(
                            content=f"[Vetto Security Violation: Exit 125] Blocked: {sec_err}",
                            tool_call_id=tool_id,
                            name=name,
                            status="error",
                        )
                    )
                else:
                    raise
            except VettoTimeoutError as time_err:
                if self.handle_tool_errors:
                    output_messages.append(
                        ToolMessage(
                            content=f"[Vetto Timeout: Exit 124] Timed out: {time_err}",
                            tool_call_id=tool_id,
                            name=name,
                            status="error",
                        )
                    )
                else:
                    raise
            except Exception as exc:
                if self.handle_tool_errors:
                    output_messages.append(
                        ToolMessage(
                            content=f"[Vetto Tool Execution Error] {exc}",
                            tool_call_id=tool_id,
                            name=name,
                            status="error",
                        )
                    )
                else:
                    raise

        return {self.messages_key: output_messages}

    async def ainvoke(
        self, state: Union[dict[str, Any], list[Any]], **kwargs: Any
    ) -> dict[str, Any]:
        """Asynchronously process incoming LangGraph state."""
        messages = state.get(self.messages_key, []) if isinstance(state, dict) else state
        if not messages:
            return {self.messages_key: []}

        last_message = messages[-1]
        tool_calls = getattr(last_message, "tool_calls", None)
        if not tool_calls and isinstance(last_message, dict):
            tool_calls = last_message.get("tool_calls", [])

        if not tool_calls:
            return {self.messages_key: []}

        output_messages: list[Any] = []
        for call in tool_calls:
            tool_id = call.get("id") or call.get("tool_call_id") or ""
            name = call.get("name") or ""
            args = call.get("args") or {}

            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    args = {"command": args}

            tool = self.tools_by_name.get(name)
            if not tool:
                msg = ToolMessage(
                    content=f"Error: Tool '{name}' not found in VettoToolNode registry.",
                    tool_call_id=tool_id,
                    name=name,
                    status="error",
                )
                output_messages.append(msg)
                continue

            try:
                if hasattr(tool, "ainvoke"):
                    raw_out = await tool.ainvoke(args)
                elif hasattr(tool, "invoke"):
                    raw_out = tool.invoke(args)
                elif callable(tool):
                    raw_out = tool(**args) if isinstance(args, dict) else tool(args)
                else:
                    raw_out = str(tool)

                content_str = (
                    json.dumps(raw_out, default=str)
                    if isinstance(raw_out, (dict, list))
                    else str(raw_out)
                )

                if isinstance(raw_out, dict):
                    if raw_out.get("violated") or raw_out.get("exit_code") == 125:
                        output_messages.append(
                            ToolMessage(
                                content=(
                                    f"[Vetto Security Violation: Exit 125] Action blocked by kernel sandbox policy.\n"
                                    f"Stderr: {raw_out.get('stderr', '')}"
                                ),
                                tool_call_id=tool_id,
                                name=name,
                                status="error",
                            )
                        )
                        continue
                    if raw_out.get("timed_out") or raw_out.get("exit_code") == 124:
                        output_messages.append(
                            ToolMessage(
                                content=(
                                    f"[Vetto Timeout: Exit 124] Execution exceeded deadline.\n"
                                    f"Stderr: {raw_out.get('stderr', '')}"
                                ),
                                tool_call_id=tool_id,
                                name=name,
                                status="error",
                            )
                        )
                        continue

                output_messages.append(
                    ToolMessage(
                        content=content_str,
                        tool_call_id=tool_id,
                        name=name,
                        status="success",
                    )
                )
            except VettoSecurityError as sec_err:
                if self.handle_tool_errors:
                    output_messages.append(
                        ToolMessage(
                            content=f"[Vetto Security Violation: Exit 125] Blocked: {sec_err}",
                            tool_call_id=tool_id,
                            name=name,
                            status="error",
                        )
                    )
                else:
                    raise
            except VettoTimeoutError as time_err:
                if self.handle_tool_errors:
                    output_messages.append(
                        ToolMessage(
                            content=f"[Vetto Timeout: Exit 124] Timed out: {time_err}",
                            tool_call_id=tool_id,
                            name=name,
                            status="error",
                        )
                    )
                else:
                    raise
            except Exception as exc:
                if self.handle_tool_errors:
                    output_messages.append(
                        ToolMessage(
                            content=f"[Vetto Tool Execution Error] {exc}",
                            tool_call_id=tool_id,
                            name=name,
                            status="error",
                        )
                    )
                else:
                    raise

        return {self.messages_key: output_messages}
