"""Unit tests for LangGraph VettoToolNode and VettoExecutionTool."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from vetto.langgraph import ToolMessage, VettoExecutionTool, VettoToolNode
from vetto.sandbox import VettoResult, VettoSandbox, VettoSecurityError, VettoTimeoutError


class TestVettoLangGraph(unittest.TestCase):
    """Test suite for LangGraph integration components."""

    def test_execution_tool_success(self) -> None:
        mock_sandbox = MagicMock(spec=VettoSandbox)
        mock_sandbox.run.return_value = VettoResult(
            exit_code=0,
            stdout="tests passed\n",
            stderr="",
            duration_ms=45.2,
        )

        tool = VettoExecutionTool(sandbox=mock_sandbox)
        res = tool.invoke({"command": "pytest"})

        self.assertEqual(res["exit_code"], 0)
        self.assertEqual(res["stdout"], "tests passed\n")
        self.assertTrue(res["success"])
        self.assertFalse(res["violated"])
        mock_sandbox.run.assert_called_once_with(
            command="pytest", cwd=None, timeout=None, raise_on_error=False
        )

    def test_execution_tool_security_violation_flagged(self) -> None:
        mock_sandbox = MagicMock(spec=VettoSandbox)
        mock_sandbox.run.return_value = VettoResult(
            exit_code=125,
            stdout="",
            stderr="vetto: access denied to ~/.ssh/id_rsa",
            duration_ms=2.1,
            violated=True,
        )

        tool = VettoExecutionTool(sandbox=mock_sandbox)
        res = tool.invoke("cat ~/.ssh/id_rsa")

        self.assertEqual(res["exit_code"], 125)
        self.assertTrue(res["violated"])
        self.assertFalse(res["success"])
        self.assertIn("access denied", res["stderr"])

    def test_tool_node_intercepts_exit_125_fail_closed(self) -> None:
        mock_sandbox = MagicMock(spec=VettoSandbox)
        mock_sandbox.run.return_value = VettoResult(
            exit_code=125,
            stdout="",
            stderr="Blocked by Landlock LSM boundary",
            duration_ms=1.5,
            violated=True,
        )

        exec_tool = VettoExecutionTool(sandbox=mock_sandbox)
        node = VettoToolNode(tools=[exec_tool], sandbox=mock_sandbox)

        # Incoming LangGraph state message from an LLM calling vetto_sandbox_execute
        mock_ai_message = MagicMock()
        mock_ai_message.tool_calls = [
            {
                "id": "call_123",
                "name": "vetto_sandbox_execute",
                "args": {"command": "curl http://169.254.169.254/latest/meta-data/"},
            }
        ]

        state = {"messages": [mock_ai_message]}
        result_state = node.invoke(state)

        messages = result_state["messages"]
        self.assertEqual(len(messages), 1)
        tool_msg = messages[0]
        self.assertEqual(tool_msg.tool_call_id, "call_123")
        self.assertEqual(tool_msg.status, "error")
        self.assertIn("[Vetto Security Violation: Exit 125]", tool_msg.content)
        self.assertIn("Blocked by Landlock LSM boundary", tool_msg.content)

    def test_tool_node_intercepts_timeout_exit_124(self) -> None:
        mock_sandbox = MagicMock(spec=VettoSandbox)
        mock_sandbox.run.return_value = VettoResult(
            exit_code=124,
            stdout="",
            stderr="Killed on timeout",
            duration_ms=60000.0,
            timed_out=True,
        )

        exec_tool = VettoExecutionTool(sandbox=mock_sandbox)
        node = VettoToolNode(tools=[exec_tool], sandbox=mock_sandbox)

        mock_ai_message = MagicMock()
        mock_ai_message.tool_calls = [
            {
                "id": "call_456",
                "name": "vetto_sandbox_execute",
                "args": {"command": "sleep 100"},
            }
        ]

        state = {"messages": [mock_ai_message]}
        result_state = node.invoke(state)

        messages = result_state["messages"]
        self.assertEqual(len(messages), 1)
        tool_msg = messages[0]
        self.assertEqual(tool_msg.tool_call_id, "call_456")
        self.assertEqual(tool_msg.status, "error")
        self.assertIn("[Vetto Timeout: Exit 124]", tool_msg.content)

    def test_tool_node_successful_execution(self) -> None:
        mock_sandbox = MagicMock(spec=VettoSandbox)
        mock_sandbox.run.return_value = VettoResult(
            exit_code=0,
            stdout="file1.txt\nfile2.txt",
            stderr="",
            duration_ms=10.0,
        )

        exec_tool = VettoExecutionTool(sandbox=mock_sandbox)
        node = VettoToolNode(tools=[exec_tool], sandbox=mock_sandbox)

        mock_ai_message = MagicMock()
        mock_ai_message.tool_calls = [
            {
                "id": "call_789",
                "name": "vetto_sandbox_execute",
                "args": {"command": "ls"},
            }
        ]

        state = {"messages": [mock_ai_message]}
        result_state = node.invoke(state)

        messages = result_state["messages"]
        self.assertEqual(len(messages), 1)
        tool_msg = messages[0]
        self.assertEqual(tool_msg.tool_call_id, "call_789")
        self.assertEqual(tool_msg.status, "success")
        self.assertIn("file1.txt", tool_msg.content)


if __name__ == "__main__":
    unittest.main()
