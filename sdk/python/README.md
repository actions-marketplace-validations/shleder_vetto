# Vetto Python SDK (`vetto-python`)

Official Python programmatic interface and LangGraph integration for the Vetto sandbox runtime.

Vetto provides daemon-less, rootless kernel execution boundaries between `fork()` and `execve()` using Linux Landlock LSM (ABI 1–6), mount/PID/network namespaces, seccomp-BPF filters, and macOS Seatbelt.

## Installation

```bash
pip install vetto-python
```

Requires `vetto` binary installed on the host:
```bash
cargo install vetto
# or
npm install -g @shledery/vetto
```

## Quickstart

```python
from vetto import VettoSandbox, VettoSecurityError, VettoTimeoutError

# Initialize sandbox with filesystem and network boundaries
sandbox = VettoSandbox(
    profile="default",
    allow_write=["/tmp/scratch"],
    allow_read=["/usr", "/lib"],
    net="off",
    timeout_seconds=30.0,
)

# Run a command synchronously
result = sandbox.run(["python3", "-c", "print('inside sandbox')"])
print(result.exit_code)  # 0
print(result.stdout)     # inside sandbox
print(result.duration_ms)

# Fail-closed Exit 125 handling
try:
    sandbox.run(["rm", "-rf", "/etc/hosts"], raise_on_error=True)
except VettoSecurityError as err:
    print(f"Blocked by policy: exit code {err.result.exit_code}")
```

## Exit Code Semantics

The SDK strictly maps Vetto kernel-level exit codes:

| Exit Code | Meaning | SDK Attribute / Exception |
|-----------|---------|---------------------------|
| `0` | Clean execution | `result.success == True` |
| `124` | Wall-clock execution timeout | `result.timed_out == True`, raises `VettoTimeoutError` |
| `125` | Fail-closed security violation | `result.violated == True`, raises `VettoSecurityError` |
| `1..123` | Child process failure | `result.exit_code > 0` |

## LangGraph Drop-in Integration

Use `VettoToolNode` to execute agent tool calls inside rootless Vetto sandboxes:

```python
from langgraph.graph import StateGraph, MessagesState
from vetto import VettoSandbox, VettoToolNode, VettoExecutionTool

sandbox = VettoSandbox(
    allow_write=["./workspace"],
    net="allowlist",
    allowed_domains=["api.anthropic.com", "github.com"],
)

# Execution tool runnable by LLM agents
exec_tool = VettoExecutionTool(sandbox=sandbox)

# Drop-in ToolNode for LangGraph
tools = [exec_tool]
tool_node = VettoToolNode(tools=tools, sandbox=sandbox)

graph = StateGraph(MessagesState)
graph.add_node("tools", tool_node)
```

When an agent attempts a forbidden action (such as modifying `.env` or accessing `~/.ssh`), `VettoToolNode` returns a structured `ToolMessage` with status `error`:
```
[Vetto Security Violation: Exit 125] Action blocked by kernel sandbox policy.
```

## Programmatic Policy Generation

```python
from vetto import PolicyBuilder

policy = (
    PolicyBuilder("custom-agent")
    .allow_write("./packages", "./apps", "/tmp")
    .allow_read("/usr", "/lib", "./")
    .deny_write(".git", "package.json")
    .deny_read("~/.ssh", "~/.aws", ".env")
    .set_network(mode="allowlist", allowlist=["registry.npmjs.org"])
    .set_limits(processes=64, open_files=512, memory_max="1G")
)

# Export to TOML string or write to file
toml_str = policy.to_toml()
policy.write_to_file(".vetto/policy.toml")
```
