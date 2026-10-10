use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use serde_json::json;

use super::common::vetto_bin;

#[test]
fn test_mcp_server_stdio_protocol() {
    let mut child = Command::new(vetto_bin())
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn vetto mcp");

    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let mut reader = BufReader::new(stdout);

    // 1. Send initialize
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    });
    writeln!(stdin, "{}", init_req).expect("write init");
    stdin.flush().expect("flush");

    let mut line = String::new();
    reader.read_line(&mut line).expect("read init response");
    let resp: serde_json::Value = serde_json::from_str(&line).expect("parse init resp");
    assert_eq!(resp["jsonrpc"], "2.0");
    assert_eq!(resp["id"], 1);
    assert_eq!(resp["result"]["serverInfo"]["name"], "vetto");

    // 2. Send tools/list
    let list_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list"
    });
    writeln!(stdin, "{}", list_req).expect("write tools/list");
    stdin.flush().expect("flush");

    line.clear();
    reader.read_line(&mut line).expect("read tools/list resp");
    let resp: serde_json::Value = serde_json::from_str(&line).expect("parse tools resp");
    assert_eq!(resp["id"], 2);
    let tools = resp["result"]["tools"].as_array().expect("tools array");
    assert_eq!(tools[0]["name"], "run_sandboxed");

    // 3. Send tools/call for unknown tool to verify clean JSON-RPC error response
    let call_err_req = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "non_existent_tool",
            "arguments": {}
        }
    });
    writeln!(stdin, "{}", call_err_req).expect("write tools/call err");
    stdin.flush().expect("flush");

    line.clear();
    reader
        .read_line(&mut line)
        .expect("read tools/call err resp");
    let resp_err: serde_json::Value =
        serde_json::from_str(&line).expect("parse tools/call err resp");
    assert_eq!(resp_err["id"], 3);
    assert!(
        resp_err.get("error").is_some() || resp_err["result"]["isError"] == true,
        "expected error response for unknown tool: {resp_err}"
    );

    drop(stdin);
    let _ = child.wait();
}

#[test]
fn test_mcp_wrap_stdio_hermeticity_and_stderr_redirection() {
    // 1. `vetto mcp wrap --help` must succeed with exit code 0
    let help_out = Command::new(vetto_bin())
        .args(["mcp", "wrap", "--help"])
        .output()
        .expect("exec vetto mcp wrap --help");

    assert!(
        help_out.status.success(),
        "vetto mcp wrap --help must succeed"
    );
    let help_text = String::from_utf8_lossy(&help_out.stdout);
    assert!(help_text.contains("vetto mcp wrap"));

    // 2. Wrap command test: verify stdout is hermetic and receives only the child stdout
    #[cfg(unix)]
    {
        let wrap_out = Command::new(vetto_bin())
            .args([
                "mcp",
                "wrap",
                "--",
                "echo",
                "{\"jsonrpc\":\"2.0\",\"id\":1}",
            ])
            .output()
            .expect("exec vetto mcp wrap echo");

        assert!(
            wrap_out.status.success(),
            "mcp wrap failed: {}",
            String::from_utf8_lossy(&wrap_out.stderr)
        );
        let stdout_str = String::from_utf8_lossy(&wrap_out.stdout);
        assert!(
            stdout_str.contains("{\"jsonrpc\":\"2.0\",\"id\":1}"),
            "stdout must contain child output: {stdout_str}"
        );
        // Ensure no Vetto banners leaked into stdout
        assert!(
            !stdout_str.contains("[vetto]"),
            "stdout must not contain vetto banners: {stdout_str}"
        );
        assert!(
            !stdout_str.contains("vetto v"),
            "stdout must not contain version banner: {stdout_str}"
        );
    }
}
