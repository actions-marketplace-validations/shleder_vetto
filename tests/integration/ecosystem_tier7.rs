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

    drop(stdin);
    let _ = child.wait();
}
