//! Dedicated Anti-SSRF regression test suite:
//! Verifies fail-closed blocking of cloud metadata endpoints (AWS/GCP/Alibaba)
//! and RFC 1918 private subnets under direct connection and 3xx redirect attempts.

use crate::common::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

#[test]
fn test_anti_ssrf_direct_metadata_aws_gcp_denied() {
    if detected_tier().as_deref() != Some("full") {
        eprintln!("SKIP: anti-ssrf needs full tier");
        return;
    }
    if !tool_available("curl") {
        eprintln!("SKIP: curl not installed");
        return;
    }
    let proj = TempProject::new("anti-ssrf-aws-gcp");
    // Even with wildcard allowlist '*', cloud metadata MUST be dropped fail-closed.
    let out = run_vetto_in(
        proj.path(),
        &[
            "--tui=none",
            "--net=allowlist:*",
            "--",
            "curl",
            "-sS",
            "-m",
            "3",
            "http://169.254.169.254/latest/meta-data/",
        ],
    );
    assert!(
        !out.status.success(),
        "direct connection to AWS/GCP metadata succeeded unexpectedly! stdout: {}, stderr: {}",
        stdout(&out),
        stderr(&out)
    );
}

#[test]
fn test_anti_ssrf_direct_metadata_alibaba_denied() {
    if detected_tier().as_deref() != Some("full") {
        eprintln!("SKIP: anti-ssrf needs full tier");
        return;
    }
    if !tool_available("curl") {
        eprintln!("SKIP: curl not installed");
        return;
    }
    let proj = TempProject::new("anti-ssrf-alibaba");
    let out = run_vetto_in(
        proj.path(),
        &[
            "--tui=none",
            "--net=allowlist:*",
            "--",
            "curl",
            "-sS",
            "-m",
            "3",
            "http://100.100.100.200/latest/meta-data/",
        ],
    );
    assert!(
        !out.status.success(),
        "direct connection to Alibaba metadata succeeded unexpectedly! stdout: {}, stderr: {}",
        stdout(&out),
        stderr(&out)
    );
}

#[test]
fn test_anti_ssrf_rfc1918_private_ips_denied() {
    if detected_tier().as_deref() != Some("full") {
        eprintln!("SKIP: anti-ssrf needs full tier");
        return;
    }
    if !tool_available("curl") {
        eprintln!("SKIP: curl not installed");
        return;
    }
    let proj = TempProject::new("anti-ssrf-rfc1918");
    let targets = [
        "http://10.0.0.1:80/",
        "http://172.16.0.1:80/",
        "http://192.168.1.1:80/",
        "http://127.0.0.8:9999/",
    ];
    for target in &targets {
        let out = run_vetto_in(
            proj.path(),
            &[
                "--tui=none",
                "--net=allowlist:*",
                "--",
                "curl",
                "-sS",
                "-m",
                "3",
                target,
            ],
        );
        assert!(
            !out.status.success(),
            "connection to private IP {target} succeeded unexpectedly! stdout: {}, stderr: {}",
            stdout(&out),
            stderr(&out)
        );
    }
}

#[test]
fn test_anti_ssrf_3xx_redirect_to_metadata_dropped() {
    if detected_tier().as_deref() != Some("full") {
        eprintln!("SKIP: anti-ssrf needs full tier");
        return;
    }
    if !tool_available("curl") {
        eprintln!("SKIP: curl not installed");
        return;
    }
    // Bind mock HTTP server on host localhost (127.0.0.1:0)
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock HTTP server");
    let local_port = listener.local_addr().expect("local addr").port();
    let _ = listener.set_nonblocking(true);

    let server_handle = thread::spawn(move || {
        let start = std::time::Instant::now();
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(3)));
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf);
                    let response = "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                    break;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if start.elapsed() > std::time::Duration::from_secs(6) {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(_) => break,
            }
        }
    });

    let proj = TempProject::new("anti-ssrf-redirect");
    // Connect to mock server via localhost, following redirects (-L)
    let url = format!("http://localhost:{local_port}/test");
    let out = run_vetto_in(
        proj.path(),
        &[
            "--tui=none",
            "--net=allowlist:localhost",
            "--",
            "curl",
            "-L",
            "-sS",
            "-m",
            "5",
            &url,
        ],
    );

    let _ = server_handle.join();

    assert!(
        !out.status.success(),
        "curl following 302 redirect to metadata should have failed! stdout: {}, stderr: {}",
        stdout(&out),
        stderr(&out)
    );
    let output = stdout(&out);
    assert!(
        !output.contains("meta-data") && !output.contains("ami-id") && !output.contains("instance-id"),
        "metadata leaked via 302 redirect! stdout: {}",
        output
    );
}
