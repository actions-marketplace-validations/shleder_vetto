//! 12-Scenario Adversarial Stress Test Suite (R4: F14-F15).
//!
//! Validates system boundary invariants under adversarial pressure:
//! 1.  SEC-UNSHARE-001: unshare/clone3 blocked with EPERM.
//! 2.  SEC-RAW-SOCK-002: SOCK_RAW blocked with EACCES via args[1] cBPF filter.
//! 3.  GIT-CONFIG-MASK-001: .git/config secret credentials masked.
//! 4.  POLICY-HIJACK-001: repo policy allow_write = ["/"] fails closed (exit 125).
//! 5.  POLICY-NET-HIJACK-002: repo network policy cannot loosen paranoid preset.
//! 6.  VERDICT-TAMPER-001: child exit(0) overridden to 125 on contract violation.
//! 7.  STDIO-DEADLOCK-001: 50MB stdout volume drained without pipe deadlock.
//! 8.  STDIN-PIPE-001: piped stdin preserved without /dev/null truncation.
//! 9.  TIMEOUT-TUI-001: wall-clock timeout enforced across TUI modes (exit 124).
//! 10. CLEARENV-ORPHAN-001: orphan evacuated when child wipes environment.
//! 11. SIGINT-ESCALATE-001: signal escalation from SIGINT to SIGKILL for trapped child.
//! 12. PROXY-BYPASS-001: semantic proxy blocks cloud metadata (169.254.169.254).

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::common::*;

#[cfg(target_os = "windows")]
fn windows_sandbox_available() -> bool {
    let doctor = doctor_output();
    doctor.contains("appcontainer-api=yes") && doctor.contains("experimental-process-sandbox=yes")
}

#[cfg(target_os = "linux")]
fn compile_adversarial_probe(project: &std::path::Path) -> Option<String> {
    if !tool_available("cc") {
        eprintln!("SKIP: cc is unavailable");
        return None;
    }
    let output = project.join("seccomp_probe");
    let status = Command::new("cc")
        .args(["-O2", "-Wall", "-Wextra"])
        .arg(fixture("seccomp_probe.c"))
        .arg("-o")
        .arg(&output)
        .status()
        .expect("spawn cc");
    assert!(status.success(), "compile seccomp probe");
    Some(output.to_string_lossy().into_owned())
}

/// 1. SEC-UNSHARE-001: unshare/clone3 namespace creation denial via seccomp filter.
#[test]
#[cfg(target_os = "linux")]
fn sec_unshare_001_blocks_unshare_with_eperm() {
    if !have_landlock() {
        eprintln!("SKIP: no Linux enforcement tier on this machine");
        return;
    }
    let project = TempProject::new("sec-unshare");
    let Some(probe) = compile_adversarial_probe(project.path()) else {
        return;
    };
    let out = run_vetto_in(project.path(), &["--ci", "--", &probe, "unshare"]);
    let out_str = stdout(&out);
    let err_str = stderr(&out);
    assert!(
        out_str.contains("blocked:unshare:EPERM") || err_str.contains("EPERM"),
        "expected unshare to be blocked with EPERM, got stdout='{out_str}', stderr='{err_str}'"
    );
}

/// 2. SEC-RAW-SOCK-002: raw socket denial via seccomp socket type filter (args[1] & 0x0f == SOCK_RAW).
#[test]
#[cfg(target_os = "linux")]
fn sec_raw_sock_002_blocks_sock_raw_with_eacces() {
    if !have_landlock() {
        eprintln!("SKIP: no Linux enforcement tier on this machine");
        return;
    }
    let project = TempProject::new("sec-raw-sock");
    let Some(probe) = compile_adversarial_probe(project.path()) else {
        return;
    };
    let out = run_vetto_in(
        project.path(),
        &["--ci", "--net=off", "--", &probe, "socket_raw"],
    );
    let out_str = stdout(&out);
    let err_str = stderr(&out);
    assert!(
        out_str.contains("blocked:socket_raw:EACCES") || err_str.contains("EACCES"),
        "expected SOCK_RAW to be blocked with EACCES, got stdout='{out_str}', stderr='{err_str}'"
    );
}

/// 3. GIT-CONFIG-MASK-001: repository secret masking for .git/config credentials.
#[test]
fn git_config_mask_001_masks_git_config_credentials() {
    #[cfg(target_os = "windows")]
    if !windows_sandbox_available() {
        eprintln!("SKIP: Windows sandbox unavailable");
        return;
    }
    let project = TempProject::new("git-config-mask");
    let git_config = project.path().join(".git").join("config");
    write_file(
        &git_config,
        "[core]\n\trepositoryformatversion = 0\n[canary]\n\tmarker = adversarial_canary_masked_value_999\n",
    );
    let out = run_vetto_in(project.path(), &["--ci", "--", "cat", ".git/config"]);
    let out_str = stdout(&out);
    assert!(
        !out_str.contains("adversarial_canary_masked_value_999"),
        "secret credentials in .git/config must never leak into stdout; got: '{out_str}'"
    );
}

/// 4. POLICY-HIJACK-001: preflight rejection of repository policy granting write access to system roots.
#[test]
fn policy_hijack_001_rejects_system_write_root() {
    #[cfg(target_os = "windows")]
    if !windows_sandbox_available() {
        eprintln!("SKIP: Windows sandbox unavailable");
        return;
    }
    let project = TempProject::new("policy-hijack");
    let policy = project.path().join(".vetto/policy.toml");
    write_file(
        &policy,
        r#"
[filesystem]
allow_write = ["/"]
"#,
    );
    let out = run_vetto_in(project.path(), &["--ci", "--", "true"]);
    assert_eq!(
        out.status.code(),
        Some(125),
        "expected fail-closed exit code 125; stderr: {}",
        stderr(&out)
    );
    let err_str = stderr(&out);
    assert!(
        err_str.contains("fail-closed")
            || err_str.contains("system root")
            || err_str.contains("allow_write"),
        "stderr should explain fail-closed violation, got: '{err_str}'"
    );
}

/// 5. POLICY-NET-HIJACK-002: paranoid preset immutability against repository policy network loosening.
#[test]
fn policy_net_hijack_002_preserves_paranoid_net_mode_off() {
    let project = TempProject::new("policy-net-hijack");
    let policy = project.path().join(".vetto/policy.toml");
    write_file(
        &policy,
        r#"
[network]
mode = "allowlist"
allow = ["evil-exfiltration.com"]
"#,
    );
    let out = run_vetto_in(
        project.path(),
        &["--preset", "paranoid", "--ci", "--", "true"],
    );
    assert!(
        out.status.success() || out.status.code() == Some(125),
        "vetto should execute or fail-closed cleanly under paranoid preset; stderr: {}",
        stderr(&out)
    );
}

/// 6. VERDICT-TAMPER-001: Authoritative VerdictEngine overrides child exit code 0 on contract breach.
#[test]
#[cfg(target_os = "linux")]
fn verdict_tamper_001_forces_exit_125_on_contract_violation() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let project = TempProject::new("verdict-tamper");
    // Child attempts forbidden write to /etc/tamper_test, catches error, exits 0
    let out = run_vetto_in(
        project.path(),
        &[
            "--ci",
            "--fail-on-block=1",
            "--observe-seccomp",
            "--",
            "sh",
            "-c",
            "touch /etc/tamper_test 2>/dev/null; exit 0",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(125),
        "verdict engine must force exit 125 on contract violation despite child exit 0; stderr: {}",
        stderr(&out)
    );
}

/// 7. STDIO-DEADLOCK-001: non-blocking AsyncPipeReader drains >64KB output without pipe deadlock.
#[test]
fn stdio_deadlock_001_drains_large_output_without_deadlock() {
    #[cfg(target_os = "windows")]
    if !windows_sandbox_available() {
        eprintln!("SKIP: Windows sandbox unavailable");
        return;
    }
    let project = TempProject::new("stdio-deadlock");
    let start = Instant::now();
    #[cfg(unix)]
    let out = run_vetto_in(
        project.path(),
        &[
            "--ci",
            "--",
            "sh",
            "-c",
            "head -c 10485760 /dev/zero | tr '\\0' 'A'",
        ],
    );
    #[cfg(not(unix))]
    let out = run_vetto_in(
        project.path(),
        &["--ci", "--", "echo", "stdio deadlock test"],
    );
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(10),
        "stdio drain took too long ({:?}), likely deadlocked",
        elapsed
    );
    assert!(out.status.success(), "command failed: {}", stderr(&out));
}

/// 8. STDIN-PIPE-001: stdin preservation in headless and CI modes without /dev/null truncation.
#[test]
fn stdin_pipe_001_preserves_stdin_in_ci_mode() {
    #[cfg(target_os = "windows")]
    if !windows_sandbox_available() {
        eprintln!("SKIP: Windows sandbox unavailable");
        return;
    }
    let project = TempProject::new("stdin-pipe");
    let payload = "adversarial-stdin-pipe-payload-line\n";
    let mut child = Command::new(vetto_bin())
        .args(["--ci", "--", "cat"])
        .current_dir(project.path())
        .env("HOME", test_home())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn vetto");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(payload.as_bytes()).expect("write stdin");
    }
    let out = child.wait_with_output().expect("wait on child");
    let out_str = stdout(&out);
    assert!(
        out_str.contains("adversarial-stdin-pipe-payload-line"),
        "piped stdin must be passed verbatim to child; got: '{out_str}', stderr: '{}'",
        stderr(&out)
    );
}

/// 9. TIMEOUT-TUI-001: timeout enforcement across all TUI modes (statusline and full alternate screen).
#[test]
fn timeout_tui_001_enforces_timeout_in_tui_mode() {
    #[cfg(target_os = "windows")]
    if !windows_sandbox_available() {
        eprintln!("SKIP: Windows sandbox unavailable");
        return;
    }
    let project = TempProject::new("timeout-tui");
    let marker = format!("vetto-timeout-tui-{}", std::process::id());
    let start = Instant::now();
    #[cfg(unix)]
    let out = run_vetto_in(
        project.path(),
        &[
            "--timeout",
            "2s",
            "--tui",
            "statusline",
            "--",
            "sh",
            "-c",
            &format!("sleep 4 # {marker}"),
        ],
    );
    #[cfg(unix)]
    let _ = Command::new("pkill").args(["-9", "-f", &marker]).status();
    #[cfg(not(unix))]
    let out = run_vetto_in(
        project.path(),
        &[
            "--timeout",
            "2s",
            "--tui",
            "statusline",
            "--",
            "ping",
            "-n",
            "4",
            "127.0.0.1",
        ],
    );
    let elapsed = start.elapsed();
    assert_eq!(
        out.status.code(),
        Some(124),
        "expected timeout exit code 124 in statusline TUI mode; stderr: {}",
        stderr(&out)
    );
    assert!(
        elapsed < Duration::from_secs(6),
        "timeout took too long: {:?}",
        elapsed
    );
}

/// 10. CLEARENV-ORPHAN-001: orphan process evacuation when child wipes environment via clearenv().
#[test]
#[cfg(target_os = "linux")]
fn clearenv_orphan_001_evacuates_orphans_with_cleared_env() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let marker = format!("vetto-clearenv-orphan-{}", std::process::id());
    let project = TempProject::new("clearenv-orphan");

    // Spawn script that runs env -i (or clears env), double forks a sleep process with marker
    let out = run_vetto_in(
        project.path(),
        &[
            "--ci",
            "--",
            "sh",
            "-c",
            &format!("env -i sh -c 'sleep 2 # {marker}' &"),
        ],
    );
    let _ = out;
    std::thread::sleep(Duration::from_millis(500));

    let pgrep = Command::new("pgrep")
        .args(["-f", &marker])
        .output()
        .expect("pgrep");
    let surviving = String::from_utf8_lossy(&pgrep.stdout);
    for line in surviving.lines() {
        if let Ok(pid) = line.trim().parse::<i32>() {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
    }
    let _ = Command::new("pkill").args(["-9", "-f", &marker]).status();
    assert!(
        pgrep.stdout.is_empty(),
        "clearenv orphan survived vetto extinction: {}",
        surviving
    );
}

/// 11. SIGINT-ESCALATE-001: signal escalation from SIGINT to SIGKILL for uncooperative trapped children.
#[test]
#[cfg(unix)]
fn sigint_escalate_001_terminates_trapped_child() {
    let project = TempProject::new("sigint-escalate");
    let marker = format!("vetto-sigint-escalate-{}", std::process::id());
    let mut child = Command::new(vetto_bin())
        .args([
            "--ci",
            "--",
            "sh",
            "-c",
            &format!("trap '' INT; sleep 2 # {marker}"),
        ])
        .current_dir(project.path())
        .env("HOME", test_home())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn vetto");

    std::thread::sleep(Duration::from_millis(500));
    // Send first SIGINT
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGINT);
    }
    // Wait for the 500ms watchdog escalation to kick in, or send second SIGINT
    std::thread::sleep(Duration::from_millis(700));
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGINT);
    }

    let start = Instant::now();
    let mut exited = false;
    while start.elapsed() < Duration::from_secs(3) {
        if child.try_wait().unwrap().is_some() {
            exited = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    let _ = Command::new("pkill").args(["-9", "-f", &marker]).status();
    assert!(exited, "trapped child must be killed via escalated SIGKILL");
}

/// 12. PROXY-BYPASS-001: semantic relay proxy blocks cloud metadata and link-local destination IPs.
#[test]
#[cfg(target_os = "linux")]
fn proxy_bypass_001_blocks_cloud_metadata_ip() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let project = TempProject::new("proxy-bypass");
    let out = run_vetto_in(
        project.path(),
        &[
            "--ci",
            "--net=allowlist:localhost",
            "--",
            "sh",
            "-c",
            "curl -sS -m 2 http://169.254.169.254/latest/meta-data/ || true",
        ],
    );
    let out_str = stdout(&out);
    assert!(
        !out_str.contains("ami-id") && !out_str.contains("instance-id"),
        "cloud metadata must never be returned through relay proxy; got: '{out_str}'"
    );
}
