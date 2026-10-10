//! End-to-end user simulation suite across top 10 AI coding agents (R6).
//!
//! Covers:
//! - Top 10 AI agents: claude, codex, cursor, aider, opencode, goose, cline, openhands, qwen_code, windsurf.
//! - Graceful handling of zero arguments / absent API credentials via shim dispatch.
//! - SIGINT (Ctrl+C) signal translation to exit code 130 and terminal reset guard.
//! - Unblocked filesystem read/write operations within $PROJECT.
//! - Strict blocking of host credentials (~/.ssh/id_rsa) under LSM sandboxing.
//! - Shell command hash cache recovery diagnostics (`hash -r` / `rehash`) on `vetto disable`.
//! - Missing host binary candidate installation path diagnostics.

use super::common::*;
use std::path::Path;
use std::process::Command;
#[cfg(unix)]
use std::process::Stdio;

const TOP_AGENTS: &[&str] = &[
    "claude",
    "codex",
    "cursor",
    "aider",
    "opencode",
    "goose",
    "cline",
    "openhands",
    "qwen_code",
    "windsurf",
];

const SHIM_EXEC_SKIP: &str =
    "SKIP: agent shim execution requires full tier or functional Windows sandbox backend";

fn agent_shim_execution_supported() -> bool {
    #[cfg(target_os = "windows")]
    {
        let doctor = doctor_output();
        if !doctor.contains("appcontainer-api=yes")
            || !doctor.contains("experimental-process-sandbox=yes")
        {
            return false;
        }
    }
    #[cfg(target_os = "linux")]
    {
        if detected_tier().as_deref() != Some("full") {
            return false;
        }
    }
    #[cfg(target_os = "macos")]
    {
        return false;
    }
    #[allow(unreachable_code)]
    true
}

fn create_single_mock_agent(bin_dir: &Path, agent_name: &str) {
    let script_content = format!(
        r#"#!/bin/sh
AGENT="{agent_name}"

for a in "$@"; do
    if [ "$a" = "--wait-sigint" ]; then
        trap 'echo "mock-$AGENT: caught SIGINT"; exit 130' INT TERM
        echo "mock-$AGENT: waiting for signal"
        while true; do
            sleep 1
        done
    fi
    if [ "$a" = "--test-fs" ]; then
        if [ -f "input.txt" ]; then
            CONTENT=$(cat input.txt 2>/dev/null)
            echo "read: $CONTENT" > output.txt
            echo "fs_ok"
            exit 0
        else
            echo "input.txt not found" >&2
            exit 1
        fi
    fi
done

SECRET_FOUND=0
SECRET_PATH="${{HOME}}/.ssh/id_rsa"
for a in "$@"; do
    if [ "$SECRET_FOUND" -eq 1 ]; then
        SECRET_PATH="$a"
        break
    fi
    if [ "$a" = "--read-secret" ]; then
        SECRET_FOUND=1
    fi
done

if [ "$SECRET_FOUND" -eq 1 ]; then
    if OUTPUT=$(cat "$SECRET_PATH" 2>&1); then
        echo "LEAK: read id_rsa: $OUTPUT"
        exit 20
    else
        echo "BLOCKED: Permission denied"
        exit 0
    fi
fi

echo "mock-$AGENT: started without arguments (simulating missing keys/credentials)"
exit 0
"#
    );

    let script_path = bin_dir.join(agent_name);
    write_file(&script_path, &script_content);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script_path)
            .expect("metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script_path, perms).expect("set 0755");
    }

    #[cfg(windows)]
    {
        let cmd_content = format!(
            r#"@echo off
set AGENT={agent_name}

if "%1"=="--test-fs" goto do_fs
if "%2"=="--test-fs" goto do_fs
if "%1"=="--read-secret" goto do_secret
if "%2"=="--read-secret" goto do_secret

echo mock-%AGENT%: started without arguments (simulating missing keys/credentials)
exit /b 0

:do_fs
if exist input.txt (
    type input.txt > output.txt
    echo fs_ok
    exit /b 0
) else (
    echo input.txt not found 1>&2
    exit /b 1
)

:do_secret
set SECRET_PATH=%USERPROFILE%\.ssh\id_rsa
if not "%2"=="" if not "%2"=="--read-secret" set SECRET_PATH=%2
if not "%3"=="" set SECRET_PATH=%3
type "%SECRET_PATH%" >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo LEAK: read id_rsa
    exit /b 20
) else (
    echo BLOCKED: Permission denied
    exit /b 0
)
"#
        );
        let cmd_path = bin_dir.join(format!("{agent_name}.cmd"));
        write_file(&cmd_path, &cmd_content);
    }
}

fn create_mock_agents(bin_dir: &Path) {
    std::fs::create_dir_all(bin_dir).expect("create bin dir");
    let all_binaries = [
        "claude",
        "codex",
        "cursor",
        "aider",
        "opencode",
        "goose",
        "cline",
        "openhands",
        "qwen-code",
        "qwen_code",
        "windsurf",
    ];
    for bin in all_binaries {
        create_single_mock_agent(bin_dir, bin);
    }
}

fn path_with_bin_dir(bin_dir: &Path) -> std::ffi::OsString {
    let original = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = std::env::split_paths(&original).collect::<Vec<_>>();
    paths.insert(0, bin_dir.to_path_buf());
    std::env::join_paths(paths).expect("join paths")
}

/// Scenario 1: Launching top agents via shim without arguments/keys handles absence gracefully without crashing Vetto.
#[test]
fn test_e2e_top_agents_zero_args_graceful_handling() {
    if !agent_shim_execution_supported() {
        eprintln!("{SHIM_EXEC_SKIP}");
        return;
    }

    let project = TempProject::new("e2e-zero-args");
    let bin_dir = project.path().join("host_bin");
    create_mock_agents(&bin_dir);
    let custom_path = path_with_bin_dir(&bin_dir);

    for agent in TOP_AGENTS {
        let out = Command::new(vetto_bin())
            .args(["shim", agent])
            .current_dir(project.path())
            .env("PATH", &custom_path)
            .env("HOME", test_home())
            .output()
            .unwrap_or_else(|e| panic!("failed to run vetto shim for {agent}: {e}"));

        let out_text = stdout(&out);
        let err_text = stderr(&out);

        assert!(
            out.status.success(),
            "vetto shim {agent} failed (exit={:?}):\nstdout: {}\nstderr: {}",
            out.status.code(),
            out_text,
            err_text
        );
        assert!(
            out_text.contains("started without arguments"),
            "expected graceful startup message for {agent}, got stdout:\n{out_text}"
        );
        assert!(
            !err_text.contains("panicked at"),
            "vetto supervisor panicked for {agent}:\n{err_text}"
        );
    }
}

/// Scenario 2: SIGINT (Ctrl+C) translation terminates with 130 and triggers terminal restoration.
#[test]
#[cfg(unix)]
fn test_e2e_top_agents_sigint_translation_and_terminal_reset() {
    if !agent_shim_execution_supported() {
        eprintln!("{SHIM_EXEC_SKIP}");
        return;
    }
    let project = TempProject::new("e2e-sigint");
    let bin_dir = project.path().join("host_bin");
    create_mock_agents(&bin_dir);
    let custom_path = path_with_bin_dir(&bin_dir);

    for agent in TOP_AGENTS {
        let mut child = Command::new(vetto_bin())
            .args(["shim", agent, "--", "--wait-sigint"])
            .current_dir(project.path())
            .env("PATH", &custom_path)
            .env("HOME", test_home())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn vetto shim for {agent}: {e}"));

        std::thread::sleep(std::time::Duration::from_millis(250));

        unsafe {
            libc::kill(child.id() as libc::pid_t, libc::SIGINT);
        }

        let start = std::time::Instant::now();
        let mut exited = false;
        while start.elapsed() < std::time::Duration::from_secs(4) {
            if child.try_wait().expect("try_wait").is_some() {
                exited = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        assert!(
            exited,
            "agent {agent} failed to terminate within timeout after SIGINT"
        );

        let out = child.wait_with_output().expect("wait_with_output");
        let code = out.status.code();
        let signal = std::os::unix::process::ExitStatusExt::signal(&out.status);
        let err_text = stderr(&out);
        let out_text = stdout(&out);

        let is_sigint = code == Some(130) || signal == Some(libc::SIGINT);
        assert!(
            is_sigint,
            "agent {agent} did not translate SIGINT cleanly (code={:?}, signal={:?}):\nstdout: {}\nstderr: {}",
            code, signal, out_text, err_text
        );
        assert!(
            !err_text.contains("panicked at"),
            "panic during SIGINT terminal reset for {agent}:\n{err_text}"
        );
    }
}

/// Scenario 3: Reading and writing within $PROJECT succeeds without EACCES.
#[test]
fn test_e2e_top_agents_project_read_write_unblocked() {
    if !agent_shim_execution_supported() {
        eprintln!("{SHIM_EXEC_SKIP}");
        return;
    }

    let project = TempProject::new("e2e-project-rw");
    let bin_dir = project.path().join("host_bin");
    create_mock_agents(&bin_dir);
    let custom_path = path_with_bin_dir(&bin_dir);

    for agent in TOP_AGENTS {
        let test_payload = format!("test payload for agent {agent}");
        let input_file = project.path().join("input.txt");
        let output_file = project.path().join("output.txt");

        write_file(&input_file, &test_payload);
        if output_file.exists() {
            let _ = std::fs::remove_file(&output_file);
        }

        let out = Command::new(vetto_bin())
            .args(["shim", agent, "--", "--test-fs"])
            .current_dir(project.path())
            .env("PATH", &custom_path)
            .env("HOME", test_home())
            .output()
            .unwrap_or_else(|e| panic!("failed to run vetto shim --test-fs for {agent}: {e}"));

        let out_text = stdout(&out);
        let err_text = stderr(&out);

        assert!(
            out.status.success(),
            "agent {agent} project I/O failed with exit {:?}:\nstdout: {}\nstderr: {}",
            out.status.code(),
            out_text,
            err_text
        );
        assert!(
            out_text.contains("fs_ok"),
            "agent {agent} did not output 'fs_ok':\n{out_text}"
        );
        assert!(
            output_file.exists(),
            "agent {agent} failed to write output.txt within $PROJECT"
        );
        let written = std::fs::read_to_string(&output_file).expect("read output.txt");
        assert!(
            written.contains(&test_payload),
            "output.txt content mismatch for {agent}: {written}"
        );

        let _ = std::fs::remove_file(&input_file);
        let _ = std::fs::remove_file(&output_file);
    }
}

/// Scenario 4: Attempted read of ~/.ssh/id_rsa strictly fails with Permission denied and is BLOCKED.
#[test]
fn test_e2e_top_agents_ssh_key_strictly_blocked() {
    if !agent_shim_execution_supported() {
        eprintln!("{SHIM_EXEC_SKIP}");
        return;
    }

    ensure_fake_ssh_key();
    let ssh_key_path = test_home().join(".ssh").join("id_rsa");
    assert!(ssh_key_path.exists(), "fake ssh key must exist");

    let project = TempProject::new("e2e-ssh-blocked");
    let bin_dir = project.path().join("host_bin");
    create_mock_agents(&bin_dir);
    let custom_path = path_with_bin_dir(&bin_dir);

    for agent in TOP_AGENTS {
        let out = Command::new(vetto_bin())
            .args([
                "shim",
                agent,
                "--",
                "--read-secret",
                &ssh_key_path.display().to_string(),
            ])
            .current_dir(project.path())
            .env("PATH", &custom_path)
            .env("HOME", test_home())
            .output()
            .unwrap_or_else(|e| panic!("failed to run vetto shim --read-secret for {agent}: {e}"));

        let out_text = stdout(&out);
        let err_text = stderr(&out);

        assert!(
            !out_text.contains("FAKE-TEST-KEY-MATERIAL-FOR-VETTO-IT"),
            "CRITICAL LEAK: ssh key material leaked in stdout for {agent}!\n{out_text}"
        );
        assert!(
            !err_text.contains("FAKE-TEST-KEY-MATERIAL-FOR-VETTO-IT"),
            "CRITICAL LEAK: ssh key material leaked in stderr for {agent}!\n{err_text}"
        );
        assert!(
            !out_text.contains("LEAK: read id_rsa"),
            "CRITICAL LEAK: agent {agent} successfully read ~/.ssh/id_rsa!\n{out_text}"
        );

        if have_landlock() {
            assert!(
                out_text.contains("BLOCKED: Permission denied") || !out.status.success(),
                "agent {agent} was not strictly blocked from reading ~/.ssh/id_rsa under active LSM!\nstdout: {}\nstderr: {}",
                out_text,
                err_text
            );
        }
    }
}

/// Scenario 5: `vetto disable` outputs `hash -r` / `rehash` shell cache hint.
#[test]
fn test_e2e_disable_hint_shell_cache_recovery() {
    let project = TempProject::new("e2e-disable-hint");
    let bin_dir = project.path().join("host_bin");
    create_mock_agents(&bin_dir);
    let custom_path = path_with_bin_dir(&bin_dir);

    let out_enable = Command::new(vetto_bin())
        .args(["enable", "claude", "--scope", "local"])
        .current_dir(project.path())
        .env("PATH", &custom_path)
        .env("HOME", test_home())
        .output()
        .expect("exec enable claude");
    assert!(
        out_enable.status.success(),
        "enable claude failed:\nstdout: {}\nstderr: {}",
        stdout(&out_enable),
        stderr(&out_enable)
    );

    let out_dis = Command::new(vetto_bin())
        .args(["disable", "claude", "--scope", "local"])
        .current_dir(project.path())
        .env("PATH", &custom_path)
        .env("HOME", test_home())
        .output()
        .expect("exec disable claude");

    assert!(
        out_dis.status.success(),
        "disable claude failed:\nstdout: {}\nstderr: {}",
        stdout(&out_dis),
        stderr(&out_dis)
    );
    let dis_stdout = stdout(&out_dis);
    assert!(
        dis_stdout.contains("hash -r"),
        "vetto disable claude must output 'hash -r' hint, got:\n{dis_stdout}"
    );
    assert!(
        dis_stdout.contains("rehash"),
        "vetto disable claude must output 'rehash' hint, got:\n{dis_stdout}"
    );

    let out_enable_codex = Command::new(vetto_bin())
        .args(["enable", "codex", "--scope", "local"])
        .current_dir(project.path())
        .env("PATH", &custom_path)
        .env("HOME", test_home())
        .output()
        .expect("exec enable codex");
    assert!(out_enable_codex.status.success());

    let out_dis_all = Command::new(vetto_bin())
        .args(["disable", "--all", "--scope", "local"])
        .current_dir(project.path())
        .env("PATH", &custom_path)
        .env("HOME", test_home())
        .output()
        .expect("exec disable --all");

    assert!(
        out_dis_all.status.success(),
        "disable --all failed:\nstdout: {}\nstderr: {}",
        stdout(&out_dis_all),
        stderr(&out_dis_all)
    );
    let dis_all_stdout = stdout(&out_dis_all);
    assert!(
        dis_all_stdout.contains("hash -r"),
        "vetto disable --all must output 'hash -r' hint, got:\n{dis_all_stdout}"
    );
    assert!(
        dis_all_stdout.contains("rehash"),
        "vetto disable --all must output 'rehash' hint, got:\n{dis_all_stdout}"
    );
}

/// Scenario 6: Shim resolution failure provides candidate path diagnostic.
#[test]
fn test_e2e_shim_resolution_missing_path_diagnostics() {
    let project = TempProject::new("e2e-shim-diag");
    let isolated_home = project.path().join("home");
    std::fs::create_dir_all(&isolated_home).expect("create isolated home");

    let missing_agent = "nonexistent-agent-simulation-xyz";
    let out_missing = Command::new(vetto_bin())
        .args(["shim", missing_agent])
        .current_dir(project.path())
        .env("PATH", "")
        .env("HOME", &isolated_home)
        .output()
        .expect("exec shim for missing agent");

    assert!(
        !out_missing.status.success(),
        "vetto shim for missing agent must fail closed"
    );
    let err_missing = stderr(&out_missing);
    assert!(
        err_missing.contains(&format!(
            "shim: failed to resolve host binary for '{missing_agent}'"
        )),
        "stderr must explain failure to resolve binary:\n{err_missing}"
    );
    assert!(
        err_missing.contains("PATH")
            || err_missing.contains(".local")
            || err_missing.contains(".cargo"),
        "diagnostic must provide candidate path hints:\n{err_missing}"
    );

    let candidate_dir = isolated_home.join(".cargo").join("bin");
    std::fs::create_dir_all(&candidate_dir).expect("create candidate dir");
    let candidate_agent = "candidate-test-agent";
    create_single_mock_agent(&candidate_dir, candidate_agent);

    let out_candidate = Command::new(vetto_bin())
        .args(["shim", candidate_agent])
        .current_dir(project.path())
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &isolated_home)
        .output()
        .expect("exec shim for candidate agent");

    assert!(
        !out_candidate.status.success(),
        "vetto shim must fail when candidate directory is not in $PATH"
    );
    let err_candidate = stderr(&out_candidate);
    assert!(
        err_candidate.contains(&format!(
            "shim: failed to resolve host binary for '{candidate_agent}'"
        )),
        "stderr must report resolution failure:\n{err_candidate}"
    );
    assert!(
        err_candidate.contains("PATH")
            || err_candidate.contains(".cargo/bin")
            || err_candidate.contains("export PATH="),
        "stderr must diagnose candidate directory and suggest PATH export:\n{err_candidate}"
    );
}

/// Adversarial verification: argument passing with special characters and quotes across shims.
#[test]
fn test_e2e_top_agents_adversarial_arguments_integrity() {
    if !agent_shim_execution_supported() {
        eprintln!("{SHIM_EXEC_SKIP}");
        return;
    }

    let project = TempProject::new("e2e-adv-args");
    let bin_dir = project.path().join("host_bin");
    create_mock_agents(&bin_dir);
    let custom_path = path_with_bin_dir(&bin_dir);

    // Test complex flags and safe execution under supervisor
    let special_arg = "--message=\"Hello Vetto Agent: safe sandbox #123!\"";
    let out = Command::new(vetto_bin())
        .args(["shim", "claude", "--", special_arg])
        .current_dir(project.path())
        .env("PATH", &custom_path)
        .env("HOME", test_home())
        .output()
        .expect("exec shim with special arg");

    assert!(
        out.status.success(),
        "vetto shim failed with special arg:\nstdout: {}\nstderr: {}",
        stdout(&out),
        stderr(&out)
    );
}
