//! Comprehensive verification of all 30 Clap CLI subcommands (Goal 3.1 & Goal 3.2).
//!
//! Validates:
//! 1. Parameterized `--help` parsing for ALL 30 subcommands (18 public, 12 hidden),
//!    guaranteeing exit code 0 and valid help text.
//! 2. Top-level `--help` structure and visibility contract (hidden subcommands hidden).
//! 3. Shell completions generation for all 5 supported shells (bash, zsh, fish, powershell, elvish).
//! 4. Man page generation (`vetto man`).
//! 5. Signal translation constants & exit code assertions (130 for SIGINT, 143 for SIGTERM).
//! 6. Bare launch zero-arg verification (`vetto` with 0 args returns summary and exit code 0).
//! 7. Bare launch in empty directory vs directory with agent preset.

use crate::common::*;
use std::process::Command;
use vetto::exit_codes::{
    map_session_exit_code, EXIT_COMMAND_NOT_FOUND, EXIT_FAIL_CLOSED, EXIT_SIGNAL_BASE,
    EXIT_SUCCESS, EXIT_TIMEOUT,
};

/// All 30 subcommands specified in `src/cli.rs`.
const ALL_30_SUBCOMMANDS: &[&str] = &[
    // 18 Public subcommands
    "mask",
    "enable",
    "disable",
    "allow",
    "deny",
    "doctor",
    "status",
    "kill",
    "verify",
    "run",
    "undo",
    "ephemeral",
    "bench",
    "diff",
    "watchdog",
    "completions",
    "man",
    "shell-env",
    // 12 Hidden subcommands
    "init",
    "hook",
    "mcp",
    "shim",
    "redteam",
    "policy",
    "scan-secrets",
    "events",
    "audit",
    "diff-sessions",
    "replay",
    "ssh-proxy",
];

const HIDDEN_SUBCOMMANDS: &[&str] = &[
    "init",
    "hook",
    "mcp",
    "shim",
    "redteam",
    "policy",
    "scan-secrets",
    "events",
    "audit",
    "diff-sessions",
    "replay",
    "ssh-proxy",
];

#[test]
fn test_all_30_subcommands_help_parsing() {
    assert_eq!(
        ALL_30_SUBCOMMANDS.len(),
        30,
        "Specification requires exactly 30 subcommands"
    );

    for &subcmd in ALL_30_SUBCOMMANDS {
        let out = Command::new(vetto_bin())
            .args([subcmd, "--help"])
            .output()
            .unwrap_or_else(|e| panic!("failed to execute `vetto {subcmd} --help`: {e}"));

        assert!(
            out.status.success(),
            "`vetto {subcmd} --help` failed with {}: {}",
            exit_diagnosis(&out),
            stderr(&out)
        );

        let help_text = stdout(&out);
        assert!(
            !help_text.is_empty(),
            "`vetto {subcmd} --help` returned empty stdout"
        );
        assert!(
            help_text.contains("Usage:") || help_text.contains("vetto"),
            "`vetto {subcmd} --help` missing usage text: {help_text}"
        );
    }
}

#[test]
fn test_top_level_help_and_hidden_commands_contract() {
    let out = Command::new(vetto_bin())
        .arg("--help")
        .output()
        .expect("execute vetto --help");

    assert!(out.status.success(), "vetto --help must succeed");
    let help_text = stdout(&out);

    // Verify key public subcommands are visible in top-level help
    assert!(help_text.contains("Commands:"), "missing Commands section");
    assert!(
        help_text.contains("enable"),
        "enable must be listed in help"
    );
    assert!(
        help_text.contains("disable"),
        "disable must be listed in help"
    );
    assert!(
        help_text.contains("doctor"),
        "doctor must be listed in help"
    );
    assert!(
        help_text.contains("status"),
        "status must be listed in help"
    );
    assert!(help_text.contains("allow"), "allow must be listed in help");
    assert!(help_text.contains("deny"), "deny must be listed in help");
    assert!(help_text.contains("run"), "run must be listed in help");
    assert!(help_text.contains("bench"), "bench must be listed in help");

    // Verify hidden subcommands are NOT exposed in top-level commands listing
    for &hidden in HIDDEN_SUBCOMMANDS {
        let needle = format!("\n  {hidden} ");
        assert!(
            !help_text.contains(&needle),
            "hidden subcommand '{hidden}' should not appear in main --help listing"
        );
    }
}

#[test]
fn test_shell_completions_generation_all_shells() {
    let shells = [
        ("bash", "complete"),
        ("zsh", "compdef"),
        ("fish", "complete"),
        ("powershell", "Register-ArgumentCompleter"),
        ("elvish", "edit:completion"),
    ];

    for (shell, marker) in shells {
        let out = Command::new(vetto_bin())
            .args(["completions", shell])
            .output()
            .unwrap_or_else(|e| panic!("failed to run `vetto completions {shell}`: {e}"));

        assert!(
            out.status.success(),
            "`vetto completions {shell}` failed: {}",
            stderr(&out)
        );

        let content = stdout(&out);
        assert!(
            content.contains(marker),
            "completions for {shell} missing marker '{marker}': {content}"
        );
    }
}

#[test]
fn test_man_page_generation() {
    let out = Command::new(vetto_bin())
        .arg("man")
        .output()
        .expect("execute vetto man");

    assert!(out.status.success(), "vetto man failed: {}", stderr(&out));
    let man_text = stdout(&out);
    assert!(
        man_text.contains(".TH") && man_text.contains("VETTO"),
        "vetto man output does not look like roff man page: {man_text}"
    );
}

#[test]
fn test_signal_translation_constants_and_exit_codes() {
    // Exact mapping assertions
    assert_eq!(EXIT_SUCCESS, 0);
    assert_eq!(EXIT_TIMEOUT, 124);
    assert_eq!(EXIT_FAIL_CLOSED, 125);
    assert_eq!(EXIT_COMMAND_NOT_FOUND, 127);
    assert_eq!(EXIT_SIGNAL_BASE, 128);

    // SIGINT (2) -> 128 + 2 = 130
    assert_eq!(map_session_exit_code(-2, false, false), 130);

    // SIGTERM (15) -> 128 + 15 = 143
    assert_eq!(map_session_exit_code(-15, false, false), 143);

    // SIGKILL (9) -> 128 + 9 = 137
    assert_eq!(map_session_exit_code(-9, false, false), 137);

    // Timeout dominant
    assert_eq!(map_session_exit_code(0, true, false), 124);
    assert_eq!(map_session_exit_code(-15, true, false), 124);

    // Fail-closed dominant
    assert_eq!(map_session_exit_code(125, false, false), 125);
    assert_eq!(map_session_exit_code(125, true, true), 125);
}

#[test]
fn test_bare_launch_zero_arg_in_empty_directory() {
    let project = TempProject::new("bare-empty");
    let proj_dir = project.path();

    let out = Command::new(vetto_bin())
        .current_dir(proj_dir)
        .env("HOME", test_home())
        .output()
        .expect("execute bare vetto");

    assert!(
        out.status.success(),
        "bare vetto in empty directory must exit 0: {}",
        stderr(&out)
    );

    let stdout_str = stdout(&out);
    assert!(
        stdout_str.contains("vetto v"),
        "missing version: {stdout_str}"
    );
    assert!(
        stdout_str.contains("environment:"),
        "missing environment: {stdout_str}"
    );
    assert!(
        stdout_str.contains("active sessions:"),
        "missing active sessions: {stdout_str}"
    );
    assert!(
        stdout_str.contains("Get started:"),
        "missing Get started guidance: {stdout_str}"
    );
    assert!(
        stdout_str.contains("vetto enable <agent>"),
        "missing enable hint: {stdout_str}"
    );
    assert!(
        stdout_str.contains("vetto run <command>"),
        "missing run hint: {stdout_str}"
    );
    assert!(
        stdout_str.contains("vetto doctor"),
        "missing doctor hint: {stdout_str}"
    );
}

#[test]
fn test_bare_launch_zero_arg_in_directory_with_agent_preset() {
    let project = TempProject::new("bare-preset");
    let proj_dir = project.path();

    // Create marker file for claude
    write_file(&proj_dir.join("CLAUDE.md"), "# Claude Project Guidelines\n");

    let out = Command::new(vetto_bin())
        .current_dir(proj_dir)
        .env("HOME", test_home())
        .output()
        .expect("execute bare vetto in dir with preset");

    // Zero-arg invocation should always safely return summary with exit code 0
    assert!(
        out.status.success(),
        "bare vetto in dir with preset must exit 0: {}",
        stderr(&out)
    );

    let stdout_str = stdout(&out);
    assert!(stdout_str.contains("vetto v"));
    assert!(stdout_str.contains("environment:"));
    assert!(stdout_str.contains("Get started:"));
}

#[test]
fn test_run_in_empty_directory_fails_with_actionable_guidance() {
    let project = TempProject::new("run-empty");
    let proj_dir = project.path();

    // Invoking `vetto run` without command in empty directory should fail with exit code 1
    let out = Command::new(vetto_bin())
        .arg("run")
        .current_dir(proj_dir)
        .env("HOME", test_home())
        .output()
        .expect("execute vetto run in empty dir");

    assert!(
        !out.status.success(),
        "vetto run in empty directory must not succeed"
    );
    assert_eq!(out.status.code(), Some(1));

    let err_str = stderr(&out);
    assert!(
        err_str.contains("Get started:"),
        "stderr must contain actionable guidance: {err_str}"
    );
}
