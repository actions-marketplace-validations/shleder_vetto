//! CLI-only reporting/completion tests; these do not require a sandbox tier.

use crate::common::*;
use std::process::Command;

#[test]
fn completions_are_available_for_all_requested_shells() {
    for shell in ["bash", "zsh", "fish", "powershell", "elvish"] {
        let output = Command::new(vetto_bin())
            .args(["completions", shell])
            .output()
            .expect("spawn completion command");
        assert!(
            output.status.success(),
            "completion failed for {shell}: {}",
            stderr(&output)
        );
        assert!(
            !output.stdout.is_empty(),
            "completion output empty for {shell}"
        );
    }
}

#[test]
fn clap_typo_suggestions_work_for_misspelled_subcommands() {
    let output = Command::new(vetto_bin())
        .arg("rn")
        .output()
        .expect("spawn misspelled subcommand");
    assert!(!output.status.success());
    let err = stderr(&output);
    assert!(
        err.contains("unrecognized subcommand") || err.contains("unexpected"),
        "stderr: {err}"
    );
    assert!(
        err.contains("run"),
        "clap should suggest 'run' for 'rn': {err}"
    );

    let output_status = Command::new(vetto_bin())
        .arg("stauts")
        .output()
        .expect("spawn misspelled subcommand");
    assert!(!output_status.status.success());
    let err_status = stderr(&output_status);
    assert!(
        err_status.contains("status"),
        "clap should suggest 'status' for 'stauts': {err_status}"
    );
}

#[test]
fn removed_phantom_subcommands_are_rejected() {
    for subcmd in ["verify-ng", "profiles", "profile", "watch", "digest"] {
        let output = Command::new(vetto_bin())
            .arg(subcmd)
            .output()
            .expect("spawn removed subcommand");
        assert!(
            !output.status.success(),
            "removed subcommand '{subcmd}' must not succeed"
        );
        let err = stderr(&output);
        assert!(
            err.contains("unrecognized subcommand") || err.contains("unexpected"),
            "stderr for '{subcmd}': {err}"
        );
    }
}

