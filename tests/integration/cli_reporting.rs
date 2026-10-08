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
fn typo_subcommands_fail_with_clap_error_not_workspace_profile() {
    for typo in [
        "rn",
        "stauts",
        "verify-ng",
        "profiles",
        "profile",
        "watch",
        "digest",
    ] {
        let output = Command::new(vetto_bin())
            .arg(typo)
            .output()
            .expect("spawn subcommand");
        assert!(!output.status.success(), "subcommand '{typo}' must fail");
        let err = stderr(&output);
        assert!(
            err.contains("unrecognized subcommand") || err.contains("unexpected"),
            "stderr for '{typo}' must be a clap error: {err}"
        );
        assert!(
            !err.contains("workspace profile"),
            "stderr for '{typo}' must not mention workspace profile: {err}"
        );
    }
}
