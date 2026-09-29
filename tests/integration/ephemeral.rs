//! Integration tests for `vetto ephemeral` and automatic workspace rollback.

use crate::common::*;
use std::fs;

#[test]
fn test_ephemeral_discards_changes_on_failure() {
    let project = TempProject::new("ephemeral-fail");
    let canary = project.path().join("canary.txt");
    write_file(&canary, "pristine content\n");

    #[cfg(unix)]
    let out = run_vetto_in(
        project.path(),
        &[
            "--ci",
            "ephemeral",
            "--discard",
            "--",
            "sh",
            "-c",
            "echo 'polluted mutation' > canary.txt; exit 1",
        ],
    );

    #[cfg(not(unix))]
    let out = run_vetto_in(
        project.path(),
        &[
            "--ci",
            "ephemeral",
            "--discard",
            "--",
            "cmd",
            "/c",
            "echo polluted > canary.txt && exit /b 1",
        ],
    );

    assert_eq!(out.status.code(), Some(1));

    let err = stderr(&out);
    assert!(
        !err.contains("was not found in"),
        "snapshot lookup failed on ephemeral rollback: {err}"
    );

    let content = fs::read_to_string(&canary).unwrap_or_default();
    assert_eq!(content, "pristine content\n");
}

#[test]
fn test_ephemeral_applies_changes_on_success() {
    let project = TempProject::new("ephemeral-success");
    let canary = project.path().join("canary.txt");
    write_file(&canary, "initial content\n");

    #[cfg(unix)]
    let out = run_vetto_in(
        project.path(),
        &[
            "--ci",
            "ephemeral",
            "--yes",
            "--",
            "sh",
            "-c",
            "echo 'updated content' > canary.txt; exit 0",
        ],
    );

    #[cfg(not(unix))]
    let out = run_vetto_in(
        project.path(),
        &[
            "--ci",
            "ephemeral",
            "--yes",
            "--",
            "cmd",
            "/c",
            "echo updated content > canary.txt && exit /b 0",
        ],
    );

    assert_eq!(out.status.code(), Some(0));

    let content = fs::read_to_string(&canary).unwrap_or_default();
    assert!(content.contains("updated content"));
}
