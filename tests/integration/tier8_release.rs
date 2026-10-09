use std::process::Command;

use crate::common;

#[test]
fn registry_response_and_semver_parsing() {
    use vetto::version::{parse_registry_version, SemVer};

    let v_old = SemVer::parse("0.2.5").expect("parse 0.2.5");
    let v_new = SemVer::parse("0.2.6").expect("parse 0.2.6");
    assert!(v_new.is_newer_than(&v_old));
    assert!(!v_old.is_newer_than(&v_new));

    let pkg_json = r#"{
        "dist-tags": {
            "latest": "0.2.6",
            "alpha": "0.2.7-alpha.1"
        }
    }"#;
    assert_eq!(
        parse_registry_version(pkg_json, "stable").as_deref(),
        Some("0.2.6")
    );
    assert_eq!(
        parse_registry_version(pkg_json, "alpha").as_deref(),
        Some("0.2.7-alpha.1")
    );
}

#[test]
fn audit_cli_listing_and_json_flags() {
    let mut cmd = Command::new(common::vetto_bin());
    cmd.arg("audit").arg("--json");

    let output = cmd.output().expect("invoke vetto audit --json");
    assert!(
        output.status.success(),
        "vetto audit --json failed: {output:?}"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.trim().starts_with('[') || stdout.trim().starts_with('{'));
}

#[test]
fn audit_cli_filtering_flags() {
    let mut cmd = Command::new(common::vetto_bin());
    cmd.arg("audit")
        .arg("--since")
        .arg("24h")
        .arg("--agent")
        .arg("claude")
        .arg("--limit")
        .arg("5")
        .arg("--json");

    let output = cmd.output().expect("invoke vetto audit with filters");
    assert!(
        output.status.success(),
        "vetto audit filtered failed: {output:?}"
    );
}

#[test]
fn github_releases_response_parsing() {
    use vetto::version::parse_registry_version;

    let gh_json = r#"{"tag_name": "v0.2.11", "name": "Release 0.2.11"}"#;
    assert_eq!(
        parse_registry_version(gh_json, "stable").as_deref(),
        Some("0.2.11")
    );

    let gh_arr = r#"[
        {"tag_name": "v0.2.12-alpha.1", "prerelease": true},
        {"tag_name": "v0.2.11", "prerelease": false}
    ]"#;
    assert_eq!(
        parse_registry_version(gh_arr, "stable").as_deref(),
        Some("0.2.11")
    );
    assert_eq!(
        parse_registry_version(gh_arr, "alpha").as_deref(),
        Some("0.2.12-alpha.1")
    );
}

#[test]
fn semver_numeric_prerelease_and_custom_tags() {
    use vetto::version::{parse_registry_version, SemVer};

    let v_alpha2 = SemVer::parse("0.2.11-alpha.2").expect("alpha.2");
    let v_alpha10 = SemVer::parse("0.2.11-alpha.10").expect("alpha.10");
    assert!(v_alpha10.is_newer_than(&v_alpha2));
    assert!(!v_alpha2.is_newer_than(&v_alpha10));

    let v_build = SemVer::parse("0.2.11+build.99").expect("build");
    assert_eq!(v_build.major, 0);
    assert_eq!(v_build.minor, 2);
    assert_eq!(v_build.patch, 11);
    assert_eq!(v_build.prerelease, None);

    let pkg_json = r#"{
        "dist-tags": {
            "latest": "0.2.11",
            "beta": "0.2.12-beta.1"
        }
    }"#;
    assert_eq!(
        parse_registry_version(pkg_json, "beta").as_deref(),
        Some("0.2.12-beta.1")
    );
}
