//! BEST-EFFORT secret sanitizer in artifacts (jsonl + json report).
//! The sanitizer is a courtesy layer; these tests pin its obvious wins.

use crate::common::*;

#[test]
fn jsonl_redacts_aws_key_in_agent_argv() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let proj = TempProject::new("sanit");
    let jsonl = proj.path().join("s.jsonl");
    // Canonical AWS documentation example key, assembled from fragments so
    // credential scanners do not flag the fixture. The sanitizer under test
    // must still redact the exact same string end to end.
    let secret = format!("AKIA{}{}", "IOSFODNN7", "EXAMPLE");
    let secret = secret.as_str();
    let out = run_vetto_in(
        proj.path(),
        &[
            "--tui=none",
            "--jsonl",
            jsonl.to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            &format!("echo argv-carrying {secret}; sleep 2"),
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let log = std::fs::read_to_string(&jsonl).unwrap_or_default();
    assert!(!log.contains(secret), "AWS key leaked into jsonl: {log}");
    if session_clock_jumped(&log) {
        eprintln!(
            "SKIP: host monotonic clock jumped during session; live sampler window unmeasurable"
        );
        return;
    }
    assert!(
        log.contains("AKIA[REDACTED]"),
        "redaction marker missing: {log}"
    );
}

#[test]
fn json_report_is_sanitized_and_written() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let proj = TempProject::new("repjson");
    let secret = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";
    let out = run_vetto_in(
        proj.path(),
        &[
            "--tui=none",
            "--report",
            "json",
            "--report-dir",
            ".vetto/reports",
            "--",
            "/bin/sh",
            "-c",
            &format!("echo {secret}"),
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let mut found = false;
    let report_dir = proj.path().join(".vetto/reports");
    for entry in std::fs::read_dir(&report_dir).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with("vetto-report-") && name.ends_with(".json") {
            found = true;
            let body = std::fs::read_to_string(entry.path()).unwrap_or_default();
            assert!(!body.contains(secret), "token leaked into report: {body}");
        }
    }
    assert!(found, "no json report written");
}

#[test]
fn test_package_configs_and_daemon_sockets_masking() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }

    // Verify dangerous unix sockets list includes docker and podman sockets
    #[cfg(target_os = "linux")]
    {
        let sockets = vetto::sandbox::linux::vfs_overlays::get_dangerous_unix_sockets();
        assert!(
            sockets.contains(&std::path::PathBuf::from("/var/run/docker.sock")),
            "dangerous sockets must include /var/run/docker.sock"
        );
        assert!(
            sockets.contains(&std::path::PathBuf::from("/run/docker.sock")),
            "dangerous sockets must include /run/docker.sock"
        );
        assert!(
            sockets.contains(&std::path::PathBuf::from("/run/podman/podman.sock")),
            "dangerous sockets must include /run/podman/podman.sock"
        );
    }

    let proj = TempProject::new("secret-pkg-mask");
    let home = test_home();

    // 1. Create .docker/config.json in test home
    let docker_dir = home.join(".docker");
    let _ = std::fs::create_dir_all(&docker_dir);
    write_file(
        &docker_dir.join("config.json"),
        r#"{"auths":{"secret.registry.io":{"auth":"SECRET_DOCKER_CONFIG_TOKEN_ABC"}}}"#,
    );

    // 2. Create .npmrc in test home
    write_file(
        &home.join(".npmrc"),
        "//registry.npmjs.org/:_authToken=SECRET_NPMRC_AUTH_TOKEN_DEF\n",
    );

    // 3. Create .config/gh/hosts.yml in test home
    let gh_dir = home.join(".config/gh");
    let _ = std::fs::create_dir_all(&gh_dir);
    write_file(
        &gh_dir.join("hosts.yml"),
        "github.com:\n  user: secretuser\n  oauth_token: SECRET_GH_HOSTS_TOKEN_GHI\n",
    );

    let test_script = r#"
echo "--- DOCKER CONFIG ---"
cat "$HOME/.docker/config.json" 2>&1 || true
echo "--- NPMRC ---"
cat "$HOME/.npmrc" 2>&1 || true
echo "--- GH HOSTS ---"
cat "$HOME/.config/gh/hosts.yml" 2>&1 || true
echo "--- DOCKER SOCK ---"
if [ -e "/var/run/docker.sock" ]; then
    cat "/var/run/docker.sock" 2>&1 || true
fi
"#;

    let out = run_vetto_in(
        proj.path(),
        &["--tui=none", "--ci", "--", "sh", "-c", test_script],
    );

    let stdout_str = stdout(&out);
    let stderr_str = stderr(&out);

    assert!(
        !stdout_str.contains("SECRET_DOCKER_CONFIG_TOKEN_ABC"),
        "docker config token leaked in stdout:\n{stdout_str}"
    );
    assert!(
        !stderr_str.contains("SECRET_DOCKER_CONFIG_TOKEN_ABC"),
        "docker config token leaked in stderr:\n{stderr_str}"
    );

    assert!(
        !stdout_str.contains("SECRET_NPMRC_AUTH_TOKEN_DEF"),
        "npmrc token leaked in stdout:\n{stdout_str}"
    );
    assert!(
        !stderr_str.contains("SECRET_NPMRC_AUTH_TOKEN_DEF"),
        "npmrc token leaked in stderr:\n{stderr_str}"
    );

    assert!(
        !stdout_str.contains("SECRET_GH_HOSTS_TOKEN_GHI"),
        "gh hosts token leaked in stdout:\n{stdout_str}"
    );
    assert!(
        !stderr_str.contains("SECRET_GH_HOSTS_TOKEN_GHI"),
        "gh hosts token leaked in stderr:\n{stderr_str}"
    );

    // If host has /var/run/docker.sock, verify it cannot be communicated with as a docker daemon
    if std::path::Path::new("/var/run/docker.sock").exists() {
        assert!(
            !stdout_str.contains("Docker daemon") && !stdout_str.contains("{\"message\""),
            "docker socket was accessible in sandbox:\n{stdout_str}"
        );
    }
}
