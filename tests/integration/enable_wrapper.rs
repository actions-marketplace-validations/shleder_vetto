//! Integration tests for `vetto enable` and `vetto disable` lifecycle.

use super::common::*;
use std::process::Command;

#[test]
fn test_enable_list_without_arguments() {
    let project = TempProject::new("enable-list");
    let out = run_vetto_in(project.path(), &["enable"]);
    assert!(
        out.status.success(),
        "vetto enable must succeed: {}",
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(text.contains("AI Coding Agents (vetto enable):"));
    assert!(text.contains("claude"));
    assert!(text.contains("codex"));
    assert!(text.contains("vetto enable <agent>"));
}

#[test]
fn test_enable_status_command() {
    let project = TempProject::new("enable-status");
    let out = run_vetto_in(project.path(), &["enable", "--status", "--scope", "local"]);
    assert!(
        out.status.success(),
        "vetto enable --status must succeed: {}",
        stderr(&out)
    );
}

#[test]
fn test_enable_and_disable_lifecycle() {
    let project = TempProject::new("enable-lifecycle");
    let proj_dir = project.path();

    // 1. Create a mock agent in a custom PATH directory
    let bin_dir = proj_dir.join("host_bin");
    std::fs::create_dir_all(&bin_dir).expect("create bin dir");
    let mock_agent = bin_dir.join("claude");
    write_file(&mock_agent, "#!/bin/sh\necho \"claude agent running\"\n");
    #[cfg(windows)]
    {
        write_file(
            &bin_dir.join("claude.cmd"),
            "@echo off\r\necho claude agent running\r\n",
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&mock_agent).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&mock_agent, perms).unwrap();
    }

    // Set PATH to include bin_dir
    let original_path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = std::env::split_paths(&original_path).collect::<Vec<_>>();
    paths.insert(0, bin_dir.clone());
    let custom_path = std::env::join_paths(paths).unwrap();

    // 2. Run vetto enable claude --scope local
    let out = Command::new(vetto_bin())
        .args(["enable", "claude", "--scope", "local"])
        .current_dir(proj_dir)
        .env("PATH", &custom_path)
        .env("HOME", test_home())
        .output()
        .expect("exec enable");

    assert!(
        out.status.success(),
        "vetto enable claude failed: {}",
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(text.contains("successfully enabled sandbox wrapper for 'claude'"));

    let shim_path = proj_dir.join(".vetto").join("shims").join("claude");
    assert!(shim_path.exists(), "shim file must exist");
    let shim_content = std::fs::read_to_string(&shim_path).expect("read shim");
    assert!(shim_content.contains("VETTO_WRAPPED"));
    assert!(shim_content.contains("VETTO_SANDBOXED"));

    // 3. Status should show claude wrapped
    let out_st = Command::new(vetto_bin())
        .args(["enable", "--status", "--scope", "local"])
        .current_dir(proj_dir)
        .env("PATH", &custom_path)
        .env("HOME", test_home())
        .output()
        .expect("exec enable status");

    assert!(out_st.status.success());
    assert!(stdout(&out_st).contains("claude"));

    // 4. Run vetto disable claude --scope local
    let out_dis = Command::new(vetto_bin())
        .args(["disable", "claude", "--scope", "local"])
        .current_dir(proj_dir)
        .env("PATH", &custom_path)
        .env("HOME", test_home())
        .output()
        .expect("exec disable");

    assert!(
        out_dis.status.success(),
        "disable failed: {}",
        stderr(&out_dis)
    );
    assert!(stdout(&out_dis).contains("disabled sandbox wrapper for 'claude'"));
    assert!(!shim_path.exists(), "shim file must be removed");
    assert!(
        mock_agent.exists(),
        "real host binary must remain untouched"
    );
}

#[test]
fn test_enable_collision_protection() {
    let project = TempProject::new("enable-collision");
    let proj_dir = project.path();

    // 1. Create a mock agent in host_bin
    let bin_dir = proj_dir.join("host_bin");
    std::fs::create_dir_all(&bin_dir).expect("create bin dir");
    let mock_agent = bin_dir.join("codex");
    write_file(&mock_agent, "#!/bin/sh\necho \"codex host\"\n");
    #[cfg(windows)]
    {
        write_file(
            &bin_dir.join("codex.cmd"),
            "@echo off\r\necho codex host\r\n",
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&mock_agent).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&mock_agent, perms).unwrap();
    }

    let original_path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = std::env::split_paths(&original_path).collect::<Vec<_>>();
    paths.insert(0, bin_dir.clone());
    let custom_path = std::env::join_paths(paths).unwrap();

    // 2. Pre-create a non-vetto file at the shim location
    let shims_dir = proj_dir.join(".vetto").join("shims");
    std::fs::create_dir_all(&shims_dir).expect("create shims dir");
    let collision_file = shims_dir.join("codex");
    write_file(&collision_file, "custom non-vetto binary content\n");

    // 3. Attempt enable without --force -> should fail
    let out_fail = Command::new(vetto_bin())
        .args(["enable", "codex", "--scope", "local"])
        .current_dir(proj_dir)
        .env("PATH", &custom_path)
        .env("HOME", test_home())
        .output()
        .expect("exec enable");

    assert!(
        !out_fail.status.success(),
        "enable without --force must fail on collision"
    );
    assert!(stderr(&out_fail).contains("not a Vetto shim"));

    // 4. Attempt enable with --force -> should succeed
    let out_force = Command::new(vetto_bin())
        .args(["enable", "codex", "--scope", "local", "--force"])
        .current_dir(proj_dir)
        .env("PATH", &custom_path)
        .env("HOME", test_home())
        .output()
        .expect("exec enable force");

    assert!(
        out_force.status.success(),
        "enable with --force must succeed: {}",
        stderr(&out_force)
    );
    let content = std::fs::read_to_string(&collision_file).expect("read overwritten shim");
    assert!(content.contains("Vetto transparent binary shim"));
}

#[test]
fn test_enable_all_command() {
    let project = TempProject::new("enable-all");
    let proj_dir = project.path();

    // 1. Create mock agents claude and agy in host_bin
    let bin_dir = proj_dir.join("host_bin");
    std::fs::create_dir_all(&bin_dir).expect("create bin dir");
    let mock_claude = bin_dir.join("claude");
    write_file(&mock_claude, "#!/bin/sh\necho \"claude agent running\"\n");
    let mock_agy = bin_dir.join("agy");
    write_file(&mock_agy, "#!/bin/sh\necho \"agy agent running\"\n");
    #[cfg(windows)]
    {
        write_file(&bin_dir.join("claude.cmd"), "@echo off\r\necho claude\r\n");
        write_file(&bin_dir.join("agy.cmd"), "@echo off\r\necho agy\r\n");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for p in [&mock_claude, &mock_agy] {
            let mut perms = std::fs::metadata(p).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(p, perms).unwrap();
        }
    }

    let original_path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = std::env::split_paths(&original_path).collect::<Vec<_>>();
    paths.insert(0, bin_dir.clone());
    let custom_path = std::env::join_paths(paths).unwrap();

    // 2. Run vetto enable --all --scope local
    let out = Command::new(vetto_bin())
        .args(["enable", "--all", "--scope", "local"])
        .current_dir(proj_dir)
        .env("PATH", &custom_path)
        .env("HOME", test_home())
        .output()
        .expect("exec enable --all");

    assert!(
        out.status.success(),
        "vetto enable --all failed: {}",
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(text.contains("claude"));
    assert!(text.contains("agy"));
    assert!(text.contains("Successfully wrapped 2 agent(s)."));

    let shims_dir = proj_dir.join(".vetto").join("shims");
    assert!(shims_dir.join("claude").exists(), "claude shim must exist");
    assert!(shims_dir.join("agy").exists(), "agy shim must exist");
}

#[test]
fn test_enable_all_multi_binary_aliases() {
    let project = TempProject::new("enable-all-aliases");
    let proj_dir = project.path();

    let bin_dir = proj_dir.join("host_bin");
    std::fs::create_dir_all(&bin_dir).expect("create bin dir");
    let mock_claude = bin_dir.join("claude");
    write_file(&mock_claude, "#!/bin/sh\necho \"claude\"\n");
    let mock_claude_code = bin_dir.join("claude-code");
    write_file(&mock_claude_code, "#!/bin/sh\necho \"claude-code\"\n");
    let mock_qwen = bin_dir.join("qwen-code");
    write_file(&mock_qwen, "#!/bin/sh\necho \"qwen-code\"\n");
    let mock_roo = bin_dir.join("roo-code");
    write_file(&mock_roo, "#!/bin/sh\necho \"roo-code\"\n");

    #[cfg(windows)]
    {
        write_file(&bin_dir.join("claude.cmd"), "@echo off\r\necho claude\r\n");
        write_file(
            &bin_dir.join("claude-code.cmd"),
            "@echo off\r\necho claude-code\r\n",
        );
        write_file(&bin_dir.join("qwen-code.cmd"), "@echo off\r\necho qwen\r\n");
        write_file(&bin_dir.join("roo-code.cmd"), "@echo off\r\necho roo\r\n");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for p in [&mock_claude, &mock_claude_code, &mock_qwen, &mock_roo] {
            let mut perms = std::fs::metadata(p).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(p, perms).unwrap();
        }
    }

    let original_path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = std::env::split_paths(&original_path).collect::<Vec<_>>();
    paths.insert(0, bin_dir.clone());
    let custom_path = std::env::join_paths(paths).unwrap();

    let out = Command::new(vetto_bin())
        .args(["enable", "--all", "--scope", "local"])
        .current_dir(proj_dir)
        .env("PATH", &custom_path)
        .env("HOME", test_home())
        .output()
        .expect("exec enable --all");

    assert!(
        out.status.success(),
        "vetto enable --all failed: {}",
        stderr(&out)
    );

    let shims_dir = proj_dir.join(".vetto").join("shims");
    assert!(shims_dir.join("claude").exists(), "claude shim must exist");
    assert!(
        shims_dir.join("claude-code").exists(),
        "claude-code alias shim must exist"
    );
    assert!(
        shims_dir.join("qwen-code").exists(),
        "qwen-code shim must exist"
    );
    assert!(
        shims_dir.join("roo-code").exists(),
        "roo-code shim must exist"
    );
}

#[test]
fn test_enable_all_and_disable_all_lifecycle() {
    let project = TempProject::new("enable-disable-all");
    let proj_dir = project.path();

    // 1. Create mock agents in host_bin
    let bin_dir = proj_dir.join("host_bin");
    std::fs::create_dir_all(&bin_dir).expect("create bin dir");
    let mock_claude = bin_dir.join("claude");
    write_file(&mock_claude, "#!/bin/sh\necho \"claude mock\"\n");
    let mock_codex = bin_dir.join("codex");
    write_file(&mock_codex, "#!/bin/sh\necho \"codex mock\"\n");
    let mock_aider = bin_dir.join("aider");
    write_file(&mock_aider, "#!/bin/sh\necho \"aider mock\"\n");

    #[cfg(windows)]
    {
        write_file(&bin_dir.join("claude.cmd"), "@echo off\r\necho claude\r\n");
        write_file(&bin_dir.join("codex.cmd"), "@echo off\r\necho codex\r\n");
        write_file(&bin_dir.join("aider.cmd"), "@echo off\r\necho aider\r\n");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for p in [&mock_claude, &mock_codex, &mock_aider] {
            let mut perms = std::fs::metadata(p).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(p, perms).unwrap();
        }
    }

    let original_path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = std::env::split_paths(&original_path).collect::<Vec<_>>();
    paths.insert(0, bin_dir.clone());
    let custom_path = std::env::join_paths(paths).unwrap();

    // 2. Enable all agents
    let out_enable = Command::new(vetto_bin())
        .args(["enable", "--all", "--scope", "local"])
        .current_dir(proj_dir)
        .env("PATH", &custom_path)
        .env("HOME", test_home())
        .output()
        .expect("exec enable --all");

    assert!(
        out_enable.status.success(),
        "enable --all failed: {}",
        stderr(&out_enable)
    );

    let shims_dir = proj_dir.join(".vetto").join("shims");
    assert!(shims_dir.join("claude").exists(), "claude shim must exist");
    assert!(shims_dir.join("codex").exists(), "codex shim must exist");
    assert!(shims_dir.join("aider").exists(), "aider shim must exist");

    // 3. Disable all agents
    let out_disable = Command::new(vetto_bin())
        .args(["disable", "--all", "--scope", "local"])
        .current_dir(proj_dir)
        .env("PATH", &custom_path)
        .env("HOME", test_home())
        .output()
        .expect("exec disable --all");

    assert!(
        out_disable.status.success(),
        "disable --all failed: {}",
        stderr(&out_disable)
    );
    let disable_stdout = stdout(&out_disable);
    assert!(
        disable_stdout.contains("disabled all sandbox wrappers"),
        "expected success summary in stdout: {disable_stdout}"
    );

    // 4. Verify all shims removed cleanly
    assert!(
        !shims_dir.join("claude").exists(),
        "claude shim must be removed"
    );
    assert!(
        !shims_dir.join("codex").exists(),
        "codex shim must be removed"
    );
    assert!(
        !shims_dir.join("aider").exists(),
        "aider shim must be removed"
    );

    // 5. Verify host binaries are untouched
    assert!(mock_claude.exists(), "host claude must remain untouched");
    assert!(mock_codex.exists(), "host codex must remain untouched");
    assert!(mock_aider.exists(), "host aider must remain untouched");

    // 6. Idempotent disable --all when no shims exist
    let out_idempotent = Command::new(vetto_bin())
        .args(["disable", "--all", "--scope", "local"])
        .current_dir(proj_dir)
        .env("PATH", &custom_path)
        .env("HOME", test_home())
        .output()
        .expect("exec idempotent disable --all");

    assert!(out_idempotent.status.success());
    assert!(stdout(&out_idempotent).contains("no active shims found"));
}

#[test]
fn test_disable_arg_validation() {
    let project = TempProject::new("disable-validation");
    let proj_dir = project.path();

    // 1. disable without agent or --all must fail
    let out_no_args = Command::new(vetto_bin())
        .args(["disable"])
        .current_dir(proj_dir)
        .output()
        .expect("exec disable with no args");

    assert!(
        !out_no_args.status.success(),
        "disable without args must fail"
    );

    // 2. disable with both agent and --all must fail
    let out_conflict = Command::new(vetto_bin())
        .args(["disable", "claude", "--all"])
        .current_dir(proj_dir)
        .output()
        .expect("exec disable with conflicting args");

    assert!(
        !out_conflict.status.success(),
        "disable with both agent and --all must fail"
    );
}

