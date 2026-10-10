//! Integration tests for fast native shim dispatcher and hook lifecycle (Step 14 & 15).

use super::common::*;
use std::process::Command;

#[test]
fn test_hook_install_and_status_and_uninstall() {
    let project = TempProject::new("shim-lifecycle");
    let proj_dir = project.path();

    // 1. Run vetto hook install --scope local
    let out = run_vetto_in(
        proj_dir,
        &["hook", "install", "--scope", "local", "--force"],
    );
    assert!(
        out.status.success(),
        "hook install failed: {}",
        stderr(&out)
    );
    let stdout_str = stdout(&out);
    assert!(stdout_str.contains("vetto hook install: successfully configured environment"));
    assert!(proj_dir.join(".vetto").join("shims").exists());
    assert!(proj_dir.join(".vetto").join("shims").join("sh").exists());

    // 2. Run vetto hook status --scope local --json
    let out_status = run_vetto_in(proj_dir, &["hook", "status", "--scope", "local", "--json"]);
    assert!(
        out_status.status.success(),
        "hook status failed: {}",
        stderr(&out_status)
    );
    let json_str = stdout(&out_status);
    let val: serde_json::Value = serde_json::from_str(&json_str).expect("parse status json");
    assert_eq!(val["scope"], "local");
    assert!(val["shims_count"].as_u64().unwrap_or(0) > 0);

    // 3. Run vetto hook uninstall --scope local
    let out_un = run_vetto_in(proj_dir, &["hook", "uninstall", "--scope", "local"]);
    assert!(
        out_un.status.success(),
        "hook uninstall failed: {}",
        stderr(&out_un)
    );
    assert!(stdout(&out_un).contains("vetto hook uninstall: successfully cleaned environment"));
}

#[test]
fn test_shim_dispatcher_and_recursion_barrier() {
    let project = TempProject::new("shim-dispatch");
    let proj_dir = project.path();

    // 1. Direct dispatch via vetto shim with recursion barrier active (_VETTO_INTERCEPTED=1)
    let out = Command::new(vetto_bin())
        .args(["shim", "sh", "--", "-c", "echo inside_barrier"])
        .current_dir(proj_dir)
        .env("_VETTO_INTERCEPTED", "1")
        .output()
        .expect("exec shim with _VETTO_INTERCEPTED");

    assert!(out.status.success(), "shim failed: {}", stderr(&out));
    let out_text = stdout(&out);
    assert!(out_text.contains("inside_barrier"));
}

#[test]
fn test_anti_recursion_barrier_all_env_vars() {
    let project = TempProject::new("shim-recursion-vars");
    let proj_dir = project.path();

    // Verify all 4 isolation barrier variables activate direct passthrough
    for env_var in [
        "_VETTO_INTERCEPTED",
        "VETTO_SANDBOXED",
        "VETTO_SHIM_ACTIVE",
        "VETTO_WRAPPED",
    ] {
        let out = Command::new(vetto_bin())
            .args(["shim", "sh", "--", "-c", "echo passthrough_ok"])
            .current_dir(proj_dir)
            .env(env_var, "1")
            .output()
            .unwrap_or_else(|e| panic!("failed to exec shim with {env_var}: {e}"));

        assert!(
            out.status.success(),
            "shim execution failed under {env_var}=1: {}",
            stderr(&out)
        );
        assert!(
            stdout(&out).contains("passthrough_ok"),
            "expected passthrough output under {env_var}=1"
        );
    }
}

#[cfg(unix)]
#[test]
fn test_shell_script_shim_hermeticity_and_passthrough() {
    let project = TempProject::new("script-shim-passthrough");
    let proj_dir = project.path();

    // 1. Create a mock tool in host_bin
    let host_bin = proj_dir.join("host_bin");
    std::fs::create_dir_all(&host_bin).unwrap();
    let real_tool = host_bin.join("mocktool");
    write_file(
        &real_tool,
        "#!/bin/sh\necho \"real_host_binary_executed $@\"\n",
    );
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(&real_tool).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&real_tool, perms).unwrap();

    // 2. Generate a real shell shim script in shims_dir
    let shims_dir = proj_dir.join(".vetto").join("shims");
    std::fs::create_dir_all(&shims_dir).unwrap();
    let shim_file = shims_dir.join("mocktool");
    let shim_content = vetto::shim::registry::ShimRegistry::generate_unix_shim_script(
        "mocktool",
        Some(std::path::Path::new(vetto_bin())),
    );
    write_file(&shim_file, &shim_content);
    let mut shim_perms = std::fs::metadata(&shim_file).unwrap().permissions();
    shim_perms.set_mode(0o755);
    std::fs::set_permissions(&shim_file, shim_perms).unwrap();

    // 3. Construct PATH with shims_dir ahead of host_bin
    let custom_path = format!(
        "{}:{}:/bin:/usr/bin",
        shims_dir.display(),
        host_bin.display()
    );

    // 4. Invoke the shim script directly with _VETTO_INTERCEPTED=1
    let out = Command::new(&shim_file)
        .arg("arg1")
        .arg("arg2")
        .current_dir(proj_dir)
        .env("PATH", &custom_path)
        .env("_VETTO_INTERCEPTED", "1")
        .output()
        .expect("exec shim script");

    assert!(
        out.status.success(),
        "shim script execution failed: {}",
        stderr(&out)
    );
    let out_str = stdout(&out);
    assert!(
        out_str.contains("real_host_binary_executed arg1 arg2"),
        "expected passthrough to real host binary: {out_str}"
    );
}

#[test]
fn test_git_guard_blocks_destructive_commands() {
    let project = TempProject::new("git-guard-block");
    let proj_dir = project.path();

    // Ensure git is installed on host before running
    if !Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return;
    }

    let destructive_commands: &[&[&str]] = &[
        &["push", "--force"],
        &["push", "-f"],
        &["push", "origin", "main"],
        &["push", "master"],
        &["reset", "--hard"],
        &["clean", "-f"],
        &["branch", "-D"],
    ];

    for args in destructive_commands {
        let mut full_args = vec!["shim", "git", "--"];
        full_args.extend(args.iter().copied());

        let out = Command::new(vetto_bin())
            .args(&full_args)
            .current_dir(proj_dir)
            .env("VETTO_GIT_GUARD", "1")
            .output()
            .unwrap_or_else(|e| panic!("failed to exec vetto shim git: {e}"));

        assert!(
            !out.status.success(),
            "destructive git command {:?} must be blocked by git guard",
            args
        );
        let err_text = stderr(&out);
        assert!(
            err_text.contains("git_guard") || err_text.contains("fail-closed"),
            "expected git_guard error message for {:?}: {err_text}",
            args
        );
    }
}

#[test]
fn test_git_guard_allows_destructive_with_override() {
    let project = TempProject::new("git-guard-override");
    let proj_dir = project.path();

    if !Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return;
    }

    // With --allow-destructive-git flag, git guard check is bypassed
    let out = Command::new(vetto_bin())
        .args(["shim", "git", "--", "--allow-destructive-git", "status"])
        .current_dir(proj_dir)
        .env("VETTO_GIT_GUARD", "1")
        .env("_VETTO_INTERCEPTED", "1")
        .output()
        .expect("exec vetto shim git with override");

    let err_text = stderr(&out);
    assert!(
        !err_text.contains("blocked by git_guard"),
        "git guard should not block when --allow-destructive-git is present: {err_text}"
    );
}
