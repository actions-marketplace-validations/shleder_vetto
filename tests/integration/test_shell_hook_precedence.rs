//! Integration tests for indestructible shell hook PATH precedence (INV-38).
//! Blueprint Section 11.3 & Section 15.4.

use crate::common::TempProject;
use vetto::cli::shell_env::{generate_shell_hook, ShellKind};

#[test]
fn test_bash_hook_cleans_and_prepends_path() {
    let dir = TempProject::new("bash-hook-precedence");
    let shims = dir.path().join("shims");
    std::fs::create_dir_all(&shims).expect("create shims dir");

    let hook_script = generate_shell_hook(ShellKind::Bash, &shims);
    assert!(
        hook_script.contains("export PATH="),
        "Hook must export PATH: {hook_script}"
    );
    assert!(
        hook_script.contains(&shims.to_string_lossy().to_string()),
        "Hook must reference shims directory: {hook_script}"
    );

    // Test in subshell on Unix systems where bash is available
    #[cfg(unix)]
    {
        let dirty_path = format!("/usr/bin:/home/user/.local/bin:{}:/bin", shims.display());
        let test_cmd = format!(
            "PATH='{}'; eval '{}'; echo \"$PATH\"",
            dirty_path, hook_script
        );

        let output = std::process::Command::new("bash")
            .arg("-c")
            .arg(&test_cmd)
            .output()
            .expect("run bash");

        assert!(
            output.status.success(),
            "bash subshell execution failed: stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let new_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        assert!(
            new_path.starts_with(&shims.to_string_lossy().to_string()),
            "Shims directory MUST be at index 0 of PATH. Got: {}",
            new_path
        );
    }
}

#[test]
fn test_zsh_hook_cleans_and_prepends_path() {
    let dir = TempProject::new("zsh-hook-precedence");
    let shims = dir.path().join("shims");
    std::fs::create_dir_all(&shims).expect("create shims dir");

    let hook_script = generate_shell_hook(ShellKind::Zsh, &shims);
    assert!(
        hook_script.contains("export PATH="),
        "Zsh hook must export PATH: {hook_script}"
    );
    assert!(
        hook_script.contains(&shims.to_string_lossy().to_string()),
        "Zsh hook must reference shims: {hook_script}"
    );
    assert!(
        hook_script.contains("_vetto_clean_path="),
        "Zsh hook must compute _vetto_clean_path: {hook_script}"
    );
}

#[test]
fn test_fish_hook_cleans_and_prepends_path() {
    let dir = TempProject::new("fish-hook-precedence");
    let shims = dir.path().join("shims");
    std::fs::create_dir_all(&shims).expect("create shims dir");

    let hook_script = generate_shell_hook(ShellKind::Fish, &shims);
    assert!(
        hook_script.contains("set -gx PATH"),
        "Fish hook must set PATH: {hook_script}"
    );
    assert!(
        hook_script.contains(&shims.to_string_lossy().to_string()),
        "Fish hook must reference shims: {hook_script}"
    );
    assert!(
        hook_script.contains("contains -i"),
        "Fish hook must inspect path indices: {hook_script}"
    );
}

#[test]
fn test_powershell_hook_cleans_and_prepends_path() {
    let dir = TempProject::new("pwsh-hook-precedence");
    let shims = dir.path().join("shims");
    std::fs::create_dir_all(&shims).expect("create shims dir");

    let hook_script = generate_shell_hook(ShellKind::PowerShell, &shims);
    assert!(
        hook_script.contains("$env:PATH"),
        "PowerShell hook must update $env:PATH: {hook_script}"
    );
    assert!(
        hook_script.contains(&shims.to_string_lossy().to_string()),
        "PowerShell hook must reference shims: {hook_script}"
    );
    assert!(
        hook_script.contains("Where-Object"),
        "PowerShell hook must filter out existing shims: {hook_script}"
    );
}

#[test]
fn test_bash_hook_handles_multiple_dirty_shims_occurrences() {
    let dir = TempProject::new("multi-shims-precedence");
    let shims = dir.path().join("shims");
    std::fs::create_dir_all(&shims).expect("create shims dir");

    let hook_script = generate_shell_hook(ShellKind::Bash, &shims);
    assert!(!hook_script.is_empty());

    #[cfg(unix)]
    {
        // Place shims in middle AND at end
        let dirty_path = format!(
            "/usr/local/bin:{}:/usr/bin:{}:/bin",
            shims.display(),
            shims.display()
        );
        let test_cmd = format!(
            "PATH='{}'; eval '{}'; echo \"$PATH\"",
            dirty_path, hook_script
        );

        let output = std::process::Command::new("bash")
            .arg("-c")
            .arg(&test_cmd)
            .output()
            .expect("run bash");

        assert!(output.status.success());
        let new_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        assert!(
            new_path.starts_with(&shims.to_string_lossy().to_string()),
            "Shims must be at index 0. Got: {new_path}"
        );
        let shims_str = shims.to_string_lossy();
        let count = new_path
            .split(':')
            .filter(|p| *p == shims_str.as_ref())
            .count();
        assert_eq!(
            count, 1,
            "Shims must appear exactly once in clean PATH, got {count}: {new_path}"
        );
    }
}

#[test]
fn test_shell_env_prompt_integration_all_shells() {
    // 1. POSIX / Bash / Zsh prompt integration
    let posix_env = vetto::cli::shell_env::emit_shell_env(Some("sess-123"), Some("full"), Some("strict"));
    assert!(posix_env.contains("export VETTO_ACTIVE=1"));
    assert!(posix_env.contains("export VETTO_PROMPT=\"[vetto:locked]\""));
    assert!(posix_env.contains("export VETTO_SANDBOX=1"));
    assert!(posix_env.contains("export VETTO_SESSION_ID=\"sess-123\""));
    assert!(posix_env.contains("export VETTO_TIER=\"full\""));
    assert!(posix_env.contains("export VETTO_PROFILE=\"strict\""));

    // 2. Fish shell prompt integration
    let orig_shell = std::env::var("SHELL").ok();
    std::env::set_var("SHELL", "/usr/bin/fish");
    let fish_env = vetto::cli::shell_env::emit_shell_env(Some("sess-456"), Some("fs-only"), Some("default"));
    assert!(fish_env.contains("set -gx VETTO_ACTIVE 1;"));
    assert!(fish_env.contains("set -gx VETTO_PROMPT \"[vetto:locked]\";"));
    assert!(fish_env.contains("set -gx VETTO_SANDBOX 1;"));
    assert!(fish_env.contains("set -gx VETTO_SESSION_ID \"sess-456\";"));
    if let Some(s) = orig_shell {
        std::env::set_var("SHELL", s);
    } else {
        std::env::remove_var("SHELL");
    }

    // 3. CLI execution of `vetto shell-env`
    let out = std::process::Command::new(crate::common::vetto_bin())
        .arg("shell-env")
        .output()
        .expect("exec vetto shell-env");

    assert!(out.status.success(), "vetto shell-env must succeed");
    let out_str = crate::common::stdout(&out);
    assert!(out_str.contains("VETTO_ACTIVE"));
    assert!(out_str.contains("[vetto:locked]"));
    assert!(out_str.contains("VETTO_SANDBOX"));
}

