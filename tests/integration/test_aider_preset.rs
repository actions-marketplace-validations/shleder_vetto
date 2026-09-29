//! Integration tests for Aider CLI native preset and shim integration (R3).
//!
//! Covers:
//! - Full schema validation of `profiles/agents/aider.toml`
//! - Enforcement of `git_guard = true` and `auto_deny_secrets = true`
//! - Complete network allowlist parity across LLM providers and registries
//! - Propagation of API keys and endpoints in environment pass-through
//! - Auto-creation of isolated agent directories (`~/.aider`, `~/.config/aider`)
//! - Auto-grant of Aider cache and history files (`.aider.input.history`, `.aider.tags.cache.v3`)
//! - Fail-closed Exit 125 interception on destructive git commands (`git reset --hard HEAD~10`, etc.)
//! - Repository `.git/config` credential masking and protection

use std::fs;

use crate::common::TempProject;
use vetto::exit_codes::{map_error_to_exit_code, EXIT_FAIL_CLOSED};
use vetto::policy::defaults::{agent_builtin, AIDER_AGENT_TOML};
use vetto::policy::loader::{load_with_options, PolicyLoadOptions, RawLayer};
use vetto::policy::presets::{agent_network_allowlist, standard_secret_deny_paths};
use vetto::policy::Tier;
use vetto::shim::{dispatch, is_destructive_git_command};

#[test]
fn test_aider_profile_schema_strict_and_parses() {
    // 1. Verify AIDER_AGENT_TOML parses into RawLayer with deny_unknown_fields
    let raw: RawLayer =
        toml::from_str(AIDER_AGENT_TOML).expect("aider.toml must parse strictly into RawLayer");

    // 2. Validate metadata
    let meta = raw.metadata.expect("aider.toml must have [metadata]");
    assert_eq!(meta.name.as_deref(), Some("aider"));
    assert!(
        meta.description.is_some(),
        "aider.toml metadata must have description"
    );

    // 3. Validate security section
    let sec = raw.security.expect("aider.toml must have [security]");
    assert_eq!(
        sec.git_guard,
        Some(true),
        "aider.toml must enforce git_guard = true"
    );
    assert_eq!(
        sec.auto_deny_secrets,
        Some(true),
        "aider.toml must enforce auto_deny_secrets = true"
    );

    // 4. Verify embedded preset in defaults registry
    let embedded = agent_builtin("aider").expect("aider must be in built-in agent registry");
    assert_eq!(embedded, AIDER_AGENT_TOML);
}

#[test]
fn test_aider_policy_loading_and_git_guard_active() {
    let temp = TempProject::new("aider-policy-load");
    let project = temp.path().join("project");
    let home = temp.path().join("home");
    fs::create_dir_all(&project).expect("create project dir");
    fs::create_dir_all(&home).expect("create home dir");

    let opts = PolicyLoadOptions {
        agent: Some("aider".to_string()),
        include_project_policy: false,
        ..Default::default()
    };

    let pol = load_with_options("default", None, &project, &home, Tier::Full, &opts)
        .expect("aider policy must load cleanly");

    // Ensure git_guard is enabled on the compiled policy
    assert!(
        pol.git_guard,
        "loaded aider policy must have git_guard = true"
    );
    assert!(
        pol.auto_deny_secrets,
        "loaded aider policy must have auto_deny_secrets = true"
    );
}

#[test]
fn test_aider_network_allowlist_completeness() {
    let domains = agent_network_allowlist("aider");

    let expected_providers = [
        "api.openai.com",
        "api.anthropic.com",
        "auth.anthropic.com",
        "openrouter.ai",
        "api.deepseek.com",
        "api.groq.com",
        "generativelanguage.googleapis.com",
        "api.mistral.ai",
        "api.cohere.ai",
        "api.cohere.com",
        "api.together.xyz",
        "api.perplexity.ai",
        "aider.chat",
        "api.github.com",
        "github.com",
        "registry.npmjs.org",
        "pypi.org",
        "files.pythonhosted.org",
    ];

    for expected in expected_providers {
        assert!(
            domains.iter().any(|d| d == expected),
            "agent_network_allowlist('aider') missing expected provider domain: {expected}"
        );
    }

    // Verify TOML [network] section directly
    let raw: RawLayer =
        toml::from_str(AIDER_AGENT_TOML).expect("parse aider.toml for network section");
    let net = raw.network.expect("aider.toml must have [network]");
    let allow = net
        .allow
        .expect("[network] must have allow list")
        .into_vec();

    for expected in expected_providers {
        assert!(
            allow.iter().any(|d| d == expected),
            "aider.toml [network].allow missing expected provider domain: {expected}"
        );
    }
}

#[test]
fn test_aider_environment_pass_through() {
    let temp = TempProject::new("aider-env-pass");
    let project = temp.path().join("project");
    let home = temp.path().join("home");
    fs::create_dir_all(&project).expect("create project dir");
    fs::create_dir_all(&home).expect("create home dir");

    let opts = PolicyLoadOptions {
        agent: Some("aider".to_string()),
        include_project_policy: false,
        ..Default::default()
    };

    let pol = load_with_options("default", None, &project, &home, Tier::Full, &opts)
        .expect("load aider policy");

    let required_keys = [
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "DEEPSEEK_API_KEY",
        "DEEPSEEK_BASE_URL",
        "GROQ_API_KEY",
        "GROQ_BASE_URL",
        "MISTRAL_API_KEY",
        "MISTRAL_BASE_URL",
        "COHERE_API_KEY",
        "TOGETHER_API_KEY",
        "PERPLEXITY_API_KEY",
        "OPENROUTER_API_KEY",
        "OLLAMA_API_BASE",
    ];

    for key in required_keys {
        assert!(
            pol.environment.pass_through.iter().any(|v| v == key),
            "aider environment pass_through missing required key: {key}"
        );
    }
}

#[test]
fn test_aider_isolated_directories_auto_created() {
    let temp = TempProject::new("aider-dir-creation");
    let project = temp.path().join("project");
    let home = temp.path().join("home");
    fs::create_dir_all(&project).expect("create project dir");
    fs::create_dir_all(&home).expect("create home dir");

    let aider_dir = home.join(".aider");
    let config_aider_dir = home.join(".config").join("aider");

    assert!(
        !aider_dir.exists(),
        "~/.aider must not exist before policy load"
    );
    assert!(
        !config_aider_dir.exists(),
        "~/.config/aider must not exist before policy load"
    );

    let opts = PolicyLoadOptions {
        agent: Some("aider".to_string()),
        include_project_policy: false,
        ..Default::default()
    };

    let _pol = load_with_options("default", None, &project, &home, Tier::Full, &opts)
        .expect("load aider policy");

    assert!(
        aider_dir.is_dir(),
        "~/.aider must be automatically created by policy loader"
    );
    assert!(
        config_aider_dir.is_dir(),
        "~/.config/aider must be automatically created by policy loader"
    );
}

#[test]
fn test_aider_filesystem_history_and_cache_allowed() {
    let temp = TempProject::new("aider-fs-rules");
    let project = temp.path().join("project");
    let home = temp.path().join("home");
    fs::create_dir_all(&project).expect("create project dir");
    fs::create_dir_all(&home).expect("create home dir");

    let input_history = project.join(".aider.input.history");
    let tags_cache = project.join(".aider.tags.cache.v3");
    let chat_history = project.join(".aider.chat.history.md");
    fs::write(&input_history, "").expect("create input history");
    fs::write(&tags_cache, "").expect("create tags cache");
    fs::write(&chat_history, "").expect("create chat history");

    let opts = PolicyLoadOptions {
        agent: Some("aider".to_string()),
        include_project_policy: false,
        ..Default::default()
    };

    let pol = load_with_options("default", None, &project, &home, Tier::Full, &opts)
        .expect("load aider policy");

    assert!(
        pol.allow_write.iter().any(|p| p == &input_history),
        "allow_write must contain $PROJECT/.aider.input.history"
    );
    assert!(
        pol.allow_write.iter().any(|p| p == &tags_cache),
        "allow_write must contain $PROJECT/.aider.tags.cache.v3"
    );
    assert!(
        pol.allow_write.iter().any(|p| p == &chat_history),
        "allow_write must contain $PROJECT/.aider.chat.history.md"
    );

    assert!(
        pol.allow_read.iter().any(|p| p == &input_history),
        "allow_read must contain $PROJECT/.aider.input.history"
    );
    assert!(
        pol.allow_read.iter().any(|p| p == &tags_cache),
        "allow_read must contain $PROJECT/.aider.tags.cache.v3"
    );
}

#[test]
fn test_aider_destructive_git_reset_fails_closed_125() {
    // 1. Check is_destructive_git_command detects reset --hard HEAD~10
    let reset_cmd: Vec<String> = vec!["reset".into(), "--hard".into(), "HEAD~10".into()];
    let reason = is_destructive_git_command(&reset_cmd);
    assert!(
        reason.is_some(),
        "git reset --hard HEAD~10 must be identified as destructive"
    );

    // 2. Dispatch through shim with VETTO_GIT_GUARD active
    std::env::set_var("VETTO_GIT_GUARD", "1");
    let dispatch_result = dispatch("git", &reset_cmd);
    std::env::remove_var("VETTO_GIT_GUARD");

    assert!(
        dispatch_result.is_err(),
        "destructive git command must be blocked by shim dispatch"
    );

    let err = dispatch_result.unwrap_err();
    let err_str = err.to_string();

    // Verify error prefix contract
    assert!(
        err_str.starts_with("fail-closed: destructive git command blocked by git_guard"),
        "error message must start with required prefix, got: {err_str}"
    );

    // Verify mapped exit code is strictly 125 (EXIT_FAIL_CLOSED), not 1
    let exit_code = map_error_to_exit_code(&err);
    assert_eq!(
        exit_code, EXIT_FAIL_CLOSED,
        "destructive git command must map to EXIT_FAIL_CLOSED (125), got: {exit_code}"
    );
}

#[test]
fn test_aider_destructive_git_commands_suite_fails_closed_125() {
    let test_cases: Vec<Vec<String>> = vec![
        vec!["reset".into(), "--hard".into()],
        vec!["reset".into(), "--hard=HEAD~1".into()],
        vec!["push".into(), "--force".into()],
        vec!["push".into(), "-f".into()],
        vec![
            "push".into(),
            "origin".into(),
            "--delete".into(),
            "branch".into(),
        ],
        vec!["clean".into(), "-f".into()],
        vec!["clean".into(), "-fd".into()],
        vec!["clean".into(), "-fdx".into()],
        vec!["checkout".into(), ".".into()],
        vec!["restore".into(), ".".into()],
        vec!["branch".into(), "-D".into(), "feature".into()],
    ];

    std::env::set_var("VETTO_GIT_GUARD", "1");
    for cmd in test_cases {
        let dispatch_result = dispatch("git", &cmd);
        assert!(
            dispatch_result.is_err(),
            "command {:?} must be blocked",
            cmd
        );
        let err = dispatch_result.unwrap_err();
        let code = map_error_to_exit_code(&err);
        assert_eq!(
            code, EXIT_FAIL_CLOSED,
            "command {:?} must map to Exit 125, got: {code}",
            cmd
        );
    }
    std::env::remove_var("VETTO_GIT_GUARD");
}

#[test]
fn test_aider_git_config_masking_and_rm_rf_git_prevention() {
    // 1. Verify standard secret deny paths contain .git/config
    let deny_paths = standard_secret_deny_paths();
    assert!(
        deny_paths.iter().any(|p| p.ends_with(".git/config")),
        "standard_secret_deny_paths must contain .git/config"
    );

    // 2. In a workspace with .git/config, verify deny resolution
    let temp = TempProject::new("aider-git-mask");
    let project = temp.path().join("project");
    let home = temp.path().join("home");
    let git_config = project.join(".git").join("config");
    fs::create_dir_all(project.join(".git")).expect("create .git");
    fs::write(&git_config, "[core]\nrepositoryformatversion = 0\n").expect("write .git/config");
    fs::create_dir_all(&home).expect("create home");

    let opts = PolicyLoadOptions {
        agent: Some("aider".to_string()),
        include_project_policy: false,
        ..Default::default()
    };

    let pol = load_with_options("default", None, &project, &home, Tier::Full, &opts)
        .expect("load aider policy");

    // Ensure .git/config is in deny_resolved
    assert!(
        pol.deny_resolved.iter().any(|d| d.path == git_config),
        ".git/config must be in deny_resolved to prevent credential theft"
    );

    // 3. Confirm benign operations are not destructive
    let benign_cmd: Vec<String> = vec!["status".into()];
    assert!(
        is_destructive_git_command(&benign_cmd).is_none(),
        "git status must not be blocked as destructive"
    );
}
