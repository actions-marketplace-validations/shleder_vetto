//! Integration tests for Phase 2: Tri-Plane Policy IR & Canonical Security Contract.

use vetto::policy_ir::{
    authorize_action, compile as legacy_compile, validate as legacy_validate, Action,
    ActionVerdict, CompilerError, ExecutionState, ExecutionStateMachine, NetworkMode,
    PolicyCompiler, PolicyError, RequestedPolicy, SecurityContract, SecurityLevel,
    StateTransitionError,
};

#[test]
fn test_legacy_policy_ir_compatibility() {
    let req = RequestedPolicy {
        level: SecurityLevel::Standard,
        allow_read: vec!["/workspace".to_string(), "/tmp".to_string()],
        allow_write: vec!["/workspace/target".to_string()],
    };
    let compiled = legacy_compile(&req).expect("legacy compile should succeed");
    assert_eq!(compiled.level, SecurityLevel::Standard);
    assert!(legacy_validate(&compiled).is_ok());
}
#[test]
fn test_policy_compiler_contract_sealing() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_p2_test_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    let sub_write = ws.join("src/output.rs");
    let contract = PolicyCompiler::compile(
        "claude",
        &ws,
        Some(NetworkMode::Allowlist),
        std::slice::from_ref(&ws),
        &[sub_write],
    )
    .expect("compile contract");

    assert_eq!(contract.contract_version, 1);
    assert_eq!(contract.agent_identity.agent_name, "claude");
    assert_eq!(contract.network.mode, NetworkMode::Allowlist);
    assert!(!contract.contract_digest_blake3.is_empty());
    assert!(contract.verify_digest(), "digest verification must succeed");

    // Anti-tamper verification
    let mut tampered = contract.clone();
    tampered.resources.max_pids = 99999;
    assert!(
        !tampered.verify_digest(),
        "tampered contract must fail digest verification"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_policy_compiler_ancestor_containment_and_escape() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_p2_escape_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    // Write path that escapes the workspace
    let escape_target = temp_dir.join("escaped_file.txt");
    let res = PolicyCompiler::compile(
        "codex",
        &ws,
        None,
        std::slice::from_ref(&ws),
        &[escape_target],
    );

    assert!(
        matches!(res, Err(CompilerError::ConflictingPermissions(_))),
        "escaping write target must fail with ConflictingPermissions"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_policy_compiler_mask_path_collision() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_p2_mask_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    // Attempting to target .env inside workspace
    let env_target = ws.join(".env");
    let res = PolicyCompiler::compile("aider", &ws, None, std::slice::from_ref(&ws), &[env_target]);

    assert!(
        matches!(res, Err(CompilerError::ConflictingPermissions(_))),
        "write target colliding with .env mask must be rejected"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_execution_state_machine_transitions() {
    let mut fsm = ExecutionStateMachine::new();
    assert_eq!(fsm.current_state(), ExecutionState::Intent);

    let expected_steps = [
        ExecutionState::PolicyCompiled,
        ExecutionState::ContractSealed,
        ExecutionState::Prepare,
        ExecutionState::Spawn,
        ExecutionState::Enforce,
        ExecutionState::Observe,
        ExecutionState::Terminate,
        ExecutionState::Cleanup,
        ExecutionState::Verify,
        ExecutionState::Attest,
        ExecutionState::Verdict,
        ExecutionState::Terminal,
    ];

    for step in expected_steps {
        fsm.transition(step).expect("valid transition");
        assert_eq!(fsm.current_state(), step);
    }
    assert!(fsm.is_terminal());

    // Transitioning from Terminal should fail
    let err = fsm.transition(ExecutionState::Intent).unwrap_err();
    assert!(matches!(
        err,
        StateTransitionError::InvalidTransition { .. }
    ));
}

#[test]
fn test_execution_state_machine_fail_closed() {
    let mut fsm = ExecutionStateMachine::new();
    fsm.transition(ExecutionState::PolicyCompiled).unwrap();

    let err = fsm.fail_closed("Simulated kernel LSM failure");
    assert!(matches!(err, StateTransitionError::FailClosed { .. }));
    assert_eq!(fsm.current_state(), ExecutionState::FailClosed);
    assert!(fsm.is_fail_closed());

    fsm.transition(ExecutionState::EmergencyCleanup).unwrap();
    fsm.transition(ExecutionState::Terminal).unwrap();
    assert!(fsm.is_terminal());
}

#[test]
fn test_contract_serde_roundtrip() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_p2_serde_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    let contract = PolicyCompiler::compile("claude", &ws, Some(NetworkMode::Allowlist), &[], &[])
        .expect("compile contract");

    // Serialization skips contract_digest_blake3 to prevent circularity
    let json = serde_json::to_string(&contract).expect("serialize contract");
    assert!(!json.contains("contract_digest_blake3"));

    // Deserialization must succeed with #[serde(default)]
    let deserialized: SecurityContract = serde_json::from_str(&json).expect("deserialize contract");
    assert_eq!(deserialized.agent_identity.agent_name, "claude");
    assert_eq!(deserialized.contract_digest_blake3, "");

    // When resealed, digest is valid
    let resealed = deserialized.unsealed().seal().expect("reseal");
    assert!(resealed.verify_digest());

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_policy_compiler_relative_read_paths() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_p2_relread_{}", std::process::id()));
    std::fs::create_dir_all(ws.join("src")).expect("create test workspace src");

    // Pass relative path "src" in raw_reads
    let contract =
        PolicyCompiler::compile("claude", &ws, None, &[std::path::PathBuf::from("src")], &[])
            .expect("compile contract with relative read path");

    let canon_src = ws.join("src").canonicalize().unwrap();
    assert!(contract.filesystem.allow_read.contains(&canon_src));
    assert!(contract.filesystem.allow_read.contains(&ws));

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_policy_compiler_git_dir_collision() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_p2_git_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    let git_dir = ws.join(".git");
    let res = PolicyCompiler::compile("claude", &ws, None, &[], &[git_dir]);
    assert!(
        matches!(res, Err(CompilerError::ConflictingPermissions(_))),
        "targeting .git directory must collide with .git/config secret mask"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_policy_compiler_directory_traversal_rejection() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_p2_trav_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    let traversal_rel = std::path::PathBuf::from("nonexistent/sub/../leak");
    let res = PolicyCompiler::compile("claude", &ws, None, &[], &[traversal_rel]);
    assert!(
        matches!(res, Err(CompilerError::ConflictingPermissions(_))),
        "relative directory traversal in write target must be rejected"
    );

    let sep = if cfg!(windows) { '\\' } else { '/' };
    let traversal_abs =
        std::path::PathBuf::from(format!("{}{sep}sub{sep}..{sep}leak", ws.display()));
    let res_abs = PolicyCompiler::compile("claude", &ws, None, &[], &[traversal_abs]);
    assert!(
        matches!(res_abs, Err(CompilerError::ConflictingPermissions(_))),
        "absolute directory traversal in write target must be rejected"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_execution_state_machine_fail_closed_idempotent() {
    let mut fsm = ExecutionStateMachine::new();
    fsm.transition(ExecutionState::PolicyCompiled).unwrap();

    let err1 = fsm.fail_closed("first error");
    assert!(matches!(err1, StateTransitionError::FailClosed { .. }));
    assert_eq!(fsm.current_state(), ExecutionState::FailClosed);

    // Re-entrant fail_closed must succeed idempotently
    let err2 = fsm.fail_closed("second error");
    assert!(matches!(err2, StateTransitionError::FailClosed { .. }));
    assert_eq!(fsm.current_state(), ExecutionState::FailClosed);

    fsm.transition(ExecutionState::EmergencyCleanup).unwrap();
    // EmergencyCleanup error can re-enter FailClosed or stay
    fsm.transition(ExecutionState::FailClosed).unwrap();
    fsm.transition(ExecutionState::EmergencyCleanup).unwrap();
    fsm.transition(ExecutionState::Terminal).unwrap();
    assert!(fsm.is_terminal());
}

// ============================================================================
// Milestone 1 Integration Tests: Capability Gate, SHA-256 (INV-36) & 4 Phases
// ============================================================================

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;
use vetto::config::NetMode as CliNetMode;
use vetto::policy::types::{DenyEntry, Policy, ResourceLimits};
use vetto::policy_ir::compiler::{EffectivePolicyInput, LoweredEnforcementMetadata};

// ----------------------------------------------------------------------------
// Group 1: Action Authorization Integration Tests (Capability Gate)
// ----------------------------------------------------------------------------

#[test]
fn test_action_authorization_allowed_workspace_io() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_m1_action_ok_{}", std::process::id()));
    std::fs::create_dir_all(ws.join("src")).expect("create test workspace");
    let test_file = ws.join("src/main.rs");
    std::fs::write(&test_file, b"fn main() {}").expect("write test file");

    let contract = PolicyCompiler::compile(
        "claude",
        &ws,
        Some(NetworkMode::Allowlist),
        std::slice::from_ref(&ws),
        std::slice::from_ref(&ws),
    )
    .expect("compile contract");

    // Workspace reads must be Allowed
    let read_verdict = authorize_action(&contract, &Action::FsRead(test_file.clone()));
    assert_eq!(read_verdict, ActionVerdict::Allowed);

    // Workspace writes must be Allowed
    let write_verdict = authorize_action(&contract, &Action::FsWrite(test_file));
    assert_eq!(write_verdict, ActionVerdict::Allowed);

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_action_authorization_blocked_secret_masks() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_m1_action_secrets_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    let contract = PolicyCompiler::compile(
        "codex",
        &ws,
        None,
        std::slice::from_ref(&ws),
        std::slice::from_ref(&ws),
    )
    .expect("compile contract");

    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root"));

    let secret_probes = vec![
        ws.join(".env"),
        ws.join(".git/config"),
        home.join(".ssh/id_rsa"),
        home.join(".aws/credentials"),
        home.join(".gnupg/secring.gpg"),
    ];

    for secret in secret_probes {
        // Read must be Denied
        let read_v = authorize_action(&contract, &Action::FsRead(secret.clone()));
        assert!(
            matches!(read_v, ActionVerdict::Denied { .. }),
            "reading secret {:?} must be denied",
            secret
        );

        // Write must be Denied
        let write_v = authorize_action(&contract, &Action::FsWrite(secret.clone()));
        assert!(
            matches!(write_v, ActionVerdict::Denied { .. }),
            "writing secret {:?} must be denied",
            secret
        );
    }

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_action_authorization_unallowed_paths() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_m1_action_unallowed_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    let contract = PolicyCompiler::compile(
        "aider",
        &ws,
        None,
        std::slice::from_ref(&ws),
        std::slice::from_ref(&ws),
    )
    .expect("compile contract");

    // Unallowed host write paths must be Denied
    let write_v = authorize_action(&contract, &Action::FsWrite(PathBuf::from("/etc/passwd")));
    assert!(
        matches!(write_v, ActionVerdict::Denied { .. }),
        "unallowed write to /etc/passwd must be denied"
    );

    // Unallowed read path must be Denied
    let read_v = authorize_action(&contract, &Action::FsRead(PathBuf::from("/root/shadow")));
    assert!(
        matches!(read_v, ActionVerdict::Denied { .. }),
        "unallowed read outside contract must be denied"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_action_authorization_network_modes() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_m1_action_net_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    // 1. NetworkMode::Off -> All network connections Denied
    let contract_off = PolicyCompiler::compile("claude", &ws, Some(NetworkMode::Off), &[], &[])
        .expect("compile contract off");

    let net_v = authorize_action(
        &contract_off,
        &Action::NetConnect {
            domain: "api.anthropic.com".into(),
            port: 443,
        },
    );
    assert!(
        matches!(net_v, ActionVerdict::Denied { .. }),
        "connections in NetMode::Off must be denied"
    );

    // 2. NetworkMode::Allowlist with explicit domains
    let mut contract_allow = contract_off.clone();
    contract_allow.network.mode = NetworkMode::Allowlist;
    contract_allow.network.allowed_domains = vec!["api.anthropic.com".into()];
    contract_allow.network.allowed_ports = vec![443];

    // Allowed domain + port
    let net_allowed = authorize_action(
        &contract_allow,
        &Action::NetConnect {
            domain: "api.anthropic.com".into(),
            port: 443,
        },
    );
    assert_eq!(net_allowed, ActionVerdict::Allowed);

    // Disallowed domain
    let net_denied = authorize_action(
        &contract_allow,
        &Action::NetConnect {
            domain: "evil.attacker.com".into(),
            port: 443,
        },
    );
    assert!(
        matches!(net_denied, ActionVerdict::Denied { .. }),
        "unlisted domain must be denied"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_action_authorization_process_exec() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_m1_action_exec_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    let mut contract =
        PolicyCompiler::compile("claude", &ws, None, &[], &[]).expect("compile contract");
    contract.agent_identity.invoked_binary = PathBuf::from("claude");
    contract.filesystem.allow_execute = vec![PathBuf::from("/bin/sh"), PathBuf::from("/usr/bin")];

    // Allowed binary in allow_execute
    let exec_ok = authorize_action(
        &contract,
        &Action::ProcessExec {
            binary: PathBuf::from("/bin/sh"),
            args: vec!["-c".into(), "echo 1".into()],
        },
    );
    assert_eq!(exec_ok, ActionVerdict::Allowed);

    // Allowed binary under /usr/bin allow_execute directory
    let exec_usr = authorize_action(
        &contract,
        &Action::ProcessExec {
            binary: PathBuf::from("/usr/bin/python3"),
            args: vec![],
        },
    );
    assert_eq!(exec_usr, ActionVerdict::Allowed);

    // Allowed invoked binary directly matching contract.agent_identity.invoked_binary
    let exec_invoked = authorize_action(
        &contract,
        &Action::ProcessExec {
            binary: PathBuf::from("claude"),
            args: vec![],
        },
    );
    assert_eq!(exec_invoked, ActionVerdict::Allowed);

    // Disallowed binary outside allowed paths
    let exec_bad = authorize_action(
        &contract,
        &Action::ProcessExec {
            binary: PathBuf::from("/tmp/malware"),
            args: vec![],
        },
    );
    assert!(
        matches!(exec_bad, ActionVerdict::Denied { .. }),
        "binary not in allow_execute must be denied"
    );

    let exec_unauthorized = authorize_action(
        &contract,
        &Action::ProcessExec {
            binary: PathBuf::from("unauthorized_binary"),
            args: vec![],
        },
    );
    assert!(
        matches!(exec_unauthorized, ActionVerdict::Denied { .. }),
        "unauthorized binary must be denied"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

// ----------------------------------------------------------------------------
// Group 2: Sealed Contract SHA-256 Verification & Determinism (INV-36)
// ----------------------------------------------------------------------------

#[test]
fn test_sealed_contract_sha256_hash_structure() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_m1_sha256_struct_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    let contract = PolicyCompiler::compile("claude", &ws, Some(NetworkMode::Allowlist), &[], &[])
        .expect("compile contract");

    // SHA-256 hash must be exactly 64 lowercase hex characters
    assert_eq!(
        contract.sealed_contract_hash.len(),
        64,
        "sealed_contract_hash must be a 64-character SHA-256 hex string"
    );
    assert!(
        contract
            .sealed_contract_hash
            .chars()
            .all(|c| c.is_ascii_hexdigit()),
        "sealed_contract_hash must be valid hexadecimal"
    );

    // Self-verification must succeed
    assert!(
        contract.verify_sha256(),
        "verify_sha256 must pass on clean contract"
    );
    assert!(contract.verify_sealed().is_ok(), "verify_sealed must pass");

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_sealed_contract_sha256_determinism() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_m1_sha256_det_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    let policy = Policy {
        name: "test-deterministic".into(),
        allow_read: vec![ws.clone()],
        limits: ResourceLimits {
            processes: Some(64),
            ..Default::default()
        },
        ..Default::default()
    };

    let argv = vec!["/bin/true".to_string()];
    let env = BTreeMap::new();
    let net = CliNetMode::Off;

    let input1 = EffectivePolicyInput {
        policy: &policy,
        argv: &argv,
        cwd: &ws,
        env: &env,
        net: &net,
        nonce: "deterministic-fixed-nonce",
        timeout: None,
        tier: None,
        backend: "deterministic-backend".into(),
        observe_seccomp: false,
        debug_ports: None,
    };
    let contract1 = PolicyCompiler::compile_effective(input1).expect("compile contract 1");

    let input2 = EffectivePolicyInput {
        policy: &policy,
        argv: &argv,
        cwd: &ws,
        env: &env,
        net: &net,
        nonce: "deterministic-fixed-nonce",
        timeout: None,
        tier: None,
        backend: "deterministic-backend".into(),
        observe_seccomp: false,
        debug_ports: None,
    };
    let contract2 = PolicyCompiler::compile_effective(input2).expect("compile contract 2");

    // Deterministic hashing invariant INV-36: identical inputs produce identical hash
    assert_eq!(
        contract1.sealed_contract_hash,
        contract2.sealed_contract_hash
    );
    assert_eq!(
        contract1.contract_digest_blake3,
        contract2.contract_digest_blake3
    );

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_sealed_contract_sha256_dual_digest_integrity() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_m1_dual_digest_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    let contract =
        PolicyCompiler::compile("claude", &ws, None, &[], &[]).expect("compile contract");

    // Both BLAKE3 and SHA-256 digests must independently verify
    assert!(
        contract.verify_digest(),
        "BLAKE3 digest verification must pass"
    );
    assert!(
        contract.verify_sha256(),
        "SHA-256 digest verification must pass"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

// ----------------------------------------------------------------------------
// Group 3: 5-Vector Anti-Tamper Detection Tests
// ----------------------------------------------------------------------------

#[test]
fn test_anti_tamper_resources_mutation() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_m1_tamper_res_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    let contract = PolicyCompiler::compile("codex", &ws, None, &[], &[]).expect("compile contract");

    // Vector 1: Tamper with resource ceilings
    let mut tampered = contract.clone();
    tampered.resources.max_pids = 99999;

    assert!(
        !tampered.verify_sha256(),
        "SHA-256 verification must detect max_pids tampering"
    );
    assert!(
        !tampered.verify_digest(),
        "BLAKE3 verification must detect max_pids tampering"
    );
    assert!(
        tampered.verify_sealed().is_err(),
        "verify_sealed must return Err on tampered contract"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_anti_tamper_filesystem_mutation() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_m1_tamper_fs_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    let contract = PolicyCompiler::compile("aider", &ws, None, &[], &[]).expect("compile contract");

    // Vector 2: Tamper with filesystem allow_write by adding an unauthorized root
    let mut tampered = contract.clone();
    tampered.filesystem.allow_write.push(PathBuf::from("/etc"));

    assert!(
        !tampered.verify_sha256(),
        "SHA-256 verification must detect allow_write injection"
    );
    assert!(
        !tampered.verify_digest(),
        "BLAKE3 verification must detect allow_write injection"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_anti_tamper_secret_mask_removal() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_m1_tamper_mask_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    let contract =
        PolicyCompiler::compile("claude", &ws, None, &[], &[]).expect("compile contract");

    // Vector 3: Tamper with secret mask paths (strip protections)
    let mut tampered = contract.clone();
    tampered.filesystem.mask_paths.clear();

    assert!(
        !tampered.verify_sha256(),
        "SHA-256 verification must detect mask_paths removal"
    );
    assert!(
        !tampered.verify_digest(),
        "BLAKE3 verification must detect mask_paths removal"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_anti_tamper_network_mutation() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_m1_tamper_net_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    let contract = PolicyCompiler::compile("cursor", &ws, Some(NetworkMode::Off), &[], &[])
        .expect("compile contract");

    // Vector 4: Tamper with network mode or domain allowlist
    let mut tampered = contract.clone();
    tampered.network.mode = NetworkMode::Direct;

    assert!(
        !tampered.verify_sha256(),
        "SHA-256 verification must detect network mode elevation"
    );

    let mut tampered_domains = contract.clone();
    tampered_domains
        .network
        .allowed_domains
        .push("attacker.example.com".into());
    assert!(
        !tampered_domains.verify_sha256(),
        "SHA-256 verification must detect domain injection"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_anti_tamper_env_injection() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_m1_tamper_env_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    let contract =
        PolicyCompiler::compile("claude", &ws, None, &[], &[]).expect("compile contract");

    // Vector 5: Tamper with environment variables (leaking secrets)
    let mut tampered = contract.clone();
    tampered
        .environment
        .pass_through_vars
        .push("AWS_SECRET_ACCESS_KEY".into());

    assert!(
        !tampered.verify_sha256(),
        "SHA-256 verification must detect credential variable pass-through injection"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

// ----------------------------------------------------------------------------
// Group 4: 4-Phase PolicyCompiler::compile_effective Validation Tests
// ----------------------------------------------------------------------------

#[test]
fn test_compile_effective_phase1_traversal_rejection() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_m1_eff_p1_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    // 1. Path traversal in allow_read
    let policy_read_trav = Policy {
        allow_read: vec![PathBuf::from("subdir/../../leak")],
        ..Default::default()
    };
    let input = EffectivePolicyInput {
        policy: &policy_read_trav,
        argv: &["/bin/true".into()],
        cwd: &ws,
        env: &BTreeMap::new(),
        net: &CliNetMode::Off,
        nonce: "test-eff-p1-1",
        timeout: None,
        tier: None,
        backend: "test".into(),
        observe_seccomp: false,
        debug_ports: None,
    };
    let res = PolicyCompiler::compile_effective(input);
    assert!(
        matches!(res, Err(CompilerError::ConflictingPermissions(_))),
        "read path traversal must be rejected"
    );

    // 2. Path traversal in allow_write
    let policy_write_trav = Policy {
        allow_write: vec![PathBuf::from("../escape_write")],
        ..Default::default()
    };
    let input2 = EffectivePolicyInput {
        policy: &policy_write_trav,
        argv: &["/bin/true".into()],
        cwd: &ws,
        env: &BTreeMap::new(),
        net: &CliNetMode::Off,
        nonce: "test-eff-p1-2",
        timeout: None,
        tier: None,
        backend: "test".into(),
        observe_seccomp: false,
        debug_ports: None,
    };
    let res2 = PolicyCompiler::compile_effective(input2);
    assert!(
        matches!(res2, Err(CompilerError::ConflictingPermissions(_))),
        "write path traversal must be rejected"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_compile_effective_phase2_ancestor_containment_and_escape() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_m1_eff_p2_esc_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    // Relative path climbing out of workspace
    let policy_rel = Policy {
        allow_write: vec![PathBuf::from("../outside_escape.txt")],
        ..Default::default()
    };
    let input_rel = EffectivePolicyInput {
        policy: &policy_rel,
        argv: &["/bin/true".into()],
        cwd: &ws,
        env: &BTreeMap::new(),
        net: &CliNetMode::Off,
        nonce: "test-eff-p2-esc",
        timeout: None,
        tier: None,
        backend: "test".into(),
        observe_seccomp: false,
        debug_ports: None,
    };
    let res_rel = PolicyCompiler::compile_effective(input_rel);
    assert!(
        matches!(res_rel, Err(CompilerError::ConflictingPermissions(_))),
        "relative write escaping workspace must be rejected"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_compile_effective_phase2_system_root_protection() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_m1_eff_p2_sys_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    for bad_path in &[
        PathBuf::from("/"),
        PathBuf::from("/etc"),
        PathBuf::from("/etc/shadow"),
        PathBuf::from("/usr/bin/hack"),
        PathBuf::from("/bin/evil"),
    ] {
        let policy = Policy {
            allow_write: vec![bad_path.clone()],
            ..Default::default()
        };
        let input = EffectivePolicyInput {
            policy: &policy,
            argv: &["/bin/true".into()],
            cwd: &ws,
            env: &BTreeMap::new(),
            net: &CliNetMode::Off,
            nonce: "test-eff-p2-sys",
            timeout: None,
            tier: None,
            backend: "test".into(),
            observe_seccomp: false,
            debug_ports: None,
        };
        let res = PolicyCompiler::compile_effective(input);
        assert!(
            matches!(res, Err(CompilerError::ConflictingPermissions(_))),
            "write target {:?} exposing system root must be rejected",
            bad_path
        );
    }

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_compile_effective_phase3_secret_mask_precedence() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_m1_eff_p3_mask_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    // 1. Direct collision with .env mask
    let policy_env = Policy {
        allow_write: vec![ws.join(".env")],
        ..Default::default()
    };
    let input = EffectivePolicyInput {
        policy: &policy_env,
        argv: &["/bin/true".into()],
        cwd: &ws,
        env: &BTreeMap::new(),
        net: &CliNetMode::Off,
        nonce: "test-eff-p3-1",
        timeout: None,
        tier: None,
        backend: "test".into(),
        observe_seccomp: false,
        debug_ports: None,
    };
    let res = PolicyCompiler::compile_effective(input);
    assert!(
        matches!(res, Err(CompilerError::ConflictingPermissions(_))),
        "colliding write with .env mask must be rejected"
    );

    // 2. Collision with policy.deny_resolved
    let custom_secret = ws.join("custom_secret.key");
    let policy_deny = Policy {
        allow_write: vec![custom_secret.clone()],
        deny_resolved: vec![DenyEntry {
            path: custom_secret,
            is_dir: false,
        }],
        ..Default::default()
    };
    let input2 = EffectivePolicyInput {
        policy: &policy_deny,
        argv: &["/bin/true".into()],
        cwd: &ws,
        env: &BTreeMap::new(),
        net: &CliNetMode::Off,
        nonce: "test-eff-p3-2",
        timeout: None,
        tier: None,
        backend: "test".into(),
        observe_seccomp: false,
        debug_ports: None,
    };
    let res2 = PolicyCompiler::compile_effective(input2);
    assert!(
        matches!(res2, Err(CompilerError::ConflictingPermissions(_))),
        "write target colliding with deny_resolved must be rejected"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_compile_effective_phase4_sealed_lowering() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_m1_eff_p4_lowering_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    let policy = Policy {
        name: "test-phase4".into(),
        allow_read: vec![ws.clone(), PathBuf::from("/usr")],
        allow_write: vec![ws.clone()],
        net_connect_ports: vec![443, 8080],
        ..Default::default()
    };

    let argv = vec!["/bin/sh".to_string(), "-c".to_string(), "ls".to_string()];
    let input = EffectivePolicyInput {
        policy: &policy,
        argv: &argv,
        cwd: &ws,
        env: &BTreeMap::new(),
        net: &CliNetMode::Allowlist(vec!["api.anthropic.com".into()]),
        nonce: "test-phase4-sealed-nonce",
        timeout: Some(Duration::from_secs(60)),
        tier: None,
        backend: "linux-enforce".into(),
        observe_seccomp: true,
        debug_ports: None,
    };

    let contract = PolicyCompiler::compile_effective(input).expect("compile effective contract");

    // Verify dual sealing
    assert!(!contract.contract_digest_blake3.is_empty());
    assert!(!contract.sealed_contract_hash.is_empty());
    assert!(contract.verify_digest());
    assert!(contract.verify_sha256());

    // Verify lowering metadata structure
    let lowering: LoweredEnforcementMetadata = contract.lower_enforcement_metadata(4);
    assert_eq!(lowering.landlock_abi, 4);
    assert!(lowering.read_paths.contains(&ws));
    assert!(lowering.write_paths.contains(&ws));
    assert!(lowering.network_connect_ports.contains(&443));
    assert!(lowering.network_connect_ports.contains(&8080));
    assert!(lowering.observe_seccomp);

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_capability_gate_action_authorization_e2e() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_gate_e2e_{}", std::process::id()));
    std::fs::create_dir_all(ws.join("src")).expect("create workspace");

    let contract = PolicyCompiler::compile(
        "claude",
        &ws,
        Some(NetworkMode::Allowlist),
        &[ws.join("src")],
        &[ws.join("src/generated.rs")],
    )
    .expect("compile contract");

    // FsRead allowed in workspace
    assert_eq!(
        authorize_action(&contract, &Action::FsRead(ws.join("src/lib.rs"))),
        ActionVerdict::Allowed
    );

    // FsWrite allowed in designated target
    assert_eq!(
        authorize_action(&contract, &Action::FsWrite(ws.join("src/generated.rs"))),
        ActionVerdict::Allowed
    );

    // FsWrite denied to unlisted path
    assert!(authorize_action(&contract, &Action::FsWrite(ws.join("src/other.rs"))).is_denied());

    // FsRead denied to secret .env
    assert!(authorize_action(&contract, &Action::FsRead(ws.join(".env"))).is_denied());

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_policy_error_exit_codes_and_reexports() {
    let err_compile = PolicyError::CompilationFailed("bad syntax".into());
    assert_eq!(err_compile.exit_code(), 125);
    assert_eq!(
        format!("{err_compile}"),
        "Policy compilation failed: bad syntax"
    );

    let err_verify = PolicyError::VerificationFailed("hash mismatch".into());
    assert_eq!(err_verify.exit_code(), 125);
    assert_eq!(
        format!("{err_verify}"),
        "Sealed contract verification failed: hash mismatch"
    );

    let err_lockdown = PolicyError::LockdownViolation("blocked mutation".into());
    assert_eq!(err_lockdown.exit_code(), 126);
    assert_eq!(
        format!("{err_lockdown}"),
        "Policy lockdown violation: blocked mutation"
    );
}

#[test]
fn test_compile_effective_lexical_normalization_dots() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_norm_dots_{}", std::process::id()));
    std::fs::create_dir_all(ws.join("src")).expect("create workspace");

    let raw_read = ws.join("./src/./lib.rs");
    let raw_write = ws.join("./src/output.rs");

    let policy = Policy {
        allow_read: vec![raw_read],
        allow_write: vec![raw_write],
        ..Policy::default()
    };

    let argv = vec!["/bin/sh".to_string()];
    let env = BTreeMap::new();
    let net = CliNetMode::Off;

    let input = EffectivePolicyInput {
        policy: &policy,
        argv: &argv,
        cwd: &ws,
        env: &env,
        net: &net,
        nonce: "test-norm-dots",
        timeout: None,
        tier: None,
        backend: "test".into(),
        observe_seccomp: false,
        debug_ports: None,
    };

    let contract = PolicyCompiler::compile_effective(input).expect("compile effective");

    // All allow_read and allow_write entries must be lexically normalized (no '.' components)
    for p in &contract.filesystem.allow_read {
        assert!(
            !p.components()
                .any(|c| matches!(c, std::path::Component::CurDir)),
            "allow_read path {:?} contains CurDir component",
            p
        );
    }
    for p in &contract.filesystem.allow_write {
        assert!(
            !p.components()
                .any(|c| matches!(c, std::path::Component::CurDir)),
            "allow_write path {:?} contains CurDir component",
            p
        );
    }

    let _ = std::fs::remove_dir_all(&ws);
}

// ============================================================================
// Milestone 2 Integration Tests: 12-State FSM, Extinction Guard & Verdict Engine
// ============================================================================

use vetto::audit::verdict::{
    EvidenceStrength, FinalVerdict, SecurityVerdict, VerdictEngine, VerdictStatus,
};
use vetto::exit_codes::EXIT_FAIL_CLOSED;

/// Helper to create a sealed mock contract for Authoritative Verdict Engine tests.
fn create_test_verdict_contract() -> SecurityContract {
    use std::path::PathBuf;
    use vetto::policy_ir::{
        AgentIdentity, AttestationContract, EnvironmentContract, FilesystemContract,
        NetworkContract, NetworkMode, ResourceContract, UnsealedSecurityContract,
    };

    let unsealed = UnsealedSecurityContract {
        production: None,
        crypto: Default::default(),
        contract_version: 1,
        contract_id: "m2-test-contract-001".to_string(),
        session_nonce: "nonce-m2-verdict-test".to_string(),
        agent_identity: AgentIdentity {
            agent_name: "test-agent".to_string(),
            agent_preset: "test".to_string(),
            agent_version: "0.2.25".to_string(),
            invoked_binary: PathBuf::from("/bin/sh"),
            invoked_args: vec!["-c".to_string(), "echo ok".to_string()],
        },
        filesystem: FilesystemContract {
            workspace_root: PathBuf::from("/workspace"),
            allow_read: vec![PathBuf::from("/workspace")],
            allow_write: vec![PathBuf::from("/workspace")],
            allow_execute: vec![PathBuf::from("/bin")],
            mask_paths: vec![PathBuf::from("/home/user/.ssh")],
            cow_overlay: true,
            execution_root_ro: true,
            shadow: false,
        },
        network: NetworkContract {
            mode: NetworkMode::Off,
            allowed_domains: vec![],
            allowed_ports: vec![],
            block_cloud_metadata: true,
            block_loopback_daemons: true,
        },
        resources: ResourceContract {
            max_pids: 128,
            max_memory_bytes: 2 * 1024 * 1024 * 1024,
            max_cpu_percent: 100,
            max_wall_time_ms: 120_000,
            max_stdout_bytes: 10 * 1024 * 1024,
            max_file_size_bytes: 100 * 1024 * 1024,
        },
        environment: EnvironmentContract {
            pass_through_vars: vec!["PATH".to_string()],
            explicit_vars: std::collections::BTreeMap::new(),
            redacted_patterns: vec!["*_KEY".to_string()],
            inject_session_nonce: true,
        },
        attestation: AttestationContract {
            generate_audit_jsonl: true,
            sign_minisign: false,
            sign_cosign_slsa: true,
            evidence_level_minimum: "HOST_FACT".to_string(),
        },
    };
    unsealed
        .seal()
        .expect("seal mock contract for verdict tests")
}

// ----------------------------------------------------------------------------
// Test 1: 12-State FSM Happy Path Transition Sequence
// Sequence: Uninitialized -> PolicyCompiled -> PreflightPassed -> IsolationConfigured
//           -> ChildSpawned -> Running -> Terminating -> CleanedUp -> Completed
// ----------------------------------------------------------------------------
#[test]
fn test_fsm_12_state_canonical_happy_path() {
    let mut fsm = ExecutionStateMachine::from_state(ExecutionState::Uninitialized);
    assert_eq!(fsm.current_state(), ExecutionState::Uninitialized);
    assert!(!fsm.is_terminal());
    assert!(!fsm.is_fail_closed());

    let canonical_sequence = [
        ExecutionState::PolicyCompiled,
        ExecutionState::PreflightPassed,
        ExecutionState::IsolationConfigured,
        ExecutionState::ChildSpawned,
        ExecutionState::Running,
        ExecutionState::Terminating,
        ExecutionState::CleanedUp,
        ExecutionState::Completed,
    ];

    for step in canonical_sequence {
        fsm.transition(step).unwrap_or_else(|e| {
            panic!("Expected valid transition to {:?}, got error: {}", step, e);
        });
        assert_eq!(fsm.current_state(), step);
    }

    assert!(
        fsm.is_terminal(),
        "Completed must be recognized as terminal state"
    );
    assert!(!fsm.is_fail_closed(), "Happy path must not be fail-closed");

    // Negative verification: no transition allowed from Completed
    let err = fsm.transition(ExecutionState::Running).unwrap_err();
    assert!(
        matches!(err, StateTransitionError::InvalidTransition { .. }),
        "Transition from terminal Completed state must be rejected"
    );

    // History verification
    let history = fsm.history();
    assert_eq!(
        history.len(),
        9,
        "Initial + 8 transitions = 9 history records"
    );
    assert_eq!(history.first().unwrap().0, ExecutionState::Uninitialized);
    assert_eq!(history.last().unwrap().0, ExecutionState::Completed);
}

// ----------------------------------------------------------------------------
// Test 2: SignalReceived Transition
// Sequence: Running -> SignalReceived -> Terminating -> CleanedUp -> Completed
// ----------------------------------------------------------------------------
#[test]
fn test_fsm_signal_received_transition() {
    let mut fsm = ExecutionStateMachine::from_state(ExecutionState::Running);
    assert_eq!(fsm.current_state(), ExecutionState::Running);

    // External OS signal (SIGINT, SIGTERM, timeout deadline) arrives
    fsm.transition(ExecutionState::SignalReceived)
        .expect("Transition from Running to SignalReceived must be valid");
    assert_eq!(fsm.current_state(), ExecutionState::SignalReceived);
    assert!(!fsm.is_terminal());
    assert!(!fsm.is_fail_closed());

    // Disallowed jumps from SignalReceived
    let bad_jump_running = fsm.transition(ExecutionState::Running).unwrap_err();
    assert!(matches!(
        bad_jump_running,
        StateTransitionError::InvalidTransition { .. }
    ));

    let bad_jump_completed = fsm.transition(ExecutionState::Completed).unwrap_err();
    assert!(matches!(
        bad_jump_completed,
        StateTransitionError::InvalidTransition { .. }
    ));

    // Valid continuation: SignalReceived -> Terminating -> CleanedUp -> Completed
    fsm.transition(ExecutionState::Terminating)
        .expect("SignalReceived -> Terminating must be valid");
    assert_eq!(fsm.current_state(), ExecutionState::Terminating);

    fsm.transition(ExecutionState::CleanedUp)
        .expect("Terminating -> CleanedUp must be valid");
    assert_eq!(fsm.current_state(), ExecutionState::CleanedUp);

    fsm.record_extinction_result(0);
    fsm.transition(ExecutionState::Completed)
        .expect("CleanedUp -> Completed must be valid with 0 survivors");
    assert_eq!(fsm.current_state(), ExecutionState::Completed);
    assert!(fsm.is_terminal());
}

// ----------------------------------------------------------------------------
// Test 3: Extinction Guard Verification
// Invariant: Block transition to Completed / Terminal when surviving_descendants > 0
// ----------------------------------------------------------------------------
#[test]
fn test_fsm_extinction_guard_blocks_completion_and_terminal() {
    // 3.1: Canonical pipeline (CleanedUp -> Completed)
    let mut fsm_canonical = ExecutionStateMachine::from_state(ExecutionState::CleanedUp);
    fsm_canonical.record_extinction_result(3); // 3 escaped descendant processes
    assert_eq!(fsm_canonical.surviving_descendants(), Some(3));

    let err_completed = fsm_canonical
        .transition(ExecutionState::Completed)
        .unwrap_err();
    match err_completed {
        StateTransitionError::InvalidTransition { from, to, reason } => {
            assert_eq!(from, ExecutionState::CleanedUp);
            assert_eq!(to, ExecutionState::Completed);
            assert!(
                reason.contains("surviving") || reason.contains("descendant"),
                "Error reason must cite surviving descendant processes: {reason}"
            );
        }
        other => panic!("Expected InvalidTransition, got: {:?}", other),
    }
    assert_eq!(fsm_canonical.current_state(), ExecutionState::CleanedUp);
    assert!(!fsm_canonical.is_terminal());

    // Resetting to 0 surviving processes allows completion
    fsm_canonical.record_extinction_result(0);
    fsm_canonical.transition(ExecutionState::Completed).unwrap();
    assert!(fsm_canonical.is_terminal());

    // 3.2: Phase 3 pipeline (Verdict -> Terminal)
    let mut fsm_phase3 = ExecutionStateMachine::from_state(ExecutionState::Verdict);
    fsm_phase3.record_extinction_result(1); // 1 leaked process
    assert_eq!(fsm_phase3.surviving_descendants(), Some(1));

    let err_terminal = fsm_phase3.transition(ExecutionState::Terminal).unwrap_err();
    match err_terminal {
        StateTransitionError::InvalidTransition { from, to, reason } => {
            assert_eq!(from, ExecutionState::Verdict);
            assert_eq!(to, ExecutionState::Terminal);
            assert!(
                reason.contains("surviving") || reason.contains("descendant"),
                "Error reason must cite surviving descendant processes: {reason}"
            );
        }
        other => panic!("Expected InvalidTransition, got: {:?}", other),
    }
    assert_eq!(fsm_phase3.current_state(), ExecutionState::Verdict);
    assert!(!fsm_phase3.is_terminal());

    fsm_phase3.record_extinction_result(0);
    fsm_phase3.transition(ExecutionState::Terminal).unwrap();
    assert!(fsm_phase3.is_terminal());
}

// ----------------------------------------------------------------------------
// Test 4: Emergency Cleanup Transition from Any Active State (Exit 125)
// Invariant: EmergencyCleanup accessible from every active state (INV-01)
// ----------------------------------------------------------------------------
#[test]
fn test_fsm_emergency_cleanup_from_all_active_states() {
    assert_eq!(
        EXIT_FAIL_CLOSED, 125,
        "Fail-closed exit code must be 125 (INV-01)"
    );

    let active_canonical_states = [
        ExecutionState::Uninitialized,
        ExecutionState::PolicyCompiled,
        ExecutionState::PreflightPassed,
        ExecutionState::IsolationConfigured,
        ExecutionState::ChildSpawned,
        ExecutionState::Running,
        ExecutionState::SignalReceived,
        ExecutionState::Terminating,
        ExecutionState::CleanedUp,
    ];

    for state in active_canonical_states {
        // Direct transition to EmergencyCleanup
        let mut fsm = ExecutionStateMachine::from_state(state);
        fsm.transition(ExecutionState::EmergencyCleanup)
            .unwrap_or_else(|e| {
                panic!(
                    "Direct transition from {:?} to EmergencyCleanup must succeed: {}",
                    state, e
                );
            });
        assert_eq!(fsm.current_state(), ExecutionState::EmergencyCleanup);
        assert!(fsm.is_fail_closed());

        // Continuation from EmergencyCleanup to Terminal
        fsm.transition(ExecutionState::Terminal).unwrap();
        assert!(fsm.is_terminal());

        // Transition via fail_closed helper
        let mut fsm_helper = ExecutionStateMachine::from_state(state);
        let err = fsm_helper.fail_closed("Kernel LSM boundary violation");
        assert!(matches!(err, StateTransitionError::FailClosed { .. }));
        assert!(fsm_helper.is_fail_closed());
        assert!(
            fsm_helper.current_state() == ExecutionState::Failed
                || fsm_helper.current_state() == ExecutionState::FailClosed
        );

        fsm_helper
            .transition(ExecutionState::EmergencyCleanup)
            .unwrap();
        assert_eq!(fsm_helper.current_state(), ExecutionState::EmergencyCleanup);
    }

    let active_phase3_states = [
        ExecutionState::Intent,
        ExecutionState::ContractSealed,
        ExecutionState::Prepare,
        ExecutionState::Spawn,
        ExecutionState::Enforce,
        ExecutionState::Observe,
        ExecutionState::Terminate,
        ExecutionState::Cleanup,
        ExecutionState::Verify,
        ExecutionState::Attest,
        ExecutionState::Verdict,
    ];

    for state in active_phase3_states {
        let mut fsm = ExecutionStateMachine::from_state(state);
        fsm.transition(ExecutionState::EmergencyCleanup)
            .unwrap_or_else(|e| {
                panic!(
                    "Phase 3 transition from {:?} to EmergencyCleanup must succeed: {}",
                    state, e
                );
            });
        assert_eq!(fsm.current_state(), ExecutionState::EmergencyCleanup);
        assert!(fsm.is_fail_closed());
    }
}

// ----------------------------------------------------------------------------
// Test 5: Authoritative Verdict Engine Decoupling & Audit Export
// Tests:
// - Policy breach -> SecurityVerdict::Violated, exit_code: 125
// - Child exit code 1 without violation -> SecurityVerdict::Satisfied, exit_code: 1
// - Dropped evidence -> SecurityVerdict::Inconclusive, exit_code: 125
// - Clean run -> SecurityVerdict::Satisfied, exit_code: 0
// - Serialization check of to_audit_export()
// ----------------------------------------------------------------------------
#[test]
fn test_authoritative_verdict_engine_decoupling_and_export() {
    let contract = create_test_verdict_contract();

    // 5.1: Policy / Kernel Breach -> SecurityVerdict::Violated, exit_code: 125
    // 5.1.a: Kernel capability denials
    let v_denials = VerdictEngine::evaluate(&contract, 2, 0, 0, true, 0);
    assert_eq!(v_denials.security_verdict, SecurityVerdict::Violated);
    assert_eq!(v_denials.status, VerdictStatus::Fail);
    assert_eq!(v_denials.exit_code, 125);
    assert_eq!(v_denials.strength, EvidenceStrength::Strong);
    assert!(!v_denials.is_contract_satisfied());
    assert!(!v_denials.is_success());
    assert_eq!(v_denials.security_badge(), "VIOLATED [STRONG]");
    assert!(v_denials.reason.contains("2 kernel capability denials"));

    // 5.1.b: Unauthorized VFS writes (non-shadow)
    let v_writes = VerdictEngine::evaluate(&contract, 0, 1, 0, true, 0);
    assert_eq!(v_writes.security_verdict, SecurityVerdict::Violated);
    assert_eq!(v_writes.status, VerdictStatus::Fail);
    assert_eq!(v_writes.exit_code, 125);
    assert!(!v_writes.is_contract_satisfied());
    assert!(!v_writes.is_success());
    assert!(v_writes
        .reason
        .contains("writes outside authorized workspace"));

    // 5.1.c: Surviving zombie processes
    let v_zombies = VerdictEngine::evaluate(&contract, 0, 0, 3, true, 0);
    assert_eq!(v_zombies.security_verdict, SecurityVerdict::Violated);
    assert_eq!(v_zombies.status, VerdictStatus::Fail);
    assert_eq!(v_zombies.exit_code, 125);
    assert!(!v_zombies.is_contract_satisfied());
    assert!(!v_zombies.is_success());
    assert!(v_zombies
        .reason
        .contains("3 descendant processes escaped extinction"));

    // 5.2: Child Process Exit Code 1 Without Security Violation -> Satisfied, exit_code: 1
    // Decoupling Invariant: Workload failure does NOT equal security breach!
    let v_workload_err = VerdictEngine::evaluate(&contract, 0, 0, 0, true, 1);
    assert_eq!(
        v_workload_err.security_verdict,
        SecurityVerdict::Satisfied,
        "Security verdict MUST be Satisfied when no invariants were breached"
    );
    assert_eq!(
        v_workload_err.exit_code, 1,
        "Original child process exit code must be preserved"
    );
    assert_eq!(v_workload_err.status, VerdictStatus::Pass);
    assert!(
        v_workload_err.is_contract_satisfied(),
        "Contract invariants were fully satisfied"
    );
    assert!(
        !v_workload_err.is_success(),
        "Nonzero exit code must not be reported as overall clean success"
    );
    assert_eq!(v_workload_err.security_badge(), "SATISFIED [STRONG]");

    // 5.3: Dropped Evidence Channel -> SecurityVerdict::Inconclusive, exit_code: 125
    let v_inconclusive = VerdictEngine::evaluate(&contract, 0, 0, 0, false, 0);
    assert_eq!(
        v_inconclusive.security_verdict,
        SecurityVerdict::Inconclusive
    );
    assert_eq!(v_inconclusive.status, VerdictStatus::Inconclusive);
    assert_eq!(v_inconclusive.exit_code, 125);
    assert!(!v_inconclusive.is_contract_satisfied());
    assert!(!v_inconclusive.is_success());
    assert_eq!(v_inconclusive.security_badge(), "INCONCLUSIVE [STRONG]");
    assert!(v_inconclusive.reason.contains("dropped events"));

    // 5.4: Clean Run -> SecurityVerdict::Satisfied, exit_code: 0
    let v_clean = VerdictEngine::evaluate(&contract, 0, 0, 0, true, 0);
    assert_eq!(v_clean.security_verdict, SecurityVerdict::Satisfied);
    assert_eq!(v_clean.status, VerdictStatus::Pass);
    assert_eq!(v_clean.exit_code, 0);
    assert!(v_clean.is_contract_satisfied());
    assert!(v_clean.is_success());
    assert_eq!(v_clean.display_badge(), "PASS [STRONG]");
    assert_eq!(v_clean.security_badge(), "SATISFIED [STRONG]");
    assert_eq!(
        v_clean.recommended_action(),
        "Commit CoW changes to host workspace."
    );

    // 5.5: Serialization Check of to_audit_export()
    // 5.5.a: Clean export serialization
    let clean_export = v_clean.to_audit_export();
    assert!(
        clean_export.is_object(),
        "Export must produce a JSON object"
    );
    assert_eq!(clean_export["status"], "PASS");
    assert_eq!(clean_export["strength"], "STRONG");
    assert_eq!(clean_export["security_verdict"], "SATISFIED");
    assert_eq!(clean_export["exit_code"], 0);
    assert_eq!(clean_export["badge"], "PASS [STRONG]");
    assert_eq!(clean_export["security_badge"], "SATISFIED [STRONG]");
    assert_eq!(clean_export["is_success"], true);
    assert_eq!(clean_export["is_contract_satisfied"], true);
    assert!(clean_export["reason"].is_string());
    assert_eq!(
        clean_export["recommended_action"],
        "Commit CoW changes to host workspace."
    );

    // JSON round-trip verification
    let clean_json_str = serde_json::to_string(&clean_export).expect("serialize export to string");
    let clean_parsed: serde_json::Value =
        serde_json::from_str(&clean_json_str).expect("deserialize export string");
    assert_eq!(clean_parsed, clean_export);

    // 5.5.b: Breach export serialization
    let breach_export = v_denials.to_audit_export();
    assert_eq!(breach_export["status"], "FAIL");
    assert_eq!(breach_export["security_verdict"], "VIOLATED");
    assert_eq!(breach_export["exit_code"], 125);
    assert_eq!(breach_export["security_badge"], "VIOLATED [STRONG]");
    assert_eq!(breach_export["is_success"], false);
    assert_eq!(breach_export["is_contract_satisfied"], false);
    assert_eq!(
        breach_export["recommended_action"],
        "Wipe CoW layer; abort session immediately."
    );

    // 5.5.c: Inconclusive export serialization
    let inconc_export = v_inconclusive.to_audit_export();
    assert_eq!(inconc_export["status"], "INCONCLUSIVE");
    assert_eq!(inconc_export["security_verdict"], "INCONCLUSIVE");
    assert_eq!(inconc_export["exit_code"], 125);
    assert_eq!(inconc_export["security_badge"], "INCONCLUSIVE [STRONG]");
    assert_eq!(
        inconc_export["recommended_action"],
        "Wipe CoW layer; audit ledger inconclusive."
    );

    // 5.6: Direct FinalVerdict constructor validation
    let constructed = FinalVerdict::new(
        VerdictStatus::Pass,
        EvidenceStrength::Strong,
        SecurityVerdict::Satisfied,
        0,
        "Workload completed with zero boundary violations",
    );
    assert_eq!(constructed.security_verdict, SecurityVerdict::Satisfied);
    assert_eq!(constructed.exit_code, 0);
    assert!(constructed.is_contract_satisfied());
    assert!(constructed.is_success());
}

// ----------------------------------------------------------------------------
// Test 6: FSM Transition Hardening Regressions (M2 Remediation)
// ----------------------------------------------------------------------------
#[test]
fn test_fsm_transition_hardening_regressions() {
    // 6.1: PolicyCompiled -> IsolationConfigured must be rejected (cannot skip PreflightPassed)
    let mut fsm_compiled = ExecutionStateMachine::from_state(ExecutionState::PolicyCompiled);
    let err_skip_preflight = fsm_compiled
        .transition(ExecutionState::IsolationConfigured)
        .unwrap_err();
    assert!(
        matches!(
            err_skip_preflight,
            StateTransitionError::InvalidTransition {
                from: ExecutionState::PolicyCompiled,
                to: ExecutionState::IsolationConfigured,
                ..
            }
        ),
        "Skipping PreflightPassed must be disallowed: {:?}",
        err_skip_preflight
    );

    // 6.2: EmergencyCleanup -> Completed must be rejected
    let mut fsm_emergency = ExecutionStateMachine::from_state(ExecutionState::EmergencyCleanup);
    let err_emergency_completed = fsm_emergency
        .transition(ExecutionState::Completed)
        .unwrap_err();
    assert!(
        matches!(
            err_emergency_completed,
            StateTransitionError::InvalidTransition {
                from: ExecutionState::EmergencyCleanup,
                to: ExecutionState::Completed,
                ..
            }
        ),
        "EmergencyCleanup -> Completed must be disallowed: {:?}",
        err_emergency_completed
    );

    // 6.3: Cleanup -> Completed must be rejected (cannot skip Verify/Attest/Verdict)
    let mut fsm_cleanup = ExecutionStateMachine::from_state(ExecutionState::Cleanup);
    let err_cleanup_completed = fsm_cleanup
        .transition(ExecutionState::Completed)
        .unwrap_err();
    assert!(
        matches!(
            err_cleanup_completed,
            StateTransitionError::InvalidTransition {
                from: ExecutionState::Cleanup,
                to: ExecutionState::Completed,
                ..
            }
        ),
        "Cleanup -> Completed must be disallowed: {:?}",
        err_cleanup_completed
    );

    // 6.4: ExecutionState::Failed and ExecutionState::FailClosed are terminal
    assert!(
        ExecutionState::Failed.is_terminal(),
        "ExecutionState::Failed must be terminal"
    );
    assert!(
        ExecutionState::FailClosed.is_terminal(),
        "ExecutionState::FailClosed must be terminal"
    );

    let fsm_failed = ExecutionStateMachine::from_state(ExecutionState::Failed);
    assert!(
        fsm_failed.is_terminal(),
        "ExecutionStateMachine in Failed state must report is_terminal == true"
    );

    let fsm_fail_closed = ExecutionStateMachine::from_state(ExecutionState::FailClosed);
    assert!(
        fsm_fail_closed.is_terminal(),
        "ExecutionStateMachine in FailClosed state must report is_terminal == true"
    );
}

// ----------------------------------------------------------------------------
// Test 7: Shadow Mode With Severed Evidence Channel Priority (M2 Remediation)
// ----------------------------------------------------------------------------
#[test]
fn test_verdict_shadow_mode_severed_evidence_priority() {
    let mut contract = create_test_verdict_contract();
    contract.filesystem.shadow = true;

    // In shadow mode with unauthorized writes and severed evidence channel:
    // Severed evidence channel takes priority over shadow mode pass.
    let verdict = VerdictEngine::evaluate(&contract, 0, 5, 0, false, 0);
    assert_eq!(
        verdict.security_verdict,
        SecurityVerdict::Inconclusive,
        "Severed evidence channel must yield Inconclusive even in shadow mode"
    );
    assert_eq!(
        verdict.status,
        VerdictStatus::Inconclusive,
        "Verdict status must be Inconclusive"
    );
    assert_eq!(
        verdict.exit_code, 125,
        "Exit code must be 125 fail-closed when evidence channel is severed"
    );
    assert!(
        !verdict.is_contract_satisfied(),
        "Contract cannot be satisfied with severed evidence channel"
    );
    assert!(
        !verdict.is_success(),
        "Execution cannot be marked success when evidence channel is severed"
    );
    assert_eq!(verdict.security_badge(), "INCONCLUSIVE [STRONG]");
    assert!(verdict.reason.contains("dropped events"));
}

// ============================================================================
// Milestone 3: Fail-Closed Loader, Schema & Real Agent Presets
// ============================================================================

// ----------------------------------------------------------------------------
// Test 8: Preset Resolution For All 32 Known Agents (Goal 2.6 / R6)
// ----------------------------------------------------------------------------
#[test]
fn test_m3_preset_resolution_all_32_agents() {
    for agent_name in vetto::policy::defaults::AGENT_PROFILE_NAMES {
        // 1. resolve_preset must resolve agent to path patterns
        let resolved = vetto::policy::presets::resolve_preset(agent_name);
        assert!(
            resolved.is_some(),
            "Agent preset '{agent_name}' must be resolved by resolve_preset"
        );
        let paths = resolved.unwrap();
        assert!(
            !paths.is_empty(),
            "Agent preset '{agent_name}' must resolve to at least one path pattern"
        );
        for path in paths {
            assert!(
                path.starts_with("$HOME") || path.starts_with("/"),
                "Path pattern '{path}' for agent '{agent_name}' must be formatted properly"
            );
        }

        // 2. Must be present in KNOWN_PRESETS
        assert!(
            vetto::policy::presets::KNOWN_PRESETS.contains(&agent_name),
            "Agent preset '{agent_name}' must be registered in KNOWN_PRESETS"
        );

        // 3. Builtin embedded TOML profile must be non-empty
        let toml_str = vetto::policy::defaults::agent_builtin(agent_name);
        assert!(
            toml_str.is_some(),
            "Agent preset '{agent_name}' must have embedded TOML profile"
        );
        let toml_content = toml_str.unwrap();
        assert!(
            !toml_content.trim().is_empty(),
            "Agent preset '{agent_name}' TOML profile must not be empty"
        );

        // 4. Case-insensitivity check
        let upper_name = agent_name.to_ascii_uppercase();
        let upper_resolved = vetto::policy::presets::resolve_preset(&upper_name);
        assert!(
            upper_resolved.is_some(),
            "Agent preset '{agent_name}' must resolve case-insensitively"
        );
    }
}

// ----------------------------------------------------------------------------
// Test 9: deny_unknown_fields Enforced With Exit Code 125 (Goal 2.7 / R7)
// ----------------------------------------------------------------------------
#[test]
fn test_m3_deny_unknown_fields_typo_fails_closed_exit_125() {
    // 9.1: Typo in filesystem section (`allow_reads` instead of `allow_read`)
    let bad_toml_fs = r#"
[metadata]
name = "typo-fs-test"

[filesystem]
allow_reads = ["/tmp"]
allow_write = ["/tmp"]
"#;
    let err_fs =
        vetto::policy::loader::schema::parse_layer(bad_toml_fs, "test-bad-fs").unwrap_err();
    let msg_fs = err_fs.to_string();
    assert!(
        msg_fs.contains("unknown field `allow_reads`"),
        "Deserializer must reject unknown field `allow_reads`: {msg_fs}"
    );
    let exit_code_fs = vetto::exit_codes::map_error_to_exit_code(&err_fs);
    assert_eq!(
        exit_code_fs,
        vetto::exit_codes::EXIT_FAIL_CLOSED,
        "Typo in filesystem schema must yield exit code 125, got {exit_code_fs}"
    );

    // 9.2: Typo at root level (`[filesystems]` instead of `[filesystem]`)
    let bad_toml_root = r#"
[filesystems]
allow_write = ["/tmp"]
"#;
    let err_root =
        vetto::policy::loader::schema::parse_layer(bad_toml_root, "test-bad-root").unwrap_err();
    let msg_root = err_root.to_string();
    assert!(
        msg_root.contains("unknown field `filesystems`"),
        "Deserializer must reject unknown root field `filesystems`: {msg_root}"
    );
    let exit_code_root = vetto::exit_codes::map_error_to_exit_code(&err_root);
    assert_eq!(
        exit_code_root,
        vetto::exit_codes::EXIT_FAIL_CLOSED,
        "Typo in root section must yield exit code 125"
    );

    // 9.3: Typo in network section (`allowed_domains` instead of `allow_domains`)
    let bad_toml_net = r#"
[network]
mode = "allowlist"
allowed_domains = ["api.anthropic.com"]
"#;
    let err_net =
        vetto::policy::loader::schema::parse_layer(bad_toml_net, "test-bad-net").unwrap_err();
    let msg_net = err_net.to_string();
    assert!(
        msg_net.contains("unknown field `allowed_domains`"),
        "Deserializer must reject unknown field `allowed_domains`: {msg_net}"
    );
    let exit_code_net = vetto::exit_codes::map_error_to_exit_code(&err_net);
    assert_eq!(
        exit_code_net,
        vetto::exit_codes::EXIT_FAIL_CLOSED,
        "Typo in network section must yield exit code 125"
    );

    // 9.4: Typo in limits section (`memory_limit` instead of `address_space_bytes`)
    let bad_toml_limits = r#"
[limits]
memory_limit = 536870912
"#;
    let err_limits =
        vetto::policy::loader::schema::parse_layer(bad_toml_limits, "test-bad-limits").unwrap_err();
    let msg_limits = err_limits.to_string();
    assert!(
        msg_limits.contains("unknown field `memory_limit`"),
        "Deserializer must reject unknown field `memory_limit`: {msg_limits}"
    );
    let exit_code_limits = vetto::exit_codes::map_error_to_exit_code(&err_limits);
    assert_eq!(
        exit_code_limits,
        vetto::exit_codes::EXIT_FAIL_CLOSED,
        "Typo in limits section must yield exit code 125"
    );
}

// ----------------------------------------------------------------------------
// Test 10: Unknown Profile or Agent Preset Fails Closed With Exit 125
// ----------------------------------------------------------------------------
#[test]
fn test_m3_unknown_profile_or_preset_fails_closed_exit_125() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_m3_unk_{}", std::process::id()));
    let home = temp_dir.join(format!("vetto_m3_home_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&ws);
    let _ = std::fs::create_dir_all(&home);

    // 10.1: Non-existent profile fails closed
    let err_prof = vetto::policy::loader::load(
        "totally_unknown_profile_xyz",
        None,
        &ws,
        &home,
        vetto::policy::Tier::Full,
    )
    .unwrap_err();
    let msg_prof = err_prof.to_string();
    assert!(
        msg_prof.contains("unknown profile 'totally_unknown_profile_xyz'"),
        "Must explicitly report unknown profile: {msg_prof}"
    );
    let exit_prof = vetto::exit_codes::map_error_to_exit_code(&err_prof);
    assert_eq!(
        exit_prof,
        vetto::exit_codes::EXIT_FAIL_CLOSED,
        "Unknown profile must yield exit code 125 fail-closed, got {exit_prof}"
    );

    // 10.2: Non-existent agent preset fails closed
    let options = vetto::policy::loader::PolicyLoadOptions {
        agent: Some("unknown_agent_vendor".to_string()),
        ..Default::default()
    };
    let err_agent = vetto::policy::loader::load_with_options(
        "default",
        None,
        &ws,
        &home,
        vetto::policy::Tier::Full,
        &options,
    )
    .unwrap_err();
    let msg_agent = err_agent.to_string();
    assert!(
        msg_agent.contains("unknown agent 'unknown_agent_vendor'"),
        "Must explicitly report unknown agent: {msg_agent}"
    );
    let exit_agent = vetto::exit_codes::map_error_to_exit_code(&err_agent);
    assert_eq!(
        exit_agent,
        vetto::exit_codes::EXIT_FAIL_CLOSED,
        "Unknown agent preset must yield exit code 125 fail-closed, got {exit_agent}"
    );

    let _ = std::fs::remove_dir_all(&ws);
    let _ = std::fs::remove_dir_all(&home);
}

// ----------------------------------------------------------------------------
// Test 11: Explicit Permissive Profile vs Default Without Permissive Fallback
// ----------------------------------------------------------------------------
#[test]
fn test_m3_permissive_profile_explicit_vs_default_fail_closed() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_m3_perm_{}", std::process::id()));
    let home = temp_dir.join(format!("vetto_m3_perm_home_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&ws);
    let _ = std::fs::create_dir_all(&home);

    // 11.1: Explicit --profile permissive allows permissive execution
    let perm_policy =
        vetto::policy::loader::load("permissive", None, &ws, &home, vetto::policy::Tier::Full)
            .expect("explicit permissive profile must load cleanly");
    assert!(
        perm_policy
            .allow_read
            .iter()
            .any(|p| p.to_string_lossy() == "/etc"),
        "Permissive policy must contain /etc in allow_read"
    );

    // 11.2: Default profile ("default") restricts /etc
    let default_policy =
        vetto::policy::loader::load("default", None, &ws, &home, vetto::policy::Tier::Full)
            .expect("default profile must load cleanly");
    assert!(
        !default_policy
            .allow_read
            .iter()
            .any(|p| p.to_string_lossy() == "/etc"),
        "Default profile must NOT grant unrestricted /etc in allow_read"
    );

    // 11.3: Error during policy loading never falls back to permissive profile
    let err = vetto::policy::loader::load(
        "invalid_nonexistent_profile",
        None,
        &ws,
        &home,
        vetto::policy::Tier::Full,
    );
    assert!(
        err.is_err(),
        "Non-existent profile must error without permissive fallback"
    );
    let exit_code = vetto::exit_codes::map_error_to_exit_code(&err.unwrap_err());
    assert_eq!(
        exit_code,
        vetto::exit_codes::EXIT_FAIL_CLOSED,
        "Failed profile must produce exit code 125 fail-closed"
    );

    let _ = std::fs::remove_dir_all(&ws);
    let _ = std::fs::remove_dir_all(&home);
}

// ----------------------------------------------------------------------------
// Test 12: Deserialization of All 10 Profiles With [network] Sections
// ----------------------------------------------------------------------------
#[test]
fn test_m3_all_10_profiles_network_sections_deserialize() {
    let target_10 = [
        "antigravity",
        "claude",
        "codex",
        "copilot",
        "cursor",
        "custom",
        "devin",
        "goose",
        "openhands",
        "windsurf",
    ];

    for agent in target_10 {
        let toml_content = vetto::policy::defaults::agent_builtin(agent)
            .unwrap_or_else(|| panic!("Built-in TOML profile for '{agent}' must exist"));

        let layer = vetto::policy::loader::schema::parse_layer(
            toml_content,
            &format!("agent_profile:{agent}"),
        )
        .unwrap_or_else(|e| {
            panic!("Profile '{agent}' must deserialize into RawLayer without error: {e}")
        });

        assert!(
            layer.network.is_some(),
            "Agent profile '{agent}' must have an explicit [network] section"
        );
        let net = layer.network.as_ref().unwrap();
        let has_mode = net.mode.is_some();
        let has_allow_domains = net.allow_domains.is_some() || net.allow.is_some();
        let has_net_presets = net.net_presets.is_some() || net.net_preset.is_some();
        assert!(
            has_mode || has_allow_domains || has_net_presets,
            "Agent profile '{agent}' [network] section must specify mode, \
             allow_domains, or net_presets"
        );
    }
}

// ----------------------------------------------------------------------------
// Test 13: Typed VettoError::Policy(PolicyError) Exit Code 125 Mapping
// ----------------------------------------------------------------------------
#[test]
fn test_m3_vetto_error_policy_exit_code_125_mapping() {
    // 13.1: PolicyError::CompilationFailed must yield 125
    let comp_err =
        vetto::policy::types::PolicyError::CompilationFailed("syntax error in schema".to_string());
    assert_eq!(comp_err.exit_code(), 125);
    let vetto_err = vetto::error::VettoError::Policy(comp_err);
    assert_eq!(
        vetto_err.exit_code(),
        vetto::exit_codes::EXIT_FAIL_CLOSED,
        "VettoError::Policy(CompilationFailed) must yield EXIT_FAIL_CLOSED (125)"
    );

    // 13.2: PolicyError::VerificationFailed must yield 125
    let verif_err = vetto::policy::types::PolicyError::VerificationFailed(
        "tampered sealed contract hash mismatch".to_string(),
    );
    assert_eq!(verif_err.exit_code(), 125);
    let vetto_verif = vetto::error::VettoError::Policy(verif_err);
    assert_eq!(
        vetto_verif.exit_code(),
        vetto::exit_codes::EXIT_FAIL_CLOSED,
        "VettoError::Policy(VerificationFailed) must yield EXIT_FAIL_CLOSED (125)"
    );

    // 13.3: PolicyError::LockdownViolation must yield 126
    let lock_err = vetto::policy::types::PolicyError::LockdownViolation(
        "attempt to override immutable root".to_string(),
    );
    assert_eq!(lock_err.exit_code(), 126);
    let vetto_lock = vetto::error::VettoError::Policy(lock_err);
    assert_eq!(
        vetto_lock.exit_code(),
        vetto::exit_codes::EXIT_POLICY_BLOCKED,
        "VettoError::Policy(LockdownViolation) must yield EXIT_POLICY_BLOCKED (126)"
    );

    // 13.4: Downcast in exit_codes::map_error_to_exit_code
    let boxed_anyhow: anyhow::Error = vetto::error::VettoError::Policy(
        vetto::policy::types::PolicyError::CompilationFailed("bad schema".into()),
    )
    .into();
    assert_eq!(
        vetto::exit_codes::map_error_to_exit_code(&boxed_anyhow),
        125,
        "map_error_to_exit_code must downcast VettoError::Policy and return 125"
    );
}

// ----------------------------------------------------------------------------
// Test 14: Comprehensive Schema Typo Matrix For All RawLayer Structs
// ----------------------------------------------------------------------------
#[test]
fn test_m3_schema_typo_matrix_fail_closed_coverage() {
    let test_cases = [
        // (section, invalid_key, expected_error_substring)
        (
            "security",
            "git_guards = true",
            "unknown field `git_guards`",
        ),
        (
            "secrets",
            "auto_denies = true",
            "unknown field `auto_denies`",
        ),
        (
            "display_only_deny",
            "denied_paths = []",
            "unknown field `denied_paths`",
        ),
        (
            "environment",
            "passthrough = []",
            "unknown field `passthrough`",
        ),
        ("unix_sockets", "allowed = []", "unknown field `allowed`"),
        ("cgroup", "memory = \"1G\"", "unknown field `memory`"),
    ];

    for (section, invalid_field, expected_sub) in test_cases {
        let toml_snippet = format!("[{section}]\n{invalid_field}\n");
        let err = vetto::policy::loader::schema::parse_layer(&toml_snippet, section).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(expected_sub),
            "Section [{section}] must reject '{invalid_field}': {msg}"
        );
        let exit_code = vetto::exit_codes::map_error_to_exit_code(&err);
        assert_eq!(
            exit_code,
            vetto::exit_codes::EXIT_FAIL_CLOSED,
            "Section [{section}] schema violation must map to exit code 125"
        );
    }
}

// ----------------------------------------------------------------------------
// Test 15: Milestone 4 - Security Linter: Root Wildcard Detection
// ----------------------------------------------------------------------------
#[test]
fn test_m4_policy_linter_root_wildcard_detection() {
    use std::path::PathBuf;
    use vetto::policy::lint::{rule_root_wildcard, Severity};
    use vetto::policy::types::Policy;

    // 15.1: Write root "/" must trigger High severity root-wildcard-write
    let mut policy = Policy::default();
    policy.allow_write = vec![PathBuf::from("/")];
    let findings = rule_root_wildcard(&policy);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::High);
    assert_eq!(findings[0].rule, "root-wildcard-write");
    assert!(findings[0].message.contains("root wildcard"));

    // 15.2: Write root "/*" must also trigger
    policy.allow_write = vec![PathBuf::from("/*")];
    let findings_star = rule_root_wildcard(&policy);
    assert_eq!(findings_star.len(), 1);
    assert_eq!(findings_star[0].severity, Severity::High);

    // 15.3: Read root "/" must trigger root-wildcard-read
    policy.allow_write.clear();
    policy.allow_read = vec![PathBuf::from("/")];
    let findings_read = rule_root_wildcard(&policy);
    assert_eq!(findings_read.len(), 1);
    assert_eq!(findings_read[0].severity, Severity::High);
    assert_eq!(findings_read[0].rule, "root-wildcard-read");

    // 15.4: Normal scoped path must not trigger
    policy.allow_read = vec![PathBuf::from("/home/user/project")];
    assert!(rule_root_wildcard(&policy).is_empty());
}

// ----------------------------------------------------------------------------
// Test 16: Milestone 4 - Security Linter: Dangerous Network CIDR & Broad /tmp
// ----------------------------------------------------------------------------
#[test]
fn test_m4_policy_linter_dangerous_cidr_and_tmp_isolation() {
    use std::path::PathBuf;
    use vetto::policy::lint::{rule_broad_tmp_write, rule_dangerous_network_cidr, Severity};
    use vetto::policy::types::Policy;

    // 16.1: Dangerous CIDR 0.0.0.0/0 must trigger High severity
    let mut policy = Policy::default();
    policy.allow_cidr = vec!["0.0.0.0/0".to_string()];
    let findings = rule_dangerous_network_cidr(&policy);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::High);
    assert_eq!(findings[0].rule, "dangerous-network-cidr");

    // 16.2: Dangerous IPv6 CIDR ::/0 must trigger High severity
    policy.allow_cidr = vec!["::/0".to_string()];
    let findings_v6 = rule_dangerous_network_cidr(&policy);
    assert_eq!(findings_v6.len(), 1);
    assert_eq!(findings_v6[0].severity, Severity::High);

    // 16.3: Safe scoped CIDR must not trigger
    policy.allow_cidr = vec!["10.0.0.0/8".to_string(), "192.168.1.0/24".to_string()];
    assert!(rule_dangerous_network_cidr(&policy).is_empty());

    // 16.4: Broad /tmp write without tmpfs_tmp must trigger Warn
    policy.allow_write = vec![PathBuf::from("/tmp")];
    policy.tmpfs_tmp = false;
    let finding_tmp = rule_broad_tmp_write(&policy);
    assert!(finding_tmp.is_some());
    let f = finding_tmp.unwrap();
    assert_eq!(f.severity, Severity::Warn);
    assert_eq!(f.rule, "broad-tmp-write");

    // 16.5: /tmp write WITH tmpfs_tmp isolation must be clean
    policy.tmpfs_tmp = true;
    assert!(rule_broad_tmp_write(&policy).is_none());
}

// ----------------------------------------------------------------------------
// Test 17: Milestone 4 - Security Linter: Missing Secret Masking & JSON Schema
// ----------------------------------------------------------------------------
#[test]
fn test_m4_policy_linter_missing_secrets_and_json_serialization() {
    use std::path::PathBuf;
    use vetto::policy::lint::{rule_missing_secret_masking, Finding, LintReport, Severity};
    use vetto::policy::types::Policy;

    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp");
    let test_home = temp_dir.join(format!("vetto_lint_home_{}", std::process::id()));
    let test_proj = temp_dir.join(format!("vetto_lint_proj_{}", std::process::id()));
    std::fs::create_dir_all(&test_home).expect("create test home");
    std::fs::create_dir_all(&test_proj).expect("create test proj");

    // Create host secret directory .ssh and project secret .env
    std::fs::create_dir_all(test_home.join(".ssh")).expect("create fake .ssh");
    std::fs::write(test_proj.join(".env"), "SECRET_KEY=12345").expect("create fake .env");

    let policy = Policy::default();
    let findings = rule_missing_secret_masking(&policy, &test_home, Some(&test_proj));
    assert!(findings
        .iter()
        .any(|f| f.rule == "missing-secret-masking" && f.severity == Severity::Warn));
    assert!(findings
        .iter()
        .any(|f| f.rule == "missing-secret-masking" && f.severity == Severity::High));

    // Test LintReport JSON serialization schema
    let report = LintReport {
        success: false,
        findings_count: findings.len(),
        high_count: 1,
        warn_count: 1,
        findings: findings.clone(),
    };
    let json_str = serde_json::to_string(&report).expect("serialize report");
    let json_val: serde_json::Value = serde_json::from_str(&json_str).expect("parse json");
    assert_eq!(json_val["success"], false);
    assert_eq!(json_val["findings_count"], findings.len());
    assert!(json_val["findings"].is_array());

    let _ = std::fs::remove_dir_all(&test_home);
    let _ = std::fs::remove_dir_all(&test_proj);
}

// ----------------------------------------------------------------------------
// Test 18: Milestone 4 - Policy Edit: AST Preservation, Dangerous Paths, Atomic .bak
// ----------------------------------------------------------------------------
#[test]
fn test_m4_policy_edit_ast_preservation_and_atomic_rollback() {
    use std::path::Path;
    use vetto::policy::edit::{
        allow_domain, allow_path, deny_domain, deny_path, validate_dangerous_path,
    };

    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp");
    let test_dir = temp_dir.join(format!("vetto_m4_edit_{}", std::process::id()));
    std::fs::create_dir_all(&test_dir).expect("create test dir");
    let policy_path = test_dir.join("policy.toml");

    // 18.1: Dangerous paths must be rejected by validator
    assert!(validate_dangerous_path("/").is_err());
    assert!(validate_dangerous_path("/*").is_err());
    assert!(validate_dangerous_path("..").is_err());
    assert!(validate_dangerous_path("../foo").is_err());
    assert!(validate_dangerous_path("~/.ssh").is_err());
    assert!(validate_dangerous_path(".env").is_err());
    assert!(validate_dangerous_path("/etc/shadow").is_err());
    assert!(validate_dangerous_path("foo\\bar").is_err());

    // 18.2: Initial policy with comments
    let initial_toml = r#"# Top comment
[metadata]
name = "test-edit-profile" # inline comment

[filesystem]
# Allowed paths
allow_write = ["src"]
"#;
    std::fs::write(&policy_path, initial_toml).expect("write initial toml");

    // 18.3: allow_path creates .bak and preserves comments
    let updated =
        allow_path("target", false, false, Some(&policy_path)).expect("allow_path must succeed");
    assert_eq!(updated, policy_path);
    let bak_path = Path::new(&format!("{}.bak", policy_path.display())).to_path_buf();
    assert!(bak_path.exists(), ".bak backup file must be created");
    let bak_content = std::fs::read_to_string(&bak_path).expect("read bak");
    assert_eq!(bak_content, initial_toml);

    let new_content = std::fs::read_to_string(&policy_path).expect("read new");
    assert!(
        new_content.contains("# Top comment"),
        "Comments must be preserved"
    );
    assert!(new_content.contains("# inline comment"));
    assert!(new_content.contains("\"target\""));

    // 18.4: allow_path rejects dangerous path
    assert!(allow_path("/etc/shadow", false, false, Some(&policy_path)).is_err());

    // 18.5: deny_path adds to display_only_deny
    deny_path("~/.aws/credentials", false, Some(&policy_path)).expect("deny_path must succeed");
    let content_after_deny = std::fs::read_to_string(&policy_path).expect("read after deny");
    assert!(content_after_deny.contains("display_only_deny"));
    assert!(content_after_deny.contains("~/.aws/credentials"));

    // 18.6: allow_domain and deny_domain
    allow_domain(
        "api.anthropic.com",
        Some("100mb"),
        false,
        Some(&policy_path),
    )
    .expect("allow_domain must succeed");
    deny_domain("evil.com", false, Some(&policy_path)).expect("deny_domain must succeed");

    let net_content = std::fs::read_to_string(&policy_path).expect("read net content");
    assert!(net_content.contains("api.anthropic.com"));
    assert!(net_content.contains("evil.com"));

    let _ = std::fs::remove_dir_all(&test_dir);
}

// ----------------------------------------------------------------------------
// Test 19: Milestone 4 - Sandbox Preflight Verify: Fast Simulated Verify & JSON
// ----------------------------------------------------------------------------
#[test]
fn test_m4_sandbox_preflight_verify_simulated_and_json_schema() {
    use std::path::PathBuf;
    use vetto::policy::types::{NetMode, Policy};
    use vetto::verify::battery_simulated;

    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp");
    let ws = temp_dir.join(format!("vetto_m4_verify_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    let mut policy = Policy::default();
    policy.name = "verify-test".to_string();
    policy.allow_write = vec![ws.clone()];
    policy.allow_read = vec![PathBuf::from("/usr")];

    let net = NetMode::Off;
    let contract_input = vetto::policy_ir::compiler::EffectivePolicyInput {
        policy: &policy,
        argv: &["verify-probe".to_string()],
        cwd: &ws,
        env: &std::collections::BTreeMap::new(),
        net: &net,
        nonce: "verify-test-nonce",
        timeout: None,
        tier: None,
        backend: "simulated".to_string(),
        observe_seccomp: false,
        debug_ports: None,
    };
    let contract = vetto::policy_ir::compiler::PolicyCompiler::compile_effective(contract_input)
        .expect("compile effective contract");

    // 19.1: Fast simulated battery execution (<15ms, in practice <1ms)
    let start = std::time::Instant::now();
    let report = battery_simulated(&contract, &policy, &net, start);
    assert_eq!(report.status(), "pass");
    assert_eq!(report.tier, "simulated");
    assert_eq!(report.leaks(), 0);
    assert!(report.duration_ms < 15, "Duration must be < 15ms");
    assert_eq!(report.sealed_contract_hash, contract.sealed_contract_hash);

    // 19.2: JSON Schema validation
    let json = report.to_json();
    assert_eq!(json["status"], "pass");
    assert_eq!(json["sealed_contract_hash"], contract.sealed_contract_hash);
    let checks = json["checks"].as_array().expect("checks array");
    assert_eq!(checks.len(), 4);
    assert_eq!(checks[0]["name"], "workspace-read");
    assert_eq!(checks[1]["name"], "secret-mask-deny");
    assert_eq!(checks[2]["name"], "network-block");
    assert_eq!(checks[3]["name"], "write-outside");

    // 19.3: SHA-256 sealed contract integrity verification (INV-36)
    assert!(
        contract.verify_sha256(),
        "Contract SHA-256 seal must verify"
    );
    let mut tampered = contract.clone();
    tampered.resources.max_pids = 999999;
    assert!(
        !tampered.verify_sha256(),
        "Tampered contract must fail SHA-256 seal verification (INV-36)"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

// ----------------------------------------------------------------------------
// Test 20: Milestone 4 - Policy Explain: Effective Rights Tree & explain_why
// ----------------------------------------------------------------------------
#[test]
fn test_m4_policy_explain_effective_rights_and_why_remediation() {
    use std::path::PathBuf;
    use vetto::policy::explain::explain_why;
    use vetto::policy::types::{DenyEntry, NetMode, Policy};
    use vetto::policy_ir::compiler::{EffectivePolicyInput, PolicyCompiler};

    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp");
    let ws = temp_dir.join(format!("vetto_m4_explain_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    let mut policy = Policy::default();
    policy.name = "explain-m4".to_string();
    policy.allow_write = vec![ws.clone()];
    policy.allow_read = vec![PathBuf::from("/usr")];
    policy.deny_write = vec![ws.join("locked.txt")];
    policy.deny_resolved = vec![DenyEntry {
        path: ws.join(".env"),
        is_dir: false,
    }];
    policy.network_allow = vec!["api.anthropic.com".to_string()];
    policy.net_connect_ports = vec![443];
    policy.limits.cpu_seconds = Some(60);

    let net_mode = NetMode::Allowlist(policy.network_allow.clone());
    let contract = PolicyCompiler::compile_effective(EffectivePolicyInput {
        policy: &policy,
        argv: &["agent".to_string()],
        cwd: &ws,
        env: &std::collections::BTreeMap::new(),
        net: &net_mode,
        nonce: "test-nonce-m4",
        timeout: None,
        tier: None,
        backend: "none".to_string(),
        observe_seccomp: false,
        debug_ports: None,
    })
    .expect("compile contract");

    // 20.1: explain_why remediation
    let exp_ws = explain_why(&policy, &ws.join("file.rs"), &ws);
    assert_eq!(exp_ws.access, "WRITABLE");

    let exp_lock = explain_why(&policy, &ws.join("locked.txt"), &ws);
    assert_eq!(exp_lock.access, "READ_ONLY");
    assert_eq!(exp_lock.rule_type, "deny_write");

    let exp_sec = explain_why(&policy, &ws.join(".env"), &ws);
    assert_eq!(exp_sec.access, "DENIED");
    assert_eq!(exp_sec.rule_type, "display_only_deny");

    let exp_out = explain_why(&policy, &PathBuf::from("/var/log/secret.log"), &ws);
    assert_eq!(exp_out.access, "BLOCKED");

    // 20.2: Structured Rights Hierarchy in JSON
    let masked_json = policy
        .deny_resolved
        .iter()
        .map(|e| serde_json::json!({ "path": e.path.display().to_string(), "is_dir": e.is_dir }))
        .collect::<Vec<_>>();

    let explain_json = serde_json::json!({
        "filesystem": {
            "workspace_root": contract.filesystem.workspace_root.display().to_string(),
            "allow_write": policy
                .allow_write
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>(),
            "allow_read": policy
                .allow_read
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>(),
            "masked_secrets": masked_json,
        },
        "process_execution": {
            "invoked_binary": contract.agent_identity.invoked_binary.display().to_string(),
            "allowed_binaries": contract
                .filesystem
                .allow_execute
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>(),
        },
        "network": {
            "mode": net_mode.label(),
            "allowed_domains": policy.network_allow.clone(),
            "allowed_ports": policy.net_connect_ports.clone(),
        },
        "quotas": {
            "cpu": {
                "rlimit_seconds": policy.limits.cpu_seconds,
                "effective_percent": contract.resources.max_cpu_percent,
            },
            "memory": { "effective_bytes": contract.resources.max_memory_bytes },
            "pids": { "effective_pids": contract.resources.max_pids },
        }
    });

    assert_eq!(explain_json["network"]["mode"], "allowlist");
    assert_eq!(
        explain_json["filesystem"]["workspace_root"],
        ws.display().to_string()
    );
    assert_eq!(explain_json["quotas"]["cpu"]["rlimit_seconds"], 60);

    let _ = std::fs::remove_dir_all(&ws);
}
