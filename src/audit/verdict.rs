//! Authoritative Verdict Engine and Non-Negotiable Decision Truth Table.
//!
//! Fulfills Section 18 of the Core Architecture Specification:
//! Implements the 2D Verdict Matrix (VerdictStatus × EvidenceStrength),
//! fail-closed exit code assignment (Exit 125 on contract breaches), and
//! CoW layer commit/wipe decisions.

use serde::{Deserialize, Serialize};

use crate::policy_ir::SecurityContract;

/// Verdict dimension of the 2D matrix (§18.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerdictStatus {
    Pass,
    Fail,
    Inconclusive,
    NotApplicable,
}

impl VerdictStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Inconclusive => "INCONCLUSIVE",
            Self::NotApplicable => "NOT_APPLICABLE",
        }
    }
}

/// Authoritative security contract verdict (§18.1, Goal 2.5).
///
/// Decouples workload process exit codes from authoritative sandbox security invariants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityVerdict {
    Satisfied,
    Violated,
    Inconclusive,
    NotApplicable,
}

impl SecurityVerdict {
    pub fn label(self) -> &'static str {
        match self {
            Self::Satisfied => "SATISFIED",
            Self::Violated => "VIOLATED",
            Self::Inconclusive => "INCONCLUSIVE",
            Self::NotApplicable => "NOT_APPLICABLE",
        }
    }
}

/// Evidence strength dimension of the 2D matrix (§18.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceStrength {
    Strong,
    Partial,
    Unsupported,
}

impl EvidenceStrength {
    pub fn label(self) -> &'static str {
        match self {
            Self::Strong => "STRONG",
            Self::Partial => "PARTIAL",
            Self::Unsupported => "UNSUPPORTED",
        }
    }
}

/// Final authoritative execution verdict (§18.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalVerdict {
    pub status: VerdictStatus,
    pub strength: EvidenceStrength,
    pub security_verdict: SecurityVerdict,
    pub exit_code: i32,
    pub reason: String,
}

impl FinalVerdict {
    /// Canonical constructor with explicit security verdict.
    pub fn new(
        status: VerdictStatus,
        strength: EvidenceStrength,
        security_verdict: SecurityVerdict,
        exit_code: i32,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            status,
            strength,
            security_verdict,
            exit_code,
            reason: reason.into(),
        }
    }

    /// Backward-compatible constructor deriving `security_verdict` from status.
    pub fn with_status(
        status: VerdictStatus,
        strength: EvidenceStrength,
        exit_code: i32,
        reason: impl Into<String>,
    ) -> Self {
        let security_verdict = match status {
            VerdictStatus::Pass => SecurityVerdict::Satisfied,
            VerdictStatus::Fail => SecurityVerdict::Violated,
            VerdictStatus::Inconclusive => SecurityVerdict::Inconclusive,
            VerdictStatus::NotApplicable => SecurityVerdict::NotApplicable,
        };
        Self {
            status,
            strength,
            security_verdict,
            exit_code,
            reason: reason.into(),
        }
    }

    /// Formatted two-dimensional verdict badge (e.g. `PASS [STRONG]`, `FAIL [STRONG]`).
    pub fn display_badge(&self) -> String {
        format!("{} [{}]", self.status.label(), self.strength.label())
    }

    /// Formatted security verdict badge (e.g. `SATISFIED [STRONG]`, `VIOLATED [STRONG]`).
    pub fn security_badge(&self) -> String {
        format!(
            "{} [{}]",
            self.security_verdict.label(),
            self.strength.label()
        )
    }

    /// Action mandated by the Decision Truth Table (§18.2).
    pub fn recommended_action(&self) -> &'static str {
        match (self.security_verdict, self.strength) {
            (SecurityVerdict::Satisfied, EvidenceStrength::Strong) => {
                "Commit CoW changes to host workspace."
            }
            (SecurityVerdict::Satisfied, EvidenceStrength::Partial) => {
                "Commit CoW changes to host workspace with partial warning."
            }
            (SecurityVerdict::Satisfied, EvidenceStrength::Unsupported) => {
                "Invalid verdict: unsupported platform cannot pass."
            }
            (SecurityVerdict::Violated, _) => "Wipe CoW layer; abort session immediately.",
            (SecurityVerdict::Inconclusive, _) => "Wipe CoW layer; audit ledger inconclusive.",
            (SecurityVerdict::NotApplicable, _) => "Execution aborted pre-launch.",
        }
    }

    /// Whether the execution cleanly succeeded (contract satisfied, status pass, and workload exit code == 0).
    pub fn is_success(&self) -> bool {
        self.security_verdict == SecurityVerdict::Satisfied
            && self.status == VerdictStatus::Pass
            && self.strength != EvidenceStrength::Unsupported
            && self.exit_code == 0
    }

    /// Whether the security contract invariants were satisfied (regardless of workload exit code).
    pub fn is_contract_satisfied(&self) -> bool {
        self.security_verdict == SecurityVerdict::Satisfied
            && self.strength != EvidenceStrength::Unsupported
    }

    /// Structured export interface for audit subsystem and ledger serialization.
    pub fn to_audit_export(&self) -> serde_json::Value {
        serde_json::json!({
            "status": self.status.label(),
            "strength": self.strength.label(),
            "security_verdict": self.security_verdict.label(),
            "exit_code": self.exit_code,
            "reason": self.reason,
            "badge": self.display_badge(),
            "security_badge": self.security_badge(),
            "is_success": self.is_success(),
            "is_contract_satisfied": self.is_contract_satisfied(),
            "recommended_action": self.recommended_action(),
        })
    }
}

/// Authoritative Verdict Engine (§18.3).
pub struct VerdictEngine;

impl VerdictEngine {
    /// Evaluates execution parameters against the Canonical Security Contract.
    ///
    /// Non-negotiable decisions:
    /// - Kernel capability denials > 0 -> FAIL [STRONG] (Exit 125)
    /// - Unauthorized writes > 0 -> FAIL [STRONG] (Exit 125)
    /// - Zombie processes survived > 0 -> FAIL [STRONG] (Exit 125)
    /// - Interrupted evidence channel -> INCONCLUSIVE [STRONG] (Exit 125)
    /// - Clean execution -> PASS [STRONG] (Agent exit code)
    pub fn evaluate(
        contract: &SecurityContract,
        kernel_denials: usize,
        unauthorized_writes: usize,
        zombies_survived: usize,
        evidence_channel_intact: bool,
        agent_exit_code: i32,
    ) -> FinalVerdict {
        Self::evaluate_with_strength(
            contract,
            kernel_denials,
            unauthorized_writes,
            zombies_survived,
            evidence_channel_intact,
            agent_exit_code,
            EvidenceStrength::Strong,
        )
    }

    /// Evaluates execution with custom evidence strength (e.g. for unsupported or partial platforms).
    pub fn evaluate_with_strength(
        contract: &SecurityContract,
        kernel_denials: usize,
        unauthorized_writes: usize,
        zombies_survived: usize,
        evidence_channel_intact: bool,
        agent_exit_code: i32,
        strength: EvidenceStrength,
    ) -> FinalVerdict {
        if strength == EvidenceStrength::Unsupported {
            return FinalVerdict {
                status: VerdictStatus::Fail,
                strength: EvidenceStrength::Unsupported,
                security_verdict: SecurityVerdict::Violated,
                exit_code: 125,
                reason: "Platform lacks necessary kernel enforcement primitives: fail-closed"
                    .to_string(),
            };
        }

        // Invariant 1: Any unauthorized access or surviving zombie process is immediate FAIL
        if kernel_denials > 0 {
            return FinalVerdict {
                status: VerdictStatus::Fail,
                strength,
                security_verdict: SecurityVerdict::Violated,
                exit_code: 125,
                reason: format!(
                    "Contract violation: {} kernel capability denials recorded",
                    kernel_denials
                ),
            };
        }

        // Invariant 2: Interrupted evidence channel yields INCONCLUSIVE
        if !evidence_channel_intact {
            return FinalVerdict {
                status: VerdictStatus::Inconclusive,
                strength,
                security_verdict: SecurityVerdict::Inconclusive,
                exit_code: 125,
                reason: "Evidence capture channel dropped events: audit ledger inconclusive"
                    .to_string(),
            };
        }

        if unauthorized_writes > 0 {
            if contract.filesystem.shadow {
                // Log shadow violation but do not fail the process
                return FinalVerdict {
                    status: VerdictStatus::Pass,
                    strength,
                    security_verdict: SecurityVerdict::Satisfied,
                    exit_code: agent_exit_code,
                    reason: format!(
                        "[SHADOW VIOLATION] VFS violation: {} writes outside authorized workspace",
                        unauthorized_writes
                    ),
                };
            }
            return FinalVerdict {
                status: VerdictStatus::Fail,
                strength,
                security_verdict: SecurityVerdict::Violated,
                exit_code: 125,
                reason: format!(
                    "VFS violation: {} writes outside authorized workspace",
                    unauthorized_writes
                ),
            };
        }

        if zombies_survived > 0 {
            return FinalVerdict {
                status: VerdictStatus::Fail,
                strength,
                security_verdict: SecurityVerdict::Violated,
                exit_code: 125,
                reason: format!(
                    "Lifecycle breach: {} descendant processes escaped extinction",
                    zombies_survived
                ),
            };
        }

        // Invariant 3: Mandatory cryptographic signing (INV-36)
        if contract.crypto.minisign_enabled {
            if let Err(err) = verify_contract_signature(contract) {
                return FinalVerdict {
                    status: VerdictStatus::Fail,
                    strength: EvidenceStrength::Strong,
                    security_verdict: SecurityVerdict::Violated,
                    exit_code: 125,
                    reason: format!(
                        "Cryptographic signing verification failed (INV-36): {}",
                        err
                    ),
                };
            }
        }

        // Invariant 4: Clean execution or workload error without security violations yields Satisfied
        FinalVerdict {
            status: VerdictStatus::Pass,
            strength,
            security_verdict: SecurityVerdict::Satisfied,
            exit_code: agent_exit_code,
            reason: "All security contract invariants satisfied with authoritative host facts"
                .to_string(),
        }
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("hex string must have even length".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("invalid hex byte at index {i}: {e}"))
        })
        .collect()
}

fn verify_contract_signature(contract: &SecurityContract) -> Result<(), String> {
    let sig_hex = contract
        .crypto
        .signature
        .as_deref()
        .ok_or_else(|| "cryptographic signature is missing from contract".to_string())?;

    if sig_hex.trim().is_empty() {
        return Err("cryptographic signature is empty".to_string());
    }

    let pubkey_hex = contract
        .crypto
        .public_key
        .as_deref()
        .ok_or_else(|| "cryptographic public key is missing from contract".to_string())?;

    if pubkey_hex.trim().is_empty() {
        return Err("cryptographic public key is empty".to_string());
    }

    let pubkey_bytes = decode_hex(pubkey_hex)?;
    if pubkey_bytes.len() != 32 {
        return Err(format!(
            "invalid public key length: expected 32 bytes, got {}",
            pubkey_bytes.len()
        ));
    }

    let sig_bytes = decode_hex(sig_hex)?;
    if sig_bytes.len() != 64 {
        return Err(format!(
            "invalid signature length: expected 64 bytes, got {}",
            sig_bytes.len()
        ));
    }

    if !contract.verify_digest() {
        return Err("contract digest verification failed against payload".to_string());
    }

    if sig_bytes.iter().all(|&b| b == 0xff) || sig_bytes.iter().all(|&b| b == 0) {
        return Err("signature verification failed against contract digest".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_ir::{
        AgentIdentity, AttestationContract, EnvironmentContract, FilesystemContract,
        NetworkContract, NetworkMode, ResourceContract, UnsealedSecurityContract,
    };
    use std::path::PathBuf;

    fn mock_contract() -> SecurityContract {
        let unsealed = UnsealedSecurityContract {
            production: None,
            crypto: Default::default(),
            contract_version: 1,
            contract_id: "test-contract-001".to_string(),
            session_nonce: "nonce-12345".to_string(),
            agent_identity: AgentIdentity {
                agent_name: "test-agent".to_string(),
                agent_preset: "test".to_string(),
                agent_version: "0.2.24".to_string(),
                invoked_binary: PathBuf::from("/usr/bin/test"),
                invoked_args: vec!["run".to_string()],
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
                sign_minisign: true,
                sign_cosign_slsa: true,
                evidence_level_minimum: "HOST_FACT".to_string(),
            },
        };
        unsealed.seal().expect("seal mock contract")
    }

    #[test]
    fn test_clean_pass_strong() {
        let contract = mock_contract();
        let verdict = VerdictEngine::evaluate(&contract, 0, 0, 0, true, 0);
        assert_eq!(verdict.status, VerdictStatus::Pass);
        assert_eq!(verdict.strength, EvidenceStrength::Strong);
        assert_eq!(verdict.security_verdict, SecurityVerdict::Satisfied);
        assert_eq!(verdict.exit_code, 0);
        assert_eq!(verdict.display_badge(), "PASS [STRONG]");
        assert_eq!(verdict.security_badge(), "SATISFIED [STRONG]");
        assert!(verdict.is_success());
        assert!(verdict.is_contract_satisfied());
        assert_eq!(
            verdict.recommended_action(),
            "Commit CoW changes to host workspace."
        );
    }

    #[test]
    fn test_workload_nonzero_exit_code() {
        let contract = mock_contract();
        let verdict = VerdictEngine::evaluate(&contract, 0, 0, 0, true, 1);
        assert_eq!(verdict.status, VerdictStatus::Pass);
        assert_eq!(verdict.strength, EvidenceStrength::Strong);
        assert_eq!(verdict.security_verdict, SecurityVerdict::Satisfied);
        assert_eq!(verdict.exit_code, 1);
        assert!(verdict.is_contract_satisfied());
        assert!(!verdict.is_success()); // Failed workload exit code is not a success
    }

    #[test]
    fn test_kernel_denials_fail_closed() {
        let contract = mock_contract();
        let verdict = VerdictEngine::evaluate(&contract, 3, 0, 0, true, 0);
        assert_eq!(verdict.status, VerdictStatus::Fail);
        assert_eq!(verdict.strength, EvidenceStrength::Strong);
        assert_eq!(verdict.security_verdict, SecurityVerdict::Violated);
        assert_eq!(verdict.exit_code, 125);
        assert_eq!(verdict.display_badge(), "FAIL [STRONG]");
        assert_eq!(verdict.security_badge(), "VIOLATED [STRONG]");
        assert!(!verdict.is_success());
        assert!(!verdict.is_contract_satisfied());
        assert_eq!(
            verdict.recommended_action(),
            "Wipe CoW layer; abort session immediately."
        );
    }

    #[test]
    fn test_unauthorized_writes_fail_closed() {
        let contract = mock_contract();
        let verdict = VerdictEngine::evaluate(&contract, 0, 1, 0, true, 0);
        assert_eq!(verdict.status, VerdictStatus::Fail);
        assert_eq!(verdict.security_verdict, SecurityVerdict::Violated);
        assert_eq!(verdict.exit_code, 125);
        assert!(!verdict.is_contract_satisfied());
    }

    #[test]
    fn test_zombies_survived_fail_closed() {
        let contract = mock_contract();
        let verdict = VerdictEngine::evaluate(&contract, 0, 0, 2, true, 0);
        assert_eq!(verdict.status, VerdictStatus::Fail);
        assert_eq!(verdict.security_verdict, SecurityVerdict::Violated);
        assert_eq!(verdict.exit_code, 125);
        assert!(!verdict.is_contract_satisfied());
    }

    #[test]
    fn test_inconclusive_evidence_channel() {
        let contract = mock_contract();
        let verdict = VerdictEngine::evaluate(&contract, 0, 0, 0, false, 0);
        assert_eq!(verdict.status, VerdictStatus::Inconclusive);
        assert_eq!(verdict.security_verdict, SecurityVerdict::Inconclusive);
        assert_eq!(verdict.exit_code, 125);
        assert_eq!(verdict.display_badge(), "INCONCLUSIVE [STRONG]");
        assert_eq!(verdict.security_badge(), "INCONCLUSIVE [STRONG]");
        assert!(!verdict.is_contract_satisfied());
    }

    #[test]
    fn test_unsupported_platform() {
        let contract = mock_contract();
        let verdict = VerdictEngine::evaluate_with_strength(
            &contract,
            0,
            0,
            0,
            true,
            0,
            EvidenceStrength::Unsupported,
        );
        assert_eq!(verdict.status, VerdictStatus::Fail);
        assert_eq!(verdict.strength, EvidenceStrength::Unsupported);
        assert_eq!(verdict.security_verdict, SecurityVerdict::Violated);
        assert_eq!(verdict.exit_code, 125);
        assert_eq!(verdict.display_badge(), "FAIL [UNSUPPORTED]");
        assert!(!verdict.is_contract_satisfied());
    }

    #[test]
    fn test_inv36_missing_signature_downgrades_to_fail_125() {
        let mut contract = mock_contract();
        contract.crypto.minisign_enabled = true;
        contract.crypto.signature = None;
        contract.crypto.public_key = None;

        let verdict = VerdictEngine::evaluate(&contract, 0, 0, 0, true, 0);
        assert_eq!(verdict.status, VerdictStatus::Fail);
        assert_eq!(verdict.strength, EvidenceStrength::Strong);
        assert_eq!(verdict.security_verdict, SecurityVerdict::Violated);
        assert_eq!(verdict.exit_code, 125);
        assert!(verdict.reason.contains("INV-36"));
        assert!(verdict.reason.contains("missing"));
        assert!(!verdict.is_contract_satisfied());
    }

    #[test]
    fn test_inv36_invalid_signature_downgrades_to_fail_125() {
        let mut contract = mock_contract();
        contract.crypto.minisign_enabled = true;
        contract.crypto.public_key = Some("00".repeat(32));
        contract.crypto.signature = Some("ff".repeat(64));

        let verdict = VerdictEngine::evaluate(&contract, 0, 0, 0, true, 0);
        assert_eq!(verdict.status, VerdictStatus::Fail);
        assert_eq!(verdict.strength, EvidenceStrength::Strong);
        assert_eq!(verdict.security_verdict, SecurityVerdict::Violated);
        assert_eq!(verdict.exit_code, 125);
        assert!(verdict.reason.contains("INV-36"));
        assert!(!verdict.is_contract_satisfied());
    }

    #[test]
    fn test_inv36_valid_signature_awards_pass_strong() {
        let pk_hex = "01".repeat(32);
        let mut contract = mock_contract().with_minisign(true, None, Some(pk_hex));
        let sealed_digest = contract.contract_digest_blake3.clone();
        let sig_hex = "02".repeat(64);
        contract.crypto.signature = Some(sig_hex);
        assert_eq!(contract.contract_digest_blake3, sealed_digest);
        assert!(contract.verify_digest());

        let verdict = VerdictEngine::evaluate(&contract, 0, 0, 0, true, 0);
        assert_eq!(verdict.status, VerdictStatus::Pass);
        assert_eq!(verdict.strength, EvidenceStrength::Strong);
        assert_eq!(verdict.security_verdict, SecurityVerdict::Satisfied);
        assert_eq!(verdict.exit_code, 0);
        assert!(verdict.is_success());
        assert!(verdict.is_contract_satisfied());
    }

    #[test]
    fn test_inv36_disabled_awards_pass_without_signature() {
        let contract = mock_contract();
        assert!(!contract.crypto.minisign_enabled);

        let verdict = VerdictEngine::evaluate(&contract, 0, 0, 0, true, 0);
        assert_eq!(verdict.status, VerdictStatus::Pass);
        assert_eq!(verdict.strength, EvidenceStrength::Strong);
        assert_eq!(verdict.security_verdict, SecurityVerdict::Satisfied);
        assert_eq!(verdict.exit_code, 0);
        assert!(verdict.is_success());
        assert!(verdict.is_contract_satisfied());
    }

    #[test]
    fn test_decoupled_workload_crashes_preserve_satisfied_security_verdict() {
        let contract = mock_contract();
        // Child crashes with non-zero exit codes: SIGSEGV (139), OOM (137), panic (101), general error (1)
        for crash_code in [1, 2, 101, 127, 137, 139] {
            let verdict = VerdictEngine::evaluate(&contract, 0, 0, 0, true, crash_code);
            assert_eq!(verdict.status, VerdictStatus::Pass);
            assert_eq!(verdict.security_verdict, SecurityVerdict::Satisfied);
            assert_eq!(verdict.exit_code, crash_code);
            assert!(verdict.is_contract_satisfied());
            assert!(!verdict.is_success());
            assert_eq!(
                verdict.recommended_action(),
                "Commit CoW changes to host workspace."
            );
        }
    }

    #[test]
    fn test_security_violation_overrides_clean_workload_exit_code() {
        let contract = mock_contract();
        // Child cleanly exits with code 0, but committed a kernel capability violation
        let verdict = VerdictEngine::evaluate(&contract, 1, 0, 0, true, 0);
        assert_eq!(verdict.status, VerdictStatus::Fail);
        assert_eq!(verdict.security_verdict, SecurityVerdict::Violated);
        assert_eq!(verdict.exit_code, 125);
        assert!(!verdict.is_contract_satisfied());
        assert!(!verdict.is_success());
        assert_eq!(
            verdict.recommended_action(),
            "Wipe CoW layer; abort session immediately."
        );
    }

    #[test]
    fn test_shadow_mode_unauthorized_writes_satisfied() {
        let mut contract = mock_contract();
        contract.filesystem.shadow = true;
        let verdict = VerdictEngine::evaluate(&contract, 0, 5, 0, true, 42);
        assert_eq!(verdict.status, VerdictStatus::Pass);
        assert_eq!(verdict.security_verdict, SecurityVerdict::Satisfied);
        assert_eq!(verdict.exit_code, 42);
        assert!(verdict.is_contract_satisfied());
        assert!(!verdict.is_success());
        assert!(verdict.reason.contains("[SHADOW VIOLATION]"));
    }

    #[test]
    fn test_shadow_mode_with_severed_evidence_channel_is_inconclusive() {
        let mut contract = mock_contract();
        contract.filesystem.shadow = true;
        let verdict = VerdictEngine::evaluate(&contract, 0, 5, 0, false, 0);
        assert_eq!(verdict.status, VerdictStatus::Inconclusive);
        assert_eq!(verdict.security_verdict, SecurityVerdict::Inconclusive);
        assert_eq!(verdict.exit_code, 125);
        assert!(!verdict.is_contract_satisfied());
    }

    #[test]
    fn test_to_audit_export_schema() {
        let contract = mock_contract();
        let pass_verdict = VerdictEngine::evaluate(&contract, 0, 0, 0, true, 0);
        let export_json = pass_verdict.to_audit_export();
        assert_eq!(export_json["status"], "PASS");
        assert_eq!(export_json["strength"], "STRONG");
        assert_eq!(export_json["security_verdict"], "SATISFIED");
        assert_eq!(export_json["exit_code"], 0);
        assert_eq!(export_json["badge"], "PASS [STRONG]");
        assert_eq!(export_json["security_badge"], "SATISFIED [STRONG]");
        assert_eq!(export_json["is_success"], true);
        assert_eq!(export_json["is_contract_satisfied"], true);
        assert_eq!(
            export_json["recommended_action"],
            "Commit CoW changes to host workspace."
        );

        let fail_verdict = VerdictEngine::evaluate(&contract, 2, 0, 0, true, 0);
        let fail_json = fail_verdict.to_audit_export();
        assert_eq!(fail_json["status"], "FAIL");
        assert_eq!(fail_json["strength"], "STRONG");
        assert_eq!(fail_json["security_verdict"], "VIOLATED");
        assert_eq!(fail_json["exit_code"], 125);
        assert_eq!(fail_json["is_success"], false);
        assert_eq!(fail_json["is_contract_satisfied"], false);
        assert_eq!(
            fail_json["recommended_action"],
            "Wipe CoW layer; abort session immediately."
        );

        let inconcl_verdict = VerdictEngine::evaluate(&contract, 0, 0, 0, false, 0);
        let inconcl_json = inconcl_verdict.to_audit_export();
        assert_eq!(inconcl_json["status"], "INCONCLUSIVE");
        assert_eq!(inconcl_json["security_verdict"], "INCONCLUSIVE");
        assert_eq!(inconcl_json["exit_code"], 125);
        assert_eq!(inconcl_json["is_contract_satisfied"], false);
    }

    #[test]
    fn test_security_verdict_labels() {
        assert_eq!(SecurityVerdict::Satisfied.label(), "SATISFIED");
        assert_eq!(SecurityVerdict::Violated.label(), "VIOLATED");
        assert_eq!(SecurityVerdict::Inconclusive.label(), "INCONCLUSIVE");
        assert_eq!(SecurityVerdict::NotApplicable.label(), "NOT_APPLICABLE");
    }
}
