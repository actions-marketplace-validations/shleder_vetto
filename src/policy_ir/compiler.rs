//! Authoritative Implementation: Policy Compiler (Phase 2 / NEXT_GEN §8).
//!
//! Deterministic translation engine between human/agent intent and the Canonical Security Contract.
//! Operates through 4 discrete, fail-closed phases:
//! 1. AST Parsing & Merging
//! 2. Strict Path Normalization & Canonicalization (openat2 RESOLVE_BENEATH ancestor checks)
//! 3. Conflict Resolution & Capability Negotiation (secret mask precedence)
//! 4. Contract Sealing & Cryptographic Digest Generation

use super::contract::{
    AgentIdentity, AttestationContract, EnvironmentContract, FilesystemContract, NetworkContract,
    NetworkMode, ResourceContract, SecurityContract, UnsealedSecurityContract,
};
use crate::policy::types::{lexical_normalize, strip_domain_port};
pub use crate::policy::types::{Action, ActionVerdict};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CompilerError {
    #[error("Path canonicalization failed: {0}")]
    PathCanonicalizationFailed(String),
    #[error("Conflicting permissions: {0}")]
    ConflictingPermissions(String),
    #[error("Unsupported capability: {0}")]
    UnsupportedCapability(String),
    #[error("Missing mandatory field: {0}")]
    MissingMandatoryField(String),
}

/// Data representation of lowered Landlock and Seccomp enforcement metadata (Phase 4).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LoweredEnforcementMetadata {
    pub landlock_abi: u32,
    pub read_paths: Vec<PathBuf>,
    pub write_paths: Vec<PathBuf>,
    pub mask_paths: Vec<PathBuf>,
    pub network_connect_ports: Vec<u16>,
    pub seccomp_profile: String,
    pub observe_seccomp: bool,
}

fn is_forbidden_system_root(path: &Path) -> bool {
    #[cfg(windows)]
    {
        let p_str = path.to_string_lossy().to_uppercase();
        if p_str == "C:\\"
            || p_str == "C:"
            || p_str.starts_with("C:\\WINDOWS")
            || p_str.starts_with("C:\\PROGRAM FILES")
            || p_str.starts_with("C:\\PROGRAMDATA")
        {
            return true;
        }
    }
    #[cfg(not(windows))]
    {
        if path == Path::new("/") {
            return true;
        }
        for sys in &[
            "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/boot", "/sys", "/proc",
            "/root",
        ] {
            let sp = Path::new(sys);
            if path == sp || path.starts_with(sp) {
                return true;
            }
        }
        // Protect /dev device nodes except /dev/null redirect sink
        if path.starts_with("/dev") && path != Path::new("/dev/null") {
            return true;
        }
    }
    false
}

pub struct PolicyCompiler;

/// Already-resolved production inputs. No defaults or path reinterpretation
/// from the request-oriented compiler are applied at this boundary.
pub struct EffectivePolicyInput<'a> {
    pub policy: &'a crate::policy::Policy,
    pub argv: &'a [String],
    pub cwd: &'a Path,
    pub env: &'a BTreeMap<String, String>,
    pub net: &'a crate::config::NetMode,
    pub nonce: &'a str,
    pub timeout: Option<std::time::Duration>,
    pub tier: Option<crate::policy::Tier>,
    pub backend: String,
    pub observe_seccomp: bool,
    pub debug_ports: Option<&'a crate::policy_ir::contract::DebugPortConfig>,
}

impl PolicyCompiler {
    pub fn compile_effective(
        input: EffectivePolicyInput<'_>,
    ) -> Result<SecurityContract, CompilerError> {
        use super::contract::ProductionContract;
        use crate::config::NetMode;

        if input.argv.first().map_or(true, |s| s.is_empty()) || input.nonce.is_empty() {
            return Err(CompilerError::MissingMandatoryField(
                "command or nonce".into(),
            ));
        }
        let policy = input.policy;

        // ====================================================================
        // Phase 1: Canonical Path Normalization & Traversal Validation
        // ====================================================================
        let workspace_root = input.cwd.to_path_buf();

        // 1. Validate allow_read paths against directory traversal
        for path in &policy.allow_read {
            let clean_path = if cfg!(windows) {
                PathBuf::from(path.to_string_lossy().replace('/', "\\"))
            } else {
                path.clone()
            };
            let path_str = path.to_string_lossy();
            if path_str.split(['/', '\\']).any(|c| c == "..")
                || clean_path
                    .components()
                    .any(|c| c.as_os_str() == ".." || matches!(c, std::path::Component::ParentDir))
            {
                return Err(CompilerError::ConflictingPermissions(format!(
                    "Read target {:?} attempts directory traversal",
                    path
                )));
            }
        }

        // 2. Normalize and resolve relative read paths against workspace_root
        let mut allow_read = Vec::new();
        for path in &policy.allow_read {
            let normalized = if path.is_absolute() {
                path.clone()
            } else {
                workspace_root.join(path)
            };
            let normalized = lexical_normalize(&normalized);
            if !allow_read.contains(&normalized) {
                allow_read.push(normalized);
            }
        }

        // ====================================================================
        // Phase 2: Ancestor Containment & Host System Roots Protection
        // ====================================================================
        // 1. Validate allow_write paths against directory traversal
        for path in &policy.allow_write {
            let clean_path = if cfg!(windows) {
                PathBuf::from(path.to_string_lossy().replace('/', "\\"))
            } else {
                path.clone()
            };
            let path_str = path.to_string_lossy();
            if path_str.split(['/', '\\']).any(|c| c == "..")
                || clean_path
                    .components()
                    .any(|c| c.as_os_str() == ".." || matches!(c, std::path::Component::ParentDir))
            {
                return Err(CompilerError::ConflictingPermissions(format!(
                    "Write target {:?} attempts directory traversal",
                    path
                )));
            }
        }

        // 2. Normalize write paths and check ancestor containment
        let mut allow_write = Vec::new();
        for path in &policy.allow_write {
            let is_rel = !path.is_absolute();
            let normalized = if is_rel {
                workspace_root.join(path)
            } else {
                path.clone()
            };

            // Fail-closed rejection if write target exposes protected system root
            if is_forbidden_system_root(&normalized) {
                return Err(CompilerError::ConflictingPermissions(format!(
                    "Write target {:?} exposes protected system root",
                    path
                )));
            }

            // Ascend directory hierarchy to locate nearest existing ancestor
            let mut ancestor = normalized.clone();
            let mut suffix_components = Vec::new();
            while !ancestor.exists() {
                if let Some(comp) = ancestor.components().next_back() {
                    if comp.as_os_str() == ".." || matches!(comp, std::path::Component::ParentDir) {
                        return Err(CompilerError::ConflictingPermissions(format!(
                            "Write target {:?} attempts directory traversal",
                            path
                        )));
                    }
                    if comp.as_os_str() != "." && !matches!(comp, std::path::Component::CurDir) {
                        suffix_components.push(comp.as_os_str().to_os_string());
                    }
                }
                if !ancestor.pop() {
                    break;
                }
            }

            let canon_ancestor = if let Ok(c) = ancestor.canonicalize() {
                c
            } else {
                ancestor
            };

            // Ancestor must not be a protected system root
            if is_forbidden_system_root(&canon_ancestor) {
                return Err(CompilerError::ConflictingPermissions(format!(
                    "Write target ancestor {:?} exposes protected system root",
                    canon_ancestor
                )));
            }

            // Relative write paths must not escape workspace
            if is_rel {
                let canon_ws = workspace_root
                    .canonicalize()
                    .unwrap_or_else(|_| workspace_root.clone());
                if !canon_ancestor.starts_with(&canon_ws)
                    && !canon_ancestor.starts_with(&workspace_root)
                {
                    return Err(CompilerError::ConflictingPermissions(format!(
                        "Write target ancestor {:?} escapes workspace {:?}",
                        canon_ancestor, workspace_root
                    )));
                }
            }

            let mut resolved = canon_ancestor;
            for comp in suffix_components.into_iter().rev() {
                resolved.push(comp);
            }
            let resolved = lexical_normalize(&resolved);
            if !allow_write.contains(&resolved) {
                allow_write.push(resolved);
            }
        }

        // ====================================================================
        // Phase 3: Secret Mask Precedence & Subtractive Deny Enforcement
        // ====================================================================
        let mut mask_paths: Vec<PathBuf> = policy
            .deny_resolved
            .iter()
            .map(|d| d.path.clone())
            .collect();

        let home_dir = get_home_dir().unwrap_or_else(|| PathBuf::from("/root"));
        let mandatory_masks = vec![
            home_dir.join(".ssh"),
            home_dir.join(".aws"),
            home_dir.join(".gnupg"),
            workspace_root.join(".env"),
            workspace_root.join(".git/config"),
        ];
        for m in mandatory_masks {
            if !mask_paths.contains(&m) {
                mask_paths.push(m);
            }
        }

        // Secret masks unconditionally override write paths
        for w in &allow_write {
            for m in &mask_paths {
                if w == m
                    || w.starts_with(m)
                    || (w != &workspace_root && w != Path::new("/tmp") && m.starts_with(w))
                {
                    return Err(CompilerError::ConflictingPermissions(format!(
                        "Write target {:?} collides with secret mask {:?}",
                        w, m
                    )));
                }
            }
        }

        // Explicit deny_write rules unconditionally override write paths
        for w in &allow_write {
            for d in &policy.deny_write {
                if w == d || w.starts_with(d) {
                    return Err(CompilerError::ConflictingPermissions(format!(
                        "Write target {:?} collides with explicit deny_write {:?}",
                        w, d
                    )));
                }
            }
        }

        // ====================================================================
        // Phase 4: Landlock/Seccomp Lowering Metadata & Cryptographic Sealing
        // ====================================================================
        let (mode, domains, mut ports) = match input.net {
            NetMode::Off => (NetworkMode::Off, vec![], vec![]),
            NetMode::Allowlist(domains) => (NetworkMode::Allowlist, domains.clone(), vec![]),
            NetMode::Strict(rules) => (
                NetworkMode::Strict,
                rules.iter().map(|r| r.domain.clone()).collect(),
                rules.iter().map(|r| r.port).collect(),
            ),
            NetMode::Ask => (NetworkMode::Ask, vec![], vec![]),
        };

        for port in &policy.net_connect_ports {
            if !ports.contains(port) {
                ports.push(*port);
            }
        }

        let max_pids = resolve_max_pids(policy)?;
        let max_memory_bytes = resolve_max_memory_bytes(policy);
        let max_cpu_percent = resolve_cpu_percent(policy);
        let max_wall_time_ms =
            u64::try_from(input.timeout.map_or(0, |t| t.as_millis())).map_err(|_| {
                CompilerError::UnsupportedCapability("timeout exceeds contract range".into())
            })?;

        #[cfg(windows)]
        let default_exec = vec![PathBuf::from(
            std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string()),
        )];
        #[cfg(not(windows))]
        let default_exec = vec![PathBuf::from("/usr"), PathBuf::from("/bin")];

        let mut allow_execute = default_exec;
        let invoked_bin = PathBuf::from(&input.argv[0]);
        if invoked_bin.is_absolute() {
            if let Some(parent) = invoked_bin.parent() {
                let parent_buf = parent.to_path_buf();
                if !allow_execute.contains(&parent_buf) {
                    allow_execute.push(parent_buf);
                }
            }
        }

        UnsealedSecurityContract {
            production: Some(ProductionContract {
                installation_policy: policy.clone(),
                net: input.net.clone(),
                timeout: input.timeout,
                tier: input.tier,
                backend: input.backend,
                observe_seccomp: input.observe_seccomp,
                debug_ports: input.debug_ports.cloned(),
            }),
            crypto: Default::default(),
            contract_version: 1,
            contract_id: format!("production-{}", input.nonce),
            session_nonce: input.nonce.to_string(),
            agent_identity: AgentIdentity {
                agent_name: policy.name.clone(),
                agent_preset: policy.name.clone(),
                agent_version: env!("CARGO_PKG_VERSION").to_string(),
                invoked_binary: PathBuf::from(&input.argv[0]),
                invoked_args: input.argv[1..].to_vec(),
            },
            filesystem: FilesystemContract {
                workspace_root,
                allow_read,
                allow_write,
                allow_execute,
                mask_paths,
                cow_overlay: policy.snapshot,
                execution_root_ro: false,
                shadow: policy.shadow,
            },
            network: NetworkContract {
                mode,
                allowed_domains: domains,
                allowed_ports: ports,
                block_cloud_metadata: input.net.uses_relay(),
                block_loopback_daemons: input.net.uses_relay(),
            },
            resources: ResourceContract {
                max_pids,
                max_memory_bytes,
                max_cpu_percent,
                max_wall_time_ms,
                max_stdout_bytes: crate::sandbox::production::PROD_MAX_STDIO as u64,
                max_file_size_bytes: policy.limits.file_size_bytes.unwrap_or(0),
            },
            environment: EnvironmentContract {
                pass_through_vars: policy.environment.pass_through.clone(),
                explicit_vars: input.env.clone(),
                redacted_patterns: policy.environment.deny.clone(),
                inject_session_nonce: true,
            },
            attestation: AttestationContract {
                generate_audit_jsonl: true,
                sign_minisign: false,
                sign_cosign_slsa: false,
                evidence_level_minimum: "HOST_FACT".into(),
            },
        }
        .seal()
        .map_err(|e| CompilerError::UnsupportedCapability(format!("contract serialization: {e}")))
    }

    pub fn compile(
        agent_name: &str,
        workspace_raw: &Path,
        cli_net_override: Option<NetworkMode>,
        raw_reads: &[PathBuf],
        raw_writes: &[PathBuf],
    ) -> Result<SecurityContract, CompilerError> {
        // Phase 1: Canonicalize workspace root
        let workspace_root = workspace_raw.canonicalize().map_err(|e| {
            CompilerError::PathCanonicalizationFailed(format!("Workspace invalid: {e}"))
        })?;

        // Phase 2: Canonicalize and filter read paths.
        // Always include workspace_root as a readable base.
        let mut allow_read = vec![workspace_root.clone()];
        for path in raw_reads {
            let clean_path = if cfg!(windows) {
                PathBuf::from(path.to_string_lossy().replace('/', "\\"))
            } else {
                path.clone()
            };
            let path_str = path.to_string_lossy();
            if path_str.split(['/', '\\']).any(|c| c == "..")
                || clean_path
                    .components()
                    .any(|c| c.as_os_str() == ".." || matches!(c, std::path::Component::ParentDir))
            {
                return Err(CompilerError::ConflictingPermissions(format!(
                    "Read target {:?} attempts directory traversal",
                    path
                )));
            }
            let normalized = if clean_path.is_absolute() {
                clean_path
            } else {
                let mut base = workspace_root.clone();
                for comp in clean_path.components() {
                    if comp.as_os_str() != "." && !matches!(comp, std::path::Component::CurDir) {
                        base.push(comp.as_os_str());
                    }
                }
                base
            };
            if let Ok(canon) = normalized.canonicalize() {
                allow_read.push(canon);
            } else {
                return Err(CompilerError::PathCanonicalizationFailed(format!(
                    "Read path invalid: {:?}",
                    path
                )));
            }
        }
        allow_read.sort();
        allow_read.dedup();

        // Normalize and canonicalize write paths and verify containment
        // std::fs::canonicalize() fails if the target file does not exist yet (e.g., new file creation).
        // The compiler performs lexical normalization and canonicalizes the nearest existing ancestor directory,
        // verifying that this ancestor resides within workspace_root.
        let mut allow_write = Vec::new();
        for path in raw_writes {
            let clean_path = if cfg!(windows) {
                PathBuf::from(path.to_string_lossy().replace('/', "\\"))
            } else {
                path.clone()
            };
            let path_str = path.to_string_lossy();
            if path_str.split(['/', '\\']).any(|c| c == "..")
                || clean_path
                    .components()
                    .any(|c| c.as_os_str() == ".." || matches!(c, std::path::Component::ParentDir))
            {
                return Err(CompilerError::ConflictingPermissions(format!(
                    "Write target {:?} attempts directory traversal",
                    path
                )));
            }
            let normalized = if clean_path.is_absolute() {
                clean_path
            } else {
                let mut base = workspace_root.clone();
                for comp in clean_path.components() {
                    if comp.as_os_str() != "." && !matches!(comp, std::path::Component::CurDir) {
                        base.push(comp.as_os_str());
                    }
                }
                base
            };

            // Ascend directory hierarchy to locate nearest existing ancestor
            let mut ancestor = normalized.clone();
            let mut suffix_components = Vec::new();
            while !ancestor.exists() {
                if let Some(comp) = ancestor.components().next_back() {
                    if comp.as_os_str() == ".." || matches!(comp, std::path::Component::ParentDir) {
                        return Err(CompilerError::ConflictingPermissions(format!(
                            "Write target {:?} attempts directory traversal",
                            path
                        )));
                    }
                    if comp.as_os_str() != "." && !matches!(comp, std::path::Component::CurDir) {
                        suffix_components.push(comp.as_os_str().to_os_string());
                    }
                }
                if !ancestor.pop() {
                    break;
                }
            }

            let canon_ancestor = ancestor.canonicalize().map_err(|e| {
                CompilerError::PathCanonicalizationFailed(format!(
                    "Write ancestor invalid for {:?}: {}",
                    path, e
                ))
            })?;

            // Hard constraint: existing ancestor must reside inside workspace_root
            if !canon_ancestor.starts_with(&workspace_root) {
                return Err(CompilerError::ConflictingPermissions(format!(
                    "Write target ancestor {:?} escapes workspace {:?}",
                    canon_ancestor, workspace_root
                )));
            }

            // Reassemble canonical ancestor with normalized relative components
            let mut resolved = canon_ancestor;
            for comp in suffix_components.into_iter().rev() {
                resolved.push(comp);
            }
            allow_write.push(resolved);
        }
        allow_write.sort();
        allow_write.dedup();

        // Phase 3: Conflict Resolution & Capability Negotiation
        // Build Mandatory Secret Masking Paths
        let home_dir = get_home_dir().unwrap_or_else(|| PathBuf::from("/root"));
        let mask_paths = vec![
            home_dir.join(".ssh"),
            home_dir.join(".aws"),
            home_dir.join(".gnupg"),
            workspace_root.join(".env"),
            workspace_root.join(".git/config"),
        ];

        // Mask paths take absolute precedence over write paths.
        // Rejects if write target matches mask, is inside mask, or encompasses mask (except workspace_root).
        for w in &allow_write {
            for m in &mask_paths {
                if w == m || w.starts_with(m) || (w != &workspace_root && m.starts_with(w)) {
                    return Err(CompilerError::ConflictingPermissions(format!(
                        "Write target {:?} collides with mandatory secret mask {:?}",
                        w, m
                    )));
                }
            }
        }

        // Resolve Network Mode
        let network_mode = cli_net_override.unwrap_or(NetworkMode::Off);

        // Build Environment Contract
        let env_contract = EnvironmentContract {
            pass_through_vars: vec!["PATH".to_string(), "LANG".to_string(), "TERM".to_string()],
            explicit_vars: BTreeMap::new(),
            redacted_patterns: vec![
                "*_KEY".to_string(),
                "*_SECRET".to_string(),
                "*_TOKEN".to_string(),
                "AWS_*".to_string(),
                "GITHUB_*".to_string(),
            ],
            inject_session_nonce: true,
        };

        // Phase 4: Contract Sealing & BLAKE3/SHA-256 Digest Generation
        let session_nonce = generate_session_nonce();

        #[cfg(windows)]
        let default_exec = vec![PathBuf::from(
            std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string()),
        )];
        #[cfg(not(windows))]
        let default_exec = vec![PathBuf::from("/usr"), PathBuf::from("/bin")];

        let unsealed = UnsealedSecurityContract {
            production: None,
            crypto: Default::default(),
            contract_version: 1,
            contract_id: format!("contract-{}", &session_nonce[..12]),
            session_nonce,
            agent_identity: AgentIdentity {
                agent_name: agent_name.to_string(),
                agent_preset: "default".to_string(),
                agent_version: env!("CARGO_PKG_VERSION").to_string(),
                invoked_binary: PathBuf::from("/bin/sh"),
                invoked_args: vec![],
            },
            filesystem: FilesystemContract {
                workspace_root,
                allow_read,
                allow_write,
                allow_execute: default_exec,
                mask_paths,
                cow_overlay: true,
                execution_root_ro: true,
                shadow: false,
            },
            network: NetworkContract {
                mode: network_mode,
                allowed_domains: vec![],
                allowed_ports: vec![80, 443],
                block_cloud_metadata: true,
                block_loopback_daemons: true,
            },
            resources: ResourceContract {
                max_pids: 128,
                max_memory_bytes: 2 * 1024 * 1024 * 1024, // 2 GB
                max_cpu_percent: 100,
                max_wall_time_ms: 120_000,              // 2 minutes
                max_stdout_bytes: 10 * 1024 * 1024,     // 10 MB
                max_file_size_bytes: 100 * 1024 * 1024, // 100 MB
            },
            environment: env_contract,
            attestation: AttestationContract {
                generate_audit_jsonl: true,
                sign_minisign: true,
                sign_cosign_slsa: false,
                evidence_level_minimum: "HOST_FACT".to_string(),
            },
        };

        unsealed.seal().map_err(|e| {
            CompilerError::PathCanonicalizationFailed(format!("Failed to seal contract: {e}"))
        })
    }
}

fn resolve_cpu_percent(policy: &crate::policy::Policy) -> u32 {
    let pol_cpu = policy.cpu_max.as_deref().and_then(cpu_str_to_percent);
    let cg_cpu = policy
        .cgroup
        .as_ref()
        .and_then(|c| c.cpu_max.as_deref())
        .and_then(cpu_str_to_percent);

    match (pol_cpu, cg_cpu) {
        (Some(p1), Some(p2)) => p1.min(p2),
        (Some(p), None) | (None, Some(p)) => p,
        (None, None) => 100, // unconstrained default
    }
}

fn cpu_str_to_percent(s: &str) -> Option<u32> {
    let ratio = crate::policy::types::parse_cpu_ratio(s)?;
    let pct = (ratio * 100.0).round() as u32;
    Some(pct.max(1))
}

fn resolve_max_memory_bytes(policy: &crate::policy::Policy) -> u64 {
    let as_bytes = policy.limits.address_space_bytes.filter(|&b| b > 0);
    let cg_bytes = policy
        .cgroup
        .as_ref()
        .and_then(|c| c.memory_max.as_deref())
        .and_then(crate::policy::types::parse_bytes_value)
        .filter(|&b| b > 0);

    match (as_bytes, cg_bytes) {
        (Some(a), Some(c)) => a.min(c),
        (Some(a), None) => a,
        (None, Some(c)) => c,
        (None, None) => 0,
    }
}

fn resolve_max_pids(policy: &crate::policy::Policy) -> Result<u32, CompilerError> {
    let proc_limit = policy.limits.processes.filter(|&p| p > 0);
    let cg_limit = policy
        .cgroup
        .as_ref()
        .and_then(|c| c.pids_max.as_deref())
        .and_then(|s| {
            if s.trim().eq_ignore_ascii_case("max") {
                None
            } else {
                s.trim().parse::<u64>().ok()
            }
        })
        .filter(|&p| p > 0);

    let effective_pids = match (proc_limit, cg_limit) {
        (Some(p1), Some(p2)) => p1.min(p2),
        (Some(p), None) => p,
        (None, Some(p)) => p,
        (None, None) => 0,
    };

    u32::try_from(effective_pids).map_err(|_| {
        CompilerError::UnsupportedCapability("process limit exceeds contract v1 range".into())
    })
}

fn get_home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

fn generate_session_nonce() -> String {
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::SystemTime;

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();

    let mut hasher = Sha256::new();
    hasher.update(now.to_le_bytes());
    hasher.update(pid.to_le_bytes());
    hasher.update(count.to_le_bytes());
    let res = hasher.finalize();
    res[0..16].iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Capability Gate Action Authorization Architecture (R1 / INV-01 / INV-08)
// ---------------------------------------------------------------------------

/// Evaluates whether an agent action is authorized by the sealed security contract.
///
/// Fast in-memory evaluation adhering to strict fail-closed principles:
/// 1. Directory traversal (`..` escapes) is strictly forbidden and rejected immediately.
/// 2. Mandatory secret masks (`mask_paths`) take absolute precedence over read/write grants.
/// 3. In-scope checks verify containment within `allow_read`, `allow_write`, or `allow_execute`.
/// 4. Outbound network requests verify `NetworkMode`, domain matching, strict port rules,
///    and block SSRF cloud metadata endpoints and loopback daemons.
pub fn authorize_action(contract: &SecurityContract, action: &Action) -> ActionVerdict {
    match action {
        Action::FsRead(target_path) => authorize_fs_read(contract, target_path),
        Action::FsWrite(target_path) => authorize_fs_write(contract, target_path),
        Action::ProcessExec { binary, args } => authorize_process_exec(contract, binary, args),
        Action::NetConnect { domain, port } => authorize_net_connect(contract, domain, *port),
    }
}

/// Resolves a path against workspace_root (if relative), normalizes components lexically,
/// and detects directory traversal attempts that escape the workspace.
fn resolve_and_check_traversal(workspace_root: &Path, target_path: &Path) -> (PathBuf, bool) {
    let clean_path = if cfg!(windows) {
        PathBuf::from(target_path.to_string_lossy().replace('/', "\\"))
    } else {
        target_path.to_path_buf()
    };

    let has_parent_dir = clean_path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir));

    let ws_norm = lexical_normalize(workspace_root);

    if target_path.is_absolute() || target_path.has_root() {
        let norm = lexical_normalize(&clean_path);
        // Absolute path attempting to use '..' to climb outside a workspace root it declared
        let escaped =
            has_parent_dir && clean_path.starts_with(&ws_norm) && !norm.starts_with(&ws_norm);
        (norm, escaped)
    } else {
        let joined = workspace_root.join(&clean_path);
        let norm = lexical_normalize(&joined);
        let escaped = has_parent_dir && !norm.starts_with(&ws_norm);
        (norm, escaped)
    }
}

fn authorize_fs_read(contract: &SecurityContract, target_path: &Path) -> ActionVerdict {
    if target_path.as_os_str().is_empty() {
        return ActionVerdict::deny("Read target path is empty", "fs_empty_path");
    }

    // Step 1: Traversal escape check
    let (resolved, is_traversal) =
        resolve_and_check_traversal(&contract.filesystem.workspace_root, target_path);

    if is_traversal {
        return ActionVerdict::deny(
            format!(
                "Read target {:?} attempts directory traversal escaping workspace {:?}",
                target_path, contract.filesystem.workspace_root
            ),
            "path_traversal",
        );
    }

    // Step 2: Secret mask precedence (INV-08: absolute priority over read grants)
    for mask in &contract.filesystem.mask_paths {
        let norm_mask = lexical_normalize(mask);
        if resolved == norm_mask || resolved.starts_with(&norm_mask) {
            return ActionVerdict::deny(
                format!(
                    "Read target {:?} collides with mandatory secret mask {:?}",
                    target_path, mask
                ),
                format!("secret_mask:{:?}", mask),
            );
        }
    }

    // Also check production policy deny_read if available in contract
    if let Some(prod) = &contract.production {
        for denied in &prod.installation_policy.deny_read {
            let norm_deny = lexical_normalize(denied);
            if resolved == norm_deny || resolved.starts_with(&norm_deny) {
                return ActionVerdict::deny(
                    format!(
                        "Read target {:?} collides with policy deny_read {:?}",
                        target_path, denied
                    ),
                    format!("deny_read:{:?}", denied),
                );
            }
        }
    }

    // Step 3: Check read scope coverage
    // Read is permitted if within allow_read, allow_write (write implies read),
    // or workspace_root.
    let is_in_scope = contract
        .filesystem
        .allow_read
        .iter()
        .chain(contract.filesystem.allow_write.iter())
        .chain(std::slice::from_ref(&contract.filesystem.workspace_root))
        .any(|root| {
            let norm_root = lexical_normalize(root);
            resolved == norm_root || resolved.starts_with(&norm_root)
        });

    if is_in_scope {
        ActionVerdict::allow()
    } else {
        ActionVerdict::deny(
            format!(
                "Read target {:?} is outside allowed read roots",
                target_path
            ),
            "fs_read_scope",
        )
    }
}

fn authorize_fs_write(contract: &SecurityContract, target_path: &Path) -> ActionVerdict {
    if target_path.as_os_str().is_empty() {
        return ActionVerdict::deny("Write target path is empty", "fs_empty_path");
    }

    // Step 1: Traversal escape check
    let (resolved, is_traversal) =
        resolve_and_check_traversal(&contract.filesystem.workspace_root, target_path);

    if is_traversal {
        return ActionVerdict::deny(
            format!(
                "Write target {:?} attempts directory traversal escaping workspace {:?}",
                target_path, contract.filesystem.workspace_root
            ),
            "path_traversal",
        );
    }

    // Step 2: Secret mask precedence (INV-08)
    // Writes are denied if:
    // a) resolved == mask (direct match)
    // b) resolved.starts_with(mask) (inside mask)
    // c) mask.starts_with(&resolved) && resolved != ws_root (parent of mask, e.g. .git for .git/config)
    let ws_root = lexical_normalize(&contract.filesystem.workspace_root);
    for mask in &contract.filesystem.mask_paths {
        let norm_mask = lexical_normalize(mask);
        let collides = resolved == norm_mask
            || resolved.starts_with(&norm_mask)
            || (norm_mask.starts_with(&resolved) && resolved != ws_root);

        if collides {
            return ActionVerdict::deny(
                format!(
                    "Write target {:?} collides with mandatory secret mask {:?}",
                    target_path, mask
                ),
                format!("secret_mask:{:?}", mask),
            );
        }
    }

    // Check production policy deny_write if available in contract
    if let Some(prod) = &contract.production {
        for denied in &prod.installation_policy.deny_write {
            let norm_deny = lexical_normalize(denied);
            let collides = resolved == norm_deny
                || resolved.starts_with(&norm_deny)
                || (norm_deny.starts_with(&resolved) && resolved != ws_root);

            if collides {
                return ActionVerdict::deny(
                    format!(
                        "Write target {:?} collides with policy deny_write {:?}",
                        target_path, denied
                    ),
                    format!("deny_write:{:?}", denied),
                );
            }
        }
    }

    // Step 3: Check write scope coverage
    if contract.filesystem.allow_write.is_empty() {
        return ActionVerdict::deny(
            format!(
                "Write target {:?} denied: write access is disabled (allow_write is empty)",
                target_path
            ),
            "fs_write_empty",
        );
    }

    let is_in_scope = contract.filesystem.allow_write.iter().any(|root| {
        let norm_root = lexical_normalize(root);
        resolved == norm_root || resolved.starts_with(&norm_root)
    });

    if is_in_scope {
        ActionVerdict::allow()
    } else {
        ActionVerdict::deny(
            format!(
                "Write target {:?} is outside allowed write roots",
                target_path
            ),
            "fs_write_scope",
        )
    }
}

fn authorize_process_exec(
    contract: &SecurityContract,
    binary: &Path,
    _args: &[String],
) -> ActionVerdict {
    if binary.as_os_str().is_empty() {
        return ActionVerdict::deny("Binary path is empty", "exec_empty_path");
    }

    let (resolved, is_traversal) =
        resolve_and_check_traversal(&contract.filesystem.workspace_root, binary);

    if is_traversal {
        return ActionVerdict::deny(
            format!(
                "Execution binary {:?} attempts directory traversal outside workspace",
                binary
            ),
            "path_traversal",
        );
    }

    // Secret mask collision check
    for mask in &contract.filesystem.mask_paths {
        let norm_mask = lexical_normalize(mask);
        if resolved == norm_mask || resolved.starts_with(&norm_mask) {
            return ActionVerdict::deny(
                format!(
                    "Execution binary {:?} collides with secret mask {:?}",
                    binary, mask
                ),
                format!("secret_mask:{:?}", mask),
            );
        }
    }

    // Direct match against explicitly invoked binary
    let norm_invoked = lexical_normalize(&contract.agent_identity.invoked_binary);
    if resolved == norm_invoked
        || lexical_normalize(binary) == norm_invoked
        || binary == &contract.agent_identity.invoked_binary
    {
        return ActionVerdict::allow();
    }

    // Check allow_execute list
    let in_exec_roots = contract.filesystem.allow_execute.iter().any(|root| {
        let norm_root = lexical_normalize(root);
        resolved == norm_root || resolved.starts_with(&norm_root)
    });

    if in_exec_roots {
        ActionVerdict::allow()
    } else {
        ActionVerdict::deny(
            format!(
                "Execution binary {:?} is not authorized by allow_execute or invoked_binary",
                binary
            ),
            "process_exec_scope",
        )
    }
}

fn authorize_net_connect(contract: &SecurityContract, domain: &str, port: u16) -> ActionVerdict {
    let clean_domain = domain.trim().trim_end_matches('.');
    if clean_domain.is_empty() {
        return ActionVerdict::deny(
            "Network destination host/domain is empty",
            "net_empty_domain",
        );
    }

    let host = strip_domain_port(clean_domain).to_ascii_lowercase();

    // Step 1: Network Mode evaluation
    match contract.network.mode {
        NetworkMode::Off => {
            return ActionVerdict::deny(
                format!(
                    "Outbound network egress to {}:{} is disabled (NetworkMode::Off)",
                    clean_domain, port
                ),
                "net_mode:off",
            );
        }
        NetworkMode::Ask => {
            if !is_domain_in_allowlist(&host, &contract.network.allowed_domains) {
                return ActionVerdict::deny(
                    format!(
                        "Connection to {}:{} requires interactive approval (NetworkMode::Ask)",
                        clean_domain, port
                    ),
                    "net_mode:ask_unapproved",
                );
            }
        }
        NetworkMode::Allowlist | NetworkMode::Strict => {}
        NetworkMode::Direct => {}
    }

    // Step 2: SSRF Cloud Metadata Blocking (INV-05 / NEXT_GEN §13)
    if contract.network.block_cloud_metadata && is_cloud_metadata_target(&host) {
        return ActionVerdict::deny(
            format!(
                "SSRF attempt to cloud metadata {}:{} blocked",
                clean_domain, port
            ),
            "cloud_metadata_block",
        );
    }

    // Step 3: Loopback Daemons Blocking
    if contract.network.block_loopback_daemons && is_loopback_target(&host) {
        return ActionVerdict::deny(
            format!(
                "Connection to loopback interface {}:{} blocked",
                clean_domain, port
            ),
            "loopback_block",
        );
    }

    if contract.network.mode == NetworkMode::Direct {
        return ActionVerdict::allow();
    }

    // Step 4: Domain Allowlist Matching
    let domain_matched = is_domain_in_allowlist(&host, &contract.network.allowed_domains);
    if !domain_matched {
        return ActionVerdict::deny(
            format!(
                "Domain '{}' is not in allowed network domains list",
                clean_domain
            ),
            "net_domain_allowlist",
        );
    }

    // Step 5: Port Restrictions (Strict mode / Explicit allowed_ports)
    if !contract.network.allowed_ports.is_empty() && !contract.network.allowed_ports.contains(&port)
    {
        return ActionVerdict::deny(
            format!(
                "Port {} is not in allowed network ports {:?}",
                port, contract.network.allowed_ports
            ),
            "net_port_allowlist",
        );
    }

    ActionVerdict::allow()
}

fn is_domain_in_allowlist(host: &str, allowed_domains: &[String]) -> bool {
    allowed_domains.iter().any(|pat| {
        let pat = strip_domain_port(pat)
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if pat == "*" {
            true
        } else if let Some(suffix) = pat.strip_prefix("*.") {
            host.ends_with(&format!(".{suffix}"))
        } else {
            host == pat || host.ends_with(&format!(".{pat}"))
        }
    })
}

fn is_cloud_metadata_target(host: &str) -> bool {
    let clean = host.trim_start_matches('[').trim_end_matches(']');
    if clean == "169.254.169.254"
        || clean == "100.100.100.200"
        || clean == "169.254.169.253"
        || clean == "instance-data"
        || clean == "metadata.google.internal"
        || clean == "metadata.azure.com"
    {
        return true;
    }
    if let Ok(ip) = clean.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                let [a, b, c, d] = v4.octets();
                (a == 169 && b == 254 && c == 169 && d == 254)
                    || (a == 100 && b == 100 && c == 100 && d == 200)
            }
            std::net::IpAddr::V6(v6) => {
                let octets = v6.octets();
                let is_v4_mapped = octets[..10].iter().all(|&b| b == 0)
                    && octets[10] == 0xff
                    && octets[11] == 0xff;
                let is_v4_compat = octets[..12].iter().all(|&b| b == 0);
                if is_v4_mapped || is_v4_compat {
                    let (a, b, c, d) = (octets[12], octets[13], octets[14], octets[15]);
                    (a == 169 && b == 254 && c == 169 && d == 254)
                        || (a == 100 && b == 100 && c == 100 && d == 200)
                } else {
                    false
                }
            }
        }
    } else {
        false
    }
}

fn is_loopback_target(host: &str) -> bool {
    let clean = host.trim_start_matches('[').trim_end_matches(']');
    if clean == "localhost" || clean.ends_with(".localhost") {
        return true;
    }
    if let Ok(ip) = clean.parse::<std::net::IpAddr>() {
        ip.is_loopback()
    } else {
        clean == "127.0.0.1" || clean.starts_with("127.") || clean == "::1"
    }
}

#[cfg(test)]
mod compiler_tests {
    use super::*;

    #[test]
    fn compile_valid_workspace_contract() {
        let temp_dir = std::env::temp_dir().canonicalize().unwrap();
        let ws = temp_dir.join(format!("vetto_test_ws_{}", generate_session_nonce()));
        std::fs::create_dir_all(&ws).unwrap();

        let sub_out = ws.join("output/new_file.txt");
        let contract = PolicyCompiler::compile(
            "claude",
            &ws,
            Some(NetworkMode::Allowlist),
            std::slice::from_ref(&ws),
            &[sub_out],
        )
        .expect("compilation should succeed");

        assert_eq!(contract.agent_identity.agent_name, "claude");
        assert_eq!(contract.network.mode, NetworkMode::Allowlist);
        assert!(contract.verify_digest());

        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn reject_escaped_write_target() {
        let temp_dir = std::env::temp_dir().canonicalize().unwrap();
        let ws = temp_dir.join(format!("vetto_test_ws_{}", generate_session_nonce()));
        std::fs::create_dir_all(&ws).unwrap();

        let outside_write = temp_dir.join("outside_target.txt");
        let result = PolicyCompiler::compile(
            "codex",
            &ws,
            None,
            std::slice::from_ref(&ws),
            &[outside_write],
        );

        assert!(matches!(
            result,
            Err(CompilerError::ConflictingPermissions(_))
        ));

        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn reject_mask_path_write_collision() {
        let temp_dir = std::env::temp_dir().canonicalize().unwrap();
        let ws = temp_dir.join(format!("vetto_test_ws_{}", generate_session_nonce()));
        std::fs::create_dir_all(&ws).unwrap();

        let env_file = ws.join(".env");
        let result =
            PolicyCompiler::compile("codex", &ws, None, std::slice::from_ref(&ws), &[env_file]);

        assert!(matches!(
            result,
            Err(CompilerError::ConflictingPermissions(_))
        ));

        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn compile_empty_reads_includes_workspace() {
        let temp_dir = std::env::temp_dir().canonicalize().unwrap();
        let ws = temp_dir.join(format!("vetto_test_ws_{}", generate_session_nonce()));
        std::fs::create_dir_all(&ws).unwrap();

        let contract = PolicyCompiler::compile("claude", &ws, None, &[], &[])
            .expect("compilation should succeed with empty raw reads");

        assert!(contract.filesystem.allow_read.contains(&ws));
        assert!(contract.verify_digest());

        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn compile_effective_resource_projections() {
        use crate::policy::types::{CgroupConfig, Policy};
        use crate::policy_ir::compiler::EffectivePolicyInput;
        use std::collections::BTreeMap;

        // 1. Unconstrained defaults to 100% CPU, 0 memory, 0 pids
        let policy = Policy::default();
        let temp_dir = std::env::temp_dir().canonicalize().unwrap();
        let input = EffectivePolicyInput {
            policy: &policy,
            argv: &["/bin/true".into()],
            cwd: &temp_dir,
            env: &BTreeMap::new(),
            net: &crate::config::NetMode::Off,
            nonce: "test-effective-res-1",
            timeout: None,
            tier: None,
            backend: "test".into(),
            observe_seccomp: false,
            debug_ports: None,
        };
        let contract = PolicyCompiler::compile_effective(input).expect("compile effective");
        assert_eq!(contract.resources.max_cpu_percent, 100);
        assert_eq!(contract.resources.max_memory_bytes, 0);
        assert_eq!(contract.resources.max_pids, 0);

        // 2. CPU percentage parsed from policy.cpu_max
        let policy_cpu = Policy {
            cpu_max: Some("50%".into()),
            ..Default::default()
        };
        let input = EffectivePolicyInput {
            policy: &policy_cpu,
            argv: &["/bin/true".into()],
            cwd: &temp_dir,
            env: &BTreeMap::new(),
            net: &crate::config::NetMode::Off,
            nonce: "test-effective-res-2",
            timeout: None,
            tier: None,
            backend: "test".into(),
            observe_seccomp: false,
            debug_ports: None,
        };
        let contract = PolicyCompiler::compile_effective(input).expect("compile effective");
        assert_eq!(contract.resources.max_cpu_percent, 50);

        // 3. Minimum between address_space_bytes and cgroup.memory_max
        let policy_mem = Policy {
            limits: crate::policy::types::ResourceLimits {
                address_space_bytes: Some(2 * 1024 * 1024 * 1024), // 2GB
                processes: Some(128),
                ..Default::default()
            },
            cgroup: Some(CgroupConfig {
                memory_max: Some("1G".into()), // 1GB
                pids_max: Some("64".into()),
                swap_max: None,
                cpu_max: Some("40%".into()),
            }),
            ..Default::default()
        };

        let input = EffectivePolicyInput {
            policy: &policy_mem,
            argv: &["/bin/true".into()],
            cwd: &temp_dir,
            env: &BTreeMap::new(),
            net: &crate::config::NetMode::Off,
            nonce: "test-effective-res-3",
            timeout: None,
            tier: None,
            backend: "test".into(),
            observe_seccomp: false,
            debug_ports: None,
        };
        let contract = PolicyCompiler::compile_effective(input).expect("compile effective");
        // Effective memory is min(2GB, 1GB) = 1GB
        assert_eq!(contract.resources.max_memory_bytes, 1024 * 1024 * 1024);
        // Effective pids is min(128, 64) = 64
        assert_eq!(contract.resources.max_pids, 64);
        // Effective cpu is min(default 100, 40) = 40
        assert_eq!(contract.resources.max_cpu_percent, 40);
    }

    #[test]
    fn test_authorize_action_fs_read_scope_and_masks() {
        let temp_dir = std::env::temp_dir().canonicalize().unwrap();
        let ws = temp_dir.join(format!("vetto_gate_test_read_{}", generate_session_nonce()));
        std::fs::create_dir_all(&ws).unwrap();

        let sub_read = ws.join("src/lib.rs");
        std::fs::create_dir_all(ws.join("src")).unwrap();
        std::fs::write(&sub_read, b"// test content").unwrap();
        let contract = PolicyCompiler::compile(
            "claude",
            &ws,
            Some(NetworkMode::Allowlist),
            &[sub_read.clone()],
            &[],
        )
        .expect("compile contract");

        // 1. Reading inside workspace is allowed
        let v_read_ws = authorize_action(&contract, &Action::FsRead(ws.join("src/lib.rs")));
        assert!(v_read_ws.is_allowed());

        // 2. Reading relative path is resolved against workspace and allowed
        let v_read_rel = authorize_action(&contract, &Action::FsRead(PathBuf::from("src/lib.rs")));
        assert!(v_read_rel.is_allowed());

        // 3. Reading secret mask .env is denied
        let v_read_env = authorize_action(&contract, &Action::FsRead(ws.join(".env")));
        assert!(v_read_env.is_denied());
        assert_eq!(
            v_read_env.denial_rule(),
            Some(format!("secret_mask:{:?}", ws.join(".env")).as_str())
        );

        // 4. Reading relative directory traversal escaping workspace is denied
        let v_read_trav = authorize_action(
            &contract,
            &Action::FsRead(PathBuf::from("../../etc/shadow")),
        );
        assert!(v_read_trav.is_denied());
        assert_eq!(v_read_trav.denial_rule(), Some("path_traversal"));

        // 5. Reading outside roots is denied
        let v_read_outside =
            authorize_action(&contract, &Action::FsRead(PathBuf::from("/var/log/syslog")));
        assert!(v_read_outside.is_denied());
        assert_eq!(v_read_outside.denial_rule(), Some("fs_read_scope"));

        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn test_authorize_action_fs_write_and_mask_precedence() {
        let temp_dir = std::env::temp_dir().canonicalize().unwrap();
        let ws = temp_dir.join(format!(
            "vetto_gate_test_write_{}",
            generate_session_nonce()
        ));
        std::fs::create_dir_all(&ws).unwrap();

        let write_target = ws.join("output/result.txt");
        let contract = PolicyCompiler::compile("codex", &ws, None, &[], &[write_target.clone()])
            .expect("compile contract");

        // 1. Writing to authorized target is allowed
        let v_write_ok = authorize_action(&contract, &Action::FsWrite(write_target));
        assert!(v_write_ok.is_allowed());

        // 2. Writing to unlisted path outside allow_write is denied
        let v_write_outside =
            authorize_action(&contract, &Action::FsWrite(ws.join("unlisted.txt")));
        assert!(v_write_outside.is_denied());
        assert_eq!(v_write_outside.denial_rule(), Some("fs_write_scope"));

        // 3. Writing to .git directory (parent of .git/config secret mask) is denied
        let v_write_git = authorize_action(&contract, &Action::FsWrite(ws.join(".git")));
        assert!(v_write_git.is_denied());
        assert!(v_write_git
            .denial_rule()
            .unwrap()
            .starts_with("secret_mask:"));

        // 4. Writing relative traversal escaping workspace is denied
        let v_write_trav =
            authorize_action(&contract, &Action::FsWrite(PathBuf::from("../escape.txt")));
        assert!(v_write_trav.is_denied());
        assert_eq!(v_write_trav.denial_rule(), Some("path_traversal"));

        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn test_authorize_action_network_rules_and_ssrf() {
        let temp_dir = std::env::temp_dir().canonicalize().unwrap();
        let ws = temp_dir.join(format!("vetto_gate_test_net_{}", generate_session_nonce()));
        std::fs::create_dir_all(&ws).unwrap();

        let mut contract =
            PolicyCompiler::compile("claude", &ws, Some(NetworkMode::Allowlist), &[], &[])
                .expect("compile contract");

        contract.network.allowed_domains = vec![
            "api.anthropic.com".to_string(),
            "*.github.com".to_string(),
        ];
        contract.network.allowed_ports = vec![443];

        // 1. Exact domain match on port 443 is allowed
        let v_net_ok = authorize_action(
            &contract,
            &Action::NetConnect {
                domain: "api.anthropic.com".into(),
                port: 443,
            },
        );
        assert!(v_net_ok.is_allowed());

        // 2. Wildcard subdomain match is allowed
        let v_net_wild = authorize_action(
            &contract,
            &Action::NetConnect {
                domain: "raw.github.com".into(),
                port: 443,
            },
        );
        assert!(v_net_wild.is_allowed());

        // 3. Disallowed domain is denied
        let v_net_evil = authorize_action(
            &contract,
            &Action::NetConnect {
                domain: "malicious.com".into(),
                port: 443,
            },
        );
        assert!(v_net_evil.is_denied());
        assert_eq!(v_net_evil.denial_rule(), Some("net_domain_allowlist"));

        // 4. Disallowed port is denied
        let v_net_port = authorize_action(
            &contract,
            &Action::NetConnect {
                domain: "api.anthropic.com".into(),
                port: 8080,
            },
        );
        assert!(v_net_port.is_denied());
        assert_eq!(v_net_port.denial_rule(), Some("net_port_allowlist"));

        // 5. SSRF Cloud metadata IP (169.254.169.254) is blocked unconditionally
        let v_net_meta = authorize_action(
            &contract,
            &Action::NetConnect {
                domain: "169.254.169.254".into(),
                port: 80,
            },
        );
        assert!(v_net_meta.is_denied());
        assert_eq!(v_net_meta.denial_rule(), Some("cloud_metadata_block"));

        // 6. Loopback is blocked
        let v_net_loop = authorize_action(
            &contract,
            &Action::NetConnect {
                domain: "localhost".into(),
                port: 6379,
            },
        );
        assert!(v_net_loop.is_denied());
        assert_eq!(v_net_loop.denial_rule(), Some("loopback_block"));

        // 7. NetworkMode::Off denies all
        contract.network.mode = NetworkMode::Off;
        let v_net_off = authorize_action(
            &contract,
            &Action::NetConnect {
                domain: "api.anthropic.com".into(),
                port: 443,
            },
        );
        assert!(v_net_off.is_denied());
        assert_eq!(v_net_off.denial_rule(), Some("net_mode:off"));

        let _ = std::fs::remove_dir_all(&ws);
    }
}
