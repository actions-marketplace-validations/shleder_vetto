//! Sandbox security capability tracking, enforcement contracts, and verification reports.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::policy::Tier;

/// Atomic security capabilities tracked by Vetto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityCapability {
    FilesystemIsolation,
    NetworkIsolation,
    ProcessIsolation,
    ProcessTreeContainment,
    ResourceLimits,
    SyscallRestriction,
    ExecutionRootIsolation,
    HostEvidence,
}

impl SecurityCapability {
    pub fn label(self) -> &'static str {
        match self {
            SecurityCapability::FilesystemIsolation => "filesystem",
            SecurityCapability::NetworkIsolation => "network",
            SecurityCapability::ProcessIsolation => "process",
            SecurityCapability::ProcessTreeContainment => "tree",
            SecurityCapability::ResourceLimits => "resources",
            SecurityCapability::SyscallRestriction => "syscalls",
            SecurityCapability::ExecutionRootIsolation => "exec-root",
            SecurityCapability::HostEvidence => "host-evidence",
        }
    }

    pub fn all() -> [SecurityCapability; 8] {
        [
            SecurityCapability::FilesystemIsolation,
            SecurityCapability::NetworkIsolation,
            SecurityCapability::ProcessIsolation,
            SecurityCapability::ProcessTreeContainment,
            SecurityCapability::ResourceLimits,
            SecurityCapability::SyscallRestriction,
            SecurityCapability::ExecutionRootIsolation,
            SecurityCapability::HostEvidence,
        ]
    }
}

/// Per-capability enforcement state for one execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnforcementState {
    Requested,
    Configured,
    Enforced,
    Verified,
    Unsupported,
    Failed,
}

impl EnforcementState {
    pub fn label(self) -> &'static str {
        match self {
            EnforcementState::Requested => "requested",
            EnforcementState::Configured => "configured",
            EnforcementState::Enforced => "enforced",
            EnforcementState::Verified => "verified",
            EnforcementState::Unsupported => "unsupported",
            EnforcementState::Failed => "failed",
        }
    }

    pub fn is_enforced(self) -> bool {
        matches!(
            self,
            EnforcementState::Enforced | EnforcementState::Verified
        )
    }
}

/// Reason for a failed enforcement state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PreparationFailureKind {
    UnsupportedOnPlatform,
    PlatformUnavailable,
    SpawnRefused,
    VerificationUnavailable,
}

impl PreparationFailureKind {
    pub fn label(self) -> &'static str {
        match self {
            PreparationFailureKind::UnsupportedOnPlatform => "unsupported-on-platform",
            PreparationFailureKind::PlatformUnavailable => "platform-unavailable",
            PreparationFailureKind::SpawnRefused => "spawn-refused",
            PreparationFailureKind::VerificationUnavailable => "verification-unavailable",
        }
    }
}

/// Backend implementation kinds.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "kebab-case")]
pub enum BackendKind {
    #[default]
    Direct,
    Linux,
    Macos,
    Windows,
}

impl BackendKind {
    pub fn label(self) -> &'static str {
        match self {
            BackendKind::Direct => "direct",
            BackendKind::Linux => "linux",
            BackendKind::Macos => "macos",
            BackendKind::Windows => "windows",
        }
    }

    pub fn all() -> [BackendKind; 4] {
        [
            BackendKind::Direct,
            BackendKind::Linux,
            BackendKind::Macos,
            BackendKind::Windows,
        ]
    }

    pub fn current_platform() -> BackendKind {
        #[cfg(target_os = "linux")]
        {
            BackendKind::Linux
        }
        #[cfg(target_os = "macos")]
        {
            BackendKind::Macos
        }
        #[cfg(target_os = "windows")]
        {
            BackendKind::Windows
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            BackendKind::Direct
        }
    }
}

/// Host-observed verification of a live confined child.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HostVerification {
    pub seccomp_filter: bool,
    pub no_new_privs: bool,
    pub pgroup_separate: bool,
    pub rlimit_as_ok: bool,
    pub rlimit_nproc_ok: bool,
    pub rlimit_cpu_ok: bool,
    pub rlimit_fsize_ok: bool,
    pub subreaper_ok: bool,
    pub win_in_job: bool,
    pub win_kill_on_close: bool,
    pub win_low_integrity: bool,
    pub win_job_ceiling: bool,
    pub cgroup_memory_ok: bool,
    pub cgroup_pids_ok: bool,
    pub cgroup_cpu_ok: bool,
    pub netns_isolated: bool,
}

impl HostVerification {
    pub fn none() -> Self {
        Self::default()
    }

    pub fn all_observed(&self) -> bool {
        self.seccomp_filter
            && self.no_new_privs
            && self.pgroup_separate
            && (self.rlimit_as_ok || self.cgroup_memory_ok)
            && (self.rlimit_nproc_ok || self.cgroup_pids_ok)
            && (self.rlimit_cpu_ok || self.cgroup_cpu_ok)
            && self.subreaper_ok
    }
}

/// One capability row inside an [`EnforcementReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityRecord {
    pub capability: SecurityCapability,
    pub requested: bool,
    pub state: EnforcementState,
    pub failure: Option<PreparationFailureKind>,
}

/// Structured preparation and enforcement outcome for an execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementReport {
    pub backend: BackendKind,
    pub scenario_id: String,
    pub session_nonce: String,
    pub registry_hash: String,
    pub frozen_hash: String,
    pub policy_hash: String,
    pub preparation_ok: bool,
    pub records: Vec<CapabilityRecord>,
}

impl EnforcementReport {
    pub fn build(
        backend: BackendKind,
        policy: &CanonicalPolicy,
        identity: &ExecutionIdentity,
        states: &BTreeMap<SecurityCapability, EnforcementState>,
        failures: &BTreeMap<SecurityCapability, PreparationFailureKind>,
        preparation_ok: bool,
    ) -> Self {
        let mut records = Vec::new();
        for cap in SecurityCapability::all() {
            let state = states
                .get(&cap)
                .copied()
                .unwrap_or(EnforcementState::Unsupported);
            let failure = failures.get(&cap).copied();
            records.push(CapabilityRecord {
                capability: cap,
                requested: true,
                state,
                failure,
            });
        }
        EnforcementReport {
            backend,
            scenario_id: identity.scenario_id.clone(),
            session_nonce: identity.session_nonce.clone(),
            registry_hash: identity.registry_hash.clone(),
            frozen_hash: identity.frozen_hash.clone(),
            policy_hash: policy.policy_hash.clone(),
            preparation_ok,
            records,
        }
    }

    pub fn state(&self, capability: SecurityCapability) -> EnforcementState {
        self.records
            .iter()
            .find(|r| r.capability == capability)
            .map(|r| r.state)
            .unwrap_or(EnforcementState::Unsupported)
    }

    pub fn state_of(&self, cap: SecurityCapability) -> EnforcementState {
        self.state(cap)
    }

    pub fn is_enforced(&self, capability: SecurityCapability) -> bool {
        self.preparation_ok && self.state(capability).is_enforced()
    }

    pub fn requested(&self) -> Vec<SecurityCapability> {
        self.records
            .iter()
            .filter(|r| r.requested)
            .map(|r| r.capability)
            .collect()
    }

    pub fn enforced(&self) -> Vec<SecurityCapability> {
        SecurityCapability::all()
            .into_iter()
            .filter(|c| self.is_enforced(*c))
            .collect()
    }

    pub fn unsupported(&self) -> Vec<SecurityCapability> {
        self.records
            .iter()
            .filter(|r| r.state == EnforcementState::Unsupported)
            .map(|r| r.capability)
            .collect()
    }

    pub fn failed(&self) -> Vec<(SecurityCapability, Option<PreparationFailureKind>)> {
        self.records
            .iter()
            .filter(|r| r.state == EnforcementState::Failed)
            .map(|r| (r.capability, r.failure))
            .collect()
    }

    pub fn verified(&self) -> Vec<SecurityCapability> {
        self.records
            .iter()
            .filter(|r| r.state == EnforcementState::Verified)
            .map(|r| r.capability)
            .collect()
    }

    pub fn allows_pass(&self, required: &[SecurityCapability]) -> bool {
        if !self.preparation_ok {
            return false;
        }
        for cap in required {
            if !self.is_enforced(*cap) {
                return false;
            }
        }
        true
    }

    pub fn binds_identity(&self, identity: &ExecutionIdentity) -> bool {
        self.scenario_id == identity.scenario_id
            && self.session_nonce == identity.session_nonce
            && self.registry_hash == identity.registry_hash
            && self.frozen_hash == identity.frozen_hash
    }

    pub fn render_deterministic(&self) -> String {
        let mut parts = vec![format!("backend={}", self.backend.label())];
        for record in &self.records {
            parts.push(format!(
                "{}={}",
                record.capability.label(),
                record.state.label()
            ));
        }
        parts.push(format!("preparation_ok={}", self.preparation_ok));
        parts.join("|")
    }
}

/// Execution identity bound to scenario and nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionIdentity {
    pub scenario_id: String,
    pub session_nonce: String,
    pub registry_hash: String,
    pub frozen_hash: String,
    #[serde(default)]
    pub contract_digest: Option<String>,
}

impl ExecutionIdentity {
    pub fn new(
        scenario_id: &str,
        session_nonce: &str,
        registry_hash: &str,
        frozen_hash: &str,
    ) -> Self {
        Self {
            scenario_id: scenario_id.to_string(),
            session_nonce: session_nonce.to_string(),
            registry_hash: registry_hash.to_string(),
            frozen_hash: frozen_hash.to_string(),
            contract_digest: None,
        }
    }
}

/// Platform-independent canonical policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalPolicy {
    pub scenario_id: String,
    pub registry_hash: String,
    pub session_nonce: String,
    pub frozen_hash: String,
    pub net_mode: String,
    pub tier: String,
    pub backend_hint: String,
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: PathBuf,
    pub allow_read: Vec<PathBuf>,
    pub allow_write: Vec<PathBuf>,
    pub deny_read: Vec<PathBuf>,
    pub deny_write: Vec<PathBuf>,
    pub deny_resolved: Vec<PathBuf>,
    pub policy_bytes: Vec<u8>,
    pub policy_hash: String,
}

impl CanonicalPolicy {
    pub fn from_frozen(spec: &FrozenSpec) -> Self {
        let policy_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&spec.policy_bytes);
            hex_encode(&hasher.finalize())
        };
        CanonicalPolicy {
            scenario_id: spec.scenario_id.clone(),
            registry_hash: spec.registry_hash.clone(),
            session_nonce: spec.nonce.clone(),
            frozen_hash: spec.hash(),
            net_mode: spec.net_mode.clone(),
            tier: spec.tier.clone(),
            backend_hint: spec.backend.clone(),
            argv: spec.argv.clone(),
            env: spec.env.clone(),
            cwd: spec.cwd.clone(),
            allow_read: spec.allow_read.iter().map(PathBuf::from).collect(),
            allow_write: spec.allow_write.iter().map(PathBuf::from).collect(),
            deny_read: spec.deny_read.iter().map(PathBuf::from).collect(),
            deny_write: spec.deny_write.iter().map(PathBuf::from).collect(),
            deny_resolved: spec.deny_resolved.iter().map(PathBuf::from).collect(),
            policy_bytes: spec.policy_bytes.clone(),
            policy_hash,
        }
    }
}

/// Frozen input specification for launch continuity.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FrozenSpec {
    pub scenario_id: String,
    pub registry_hash: String,
    pub tier: String,
    pub net_mode: String,
    pub backend: String,
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: PathBuf,
    pub allow_read: Vec<String>,
    pub allow_write: Vec<String>,
    pub deny_read: Vec<String>,
    pub deny_write: Vec<String>,
    pub deny_resolved: Vec<String>,
    pub nonce: String,
    pub policy_bytes: Vec<u8>,
}

impl FrozenSpec {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.canonical_bytes());
        hex_encode(&hasher.finalize())
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[allow(clippy::too_many_arguments)]
pub fn freeze_spec(
    scenario_id: &str,
    registry_hash: &str,
    policy: &crate::policy::Policy,
    tier: &str,
    net_mode: &crate::config::NetMode,
    backend_describe: &str,
    argv: &[String],
    env: &BTreeMap<String, String>,
    cwd: &std::path::Path,
    nonce: &str,
) -> FrozenSpec {
    let mut allow_read: Vec<String> = policy
        .allow_read
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    allow_read.sort();
    let mut allow_write: Vec<String> = policy
        .allow_write
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    allow_write.sort();
    let mut deny_read: Vec<String> = policy
        .deny_read
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    deny_read.sort();
    let mut deny_write: Vec<String> = policy
        .deny_write
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    deny_write.sort();
    let mut deny_resolved: Vec<String> = policy
        .deny_resolved
        .iter()
        .map(|e| e.path.display().to_string())
        .collect();
    deny_resolved.sort();

    FrozenSpec {
        scenario_id: scenario_id.to_string(),
        registry_hash: registry_hash.to_string(),
        tier: tier.to_string(),
        net_mode: net_mode.label(),
        backend: backend_describe.to_string(),
        argv: argv.to_vec(),
        env: env.clone(),
        cwd: cwd.to_path_buf(),
        allow_read,
        allow_write,
        deny_read,
        deny_write,
        deny_resolved,
        nonce: nonce.to_string(),
        policy_bytes: Vec::new(),
    }
}

/// Pre-exec child plan for isolation setup.
#[derive(Debug, Clone, Default)]
pub struct ChildEnforcementPlan {
    pub net_deny: bool,
    pub new_pgroup: bool,
    pub rlimit_as: Option<u64>,
    pub rlimit_nproc: Option<u64>,
    pub rlimit_cpu: Option<u64>,
    pub rlimit_fsize: Option<u64>,
    pub chroot: Option<PathBuf>,
    pub mask_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Default)]
pub struct PrepareContext {
    #[cfg(target_os = "linux")]
    pub expected_limits: Option<crate::sandbox::linux::proctrack::ExpectedLimits>,
}

/// Minimal backend capability interface.
pub trait SandboxBackend: Send {
    fn kind(&self) -> BackendKind;
    fn name(&self) -> &'static str;
    fn supports(&self, capability: SecurityCapability) -> bool;
    fn prepare(
        &mut self,
        policy: &CanonicalPolicy,
        identity: &ExecutionIdentity,
    ) -> EnforcementReport {
        self.prepare_with_context(policy, identity, &PrepareContext::default())
    }
    fn prepare_with_context(
        &mut self,
        policy: &CanonicalPolicy,
        identity: &ExecutionIdentity,
        _ctx: &PrepareContext,
    ) -> EnforcementReport {
        self.prepare(policy, identity)
    }
    fn pre_exec_plan(&self) -> Option<ChildEnforcementPlan> {
        None
    }
    fn note_spawned(&mut self, _pid: u32) {}
    fn note_host_verified(&mut self, _verification: &HostVerification) {}
    fn note_tree_clean(&mut self, _clean: bool) {}
    fn note_diagnostic(&mut self, _diag: String) {}
    fn diagnostic(&self) -> Option<String> {
        None
    }
    fn restrict_tier(&mut self, _tier: Option<Tier>) {}
    fn enforcement(&self) -> Option<&EnforcementReport>;
    fn teardown(&mut self) {}
}

#[derive(Debug, Clone, Default)]
pub struct DirectBackend {
    report: Option<EnforcementReport>,
}

impl DirectBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SandboxBackend for DirectBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Direct
    }

    fn name(&self) -> &'static str {
        "direct-exec"
    }

    fn supports(&self, capability: SecurityCapability) -> bool {
        capability == SecurityCapability::HostEvidence
    }

    fn prepare_with_context(
        &mut self,
        policy: &CanonicalPolicy,
        identity: &ExecutionIdentity,
        _ctx: &PrepareContext,
    ) -> EnforcementReport {
        let mut states = BTreeMap::new();
        for cap in SecurityCapability::all() {
            let state = if cap == SecurityCapability::HostEvidence {
                EnforcementState::Enforced
            } else {
                EnforcementState::Unsupported
            };
            states.insert(cap, state);
        }
        let report = EnforcementReport::build(
            BackendKind::Direct,
            policy,
            identity,
            &states,
            &BTreeMap::new(),
            true,
        );
        self.report = Some(report.clone());
        report
    }

    fn enforcement(&self) -> Option<&EnforcementReport> {
        self.report.as_ref()
    }
}

#[derive(Debug, Clone, Default)]
pub struct GenericPlatformBackend {
    kind: BackendKind,
    report: Option<EnforcementReport>,
    plan: Option<ChildEnforcementPlan>,
    tier: Option<Tier>,
    diag: Option<String>,
}

impl GenericPlatformBackend {
    pub fn new(kind: BackendKind) -> Self {
        Self {
            kind,
            report: None,
            plan: None,
            tier: None,
            diag: None,
        }
    }
}

impl SandboxBackend for GenericPlatformBackend {
    fn kind(&self) -> BackendKind {
        self.kind
    }

    fn name(&self) -> &'static str {
        self.kind.label()
    }

    fn supports(&self, capability: SecurityCapability) -> bool {
        match self.kind {
            BackendKind::Direct => capability == SecurityCapability::HostEvidence,
            BackendKind::Linux => true,
            BackendKind::Macos => matches!(
                capability,
                SecurityCapability::FilesystemIsolation
                    | SecurityCapability::NetworkIsolation
                    | SecurityCapability::ProcessIsolation
                    | SecurityCapability::ProcessTreeContainment
                    | SecurityCapability::HostEvidence
            ),
            BackendKind::Windows => matches!(
                capability,
                SecurityCapability::ProcessIsolation
                    | SecurityCapability::ProcessTreeContainment
                    | SecurityCapability::ResourceLimits
                    | SecurityCapability::HostEvidence
            ),
        }
    }

    fn prepare_with_context(
        &mut self,
        policy: &CanonicalPolicy,
        identity: &ExecutionIdentity,
        _ctx: &PrepareContext,
    ) -> EnforcementReport {
        let mut states = BTreeMap::new();
        for cap in SecurityCapability::all() {
            let state = if self.supports(cap) {
                EnforcementState::Enforced
            } else {
                EnforcementState::Unsupported
            };
            states.insert(cap, state);
        }
        let report =
            EnforcementReport::build(self.kind, policy, identity, &states, &BTreeMap::new(), true);
        self.plan = Some(ChildEnforcementPlan {
            net_deny: policy.net_mode == "off",
            new_pgroup: true,
            ..Default::default()
        });
        self.report = Some(report.clone());
        report
    }

    fn pre_exec_plan(&self) -> Option<ChildEnforcementPlan> {
        self.plan.clone()
    }

    fn note_spawned(&mut self, _pid: u32) {
        if let Some(r) = self.report.as_mut() {
            for rec in &mut r.records {
                if rec.state == EnforcementState::Configured {
                    rec.state = EnforcementState::Enforced;
                }
            }
        }
    }

    fn note_host_verified(&mut self, verification: &HostVerification) {
        if let Some(r) = self.report.as_mut() {
            for rec in &mut r.records {
                if rec.capability == SecurityCapability::ProcessIsolation
                    && verification.no_new_privs
                {
                    rec.state = EnforcementState::Verified;
                }
                if rec.capability == SecurityCapability::SyscallRestriction
                    && verification.seccomp_filter
                {
                    rec.state = EnforcementState::Verified;
                }
                if rec.capability == SecurityCapability::ProcessTreeContainment
                    && (verification.subreaper_ok || verification.win_in_job)
                {
                    rec.state = EnforcementState::Verified;
                }
                if rec.capability == SecurityCapability::ResourceLimits
                    && (verification.rlimit_as_ok
                        || verification.rlimit_cpu_ok
                        || verification.rlimit_fsize_ok
                        || verification.rlimit_nproc_ok
                        || verification.win_job_ceiling
                        || verification.cgroup_memory_ok
                        || verification.cgroup_cpu_ok
                        || verification.cgroup_pids_ok)
                {
                    rec.state = EnforcementState::Verified;
                }
            }
        }
    }

    fn note_tree_clean(&mut self, clean: bool) {
        if let Some(r) = self.report.as_mut() {
            for rec in &mut r.records {
                if rec.capability == SecurityCapability::ProcessTreeContainment {
                    if clean {
                        rec.state = EnforcementState::Verified;
                    } else {
                        rec.state = EnforcementState::Failed;
                        rec.failure = Some(PreparationFailureKind::VerificationUnavailable);
                    }
                }
            }
        }
    }

    fn note_diagnostic(&mut self, diag: String) {
        self.diag = Some(diag);
    }

    fn diagnostic(&self) -> Option<String> {
        self.diag.clone()
    }

    fn restrict_tier(&mut self, tier: Option<Tier>) {
        self.tier = tier;
    }

    fn enforcement(&self) -> Option<&EnforcementReport> {
        self.report.as_ref()
    }
}

#[derive(Debug, Clone, Default)]
pub struct LinuxBackend {
    inner: GenericPlatformBackend,
}

impl LinuxBackend {
    pub fn new() -> Self {
        Self {
            inner: GenericPlatformBackend::new(BackendKind::Linux),
        }
    }
}

impl std::ops::Deref for LinuxBackend {
    type Target = GenericPlatformBackend;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl std::ops::DerefMut for LinuxBackend {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl SandboxBackend for LinuxBackend {
    fn kind(&self) -> BackendKind {
        self.inner.kind()
    }
    fn name(&self) -> &'static str {
        self.inner.name()
    }
    fn supports(&self, capability: SecurityCapability) -> bool {
        self.inner.supports(capability)
    }
    fn prepare(
        &mut self,
        policy: &CanonicalPolicy,
        identity: &ExecutionIdentity,
    ) -> EnforcementReport {
        self.inner.prepare(policy, identity)
    }
    fn prepare_with_context(
        &mut self,
        policy: &CanonicalPolicy,
        identity: &ExecutionIdentity,
        ctx: &PrepareContext,
    ) -> EnforcementReport {
        self.inner.prepare_with_context(policy, identity, ctx)
    }
    fn pre_exec_plan(&self) -> Option<ChildEnforcementPlan> {
        self.inner.pre_exec_plan()
    }
    fn note_spawned(&mut self, pid: u32) {
        self.inner.note_spawned(pid);
    }
    fn note_host_verified(&mut self, verification: &HostVerification) {
        self.inner.note_host_verified(verification);
    }
    fn note_tree_clean(&mut self, clean: bool) {
        self.inner.note_tree_clean(clean);
    }
    fn note_diagnostic(&mut self, diag: String) {
        self.inner.note_diagnostic(diag);
    }
    fn diagnostic(&self) -> Option<String> {
        self.inner.diagnostic()
    }
    fn restrict_tier(&mut self, tier: Option<Tier>) {
        self.inner.restrict_tier(tier);
    }
    fn enforcement(&self) -> Option<&EnforcementReport> {
        self.inner.enforcement()
    }
}

pub type MacosBackend = GenericPlatformBackend;
pub type WindowsBackend = GenericPlatformBackend;

pub fn select_backend(kind: BackendKind) -> Box<dyn SandboxBackend> {
    match kind {
        BackendKind::Direct => Box::new(DirectBackend::new()),
        BackendKind::Linux => Box::new(LinuxBackend::new()),
        other => Box::new(GenericPlatformBackend::new(other)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixEntry {
    pub backend: BackendKind,
    pub capability: SecurityCapability,
    pub supported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformMatrix {
    pub entries: Vec<MatrixEntry>,
}

impl PlatformMatrix {
    pub fn current() -> Self {
        let mut entries = Vec::new();
        for kind in BackendKind::all() {
            let backend = select_backend(kind);
            for capability in SecurityCapability::all() {
                entries.push(MatrixEntry {
                    backend: kind,
                    capability,
                    supported: backend.supports(capability),
                });
            }
        }
        Self { entries }
    }

    pub fn supports(&self, backend: BackendKind, cap: SecurityCapability) -> bool {
        self.entries
            .iter()
            .find(|e| e.backend == backend && e.capability == cap)
            .map(|e| e.supported)
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    Pass,
    Fail,
    Inconclusive,
    NotApplicable,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Pass => "PASS",
            Verdict::Fail => "FAIL",
            Verdict::Inconclusive => "INCONCLUSIVE",
            Verdict::NotApplicable => "NOT_APPLICABLE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClaimStrength {
    Strong,
    Partial,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    Aux,
    Spawn,
    FsRead,
    FsWrite,
    Net,
    Proc,
    Secrets,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    Blocker,
    High,
    #[default]
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scenario {
    pub id: String,
    pub category: Category,
    pub severity: Severity,
    pub required_caps: Vec<String>,
    pub strength: BTreeMap<String, ClaimStrength>,
    pub quorum: usize,
    pub known_limitation: String,
    #[serde(default)]
    pub residual_risk: String,
}

impl Scenario {
    pub fn strength_for(&self, target: Target) -> ClaimStrength {
        self.strength
            .get(target.label())
            .copied()
            .unwrap_or(ClaimStrength::Unsupported)
    }

    pub fn lint(&self) -> Result<(), String> {
        if self.id.trim().is_empty() {
            return Err("scenario id is empty".to_string());
        }
        if self.quorum < 1 {
            return Err(format!("{}: quorum must be >= 1", self.id));
        }
        if self.known_limitation.trim().is_empty() {
            return Err(format!("{}: known_limitation must be non-empty", self.id));
        }
        if self.strength.values().any(|s| *s == ClaimStrength::Partial)
            && self.residual_risk.trim().is_empty()
        {
            return Err(format!(
                "{}: PARTIAL target requires residual_risk",
                self.id
            ));
        }
        Ok(())
    }
}

pub fn required_capabilities(scenario: &Scenario) -> Vec<SecurityCapability> {
    match scenario.category {
        Category::Aux => vec![SecurityCapability::HostEvidence],
        Category::Spawn => vec![
            SecurityCapability::ProcessIsolation,
            SecurityCapability::HostEvidence,
        ],
        Category::FsRead | Category::FsWrite => vec![
            SecurityCapability::FilesystemIsolation,
            SecurityCapability::ExecutionRootIsolation,
            SecurityCapability::HostEvidence,
        ],
        Category::Net => vec![
            SecurityCapability::NetworkIsolation,
            SecurityCapability::HostEvidence,
        ],
        Category::Proc => vec![
            SecurityCapability::ProcessIsolation,
            SecurityCapability::ProcessTreeContainment,
            SecurityCapability::HostEvidence,
        ],
        Category::Secrets => vec![
            SecurityCapability::FilesystemIsolation,
            SecurityCapability::HostEvidence,
        ],
    }
}

pub fn allows_pass(report: &EnforcementReport, scenario: &Scenario) -> bool {
    report.allows_pass(&required_capabilities(scenario))
}

pub fn apply_backend_ceiling(
    verdict: Verdict,
    report: &EnforcementReport,
    scenario: &Scenario,
) -> Verdict {
    match verdict {
        Verdict::Pass if !allows_pass(report, scenario) => Verdict::Inconclusive,
        other => other,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Target {
    LinuxFull,
    LinuxFsOnly,
    LinuxSeccomp,
    Macos,
    Windows,
}

impl Target {
    pub fn label(&self) -> &'static str {
        match self {
            Target::LinuxFull => "linux-full",
            Target::LinuxFsOnly => "linux-fs-only",
            Target::LinuxSeccomp => "linux-seccomp",
            Target::Macos => "macos",
            Target::Windows => "windows",
        }
    }
}

pub fn current_target(tier_label: Option<&str>) -> Target {
    #[cfg(target_os = "linux")]
    {
        match tier_label {
            Some("full") => Target::LinuxFull,
            Some("fs-only") => Target::LinuxFsOnly,
            Some("seccomp") => Target::LinuxSeccomp,
            _ => Target::LinuxSeccomp,
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = tier_label;
        Target::Macos
    }
    #[cfg(target_os = "windows")]
    {
        let _ = tier_label;
        Target::Windows
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = tier_label;
        Target::LinuxSeccomp
    }
}

pub fn eval_is_loopback_host(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h == "localhost" {
        return true;
    }
    let clean = h.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = clean.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => v4.is_loopback(),
            std::net::IpAddr::V6(v6) => {
                if v6.is_loopback() {
                    return true;
                }
                let octets = v6.octets();
                let is_v4_mapped = octets[..10].iter().all(|&b| b == 0)
                    && octets[10] == 0xff
                    && octets[11] == 0xff;
                let is_v4_compat = octets[..12].iter().all(|&b| b == 0);
                if is_v4_mapped || is_v4_compat {
                    std::net::Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15])
                        .is_loopback()
                } else {
                    false
                }
            }
        }
    } else {
        false
    }
}
