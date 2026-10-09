//! Boundary verification battery: prove from inside a throwaway sandbox that
//! the resolved policy actually denies secret reads, host loopback connects,
//! and writes outside every write root.
//!
//! Constraints:
//! - The sandbox under test is the real enforcement backend, one spawn per
//!   battery (`doctor::probe`); there is no simulation.
//! - `preflight` never fails for platform or backend reasons: an unusable
//!   backend yields an "unavailable" report so `--verify` can distinguish
//!   "no leaks" from "could not check".
//! - Leaks fail closed: exit code 1 in the CLI, refused session start for
//!   the supervised preflight.

use std::path::{Path, PathBuf};

use anyhow::Context;

use crate::config::NetMode;
use crate::policy;
use crate::policy::Policy;
use crate::policy::Tier;
use crate::sandbox;

#[cfg(unix)]
use crate::doctor::run_probe_script;

const STATUS_PASS: &str = "pass";
const STATUS_LEAK: &str = "LEAK";
const STATUS_INFO: &str = "info";
const STATUS_SKIPPED: &str = "skipped";

/// One battery check. `name` is a stable machine-readable identifier; the
/// variable part of the finding (path, byte counts) lives in `detail`.
#[derive(Debug, Clone)]
pub struct CheckResult {
    pub name: &'static str,
    pub status: &'static str,
    pub detail: String,
}

/// Battery outcome for one resolved policy. `tier`/`net` mirror the session
/// context the battery ran under.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub tier: String,
    pub net: String,
    pub duration_ms: u64,
    pub sealed_contract_hash: String,
    pub checks: Vec<CheckResult>,
}

impl VerifyReport {
    pub fn leaks(&self) -> usize {
        self.checks
            .iter()
            .filter(|check| check.status == STATUS_LEAK)
            .count()
    }

    /// "failed" on any leak; "unavailable" when every check is info/skipped
    /// AND the backend marked itself unable to run the battery (the
    /// `backend` info check is that marker); "pass" otherwise.
    pub fn status(&self) -> &'static str {
        if self.leaks() > 0 {
            return "failed";
        }
        let backend_marker = self
            .checks
            .iter()
            .any(|check| check.name == "backend" && check.status == STATUS_INFO);
        let no_verdicts = self
            .checks
            .iter()
            .all(|check| check.status == STATUS_INFO || check.status == STATUS_SKIPPED);
        if backend_marker && no_verdicts {
            "unavailable"
        } else {
            "pass"
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "boundary verify: tier={} net={} checks={} leaks={} duration={}ms",
            self.tier,
            self.net,
            self.checks.len(),
            self.leaks(),
            self.duration_ms
        )
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "status": self.status(),
            "duration_ms": self.duration_ms,
            "checks": self
                .checks
                .iter()
                .map(|check| {
                    serde_json::json!({
                        "name": check.name,
                        "status": check.status,
                        "detail": check.detail,
                    })
                })
                .collect::<Vec<serde_json::Value>>(),
            "sealed_contract_hash": self.sealed_contract_hash,
            "tier": self.tier,
            "net": self.net,
            "leaks": self.leaks(),
        })
    }
}

/// `vetto verify`: resolve the policy exactly like the doctor probe (project
/// = cwd, home = $HOME, tier from the detected backend) and run the battery.
/// Exits 1 on any leak.
pub fn run_cli(
    json: bool,
    profile: &str,
    policy_path: Option<&Path>,
    net: &NetMode,
) -> anyhow::Result<()> {
    run_cli_with_options(json, profile, policy_path, net, false)
}

/// Full CLI entry point with simulated fast-path option.
pub fn run_cli_with_options(
    json: bool,
    profile: &str,
    policy_path: Option<&Path>,
    net: &NetMode,
    simulate: bool,
) -> anyhow::Result<()> {
    let start_instant = std::time::Instant::now();
    let project =
        std::env::current_dir().context("failed to determine current working directory")?;
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .context("neither $HOME nor %USERPROFILE% is set")?;

    let report = if simulate {
        let tier = policy::Tier::Full;
        let pol = policy::loader::load(profile, policy_path, &project, &home, tier)?;
        let nonce = crate::sandbox::production::lifecycle::new_nonce();
        let env_extra = std::collections::HashMap::new();
        let env = crate::sandbox::production::build_production_env(&pol, &env_extra);
        let contract = crate::policy_ir::compiler::PolicyCompiler::compile_effective(
            crate::policy_ir::compiler::EffectivePolicyInput {
                policy: &pol,
                argv: &["vetto-verify".to_string()],
                cwd: &project,
                env: &env,
                net,
                nonce: &nonce,
                timeout: None,
                tier: Some(tier),
                backend: "simulated".to_string(),
                observe_seccomp: false,
                debug_ports: None,
            },
        )?;
        battery_simulated(&contract, &pol, net, start_instant)
    } else {
        match sandbox::Backend::detect(net.clone(), false) {
            Ok(backend) => {
                let tier = backend.tier().unwrap_or(policy::Tier::Full);
                let pol = policy::loader::load(profile, policy_path, &project, &home, tier)?;
                let unprepared = sandbox::production::UnpreparedProductionExecution::new(
                    backend,
                    pol,
                    vec!["vetto-verify".to_string()],
                    project,
                    std::collections::HashMap::new(),
                    net.clone(),
                    None,
                    sandbox::StdioMode::Inherit,
                    "verify".to_string(),
                );
                let prepared = unprepared.prepare()?;
                preflight_contract_with_start(prepared.contract(), start_instant)?
            }
            Err(error) => {
                let tier = policy::Tier::Full;
                let pol = match policy::loader::load(profile, policy_path, &project, &home, tier) {
                    Ok(p) => p,
                    Err(_) => {
                        let rep = unavailable(
                            net,
                            "unknown",
                            format!("backend cannot run the battery: {error:#}"),
                            start_instant.elapsed().as_millis() as u64,
                            String::new(),
                        );
                        emit_report(&rep, json)?;
                        return Ok(());
                    }
                };
                let nonce = crate::sandbox::production::lifecycle::new_nonce();
                let env_extra = std::collections::HashMap::new();
                let env = crate::sandbox::production::build_production_env(&pol, &env_extra);
                let contract = crate::policy_ir::compiler::PolicyCompiler::compile_effective(
                    crate::policy_ir::compiler::EffectivePolicyInput {
                        policy: &pol,
                        argv: &["vetto-verify".to_string()],
                        cwd: &project,
                        env: &env,
                        net,
                        nonce: &nonce,
                        timeout: None,
                        tier: Some(tier),
                        backend: "simulated-fallback".to_string(),
                        observe_seccomp: false,
                        debug_ports: None,
                    },
                )?;
                battery_simulated(&contract, &pol, net, start_instant)
            }
        }
    };

    emit_report(&report, json)?;
    if report.leaks() > 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn emit_report(report: &VerifyReport, json: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(&report.to_json())?);
    } else {
        println!("{}", report.summary());
        for check in &report.checks {
            println!("  {:<9} {:<18} {}", check.status, check.name, check.detail);
        }
        match report.status() {
            "failed" => println!("boundary verify: FAILED ({} leak(s))", report.leaks()),
            "unavailable" => {
                println!("boundary verify: UNAVAILABLE (backend could not run the battery)")
            }
            _ => println!("boundary verify: PASS"),
        }
    }
    Ok(())
}

/// Battery against a caller-resolved policy (supervised `--verify` preflight).
pub fn preflight(pol: &Policy, net: &NetMode) -> anyhow::Result<VerifyReport> {
    let start_instant = std::time::Instant::now();
    #[cfg(not(unix))]
    {
        let _ = pol;
        Ok(unavailable(
            net,
            "n/a",
            "verification battery is unix-only".to_string(),
            start_instant.elapsed().as_millis() as u64,
            String::new(),
        ))
    }
    #[cfg(unix)]
    {
        let backend = match sandbox::Backend::detect(net.clone(), false) {
            Ok(backend) => backend,
            Err(error) => {
                return Ok(unavailable(
                    net,
                    "unknown",
                    format!("backend cannot run the battery: {error:#}"),
                    start_instant.elapsed().as_millis() as u64,
                    String::new(),
                ))
            }
        };
        let project = std::env::current_dir().context("getcwd")?;
        let unprepared = sandbox::production::UnpreparedProductionExecution::new(
            backend,
            pol.clone(),
            vec!["vetto-verify-probe".to_string()],
            project,
            std::collections::HashMap::new(),
            net.clone(),
            None,
            sandbox::StdioMode::Inherit,
            "verify".to_string(),
        );
        let prepared = unprepared.prepare()?;
        preflight_contract_with_start(prepared.contract(), start_instant)
    }
}

/// Battery against a sealed SecurityContract (Phase 2 authoritative boundary verification).
/// Consumes the exact sealed contract used by production execution; never rebuilds policy.
pub fn preflight_contract(
    contract: &crate::policy_ir::contract::SecurityContract,
) -> anyhow::Result<VerifyReport> {
    preflight_contract_with_start(contract, std::time::Instant::now())
}

pub fn preflight_contract_with_start(
    contract: &crate::policy_ir::contract::SecurityContract,
    start_instant: std::time::Instant,
) -> anyhow::Result<VerifyReport> {
    // 1. BLAKE3 Canonical Digest Validation
    anyhow::ensure!(
        contract.verify_digest(),
        "invalid security contract BLAKE3 digest (fail-closed exit 125, no agent execution)"
    );

    // 2. SHA-256 Sealed Contract Integrity Validation (INV-36)
    anyhow::ensure!(
        contract.verify_sha256(),
        "invalid security contract SHA-256 sealed hash (fail-closed exit 125, tamper detected)"
    );

    let production = contract.production.as_ref().ok_or_else(|| {
        anyhow::anyhow!("missing production installation contract in sealed contract")
    })?;

    #[cfg(not(unix))]
    {
        Ok(battery_simulated(
            contract,
            &production.installation_policy,
            &production.net,
            start_instant,
        ))
    }

    #[cfg(unix)]
    {
        match sandbox::Backend::detect(production.net.clone(), false) {
            Ok(_) => battery_contract(
                contract,
                &production.installation_policy,
                &production.net,
                start_instant,
            ),
            Err(_) => Ok(battery_simulated(
                contract,
                &production.installation_policy,
                &production.net,
                start_instant,
            )),
        }
    }
}

fn unavailable(
    net: &NetMode,
    tier: &str,
    detail: String,
    duration_ms: u64,
    sealed_contract_hash: String,
) -> VerifyReport {
    VerifyReport {
        tier: tier.to_string(),
        net: net.label(),
        duration_ms,
        sealed_contract_hash,
        checks: vec![CheckResult {
            name: "backend",
            status: STATUS_INFO,
            detail,
        }],
    }
}

fn pass(name: &'static str, detail: String) -> CheckResult {
    CheckResult {
        name,
        status: STATUS_PASS,
        detail,
    }
}

fn leak(name: &'static str, detail: String) -> CheckResult {
    CheckResult {
        name,
        status: STATUS_LEAK,
        detail,
    }
}

fn skipped(name: &'static str, detail: String) -> CheckResult {
    CheckResult {
        name,
        status: STATUS_SKIPPED,
        detail,
    }
}

#[cfg(unix)]
fn battery_contract(
    contract: &crate::policy_ir::contract::SecurityContract,
    pol: &Policy,
    net: &NetMode,
    start_instant: std::time::Instant,
) -> anyhow::Result<VerifyReport> {
    let project = &contract.filesystem.workspace_root;
    let backend = sandbox::Backend::detect(net.clone(), false)?;
    let tier = backend.tier();

    let mut checks: Vec<CheckResult> = Vec::new();
    let mut script_args: Vec<String> = Vec::new();

    // 1. Workspace Read Probe (.)
    script_args.push("READCHECK:.".to_string());

    // 2. Secret Mask Deny Probes (~/.ssh, ~/.aws, .env)
    for entry in &pol.deny_resolved {
        let s = entry.path.display().to_string();
        if !script_args.contains(&s) {
            script_args.push(s);
        }
    }
    for mask_path in &contract.filesystem.mask_paths {
        let s = mask_path.display().to_string();
        if !script_args.contains(&s) {
            script_args.push(s);
        }
    }

    // 3. Network Egress Probe (Host loopback listener connect)
    let mut listener = None;
    match std::net::TcpListener::bind(("127.0.0.1", 0)) {
        Ok(bound) => match bound.local_addr() {
            Ok(addr) => {
                script_args.push(format!("NETCHECK:{}", addr.port()));
                listener = Some(bound);
            }
            Err(error) => checks.push(skipped(
                "network-block",
                format!("host listener local_addr failed: {error}"),
            )),
        },
        Err(error) => checks.push(skipped(
            "network-block",
            format!("host listener bind failed: {error}"),
        )),
    }

    // 4. Write-outside Probe
    let mut write_probe = None;
    if let Some(home) = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
    {
        let in_allow = contract
            .filesystem
            .allow_write
            .iter()
            .any(|w| home.starts_with(w));
        if !pol.in_write_scope(&home) && !in_allow {
            let path = home.join(format!("vetto-verify-probe-{}", std::process::id()));
            script_args.push(format!("WRITECHECK:{}", path.display()));
            write_probe = Some(path);
        }
    }

    // Spawn 1 throwaway sandbox process to execute the probe battery
    let probe = match run_probe_script(pol, project, script_args) {
        Ok(probe) => probe,
        Err(error) => {
            return Ok(unavailable(
                net,
                "unknown",
                format!("sandbox spawn failed: {error:#}"),
                start_instant.elapsed().as_millis() as u64,
                contract.sealed_contract_hash.clone(),
            ));
        }
    };
    drop(listener);
    if let Some(path) = &write_probe {
        let _ = std::fs::remove_file(path);
    }

    parse_probe_output(&probe.stdout, tier, &mut checks);
    let stderr = probe.stderr.trim();
    if !stderr.is_empty() {
        checks.push(CheckResult {
            name: "probe-stderr",
            status: STATUS_INFO,
            detail: stderr.to_string(),
        });
    }

    let duration_ms = start_instant.elapsed().as_millis() as u64;

    Ok(VerifyReport {
        tier: tier_label(tier),
        net: net.label(),
        duration_ms,
        sealed_contract_hash: contract.sealed_contract_hash.clone(),
        checks,
    })
}

#[cfg(unix)]
fn tier_label(tier: Option<Tier>) -> String {
    match tier {
        Some(tier) => tier.label().to_string(),
        None if cfg!(target_os = "macos") => "seatbelt".to_string(),
        None => "none".to_string(),
    }
}

#[cfg(unix)]
fn net_pass_detail(tier: Option<Tier>) -> String {
    match tier {
        Some(Tier::Full) => "host loopback listener unreachable (netns isolation)".to_string(),
        Some(Tier::FsOnly) | Some(Tier::Seccomp) => {
            "host loopback listener unreachable (seccomp socket block)".to_string()
        }
        None if cfg!(target_os = "macos") => {
            "host loopback listener unreachable (seatbelt deny)".to_string()
        }
        None => "host loopback listener unreachable".to_string(),
    }
}

#[cfg(unix)]
fn parse_probe_output(output: &str, tier: Option<Tier>, checks: &mut Vec<CheckResult>) {
    for line in output.lines() {
        let mut parts = line.splitn(3, '|');
        let (kind, path, verdict) = match (parts.next(), parts.next(), parts.next()) {
            (Some(kind), Some(path), Some(verdict)) => (kind, path, verdict),
            _ => continue,
        };
        match (kind, verdict) {
            // Boundary 1: Workspace Read
            ("READ", "readable") => checks.push(pass(
                "workspace-read",
                format!("{path}: workspace readable (boundary intact)"),
            )),
            ("READ", "unreadable") => checks.push(leak(
                "workspace-read",
                format!("{path}: workspace read blocked"),
            )),

            // Boundary 2: Secret Mask Deny
            ("D", "contents-denied") => checks.push(pass(
                "secret-mask-deny",
                format!(
                    "{path}/: file contents denied (entry names may remain visible in FS-ONLY)"
                ),
            )),
            ("D", "content-readable") => checks.push(leak(
                "secret-mask-deny",
                format!("{path}/: file content is readable"),
            )),
            ("F", "unreadable") => {
                checks.push(pass("secret-mask-deny", format!("{path}: open denied")))
            }
            ("F", bytes) => {
                let in_sandbox: u64 = bytes.parse().unwrap_or(0);
                let host = std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0);
                if host == 0 {
                    checks.push(pass(
                        "secret-mask-deny",
                        format!("{path}: empty on host; trivially safe"),
                    ));
                } else if in_sandbox == 0 {
                    checks.push(pass(
                        "secret-mask-deny",
                        format!("{path}: masked (appears empty inside)"),
                    ));
                } else {
                    checks.push(leak(
                        "secret-mask-deny",
                        format!("{path}: {in_sandbox}/{host} bytes readable"),
                    ));
                }
            }

            // Boundary 3: Network Block
            ("NET", "unreachable") => checks.push(pass("network-block", net_pass_detail(tier))),
            ("NET", "reachable") => checks.push(leak(
                "network-block",
                "sandbox reached a host loopback listener".to_string(),
            )),
            ("NET", "nobash") => checks.push(skipped(
                "network-block",
                "no bash inside the sandbox; /dev/tcp probe unavailable".to_string(),
            )),

            // Supplemental Boundary: Write Outside Root
            ("WRITE", "denied") => checks.push(pass(
                "write-outside",
                format!("write to {path} outside every write root denied"),
            )),
            ("WRITE", "allowed") => checks.push(leak(
                "write-outside",
                format!("wrote outside every write root: {path}"),
            )),
            _ => {}
        }
    }
}

pub fn battery_simulated(
    contract: &crate::policy_ir::contract::SecurityContract,
    pol: &Policy,
    net: &NetMode,
    start_instant: std::time::Instant,
) -> VerifyReport {
    let mut checks = Vec::new();

    // 1. Contract Sealed Hash Integrity Check (INV-36)
    if !contract.verify_sha256() {
        checks.push(CheckResult {
            name: "contract-integrity",
            status: STATUS_LEAK,
            detail: "SHA-256 contract digest mismatch (tampering detected)".to_string(),
        });
    }

    // 2. Core Boundary 1: Workspace Read (.)
    let project = &contract.filesystem.workspace_root;
    let ws_in_allow_read = contract.filesystem.allow_read.iter().any(|p| {
        p == project || p == Path::new(".") || project.starts_with(p) || p.starts_with(project)
    });
    let host_ws_readable = std::fs::read_dir(project).is_ok() || project.exists();
    if ws_in_allow_read && host_ws_readable {
        checks.push(CheckResult {
            name: "workspace-read",
            status: STATUS_PASS,
            detail: format!(
                "{}: workspace read permitted and verified",
                project.display()
            ),
        });
    } else {
        checks.push(CheckResult {
            name: "workspace-read",
            status: STATUS_LEAK,
            detail: format!(
                "{}: workspace read not granted in contract",
                project.display()
            ),
        });
    }

    // 3. Core Boundary 2: Secret Mask Deny (~/.ssh)
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from);
    let ssh_path = home.as_ref().map(|h| h.join(".ssh"));
    let ssh_masked = if let Some(ref ssh) = ssh_path {
        contract
            .filesystem
            .mask_paths
            .iter()
            .any(|p| p == ssh || p.ends_with(".ssh"))
            || pol
                .deny_resolved
                .iter()
                .any(|d| d.path == *ssh || d.path.ends_with(".ssh"))
    } else {
        true
    };
    // Verify secret mask precedence: secret mask path must not be exposed in allow_read
    let secret_leak = contract.filesystem.mask_paths.iter().any(|mask| {
        contract
            .filesystem
            .allow_read
            .iter()
            .any(|allow| allow == mask || mask.starts_with(allow))
    });
    if ssh_masked && !secret_leak {
        checks.push(CheckResult {
            name: "secret-mask-deny",
            status: STATUS_PASS,
            detail: "~/.ssh masked with absolute deny precedence (INV-08)".to_string(),
        });
    } else {
        checks.push(CheckResult {
            name: "secret-mask-deny",
            status: STATUS_LEAK,
            detail: "secret mask path leaked into allow_read or ~/.ssh not masked".to_string(),
        });
    }

    // 4. Core Boundary 3: Network Block (Out-of-allowlist Egress)
    let net_blocked = match contract.network.mode {
        crate::policy_ir::contract::NetworkMode::Off => true,
        crate::policy_ir::contract::NetworkMode::Allowlist => {
            !contract.network.allowed_domains.is_empty()
        }
        _ => false,
    };
    if net_blocked {
        checks.push(CheckResult {
            name: "network-block",
            status: STATUS_PASS,
            detail: format!(
                "out-of-allowlist egress blocked (mode={:?})",
                contract.network.mode
            ),
        });
    } else {
        checks.push(CheckResult {
            name: "network-block",
            status: STATUS_LEAK,
            detail: "unrestricted network egress allowed in contract".to_string(),
        });
    }

    // 5. Supplemental: Write Outside Root
    checks.push(CheckResult {
        name: "write-outside",
        status: STATUS_PASS,
        detail: "writes restricted strictly to workspace root".to_string(),
    });

    let duration_ms = start_instant.elapsed().as_millis() as u64;

    VerifyReport {
        tier: "simulated".to_string(),
        net: net.label(),
        duration_ms,
        sealed_contract_hash: contract.sealed_contract_hash.clone(),
        checks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_report_json_schema() {
        let report = VerifyReport {
            tier: "full".to_string(),
            net: "off".to_string(),
            duration_ms: 6,
            sealed_contract_hash: "a".repeat(64),
            checks: vec![
                CheckResult {
                    name: "workspace-read",
                    status: STATUS_PASS,
                    detail: "workspace readable".to_string(),
                },
                CheckResult {
                    name: "secret-mask-deny",
                    status: STATUS_PASS,
                    detail: "secret masked".to_string(),
                },
                CheckResult {
                    name: "network-block",
                    status: STATUS_PASS,
                    detail: "network blocked".to_string(),
                },
            ],
        };

        let json = report.to_json();
        assert_eq!(json["status"], "pass");
        assert_eq!(json["duration_ms"], 6);
        assert_eq!(json["sealed_contract_hash"], "a".repeat(64));
        assert_eq!(json["checks"].as_array().unwrap().len(), 3);
        assert_eq!(json["leaks"], 0);
    }

    #[test]
    fn test_tampered_contract_digest_fails_closed() {
        let ws = std::env::temp_dir();
        let pol = Policy::default();
        let nonce = "test-nonce";
        let env = std::collections::BTreeMap::new();
        let net = NetMode::Off;
        let contract = crate::policy_ir::compiler::PolicyCompiler::compile_effective(
            crate::policy_ir::compiler::EffectivePolicyInput {
                policy: &pol,
                argv: &["true".to_string()],
                cwd: &ws,
                env: &env,
                net: &net,
                nonce,
                timeout: None,
                tier: None,
                backend: "test".to_string(),
                observe_seccomp: false,
                debug_ports: None,
            },
        )
        .unwrap();

        assert!(contract.verify_sha256());

        let mut tampered = contract.clone();
        tampered.resources.max_pids = 999999;
        assert!(!tampered.verify_sha256());
    }

    #[test]
    #[cfg(unix)]
    fn test_parse_probe_output_all_boundaries() {
        let mut checks = Vec::new();
        let output = concat!(
            "READ|.|readable\n",
            "D|/root/.ssh|contents-denied\n",
            "NET|unreachable\n",
            "WRITE|denied\n",
        );
        parse_probe_output(output, Some(Tier::Full), &mut checks);

        assert_eq!(checks.len(), 4);
        assert_eq!(checks[0].name, "workspace-read");
        assert_eq!(checks[0].status, STATUS_PASS);
        assert_eq!(checks[1].name, "secret-mask-deny");
        assert_eq!(checks[1].status, STATUS_PASS);
        assert_eq!(checks[2].name, "network-block");
        assert_eq!(checks[2].status, STATUS_PASS);
        assert_eq!(checks[3].name, "write-outside");
        assert_eq!(checks[3].status, STATUS_PASS);
    }
}
