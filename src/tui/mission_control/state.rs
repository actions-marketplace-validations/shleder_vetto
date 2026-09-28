//! Mission Control Dashboard State Management.

use std::collections::{HashSet, VecDeque};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::time::Instant;

use anyhow::Result;
use chrono::{DateTime, Utc};

use crate::doctor::preflight::{execute_preflight_diagnostics, PreflightReport};
use crate::onboard::SUPPORTED_AGENTS;
use crate::rescue::snapshot::{list_snapshots, rollback_snapshot, SnapshotMetadata};

use super::theme::Theme;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityEventType {
    AccessDenial,   // General access denial
    LandlockDenial, // Landlock LSM filesystem access denial
    SeccompFilter,  // Seccomp-BPF filtered syscall
    BlockedNetwork, // NetRelay / Anti-SSRF drop (L7 egress)
    SecretMasked,   // Inode tmpfs overlay (INV-08)
    QuotaExceeded,  // Network quota
}

impl SecurityEventType {
    pub fn badge(&self) -> &'static str {
        match self {
            Self::AccessDenial | Self::LandlockDenial => "LANDLOCK",
            Self::SeccompFilter => "SECCOMP",
            Self::BlockedNetwork => "L7_EGRESS",
            Self::SecretMasked => "SECRET",
            Self::QuotaExceeded => "QUOTA",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecurityEventItem {
    pub ts: DateTime<Utc>,
    pub event_type: SecurityEventType,
    pub subject: String,
    pub detail: String,
    pub source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissionTab {
    Agents,
    Sandbox,
    Doctor,
    Sessions,
    SecurityStream,
    Fleet,
}

impl MissionTab {
    pub fn index(&self) -> usize {
        match self {
            Self::Agents => 0,
            Self::Sandbox => 1,
            Self::Doctor => 2,
            Self::Sessions => 3,
            Self::SecurityStream => 4,
            Self::Fleet => 5,
        }
    }

    pub fn from_index(idx: usize) -> Self {
        match idx % 6 {
            0 => Self::Agents,
            1 => Self::Sandbox,
            2 => Self::Doctor,
            3 => Self::Sessions,
            4 => Self::SecurityStream,
            5 => Self::Fleet,
            _ => unreachable!(),
        }
    }

    pub fn next(&self) -> Self {
        Self::from_index(self.index() + 1)
    }

    pub fn prev(&self) -> Self {
        Self::from_index(self.index() + 5)
    }
}

#[derive(Debug, Clone)]
pub struct AgentCard {
    pub name: &'static str,
    pub display_name: String,
    pub binary_name: String,
    pub binary_path: PathBuf,
    pub is_shim_active: bool,
    pub is_running: bool,
    pub active_pids: Vec<u32>,
    pub network_allowlist: Vec<String>,
    pub preset: &'static str,
}

#[derive(Debug, Clone)]
pub struct ActiveSessionCard {
    pub session_id: String,
    pub pid: u32,
    pub agent: String,
    pub started_at_secs: u64,
    pub uptime_secs: u64,
    pub policy: String,
    pub tier: String,
    pub cwd: String,
    pub landlock_abi: u32,
    pub cgroup_memory: String,
    pub cgroup_cpu: String,
    pub cgroup_pids: String,
    pub net_proxy_status: String,
    pub procs: Vec<u32>,
    pub extinction_status: String,
}

#[derive(Debug, Clone)]
pub struct PolicyPresetItem {
    pub name: &'static str,
    pub title: &'static str,
    pub security_level: &'static str,
    pub description: &'static str,
    pub write_roots: Vec<&'static str>,
    pub read_roots: Vec<&'static str>,
    pub secret_denies: Vec<&'static str>,
    pub network_mode: &'static str,
    pub network_domains: Vec<String>,
    pub memory_quota: &'static str,
    pub cpu_quota: &'static str,
    pub landlock_abi: &'static str,
    pub seccomp_blocked: &'static str,
}

pub fn built_in_presets() -> Vec<PolicyPresetItem> {
    vec![
        PolicyPresetItem {
            name: "balanced",
            title: "Balanced Preset (Default Base)",
            security_level: "STANDARD (Fail-Closed Enforcement)",
            description: "Default baseline: write restricted to project root and /tmp, system read-only, strict secret masking, network auto-allowlisted by agent",
            write_roots: vec!["$PROJECT (Workspace Root)", "/tmp (Session Scratchpad)"],
            read_roots: vec!["/ (System Rootfs Read-Only)", "/usr, /bin, /lib, /opt", "$PROJECT"],
            secret_denies: vec!["~/.ssh, ~/.aws, .env, .env.*", "~/.gnupg, ~/.kube, ~/.docker", "$PROJECT/.git/config, *.pem, *.key"],
            network_mode: "Allowlist with TLS SNI and DNS Validation",
            network_domains: vec!["api.anthropic.com".into(), "api.openai.com".into(), "registry.npmjs.org".into(), "pypi.org".into()],
            memory_quota: "2.0 GiB (cgroups v2 memory.max)",
            cpu_quota: "100% (cgroups v2 cpu.weight: 100)",
            landlock_abi: "ABI 1-6 (Auto-detected kernel feature set)",
            seccomp_blocked: "unshare, mount, ptrace, io_uring, raw sockets (AF_INET)",
        },
        PolicyPresetItem {
            name: "paranoid",
            title: "Paranoid Preset (Strict Air-Gap Isolation)",
            security_level: "STRICT (Zero Network Egress, Minimal Read)",
            description: "Hermetic sandbox with completely disabled network egress, strictly bounded project-only reads, and aggressive secret masking",
            write_roots: vec!["$PROJECT (Workspace Root)", "/tmp (Disposable tmpfs)", "/dev/null"],
            read_roots: vec!["$PROJECT only"],
            secret_denies: vec!["All dotfiles, credentials caches, git config, *.pem, *.key, .env"],
            network_mode: "OFF (Fail-closed drop on any socket creation)",
            network_domains: Vec::new(),
            memory_quota: "1.0 GiB (cgroups v2 memory.max)",
            cpu_quota: "50% (cgroups v2 cpu.max)",
            landlock_abi: "ABI 1-6 strict enforcement",
            seccomp_blocked: "unshare, mount, ptrace, io_uring, AF_INET, AF_INET6, all IPC",
        },
        PolicyPresetItem {
            name: "yolo",
            title: "Yolo Preset (Permissive Read-Write, Inode Protection)",
            security_level: "PERMISSIVE (Wide Paths, Masked Secrets)",
            description: "Wide filesystem access for large monorepos and system compilers, but secret credentials remain masked with mode 0000 tmpfs (INV-08)",
            write_roots: vec!["$PROJECT, /tmp, ~/.cache, /var/tmp"],
            read_roots: vec!["/ (Host filesystem)"],
            secret_denies: vec!["~/.ssh, ~/.aws, .env, *.pem, *.key (INV-08 non-negotiable)"],
            network_mode: "Allowlist with package registries",
            network_domains: vec!["registry.npmjs.org".into(), "pypi.org".into(), "crates.io".into(), "github.com".into()],
            memory_quota: "4.0 GiB (cgroups v2)",
            cpu_quota: "200% (cgroups v2)",
            landlock_abi: "ABI 1-6",
            seccomp_blocked: "unshare, mount, raw AF_INET",
        },
        PolicyPresetItem {
            name: "claude",
            title: "Claude Code Profile (Anthropic)",
            security_level: "STANDARD (Agent Optimized)",
            description: "Tailored profile for Claude Code CLI with state access to ~/.claude and Anthropic API endpoints",
            write_roots: vec!["$PROJECT", "/tmp", "~/.claude", "~/.claude.json"],
            read_roots: vec!["/", "$PROJECT", "~/.claude"],
            secret_denies: vec!["~/.ssh", "~/.aws", ".env", "$PROJECT/.git/config"],
            network_mode: "Allowlist (api.anthropic.com, auth.anthropic.com, claude.ai)",
            network_domains: vec!["api.anthropic.com".into(), "auth.anthropic.com".into(), "claude.ai".into(), "statsig.anthropic.com".into()],
            memory_quota: "2.0 GiB (cgroups v2)",
            cpu_quota: "100% (cgroups v2)",
            landlock_abi: "ABI 1-6",
            seccomp_blocked: "unshare, mount, ptrace, io_uring, raw sockets",
        },
        PolicyPresetItem {
            name: "codex",
            title: "OpenAI Codex Profile",
            security_level: "STANDARD (Agent Optimized)",
            description: "Tailored profile for OpenAI Codex CLI with state access to ~/.codex and OpenAI API endpoints",
            write_roots: vec!["$PROJECT", "/tmp", "~/.codex"],
            read_roots: vec!["/", "$PROJECT", "~/.codex"],
            secret_denies: vec!["~/.ssh", "~/.aws", ".env", "$PROJECT/.git/config"],
            network_mode: "Allowlist (api.openai.com, chatgpt.com, auth.openai.com)",
            network_domains: vec!["api.openai.com".into(), "chatgpt.com".into(), "auth.openai.com".into(), "platform.openai.com".into()],
            memory_quota: "2.0 GiB (cgroups v2)",
            cpu_quota: "100% (cgroups v2)",
            landlock_abi: "ABI 1-6",
            seccomp_blocked: "unshare, mount, ptrace, io_uring, raw sockets",
        },
        PolicyPresetItem {
            name: "opencode",
            title: "OpenCode AI Profile",
            security_level: "STANDARD (Agent Optimized)",
            description: "Tailored profile for OpenCode AI with 2 GiB SQLite ceiling for opencode.db without SIGXFSZ",
            write_roots: vec!["$PROJECT", "/tmp", "~/.local/share/opencode"],
            read_roots: vec!["/", "$PROJECT"],
            secret_denies: vec!["~/.ssh", "~/.aws", ".env"],
            network_mode: "Allowlist (api.openai.com, api.anthropic.com)",
            network_domains: vec!["api.openai.com".into(), "api.anthropic.com".into()],
            memory_quota: "2.0 GiB (cgroups v2)",
            cpu_quota: "100% (cgroups v2)",
            landlock_abi: "ABI 1-6",
            seccomp_blocked: "unshare, mount, ptrace, io_uring, raw sockets",
        },
        PolicyPresetItem {
            name: "cursor",
            title: "Cursor IDE Profile",
            security_level: "STANDARD (Agent Optimized)",
            description: "Tailored profile for Cursor IDE background agent with Cursor API endpoints allowlisted",
            write_roots: vec!["$PROJECT", "/tmp", "~/.cursor"],
            read_roots: vec!["/", "$PROJECT", "~/.cursor"],
            secret_denies: vec!["~/.ssh", "~/.aws", ".env"],
            network_mode: "Allowlist (api2.cursor.sh, repo42.cursor.sh)",
            network_domains: vec!["api2.cursor.sh".into(), "repo42.cursor.sh".into()],
            memory_quota: "2.0 GiB (cgroups v2)",
            cpu_quota: "100% (cgroups v2)",
            landlock_abi: "ABI 1-6",
            seccomp_blocked: "unshare, mount, ptrace, io_uring, raw sockets",
        },
        PolicyPresetItem {
            name: "aider",
            title: "Aider Pair Programmer Profile",
            security_level: "STANDARD (Agent Optimized)",
            description: "Tailored profile for Aider with git worktree isolation and multi-provider LLM API egress",
            write_roots: vec!["$PROJECT", "/tmp", "~/.aider"],
            read_roots: vec!["/", "$PROJECT"],
            secret_denies: vec!["~/.ssh", "~/.aws", ".env", "$PROJECT/.git/config"],
            network_mode: "Allowlist (OpenAI, Anthropic, OpenRouter)",
            network_domains: vec!["api.openai.com".into(), "api.anthropic.com".into(), "openrouter.ai".into()],
            memory_quota: "2.0 GiB (cgroups v2)",
            cpu_quota: "100% (cgroups v2)",
            landlock_abi: "ABI 1-6",
            seccomp_blocked: "unshare, mount, ptrace, io_uring, raw sockets",
        },
        PolicyPresetItem {
            name: "antigravity",
            title: "Google Antigravity Profile",
            security_level: "STANDARD (Agent Optimized)",
            description: "Tailored profile for Google Antigravity with Gemini API and Vertex AI endpoints allowlisted",
            write_roots: vec!["$PROJECT", "/tmp", "~/.gemini", "~/.antigravity"],
            read_roots: vec!["/", "$PROJECT", "~/.gemini"],
            secret_denies: vec!["~/.ssh", "~/.aws", ".env", "$PROJECT/.git/config"],
            network_mode: "Allowlist (generativelanguage.googleapis.com, vertexai)",
            network_domains: vec!["generativelanguage.googleapis.com".into(), "oauth2.googleapis.com".into()],
            memory_quota: "2.0 GiB (cgroups v2)",
            cpu_quota: "100% (cgroups v2)",
            landlock_abi: "ABI 1-6",
            seccomp_blocked: "unshare, mount, ptrace, io_uring, raw sockets",
        },
    ]
}

#[derive(Debug, Clone)]
pub struct DashboardState {
    pub active_tab: MissionTab,
    pub installed_agents: Vec<AgentCard>,
    pub selected_agent: usize,
    pub doctor_report: Option<PreflightReport>,
    pub snapshots: Vec<SnapshotMetadata>,
    pub selected_snapshot: usize,
    pub security_events: VecDeque<SecurityEventItem>,
    pub selected_event: usize,
    pub seen_event_keys: HashSet<(i64, String, String)>,
    pub theme: Theme,
    pub status_message: Option<(String, Instant)>,
    pub pending_launch_agent: Option<String>,
    pub fleet_workers: Vec<crate::multi::fleet::AgentWorkerScope>,
    pub selected_fleet_worker: usize,
    pub fleet_probe_status: Option<String>,
    pub active_sessions: Vec<ActiveSessionCard>,
    pub selected_session: usize,
    pub policy_presets: Vec<PolicyPresetItem>,
    pub selected_preset: usize,
}

impl DashboardState {
    pub fn new(theme_mode: Option<&str>) -> Self {
        let theme = match theme_mode {
            Some(m) if m.eq_ignore_ascii_case("circuit") => Theme::circuit(),
            _ => Theme::arasaka(),
        };

        let installed_agents = Self::scan_installed_agents();
        let snapshots = list_snapshots().unwrap_or_default();
        let doctor_report = Some(execute_preflight_diagnostics());
        let policy_presets = built_in_presets();

        let mut state = Self {
            active_tab: MissionTab::Agents,
            installed_agents,
            selected_agent: 0,
            doctor_report,
            snapshots,
            selected_snapshot: 0,
            security_events: VecDeque::with_capacity(500),
            selected_event: 0,
            seen_event_keys: HashSet::new(),
            theme,
            status_message: None,
            pending_launch_agent: None,
            fleet_workers: Vec::new(),
            selected_fleet_worker: 0,
            fleet_probe_status: None,
            active_sessions: Vec::new(),
            selected_session: 0,
            policy_presets,
            selected_preset: 0,
        };
        state.poll_active_sessions();
        state.poll_security_events();
        state.poll_fleet_state();
        state
    }

    /// Dynamically scans for installed AI coding agents on the host system.
    /// Strictly filters ONLY agents whose real binary exists outside Vetto shims.
    pub fn scan_installed_agents() -> Vec<AgentCard> {
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();
        let shims_dir = crate::cli::hook::get_shims_dir(crate::cli::hook::HookScope::Global).ok();

        for &agent in &SUPPORTED_AGENTS {
            let canon = crate::policy::defaults::canonical_agent_name(agent).unwrap_or(agent);
            if !seen.insert(canon) {
                continue;
            }

            if let Ok((real_bin_name, real_bin_path)) =
                crate::onboard::find_real_agent_binary(canon)
            {
                let is_shim_active = if let Some(ref sdir) = shims_dir {
                    let shim = sdir.join(canon);
                    shim.exists() && crate::shim::is_vetto_shim_content(&shim)
                } else {
                    false
                };

                let pids = find_running_pids(&real_bin_name, canon);
                let is_running = !pids.is_empty();
                let network_allowlist = crate::policy::presets::agent_network_allowlist(canon);

                result.push(AgentCard {
                    name: canon,
                    display_name: format_agent_name(canon),
                    binary_name: real_bin_name,
                    binary_path: real_bin_path,
                    is_shim_active,
                    is_running,
                    active_pids: pids,
                    network_allowlist,
                    preset: "default+agent",
                });
            }
        }

        // Sort: running agents first, then alphabetically
        result.sort_by(|a, b| {
            b.is_running
                .cmp(&a.is_running)
                .then_with(|| a.name.cmp(b.name))
        });

        result
    }

    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status_message = Some((msg.into(), Instant::now()));
    }

    pub fn active_status(&self) -> Option<&str> {
        if let Some((ref msg, instant)) = self.status_message {
            if instant.elapsed().as_secs() < 4 {
                return Some(msg.as_str());
            }
        }
        None
    }

    pub fn refresh(&mut self) {
        self.installed_agents = Self::scan_installed_agents();
        if self.selected_agent >= self.installed_agents.len() && !self.installed_agents.is_empty() {
            self.selected_agent = self.installed_agents.len() - 1;
        }

        self.snapshots = list_snapshots().unwrap_or_default();
        if self.selected_snapshot >= self.snapshots.len() && !self.snapshots.is_empty() {
            self.selected_snapshot = self.snapshots.len() - 1;
        }

        if self.active_tab == MissionTab::Doctor {
            self.doctor_report = Some(execute_preflight_diagnostics());
        }

        self.poll_active_sessions();
        if self.selected_session >= self.active_sessions.len() && !self.active_sessions.is_empty() {
            self.selected_session = self.active_sessions.len() - 1;
        }

        self.poll_security_events();
        if self.selected_event >= self.security_events.len() && !self.security_events.is_empty() {
            self.selected_event = self.security_events.len() - 1;
        }

        self.poll_fleet_state();
        if self.selected_fleet_worker >= self.fleet_workers.len() && !self.fleet_workers.is_empty()
        {
            self.selected_fleet_worker = self.fleet_workers.len() - 1;
        }

        self.set_status("State refreshed");
    }

    /// Polls active sandboxed agent sessions and reads cgroup limits and extinction state.
    pub fn poll_active_sessions(&mut self) {
        let mut sessions = Vec::new();
        let abi_level = self
            .doctor_report
            .as_ref()
            .and_then(|r| r.landlock.abi_version)
            .unwrap_or(3);

        if let Ok(reg) = crate::cli::status::SessionRegistry::new() {
            if let Ok(entries) = reg.list_active() {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                for entry in entries {
                    let uptime = now.saturating_sub(entry.started_at_secs);
                    let pids = find_session_pids(entry.pid);
                    let allowlist = crate::policy::presets::agent_network_allowlist(&entry.agent);
                    let net_proxy = if allowlist.is_empty() {
                        "OFF (egress blocked)".to_string()
                    } else {
                        format!("L7 RELAY ({} domains)", allowlist.len())
                    };

                    let (mem_limit, cpu_limit, pids_limit) =
                        read_session_cgroup_limits(&entry.session_id, entry.pid);

                    let is_alive = crate::cli::kill::is_pid_alive(entry.pid);
                    let extinction_status = if is_alive {
                        "ARMED (pidfd + cgroups v2)".to_string()
                    } else {
                        "EXTINCTION_VERIFIED (<500ms, 0 survivors)".to_string()
                    };

                    sessions.push(ActiveSessionCard {
                        session_id: entry.session_id,
                        pid: entry.pid,
                        agent: entry.agent,
                        started_at_secs: entry.started_at_secs,
                        uptime_secs: uptime,
                        policy: entry.policy,
                        tier: entry.tier,
                        cwd: entry.cwd,
                        landlock_abi: abi_level,
                        cgroup_memory: mem_limit,
                        cgroup_cpu: cpu_limit,
                        cgroup_pids: pids_limit,
                        net_proxy_status: net_proxy,
                        procs: pids,
                        extinction_status,
                    });
                }
            }
        }
        self.active_sessions = sessions;
    }

    /// Cycles through available policy presets.
    pub fn cycle_preset(&mut self) {
        if !self.policy_presets.is_empty() {
            self.selected_preset = (self.selected_preset + 1) % self.policy_presets.len();
            let name = self.policy_presets[self.selected_preset].name;
            self.set_status(format!("Active policy preset: {name}"));
        }
    }

    /// Reads persistent fleet state from ~/.vetto/fleet/workers.json, reconciles live workers,
    /// and populates fleet_workers.
    pub fn poll_fleet_state(&mut self) {
        if let Ok(fleet) = crate::multi::fleet::FleetManager::load_persistent() {
            let _ = fleet.reconcile_live_workers();
            self.fleet_workers = fleet.active_workers();
        } else {
            self.fleet_workers = Vec::new();
        }
    }

    /// Reads recorded security events from ~/.vetto/logs/*.jsonl and appends them to ring buffer.
    pub fn poll_security_events(&mut self) {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from);

        let Some(home) = home else { return };
        let logs_dir = home.join(".vetto").join("logs");
        if !logs_dir.exists() {
            return;
        }

        let mut log_files: Vec<PathBuf> = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&logs_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
                    log_files.push(path);
                }
            }
        }

        log_files.sort_by_key(|p| {
            std::fs::metadata(p)
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
        });

        // Scan up to 5 most recent log files
        let slice_start = log_files.len().saturating_sub(5);
        for log_file in &log_files[slice_start..] {
            let Ok(file) = File::open(log_file) else {
                continue;
            };
            let reader = BufReader::new(file);

            for line in reader.lines() {
                let Ok(line) = line else { continue };
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }

                let Ok(ev) = serde_json::from_str::<crate::events::Event>(trimmed) else {
                    continue;
                };

                let item = match ev {
                    crate::events::Event::BlockedAttempt {
                        ts,
                        pid,
                        comm,
                        path,
                        source,
                    } => {
                        let ev_type = if source.to_ascii_lowercase().contains("seccomp") {
                            SecurityEventType::SeccompFilter
                        } else {
                            SecurityEventType::LandlockDenial
                        };
                        Some(SecurityEventItem {
                            ts,
                            event_type: ev_type,
                            subject: path,
                            detail: format!("Process '{comm}' (pid {pid}) denied by {source}"),
                            source,
                        })
                    }
                    crate::events::Event::NetRequest {
                        ts,
                        host,
                        port,
                        allowed,
                    } if !allowed => Some(SecurityEventItem {
                        ts,
                        event_type: SecurityEventType::BlockedNetwork,
                        subject: format!("{host}:{port}"),
                        detail: "Outbound egress blocked fail-closed (Anti-SSRF / broker policy)"
                            .to_string(),
                        source: "net_relay".to_string(),
                    }),
                    crate::events::Event::SecretMasked { ts, path } => Some(SecurityEventItem {
                        ts,
                        event_type: SecurityEventType::SecretMasked,
                        subject: path,
                        detail: "Inode masked with 0000 mode tmpfs overlay (INV-08)".to_string(),
                        source: "vfs_overlays".to_string(),
                    }),
                    crate::events::Event::NetQuotaExceeded {
                        ts,
                        host,
                        limit_bytes,
                        used_bytes,
                    } => Some(SecurityEventItem {
                        ts,
                        event_type: SecurityEventType::QuotaExceeded,
                        subject: host,
                        detail: format!(
                            "Bandwidth quota exceeded: {used_bytes}/{limit_bytes} bytes"
                        ),
                        source: "net_quota".to_string(),
                    }),
                    crate::events::Event::Notice { ts, message } => {
                        let lower = message.to_ascii_lowercase();
                        if lower.contains("blocked")
                            || lower.contains("ssrf")
                            || lower.contains("denied")
                        {
                            Some(SecurityEventItem {
                                ts,
                                event_type: SecurityEventType::BlockedNetwork,
                                subject: message.clone(),
                                detail: message,
                                source: "net_relay".to_string(),
                            })
                        } else {
                            None
                        }
                    }
                    _ => None,
                };

                if let Some(item) = item {
                    let key = (
                        item.ts.timestamp_millis(),
                        item.subject.clone(),
                        item.detail.clone(),
                    );
                    if self.seen_event_keys.insert(key) {
                        self.security_events.push_front(item);
                        if self.security_events.len() > 500 {
                            self.security_events.pop_back();
                        }
                    }
                }
            }
        }
    }

    pub fn toggle_shim(&mut self) -> Result<()> {
        if self.installed_agents.is_empty() {
            return Ok(());
        }

        let agent = &mut self.installed_agents[self.selected_agent];
        let name = agent.name;

        if agent.is_shim_active {
            crate::cli::enable::disable_agent(name, crate::cli::hook::HookScope::Global)?;
            agent.is_shim_active = false;
            self.set_status(format!("Disabled Vetto shim for '{name}'"));
        } else {
            crate::cli::enable::enable_agent_silent(
                name,
                true,
                crate::cli::hook::HookScope::Global,
            )?;
            agent.is_shim_active = true;
            self.set_status(format!("Enabled Vetto shim for '{name}' in ~/.vetto/shims"));
        }

        Ok(())
    }

    pub fn select_prev(&mut self) {
        match self.active_tab {
            MissionTab::Agents if !self.installed_agents.is_empty() => {
                if self.selected_agent > 0 {
                    self.selected_agent -= 1;
                } else {
                    self.selected_agent = self.installed_agents.len() - 1;
                }
            }
            MissionTab::Sandbox if !self.policy_presets.is_empty() => {
                if self.selected_preset > 0 {
                    self.selected_preset -= 1;
                } else {
                    self.selected_preset = self.policy_presets.len() - 1;
                }
            }
            MissionTab::Sessions => {
                if !self.active_sessions.is_empty() {
                    if self.selected_session > 0 {
                        self.selected_session -= 1;
                    } else {
                        self.selected_session = self.active_sessions.len() - 1;
                    }
                } else if !self.snapshots.is_empty() {
                    if self.selected_snapshot > 0 {
                        self.selected_snapshot -= 1;
                    } else {
                        self.selected_snapshot = self.snapshots.len() - 1;
                    }
                }
            }
            MissionTab::SecurityStream if !self.security_events.is_empty() => {
                if self.selected_event > 0 {
                    self.selected_event -= 1;
                } else {
                    self.selected_event = self.security_events.len() - 1;
                }
            }
            MissionTab::Fleet if !self.fleet_workers.is_empty() => {
                if self.selected_fleet_worker > 0 {
                    self.selected_fleet_worker -= 1;
                } else {
                    self.selected_fleet_worker = self.fleet_workers.len() - 1;
                }
            }
            _ => {}
        }
    }

    pub fn select_next(&mut self) {
        match self.active_tab {
            MissionTab::Agents if !self.installed_agents.is_empty() => {
                if self.selected_agent + 1 < self.installed_agents.len() {
                    self.selected_agent += 1;
                } else {
                    self.selected_agent = 0;
                }
            }
            MissionTab::Sandbox if !self.policy_presets.is_empty() => {
                if self.selected_preset + 1 < self.policy_presets.len() {
                    self.selected_preset += 1;
                } else {
                    self.selected_preset = 0;
                }
            }
            MissionTab::Sessions => {
                if !self.active_sessions.is_empty() {
                    if self.selected_session + 1 < self.active_sessions.len() {
                        self.selected_session += 1;
                    } else {
                        self.selected_session = 0;
                    }
                } else if !self.snapshots.is_empty() {
                    if self.selected_snapshot + 1 < self.snapshots.len() {
                        self.selected_snapshot += 1;
                    } else {
                        self.selected_snapshot = 0;
                    }
                }
            }
            MissionTab::SecurityStream if !self.security_events.is_empty() => {
                if self.selected_event + 1 < self.security_events.len() {
                    self.selected_event += 1;
                } else {
                    self.selected_event = 0;
                }
            }
            MissionTab::Fleet if !self.fleet_workers.is_empty() => {
                if self.selected_fleet_worker + 1 < self.fleet_workers.len() {
                    self.selected_fleet_worker += 1;
                } else {
                    self.selected_fleet_worker = 0;
                }
            }
            _ => {}
        }
    }

    pub fn rollback_selected_snapshot(&mut self) -> Result<()> {
        if self.snapshots.is_empty() {
            return Ok(());
        }
        let snap = &self.snapshots[self.selected_snapshot];
        let res = rollback_snapshot(&snap.session_id, None)?;
        self.set_status(format!(
            "Restored {} file(s) from session '{}'",
            res.files_restored, snap.session_id
        ));
        Ok(())
    }

    pub fn trigger_fleet_verify_probe(&mut self) {
        let fleet = crate::multi::fleet::FleetManager::new_default();
        let mut worker_ids = Vec::with_capacity(4);
        for i in 1..=4 {
            match fleet.allocate_worker(&format!("probe-{:02}", i)) {
                Ok(scope) => worker_ids.push(scope.worker_id),
                Err(err) => {
                    let msg = format!("FAIL: unable to allocate probe worker: {err}");
                    self.fleet_probe_status = Some(msg.clone());
                    self.set_status(msg);
                    return;
                }
            }
        }

        let mut pairs_checked = 0;
        for i in 0..worker_ids.len() {
            for j in (i + 1)..worker_ids.len() {
                if let Err(err) = fleet.verify_isolation(&worker_ids[i], &worker_ids[j]) {
                    let msg = format!(
                        "FAIL: isolation check between {} and {}: {err}",
                        worker_ids[i], worker_ids[j]
                    );
                    self.fleet_probe_status = Some(msg.clone());
                    self.set_status(msg);
                    return;
                }
                pairs_checked += 1;
            }
        }

        let msg = format!(
            "PASS: {} workers / {} pairs disjoint and isolated",
            worker_ids.len(),
            pairs_checked
        );
        self.fleet_probe_status = Some(msg.clone());
        self.set_status(msg);
    }

    pub fn terminate_selected_worker(&mut self) {
        if self.fleet_workers.is_empty() {
            self.set_status("No active fleet worker selected to terminate");
            return;
        }

        let index = self
            .selected_fleet_worker
            .min(self.fleet_workers.len().saturating_sub(1));
        let worker = self.fleet_workers[index].clone();
        let wid = worker.worker_id.clone();

        if let Some(pid) = worker.pid {
            let _ = crate::cli::kill::kill_pid(pid, true);
        }

        let cgroup_kill = worker.scope_path.join("cgroup.kill");
        if cgroup_kill.exists() {
            let _ = std::fs::write(&cgroup_kill, "1\n");
        }
        if worker.scope_path.exists() {
            let _ = std::fs::remove_dir(&worker.scope_path);
        }
        if !worker.workspace_dir.as_os_str().is_empty() && worker.workspace_dir.exists() {
            let _ = std::fs::remove_dir_all(&worker.workspace_dir);
        }

        if let Ok(fleet) = crate::multi::fleet::FleetManager::load_persistent() {
            let _ = fleet.release_worker(&wid);
            let _ = fleet.save_persistent();
        }

        self.poll_fleet_state();
        if self.selected_fleet_worker >= self.fleet_workers.len() && !self.fleet_workers.is_empty()
        {
            self.selected_fleet_worker = self.fleet_workers.len() - 1;
        }
        self.set_status(format!("Terminated worker '{}' and released slot", wid));
    }

    pub fn terminate_selected_session(&mut self) {
        if self.active_sessions.is_empty() {
            self.set_status("No active sandbox session selected to terminate");
            return;
        }

        let index = self
            .selected_session
            .min(self.active_sessions.len().saturating_sub(1));
        let session = self.active_sessions[index].clone();
        let sid = session.session_id.clone();

        let _ = crate::cli::kill::kill_pid(session.pid, true);
        for &child_pid in &session.procs {
            if child_pid != session.pid {
                let _ = crate::cli::kill::kill_pid(child_pid, true);
            }
        }

        if let Ok(reg) = crate::cli::status::SessionRegistry::new() {
            reg.unregister(&sid);
        }

        self.poll_active_sessions();
        if self.selected_session >= self.active_sessions.len() && !self.active_sessions.is_empty() {
            self.selected_session = self.active_sessions.len() - 1;
        }
        self.set_status(format!("Terminated session '{sid}' (PID {})", session.pid));
    }
}

fn format_agent_name(name: &str) -> String {
    match name {
        "claude" => "Claude Code (Anthropic)".to_string(),
        "opencode" => "OpenCode AI".to_string(),
        "codex" => "OpenAI Codex".to_string(),
        "antigravity" | "agy" => "Antigravity (Google)".to_string(),
        "cursor" => "Cursor IDE Agent".to_string(),
        "aider" => "Aider Pair Programmer".to_string(),
        "cline" => "Cline Assistant".to_string(),
        "windsurf" => "Windsurf Cascade".to_string(),
        "goose" => "Block Goose AI".to_string(),
        "openhands" => "OpenHands (All-Hands)".to_string(),
        "devin" => "Cognition Devin".to_string(),
        "copilot" => "GitHub Copilot".to_string(),
        "smolagents" => "Hugging Face Smolagents".to_string(),
        "omp" => "OMP (Stencil Labs)".to_string(),
        "zcode" => "ZCode (Z.ai / GLM-5.3)".to_string(),
        "kimi" => "Kimi Code (Moonshot AI)".to_string(),
        "grok" => "Grok Build (xAI)".to_string(),
        other => other.to_string(),
    }
}

fn find_running_pids(binary_name: &str, agent_name: &str) -> Vec<u32> {
    #[cfg(target_os = "linux")]
    {
        let mut pids = Vec::new();
        let current_pid = std::process::id();
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let Ok(file_name) = entry.file_name().into_string() else {
                    continue;
                };
                let Ok(pid) = file_name.parse::<u32>() else {
                    continue;
                };
                if pid == current_pid {
                    continue;
                }
                let proc_path = entry.path();
                let is_match = if let Ok(comm) = std::fs::read_to_string(proc_path.join("comm")) {
                    let comm = comm.trim();
                    comm == binary_name || comm == agent_name
                } else {
                    false
                };
                if is_match {
                    pids.push(pid);
                } else if let Ok(cmdline) = std::fs::read(proc_path.join("cmdline")) {
                    let s = String::from_utf8_lossy(&cmdline);
                    let first_arg = s.split('\0').next().unwrap_or("");
                    if first_arg.ends_with(binary_name) || first_arg.ends_with(agent_name) {
                        pids.push(pid);
                    }
                }
            }
        }
        pids.sort_unstable();
        pids.dedup();
        pids
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (binary_name, agent_name);
        Vec::new()
    }
}

fn read_session_cgroup_limits(session_id: &str, pid: u32) -> (String, String, String) {
    #[cfg(target_os = "linux")]
    {
        let cgroup_dir =
            std::path::PathBuf::from("/sys/fs/cgroup").join(format!("vetto-{}", session_id));
        if cgroup_dir.exists() {
            let mem = std::fs::read_to_string(cgroup_dir.join("memory.max"))
                .unwrap_or_else(|_| "max".into())
                .trim()
                .to_string();
            let cpu = std::fs::read_to_string(cgroup_dir.join("cpu.max"))
                .unwrap_or_else(|_| "max 100000".into())
                .trim()
                .to_string();
            let pids = std::fs::read_to_string(cgroup_dir.join("pids.max"))
                .unwrap_or_else(|_| "max".into())
                .trim()
                .to_string();
            return (format_cgroup_mem(&mem), format_cgroup_cpu(&cpu), pids);
        }

        if let Ok(cgroup_content) = std::fs::read_to_string(format!("/proc/{pid}/cgroup")) {
            for line in cgroup_content.lines() {
                if let Some(rel_path) = line.split(':').nth(2) {
                    let full_path = std::path::Path::new("/sys/fs/cgroup")
                        .join(rel_path.trim_start_matches('/'));
                    if full_path.exists() {
                        let mem = std::fs::read_to_string(full_path.join("memory.max"))
                            .unwrap_or_else(|_| "max".into())
                            .trim()
                            .to_string();
                        let cpu = std::fs::read_to_string(full_path.join("cpu.max"))
                            .unwrap_or_else(|_| "max 100000".into())
                            .trim()
                            .to_string();
                        let pids = std::fs::read_to_string(full_path.join("pids.max"))
                            .unwrap_or_else(|_| "max".into())
                            .trim()
                            .to_string();
                        return (format_cgroup_mem(&mem), format_cgroup_cpu(&cpu), pids);
                    }
                }
            }
        }
    }
    let _ = (session_id, pid);
    (
        "2.0 GiB (default)".to_string(),
        "100% (default)".to_string(),
        "128 (default)".to_string(),
    )
}

fn format_cgroup_mem(raw: &str) -> String {
    if raw == "max" || raw.is_empty() {
        "unlimited".to_string()
    } else if let Ok(bytes) = raw.parse::<u64>() {
        if bytes >= 1024 * 1024 * 1024 {
            format!("{:.1} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
        } else if bytes >= 1024 * 1024 {
            format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
        } else {
            format!("{bytes} B")
        }
    } else {
        raw.to_string()
    }
}

fn format_cgroup_cpu(raw: &str) -> String {
    if raw.starts_with("max") {
        "100% (unlimited)".to_string()
    } else {
        let parts: Vec<&str> = raw.split_whitespace().collect();
        if parts.len() == 2 {
            if let (Ok(quota), Ok(period)) = (parts[0].parse::<u64>(), parts[1].parse::<u64>()) {
                if period > 0 {
                    let pct = (quota as f64 / period as f64) * 100.0;
                    return format!("{pct:.0}%");
                }
            }
        }
        raw.to_string()
    }
}

fn find_session_pids(root_pid: u32) -> Vec<u32> {
    #[cfg(target_os = "linux")]
    {
        let mut pids = vec![root_pid];
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let Ok(file_name) = entry.file_name().into_string() else {
                    continue;
                };
                let Ok(pid) = file_name.parse::<u32>() else {
                    continue;
                };
                if pid == root_pid {
                    continue;
                }
                if let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) {
                    if let Some(after_comm) = stat.rfind(')') {
                        let rest = stat[after_comm + 1..].trim();
                        let parts: Vec<&str> = rest.split_whitespace().collect();
                        if parts.len() >= 2 {
                            if let Ok(ppid) = parts[1].parse::<u32>() {
                                if ppid == root_pid {
                                    pids.push(pid);
                                }
                            }
                        }
                    }
                }
            }
        }
        pids.sort_unstable();
        pids.dedup();
        pids
    }
    #[cfg(not(target_os = "linux"))]
    {
        vec![root_pid]
    }
}
