//! Mission Control Dashboard State Management.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Result;
use chrono::{DateTime, Utc};

use crate::doctor::preflight::{execute_preflight_diagnostics, PreflightReport};
use crate::onboard::SUPPORTED_AGENTS;
use crate::rescue::snapshot::{list_snapshots, rollback_snapshot, SnapshotMetadata};

use super::theme::Theme;

const MAX_INITIAL_LOG_TAIL_BYTES: u64 = 512 * 1024;

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
    pub cgroup_scope: String,
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

fn agent_preset_item(
    name: &'static str,
    title: &'static str,
    description: &'static str,
    write_roots: Vec<&'static str>,
    read_roots: Vec<&'static str>,
) -> PolicyPresetItem {
    let network_domains = crate::policy::presets::agent_network_allowlist(name);
    let network_mode = if network_domains.is_empty() {
        "OFF (Fail-closed drop on any socket creation)"
    } else {
        "Allowlist with TLS SNI and L7 Anti-SSRF Validation"
    };
    PolicyPresetItem {
        name,
        title,
        security_level: "STANDARD (Agent Optimized)",
        description,
        write_roots,
        read_roots,
        secret_denies: vec![
            "~/.ssh, ~/.aws, .env, .env.*",
            "~/.gnupg, ~/.kube, ~/.docker",
            "$PROJECT/.git/config, *.pem, *.key",
        ],
        network_mode,
        network_domains,
        memory_quota: "2.0 GiB (cgroups v2)",
        cpu_quota: "100% (cgroups v2)",
        landlock_abi: "ABI 1-6",
        seccomp_blocked: "unshare, mount, ptrace, io_uring, raw sockets",
    }
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
        agent_preset_item(
            "claude",
            "Claude Code Profile (Anthropic)",
            "Tailored profile for Claude Code CLI with state access to ~/.claude and Anthropic API endpoints",
            vec!["$PROJECT", "/tmp", "~/.claude", "~/.claude.json"],
            vec!["/", "$PROJECT", "~/.claude"],
        ),
        agent_preset_item(
            "codex",
            "OpenAI Codex Profile",
            "Tailored profile for OpenAI Codex CLI with state access to ~/.codex and OpenAI API endpoints",
            vec!["$PROJECT", "/tmp", "~/.codex"],
            vec!["/", "$PROJECT", "~/.codex"],
        ),
        agent_preset_item(
            "opencode",
            "OpenCode AI Profile",
            "Tailored profile for OpenCode AI with 2 GiB SQLite ceiling for opencode.db without SIGXFSZ",
            vec!["$PROJECT", "/tmp", "~/.local/share/opencode"],
            vec!["/", "$PROJECT"],
        ),
        agent_preset_item(
            "cursor",
            "Cursor IDE Profile",
            "Tailored profile for Cursor IDE background agent with Cursor API endpoints allowlisted",
            vec!["$PROJECT", "/tmp", "~/.cursor"],
            vec!["/", "$PROJECT", "~/.cursor"],
        ),
        agent_preset_item(
            "aider",
            "Aider Pair Programmer Profile",
            "Tailored profile for Aider with git worktree isolation and multi-provider LLM API egress",
            vec!["$PROJECT", "/tmp", "~/.aider"],
            vec!["/", "$PROJECT"],
        ),
        agent_preset_item(
            "antigravity",
            "Google Antigravity Profile",
            "Tailored profile for Google Antigravity with Gemini API and Vertex AI endpoints allowlisted",
            vec!["$PROJECT", "/tmp", "~/.gemini", "~/.antigravity"],
            vec!["/", "$PROJECT", "~/.gemini"],
        ),
        agent_preset_item(
            "omnigent",
            "Omnigent AI Profile",
            "Tailored profile for Omnigent autonomous runtime with ~/.omnigent state and L7 anti-SSRF relay",
            vec!["$PROJECT", "/tmp", "~/.omnigent", "~/.config/omnigent"],
            vec!["/", "$PROJECT", "~/.omnigent"],
        ),
        agent_preset_item(
            "hermes",
            "Hermes Agent Profile (Nous Research)",
            "Tailored profile for Hermes Agent runtime with Nous Research and Together AI endpoints",
            vec!["$PROJECT", "/tmp", "~/.hermes", "~/.cache"],
            vec!["/", "$PROJECT", "~/.hermes"],
        ),
        agent_preset_item(
            "kilo",
            "Kilo Code Profile",
            "Tailored profile for Kilo Code CLI agent with ~/.kilo state and multi-provider API allowlist",
            vec!["$PROJECT", "/tmp", "~/.kilo", "~/.cache"],
            vec!["/", "$PROJECT", "~/.kilo"],
        ),
        agent_preset_item(
            "pi",
            "Pi Coding Runtime Profile",
            "Tailored profile for Pi coding agent with Groq, OpenAI, and Anthropic API allowlist",
            vec!["$PROJECT", "/tmp", "~/.pi", "~/.cache"],
            vec!["/", "$PROJECT", "~/.pi"],
        ),
        agent_preset_item(
            "command_code",
            "Command Code Profile (Cohere)",
            "Tailored profile for Command Code CLI with Cohere API and package registry allowlist",
            vec!["$PROJECT", "/tmp", "~/.command_code", "~/.cache"],
            vec!["/", "$PROJECT", "~/.command_code"],
        ),
        agent_preset_item(
            "freebuff",
            "Freebuff Agent Profile",
            "Tailored profile for Freebuff coding agent with DeepSeek and OpenRouter API allowlist",
            vec!["$PROJECT", "/tmp", "~/.freebuff", "~/.cache"],
            vec!["/", "$PROJECT", "~/.freebuff"],
        ),
        agent_preset_item(
            "deepseek_harness",
            "DeepSeek Harness Profile",
            "Tailored profile for DeepSeek Harness CLI with DeepSeek API and package registry egress",
            vec!["$PROJECT", "/tmp", "~/.deepseek", "~/.cache"],
            vec!["/", "$PROJECT", "~/.deepseek"],
        ),
        agent_preset_item(
            "omp",
            "OMP Profile (Stencil Labs)",
            "Tailored profile for OMP Rust coding agent with multi-model provider allowlist",
            vec!["$PROJECT", "/tmp", "~/.omp", "~/.cache"],
            vec!["/", "$PROJECT", "~/.omp"],
        ),
        agent_preset_item(
            "zcode",
            "ZCode Profile (Z.ai / GLM)",
            "Tailored profile for ZCode CLI with Z.ai and GLM endpoint allowlist",
            vec!["$PROJECT", "/tmp", "~/.zcode", "~/.cache"],
            vec!["/", "$PROJECT", "~/.zcode"],
        ),
        agent_preset_item(
            "kimi",
            "Kimi Code Profile (Moonshot AI)",
            "Tailored profile for Kimi Code CLI with Moonshot AI API allowlist",
            vec!["$PROJECT", "/tmp", "~/.kimi", "~/.cache"],
            vec!["/", "$PROJECT", "~/.kimi"],
        ),
        agent_preset_item(
            "grok",
            "Grok Build Profile (xAI)",
            "Tailored profile for xAI Grok Build CLI with x.ai API allowlist",
            vec!["$PROJECT", "/tmp", "~/.grok", "~/.cache"],
            vec!["/", "$PROJECT", "~/.grok"],
        ),
        agent_preset_item(
            "cline",
            "Cline Assistant Profile",
            "Tailored profile for Cline CLI with Anthropic, OpenAI, and OpenRouter egress",
            vec!["$PROJECT", "/tmp", "~/.cline", "~/.cache"],
            vec!["/", "$PROJECT", "~/.cline"],
        ),
        agent_preset_item(
            "copilot",
            "GitHub Copilot CLI Profile",
            "Tailored profile for GitHub Copilot CLI with GitHub API and Copilot proxy allowlist",
            vec!["$PROJECT", "/tmp", "~/.config/github-copilot"],
            vec!["/", "$PROJECT", "~/.config/github-copilot"],
        ),
        agent_preset_item(
            "windsurf",
            "Windsurf Cascade Profile",
            "Tailored profile for Windsurf CLI with Codeium API allowlist",
            vec!["$PROJECT", "/tmp", "~/.codeium", "~/.windsurf"],
            vec!["/", "$PROJECT", "~/.codeium"],
        ),
        agent_preset_item(
            "goose",
            "Block Goose AI Profile",
            "Tailored profile for Block Goose CLI agent with multi-provider LLM egress",
            vec!["$PROJECT", "/tmp", "~/.config/goose", "~/.local/share/goose"],
            vec!["/", "$PROJECT", "~/.config/goose"],
        ),
        agent_preset_item(
            "openhands",
            "OpenHands Profile (All-Hands)",
            "Tailored profile for OpenHands agent runtime with bounded workspace write access",
            vec!["$PROJECT", "/tmp", "~/.openhands"],
            vec!["/", "$PROJECT", "~/.openhands"],
        ),
        agent_preset_item(
            "devin",
            "Cognition Devin CLI Profile",
            "Tailored profile for Devin CLI runtime with Cognition API allowlist",
            vec!["$PROJECT", "/tmp", "~/.devin"],
            vec!["/", "$PROJECT", "~/.devin"],
        ),
        agent_preset_item(
            "smolagents",
            "Hugging Face Smolagents Profile",
            "Tailored profile for Smolagents with Hugging Face Hub and inference API allowlist",
            vec!["$PROJECT", "/tmp", "~/.cache/huggingface"],
            vec!["/", "$PROJECT", "~/.cache/huggingface"],
        ),
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
    pub log_file_offsets: HashMap<PathBuf, u64>,
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
            log_file_offsets: HashMap::new(),
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
                    let (mem_limit, cpu_limit, pids_limit, cgroup_scope) =
                        read_session_cgroup_limits(&entry.session_id, entry.pid);
                    let pids = find_session_pids(entry.pid, &cgroup_scope);
                    let allowlist = crate::policy::presets::agent_network_allowlist(&entry.agent);
                    let net_proxy = if allowlist.is_empty() {
                        "OFF (egress blocked)".to_string()
                    } else {
                        format!("L7 RELAY ({} domains)", allowlist.len())
                    };

                    let is_alive = crate::cli::status::is_pid_alive(entry.pid);
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
                        cgroup_scope,
                        net_proxy_status: net_proxy,
                        procs: pids,
                        extinction_status,
                    });
                }
            }
        }
        self.active_sessions = sessions;
        if self.active_sessions.is_empty() {
            self.selected_session = 0;
        } else if self.selected_session >= self.active_sessions.len() {
            self.selected_session = self.active_sessions.len() - 1;
        }
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
        if self.fleet_workers.is_empty() {
            self.selected_fleet_worker = 0;
        } else if self.selected_fleet_worker >= self.fleet_workers.len() {
            self.selected_fleet_worker = self.fleet_workers.len() - 1;
        }
    }

    /// Reads recorded security events from ~/.vetto/logs/*.jsonl and appends them to ring buffer.
    pub fn poll_security_events(&mut self) {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from);

        let Some(home) = home else { return };
        let logs_dir = home.join(".vetto").join("logs");
        self.poll_security_events_from_dir(&logs_dir);
    }

    /// Incrementally tails the most recent `.jsonl` security log files in `logs_dir`.
    pub fn poll_security_events_from_dir(&mut self, logs_dir: &Path) {
        if !logs_dir.exists() {
            return;
        }

        let mut log_files: Vec<PathBuf> = Vec::new();
        if let Ok(entries) = std::fs::read_dir(logs_dir) {
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

        // Scan up to 5 most recent log files using incremental byte offsets
        let slice_start = log_files.len().saturating_sub(5);
        let active_slice = &log_files[slice_start..];
        self.log_file_offsets
            .retain(|path, _| active_slice.contains(path));

        for log_file in active_slice {
            let Ok(mut file) = File::open(log_file) else {
                continue;
            };
            let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
            let prev_offset = self.log_file_offsets.get(log_file).copied();

            let mut skip_partial_first_line = false;
            let start_offset = match prev_offset {
                Some(off) if off <= file_len => off,
                Some(_) => {
                    // File was truncated or rotated
                    if file_len > MAX_INITIAL_LOG_TAIL_BYTES {
                        skip_partial_first_line = true;
                        file_len - MAX_INITIAL_LOG_TAIL_BYTES
                    } else {
                        0
                    }
                }
                None => {
                    if file_len > MAX_INITIAL_LOG_TAIL_BYTES {
                        skip_partial_first_line = true;
                        file_len - MAX_INITIAL_LOG_TAIL_BYTES
                    } else {
                        0
                    }
                }
            };

            if start_offset == file_len && prev_offset.is_some() {
                continue;
            }

            if file.seek(SeekFrom::Start(start_offset)).is_err() {
                continue;
            }

            let mut reader = BufReader::new(file);
            let mut cursor = start_offset;

            if skip_partial_first_line {
                let mut discarded = String::new();
                if let Ok(bytes) = reader.read_line(&mut discarded) {
                    cursor += bytes as u64;
                }
            }

            let mut line = String::new();
            loop {
                line.clear();
                let Ok(bytes_read) = reader.read_line(&mut line) else {
                    break;
                };
                if bytes_read == 0 {
                    break;
                }
                // Only advance the offset past complete newline-terminated lines
                // (or EOF when initial load parses a small static file)
                if !line.ends_with('\n') && prev_offset.is_some() {
                    break;
                }
                cursor += bytes_read as u64;

                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }

                let Ok(ev) = serde_json::from_str::<crate::events::Event>(trimmed) else {
                    continue;
                };

                let item = classify_security_event(ev);

                if let Some(item) = item {
                    let key = (
                        item.ts.timestamp_millis(),
                        item.subject.clone(),
                        item.detail.clone(),
                    );
                    if self.seen_event_keys.insert(key) {
                        self.security_events.push_front(item);
                        if self.security_events.len() > 500 {
                            if let Some(evicted) = self.security_events.pop_back() {
                                let evicted_key = (
                                    evicted.ts.timestamp_millis(),
                                    evicted.subject,
                                    evicted.detail,
                                );
                                self.seen_event_keys.remove(&evicted_key);
                            }
                        }
                    }
                }
            }

            self.log_file_offsets.insert(log_file.clone(), cursor);
        }

        if self.security_events.is_empty() {
            self.selected_event = 0;
        } else if self.selected_event >= self.security_events.len() {
            self.selected_event = self.security_events.len() - 1;
        }
    }

    pub fn toggle_shim(&mut self) -> Result<()> {
        if self.installed_agents.is_empty() {
            return Ok(());
        }

        let idx = self
            .selected_agent
            .min(self.installed_agents.len().saturating_sub(1));
        let agent = &mut self.installed_agents[idx];
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

    pub fn select_prev_snapshot(&mut self) {
        if !self.snapshots.is_empty() {
            if self.selected_snapshot > 0 {
                self.selected_snapshot -= 1;
            } else {
                self.selected_snapshot = self.snapshots.len() - 1;
            }
        }
    }

    pub fn select_next_snapshot(&mut self) {
        if !self.snapshots.is_empty() {
            if self.selected_snapshot + 1 < self.snapshots.len() {
                self.selected_snapshot += 1;
            } else {
                self.selected_snapshot = 0;
            }
        }
    }

    pub fn rollback_selected_snapshot(&mut self) -> Result<()> {
        if self.snapshots.is_empty() {
            return Ok(());
        }
        let idx = self
            .selected_snapshot
            .min(self.snapshots.len().saturating_sub(1));
        let snap = &self.snapshots[idx];
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

        // 1. Trigger atomic cgroups v2 process tree extinction (cgroup.kill) if dedicated vetto scope exists
        let cgroup_path = PathBuf::from(&session.cgroup_scope);
        if session.cgroup_scope.contains("vetto") {
            let cgroup_kill = cgroup_path.join("cgroup.kill");
            if cgroup_kill.exists() {
                let _ = std::fs::write(&cgroup_kill, "1\n");
            }
        }
        let default_cgroup_kill = PathBuf::from("/sys/fs/cgroup")
            .join(format!("vetto-{sid}"))
            .join("cgroup.kill");
        if default_cgroup_kill.exists() {
            let _ = std::fs::write(&default_cgroup_kill, "1\n");
        }

        // 2. Signal all descendant processes in reverse (leaves-first) order, then root PID
        for &child_pid in session.procs.iter().rev() {
            if child_pid != session.pid {
                let _ = crate::cli::kill::kill_pid(child_pid, true);
            }
        }
        let _ = crate::cli::kill::kill_pid(session.pid, true);

        if let Ok(reg) = crate::cli::status::SessionRegistry::new() {
            reg.unregister(&sid);
        }

        self.poll_active_sessions();
        self.set_status(format!(
            "Terminated session '{sid}' (PID {} + {} descendants)",
            session.pid,
            session.procs.len().saturating_sub(1)
        ));
    }
}

pub(crate) fn classify_security_event(ev: crate::events::Event) -> Option<SecurityEventItem> {
    match ev {
        crate::events::Event::BlockedAttempt {
            ts,
            pid,
            comm,
            path,
            source,
        } => {
            let lower_src = source.to_ascii_lowercase();
            // Distinguish seccomp-BPF syscall filter violations from filesystem path denials
            // (note: "observe-seccomp" records filesystem paths opened via openat/statx)
            let is_fs_path = path.starts_with('/')
                || path.starts_with("~/")
                || path.starts_with("./")
                || path.starts_with("../");
            let is_syscall_event = path.starts_with("syscall:")
                || lower_src == "seccomp"
                || lower_src == "seccomp-bpf"
                || (lower_src.contains("seccomp") && !is_fs_path);
            let ev_type = if is_syscall_event {
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
            detail: "Outbound egress blocked fail-closed (Anti-SSRF / broker policy)".to_string(),
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
            detail: format!("Bandwidth quota exceeded: {used_bytes}/{limit_bytes} bytes"),
            source: "net_quota".to_string(),
        }),
        crate::events::Event::Notice { ts, message } => {
            let lower = message.to_ascii_lowercase();
            if lower.contains("blocked") || lower.contains("ssrf") || lower.contains("denied") {
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
        "hermes" => "Hermes Agent (Nous Research)".to_string(),
        "kilo" => "Kilo Code CLI".to_string(),
        "pi" => "Pi Coding Agent".to_string(),
        "command_code" => "Command Code CLI".to_string(),
        "freebuff" => "Freebuff Agent".to_string(),
        "deepseek_harness" => "DeepSeek Harness".to_string(),
        "omnigent" => "Omnigent Agent".to_string(),
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

fn read_session_cgroup_limits(session_id: &str, pid: u32) -> (String, String, String, String) {
    let default_scope = format!("/sys/fs/cgroup/vetto-{session_id}");
    #[cfg(target_os = "linux")]
    {
        let candidates = [
            std::path::PathBuf::from("/sys/fs/cgroup").join(format!("vetto-{session_id}")),
            std::path::PathBuf::from("/sys/fs/cgroup/vetto").join(session_id),
        ];
        for cgroup_dir in &candidates {
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
                return (
                    format_cgroup_mem(&mem),
                    format_cgroup_cpu(&cpu),
                    pids,
                    cgroup_dir.display().to_string(),
                );
            }
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
                        return (
                            format_cgroup_mem(&mem),
                            format_cgroup_cpu(&cpu),
                            pids,
                            full_path.display().to_string(),
                        );
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
        default_scope,
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

/// Pure BFS traversal over `(pid, ppid)` edges returning `root_pid` followed by all descendants.
pub(crate) fn collect_descendant_pids(root_pid: u32, ppid_pairs: &[(u32, u32)]) -> Vec<u32> {
    let mut children_by_ppid: HashMap<u32, Vec<u32>> = HashMap::new();
    for &(pid, ppid) in ppid_pairs {
        if pid != root_pid {
            children_by_ppid.entry(ppid).or_default().push(pid);
        }
    }
    for list in children_by_ppid.values_mut() {
        list.sort_unstable();
        list.dedup();
    }

    let mut result = vec![root_pid];
    let mut visited: HashSet<u32> = HashSet::new();
    visited.insert(root_pid);
    let mut queue: VecDeque<u32> = VecDeque::new();
    queue.push_back(root_pid);

    while let Some(current) = queue.pop_front() {
        if let Some(children) = children_by_ppid.get(&current) {
            for &child in children {
                if visited.insert(child) {
                    result.push(child);
                    queue.push_back(child);
                }
            }
        }
    }

    result
}

fn find_session_pids(root_pid: u32, cgroup_scope: &str) -> Vec<u32> {
    #[cfg(target_os = "linux")]
    {
        let mut ppid_pairs = Vec::new();
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let Ok(file_name) = entry.file_name().into_string() else {
                    continue;
                };
                let Ok(pid) = file_name.parse::<u32>() else {
                    continue;
                };
                if let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) {
                    if let Some(after_comm) = stat.rfind(')') {
                        let rest = stat[after_comm + 1..].trim();
                        let parts: Vec<&str> = rest.split_whitespace().collect();
                        if parts.len() >= 2 {
                            if let Ok(ppid) = parts[1].parse::<u32>() {
                                ppid_pairs.push((pid, ppid));
                            }
                        }
                    }
                }
            }
        }

        let mut pids = collect_descendant_pids(root_pid, &ppid_pairs);

        // Also include PIDs registered in a dedicated vetto cgroup scope if present
        if cgroup_scope.contains("vetto") {
            let cgroup_procs = Path::new(cgroup_scope).join("cgroup.procs");
            if let Ok(content) = std::fs::read_to_string(cgroup_procs) {
                for line in content.lines() {
                    if let Ok(pid) = line.trim().parse::<u32>() {
                        if !pids.contains(&pid) {
                            pids.push(pid);
                        }
                    }
                }
            }
        }

        pids
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cgroup_scope;
        vec![root_pid]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collect_descendant_pids_multi_level_bfs() {
        // 4-level tree: 100 -> (200, 201), 200 -> 300 -> 400, plus unrelated 999 -> 1000
        let pairs = vec![
            (100, 1),
            (200, 100),
            (201, 100),
            (300, 200),
            (400, 300),
            (999, 1),
            (1000, 999),
            // Synthetic cycle edge to ensure visited guard prevents infinite loop
            (200, 400),
        ];
        let pids = collect_descendant_pids(100, &pairs);
        assert_eq!(pids, vec![100, 200, 201, 300, 400]);
    }

    #[test]
    fn test_classify_security_event_observe_seccomp_vs_syscall_filter() {
        let fs_ev = crate::events::Event::BlockedAttempt {
            ts: Utc::now(),
            pid: 1234,
            comm: "claude".to_string(),
            path: "/etc/shadow".to_string(),
            source: "observe-seccomp".to_string(),
        };
        let classified_fs = classify_security_event(fs_ev).expect("should classify fs event");
        assert_eq!(classified_fs.event_type, SecurityEventType::LandlockDenial);
        assert_eq!(classified_fs.event_type.badge(), "LANDLOCK");

        let syscall_ev = crate::events::Event::BlockedAttempt {
            ts: Utc::now(),
            pid: 1234,
            comm: "claude".to_string(),
            path: "syscall:ptrace".to_string(),
            source: "seccomp-bpf".to_string(),
        };
        let classified_sys =
            classify_security_event(syscall_ev).expect("should classify syscall event");
        assert_eq!(classified_sys.event_type, SecurityEventType::SeccompFilter);
        assert_eq!(classified_sys.event_type.badge(), "SECCOMP");
    }

    #[test]
    fn test_poll_security_events_incremental_tailing_and_large_file_cap() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let log_path = tmp.path().join("session-test.jsonl");

        // Write > 512 KiB of padding comments followed by one valid event
        let mut initial = String::with_capacity(600 * 1024);
        let comment_line = format!("# {}\n", "x".repeat(100));
        while initial.len() < 550 * 1024 {
            initial.push_str(&comment_line);
        }
        initial.push_str(
            r#"{"ts":"2026-09-28T12:00:00Z","type":"secret_masked","path":"/home/user/.ssh/id_ed25519"}"#,
        );
        initial.push('\n');
        std::fs::write(&log_path, &initial).expect("write initial log");

        let mut state = DashboardState {
            active_tab: MissionTab::SecurityStream,
            installed_agents: Vec::new(),
            selected_agent: 0,
            doctor_report: None,
            snapshots: Vec::new(),
            selected_snapshot: 0,
            security_events: VecDeque::new(),
            selected_event: 0,
            seen_event_keys: HashSet::new(),
            log_file_offsets: HashMap::new(),
            theme: Theme::arasaka(),
            status_message: None,
            pending_launch_agent: None,
            fleet_workers: Vec::new(),
            selected_fleet_worker: 0,
            fleet_probe_status: None,
            active_sessions: Vec::new(),
            selected_session: 0,
            policy_presets: built_in_presets(),
            selected_preset: 0,
        };

        state.poll_security_events_from_dir(tmp.path());
        assert_eq!(state.security_events.len(), 1);
        assert_eq!(
            state.security_events[0].event_type,
            SecurityEventType::SecretMasked
        );
        let first_offset = *state.log_file_offsets.get(&log_path).expect("offset saved");
        assert_eq!(first_offset, initial.len() as u64);

        // Append a second event and verify incremental read picks up only the new bytes
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .expect("open append");
        writeln!(
            f,
            r#"{{"ts":"2026-09-28T12:00:05Z","type":"net_request","host":"169.254.169.254","port":80,"allowed":false}}"#
        )
        .expect("append line");
        drop(f);

        state.poll_security_events_from_dir(tmp.path());
        assert_eq!(state.security_events.len(), 2);
        assert_eq!(
            state.security_events[0].event_type,
            SecurityEventType::BlockedNetwork
        );
        let second_offset = *state
            .log_file_offsets
            .get(&log_path)
            .expect("updated offset");
        assert!(second_offset > first_offset);
    }

    #[test]
    fn test_built_in_presets_covers_all_supported_agents() {
        let presets = built_in_presets();
        // 3 base presets + 24 canonical agent presets = 27
        assert_eq!(presets.len(), 27);
        for &agent_name in &SUPPORTED_AGENTS {
            let canon =
                crate::policy::defaults::canonical_agent_name(agent_name).unwrap_or(agent_name);
            assert!(
                presets.iter().any(|p| p.name == canon),
                "missing preset for supported agent {canon}"
            );
        }
    }
}
