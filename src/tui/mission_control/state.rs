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
    AccessDenial,   // Landlock/Seccomp
    BlockedNetwork, // NetRelay / Anti-SSRF drop
    SecretMasked,   // Inode tmpfs overlay
    QuotaExceeded,  // Network quota
}

impl SecurityEventType {
    pub fn badge(&self) -> &'static str {
        match self {
            Self::AccessDenial => "DENIAL",
            Self::BlockedNetwork => "NET_DROP",
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
}

impl MissionTab {
    pub fn index(&self) -> usize {
        match self {
            Self::Agents => 0,
            Self::Sandbox => 1,
            Self::Doctor => 2,
            Self::Sessions => 3,
            Self::SecurityStream => 4,
        }
    }

    pub fn from_index(idx: usize) -> Self {
        match idx % 5 {
            0 => Self::Agents,
            1 => Self::Sandbox,
            2 => Self::Doctor,
            3 => Self::Sessions,
            4 => Self::SecurityStream,
            _ => unreachable!(),
        }
    }

    pub fn next(&self) -> Self {
        Self::from_index(self.index() + 1)
    }

    pub fn prev(&self) -> Self {
        Self::from_index(self.index() + 4)
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
        };
        state.poll_security_events();
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

        self.poll_security_events();
        if self.selected_event >= self.security_events.len() && !self.security_events.is_empty() {
            self.selected_event = self.security_events.len() - 1;
        }

        self.set_status("State refreshed");
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
                    } => Some(SecurityEventItem {
                        ts,
                        event_type: SecurityEventType::AccessDenial,
                        subject: path,
                        detail: format!("Process '{comm}' (pid {pid}) denied by {source}"),
                        source,
                    }),
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
                };

                if let Some(item) = item {
                    let key = (item.ts.timestamp_millis(), item.subject.clone(), item.detail.clone());
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
            MissionTab::Sessions if !self.snapshots.is_empty() => {
                if self.selected_snapshot > 0 {
                    self.selected_snapshot -= 1;
                } else {
                    self.selected_snapshot = self.snapshots.len() - 1;
                }
            }
            MissionTab::SecurityStream if !self.security_events.is_empty() => {
                if self.selected_event > 0 {
                    self.selected_event -= 1;
                } else {
                    self.selected_event = self.security_events.len() - 1;
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
            MissionTab::Sessions if !self.snapshots.is_empty() => {
                if self.selected_snapshot + 1 < self.snapshots.len() {
                    self.selected_snapshot += 1;
                } else {
                    self.selected_snapshot = 0;
                }
            }
            MissionTab::SecurityStream if !self.security_events.is_empty() => {
                if self.selected_event + 1 < self.security_events.len() {
                    self.selected_event += 1;
                } else {
                    self.selected_event = 0;
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
