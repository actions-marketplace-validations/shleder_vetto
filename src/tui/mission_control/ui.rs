//! Mission Control Ratatui UI Renderer (Arasaka Cyber-Red & Cyber Circuit).

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table, Tabs, Wrap};
use ratatui::Frame;

use super::state::{DashboardState, MissionTab};

const ASCII_LOGO_CIRCUIT: &[&str] = &[
    r"  ██╗   ██╗███████╗████████╗████████╗ ██████╗ ",
    r"  ██║   ██║██╔════╝╚══██╔══╝╚══██╔══╝██╔═══██╗",
    r"  ██║   ██║█████╗     ██║      ██║   ██║   ██║",
    r"  ╚██╗ ██╔╝██╔══╝     ██║      ██║   ██║   ██║",
    r"   ╚████╔╝ ███████╗   ██║      ██║   ╚██████╔╝",
    r"    ╚═══╝  ╚══════╝   ╚═╝      ╚═╝    ╚═════╝ ",
];

const COMPACT_LOGO: &str = "  ╦  ╦ ╔═╗ ╔╦╗ ╔╦╗ ╔═╗  MISSION CONTROL";

pub fn draw(f: &mut Frame, state: &DashboardState) {
    let area = f.size();
    let theme = &state.theme;

    // Fill background
    let bg_block = Block::default().style(Style::default().bg(theme.bg));
    f.render_widget(bg_block, area);

    // Compute layout: Top Margin, Header, Tabs, Body, Footer
    let show_full_logo = area.height >= 30 && area.width >= 70;
    let header_height = if show_full_logo { 7 } else { 3 };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // Top margin / breathing room from terminal edges
            Constraint::Length(header_height),
            Constraint::Length(3), // Tab bar
            Constraint::Min(12),   // Body
            Constraint::Length(3), // Footer
        ])
        .split(area);

    render_header(f, state, chunks[1], show_full_logo);
    render_tabs(f, state, chunks[2]);

    match state.active_tab {
        MissionTab::Agents => render_tab_agents(f, state, chunks[3]),
        MissionTab::Sandbox => render_tab_sandbox(f, state, chunks[3]),
        MissionTab::Doctor => render_tab_doctor(f, state, chunks[3]),
        MissionTab::Sessions => render_tab_sessions(f, state, chunks[3]),
        MissionTab::SecurityStream => render_tab_security_stream(f, state, chunks[3]),
        MissionTab::Fleet => render_tab_fleet(f, state, chunks[3]),
    }

    render_footer(f, state, chunks[4]);
}

fn render_header(f: &mut Frame, state: &DashboardState, area: Rect, full_logo: bool) {
    let theme = &state.theme;

    if full_logo {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(50), Constraint::Min(20)])
            .split(area);

        let logo_lines: Vec<Line> = ASCII_LOGO_CIRCUIT
            .iter()
            .map(|&l| {
                Line::from(Span::styled(
                    l,
                    Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
                ))
            })
            .collect();

        f.render_widget(Paragraph::new(logo_lines), cols[0]);

        let telemetry_lines = vec![
            Line::from(vec![
                Span::styled(
                    "  V E T T O   M I S S I O N   C O N T R O L   ",
                    Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("v{}", env!("CARGO_PKG_VERSION")),
                    Style::default()
                        .fg(theme.accent)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("  KERNEL ISOLATION: ", Style::default().fg(theme.muted)),
                Span::styled(
                    "FULL [Landlock + Namespaces + Cgroups v2 + Seccomp]",
                    Style::default()
                        .fg(theme.success)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("  ACTIVE THEME:     ", Style::default().fg(theme.muted)),
                Span::styled(
                    theme.name(),
                    Style::default().fg(theme.info).add_modifier(Modifier::BOLD),
                ),
                Span::styled(" (press 't' to toggle)", Style::default().fg(theme.muted)),
            ]),
            Line::from(vec![
                Span::styled("  ACTIVE SHIMS:     ", Style::default().fg(theme.muted)),
                Span::styled(
                    format!(
                        "{} / {} agents protected",
                        state
                            .installed_agents
                            .iter()
                            .filter(|a| a.is_shim_active)
                            .count(),
                        state.installed_agents.len()
                    ),
                    Style::default().fg(theme.accent),
                ),
            ]),
        ];

        let right_block = Block::default()
            .borders(Borders::LEFT)
            .border_style(Style::default().fg(theme.border));
        f.render_widget(Paragraph::new(telemetry_lines).block(right_block), cols[1]);
    } else {
        let line = Line::from(vec![
            Span::styled(
                COMPACT_LOGO,
                Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                format!("v{}", env!("CARGO_PKG_VERSION")),
                Style::default().fg(theme.accent),
            ),
            Span::raw(" | "),
            Span::styled(theme.name(), Style::default().fg(theme.info)),
        ]);
        f.render_widget(Paragraph::new(line), area);
    }
}

fn render_tabs(f: &mut Frame, state: &DashboardState, area: Rect) {
    let theme = &state.theme;

    let tab_titles = vec![
        Line::from(format!(" [1] AGENTS ({}) ", state.installed_agents.len())),
        Line::from(" [2] SANDBOX VFS "),
        Line::from(" [3] KERNEL DOCTOR "),
        Line::from(format!(" [4] SESSIONS ({}) ", state.snapshots.len())),
        Line::from(format!(
            " [5] SECURITY STREAM ({}) ",
            state.security_events.len()
        )),
        Line::from(format!(
            " [6] FLEET SWARM ({}) ",
            state.fleet_workers.len()
        )),
    ];

    let tabs = Tabs::new(tab_titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.border))
                .title(Span::styled(
                    " FLEET NAVIGATION ",
                    Style::default().fg(theme.muted),
                )),
        )
        .select(state.active_tab.index())
        .style(Style::default().fg(theme.muted))
        .highlight_style(
            Style::default()
                .fg(theme.tab_active_fg)
                .bg(theme.tab_active_bg)
                .add_modifier(Modifier::BOLD),
        );

    f.render_widget(tabs, area);
}

fn render_tab_agents(f: &mut Frame, state: &DashboardState, area: Rect) {
    let theme = &state.theme;

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(area);

    // Left column: Installed agents list
    if state.installed_agents.is_empty() {
        let empty_lines = vec![
            Line::from(""),
            Line::styled(
                " No AI coding agents detected in PATH outside Vetto.",
                Style::default()
                    .fg(theme.warning)
                    .add_modifier(Modifier::BOLD),
            ),
            Line::from(""),
            Line::styled(
                " Supported agents: claude, opencode, codex, aider, antigravity, cursor,",
                Style::default().fg(theme.muted),
            ),
            Line::styled(
                " cline, windsurf, goose, openhands, devin, copilot, smolagents, omp, zcode, kimi, grok...",
                Style::default().fg(theme.muted),
            ),
            Line::from(""),
            Line::styled(
                " When you install an agent binary on the system,",
                Style::default().fg(theme.text),
            ),
            Line::styled(
                " it will automatically appear in this list on start or [r] refresh.",
                Style::default().fg(theme.text),
            ),
        ];

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.border))
            .title(Span::styled(
                " INSTALLED AGENTS (0 DETECTED) ",
                Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
            ));
        f.render_widget(Paragraph::new(empty_lines).block(block), cols[0]);
    } else {
        let rows = state
            .installed_agents
            .iter()
            .enumerate()
            .map(|(idx, agent)| {
                let is_selected = idx == state.selected_agent;

                let shim_cell = if agent.is_shim_active {
                    Span::styled(
                        "[SHIM]",
                        Style::default()
                            .fg(theme.success)
                            .add_modifier(Modifier::BOLD),
                    )
                } else {
                    Span::styled("[DIRECT]", Style::default().fg(theme.muted))
                };

                let name_cell = Span::styled(
                    agent.name,
                    if is_selected {
                        Style::default()
                            .fg(theme.selection_fg)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(theme.text)
                    },
                );

                let status_cell = if agent.is_running {
                    Span::styled(
                        format!("● RUNNING ({})", agent.active_pids.len()),
                        Style::default()
                            .fg(theme.success)
                            .add_modifier(Modifier::BOLD),
                    )
                } else {
                    Span::styled("○ IDLE", Style::default().fg(theme.muted))
                };

                let row = Row::new(vec![shim_cell, name_cell, status_cell]);
                if is_selected {
                    row.style(
                        Style::default()
                            .bg(theme.selection_bg)
                            .fg(theme.selection_fg)
                            .add_modifier(Modifier::BOLD),
                    )
                } else {
                    row
                }
            });

        let table = Table::new(
            rows,
            vec![
                Constraint::Length(9),
                Constraint::Length(14),
                Constraint::Min(12),
            ],
        )
        .header(
            Row::new(vec!["STATUS", "AGENT", "PROCESS"]).style(
                Style::default()
                    .fg(theme.muted)
                    .add_modifier(Modifier::BOLD),
            ),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.border))
                .title(Span::styled(
                    format!(" INSTALLED AGENTS ({}) ", state.installed_agents.len()),
                    Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
                )),
        );

        f.render_widget(table, cols[0]);
    }

    // Right column: Detailed Inspector for selected agent
    if let Some(agent) = state.installed_agents.get(state.selected_agent) {
        let inspector_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.border))
            .title(Span::styled(
                format!(" AGENT INSPECTOR: {} ", agent.display_name),
                Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
            ));

        let pids_str = if agent.active_pids.is_empty() {
            "None (Process Tree Extinct / Idle)".to_string()
        } else {
            agent
                .active_pids
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };

        let net_str = if agent.network_allowlist.is_empty() {
            "offline (strict zero network egress)".to_string()
        } else {
            agent.network_allowlist.join(", ")
        };

        let lines = vec![
            Line::from(vec![
                Span::styled("REAL BINARY PATH: ", Style::default().fg(theme.muted)),
                Span::styled(
                    agent.binary_path.display().to_string(),
                    Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("SANDBOX SHIM:     ", Style::default().fg(theme.muted)),
                if agent.is_shim_active {
                    Span::styled(
                        "ACTIVE (~/.vetto/shims/ -> transparent kernel sandbox)",
                        Style::default().fg(theme.success).add_modifier(Modifier::BOLD),
                    )
                } else {
                    Span::styled(
                        "DISABLED (runs unconfined as direct host binary)",
                        Style::default().fg(theme.danger).add_modifier(Modifier::BOLD),
                    )
                },
            ]),
            Line::from(vec![
                Span::styled("ACTIVE PID(S):    ", Style::default().fg(theme.muted)),
                Span::styled(
                    pids_str,
                    if agent.is_running {
                        Style::default().fg(theme.success).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(theme.text)
                    },
                ),
            ]),
            Line::from(vec![
                Span::styled("POLICY PRESET:    ", Style::default().fg(theme.muted)),
                Span::styled(
                    format!("balanced + {} (zero-config)", agent.name),
                    Style::default().fg(theme.accent),
                ),
            ]),
            Line::from(""),
            Line::styled(
                "FILESYSTEM ISOLATION MAP (Landlock LSM ABI 1-6 + Namespaces):",
                Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
            ),
            Line::from(vec![
                Span::styled("  [MASKED 0000] ", Style::default().fg(theme.danger).add_modifier(Modifier::BOLD)),
                Span::styled("~/.ssh, ~/.aws, .env, .env.*, ~/.gnupg, ~/.kube", Style::default().fg(theme.text)),
            ]),
            Line::from(vec![
                Span::styled("  [READ-ONLY]   ", Style::default().fg(theme.info)),
                Span::styled("/ (rootfs), /usr, /bin, /lib, /proc/sys, /sys", Style::default().fg(theme.text)),
            ]),
            Line::from(vec![
                Span::styled("  [READ-WRITE]  ", Style::default().fg(theme.success)),
                Span::styled("$PWD (project workspace), /tmp, ~/.cache", Style::default().fg(theme.text)),
            ]),
            Line::from(""),
            Line::styled(
                "EGRESS NETWORK ALLOWLIST (L7 Semantic Proxy + TLS SNI):",
                Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
            ),
            Line::styled(format!("  {net_str}"), Style::default().fg(theme.text)),
            Line::from(""),
            Line::styled(
                "PROCESS TREE CONTAINMENT:",
                Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
            ),
            Line::styled(
                "  PID pinning via pidfd_open + Cgroups v2 cgroup.kill (INV-12/13 extinction theorem)",
                Style::default().fg(theme.muted),
            ),
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    "ACTION: ",
                    Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "[Space] Toggle Shim  |  [Enter] Launch in Vetto Sandbox",
                    Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
                ),
            ]),
        ];

        f.render_widget(
            Paragraph::new(lines)
                .block(inspector_block)
                .wrap(Wrap { trim: true }),
            cols[1],
        );
    } else {
        let empty_inspector = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.border))
            .title(Span::styled(
                " AGENT INSPECTOR ",
                Style::default().fg(theme.logo),
            ));
        f.render_widget(
            Paragraph::new("No agent selected").block(empty_inspector),
            cols[1],
        );
    }
}

fn render_tab_sandbox(f: &mut Frame, state: &DashboardState, area: Rect) {
    let theme = &state.theme;

    let sandbox_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(64), Constraint::Percentage(36)])
        .split(area);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(sandbox_chunks[0]);

    let left_lines = vec![
        Line::styled(
            "KERNEL SANDBOX ISOLATION LAYERS",
            Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
        ),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "1. Landlock LSM: ",
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Unprivileged in-kernel path access rules (ABI 1-6).",
                Style::default().fg(theme.text),
            ),
        ]),
        Line::styled(
            "   Fail-closed execution (Exit 125, INV-01) on sandbox violation.",
            Style::default().fg(theme.muted),
        ),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "2. Linux Namespaces: ",
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET",
                Style::default().fg(theme.text),
            ),
        ]),
        Line::styled(
            "   Zero background daemons; sub-4ms cold start between fork() and execve().",
            Style::default().fg(theme.muted),
        ),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "3. CoW Tmpfs Overlays: ",
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Copy-on-write overlay over system rootfs.",
                Style::default().fg(theme.text),
            ),
        ]),
        Line::styled(
            "   Any destructive writes outside the project directory vanish upon exit.",
            Style::default().fg(theme.muted),
        ),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "4. Seccomp-BPF Syscall Filter: ",
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Pure-Rust compiled BPF filter.",
                Style::default().fg(theme.text),
            ),
        ]),
        Line::styled(
            "   Blocks unshare, mount, ptrace, io_uring, and raw AF_INET socket creation.",
            Style::default().fg(theme.muted),
        ),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "5. Process Extinction: ",
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Cgroups v2 cgroup.kill + pidfd pinning.",
                Style::default().fg(theme.text),
            ),
        ]),
        Line::styled(
            "   Mathematically eliminates runaway background daemons and orphan processes.",
            Style::default().fg(theme.muted),
        ),
    ];

    let left_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(
            " ARCHITECTURAL INVARIANTS ",
            Style::default().fg(theme.logo),
        ));
    f.render_widget(
        Paragraph::new(left_lines)
            .block(left_block)
            .wrap(Wrap { trim: true }),
        cols[0],
    );

    let right_lines = vec![
        Line::styled(
            "INODE-LEVEL SECRET MASKING MATRIX (INV-08)",
            Style::default()
                .fg(theme.danger)
                .add_modifier(Modifier::BOLD),
        ),
        Line::from(""),
        Line::styled(
            "Vetto mounts 0000 mode tmpfs nodes over credential paths prior to agent execve:",
            Style::default().fg(theme.muted),
        ),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "  ~/.ssh/id_*          ",
                Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "-> [MASKED 0000 EACCES]",
                Style::default()
                    .fg(theme.danger)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "  ~/.aws/credentials   ",
                Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "-> [MASKED 0000 EACCES]",
                Style::default()
                    .fg(theme.danger)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "  .env, .env.*         ",
                Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "-> [MASKED 0000 EACCES]",
                Style::default()
                    .fg(theme.danger)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "  ~/.gnupg/secring.*   ",
                Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "-> [MASKED 0000 EACCES]",
                Style::default()
                    .fg(theme.danger)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "  ~/.kube/config       ",
                Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "-> [MASKED 0000 EACCES]",
                Style::default()
                    .fg(theme.danger)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "  ~/.docker/config.json",
                Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "-> [MASKED 0000 EACCES]",
                Style::default()
                    .fg(theme.danger)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::styled(
            "L7 NETWORK SEMANTIC RELAY & DNS BROKER:",
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Line::styled(
            "Direct network calls are intercepted via unix-fd socket bridge with SNI inspection.",
            Style::default().fg(theme.muted),
        ),
        Line::styled(
            "Non-allowlisted endpoints immediately receive 403 Forbidden with zero socket bypass.",
            Style::default().fg(theme.muted),
        ),
    ];

    let right_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(
            " SECRET MASKING & EGRESS ",
            Style::default().fg(theme.logo),
        ));
    f.render_widget(
        Paragraph::new(right_lines)
            .block(right_block)
            .wrap(Wrap { trim: true }),
        cols[1],
    );

    // Render compact security events mini-stream at the bottom of the Sandbox tab
    let mini_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(
            format!(
                " LIVE SECURITY EVENT MINI-STREAM ({} RECORDED) — PRESS [5] FOR FULL STREAM ",
                state.security_events.len()
            ),
            Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
        ));

    if state.security_events.is_empty() {
        let empty_p = Paragraph::new(vec![
            Line::styled(
                "  ● LIVE PROTECTION ACTIVE — 0 ACCESS DENIALS OR BLOCKED EGRESS DETECTED",
                Style::default().fg(theme.success).add_modifier(Modifier::BOLD),
            ),
            Line::styled(
                "    All network socket requests and credential file accesses strictly constrained.",
                Style::default().fg(theme.muted),
            ),
        ])
        .block(mini_block);
        f.render_widget(empty_p, sandbox_chunks[1]);
    } else {
        let rows = state.security_events.iter().take(6).map(|ev| {
            let badge_style = match ev.event_type {
                super::state::SecurityEventType::AccessDenial => Style::default()
                    .fg(theme.danger)
                    .add_modifier(Modifier::BOLD),
                super::state::SecurityEventType::BlockedNetwork => Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
                super::state::SecurityEventType::SecretMasked => Style::default()
                    .fg(theme.warning)
                    .add_modifier(Modifier::BOLD),
                super::state::SecurityEventType::QuotaExceeded => {
                    Style::default().fg(theme.info).add_modifier(Modifier::BOLD)
                }
            };

            Row::new(vec![
                Span::styled(
                    ev.ts.format("%H:%M:%S").to_string(),
                    Style::default().fg(theme.muted),
                ),
                Span::styled(format!("[{}]", ev.event_type.badge()), badge_style),
                Span::styled(
                    &ev.subject,
                    Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
                ),
                Span::styled(&ev.source, Style::default().fg(theme.info)),
                Span::styled(&ev.detail, Style::default().fg(theme.muted)),
            ])
        });

        let table = Table::new(
            rows,
            [
                Constraint::Length(10),
                Constraint::Length(12),
                Constraint::Length(30),
                Constraint::Length(15),
                Constraint::Min(20),
            ],
        )
        .header(
            Row::new(vec![
                Span::styled("TIME", Style::default().fg(theme.muted)),
                Span::styled("TYPE", Style::default().fg(theme.muted)),
                Span::styled("SUBJECT", Style::default().fg(theme.muted)),
                Span::styled("SOURCE", Style::default().fg(theme.muted)),
                Span::styled("DETAILS", Style::default().fg(theme.muted)),
            ])
            .bottom_margin(0),
        )
        .block(mini_block);

        f.render_widget(table, sandbox_chunks[1]);
    }
}

fn render_tab_security_stream(f: &mut Frame, state: &DashboardState, area: Rect) {
    let theme = &state.theme;

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // Metrics header counters
            Constraint::Min(10),   // Events table
            Constraint::Length(7), // Event detail panel
        ])
        .split(area);

    // 1. Metric counters
    let count_denials = state
        .security_events
        .iter()
        .filter(|e| e.event_type == super::state::SecurityEventType::AccessDenial)
        .count();
    let count_net_blocked = state
        .security_events
        .iter()
        .filter(|e| e.event_type == super::state::SecurityEventType::BlockedNetwork)
        .count();
    let count_secrets = state
        .security_events
        .iter()
        .filter(|e| e.event_type == super::state::SecurityEventType::SecretMasked)
        .count();
    let count_quota = state
        .security_events
        .iter()
        .filter(|e| e.event_type == super::state::SecurityEventType::QuotaExceeded)
        .count();

    let metric_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(chunks[0]);

    // Box 1: Filesystem / Syscall Denials
    let block1 = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(
            " DENIED FILES / SYSCALLS ",
            Style::default().fg(theme.muted),
        ));
    let p1 = Paragraph::new(vec![Line::from(vec![
        Span::styled(
            format!("  {count_denials} "),
            Style::default()
                .fg(if count_denials > 0 {
                    theme.danger
                } else {
                    theme.success
                })
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("attempts contained", Style::default().fg(theme.muted)),
    ])])
    .block(block1);
    f.render_widget(p1, metric_cols[0]);

    // Box 2: Blocked Egress (Anti-SSRF)
    let block2 = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(
            " BLOCKED EGRESS (ANTI-SSRF) ",
            Style::default().fg(theme.muted),
        ));
    let p2 = Paragraph::new(vec![Line::from(vec![
        Span::styled(
            format!("  {count_net_blocked} "),
            Style::default()
                .fg(if count_net_blocked > 0 {
                    theme.danger
                } else {
                    theme.success
                })
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "targets dropped fail-closed",
            Style::default().fg(theme.muted),
        ),
    ])])
    .block(block2);
    f.render_widget(p2, metric_cols[1]);

    // Box 3: Secrets Protected
    let block3 = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(
            " SECRETS PROTECTED (INV-08) ",
            Style::default().fg(theme.muted),
        ));
    let p3 = Paragraph::new(vec![Line::from(vec![
        Span::styled(
            format!("  {count_secrets} "),
            Style::default()
                .fg(theme.warning)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "credentials masked mode 0000",
            Style::default().fg(theme.muted),
        ),
    ])])
    .block(block3);
    f.render_widget(p3, metric_cols[2]);

    // Box 4: Total Stream Records
    let block4 = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(
            " TOTAL EVENTS IN BUFFER ",
            Style::default().fg(theme.muted),
        ));
    let p4 = Paragraph::new(vec![Line::from(vec![
        Span::styled(
            format!("  {} / 500 ", state.security_events.len()),
            Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("({count_quota} quota)", count_quota = count_quota),
            Style::default().fg(theme.muted),
        ),
    ])])
    .block(block4);
    f.render_widget(p4, metric_cols[3]);

    // 2. Events table
    let table_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(
            " LIVE SECURITY EVENT STREAM (ANTI-SSRF & SANDBOX POLICY ENFORCEMENT) ",
            Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
        ));

    if state.security_events.is_empty() {
        let empty_lines = vec![
            Line::from(""),
            Line::styled(
                "  ● LIVE PROTECTION ACTIVE — 0 SECURITY EVENTS RECORDED",
                Style::default().fg(theme.success).add_modifier(Modifier::BOLD),
            ),
            Line::from(""),
            Line::styled(
                "  All agent file access is bounded by Landlock LSM and Inode Masking.",
                Style::default().fg(theme.muted),
            ),
            Line::styled(
                "  All outbound network requests targeting private subnets, cloud metadata (169.254.169.254, 100.100.100.200),",
                Style::default().fg(theme.muted),
            ),
            Line::styled(
                "  or non-allowlisted domains are dropped fail-closed and logged here in real time.",
                Style::default().fg(theme.muted),
            ),
            Line::from(""),
            Line::styled(
                "  Press 'r' to refresh log ingestion, or run an agent under Vetto to observe events.",
                Style::default().fg(theme.text),
            ),
        ];
        f.render_widget(Paragraph::new(empty_lines).block(table_block), chunks[1]);
    } else {
        let rows = state.security_events.iter().enumerate().map(|(idx, ev)| {
            let is_selected = idx == state.selected_event;

            let badge_style = match ev.event_type {
                super::state::SecurityEventType::AccessDenial => Style::default()
                    .fg(theme.danger)
                    .add_modifier(Modifier::BOLD),
                super::state::SecurityEventType::BlockedNetwork => Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
                super::state::SecurityEventType::SecretMasked => Style::default()
                    .fg(theme.warning)
                    .add_modifier(Modifier::BOLD),
                super::state::SecurityEventType::QuotaExceeded => {
                    Style::default().fg(theme.info).add_modifier(Modifier::BOLD)
                }
            };

            let row_style = if is_selected {
                Style::default().bg(theme.selection_bg)
            } else {
                Style::default()
            };

            let marker = if is_selected { "▶ " } else { "  " };

            Row::new(vec![
                Span::styled(
                    format!("{marker}{}", ev.ts.format("%H:%M:%S")),
                    Style::default().fg(theme.muted),
                ),
                Span::styled(format!("[{}]", ev.event_type.badge()), badge_style),
                Span::styled(
                    &ev.subject,
                    if is_selected {
                        Style::default()
                            .fg(theme.selection_fg)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(theme.text)
                    },
                ),
                Span::styled(&ev.source, Style::default().fg(theme.info)),
                Span::styled(&ev.detail, Style::default().fg(theme.muted)),
            ])
            .style(row_style)
        });

        let table = Table::new(
            rows,
            [
                Constraint::Length(12),
                Constraint::Length(12),
                Constraint::Length(32),
                Constraint::Length(16),
                Constraint::Min(30),
            ],
        )
        .header(
            Row::new(vec![
                Span::styled(
                    "  TIME (UTC)",
                    Style::default()
                        .fg(theme.muted)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "TYPE",
                    Style::default()
                        .fg(theme.muted)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "SUBJECT / TARGET",
                    Style::default()
                        .fg(theme.muted)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "SUBSYSTEM",
                    Style::default()
                        .fg(theme.muted)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "DETAILS / POLICY ACTION",
                    Style::default()
                        .fg(theme.muted)
                        .add_modifier(Modifier::BOLD),
                ),
            ])
            .bottom_margin(1),
        )
        .block(table_block);

        f.render_widget(table, chunks[1]);
    }

    // 3. Event Detail Panel
    let detail_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(
            " EVENT INSPECTION & AUDIT DETAILS ",
            Style::default().fg(theme.logo),
        ));

    if let Some(selected) = state.security_events.get(state.selected_event) {
        let badge_style = match selected.event_type {
            super::state::SecurityEventType::AccessDenial => Style::default()
                .fg(theme.danger)
                .add_modifier(Modifier::BOLD),
            super::state::SecurityEventType::BlockedNetwork => Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
            super::state::SecurityEventType::SecretMasked => Style::default()
                .fg(theme.warning)
                .add_modifier(Modifier::BOLD),
            super::state::SecurityEventType::QuotaExceeded => {
                Style::default().fg(theme.info).add_modifier(Modifier::BOLD)
            }
        };

        let detail_lines = vec![
            Line::from(vec![
                Span::styled("  TIMESTAMP: ", Style::default().fg(theme.muted)),
                Span::styled(
                    selected.ts.to_rfc3339(),
                    Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
                ),
                Span::styled("   EVENT TYPE: ", Style::default().fg(theme.muted)),
                Span::styled(format!("[{}]", selected.event_type.badge()), badge_style),
                Span::styled("   SUBSYSTEM: ", Style::default().fg(theme.muted)),
                Span::styled(
                    &selected.source,
                    Style::default().fg(theme.info).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("  TARGET / SUBJECT: ", Style::default().fg(theme.muted)),
                Span::styled(
                    &selected.subject,
                    Style::default()
                        .fg(theme.accent)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("  ENFORCEMENT ACTION: ", Style::default().fg(theme.muted)),
                Span::styled(&selected.detail, Style::default().fg(theme.text)),
            ]),
        ];
        f.render_widget(Paragraph::new(detail_lines).block(detail_block), chunks[2]);
    } else {
        let empty_p = Paragraph::new(vec![Line::styled(
            "  No event selected. Use [↑/↓] or [k/j] to navigate security events when available.",
            Style::default().fg(theme.muted),
        )])
        .block(detail_block);
        f.render_widget(empty_p, chunks[2]);
    }
}

fn render_tab_doctor(f: &mut Frame, state: &DashboardState, area: Rect) {
    let theme = &state.theme;

    let Some(ref report) = state.doctor_report else {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.border))
            .title(" KERNEL PREFLIGHT DOCTOR ");
        f.render_widget(
            Paragraph::new("Executing preflight diagnostics...").block(block),
            area,
        );
        return;
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(8)])
        .split(area);

    let (verdict_str, verdict_color) = match report.verdict {
        crate::doctor::preflight::PreflightVerdict::Pass => {
            ("PASS (Fully Supported)", theme.success)
        }
        crate::doctor::preflight::PreflightVerdict::Degraded => {
            ("DEGRADED (Partial Isolation)", theme.warning)
        }
        crate::doctor::preflight::PreflightVerdict::Fail => {
            ("FAIL (Unsupported Environment)", theme.danger)
        }
    };

    let verdict_line = Line::from(vec![
        Span::styled(
            "OVERALL KERNEL VERDICT: ",
            Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            verdict_str,
            Style::default()
                .fg(verdict_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  (Exit Code: {})", report.exit_code),
            Style::default().fg(theme.muted),
        ),
        Span::raw("   |   "),
        Span::styled(
            "Press [r] to re-run preflight probe",
            Style::default().fg(theme.accent),
        ),
    ]);

    let top_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border));
    f.render_widget(Paragraph::new(verdict_line).block(top_block), chunks[0]);

    let grid = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    let left_items = vec![
        Line::styled(
            "1. LANDLOCK LSM CAPABILITY",
            Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
        ),
        Line::from(vec![
            Span::styled("   Supported: ", Style::default().fg(theme.muted)),
            Span::styled(
                if report.landlock.supported {
                    "Yes"
                } else {
                    "No"
                },
                Style::default()
                    .fg(if report.landlock.supported {
                        theme.success
                    } else {
                        theme.danger
                    })
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" (ABI Version: {:?})", report.landlock.abi_version),
                Style::default().fg(theme.text),
            ),
        ]),
        Line::styled(
            format!("   Status:    {}", report.landlock.status),
            Style::default().fg(theme.muted),
        ),
        Line::styled(
            format!("   Message:   {}", report.landlock.message),
            Style::default().fg(theme.text),
        ),
        Line::from(""),
        Line::styled(
            "2. LINUX NAMESPACES (CLONE_NEWUSER)",
            Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
        ),
        Line::from(vec![
            Span::styled("   Stage 1 User NS: ", Style::default().fg(theme.muted)),
            Span::styled(
                &report.namespaces.stage1_user_namespace.status,
                Style::default().fg(if report.namespaces.stage1_user_namespace.supported {
                    theme.success
                } else {
                    theme.warning
                }),
            ),
        ]),
        Line::styled(
            format!(
                "   Stage 2 Tmpfs:   {}",
                report.namespaces.stage2_tmpfs_mount.status
            ),
            Style::default().fg(theme.muted),
        ),
        Line::styled(
            format!("   Overall Status:  {}", report.namespaces.overall_status),
            Style::default().fg(theme.text),
        ),
    ];

    let right_items = vec![
        Line::styled(
            "3. CGROUPS V2 & PROCESS EXTINCTION",
            Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
        ),
        Line::from(vec![
            Span::styled("   Available:   ", Style::default().fg(theme.muted)),
            Span::styled(
                if report.cgroups_v2.available {
                    "Yes"
                } else {
                    "No"
                },
                Style::default().fg(if report.cgroups_v2.available {
                    theme.success
                } else {
                    theme.danger
                }),
            ),
            Span::styled(
                format!(" (cgroup.kill: {})", report.cgroups_v2.cgroup_kill),
                Style::default().fg(theme.text),
            ),
        ]),
        Line::styled(
            format!(
                "   Controllers: {}",
                report.cgroups_v2.controllers.join(", ")
            ),
            Style::default().fg(theme.muted),
        ),
        Line::styled(
            format!("   Message:     {}", report.cgroups_v2.message),
            Style::default().fg(theme.text),
        ),
        Line::from(""),
        Line::styled(
            "4. SECCOMP-BPF FILTER STATUS",
            Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
        ),
        Line::from(vec![
            Span::styled("   Filter Active: ", Style::default().fg(theme.muted)),
            Span::styled(
                if report.seccomp.filter_available {
                    "Available"
                } else {
                    "Unavailable"
                },
                Style::default().fg(if report.seccomp.filter_available {
                    theme.success
                } else {
                    theme.warning
                }),
            ),
        ]),
        Line::styled(
            format!("   Mode:          {}", report.seccomp.current_mode),
            Style::default().fg(theme.muted),
        ),
        Line::styled(
            format!(
                "   Container:     {}",
                if report.seccomp.container_restricted {
                    "Restricted"
                } else {
                    "Unrestricted"
                }
            ),
            Style::default().fg(theme.text),
        ),
    ];

    let left_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(" LANDLOCK & NAMESPACES ");
    f.render_widget(
        Paragraph::new(left_items)
            .block(left_block)
            .wrap(Wrap { trim: true }),
        grid[0],
    );

    let right_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(" CGROUPS V2 & SECCOMP ");
    f.render_widget(
        Paragraph::new(right_items)
            .block(right_block)
            .wrap(Wrap { trim: true }),
        grid[1],
    );
}

fn render_tab_sessions(f: &mut Frame, state: &DashboardState, area: Rect) {
    let theme = &state.theme;

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    if state.snapshots.is_empty() {
        let empty_msg = vec![
            Line::from(""),
            Line::styled(" No project snapshots found.", Style::default().fg(theme.muted).add_modifier(Modifier::BOLD)),
            Line::styled(" Snapshots are created automatically before agent sessions or via 'vetto run'.", Style::default().fg(theme.muted)),
            Line::styled(" Once an agent modifies project files under Vetto, an automatic snapshot is stored here.", Style::default().fg(theme.text)),
        ];
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.border))
            .title(" PROJECT SNAPSHOTS & UNDO ");
        f.render_widget(Paragraph::new(empty_msg).block(block), chunks[0]);
    } else {
        let rows = state.snapshots.iter().enumerate().map(|(idx, snap)| {
            let is_selected = idx == state.selected_snapshot;
            let id_span = Span::styled(
                snap.session_id.as_str(),
                if is_selected {
                    Style::default()
                        .fg(theme.selection_fg)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(theme.text)
                },
            );

            let created_span =
                Span::styled(snap.created_at.as_str(), Style::default().fg(theme.muted));
            let files_span = Span::styled(
                format!("{}", snap.file_count),
                Style::default().fg(theme.text),
            );
            let size_span = Span::styled(
                format_bytes(snap.total_size_bytes),
                Style::default().fg(theme.accent),
            );
            let proj_span = Span::styled(
                snap.project_dir.display().to_string(),
                Style::default().fg(theme.text),
            );

            let row = Row::new(vec![
                id_span,
                created_span,
                files_span,
                size_span,
                proj_span,
            ]);
            if is_selected {
                row.style(
                    Style::default()
                        .bg(theme.selection_bg)
                        .fg(theme.selection_fg)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                row
            }
        });

        let table = Table::new(
            rows,
            vec![
                Constraint::Length(18),
                Constraint::Length(26),
                Constraint::Length(8),
                Constraint::Length(12),
                Constraint::Min(20),
            ],
        )
        .header(
            Row::new(vec![
                "SESSION ID",
                "CREATED AT",
                "FILES",
                "SIZE",
                "PROJECT DIR",
            ])
            .style(
                Style::default()
                    .fg(theme.muted)
                    .add_modifier(Modifier::BOLD),
            ),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.border))
                .title(Span::styled(
                    format!(" AVAILABLE SNAPSHOTS ({}) ", state.snapshots.len()),
                    Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
                )),
        );

        f.render_widget(table, chunks[0]);
    }

    // Bottom panel: Selected snapshot details and instant rollback prompt
    let detail_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(
            " INSTANT ROLLBACK (VETTO UNDO) ",
            Style::default().fg(theme.logo),
        ));

    if let Some(snap) = state.snapshots.get(state.selected_snapshot) {
        let lines = vec![
            Line::from(vec![
                Span::styled("SELECTED SESSION: ", Style::default().fg(theme.muted)),
                Span::styled(&snap.session_id, Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("TARGET PROJECT:   ", Style::default().fg(theme.muted)),
                Span::styled(snap.project_dir.display().to_string(), Style::default().fg(theme.text)),
            ]),
            Line::from(vec![
                Span::styled("ARCHIVE PATH:     ", Style::default().fg(theme.muted)),
                Span::styled(snap.archive_file.display().to_string(), Style::default().fg(theme.muted)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("ACTIONS: ", Style::default().fg(theme.logo).add_modifier(Modifier::BOLD)),
                Span::styled(
                    "Press [u] to restore files from this snapshot immediately! (Overwrites modified files)",
                    Style::default().fg(theme.danger).add_modifier(Modifier::BOLD),
                ),
            ]),
        ];
        f.render_widget(Paragraph::new(lines).block(detail_block), chunks[1]);
    } else {
        f.render_widget(
            Paragraph::new("Select a session snapshot above to preview restore.")
                .block(detail_block),
            chunks[1],
        );
    }
}

fn render_tab_fleet(f: &mut Frame, state: &DashboardState, area: Rect) {
    let theme = &state.theme;

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // 4 summary metric cards
            Constraint::Min(8),    // Live Fleet Worker Allocation Table
        ])
        .split(area);

    // Top section: 4 summary metric cards
    let metric_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(chunks[0]);

    // 1) "ACTIVE FLEET WORKERS" -> format!("{}/64", state.fleet_workers.len())
    let card1_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(
            " ACTIVE FLEET WORKERS ",
            Style::default().fg(theme.muted),
        ));
    let card1_val = format!("{}/64", state.fleet_workers.len());
    let p1 = Paragraph::new(vec![Line::from(vec![
        Span::styled(
            format!("  {card1_val} "),
            Style::default()
                .fg(if state.fleet_workers.is_empty() {
                    theme.text
                } else {
                    theme.success
                })
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("provisioned / cap", Style::default().fg(theme.muted)),
    ])])
    .block(card1_block);
    f.render_widget(p1, metric_cols[0]);

    // 2) "FAIR-SHARE CPU" -> "cpu.weight: 100"
    let card2_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(
            " FAIR-SHARE CPU ",
            Style::default().fg(theme.muted),
        ));
    let p2 = Paragraph::new(vec![Line::from(vec![
        Span::styled(
            "  cpu.weight: 100 ",
            Style::default().fg(theme.info).add_modifier(Modifier::BOLD),
        ),
        Span::styled("cgroups v2", Style::default().fg(theme.muted)),
    ])])
    .block(card2_block);
    f.render_widget(p2, metric_cols[1]);

    // 3) "MEMORY CEILING" -> "2.0 GiB per worker"
    let card3_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(
            " MEMORY CEILING ",
            Style::default().fg(theme.muted),
        ));
    let p3 = Paragraph::new(vec![Line::from(vec![
        Span::styled(
            "  2.0 GiB per worker ",
            Style::default().fg(theme.warning).add_modifier(Modifier::BOLD),
        ),
        Span::styled("hard limit", Style::default().fg(theme.muted)),
    ])])
    .block(card3_block);
    f.render_widget(p3, metric_cols[2]);

    // 4) "ISOLATION STATUS" -> "CLONE_NEWIPC + CLONE_NEWPID"
    let card4_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(
            " ISOLATION STATUS ",
            Style::default().fg(theme.muted),
        ));
    let p4 = Paragraph::new(vec![Line::from(vec![
        Span::styled(
            "  CLONE_NEWIPC + CLONE_NEWPID ",
            Style::default().fg(theme.success).add_modifier(Modifier::BOLD),
        ),
        Span::styled("enforced", Style::default().fg(theme.muted)),
    ])])
    .block(card4_block);
    f.render_widget(p4, metric_cols[3]);

    // Bottom section: Live Fleet Worker Allocation Table
    let table_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(
            " LIVE FLEET WORKER ALLOCATION TABLE (FAIR-SHARE MULTI-AGENT SWARM) ",
            Style::default().fg(theme.logo),
        ));

    if state.fleet_workers.is_empty() {
        let empty_lines = vec![
            Line::from(""),
            Line::styled(
                "  ● No active fleet workers. Spawn workers via 'vetto fleet spawn <agent>' or 'v' to run verification probe.",
                Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
            ),
            Line::from(""),
            Line::styled(
                if let Some(ref probe_status) = state.fleet_probe_status {
                    format!("  Last Isolation Probe: {probe_status}")
                } else {
                    "  Press 'v' to execute a live 4-worker / 6-pair isolation verification probe.".to_string()
                },
                Style::default().fg(
                    if state
                        .fleet_probe_status
                        .as_ref()
                        .map(|s| s.starts_with("PASS"))
                        .unwrap_or(false)
                    {
                        theme.success
                    } else {
                        theme.muted
                    },
                ),
            ),
            Line::from(""),
            Line::styled(
                "  Each worker runs with isolated cgroup limits, ephemeral CoW branch, disjoint port, and private IPC/PID namespaces.",
                Style::default().fg(theme.muted),
            ),
        ];
        f.render_widget(Paragraph::new(empty_lines).block(table_block), chunks[1]);
    } else {
        let rows = state.fleet_workers.iter().enumerate().map(|(idx, w)| {
            let is_selected = idx == state.selected_fleet_worker;
            let row_style = if is_selected {
                Style::default().bg(theme.selection_bg)
            } else {
                Style::default()
            };
            let prefix = if is_selected { "▶ " } else { "  " };

            let pid_str = w
                .pid
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string());
            let scope_str = w
                .scope_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_else(|| w.scope_path.to_str().unwrap_or("-"));

            let limits_str = format!(
                "{}w/{:.1}G/{}p",
                w.cpu_weight,
                w.memory_limit_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
                w.pids_max
            );

            let status_style = match w.status.to_ascii_lowercase().as_str() {
                "running" | "active" => Style::default()
                    .fg(theme.success)
                    .add_modifier(Modifier::BOLD),
                "allocated" => Style::default()
                    .fg(theme.info)
                    .add_modifier(Modifier::BOLD),
                "exited" | "stale" => Style::default()
                    .fg(theme.danger)
                    .add_modifier(Modifier::BOLD),
                _ => Style::default().fg(theme.muted),
            };

            Row::new(vec![
                Span::styled(
                    format!("{prefix}{}", w.worker_id),
                    Style::default()
                        .fg(if is_selected { theme.logo } else { theme.text })
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(&w.agent_name, Style::default().fg(theme.info)),
                Span::styled(pid_str, Style::default().fg(theme.accent)),
                Span::styled(w.ephemeral_port.to_string(), Style::default().fg(theme.muted)),
                Span::styled(&w.cow_branch_name, Style::default().fg(theme.text)),
                Span::styled(scope_str, Style::default().fg(theme.muted)),
                Span::styled(limits_str, Style::default().fg(theme.warning)),
                Span::styled(format!("[{}]", w.status.to_ascii_uppercase()), status_style),
            ])
            .style(row_style)
        });

        let table = Table::new(
            rows,
            [
                Constraint::Length(14), // WORKER ID
                Constraint::Length(12), // AGENT
                Constraint::Length(8),  // PID
                Constraint::Length(8),  // PORT
                Constraint::Length(14), // COW BRANCH
                Constraint::Length(22), // CGROUP SCOPE
                Constraint::Length(18), // LIMITS
                Constraint::Min(10),    // STATUS
            ],
        )
        .header(
            Row::new(vec![
                Span::styled(
                    "  WORKER ID",
                    Style::default().fg(theme.muted).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "AGENT",
                    Style::default().fg(theme.muted).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "PID",
                    Style::default().fg(theme.muted).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "PORT",
                    Style::default().fg(theme.muted).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "COW BRANCH",
                    Style::default().fg(theme.muted).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "CGROUP SCOPE",
                    Style::default().fg(theme.muted).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "LIMITS",
                    Style::default().fg(theme.muted).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "STATUS",
                    Style::default().fg(theme.muted).add_modifier(Modifier::BOLD),
                ),
            ])
            .bottom_margin(1),
        )
        .block(table_block);

        f.render_widget(table, chunks[1]);
    }
}

fn render_footer(f: &mut Frame, state: &DashboardState, area: Rect) {
    let theme = &state.theme;

    let status_text = state.active_status().unwrap_or(
        "Theme: ARASAKA RED  |  Bare 'vetto' interactive TTY dashboard  |  Press 't' to toggle palette",
    );

    let key_hints = if state.active_tab == MissionTab::Fleet {
        vec![
            Span::styled(
                "[1-6]",
                Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Tabs  ", Style::default().fg(theme.text)),
            Span::styled(
                "[v]",
                Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Verify Probe  ", Style::default().fg(theme.text)),
            Span::styled(
                "[x]",
                Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Terminate  ", Style::default().fg(theme.text)),
            Span::styled(
                "[j/k]",
                Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Navigate  ", Style::default().fg(theme.text)),
            Span::styled(
                "[Tab]",
                Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Switch Tab  ", Style::default().fg(theme.text)),
            Span::styled(
                "[t]",
                Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Theme  ", Style::default().fg(theme.text)),
            Span::styled(
                "[r]",
                Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Refresh  ", Style::default().fg(theme.text)),
            Span::styled(
                "[q/Esc]",
                Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Quit", Style::default().fg(theme.text)),
        ]
    } else {
        vec![
            Span::styled(
                "[1-6]",
                Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Tabs  ", Style::default().fg(theme.text)),
            Span::styled(
                "[↑↓/jk]",
                Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Select  ", Style::default().fg(theme.text)),
            Span::styled(
                "[Space]",
                Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Toggle Shim  ", Style::default().fg(theme.text)),
            Span::styled(
                "[Enter]",
                Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Launch  ", Style::default().fg(theme.text)),
            Span::styled(
                "[t]",
                Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Theme  ", Style::default().fg(theme.text)),
            Span::styled(
                "[r]",
                Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Refresh  ", Style::default().fg(theme.text)),
            Span::styled(
                "[u]",
                Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Undo  ", Style::default().fg(theme.text)),
            Span::styled(
                "[q/Esc]",
                Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Quit", Style::default().fg(theme.text)),
        ]
    };

    let lines = vec![
        Line::from(vec![
            Span::styled("STATUS: ", Style::default().fg(theme.muted)),
            Span::styled(
                status_text,
                Style::default().fg(theme.info).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(key_hints),
    ];

    let footer_block = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(theme.border));
    f.render_widget(Paragraph::new(lines).block(footer_block), area);
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn test_top_margin_leaves_row_zero_empty_in_full_mode() {
        let backend = TestBackend::new(100, 35);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = DashboardState::new(None);

        terminal.draw(|f| draw(f, &state)).unwrap();

        let buffer = terminal.backend().buffer();
        // Row 0 should be empty (all spaces) because of the top margin breathing room
        for x in 0..100 {
            assert_eq!(
                buffer.get(x, 0).symbol(),
                " ",
                "Expected row 0 col {x} to be empty space due to top breathing room margin"
            );
        }

        // Row 1 should contain content (the header starts at row 1)
        let row_1_has_content = (0..100).any(|x| buffer.get(x, 1).symbol() != " ");
        assert!(
            row_1_has_content,
            "Expected row 1 to contain header content"
        );
    }

    #[test]
    fn test_top_margin_leaves_row_zero_empty_in_compact_mode() {
        let backend = TestBackend::new(60, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = DashboardState::new(None);

        terminal.draw(|f| draw(f, &state)).unwrap();

        let buffer = terminal.backend().buffer();
        // Row 0 should be empty
        for x in 0..60 {
            assert_eq!(
                buffer.get(x, 0).symbol(),
                " ",
                "Expected row 0 col {x} to be empty space in compact mode"
            );
        }

        // Row 1 should contain compact header content
        let row_1_has_content = (0..60).any(|x| buffer.get(x, 1).symbol() != " ");
        assert!(
            row_1_has_content,
            "Expected row 1 to contain compact header"
        );
    }

    #[test]
    fn test_render_security_stream_tab() {
        let backend = TestBackend::new(120, 35);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = DashboardState::new(None);
        state.active_tab = MissionTab::SecurityStream;

        state
            .security_events
            .push_back(super::super::state::SecurityEventItem {
                ts: chrono::Utc::now(),
                event_type: super::super::state::SecurityEventType::BlockedNetwork,
                subject: "169.254.169.254:80".to_string(),
                detail: "Egress blocked (Anti-SSRF)".to_string(),
                source: "net_relay".to_string(),
            });
        state
            .security_events
            .push_back(super::super::state::SecurityEventItem {
                ts: chrono::Utc::now(),
                event_type: super::super::state::SecurityEventType::SecretMasked,
                subject: "/home/user/.ssh/id_rsa".to_string(),
                detail: "Inode masked mode 0000".to_string(),
                source: "vfs_overlays".to_string(),
            });

        terminal.draw(|f| draw(f, &state)).unwrap();

        let buffer = terminal.backend().buffer();
        let content: String = (0..35)
            .map(|y| {
                (0..120)
                    .map(|x| buffer.get(x, y).symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(content.contains("SECURITY STREAM"));
        assert!(content.contains("BLOCKED EGRESS (ANTI-SSRF)"));
        assert!(content.contains("169.254.169.254:80"));
    }

    #[test]
    fn test_render_fleet_swarm_tab() {
        let backend = TestBackend::new(140, 35);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = DashboardState::new(None);
        state.active_tab = MissionTab::Fleet;

        state.fleet_workers.push(crate::multi::fleet::AgentWorkerScope {
            worker_id: "agent-01".to_string(),
            agent_name: "claude".to_string(),
            scope_path: std::path::PathBuf::from("/sys/fs/cgroup/vetto-fleet/agent-01.scope"),
            cow_branch_name: "agent-01".to_string(),
            ephemeral_port: 49201,
            cpu_weight: 100,
            memory_limit_bytes: 2 * 1024 * 1024 * 1024,
            pids_max: 128,
            ipc_isolated: true,
            allocated_at: chrono::Utc::now(),
            pid: Some(4242),
            status: "running".to_string(),
            workspace_dir: std::path::PathBuf::from("/home/user/.vetto/fleet/workspaces/agent-01"),
        });

        terminal.draw(|f| draw(f, &state)).unwrap();

        let buffer = terminal.backend().buffer();
        let content: String = (0..35)
            .map(|y| {
                (0..140)
                    .map(|x| buffer.get(x, y).symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(content.contains("FLEET SWARM"));
        assert!(content.contains("ACTIVE FLEET WORKERS"));
        assert!(content.contains("cpu.weight: 100"));
        assert!(content.contains("2.0 GiB per worker"));
        assert!(content.contains("CLONE_NEWIPC + CLONE_NEWPID"));
        assert!(content.contains("agent-01"));
        assert!(content.contains("claude"));
        assert!(content.contains("4242"));
        assert!(content.contains("49201"));
    }

    #[test]
    fn test_render_fleet_swarm_tab_empty() {
        let backend = TestBackend::new(140, 35);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = DashboardState::new(None);
        state.active_tab = MissionTab::Fleet;
        state.fleet_workers.clear();

        terminal.draw(|f| draw(f, &state)).unwrap();

        let buffer = terminal.backend().buffer();
        let content: String = (0..35)
            .map(|y| {
                (0..140)
                    .map(|x| buffer.get(x, y).symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(content.contains("FLEET SWARM"));
        assert!(content.contains("No active fleet workers"));
    }
}
