//! vetto — daemon-less sandbox + security layer for AI coding agents.
//!
//! Session wiring order matters and is load-bearing:
//!   1. CLI/config, policy load, stdio plumbing — no threads yet.
//!   2. Backend::detect + spawn: EVERY fork happens here, single-threaded.
//!   3. Only after a successful spawn: event bus consumers (broker, notifier,
//!      audit reader, visibility poller, jsonl, stats) and the UI loop.

use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::os::fd::IntoRawFd;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Parser;

use vetto::config::{NetMode, RunConfig, TuiMode};
use vetto::events::{Event, EventBus};
#[cfg(unix)]
use vetto::pty;
#[cfg(unix)]
use vetto::tui;
use vetto::{
    cli, daemon, events, exit_codes, history, logger, mcp, multi, policy, profile, remote, report,
    rescue, sandbox, shim, watchdog,
};

fn main() {
    if let Err(err) = run() {
        eprintln!("vetto: error: {err}");
        let code = exit_codes::map_error_to_exit_code(&err);
        std::process::exit(code);
    }
}

fn fast_tier_detect() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        let p = sandbox::linux::probe();
        match sandbox::linux::pick_tier(&p) {
            Ok(t) => t.label(),
            Err(_) => "none",
        }
    }
    #[cfg(target_os = "macos")]
    {
        "macos-seatbelt"
    }
    #[cfg(target_os = "windows")]
    {
        "windows-sandbox"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "none"
    }
}

fn preprocess_cli_args(raw_args: &[String]) -> Result<Vec<String>> {
    if raw_args.iter().any(|a| a == "--") {
        return Ok(raw_args.to_vec());
    }

    const KNOWN_SUBCOMMANDS: &[&str] = &[
        "mask",
        "enable",
        "disable",
        "allow",
        "deny",
        "doctor",
        "tour",
        "status",
        "tui",
        "mission-control",
        "mission_control",
        "kill",
        "fleet",
        "verify",
        "verify-ng",
        "run",
        "exec",
        "wizard",
        "undo",
        "ephemeral",
        "eval",
        "bench",
        "diff",
        "pack",
        "unpack",
        "watchdog",
        "init",
        "profiles",
        "hook",
        "plugin",
        "mcp",
        "daemon",
        "serve",
        "shim",
        "multi",
        "rescue",
        "report",
        "redteam",
        "policy",
        "completions",
        "man",
        "shell-env",
        "profile",
        "why-slow",
        "upgrade",
        "scan-secrets",
        "watch",
        "rollback",
        "events",
        "audit",
        "digest",
        "diff-sessions",
        "replay",
        "ssh-proxy",
        "__ssh-proxy",
        "help",
        "version",
    ];

    const OPTIONS_WITH_VALUE: &[&str] = &[
        "--profile",
        "--preset",
        "--policy",
        "--net",
        "--tui",
        "--backend",
        "--jsonl",
        "--report",
        "--report-dir",
        "--report-retention",
        "--report-max-age-secs",
        "--otel-endpoint",
        "--timeout",
        "--limits",
        "--remote",
        "--agent",
        "--manifest",
        "--deny-glob",
    ];

    let mut i = 1;
    while i < raw_args.len() {
        let arg = &raw_args[i];
        if arg.starts_with("--") {
            if arg.contains('=') {
                i += 1;
                continue;
            }
            if arg == "--fail-on-block" {
                if let Some(next) = raw_args.get(i + 1) {
                    if next.chars().all(|c| c.is_ascii_digit()) {
                        i += 2;
                        continue;
                    }
                }
                i += 1;
                continue;
            }
            if OPTIONS_WITH_VALUE.contains(&arg.as_str()) {
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        if arg.starts_with('-') {
            if arg == "-a" {
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }

        if KNOWN_SUBCOMMANDS.contains(&arg.as_str()) {
            return Ok(raw_args.to_vec());
        }

        if let Some(_canon) =
            vetto::policy::defaults::canonical_agent_name(arg).filter(|&c| c != "custom")
        {
            let mut rewritten = raw_args.to_vec();
            rewritten.insert(i, "--".to_string());
            return Ok(rewritten);
        }

        break;
    }

    Ok(raw_args.to_vec())
}

fn run() -> Result<()> {
    // Activation funnel milestone (issue #27): first-ever run. Once-only via
    // marker file; silent unless telemetry is explicitly opted in.
    let _ = vetto::telemetry::record_funnel_milestone("install");

    // Check if invoked via vetto-bench executable alias
    let is_vetto_bench = std::env::args_os().next().is_some_and(|a| {
        std::path::Path::new(&a)
            .file_stem()
            .and_then(|s| s.to_str())
            .is_some_and(|stem| stem.eq_ignore_ascii_case("vetto-bench"))
    });

    if is_vetto_bench {
        let mut rewritten_args = vec!["vetto".to_string(), "bench".to_string()];
        rewritten_args.extend(std::env::args().skip(1));
        let cli = match cli::Cli::try_parse_from(&rewritten_args) {
            Ok(c) => c,
            Err(e) => e.exit(),
        };
        logger::init_flags(cli.quiet, cli.verbose);
        if let Some(cli::Command::Bench(ref bench_args)) = cli.command {
            return cli::bench::execute_bench(bench_args, &cli);
        }
    }

    let raw_args: Vec<String> = std::env::args().collect();
    let has_version = raw_args.iter().any(|a| a == "--version" || a == "-V");
    let has_json = raw_args.iter().any(|a| a == "--json");
    if has_version && has_json {
        let commit = option_env!("VETTO_GIT_HASH").unwrap_or("unknown");
        println!(
            "{}",
            serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "tier": fast_tier_detect(),
                "commit": commit,
            })
        );
        return Ok(());
    }

    // Fast path: if invoked via a toolchain shim name (e.g. `node`, `git`), dispatch immediately
    if let Some(binary) = shim::detect_argv0_shim() {
        let args: Vec<String> = std::env::args().skip(1).collect();
        return shim::run_cli(Some(binary), args);
    }

    // Apply a previously staged auto-update before doing anything else.
    // Skipped for shims (agent hot path), --version (observation only) and
    // the upgrade command itself (it manages its own lifecycle).
    let first_arg = raw_args.get(1).map(|s| s.as_str()).unwrap_or("");
    if first_arg != "upgrade" {
        match vetto::version::apply_pending_staged_update() {
            Ok(true) => println!("vetto: continuing with the updated binary on next invocation."),
            Ok(false) => {}
            Err(e) => eprintln!("vetto: warning: staged update not applied: {e:#}"),
        }
    }

    let processed_args = preprocess_cli_args(&raw_args)?;
    let args = cli::Cli::parse_from(&processed_args);
    logger::init_flags(args.quiet, args.verbose);
    if args.is_container {
        let env_info = vetto::doctor::detect_environment();
        if env_info.is_container {
            println!("true");
            std::process::exit(0);
        } else {
            println!("false");
            std::process::exit(1);
        }
    }

    if let Some(remote_url) = &args.remote {
        return remote::run_remote_client(
            remote_url,
            args.agent.clone(),
            args.policy.clone(),
            args.net.clone(),
        );
    }

    if args.multi {
        if args.command.is_some() {
            bail!("--multi cannot be combined with a subcommand");
        }
        let code = multi::run_cli(
            args.multi_manifest.clone(),
            args.agents.clone(),
            args.agent.clone(),
        )?;
        if code != 0 {
            std::process::exit(code);
        }
        return Ok(());
    }
    if args.multi_manifest.is_some() {
        bail!("--manifest is only valid with --multi or the `multi` subcommand");
    }

    match &args.command {
        Some(cli::Command::Mask(mask_args)) => cli::mask::run_mask(mask_args),
        Some(cli::Command::Enable(enable_args)) => cli::enable::run_enable(enable_args),
        Some(cli::Command::Disable(disable_args)) => cli::enable::run_disable(disable_args),
        Some(cli::Command::Run {
            command,
            args: run_args,
            benchmark,
        }) => {
            let mut cfg = RunConfig::from_cli(&args)?;
            if let Some(cmd) = command {
                if let Some(canon) =
                    vetto::policy::defaults::canonical_agent_name(cmd).filter(|&c| c != "custom")
                {
                    if let Ok(shims_dir) =
                        vetto::cli::hook::get_shims_dir(vetto::cli::hook::HookScope::Global)
                    {
                        let shim_path = shims_dir.join(canon);
                        let is_wrapped =
                            shim_path.exists() && vetto::shim::is_vetto_shim_content(&shim_path);
                        if !is_wrapped {
                            let target_agent =
                                if let Ok((bin, _)) = vetto::onboard::find_real_agent_binary(cmd) {
                                    bin
                                } else {
                                    canon.to_string()
                                };
                            let _ = vetto::cli::enable::enable_agent_silent(
                                &target_agent,
                                false,
                                vetto::cli::hook::HookScope::Global,
                            );
                        }
                    }
                }

                let mut full_cmd = vec![cmd.clone()];
                full_cmd.extend(run_args.clone());
                cfg.agent = full_cmd;
                if cfg.agent_preset.is_none() {
                    cfg.agent_preset = vetto::config::detect_agent_preset(&cfg.agent);
                }
                if matches!(cfg.net, NetMode::Off) && args.net.is_none() {
                    if let Some(ref agent) = cfg.agent_preset {
                        let domains = policy::presets::agent_network_allowlist(agent);
                        if !domains.is_empty() {
                            cfg.net = NetMode::Allowlist(domains);
                        }
                    }
                }
                if args.tui.is_none()
                    && cfg.tui == TuiMode::Statusline
                    && vetto::config::should_default_to_no_tui(
                        cfg.agent_preset.as_deref(),
                        &cfg.agent,
                    )
                {
                    cfg.tui = TuiMode::None;
                }
            } else {
                resolve_target_agent(&mut cfg, &args, run_args, true)?;
            }
            if *benchmark || args.benchmark {
                let bench_args = cli::bench::BenchArgs {
                    workspace: None,
                    timeout: cfg.session_timeout.map(|d| d.as_secs()).unwrap_or(180),
                    memory_mb: 4096,
                    net: args.net.clone(),
                    json: false,
                    instance_id: None,
                    profile: "swebench".to_string(),
                    env: vec![],
                    command: cfg.agent.clone(),
                };
                return cli::bench::execute_bench(&bench_args, &args);
            }
            supervise(cfg)
        }

        Some(cli::Command::Doctor {
            probe,
            check_agent,
            fix,
            preflight,
            json,
        }) => {
            if *preflight || *json {
                let report = vetto::doctor::preflight::run_preflight(*json)?;
                if report.verdict == vetto::doctor::preflight::PreflightVerdict::Fail {
                    std::process::exit(vetto::exit_codes::EXIT_FAIL_CLOSED);
                }
                Ok(())
            } else {
                doctor::run_doctor(*probe, check_agent.as_deref(), *fix)
            }
        }
        Some(cli::Command::Wizard(args)) => cli::wizard::run_wizard_cli(args),
        Some(cli::Command::Undo(undo_args)) => cli::undo::run_undo(undo_args),
        Some(cli::Command::Ephemeral(ephemeral_args)) => {
            let mut cfg = RunConfig::from_cli(&args)?;
            cfg.ephemeral = true;
            cfg.snapshot = true;
            cfg.ephemeral_auto_accept = ephemeral_args.yes;
            cfg.ephemeral_force_discard = ephemeral_args.discard;
            if !ephemeral_args.command.is_empty() {
                cfg.agent = ephemeral_args.command.clone();
                if cfg.agent_preset.is_none() {
                    cfg.agent_preset = vetto::config::detect_agent_preset(&cfg.agent);
                }
                if matches!(cfg.net, NetMode::Off) && args.net.is_none() {
                    if let Some(ref agent) = cfg.agent_preset {
                        let domains = policy::presets::agent_network_allowlist(agent);
                        if !domains.is_empty() {
                            cfg.net = NetMode::Allowlist(domains);
                        }
                    }
                }
            }
            if cfg.agent.is_empty() {
                let project = std::env::current_dir().context("getcwd")?;
                let detected = match vetto::onboard::detect_agent(&project) {
                    Ok(detected) => detected,
                    Err(e) => bail!(
                        "no AI agent detected in {} ({e})\n\n\
                         Usage: vetto ephemeral [OPTIONS] -- <command> [args...]",
                        project.display()
                    ),
                };
                eprintln!(
                    "vetto: zero-config auto-detected agent '{}' ({})",
                    detected.name, detected.reason
                );
                cfg.agent = detected.command;
                if cfg.agent_preset.is_none() {
                    cfg.agent_preset = Some(detected.name.to_string());
                }
                if !cfg.explicit_net && !detected.network_domains.is_empty() {
                    cfg.net = NetMode::Allowlist(detected.network_domains);
                }
            }
            supervise(cfg)
        }
        Some(cli::Command::Eval(eval_args)) => {
            let cfg = cli::eval::configure_eval_run(eval_args, &args)?;
            supervise(cfg)
        }
        Some(cli::Command::Bench(bench_args)) => cli::bench::execute_bench(bench_args, &args),
        Some(cli::Command::Diff(args)) => cli::diff::run_diff(args),
        Some(cli::Command::Pack(args)) => cli::bundle::run_pack(args),
        Some(cli::Command::Unpack(args)) => cli::bundle::run_unpack(args),
        Some(cli::Command::Watchdog(args)) => watchdog::run_cli(args),
        Some(cli::Command::Init { force, wizard }) => {
            if *wizard {
                cli::wizard::run_wizard_cli(&cli::wizard::WizardArgs {
                    path: ".".to_string(),
                    yes: false,
                    force: *force,
                    preset: None,
                    agent: None,
                })
            } else {
                init(*force, *wizard)
            }
        }
        Some(cli::Command::Profiles) => profiles(),
        Some(cli::Command::Hook { command }) => cli::hook::run_cli(command),
        Some(cli::Command::Registry { command }) => cli::registry::run_cli(command),
        Some(cli::Command::Plugin { command }) => cli::plugin::run_cli(command),
        Some(cli::Command::Mcp { command }) => match command {
            None | Some(cli::McpCommand::Serve) => mcp::run_stdio_server(),
            Some(cli::McpCommand::Wrap(args)) => mcp::run_wrap(args),
        },
        Some(cli::Command::Daemon { command }) => daemon::run_cli(command),
        Some(cli::Command::Serve { port }) => remote::run_serve(*port),
        Some(cli::Command::Shim { binary, args }) => shim::run_cli(binary.clone(), args.clone()),
        Some(cli::Command::ShellEnv {
            session_id,
            tier,
            profile,
        }) => cli::shell_env::run_shell_env(
            session_id.as_deref(),
            tier.as_deref(),
            profile.as_deref(),
        ),
        Some(cli::Command::Status { json }) => cli::status::run_cli(*json),
        Some(cli::Command::Tui { theme }) => {
            #[cfg(unix)]
            {
                vetto::tui::mission_control::run_dashboard(theme.as_deref())
            }
            #[cfg(not(unix))]
            {
                let _ = theme;
                eprintln!(
                    "TUI Mission Control Dashboard is currently supported on Unix platforms."
                );
                std::process::exit(1);
            }
        }
        Some(cli::Command::Kill(kill_args)) => cli::kill::run_cli(kill_args),
        Some(cli::Command::Fleet { command }) => cli::fleet::run_cli(command.clone()),
        Some(cli::Command::Profile { command }) => match command {
            cli::ProfileCommand::Save {
                name,
                agent,
                policy,
                net,
                profile,
            } => {
                let agent_vec = agent.as_ref().map(|a| vec![a.clone()]).unwrap_or_default();
                profile::save_profile(
                    name,
                    agent_vec,
                    policy.clone(),
                    net.clone(),
                    profile.clone(),
                )
            }
            cli::ProfileCommand::List { json } => profile::list_profiles(*json),
            cli::ProfileCommand::Rm { name } => profile::remove_profile(name),
        },
        Some(cli::Command::WhySlow { session, json }) => cli::why_slow::run_cli(session, *json),
        Some(cli::Command::Allow {
            target,
            preset,
            quota,
            read_only,
            net,
            cidr,
            global,
        }) => vetto::policy::edit::run_allow(
            target.as_deref(),
            preset.as_deref(),
            quota.as_deref(),
            *read_only,
            *net,
            *cidr,
            *global,
            args.policy.as_deref().map(Path::new),
        ),
        Some(cli::Command::Deny {
            target,
            preset,
            glob,
            global,
        }) => vetto::policy::edit::run_deny(
            target.as_deref(),
            preset.as_deref(),
            *glob,
            *global,
            args.policy.as_deref().map(Path::new),
        ),
        Some(cli::Command::Multi {
            manifest,
            agents,
            command,
        }) => {
            let code = multi::run_cli(manifest.clone(), agents.clone(), command.clone())?;
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }
        Some(cli::Command::Report {
            command: cli::ReportCommand::Compare { session1, session2 },
        }) => report::compare_reports(session1, session2),
        Some(cli::Command::Events {
            session,
            filter,
            follow,
            json,
            table: _,
        }) => events::run_events(session, filter.as_deref(), *follow, *json),
        Some(cli::Command::Audit {
            session_id,
            latest,
            since,
            agent,
            limit,
            query,
            json,
            recap,
            digest,
        }) => {
            if *digest {
                vetto::audit::run_digest(since.as_deref(), *json)
            } else {
                vetto::audit::run_audit_command(
                    session_id.as_deref(),
                    *latest,
                    since.as_deref(),
                    agent.as_deref(),
                    *limit,
                    query.as_deref(),
                    *json,
                    *recap,
                )
            }
        }
        Some(cli::Command::Digest { since, json }) => vetto::audit::run_digest(Some(since), *json),
        Some(cli::Command::DiffSessions {
            session_a,
            session_b,
            json,
        }) => {
            let reports_dir = args
                .report_dir
                .as_ref()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(".vetto/reports"));
            let diff =
                vetto::audit::diff_sessions::compare_sessions(session_a, session_b, &reports_dir)?;
            if *json {
                println!("{}", serde_json::to_string_pretty(&diff)?);
            } else {
                print!("{}", vetto::audit::diff_sessions::format_diff_text(&diff));
            }
            Ok(())
        }
        Some(cli::Command::Replay {
            session,
            speed,
            json,
        }) => events::run_replay(session, *speed, *json),
        Some(cli::Command::Rescue {
            adapter,
            root,
            json,
            command,
        }) => rescue::run_cli(adapter, root.as_deref(), *json, command),
        Some(cli::Command::Verify { json }) => {
            let net = vetto::config::parse_net_mode(args.net.as_deref().unwrap_or("off"))?;
            vetto::verify::run_cli(
                *json,
                &args.profile,
                args.policy.as_deref().map(PathBuf::from).as_deref(),
                &net,
            )
        }
        Some(cli::Command::VerifyNg { json, lint }) => {
            vetto::verify_ng::run_verify_ng(*json, *lint)
        }
        Some(cli::Command::Redteam { json }) => {
            let report = vetto::redteam::run_redteam_battery();
            if *json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("vetto redteam — isolation & containment attack battery\n");
                for r in &report.results {
                    println!("[{:?}] #{}: {} — {}", r.status, r.id, r.name, r.description);
                    println!("       detail: {}", r.details);
                }
                println!("\n{}", report.summary());
            }
            if !report.success {
                std::process::exit(1);
            }
            Ok(())
        }
        Some(cli::Command::Policy { command }) => match command {
            cli::PolicyCommand::Explain { json, why, limits } => {
                let net = vetto::config::parse_net_mode(args.net.as_deref().unwrap_or("off"))?;
                let effective_limits = limits.as_deref().or(args.limits.as_deref());
                let backend = sandbox::Backend::detect(net.clone(), false).ok();
                let tier = backend.as_ref().and_then(|b| b.tier());
                let backend_desc = backend.as_ref().map(|b| b.describe());
                let observes_seccomp = backend
                    .as_ref()
                    .map(|b| b.observes_seccomp())
                    .unwrap_or(false);
                vetto::policy::explain::run_cli(
                    *json,
                    why.as_deref(),
                    &args.profile,
                    args.policy.as_deref().map(PathBuf::from).as_deref(),
                    &net,
                    effective_limits,
                    tier,
                    backend_desc.as_deref(),
                    observes_seccomp,
                )
            }
            cli::PolicyCommand::Show { effective, json } => {
                let net = vetto::config::parse_net_mode(args.net.as_deref().unwrap_or("off"))?;
                let backend = sandbox::Backend::detect(net.clone(), false).ok();
                let tier = backend.as_ref().and_then(|b| b.tier());
                let backend_desc = backend.as_ref().map(|b| b.describe());
                let observes_seccomp = backend
                    .as_ref()
                    .map(|b| b.observes_seccomp())
                    .unwrap_or(false);
                vetto::policy::explain::run_show(
                    *effective,
                    *json,
                    &args.profile,
                    args.policy.as_deref().map(PathBuf::from).as_deref(),
                    &net,
                    tier,
                    backend_desc.as_deref(),
                    observes_seccomp,
                )
            }
            cli::PolicyCommand::Lint { strict } => {
                let tier = sandbox::Backend::detect(NetMode::Off, false)
                    .ok()
                    .and_then(|b| b.tier());
                vetto::policy::lint::run_cli(
                    *strict,
                    &args.profile,
                    args.policy.as_deref().map(PathBuf::from).as_deref(),
                    tier,
                )
            }
            cli::PolicyCommand::Import {
                from,
                path,
                claude,
                codex,
                output,
            } => {
                let home = std::env::var_os("HOME")
                    .or_else(|| std::env::var_os("USERPROFILE"))
                    .map(PathBuf::from)
                    .context(
                        "neither HOME nor USERPROFILE is set; vetto needs it to resolve paths",
                    )?;
                let effective_claude = claude.as_deref().or_else(|| {
                    if from.as_deref() == Some("claude") {
                        path.as_deref()
                    } else {
                        None
                    }
                });
                let effective_codex = codex.as_deref().or_else(|| {
                    if from.as_deref() == Some("codex") {
                        path.as_deref()
                    } else {
                        None
                    }
                });
                vetto::policy::import::run_import(
                    effective_claude,
                    effective_codex,
                    output,
                    &home,
                )?;
                println!("vetto: imported policy written to {}", output.display());
                Ok(())
            }
            cli::PolicyCommand::Sign { file, key, out } => {
                let sig_path =
                    policy::crypto::sign_policy_file(file, key.as_deref(), out.as_deref())?;
                println!(
                    "Successfully signed policy file {} -> {}",
                    file.display(),
                    sig_path.display()
                );
                Ok(())
            }
            cli::PolicyCommand::Verify { file, sig, key } => {
                policy::crypto::verify_policy_file(file, sig.as_deref(), key.as_deref())?;
                println!(
                    "Policy cryptographic verification SUCCESS for {}",
                    file.display()
                );
                Ok(())
            }
            cli::PolicyCommand::Use { name, force } => {
                let project = std::env::current_dir().context("getcwd")?;
                let path = policy::community::install_community_policy(name, &project, *force)?;
                println!(
                    "Installed community policy '{}' into {}",
                    name,
                    path.display()
                );
                Ok(())
            }
            cli::PolicyCommand::List => {
                println!("Available community policies in registry:");
                for (name, desc) in policy::community::list_community_policies() {
                    println!("  {:16} {}", name, desc);
                }
                Ok(())
            }
        },
        Some(cli::Command::Completions { shell }) => cli::print_completions(*shell),
        Some(cli::Command::Man) => cli::print_man(),
        Some(cli::Command::Upgrade {
            channel,
            check,
            dry_run,
            rollback,
        }) => {
            if *rollback {
                vetto::version::run_rollback(*dry_run)
            } else {
                vetto::version::run_upgrade(channel.as_deref(), *check, *dry_run)
            }
        }
        Some(cli::Command::Tour { non_interactive }) => vetto::tour::run_tour(*non_interactive),
        Some(cli::Command::ScanSecrets {
            path,
            json,
            max_size,
            max_files,
        }) => scan_secrets_cli(path.as_deref(), *json, *max_size, *max_files),
        Some(cli::Command::Watch { target, path, json }) => {
            vetto::watch::run_watch(target, path.as_deref(), *json)
        }
        Some(cli::Command::Rollback { session, target }) => {
            let res = vetto::rescue::snapshot::rollback_snapshot(session, target.as_deref())?;
            println!(
                "vetto rollback: successfully restored {} file(s) ({} bytes) to {}",
                res.files_restored,
                res.bytes_restored,
                res.target_dir.display()
            );
            Ok(())
        }
        Some(cli::Command::SshProxy { host, port }) => {
            #[cfg(target_os = "linux")]
            {
                sandbox::linux::net_relay::run_ssh_proxy(host, *port)
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (host, port);
                bail!("the SSH proxy helper is available on Linux only")
            }
        }
        Some(cli::Command::External(ext_args)) => {
            if let Some(prof_name) = ext_args.first() {
                let storage = profile::ProfileStorage::new()?;
                let prof = storage.load(prof_name)?;
                let mut cfg = RunConfig::from_cli(&args)?;
                cfg.agent = prof.agent;
                cfg.net = vetto::config::parse_net_mode(&prof.net)?;
                if cfg.policy_path.is_none() {
                    cfg.policy_path = prof.policy_path;
                }
                let _ = std::env::set_current_dir(&prof.cwd);
                supervise(cfg)
            } else {
                bail!("no command provided");
            }
        }
        None => {
            #[cfg(unix)]
            {
                use std::io::IsTerminal;
                if std::env::args().len() == 1 && std::io::stdout().is_terminal() {
                    return vetto::tui::mission_control::run_dashboard(None);
                }
            }

            let mut cfg = RunConfig::from_cli(&args)?;
            let mut profile_loaded = false;
            if cfg.agent.is_empty() && args.profile != "default" {
                if let Ok(storage) = profile::ProfileStorage::new() {
                    if let Ok(prof) = storage.load(&args.profile) {
                        cfg.agent = prof.agent;
                        cfg.net = vetto::config::parse_net_mode(&prof.net)?;
                        if cfg.policy_path.is_none() {
                            cfg.policy_path = prof.policy_path;
                        }
                        let _ = std::env::set_current_dir(&prof.cwd);
                        profile_loaded = true;
                    }
                }
            }
            if !profile_loaded {
                resolve_target_agent(&mut cfg, &args, &[], false)?;
            }
            if args.tui.is_none()
                && cfg.tui == TuiMode::Statusline
                && vetto::config::should_default_to_no_tui(cfg.agent_preset.as_deref(), &cfg.agent)
            {
                cfg.tui = TuiMode::None;
            }
            if args.benchmark {
                let bench_args = cli::bench::BenchArgs {
                    workspace: None,
                    timeout: cfg.session_timeout.map(|d| d.as_secs()).unwrap_or(180),
                    memory_mb: 4096,
                    net: args.net.clone(),
                    json: false,
                    instance_id: None,
                    profile: "swebench".to_string(),
                    env: vec![],
                    command: cfg.agent.clone(),
                };
                return cli::bench::execute_bench(&bench_args, &args);
            }
            supervise(cfg)
        }
    }
}

fn resolve_target_agent(
    cfg: &mut RunConfig,
    args: &cli::Cli,
    extra_args: &[String],
    is_run_subcommand: bool,
) -> Result<()> {
    if !cfg.agent.is_empty() && !cfg.agent[0].starts_with('-') {
        return Ok(());
    }

    if let Some(ref agent_name) = cfg.agent_preset.clone() {
        let (bin, _path) = vetto::onboard::find_real_agent_binary(agent_name)?;
        if cfg.agent.is_empty() {
            cfg.agent = vec![bin];
            cfg.agent.extend(extra_args.iter().cloned());
        } else {
            cfg.agent.insert(0, bin);
        }
        if !cfg.explicit_net {
            let domains = policy::presets::agent_network_allowlist(agent_name);
            if !domains.is_empty() {
                cfg.net = NetMode::Allowlist(domains);
            }
        }
        if args.tui.is_none()
            && cfg.tui == TuiMode::Statusline
            && vetto::config::should_default_to_no_tui(Some(agent_name.as_str()), &cfg.agent)
        {
            cfg.tui = TuiMode::None;
        }
        let canon = vetto::policy::defaults::canonical_agent_name(agent_name).unwrap_or(agent_name);
        if let Ok(shims_dir) = vetto::cli::hook::get_shims_dir(vetto::cli::hook::HookScope::Global)
        {
            let shim_path = shims_dir.join(canon);
            let is_wrapped = shim_path.exists() && vetto::shim::is_vetto_shim_content(&shim_path);
            if !is_wrapped {
                let _ = vetto::cli::enable::enable_agent_silent(
                    canon,
                    false,
                    vetto::cli::hook::HookScope::Global,
                );
            }
        }
        return Ok(());
    }

    let project = std::env::current_dir().context("getcwd")?;
    let detected = match vetto::onboard::detect_agent(&project) {
        Ok(detected) => detected,
        Err(e) => {
            let guidance = if is_run_subcommand {
                "1. `vetto enable` — wrap installed agents (e.g. `vetto enable claude`)\n  \
                 2. `vetto run <command>` — e.g. `vetto run claude` or `vetto run -- python agent.py`\n  \
                 3. `vetto doctor` — see what this kernel can enforce\n\n\
                 Docs: https://shleder.github.io/vetto/"
            } else {
                "1. `vetto enable` — wrap installed agents (e.g. `vetto enable claude`)\n  \
                 2. `vetto doctor` — see what this kernel can enforce\n  \
                 3. `vetto tour` — guided introduction\n  \
                 4. `vetto -- <command>` — sandbox any binary, e.g. `vetto -- python agent.py`\n\n\
                 Docs: https://shleder.github.io/vetto/"
            };
            bail!("{e}\n\nGet started:\n  {guidance}");
        }
    };
    eprintln!(
        "vetto: zero-config auto-detected agent '{}' ({})",
        detected.name, detected.reason
    );
    cfg.agent = detected.command;
    cfg.agent.extend(extra_args.iter().cloned());
    cfg.agent_preset = Some(detected.name.to_string());
    if !cfg.explicit_net && !detected.network_domains.is_empty() {
        cfg.net = NetMode::Allowlist(detected.network_domains);
    }
    if args.tui.is_none()
        && cfg.tui == TuiMode::Statusline
        && vetto::config::should_default_to_no_tui(cfg.agent_preset.as_deref(), &cfg.agent)
    {
        cfg.tui = TuiMode::None;
    }
    if let Ok(shims_dir) = vetto::cli::hook::get_shims_dir(vetto::cli::hook::HookScope::Global) {
        let shim_path = shims_dir.join(detected.name);
        let is_wrapped = shim_path.exists() && vetto::shim::is_vetto_shim_content(&shim_path);
        if !is_wrapped {
            let _ = vetto::cli::enable::enable_agent_silent(
                detected.name,
                false,
                vetto::cli::hook::HookScope::Global,
            );
        }
    }
    Ok(())
}

fn scan_secrets_cli(
    path: Option<&Path>,
    json: bool,
    max_size: Option<u64>,
    max_files: Option<usize>,
) -> Result<()> {
    let target = path.unwrap_or(Path::new("."));
    let mut options = policy::secretscan::SecretScanOptions::default();
    if let Some(ms) = max_size {
        options.max_file_size_bytes = ms;
    }
    if let Some(mf) = max_files {
        options.max_files = mf;
    }

    let result = if target.is_file() {
        let findings = policy::secretscan::scan_file(target, options.max_file_size_bytes);
        let bytes_scanned = std::fs::metadata(target).map(|m| m.len()).unwrap_or(0);
        policy::secretscan::SecretScanResult {
            findings,
            files_scanned: 1,
            bytes_scanned,
            timed_out: false,
        }
    } else {
        policy::secretscan::scan_directory(target, &options)
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!(
            "vetto scan-secrets: scanned {} file(s) ({} bytes)",
            result.files_scanned, result.bytes_scanned
        );
        if result.timed_out {
            println!("warning: scan hit time or file limit; partial results shown");
        }
        if result.is_clean() {
            println!("clean: no secrets detected");
        } else {
            println!("findings ({}):", result.findings.len());
            for f in &result.findings {
                println!(
                    "  - {}:{} [{}] {}",
                    f.path.display(),
                    f.line,
                    f.rule,
                    f.preview
                );
            }
        }
    }

    use std::io::Write;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();

    if !result.is_clean() {
        std::process::exit(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// supervise: a sandboxed agent session
// ---------------------------------------------------------------------------

fn supervise(mut cfg: RunConfig) -> Result<()> {
    if cfg.agent.is_empty() {
        bail!("no agent command provided; usage: vetto [OPTIONS] -- <command> [args...]");
    }

    // Resolve the agent command before sandbox detection so missing commands immediately return exit code 127
    let mut agent_cmd = cfg.agent.clone();
    agent_cmd[0] = resolve_in_path(&agent_cmd[0])?;

    let user_config = vetto::version::load_user_config().unwrap_or_default();
    if !cfg.benchmark {
        vetto::version::print_banner_if_update_available(
            env!("CARGO_PKG_VERSION"),
            &user_config.channel,
        );

        // Opt-in background staging (default off): when a newer release is known
        // and this is a direct-binary install, download+verify it now so a later
        // startup can apply it. Synchronous and cache-gated (24h), so at most one
        // download per day. Managed installs (npm/cargo/brew) are left to their
        // package managers.
        if vetto::version::auto_update_enabled(&user_config) {
            stage_update_if_available(&user_config);
        }
    }

    let backend_res = sandbox::Backend::detect_with_backend(
        cfg.net.clone(),
        cfg.observe_seccomp,
        cfg.backend.as_deref(),
    );
    let (mut backend_opt, tier) = match backend_res {
        Ok(b) => {
            let t = b.tier();
            (Some(Box::new(b)), t)
        }
        Err(e) => {
            if cfg.dry_run && cfg.backend.as_deref().unwrap_or("auto") == "auto" {
                // F6: dry-run never fabricates a tier — None renders as
                // "unknown (dry-run, NOT ENFORCED)", never "full".
                (None, None)
            } else {
                return Err(e);
            }
        }
    };

    let project = std::env::current_dir().context("getcwd")?;

    #[cfg(windows)]
    if cfg.windows_sandbox {
        let command_str = agent_cmd.join(" ");
        let spec = vetto::sandbox::windows::windows_sandbox::SandboxSpec {
            command: command_str,
            working_directory: Some(project.clone()),
            networking: !matches!(cfg.net, NetMode::Off),
            mapped_read_only: Vec::new(),
            mapped_read_write: vec![(project.clone(), project.clone())],
            memory_mb: None,
        };
        let temp_wsb = std::env::temp_dir().join(format!("vetto-{}.wsb", std::process::id()));
        vetto::sandbox::windows::windows_sandbox::write_config(&temp_wsb, &spec)?;
        println!(
            "vetto: launching Windows Sandbox (disposable VM) with config: {}",
            temp_wsb.display()
        );
        let mut child = vetto::sandbox::windows::windows_sandbox::launch_config(&temp_wsb, true)?;
        let status = child.wait()?;
        let _ = std::fs::remove_file(&temp_wsb);
        std::process::exit(status.code().unwrap_or(0));
    }
    #[cfg(not(windows))]
    if cfg.windows_sandbox {
        bail!("--windows-sandbox is only supported on Windows");
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .context(
            "neither $HOME nor %USERPROFILE% is set; vetto needs it to resolve policy variables",
        )?;

    let tier_for_policy = match tier {
        Some(t) => t,
        None => policy::Tier::Full, // macOS: no FS-ONLY enumeration semantics
    };
    let overrides = policy::loader::PolicyOverrides {
        deny_glob: cfg.deny_glob.clone(),
        git_guard: if cfg.git_guard { Some(true) } else { None },
        snapshot: if cfg.snapshot || cfg.ephemeral {
            Some(true)
        } else {
            None
        },
        auto_deny_secrets: if cfg.auto_deny_secrets {
            Some(true)
        } else {
            None
        },
        read_only_caches: if cfg.read_only_caches {
            Some(true)
        } else {
            None
        },
        shadow: if cfg.shadow { Some(true) } else { None },
        tmpfs_tmp: if cfg.tmpfs_tmp { Some(true) } else { None },
        net_quota: cfg.net_quota.clone(),
        ..policy::loader::PolicyOverrides::default()
    };
    let policy_options = policy::loader::PolicyLoadOptions {
        agent: cfg.agent_preset.clone(),
        preset: cfg.preset,
        include_project_policy: true,
        overrides,
        ..policy::loader::PolicyLoadOptions::default()
    };
    let mut pol = policy::loader::load_with_options(
        &cfg.profile,
        cfg.policy_path.as_deref(),
        &project,
        &home,
        tier_for_policy,
        &policy_options,
    )?;

    // Bridge policy network allowlist into runtime configuration if network was not explicitly set on CLI.
    if !cfg.explicit_net {
        if pol.deny_network || pol.network_mode.as_deref() == Some("off") {
            cfg.net = NetMode::Off;
        } else if !pol.network_allow.is_empty() {
            let mut domains = match &cfg.net {
                NetMode::Allowlist(existing) => existing.clone(),
                _ => Vec::new(),
            };
            domains.extend(pol.network_allow.clone());
            domains.sort();
            domains.dedup();
            if !domains.is_empty() {
                cfg.net = NetMode::Allowlist(domains);
            }
        }
        if backend_opt.is_some() {
            backend_opt = Some(Box::new(sandbox::Backend::detect_with_backend(
                cfg.net.clone(),
                cfg.observe_seccomp,
                cfg.backend.as_deref(),
            )?));
        }
    }

    if (pol.git_guard || cfg.git_guard) && !pol.allow_write.is_empty() {
        if let Some(branch) = policy::conditions::detect_git_branch(&project) {
            if branch == "main" || branch == "master" {
                bail!(
                    "git_guard: working copy is on branch '{branch}'; refusing to run with write permissions (create a feature branch, e.g. 'git checkout -b feature/...')"
                );
            }
        }
    }

    // Determine whether working directory is the user home directory or root
    let is_home_or_root = project == home
        || project.parent().is_none()
        || match (
            std::fs::canonicalize(&project),
            std::fs::canonicalize(&home),
        ) {
            (Ok(cp), Ok(ch)) => cp == ch || cp.parent().is_none(),
            _ => false,
        };

    // Only capture a project manifest if diff reporting or snapshotting is requested
    let diff_requested =
        (cfg.snapshot || cfg.ephemeral || !cfg.report_formats.is_empty()) && !cfg.benchmark;

    let diff_enabled = diff_requested && !is_home_or_root;

    let initial_manifest = if diff_enabled {
        // Fast stat-only capture with budget cap (1000 files, 150ms budget)
        report::diff_project::ProjectManifest::capture_fast(
            &project,
            1000,
            std::time::Duration::from_millis(150),
        )
    } else {
        report::diff_project::ProjectManifest::default()
    };
    let session_id = format!(
        "{}-{}",
        chrono::Utc::now().format("%Y%m%d-%H%M%S"),
        std::process::id()
    );

    if cfg.auto_branch || cfg.git_guard {
        if let Ok(Some(branch)) = crate::shim::ensure_session_branch(&project, &session_id) {
            eprintln!("vetto: git-guard: switched from main to session branch {branch} to protect default branch");
        }
    }

    if !cfg.benchmark
        && (pol.snapshot || cfg.snapshot || cfg.ephemeral || !cfg.agent.is_empty())
        && !is_home_or_root
    {
        match rescue::snapshot::create_snapshot(
            &project,
            &session_id,
            rescue::snapshot::DEFAULT_MAX_SNAPSHOT_SIZE,
        ) {
            Ok(meta) => {
                tracing::debug!(
                    "created snapshot for session {session_id} ({} files, {} bytes)",
                    meta.file_count,
                    meta.total_size_bytes
                );
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("exceeds maximum snapshot limit") {
                    tracing::debug!("vetto: snapshot skipped (project exceeds 50MB limit): {msg}");
                } else {
                    tracing::debug!("vetto: snapshot creation skipped: {e}");
                }
            }
        }
    }
    if tier == Some(policy::Tier::FsOnly) && !pol.deny_resolved.is_empty() {
        pol.warnings.push(
            "fs-only tier: display_only_deny paths cannot be masked with mount \
             overlays here. They are carved out of the read allowlist instead: \
             directory entry NAMES may stay visible (content stays denied), and \
             a file created directly at a write root cannot be read back in this \
             session because read is stripped from write-root rules to keep \
             carved-out secrets unreadable. Prefer the full tier if either \
             property matters for this session."
                .to_string(),
        );
    }
    if let Some(spec) = &cfg.limits_spec {
        policy::limits_spec::apply_cli(&mut pol, spec)?;
    }
    use std::io::Write;
    for w in &pol.warnings {
        eprint!("vetto: policy warning: {w}\r\n");
    }
    let _ = std::io::stderr().flush();
    let _ = std::io::stdout().flush();

    let bin_path = std::path::PathBuf::from(&agent_cmd[0]);
    if let Some(parent) = bin_path.parent() {
        if !pol.in_read_scope(&bin_path) {
            pol.allow_read.push(parent.to_path_buf());
        }
    }
    if pol.in_write_scope(std::path::Path::new(&agent_cmd[0])) {
        // If binary is in write scope (e.g. running from HOME), protect it automatically by excluding from writes
        pol.deny_write.push(bin_path.clone());
    }

    if cfg.dry_run {
        // F6: backend detection failed + dry-run => None tier renders as
        // "unknown (dry-run)", never a fabricated "full".
        let label = match tier {
            Some(_) => tier_label(tier),
            None => "unknown (dry-run)",
        };
        return dry_run(&cfg, &pol, &agent_cmd, label);
    }

    // Dry-run returned above, so detection succeeded here. Keep the
    // detected mechanics boxed only until the execution boundary takes
    // ownership of it at construction (no second detection below).
    let backend = match backend_opt {
        Some(b) => b,
        None => Box::new(sandbox::Backend::detect_with_backend(
            cfg.net.clone(),
            cfg.observe_seccomp,
            cfg.backend.as_deref(),
        )?),
    };
    tracing::debug!("backend: {}", backend.describe());

    if cfg.net.uses_relay()
        && (tier == Some(policy::Tier::FsOnly) || tier == Some(policy::Tier::Seccomp))
    {
        bail!(
            "network relay modes require Tier FULL (missing unprivileged user namespaces); \
             refusing to run (fail-closed)\n\
             action: enable unprivileged userns (`sysctl -w kernel.unprivileged_userns_clone=1`) or re-run with `--net=off`; run `vetto doctor` for the full capability picture"
        );
    }

    #[cfg(not(target_os = "linux"))]
    if cfg.git_ssh {
        bail!(
            "--git-ssh is available on Linux only\n\
             action: use standard HTTPS git remotes (`--net=allowlist:github.com`) on this OS; run `vetto doctor` for supported network features"
        );
    }

    let mut env_extra: HashMap<String, String> = {
        let mut env_extra = HashMap::new();
        env_extra.insert("VETTO_SANDBOX".into(), "1".into());
        env_extra.insert("VETTO_SANDBOXED".into(), "1".into());
        env_extra.insert("VETTO_SESSION_ID".into(), session_id.clone());
        env_extra.insert("VETTO_TIER".into(), tier_label(tier).into());
        env_extra.insert("VETTO_PROFILE".into(), pol.name.clone());
        env_extra.insert("VETTO_VERSION".into(), env!("CARGO_PKG_VERSION").into());
        #[cfg(target_os = "linux")]
        {
            if cfg.net.uses_relay() {
                for (k, v) in sandbox::linux::net_relay::build_proxy_env(
                    sandbox::linux::net_relay::RELAY_PORT_BASE,
                ) {
                    env_extra.insert(k, v);
                }
            }
            if cfg.git_ssh {
                let exe =
                    std::env::current_exe().context("resolve vetto executable for SSH helper")?;
                env_extra.insert(
                    "GIT_SSH_COMMAND".into(),
                    sandbox::linux::net_relay::build_git_ssh_command(&exe),
                );
            }
        }
        env_extra
    };

    if pol.git_guard || cfg.git_guard {
        env_extra.insert("VETTO_GIT_GUARD".into(), "1".into());
    }
    // Stage 3C: per-run production identity is owned by the execution
    // boundary (Unprepared → prepare → spawn). The boundary mints the nonce,
    // freezes argv/cwd/env/policy/net/stdio, prepares the Stage 3B backend
    // against the frozen bundle, and spawns the real child. `env_extra` here
    // only carries pre-freeze inputs; nothing is reconstructed after prepare.

    #[cfg(not(unix))]
    if !pol.secret_proxies.is_empty() {
        bail!(
            "secrets.proxy requires the Unix credential broker, which is not supported on this platform: \
             refusing to run rather than leak broker-managed secrets ({}) into the agent environment. \
             Remove [secrets] proxy entries or run on Linux/macOS",
            pol.secret_proxies.join(", ")
        );
    }

    #[cfg(unix)]
    let cred_sock = if !pol.secret_proxies.is_empty() {
        let sock = std::env::temp_dir().join(format!("vetto-cred-{}.sock", std::process::id()));
        env_extra.insert(
            "VETTO_CRED_BROKER_SOCK".into(),
            sock.to_string_lossy().to_string(),
        );
        Some(sock)
    } else {
        None
    };

    // stdio plumbing, owned by main and closed here after spawn.
    #[cfg(unix)]
    let mut pty_master: Option<OwnedFd> = None;
    #[cfg(unix)]
    let mut pty_slave: Option<OwnedFd> = None;
    #[cfg(unix)]
    let mut stdout_r: Option<OwnedFd> = None;
    #[cfg(unix)]
    let mut stdout_w: Option<OwnedFd> = None;
    #[cfg(unix)]
    let mut stderr_r: Option<OwnedFd> = None;
    #[cfg(unix)]
    let mut stderr_w: Option<OwnedFd> = None;
    #[cfg(unix)]
    let stdio = match cfg.tui {
        TuiMode::Statusline => {
            let (rows, cols) = crossterm::terminal::size().unwrap_or((24, 80));
            let p = pty::Pty::open(rows.saturating_sub(1).max(1), cols)?;
            let pty::Pty { master, slave } = p;
            let slave_fd = slave.as_raw_fd();
            pty_master = Some(master);
            pty_slave = Some(slave);
            sandbox::StdioMode::Pty { slave_fd }
        }
        TuiMode::Full => {
            let (r1, w1) = pipe2()?;
            let (r2, w2) = pipe2()?;
            let stdio = sandbox::StdioMode::Captured {
                stdout_w: w1.as_raw_fd(),
                stderr_w: w2.as_raw_fd(),
            };
            stdout_r = Some(r1);
            stdout_w = Some(w1);
            stderr_r = Some(r2);
            stderr_w = Some(w2);
            stdio
        }
        TuiMode::None => {
            let is_interactive = vetto::config::is_interactive_agent_command(
                cfg.agent_preset.as_deref(),
                &cfg.agent,
            );
            if !is_interactive && cfg.mask_secrets {
                let (r1, w1) = pipe2()?;
                let (r2, w2) = pipe2()?;
                let stdio = sandbox::StdioMode::Captured {
                    stdout_w: w1.as_raw_fd(),
                    stderr_w: w2.as_raw_fd(),
                };
                stdout_r = Some(r1);
                stdout_w = Some(w1);
                stderr_r = Some(r2);
                stderr_w = Some(w2);
                stdio
            } else {
                sandbox::StdioMode::Inherit
            }
        }
    };
    #[cfg(windows)]
    let stdio = {
        if cfg.tui != TuiMode::None {
            bail!(
                "the Windows backend currently requires --tui=none or --ci\n\
                 action: re-run with `--tui=none` or `--ci`"
            );
        }
        sandbox::StdioMode::Inherit
    };

    // Stage 3C authoritative boundary: frozen inputs → prepared Stage 3B
    // backend → the single real spawn. The SAME execution object owns frozen
    // policy/identity/nonce, backend state, child spawn (Full namespaces +
    // mounts + relay + PTY through the legacy mechanics it owns), host
    // verification, timeout, cleanup and the final report. Fail-closed: a
    // failed preparation never spawns (no fallback). The previously
    // detected `backend` box below is moved into the boundary here (its
    // earlier borrow for `describe` ended at the trace line above).
    let frozen_timeout = cfg.session_timeout;
    let unprepared = sandbox::production::UnpreparedProductionExecution::new(
        *backend,
        pol,
        agent_cmd.clone(),
        project.clone(),
        env_extra,
        cfg.net.clone(),
        frozen_timeout,
        stdio,
        sandbox::production::PROD_SCENARIO_ID.to_string(),
    );
    let prepared = unprepared.prepare()?;
    // Supervisor installation values come from the same verified contract as spawn.
    let contract = prepared.contract().clone();
    let production = contract
        .production
        .as_ref()
        .expect("validated production contract");
    let pol = production.installation_policy.clone();

    // Pre-spawn boundary verification through the sealed contract production
    // boundary. The exact sealed contract about to be spawned is verified;
    // any leaks or digest tampering fails closed before spawn.
    let verify_outcome = if cfg.verify_preflight {
        let report = vetto::verify::preflight_contract(prepared.contract())?;
        eprintln!("vetto: verify: {}", report.summary());
        if report.leaks() > 0 {
            if cfg.shadow {
                eprintln!(
                    "vetto: shadow: would deny session startup due to boundary verification leaks (shadow mode active; continuing)"
                );
            } else {
                bail!(
                    "--verify: boundary verification failed (detected filesystem or network leaks); \
                     refusing to start the agent (fail-closed)\n\
                     action: review the leak findings above and adjust your policy grants; run `vetto doctor --probe`"
                );
            }
        }
        Some(report)
    } else {
        None
    };

    let started = std::time::Instant::now();
    // `take_*`/`&mut handle` are `cfg`-gated (Linux/unix): `mut` is dead on
    // Windows, required elsewhere. `allow` keeps one spelling, not two.
    #[allow(unused_mut)]
    let mut spawned = prepared.spawn()?;

    // Close main's duplicates of the child-side stdio fds so EOF semantics
    // work: only the sandbox holds the write ends / slave now.
    #[cfg(unix)]
    drop(pty_slave.take());
    #[cfg(unix)]
    drop(stdout_w.take());
    #[cfg(unix)]
    drop(stderr_w.take());

    // ---- Phase 2: threads now allowed -------------------------------------
    let bus = EventBus::new();
    let root_pid = spawned.handle.root_pid;

    #[cfg(target_os = "linux")]
    let relay_port = spawned.relay_port();
    #[cfg(not(target_os = "linux"))]
    let relay_port: Option<u16> = None;

    #[cfg(unix)]
    let mut out_reader: Option<sandbox::production::AsyncPipeReader> = None;
    #[cfg(unix)]
    let mut err_reader: Option<sandbox::production::AsyncPipeReader> = None;
    #[cfg(unix)]
    if cfg.tui == TuiMode::None && cfg.mask_secrets {
        if let Some(r1) = stdout_r.take() {
            out_reader = Some(sandbox::production::AsyncPipeReader::spawn(
                r1,
                sandbox::production::PROD_MAX_STDIO,
                std::time::Duration::from_millis(200),
            ));
        }
        if let Some(r2) = stderr_r.take() {
            err_reader = Some(sandbox::production::AsyncPipeReader::spawn(
                r2,
                sandbox::production::PROD_MAX_STDIO,
                std::time::Duration::from_millis(200),
            ));
        }
    }

    if !cfg.benchmark {
        if let Ok(reg) = cli::status::SessionRegistry::new() {
            let agent_name = cfg.agent_preset.as_deref().unwrap_or_else(|| &cfg.agent[0]);
            let _ = reg.register(
                &session_id,
                root_pid,
                agent_name,
                &pol.name,
                tier_label(tier),
                &project,
            );
        }
    }

    if cfg.system_log || pol.system_log {
        logger::system_log::SystemLogSink::spawn(&bus);
    }

    if cfg.auto_timeout_requested {
        if let Some(t) = cfg.session_timeout {
            bus.publish(Event::Notice {
                ts: events::types::now(),
                message: format!("auto-timeout selected: {}", format_duration(t)),
            });
        } else {
            bus.publish(Event::Notice {
                ts: events::types::now(),
                message: "no past history found for agent; running without timeout".to_string(),
            });
        }
    }

    // Subscribe the sinks FIRST so nothing (incl. SessionStarted) is missed.
    let default_log_path = home
        .join(".vetto")
        .join("logs")
        .join(format!("session-{root_pid}.jsonl"));
    if !cfg.benchmark {
        if let Some(parent) = default_log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        logger::jsonl::JsonlSink::spawn(&bus, default_log_path.clone());
    }

    let jsonl_path = cfg.jsonl_path.clone();
    if let Some(path) = &jsonl_path {
        if path != &default_log_path {
            logger::jsonl::JsonlSink::spawn(&bus, path.clone());
        }
    }
    if cfg.oslog || pol.oslog {
        logger::oslog::OsLogSink::spawn(&bus);
    }
    let stats = report::stats::StatsCollector::spawn(&bus);

    let otel_session = std::sync::Arc::new(vetto::telemetry::TelemetrySession::start(
        cfg.otel,
        cfg.otel_endpoint.as_deref(),
        &format!("session-{root_pid}"),
        tier_label(tier),
        &cfg.net.label(),
        &pol.name,
    )?);
    vetto::telemetry::spawn_telemetry_subscriber(&bus, otel_session.clone());

    if cfg.notify {
        vetto::notify::DesktopNotifier::spawn(&bus, true);
    }
    bus.publish(Event::SessionStarted {
        ts: events::types::now(),
        pid: root_pid,
        tier: tier_label(tier).to_string(),
        net_mode: cfg.net.label(),
        profile: pol.name.clone(),
        shadow: pol.shadow,
    });

    #[cfg(unix)]
    let mut _cred_broker_handle = None;
    #[cfg(unix)]
    if let Some(sock) = cred_sock {
        let mut host_secrets = HashMap::new();
        for key in &pol.secret_proxies {
            if let Ok(val) = std::env::var(key) {
                host_secrets.insert(key.clone(), val);
            }
        }
        let allowlist_domains = match &production.net {
            vetto::config::NetMode::Allowlist(d) => d.clone(),
            vetto::config::NetMode::Strict(rules) => {
                rules.iter().map(|r| r.domain.clone()).collect()
            }
            vetto::config::NetMode::Off | vetto::config::NetMode::Ask => Vec::new(),
        };
        let broker_config = vetto::cred_broker::CredBrokerConfig {
            proxy_secrets: pol.secret_proxies.clone(),
            allowlist_domains,
        };
        match vetto::cred_broker::spawn_credential_broker(
            sock,
            broker_config,
            host_secrets,
            bus.clone(),
        ) {
            Ok(h) => _cred_broker_handle = Some(h),
            Err(e) => eprintln!("vetto: warning: failed to spawn credential broker: {e}"),
        }
    }

    match tier {
        Some(policy::Tier::Full) => {
            for d in &pol.deny_resolved {
                bus.publish(Event::SecretMasked {
                    ts: events::types::now(),
                    path: d.path.display().to_string(),
                });
            }
        }
        Some(policy::Tier::Seccomp) => {
            bus.publish(Event::Notice {
                ts: events::types::now(),
                message: "WARNING: Running in Tier SECCOMP (micro-mode). Filesystem isolation is NOT enforced on this system because Landlock is unavailable. Only syscall filtering and network blocking are active."
                    .to_string(),
            });
        }
        _ => {
            bus.publish(Event::Notice {
                ts: events::types::now(),
                message: "fs-only/macos tier: intra-project secrets are masked \
                          by load-time policy rules, not mount overlays"
                    .to_string(),
            });
            if tier == Some(policy::Tier::FsOnly) && !pol.deny_resolved.is_empty() {
                bus.publish(Event::Notice {
                    ts: events::types::now(),
                    message: "fs-only tier: denied secret paths are allowlist-carved, \
                              not masked — entry names may be visible and files created \
                              directly at a write root cannot be read back this session"
                        .to_string(),
                });
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(fd) = spawned.take_broker_ctrl_fd() {
            let broker_policy = match &production.net {
                NetMode::Allowlist(d) => {
                    sandbox::linux::net_relay::BrokerPolicy::Allowlist(d.clone())
                }
                NetMode::Strict(rules) => {
                    sandbox::linux::net_relay::BrokerPolicy::Strict(rules.clone())
                }
                NetMode::Ask => {
                    sandbox::linux::net_relay::BrokerPolicy::Ask(pol.network_allow.clone())
                }
                NetMode::Off => sandbox::linux::net_relay::BrokerPolicy::Allowlist(Vec::new()),
            };
            let mut broker_config = sandbox::linux::net_relay::BrokerConfig::from(broker_policy);
            broker_config.allow_cidr = pol.allow_cidr.clone();
            broker_config.quotas = pol.net_quota.clone();
            broker_config.policy_path = cfg.policy_path.clone();
            broker_config.block_doh = cfg.block_doh;
            sandbox::linux::net_relay::spawn_broker(fd.into_raw_fd(), broker_config, bus.clone());
        }
        let _ = relay_port;
        if let Some(fd) = spawned.take_notif_listener() {
            let notifier_policy = std::sync::Arc::new(pol.clone());
            if let Some(notify_cfg) = &pol.seccomp_notify {
                if notify_cfg.enabled {
                    sandbox::linux::observe_seccomp::spawn_enforcement_supervisor(
                        fd,
                        bus.clone(),
                        notify_cfg.clone(),
                        notifier_policy,
                        project.clone(),
                    );
                    bus.publish(Event::Notice {
                        ts: events::types::now(),
                        message: "seccomp user-notify supervisor enforcement active (default deny)"
                            .to_string(),
                    });
                } else {
                    sandbox::linux::observe_seccomp::spawn_notifier(
                        fd,
                        bus.clone(),
                        notifier_policy,
                        project.clone(),
                    );
                }
            } else {
                sandbox::linux::observe_seccomp::spawn_notifier(
                    fd,
                    bus.clone(),
                    notifier_policy,
                    project.clone(),
                );
                bus.publish(Event::Notice {
                    ts: events::types::now(),
                    message: "blocked-attempt observation via --observe-seccomp \
                              (BEST-EFFORT; paths are racy; Landlock stays the sole enforcer)"
                        .to_string(),
                });
            }
        }
        let audit_reason = sandbox::linux::audit_reader::spawn_reader_if_available(bus.clone());
        if !cfg.observe_seccomp {
            if let Some(reason) = audit_reason {
                bus.publish(Event::Notice {
                    ts: events::types::now(),
                    message: format!(
                        "blocked-attempt feed unavailable ({reason}). Enforcement is ACTIVE."
                    ),
                });
            }
        }
        sandbox::linux::visibility::spawn_poller(bus.clone(), vec![root_pid]);
    }
    #[cfg(target_os = "macos")]
    {
        let _ = &relay_port;
        if let Some(reason) = sandbox::macos::fsevents::spawn_watcher_if_available(&bus) {
            bus.publish(Event::Notice {
                ts: events::types::now(),
                message: reason,
            });
        }
    }
    // Windows has no relay/poller/fsevents branch: the binding above is
    // `None` by construction; silence it with one spelling, not `cfg` soup.
    #[cfg(target_os = "windows")]
    let _ = &relay_port;

    install_sigint_forwarder(root_pid, tier);

    // ---- Phase 3: run the UI / wait ---------------------------------------
    // The SAME `SpawnedProductionExecution` owns the wait in every mode:
    // interactive dashboards borrow `spawned.handle` for their loops, then
    // `finish` runs the nonce-targeted tree sweep + teardown and returns the
    // typed result. Headless mode goes through `wait_collect` (proven killer
    // path with the frozen timeout). `finish` is the ONLY way to obtain a
    // `ProductionResult`: the sweep cannot be skipped.
    #[cfg(unix)]
    let (exit_code, timed_out) = match cfg.tui {
        TuiMode::Statusline => {
            let master = pty_master.expect("statusline wires a pty");
            let (code, timed_out) = tui::statusline::run(
                &bus,
                &master,
                &mut spawned.handle,
                tier_label(tier),
                &cfg.net.label(),
                &pol.name,
                cfg.session_timeout,
            );
            let result = spawned.finish(Some(code), timed_out);
            if timed_out {
                bus.publish(Event::SessionTimeout {
                    ts: events::types::now(),
                });
            }
            eprintln!(
                "vetto: enforcement {}",
                result.report.render_deterministic()
            );
            (result.exit_code.unwrap_or(code), result.timed_out)
        }
        TuiMode::Full => {
            let out = stdout_r.expect("full mode wires stdout pipe");
            let err = stderr_r.expect("full mode wires stderr pipe");
            let (code, timed_out) = tui::full::run(
                &bus,
                out,
                err,
                &mut spawned.handle,
                tier_label(tier),
                &cfg.net.label(),
                &pol.name,
                cfg.session_timeout,
            );
            let result = spawned.finish(Some(code), timed_out);
            if timed_out {
                bus.publish(Event::SessionTimeout {
                    ts: events::types::now(),
                });
            }
            eprintln!(
                "vetto: enforcement {}",
                result.report.render_deterministic()
            );
            (result.exit_code.unwrap_or(code), result.timed_out)
        }
        TuiMode::None => {
            // The frozen timeout is `Some` exactly when `session_timeout`
            // is set in this mode, so `wait_collect` enforces the identical
            // proven deadline (deadline → try_wait → terminate → bounded
            // re-wait → drain → nonce sweep → typed report). Emit the
            // SessionTimeout event when it fired.
            let result = spawned.wait_collect();
            if result.timed_out && cfg.session_timeout.is_some() {
                eprintln!(
                    "vetto: session timeout ({}) reached; terminating the sandbox",
                    format_duration(cfg.session_timeout.unwrap_or_default())
                );
                bus.publish(Event::SessionTimeout {
                    ts: events::types::now(),
                });
            }
            eprintln!(
                "vetto: enforcement {}",
                result.report.render_deterministic()
            );
            if let Some(h) = out_reader.take() {
                h.notify_child_exited();
                let out = h.join();
                if !out.is_empty() {
                    use std::io::Write;
                    let mut redactor = pty::AnsiRedactor::new();
                    let redacted = redactor.redact_chunk(&out);
                    let flushed = redactor.flush();
                    let mut dest = std::io::stdout();
                    let _ = dest.write_all(&redacted);
                    if !flushed.is_empty() {
                        let _ = dest.write_all(&flushed);
                    }
                    let _ = dest.flush();
                }
            }
            if let Some(h) = err_reader.take() {
                h.notify_child_exited();
                let err = h.join();
                if !err.is_empty() {
                    use std::io::Write;
                    let mut redactor = pty::AnsiRedactor::new();
                    let redacted = redactor.redact_chunk(&err);
                    let flushed = redactor.flush();
                    let mut dest = std::io::stderr();
                    let _ = dest.write_all(&redacted);
                    if !flushed.is_empty() {
                        let _ = dest.write_all(&flushed);
                    }
                    let _ = dest.flush();
                }
            }
            (result.exit_code.unwrap_or(-1), result.timed_out)
        }
    };
    #[cfg(windows)]
    let (exit_code, timed_out) = {
        // Windows has no TUI in-process supervisor (rejected at startup
        // above): drive the headless wait through the same boundary.
        let result = spawned.wait_collect();
        eprintln!(
            "vetto: enforcement {}",
            result.report.render_deterministic()
        );
        (result.exit_code.unwrap_or(-1), result.timed_out)
    };
    #[cfg(unix)]
    CHILD_TARGET.store(0, std::sync::atomic::Ordering::SeqCst);

    let duration_secs = started.elapsed().as_secs();
    bus.publish(Event::SessionEnded {
        ts: events::types::now(),
        exit_code,
        duration_secs,
    });
    std::thread::sleep(std::time::Duration::from_millis(100)); // let sinks drain

    let snap = stats.snapshot();
    let _ = vetto::telemetry::send_session_telemetry(&snap, tier_label(tier));
    // Activation funnel milestone (issue #27): first supervised session done.
    let _ = vetto::telemetry::record_funnel_milestone("first_session");
    let diff = if diff_enabled {
        report::diff_project::ProjectDiff::compute(&initial_manifest, &project)
    } else {
        report::diff_project::ProjectDiff::default()
    };
    if !diff.is_empty() {
        bus.publish(Event::Notice {
            ts: events::types::now(),
            message: diff.summary(),
        });
        eprintln!("vetto: {}", diff.summary());
    }

    bus.publish(Event::Notice {
        ts: events::types::now(),
        message: format!("I/O summary: {}", snap.io_summary()),
    });
    let mut primary_report = None;
    if !cfg.report_formats.is_empty() {
        let report_options = report::ReportOptions {
            report_dir: cfg.report_dir.clone(),
            auto_cleanup: cfg.report_auto_cleanup,
            retention: cfg.report_retention,
            max_age_secs: cfg.report_max_age_secs,
        };
        for p in report::write_reports_with_options(&snap, &cfg.report_formats, &report_options)? {
            eprintln!("vetto: report written: {}", p.display());
            if primary_report.is_none() {
                primary_report = Some(p);
            }
        }
    }
    if let Ok(reg) = cli::status::SessionRegistry::new() {
        reg.unregister(&session_id);
    }
    if !cfg.benchmark {
        let agent_name = cfg
            .agent_preset
            .clone()
            .unwrap_or_else(|| cfg.agent[0].clone());
        let _ = history::append_session_history(
            &project,
            &history::SessionHistoryRecord {
                agent: agent_name,
                duration_secs,
                ts: events::types::now().to_rfc3339(),
                exit_code,
            },
        );
    }

    let blocked_file_total: u64 = snap.blocked_attempts.iter().map(|b| b.count).sum();
    let blocked_network_total = snap
        .net_requests
        .iter()
        .filter(|request| !request.allowed)
        .count() as u64;
    let blocked_total = blocked_file_total.saturating_add(blocked_network_total);

    let blocked_threshold_reached = match cfg.fail_on_block {
        Some(threshold) => blocked_total >= threshold,
        None => false,
    };
    if timed_out {
        // Mirror GNU timeout(1): 124 means "we killed it at the deadline".
        eprintln!("vetto: session timed out; killed at the deadline (exit 124)");
    }
    if let Some(threshold) = cfg.fail_on_block {
        if blocked_total >= threshold {
            if cfg.shadow {
                eprintln!(
                    "vetto: shadow: would deny/fail session on block threshold (blocked={} threshold={}) (shadow mode active; exit code unchanged)",
                    blocked_total, threshold
                );
            } else {
                eprintln!(
                    "vetto: fail-on-block threshold reached (blocked={} threshold={})",
                    blocked_total, threshold
                );
            }
        }
    }

    let evidence_channel_intact = vetto::sandbox::is_evidence_channel_intact();
    let verdict = vetto::audit::VerdictEngine::evaluate(
        &contract,
        blocked_total as usize,
        0, // unauthorized writes
        0, // surviving zombies
        evidence_channel_intact,
        exit_code,
    );

    let mut code = exit_codes::map_session_exit_code(
        exit_code,
        timed_out,
        blocked_threshold_reached && !cfg.shadow,
    );

    if !cfg.shadow
        && !timed_out
        && (verdict.exit_code == exit_codes::EXIT_FAIL_CLOSED
            || verdict.status != vetto::audit::VerdictStatus::Pass
            || blocked_total > 0)
    {
        code = exit_codes::EXIT_FAIL_CLOSED;
    }
    if cfg.ci {
        println!(
            "{}",
            serde_json::json!({
                "vetto_ci": {
                    "exit_code": exit_code,
                    "final_exit_code": code,
                    "duration_secs": duration_secs,
                    "tier": tier_label(tier),
                    "net": cfg.net.label(),
                    "profile": pol.name,
                    "blocked_attempts": blocked_total,
                    "blocked_file_attempts": blocked_file_total,
                    "network_denied": blocked_network_total,
                    "bytes_read": snap.bytes_read,
                    "bytes_written": snap.bytes_written,
                    "read_ops": snap.read_ops,
                    "write_ops": snap.write_ops,
                    "files_modified": diff.total_changed(),
                    "events_total": snap.events_total,
                    "verify": verify_outcome
                        .map(|report| report.status().to_string())
                        .unwrap_or_else(|| "off".to_string()),
                    "timed_out": timed_out,
                    "sanitizer": "BEST-EFFORT",
                }
            })
        );
    } else {
        eprintln!(
            "vetto: agent exited {} after {}s (blocked={}, events={}, I/O: {}, tier={}{})",
            exit_code,
            duration_secs,
            blocked_total,
            snap.events_total,
            snap.io_summary(),
            tier_label(tier),
            if timed_out { ", TIMEOUT" } else { "" },
        );
        if let Some(hint) = exit_codes::recap_hint(code, blocked_total, timed_out) {
            eprintln!("vetto: recap: {hint}");
        }
        // Session security recap: top denied paths, egress split, intent —
        // from the in-memory snapshot, zero extra I/O. Silent on clean runs.
        if !cfg.ci {
            let mut top_denied: Vec<(String, u64)> = snap
                .blocked_attempts
                .iter()
                .map(|b| (b.path.clone(), b.count))
                .collect();
            top_denied.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
            let mut egress_map: std::collections::BTreeMap<String, u64> =
                std::collections::BTreeMap::new();
            let mut egress_allowed: Vec<String> = Vec::new();
            for r in &snap.net_requests {
                if r.allowed {
                    let h = format!("{}:{}", r.host, r.port);
                    if !egress_allowed.contains(&h) {
                        egress_allowed.push(h);
                    }
                } else {
                    *egress_map
                        .entry(format!("{}:{}", r.host, r.port))
                        .or_insert(0) += 1;
                }
            }
            let mut egress_denied: Vec<(String, u64)> = egress_map.into_iter().collect();
            egress_denied.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
            let recap_input = vetto::audit::SessionRecapInput {
                exit_code,
                duration_secs,
                events_total: snap.events_total,
                top_denied,
                denials_total: blocked_total,
                egress_denied,
                egress_allowed,
                op_counts: snap.op_counts.clone(),
                files_changed: diff.total_changed(),
                verify_status: verify_outcome
                    .as_ref()
                    .map(|report| report.status().to_string())
                    .unwrap_or_else(|| "off".to_string()),
            };
            if let Some(lines) = vetto::audit::format_session_recap(&recap_input) {
                for line in lines {
                    eprintln!("vetto: recap: {line}");
                }
            }
        }
    }

    otel_session.finish(code);

    let history_record = vetto::audit::AuditRecord {
        ts: events::types::now(),
        session_id: format!("session-{root_pid}"),
        agent: cfg
            .agent_preset
            .clone()
            .unwrap_or_else(|| cfg.agent.first().cloned().unwrap_or_default()),
        command: Some(cfg.agent.join(" ")),
        profile: pol.name.clone(),
        policy_path: cfg.policy_path.as_ref().map(|p| p.display().to_string()),
        exit_code: code,
        duration_secs,
        tier: tier_label(tier).to_string(),
        net_mode: cfg.net.label(),
        blocked_count: blocked_total,
        events_total: snap.events_total,
        report_path: primary_report.as_ref().map(|p| p.display().to_string()),
        log_path: Some(default_log_path.display().to_string()),
    };
    if !cfg.benchmark {
        let _ = vetto::audit::record_session_history(&history_record);
    }

    if cfg.ephemeral {
        rescue::ephemeral::handle_ephemeral_completion(
            &session_id,
            &project,
            exit_code,
            cfg.ephemeral_auto_accept,
            cfg.ephemeral_force_discard,
        )?;
    }

    std::process::exit(code);
}

fn tier_label(tier: Option<policy::Tier>) -> &'static str {
    match tier {
        Some(policy::Tier::Full) => policy::Tier::Full.label(),
        Some(policy::Tier::FsOnly) => policy::Tier::FsOnly.label(),
        Some(policy::Tier::Seccomp) => policy::Tier::Seccomp.label(),
        None => "macos-seatbelt",
    }
}

/// Unix helper: proven killer path for a borrowed handle (interactive
/// supervisor branches that wait outside the boundary). Unused on Windows.
#[cfg(unix)]
#[allow(dead_code)]
fn wait_with_timeout(
    handle: &mut sandbox::SandboxHandle,
    bus: &EventBus,
    limit: std::time::Duration,
) -> (i32, bool) {
    let deadline = std::time::Instant::now() + limit;
    let (outcome, code) = vetto::verify_ng::killer::kill_on_deadline_with(
        handle,
        deadline,
        std::time::Duration::from_millis(100),
    );
    if outcome == vetto::verify_ng::killer::KillOutcome::KilledOnDeadline {
        eprintln!(
            "vetto: session timeout ({}) reached; terminating the sandbox",
            format_duration(limit)
        );
        bus.publish(Event::SessionTimeout {
            ts: events::types::now(),
        });
        return (code, true);
    }
    (code, false)
}

fn format_duration(limit: std::time::Duration) -> String {
    let secs = limit.as_secs();
    if secs % 3600 == 0 && secs >= 3600 {
        format!("{}h", secs / 3600)
    } else if secs % 60 == 0 && secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

fn dry_run(cfg: &RunConfig, pol: &policy::Policy, agent_cmd: &[String], tier: &str) -> Result<()> {
    println!("vetto dry-run — NOT ENFORCED, nothing executed");
    println!("  tier:  {tier}");
    println!("  net:   {}", cfg.net.label());
    println!("  git ssh: {}", if cfg.git_ssh { "enabled" } else { "off" });
    println!(
        "  shadow: {}",
        if cfg.shadow {
            "enabled (policy layer only)"
        } else {
            "off"
        }
    );
    if let Some(preset) = cfg.preset {
        println!("  preset: {}", preset.as_str());
    }
    println!("  tui:   {:?}", cfg.tui);
    println!("  policy: {}", pol.summary());
    println!("  write roots:");
    for p in &pol.allow_write {
        println!("    {}", p.display());
    }
    println!("  read roots ({}):", pol.allow_read.len());
    for p in pol.allow_read.iter().take(50) {
        println!("    {}", p.display());
    }
    println!("  deny paths resolved: {}", pol.deny_resolved.len());
    for d in pol.deny_resolved.iter().take(50) {
        println!(
            "    {}{}",
            d.path.display(),
            if d.is_dir { "/" } else { "" }
        );
    }
    if let Some(path) = cfg.policy_path.as_deref() {
        if let Some(count) = explicit_policy_deny_count(path) {
            let noun = if count == 1 { "path" } else { "paths" };
            println!("  explicit CLI policy: {count} deny {noun} included above");
        }
    }
    println!(
        "  agent: {}",
        vetto::logger::sanitizer::sanitize_line(&agent_cmd.join(" "))
    );
    Ok(())
}

fn explicit_policy_deny_count(path: &Path) -> Option<usize> {
    let text = std::fs::read_to_string(path).ok()?;
    let document: toml::Value = toml::from_str(&text).ok()?;
    let paths = document.get("display_only_deny")?.get("paths")?;
    Some(match paths {
        toml::Value::Array(values) => values.len(),
        toml::Value::String(_) => 1,
        _ => 0,
    })
}

#[cfg(unix)]
fn pipe2() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: valid out-array.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        bail!("pipe: {}", std::io::Error::last_os_error());
    }
    for fd in fds {
        // SAFETY: fd came from the successful pipe call.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: both descriptors came from the successful pipe call.
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            bail!("fcntl(F_GETFD): {error}");
        }
        // SAFETY: fd came from the successful pipe call; preserve existing
        // descriptor flags while adding close-on-exec.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: both descriptors came from the successful pipe call.
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            bail!("fcntl(F_SETFD, FD_CLOEXEC): {error}");
        }
    }
    // SAFETY: fresh descriptors from a successful pipe and CLOEXEC setup.
    Ok((unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
        OwnedFd::from_raw_fd(fds[1])
    }))
}

fn resolve_in_path(cmd: &str) -> Result<String> {
    let command_path = Path::new(cmd);
    if command_path.is_absolute() || command_path.components().count() > 1 {
        return Ok(cmd.to_string());
    }
    if let Ok(real) = vetto::shim::find_real_binary(cmd) {
        return Ok(real.to_string_lossy().into_owned());
    }
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(cmd);
            if is_executable_file(&candidate) {
                return Ok(candidate.to_string_lossy().into_owned());
            }
            #[cfg(windows)]
            if candidate.extension().is_none() {
                let extensions =
                    std::env::var_os("PATHEXT").unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".into());
                for extension in extensions.to_string_lossy().split(';') {
                    let extension = extension.trim().trim_start_matches('.');
                    if extension.is_empty() {
                        continue;
                    }
                    let candidate = candidate.with_extension(extension);
                    if is_executable_file(&candidate) {
                        return Ok(candidate.to_string_lossy().into_owned());
                    }
                }
            }
        }
    }
    bail!("agent command '{cmd}' not found in PATH")
}

fn is_executable_file(p: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(p) {
            Ok(m) => m.is_file() && (m.permissions().mode() & 0o111) != 0,
            Err(_) => false,
        }
    }
    #[cfg(windows)]
    {
        p.is_file()
    }
}

// ---------------------------------------------------------------------------
// Ctrl+C forwarding
// ---------------------------------------------------------------------------

#[cfg(unix)]
static CHILD_TARGET: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
#[cfg(unix)]
static SIGINT_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(unix)]
extern "C" fn on_sigint(_sig: libc::c_int) {
    let t = CHILD_TARGET.load(std::sync::atomic::Ordering::SeqCst);
    if t != 0 {
        let count = SIGINT_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if count == 0 {
            // First interrupt: forward SIGINT to child/group.
            unsafe { libc::kill(t, libc::SIGINT) };
        } else {
            // Escalation: second interrupt forces immediate SIGKILL.
            unsafe { libc::kill(t, libc::SIGKILL) };
        }
    }
}

#[cfg(unix)]
fn install_sigint_forwarder(root_pid: u32, tier: Option<policy::Tier>) {
    let target = match tier {
        Some(policy::Tier::FsOnly) => -(root_pid as i32), // whole process group
        _ => root_pid as i32,
    };
    SIGINT_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
    CHILD_TARGET.store(target, std::sync::atomic::Ordering::SeqCst);

    // Watchdog thread: escalates to SIGKILL 500ms after first SIGINT if child remains alive.
    std::thread::Builder::new()
        .name("vetto-sigint-watchdog".into())
        .spawn(move || loop {
            if CHILD_TARGET.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                break;
            }
            if SIGINT_COUNT.load(std::sync::atomic::Ordering::SeqCst) > 0 {
                std::thread::sleep(std::time::Duration::from_millis(500));
                let t = CHILD_TARGET.load(std::sync::atomic::Ordering::SeqCst);
                if t != 0 {
                    let pid = t.abs();
                    if unsafe { libc::kill(pid, 0) } == 0 {
                        unsafe { libc::kill(t, libc::SIGKILL) };
                    }
                }
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        })
        .ok();

    // SAFETY: registering our extern handler.
    let h = on_sigint as *const () as libc::sighandler_t;
    if unsafe { libc::signal(libc::SIGINT, h) } == libc::SIG_ERR {
        eprintln!("vetto: warning: could not install SIGINT forwarder");
    }
    // SIGTERM gets the same forwarding so `kill <vetto>` tears the sandbox
    // down through the normal wait/cleanup path instead of mid-flight.
    if unsafe { libc::signal(libc::SIGTERM, h) } == libc::SIG_ERR {
        eprintln!("vetto: warning: could not install SIGTERM forwarder");
    }
}

#[cfg(windows)]
fn install_sigint_forwarder(_root_pid: u32, _tier: Option<policy::Tier>) {}

/// Opt-in background staging hook (see call site in supervise()).
/// Direct-binary installs only; managed installs stay with npm/cargo/brew.
fn stage_update_if_available(user_config: &vetto::version::UserConfig) {
    let exe_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return,
    };
    if vetto::version::detect_install_method(&exe_path) != vetto::version::InstallMethod::Binary {
        return;
    }
    let Some(notice) =
        vetto::version::check_version(env!("CARGO_PKG_VERSION"), &user_config.channel, false)
    else {
        return;
    };
    let Some((url, ext)) = vetto::version::binary_archive_url(&notice.latest_version) else {
        return;
    };
    match vetto::version::stage_update(&notice.latest_version, &url, ext) {
        Ok(dir) => println!(
            "vetto: update v{} staged, applies on next startup ({}).",
            notice.latest_version,
            dir.display()
        ),
        Err(e) => eprintln!("vetto: warning: background staging failed: {e:#}"),
    }
}

// ---------------------------------------------------------------------------
// init / profiles
// ---------------------------------------------------------------------------

fn init(force: bool, wizard: bool) -> Result<()> {
    vetto::init::run_init(Path::new("."), force, wizard)
}

fn profiles() -> Result<()> {
    println!("built-in profiles:");
    for name in policy::defaults::PROFILE_NAMES {
        let desc = match name {
            "default" => "project+tmp write, toolchain caches read-only, secrets masked",
            "strict" => "minimal: project write only, no caches, no git identity",
            "audit" => "same fs as default; pair with --observe-seccomp/--jsonl/--report",
            "permissive" => "wide toolchain read surface; secrets still denied",
            _ => "",
        };
        println!("  {name:<12} {desc}");
    }
    Ok(())
}
