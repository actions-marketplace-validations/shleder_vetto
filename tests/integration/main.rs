//! Integration test harness: every test drives the COMPILED vetto binary as
//! a child process. All enforcement tests are conditional on the platform
//! actually supporting a tier (see common::detected_tier) — skipping on
//! unsupported environments is part of the spec, not a failure.

#![allow(clippy::all)]
#![allow(dead_code)]

mod common;

mod adv_isolation;
mod adversarial_suite;
#[cfg(target_os = "linux")]
mod anti_ssrf;
mod cli_30_subcommands;
mod cli_auto_enable;
mod cli_reporting;
#[cfg(target_os = "linux")]
mod computer_use_plugins;
mod doctor_parity;
mod doctor_preflight;
mod ecosystem_tier7;
mod enable_wrapper;
#[cfg(unix)]
mod entrypoint_contract_parity;
#[cfg(target_os = "linux")]
mod env_stripping;
mod ephemeral;
mod heavy_scenarios;
#[cfg(target_os = "linux")]
mod lifecycle_phase3;
#[cfg(target_os = "linux")]
mod linux_downgrade;
#[cfg(target_os = "linux")]
mod linux_landlock;
#[cfg(target_os = "linux")]
mod linux_limits_cli;
#[cfg(target_os = "linux")]
mod linux_netmodes;
#[cfg(target_os = "linux")]
mod linux_orphans;
#[cfg(target_os = "linux")]
mod linux_redteam;
#[cfg(target_os = "linux")]
mod linux_seccomp_blocks;
#[cfg(target_os = "linux")]
mod linux_subagents;
#[cfg(target_os = "linux")]
mod linux_tiers;
#[cfg(target_os = "linux")]
mod linux_timeout;
#[cfg(target_os = "linux")]
mod linux_verify;
#[cfg(target_os = "linux")]
mod linux_visibility;
mod macos_prod;
mod macos_seatbelt;
mod onboarding;
mod policy_loading;
mod policy_overlays;
mod policy_parity;
mod policy_tools;
mod policy_ux_phase5;
mod prod_stage3c;
mod resource_limits_e2e;
mod secret_masking;
mod shim_interception;
mod test_agent_profiles_e2e;
mod test_aider_preset;
mod test_bench_mode;
#[cfg(target_os = "linux")]
mod test_job_control;
mod test_shell_hook_precedence;
mod test_startup_latency;
mod tier3_files_secrets;
mod tier8_release;
mod tier9_friction;
mod windows_enforcement;
mod windows_production;
