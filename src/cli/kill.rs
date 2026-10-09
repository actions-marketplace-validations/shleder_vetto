//! Process safety & runaway process killer (`vetto kill`).
//!
//! Terminates runaway or hanging AI agent processes and active Vetto sessions
//! by PID or Session ID, and provides a `--hung` scanner to kill sessions exceeding
//! a runtime threshold (default: 30 minutes).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Result};
use clap::Args;

/// Command-line arguments for `vetto kill`.
#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct KillArgs {
    /// Target session ID or process ID (PID) to terminate.
    #[arg(value_name = "TARGET")]
    pub target: Option<String>,

    /// Kill any active Vetto session/process running longer than 30 minutes (or --older-than).
    #[arg(long)]
    pub hung: bool,

    /// Duration threshold for hung sessions (e.g. 10m, 1h). Implies --hung.
    #[arg(long, value_name = "DURATION")]
    pub older_than: Option<String>,

    /// Send SIGKILL immediately without graceful SIGTERM.
    #[arg(short = '9', long = "force")]
    pub force: bool,
}

/// Terminates cgroup v2 processes associated with a session if cgroup is active.
pub fn kill_cgroup_session(session_id: &str, cgroup_path: Option<&str>) {
    let mut cg_dirs = Vec::new();
    if let Some(path) = cgroup_path {
        cg_dirs.push(std::path::PathBuf::from(path));
    }
    cg_dirs.push(std::path::PathBuf::from(format!(
        "/sys/fs/cgroup/vetto-{session_id}"
    )));

    for cg in cg_dirs {
        let kill_file = cg.join("cgroup.kill");
        if kill_file.exists() {
            let _ = std::fs::write(&kill_file, "1");
        }
    }
}

/// Kills a process by PID, optionally sending SIGKILL immediately or with a grace period.
pub fn kill_pid(pid: u32, force: bool) -> Result<()> {
    if pid <= 1 {
        bail!("Refusing to kill reserved PID {pid}");
    }

    #[cfg(target_os = "linux")]
    {
        let pinned = crate::sandbox::linux::proctrack::PinnedProcess::open(pid as i32);
        let sig = if force { libc::SIGKILL } else { libc::SIGTERM };

        if pinned.pidfd.is_some() {
            let _ = pinned.send_signal(sig);
        } else {
            let pid_i = pid as libc::pid_t;
            unsafe {
                if libc::kill(-pid_i, sig) != 0 {
                    libc::kill(pid_i, sig);
                }
            }
        }

        if !force {
            let deadline = std::time::Instant::now() + Duration::from_millis(500);
            while std::time::Instant::now() < deadline {
                if !crate::cli::status::is_pid_alive(pid) {
                    crate::sandbox::linux::proctrack::sweep_reparented(100, pid as i32);
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            if crate::cli::status::is_pid_alive(pid) {
                if pinned.pidfd.is_some() {
                    let _ = pinned.send_signal(libc::SIGKILL);
                } else {
                    let pid_i = pid as libc::pid_t;
                    unsafe {
                        if libc::kill(-pid_i, libc::SIGKILL) != 0 {
                            libc::kill(pid_i, libc::SIGKILL);
                        }
                    }
                }
            }
        }

        // Tree sweep: reap reparented orphan descendants (INV-12/13)
        crate::sandbox::linux::proctrack::sweep_reparented(100, pid as i32);
        Ok(())
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    {
        let pid_i = pid as libc::pid_t;
        let sig = if force { libc::SIGKILL } else { libc::SIGTERM };
        unsafe {
            if libc::kill(-pid_i, sig) != 0 {
                libc::kill(pid_i, sig);
            }
        }
        if !force {
            let deadline = std::time::Instant::now() + Duration::from_millis(500);
            while std::time::Instant::now() < deadline {
                if !crate::cli::status::is_pid_alive(pid) {
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            if crate::cli::status::is_pid_alive(pid) {
                unsafe {
                    if libc::kill(-pid_i, libc::SIGKILL) != 0 {
                        libc::kill(pid_i, libc::SIGKILL);
                    }
                }
            }
        }
        Ok(())
    }

    #[cfg(windows)]
    {
        let flag = if force { "/F" } else { "/T" };
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), flag])
            .output();
        Ok(())
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (pid, force);
        Ok(())
    }
}

/// Main entrypoint for `vetto kill`.
pub fn run_cli(args: &KillArgs) -> Result<()> {
    if let Some(target) = &args.target {
        if let Ok(pid) = target.parse::<u32>() {
            kill_by_pid(pid, args.force)
        } else {
            kill_by_session_id(target, args.force)
        }
    } else if args.hung || args.older_than.is_some() {
        let threshold = match &args.older_than {
            Some(raw) => crate::watchdog::timeout::parse_timeout(raw)?,
            None => Duration::from_secs(30 * 60),
        };
        kill_hung_sessions(threshold, args.force)
    } else {
        bail!("Specify a target PID or Session ID, or use --hung to terminate hung sessions.");
    }
}

fn kill_by_pid(pid: u32, force: bool) -> Result<()> {
    let registry = crate::cli::status::SessionRegistry::new()?;
    let active = registry.list_active()?;
    let session = active.iter().find(|s| s.pid == pid);

    if let Some(s) = session {
        kill_cgroup_session(&s.session_id, s.cgroup_path.as_deref());
        kill_pid(pid, force)?;
        registry.unregister(&s.session_id);
        println!("Terminated session {} (PID {})", s.session_id, pid);
        return Ok(());
    }

    if crate::cli::status::is_pid_alive(pid) {
        kill_pid(pid, force)?;
        println!("Terminated process PID {}", pid);
        Ok(())
    } else {
        bail!("Process PID {} is not running", pid);
    }
}

fn kill_by_session_id(target: &str, force: bool) -> Result<()> {
    let registry = crate::cli::status::SessionRegistry::new()?;
    let active = registry.list_active()?;
    let matched: Vec<_> = active
        .into_iter()
        .filter(|s| s.session_id == target || s.session_id.starts_with(target))
        .collect();

    if !matched.is_empty() {
        for s in matched {
            kill_cgroup_session(&s.session_id, s.cgroup_path.as_deref());
            kill_pid(s.pid, force)?;
            registry.unregister(&s.session_id);
            println!("Terminated session {} (PID {})", s.session_id, s.pid);
        }
        return Ok(());
    }

    bail!("No active session found matching '{target}'");
}

fn kill_hung_sessions(threshold: Duration, force: bool) -> Result<()> {
    let registry = crate::cli::status::SessionRegistry::new()?;
    let active = registry.list_active()?;
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut killed = 0;
    for s in &active {
        let elapsed = now_secs.saturating_sub(s.started_at_secs);
        if elapsed >= threshold.as_secs() {
            kill_cgroup_session(&s.session_id, s.cgroup_path.as_deref());
            kill_pid(s.pid, force)?;
            registry.unregister(&s.session_id);
            println!(
                "Terminated hung session {} (PID {}, running for {}s)",
                s.session_id, s.pid, elapsed
            );
            killed += 1;
        }
    }

    if killed == 0 {
        println!("No hung sessions found running longer than {:?}", threshold);
    } else {
        println!("Successfully terminated {} hung session(s)", killed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_refuse_reserved_pids() {
        assert!(kill_pid(0, false).is_err());
        assert!(kill_pid(1, false).is_err());
        assert!(kill_pid(0, true).is_err());
        assert!(kill_pid(1, true).is_err());
    }

    #[test]
    fn test_kill_args_validation() {
        let args = KillArgs {
            target: None,
            hung: false,
            older_than: None,
            force: false,
        };
        assert!(run_cli(&args).is_err());
    }
}
