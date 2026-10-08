//! Linux child-process tracking for the FS-ONLY tier: the sub-reaper
//! registration plus the bounded orphan sweep.
//!
//! FS-ONLY runs the agent WITHOUT a PID namespace. The agent's process group
//! is killed with `kill(-pgid)` at teardown, but any descendant that called
//! `setsid()` lives in its own session and survives that signal. The closing
//! mechanism is:
//!
//! 1. Before the fork, vetto registers itself as a child sub-reaper
//!    (`PR_SET_CHILD_SUBREAPER`, see [`set_subreaper`]). When the
//!    agent child terminates, surviving descendants are reparented to vetto
//!    instead of init.
//! 2. After the group kill, [`sweep_reparented`] scans `/proc` for live
//!    processes whose PPid is vetto, SIGKILLs the ones OUTSIDE vetto's own
//!    session (setsid-detached escapers of this sandbox) and reaps their
//!    exit statuses. Same-session processes are concurrent sandboxes
//!    (multi-agent sessions, parallel harnesses) or helpers — killing them
//!    would violate cleanup isolation, so they are spared.
//! 3. Because `supervise` exits through `std::process::exit` (which skips
//!    `Drop`), the normal-exit path never runs `SandboxHandle::terminate`.
//!    [`arm_exit_sweep`] registers an `atexit` handler as the safety net so
//!    a normally-exiting session still sweeps its reparented escapers.
//!
//! The sweep is bounded and best-effort: if the sub-reaper prctl failed, if
//! an orphan sits in uninterruptible sleep past the deadline, or if a
//! reparenting cascade outlives the budget, escapers can still survive. This
//! is honest degradation from the FULL tier, where the PID namespace kills
//! everything in the kernel.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// PinnedProcess binds a process via Linux `pidfd_open(2)` (Linux 5.3+).
/// This prevents PID recycling races (INV-21): signals delivered via
/// `pidfd_send_signal(2)` are guaranteed to target the exact intended process
/// instance, or fail closed with `ESRCH`, never misdirecting signals to a
/// recycled PID.
#[derive(Debug)]
pub struct PinnedProcess {
    pub pid: i32,
    pub pidfd: Option<OwnedFd>,
}

impl PinnedProcess {
    /// Open a pinned process descriptor for `pid`.
    /// On Linux >= 5.3, uses `SYS_pidfd_open(pid, 0)`.
    /// On older kernels or non-Linux targets, falls back to `pidfd = None`.
    pub fn open(pid: i32) -> Self {
        #[cfg(target_os = "linux")]
        {
            const SYS_PIDFD_OPEN: libc::c_long = 434;
            let res = unsafe { libc::syscall(SYS_PIDFD_OPEN, pid as libc::pid_t, 0u32) };
            if res >= 0 {
                return Self {
                    pid,
                    pidfd: Some(unsafe { OwnedFd::from_raw_fd(res as i32) }),
                };
            }
        }
        Self { pid, pidfd: None }
    }

    /// Deliver a signal to the pinned process without PID recycling races.
    /// Returns Ok(()) on success, or Err(io::Error) on failure.
    pub fn send_signal(&self, sig: i32) -> Result<(), std::io::Error> {
        #[cfg(target_os = "linux")]
        {
            if let Some(ref fd) = self.pidfd {
                const SYS_PIDFD_SEND_SIGNAL: libc::c_long = 424;
                let res = unsafe {
                    libc::syscall(
                        SYS_PIDFD_SEND_SIGNAL,
                        fd.as_raw_fd(),
                        sig,
                        std::ptr::null::<libc::siginfo_t>(),
                        0u32,
                    )
                };
                if res == 0 {
                    return Ok(());
                }
                return Err(std::io::Error::last_os_error());
            }
        }
        // Fallback for Linux < 5.3: verify process existence before signaling
        unsafe {
            if libc::kill(self.pid, sig) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        }
    }

    /// Non-blocking reap of the process. Must only be called AFTER signal delivery.
    pub fn try_wait(&self) -> Option<i32> {
        let mut status = 0i32;
        let res = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
        if res > 0 {
            Some(status)
        } else {
            None
        }
    }
}

/// Upper bound for one sweep. Synchronized with MAX_EXTINCTION_DEADLINE_MS.
pub const SWEEP_BUDGET_MS: u64 = crate::proctree::MAX_EXTINCTION_DEADLINE_MS;

/// Pause between `/proc` scans while waiting for the root to terminate or
/// for reparenting to become visible.
const SWEEP_POLL: Duration = Duration::from_millis(10);

// (root_pid, pgid) of the FS-ONLY sandbox, armed once per process.
static FS_GUARD: OnceLock<(i32, i32)> = OnceLock::new();

/// Register the process-exit safety net for the FS-ONLY sandbox.
///
/// The handler kills the sandbox process group and runs one bounded sweep.
/// On the normal exit path this is the ONLY teardown that runs (supervise
/// uses `std::process::exit`, which does not run `Drop`); on the timeout and
/// TUI paths the same work happens through `SandboxHandle::terminate` and
/// the exit-time re-run is an idempotent no-op. Call this AFTER the last
/// fork in the process so forked children never inherit an armed handler
/// (execve clears it anyway).
pub fn arm_exit_sweep(root_pid: i32, pgid: i32) {
    if FS_GUARD.set((root_pid, pgid)).is_err() {
        return; // already armed for this process
    }
    // SAFETY: the handler is a plain extern "C" fn whose only state is the
    // static guard above.
    unsafe { libc::atexit(exit_sweep) };
}

extern "C" fn exit_sweep() {
    let Some(&(root_pid, pgid)) = FS_GUARD.get() else {
        return;
    };
    // SAFETY: kill targets the sandbox process group recorded at spawn time.
    // An empty or already-dead group returns ESRCH, which is ignored.
    unsafe { libc::kill(-pgid, libc::SIGKILL) };
    // Never kill(root_pid) here: on the normal path the root was already
    // reaped by wait(), and its pid may in principle have been reused. The
    // group kill and the sweep (which skips the root pid) are sufficient.
    sweep_reparented(SWEEP_BUDGET_MS, root_pid);
}

/// Kill and reap every reparented orphan descendant of this process.
///
/// Loop until the deadline: scan `/proc` for live processes whose PPid is
/// our pid (excluding `root_pid`, whose exit status belongs to
/// `SandboxHandle::wait`), SIGKILL each survivor and reap it with a targeted
/// `waitpid`. Targeted reaping — never `waitpid(-1)` — guarantees the root
/// pid's exit status is never consumed out from under `wait`. Returns the
/// number of SIGKILL signals delivered (zombies included; their kill is a
/// no-op that precedes the reaping).
///
/// ISOLATION (cleanup_A must never target B): a victim is killed ONLY if it
/// lives OUTSIDE our session (`getsid(victim) != getsid(self)`). Our escapers
/// are setsid-detached by construction, so they always qualify; concurrent
/// sandboxes in this process (multi-agent sessions, parallel tests) and the
/// harness's own helpers share our session and are spared. Same-session
/// setpgid-only escapers that additionally exec-cleaned their environ are a
/// documented residual (the nonce-targeted sweep still catches every
/// non-exec-cleaned one). Any lookup error skips the victim conservatively.
pub fn sweep_reparented(deadline_ms: u64, root_pid: i32) -> usize {
    // SAFETY: scalar getpid.
    let me = unsafe { libc::getpid() } as u32;
    // SAFETY: scalar getsid on our own process; always succeeds.
    let my_sid = session_of(0);
    let deadline = Instant::now() + Duration::from_millis(deadline_ms);
    let mut killed = 0usize;
    loop {
        let candidates = scan_children(me, root_pid);

        // 1. Filter candidates into killable orphans vs non-killable.
        // Pin killable processes via pidfd immediately, BEFORE any waitpid call (INV-21).
        let mut killable = Vec::new();
        let mut non_killable = Vec::new();

        for pid in candidates {
            if pid == root_pid || crate::sandbox::handle::is_active_root(pid as u32) {
                continue;
            }
            let their_pgid = unsafe { libc::getpgid(pid) };
            let is_killable = match (my_sid, session_of(pid)) {
                (Some(mine), Some(theirs)) if mine != theirs => true,
                _ => their_pgid == root_pid,
            };
            if is_killable {
                killable.push(PinnedProcess::open(pid));
            } else {
                non_killable.push(pid);
            }
        }

        if killable.is_empty() {
            // Reap any lingering non-killable zombie children (without signals)
            for pid in non_killable {
                let mut status = 0i32;
                unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            }
            if root_settled(root_pid, me) {
                return killed;
            }
        } else {
            // 2. Deliver SIGKILL via pidfd BEFORE calling waitpid (INV-21)
            for pinned in &killable {
                if pinned.send_signal(libc::SIGKILL).is_ok() {
                    killed += 1;
                }
            }
            // 3. ONLY AFTER signal delivery, reap terminated children
            for pinned in &killable {
                pinned.try_wait();
            }
            // 4. Also reap any non-killable zombie children
            for pid in non_killable {
                let mut status = 0i32;
                unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            }
        }
        if Instant::now() >= deadline {
            return killed;
        }
        std::thread::sleep(SWEEP_POLL);
    }
}

/// Every live or zombie process whose PPid is `me`, excluding `exclude_pid`.
pub fn scan_children(me: u32, exclude_pid: i32) -> Vec<i32> {
    let mut children = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return children;
    };
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Ok(pid) = name.parse::<i32>() else {
            continue;
        };
        if pid <= 0 || pid == exclude_pid || crate::sandbox::handle::is_active_root(pid as u32) {
            continue;
        }
        let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
            continue; // vanished between readdir and read: not a candidate
        };
        if ppid_from_status(&status) == Some(me) {
            children.push(pid);
        }
    }
    children
}

/// Session id of `pid` (`None` on any lookup error: the victim vanished or
/// is unreachable, and must be skipped conservatively).
pub fn session_of(pid: libc::pid_t) -> Option<libc::pid_t> {
    // SAFETY: scalar getsid on a possibly-vanished pid; errors are normal.
    let sid = unsafe { libc::getsid(pid) };
    if sid < 0 {
        None
    } else {
        Some(sid)
    }
}

/// True when the root can no longer produce new orphans: the process is gone
/// (reaped, or never existed), its pid was reused by a non-child, or it is a
/// zombie — at termination the kernel already reparented its children.
fn root_settled(root_pid: i32, me: u32) -> bool {
    let Ok(status) = std::fs::read_to_string(format!("/proc/{root_pid}/status")) else {
        return true;
    };
    if ppid_from_status(&status) != Some(me) {
        return true;
    }
    state_letter(&status) == Some('Z')
}

/// Parse the `PPid:` field out of a `/proc/<pid>/status` body.
pub fn ppid_from_status(status_text: &str) -> Option<u32> {
    for line in status_text.lines() {
        let line = line.trim_start();
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse::<u32>().ok();
        }
    }
    None
}

/// Parse the single-letter process state (`State:\tZ (zombie)`).
fn state_letter(status_text: &str) -> Option<char> {
    for line in status_text.lines() {
        let line = line.trim_start();
        if let Some(rest) = line.strip_prefix("State:") {
            return rest.trim_start().chars().next();
        }
    }
    None
}

/// Linux sub-reaper management: mark the calling process as a sub-reaper
/// so that orphaned descendant processes are adopted by this process rather
/// than PID 1 of the init system.
#[cfg(target_os = "linux")]
pub fn set_subreaper() -> crate::error::VettoResult<()> {
    const PR_SET_CHILD_SUBREAPER: libc::c_int = 36;
    // SAFETY: scalar prctl call
    if unsafe { libc::prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
        return Err(crate::error::VettoError::Sandbox(format!(
            "PR_SET_CHILD_SUBREAPER: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn set_subreaper() -> crate::error::VettoResult<()> {
    Ok(())
}

/// Byte-substring search (haystack may be NUL-separated, e.g. `environ`).
pub fn contains_slice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Outcome of one nonce-targeted tree sweep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepOutcome {
    pub clean: bool,
    pub killed: usize,
    pub residual: Vec<i32>,
    pub subreaper: bool,
    pub blind: bool,
}

/// True when this process is a child sub-reaper (`PR_SET_CHILD_SUBREAPER`).
#[cfg(target_os = "linux")]
pub fn is_child_subreaper() -> bool {
    let mut flag: libc::c_int = 0;
    let rc = unsafe {
        libc::prctl(
            libc::PR_GET_CHILD_SUBREAPER,
            &mut flag as *mut libc::c_int as libc::c_ulong,
            0,
            0,
            0,
        )
    };
    rc == 0 && flag == 1
}

#[cfg(not(target_os = "linux"))]
pub fn is_child_subreaper() -> bool {
    false
}

/// Real UID from a `/proc/<pid>/status` body.
pub fn status_uid(status_body: &str) -> Option<u32> {
    for line in status_body.lines() {
        if let Some(rest) = line.trim_start().strip_prefix("Uid:") {
            let first = rest.split_whitespace().next().unwrap_or("");
            return first.parse::<u32>().ok();
        }
    }
    None
}

/// True when a `/proc/<pid>/status` body describes a zombie or dead process.
pub fn pid_is_zombie(status: &str) -> bool {
    for line in status.lines() {
        if let Some(rest) = line.trim_start().strip_prefix("State:") {
            let s = rest.trim_start();
            return s.starts_with('Z') || s.starts_with('X');
        }
    }
    false
}

/// True while `kill(pid, 0)` succeeds.
pub fn pid_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

/// Sweep this run's residual processes after the root was reaped.
pub fn sweep_tree_by_nonce(nonce: &str, root_pid: u32) -> Option<SweepOutcome> {
    #[cfg(target_os = "linux")]
    {
        Some(sweep_tree_by_nonce_linux(nonce, root_pid))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (nonce, root_pid);
        None
    }
}

#[cfg(target_os = "linux")]
fn sweep_tree_by_nonce_linux(nonce: &str, root_pid: u32) -> SweepOutcome {
    let subreaper = is_child_subreaper();
    let mut outcome = SweepOutcome {
        clean: false,
        killed: 0,
        residual: Vec::new(),
        subreaper,
        blind: false,
    };
    if !subreaper {
        outcome.blind = true;
        return outcome;
    }
    let me = unsafe { libc::getpid() } as u32;
    let me_uid = unsafe { libc::geteuid() };
    let needle = nonce.as_bytes();
    let deadline =
        Instant::now() + Duration::from_millis(crate::proctree::MAX_EXTINCTION_DEADLINE_MS);
    loop {
        let (matched, blind) = scan_nonce_pids(needle, root_pid, me, me_uid);
        if blind {
            outcome.blind = true;
        }
        if matched.is_empty() {
            if !outcome.blind {
                outcome.clean = true;
            }
            return outcome;
        }
        for pid in &matched {
            if unsafe { libc::kill(*pid, libc::SIGKILL) } == 0 {
                outcome.killed += 1;
            }
            let mut status = 0i32;
            unsafe { libc::waitpid(*pid, &mut status, libc::WNOHANG) };
        }
        if Instant::now() >= deadline {
            if blind {
                outcome.blind = true;
            }
            outcome.residual = last_nonce_pids(nonce, root_pid, me);
            return outcome;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(target_os = "linux")]
fn scan_nonce_pids(needle: &[u8], root_pid: u32, me: u32, me_uid: libc::uid_t) -> (Vec<i32>, bool) {
    let mut matched = Vec::new();
    let mut blind = false;
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return (matched, true);
    };
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Ok(pid) = name.parse::<i32>() else {
            continue;
        };
        if pid <= 0
            || pid as u32 == root_pid
            || pid as u32 == me
            || crate::sandbox::handle::is_active_root(pid as u32)
        {
            continue;
        }
        let status = match std::fs::read_to_string(format!("/proc/{pid}/status")) {
            Ok(s) => s,
            Err(e)
                if e.raw_os_error() == Some(libc::ENOENT)
                    || e.raw_os_error() == Some(libc::ESRCH) =>
            {
                continue;
            }
            Err(_) => continue,
        };
        if let Some(uid) = status_uid(&status) {
            if uid != me_uid {
                continue;
            }
        }
        let env = match std::fs::read(format!("/proc/{pid}/environ")) {
            Ok(env) => env,
            Err(e)
                if e.raw_os_error() == Some(libc::ENOENT)
                    || e.raw_os_error() == Some(libc::ESRCH) =>
            {
                continue;
            }
            Err(_) => {
                if pid_is_zombie(&status) || !pid_alive(pid as u32) {
                    continue;
                }
                if let Ok(latest_status) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
                    if pid_is_zombie(&latest_status) {
                        continue;
                    }
                } else {
                    continue;
                }
                if ppid_from_status(&status) == Some(me) {
                    blind = true;
                }
                continue;
            }
        };
        if contains_slice(&env, needle) {
            matched.push(pid);
        } else if (env.is_empty()
            || (!contains_slice(&env, b"VETTO_RUN_NONCE=")
                && !contains_slice(&env, b"VETTO_PROD_NONCE=")
                && !contains_slice(&env, b"VETTO_VNG_NONCE=")))
            && pid_alive(pid as u32)
            && !pid_is_zombie(&status)
            && ppid_from_status(&status) == Some(me)
            && pid != root_pid as i32
            && !crate::sandbox::handle::is_active_root(pid as u32)
        {
            let my_sid = session_of(0);
            let their_sid = session_of(pid);
            let their_pgid = unsafe { libc::getpgid(pid) };
            let is_orphan = match (my_sid, their_sid) {
                (Some(mine), Some(theirs)) if mine != theirs => true,
                _ => their_pgid == root_pid as i32,
            };
            if is_orphan {
                blind = true;
                matched.push(pid);
            }
        }
    }
    (matched, blind)
}

#[cfg(target_os = "linux")]
fn last_nonce_pids(nonce: &str, root_pid: u32, me: u32) -> Vec<i32> {
    let mut out = Vec::new();
    let needle = nonce.as_bytes();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            let Ok(pid) = name.parse::<i32>() else {
                continue;
            };
            if pid <= 0
                || pid as u32 == root_pid
                || pid as u32 == me
                || crate::sandbox::handle::is_active_root(pid as u32)
            {
                continue;
            }
            let Ok(env) = std::fs::read(format!("/proc/{pid}/environ")) else {
                continue;
            };
            if contains_slice(&env, needle) {
                out.push(pid);
            }
        }
    }
    out.sort_unstable();
    out.truncate(8);
    out
}

pub fn limits_field_is(limits_body: &str, row: &str, expected: u64) -> bool {
    for line in limits_body.lines() {
        if let Some(idx) = line.find(row) {
            let after = line[idx + row.len()..].trim_start();
            let mut cols = after.split_whitespace();
            let soft = cols.next().unwrap_or("");
            let hard = cols.next().unwrap_or("");
            let want = expected.to_string();
            return soft == want && hard == want;
        }
    }
    false
}

pub fn proc_field_is(status_body: &str, field: &str, expected: &str) -> bool {
    for line in status_body.lines() {
        if let Some(rest) = line.trim_start().strip_prefix(field) {
            return rest.trim() == expected;
        }
    }
    false
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExpectedLimits {
    pub rlimit_as: Option<u64>,
    pub rlimit_nproc: Option<u64>,
    pub rlimit_cpu: Option<u64>,
    pub rlimit_fsize: Option<u64>,
    pub cgroup_memory_max: Option<String>,
    pub cgroup_pids_max: Option<String>,
    pub cgroup_cpu_max: Option<String>,
    pub cgroup_swap_max: Option<String>,
}

pub fn verify_child_host(pid: u32) -> crate::sandbox::capability::HostVerification {
    #[cfg(target_os = "linux")]
    {
        verify_child_host_linux(pid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        crate::sandbox::capability::HostVerification::none()
    }
}

#[cfg(target_os = "linux")]
fn verify_child_host_linux(pid: u32) -> crate::sandbox::capability::HostVerification {
    use crate::sandbox::capability::HostVerification;
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut out = HostVerification::none();
    loop {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok();
        if let Some(body) = status.as_deref() {
            if proc_field_is(body, "Seccomp:", "2") {
                out.seccomp_filter = true;
            }
            if proc_field_is(body, "NoNewPrivs:", "1") {
                out.no_new_privs = true;
            }
        }
        let pgid = unsafe { libc::getpgid(pid as libc::pid_t) };
        if pgid == pid as libc::pid_t {
            out.pgroup_separate = true;
        }
        if let (Ok(child_netns), Ok(host_netns)) = (
            std::fs::read_link(format!("/proc/{pid}/ns/net")),
            std::fs::read_link("/proc/self/ns/net"),
        ) {
            if child_netns != host_netns {
                out.netns_isolated = true;
            }
        }
        out.subreaper_ok = is_child_subreaper();
        let zombie = match status.as_deref() {
            Some(body) => pid_is_zombie(body),
            None => false,
        };
        if out.all_observed() || Instant::now() >= deadline || !pid_alive(pid) || zombie {
            return out;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ppid_is_parsed_from_proc_status_body() {
        let status = "Name:\tsleep\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t4242\n\
                      Ngid:\t0\nPid:\t4242\nPPid:\t1337\nTracerPid:\t0\nUid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(ppid_from_status(status), Some(1337));
    }

    #[test]
    fn ppid_of_pid_one_is_parsed() {
        let status = "Name:\tsystemd\nState:\tS (sleeping)\nPPid:\t0\n";
        assert_eq!(ppid_from_status(status), Some(0));
    }

    #[test]
    fn missing_or_malformed_ppid_is_none() {
        assert_eq!(ppid_from_status("Name:\tx\nState:\tR (running)\n"), None);
        assert_eq!(ppid_from_status(""), None);
        assert_eq!(ppid_from_status("PPid:\tnot-a-number\n"), None);
        // Only an exact field match counts; a longer field name is ignored.
        assert_eq!(ppid_from_status("PPidTracer:\t5\n"), None);
    }

    #[test]
    fn indented_ppid_line_is_still_found() {
        let status = "Name:\tsleep\n  PPid:  99\n";
        assert_eq!(ppid_from_status(status), Some(99));
    }

    #[test]
    fn state_letter_reads_the_first_state_char() {
        assert_eq!(state_letter("State:\tZ (zombie)\n"), Some('Z'));
        assert_eq!(state_letter("State:\tS (sleeping)\n"), Some('S'));
        assert_eq!(state_letter("Name:\tx\n"), None);
    }
}
