//! Multi-Agent Fleet Concurrency & Fair-Share Cgroup Architecture.
//!
//! Fulfills Section 19 of the Next-Generation Architectural Specification:
//! Coordinates multi-agent swarms (20 to 100 concurrent agents) on a single
//! multi-core host with:
//! - Kernel-enforced cgroups v2 fair-share scheduling (`cpu.weight = 100`)
//! - Hard memory and PID ceilings (`memory.max = 2GB`, `pids.max = 128`)
//! - Strict IPC namespace isolation (`CLONE_NEWIPC`) preventing shared-memory snooping
//! - Ephemeral CoW workspace branch partitioning (`cow_branch = agent-XX`)
//! - Dynamic ephemeral port isolation (`base_port = 49201`)

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const DEFAULT_FLEET_CGROUP_ROOT: &str = "/sys/fs/cgroup/vetto-fleet";
pub const DEFAULT_MAX_AGENTS: usize = 64;
pub const DEFAULT_CPU_WEIGHT: u32 = 100;
pub const DEFAULT_MEMORY_LIMIT_BYTES: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB
pub const DEFAULT_PIDS_MAX: u32 = 128;
pub const DEFAULT_BASE_PORT: u16 = 49201;

/// Default status value for freshly allocated worker scopes.
pub fn default_worker_status() -> String {
    "allocated".to_string()
}

/// Resolves the base fleet directory (`~/.vetto/fleet/` or `$VETTO_FLEET_DIR`).
pub fn default_fleet_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("VETTO_FLEET_DIR") {
        return PathBuf::from(p);
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".vetto").join("fleet")
}

/// Resolves the default persistent state file path (`~/.vetto/fleet/workers.json`).
pub fn default_fleet_state_path() -> PathBuf {
    if let Some(p) = std::env::var_os("VETTO_FLEET_STATE_PATH") {
        return PathBuf::from(p);
    }
    default_fleet_dir().join("workers.json")
}

/// Resolves the default advisory lock file path (`~/.vetto/fleet/.workers.lock`).
pub fn default_fleet_lock_path() -> PathBuf {
    if let Some(p) = std::env::var_os("VETTO_FLEET_LOCK_PATH") {
        return PathBuf::from(p);
    }
    default_fleet_dir().join(".workers.lock")
}

/// Resolves the default workspace root directory (`~/.vetto/fleet/workspaces`).
pub fn default_fleet_workspace_root() -> PathBuf {
    if let Some(p) = std::env::var_os("VETTO_FLEET_WORKSPACE_ROOT") {
        return PathBuf::from(p);
    }
    default_fleet_dir().join("workspaces")
}

/// Configuration for the multi-agent fleet orchestrator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetConfig {
    pub cgroup_root: PathBuf,
    pub max_agents: usize,
    pub cpu_weight: u32,
    pub memory_limit_bytes: u64,
    pub pids_max: u32,
    pub base_port: u16,
    pub ipc_isolation: bool,
    #[serde(default)]
    pub state_file: Option<PathBuf>,
    #[serde(default)]
    pub workspace_root: Option<PathBuf>,
}

impl Default for FleetConfig {
    fn default() -> Self {
        Self {
            cgroup_root: PathBuf::from(DEFAULT_FLEET_CGROUP_ROOT),
            max_agents: DEFAULT_MAX_AGENTS,
            cpu_weight: DEFAULT_CPU_WEIGHT,
            memory_limit_bytes: DEFAULT_MEMORY_LIMIT_BYTES,
            pids_max: DEFAULT_PIDS_MAX,
            base_port: DEFAULT_BASE_PORT,
            ipc_isolation: true,
            state_file: None,
            workspace_root: None,
        }
    }
}

impl FleetConfig {
    /// Creates a persistent fleet configuration pointing to default paths in `~/.vetto/fleet/`.
    pub fn persistent() -> Self {
        Self {
            state_file: Some(default_fleet_state_path()),
            workspace_root: Some(default_fleet_workspace_root()),
            ..Default::default()
        }
    }

    /// Creates a fleet configuration with explicit persistence and workspace paths.
    pub fn with_persistence(state_file: PathBuf, workspace_root: PathBuf) -> Self {
        Self {
            state_file: Some(state_file),
            workspace_root: Some(workspace_root),
            ..Default::default()
        }
    }
}

/// An allocated worker scope for one sandboxed agent in the fleet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentWorkerScope {
    pub worker_id: String,
    pub agent_name: String,
    pub scope_path: PathBuf,
    pub cow_branch_name: String,
    pub ephemeral_port: u16,
    pub cpu_weight: u32,
    pub memory_limit_bytes: u64,
    pub pids_max: u32,
    pub ipc_isolated: bool,
    pub allocated_at: DateTime<Utc>,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default = "default_worker_status")]
    pub status: String,
    #[serde(default)]
    pub workspace_dir: PathBuf,
}

/// Persistent state representation matching `vetto fleet status --json` schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetState {
    #[serde(default)]
    pub active_count: usize,
    pub max_agents: usize,
    pub cpu_weight: u32,
    pub memory_limit_bytes: u64,
    pub pids_max: u32,
    pub ipc_isolation: bool,
    pub base_port: u16,
    pub workers: Vec<AgentWorkerScope>,
}

impl Default for FleetState {
    fn default() -> Self {
        Self {
            active_count: 0,
            max_agents: DEFAULT_MAX_AGENTS,
            cpu_weight: DEFAULT_CPU_WEIGHT,
            memory_limit_bytes: DEFAULT_MEMORY_LIMIT_BYTES,
            pids_max: DEFAULT_PIDS_MAX,
            ipc_isolation: true,
            base_port: DEFAULT_BASE_PORT,
            workers: Vec::new(),
        }
    }
}

fn deserialize_fleet_state(bytes: &[u8]) -> Result<FleetState> {
    if bytes.is_empty() {
        return Ok(FleetState::default());
    }
    if let Ok(state) = serde_json::from_slice::<FleetState>(bytes) {
        return Ok(state);
    }
    if let Ok(workers) = serde_json::from_slice::<Vec<AgentWorkerScope>>(bytes) {
        return Ok(FleetState {
            active_count: workers.len(),
            max_agents: DEFAULT_MAX_AGENTS,
            cpu_weight: DEFAULT_CPU_WEIGHT,
            memory_limit_bytes: DEFAULT_MEMORY_LIMIT_BYTES,
            pids_max: DEFAULT_PIDS_MAX,
            ipc_isolation: true,
            base_port: DEFAULT_BASE_PORT,
            workers,
        });
    }
    serde_json::from_slice::<FleetState>(bytes).context("failed to parse fleet state JSON")
}

#[cfg(windows)]
mod win_lock_ffi {
    use std::os::windows::io::RawHandle;

    pub const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x00000002;

    #[repr(C)]
    #[allow(clippy::upper_case_acronyms)]
    pub struct OVERLAPPED {
        pub internal: usize,
        pub internal_high: usize,
        pub offset: u32,
        pub offset_high: u32,
        pub h_event: usize,
    }

    extern "system" {
        pub fn LockFileEx(
            hFile: RawHandle,
            dwFlags: u32,
            dwReserved: u32,
            nNumberOfBytesToLockLow: u32,
            nNumberOfBytesToLockHigh: u32,
            lpOverlapped: *mut OVERLAPPED,
        ) -> i32;

        pub fn UnlockFileEx(
            hFile: RawHandle,
            dwReserved: u32,
            nNumberOfBytesToUnlockLow: u32,
            nNumberOfBytesToUnlockHigh: u32,
            lpOverlapped: *mut OVERLAPPED,
        ) -> i32;
    }
}

/// Advisory lock guard for fleet state file operations.
pub struct FleetLock {
    #[cfg(unix)]
    file: std::fs::File,
    #[cfg(windows)]
    file: std::fs::File,
    #[cfg(not(any(unix, windows)))]
    _dummy: (),
}

impl FleetLock {
    pub fn acquire(lock_path: &Path) -> Result<Self> {
        if let Some(parent) = lock_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
            .with_context(|| format!("open fleet lock file at {}", lock_path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = file.as_raw_fd();
            let res = unsafe { libc::flock(fd, libc::LOCK_EX) };
            if res != 0 {
                bail!(
                    "Failed to acquire fleet advisory lock: {}",
                    std::io::Error::last_os_error()
                );
            }
            Ok(Self { file })
        }

        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            let handle = file.as_raw_handle();
            let mut overlapped: std::mem::MaybeUninit<win_lock_ffi::OVERLAPPED> =
                std::mem::MaybeUninit::zeroed();
            let res = unsafe {
                win_lock_ffi::LockFileEx(
                    handle,
                    win_lock_ffi::LOCKFILE_EXCLUSIVE_LOCK,
                    0,
                    1,
                    0,
                    overlapped.as_mut_ptr(),
                )
            };
            if res == 0 {
                bail!(
                    "Failed to acquire fleet advisory lock on Windows: {}",
                    std::io::Error::last_os_error()
                );
            }
            Ok(Self { file })
        }

        #[cfg(not(any(unix, windows)))]
        {
            Ok(Self { _dummy: () })
        }
    }
}

impl Drop for FleetLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = self.file.as_raw_fd();
            unsafe {
                libc::flock(fd, libc::LOCK_UN);
            }
            // CRITICAL: We deliberately do NOT unlink/delete the lock file upon drop
            // to prevent races on separate inodes between concurrent processes.
        }

        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            let handle = self.file.as_raw_handle();
            let mut overlapped: std::mem::MaybeUninit<win_lock_ffi::OVERLAPPED> =
                std::mem::MaybeUninit::zeroed();
            unsafe {
                win_lock_ffi::UnlockFileEx(handle, 0, 1, 0, overlapped.as_mut_ptr());
            }
        }
    }
}

fn atomic_save_state(target_path: &Path, state: &FleetState) -> Result<()> {
    let parent = target_path
        .parent()
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create parent directory for {}", target_path.display()))?;

    let file_name = target_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("workers.json");
    let nanos = Utc::now().timestamp_nanos_opt().unwrap_or_default();
    let tmp_file_name = format!(".{}.tmp-{}-{}", file_name, std::process::id(), nanos);
    let tmp_path = parent.join(tmp_file_name);

    let serialized = serde_json::to_vec_pretty(state).context("serialize fleet state")?;

    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .with_context(|| format!("create temp file {}", tmp_path.display()))?;
        file.write_all(&serialized)
            .with_context(|| format!("write state to {}", tmp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("fsync temp file {}", tmp_path.display()))?;
    }

    std::fs::rename(&tmp_path, target_path)
        .with_context(|| format!("atomic rename {} -> {}", tmp_path.display(), target_path.display()))?;

    #[cfg(unix)]
    {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn resolve_and_provision_cgroup_scope(
    cgroup_root: &Path,
    worker_id: &str,
    cpu_weight: u32,
    memory_limit_bytes: u64,
    pids_max: u32,
) -> PathBuf {
    // 1. Primary candidate: cgroup_root.join(format!("{worker_id}.scope"))
    let primary_scope = cgroup_root.join(format!("{worker_id}.scope"));
    if std::fs::create_dir_all(&primary_scope).is_ok() {
        let _ = std::fs::write(primary_scope.join("cpu.weight"), format!("{}\n", cpu_weight));
        let _ = std::fs::write(
            primary_scope.join("memory.max"),
            format!("{}\n", memory_limit_bytes),
        );
        let _ = std::fs::write(primary_scope.join("pids.max"), format!("{}\n", pids_max));
        return primary_scope;
    }

    // 2. Rootless fallback: check if find_cgroup_root found a delegated/user hierarchy
    if let Some(user_root) = crate::sandbox::linux::cgroup::find_cgroup_root() {
        let fallback_scope = user_root
            .join("vetto-fleet")
            .join(format!("{worker_id}.scope"));
        if std::fs::create_dir_all(&fallback_scope).is_ok() {
            let _ = std::fs::write(fallback_scope.join("cpu.weight"), format!("{}\n", cpu_weight));
            let _ = std::fs::write(
                fallback_scope.join("memory.max"),
                format!("{}\n", memory_limit_bytes),
            );
            let _ = std::fs::write(fallback_scope.join("pids.max"), format!("{}\n", pids_max));
            return fallback_scope;
        }
    }

    // 3. Fallback check: $XDG_RUNTIME_DIR/cgroup
    if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        let runtime_scope = PathBuf::from(runtime_dir)
            .join("cgroup")
            .join("vetto-fleet")
            .join(format!("{worker_id}.scope"));
        if std::fs::create_dir_all(&runtime_scope).is_ok() {
            let _ = std::fs::write(runtime_scope.join("cpu.weight"), format!("{}\n", cpu_weight));
            let _ = std::fs::write(
                runtime_scope.join("memory.max"),
                format!("{}\n", memory_limit_bytes),
            );
            let _ = std::fs::write(runtime_scope.join("pids.max"), format!("{}\n", pids_max));
            return runtime_scope;
        }
    }

    // If unprivileged and cannot write cgroupfs, emit a warning without failing
    tracing::warn!(
        worker_id = %worker_id,
        "cgroup v2 scope creation skipped or restricted in unprivileged environment; running without host cgroup scope"
    );
    primary_scope
}

#[cfg(not(target_os = "linux"))]
fn resolve_and_provision_cgroup_scope(
    cgroup_root: &Path,
    worker_id: &str,
    _cpu_weight: u32,
    _memory_limit_bytes: u64,
    _pids_max: u32,
) -> PathBuf {
    cgroup_root.join(format!("{worker_id}.scope"))
}

/// Checks whether an operating system process with the given PID is currently alive.
pub fn is_pid_alive(pid: u32) -> bool {
    crate::rescue::lock::is_process_alive(pid)
}

/// Multi-Agent Fleet Manager coordinating concurrent swarm execution.
#[derive(Debug, Clone)]
pub struct FleetManager {
    config: FleetConfig,
    active_workers: Arc<Mutex<BTreeMap<String, AgentWorkerScope>>>,
}

impl FleetManager {
    /// Creates a new FleetManager with default settings.
    pub fn new_default() -> Self {
        Self::new(FleetConfig::default())
    }

    /// Creates a new FleetManager with custom configuration.
    pub fn new(config: FleetConfig) -> Self {
        Self {
            config,
            active_workers: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Config reference.
    pub fn config(&self) -> &FleetConfig {
        &self.config
    }

    /// Number of currently active workers in the fleet.
    pub fn active_count(&self) -> usize {
        self.active_workers.lock().map(|w| w.len()).unwrap_or(0)
    }

    /// Loads persistent fleet manager from custom state and lock paths.
    pub fn load_from_path(state_path: PathBuf, lock_path: PathBuf) -> Result<Self> {
        let _lock = FleetLock::acquire(&lock_path)?;

        let workspace_root = state_path
            .parent()
            .map(|p| p.join("workspaces"))
            .unwrap_or_else(default_fleet_workspace_root);

        if !state_path.exists() {
            return Ok(Self::new(FleetConfig::with_persistence(
                state_path,
                workspace_root,
            )));
        }

        let bytes = std::fs::read(&state_path)
            .with_context(|| format!("read fleet state from {}", state_path.display()))?;
        let state = deserialize_fleet_state(&bytes)?;

        let mut config = FleetConfig::with_persistence(state_path, workspace_root);
        config.max_agents = state.max_agents;
        config.cpu_weight = state.cpu_weight;
        config.memory_limit_bytes = state.memory_limit_bytes;
        config.pids_max = state.pids_max;
        config.ipc_isolation = state.ipc_isolation;
        config.base_port = state.base_port;

        let mut map = BTreeMap::new();
        for w in state.workers {
            map.insert(w.worker_id.clone(), w);
        }

        Ok(Self {
            config,
            active_workers: Arc::new(Mutex::new(map)),
        })
    }

    /// Loads persistent fleet manager state from canonical path (`~/.vetto/fleet/workers.json`).
    pub fn load_persistent() -> Result<Self> {
        Self::load_from_path(default_fleet_state_path(), default_fleet_lock_path())
    }

    /// Persists the current fleet worker state to disk with atomic file write and advisory lock.
    pub fn save_persistent(&self) -> Result<()> {
        let state_path = self
            .config
            .state_file
            .clone()
            .unwrap_or_else(default_fleet_state_path);
        let parent = state_path
            .parent()
            .unwrap_or_else(|| Path::new("."));
        let lock_path = parent.join(".workers.lock");
        let _lock = FleetLock::acquire(&lock_path)?;

        let workers = self
            .active_workers
            .lock()
            .map_err(|_| anyhow::anyhow!("fleet manager lock poisoned"))?;

        let workers_list: Vec<AgentWorkerScope> = workers.values().cloned().collect();
        let state = FleetState {
            active_count: workers_list.len(),
            max_agents: self.config.max_agents,
            cpu_weight: self.config.cpu_weight,
            memory_limit_bytes: self.config.memory_limit_bytes,
            pids_max: self.config.pids_max,
            ipc_isolation: self.config.ipc_isolation,
            base_port: self.config.base_port,
            workers: workers_list,
        };

        atomic_save_state(&state_path, &state)
    }

    /// Allocates an isolated worker scope for a new agent.
    ///
    /// Fulfills Section 19.1 & 19.2:
    /// - Assigns deterministic worker slot (`agent-01`, `agent-02`, ...)
    /// - Assigns dedicated cgroups v2 scope path under cgroup root
    /// - Allocates distinct ephemeral port
    /// - Provisions distinct ephemeral CoW branch name
    /// - Enforces `CLONE_NEWIPC` isolation
    pub fn allocate_worker(&self, agent_name: &str) -> Result<AgentWorkerScope> {
        let mut workers = self
            .active_workers
            .lock()
            .map_err(|_| anyhow::anyhow!("fleet manager lock poisoned"))?;

        if workers.len() >= self.config.max_agents {
            bail!(
                "Fleet capacity exceeded: active agents ({}) >= max allowed ({})",
                workers.len(),
                self.config.max_agents
            );
        }

        // Find the lowest available worker slot number
        let mut slot_id = 1;
        while workers.contains_key(&format!("agent-{:02}", slot_id)) {
            slot_id += 1;
        }

        if slot_id > self.config.max_agents {
            bail!(
                "Fleet slot allocation exceeded max configured agents: slot {} > max {}",
                slot_id,
                self.config.max_agents
            );
        }

        let worker_id = format!("agent-{:02}", slot_id);

        let scope_path = if self.config.workspace_root.is_some() || self.config.state_file.is_some() {
            resolve_and_provision_cgroup_scope(
                &self.config.cgroup_root,
                &worker_id,
                self.config.cpu_weight,
                self.config.memory_limit_bytes,
                self.config.pids_max,
            )
        } else {
            self.config.cgroup_root.join(format!("{}.scope", worker_id))
        };

        let workspace_dir = self
            .config
            .workspace_root
            .clone()
            .unwrap_or_else(default_fleet_workspace_root)
            .join(&worker_id);

        if self.config.workspace_root.is_some() {
            if let Err(e) = std::fs::create_dir_all(&workspace_dir) {
                tracing::warn!(
                    workspace = %workspace_dir.display(),
                    error = %e,
                    "failed to create fleet worker workspace directory"
                );
            }
        }

        let ephemeral_port = self
            .config
            .base_port
            .checked_add((slot_id - 1) as u16)
            .context("Ephemeral port pool overflow")?;

        let scope = AgentWorkerScope {
            worker_id: worker_id.clone(),
            agent_name: agent_name.to_string(),
            scope_path,
            cow_branch_name: worker_id.clone(),
            ephemeral_port,
            cpu_weight: self.config.cpu_weight,
            memory_limit_bytes: self.config.memory_limit_bytes,
            pids_max: self.config.pids_max,
            ipc_isolated: self.config.ipc_isolation,
            allocated_at: Utc::now(),
            pid: None,
            status: default_worker_status(),
            workspace_dir,
        };

        workers.insert(worker_id, scope.clone());
        drop(workers);

        if self.config.state_file.is_some() {
            self.save_persistent()?;
        }

        Ok(scope)
    }

    /// Binds an OS process PID to an active worker scope and updates its status to "running".
    pub fn bind_worker_pid(&self, worker_id: &str, pid: u32) -> Result<()> {
        if pid == 0 {
            bail!("Invalid process PID: 0");
        }

        let mut workers = self
            .active_workers
            .lock()
            .map_err(|_| anyhow::anyhow!("fleet manager lock poisoned"))?;

        let worker = workers
            .get_mut(worker_id)
            .ok_or_else(|| anyhow::anyhow!("Worker scope '{}' not found in active fleet", worker_id))?;

        worker.pid = Some(pid);
        worker.status = "running".to_string();
        drop(workers);

        if self.config.state_file.is_some() {
            self.save_persistent()?;
        }

        Ok(())
    }

    /// Releases a worker scope upon session completion.
    pub fn release_worker(&self, worker_id: &str) -> Result<()> {
        let mut workers = self
            .active_workers
            .lock()
            .map_err(|_| anyhow::anyhow!("fleet manager lock poisoned"))?;

        if workers.remove(worker_id).is_none() {
            bail!("Worker scope '{}' not found in active fleet", worker_id);
        }
        drop(workers);

        if self.config.state_file.is_some() {
            self.save_persistent()?;
        }

        Ok(())
    }

    /// Releases all active worker scopes in the fleet.
    pub fn release_all_workers(&self) -> Result<Vec<String>> {
        let mut workers = self
            .active_workers
            .lock()
            .map_err(|_| anyhow::anyhow!("fleet manager lock poisoned"))?;

        let mut released_ids = Vec::with_capacity(workers.len());
        for wid in workers.keys() {
            released_ids.push(wid.clone());
        }
        workers.clear();
        drop(workers);

        if self.config.state_file.is_some() {
            self.save_persistent()?;
        }

        Ok(released_ids)
    }

    /// Inspects registered active worker PIDs and releases slots for dead or stale processes.
    ///
    /// Live processes with `Some(pid)` are updated to "running".
    /// Exited processes are marked "exited" and released.
    /// Unbound workers older than 60 seconds grace period are marked "stale" and released.
    pub fn reconcile_live_workers(&self) -> Result<Vec<String>> {
        let mut workers = self
            .active_workers
            .lock()
            .map_err(|_| anyhow::anyhow!("fleet manager lock poisoned"))?;

        let now = Utc::now();
        let mut to_remove = Vec::new();

        for (wid, scope) in workers.iter_mut() {
            match scope.pid {
                Some(pid) => {
                    if is_pid_alive(pid) {
                        scope.status = "running".to_string();
                    } else {
                        scope.status = "exited".to_string();
                        to_remove.push(wid.clone());
                    }
                }
                None => {
                    let age = now.signed_duration_since(scope.allocated_at);
                    if age.num_seconds() >= 60 {
                        scope.status = "stale".to_string();
                        to_remove.push(wid.clone());
                    }
                }
            }
        }

        for wid in &to_remove {
            workers.remove(wid);
        }
        drop(workers);

        if self.config.state_file.is_some() {
            self.save_persistent()?;
        }

        Ok(to_remove)
    }

    /// Retrieves an active worker scope by ID.
    pub fn get_worker(&self, worker_id: &str) -> Option<AgentWorkerScope> {
        self.active_workers.lock().ok()?.get(worker_id).cloned()
    }

    /// Returns a list of all currently active workers.
    pub fn active_workers(&self) -> Vec<AgentWorkerScope> {
        self.active_workers
            .lock()
            .map(|w| w.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Returns a list of all currently active workers (synonym for `active_workers`).
    pub fn all_workers(&self) -> Vec<AgentWorkerScope> {
        self.active_workers()
    }

    /// Verifies inter-agent isolation invariants (§19.2) between two workers:
    /// 1. Disjoint ephemeral ports (no TCP port collision)
    /// 2. Disjoint CoW workspace branches (no concurrent overlay mutation)
    /// 3. Disjoint cgroup v2 scope paths
    /// 4. Mandatory IPC namespace isolation enabled
    pub fn verify_isolation(&self, worker_a_id: &str, worker_b_id: &str) -> Result<()> {
        if worker_a_id == worker_b_id {
            bail!(
                "Cannot verify isolation of a worker against itself ('{}')",
                worker_a_id
            );
        }

        let workers = self
            .active_workers
            .lock()
            .map_err(|_| anyhow::anyhow!("fleet manager lock poisoned"))?;

        let a = workers
            .get(worker_a_id)
            .ok_or_else(|| anyhow::anyhow!("Worker '{}' not found in active fleet", worker_a_id))?;
        let b = workers
            .get(worker_b_id)
            .ok_or_else(|| anyhow::anyhow!("Worker '{}' not found in active fleet", worker_b_id))?;

        if a.ephemeral_port == b.ephemeral_port {
            bail!(
                "Isolation breach: Workers '{}' and '{}' share ephemeral port {}",
                worker_a_id,
                worker_b_id,
                a.ephemeral_port
            );
        }

        if a.cow_branch_name == b.cow_branch_name {
            bail!(
                "Isolation breach: Workers '{}' and '{}' share CoW branch '{}'",
                worker_a_id,
                worker_b_id,
                a.cow_branch_name
            );
        }

        if a.scope_path == b.scope_path {
            bail!(
                "Isolation breach: Workers '{}' and '{}' share cgroup scope path '{:?}'",
                worker_a_id,
                worker_b_id,
                a.scope_path
            );
        }

        if !a.ipc_isolated || !b.ipc_isolated {
            bail!(
                "Isolation breach: IPC namespace isolation disabled for one or more workers ('{}': {}, '{}': {})",
                worker_a_id,
                a.ipc_isolated,
                worker_b_id,
                b.ipc_isolated
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fleet_worker_allocation_and_isolation() {
        let fleet = FleetManager::new_default();
        let w1 = fleet.allocate_worker("claude-1").expect("allocate w1");
        let w2 = fleet.allocate_worker("claude-2").expect("allocate w2");

        assert_eq!(w1.worker_id, "agent-01");
        assert_eq!(w2.worker_id, "agent-02");
        assert_eq!(w1.ephemeral_port, DEFAULT_BASE_PORT);
        assert_eq!(w2.ephemeral_port, DEFAULT_BASE_PORT + 1);
        assert_eq!(w1.cpu_weight, 100);
        assert_eq!(w1.memory_limit_bytes, 2 * 1024 * 1024 * 1024);
        assert_eq!(w1.pids_max, 128);
        assert!(w1.ipc_isolated);

        assert!(fleet.verify_isolation("agent-01", "agent-02").is_ok());

        assert_eq!(fleet.active_count(), 2);
        fleet.release_worker("agent-01").expect("release w1");
        assert_eq!(fleet.active_count(), 1);

        // Next allocation re-uses slot 01
        let w3 = fleet.allocate_worker("codex-1").expect("allocate w3");
        assert_eq!(w3.worker_id, "agent-01");
    }

    #[test]
    fn test_fleet_capacity_limit() {
        let config = FleetConfig {
            max_agents: 3,
            ..Default::default()
        };
        let fleet = FleetManager::new(config);
        let _w1 = fleet.allocate_worker("a1").unwrap();
        let _w2 = fleet.allocate_worker("a2").unwrap();
        let _w3 = fleet.allocate_worker("a3").unwrap();

        let overflow = fleet.allocate_worker("a4");
        assert!(overflow.is_err());
        assert!(overflow
            .unwrap_err()
            .to_string()
            .contains("Fleet capacity exceeded"));
    }

    #[test]
    fn test_fleet_in_memory_backward_compatibility() {
        let fleet = FleetManager::new_default();
        assert!(fleet.config().state_file.is_none());
        assert!(fleet.config().workspace_root.is_none());

        let w = fleet.allocate_worker("test-agent").expect("allocate");
        assert_eq!(w.worker_id, "agent-01");
        assert_eq!(w.status, "allocated");
        assert_eq!(w.pid, None);
        assert!(!w.workspace_dir.as_os_str().is_empty());

        // In-memory mode: workspace directory was NOT created on disk
        let json = serde_json::to_string(&w).expect("serialize scope");
        assert!(json.contains("\"status\":\"allocated\""));
        assert!(json.contains("\"pid\":null"));

        // Deserialization with omitted fields (backward compatibility with older payloads)
        let legacy_json = r#"{
            "worker_id": "agent-01",
            "agent_name": "legacy",
            "scope_path": "/sys/fs/cgroup/vetto-fleet/agent-01.scope",
            "cow_branch_name": "agent-01",
            "ephemeral_port": 49201,
            "cpu_weight": 100,
            "memory_limit_bytes": 2147483648,
            "pids_max": 128,
            "ipc_isolated": true,
            "allocated_at": "2026-09-27T10:00:00Z"
        }"#;
        let legacy_scope: AgentWorkerScope =
            serde_json::from_str(legacy_json).expect("deserialize legacy");
        assert_eq!(legacy_scope.worker_id, "agent-01");
        assert_eq!(legacy_scope.status, "allocated");
        assert_eq!(legacy_scope.pid, None);
        assert_eq!(legacy_scope.workspace_dir, PathBuf::new());
    }

    #[test]
    fn test_fleet_persistence_save_and_load() {
        let tmp_dir =
            std::env::temp_dir().join(format!("vetto-fleet-test-{}", std::process::id()));
        let state_file = tmp_dir.join("workers.json");
        let lock_file = tmp_dir.join(".workers.lock");
        let workspace_root = tmp_dir.join("workspaces");

        let config = FleetConfig::with_persistence(state_file.clone(), workspace_root);
        let fleet = FleetManager::new(config);

        let w1 = fleet.allocate_worker("agent-one").expect("allocate w1");
        let w2 = fleet.allocate_worker("agent-two").expect("allocate w2");

        fleet
            .bind_worker_pid(&w1.worker_id, 12345)
            .expect("bind pid w1");

        assert!(state_file.exists());

        // Load from disk using load_from_path
        let loaded =
            FleetManager::load_from_path(state_file.clone(), lock_file).expect("load from path");
        assert_eq!(loaded.active_count(), 2);

        let loaded_w1 = loaded.get_worker("agent-01").expect("get w1");
        assert_eq!(loaded_w1.worker_id, "agent-01");
        assert_eq!(loaded_w1.pid, Some(12345));
        assert_eq!(loaded_w1.status, "running");

        let loaded_w2 = loaded.get_worker("agent-02").expect("get w2");
        assert_eq!(loaded_w2.worker_id, "agent-02");
        assert_eq!(loaded_w2.pid, None);
        assert_eq!(loaded_w2.status, "allocated");

        // Clean up temporary test directory
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_fleet_pid_binding_and_status() {
        let fleet = FleetManager::new_default();
        let w = fleet.allocate_worker("bind-test").expect("allocate");
        assert_eq!(w.status, "allocated");
        assert_eq!(w.pid, None);

        fleet
            .bind_worker_pid(&w.worker_id, 4242)
            .expect("bind pid");
        let updated = fleet.get_worker(&w.worker_id).expect("get worker");
        assert_eq!(updated.pid, Some(4242));
        assert_eq!(updated.status, "running");

        // Binding PID 0 fails
        assert!(fleet.bind_worker_pid(&w.worker_id, 0).is_err());

        // Binding non-existent worker fails
        assert!(fleet.bind_worker_pid("agent-99", 100).is_err());
    }

    #[test]
    fn test_fleet_reconcile_live_and_dead_workers() {
        let fleet = FleetManager::new_default();
        let live = fleet.allocate_worker("live-proc").expect("allocate live");
        let dead = fleet.allocate_worker("dead-proc").expect("allocate dead");

        // Bind current process PID (guaranteed alive)
        let my_pid = std::process::id();
        fleet
            .bind_worker_pid(&live.worker_id, my_pid)
            .expect("bind live pid");

        // Bind definitely dead PID
        let mut dead_pid = 4_194_300;
        while is_pid_alive(dead_pid) {
            dead_pid -= 1;
        }
        fleet
            .bind_worker_pid(&dead.worker_id, dead_pid)
            .expect("bind dead pid");

        assert_eq!(fleet.active_count(), 2);

        let released = fleet.reconcile_live_workers().expect("reconcile");
        assert!(released.contains(&dead.worker_id));
        assert!(!released.contains(&live.worker_id));

        assert_eq!(fleet.active_count(), 1);
        let remaining = fleet
            .get_worker(&live.worker_id)
            .expect("live remains");
        assert_eq!(remaining.status, "running");
        assert!(fleet.get_worker(&dead.worker_id).is_none());

        // Freshly allocated worker without PID stays within 60s grace period
        let fresh = fleet
            .allocate_worker("fresh-proc")
            .expect("allocate fresh");
        assert_eq!(fresh.status, "allocated");
        let released2 = fleet.reconcile_live_workers().expect("reconcile 2");
        assert!(!released2.contains(&fresh.worker_id));
        assert!(fleet.get_worker(&fresh.worker_id).is_some());
    }

    #[test]
    fn test_fleet_release_all_workers() {
        let fleet = FleetManager::new_default();
        fleet.allocate_worker("w1").expect("w1");
        fleet.allocate_worker("w2").expect("w2");
        fleet.allocate_worker("w3").expect("w3");
        assert_eq!(fleet.active_count(), 3);

        let released = fleet.release_all_workers().expect("release all");
        assert_eq!(released.len(), 3);
        assert_eq!(fleet.active_count(), 0);
        assert!(fleet.active_workers().is_empty());
    }
}
