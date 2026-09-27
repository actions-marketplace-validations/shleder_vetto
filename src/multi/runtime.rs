//! Fail-closed multi-agent launcher.
//!
//! Every `MultiSession` owns its own `SpawnedProductionExecution` (frozen
//! inputs + prepared Stage 3B backend + real child + nonce + sweep
//! identity), event bus, stats collector and captured stdout/stderr
//! buffers. There is no shared child process, no shared backend state, and
//! no unsandboxed fallback. All backend detection and policy loading happens
//! before any process is spawned; a spawn failure tears down already-created
//! executions and returns an error to the caller.
//!
//! Phase 4 (Step 23 & 24): Virtual port allocation, debug port guardrails,
//! sub-reaper configuration, and cross-agent isolation tracking.

#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
#[cfg(unix)]
use std::sync::atomic::Ordering;
use std::sync::{atomic::AtomicBool, Arc, Mutex};
use std::time::Instant;

#[cfg(unix)]
use crate::config::NetMode;
use crate::error::VettoError;
#[cfg(unix)]
use crate::events::Event;
use crate::events::EventBus;
use crate::multi::fleet::{AgentWorkerScope, FleetManager};
use crate::multi::isolation::IsolationBarrier;
use crate::multi::{AgentSpec, Manifest, MultiAggregator, MultiEventStream, VirtualPortPool};
#[cfg(unix)]
use crate::policy;
use crate::report::stats::StatsCollector;
use crate::report::{self, storage::ReportStorage, ReportOptions};
#[cfg(unix)]
use crate::sandbox::{Backend, StdioMode};
#[cfg(unix)]
use anyhow::bail;
use anyhow::{Context, Result};

#[cfg(unix)]
use std::collections::HashMap;
#[cfg(unix)]
use std::io::Read;
#[cfg(target_os = "linux")]
use std::os::fd::IntoRawFd;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

#[cfg(unix)]
const OUTPUT_CAP: usize = 512 * 1024;

#[derive(Default)]
pub struct OutputBuffers {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl OutputBuffers {
    pub fn text(&self) -> String {
        let mut bytes = self.stdout.clone();
        bytes.extend_from_slice(&self.stderr);
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

pub struct MultiSession {
    pub spec: AgentSpec,
    pub bus: EventBus,
    pub stats: StatsCollector,
    pub output: Arc<Mutex<OutputBuffers>>,
    /// Shared ownership of the SAME `SpawnedProductionExecution` that owns
    /// the backend state, nonce and sweep identity: dashboards lock it for
    /// pause/resume/terminate/try_wait, the wait thread locks it for the
    /// proven wait + `finish` (nonce sweep + teardown + typed report).
    /// Single owner, no handle/execution split, no shared backend state.
    pub execution: Arc<Mutex<Option<crate::sandbox::production::SpawnedProductionExecution>>>,
    pub finished: Arc<AtomicBool>,
    pub started: Instant,
    pub allocated_ports: Vec<u16>,
    /// Stage 3C per-run identity: the nonce the execution boundary minted
    /// for this agent (also in the child env for the nonce-targeted sweep).
    /// Never shared across agents.
    pub prod_nonce: String,
    /// Host-observed root PID of this agent's child (owned by the boundary
    /// spawn, used by the wait thread for the nonce sweep).
    pub root_pid: u32,
    /// Allocated FleetManager worker scope for this agent.
    pub worker_scope: Option<AgentWorkerScope>,
}

#[cfg(unix)]
struct PendingSession {
    spec: AgentSpec,
    bus: EventBus,
    execution: crate::sandbox::production::SpawnedProductionExecution,
    stdout_r: OwnedFd,
    stderr_r: OwnedFd,
    allocated_ports: Vec<u16>,
    worker_scope: AgentWorkerScope,
}

impl MultiSession {
    fn with_execution<R>(
        &self,
        f: impl FnOnce(&mut crate::sandbox::production::SpawnedProductionExecution) -> R,
    ) -> Option<R> {
        self.execution.lock().ok()?.as_mut().map(f)
    }

    pub fn pause(&self) {
        let _ = self.with_execution(|e| e.handle.pause());
    }

    pub fn resume(&self) {
        let _ = self.with_execution(|e| e.handle.resume());
    }

    pub fn terminate(&self) {
        let _ = self.with_execution(|e| e.handle.terminate());
    }

    pub fn try_wait(&self) -> Option<i32> {
        self.with_execution(|e| e.handle.try_wait()).flatten()
    }

    pub fn output_text(&self) -> String {
        self.output
            .lock()
            .map(|output| output.text())
            .unwrap_or_default()
    }

    /// Returns the fleet worker ID if assigned to this session.
    pub fn worker_id(&self) -> Option<&str> {
        self.worker_scope.as_ref().map(|s| s.worker_id.as_str())
    }

    /// Returns a reference to the allocated worker scope if available.
    pub fn worker_scope(&self) -> Option<&AgentWorkerScope> {
        self.worker_scope.as_ref()
    }
}

pub struct MultiRuntime {
    pub manifest: Manifest,
    pub sessions: Vec<MultiSession>,
    pub stream: MultiEventStream,
    pub aggregator: MultiAggregator,
    pub port_pool: VirtualPortPool,
    pub isolation_barrier: IsolationBarrier,
    pub fleet_manager: FleetManager,
    pub report_dir: Option<PathBuf>,
}

impl MultiRuntime {
    /// Creates a new MultiRuntime with a default FleetManager.
    pub fn new(
        manifest: Manifest,
        sessions: Vec<MultiSession>,
        stream: MultiEventStream,
        aggregator: MultiAggregator,
        port_pool: VirtualPortPool,
        isolation_barrier: IsolationBarrier,
        report_dir: Option<PathBuf>,
    ) -> Self {
        Self {
            manifest,
            sessions,
            stream,
            aggregator,
            port_pool,
            isolation_barrier,
            fleet_manager: FleetManager::new_default(),
            report_dir,
        }
    }

    /// Creates a new MultiRuntime with an explicit FleetManager.
    pub fn with_fleet_manager(
        manifest: Manifest,
        sessions: Vec<MultiSession>,
        stream: MultiEventStream,
        aggregator: MultiAggregator,
        port_pool: VirtualPortPool,
        isolation_barrier: IsolationBarrier,
        fleet_manager: FleetManager,
        report_dir: Option<PathBuf>,
    ) -> Self {
        Self {
            manifest,
            sessions,
            stream,
            aggregator,
            port_pool,
            isolation_barrier,
            fleet_manager,
            report_dir,
        }
    }

    /// Returns a reference to the runtime's FleetManager.
    pub fn fleet_manager(&self) -> &FleetManager {
        &self.fleet_manager
    }

    /// Returns a mutable reference to the runtime's FleetManager.
    pub fn fleet_manager_mut(&mut self) -> &mut FleetManager {
        &mut self.fleet_manager
    }
    /// Prepare and launch all agents. The preflight phase deliberately owns
    /// no child handles: invalid policy/network/command input is rejected
    /// before the first fork. Once spawning begins, any failure terminates
    /// every already-created sandbox and releases allocated worker scopes
    /// before returning the error.
    #[cfg(unix)]
    pub fn launch(manifest: Manifest, project: PathBuf, home: PathBuf) -> Result<Self> {
        let fleet_manager = if std::env::var_os("VETTO_FLEET_PERSISTENT").is_some() {
            FleetManager::load_persistent().unwrap_or_else(|_| FleetManager::new_default())
        } else {
            FleetManager::new_default()
        };
        Self::launch_with_fleet(manifest, project, home, fleet_manager)
    }

    /// Prepare and launch all agents with a custom or persistent FleetManager.
    #[cfg(unix)]
    pub fn launch_with_fleet(
        manifest: Manifest,
        project: PathBuf,
        home: PathBuf,
        fleet_manager: FleetManager,
    ) -> Result<Self> {
        manifest.validate()?;

        // Configure supervisor process as sub-reaper so orphaned child processes
        // inside agent PID namespaces are adopted and reaped by Vetto.
        let _ = crate::multi::isolation::set_subreaper();

        let port_pool = VirtualPortPool::default();
        let isolation_barrier = IsolationBarrier::new();

        let mut prepared = Vec::with_capacity(manifest.agents.len());
        let mut allocated_worker_ids = Vec::with_capacity(manifest.agents.len());

        for (idx, spec) in manifest.agents.iter().enumerate() {
            let worker_scope = match fleet_manager.allocate_worker(&spec.name) {
                Ok(scope) => {
                    allocated_worker_ids.push(scope.worker_id.clone());
                    scope
                }
                Err(err) => {
                    for wid in &allocated_worker_ids {
                        let _ = fleet_manager.release_worker(wid);
                    }
                    return Err(err).with_context(|| {
                        format!("allocate fleet worker scope for agent '{}'", spec.name)
                    });
                }
            };

            let net = match crate::config::parse_net_mode(&spec.net) {
                Ok(n) => n,
                Err(err) => {
                    for wid in &allocated_worker_ids {
                        let _ = fleet_manager.release_worker(wid);
                    }
                    return Err(err).with_context(|| format!("agent '{}' network mode", spec.name));
                }
            };

            let backend = match Backend::detect(net.clone(), spec.observe_seccomp) {
                Ok(b) => b,
                Err(err) => {
                    for wid in &allocated_worker_ids {
                        let _ = fleet_manager.release_worker(wid);
                    }
                    return Err(err).with_context(|| {
                        format!("establish sandbox backend for agent '{}'", spec.name)
                    });
                }
            };

            let tier = backend.tier().unwrap_or(policy::Tier::Full);
            let policy = match policy::loader::load(
                &spec.profile,
                spec.policy.as_deref(),
                &project,
                &home,
                tier,
            ) {
                Ok(p) => p,
                Err(err) => {
                    for wid in &allocated_worker_ids {
                        let _ = fleet_manager.release_worker(wid);
                    }
                    return Err(err)
                        .with_context(|| format!("load policy for agent '{}'", spec.name));
                }
            };

            let mut command = spec.command.clone();
            command[0] = match resolve_in_path(&command[0]) {
                Ok(c) => c,
                Err(err) => {
                    for wid in &allocated_worker_ids {
                        let _ = fleet_manager.release_worker(wid);
                    }
                    return Err(err)
                        .with_context(|| format!("resolve command for agent '{}'", spec.name));
                }
            };

            // Do not silently permit a policy to exclude the executable.
            if !policy.in_read_scope(Path::new(&command[0])) {
                tracing::warn!(
                    agent = %spec.name,
                    command = %command[0],
                    "agent executable is outside policy read scope; sandbox exec may be denied"
                );
            }

            let allocated_ports = port_pool
                .allocate_ports(&spec.name, 4)
                .unwrap_or_else(|_| vec![port_pool.allocate_relay_port(idx)]);

            prepared.push(Prepared {
                spec: spec.clone(),
                net,
                backend: Some(backend),
                policy,
                command,
                allocated_ports,
                worker_scope,
            });
        }

        // Full pairwise isolation verification across all allocated worker scopes before fork
        for i in 0..prepared.len() {
            for j in (i + 1)..prepared.len() {
                if let Err(err) = fleet_manager.verify_isolation(
                    &prepared[i].worker_scope.worker_id,
                    &prepared[j].worker_scope.worker_id,
                ) {
                    for wid in &allocated_worker_ids {
                        let _ = fleet_manager.release_worker(wid);
                    }
                    return Err(err).with_context(|| {
                        format!(
                            "pairwise fleet isolation verification failed between '{}' and '{}'",
                            prepared[i].spec.name, prepared[j].spec.name
                        )
                    });
                }
            }
        }

        // Single-threaded fork phase (only serialization: fork-safety).
        // Agents run concurrently afterwards; each owns its execution.
        let mut pending = Vec::with_capacity(prepared.len());
        for prep in prepared {
            match spawn_one(prep, &project, &fleet_manager) {
                Ok(session) => pending.push(session),
                Err(error) => {
                    for session in pending.iter_mut() {
                        // Fail-closed: terminate the already-spawned boundary
                        // children via their own executions (handle Drop also
                        // terminates; explicit first for prompt teardown).
                        session.execution.handle.terminate();
                    }
                    for wid in &allocated_worker_ids {
                        let _ = fleet_manager.release_worker(wid);
                    }
                    return Err(anyhow::Error::new(VettoError::Sandbox(format!(
                        "multi-agent launch aborted; no unsandboxed fallback: {error:#}"
                    ))));
                }
            }
        }

        // Full pairwise isolation verification across all allocated worker scopes before activation
        for i in 0..pending.len() {
            for j in (i + 1)..pending.len() {
                if let Err(err) = fleet_manager.verify_isolation(
                    &pending[i].worker_scope.worker_id,
                    &pending[j].worker_scope.worker_id,
                ) {
                    for session in pending.iter_mut() {
                        session.execution.handle.terminate();
                    }
                    for wid in &allocated_worker_ids {
                        let _ = fleet_manager.release_worker(wid);
                    }
                    return Err(err).with_context(|| {
                        format!(
                            "pre-activation fleet isolation verification failed between '{}' and '{}'",
                            pending[i].spec.name, pending[j].spec.name
                        )
                    });
                }
            }
        }

        let stream = MultiEventStream::new();
        let aggregator =
            MultiAggregator::new(manifest.agents.iter().map(|agent| agent.name.clone()));
        crate::multi::spawn_aggregator(&stream, aggregator.clone());
        let mut sessions = Vec::with_capacity(pending.len());
        for pending in pending {
            let session = activate_pending(
                pending,
                &project,
                &stream,
                &isolation_barrier,
                &fleet_manager,
            );
            sessions.push(session);
        }

        Ok(Self {
            report_dir: manifest.report_dir.clone(),
            manifest,
            sessions,
            stream,
            aggregator,
            port_pool,
            isolation_barrier,
            fleet_manager,
        })
    }

    #[cfg(not(unix))]
    pub fn launch(_manifest: Manifest, _project: PathBuf, _home: PathBuf) -> Result<Self> {
        Err(anyhow::Error::new(VettoError::UnsupportedPlatform(
            "multi-agent",
        )))
    }

    #[cfg(not(unix))]
    pub fn launch_with_fleet(
        _manifest: Manifest,
        _project: PathBuf,
        _home: PathBuf,
        _fleet_manager: FleetManager,
    ) -> Result<Self> {
        Err(anyhow::Error::new(VettoError::UnsupportedPlatform(
            "multi-agent",
        )))
    }

    pub fn terminate(&self, index: usize) -> Result<()> {
        let session = self
            .sessions
            .get(index)
            .ok_or_else(|| anyhow::anyhow!("unknown multi-agent pane {index}"))?;
        session.terminate();
        Ok(())
    }

    pub fn terminate_all(&self) {
        for session in &self.sessions {
            session.terminate();
        }
    }

    pub fn combined_report(&self) -> serde_json::Value {
        self.aggregator.report_json()
    }

    pub fn write_reports(&self) -> Result<Vec<PathBuf>> {
        let mut written = Vec::new();
        let rows = self.aggregator.snapshot();
        for agent in &self.manifest.agents {
            let dir = agent.report_path(self.report_dir.as_deref());
            let options = ReportOptions {
                report_dir: Some(dir),
                auto_cleanup: false,
                retention: None,
                max_age_secs: None,
            };
            let storage = ReportStorage::new(&options)
                .with_context(|| format!("prepare report directory for agent '{}'", agent.name))?;
            let row = rows
                .iter()
                .find(|stats| stats.name == agent.name)
                .cloned()
                .unwrap_or_else(|| crate::multi::AgentStats::new(agent.name.clone()));
            let mut value = serde_json::to_value(row).context("serialize agent report")?;
            report::sanitize_json_strings(&mut value);
            let text = serde_json::to_string_pretty(&value).context("render agent report")?;
            let path = storage
                .write("json", &text)
                .with_context(|| format!("write report for agent '{}'", agent.name))?;
            written.push(path);
        }
        let combined_dir = self
            .report_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("."));
        let options = ReportOptions {
            report_dir: Some(combined_dir),
            auto_cleanup: false,
            retention: None,
            max_age_secs: None,
        };
        let storage = ReportStorage::new(&options).context("prepare combined report directory")?;
        let mut combined = self.combined_report();
        report::sanitize_json_strings(&mut combined);
        let combined = serde_json::to_string_pretty(&combined).context("render combined report")?;
        let combined_path = storage
            .write("json", &combined)
            .context("write combined report")?;
        written.push(combined_path);
        Ok(written)
    }
}

#[cfg(unix)]
struct Prepared {
    spec: AgentSpec,
    net: NetMode,
    backend: Option<Backend>,
    policy: policy::Policy,
    command: Vec<String>,
    allocated_ports: Vec<u16>,
    worker_scope: AgentWorkerScope,
}

#[cfg(unix)]
fn spawn_one(
    prepared: Prepared,
    project: &Path,
    fleet_manager: &FleetManager,
) -> Result<PendingSession> {
    let Prepared {
        spec,
        net,
        backend,
        policy,
        command,
        allocated_ports,
        worker_scope,
    } = prepared;
    let backend = backend.ok_or_else(|| anyhow::anyhow!("sandbox backend was consumed"))?;
    let (stdout_r, stdout_w) = pipe2()?;
    let (stderr_r, stderr_w) = pipe2()?;
    // Stage 3C authoritative boundary, one execution per agent: the SAME
    // object owns frozen policy/identity/nonce, the prepared Stage 3B
    // backend, and the real child spawn (Full namespaces + mounts + relay
    // through the legacy mechanics it owns). No backend state, FrozenSpec,
    // nonce or spawn ledger is ever shared across agents. `prepare` fails
    // closed with no spawn possible; `spawn` consumes the preparation so one
    // backend cannot be prepared while another is spawned.
    let mut extra = relay_env(&net);
    extra.insert(
        "VETTO_FLEET_WORKER_ID".to_string(),
        worker_scope.worker_id.clone(),
    );
    extra.insert(
        "VETTO_FLEET_PORT".to_string(),
        worker_scope.ephemeral_port.to_string(),
    );
    extra.insert(
        "VETTO_FLEET_WORKSPACE".to_string(),
        worker_scope.workspace_dir.to_string_lossy().into_owned(),
    );

    let unprepared = crate::sandbox::production::UnpreparedProductionExecution::new(
        backend,
        policy,
        command,
        project.to_path_buf(),
        extra,
        net,
        // Multi-agent sessions are interactive (dashboard/bridge driven):
        // no headless deadline is frozen; the wait thread below polls to
        // natural exit through the proven killer path.
        None,
        StdioMode::Captured {
            stdout_w: stdout_w.as_raw_fd(),
            stderr_w: stderr_w.as_raw_fd(),
        },
        format!("multi:{}", spec.name),
    )
    .with_debug_ports(spec.debug_ports.clone().unwrap_or_default());
    let prepared_exec = unprepared
        .prepare()
        .with_context(|| format!("prepare sandbox for agent '{}'", spec.name))?;
    let execution = prepared_exec
        .spawn()
        .with_context(|| format!("spawn agent '{}' inside its sandbox", spec.name))?;

    let root_pid = execution.handle.root_pid;
    if let Err(err) = fleet_manager.bind_worker_pid(&worker_scope.worker_id, root_pid) {
        let mut exec = execution;
        exec.handle.terminate();
        return Err(err).with_context(|| {
            format!(
                "bind worker PID {} for agent '{}' ({})",
                root_pid, spec.name, worker_scope.worker_id
            )
        });
    }

    drop(stdout_w);
    drop(stderr_w);

    Ok(PendingSession {
        spec,
        bus: EventBus::new(),
        execution,
        stdout_r,
        stderr_r,
        allocated_ports,
        worker_scope,
    })
}

#[cfg(unix)]
fn activate_pending(
    pending: PendingSession,
    project: &Path,
    stream: &MultiEventStream,
    isolation_barrier: &IsolationBarrier,
    fleet_manager: &FleetManager,
) -> MultiSession {
    #[cfg(not(target_os = "linux"))]
    let _ = project;
    // `take_*` below is Linux-only: `mut` is dead on macOS, required on
    // Linux. `allow` keeps one spelling, not two.
    #[allow(unused_mut)]
    let PendingSession {
        spec,
        bus,
        mut execution,
        stdout_r,
        stderr_r,
        allocated_ports,
        worker_scope,
    } = pending;
    let contract = execution.contract().clone();
    let production = contract
        .production
        .as_ref()
        .expect("validated production contract");
    let policy = &production.installation_policy;
    let net = &production.net;
    let tier = production.tier;
    // Per-run identity owned by the boundary spawn: nonce binds the frozen
    // spec, the backend report and the nonce-targeted tree sweep below.
    let prod_nonce = execution.nonce().to_string();
    let stats = StatsCollector::spawn(&bus);
    let root_pid = execution.handle.root_pid;

    // Register agent in the isolation barrier
    let is_full = tier == Some(policy::Tier::Full);
    isolation_barrier.register_agent(
        &spec.name,
        root_pid,
        is_full,
        is_full,
        policy.limits.address_space_bytes,
    );

    // Subscribe the aggregate bridge before publishing SessionStarted
    stream.bridge_agent(spec.name.clone(), &bus);
    bus.publish(Event::SessionStarted {
        ts: crate::events::types::now(),
        pid: root_pid,
        tier: tier.map(|tier| tier.label()).unwrap_or("none").to_string(),
        net_mode: net.label(),
        profile: policy.name.clone(),
        shadow: false,
    });

    #[cfg(target_os = "linux")]
    {
        if let Some(fd) = execution.take_broker_ctrl_fd() {
            let broker_policy = match net {
                NetMode::Allowlist(domains) => {
                    crate::sandbox::linux::net_relay::BrokerPolicy::Allowlist(domains.clone())
                }
                NetMode::Strict(rules) => {
                    crate::sandbox::linux::net_relay::BrokerPolicy::Strict(rules.clone())
                }
                NetMode::Ask => crate::sandbox::linux::net_relay::BrokerPolicy::Ask(
                    policy.network_allow.clone(),
                ),
                NetMode::Off => {
                    crate::sandbox::linux::net_relay::BrokerPolicy::Allowlist(Vec::new())
                }
            };
            let debug_config = production
                .debug_ports
                .as_ref()
                .map(|p| crate::sandbox::linux::debug_guard::DebugPortConfig {
                    isolate_devtools: p.isolate_devtools,
                    isolate_node_inspect: p.isolate_node_inspect,
                    isolate_debugpy: p.isolate_debugpy,
                    allowed_ports: p.allowed_ports.clone(),
                })
                .expect("multi preparation binds resolved debug port configuration");
            let debug_guard = crate::sandbox::linux::debug_guard::DebugPortGuard::new(debug_config);
            let broker_config = crate::sandbox::linux::net_relay::BrokerConfig {
                policy: broker_policy,
                debug_guard: Some(debug_guard),
                mode: crate::sandbox::linux::net_relay::RelayMode::NetNs,
                allow_cidr: policy.allow_cidr.clone(),
                quotas: policy.net_quota.clone(),
                policy_path: spec.policy.as_ref().map(std::path::PathBuf::from),
                block_doh: matches!(
                    net,
                    crate::config::NetMode::Allowlist(_) | crate::config::NetMode::Strict(_)
                ),
                http_proxy: std::env::var("HTTP_PROXY")
                    .or_else(|_| std::env::var("http_proxy"))
                    .ok(),
                https_proxy: std::env::var("HTTPS_PROXY")
                    .or_else(|_| std::env::var("https_proxy"))
                    .ok(),
                no_proxy: std::env::var("NO_PROXY")
                    .or_else(|_| std::env::var("no_proxy"))
                    .ok(),
            };
            crate::sandbox::linux::net_relay::spawn_broker(
                fd.into_raw_fd(),
                broker_config,
                bus.clone(),
            );
        }
        if let Some(fd) = execution.take_notif_listener() {
            crate::sandbox::linux::observe_seccomp::spawn_notifier(
                fd,
                bus.clone(),
                Arc::new(policy.clone()),
                project.to_path_buf(),
            );
        }
        crate::sandbox::linux::visibility::spawn_poller(bus.clone(), vec![root_pid]);
    }

    let output = Arc::new(Mutex::new(OutputBuffers::default()));
    spawn_pipe_reader(stdout_r, Arc::clone(&output), true);
    spawn_pipe_reader(stderr_r, Arc::clone(&output), false);

    // The live execution stays shared with the dashboards (pause/resume/
    // terminate/try_wait lock it) while the wait thread below drives the
    // proven wait on the SAME object and then `finish`es it (nonce sweep
    // for THIS run + teardown + typed report). Single owner, no split.
    let execution = Arc::new(Mutex::new(Some(execution)));
    let finished = Arc::new(AtomicBool::new(false));
    let wait_execution = Arc::clone(&execution);
    let wait_finished = Arc::clone(&finished);
    let wait_bus = bus.clone();
    let agent_name = spec.name.clone();
    let barrier_clone = isolation_barrier.clone();
    let fleet_clone = fleet_manager.clone();
    let worker_id = worker_scope.worker_id.clone();

    std::thread::Builder::new()
        .name(format!("vetto-multi-wait-{}", spec.name))
        .spawn(move || {
            // Proven wait on the SAME execution's handle: deadline →
            // try_wait polling → terminate → bounded re-wait. The 24h
            // deadline is the interactive-session equivalent of "no
            // headless deadline": the dashboard/terminate path owns the
            // lifetime; the killer path still guarantees no bare block.
            let code = wait_execution
                .lock()
                .map(|mut slot| {
                    slot.as_mut()
                        .map(|e| {
                            let deadline =
                                Instant::now() + std::time::Duration::from_secs(3600 * 24);
                            let (outcome, c) = crate::verify_ng::killer::kill_on_deadline_with(
                                &mut e.handle,
                                deadline,
                                std::time::Duration::from_millis(100),
                            );
                            let _ = outcome;
                            c
                        })
                        .unwrap_or(-1)
                })
                .unwrap_or(-1);
            // `finish` consumes the SAME execution: nonce-targeted sweep
            // for THIS run, backend teardown, typed report. Cannot skip.
            let finished_exit_code = wait_execution
                .lock()
                .map(|mut slot| {
                    slot.take().map(|e| {
                        let result = e.finish(Some(code), false);
                        result.exit_code.unwrap_or(code)
                    })
                })
                .unwrap_or(None)
                .unwrap_or(code);

            // Release the worker scope in FleetManager upon completion
            let _ = fleet_clone.release_worker(&worker_id);

            wait_bus.publish(Event::SessionEnded {
                ts: crate::events::types::now(),
                exit_code: finished_exit_code,
                duration_secs: 0,
            });
            barrier_clone.unregister_agent(&agent_name);
            wait_finished.store(true, Ordering::SeqCst);
        })
        .expect("spawn multi wait thread");

    MultiSession {
        spec,
        bus,
        stats,
        output,
        execution,
        finished,
        started: Instant::now(),
        allocated_ports,
        prod_nonce,
        root_pid,
        worker_scope: Some(worker_scope),
    }
}

#[cfg(unix)]
fn spawn_pipe_reader(fd: OwnedFd, output: Arc<Mutex<OutputBuffers>>, stdout: bool) {
    std::thread::Builder::new()
        .name("vetto-multi-output".into())
        .spawn(move || {
            let mut file: std::fs::File = fd.into();
            let mut chunk = [0u8; 8192];
            loop {
                match file.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if let Ok(mut output) = output.lock() {
                            let target = if stdout {
                                &mut output.stdout
                            } else {
                                &mut output.stderr
                            };
                            target.extend_from_slice(&chunk[..n]);
                            if target.len() > OUTPUT_CAP {
                                let excess = target.len() - OUTPUT_CAP;
                                target.drain(..excess);
                            }
                        }
                    }
                }
            }
        })
        .expect("spawn multi output reader");
}

#[cfg(unix)]
fn pipe2() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: valid out-array for the libc pipe call.
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
        // SAFETY: fd came from the successful pipe call.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: both descriptors came from the successful pipe call.
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            bail!("fcntl(F_SETFD): {error}");
        }
    }
    // SAFETY: fresh descriptors from a successful pipe and CLOEXEC setup.
    Ok((unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
        OwnedFd::from_raw_fd(fds[1])
    }))
}

#[cfg(target_os = "linux")]
fn relay_env(net: &NetMode) -> HashMap<String, String> {
    let mut env = HashMap::new();
    if net.uses_relay() {
        for (key, value) in crate::sandbox::linux::net_relay::build_proxy_env(
            crate::sandbox::linux::net_relay::RELAY_PORT_BASE,
        ) {
            env.insert(key, value);
        }
    }
    env
}

#[cfg(all(unix, not(target_os = "linux")))]
fn relay_env(_net: &NetMode) -> HashMap<String, String> {
    HashMap::new()
}

#[cfg(unix)]
fn resolve_in_path(command: &str) -> Result<String> {
    if command.contains('/') {
        return Ok(command.to_string());
    }
    for dir in std::env::var_os("PATH")
        .unwrap_or_default()
        .to_string_lossy()
        .split(':')
    {
        if dir.is_empty() {
            continue;
        }
        let candidate = Path::new(dir).join(command);
        if std::fs::metadata(&candidate)
            .map(|meta| meta.is_file())
            .unwrap_or(false)
        {
            return Ok(candidate.to_string_lossy().into_owned());
        }
    }
    bail!("agent command '{command}' not found in PATH")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multi::fleet::FleetConfig;
    use crate::multi::parse_manifest_str;
    use std::path::Path;

    #[test]
    fn report_directory_is_per_agent() {
        let manifest = parse_manifest_str(
            r#"
                [[agents]]
                name = "one"
                command = ["one"]
                [[agents]]
                name = "two"
                command = ["two"]
            "#,
        )
        .expect("manifest");
        let root = Path::new("reports");
        assert_ne!(
            manifest.agents[0].report_path(Some(root)),
            manifest.agents[1].report_path(Some(root))
        );
    }

    #[test]
    fn aborted_launch_maps_to_fail_closed() {
        // "no unsandboxed fallback" must exit 125 via the typed path:
        // the legacy substring fallback does not contain this message.
        let err = anyhow::Error::new(crate::error::VettoError::Sandbox(
            "multi-agent launch aborted; no unsandboxed fallback: boom".into(),
        ));
        assert_eq!(
            crate::exit_codes::map_error_to_exit_code(&err),
            crate::exit_codes::EXIT_FAIL_CLOSED
        );
    }

    #[test]
    fn test_multi_runtime_new_initializes_default_fleet_manager() {
        let manifest = Manifest {
            version: 1,
            agents: Vec::new(),
            report_dir: None,
        };
        let runtime = MultiRuntime::new(
            manifest,
            Vec::new(),
            MultiEventStream::new(),
            MultiAggregator::new(Vec::<String>::new()),
            VirtualPortPool::default(),
            IsolationBarrier::new(),
            None,
        );
        assert_eq!(runtime.fleet_manager.active_count(), 0);
        assert_eq!(
            runtime.fleet_manager.config().max_agents,
            crate::multi::DEFAULT_MAX_AGENTS
        );
        assert!(runtime.fleet_manager.config().ipc_isolation);
    }

    #[test]
    fn test_multi_runtime_with_fleet_manager() {
        let manifest = Manifest {
            version: 1,
            agents: Vec::new(),
            report_dir: None,
        };
        let config = FleetConfig {
            max_agents: 16,
            cpu_weight: 200,
            memory_limit_bytes: 1024 * 1024 * 1024,
            pids_max: 64,
            base_port: 50000,
            ipc_isolation: true,
            state_file: None,
            workspace_root: None,
            ..Default::default()
        };
        let custom_fleet = FleetManager::new(config);
        let runtime = MultiRuntime::with_fleet_manager(
            manifest,
            Vec::new(),
            MultiEventStream::new(),
            MultiAggregator::new(Vec::<String>::new()),
            VirtualPortPool::default(),
            IsolationBarrier::new(),
            custom_fleet,
            None,
        );
        assert_eq!(runtime.fleet_manager.active_count(), 0);
        assert_eq!(runtime.fleet_manager.config().max_agents, 16);
        assert_eq!(runtime.fleet_manager.config().cpu_weight, 200);
        assert_eq!(runtime.fleet_manager.config().base_port, 50000);
    }

    #[test]
    fn test_multi_session_worker_scope_accessors() {
        let fleet = FleetManager::new_default();
        let scope = fleet.allocate_worker("agent-test").expect("allocate");
        let worker_id_expected = scope.worker_id.clone();

        let session = MultiSession {
            spec: AgentSpec {
                name: "agent-test".into(),
                command: vec!["true".into()],
                profile: "default".into(),
                policy: None,
                net: "off".into(),
                observe_seccomp: false,
                report_dir: None,
                debug_ports: None,
            },
            bus: EventBus::new(),
            stats: StatsCollector::spawn(&EventBus::new()),
            output: Arc::new(Mutex::new(OutputBuffers::default())),
            execution: Arc::new(Mutex::new(None)),
            finished: Arc::new(AtomicBool::new(false)),
            started: Instant::now(),
            allocated_ports: vec![49201],
            prod_nonce: "nonce-123".into(),
            root_pid: 12345,
            worker_scope: Some(scope.clone()),
        };

        assert_eq!(session.worker_id(), Some(worker_id_expected.as_str()));
        assert_eq!(session.worker_scope(), Some(&scope));
    }

    #[test]
    fn test_fleet_pairwise_isolation_verification_logic() {
        let fleet = FleetManager::new_default();
        let scope1 = fleet.allocate_worker("agent-one").expect("scope 1");
        let scope2 = fleet.allocate_worker("agent-two").expect("scope 2");

        assert_ne!(scope1.worker_id, scope2.worker_id);
        assert_ne!(scope1.ephemeral_port, scope2.ephemeral_port);
        assert_ne!(scope1.cow_branch_name, scope2.cow_branch_name);
        assert_ne!(scope1.scope_path, scope2.scope_path);

        fleet
            .verify_isolation(&scope1.worker_id, &scope2.worker_id)
            .expect("pairwise isolation must pass between distinct workers");

        // Release one worker
        fleet
            .release_worker(&scope1.worker_id)
            .expect("release worker 1");
        assert_eq!(fleet.active_count(), 1);

        // Verification with released worker fails
        assert!(fleet
            .verify_isolation(&scope1.worker_id, &scope2.worker_id)
            .is_err());
    }

    #[test]
    fn test_fleet_env_extra_generation() {
        let fleet = FleetManager::new_default();
        let scope = fleet.allocate_worker("test-worker").expect("scope");
        let mut extra = std::collections::HashMap::new();
        extra.insert("VETTO_FLEET_WORKER_ID".to_string(), scope.worker_id.clone());
        extra.insert(
            "VETTO_FLEET_PORT".to_string(),
            scope.ephemeral_port.to_string(),
        );
        extra.insert(
            "VETTO_FLEET_WORKSPACE".to_string(),
            scope.workspace_dir.to_string_lossy().into_owned(),
        );

        assert_eq!(extra.get("VETTO_FLEET_WORKER_ID"), Some(&scope.worker_id));
        assert_eq!(
            extra.get("VETTO_FLEET_PORT"),
            Some(&scope.ephemeral_port.to_string())
        );
        assert!(extra.contains_key("VETTO_FLEET_WORKSPACE"));
    }

    #[cfg(unix)]
    #[test]
    fn write_reports_refuses_symlinked_agent_directory() {
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("vetto-multi-storage-{nonce}"));
        let real = root.join("real");
        let link = root.join("link");
        std::fs::create_dir_all(&real).expect("create real report directory");
        symlink(&real, &link).expect("create report directory symlink");

        let manifest = Manifest {
            version: 1,
            agents: vec![AgentSpec {
                name: "one".into(),
                command: vec!["agent".into()],
                profile: "default".into(),
                policy: None,
                net: "off".into(),
                observe_seccomp: false,
                report_dir: Some(link.clone()),
                debug_ports: None,
            }],
            report_dir: Some(root.join("combined")),
        };
        let runtime = MultiRuntime {
            manifest,
            sessions: Vec::new(),
            stream: MultiEventStream::new(),
            aggregator: MultiAggregator::new(["one".to_string()]),
            port_pool: VirtualPortPool::default(),
            isolation_barrier: IsolationBarrier::new(),
            fleet_manager: FleetManager::new_default(),
            report_dir: Some(root.join("combined")),
        };

        assert!(runtime.write_reports().is_err());
        assert!(real
            .read_dir()
            .expect("read real directory")
            .next()
            .is_none());

        std::fs::remove_file(&link).expect("remove report directory symlink");
        std::fs::remove_dir(&real).expect("remove real report directory");
        std::fs::remove_dir(&root).expect("remove report root");
    }
}
