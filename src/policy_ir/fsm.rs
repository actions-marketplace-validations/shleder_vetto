//! Authoritative Implementation: Execution State Machine Formalization (Phase 2 / NEXT_GEN §10).
//!
//! Enforces deterministic, 12-state execution lifecycle with strict transition guards
//! and fail-closed error transitions per Transition Truth Table 10.2.

use serde::{Deserialize, Serialize};

/// Execution States for sandboxed agent workload lifecycle.
///
/// Contains the 12 Canonical Execution States (Stage 2 / Goal 2.4 / R4) alongside
/// Phase 3 runtime variants for complete backward compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExecutionState {
    // ========================================================================
    // 12 Canonical States (Stage 2 / Goal 2.4 / R4)
    // ========================================================================
    /// Initial uninitialized state before policy compilation or preflight
    Uninitialized,
    /// Policy parsed, normalized, and validated into IR
    PolicyCompiled,
    /// Preflight verification passed; contract cryptographically sealed
    PreflightPassed,
    /// Host isolation primitives (Landlock LSM, Namespaces, Seccomp, Cgroups) configured
    IsolationConfigured,
    /// Sandboxed child process spawned in isolated namespace
    ChildSpawned,
    /// Process running; supervisor active with non-blocking async stdio drain
    Running,
    /// Signal (SIGINT, SIGTERM, etc.) or termination request received during execution
    SignalReceived,
    /// Process termination in progress (SIGTERM/SIGKILL escalation)
    Terminating,
    /// Process tree extinguished and host resources/cgroups cleaned up
    CleanedUp,
    /// Execution successfully completed with verified 0 surviving descendants
    Completed,
    /// Emergency cleanup of leaked host artifacts upon failure (Exit 125, INV-01)
    EmergencyCleanup,
    /// Terminal failure / fail-closed state upon policy or kernel failure (Exit 125)
    Failed,

    // ========================================================================
    // Phase 3 Runtime Variants (100% Backward Compatibility)
    // ========================================================================
    /// Initial intent collection from agent profile / CLI (legacy alias for Uninitialized)
    Intent,
    /// Canonical contract sealed with BLAKE3/SHA-256 digest (legacy alias for PreflightPassed)
    ContractSealed,
    /// Host resources (cgroups, pipes, namespaces) allocated (legacy alias for IsolationConfigured)
    Prepare,
    /// Process created in suspended/pre-exec state (legacy alias for ChildSpawned)
    Spawn,
    /// Self-restriction (Landlock) and synchronization handshake completed
    Enforce,
    /// Process running; supervisor active with non-blocking async drain (legacy alias for Running)
    Observe,
    /// Normal exit, timeout reached, or tripwire triggered (legacy alias for Terminating)
    Terminate,
    /// Process tree extinction and cgroup/JobObject cleanup (legacy alias for CleanedUp)
    Cleanup,
    /// Independent verification of 0 surviving descendants & audit traces
    Verify,
    /// Merkle DAG generated and audit ledger cryptographically signed
    Attest,
    /// Two-dimensional verdict matrix evaluated
    Verdict,
    /// Fail-closed containment state upon any policy/kernel failure (legacy alias for Failed)
    FailClosed,
    /// Execution complete; final exit code yielded (legacy alias for Completed)
    Terminal,
}

impl ExecutionState {
    /// Array of all 12 canonical states in sequential lifecycle order.
    pub const CANONICAL_STATES: [Self; 12] = [
        Self::Uninitialized,
        Self::PolicyCompiled,
        Self::PreflightPassed,
        Self::IsolationConfigured,
        Self::ChildSpawned,
        Self::Running,
        Self::SignalReceived,
        Self::Terminating,
        Self::CleanedUp,
        Self::Completed,
        Self::EmergencyCleanup,
        Self::Failed,
    ];

    /// Returns `true` if this state is one of the 12 canonical states.
    pub fn is_canonical(&self) -> bool {
        matches!(
            self,
            Self::Uninitialized
                | Self::PolicyCompiled
                | Self::PreflightPassed
                | Self::IsolationConfigured
                | Self::ChildSpawned
                | Self::Running
                | Self::SignalReceived
                | Self::Terminating
                | Self::CleanedUp
                | Self::Completed
                | Self::EmergencyCleanup
                | Self::Failed
        )
    }

    /// Project any execution state onto its canonical 12-state equivalent.
    pub fn to_canonical(&self) -> Self {
        match self {
            Self::Uninitialized | Self::Intent => Self::Uninitialized,
            Self::PolicyCompiled => Self::PolicyCompiled,
            Self::PreflightPassed | Self::ContractSealed => Self::PreflightPassed,
            Self::IsolationConfigured | Self::Prepare | Self::Enforce => Self::IsolationConfigured,
            Self::ChildSpawned | Self::Spawn => Self::ChildSpawned,
            Self::Running | Self::Observe => Self::Running,
            Self::SignalReceived => Self::SignalReceived,
            Self::Terminating | Self::Terminate => Self::Terminating,
            Self::CleanedUp | Self::Cleanup | Self::Verify | Self::Attest | Self::Verdict => {
                Self::CleanedUp
            }
            Self::Completed | Self::Terminal => Self::Completed,
            Self::EmergencyCleanup => Self::EmergencyCleanup,
            Self::Failed | Self::FailClosed => Self::Failed,
        }
    }

    /// Returns `true` if this state is a terminal lifecycle state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Terminal)
    }

    /// Returns `true` if this state represents an active (non-terminal) phase.
    pub fn is_active(&self) -> bool {
        !self.is_terminal()
    }

    /// Returns a human-readable identifier for the state.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Uninitialized => "Uninitialized",
            Self::PolicyCompiled => "PolicyCompiled",
            Self::PreflightPassed => "PreflightPassed",
            Self::IsolationConfigured => "IsolationConfigured",
            Self::ChildSpawned => "ChildSpawned",
            Self::Running => "Running",
            Self::SignalReceived => "SignalReceived",
            Self::Terminating => "Terminating",
            Self::CleanedUp => "CleanedUp",
            Self::Completed => "Completed",
            Self::EmergencyCleanup => "EmergencyCleanup",
            Self::Failed => "Failed",
            Self::Intent => "Intent",
            Self::ContractSealed => "ContractSealed",
            Self::Prepare => "Prepare",
            Self::Spawn => "Spawn",
            Self::Enforce => "Enforce",
            Self::Observe => "Observe",
            Self::Terminate => "Terminate",
            Self::Cleanup => "Cleanup",
            Self::Verify => "Verify",
            Self::Attest => "Attest",
            Self::Verdict => "Verdict",
            Self::FailClosed => "FailClosed",
            Self::Terminal => "Terminal",
        }
    }
}

impl std::fmt::Display for ExecutionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum StateTransitionError {
    #[error("Invalid state transition from {from:?} to {to:?}: {reason}")]
    InvalidTransition {
        from: ExecutionState,
        to: ExecutionState,
        reason: &'static str,
    },
    #[error("Execution failed closed in state {state:?}: {error} (Exit 125)")]
    FailClosed {
        state: ExecutionState,
        error: String,
    },
}

impl StateTransitionError {
    /// Return the canonical Exit 125 code associated with fail-closed state errors.
    pub fn exit_code(&self) -> i32 {
        125
    }
}

#[derive(Debug, Clone)]
pub struct ExecutionStateMachine {
    current_state: ExecutionState,
    history: Vec<(ExecutionState, std::time::Instant)>,
    surviving_descendants: Option<usize>,
}

impl Default for ExecutionStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutionStateMachine {
    /// Create a new FSM initialized in `ExecutionState::Intent` for 100% backward compatibility.
    pub fn new() -> Self {
        Self {
            current_state: ExecutionState::Intent,
            history: vec![(ExecutionState::Intent, std::time::Instant::now())],
            surviving_descendants: None,
        }
    }

    /// Create a new FSM explicitly initialized in the canonical `ExecutionState::Uninitialized`.
    pub fn new_canonical() -> Self {
        Self {
            current_state: ExecutionState::Uninitialized,
            history: vec![(ExecutionState::Uninitialized, std::time::Instant::now())],
            surviving_descendants: None,
        }
    }

    /// Create an FSM initialized in an arbitrary state.
    pub fn from_state(state: ExecutionState) -> Self {
        Self {
            current_state: state,
            history: vec![(state, std::time::Instant::now())],
            surviving_descendants: None,
        }
    }

    /// Number of surviving descendant processes recorded by tree sweep / proctree.
    pub fn surviving_descendants(&self) -> Option<usize> {
        self.surviving_descendants
    }

    /// Record the host extinction audit result.
    pub fn record_extinction_result(&mut self, surviving: usize) {
        self.surviving_descendants = Some(surviving);
    }

    /// Current execution state.
    pub fn current_state(&self) -> ExecutionState {
        self.current_state
    }

    /// Canonical representation of the current execution state.
    pub fn canonical_state(&self) -> ExecutionState {
        self.current_state.to_canonical()
    }

    /// Transition history log with timestamps.
    pub fn history(&self) -> &[(ExecutionState, std::time::Instant)] {
        &self.history
    }

    /// Returns `true` if current state is either Completed or Terminal.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.current_state,
            ExecutionState::Completed | ExecutionState::Terminal
        )
    }

    /// Returns `true` if execution has transitioned through FailClosed, Failed, or EmergencyCleanup.
    pub fn is_fail_closed(&self) -> bool {
        matches!(
            self.current_state,
            ExecutionState::FailClosed | ExecutionState::EmergencyCleanup | ExecutionState::Failed
        ) || self.history.iter().any(|(s, _)| {
            matches!(
                s,
                ExecutionState::FailClosed
                    | ExecutionState::EmergencyCleanup
                    | ExecutionState::Failed
            )
        })
    }

    /// Determine if the state machine is operating in canonical 12-state mode.
    pub fn is_canonical_mode(&self) -> bool {
        match self.current_state {
            ExecutionState::Uninitialized
            | ExecutionState::PreflightPassed
            | ExecutionState::IsolationConfigured
            | ExecutionState::ChildSpawned
            | ExecutionState::Running
            | ExecutionState::SignalReceived
            | ExecutionState::Terminating
            | ExecutionState::CleanedUp
            | ExecutionState::Completed
            | ExecutionState::Failed => true,

            ExecutionState::Intent
            | ExecutionState::ContractSealed
            | ExecutionState::Prepare
            | ExecutionState::Spawn
            | ExecutionState::Enforce
            | ExecutionState::Observe
            | ExecutionState::Terminate
            | ExecutionState::Cleanup
            | ExecutionState::Verify
            | ExecutionState::Attest
            | ExecutionState::Verdict
            | ExecutionState::FailClosed
            | ExecutionState::Terminal => false,

            ExecutionState::PolicyCompiled | ExecutionState::EmergencyCleanup => {
                let has_canonical = self.history.iter().any(|(s, _)| {
                    matches!(
                        s,
                        ExecutionState::Uninitialized
                            | ExecutionState::PreflightPassed
                            | ExecutionState::IsolationConfigured
                            | ExecutionState::ChildSpawned
                            | ExecutionState::Running
                            | ExecutionState::SignalReceived
                            | ExecutionState::Terminating
                            | ExecutionState::CleanedUp
                            | ExecutionState::Completed
                            | ExecutionState::Failed
                    )
                });
                let has_legacy = self.history.iter().any(|(s, _)| {
                    matches!(
                        s,
                        ExecutionState::Intent
                            | ExecutionState::ContractSealed
                            | ExecutionState::Prepare
                            | ExecutionState::Spawn
                            | ExecutionState::Enforce
                            | ExecutionState::Observe
                            | ExecutionState::Terminate
                            | ExecutionState::Cleanup
                            | ExecutionState::Verify
                            | ExecutionState::Attest
                            | ExecutionState::Verdict
                            | ExecutionState::FailClosed
                            | ExecutionState::Terminal
                    )
                });
                has_canonical && !has_legacy
            }
        }
    }

    /// Perform state transition to `next`.
    ///
    /// Validates transition legality against both the 12 Canonical State table
    /// and Phase 3 runtime variants, enforcing the process extinction guard.
    pub fn transition(&mut self, next: ExecutionState) -> Result<(), StateTransitionError> {
        // Guard Invariant: block transition to terminal states if live descendant processes exist
        if (next == ExecutionState::Terminal || next == ExecutionState::Completed)
            && self.surviving_descendants.unwrap_or(0) > 0
        {
            return Err(StateTransitionError::InvalidTransition {
                from: self.current_state,
                to: next,
                reason: "terminal state forbidden: live descendant processes detected",
            });
        }

        let valid = match (self.current_state, next) {
            // ================================================================
            // 1. Canonical 12-State Forward Pipeline
            // ================================================================
            (ExecutionState::Uninitialized, ExecutionState::PolicyCompiled) => true,
            (ExecutionState::PolicyCompiled, ExecutionState::PreflightPassed) => true,
            (ExecutionState::PreflightPassed, ExecutionState::IsolationConfigured) => true,
            (ExecutionState::IsolationConfigured, ExecutionState::ChildSpawned) => true,
            (ExecutionState::ChildSpawned, ExecutionState::Running) => true,
            (ExecutionState::Running, ExecutionState::Terminating) => true,
            (ExecutionState::Running, ExecutionState::SignalReceived) => true,
            (ExecutionState::SignalReceived, ExecutionState::Terminating) => true,
            (ExecutionState::Terminating, ExecutionState::CleanedUp) => true,
            (ExecutionState::CleanedUp, ExecutionState::Completed) => true,

            // ================================================================
            // 2. Phase 3 Legacy Forward Pipeline (Table 10.2)
            // ================================================================
            (ExecutionState::Intent, ExecutionState::PolicyCompiled) => true,
            (ExecutionState::PolicyCompiled, ExecutionState::ContractSealed) => true,
            (ExecutionState::ContractSealed, ExecutionState::Prepare) => true,
            (ExecutionState::Prepare, ExecutionState::Spawn) => true,
            (ExecutionState::Spawn, ExecutionState::Enforce) => true,
            (ExecutionState::Enforce, ExecutionState::Observe) => true,
            (ExecutionState::Observe, ExecutionState::Terminate) => true,
            (ExecutionState::Terminate, ExecutionState::Cleanup) => true,
            (ExecutionState::Cleanup, ExecutionState::Verify) => true,
            (ExecutionState::Verify, ExecutionState::Attest) => true,
            (ExecutionState::Attest, ExecutionState::Verdict) => true,
            (ExecutionState::Verdict, ExecutionState::Terminal) => true,

            // ================================================================
            // 3. Cross-Pipeline Interop Bridges
            // ================================================================
            // Initial & Preflight bridges
            (ExecutionState::Uninitialized, ExecutionState::Intent) => true,
            (ExecutionState::Intent, ExecutionState::Uninitialized) => true,
            (ExecutionState::PolicyCompiled, ExecutionState::IsolationConfigured) => true,
            (ExecutionState::PreflightPassed, ExecutionState::Prepare) => true,
            (ExecutionState::ContractSealed, ExecutionState::IsolationConfigured) => true,

            // Isolation & Spawn bridges
            (ExecutionState::IsolationConfigured, ExecutionState::Spawn) => true,
            (ExecutionState::Prepare, ExecutionState::ChildSpawned) => true,
            (ExecutionState::ChildSpawned, ExecutionState::Observe) => true,
            (ExecutionState::Spawn, ExecutionState::Running) => true,
            (ExecutionState::Enforce, ExecutionState::Running) => true,

            // Running / Observe / Signal / Termination bridges
            (ExecutionState::Observe, ExecutionState::SignalReceived) => true,
            (ExecutionState::Observe, ExecutionState::Terminating) => true,
            (ExecutionState::Running, ExecutionState::Terminate) => true,
            (ExecutionState::SignalReceived, ExecutionState::Terminate) => true,

            // Teardown / Cleanup / Verification bridges
            (ExecutionState::Terminate, ExecutionState::CleanedUp) => true,
            (ExecutionState::Terminating, ExecutionState::Cleanup) => true,
            (ExecutionState::CleanedUp, ExecutionState::Verify) => true,
            (ExecutionState::Cleanup, ExecutionState::CleanedUp) => true,
            (ExecutionState::CleanedUp, ExecutionState::Terminal) => true,
            (ExecutionState::Verdict, ExecutionState::Completed) => true,
            (ExecutionState::Cleanup, ExecutionState::Completed) => true,
            (ExecutionState::Completed, ExecutionState::Terminal) => true,
            (ExecutionState::Terminal, ExecutionState::Completed) => true,

            // ================================================================
            // 4. Fail-Closed & Emergency Cleanup Transitions from Any Active State
            // ================================================================
            // Canonical active states -> FailClosed / Failed / EmergencyCleanup
            (ExecutionState::Uninitialized, ExecutionState::FailClosed) => true,
            (ExecutionState::Uninitialized, ExecutionState::Failed) => true,
            (ExecutionState::Uninitialized, ExecutionState::EmergencyCleanup) => true,

            (ExecutionState::PolicyCompiled, ExecutionState::FailClosed) => true,
            (ExecutionState::PolicyCompiled, ExecutionState::Failed) => true,
            (ExecutionState::PolicyCompiled, ExecutionState::EmergencyCleanup) => true,

            (ExecutionState::PreflightPassed, ExecutionState::FailClosed) => true,
            (ExecutionState::PreflightPassed, ExecutionState::Failed) => true,
            (ExecutionState::PreflightPassed, ExecutionState::EmergencyCleanup) => true,

            (ExecutionState::IsolationConfigured, ExecutionState::FailClosed) => true,
            (ExecutionState::IsolationConfigured, ExecutionState::Failed) => true,
            (ExecutionState::IsolationConfigured, ExecutionState::EmergencyCleanup) => true,

            (ExecutionState::ChildSpawned, ExecutionState::FailClosed) => true,
            (ExecutionState::ChildSpawned, ExecutionState::Failed) => true,
            (ExecutionState::ChildSpawned, ExecutionState::EmergencyCleanup) => true,

            (ExecutionState::Running, ExecutionState::FailClosed) => true,
            (ExecutionState::Running, ExecutionState::Failed) => true,
            (ExecutionState::Running, ExecutionState::EmergencyCleanup) => true,

            (ExecutionState::SignalReceived, ExecutionState::FailClosed) => true,
            (ExecutionState::SignalReceived, ExecutionState::Failed) => true,
            (ExecutionState::SignalReceived, ExecutionState::EmergencyCleanup) => true,

            (ExecutionState::Terminating, ExecutionState::FailClosed) => true,
            (ExecutionState::Terminating, ExecutionState::Failed) => true,
            (ExecutionState::Terminating, ExecutionState::EmergencyCleanup) => true,

            (ExecutionState::CleanedUp, ExecutionState::FailClosed) => true,
            (ExecutionState::CleanedUp, ExecutionState::Failed) => true,
            (ExecutionState::CleanedUp, ExecutionState::EmergencyCleanup) => true,

            // Phase 3 active states -> FailClosed / Failed / EmergencyCleanup
            (ExecutionState::Intent, ExecutionState::FailClosed) => true,
            (ExecutionState::Intent, ExecutionState::Failed) => true,
            (ExecutionState::Intent, ExecutionState::EmergencyCleanup) => true,

            (ExecutionState::ContractSealed, ExecutionState::FailClosed) => true,
            (ExecutionState::ContractSealed, ExecutionState::Failed) => true,
            (ExecutionState::ContractSealed, ExecutionState::EmergencyCleanup) => true,

            (ExecutionState::Prepare, ExecutionState::FailClosed) => true,
            (ExecutionState::Prepare, ExecutionState::Failed) => true,
            (ExecutionState::Prepare, ExecutionState::EmergencyCleanup) => true,

            (ExecutionState::Spawn, ExecutionState::FailClosed) => true,
            (ExecutionState::Spawn, ExecutionState::Failed) => true,
            (ExecutionState::Spawn, ExecutionState::EmergencyCleanup) => true,

            (ExecutionState::Enforce, ExecutionState::FailClosed) => true,
            (ExecutionState::Enforce, ExecutionState::Failed) => true,
            (ExecutionState::Enforce, ExecutionState::EmergencyCleanup) => true,

            (ExecutionState::Observe, ExecutionState::FailClosed) => true,
            (ExecutionState::Observe, ExecutionState::Failed) => true,
            (ExecutionState::Observe, ExecutionState::EmergencyCleanup) => true,

            (ExecutionState::Terminate, ExecutionState::FailClosed) => true,
            (ExecutionState::Terminate, ExecutionState::Failed) => true,
            (ExecutionState::Terminate, ExecutionState::EmergencyCleanup) => true,

            (ExecutionState::Cleanup, ExecutionState::FailClosed) => true,
            (ExecutionState::Cleanup, ExecutionState::Failed) => true,
            (ExecutionState::Cleanup, ExecutionState::EmergencyCleanup) => true,

            (ExecutionState::Verify, ExecutionState::FailClosed) => true,
            (ExecutionState::Verify, ExecutionState::Failed) => true,
            (ExecutionState::Verify, ExecutionState::EmergencyCleanup) => true,

            (ExecutionState::Attest, ExecutionState::FailClosed) => true,
            (ExecutionState::Attest, ExecutionState::Failed) => true,
            (ExecutionState::Attest, ExecutionState::EmergencyCleanup) => true,

            (ExecutionState::Verdict, ExecutionState::FailClosed) => true,
            (ExecutionState::Verdict, ExecutionState::Failed) => true,
            (ExecutionState::Verdict, ExecutionState::EmergencyCleanup) => true,

            // ================================================================
            // 5. Fail-Closed Recovery & Terminal Error Paths
            // ================================================================
            (ExecutionState::FailClosed, ExecutionState::FailClosed) => true,
            (ExecutionState::Failed, ExecutionState::Failed) => true,
            (ExecutionState::FailClosed, ExecutionState::Failed) => true,
            (ExecutionState::Failed, ExecutionState::FailClosed) => true,
            (ExecutionState::FailClosed, ExecutionState::EmergencyCleanup) => true,
            (ExecutionState::Failed, ExecutionState::EmergencyCleanup) => true,

            (ExecutionState::EmergencyCleanup, ExecutionState::EmergencyCleanup) => true,
            (ExecutionState::EmergencyCleanup, ExecutionState::FailClosed) => true,
            (ExecutionState::EmergencyCleanup, ExecutionState::Failed) => true,
            (ExecutionState::EmergencyCleanup, ExecutionState::Terminal) => true,
            (ExecutionState::EmergencyCleanup, ExecutionState::Completed) => true,

            _ => false,
        };

        if !valid {
            return Err(StateTransitionError::InvalidTransition {
                from: self.current_state,
                to: next,
                reason: "transition disallowed by execution state machine transition table",
            });
        }

        self.current_state = next;
        self.history.push((next, std::time::Instant::now()));
        Ok(())
    }

    /// Abort execution fail-closed, moving to `Failed` (canonical) or `FailClosed` (Phase 3).
    pub fn fail_closed(&mut self, error: impl Into<String>) -> StateTransitionError {
        let err_str = error.into();
        let prev_state = self.current_state;
        let target = if self.is_canonical_mode() {
            ExecutionState::Failed
        } else {
            ExecutionState::FailClosed
        };
        if let Err(e) = self.transition(target) {
            return e;
        }
        StateTransitionError::FailClosed {
            state: prev_state,
            error: err_str,
        }
    }

    /// Abort execution fail-closed, explicitly targeting canonical `ExecutionState::Failed`.
    pub fn fail_closed_canonical(&mut self, error: impl Into<String>) -> StateTransitionError {
        self.fail_closed_to(ExecutionState::Failed, error)
    }

    /// Abort execution fail-closed directly into `ExecutionState::EmergencyCleanup`.
    pub fn fail_closed_emergency(&mut self, error: impl Into<String>) -> StateTransitionError {
        self.fail_closed_to(ExecutionState::EmergencyCleanup, error)
    }

    /// Abort execution fail-closed to a specific target state.
    pub fn fail_closed_to(
        &mut self,
        target: ExecutionState,
        error: impl Into<String>,
    ) -> StateTransitionError {
        let err_str = error.into();
        let prev_state = self.current_state;
        if let Err(e) = self.transition(target) {
            return e;
        }
        StateTransitionError::FailClosed {
            state: prev_state,
            error: err_str,
        }
    }
}

#[cfg(test)]
mod fsm_tests {
    use super::*;

    // ========================================================================
    // Canonical 12-State Tests
    // ========================================================================

    #[test]
    fn canonical_12_state_happy_path() {
        let mut fsm = ExecutionStateMachine::new_canonical();
        assert_eq!(fsm.current_state(), ExecutionState::Uninitialized);
        assert!(fsm.is_canonical_mode());

        let sequence = [
            ExecutionState::PolicyCompiled,
            ExecutionState::PreflightPassed,
            ExecutionState::IsolationConfigured,
            ExecutionState::ChildSpawned,
            ExecutionState::Running,
            ExecutionState::Terminating,
            ExecutionState::CleanedUp,
            ExecutionState::Completed,
        ];

        for next in sequence {
            assert!(
                fsm.transition(next).is_ok(),
                "failed transition to {next:?}"
            );
            assert_eq!(fsm.current_state(), next);
        }

        assert!(fsm.is_terminal());
        assert_eq!(fsm.history().len(), 9);
        assert_eq!(fsm.canonical_state(), ExecutionState::Completed);
    }

    #[test]
    fn canonical_signal_received_lifecycle() {
        let mut fsm = ExecutionStateMachine::new_canonical();
        fsm.transition(ExecutionState::PolicyCompiled).unwrap();
        fsm.transition(ExecutionState::PreflightPassed).unwrap();
        fsm.transition(ExecutionState::IsolationConfigured).unwrap();
        fsm.transition(ExecutionState::ChildSpawned).unwrap();
        fsm.transition(ExecutionState::Running).unwrap();

        // Signal (SIGINT/SIGTERM) received during execution
        assert!(fsm.transition(ExecutionState::SignalReceived).is_ok());
        assert_eq!(fsm.current_state(), ExecutionState::SignalReceived);
        assert_eq!(fsm.canonical_state(), ExecutionState::SignalReceived);

        assert!(fsm.transition(ExecutionState::Terminating).is_ok());
        assert!(fsm.transition(ExecutionState::CleanedUp).is_ok());
        assert!(fsm.transition(ExecutionState::Completed).is_ok());
        assert!(fsm.is_terminal());
    }

    #[test]
    fn canonical_fail_closed_to_failed_and_emergency_cleanup() {
        let mut fsm = ExecutionStateMachine::new_canonical();
        fsm.transition(ExecutionState::PolicyCompiled).unwrap();
        fsm.transition(ExecutionState::PreflightPassed).unwrap();
        fsm.transition(ExecutionState::IsolationConfigured).unwrap();

        // Anomaly encountered in IsolationConfigured
        let err = fsm.fail_closed("Seccomp-BPF compilation rejected by kernel");
        assert!(matches!(err, StateTransitionError::FailClosed { .. }));
        assert_eq!(fsm.current_state(), ExecutionState::Failed);
        assert!(fsm.is_fail_closed());

        // Emergency cleanup transition
        assert!(fsm.transition(ExecutionState::EmergencyCleanup).is_ok());
        assert!(fsm.transition(ExecutionState::Completed).is_ok());
        assert!(fsm.is_terminal());
        assert!(fsm.is_fail_closed());
    }

    #[test]
    fn canonical_direct_transition_to_emergency_cleanup() {
        let mut fsm = ExecutionStateMachine::new_canonical();
        fsm.transition(ExecutionState::PolicyCompiled).unwrap();
        fsm.transition(ExecutionState::PreflightPassed).unwrap();
        fsm.transition(ExecutionState::IsolationConfigured).unwrap();
        fsm.transition(ExecutionState::ChildSpawned).unwrap();
        fsm.transition(ExecutionState::Running).unwrap();

        // Direct transition from active Running to EmergencyCleanup upon panic
        assert!(fsm.transition(ExecutionState::EmergencyCleanup).is_ok());
        assert_eq!(fsm.current_state(), ExecutionState::EmergencyCleanup);
        assert!(fsm.is_fail_closed());

        assert!(fsm.transition(ExecutionState::Completed).is_ok());
        assert!(fsm.is_terminal());
    }

    #[test]
    fn canonical_reject_completed_with_surviving_descendants() {
        let mut fsm = ExecutionStateMachine::new_canonical();
        fsm.transition(ExecutionState::PolicyCompiled).unwrap();
        fsm.transition(ExecutionState::PreflightPassed).unwrap();
        fsm.transition(ExecutionState::IsolationConfigured).unwrap();
        fsm.transition(ExecutionState::ChildSpawned).unwrap();
        fsm.transition(ExecutionState::Running).unwrap();
        fsm.transition(ExecutionState::Terminating).unwrap();
        fsm.transition(ExecutionState::CleanedUp).unwrap();

        // Extinction audit reveals 3 orphaned descendant processes
        fsm.record_extinction_result(3);

        let err = fsm.transition(ExecutionState::Completed).unwrap_err();
        assert!(matches!(
            err,
            StateTransitionError::InvalidTransition {
                from: ExecutionState::CleanedUp,
                to: ExecutionState::Completed,
                ..
            }
        ));
        assert_eq!(fsm.current_state(), ExecutionState::CleanedUp);
        assert!(!fsm.is_terminal());

        // Once extinction verifier succeeds with 0 survivors, transition is allowed
        fsm.record_extinction_result(0);
        assert!(fsm.transition(ExecutionState::Completed).is_ok());
        assert!(fsm.is_terminal());
    }

    #[test]
    fn canonical_mapping_exhaustiveness() {
        for state in ExecutionState::CANONICAL_STATES {
            assert!(state.is_canonical());
            assert_eq!(state.to_canonical(), state);
        }

        assert_eq!(
            ExecutionState::Intent.to_canonical(),
            ExecutionState::Uninitialized
        );
        assert_eq!(
            ExecutionState::ContractSealed.to_canonical(),
            ExecutionState::PreflightPassed
        );
        assert_eq!(
            ExecutionState::Prepare.to_canonical(),
            ExecutionState::IsolationConfigured
        );
        assert_eq!(
            ExecutionState::Enforce.to_canonical(),
            ExecutionState::IsolationConfigured
        );
        assert_eq!(
            ExecutionState::Spawn.to_canonical(),
            ExecutionState::ChildSpawned
        );
        assert_eq!(
            ExecutionState::Observe.to_canonical(),
            ExecutionState::Running
        );
        assert_eq!(
            ExecutionState::Terminate.to_canonical(),
            ExecutionState::Terminating
        );
        assert_eq!(
            ExecutionState::Cleanup.to_canonical(),
            ExecutionState::CleanedUp
        );
        assert_eq!(
            ExecutionState::Verify.to_canonical(),
            ExecutionState::CleanedUp
        );
        assert_eq!(
            ExecutionState::Attest.to_canonical(),
            ExecutionState::CleanedUp
        );
        assert_eq!(
            ExecutionState::Verdict.to_canonical(),
            ExecutionState::CleanedUp
        );
        assert_eq!(
            ExecutionState::Terminal.to_canonical(),
            ExecutionState::Completed
        );
        assert_eq!(
            ExecutionState::FailClosed.to_canonical(),
            ExecutionState::Failed
        );
    }

    #[test]
    fn cross_pipeline_interop_bridges() {
        // Start in Intent, proceed into canonical states
        let mut fsm = ExecutionStateMachine::new();
        assert_eq!(fsm.current_state(), ExecutionState::Intent);

        fsm.transition(ExecutionState::PolicyCompiled).unwrap();
        fsm.transition(ExecutionState::PreflightPassed).unwrap();
        fsm.transition(ExecutionState::Prepare).unwrap();
        fsm.transition(ExecutionState::ChildSpawned).unwrap();
        fsm.transition(ExecutionState::Running).unwrap();
        fsm.transition(ExecutionState::Terminate).unwrap();
        fsm.transition(ExecutionState::CleanedUp).unwrap();
        fsm.transition(ExecutionState::Terminal).unwrap();
        assert!(fsm.is_terminal());
    }

    // ========================================================================
    // Backward Compatibility Tests (Phase 3 Runtime Variants)
    // ========================================================================

    #[test]
    fn complete_happy_path_lifecycle() {
        let mut fsm = ExecutionStateMachine::new();
        assert_eq!(fsm.current_state(), ExecutionState::Intent);

        let sequence = [
            ExecutionState::PolicyCompiled,
            ExecutionState::ContractSealed,
            ExecutionState::Prepare,
            ExecutionState::Spawn,
            ExecutionState::Enforce,
            ExecutionState::Observe,
            ExecutionState::Terminate,
            ExecutionState::Cleanup,
            ExecutionState::Verify,
            ExecutionState::Attest,
            ExecutionState::Verdict,
            ExecutionState::Terminal,
        ];

        for next in sequence {
            assert!(fsm.transition(next).is_ok());
            assert_eq!(fsm.current_state(), next);
        }

        assert!(fsm.is_terminal());
        assert_eq!(fsm.history().len(), 13);
    }

    #[test]
    fn reject_skipping_lifecycle_states() {
        let mut fsm = ExecutionStateMachine::new();
        // Cannot jump directly from Intent to Spawn
        let err = fsm.transition(ExecutionState::Spawn).unwrap_err();
        assert!(matches!(
            err,
            StateTransitionError::InvalidTransition { .. }
        ));
        assert_eq!(fsm.current_state(), ExecutionState::Intent);
    }

    #[test]
    fn fail_closed_and_emergency_cleanup() {
        let mut fsm = ExecutionStateMachine::new();
        fsm.transition(ExecutionState::PolicyCompiled).unwrap();
        fsm.transition(ExecutionState::ContractSealed).unwrap();
        fsm.transition(ExecutionState::Prepare).unwrap();

        // Anomaly encountered during spawn
        let err = fsm.fail_closed("LSM hook rejected in kernel");
        assert!(matches!(err, StateTransitionError::FailClosed { .. }));
        assert_eq!(fsm.current_state(), ExecutionState::FailClosed);
        assert!(fsm.is_fail_closed());

        // Emergency cleanup transition
        assert!(fsm.transition(ExecutionState::EmergencyCleanup).is_ok());
        assert!(fsm.transition(ExecutionState::Terminal).is_ok());
        assert!(fsm.is_terminal());
        assert!(fsm.is_fail_closed());
    }

    #[test]
    fn reject_terminal_with_surviving_descendants() {
        let mut fsm = ExecutionStateMachine::new();
        fsm.transition(ExecutionState::PolicyCompiled).unwrap();
        fsm.transition(ExecutionState::ContractSealed).unwrap();
        fsm.transition(ExecutionState::Prepare).unwrap();
        fsm.transition(ExecutionState::Spawn).unwrap();
        fsm.transition(ExecutionState::Enforce).unwrap();
        fsm.transition(ExecutionState::Observe).unwrap();
        fsm.transition(ExecutionState::Terminate).unwrap();
        fsm.transition(ExecutionState::Cleanup).unwrap();

        // 2 residual processes detected
        fsm.record_extinction_result(2);

        let err = fsm.fail_closed("residual processes found");
        assert!(matches!(err, StateTransitionError::FailClosed { .. }));
        assert_eq!(fsm.current_state(), ExecutionState::FailClosed);

        fsm.transition(ExecutionState::EmergencyCleanup).unwrap();

        // Invariant guard: Terminal MUST fail
        let err = fsm.transition(ExecutionState::Terminal).unwrap_err();
        assert!(matches!(
            err,
            StateTransitionError::InvalidTransition {
                from: ExecutionState::EmergencyCleanup,
                to: ExecutionState::Terminal,
                ..
            }
        ));
        assert_eq!(fsm.current_state(), ExecutionState::EmergencyCleanup);
        assert!(!fsm.is_terminal());

        // When cleared to 0 survivors, Terminal transition succeeds
        fsm.record_extinction_result(0);
        assert!(fsm.transition(ExecutionState::Terminal).is_ok());
        assert!(fsm.is_terminal());
    }

    #[test]
    fn fail_closed_from_terminal_returns_invalid_transition() {
        let mut fsm = ExecutionStateMachine::new();
        let sequence = [
            ExecutionState::PolicyCompiled,
            ExecutionState::ContractSealed,
            ExecutionState::Prepare,
            ExecutionState::Spawn,
            ExecutionState::Enforce,
            ExecutionState::Observe,
            ExecutionState::Terminate,
            ExecutionState::Cleanup,
            ExecutionState::Verify,
            ExecutionState::Attest,
            ExecutionState::Verdict,
            ExecutionState::Terminal,
        ];
        for s in sequence {
            fsm.transition(s).unwrap();
        }
        assert!(fsm.is_terminal());

        let err = fsm.fail_closed("late error after terminal");
        assert!(matches!(
            err,
            StateTransitionError::InvalidTransition {
                from: ExecutionState::Terminal,
                to: ExecutionState::FailClosed,
                ..
            }
        ));
    }
}
