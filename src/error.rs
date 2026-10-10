use thiserror::Error;

use crate::exit_codes::{EXIT_AGENT_ERROR, EXIT_FAIL_CLOSED, EXIT_POLICY_BLOCKED};
use crate::policy::types::PolicyError;

/// Public error taxonomy. Some variants are reserved for macOS/Windows
/// code paths and platform-gated constructors; they exist so the error
/// surface stays stable.
#[allow(dead_code)]
#[derive(Error, Debug)]
pub enum VettoError {
    #[error("landlock: {0}")]
    Landlock(String),
    #[error("namespace operation failed: {0}")]
    Namespace(String),
    #[error("mount operation failed: {0}")]
    Mount(String),
    #[error("seccomp: {0}")]
    Seccomp(String),
    #[error("sandbox setup failed: {0}")]
    Sandbox(String),
    #[error("pty error: {0}")]
    Pty(String),
    #[error("cli error: {0}")]
    Cli(String),
    #[error("policy error: {0}")]
    Policy(PolicyError),
    #[error("policy lockdown violation: {0}")]
    PolicyLockdownViolation(String),
    #[error("{0} is not supported by this vetto 0.x build (see SECURITY.md roadmap)")]
    UnsupportedPlatform(&'static str),
}

pub type VettoResult<T> = Result<T, VettoError>;

impl VettoError {
    /// Deterministic exit code for this error. Prefer this over
    /// [`crate::exit_codes::map_error_to_exit_code`], which falls back to
    /// substring matching on arbitrary `anyhow` messages and is kept only
    /// for errors that do not carry a typed `VettoError`.
    pub fn exit_code(&self) -> i32 {
        match self {
            VettoError::Landlock(_)
            | VettoError::Namespace(_)
            | VettoError::Mount(_)
            | VettoError::Seccomp(_)
            | VettoError::Sandbox(_)
            | VettoError::UnsupportedPlatform(_) => EXIT_FAIL_CLOSED,
            VettoError::Pty(_) | VettoError::Cli(_) => EXIT_AGENT_ERROR,
            VettoError::Policy(ref err) => err.exit_code(),
            VettoError::PolicyLockdownViolation(_) => EXIT_POLICY_BLOCKED,
        }
    }

    /// Convenience: agent binary could not be resolved via PATH/shims.
    pub fn agent_not_found(detail: impl Into<String>) -> anyhow::Error {
        // Surfaced through the legacy substring path as COMMAND_NOT_FOUND
        // until all call sites construct typed errors directly.
        anyhow::anyhow!("agent command not found in PATH: {}", detail.into())
    }

    /// Helper: construct a fail-closed policy compilation error.
    pub fn policy(detail: impl Into<String>) -> Self {
        VettoError::Policy(PolicyError::CompilationFailed(detail.into()))
    }
}

impl From<PolicyError> for VettoError {
    fn from(err: PolicyError) -> Self {
        VettoError::Policy(err)
    }
}
