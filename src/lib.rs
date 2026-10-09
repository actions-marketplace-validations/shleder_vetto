//! Reusable vetto components.
//!
//! The binary in [`main`](../main.rs) is intentionally a thin session
//! orchestrator.  Keeping the implementation modules behind this library
//! boundary lets integration tests, benchmarks, and downstream tooling use
//! the same policy, sandbox, observation, PTY, and report code as the CLI.

pub mod audit;
pub mod cli;
pub mod config;
pub mod cred_broker;
pub mod doctor;
pub mod error;
pub mod events;
pub mod exit_codes;
pub mod fs;
pub mod git;
pub mod history;
pub mod init;
pub mod logger;
pub mod mcp;
pub mod onboard;
pub mod policy;
pub mod policy_ir;
pub mod proctree;
pub mod pty;
pub mod redteam;
pub mod report;
pub mod rescue;
pub mod sandbox;
pub mod sanitizer;
pub mod shim;
pub mod supervise;
#[cfg(unix)]
pub mod tui;
pub mod verify;
pub mod version;
pub mod watchdog;
