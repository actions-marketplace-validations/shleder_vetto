//! Terminal UI: statusline pass-through + full dashboard.

#[cfg(unix)]
pub mod app;
pub mod guard;
#[cfg(unix)]
pub mod input;
#[cfg(unix)]
pub mod statusline;

pub use guard::TerminalResetGuard;
