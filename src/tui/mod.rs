//! Terminal UI: statusline pass-through + full dashboard.

pub mod app;
pub mod guard;
pub mod input;
pub mod statusline;

pub use guard::TerminalResetGuard;
