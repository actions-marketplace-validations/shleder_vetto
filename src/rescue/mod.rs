//! Workspace snapshot, atomic rollback, lock management and ephemeral execution cleanup.

pub mod ephemeral;
pub mod lock;
pub mod rollback;
pub mod snapshot;
pub mod types;

pub use ephemeral::handle_ephemeral_completion;
pub use types::{ChangeType, SecurityTelemetry};
