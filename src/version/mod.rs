//! Release engineering, version parsing, and channel management.

pub mod config;
pub mod parser;

pub use config::{auto_update_enabled, load_user_config, UserConfig};
pub use parser::{parse_registry_version, SemVer};
