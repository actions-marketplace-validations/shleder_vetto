use std::path::PathBuf;

use clap::Subcommand;

/// CLI command variants for the `vetto rescue` subsystem.
#[derive(Subcommand, Debug, Clone)]
pub enum RescueCommand {
    /// Discover sessions. Codex defaults to verified index-first (limit 50);
    /// other adapters use their bounded filesystem discovery.
    Scan {
        /// For Codex, use a verified provider index and return at most COUNT
        /// sessions. This never falls back to a filesystem walk.
        #[arg(long, value_name = "COUNT", conflicts_with = "all")]
        limit: Option<usize>,
        /// Explicitly use the bounded recursive filesystem walk. For Codex,
        /// this opts out of the default index-first scan.
        #[arg(long, conflicts_with = "limit")]
        all: bool,
    },
    /// Diagnose one exact session key without changing agent state.
    Diagnose {
        #[arg(value_name = "SESSION")]
        session: String,
    },
    /// Create a verified, exclusive new copy outside the agent state root.
    Snapshot {
        #[arg(value_name = "SESSION")]
        session: String,
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Create a recovery fork as a verified new copy outside agent state.
    Fork {
        #[arg(value_name = "SESSION")]
        session: String,
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Perform transactional state repair on a session with backup receipt.
    Repair {
        #[arg(value_name = "SESSION")]
        session: String,
        /// Directory in which pre-repair backups are stored (defaults to ~/.vetto/rescue_backups).
        #[arg(long, value_name = "PATH")]
        backup_dir: Option<PathBuf>,
    },
    /// Rollback a previous state repair using a repair receipt.
    Rollback {
        /// Path to the repair receipt JSON file.
        #[arg(long, value_name = "RECEIPT_PATH")]
        receipt: PathBuf,
        /// Explicit target path override (if target was moved or renamed).
        #[arg(long, value_name = "TARGET_PATH")]
        target: Option<PathBuf>,
    },
}

/// Security telemetry collected from session logs and reports.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityTelemetry {
    pub blocked_file_count: u64,
    pub blocked_file_paths: Vec<String>,
    pub blocked_network_count: u64,
    pub blocked_network_destinations: Vec<String>,
    pub allowed_egress: Vec<String>,
}

/// Kind of file modification observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeType {
    Added,
    Modified,
    Deleted,
}

pub const DEFAULT_MAX_FILES: usize = 10_000;
pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
pub const DEFAULT_MAX_SESSION_BYTES: u64 = 64 * 1024 * 1024;
pub const DEFAULT_MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct RescueContext {
    pub root: PathBuf,
    pub max_files: usize,
    pub max_total_bytes: u64,
    pub max_session_bytes: u64,
    pub max_record_bytes: usize,
}

impl RescueContext {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            max_files: DEFAULT_MAX_FILES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_session_bytes: DEFAULT_MAX_SESSION_BYTES,
            max_record_bytes: DEFAULT_MAX_RECORD_BYTES,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Availability {
    Available,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterStatus {
    pub adapter: String,
    pub availability: Availability,
    pub support_level: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRef {
    pub adapter: String,
    pub key: String,
    pub relative_path: String,
    pub bytes: u64,
    pub modified_unix_secs: Option<u64>,
    #[serde(skip)]
    pub source_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SessionHealth {
    Healthy,
    Warning,
    Corrupt,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionView {
    pub adapter: String,
    pub key: String,
    pub relative_path: String,
    pub bytes: u64,
    pub sha256: String,
    pub health: SessionHealth,
    pub records: usize,
    pub malformed_records: usize,
    pub oversized_records: usize,
    pub terminated_with_newline: bool,
    /// Stable, machine-readable semantic findings discovered without replaying
    /// the provider state.  Adapters must keep these bounded and must never
    /// include raw prompts, tool arguments, or credentials.
    pub findings: Vec<String>,
    pub notices: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotReceipt {
    pub adapter: String,
    pub source_key: String,
    pub destination: String,
    pub bytes: u64,
    pub sha256: String,
    pub source_preserved: bool,
}

/// Cryptographically verifiable receipt produced upon successful state repair.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepairReceipt {
    pub adapter: String,
    pub session_key: String,
    pub original_sha256: String,
    pub repaired_sha256: String,
    pub backup_archive_path: PathBuf,
    pub actions_applied: Vec<String>,
    pub timestamp_unix_secs: u64,
}

/// Receipt generated upon successful atomic rollback of a previous state repair.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollbackReceipt {
    pub adapter: String,
    pub session_key: String,
    pub target_path: String,
    pub restored_sha256: String,
    pub timestamp_unix_secs: u64,
}
