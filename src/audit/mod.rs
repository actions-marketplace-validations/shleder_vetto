//! Audit history indexing, session security inspection, daily digest, and verdict evaluation.

pub mod diff_sessions;
pub mod digest;
pub mod history;
pub mod ledger;
pub mod recap;
pub mod record;
pub mod verdict;

pub use digest::run_digest;
pub use history::{
    append_session_history, compute_auto_timeout, compute_auto_timeout_for_agent,
    default_history_path, inspect_latest_session, inspect_session, load_agent_durations,
    load_agent_durations_from_records, record_session_history, run_audit, run_audit_command,
    verify_ledger_cli, AuditRecord, SessionAuditDetail, SessionHistoryRecord,
    MIN_AUTO_TIMEOUT_SECS,
};
pub use ledger::{AuditLedger, LedgerCorruption, LedgerVerificationResult, GENESIS_HASH};
pub use recap::{format_session_recap, SessionRecapInput, RECAP_TOP_N};
pub use record::{
    AuditPayload, FsMutationPayload, FsMutationType, RecordType, ResourceSamplePayload,
    SessionInitPayload, SessionVerdictPayload, SyscallActionTaken, SyscallDenialPayload,
    TierClassification, TreeExtinctionPayload, VettoAuditRecord,
};
pub use verdict::{EvidenceStrength, FinalVerdict, VerdictEngine, VerdictStatus};
