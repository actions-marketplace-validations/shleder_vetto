//! Tamper-evident SHA-256 audit ledger with hash chaining.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub const GENESIS_HASH: &str = "GENESIS";

/// An append-only audit ledger implementing tamper-evident hash chaining (INV-34, INV-35).
pub struct AuditLedger {
    file: BufWriter<File>,
    seq: u64,
    prev_hash: String,
}

#[derive(Serialize)]
struct EventEnvelope<'a, T: Serialize> {
    seq: u64,
    prev_hash: &'a str,
    hash: &'a str,
    #[serde(flatten)]
    payload: &'a T,
}

#[derive(Serialize)]
struct SignatureEnvelope<'a> {
    seq: u64,
    prev_hash: &'a str,
    signature: String,
}

fn manual_hex_hash(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let result = hasher.finalize();
    let mut out = String::with_capacity(64);
    for b in result {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

impl AuditLedger {
    /// Creates or opens an audit ledger at the specified host path.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.as_ref())
            .context("Failed to open vetto-audit.jsonl")?;

        Ok(Self {
            file: BufWriter::new(f),
            seq: 0,
            prev_hash: GENESIS_HASH.to_string(),
        })
    }

    /// Records an event to the ledger, cryptographically linking it to the preceding event hash.
    pub fn record_event<T: Serialize>(&mut self, event: &T) -> Result<String> {
        let payload_value = serde_json::to_value(event)?;
        let payload_json = serde_json::to_string(&payload_value)?;
        let data_to_hash = format!("{}:{}:{}", self.prev_hash, self.seq, payload_json);
        let current_hash = manual_hex_hash(&data_to_hash);

        let envelope = EventEnvelope {
            seq: self.seq,
            prev_hash: &self.prev_hash,
            hash: &current_hash,
            payload: event,
        };

        let envelope_json = serde_json::to_string(&envelope)?;
        writeln!(self.file, "{}", envelope_json)?;
        self.file.flush()?;

        self.prev_hash = current_hash.clone();
        self.seq += 1;

        Ok(current_hash)
    }

    /// Records a typed audit entry adhering to machine-verifiable schema.
    pub fn record_audit_record(
        &mut self,
        record: &crate::audit::VettoAuditRecord,
    ) -> Result<String> {
        self.record_event(record)
    }

    /// Appends a closing record to the ledger.
    pub fn sign_and_close(mut self) -> Result<String> {
        let sig = manual_hex_hash(&format!("CLOSE:{}", self.prev_hash));
        let env = SignatureEnvelope {
            seq: self.seq,
            prev_hash: &self.prev_hash,
            signature: sig.clone(),
        };

        let env_json = serde_json::to_string(&env)?;
        writeln!(self.file, "{}", env_json)?;
        self.file.flush()?;

        Ok(sig)
    }

    /// Verifies the cryptographic Merkle DAG hash chain of an audit ledger file (INV-34).
    pub fn verify_file<P: AsRef<Path>>(path: P) -> Result<bool> {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        use std::io::BufRead;
        let reader = std::io::BufReader::new(file);
        let mut expected_prev = GENESIS_HASH.to_string();
        let mut expected_seq: u64 = 0;
        let mut seen_signature = false;
        let mut has_terminal_record = false;

        for line_res in reader.lines() {
            let line = line_res?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if seen_signature {
                return Ok(false);
            }
            let value: serde_json::Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(_) => return Ok(false),
            };

            let mut obj = match value {
                serde_json::Value::Object(map) => map,
                _ => return Ok(false),
            };

            if !obj.contains_key("hash") && obj.contains_key("signature") {
                let prev_hash = match obj.get("prev_hash").and_then(|v| v.as_str()) {
                    Some(p) => p,
                    None => return Ok(false),
                };
                let seq = match obj.get("seq").and_then(|v| v.as_u64()) {
                    Some(s) => s,
                    None => return Ok(false),
                };
                if prev_hash != expected_prev || seq != expected_seq {
                    return Ok(false);
                }
                seen_signature = true;
                continue;
            }

            if let Some(record_type) = obj.get("record_type").and_then(|v| v.as_str()) {
                if record_type == "SESSION_VERDICT" {
                    has_terminal_record = true;
                }
            }

            let seq = match obj.remove("seq").and_then(|v| v.as_u64()) {
                Some(s) => s,
                None => return Ok(false),
            };
            let prev_hash = match obj
                .remove("prev_hash")
                .and_then(|v| v.as_str().map(|s| s.to_string()))
            {
                Some(p) => p,
                None => return Ok(false),
            };
            let hash = match obj
                .remove("hash")
                .and_then(|v| v.as_str().map(|s| s.to_string()))
            {
                Some(h) => h,
                None => return Ok(false),
            };

            if seq != expected_seq || prev_hash != expected_prev {
                return Ok(false);
            }

            let payload_json = serde_json::to_string(&serde_json::Value::Object(obj))?;
            let data_to_hash = format!("{}:{}:{}", prev_hash, seq, payload_json);
            let recomputed = manual_hex_hash(&data_to_hash);
            if recomputed != hash {
                return Ok(false);
            }

            expected_prev = hash;
            expected_seq += 1;
        }

        Ok(expected_seq > 0 && (has_terminal_record || seen_signature))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_ledger_lifecycle_and_verification() {
        let temp_dir =
            std::env::temp_dir().join(format!("vetto-test-ledger-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let ledger_path = temp_dir.join("ledger.jsonl");
        let _ = std::fs::remove_file(&ledger_path);

        let mut ledger = AuditLedger::new(&ledger_path).expect("create ledger");

        #[derive(Serialize)]
        struct TestPayload {
            message: String,
            code: i32,
            #[serde(skip_serializing_if = "Option::is_none")]
            record_type: Option<String>,
        }

        let p1 = TestPayload {
            message: "init".into(),
            code: 0,
            record_type: None,
        };
        let p2 = TestPayload {
            message: "verdict".into(),
            code: 0,
            record_type: Some("SESSION_VERDICT".into()),
        };

        ledger.record_event(&p1).expect("record p1");
        ledger.record_event(&p2).expect("record p2");

        assert!(AuditLedger::verify_file(&ledger_path).expect("verify ledger"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
