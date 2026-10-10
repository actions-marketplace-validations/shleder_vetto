//! Tamper-evident SHA-256 audit ledger with hash chaining.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const GENESIS_HASH: &str = "GENESIS";

/// Details of a detected ledger corruption or tampering incident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerCorruption {
    pub line_number: usize,
    pub seq: Option<u64>,
    pub expected_hash: Option<String>,
    pub actual_hash: Option<String>,
    pub reason: String,
}

/// Comprehensive outcome of ledger cryptographic verification (INV-34, INV-35).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerVerificationResult {
    pub is_valid: bool,
    pub records_verified: u64,
    pub last_seq: Option<u64>,
    pub last_hash: Option<String>,
    pub has_terminal_record: bool,
    pub has_signature: bool,
    pub corruption: Option<LedgerCorruption>,
}

impl LedgerVerificationResult {
    /// Total records successfully verified in the ledger.
    #[inline]
    pub fn total_records(&self) -> u64 {
        self.records_verified
    }
}

/// Typed error variants for audit ledger operations.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum LedgerError {
    #[error("LedgerClosed: Cannot append to finalized and signed audit ledger")]
    LedgerClosed,
    #[error("LedgerCorrupted: {0}")]
    Corrupted(String),
}

/// An append-only audit ledger implementing tamper-evident hash chaining (INV-34, INV-35).
#[derive(Debug)]
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
    /// Resumes `seq` and `prev_hash` from the existing ledger file if present.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_ref = path.as_ref();
        if let Some(parent) = path_ref.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mut seq = 0;
        let mut prev_hash = GENESIS_HASH.to_string();

        if path_ref.exists() && path_ref.metadata().map(|m| m.len() > 0).unwrap_or(false) {
            let result = Self::verify_file_detailed(path_ref)?;
            if result.has_signature || result.has_terminal_record {
                return Err(LedgerError::LedgerClosed.into());
            }
            if !result.is_valid {
                if let Some(ref c) = result.corruption {
                    if !c.reason.contains("Missing terminal record") {
                        anyhow::bail!("Cannot open corrupted audit ledger: {}", c.reason);
                    }
                }
            }
            if let Some(s) = result.last_seq {
                seq = s + 1;
            }
            if let Some(h) = result.last_hash {
                prev_hash = h;
            }
        }

        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path_ref)
            .context("Failed to open audit ledger")?;

        Ok(Self {
            file: BufWriter::new(f),
            seq,
            prev_hash,
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
        Self::verify_file_detailed(path).map(|r| r.is_valid)
    }

    /// Detailed verification of an audit ledger file with precise corruption diagnosis.
    pub fn verify_file_detailed<P: AsRef<Path>>(path: P) -> Result<LedgerVerificationResult> {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(LedgerVerificationResult {
                    is_valid: false,
                    records_verified: 0,
                    last_seq: None,
                    last_hash: None,
                    has_terminal_record: false,
                    has_signature: false,
                    corruption: Some(LedgerCorruption {
                        line_number: 0,
                        seq: None,
                        expected_hash: None,
                        actual_hash: None,
                        reason: "File not found".to_string(),
                    }),
                });
            }
            Err(e) => return Err(e.into()),
        };

        let reader = BufReader::new(file);
        let mut expected_prev = GENESIS_HASH.to_string();
        let mut expected_seq: u64 = 0;
        let mut seen_signature = false;
        let mut has_terminal_record = false;
        let mut records_verified: u64 = 0;
        let mut last_hash: Option<String> = None;
        let mut line_number = 0;

        for line_res in reader.lines() {
            line_number += 1;
            let line = line_res?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            if seen_signature {
                return Ok(LedgerVerificationResult {
                    is_valid: false,
                    records_verified,
                    last_seq: if expected_seq > 0 {
                        Some(expected_seq - 1)
                    } else {
                        None
                    },
                    last_hash,
                    has_terminal_record,
                    has_signature: true,
                    corruption: Some(LedgerCorruption {
                        line_number,
                        seq: Some(expected_seq),
                        expected_hash: None,
                        actual_hash: None,
                        reason: "Extraneous record found after signature envelope".to_string(),
                    }),
                });
            }

            let value: serde_json::Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(e) => {
                    return Ok(LedgerVerificationResult {
                        is_valid: false,
                        records_verified,
                        last_seq: if expected_seq > 0 {
                            Some(expected_seq - 1)
                        } else {
                            None
                        },
                        last_hash,
                        has_terminal_record,
                        has_signature: seen_signature,
                        corruption: Some(LedgerCorruption {
                            line_number,
                            seq: Some(expected_seq),
                            expected_hash: None,
                            actual_hash: None,
                            reason: format!("JSON parse error: {e}"),
                        }),
                    });
                }
            };

            let mut obj = match value {
                serde_json::Value::Object(map) => map,
                _ => {
                    return Ok(LedgerVerificationResult {
                        is_valid: false,
                        records_verified,
                        last_seq: if expected_seq > 0 {
                            Some(expected_seq - 1)
                        } else {
                            None
                        },
                        last_hash,
                        has_terminal_record,
                        has_signature: seen_signature,
                        corruption: Some(LedgerCorruption {
                            line_number,
                            seq: Some(expected_seq),
                            expected_hash: None,
                            actual_hash: None,
                            reason: "Record is not a JSON object".to_string(),
                        }),
                    });
                }
            };

            if !obj.contains_key("hash") && obj.contains_key("signature") {
                let prev_hash = match obj.get("prev_hash").and_then(|v| v.as_str()) {
                    Some(p) => p,
                    None => {
                        return Ok(LedgerVerificationResult {
                            is_valid: false,
                            records_verified,
                            last_seq: if expected_seq > 0 {
                                Some(expected_seq - 1)
                            } else {
                                None
                            },
                            last_hash,
                            has_terminal_record,
                            has_signature: seen_signature,
                            corruption: Some(LedgerCorruption {
                                line_number,
                                seq: Some(expected_seq),
                                expected_hash: None,
                                actual_hash: None,
                                reason: "Missing prev_hash in signature envelope".to_string(),
                            }),
                        });
                    }
                };
                let seq = match obj.get("seq").and_then(|v| v.as_u64()) {
                    Some(s) => s,
                    None => {
                        return Ok(LedgerVerificationResult {
                            is_valid: false,
                            records_verified,
                            last_seq: if expected_seq > 0 {
                                Some(expected_seq - 1)
                            } else {
                                None
                            },
                            last_hash,
                            has_terminal_record,
                            has_signature: seen_signature,
                            corruption: Some(LedgerCorruption {
                                line_number,
                                seq: Some(expected_seq),
                                expected_hash: None,
                                actual_hash: None,
                                reason: "Missing seq in signature envelope".to_string(),
                            }),
                        });
                    }
                };

                if prev_hash != expected_prev || seq != expected_seq {
                    return Ok(LedgerVerificationResult {
                        is_valid: false,
                        records_verified,
                        last_seq: if expected_seq > 0 { Some(expected_seq - 1) } else { None },
                        last_hash,
                        has_terminal_record,
                        has_signature: seen_signature,
                        corruption: Some(LedgerCorruption {
                            line_number,
                            seq: Some(seq),
                            expected_hash: Some(expected_prev.clone()),
                            actual_hash: Some(prev_hash.to_string()),
                            reason: format!(
                                "Signature envelope mismatch: expected seq={}, prev_hash='{}', got seq={}, prev_hash='{}'",
                                expected_seq, expected_prev, seq, prev_hash
                            ),
                        }),
                    });
                }

                let expected_sig = manual_hex_hash(&format!("CLOSE:{}", expected_prev));
                let actual_sig = obj.get("signature").and_then(|v| v.as_str()).unwrap_or("");
                if actual_sig != expected_sig {
                    return Ok(LedgerVerificationResult {
                        is_valid: false,
                        records_verified,
                        last_seq: if expected_seq > 0 {
                            Some(expected_seq - 1)
                        } else {
                            None
                        },
                        last_hash: Some(expected_prev.to_string()),
                        has_terminal_record,
                        has_signature: false,
                        corruption: Some(LedgerCorruption {
                            line_number,
                            seq: Some(expected_seq),
                            expected_hash: Some(expected_sig),
                            actual_hash: Some(actual_sig.to_string()),
                            reason: "Signature envelope hash mismatch".to_string(),
                        }),
                    });
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
                None => {
                    return Ok(LedgerVerificationResult {
                        is_valid: false,
                        records_verified,
                        last_seq: if expected_seq > 0 {
                            Some(expected_seq - 1)
                        } else {
                            None
                        },
                        last_hash,
                        has_terminal_record,
                        has_signature: seen_signature,
                        corruption: Some(LedgerCorruption {
                            line_number,
                            seq: None,
                            expected_hash: None,
                            actual_hash: None,
                            reason: "Record missing 'seq' field".to_string(),
                        }),
                    });
                }
            };

            let prev_hash = match obj
                .remove("prev_hash")
                .and_then(|v| v.as_str().map(|s| s.to_string()))
            {
                Some(p) => p,
                None => {
                    return Ok(LedgerVerificationResult {
                        is_valid: false,
                        records_verified,
                        last_seq: if expected_seq > 0 {
                            Some(expected_seq - 1)
                        } else {
                            None
                        },
                        last_hash,
                        has_terminal_record,
                        has_signature: seen_signature,
                        corruption: Some(LedgerCorruption {
                            line_number,
                            seq: Some(seq),
                            expected_hash: None,
                            actual_hash: None,
                            reason: "Record missing 'prev_hash' field".to_string(),
                        }),
                    });
                }
            };

            let hash = match obj
                .remove("hash")
                .and_then(|v| v.as_str().map(|s| s.to_string()))
            {
                Some(h) => h,
                None => {
                    return Ok(LedgerVerificationResult {
                        is_valid: false,
                        records_verified,
                        last_seq: if expected_seq > 0 {
                            Some(expected_seq - 1)
                        } else {
                            None
                        },
                        last_hash,
                        has_terminal_record,
                        has_signature: seen_signature,
                        corruption: Some(LedgerCorruption {
                            line_number,
                            seq: Some(seq),
                            expected_hash: None,
                            actual_hash: None,
                            reason: "Record missing 'hash' field".to_string(),
                        }),
                    });
                }
            };

            if seq != expected_seq {
                return Ok(LedgerVerificationResult {
                    is_valid: false,
                    records_verified,
                    last_seq: if expected_seq > 0 {
                        Some(expected_seq - 1)
                    } else {
                        None
                    },
                    last_hash,
                    has_terminal_record,
                    has_signature: seen_signature,
                    corruption: Some(LedgerCorruption {
                        line_number,
                        seq: Some(seq),
                        expected_hash: None,
                        actual_hash: None,
                        reason: format!("Sequence break: expected {}, got {}", expected_seq, seq),
                    }),
                });
            }

            if prev_hash != expected_prev {
                return Ok(LedgerVerificationResult {
                    is_valid: false,
                    records_verified,
                    last_seq: if expected_seq > 0 {
                        Some(expected_seq - 1)
                    } else {
                        None
                    },
                    last_hash,
                    has_terminal_record,
                    has_signature: seen_signature,
                    corruption: Some(LedgerCorruption {
                        line_number,
                        seq: Some(seq),
                        expected_hash: Some(expected_prev),
                        actual_hash: Some(prev_hash),
                        reason: "Hash chain break: prev_hash does not match previous entry's hash"
                            .to_string(),
                    }),
                });
            }

            let payload_json = serde_json::to_string(&serde_json::Value::Object(obj))?;
            let data_to_hash_canonical = format!("{}:{}:{}", prev_hash, seq, payload_json);
            let recomputed = manual_hex_hash(&data_to_hash_canonical);
            let data_to_hash_alt = format!("{}:{}:{}", seq, prev_hash, payload_json);
            let recomputed_alt = manual_hex_hash(&data_to_hash_alt);

            if recomputed != hash && recomputed_alt != hash {
                return Ok(LedgerVerificationResult {
                    is_valid: false,
                    records_verified,
                    last_seq: if expected_seq > 0 {
                        Some(expected_seq - 1)
                    } else {
                        None
                    },
                    last_hash,
                    has_terminal_record,
                    has_signature: seen_signature,
                    corruption: Some(LedgerCorruption {
                        line_number,
                        seq: Some(seq),
                        expected_hash: Some(recomputed),
                        actual_hash: Some(hash),
                        reason: "Cryptographic hash mismatch: record payload was tampered"
                            .to_string(),
                    }),
                });
            }

            expected_prev = hash.clone();
            last_hash = Some(hash);
            expected_seq += 1;
            records_verified += 1;
        }

        let is_valid = expected_seq > 0 && (has_terminal_record || seen_signature);
        let corruption = if is_valid {
            None
        } else if expected_seq == 0 {
            Some(LedgerCorruption {
                line_number: 0,
                seq: None,
                expected_hash: None,
                actual_hash: None,
                reason: "Empty ledger: 0 records found".to_string(),
            })
        } else {
            Some(LedgerCorruption {
                line_number,
                seq: Some(expected_seq - 1),
                expected_hash: None,
                actual_hash: None,
                reason: "Missing terminal record (SESSION_VERDICT) or signature envelope"
                    .to_string(),
            })
        };

        Ok(LedgerVerificationResult {
            is_valid,
            records_verified,
            last_seq: if expected_seq > 0 {
                Some(expected_seq - 1)
            } else {
                None
            },
            last_hash,
            has_terminal_record,
            has_signature: seen_signature,
            corruption,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize)]
    struct TestPayload {
        message: String,
        code: i32,
        #[serde(skip_serializing_if = "Option::is_none")]
        record_type: Option<String>,
    }

    #[test]
    fn test_audit_ledger_lifecycle_and_verification() {
        let temp_dir =
            std::env::temp_dir().join(format!("vetto-test-ledger-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let ledger_path = temp_dir.join("ledger.jsonl");
        let _ = std::fs::remove_file(&ledger_path);

        let mut ledger = AuditLedger::new(&ledger_path).expect("create ledger");

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

        let result = AuditLedger::verify_file_detailed(&ledger_path).expect("verify ledger");
        assert!(result.is_valid);
        assert_eq!(result.records_verified, 2);
        assert!(result.has_terminal_record);
        assert!(result.corruption.is_none());

        assert!(AuditLedger::verify_file(&ledger_path).expect("verify file bool"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_audit_ledger_tamper_detection() {
        let temp_dir =
            std::env::temp_dir().join(format!("vetto-test-ledger-tamper-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let ledger_path = temp_dir.join("ledger.jsonl");
        let _ = std::fs::remove_file(&ledger_path);

        let mut ledger = AuditLedger::new(&ledger_path).expect("create ledger");

        let p1 = TestPayload {
            message: "event1".into(),
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

        // Tamper with first line: modify payload
        let content = std::fs::read_to_string(&ledger_path).expect("read");
        let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
        lines[0] = lines[0].replace("event1", "malicious_injected");
        std::fs::write(&ledger_path, lines.join("\n") + "\n").expect("write");

        let result = AuditLedger::verify_file_detailed(&ledger_path).expect("verify");
        assert!(!result.is_valid);
        let corr = result.corruption.expect("corruption detail");
        assert_eq!(corr.line_number, 1);
        assert_eq!(corr.seq, Some(0));
        assert!(corr.reason.contains("Cryptographic hash mismatch"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_audit_ledger_append_resumption() {
        let temp_dir =
            std::env::temp_dir().join(format!("vetto-test-ledger-resume-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let ledger_path = temp_dir.join("ledger.jsonl");
        let _ = std::fs::remove_file(&ledger_path);

        {
            let mut ledger = AuditLedger::new(&ledger_path).expect("create ledger");
            let p1 = TestPayload {
                message: "first".into(),
                code: 0,
                record_type: None,
            };
            ledger.record_event(&p1).expect("record p1");
        }

        // Re-open existing ledger: seq should resume at 1
        {
            let mut ledger = AuditLedger::new(&ledger_path).expect("resume ledger");
            assert_eq!(ledger.seq, 1);
            let p2 = TestPayload {
                message: "verdict".into(),
                code: 0,
                record_type: Some("SESSION_VERDICT".into()),
            };
            ledger.record_event(&p2).expect("record p2");
        }

        let result = AuditLedger::verify_file_detailed(&ledger_path).expect("verify");
        assert!(result.is_valid);
        assert_eq!(result.records_verified, 2);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_audit_ledger_signed_cannot_append() {
        let temp_dir =
            std::env::temp_dir().join(format!("vetto-test-ledger-signed-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let ledger_path = temp_dir.join("ledger.jsonl");

        {
            let mut ledger = AuditLedger::new(&ledger_path).expect("create ledger");
            let p1 = TestPayload {
                message: "only_event".into(),
                code: 0,
                record_type: None,
            };
            ledger.record_event(&p1).expect("record");
            ledger.sign_and_close().expect("sign and close");
        }

        let verify_res = AuditLedger::verify_file_detailed(&ledger_path).expect("verify");
        assert!(verify_res.is_valid);
        assert!(verify_res.has_signature);

        let reopen_res = AuditLedger::new(&ledger_path);
        assert!(reopen_res.is_err());
        assert!(reopen_res
            .unwrap_err()
            .to_string()
            .contains("Cannot append to finalized and signed audit ledger"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_audit_ledger_signature_tamper_detection() {
        let temp_dir = std::env::temp_dir().join(format!(
            "vetto-test-ledger-sigtamper-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&temp_dir);
        let ledger_path = temp_dir.join("ledger.jsonl");

        {
            let mut ledger = AuditLedger::new(&ledger_path).expect("create ledger");
            let p1 = TestPayload {
                message: "event".into(),
                code: 0,
                record_type: None,
            };
            ledger.record_event(&p1).expect("record");
            ledger.sign_and_close().expect("sign and close");
        }

        // Tamper with signature envelope
        let content = std::fs::read_to_string(&ledger_path).expect("read");
        let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
        assert_eq!(lines.len(), 2);
        lines[1] = lines[1].replace(
            "\"signature\":\"",
            "\"signature\":\"00000000000000000000000000000000",
        );
        std::fs::write(&ledger_path, lines.join("\n") + "\n").expect("write");

        let verify_res = AuditLedger::verify_file_detailed(&ledger_path).expect("verify");
        assert!(!verify_res.is_valid);
        let corr = verify_res.corruption.expect("corruption");
        assert_eq!(corr.reason, "Signature envelope hash mismatch");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_audit_ledger_creates_parent_directory() {
        let temp_dir = std::env::temp_dir().join(format!(
            "vetto-test-ledger-parent-{}/nested/sub",
            std::process::id()
        ));
        let ledger_path = temp_dir.join("ledger.jsonl");
        assert!(!temp_dir.exists());

        let mut ledger = AuditLedger::new(&ledger_path).expect("create ledger with missing parent");
        let p1 = TestPayload {
            message: "ok".into(),
            code: 0,
            record_type: None,
        };
        ledger.record_event(&p1).expect("record");
        assert!(ledger_path.exists());

        let _ = std::fs::remove_dir_all(
            std::env::temp_dir().join(format!("vetto-test-ledger-parent-{}", std::process::id())),
        );
    }

    #[test]
    fn test_audit_ledger_typed_ledger_closed_error() {
        let temp_dir = std::env::temp_dir().join(format!(
            "vetto-test-ledger-typed-err-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&temp_dir);
        let ledger_path = temp_dir.join("ledger.jsonl");

        {
            let mut ledger = AuditLedger::new(&ledger_path).expect("create ledger");
            let p = TestPayload {
                message: "finalized".into(),
                code: 0,
                record_type: None,
            };
            ledger.record_event(&p).expect("record");
            ledger.sign_and_close().expect("sign and close");
        }

        let reopen_res = AuditLedger::new(&ledger_path);
        assert!(reopen_res.is_err());
        let err = reopen_res.unwrap_err();
        assert_eq!(
            err.downcast_ref::<LedgerError>(),
            Some(&LedgerError::LedgerClosed)
        );
        assert!(err
            .to_string()
            .contains("LedgerClosed: Cannot append to finalized and signed audit ledger"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_audit_ledger_tamper_payload_modification_at_n() {
        let temp_dir = std::env::temp_dir().join(format!(
            "vetto-test-ledger-payload-tamper-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&temp_dir);
        let ledger_path = temp_dir.join("ledger.jsonl");

        {
            let mut ledger = AuditLedger::new(&ledger_path).expect("create ledger");
            for i in 0..3 {
                let p = TestPayload {
                    message: format!("event_{i}"),
                    code: i,
                    record_type: if i == 2 {
                        Some("SESSION_VERDICT".into())
                    } else {
                        None
                    },
                };
                ledger.record_event(&p).expect("record");
            }
            ledger.sign_and_close().expect("sign and close");
        }

        // Mutate payload on line 2 (1-based line number 2, seq 1)
        let content = std::fs::read_to_string(&ledger_path).expect("read");
        let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
        assert!(lines.len() >= 4); // 3 events + 1 signature
        lines[1] = lines[1].replace("\"event_1\"", "\"event_tampered\"");
        std::fs::write(&ledger_path, lines.join("\n") + "\n").expect("write");

        let verify_res = AuditLedger::verify_file_detailed(&ledger_path).expect("verify");
        assert!(!verify_res.is_valid);
        let corr = verify_res.corruption.expect("corruption details");
        assert_eq!(corr.line_number, 2);
        assert_eq!(corr.seq, Some(1));
        assert!(corr.reason.contains("Cryptographic hash mismatch"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_audit_ledger_tamper_line_deletion() {
        let temp_dir =
            std::env::temp_dir().join(format!("vetto-test-ledger-line-del-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let ledger_path = temp_dir.join("ledger.jsonl");

        {
            let mut ledger = AuditLedger::new(&ledger_path).expect("create ledger");
            for i in 0..3 {
                let p = TestPayload {
                    message: format!("event_{i}"),
                    code: i,
                    record_type: if i == 2 {
                        Some("SESSION_VERDICT".into())
                    } else {
                        None
                    },
                };
                ledger.record_event(&p).expect("record");
            }
            ledger.sign_and_close().expect("sign and close");
        }

        // Delete line 2 (seq 1) from the middle of the ledger
        let content = std::fs::read_to_string(&ledger_path).expect("read");
        let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
        assert!(lines.len() >= 4);
        lines.remove(1); // removes index 1 (line 2)
        std::fs::write(&ledger_path, lines.join("\n") + "\n").expect("write");

        let verify_res = AuditLedger::verify_file_detailed(&ledger_path).expect("verify");
        assert!(!verify_res.is_valid);
        let corr = verify_res.corruption.expect("corruption details");
        assert_eq!(corr.line_number, 2);
        assert!(corr.reason.contains("Sequence break") || corr.reason.contains("Hash chain break"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_audit_ledger_tamper_forged_record_seq_spoofing() {
        let temp_dir = std::env::temp_dir().join(format!(
            "vetto-test-ledger-seq-spoof-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&temp_dir);
        let ledger_path = temp_dir.join("ledger.jsonl");

        let hash_0 = {
            let mut ledger = AuditLedger::new(&ledger_path).expect("create ledger");
            let p = TestPayload {
                message: "genesis_event".into(),
                code: 0,
                record_type: None,
            };
            ledger.record_event(&p).expect("record")
        };

        // Inject forged record with invalid seq 99
        let forged_line = format!(
            r#"{{"seq":99,"prev_hash":"{hash_0}","hash":"0000000000000000000000000000000000000000000000000000000000000000","message":"forged","code":99}}"#
        );
        let mut content = std::fs::read_to_string(&ledger_path).expect("read");
        content.push_str(&forged_line);
        content.push('\n');
        std::fs::write(&ledger_path, content).expect("write");

        let verify_res = AuditLedger::verify_file_detailed(&ledger_path).expect("verify");
        assert!(!verify_res.is_valid);
        let corr = verify_res.corruption.expect("corruption details");
        assert_eq!(corr.line_number, 2);
        assert!(corr.reason.contains("Sequence break"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_audit_ledger_tamper_records_after_signature_envelope() {
        let temp_dir = std::env::temp_dir().join(format!(
            "vetto-test-ledger-after-sig-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&temp_dir);
        let ledger_path = temp_dir.join("ledger.jsonl");

        {
            let mut ledger = AuditLedger::new(&ledger_path).expect("create ledger");
            let p = TestPayload {
                message: "final".into(),
                code: 0,
                record_type: Some("SESSION_VERDICT".into()),
            };
            ledger.record_event(&p).expect("record");
            ledger.sign_and_close().expect("sign and close");
        }

        // Append extraneous record after signature envelope
        let extraneous_line = r#"{"seq":2,"prev_hash":"0000","hash":"0000","message":"illegal"}"#;
        let mut content = std::fs::read_to_string(&ledger_path).expect("read");
        content.push_str(extraneous_line);
        content.push('\n');
        std::fs::write(&ledger_path, content).expect("write");

        let verify_res = AuditLedger::verify_file_detailed(&ledger_path).expect("verify");
        assert!(!verify_res.is_valid);
        let corr = verify_res.corruption.expect("corruption details");
        assert!(corr
            .reason
            .contains("Extraneous record found after signature envelope"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
