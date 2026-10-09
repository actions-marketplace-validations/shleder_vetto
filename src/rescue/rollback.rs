//! Transactional repair receipts and atomic rollback subsystem.
//!
//! Enforces two-phase atomic commits for all rescue state repairs:
//! 1. Writes repaired content to a temporary sibling file `.<file>.vetto_tmp.<pid>.<nonce>`.
//! 2. Flushes data to disk with `File::sync_all()`.
//! 3. Performs an atomic swap via `std::fs::rename()` over the target file.
//! 4. Synchronizes the parent directory.
//!
//! Provides `rollback_session` for two-phase atomic workspace rollback (`vetto undo`)
//! including deletion of untracked files added by the agent.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

use super::{RepairReceipt, RollbackReceipt};

static ROLLBACK_NONCE: AtomicU64 = AtomicU64::new(0);

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Result of a project rollback operation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RollbackResult {
    pub session_id: String,
    pub target_dir: PathBuf,
    pub files_restored: usize,
    pub bytes_restored: u64,
    pub files_deleted: usize,
}

/// Atomically writes `bytes` to `target_path` via a temporary sibling file
/// and `std::fs::rename`, optionally setting POSIX file permissions.
pub fn atomic_commit_bytes_with_mode(
    target_path: &Path,
    bytes: &[u8],
    mode: Option<u32>,
) -> Result<()> {
    let parent = target_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("create parent dir {}", parent.display()))?;

    let file_name = target_path
        .file_name()
        .context("target path has no filename")?
        .to_string_lossy();

    let nonce = ROLLBACK_NONCE.fetch_add(1, Ordering::Relaxed);
    let tmp_name = format!(".{}.vetto_tmp.{}.{}", file_name, std::process::id(), nonce);
    let tmp_path = parent.join(tmp_name);

    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
    {
        Ok(f) => f,
        Err(e) => {
            let _ = fs::remove_file(&tmp_path);
            return Err(e).with_context(|| format!("create atomic tmp file {}", tmp_path.display()));
        }
    };

    if let Err(e) = file.write_all(bytes) {
        drop(file);
        let _ = fs::remove_file(&tmp_path);
        return Err(e).with_context(|| format!("write to atomic tmp file {}", tmp_path.display()));
    }

    if let Err(e) = file.sync_all() {
        drop(file);
        let _ = fs::remove_file(&tmp_path);
        return Err(e).with_context(|| format!("sync atomic tmp file {}", tmp_path.display()));
    }
    drop(file);

    #[cfg(unix)]
    if let Some(m) = mode {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(m));
    }

    if let Err(e) = fs::rename(&tmp_path, target_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e).with_context(|| {
            format!(
                "atomic swap {} -> {}",
                tmp_path.display(),
                target_path.display()
            )
        });
    }

    #[cfg(unix)]
    if let Ok(dir_file) = File::open(parent) {
        let _ = dir_file.sync_all();
    }

    Ok(())
}

/// Atomically writes `bytes` to `target_path` via a temporary sibling file
/// and `std::fs::rename`.
pub fn atomic_commit_bytes(target_path: &Path, bytes: &[u8]) -> Result<()> {
    atomic_commit_bytes_with_mode(target_path, bytes, None)
}

/// Rollback / restore a project snapshot.
/// 1. Atomically restores all snapshot files (with original permissions).
/// 2. Deletes any untracked files added during the session.
/// 3. Returns accurate statistics for restored files, bytes, and deleted files.
pub fn rollback_session(
    session: &str,
    target_dir_override: Option<&Path>,
) -> Result<RollbackResult> {
    let session_path = Path::new(session);
    let (archive_path, project_dir) = if session_path.is_file() {
        let parent = session_path.parent().unwrap_or(Path::new("."));
        let meta_file = parent.join("metadata.json");
        let proj = if meta_file.exists() {
            let text = std::fs::read_to_string(&meta_file).unwrap_or_default();
            let meta: Option<super::snapshot::SnapshotMetadata> = serde_json::from_str(&text).ok();
            meta.map(|m| m.project_dir)
                .unwrap_or_else(|| PathBuf::from("."))
        } else {
            PathBuf::from(".")
        };
        (session_path.to_path_buf(), proj)
    } else {
        let root = super::snapshot::snapshots_root_dir()?;
        let dir = root.join(session);
        if !dir.exists() {
            bail!(
                "snapshot for session '{session}' was not found in {}",
                root.display()
            );
        }
        let archive = dir.join("snapshot.tar");
        if !archive.exists() {
            bail!("snapshot archive '{}' not found", archive.display());
        }
        let meta_file = dir.join("metadata.json");
        let proj = if meta_file.exists() {
            let text = std::fs::read_to_string(&meta_file).unwrap_or_default();
            let meta: Option<super::snapshot::SnapshotMetadata> = serde_json::from_str(&text).ok();
            meta.map(|m| m.project_dir)
                .unwrap_or_else(|| PathBuf::from("."))
        } else {
            PathBuf::from(".")
        };
        (archive, proj)
    };

    let dest = target_dir_override.unwrap_or(&project_dir);
    fs::create_dir_all(dest)
        .with_context(|| format!("failed to create restore directory {}", dest.display()))?;

    let mut archive_file = File::open(&archive_path)
        .with_context(|| format!("failed to open snapshot archive {}", archive_path.display()))?;

    let mut files_restored = 0;
    let mut bytes_restored = 0u64;
    let mut snapshot_files = HashSet::new();

    loop {
        let mut header = [0u8; 512];
        let n = archive_file.read(&mut header)?;
        if n < 512 || header.iter().all(|&b| b == 0) {
            break;
        }

        let (name, size, mode) = super::snapshot::parse_tar_header_with_mode(&header)?;
        if name.is_empty() {
            break;
        }

        let mut data = vec![0u8; size as usize];
        archive_file.read_exact(&mut data)?;

        let padding = (512 - (size % 512)) % 512;
        if padding > 0 {
            let mut pad_buf = vec![0u8; padding as usize];
            archive_file.read_exact(&mut pad_buf)?;
        }

        let clean_path = Path::new(&name);
        if clean_path.is_absolute()
            || clean_path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            continue;
        }

        snapshot_files.insert(clean_path.to_path_buf());
        let out_path = dest.join(clean_path);
        atomic_commit_bytes_with_mode(&out_path, &data, Some(mode))?;
        files_restored += 1;
        bytes_restored += size;
    }

    // Clean up untracked files created by the agent during session
    let mut files_deleted = 0;
    let mut disk_dirs = Vec::new();
    let mut queue = vec![dest.to_path_buf()];

    while let Some(dir) = queue.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };

            if file_type.is_dir() {
                if !crate::fs::is_ignored_directory(&name) {
                    disk_dirs.push(path.clone());
                    queue.push(path);
                }
            } else if file_type.is_file() {
                if let Ok(rel) = path.strip_prefix(dest) {
                    if !snapshot_files.contains(rel) {
                        let _ = fs::remove_file(&path);
                        files_deleted += 1;
                    }
                }
            }
        }
    }

    // Clean up newly created empty directories (in reverse order)
    disk_dirs.sort_by(|a, b| b.cmp(a));
    for dir in disk_dirs {
        if let Ok(mut entries) = fs::read_dir(&dir) {
            if entries.next().is_none() {
                let _ = fs::remove_dir(&dir);
            }
        }
    }

    Ok(RollbackResult {
        session_id: session.to_string(),
        target_dir: dest.to_path_buf(),
        files_restored,
        bytes_restored,
        files_deleted,
    })
}

/// Rollback a previous repair by verifying receipt hashes and restoring
/// the pre-repair backup archive atomically.
pub fn rollback_repair(
    receipt_path: &Path,
    target_override: Option<&Path>,
) -> Result<RollbackReceipt> {
    let receipt_bytes = fs::read(receipt_path)
        .with_context(|| format!("read repair receipt {}", receipt_path.display()))?;
    let receipt: RepairReceipt = serde_json::from_slice(&receipt_bytes)
        .with_context(|| format!("parse repair receipt {}", receipt_path.display()))?;

    let backup_path = &receipt.backup_archive_path;
    if !backup_path.exists() {
        bail!(
            "backup archive {} specified in receipt does not exist",
            backup_path.display()
        );
    }

    let backup_bytes = fs::read(backup_path)
        .with_context(|| format!("read backup archive {}", backup_path.display()))?;
    let actual_backup_sha256 = sha256_bytes(&backup_bytes);

    if actual_backup_sha256 != receipt.original_sha256 {
        bail!(
            "backup archive cryptographic hash mismatch: expected {}, found {}",
            receipt.original_sha256,
            actual_backup_sha256
        );
    }

    let target_path: PathBuf = match target_override {
        Some(t) => t.to_path_buf(),
        None => {
            let candidate = PathBuf::from(&receipt.session_key);
            if candidate.exists() {
                candidate
            } else {
                bail!(
                    "target file for session {} could not be automatically determined; pass --target explicitly",
                    receipt.session_key
                );
            }
        }
    };

    atomic_commit_bytes(&target_path, &backup_bytes)?;

    let restored_bytes = fs::read(&target_path)
        .with_context(|| format!("read restored target {}", target_path.display()))?;
    let restored_sha256 = sha256_bytes(&restored_bytes);

    if restored_sha256 != receipt.original_sha256 {
        bail!("rollback verification hash mismatch after restore");
    }

    let timestamp_unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Ok(RollbackReceipt {
        adapter: receipt.adapter,
        session_key: receipt.session_key,
        target_path: target_path.to_string_lossy().to_string(),
        restored_sha256,
        timestamp_unix_secs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn test_dir(tag: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "vetto-rollback-{tag}-{}-{nonce}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn atomic_commit_writes_file_cleanly() {
        let dir = test_dir("commit");
        let target = dir.join("session.jsonl");
        atomic_commit_bytes(&target, b"line 1\nline 2\n").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"line 1\nline 2\n");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn rollback_restores_exact_pre_repair_bytes_from_receipt() {
        let dir = test_dir("rb-test");
        let target = dir.join("session.jsonl");
        let original_data = b"original pre-repair content\n";
        let repaired_data = b"repaired content\n";

        fs::write(&target, repaired_data).unwrap();

        let backup_file = dir.join("backup_session.jsonl");
        fs::write(&backup_file, original_data).unwrap();

        let receipt = RepairReceipt {
            adapter: "test".to_string(),
            session_key: "session.jsonl".to_string(),
            original_sha256: sha256_bytes(original_data),
            repaired_sha256: sha256_bytes(repaired_data),
            backup_archive_path: backup_file.clone(),
            actions_applied: vec!["test_repair".to_string()],
            timestamp_unix_secs: 1234567,
        };

        let receipt_path = dir.join("receipt.json");
        fs::write(
            &receipt_path,
            serde_json::to_string_pretty(&receipt).unwrap(),
        )
        .unwrap();

        let rb_receipt = rollback_repair(&receipt_path, Some(&target)).expect("rollback");
        assert_eq!(rb_receipt.restored_sha256, receipt.original_sha256);
        assert_eq!(fs::read(&target).unwrap(), original_data);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn rollback_rejects_tampered_backup() {
        let dir = test_dir("tamper-test");
        let target = dir.join("session.jsonl");
        let original_data = b"original content";
        let backup_file = dir.join("backup.jsonl");
        fs::write(&backup_file, b"tampered content").unwrap();

        let receipt = RepairReceipt {
            adapter: "test".to_string(),
            session_key: "session.jsonl".to_string(),
            original_sha256: sha256_bytes(original_data),
            repaired_sha256: sha256_bytes(b"repaired"),
            backup_archive_path: backup_file,
            actions_applied: vec![],
            timestamp_unix_secs: 100,
        };

        let receipt_path = dir.join("receipt.json");
        fs::write(&receipt_path, serde_json::to_string(&receipt).unwrap()).unwrap();

        let res = rollback_repair(&receipt_path, Some(&target));
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("hash mismatch"));

        let _ = fs::remove_dir_all(dir);
    }
}
