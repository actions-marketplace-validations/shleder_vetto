//! Ephemeral Disposable Sandbox Engine.
//!
//! Provides automatic rollback on failure/cancellation and interactive/flag-based
//! workspace application on success, protecting projects from speculative agent mutations.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;

fn find_snapshot_archive(session_id: &str) -> Option<PathBuf> {
    let direct = Path::new(session_id);
    if direct.is_file() {
        return Some(direct.to_path_buf());
    }
    if let Ok(root) = crate::rescue::snapshot::snapshots_root_dir() {
        let candidate = root.join(session_id).join("snapshot.tar");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    if let Ok(snapshots) = crate::rescue::snapshot::list_snapshots() {
        for s in snapshots {
            if s.session_id == session_id && s.archive_file.is_file() {
                return Some(s.archive_file);
            }
        }
    }
    None
}

fn print_change_preview(session_id: &str, project_dir: &Path) {
    let Some(archive) = find_snapshot_archive(session_id) else {
        return;
    };
    let Ok((modified, added, deleted)) =
        super::snapshot::preview_snapshot_changes(&archive, project_dir)
    else {
        return;
    };

    if added == 0 && modified == 0 && deleted == 0 {
        eprintln!("[VETTO EPHEMERAL] No filesystem changes detected.");
    } else {
        eprintln!(
            "[VETTO EPHEMERAL] Changes: {modified} modified, {added} added, {deleted} deleted"
        );
    }
}

/// Handle post-session ephemeral actions: auto-rollback on failure/force-discard,
/// or prompt user / auto-accept on session success.
pub fn handle_ephemeral_completion(
    session_id: &str,
    project_dir: &Path,
    exit_code: i32,
    auto_accept: bool,
    force_discard: bool,
) -> Result<()> {
    let res = if force_discard || exit_code != 0 {
        if find_snapshot_archive(session_id).is_some() {
            crate::rescue::snapshot::rollback_snapshot(session_id, Some(project_dir))?;
            eprintln!(
                "[VETTO EPHEMERAL] Session ended (exit {exit_code}). \
                 Working tree automatically restored to clean pre-session state."
            );
        } else {
            eprintln!(
                "[VETTO EPHEMERAL] Session ended (exit {exit_code}). \
                 No pre-session snapshot found for automatic rollback."
            );
        }
        Ok(())
    } else if auto_accept {
        eprintln!("[VETTO EPHEMERAL] Session succeeded. Changes kept in workspace.");
        Ok(())
    } else if std::io::stdin().is_terminal() {
        print_change_preview(session_id, project_dir);
        eprint!("[VETTO EPHEMERAL] Apply changes to workspace? [Y/n]: ");
        let _ = std::io::stderr().flush();

        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input);
        let trimmed = input.trim();
        if trimmed.eq_ignore_ascii_case("n") || trimmed.eq_ignore_ascii_case("no") {
            if find_snapshot_archive(session_id).is_some() {
                crate::rescue::snapshot::rollback_snapshot(session_id, Some(project_dir))?;
                eprintln!(
                    "[VETTO EPHEMERAL] Changes discarded. Working tree restored to clean state."
                );
            } else {
                eprintln!("[VETTO EPHEMERAL] No pre-session snapshot found to restore.");
            }
        } else {
            eprintln!("[VETTO EPHEMERAL] Changes kept in workspace.");
        }
        Ok(())
    } else {
        // Non-interactive (piped / CI): default to keeping changes on exit 0
        eprintln!("[VETTO EPHEMERAL] Changes kept in workspace.");
        Ok(())
    };

    // Clean up temporary snapshot directory for ephemeral session
    if let Ok(root) = crate::rescue::snapshot::snapshots_root_dir() {
        let snap_dir = root.join(session_id);
        if snap_dir.exists() {
            let _ = std::fs::remove_dir_all(&snap_dir);
        }
    }

    res
}

/// RAII guard that automatically triggers rollback and snapshot cleanup if dropped prematurely.
pub struct EphemeralGuard {
    session_id: String,
    project_dir: PathBuf,
    completed: bool,
}

impl EphemeralGuard {
    pub fn new(session_id: String, project_dir: PathBuf) -> Self {
        Self {
            session_id,
            project_dir,
            completed: false,
        }
    }

    pub fn complete(mut self) {
        self.completed = true;
    }
}

impl Drop for EphemeralGuard {
    fn drop(&mut self) {
        if !self.completed {
            let _ = crate::rescue::snapshot::rollback_snapshot(
                &self.session_id,
                Some(&self.project_dir),
            );
            if let Ok(root) = crate::rescue::snapshot::snapshots_root_dir() {
                let _ = std::fs::remove_dir_all(root.join(&self.session_id));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rescue::snapshot::{create_snapshot, DEFAULT_MAX_SNAPSHOT_SIZE};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_test_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vetto-ephem-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_ephemeral_discards_on_failure() {
        let project_dir = temp_test_dir("fail");
        let file_path = project_dir.join("code.rs");
        fs::write(&file_path, "fn main() { /* clean */ }\n").unwrap();

        let session_id = format!(
            "test-fail-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        create_snapshot(&project_dir, &session_id, DEFAULT_MAX_SNAPSHOT_SIZE).unwrap();

        // Mutate file to simulate agent failure state
        fs::write(&file_path, "fn main() { /* broken */ }\n").unwrap();
        assert_eq!(
            fs::read_to_string(&file_path).unwrap(),
            "fn main() { /* broken */ }\n"
        );

        // Fail with exit code 1
        handle_ephemeral_completion(&session_id, &project_dir, 1, false, false).unwrap();

        // Working tree restored
        assert_eq!(
            fs::read_to_string(&file_path).unwrap(),
            "fn main() { /* clean */ }\n"
        );

        let _ = fs::remove_dir_all(&project_dir);
        if let Ok(root) = crate::rescue::snapshot::snapshots_root_dir() {
            let _ = fs::remove_dir_all(root.join(&session_id));
        }
    }

    #[test]
    fn test_ephemeral_force_discard() {
        let project_dir = temp_test_dir("force");
        let file_path = project_dir.join("code.rs");
        fs::write(&file_path, "fn main() { /* original */ }\n").unwrap();

        let session_id = format!(
            "test-force-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        create_snapshot(&project_dir, &session_id, DEFAULT_MAX_SNAPSHOT_SIZE).unwrap();

        // Mutate file
        fs::write(&file_path, "fn main() { /* unwanted */ }\n").unwrap();

        // Force discard even with exit code 0
        handle_ephemeral_completion(&session_id, &project_dir, 0, false, true).unwrap();

        // Working tree restored
        assert_eq!(
            fs::read_to_string(&file_path).unwrap(),
            "fn main() { /* original */ }\n"
        );

        let _ = fs::remove_dir_all(&project_dir);
        if let Ok(root) = crate::rescue::snapshot::snapshots_root_dir() {
            let _ = fs::remove_dir_all(root.join(&session_id));
        }
    }

    #[test]
    fn test_ephemeral_auto_accept() {
        let project_dir = temp_test_dir("accept");
        let file_path = project_dir.join("code.rs");
        fs::write(&file_path, "fn main() { /* original */ }\n").unwrap();

        let session_id = format!(
            "test-accept-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        create_snapshot(&project_dir, &session_id, DEFAULT_MAX_SNAPSHOT_SIZE).unwrap();

        // Mutate file
        fs::write(&file_path, "fn main() { /* good changes */ }\n").unwrap();

        // auto_accept is true with exit code 0
        handle_ephemeral_completion(&session_id, &project_dir, 0, true, false).unwrap();

        // Changes are kept
        assert_eq!(
            fs::read_to_string(&file_path).unwrap(),
            "fn main() { /* good changes */ }\n"
        );

        let _ = fs::remove_dir_all(&project_dir);
        if let Ok(root) = crate::rescue::snapshot::snapshots_root_dir() {
            let _ = fs::remove_dir_all(root.join(&session_id));
        }
    }

    #[test]
    fn test_ephemeral_graceful_when_no_snapshot() {
        let project_dir = temp_test_dir("no-snap");
        let non_existent_session = "non-existent-session-id-999999";

        // Must exit Ok(()) without panicking or bailing even if session snapshot does not exist
        let res = handle_ephemeral_completion(non_existent_session, &project_dir, 1, false, false);
        assert!(res.is_ok());

        let res_discard =
            handle_ephemeral_completion(non_existent_session, &project_dir, 0, false, true);
        assert!(res_discard.is_ok());

        let _ = fs::remove_dir_all(&project_dir);
    }

    #[test]
    fn test_ephemeral_guard_drop_rolls_back() {
        let project_dir = temp_test_dir("guard-drop");
        let file_path = project_dir.join("code.rs");
        fs::write(&file_path, "fn main() { /* original */ }\n").unwrap();

        let session_id = format!(
            "test-guard-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        create_snapshot(&project_dir, &session_id, DEFAULT_MAX_SNAPSHOT_SIZE).unwrap();

        {
            let _guard = EphemeralGuard::new(session_id.clone(), project_dir.clone());
            fs::write(&file_path, "fn main() { /* crashed halfway */ }\n").unwrap();
            // Drop without complete()
        }

        assert_eq!(
            fs::read_to_string(&file_path).unwrap(),
            "fn main() { /* original */ }\n"
        );

        let _ = fs::remove_dir_all(&project_dir);
    }

    #[test]
    fn test_ephemeral_guard_complete_keeps_changes() {
        let project_dir = temp_test_dir("guard-complete");
        let file_path = project_dir.join("code.rs");
        fs::write(&file_path, "fn main() { /* original */ }\n").unwrap();

        let session_id = format!(
            "test-guard-complete-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        create_snapshot(&project_dir, &session_id, DEFAULT_MAX_SNAPSHOT_SIZE).unwrap();

        {
            let guard = EphemeralGuard::new(session_id.clone(), project_dir.clone());
            fs::write(&file_path, "fn main() { /* kept */ }\n").unwrap();
            guard.complete();
        }

        assert_eq!(
            fs::read_to_string(&file_path).unwrap(),
            "fn main() { /* kept */ }\n"
        );

        let _ = fs::remove_dir_all(&project_dir);
        if let Ok(root) = crate::rescue::snapshot::snapshots_root_dir() {
            let _ = fs::remove_dir_all(root.join(&session_id));
        }
    }

    #[test]
    fn test_ephemeral_guard_panic_unwind() {
        let project_dir = temp_test_dir("guard-panic");
        let file_path = project_dir.join("code.rs");
        fs::write(&file_path, "fn main() { /* clean */ }\n").unwrap();

        let session_id = format!(
            "test-guard-panic-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        create_snapshot(&project_dir, &session_id, DEFAULT_MAX_SNAPSHOT_SIZE).unwrap();

        let proj_clone = project_dir.clone();
        let file_clone = file_path.clone();
        let sess_clone = session_id.clone();

        let panic_result = std::panic::catch_unwind(move || {
            let _guard = EphemeralGuard::new(sess_clone, proj_clone);
            fs::write(&file_clone, "fn main() { /* tainted before panic */ }\n").unwrap();
            panic!("simulated worker abort");
        });

        assert!(panic_result.is_err(), "must catch panic");

        // The guard must have triggered rollback in Drop during unwind!
        assert_eq!(
            fs::read_to_string(&file_path).unwrap(),
            "fn main() { /* clean */ }\n"
        );

        if let Ok(root) = crate::rescue::snapshot::snapshots_root_dir() {
            assert!(
                !root.join(&session_id).exists(),
                "snapshot archive must be cleaned up on drop"
            );
        }

        let _ = fs::remove_dir_all(&project_dir);
    }
}
