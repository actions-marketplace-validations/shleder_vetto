//! Project Diff Report (Feature 30).
//!
//! Creates an initial manifest of project files (path, mtime, size, quick sha256 hash)
//! and compares it with the final session state to report modified/created/deleted files
//! without duplicating the whole project tree.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub use crate::rescue::types::ChangeType;

/// File metadata captured in the baseline manifest.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FileFingerprint {
    pub size: u64,
    pub mtime_secs: u64,
    pub mode: u32,
    pub sha256: String,
}

/// Baseline manifest of project files before session execution.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ProjectManifest {
    pub files: BTreeMap<PathBuf, FileFingerprint>,
}

impl ProjectManifest {
    /// Captures a project manifest using fast metadata inspection without reading file contents.
    pub fn capture_fast(root: &Path, max_files: usize, budget: Duration) -> Self {
        let mut files = BTreeMap::new();
        let mut queue = vec![root.to_path_buf()];
        let start = std::time::Instant::now();

        while let Some(dir) = queue.pop() {
            if start.elapsed() >= budget || files.len() >= max_files {
                break;
            }

            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };

            for entry in entries.flatten() {
                if start.elapsed() >= budget || files.len() >= max_files {
                    break;
                }

                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();

                if path.is_dir() {
                    if !crate::fs::is_ignored_directory(&name) {
                        queue.push(path);
                    }
                } else if path.is_file() {
                    if let Ok(rel) = path.strip_prefix(root) {
                        if let Some(fp) = fast_fingerprint_file(&path) {
                            files.insert(rel.to_path_buf(), fp);
                        }
                    }
                }
            }
        }

        Self { files }
    }

    /// Legacy capture compatibility method with bounded budget.
    pub fn capture(root: &Path) -> Self {
        Self::capture_fast(root, 1000, Duration::from_millis(150))
    }
}

/// Summary of project file differences after session completion.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProjectDiff {
    pub added: Vec<PathBuf>,
    pub modified: Vec<PathBuf>,
    pub deleted: Vec<PathBuf>,
    pub permissions_changed: Vec<PathBuf>,
}

impl ProjectDiff {
    pub fn total_changed(&self) -> usize {
        self.added.len() + self.modified.len() + self.deleted.len() + self.permissions_changed.len()
    }

    pub fn is_empty(&self) -> bool {
        self.total_changed() == 0
    }

    pub fn summary(&self) -> String {
        format!(
            "agent modified: {} file(s) ({} added, {} modified, {} deleted, {} permissions changed)",
            self.total_changed(),
            self.added.len(),
            self.modified.len(),
            self.deleted.len(),
            self.permissions_changed.len(),
        )
    }

    /// Convert internal diff summary to structured JSON Value.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "added": self.added,
            "modified": self.modified,
            "deleted": self.deleted,
            "permissions_changed": self.permissions_changed,
            "total_changed": self.total_changed(),
            "summary": self.summary(),
        })
    }

    /// Compute the diff between two in-memory manifests.
    pub fn compute_between(initial: &ProjectManifest, final_manifest: &ProjectManifest) -> Self {
        let mut added = Vec::new();
        let mut modified = Vec::new();
        let mut deleted = Vec::new();
        let mut permissions_changed = Vec::new();

        let initial_keys: BTreeSet<&PathBuf> = initial.files.keys().collect();
        let final_keys: BTreeSet<&PathBuf> = final_manifest.files.keys().collect();

        // Added files
        for key in final_keys.difference(&initial_keys) {
            added.push((*key).clone());
        }

        // Deleted files
        for key in initial_keys.difference(&final_keys) {
            deleted.push((*key).clone());
        }

        // Modified or permissions_changed files
        for key in initial_keys.intersection(&final_keys) {
            let initial_fp = &initial.files[*key];
            let final_fp = &final_manifest.files[*key];
            if initial_fp != final_fp {
                if initial_fp.sha256 == final_fp.sha256
                    && initial_fp.size == final_fp.size
                    && initial_fp.mode != final_fp.mode
                {
                    permissions_changed.push((*key).clone());
                } else {
                    modified.push((*key).clone());
                }
            }
        }

        added.sort();
        modified.sort();
        deleted.sort();
        permissions_changed.sort();

        Self {
            added,
            modified,
            deleted,
            permissions_changed,
        }
    }

    /// Compute the diff between an initial baseline manifest and current state on disk.
    pub fn compute(initial: &ProjectManifest, root: &Path) -> Self {
        let final_manifest = ProjectManifest::capture(root);
        Self::compute_between(initial, &final_manifest)
    }
}

pub fn fast_fingerprint_file(path: &Path) -> Option<FileFingerprint> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return None;
    }

    let size = meta.len();
    let mtime_secs = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);

    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode()
    };
    #[cfg(not(unix))]
    let mode = 0u32;

    #[cfg(unix)]
    let inode = {
        use std::os::unix::fs::MetadataExt;
        meta.ino()
    };
    #[cfg(not(unix))]
    let inode = 0u64;

    Some(FileFingerprint {
        size,
        mtime_secs,
        mode,
        sha256: format!("{size}-{mtime_secs}-{inode}"),
    })
}

/// Detect whether arbitrary byte stream is binary.
pub fn is_binary(bytes: &[u8]) -> bool {
    let probe_len = bytes.len().min(8192);
    if bytes[..probe_len].contains(&0) {
        return true;
    }
    std::str::from_utf8(bytes).is_err()
}

/// A single operation in a Myers diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffOp<'a> {
    Equal(&'a str),
    Delete(&'a str),
    Insert(&'a str),
}

/// Formats unified diff for a single file into ANSI colored and plain text patches.
pub fn format_unified_diff(
    path: &str,
    old_lines: &[&str],
    new_lines: &[&str],
    is_added: bool,
    is_deleted: bool,
) -> (usize, usize, String, String) {
    if is_added {
        let lines_added = new_lines.len();
        let mut color_patch = format!(
            "\x1b[1;37m--- /dev/null\n+++ b/{path}\x1b[0m\n\
             \x1b[36m@@ -0,0 +1,{lines_added} @@\x1b[0m\n"
        );
        let mut plain_patch = format!(
            "--- /dev/null\n+++ b/{path}\n\
             @@ -0,0 +1,{lines_added} @@\n"
        );
        for l in new_lines {
            color_patch.push_str("\x1b[32m+");
            color_patch.push_str(l);
            color_patch.push_str("\x1b[0m\n");
            plain_patch.push('+');
            plain_patch.push_str(l);
            plain_patch.push('\n');
        }
        return (lines_added, 0, color_patch, plain_patch);
    }

    if is_deleted {
        let lines_deleted = old_lines.len();
        let mut color_patch = format!(
            "\x1b[1;37m--- a/{path}\n+++ /dev/null\x1b[0m\n\
             \x1b[36m@@ -1,{lines_deleted} +0,0 @@\x1b[0m\n"
        );
        let mut plain_patch = format!(
            "--- a/{path}\n+++ /dev/null\n\
             @@ -1,{lines_deleted} +0,0 @@\n"
        );
        for l in old_lines {
            color_patch.push_str("\x1b[31m-");
            color_patch.push_str(l);
            color_patch.push_str("\x1b[0m\n");
            plain_patch.push('-');
            plain_patch.push_str(l);
            plain_patch.push('\n');
        }
        return (0, lines_deleted, color_patch, plain_patch);
    }

    let ops = compute_diff_ops(old_lines, new_lines);
    let lines_added = ops
        .iter()
        .filter(|op| matches!(op, DiffOp::Insert(_)))
        .count();
    let lines_deleted = ops
        .iter()
        .filter(|op| matches!(op, DiffOp::Delete(_)))
        .count();

    if lines_added == 0 && lines_deleted == 0 {
        return (0, 0, String::new(), String::new());
    }

    let (color_body, plain_body) = render_hunks(&ops);
    let color_patch = format!("\x1b[1;37m--- a/{path}\n+++ b/{path}\x1b[0m\n{color_body}");
    let plain_patch = format!("--- a/{path}\n+++ b/{path}\n{plain_body}");

    (lines_added, lines_deleted, color_patch, plain_patch)
}

/// Compute diff operations using Myers diff algorithm with common prefix/suffix optimization.
pub fn compute_diff_ops<'a>(old_lines: &[&'a str], new_lines: &[&'a str]) -> Vec<DiffOp<'a>> {
    let n = old_lines.len();
    let m = new_lines.len();

    let mut prefix_len = 0;
    while prefix_len < n && prefix_len < m && old_lines[prefix_len] == new_lines[prefix_len] {
        prefix_len += 1;
    }

    let mut suffix_len = 0;
    while suffix_len < (n - prefix_len)
        && suffix_len < (m - prefix_len)
        && old_lines[n - 1 - suffix_len] == new_lines[m - 1 - suffix_len]
    {
        suffix_len += 1;
    }

    let a = &old_lines[prefix_len..n - suffix_len];
    let b = &new_lines[prefix_len..m - suffix_len];
    let len_a = a.len();
    let len_b = b.len();

    let mut middle_ops = Vec::new();

    if len_a == 0 {
        for &line in b {
            middle_ops.push(DiffOp::Insert(line));
        }
    } else if len_b == 0 {
        for &line in a {
            middle_ops.push(DiffOp::Delete(line));
        }
    } else {
        let max_edits = len_a + len_b;
        let limit_d = max_edits.min(2000);
        let offset = max_edits as isize;
        let mut v = vec![0usize; 2 * max_edits + 1];
        let mut trace = Vec::with_capacity(limit_d + 1);
        let mut solved_d = None;

        for d in 0..=limit_d {
            trace.push(v.clone());
            let mut k = -(d as isize);
            while k <= d as isize {
                let k_idx = (k + offset) as usize;
                let mut x = if k == -(d as isize)
                    || (k != d as isize
                        && v[(k - 1 + offset) as usize] < v[(k + 1 + offset) as usize])
                {
                    v[(k + 1 + offset) as usize]
                } else {
                    v[(k - 1 + offset) as usize] + 1
                };
                let mut y = (x as isize - k) as usize;
                while x < len_a && y < len_b && a[x] == b[y] {
                    x += 1;
                    y += 1;
                }
                v[k_idx] = x;
                if x >= len_a && y >= len_b {
                    solved_d = Some(d);
                    break;
                }
                k += 2;
            }
            if solved_d.is_some() {
                break;
            }
        }

        if let Some(mut d) = solved_d {
            let mut x = len_a;
            let mut y = len_b;
            while d > 0 {
                let k = x as isize - y as isize;
                let prev_v = &trace[d];
                let prev_k = if k == -(d as isize)
                    || (k != d as isize
                        && prev_v[(k - 1 + offset) as usize] < prev_v[(k + 1 + offset) as usize])
                {
                    k + 1
                } else {
                    k - 1
                };
                let prev_x = prev_v[(prev_k + offset) as usize];
                let prev_y = (prev_x as isize - prev_k) as usize;

                while x > prev_x && y > prev_y {
                    middle_ops.push(DiffOp::Equal(a[x - 1]));
                    x -= 1;
                    y -= 1;
                }
                if x == prev_x {
                    middle_ops.push(DiffOp::Insert(b[y - 1]));
                    y -= 1;
                } else {
                    middle_ops.push(DiffOp::Delete(a[x - 1]));
                    x -= 1;
                }
                d -= 1;
            }
            while x > 0 && y > 0 {
                middle_ops.push(DiffOp::Equal(a[x - 1]));
                x -= 1;
                y -= 1;
            }
            middle_ops.reverse();
        } else {
            for &line in a {
                middle_ops.push(DiffOp::Delete(line));
            }
            for &line in b {
                middle_ops.push(DiffOp::Insert(line));
            }
        }
    }

    let mut ops = Vec::with_capacity(n + m);
    for &line in &old_lines[..prefix_len] {
        ops.push(DiffOp::Equal(line));
    }
    ops.extend(middle_ops);
    for &line in &old_lines[n - suffix_len..] {
        ops.push(DiffOp::Equal(line));
    }

    ops
}

/// Renders diff operations into unified diff hunk format (color and plain strings).
pub fn render_hunks(ops: &[DiffOp]) -> (String, String) {
    let mut change_indices = Vec::new();
    for (i, op) in ops.iter().enumerate() {
        if !matches!(op, DiffOp::Equal(_)) {
            change_indices.push(i);
        }
    }

    if change_indices.is_empty() {
        return (String::new(), String::new());
    }

    let mut clusters: Vec<(usize, usize)> = Vec::new();
    let mut cur_start = change_indices[0];
    let mut cur_end = change_indices[0];

    for &idx in &change_indices[1..] {
        if idx <= cur_end + 6 {
            cur_end = idx;
        } else {
            clusters.push((cur_start, cur_end));
            cur_start = idx;
            cur_end = idx;
        }
    }
    clusters.push((cur_start, cur_end));

    let mut color_out = String::new();
    let mut plain_out = String::new();

    for (c_start, c_end) in clusters {
        let h_start = c_start.saturating_sub(3);
        let h_end = (c_end + 4).min(ops.len());

        let old_start = 1 + ops[..h_start]
            .iter()
            .filter(|op| matches!(op, DiffOp::Equal(_) | DiffOp::Delete(_)))
            .count();
        let new_start = 1 + ops[..h_start]
            .iter()
            .filter(|op| matches!(op, DiffOp::Equal(_) | DiffOp::Insert(_)))
            .count();

        let old_count = ops[h_start..h_end]
            .iter()
            .filter(|op| matches!(op, DiffOp::Equal(_) | DiffOp::Delete(_)))
            .count();
        let new_count = ops[h_start..h_end]
            .iter()
            .filter(|op| matches!(op, DiffOp::Equal(_) | DiffOp::Insert(_)))
            .count();

        let _ = writeln!(
            color_out,
            "\x1b[36m@@ -{old_start},{old_count} +{new_start},{new_count} @@\x1b[0m"
        );
        let _ = writeln!(
            plain_out,
            "@@ -{old_start},{old_count} +{new_start},{new_count} @@"
        );

        for op in &ops[h_start..h_end] {
            match op {
                DiffOp::Equal(l) => {
                    color_out.push(' ');
                    color_out.push_str(l);
                    color_out.push('\n');
                    plain_out.push(' ');
                    plain_out.push_str(l);
                    plain_out.push('\n');
                }
                DiffOp::Delete(l) => {
                    color_out.push_str("\x1b[31m-");
                    color_out.push_str(l);
                    color_out.push_str("\x1b[0m\n");
                    plain_out.push('-');
                    plain_out.push_str(l);
                    plain_out.push('\n');
                }
                DiffOp::Insert(l) => {
                    color_out.push_str("\x1b[32m+");
                    color_out.push_str(l);
                    color_out.push_str("\x1b[0m\n");
                    plain_out.push('+');
                    plain_out.push_str(l);
                    plain_out.push('\n');
                }
            }
        }
    }

    (color_out, plain_out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_test_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vetto-diff-{tag}-{}",
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
    fn detects_added_modified_and_deleted_files() {
        let dir = temp_test_dir("diff-test");
        let initial_file = dir.join("initial.txt");
        let deleted_file = dir.join("deleted.txt");
        fs::write(&initial_file, "initial content\n").unwrap();
        fs::write(&deleted_file, "to be deleted\n").unwrap();

        let manifest = ProjectManifest::capture(&dir);
        assert_eq!(manifest.files.len(), 2);

        // Perform modifications
        fs::write(&initial_file, "modified content\n").unwrap();
        fs::remove_file(&deleted_file).unwrap();
        fs::write(dir.join("added.txt"), "new file\n").unwrap();

        let diff = ProjectDiff::compute(&manifest, &dir);
        assert_eq!(diff.added, vec![PathBuf::from("added.txt")]);
        assert_eq!(diff.modified, vec![PathBuf::from("initial.txt")]);
        assert_eq!(diff.deleted, vec![PathBuf::from("deleted.txt")]);
        assert_eq!(diff.total_changed(), 3);
        assert!(diff.summary().contains("3 file(s)"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn capture_fast_respects_max_files() {
        let dir = temp_test_dir("max-files-test");
        for i in 0..10 {
            fs::write(dir.join(format!("file_{i}.txt")), format!("data {i}\n")).unwrap();
        }

        let manifest = ProjectManifest::capture_fast(&dir, 4, Duration::from_secs(5));
        assert_eq!(manifest.files.len(), 4);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fast_fingerprint_file_format_and_properties() {
        let dir = temp_test_dir("fp-test");
        let file = dir.join("test.txt");
        fs::write(&file, "hello world\n").unwrap();

        let fp = fast_fingerprint_file(&file).expect("fingerprint should succeed");
        assert_eq!(fp.size, 12);
        assert!(fp.sha256.starts_with("12-"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(unix)]
    fn fast_fingerprint_file_rejects_symlinks() {
        let dir = temp_test_dir("symlink-test");
        let file = dir.join("target.txt");
        let link = dir.join("link.txt");
        fs::write(&file, "target\n").unwrap();
        std::os::unix::fs::symlink(&file, &link).unwrap();

        assert!(fast_fingerprint_file(&link).is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn detects_permissions_changed_in_manifest() {
        let initial_fp = FileFingerprint {
            size: 42,
            mtime_secs: 1000,
            mode: 0o644,
            sha256: "42-1000-12345".to_string(),
        };
        let final_fp = FileFingerprint {
            size: 42,
            mtime_secs: 1000,
            mode: 0o755,
            sha256: "42-1000-12345".to_string(),
        };

        let mut initial_files = BTreeMap::new();
        initial_files.insert(PathBuf::from("script.sh"), initial_fp);
        let initial = ProjectManifest { files: initial_files };

        let mut final_files = BTreeMap::new();
        final_files.insert(PathBuf::from("script.sh"), final_fp);
        let final_manifest = ProjectManifest { files: final_files };

        let diff = ProjectDiff::compute_between(&initial, &final_manifest);
        assert_eq!(diff.permissions_changed, vec![PathBuf::from("script.sh")]);
        assert!(diff.added.is_empty());
        assert!(diff.modified.is_empty());
        assert!(diff.deleted.is_empty());
        assert_eq!(diff.total_changed(), 1);
        assert!(diff.summary().contains("1 permissions changed"));
    }

    #[test]
    #[cfg(unix)]
    fn detects_permissions_changed_on_disk() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_test_dir("perm-test");
        let script = dir.join("run.sh");
        fs::write(&script, "#!/bin/sh\necho ok\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o644)).unwrap();

        let initial = ProjectManifest::capture(&dir);
        assert_eq!(initial.files.len(), 1);
        assert_eq!(initial.files[&PathBuf::from("run.sh")].mode & 0o777, 0o644);

        // Change permissions only
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

        let diff = ProjectDiff::compute(&initial, &dir);
        assert_eq!(diff.permissions_changed, vec![PathBuf::from("run.sh")]);
        assert!(diff.modified.is_empty());
        assert!(diff.added.is_empty());
        assert!(diff.deleted.is_empty());
        assert_eq!(diff.total_changed(), 1);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_project_diff_json_export() {
        let diff = ProjectDiff {
            added: vec![PathBuf::from("new.rs")],
            modified: vec![PathBuf::from("main.rs")],
            deleted: vec![PathBuf::from("old.rs")],
            permissions_changed: vec![PathBuf::from("run.sh")],
        };

        let json = diff.to_json();
        assert_eq!(json["total_changed"], 4);
        assert_eq!(json["added"].as_array().unwrap().len(), 1);
        assert_eq!(json["added"][0], "new.rs");
        assert_eq!(json["modified"][0], "main.rs");
        assert_eq!(json["deleted"][0], "old.rs");
        assert_eq!(json["permissions_changed"][0], "run.sh");
        assert!(json["summary"].as_str().unwrap().contains("4 file(s)"));

        // Roundtrip serialization
        let serialized = serde_json::to_string(&diff).unwrap();
        let deserialized: ProjectDiff = serde_json::from_str(&serialized).unwrap();
        assert_eq!(diff, deserialized);
    }

    #[test]
    fn test_myers_diff_ops_and_hunks() {
        let old = vec!["line 1", "line 2", "line 3"];
        let new = vec!["line 1", "line 2 modified", "line 3", "line 4"];

        let ops = compute_diff_ops(&old, &new);
        assert!(ops.contains(&DiffOp::Equal("line 1")));
        assert!(ops.contains(&DiffOp::Delete("line 2")));
        assert!(ops.contains(&DiffOp::Insert("line 2 modified")));
        assert!(ops.contains(&DiffOp::Insert("line 4")));

        let (color_hunk, plain_hunk) = render_hunks(&ops);
        assert!(plain_hunk.contains("@@ -1,3 +1,4 @@"));
        assert!(plain_hunk.contains("-line 2"));
        assert!(plain_hunk.contains("+line 2 modified"));
        assert!(plain_hunk.contains("+line 4"));
        assert!(color_hunk.contains("\x1b[31m-line 2\x1b[0m"));
        assert!(color_hunk.contains("\x1b[32m+line 2 modified\x1b[0m"));
    }

    #[test]
    fn test_format_unified_diff_added_and_deleted() {
        let added_lines = vec!["alpha", "beta"];
        let (add_count, del_count, color_patch, plain_patch) =
            format_unified_diff("foo.txt", &[], &added_lines, true, false);
        assert_eq!(add_count, 2);
        assert_eq!(del_count, 0);
        assert!(plain_patch.contains("--- /dev/null\n+++ b/foo.txt"));
        assert!(plain_patch.contains("@@ -0,0 +1,2 @@"));
        assert!(plain_patch.contains("+alpha\n+beta\n"));
        assert!(color_patch.contains("\x1b[32m+alpha\x1b[0m"));

        let deleted_lines = vec!["gamma"];
        let (add_count, del_count, color_patch, plain_patch) =
            format_unified_diff("bar.txt", &deleted_lines, &[], false, true);
        assert_eq!(add_count, 0);
        assert_eq!(del_count, 1);
        assert!(plain_patch.contains("--- a/bar.txt\n+++ /dev/null"));
        assert!(plain_patch.contains("@@ -1,1 +0,0 @@"));
        assert!(plain_patch.contains("-gamma\n"));
        assert!(color_patch.contains("\x1b[31m-gamma\x1b[0m"));
    }

    #[test]
    fn test_format_unified_diff_modified_and_identical() {
        let old = vec!["same 1", "old text", "same 2"];
        let new = vec!["same 1", "new text", "same 2"];
        let (add_count, del_count, _, plain_patch) =
            format_unified_diff("mod.txt", &old, &new, false, false);
        assert_eq!(add_count, 1);
        assert_eq!(del_count, 1);
        assert!(plain_patch.contains("--- a/mod.txt\n+++ b/mod.txt"));
        assert!(plain_patch.contains("-old text"));
        assert!(plain_patch.contains("+new text"));

        // Identical
        let (add_count, del_count, color_patch, plain_patch) =
            format_unified_diff("same.txt", &old, &old, false, false);
        assert_eq!(add_count, 0);
        assert_eq!(del_count, 0);
        assert!(color_patch.is_empty());
        assert!(plain_patch.is_empty());
    }

    #[test]
    fn test_is_binary_detection() {
        assert!(!is_binary(b"hello world\nthis is plain text\n"));
        assert!(is_binary(b"hello \x00 world"));
        assert!(is_binary(&[0xff, 0xfe, 0xfd]));
    }
}
