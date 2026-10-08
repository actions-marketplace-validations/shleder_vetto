//! Git repository introspection utilities.

use std::path::Path;

/// Detect active git branch from `.git/HEAD`.
pub fn detect_git_branch(project: &Path) -> Option<String> {
    let head_path = project.join(".git/HEAD");
    let metadata = std::fs::symlink_metadata(&head_path).ok()?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return None;
    }
    let head = std::fs::read_to_string(head_path).ok()?;
    let reference = head.trim().strip_prefix("ref: refs/heads/")?;
    if reference.is_empty() || reference.contains('\0') || reference.contains("..") {
        return None;
    }
    Some(reference.to_string())
}

/// Detect active git tag from `.git` refs or HEAD.
pub fn detect_git_tag(project: &Path) -> Option<String> {
    let head_path = project.join(".git/HEAD");
    let head_content = std::fs::read_to_string(&head_path).ok()?.trim().to_string();

    let tag_ref_prefix = "ref: refs/tags/";
    if let Some(tag) = head_content.strip_prefix(tag_ref_prefix) {
        return Some(tag.to_string());
    }

    let head_sha = if head_content.starts_with("ref: ") {
        let ref_rel = head_content.strip_prefix("ref: ")?.trim();
        let ref_path = project.join(".git").join(ref_rel);
        std::fs::read_to_string(ref_path).ok()?.trim().to_string()
    } else {
        head_content
    };

    let tags_dir = project.join(".git/refs/tags");
    if let Ok(entries) = std::fs::read_dir(tags_dir) {
        for entry in entries.flatten() {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                if content.trim() == head_sha {
                    return Some(entry.file_name().to_string_lossy().to_string());
                }
            }
        }
    }

    let packed_refs = project.join(".git/packed-refs");
    if let Ok(content) = std::fs::read_to_string(packed_refs) {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            if let (Some(sha), Some(ref_name)) = (parts.next(), parts.next()) {
                if sha == head_sha {
                    if let Some(tag_name) = ref_name.strip_prefix("refs/tags/") {
                        return Some(tag_name.to_string());
                    }
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_git_branch_valid_and_nonexistent() {
        let temp_dir = std::env::temp_dir().join(format!("vetto-git-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(temp_dir.join(".git")).unwrap();

        std::fs::write(temp_dir.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        assert_eq!(detect_git_branch(&temp_dir), Some("main".to_string()));

        let _ = std::fs::remove_dir_all(&temp_dir);
        assert_eq!(detect_git_branch(&temp_dir), None);
    }
}
