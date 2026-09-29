//! Post-load sanity checks producing warnings (never hard failures unless
//! something makes enforcement impossible).

use std::path::PathBuf;

use super::types::Policy;

pub const SYSTEM_WRITE_ROOTS: [&str; 12] = [
    "/",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/etc",
    "/boot",
    "C:\\",
    "C:\\Windows",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
];

pub fn check(policy: &mut Policy) -> anyhow::Result<()> {
    // Writing to system locations is almost always a misconfiguration.
    let home = home_dir();
    for w in &policy.allow_write {
        let canonical = std::fs::canonicalize(w).unwrap_or_else(|_| w.clone());
        let can_str = canonical.to_string_lossy();
        if SYSTEM_WRITE_ROOTS.contains(&can_str.as_ref()) {
            anyhow::bail!(
                "fail-closed: allow_write includes dangerous system path '{}' (exit 125)",
                w.display()
            );
        }
        if let Some(h) = &home {
            let is_yolo = policy.metadata.name.contains("yolo");
            if &canonical == h && !is_yolo {
                policy.warnings.push(format!(
                    "allow_write includes $HOME '{}' — user files and configuration are mutable",
                    w.display()
                ));
            }
        }
    }

    // Reading $HOME wholesale exposes every secret by definition.
    if let Some(home) = home_dir() {
        if policy
            .allow_read
            .iter()
            .any(|p| std::fs::canonicalize(p).map(|c| c == home).unwrap_or(false))
        {
            policy.warnings.push(
                "allow_read includes $HOME itself — all user secrets are readable \
                 regardless of display_only_deny"
                    .to_string(),
            );
        }
    }

    // Non-existent write roots make enforcement impossible -> drop loudly.
    // If an ancestor path is already present in allow_write (and exists),
    // the non-existent child is already covered by the ancestor rule, so
    // it is pruned cleanly without emitting a redundant warning.
    let existing_write_roots: Vec<PathBuf> = policy
        .allow_write
        .iter()
        .filter(|p| p.exists())
        .cloned()
        .collect();

    policy.allow_write.retain(|p| {
        let exists = p.exists();
        if !exists {
            let covered_by_ancestor = existing_write_roots.iter().any(|root| {
                if let (Ok(p_canon), Ok(r_canon)) = (p.canonicalize(), root.canonicalize()) {
                    p_canon.starts_with(r_canon)
                } else {
                    p.starts_with(root)
                }
            });
            if !covered_by_ancestor {
                policy.warnings.push(format!(
                    "allow_write path '{}' does not exist; dropped",
                    p.display()
                ));
            }
        }
        exists
    });

    Ok(())
}

fn home_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_existent_child_of_allowed_root_drops_silently_without_warning() {
        let temp = std::env::temp_dir().join(format!("vetto-chk-child-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp);
        let parent = temp.clone();
        let child = parent.join("non_existent_subdir/plugins");

        let mut policy = Policy {
            allow_write: vec![parent.clone(), child.clone()],
            ..Default::default()
        };

        let res = check(&mut policy);
        let _ = std::fs::remove_dir_all(&temp);
        res.expect("check succeeds");

        assert_eq!(policy.allow_write, vec![parent]);
        assert!(
            policy.warnings.is_empty(),
            "non-existent child of existing allowed root must not trigger warning: {:?}",
            policy.warnings
        );
    }

    #[test]
    fn test_non_existent_independent_path_drops_with_warning() {
        let temp = std::env::temp_dir().join(format!("vetto-chk-indep-{}", std::process::id()));
        let non_existent = temp.join("completely_missing_independent_path");

        let mut policy = Policy {
            allow_write: vec![non_existent.clone()],
            ..Default::default()
        };

        check(&mut policy).expect("check succeeds");

        assert!(policy.allow_write.is_empty());
        assert_eq!(policy.warnings.len(), 1);
        assert!(policy.warnings[0].contains("does not exist; dropped"));
    }
}
