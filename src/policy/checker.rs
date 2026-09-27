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
    policy.allow_write.retain(|p| {
        let exists = p.exists();
        if !exists {
            policy.warnings.push(format!(
                "allow_write path '{}' does not exist; dropped",
                p.display()
            ));
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
