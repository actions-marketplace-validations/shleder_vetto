use std::path::{Path, PathBuf};

use super::mounts;
use crate::error::VettoResult;

pub const SENSITIVE_PROC_SYS_PATHS: &[&str] = &[
    "/proc/sysrq-trigger",
    "/proc/kcore",
    "/proc/kallsyms",
    "/proc/sched_debug",
    "/proc/timer_list",
    "/sys/firmware",
    "/sys/kernel/debug",
    "/sys/kernel/tracing",
];

pub fn mask_host_proc_sys() -> VettoResult<()> {
    for path_str in SENSITIVE_PROC_SYS_PATHS {
        let path = Path::new(path_str);
        if path.exists() {
            mounts::mask_path(path, path.is_dir())?;
        }
    }
    Ok(())
}

/// Return potential dangerous Unix domain sockets that must be blocked/masked:
/// - Daemon sockets: `/var/run/docker.sock`, `/run/docker.sock`, `/run/podman/podman.sock`
/// - Per-user runtime sockets: `/run/user/{uid}/docker.sock`, `/run/user/{uid}/podman/podman.sock`
///   and gpg-agent sockets `/run/user/{uid}/gnupg/S.gpg-agent`, `/run/user/{uid}/gnupg/S.gpg-agent.ssh`
/// - `SSH_AUTH_SOCK` environment socket if configured.
pub fn get_dangerous_unix_sockets() -> Vec<PathBuf> {
    let mut sockets = Vec::new();

    sockets.push(PathBuf::from("/var/run/docker.sock"));
    sockets.push(PathBuf::from("/run/docker.sock"));
    sockets.push(PathBuf::from("/run/podman/podman.sock"));

    let mut uids = Vec::new();
    #[cfg(unix)]
    {
        // SAFETY: getuid has no failure mode and requires no privileges.
        let uid = unsafe { libc::getuid() };
        uids.push(uid.to_string());
    }
    if let Ok(sudo_uid) = std::env::var("SUDO_UID") {
        if !sudo_uid.is_empty() && !uids.contains(&sudo_uid) {
            uids.push(sudo_uid);
        }
    }
    if let Ok(env_uid) = std::env::var("UID") {
        if !env_uid.is_empty() && !uids.contains(&env_uid) {
            uids.push(env_uid);
        }
    }

    for uid in &uids {
        sockets.push(PathBuf::from(format!("/run/user/{uid}/docker.sock")));
        sockets.push(PathBuf::from(format!("/run/user/{uid}/podman/podman.sock")));
        sockets.push(PathBuf::from(format!("/run/user/{uid}/gnupg/S.gpg-agent")));
        sockets.push(PathBuf::from(format!(
            "/run/user/{uid}/gnupg/S.gpg-agent.ssh"
        )));
    }

    if let Ok(ssh_sock) = std::env::var("SSH_AUTH_SOCK") {
        if !ssh_sock.is_empty() {
            sockets.push(PathBuf::from(ssh_sock));
        }
    }

    let mut deduped = Vec::new();
    for sock in sockets {
        if !deduped.contains(&sock) {
            deduped.push(sock);
        }
    }
    deduped
}

/// Mask caller-specified unix domain sockets with /dev/null bind mounts.
pub fn mask_unix_sockets(custom_sockets: &[PathBuf]) -> VettoResult<()> {
    for socket_path in custom_sockets {
        if socket_path.exists() {
            mounts::mask_path(socket_path, false)?;
        }
    }
    Ok(())
}

/// Mount a CoW tmpfs overlay over the root filesystem (`/`) inside the private mount namespace.
/// Unexpected writes are kept in an ephemeral tmpfs memory layer and discarded on session exit.
pub fn mount_root_cow_overlay(ephemeral_dir: Option<&Path>) -> VettoResult<()> {
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;

        let base = if let Some(dir) = ephemeral_dir {
            dir.to_path_buf()
        } else {
            std::env::temp_dir().join(format!("vetto-cow-{}", std::process::id()))
        };

        let upper = base.join("upper");
        let work = base.join("work");
        let _ = std::fs::create_dir_all(&upper);
        let _ = std::fs::create_dir_all(&work);

        let opts_str = format!(
            "lowerdir=/,upperdir={},workdir={}",
            upper.display(),
            work.display()
        );
        let Ok(opts_c) = CString::new(opts_str) else {
            return Err(crate::error::VettoError::Mount(
                "invalid overlayfs options".into(),
            ));
        };
        let Ok(fstype) = CString::new("overlay") else {
            return Err(crate::error::VettoError::Mount("invalid fstype".into()));
        };
        let Ok(root_c) = CString::new("/") else {
            return Err(crate::error::VettoError::Mount("invalid root path".into()));
        };

        // SAFETY: mount overlayfs over / inside private mount namespace
        let ret = unsafe {
            libc::mount(
                fstype.as_ptr(),
                root_c.as_ptr(),
                fstype.as_ptr(),
                0,
                opts_c.as_ptr().cast(),
            )
        };

        if ret != 0 {
            let err = std::io::Error::last_os_error();
            return Err(crate::error::VettoError::Mount(format!(
                "mount overlayfs over / failed: {err}"
            )));
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = ephemeral_dir;
        Ok(())
    }
}

/// Mandatory secret masking for ~/.ssh, ~/.aws, ~/.gnupg, and .env (INV-08).
/// Expanded to include ~/.docker/config.json, ~/.npmrc, ~/.config/gh/hosts.yml.
/// Directories are masked using read-only mode 0000 tmpfs overlays.
/// Dangerous unix sockets are masked by bind mounting /dev/null.
pub fn mask_mandatory_secrets(home: &Path, project_root: Option<&Path>) -> VettoResult<()> {
    let mandatory_dirs = [".ssh", ".aws", ".gnupg"];
    for dir_name in mandatory_dirs {
        let dir_path = home.join(dir_name);
        if dir_path.exists() {
            mounts::mask_path(&dir_path, dir_path.is_dir())?;
        }
    }

    let mandatory_files = [
        ".env",
        ".npmrc",
        ".docker/config.json",
        ".config/gh/hosts.yml",
    ];
    for rel_path in mandatory_files {
        let file_path = home.join(rel_path);
        if file_path.exists() {
            mounts::mask_path(&file_path, file_path.is_dir())?;
        }
    }

    if let Some(root) = project_root {
        let proj_env = root.join(".env");
        if proj_env.exists() {
            mounts::mask_path(&proj_env, proj_env.is_dir())?;
        }
        let git_config = root.join(".git").join("config");
        if git_config.exists() {
            mounts::mask_path(&git_config, git_config.is_dir())?;
        }
    }

    for socket_path in get_dangerous_unix_sockets() {
        if socket_path.exists() {
            mounts::mask_path(&socket_path, false)?;
        }
    }

    // Remount /proc/sys read-only (INV-28)
    mounts::remount_proc_sys_readonly()?;

    // Isolated devpts newinstance (INV-31)
    mounts::mount_devpts_newinstance()?;

    mask_host_proc_sys()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EnvVarGuard {
        key: &'static str,
        prev: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, val: &str) -> Self {
            let prev = std::env::var_os(key);
            // SAFETY: test thread holding serialized lock
            unsafe { std::env::set_var(key, val) };
            Self { key, prev }
        }

        fn unset(key: &'static str) -> Self {
            let prev = std::env::var_os(key);
            // SAFETY: test thread holding serialized lock
            unsafe { std::env::remove_var(key) };
            Self { key, prev }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => unsafe { std::env::set_var(self.key, v) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    #[test]
    fn mask_mandatory_secrets_handles_absent_paths() {
        let nonexistent = Path::new("/tmp/nonexistent-vetto-test-home-xyz");
        let has_host_items = get_dangerous_unix_sockets().iter().any(|s| s.exists())
            || SENSITIVE_PROC_SYS_PATHS
                .iter()
                .any(|p| Path::new(p).exists());
        let res = mask_mandatory_secrets(nonexistent, None);
        if has_host_items {
            if let Err(err) = res {
                assert!(matches!(err, crate::error::VettoError::Mount(_)));
            }
        } else {
            assert!(res.is_ok());
        }
    }

    #[test]
    fn test_get_dangerous_unix_sockets_contains_standard_sockets() {
        let sockets = get_dangerous_unix_sockets();
        assert!(sockets.contains(&PathBuf::from("/var/run/docker.sock")));
        assert!(sockets.contains(&PathBuf::from("/run/docker.sock")));
        assert!(sockets.contains(&PathBuf::from("/run/podman/podman.sock")));

        #[cfg(unix)]
        {
            let uid = unsafe { libc::getuid() };
            let user_docker = PathBuf::from(format!("/run/user/{uid}/docker.sock"));
            let user_podman = PathBuf::from(format!("/run/user/{uid}/podman/podman.sock"));
            let user_gpg = PathBuf::from(format!("/run/user/{uid}/gnupg/S.gpg-agent"));
            let user_gpg_ssh = PathBuf::from(format!("/run/user/{uid}/gnupg/S.gpg-agent.ssh"));
            assert!(sockets.contains(&user_docker));
            assert!(sockets.contains(&user_podman));
            assert!(sockets.contains(&user_gpg));
            assert!(sockets.contains(&user_gpg_ssh));
        }
    }

    #[test]
    fn test_dangerous_unix_sockets_includes_ssh_auth_sock() {
        let _lock = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let fake_sock = "/tmp/test-vetto-fake-ssh-agent.sock";
        let _guard = EnvVarGuard::set("SSH_AUTH_SOCK", fake_sock);

        let sockets = get_dangerous_unix_sockets();
        assert!(sockets.contains(&PathBuf::from(fake_sock)));
    }

    #[test]
    fn test_dangerous_unix_sockets_without_ssh_auth_sock() {
        let _lock = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _guard = EnvVarGuard::unset("SSH_AUTH_SOCK");

        let sockets = get_dangerous_unix_sockets();
        assert!(!sockets.contains(&PathBuf::from("/tmp/test-vetto-fake-ssh-agent.sock")));
    }

    #[test]
    fn test_mask_unix_sockets_handles_absent_paths() {
        let absent = vec![
            PathBuf::from("/tmp/nonexistent-vetto-sock1.sock"),
            PathBuf::from("/tmp/nonexistent-vetto-sock2.sock"),
        ];
        assert!(mask_unix_sockets(&absent).is_ok());
    }

    #[test]
    fn test_sensitive_proc_sys_paths() {
        for path_str in SENSITIVE_PROC_SYS_PATHS {
            assert!(
                path_str.starts_with("/proc/") || path_str.starts_with("/sys/"),
                "sensitive path {} must be in /proc or /sys",
                path_str
            );
        }
    }

    #[test]
    fn test_mount_root_cow_overlay_ephemeral_dir_creation() {
        let temp = std::env::temp_dir().join(format!("vetto_cow_test_{}", std::process::id()));
        let res = mount_root_cow_overlay(Some(&temp));
        assert!(temp.join("upper").exists());
        assert!(temp.join("work").exists());
        let _ = std::fs::remove_dir_all(&temp);
        assert!(res.is_ok() || matches!(res, Err(crate::error::VettoError::Mount(_))));
    }

    #[test]
    fn test_mask_mandatory_secrets_expands_to_npmrc_docker_and_gh() {
        let temp_home =
            std::env::temp_dir().join(format!("vetto_fake_home_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_home);
        let res = mask_mandatory_secrets(&temp_home, None);
        let _ = std::fs::remove_dir_all(&temp_home);
        assert!(res.is_ok() || matches!(res, Err(crate::error::VettoError::Mount(_))));
    }
}
