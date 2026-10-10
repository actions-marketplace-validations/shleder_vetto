//! Tier downgrade matrix tests and fail-closed guarantee verification.

use crate::common::*;
use vetto::policy::Tier;
use vetto::sandbox::linux::{pick_tier, Probe};

#[test]
fn test_pick_tier_matrix_downgrade_guarantee() {
    // 1. Full capabilities -> Tier::Full
    let probe_full = Probe {
        kernel: "6.1.0".into(),
        landlock_abi: Some(3),
        userns_available: true,
        full_tier_available: true,
        seccomp_filter_available: true,
        seccomp_notify_available: true,
        audit_feed_readable: true,
        cgroup_controllers: vec!["cpu".into(), "memory".into(), "pids".into()],
    };
    assert_eq!(pick_tier(&probe_full).unwrap(), Tier::Full);

    // 2. No userns / mount stack -> degrades to Tier::FsOnly
    let probe_fs_only = Probe {
        kernel: "6.1.0".into(),
        landlock_abi: Some(3),
        userns_available: false,
        full_tier_available: false,
        seccomp_filter_available: true,
        seccomp_notify_available: true,
        audit_feed_readable: true,
        cgroup_controllers: vec!["cpu".into(), "memory".into(), "pids".into()],
    };
    assert_eq!(pick_tier(&probe_fs_only).unwrap(), Tier::FsOnly);

    // 3. No landlock -> degrades to Tier::Seccomp is forbidden; must fail closed (INV-01)
    let probe_seccomp = Probe {
        kernel: "5.10.0".into(),
        landlock_abi: None,
        userns_available: false,
        full_tier_available: false,
        seccomp_filter_available: true,
        seccomp_notify_available: false,
        audit_feed_readable: false,
        cgroup_controllers: vec![],
    };
    assert!(pick_tier(&probe_seccomp).is_err());

    // 4. No landlock and no seccomp -> FAIL-CLOSED
    let probe_none = Probe {
        kernel: "4.19.0".into(),
        landlock_abi: None,
        userns_available: false,
        full_tier_available: false,
        seccomp_filter_available: false,
        seccomp_notify_available: false,
        audit_feed_readable: false,
        cgroup_controllers: vec![],
    };
    assert!(pick_tier(&probe_none).is_err());
}

#[test]
fn test_force_tier_seccomp_micro_mode() {
    let proj = TempProject::new("downgrade_seccomp");
    let out = run_vetto_env_in(proj.path(), &["doctor"], &[("VETTO_FORCE_TIER", "seccomp")]);
    let text = stdout(&out);
    assert!(
        text.lines()
            .any(|l| l.contains("chosen tier:") && l.contains("seccomp")),
        "force seccomp must report chosen tier seccomp: {text}"
    );
}

#[test]
fn test_seccomp_tier_executes_simple_command() {
    let proj = TempProject::new("seccomp_exec");
    let out = run_vetto_env_in(
        proj.path(),
        &["--tui=none", "--ci", "--", "sh", "-c", "echo seccomp_alive"],
        &[("VETTO_FORCE_TIER", "seccomp")],
    );
    let text = stdout(&out);
    assert!(
        text.contains("seccomp_alive"),
        "seccomp micro tier execution failed: {text}"
    );
}

#[test]
fn test_landlock_abi_under_4_with_net_rules_fails_closed_contract() {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
        use vetto::error::VettoError;
        use vetto::sandbox::linux::landlock::{apply_net_port_rules, apply_policy_advanced};

        let f = std::fs::File::open("/dev/null").expect("open /dev/null");
        // SAFETY: valid opened file descriptor
        let fake_ruleset = unsafe { OwnedFd::from_raw_fd(f.into_raw_fd()) };

        // Test ABI 1, 2, 3 (< 4) with strict_net = true
        for abi in [1, 2, 3] {
            let res = apply_net_port_rules(&fake_ruleset, abi, &[80], &[443], true);
            assert!(
                res.is_err(),
                "strict_net on ABI {abi} (< 4) must fail closed"
            );
            let err = res.unwrap_err();
            assert!(matches!(err, VettoError::Landlock(_)));
            assert_eq!(err.exit_code(), 125, "must exit 125 (INV-01)");
            assert!(
                err.to_string().contains("fail-closed (INV-01)"),
                "error message must cite INV-01: {err}"
            );
        }

        // When strict_net is false on ABI < 4, graceful downgrade is permitted
        assert!(apply_net_port_rules(&fake_ruleset, 3, &[80], &[443], false).is_ok());

        // Also verify live apply_policy_advanced fail-closed behavior if running on ABI < 4 kernel
        if let Some(abi) = vetto::sandbox::linux::landlock::abi_version() {
            if abi < 4 {
                let res = apply_policy_advanced(&[], &[], false, &[], &[], true);
                assert!(
                    res.is_err(),
                    "apply_policy_advanced on ABI < 4 with strict_net must fail closed"
                );
                let err = res.unwrap_err();
                assert_eq!(err.exit_code(), 125);
                assert!(err.to_string().contains("fail-closed (INV-01)"));
            }
        }
    }
}
