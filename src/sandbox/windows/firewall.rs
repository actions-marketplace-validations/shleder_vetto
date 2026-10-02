//! Opt-in Windows Filtering Platform capability probe and configuration types.
//!
//! This module probes Windows Filtering Platform (WFP) availability and elevated
//! token capabilities without requesting elevation or mutating host firewall state.

use std::ffi::c_void;
use std::mem::size_of;
#[cfg(test)]
use std::net::Ipv6Addr;
use std::net::{IpAddr, Ipv4Addr};
use std::ptr::{null, null_mut};

use anyhow::{bail, Result};

type Handle = *mut c_void;
type Dword = u32;
type Bool = i32;

const ERROR_SUCCESS: Dword = 0;
const RPC_C_AUTHN_DEFAULT: Dword = 0xffff_ffff;
const TOKEN_QUERY: Dword = 0x0008;
const TOKEN_ELEVATION: Dword = 20;
const SECURITY_MAX_SID_SIZE: Dword = 68;
const WIN_BUILTIN_ADMINISTRATORS_SID: Dword = 26;

#[repr(C)]
struct TokenElevation {
    token_is_elevated: Dword,
}

#[link(name = "fwpuclnt")]
extern "system" {
    fn FwpmEngineOpen0(
        server_name: *const u16,
        authn_service: Dword,
        auth_identity: *const c_void,
        session: *const c_void,
        engine_handle: *mut Handle,
    ) -> Dword;
    fn FwpmEngineClose0(engine_handle: Handle) -> Dword;
}

#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(process: Handle, desired_access: Dword, token: *mut Handle) -> Bool;
    fn GetTokenInformation(
        token: Handle,
        information_class: Dword,
        information: *mut c_void,
        information_length: Dword,
        return_length: *mut Dword,
    ) -> Bool;
    fn CreateWellKnownSid(
        sid_type: Dword,
        domain_sid: *const c_void,
        sid: *mut c_void,
        sid_size: *mut Dword,
    ) -> Bool;
    fn CheckTokenMembership(
        token: Handle,
        sid_to_check: *const c_void,
        is_member: *mut Bool,
    ) -> Bool;
}

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn CloseHandle(handle: Handle) -> Bool;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkMode {
    Off,
    Allowlist,
    Strict,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedEndpoint {
    pub addr: IpAddr,
    pub port: u16,
}

impl PinnedEndpoint {
    pub fn new(addr: IpAddr, port: u16) -> Result<Self> {
        if port == 0 || is_non_routable(addr) {
            bail!("WFP endpoint is unspecified, multicast, or otherwise invalid: {addr}:{port}");
        }
        Ok(Self { addr, port })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedPolicy {
    pub mode: NetworkMode,
    pub endpoints: Vec<PinnedEndpoint>,
    /// Optional loopback endpoint for a broker.
    pub broker_loopback: Option<PinnedEndpoint>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirewallCapabilities {
    pub api_available: bool,
    pub engine_readable: bool,
    pub elevated_admin_token: bool,
    pub can_attempt_write: bool,
    pub process_id_scope: bool,
    pub note: String,
}

/// Probe WFP and token state without adding a filter or requesting elevation.
pub fn capabilities() -> FirewallCapabilities {
    let mut result = FirewallCapabilities {
        api_available: true,
        engine_readable: false,
        elevated_admin_token: false,
        can_attempt_write: false,
        process_id_scope: false,
        note: "WFP ALE exposes executable-image scope, not a reliable process-ID condition; use broker or explicit image scope".to_string(),
    };
    let mut engine = null_mut();
    let status =
        unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_DEFAULT, null(), null(), &mut engine) };
    if status == ERROR_SUCCESS && !engine.is_null() {
        result.engine_readable = true;
        unsafe {
            let _ = FwpmEngineClose0(engine);
        }
    } else {
        result.note =
            format!("WFP engine probe failed with status 0x{status:08x}; no policy was attempted");
    }
    result.elevated_admin_token = elevated_admin_token();
    result.can_attempt_write = result.engine_readable && result.elevated_admin_token;
    result
}

fn elevated_admin_token() -> bool {
    unsafe {
        let process = GetCurrentProcess();
        let mut token = null_mut();
        if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 || token.is_null() {
            return false;
        }
        let mut elevation = TokenElevation {
            token_is_elevated: 0,
        };
        let mut returned = 0;
        let elevated = GetTokenInformation(
            token,
            TOKEN_ELEVATION,
            (&mut elevation as *mut TokenElevation).cast(),
            size_of::<TokenElevation>() as Dword,
            &mut returned,
        ) != 0
            && elevation.token_is_elevated != 0;
        let mut sid_storage = [0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut sid_size = SECURITY_MAX_SID_SIZE;
        let sid_ok = CreateWellKnownSid(
            WIN_BUILTIN_ADMINISTRATORS_SID,
            null(),
            sid_storage.as_mut_ptr().cast(),
            &mut sid_size,
        ) != 0;
        let mut member: Bool = 0;
        let member_ok = sid_ok
            && CheckTokenMembership(token, sid_storage.as_ptr().cast(), &mut member) != 0
            && member != 0;
        let _ = CloseHandle(token);
        elevated && member_ok
    }
}

fn is_non_routable(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(value) => {
            let octets = value.octets();
            value.is_unspecified()
                || value.is_loopback()
                || value.is_private()
                || value.is_multicast()
                || value.is_broadcast()
                || value.is_link_local()
                || octets[0] == 0
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 169 && octets[1] == 254)
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
                || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
                || (octets[0] == 169 && octets[1] == 254 && octets[2] == 169 && octets[3] == 254)
        }
        IpAddr::V6(value) => {
            let segments = value.segments();
            let mapped_or_compatible_v4 = segments[0] == 0
                && segments[1] == 0
                && segments[2] == 0
                && segments[3] == 0
                && segments[4] == 0
                && (segments[5] == 0xffff || segments[5] == 0);
            let mapped_v4 = if mapped_or_compatible_v4 {
                Some(Ipv4Addr::new(
                    (segments[6] >> 8) as u8,
                    segments[6] as u8,
                    (segments[7] >> 8) as u8,
                    segments[7] as u8,
                ))
            } else {
                None
            };
            value.is_unspecified()
                || value.is_loopback()
                || value.is_multicast()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || (segments[0] == 0x0064 && segments[1] == 0xff9b)
                || mapped_v4.is_some_and(|address| is_non_routable(IpAddr::V4(address)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_reject_non_routable_addresses() {
        assert!(PinnedEndpoint::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 443).is_err());
        assert!(PinnedEndpoint::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443).is_err());
        assert!(PinnedEndpoint::new(IpAddr::V6("::ffff:10.0.0.1".parse().unwrap()), 443).is_err());
        assert!(PinnedEndpoint::new(IpAddr::V6("::10.0.0.1".parse().unwrap()), 443).is_err());
        assert!(PinnedEndpoint::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443).is_ok());
    }
}
