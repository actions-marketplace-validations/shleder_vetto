//! Windows production execution verification: host-side observation of Job Object and child token.

use crate::sandbox::capability::HostVerification;
use std::time::Duration;

#[cfg(target_os = "windows")]
use std::os::windows::io::RawHandle;
#[cfg(target_os = "windows")]
use std::time::Instant;

#[cfg(not(target_os = "windows"))]
pub type RawHandle = *mut std::ffi::c_void;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct JobLimitsQuery {
    pub limit_flags: u32,
    pub max_memory_bytes: Option<u64>,
    pub max_processes: Option<u32>,
}

#[cfg(target_os = "windows")]
type Dword = u32;
#[cfg(target_os = "windows")]
type Bool = i32;

#[cfg(target_os = "windows")]
const STILL_ACTIVE: Dword = 259;
#[cfg(target_os = "windows")]
const PROCESS_QUERY_LIMITED_INFORMATION: Dword = 0x1000;
#[cfg(target_os = "windows")]
const ERROR_INVALID_PARAMETER: Dword = 87;
#[cfg(target_os = "windows")]
const ERROR_MORE_DATA: Dword = 234;
#[cfg(target_os = "windows")]
const JOB_OBJECT_BASIC_PROCESS_ID_LIST: Dword = 3;
#[cfg(target_os = "windows")]
const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: Dword = 9;
#[cfg(target_os = "windows")]
const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: Dword = 0x00002000;
#[cfg(target_os = "windows")]
const JOB_OBJECT_LIMIT_JOB_MEMORY: Dword = 0x00000200;
#[cfg(target_os = "windows")]
const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: Dword = 0x00000008;
#[cfg(target_os = "windows")]
const TOKEN_QUERY: Dword = 0x0008;
#[cfg(target_os = "windows")]
const SECURITY_MANDATORY_LOW_RID: u32 = 0x00001000;
#[cfg(target_os = "windows")]
const LIMIT_FLAGS_OFFSET: usize = 16;

#[cfg(target_os = "windows")]
extern "system" {
    fn IsProcessInJob(process: RawHandle, job: RawHandle, result: *mut Bool) -> Bool;
    fn QueryInformationJobObject(
        job: RawHandle,
        info_class: Dword,
        info: *mut std::ffi::c_void,
        info_len: Dword,
        returned: *mut Dword,
    ) -> Bool;
    fn OpenProcess(desired_access: Dword, inherit_handle: Bool, process_id: Dword) -> RawHandle;
    fn GetExitCodeProcess(process: RawHandle, exit_code: *mut Dword) -> Bool;
    fn OpenProcessToken(process: RawHandle, desired_access: Dword, token: *mut RawHandle) -> Bool;
    fn GetTokenInformation(
        token: RawHandle,
        info_class: Dword,
        info: *mut std::ffi::c_void,
        info_len: Dword,
        returned: *mut Dword,
    ) -> Bool;
    fn GetSidSubAuthorityCount(sid: *mut std::ffi::c_void) -> *mut u8;
    fn GetSidSubAuthority(sid: *mut std::ffi::c_void, index: Dword) -> *mut Dword;
    fn CloseHandle(handle: RawHandle) -> Bool;
    fn GetLastError() -> Dword;
}

/// Host-observed verification of a live confined Windows child.
#[cfg(target_os = "windows")]
pub unsafe fn verify_production_child(process: RawHandle, job: RawHandle) -> HostVerification {
    let mut out = HostVerification::none();
    if process.is_null() || job.is_null() {
        return out;
    }
    let mut in_job: Bool = 0;
    if unsafe { IsProcessInJob(process, job, &mut in_job) } != 0 && in_job != 0 {
        out.win_in_job = true;
    }
    let flags = unsafe { job_limit_flags(job) };
    if flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE != 0 {
        out.win_kill_on_close = true;
    }
    if flags & (JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_ACTIVE_PROCESS) != 0 {
        out.win_job_ceiling = true;
    }
    if unsafe { child_runs_low_integrity(process) } {
        out.win_low_integrity = true;
    }
    out
}

#[cfg(not(target_os = "windows"))]
pub unsafe fn verify_production_child(_process: RawHandle, _job: RawHandle) -> HostVerification {
    HostVerification::none()
}

#[cfg(target_os = "windows")]
unsafe fn job_limit_flags(job: RawHandle) -> Dword {
    let mut buffer = [0u8; 256];
    let ok = unsafe {
        QueryInformationJobObject(
            job,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            buffer.as_mut_ptr().cast(),
            buffer.len() as Dword,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return 0;
    }
    Dword::from_ne_bytes([
        buffer[LIMIT_FLAGS_OFFSET],
        buffer[LIMIT_FLAGS_OFFSET + 1],
        buffer[LIMIT_FLAGS_OFFSET + 2],
        buffer[LIMIT_FLAGS_OFFSET + 3],
    ])
}

#[cfg(target_os = "windows")]
unsafe fn child_runs_low_integrity(process: RawHandle) -> bool {
    let mut token: RawHandle = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 || token.is_null() {
        return false;
    }
    let holds_low = integrity_rid(token).is_some_and(|rid| rid <= SECURITY_MANDATORY_LOW_RID);
    unsafe { CloseHandle(token) };
    holds_low
}

#[cfg(target_os = "windows")]
unsafe fn integrity_rid(token: RawHandle) -> Option<u32> {
    const TOKEN_MANDATORY_POLICY: Dword = 25; // TokenIntegrityLevel
    let mut needed: Dword = 0;
    let _ = unsafe {
        GetTokenInformation(
            token,
            TOKEN_MANDATORY_POLICY,
            std::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    if needed == 0 || needed > 4096 {
        return None;
    }
    let mut buffer = vec![0u8; needed as usize];
    let ok = unsafe {
        GetTokenInformation(
            token,
            TOKEN_MANDATORY_POLICY,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        return None;
    }
    let sid_ptr = *buffer.as_ptr().cast::<*mut std::ffi::c_void>();
    if sid_ptr.is_null() {
        return None;
    }
    let count_ptr = unsafe { GetSidSubAuthorityCount(sid_ptr) };
    if count_ptr.is_null() {
        return None;
    }
    let count = unsafe { *count_ptr };
    if count == 0 {
        return None;
    }
    let last_sub_auth = unsafe { GetSidSubAuthority(sid_ptr, (count - 1) as Dword) };
    if last_sub_auth.is_null() {
        return None;
    }
    Some(unsafe { *last_sub_auth })
}

#[cfg(target_os = "windows")]
pub unsafe fn job_assigned_pids(job: RawHandle) -> Vec<u32> {
    let mut capacity: usize = 64;
    for _ in 0..4 {
        let mut buffer = vec![0u32; 2 + capacity];
        let bytes = (buffer.len() * 4) as Dword;
        let ok = unsafe {
            QueryInformationJobObject(
                job,
                JOB_OBJECT_BASIC_PROCESS_ID_LIST,
                buffer.as_mut_ptr().cast(),
                bytes,
                std::ptr::null_mut(),
            )
        };
        if ok != 0 {
            let count = buffer[1] as usize;
            if count > capacity {
                capacity = count + 16;
                continue;
            }
            return buffer.into_iter().skip(2).take(count).collect();
        }
        if unsafe { GetLastError() } != ERROR_MORE_DATA {
            return Vec::new();
        }
        capacity *= 4;
    }
    Vec::new()
}

#[cfg(not(target_os = "windows"))]
pub unsafe fn job_assigned_pids(_job: RawHandle) -> Vec<u32> {
    Vec::new()
}

#[cfg(target_os = "windows")]
pub fn pids_still_alive(pids: &[u32], budget: Duration) -> Vec<u32> {
    let deadline = Instant::now() + budget;
    let mut alive: Vec<u32> = pids.to_vec();
    while !alive.is_empty() && Instant::now() < deadline {
        alive.retain(|&pid| pid_may_be_alive(pid));
        if !alive.is_empty() {
            std::thread::sleep(Duration::from_millis(25));
        }
    }
    alive
}

#[cfg(not(target_os = "windows"))]
pub fn pids_still_alive(pids: &[u32], _budget: Duration) -> Vec<u32> {
    pids.to_vec()
}

#[cfg(target_os = "windows")]
fn pid_may_be_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return unsafe { GetLastError() } != ERROR_INVALID_PARAMETER;
    }
    let mut code: Dword = STILL_ACTIVE;
    let ok = unsafe { GetExitCodeProcess(handle, &mut code) };
    unsafe { CloseHandle(handle) };
    ok == 0 || code == STILL_ACTIVE
}

pub fn verify_job_limits_against_expected(
    query: &JobLimitsQuery,
    expected_memory: Option<u64>,
    expected_pids: Option<u32>,
) -> bool {
    if let Some(exp_mem) = expected_memory {
        if query.max_memory_bytes != Some(exp_mem) {
            return false;
        }
    }
    if let Some(exp_pids) = expected_pids {
        if query.max_processes != Some(exp_pids) {
            return false;
        }
    }
    true
}

pub fn verify_windows_anti_tamper(
    contract: &crate::policy_ir::contract::SecurityContract,
    query: &JobLimitsQuery,
) -> bool {
    if !contract.verify_digest() {
        return false;
    }
    let res = &contract.resources;
    if res.max_memory_bytes > 0 {
        if let Some(actual_mem) = query.max_memory_bytes {
            if actual_mem > res.max_memory_bytes {
                return false;
            }
        }
    }
    if res.max_pids > 0 {
        if let Some(actual_pids) = query.max_processes {
            if actual_pids > res.max_pids {
                return false;
            }
        }
    }
    true
}
