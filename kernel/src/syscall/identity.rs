//! Identity syscalls: getpid, gettid, getuid, uname, sysinfo, getrandom.
//! All thread-local — no kernel Worker needed.
//!
//! Struct layouts (RV64):
//!
//! struct new_utsname {              // 390 bytes total
//!     sysname:    [u8; 65],         // offset 0
//!     nodename:   [u8; 65],         // offset 65
//!     release:    [u8; 65],         // offset 130
//!     version:    [u8; 65],         // offset 195
//!     machine:    [u8; 65],         // offset 260
//!     domainname: [u8; 65],         // offset 325
//! };
//! https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/utsname.h
//!
//! struct sysinfo {                  // 112 bytes total
//!     uptime:    i64,               // offset 0
//!     loads:     [u64; 3],          // offset 8
//!     totalram:  u64,               // offset 32
//!     freeram:   u64,               // offset 40
//!     sharedram: u64,               // offset 48
//!     bufferram: u64,               // offset 56
//!     totalswap: u64,               // offset 64
//!     freeswap:  u64,               // offset 72
//!     procs:     u16,               // offset 80
//!     pad:       u16,               // offset 82
//!     _pad:      [u8; 4],           // offset 84 (alignment)
//!     totalhigh: u64,               // offset 88
//!     freehigh:  u64,               // offset 96
//!     mem_unit:  u32,               // offset 104
//!     _f:        [u8; 0],           // offset 108 (padding, 0 bytes on 64-bit)
//! };
//! https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/sysinfo.h

use crate::abi::*;
use crate::guest_mem;
use crate::types::ThreadState;

pub const SYSINFO_TOTALRAM_BYTES: u64 = 256 * 1024 * 1024;
pub const SYSINFO_FREERAM_BYTES: u64 = 128 * 1024 * 1024;
pub const SYSINFO_MEM_UNIT: u32 = 1;

fn guest_range_valid(addr: u64, len: usize) -> bool {
    let len = len as u64;
    addr != 0 && addr <= u32::MAX as u64 && len <= (u32::MAX as u64 + 1).saturating_sub(addr)
}

fn parse_cred_arg(raw: i64) -> Result<Option<u32>, i64> {
    if raw == -1 {
        return Ok(None);
    }
    if raw < 0 || raw > u32::MAX as i64 {
        return Err(EINVAL);
    }
    Ok(Some(raw as u32))
}

fn can_change_uid(vm: &ThreadState, uid: Option<u32>, euid: Option<u32>) -> bool {
    if vm.euid == 0 {
        return true;
    }
    uid.is_none_or(|id| id == vm.uid || id == vm.euid)
        && euid.is_none_or(|id| id == vm.uid || id == vm.euid)
}

fn can_change_gid(vm: &ThreadState, gid: Option<u32>, egid: Option<u32>) -> bool {
    if vm.euid == 0 {
        return true;
    }
    gid.is_none_or(|id| id == vm.gid || id == vm.egid)
        && egid.is_none_or(|id| id == vm.gid || id == vm.egid)
}

/// getpid: return process ID from ProcessState in guest Memory.
pub fn sys_getpid(vm: &ThreadState, base: u32) -> i64 {
    // Read pid from ProcessState in guest memory
    let ps_ptr = vm.process_ptr;
    if ps_ptr == 0 {
        return 1;
    } // fallback: pid 1
    unsafe {
        let pid_offset = core::mem::offset_of!(crate::types::ProcessState, pid);
        guest_mem::read_i32(base, ps_ptr as u64 + pid_offset as u64) as i64
    }
}

/// getppid: return parent process ID from ProcessState in guest Memory.
pub fn sys_getppid(vm: &ThreadState, base: u32) -> i64 {
    let ps_ptr = vm.process_ptr;
    if ps_ptr == 0 {
        return 0;
    }
    unsafe {
        let ppid_offset = core::mem::offset_of!(crate::types::ProcessState, ppid);
        guest_mem::read_i32(base, ps_ptr as u64 + ppid_offset as u64) as i64
    }
}

/// gettid: return thread ID from ThreadState (thread-local, no kernel Worker).
pub fn sys_gettid(vm: &ThreadState) -> i64 {
    vm.tid as i64
}

/// uname: write UTS struct to guest memory.
/// struct utsname { char sysname[65]; nodename[65]; release[65]; version[65]; machine[65]; domainname[65]; }
pub fn sys_uname(vm: &ThreadState, base: u32, buf_addr: u64) -> i64 {
    let _ = vm;
    if !guest_range_valid(buf_addr, 390)
        || crate::syscall::memory::range_has_prot_none(buf_addr, 390)
    {
        return crate::abi::EFAULT;
    }
    let fields: [&[u8]; 6] = [
        b"Linux\0",
        b"tidemark\0",
        b"6.1.0\0",
        b"#1 SMP\0",
        b"riscv64\0",
        b"\0",
    ];
    let mut offset = 0u64;
    for field in &fields {
        unsafe {
            guest_mem::write_bytes(base, buf_addr + offset, field);
        }
        offset += 65;
    }
    0
}

/// sysinfo: write basic system info.
/// struct sysinfo { uptime, loads[3], totalram, freeram, ... }
pub fn sys_sysinfo(_vm: &ThreadState, base: u32, buf_addr: u64) -> i64 {
    if !guest_range_valid(buf_addr, 112)
        || crate::syscall::memory::range_has_prot_none(buf_addr, 112)
    {
        return crate::abi::EFAULT;
    }
    // Zero the entire struct (112 bytes on 64-bit)
    unsafe {
        guest_mem::zero_mem(base, buf_addr, 112);
        // uptime (offset 0): 60 seconds
        guest_mem::write_u64(base, buf_addr, 60);
        // totalram (offset 32)
        guest_mem::write_u64(base, buf_addr + 32, SYSINFO_TOTALRAM_BYTES);
        // freeram (offset 40)
        guest_mem::write_u64(base, buf_addr + 40, SYSINFO_FREERAM_BYTES);
        // mem_unit (offset 104): 1
        guest_mem::write_u32(base, buf_addr + 104, SYSINFO_MEM_UNIT);
    }
    0
}

/// getrandom: fill buffer with pseudo-random bytes.
/// Simple xorshift64 seeded from tid + pc for reproducibility.
pub fn sys_getrandom(vm: &ThreadState, base: u32, buf: u64, len: u64, _flags: u64) -> i64 {
    let mut state = (vm.tid as u64)
        .wrapping_mul(6364136223846793005)
        .wrapping_add(vm.pc);
    if state == 0 {
        state = 1;
    }
    let count = len as usize;
    for i in 0..count {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        unsafe {
            guest_mem::write_u8(base, buf + i as u64, state as u8);
        }
    }
    count as i64
}

/// getuid/geteuid/getgid/getegid: read credentials from ThreadState.
pub fn sys_getuid(vm: &ThreadState) -> i64 {
    vm.uid as i64
}

pub fn sys_geteuid(vm: &ThreadState) -> i64 {
    vm.euid as i64
}

pub fn sys_getgid(vm: &ThreadState) -> i64 {
    vm.gid as i64
}

pub fn sys_getegid(vm: &ThreadState) -> i64 {
    vm.egid as i64
}

pub fn sys_getresuid(
    vm: &ThreadState,
    base: u32,
    ruid_addr: u64,
    euid_addr: u64,
    suid_addr: u64,
) -> i64 {
    for addr in [ruid_addr, euid_addr, suid_addr] {
        if !guest_range_valid(addr, 4) || crate::syscall::memory::range_has_prot_none(addr, 4) {
            return EFAULT;
        }
    }

    unsafe {
        guest_mem::write_u32(base, ruid_addr, vm.uid);
        guest_mem::write_u32(base, euid_addr, vm.euid);
        guest_mem::write_u32(base, suid_addr, vm.euid);
    }
    0
}

pub fn sys_getresgid(
    vm: &ThreadState,
    base: u32,
    rgid_addr: u64,
    egid_addr: u64,
    sgid_addr: u64,
) -> i64 {
    for addr in [rgid_addr, egid_addr, sgid_addr] {
        if !guest_range_valid(addr, 4) || crate::syscall::memory::range_has_prot_none(addr, 4) {
            return EFAULT;
        }
    }

    unsafe {
        guest_mem::write_u32(base, rgid_addr, vm.gid);
        guest_mem::write_u32(base, egid_addr, vm.egid);
        guest_mem::write_u32(base, sgid_addr, vm.egid);
    }
    0
}

pub fn sys_setuid(vm: &mut ThreadState, uid: i64) -> i64 {
    let Ok(Some(uid)) = parse_cred_arg(uid) else {
        return EINVAL;
    };
    if vm.euid != 0 && uid != vm.uid && uid != vm.euid {
        return EPERM;
    }
    vm.uid = uid;
    vm.euid = uid;
    0
}

pub fn sys_setgid(vm: &mut ThreadState, gid: i64) -> i64 {
    let Ok(Some(gid)) = parse_cred_arg(gid) else {
        return EINVAL;
    };
    if vm.euid != 0 && gid != vm.gid && gid != vm.egid {
        return EPERM;
    }
    vm.gid = gid;
    vm.egid = gid;
    0
}

pub fn sys_setreuid(vm: &mut ThreadState, ruid: i64, euid: i64) -> i64 {
    let uid = match parse_cred_arg(ruid) {
        Ok(uid) => uid,
        Err(err) => return err,
    };
    let euid = match parse_cred_arg(euid) {
        Ok(euid) => euid,
        Err(err) => return err,
    };
    if !can_change_uid(vm, uid, euid) {
        return EPERM;
    }
    if let Some(uid) = uid {
        vm.uid = uid;
    }
    if let Some(euid) = euid {
        vm.euid = euid;
    }
    0
}

pub fn sys_setregid(vm: &mut ThreadState, rgid: i64, egid: i64) -> i64 {
    let gid = match parse_cred_arg(rgid) {
        Ok(gid) => gid,
        Err(err) => return err,
    };
    let egid = match parse_cred_arg(egid) {
        Ok(egid) => egid,
        Err(err) => return err,
    };
    if !can_change_gid(vm, gid, egid) {
        return EPERM;
    }
    if let Some(gid) = gid {
        vm.gid = gid;
    }
    if let Some(egid) = egid {
        vm.egid = egid;
    }
    0
}

pub fn sys_setresuid(vm: &mut ThreadState, ruid: i64, euid: i64, _suid: i64) -> i64 {
    sys_setreuid(vm, ruid, euid)
}

pub fn sys_setresgid(vm: &mut ThreadState, rgid: i64, egid: i64, _sgid: i64) -> i64 {
    sys_setregid(vm, rgid, egid)
}
