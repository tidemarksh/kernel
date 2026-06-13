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
const RISCV_HWPROBE_KEY_MVENDORID: i64 = 0;
const RISCV_HWPROBE_KEY_MARCHID: i64 = 1;
const RISCV_HWPROBE_KEY_MIMPID: i64 = 2;
const RISCV_HWPROBE_KEY_BASE_BEHAVIOR: i64 = 3;
const RISCV_HWPROBE_KEY_IMA_EXT_0: i64 = 4;
const RISCV_HWPROBE_KEY_CPUPERF_0: i64 = 5;
const RISCV_HWPROBE_KEY_ZICBOZ_BLOCK_SIZE: i64 = 6;
const RISCV_HWPROBE_KEY_HIGHEST_VIRT_ADDRESS: i64 = 7;
const RISCV_HWPROBE_BASE_BEHAVIOR_IMA: u64 = 1 << 0;
const RISCV_HWPROBE_IMA_FD: u64 = 1 << 0;
const RISCV_HWPROBE_IMA_C: u64 = 1 << 1;
const RISCV_HWPROBE_MISALIGNED_UNKNOWN: u64 = 0;
const RISCV_HWPROBE_HIGHEST_VIRT_ADDRESS_SV48: u64 = 0x0000_7fff_ffff_ffff;
const RISCV_HWPROBE_WHICH_CPUS: u64 = 1 << 0;
const GRND_NONBLOCK: u64 = 0x0001;
const GRND_RANDOM: u64 = 0x0002;

static mut GETRANDOM_STATE: u64 = 0;

fn guest_range_valid(base: u32, addr: u64, len: usize) -> bool {
    let Ok(len) = u64::try_from(len) else {
        return false;
    };
    addr != 0 && crate::syscall::memory::guest_range_accessible(base, addr, len)
}

fn splitmix64_next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn getrandom_seed(vm: &ThreadState, buf: u64, len: u64) -> u64 {
    let (sec, nsec) = crate::syscall::time::current_timespec(0).unwrap_or((0, 0));
    sec.rotate_left(7)
        ^ nsec.rotate_left(29)
        ^ (vm.tid as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ^ vm.pc.rotate_left(17)
        ^ buf.rotate_left(31)
        ^ len.rotate_left(47)
}

fn parse_cred_arg(raw: i64) -> Result<Option<u32>, i64> {
    if raw == -1 || raw == u32::MAX as i64 {
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

pub(crate) fn sysinfo_totalram_bytes_for_policy(guest_memory_policy_limit: u64) -> u64 {
    if guest_memory_policy_limit != 0 {
        guest_memory_policy_limit
    } else {
        SYSINFO_TOTALRAM_BYTES
    }
}

pub(crate) fn sysinfo_freeram_bytes(totalram: u64) -> u64 {
    if totalram == SYSINFO_TOTALRAM_BYTES {
        SYSINFO_FREERAM_BYTES
    } else {
        totalram / 2
    }
}

fn sysinfo_totalram_bytes(vm: &ThreadState) -> u64 {
    sysinfo_totalram_bytes_for_policy(vm.guest_memory_policy_limit)
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
    if !guest_range_valid(base, buf_addr, 390) {
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
pub fn sys_sysinfo(vm: &ThreadState, base: u32, buf_addr: u64) -> i64 {
    if !guest_range_valid(base, buf_addr, 112) {
        return crate::abi::EFAULT;
    }
    let totalram = sysinfo_totalram_bytes(vm);
    let freeram = sysinfo_freeram_bytes(totalram);
    // Zero the entire struct (112 bytes on 64-bit)
    unsafe {
        guest_mem::zero_mem(base, buf_addr, 112);
        // uptime (offset 0): 60 seconds
        guest_mem::write_u64(base, buf_addr, 60);
        // totalram (offset 32)
        guest_mem::write_u64(base, buf_addr + 32, totalram);
        // freeram (offset 40)
        guest_mem::write_u64(base, buf_addr + 40, freeram);
        // mem_unit (offset 104): 1
        guest_mem::write_u32(base, buf_addr + 104, SYSINFO_MEM_UNIT);
    }
    0
}

/// getrandom: fill the caller's buffer with bytes from a kernel-managed PRNG.
/// https://man7.org/linux/man-pages/man2/getrandom.2.html requires
/// Linux-shaped flag validation, and repeated calls must not hand back the same
/// byte stream for the same call site.
pub fn sys_getrandom(vm: &ThreadState, base: u32, buf: u64, len: u64, flags: u64) -> i64 {
    let allowed_flags = GRND_NONBLOCK | GRND_RANDOM;
    if flags & !allowed_flags != 0 {
        return EINVAL;
    }
    if len == 0 {
        return 0;
    }
    let count = match usize::try_from(len) {
        Ok(count) => count,
        Err(_) => return EFAULT,
    };
    if !guest_range_valid(base, buf, count) {
        return EFAULT;
    }

    let mut state = unsafe { core::ptr::read(core::ptr::addr_of!(GETRANDOM_STATE)) };
    if state == 0 {
        state = getrandom_seed(vm, buf, len);
        if state == 0 {
            state = 1;
        }
    }

    let mut remaining_word = 0u64;
    let mut remaining_bytes = 0usize;
    for i in 0..count {
        if remaining_bytes == 0 {
            remaining_word = splitmix64_next(&mut state);
            remaining_bytes = 8;
        }
        unsafe {
            guest_mem::write_u8(base, buf + i as u64, remaining_word as u8);
        }
        remaining_word >>= 8;
        remaining_bytes -= 1;
    }

    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(GETRANDOM_STATE), state);
    }
    count as i64
}

/// riscv_hwprobe reports RISC-V hardware capabilities to userspace.
/// https://docs.kernel.org/arch/riscv/hwprobe.html
/// https://github.com/torvalds/linux/blob/v6.12/arch/riscv/include/uapi/asm/hwprobe.h
///
/// Tidemark exposes the minimum stable capabilities needed by the guest ABI
/// and marks unknown keys as unsupported, matching the Linux key/value shape.
pub fn sys_riscv_hwprobe(
    _vm: &ThreadState,
    base: u32,
    pairs_addr: u64,
    pair_count: u64,
    cpusetsize: u64,
    cpus_addr: u64,
    flags: u64,
) -> i64 {
    if (flags & !RISCV_HWPROBE_WHICH_CPUS) != 0 {
        return EINVAL;
    }
    let pairs_len = match (pair_count as usize).checked_mul(16) {
        Some(len) => len,
        None => return EFAULT,
    };
    if pair_count != 0
        && !guest_range_valid(base, pairs_addr, pairs_len)
    {
        return EFAULT;
    }
    if cpus_addr != 0
        && cpusetsize != 0
        && !guest_range_valid(base, cpus_addr, cpusetsize as usize)
    {
        return EFAULT;
    }

    for index in 0..pair_count {
        let pair_addr = pairs_addr + index * 16;
        let key = unsafe { guest_mem::read_i64(base, pair_addr) };
        let value = match key {
            RISCV_HWPROBE_KEY_MVENDORID | RISCV_HWPROBE_KEY_MARCHID | RISCV_HWPROBE_KEY_MIMPID => 0,
            RISCV_HWPROBE_KEY_BASE_BEHAVIOR => RISCV_HWPROBE_BASE_BEHAVIOR_IMA,
            RISCV_HWPROBE_KEY_IMA_EXT_0 => RISCV_HWPROBE_IMA_FD | RISCV_HWPROBE_IMA_C,
            RISCV_HWPROBE_KEY_CPUPERF_0 => RISCV_HWPROBE_MISALIGNED_UNKNOWN,
            RISCV_HWPROBE_KEY_ZICBOZ_BLOCK_SIZE => 0,
            RISCV_HWPROBE_KEY_HIGHEST_VIRT_ADDRESS => RISCV_HWPROBE_HIGHEST_VIRT_ADDRESS_SV48,
            _ => {
                unsafe {
                    guest_mem::write_u64(base, pair_addr, (-1i64) as u64);
                    guest_mem::write_u64(base, pair_addr + 8, 0);
                }
                continue;
            }
        };
        unsafe {
            guest_mem::write_u64(base, pair_addr + 8, value);
        }
    }

    if (flags & RISCV_HWPROBE_WHICH_CPUS) != 0 && cpus_addr != 0 && cpusetsize != 0 {
        unsafe {
            guest_mem::zero_mem(base, cpus_addr, cpusetsize as usize);
            guest_mem::write_u8(base, cpus_addr, 1);
        }
    }

    0
}

/// riscv_flush_icache: synchronize instruction visibility for the current process.
/// https://github.com/torvalds/linux/blob/v6.12/arch/riscv/include/uapi/asm/unistd.h
/// https://man7.org/linux/man-pages/man2/cacheflush.2.html
///
/// Tidemark does not model per-core I-cache state, so this is a Linux-shaped no-op.
/// The address range and flags are accepted and ignored.
pub fn sys_riscv_flush_icache(
    vm: &mut ThreadState,
    _base: u32,
    start: u64,
    end: u64,
    _flags: u64,
) -> i64 {
    if vm.block_cache_ptr != 0 {
        // Some guest runtimes issue the second argument as a byte count. Linux
        // accepts the syscall as a synchronization hint, so invalidate broadly
        // enough for both start/end and observed start/length forms.
        let invalidate_end = if end < start {
            start.saturating_add(end)
        } else {
            end
        };
        let mut cache = unsafe {
            crate::cpu::block_cache::BlockCache::from_ptr(
                vm.block_cache_ptr as *mut crate::cpu::block_cache::BlockEntry,
            )
        };
        cache.invalidate_range(start, invalidate_end);
    }
    0
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
        if !guest_range_valid(base, addr, 4) {
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
        if !guest_range_valid(base, addr, 4) {
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

pub fn sys_getgroups(base: u32, size: i64, list_addr: u64) -> i64 {
    if size < 0 {
        return EINVAL;
    }
    if size == 0 {
        return 0;
    }
    let bytes = match (size as usize).checked_mul(4) {
        Some(bytes) => bytes,
        None => return EINVAL,
    };
    if !guest_range_valid(base, list_addr, bytes) {
        return EFAULT;
    }
    unsafe {
        guest_mem::zero_mem(base, list_addr, bytes);
    }
    0
}

pub fn sys_setgroups(vm: &ThreadState, size: i64, list_addr: u64) -> i64 {
    if size < 0 {
        return EINVAL;
    }
    if size > 0 {
        let bytes = match (size as usize).checked_mul(4) {
            Some(bytes) => bytes,
            None => return EINVAL,
        };
        if !guest_range_valid(vm.guest_base, list_addr, bytes) {
            return EFAULT;
        }
    }
    if vm.euid != 0 {
        return EPERM;
    }
    0
}
