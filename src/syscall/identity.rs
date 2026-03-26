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

use crate::guest_mem;
use crate::types::ThreadState;

/// getpid: return process ID from ProcessState in guest Memory.
pub fn sys_getpid(vm: &ThreadState) -> i64 {
    // Read pid from ProcessState in guest memory
    let ps_ptr = vm.process_ptr;
    if ps_ptr == 0 { return 1; } // fallback: pid 1
    unsafe {
        let pid_offset = core::mem::offset_of!(crate::types::ProcessState, pid);
        guest_mem::read_i32(0, ps_ptr as u64 + pid_offset as u64) as i64
    }
}

/// getppid: return parent process ID from ProcessState in guest Memory.
pub fn sys_getppid(vm: &ThreadState) -> i64 {
    let ps_ptr = vm.process_ptr;
    if ps_ptr == 0 { return 0; }
    unsafe {
        let ppid_offset = core::mem::offset_of!(crate::types::ProcessState, ppid);
        guest_mem::read_i32(0, ps_ptr as u64 + ppid_offset as u64) as i64
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
    // Zero the entire struct (112 bytes on 64-bit)
    unsafe {
        guest_mem::zero_mem(base, buf_addr, 112);
        // uptime (offset 0): 60 seconds
        guest_mem::write_u64(base, buf_addr, 60);
        // totalram (offset 32): 256 MB
        guest_mem::write_u64(base, buf_addr + 32, 256 * 1024 * 1024);
        // freeram (offset 40): 128 MB
        guest_mem::write_u64(base, buf_addr + 40, 128 * 1024 * 1024);
        // mem_unit (offset 104): 1
        guest_mem::write_u32(base, buf_addr + 104, 1);
    }
    0
}

/// getrandom: fill buffer with pseudo-random bytes.
/// Simple xorshift64 seeded from tid + pc for reproducibility.
pub fn sys_getrandom(vm: &ThreadState, base: u32, buf: u64, len: u64, _flags: u64) -> i64 {
    let mut state = (vm.tid as u64).wrapping_mul(6364136223846793005).wrapping_add(vm.pc);
    if state == 0 { state = 1; }
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

/// getuid/geteuid/getgid/getegid: always return 0 (root).
pub fn sys_getuid() -> i64 { 0 }

/// sched_yield: no-op, return success.
pub fn sys_sched_yield() -> i64 { 0 }

#[cfg(test)]
mod tests {
    use crate::test_helpers::TestVm;

    #[test]
    fn identity_syscalls() {
        let mut t = TestVm::new();
        assert_eq!(super::sys_getpid(&t.vm), 42);
        assert_eq!(super::sys_getppid(&t.vm), 1);
        assert_eq!(super::sys_gettid(&t.vm), 1);

        // uname
        let buf = t.scratch;
        assert_eq!(super::sys_uname(&t.vm, t.base, buf), 0);
        let mut sysname = [0u8; 6];
        unsafe { crate::guest_mem::read_bytes(t.base, buf, &mut sysname); }
        assert_eq!(&sysname, b"Linux\0");

        // sysinfo
        let buf2 = t.scratch + 0x1000;
        assert_eq!(super::sys_sysinfo(&t.vm, t.base, buf2), 0);
        let totalram = unsafe { crate::guest_mem::read_u64(t.base, buf2 + 32) };
        assert!(totalram > 0);

        // getrandom
        let buf3 = t.scratch + 0x2000;
        unsafe { crate::guest_mem::zero_mem(t.base, buf3, 16); }
        let ret = super::sys_getrandom(&t.vm, t.base, buf3, 16, 0);
        assert_eq!(ret, 16);
        let mut bytes = [0u8; 16];
        unsafe { crate::guest_mem::read_bytes(t.base, buf3, &mut bytes); }
        assert!(bytes.iter().any(|&b| b != 0), "getrandom should produce non-zero bytes");
    }
}
