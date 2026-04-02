//! Runtime/mock support for wasm32-wasi integration tests.
//!
//! This module keeps plain-fork handoff helpers out of the Linux syscall
//! semantics layer while still allowing the integration-test harness to model
//! the TS/runtime side of `STATUS_EXECVE_SPAWN`.

use alloc_crate::{vec, vec::Vec};
use crate::abi::MAP_SHARED;
use crate::guest_mem;
use crate::syscall::memory;

struct SharedMappingSnapshot {
    start: u64,
    bytes: Vec<u8>,
}

struct PlainForkFutexWait {
    pid: i32,
    addr: u32,
    woken: bool,
}

pub struct PlainForkSnapshot {
    mm_state: memory::AddressSpaceSnapshot,
}

static mut GUEST_OUTPUT: Option<Vec<u8>> = None;
static mut PLAIN_FORK_FUTEX_WAITS: Option<Vec<PlainForkFutexWait>> = None;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WriteTraceSummary {
    pub write_calls: u32,
    pub writev_calls: u32,
    pub last_fd: u64,
    pub last_nr: u64,
    pub last_buf_addr: u64,
    pub last_count: u64,
    pub last_result: i64,
    pub last_ofd_id: u32,
    pub last_ofd_type: i32,
    pub last_ofd_ino: u32,
    pub last_status_flags: i32,
    pub last_pipe_read_open: i32,
    pub last_pipe_write_open: i32,
}

static mut WRITE_TRACE: WriteTraceSummary = WriteTraceSummary {
    write_calls: 0,
    writev_calls: 0,
    last_fd: 0,
    last_nr: 0,
    last_buf_addr: 0,
    last_count: 0,
    last_result: 0,
    last_ofd_id: 0,
    last_ofd_type: 0,
    last_ofd_ino: 0,
    last_status_flags: 0,
    last_pipe_read_open: 0,
    last_pipe_write_open: 0,
};
static mut LAST_WRITE_BYTES: [u8; 64] = [0; 64];
static mut LAST_WRITE_BYTES_LEN: u32 = 0;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SyscallTraceSummary {
    pub vm_ptr: u32,
    pub nr: u64,
    pub result: i64,
    pub status: i32,
}

static mut SYSCALL_TRACE: SyscallTraceSummary = SyscallTraceSummary {
    vm_ptr: 0,
    nr: 0,
    result: 0,
    status: 0,
};

const FD_SYSCALL_TRACE_CAP: usize = 128;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FdSyscallTraceEntry {
    pub vm_ptr: u32,
    pub nr: u64,
    pub arg0: u64,
    pub arg0_ofd_id: u32,
    pub arg0_ofd_type: i32,
    pub arg1: u64,
    pub arg2: u64,
    pub arg2_ofd_id: u32,
    pub arg2_ofd_type: i32,
    pub arg3: u64,
    pub result: i64,
    pub status: i32,
}

static mut FD_SYSCALL_TRACE: [FdSyscallTraceEntry; FD_SYSCALL_TRACE_CAP] = [FdSyscallTraceEntry {
    vm_ptr: 0,
    nr: 0,
    arg0: 0,
    arg0_ofd_id: 0,
    arg0_ofd_type: 0,
    arg1: 0,
    arg2: 0,
    arg2_ofd_id: 0,
    arg2_ofd_type: 0,
    arg3: 0,
    result: 0,
    status: 0,
}; FD_SYSCALL_TRACE_CAP];
static mut FD_SYSCALL_TRACE_LEN: u32 = 0;
static mut FD_SYSCALL_TRACE_NEXT: u32 = 0;

const SYNC_EFFECT_PIPE_STATE: u32 = 1 << 0;
const SYNC_EFFECT_SOCKET_STATE: u32 = 1 << 1;
const SYNC_EFFECT_EPOLL_STATE: u32 = 1 << 2;
const SYNC_EFFECT_EPOLL_DEPENDENT_OFD_STATE: u32 = 1 << 3;
const SYNC_EFFECT_PROCESS_LIFECYCLE: u32 = 1 << 4;
const SYNC_EFFECT_SIGNAL_WAITERS: u32 = 1 << 5;
const SYNC_EFFECT_FORK_SHARED_OFD_STATE: u32 = 1 << 6;

static mut COMPLETED_SYNC_EFFECTS: u32 = 0;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MemoryTraceSummary {
    pub nr: u64,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub result: i64,
}

static mut MEMORY_TRACE: MemoryTraceSummary = MemoryTraceSummary {
    nr: 0,
    arg0: 0,
    arg1: 0,
    arg2: 0,
    arg3: 0,
    result: 0,
};

static mut LAST_EXECVE_PATH: [u8; 256] = [0; 256];
static mut LAST_EXECVE_LEN: u32 = 0;
static mut LAST_EXECVE_STAGE: u32 = 0;
static mut LAST_EXECVE_VALUE0: u64 = 0;
static mut LAST_EXECVE_VALUE1: u64 = 0;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PipeCloseTraceSummary {
    pub pipe_idx: u32,
    pub is_read_end: u32,
    pub ofd_id: u32,
    pub read_open: i32,
    pub write_open: i32,
}

static mut PIPE_CLOSE_TRACE: PipeCloseTraceSummary = PipeCloseTraceSummary {
    pipe_idx: 0,
    is_read_end: 0,
    ofd_id: 0,
    read_open: 0,
    write_open: 0,
};

pub fn snapshot_plain_fork() -> PlainForkSnapshot {
    PlainForkSnapshot {
        mm_state: memory::snapshot_for_plain_fork(),
    }
}

pub fn clear_guest_output() {
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(GUEST_OUTPUT), Some(Vec::new()));
    }
}

pub fn clear_write_trace() {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(WRITE_TRACE),
            WriteTraceSummary {
                write_calls: 0,
                writev_calls: 0,
                last_fd: 0,
                last_nr: 0,
                last_buf_addr: 0,
                last_count: 0,
                last_result: 0,
                last_ofd_id: 0,
                last_ofd_type: 0,
                last_ofd_ino: 0,
                last_status_flags: 0,
                last_pipe_read_open: 0,
                last_pipe_write_open: 0,
            },
        );
        core::ptr::write(core::ptr::addr_of_mut!(LAST_WRITE_BYTES), [0; 64]);
        core::ptr::write(core::ptr::addr_of_mut!(LAST_WRITE_BYTES_LEN), 0);
    }
}

pub fn clear_syscall_trace() {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(SYSCALL_TRACE),
            SyscallTraceSummary {
                vm_ptr: 0,
                nr: 0,
                result: 0,
                status: 0,
            },
        );
        core::ptr::write(core::ptr::addr_of_mut!(COMPLETED_SYNC_EFFECTS), 0);
    }
}

pub fn clear_memory_trace() {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(MEMORY_TRACE),
            MemoryTraceSummary {
                nr: 0,
                arg0: 0,
                arg1: 0,
                arg2: 0,
                arg3: 0,
                result: 0,
            },
        );
    }
}

pub fn clear_execve_trace() {
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(LAST_EXECVE_PATH), [0; 256]);
        core::ptr::write(core::ptr::addr_of_mut!(LAST_EXECVE_LEN), 0);
    }
}

pub fn clear_pipe_close_trace() {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(PIPE_CLOSE_TRACE),
            PipeCloseTraceSummary {
                pipe_idx: 0,
                is_read_end: 0,
                ofd_id: 0,
                read_open: 0,
                write_open: 0,
            },
        );
    }
}

pub fn clear_plain_fork_futex_waits() {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(PLAIN_FORK_FUTEX_WAITS),
            Some(Vec::new()),
        );
    }
}

pub fn register_plain_fork_futex_wait(pid: i32, addr: u32) {
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(PLAIN_FORK_FUTEX_WAITS);
        if slot.is_none() {
            *slot = Some(Vec::new());
        }
        if let Some(waits) = slot.as_mut() {
            if let Some(wait) = waits.iter_mut().find(|wait| wait.pid == pid) {
                wait.addr = addr;
                wait.woken = false;
                return;
            }
            waits.push(PlainForkFutexWait {
                pid,
                addr,
                woken: false,
            });
        }
    }
}

pub fn clear_plain_fork_futex_wait(pid: i32) {
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(PLAIN_FORK_FUTEX_WAITS);
        if let Some(waits) = slot.as_mut() {
            waits.retain(|wait| wait.pid != pid);
        }
    }
}

pub fn wake_plain_fork_futex_waits(addr: u32, max_wake: u32) -> u32 {
    if max_wake == 0 {
        return 0;
    }

    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(PLAIN_FORK_FUTEX_WAITS);
        let Some(waits) = slot.as_mut() else {
            return 0;
        };

        let mut woken = 0;
        for wait in waits.iter_mut() {
            if wait.addr != addr || wait.woken {
                continue;
            }
            wait.woken = true;
            woken += 1;
            if woken == max_wake {
                break;
            }
        }
        woken
    }
}

pub fn requeue_plain_fork_futex_waits(addr: u32, new_addr: u32, max_requeue: u32) -> u32 {
    if max_requeue == 0 || addr == new_addr {
        return 0;
    }

    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(PLAIN_FORK_FUTEX_WAITS);
        let Some(waits) = slot.as_mut() else {
            return 0;
        };

        let mut requeued = 0;
        for wait in waits.iter_mut() {
            if wait.addr != addr || wait.woken {
                continue;
            }
            wait.addr = new_addr;
            requeued += 1;
            if requeued == max_requeue {
                break;
            }
        }
        requeued
    }
}

pub fn take_plain_fork_futex_wake(pid: i32, addr: u32) -> bool {
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(PLAIN_FORK_FUTEX_WAITS);
        let Some(waits) = slot.as_mut() else {
            return false;
        };

        if let Some(idx) = waits
            .iter()
            .position(|wait| wait.pid == pid && wait.addr == addr && wait.woken)
        {
            waits.remove(idx);
            true
        } else {
            false
        }
    }
}

pub fn append_guest_output(bytes: &[u8]) {
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(GUEST_OUTPUT);
        if slot.is_none() {
            *slot = Some(Vec::new());
        }
        if let Some(buf) = slot.as_mut() {
            buf.extend_from_slice(bytes);
        }
    }
}

pub fn take_guest_output() -> Vec<u8> {
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(GUEST_OUTPUT);
        slot.take().unwrap_or_default()
    }
}

pub fn record_write_attempt(
    fd: u64,
    nr: u64,
    buf_addr: u64,
    count: u64,
    result: i64,
    ofd_id: u32,
    ofd_type: i32,
    ofd_ino: u32,
    status_flags: i32,
    pipe_read_open: i32,
    pipe_write_open: i32,
    bytes: Option<&[u8]>,
) {
    unsafe {
        let trace = &mut *core::ptr::addr_of_mut!(WRITE_TRACE);
        if nr == crate::abi::SYS_WRITEV {
            trace.writev_calls = trace.writev_calls.saturating_add(1);
        } else {
            trace.write_calls = trace.write_calls.saturating_add(1);
        }
        trace.last_fd = fd;
        trace.last_nr = nr;
        trace.last_buf_addr = buf_addr;
        trace.last_count = count;
        trace.last_result = result;
        trace.last_ofd_id = ofd_id;
        trace.last_ofd_type = ofd_type;
        trace.last_ofd_ino = ofd_ino;
        trace.last_status_flags = status_flags;
        trace.last_pipe_read_open = pipe_read_open;
        trace.last_pipe_write_open = pipe_write_open;

        let mut snapshot = [0u8; 64];
        let snapshot_len = bytes.map_or(0, |bytes| {
            let len = bytes.len().min(snapshot.len());
            snapshot[..len].copy_from_slice(&bytes[..len]);
            len as u32
        });
        core::ptr::write(core::ptr::addr_of_mut!(LAST_WRITE_BYTES), snapshot);
        core::ptr::write(core::ptr::addr_of_mut!(LAST_WRITE_BYTES_LEN), snapshot_len);
    }
}

pub fn record_pipe_close_event(
    pipe_idx: u32,
    is_read_end: bool,
    ofd_id: u32,
    read_open: i32,
    write_open: i32,
) {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(PIPE_CLOSE_TRACE),
            PipeCloseTraceSummary {
                pipe_idx,
                is_read_end: if is_read_end { 1 } else { 0 },
                ofd_id,
                read_open,
                write_open,
            },
        );
    }
}

pub fn pipe_close_trace_summary() -> PipeCloseTraceSummary {
    unsafe { core::ptr::read(core::ptr::addr_of!(PIPE_CLOSE_TRACE)) }
}

pub fn record_syscall(vm_ptr: u32, nr: u64, result: i64, status: i32) {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(SYSCALL_TRACE),
            SyscallTraceSummary {
                vm_ptr,
                nr,
                result,
                status,
            },
        );
        if status == crate::abi::STATUS_OK {
            let effects = match nr {
                crate::abi::SYS_READ
                | crate::abi::SYS_WRITE
                | crate::abi::SYS_LSEEK
                | crate::abi::SYS_READV
                | crate::abi::SYS_WRITEV
                | crate::abi::SYS_CLOSE
                | crate::abi::SYS_DUP
                | crate::abi::SYS_DUP3
                | crate::abi::SYS_FCNTL => {
                    SYNC_EFFECT_PIPE_STATE
                        | SYNC_EFFECT_SOCKET_STATE
                        | SYNC_EFFECT_EPOLL_STATE
                        | SYNC_EFFECT_EPOLL_DEPENDENT_OFD_STATE
                        | SYNC_EFFECT_FORK_SHARED_OFD_STATE
                }
                crate::abi::SYS_PIPE2 => {
                    SYNC_EFFECT_PIPE_STATE
                        | SYNC_EFFECT_EPOLL_STATE
                        | SYNC_EFFECT_FORK_SHARED_OFD_STATE
                }
                crate::abi::SYS_SOCKET
                | crate::abi::SYS_BIND
                | crate::abi::SYS_LISTEN
                | crate::abi::SYS_ACCEPT4 => {
                    SYNC_EFFECT_SOCKET_STATE
                        | SYNC_EFFECT_EPOLL_STATE
                        | SYNC_EFFECT_FORK_SHARED_OFD_STATE
                }
                crate::abi::SYS_EVENTFD2 => {
                    SYNC_EFFECT_EPOLL_DEPENDENT_OFD_STATE
                        | SYNC_EFFECT_EPOLL_STATE
                        | SYNC_EFFECT_FORK_SHARED_OFD_STATE
                }
                crate::abi::SYS_EPOLL_CTL => SYNC_EFFECT_EPOLL_STATE,
                crate::abi::SYS_EXECVE
                | crate::abi::SYS_SETPGID
                | crate::abi::SYS_SETSID => SYNC_EFFECT_PROCESS_LIFECYCLE,
                crate::abi::SYS_KILL
                | crate::abi::SYS_TKILL
                | crate::abi::SYS_TGKILL => SYNC_EFFECT_SIGNAL_WAITERS,
                _ => 0,
            };
            let current = core::ptr::read(core::ptr::addr_of!(COMPLETED_SYNC_EFFECTS));
            core::ptr::write(core::ptr::addr_of_mut!(COMPLETED_SYNC_EFFECTS), current | effects);
        }
    }
}

pub fn record_fd_syscall(
    vm_ptr: u32,
    nr: u64,
    arg0: u64,
    arg0_ofd_id: u32,
    arg0_ofd_type: i32,
    arg1: u64,
    arg2: u64,
    arg2_ofd_id: u32,
    arg2_ofd_type: i32,
    arg3: u64,
    result: i64,
    status: i32,
) {
    let should_record = matches!(
        nr,
        crate::abi::SYS_EPOLL_CREATE1
            | crate::abi::SYS_EPOLL_CTL
            | crate::abi::SYS_EPOLL_PWAIT
            | crate::abi::SYS_CLOSE
            | crate::abi::SYS_DUP
            | crate::abi::SYS_DUP3
            | crate::abi::SYS_PIPE2
            | crate::abi::SYS_FCNTL
    );
    if !should_record {
        return;
    }

    unsafe {
        let idx = (FD_SYSCALL_TRACE_NEXT as usize) % FD_SYSCALL_TRACE_CAP;
        FD_SYSCALL_TRACE[idx] = FdSyscallTraceEntry {
            vm_ptr,
            nr,
            arg0,
            arg0_ofd_id,
            arg0_ofd_type,
            arg1,
            arg2,
            arg2_ofd_id,
            arg2_ofd_type,
            arg3,
            result,
            status,
        };
        FD_SYSCALL_TRACE_NEXT = ((idx + 1) % FD_SYSCALL_TRACE_CAP) as u32;
        if FD_SYSCALL_TRACE_LEN < FD_SYSCALL_TRACE_CAP as u32 {
            FD_SYSCALL_TRACE_LEN += 1;
        }
    }
}

pub fn fd_syscall_trace_len() -> u32 {
    unsafe { FD_SYSCALL_TRACE_LEN }
}

pub fn fd_syscall_trace_entry(index: u32) -> FdSyscallTraceEntry {
    unsafe {
        let len = FD_SYSCALL_TRACE_LEN.min(FD_SYSCALL_TRACE_CAP as u32);
        if index >= len {
            return FdSyscallTraceEntry {
                vm_ptr: 0,
                nr: 0,
                arg0: 0,
                arg0_ofd_id: 0,
                arg0_ofd_type: 0,
                arg1: 0,
                arg2: 0,
                arg2_ofd_id: 0,
                arg2_ofd_type: 0,
                arg3: 0,
                result: 0,
                status: 0,
            };
        }
        let start = if len < FD_SYSCALL_TRACE_CAP as u32 {
            0
        } else {
            FD_SYSCALL_TRACE_NEXT % FD_SYSCALL_TRACE_CAP as u32
        };
        let idx = ((start + index) as usize) % FD_SYSCALL_TRACE_CAP;
        FD_SYSCALL_TRACE[idx]
    }
}

pub fn completed_sync_effects() -> u32 {
    unsafe { core::ptr::read(core::ptr::addr_of!(COMPLETED_SYNC_EFFECTS)) }
}

pub fn record_memory_syscall(nr: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64, result: i64) {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(MEMORY_TRACE),
            MemoryTraceSummary {
                nr,
                arg0,
                arg1,
                arg2,
                arg3,
                result,
            },
        );
    }
}

pub fn record_execve_path(path: &[u8]) {
    unsafe {
        let mut buf = [0u8; 256];
        let len = path.len().min(buf.len());
        buf[..len].copy_from_slice(&path[..len]);
        core::ptr::write(core::ptr::addr_of_mut!(LAST_EXECVE_PATH), buf);
        core::ptr::write(core::ptr::addr_of_mut!(LAST_EXECVE_LEN), len as u32);
    }
}

pub fn record_execve_stage(stage: u32, value0: u64, value1: u64) {
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(LAST_EXECVE_STAGE), stage);
        core::ptr::write(core::ptr::addr_of_mut!(LAST_EXECVE_VALUE0), value0);
        core::ptr::write(core::ptr::addr_of_mut!(LAST_EXECVE_VALUE1), value1);
    }
}

pub fn write_trace_summary() -> WriteTraceSummary {
    unsafe { *core::ptr::addr_of!(WRITE_TRACE) }
}

pub fn write_trace_ptr() -> u32 {
    unsafe { core::ptr::addr_of!(LAST_WRITE_BYTES) as u32 }
}

pub fn write_trace_len() -> u32 {
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_WRITE_BYTES_LEN)) }
}

pub fn syscall_trace_summary() -> SyscallTraceSummary {
    unsafe { *core::ptr::addr_of!(SYSCALL_TRACE) }
}

pub fn memory_trace_summary() -> MemoryTraceSummary {
    unsafe { *core::ptr::addr_of!(MEMORY_TRACE) }
}

pub fn execve_trace_ptr() -> u32 {
    unsafe { core::ptr::addr_of!(LAST_EXECVE_PATH) as u32 }
}

pub fn execve_trace_len() -> u32 {
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_EXECVE_LEN)) }
}

pub fn execve_stage() -> u32 {
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_EXECVE_STAGE)) }
}

pub fn execve_value0() -> u64 {
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_EXECVE_VALUE0)) }
}

pub fn execve_value1() -> u64 {
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_EXECVE_VALUE1)) }
}

pub fn restore_plain_fork_parent<F, E>(
    base: u32,
    guest_limit: u64,
    snapshot: &PlainForkSnapshot,
    restore_guest_memory: F,
) -> Result<(), E>
where
    F: FnOnce() -> Result<(), E>,
{
    // The runtime restores guest bytes here. Kernel-owned objects are not part
    // of the plain-fork snapshot and are reattached from the canonical owner.
    memory::flush_shared_mappings(base);
    let shared_mappings = snapshot_shared_mappings(base, guest_limit, &snapshot.mm_state);
    restore_guest_memory()?;
    memory::restore_after_plain_fork(&snapshot.mm_state);
    memory::refresh_shared_file_mappings(base, guest_limit);
    restore_shared_mappings(base, &shared_mappings);
    Ok(())
}

fn snapshot_shared_mappings(
    base: u32,
    guest_limit: u64,
    snapshot: &memory::AddressSpaceSnapshot,
) -> Vec<SharedMappingSnapshot> {
    let mut snapshots = Vec::new();

    for vma in snapshot.vmas() {
        if (vma.flags as u64 & MAP_SHARED) == 0 || vma.fd >= 0 {
            continue;
        }

        let start = vma.start.min(guest_limit);
        let end = vma.end.min(guest_limit);
        if start >= end {
            continue;
        }

        let mut bytes = vec![0u8; (end - start) as usize];
        unsafe {
            guest_mem::read_bytes(base, start, &mut bytes);
        }
        snapshots.push(SharedMappingSnapshot { start, bytes });
    }

    snapshots
}

fn restore_shared_mappings(base: u32, snapshots: &[SharedMappingSnapshot]) {
    for snapshot in snapshots {
        unsafe {
            guest_mem::write_bytes(base, snapshot.start, &snapshot.bytes);
        }
    }
}
