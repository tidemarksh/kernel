//! Additive supervisor shadow protocol.
//!
//! Phase A records deterministic shadows of runtime decisions without changing
//! guest-visible behavior. Later phases can replace these no-op decisions with
//! supervisor-owned policy.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub const SUPERVISOR_ABI_VERSION: u32 = 1;
pub const SUPERVISOR_DEBUG_SNAPSHOT_BYTES: u32 = 88;
pub const SUPERVISOR_FUTEX_WAIT_COMPLETION_WOKEN: u32 = 1;
pub const SUPERVISOR_FUTEX_WAIT_COMPLETION_NOT_EQUAL: u32 = 2;
pub const SUPERVISOR_FUTEX_WAIT_COMPLETION_TIMED_OUT: u32 = 3;
pub const SUPERVISOR_FUTEX_WAIT_COMPLETION_INVALID_ADDRESS: u32 = 4;
pub const SUPERVISOR_FUTEX_WAIT_COMPLETION_SIGNAL_CHECK: u32 = 5;

const SNAPSHOT_MAGIC: u32 = 0x5055_5354; // "TSUP" little-endian.
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

static THREAD_EVENT_COUNT: AtomicU64 = AtomicU64::new(0);
static HOST_COMPLETION_COUNT: AtomicU64 = AtomicU64::new(0);
static HOST_OP_POLL_COUNT: AtomicU64 = AtomicU64::new(0);
static RESUME_POLL_COUNT: AtomicU64 = AtomicU64::new(0);
static THREAD_EVENT_LOG_HASH: AtomicU64 = AtomicU64::new(FNV_OFFSET);
static HOST_COMPLETION_LOG_HASH: AtomicU64 = AtomicU64::new(FNV_OFFSET);
static LAST_THREAD_EVENT_HASH: AtomicU64 = AtomicU64::new(0);
static LAST_HOST_COMPLETION_HASH: AtomicU64 = AtomicU64::new(0);
static LAST_THREAD_EVENT_LEN: AtomicU32 = AtomicU32::new(0);
static LAST_HOST_COMPLETION_LEN: AtomicU32 = AtomicU32::new(0);

pub fn init() {
    THREAD_EVENT_COUNT.store(0, Ordering::Relaxed);
    HOST_COMPLETION_COUNT.store(0, Ordering::Relaxed);
    HOST_OP_POLL_COUNT.store(0, Ordering::Relaxed);
    RESUME_POLL_COUNT.store(0, Ordering::Relaxed);
    THREAD_EVENT_LOG_HASH.store(FNV_OFFSET, Ordering::Relaxed);
    HOST_COMPLETION_LOG_HASH.store(FNV_OFFSET, Ordering::Relaxed);
    LAST_THREAD_EVENT_HASH.store(0, Ordering::Relaxed);
    LAST_HOST_COMPLETION_HASH.store(0, Ordering::Relaxed);
    LAST_THREAD_EVENT_LEN.store(0, Ordering::Relaxed);
    LAST_HOST_COMPLETION_LEN.store(0, Ordering::Relaxed);
}

pub fn thread_event_count() -> u64 {
    THREAD_EVENT_COUNT.load(Ordering::Relaxed)
}

pub fn host_completion_count() -> u64 {
    HOST_COMPLETION_COUNT.load(Ordering::Relaxed)
}

pub fn host_op_poll_count() -> u64 {
    HOST_OP_POLL_COUNT.load(Ordering::Relaxed)
}

pub fn resume_poll_count() -> u64 {
    RESUME_POLL_COUNT.load(Ordering::Relaxed)
}

pub fn thread_event_log_hash() -> u64 {
    THREAD_EVENT_LOG_HASH.load(Ordering::Relaxed)
}

pub fn host_completion_log_hash() -> u64 {
    HOST_COMPLETION_LOG_HASH.load(Ordering::Relaxed)
}

fn fnv_hash(bytes: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn fold_log_hash(current: &AtomicU64, entry_hash: u64, entry_len: u32) -> u64 {
    let previous = current.load(Ordering::Relaxed);
    let mut next = previous ^ entry_hash;
    next = next.wrapping_mul(FNV_PRIME);
    next ^= u64::from(entry_len);
    next = next.wrapping_mul(FNV_PRIME);
    current.store(next, Ordering::Relaxed);
    next
}

fn read_shadow_bytes(ptr: u32, len: u32) -> Result<&'static [u8], i32> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr == 0 {
        return Err(crate::abi::EFAULT as i32);
    }
    let start = ptr as usize;
    let len = len as usize;
    let end = start.checked_add(len).ok_or(crate::abi::EFAULT as i32)?;
    if end > isize::MAX as usize {
        return Err(crate::abi::EFAULT as i32);
    }
    Ok(unsafe { core::slice::from_raw_parts(start as *const u8, len) })
}

fn write_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_snapshot(out_ptr: u32, out_len: u32) -> i32 {
    if out_len == 0 {
        return SUPERVISOR_DEBUG_SNAPSHOT_BYTES as i32;
    }
    if out_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    if out_len < SUPERVISOR_DEBUG_SNAPSHOT_BYTES {
        return crate::abi::ENOSPC as i32;
    }

    let mut snapshot = [0u8; SUPERVISOR_DEBUG_SNAPSHOT_BYTES as usize];
    write_u32(&mut snapshot, 0, SNAPSHOT_MAGIC);
    write_u32(&mut snapshot, 4, SUPERVISOR_ABI_VERSION);
    write_u32(&mut snapshot, 8, SUPERVISOR_DEBUG_SNAPSHOT_BYTES);
    write_u32(&mut snapshot, 12, 0);
    write_u64(&mut snapshot, 16, thread_event_count());
    write_u64(&mut snapshot, 24, host_completion_count());
    write_u64(&mut snapshot, 32, host_op_poll_count());
    write_u64(&mut snapshot, 40, resume_poll_count());
    write_u64(&mut snapshot, 48, thread_event_log_hash());
    write_u64(&mut snapshot, 56, host_completion_log_hash());
    write_u32(
        &mut snapshot,
        64,
        LAST_THREAD_EVENT_LEN.load(Ordering::Relaxed),
    );
    write_u32(
        &mut snapshot,
        68,
        LAST_HOST_COMPLETION_LEN.load(Ordering::Relaxed),
    );
    write_u64(
        &mut snapshot,
        72,
        LAST_THREAD_EVENT_HASH.load(Ordering::Relaxed),
    );
    write_u64(
        &mut snapshot,
        80,
        LAST_HOST_COMPLETION_HASH.load(Ordering::Relaxed),
    );

    let out = unsafe {
        core::slice::from_raw_parts_mut(
            out_ptr as usize as *mut u8,
            SUPERVISOR_DEBUG_SNAPSHOT_BYTES as usize,
        )
    };
    out.copy_from_slice(&snapshot);
    SUPERVISOR_DEBUG_SNAPSHOT_BYTES as i32
}

fn thread_state_from_ptr_mut(vm_ptr: u32) -> Result<&'static mut crate::types::ThreadState, i32> {
    if vm_ptr == 0 {
        return Err(crate::abi::EFAULT as i32);
    }
    Ok(unsafe { &mut *(vm_ptr as *mut crate::types::ThreadState) })
}

fn complete_futex_wait(vm_ptr: u32, completion: u32) -> i32 {
    let vm = match thread_state_from_ptr_mut(vm_ptr) {
        Ok(vm) => vm,
        Err(errno) => return errno,
    };
    let base = vm.guest_base;
    let blocked_addr = crate::syscall::thread::thread_record_blocked_addr(vm, base);
    let signal_pending =
        crate::syscall::signal::pending_signal_interrupts_blocked_syscall(vm, base)
            || vm.sig_pending != 0;

    let result = if blocked_addr == 0 {
        Some(0)
    } else if blocked_addr == u64::MAX {
        Some(crate::abi::EAGAIN)
    } else if signal_pending || completion == SUPERVISOR_FUTEX_WAIT_COMPLETION_SIGNAL_CHECK {
        Some(crate::abi::EINTR)
    } else {
        match completion {
            SUPERVISOR_FUTEX_WAIT_COMPLETION_NOT_EQUAL => Some(0),
            SUPERVISOR_FUTEX_WAIT_COMPLETION_TIMED_OUT => Some(crate::abi::ETIMEDOUT),
            SUPERVISOR_FUTEX_WAIT_COMPLETION_INVALID_ADDRESS => Some(crate::abi::EAGAIN),
            SUPERVISOR_FUTEX_WAIT_COMPLETION_WOKEN => None,
            _ => Some(crate::abi::EINVAL),
        }
    };

    if let Some(result) = result {
        crate::syscall::thread::resume_futex_wait_result(vm, base, result);
    }
    vm.status
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_abi_version() -> u32 {
    SUPERVISOR_ABI_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_debug_snapshot_bytes() -> u32 {
    SUPERVISOR_DEBUG_SNAPSHOT_BYTES
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_futex_wait_completion_woken() -> u32 {
    SUPERVISOR_FUTEX_WAIT_COMPLETION_WOKEN
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_futex_wait_completion_not_equal() -> u32 {
    SUPERVISOR_FUTEX_WAIT_COMPLETION_NOT_EQUAL
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_futex_wait_completion_timed_out() -> u32 {
    SUPERVISOR_FUTEX_WAIT_COMPLETION_TIMED_OUT
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_futex_wait_completion_invalid_address() -> u32 {
    SUPERVISOR_FUTEX_WAIT_COMPLETION_INVALID_ADDRESS
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_futex_wait_completion_signal_check() -> u32 {
    SUPERVISOR_FUTEX_WAIT_COMPLETION_SIGNAL_CHECK
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_reset_shadow_log() {
    init();
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_thread_event_count() -> u64 {
    thread_event_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_host_completion_count() -> u64 {
    host_completion_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_host_op_poll_count() -> u64 {
    host_op_poll_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_resume_poll_count() -> u64 {
    resume_poll_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_thread_event_log_hash() -> u64 {
    thread_event_log_hash()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_host_completion_log_hash() -> u64 {
    host_completion_log_hash()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_submit_thread_event(event_ptr: u32, event_len: u32) -> i32 {
    let bytes = match read_shadow_bytes(event_ptr, event_len) {
        Ok(bytes) => bytes,
        Err(errno) => return errno,
    };
    let entry_hash = fnv_hash(bytes);
    THREAD_EVENT_COUNT.fetch_add(1, Ordering::Relaxed);
    LAST_THREAD_EVENT_HASH.store(entry_hash, Ordering::Relaxed);
    LAST_THREAD_EVENT_LEN.store(event_len, Ordering::Relaxed);
    fold_log_hash(&THREAD_EVENT_LOG_HASH, entry_hash, event_len);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_complete_host_op(completion_ptr: u32, completion_len: u32) -> i32 {
    let bytes = match read_shadow_bytes(completion_ptr, completion_len) {
        Ok(bytes) => bytes,
        Err(errno) => return errno,
    };
    let entry_hash = fnv_hash(bytes);
    HOST_COMPLETION_COUNT.fetch_add(1, Ordering::Relaxed);
    LAST_HOST_COMPLETION_HASH.store(entry_hash, Ordering::Relaxed);
    LAST_HOST_COMPLETION_LEN.store(completion_len, Ordering::Relaxed);
    fold_log_hash(&HOST_COMPLETION_LOG_HASH, entry_hash, completion_len);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_complete_futex_wait(vm_ptr: u32, completion: u32) -> i32 {
    complete_futex_wait(vm_ptr, completion)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_next_host_op(_out_ptr: u32, _out_len: u32) -> i32 {
    HOST_OP_POLL_COUNT.fetch_add(1, Ordering::Relaxed);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_next_resume(_out_ptr: u32, _out_len: u32) -> i32 {
    RESUME_POLL_COUNT.fetch_add(1, Ordering::Relaxed);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_debug_snapshot(out_ptr: u32, out_len: u32) -> i32 {
    write_snapshot(out_ptr, out_len)
}
