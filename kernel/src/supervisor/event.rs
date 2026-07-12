use core::sync::atomic::{AtomicU32, Ordering};

const THREAD_EVENT_STATE_CAP: usize = 256;

#[derive(Clone, Copy)]
struct ThreadEventState {
    vm_ptr: u32,
    pid: u32,
    tid: u32,
    status: u32,
    event_kind: u32,
    sequence: u64,
    arrival_seq: u64,
    sync_effects: u32,
    blocked_reason: u32,
    pc: u64,
    sp: u64,
    detail: u64,
}

pub(super) struct ThreadEventOverride {
    pub(super) state: u32,
    pub(super) status: u32,
    pub(super) blocked_addr: u64,
}

impl ThreadEventState {
    const fn empty() -> Self {
        Self {
            vm_ptr: 0,
            pid: 0,
            tid: 0,
            status: 0,
            event_kind: 0,
            sequence: 0,
            arrival_seq: 0,
            sync_effects: 0,
            blocked_reason: 0,
            pc: 0,
            sp: 0,
            detail: 0,
        }
    }
}

static THREAD_EVENT_STATE_LOCK: AtomicU32 = AtomicU32::new(0);
static THREAD_EVENT_STATE_REPLACE_CURSOR: AtomicU32 = AtomicU32::new(0);
static mut THREAD_EVENT_STATE: [ThreadEventState; THREAD_EVENT_STATE_CAP] =
    [ThreadEventState::empty(); THREAD_EVENT_STATE_CAP];

fn with_state_lock<T>(f: impl FnOnce() -> T) -> T {
    loop {
        if THREAD_EVENT_STATE_LOCK
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            break;
        }
        core::hint::spin_loop();
    }
    let result = f();
    THREAD_EVENT_STATE_LOCK.store(0, Ordering::Release);
    result
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let chunk = bytes.get(offset..end)?;
    Some(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let chunk = bytes.get(offset..end)?;
    Some(u64::from_le_bytes([
        chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
    ]))
}

fn decode(bytes: &[u8], arrival_seq: u64) -> Option<ThreadEventState> {
    if bytes.len() < super::SUPERVISOR_THREAD_EVENT_RECORD_BYTES as usize {
        return None;
    }
    if read_u32(bytes, 0)? != super::SUPERVISOR_THREAD_EVENT_RECORD_MAGIC {
        return None;
    }
    if read_u32(bytes, 4)? != super::SUPERVISOR_ABI_VERSION {
        return None;
    }
    let record_len = read_u32(bytes, 8)?;
    if record_len < super::SUPERVISOR_THREAD_EVENT_RECORD_BYTES {
        return None;
    }
    let vm_ptr = read_u64(bytes, 24)?;
    if vm_ptr == 0 || vm_ptr > u32::MAX as u64 {
        return None;
    }
    Some(ThreadEventState {
        vm_ptr: vm_ptr as u32,
        pid: read_u32(bytes, 32)?,
        tid: read_u32(bytes, 36)?,
        status: read_u32(bytes, 40)?,
        event_kind: read_u32(bytes, 12)?,
        sequence: read_u64(bytes, 16)?,
        arrival_seq,
        sync_effects: read_u32(bytes, 44)?,
        blocked_reason: read_u32(bytes, 48)?,
        pc: read_u64(bytes, 56)?,
        sp: read_u64(bytes, 64)?,
        detail: read_u64(bytes, 72)?,
    })
}

fn store_event(event: ThreadEventState) {
    with_state_lock(|| unsafe {
        let table = core::ptr::addr_of_mut!(THREAD_EVENT_STATE) as *mut ThreadEventState;
        let mut empty_slot: Option<usize> = None;
        for idx in 0..THREAD_EVENT_STATE_CAP {
            let current = core::ptr::read(table.add(idx));
            if current.vm_ptr == event.vm_ptr {
                core::ptr::write(table.add(idx), event);
                return;
            }
            if current.vm_ptr == 0 && empty_slot.is_none() {
                empty_slot = Some(idx);
            }
        }
        let idx = empty_slot.unwrap_or_else(|| {
            let cursor = THREAD_EVENT_STATE_REPLACE_CURSOR.fetch_add(1, Ordering::Relaxed);
            cursor as usize % THREAD_EVENT_STATE_CAP
        });
        core::ptr::write(table.add(idx), event);
    });
}

fn stale_after_authoritative_transition(event: ThreadEventState) -> bool {
    if event.event_kind != super::SUPERVISOR_THREAD_EVENT_KIND_BLOCKED {
        return false;
    }
    super::thread::state_from_ptr(event.vm_ptr)
        .is_some_and(|thread| thread.status as u32 != event.status)
}

fn find_event(vm_ptr: u32, tid: u32) -> Option<ThreadEventState> {
    if vm_ptr == 0 {
        return None;
    }
    with_state_lock(|| unsafe {
        let table = core::ptr::addr_of!(THREAD_EVENT_STATE) as *const ThreadEventState;
        for idx in 0..THREAD_EVENT_STATE_CAP {
            let current = core::ptr::read(table.add(idx));
            if current.vm_ptr == vm_ptr && (tid == 0 || current.tid == 0 || current.tid == tid) {
                return Some(current);
            }
        }
        None
    })
}

fn event_state_override(event: ThreadEventState) -> Option<ThreadEventOverride> {
    let state = match event.event_kind {
        super::SUPERVISOR_THREAD_EVENT_KIND_BLOCKED => {
            if event.status == crate::abi::STATUS_FUTEX_WAIT as u32 {
                crate::types::THREAD_BLOCKED_FUTEX as u32
            } else {
                crate::types::THREAD_BLOCKED_POLL as u32
            }
        }
        super::SUPERVISOR_THREAD_EVENT_KIND_READY
        | super::SUPERVISOR_THREAD_EVENT_KIND_HOST_COMPLETION_ARRIVED
        | super::SUPERVISOR_THREAD_EVENT_KIND_BACKING_STORE_READY => {
            crate::types::THREAD_RUNNING as u32
        }
        super::SUPERVISOR_THREAD_EVENT_KIND_FAULTED => crate::types::THREAD_EXITING as u32,
        super::SUPERVISOR_THREAD_EVENT_KIND_EXITED => crate::types::THREAD_DEAD as u32,
        _ => return None,
    };
    Some(ThreadEventOverride {
        state,
        status: event.status,
        blocked_addr: event.detail,
    })
}

pub(super) fn thread_state_override(vm_ptr: u32, tid: u32) -> Option<ThreadEventOverride> {
    find_event(vm_ptr, tid).and_then(event_state_override)
}

pub(super) fn runnable_override(vm_ptr: u32, tid: u32) -> Option<bool> {
    let event = find_event(vm_ptr, tid)?;
    let _ = (
        event.pid,
        event.sequence,
        event.arrival_seq,
        event.sync_effects,
        event.blocked_reason,
        event.pc,
        event.sp,
    );
    match event.event_kind {
        super::SUPERVISOR_THREAD_EVENT_KIND_READY => Some(true),
        super::SUPERVISOR_THREAD_EVENT_KIND_HOST_COMPLETION_ARRIVED
        | super::SUPERVISOR_THREAD_EVENT_KIND_BACKING_STORE_READY => Some(true),
        super::SUPERVISOR_THREAD_EVENT_KIND_BLOCKED
        | super::SUPERVISOR_THREAD_EVENT_KIND_FAULTED
        | super::SUPERVISOR_THREAD_EVENT_KIND_EXITED => Some(false),
        _ => None,
    }
}

pub(super) fn clear_woken_futex_override(vm_ptr: u32, tid: u32) {
    if vm_ptr == 0 || tid == 0 {
        return;
    }
    with_state_lock(|| unsafe {
        let table = core::ptr::addr_of_mut!(THREAD_EVENT_STATE) as *mut ThreadEventState;
        for idx in 0..THREAD_EVENT_STATE_CAP {
            let current = core::ptr::read(table.add(idx));
            if current.vm_ptr != vm_ptr || (current.tid != 0 && current.tid != tid) {
                continue;
            }
            if current.event_kind == super::SUPERVISOR_THREAD_EVENT_KIND_BLOCKED
                && current.status == crate::abi::STATUS_FUTEX_WAIT as u32
            {
                core::ptr::write(table.add(idx), ThreadEventState::empty());
            }
            return;
        }
    });
}

pub(super) fn init_state() {
    THREAD_EVENT_STATE_REPLACE_CURSOR.store(0, Ordering::Relaxed);
    with_state_lock(|| unsafe {
        let table = core::ptr::addr_of_mut!(THREAD_EVENT_STATE) as *mut ThreadEventState;
        for idx in 0..THREAD_EVENT_STATE_CAP {
            core::ptr::write(table.add(idx), ThreadEventState::empty());
        }
    });
}

pub(super) fn submit(event_ptr: u32, event_len: u32) -> i32 {
    let bytes = match super::read_shadow_bytes(event_ptr, event_len) {
        Ok(bytes) => bytes,
        Err(errno) => return errno,
    };
    let arrival_seq = super::log::record_thread_event(bytes, event_len);
    if let Some(event) = decode(bytes, arrival_seq) {
        if !stale_after_authoritative_transition(event) {
            store_event(event);
        }
    }
    0
}
