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

fn find_event(vm_ptr: u32, tid: u32) -> Option<ThreadEventState> {
    if vm_ptr == 0 {
        return None;
    }
    with_state_lock(|| unsafe {
        let table = core::ptr::addr_of!(THREAD_EVENT_STATE) as *const ThreadEventState;
        for idx in 0..THREAD_EVENT_STATE_CAP {
            let current = core::ptr::read(table.add(idx));
            if current.vm_ptr == vm_ptr && (tid == 0 || current.tid == tid) {
                return Some(current);
            }
        }
        None
    })
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
    let entry_hash = super::fnv_hash(bytes);
    let arrival_seq = super::THREAD_EVENT_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    super::LAST_THREAD_EVENT_HASH.store(entry_hash, Ordering::Relaxed);
    super::LAST_THREAD_EVENT_LEN.store(event_len, Ordering::Relaxed);
    super::fold_log_hash(&super::THREAD_EVENT_LOG_HASH, entry_hash, event_len);
    if let Some(event) = decode(bytes, arrival_seq) {
        store_event(event);
    }
    0
}

pub(super) fn suppresses_runnable(vm_ptr: u32, tid: u32) -> bool {
    let Some(event) = find_event(vm_ptr, tid) else {
        return false;
    };
    let _ = (
        event.pid,
        event.status,
        event.sequence,
        event.arrival_seq,
        event.sync_effects,
        event.blocked_reason,
        event.pc,
        event.sp,
        event.detail,
    );
    matches!(
        event.event_kind,
        super::SUPERVISOR_THREAD_EVENT_KIND_BLOCKED
            | super::SUPERVISOR_THREAD_EVENT_KIND_FAULTED
            | super::SUPERVISOR_THREAD_EVENT_KIND_EXITED
    )
}
