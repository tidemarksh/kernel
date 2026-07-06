use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
const REPLAY_LOG_CAP: usize = super::SUPERVISOR_REPLAY_LOG_CAPACITY as usize;
const REPLAY_PAYLOAD_BYTES: usize = super::SUPERVISOR_REPLAY_LOG_PAYLOAD_BYTES as usize;

static THREAD_EVENT_COUNT: AtomicU64 = AtomicU64::new(0);
static HOST_COMPLETION_COUNT: AtomicU64 = AtomicU64::new(0);
static THREAD_EVENT_LOG_HASH: AtomicU64 = AtomicU64::new(FNV_OFFSET);
static HOST_COMPLETION_LOG_HASH: AtomicU64 = AtomicU64::new(FNV_OFFSET);
static HOST_OP_LOG_HASH: AtomicU64 = AtomicU64::new(FNV_OFFSET);
static LAST_THREAD_EVENT_HASH: AtomicU64 = AtomicU64::new(0);
static LAST_HOST_COMPLETION_HASH: AtomicU64 = AtomicU64::new(0);
static LAST_HOST_OP_HASH: AtomicU64 = AtomicU64::new(0);
static LAST_THREAD_EVENT_LEN: AtomicU32 = AtomicU32::new(0);
static LAST_HOST_COMPLETION_LEN: AtomicU32 = AtomicU32::new(0);
static LAST_HOST_OP_LEN: AtomicU32 = AtomicU32::new(0);
static REPLAY_LOG_LOCK: AtomicU32 = AtomicU32::new(0);
static REPLAY_LOG_COUNT: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
pub(super) struct ReplayLogEntry {
    pub(super) source: u32,
    pub(super) payload_len: u32,
    pub(super) log_seq: u64,
    pub(super) record_seq: u64,
    pub(super) entry_hash: u64,
    pub(super) payload: [u8; REPLAY_PAYLOAD_BYTES],
}

impl ReplayLogEntry {
    pub(super) const fn empty() -> Self {
        Self {
            source: 0,
            payload_len: 0,
            log_seq: 0,
            record_seq: 0,
            entry_hash: 0,
            payload: [0; REPLAY_PAYLOAD_BYTES],
        }
    }
}

static mut REPLAY_LOG: [ReplayLogEntry; REPLAY_LOG_CAP] = [ReplayLogEntry::empty(); REPLAY_LOG_CAP];

fn with_replay_log_lock<T>(f: impl FnOnce() -> T) -> T {
    loop {
        if REPLAY_LOG_LOCK
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            break;
        }
        core::hint::spin_loop();
    }
    let result = f();
    REPLAY_LOG_LOCK.store(0, Ordering::Release);
    result
}

pub(super) fn init() {
    THREAD_EVENT_COUNT.store(0, Ordering::Relaxed);
    HOST_COMPLETION_COUNT.store(0, Ordering::Relaxed);
    THREAD_EVENT_LOG_HASH.store(FNV_OFFSET, Ordering::Relaxed);
    HOST_COMPLETION_LOG_HASH.store(FNV_OFFSET, Ordering::Relaxed);
    HOST_OP_LOG_HASH.store(FNV_OFFSET, Ordering::Relaxed);
    LAST_THREAD_EVENT_HASH.store(0, Ordering::Relaxed);
    LAST_HOST_COMPLETION_HASH.store(0, Ordering::Relaxed);
    LAST_HOST_OP_HASH.store(0, Ordering::Relaxed);
    LAST_THREAD_EVENT_LEN.store(0, Ordering::Relaxed);
    LAST_HOST_COMPLETION_LEN.store(0, Ordering::Relaxed);
    LAST_HOST_OP_LEN.store(0, Ordering::Relaxed);
    REPLAY_LOG_COUNT.store(0, Ordering::Relaxed);
    with_replay_log_lock(|| unsafe {
        let log_ptr = core::ptr::addr_of_mut!(REPLAY_LOG) as *mut ReplayLogEntry;
        for idx in 0..REPLAY_LOG_CAP {
            core::ptr::write(log_ptr.add(idx), ReplayLogEntry::empty());
        }
    });
}

pub(super) fn thread_event_count() -> u64 {
    THREAD_EVENT_COUNT.load(Ordering::Relaxed)
}

pub(super) fn host_completion_count() -> u64 {
    HOST_COMPLETION_COUNT.load(Ordering::Relaxed)
}

pub(super) fn thread_event_log_hash() -> u64 {
    THREAD_EVENT_LOG_HASH.load(Ordering::Relaxed)
}

pub(super) fn host_completion_log_hash() -> u64 {
    HOST_COMPLETION_LOG_HASH.load(Ordering::Relaxed)
}

pub(super) fn host_op_log_hash() -> u64 {
    HOST_OP_LOG_HASH.load(Ordering::Relaxed)
}

pub(super) fn last_thread_event_hash() -> u64 {
    LAST_THREAD_EVENT_HASH.load(Ordering::Relaxed)
}

pub(super) fn last_host_completion_hash() -> u64 {
    LAST_HOST_COMPLETION_HASH.load(Ordering::Relaxed)
}

pub(super) fn last_host_op_hash() -> u64 {
    LAST_HOST_OP_HASH.load(Ordering::Relaxed)
}

pub(super) fn last_thread_event_len() -> u32 {
    LAST_THREAD_EVENT_LEN.load(Ordering::Relaxed)
}

pub(super) fn last_host_completion_len() -> u32 {
    LAST_HOST_COMPLETION_LEN.load(Ordering::Relaxed)
}

pub(super) fn last_host_op_len() -> u32 {
    LAST_HOST_OP_LEN.load(Ordering::Relaxed)
}

pub(super) fn replay_log_total_count() -> u64 {
    REPLAY_LOG_COUNT.load(Ordering::Relaxed)
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

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let slice = bytes.get(offset..end)?;
    Some(u64::from_le_bytes(slice.try_into().ok()?))
}

fn record_seq_from_payload(encoded: &[u8], fallback: u64) -> u64 {
    read_u64(encoded, 16).unwrap_or(fallback)
}

fn record_replay_entry(source: u32, encoded: &[u8], record_seq: u64, entry_hash: u64) {
    let log_seq = REPLAY_LOG_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    let payload_len = encoded.len().min(REPLAY_PAYLOAD_BYTES);
    let mut entry = ReplayLogEntry {
        source,
        payload_len: payload_len as u32,
        log_seq,
        record_seq,
        entry_hash,
        payload: [0; REPLAY_PAYLOAD_BYTES],
    };
    entry.payload[..payload_len].copy_from_slice(&encoded[..payload_len]);

    with_replay_log_lock(|| unsafe {
        let index = ((log_seq - 1) % REPLAY_LOG_CAP as u64) as usize;
        let log_ptr = core::ptr::addr_of_mut!(REPLAY_LOG) as *mut ReplayLogEntry;
        core::ptr::write(log_ptr.add(index), entry);
    });
}

pub(super) fn copy_replay_log_entries(out: &mut [ReplayLogEntry; REPLAY_LOG_CAP]) -> u32 {
    with_replay_log_lock(|| unsafe {
        let total = REPLAY_LOG_COUNT.load(Ordering::Relaxed);
        let count = (total.min(REPLAY_LOG_CAP as u64)) as usize;
        let first_log_seq = total.saturating_sub(count as u64) + 1;
        let log_ptr = core::ptr::addr_of!(REPLAY_LOG) as *const ReplayLogEntry;
        for idx in 0..REPLAY_LOG_CAP {
            out[idx] = ReplayLogEntry::empty();
        }
        for idx in 0..count {
            let log_seq = first_log_seq + idx as u64;
            let ring_index = ((log_seq - 1) % REPLAY_LOG_CAP as u64) as usize;
            out[idx] = core::ptr::read(log_ptr.add(ring_index));
        }
        count as u32
    })
}

pub(super) fn record_thread_event(encoded: &[u8], entry_len: u32) -> u64 {
    let entry_hash = fnv_hash(encoded);
    let arrival_seq = THREAD_EVENT_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    LAST_THREAD_EVENT_HASH.store(entry_hash, Ordering::Relaxed);
    LAST_THREAD_EVENT_LEN.store(entry_len, Ordering::Relaxed);
    fold_log_hash(&THREAD_EVENT_LOG_HASH, entry_hash, entry_len);
    record_replay_entry(
        super::SUPERVISOR_REPLAY_LOG_SOURCE_THREAD_EVENT,
        encoded,
        record_seq_from_payload(encoded, arrival_seq),
        entry_hash,
    );
    arrival_seq
}

pub(super) fn record_host_completion(encoded: &[u8], entry_len: u32) {
    let entry_hash = fnv_hash(encoded);
    let count = HOST_COMPLETION_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    LAST_HOST_COMPLETION_HASH.store(entry_hash, Ordering::Relaxed);
    LAST_HOST_COMPLETION_LEN.store(entry_len, Ordering::Relaxed);
    fold_log_hash(&HOST_COMPLETION_LOG_HASH, entry_hash, entry_len);
    record_replay_entry(
        super::SUPERVISOR_REPLAY_LOG_SOURCE_HOST_COMPLETION,
        encoded,
        record_seq_from_payload(encoded, count),
        entry_hash,
    );
}

pub(super) fn record_host_op(encoded: &[u8], entry_len: u32) {
    let entry_hash = fnv_hash(encoded);
    LAST_HOST_OP_HASH.store(entry_hash, Ordering::Relaxed);
    LAST_HOST_OP_LEN.store(entry_len, Ordering::Relaxed);
    fold_log_hash(&HOST_OP_LOG_HASH, entry_hash, entry_len);
    record_replay_entry(
        super::SUPERVISOR_REPLAY_LOG_SOURCE_HOST_OP,
        encoded,
        record_seq_from_payload(encoded, 0),
        entry_hash,
    );
}
