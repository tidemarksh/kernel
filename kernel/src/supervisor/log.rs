use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

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

pub(super) fn record_thread_event(encoded: &[u8], entry_len: u32) -> u64 {
    let entry_hash = fnv_hash(encoded);
    let arrival_seq = THREAD_EVENT_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    LAST_THREAD_EVENT_HASH.store(entry_hash, Ordering::Relaxed);
    LAST_THREAD_EVENT_LEN.store(entry_len, Ordering::Relaxed);
    fold_log_hash(&THREAD_EVENT_LOG_HASH, entry_hash, entry_len);
    arrival_seq
}

pub(super) fn record_host_completion(encoded: &[u8], entry_len: u32) {
    let entry_hash = fnv_hash(encoded);
    HOST_COMPLETION_COUNT.fetch_add(1, Ordering::Relaxed);
    LAST_HOST_COMPLETION_HASH.store(entry_hash, Ordering::Relaxed);
    LAST_HOST_COMPLETION_LEN.store(entry_len, Ordering::Relaxed);
    fold_log_hash(&HOST_COMPLETION_LOG_HASH, entry_hash, entry_len);
}

pub(super) fn record_host_op(encoded: &[u8], entry_len: u32) {
    let entry_hash = fnv_hash(encoded);
    LAST_HOST_OP_HASH.store(entry_hash, Ordering::Relaxed);
    LAST_HOST_OP_LEN.store(entry_len, Ordering::Relaxed);
    fold_log_hash(&HOST_OP_LOG_HASH, entry_hash, entry_len);
}
