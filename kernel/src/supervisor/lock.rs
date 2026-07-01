use core::sync::atomic::{AtomicU32, Ordering};

pub(super) fn with_spin_lock<T>(lock: &AtomicU32, f: impl FnOnce() -> T) -> T {
    loop {
        if lock
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            break;
        }
        core::hint::spin_loop();
    }
    let result = f();
    lock.store(0, Ordering::Release);
    result
}
