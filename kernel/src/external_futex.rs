//! Harness-only external futex waiter bridge.
//!
//! Deferred plain-fork children are not live in kernel thread state while the
//! parent continues executing inside the harness runner. This bridge lets
//! FUTEX_WAKE/FUTEX_CMP_REQUEUE account for those external waiters so the
//! guest-visible futex result matches the process topology the harness is
//! simulating. This is not debug instrumentation: it is the narrow adapter that
//! preserves futex return-value semantics for deferred plain-fork children.

#[cfg(any(test, all(target_arch = "wasm32", feature = "harness")))]
pub(crate) use crate::harness_support::{
    requeue_plain_fork_futex_waits, wake_plain_fork_futex_waits,
};

#[cfg(not(any(test, all(target_arch = "wasm32", feature = "harness"))))]
#[inline(always)]
pub(crate) fn wake_plain_fork_futex_waits(addr: u32, max_wake: u32) -> u32 {
    let _ = (addr, max_wake);
    0
}

#[cfg(not(any(test, all(target_arch = "wasm32", feature = "harness"))))]
#[inline(always)]
pub(crate) fn requeue_plain_fork_futex_waits(addr: u32, new_addr: u32, max_requeue: u32) -> u32 {
    let _ = (addr, new_addr, max_requeue);
    0
}
