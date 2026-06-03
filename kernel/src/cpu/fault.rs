//! Guest memory bounds and synchronous fault delivery helpers.
//!
//! Reference: RISC-V ISA spec V20191213
//!   (https://github.com/riscv/riscv-isa-manual/releases/tag/Ratified-IMAFDQC)
//!   §2 (RV32I), §5 (RV64I)
//!
//! These helpers keep guest address validation and synchronous SIGSEGV
//! delivery out of the main exec loop.

use crate::abi;
use crate::types::ThreadState;

// =============================================================================
// Guest memory bounds
// =============================================================================

/// Return the guest-visible byte length of the shared linear memory.
#[inline(always)]
fn guest_memory_limit(base: u32) -> u64 {
    crate::wasm::memory_size_bytes().saturating_sub(base as u64)
}

/// Check whether `[addr, addr + len)` lies within guest memory.
#[inline(always)]
pub(super) fn guest_range_in_bounds(base: u32, addr: u64, len: u64) -> bool {
    let limit = guest_memory_limit(base);
    addr.checked_add(len).is_some_and(|end| end <= limit)
}

/// Result of validating a guest memory access before instruction execution.
pub(super) enum AccessOutcome {
    /// The access is valid and execution may proceed.
    Ok,
    /// A synchronous signal was delivered and the interpreter should restart.
    Restart,
    /// Execution must stop and return to the caller.
    Return,
}

/// Validate a guest memory access and deliver SIGSEGV on failure.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn ensure_guest_access(
    vm: &mut ThreadState,
    x: &mut [u64; 32],
    f: &mut [u64; 32],
    fcsr: &mut u32,
    pc: &mut u64,
    base: u32,
    addr: u64,
    width: u64,
    prot: i32,
) -> AccessOutcome {
    let permitted =
        width != 0 && crate::syscall::memory::guest_range_permitted(vm, base, addr, width, prot);
    if !permitted {
        let in_bounds = width != 0 && guest_range_in_bounds(base, addr, width);
        let accerr = in_bounds
            && crate::syscall::memory::has_prot_none()
            && crate::syscall::memory::is_prot_none(addr);
        unsafe {
            if !deliver_sync_sigsegv(vm, x, f, fcsr, pc, base, addr, accerr) {
                return AccessOutcome::Return;
            }
        }
        return AccessOutcome::Restart;
    }
    AccessOutcome::Ok
}

// =============================================================================
// Synchronous signal delivery
// =============================================================================

/// Deliver a synchronous SIGSEGV and reload thread register state from `vm`.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn deliver_sync_sigsegv(
    vm: &mut ThreadState,
    x: &mut [u64; 32],
    f: &mut [u64; 32],
    fcsr: &mut u32,
    pc: &mut u64,
    base: u32,
    addr: u64,
    accerr: bool,
) -> bool {
    crate::tracepoints::record_fault_dispatch_trace(vm, 1, *pc, x[1], x[2], x[27], addr);
    vm.x = *x;
    vm.f = *f;
    vm.pc = *pc;
    vm.fcsr = *fcsr;
    crate::tracepoints::record_sync_signal_trace(vm, *pc, x[1], x[2], x[27], x[10], addr);
    crate::syscall::signal::queue_sigsegv(vm, *pc, addr, accerr);
    crate::syscall::signal::check_pending(vm, base);
    crate::tracepoints::record_fault_dispatch_trace(vm, 2, vm.pc, vm.x[1], vm.x[2], vm.x[27], addr);
    *x = vm.x;
    *f = vm.f;
    *pc = vm.pc;
    *fcsr = vm.fcsr;
    vm.status == abi::STATUS_OK
}
