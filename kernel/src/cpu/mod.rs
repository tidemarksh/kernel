//! CPU execution engine: interpreter + block cache + JIT integration.
//!
//! Reference: RISC-V ISA spec V20191213
//!   https://github.com/riscv/riscv-isa-manual/releases/tag/Ratified-IMAFDQC
//!   RV64I (§5), M (§7), A (§8), F (§11), D (§12), C (§16)
//!
//! exec() is the main interpreter loop. It runs `budget` instructions,
//! then returns to the caller. Block cache amortizes decode cost.
//! JIT hooks (trace recording, JIT_READY handoff) are integrated
//! but disabled until the JIT compiler.

mod atomic;
pub mod block_cache;
mod block_exec;
mod csr;
pub mod decode;
mod dispatch;
mod fault;
mod fp;
mod integer;
mod system;
pub mod trace;

use self::block_cache::BlockCache;
use self::dispatch::{StepOutcome, exec_decoded};
use self::fault::{deliver_sync_sigsegv, guest_range_in_bounds};
use self::trace::{HotCounts, JitBitmap, TraceBuffer};
use crate::abi;
use crate::guest_mem;
use crate::types::ThreadState;

const REG_WRITE_SOURCE_STEP: u32 = 1;
const REG_WRITE_SOURCE_VM_RESTORE: u32 = 2;

/// Execute up to `budget` guest instructions.
/// Returns remaining budget (negative = overrun).
///
/// STATUS is set in `vm.status` when execution stops early:
///   STATUS_FAULT — illegal instruction, ECALL, or exit
///   STATUS_FS — FS syscall pending
///   STATUS_JIT_READY — JIT code available for current PC
///
/// # Safety
/// `vm` must point to a valid ThreadState. Guest memory must be accessible.
pub unsafe fn exec(
    vm: &mut ThreadState,
    budget: i32,
    cache: Option<&mut BlockCache>,
    hot_counts: Option<&mut HotCounts>,
    jit_bitmap: Option<&JitBitmap>,
    trace_buf: Option<&mut TraceBuffer>,
) -> i32 {
    unsafe {
        exec_at_base(
            vm,
            budget,
            ram_base(vm),
            cache,
            hot_counts,
            jit_bitmap,
            trace_buf,
        )
    }
}

/// Execute up to `budget` guest instructions from a caller-specified RAM base.
///
/// The production runtime always uses RAM base 0. Tests may place guest RAM at
/// a non-zero offset to avoid overlapping the host WASI runtime's own memory.
///
/// # Safety
/// `vm` must point to a valid ThreadState. Guest memory at `base..` must be
/// accessible for the guest address space referenced by the thread.
pub unsafe fn exec_at_base(
    vm: &mut ThreadState,
    budget: i32,
    base: u32,
    mut cache: Option<&mut BlockCache>,
    mut hot_counts: Option<&mut HotCounts>,
    jit_bitmap: Option<&JitBitmap>,
    mut trace_buf: Option<&mut TraceBuffer>,
) -> i32 {
    unsafe {
        let mut pc = vm.pc;
        let mut x = vm.x;
        let mut f = vm.f;
        let mut fcsr = vm.fcsr;
        let mut remaining = budget;

        loop {
            if remaining <= 0 {
                // Budget boundary: check pending signals (RISC-V ISA spec + Linux semantics)
                // WASM has no async interrupts, so check at budget boundaries in addition
                // to syscall return boundaries.
                let prev_sp = x[2];
                let prev_tp = x[4];
                let prev_s11 = x[27];
                vm.x = x;
                vm.f = f;
                vm.pc = pc;
                vm.fcsr = fcsr;
                if crate::syscall::signal::check_pending(vm, base) {
                    x = vm.x;
                    f = vm.f;
                    pc = vm.pc;
                    fcsr = vm.fcsr;
                    crate::harness_hooks::record_special_reg_transitions(
                        vm.tid,
                        pc,
                        0,
                        REG_WRITE_SOURCE_VM_RESTORE,
                        prev_sp,
                        prev_tp,
                        prev_s11,
                        &x,
                    );
                    if vm.status != abi::STATUS_OK {
                        return remaining;
                    }
                }
                break;
            }
            remaining -= 1;
            let prev_sp = x[2];
            let prev_tp = x[4];
            let prev_s11 = x[27];
            let instr_pc = pc;

            // Fetch instruction
            crate::syscall::signal::note_pc(vm, pc);
            if crate::syscall::signal::is_current_sigreturn_trampoline(x[2], pc) {
                vm.x = x;
                vm.f = f;
                vm.pc = pc;
                vm.fcsr = fcsr;
                crate::syscall::signal::sys_rt_sigreturn(vm, base);
                x = vm.x;
                f = vm.f;
                pc = vm.pc;
                fcsr = vm.fcsr;
                crate::harness_hooks::record_special_reg_transitions(
                    vm.tid,
                    instr_pc,
                    0,
                    REG_WRITE_SOURCE_VM_RESTORE,
                    prev_sp,
                    prev_tp,
                    prev_s11,
                    &x,
                );
                x[0] = 0;
                crate::harness_hooks::record_zero_reg_transition(
                    vm.tid, instr_pc, 0, prev_sp, prev_s11, &x,
                );
                continue;
            }
            if !crate::syscall::memory::guest_range_permitted(pc, 2, abi::PROT_EXEC) {
                let fault_addr = pc;
                let accerr = guest_range_in_bounds(base, pc, 2);
                if !deliver_sync_sigsegv(
                    vm, &mut x, &mut f, &mut fcsr, &mut pc, base, fault_addr, accerr,
                ) {
                    return remaining;
                }
                continue;
            }
            let raw16 = guest_mem::read_u16(base, pc);
            let (raw, step): (u32, u64) = if (raw16 & 3) != 3 {
                // Compressed (RVC)
                let expanded = decode::expand_compressed(raw16);
                if expanded == 0 {
                    // Invalid compressed instruction → SIGILL
                    vm.x = x;
                    vm.f = f;
                    vm.pc = pc;
                    vm.fcsr = fcsr;
                    crate::syscall::signal::queue_sigill(vm, pc);
                    crate::syscall::signal::check_pending(vm, base);
                    x = vm.x;
                    f = vm.f;
                    pc = vm.pc;
                    fcsr = vm.fcsr;
                    crate::harness_hooks::record_special_reg_transitions(
                        vm.tid,
                        instr_pc,
                        raw16 as u32,
                        REG_WRITE_SOURCE_VM_RESTORE,
                        prev_sp,
                        prev_tp,
                        prev_s11,
                        &x,
                    );
                    if vm.status != abi::STATUS_OK {
                        return remaining;
                    }
                    // If handler returned, skip the instruction
                    continue;
                }
                (expanded, 2)
            } else {
                if !crate::syscall::memory::guest_range_permitted(pc, 4, abi::PROT_EXEC) {
                    let fault_addr = pc;
                    let accerr = guest_range_in_bounds(base, pc, 4);
                    if !deliver_sync_sigsegv(
                        vm, &mut x, &mut f, &mut fcsr, &mut pc, base, fault_addr, accerr,
                    ) {
                        return remaining;
                    }
                    continue;
                }
                (guest_mem::read_u32(base, pc), 4)
            };

            // --- Trace recording (JIT the JIT compiler hook) ---
            if let Some(ref mut tb) = trace_buf
                && tb.recording != 0
                && tb.record(pc, raw, step as u32)
            {
                // Buffer full → stop recording, signal trace ready
                tb.stop();
                vm.x = x;
                vm.f = f;
                vm.pc = pc;
                vm.status = abi::STATUS_JIT_READY;
                return remaining;
            }

            crate::harness_hooks::record_exec_trace(instr_pc, raw, step, &x);
            match exec_decoded(
                vm,
                raw,
                step,
                instr_pc,
                base,
                &mut x,
                &mut f,
                &mut fcsr,
                &mut pc,
                &mut remaining,
                cache.as_deref_mut(),
                hot_counts.as_deref_mut(),
                jit_bitmap,
                trace_buf.as_deref_mut(),
                prev_sp,
                prev_tp,
                prev_s11,
            ) {
                StepOutcome::Advance => {}
                StepOutcome::Restart => continue,
                StepOutcome::Return(remaining) => return remaining,
            }

            // Enforce x0 = 0
            x[0] = 0;
            crate::harness_hooks::record_special_reg_transitions(
                vm.tid,
                instr_pc,
                raw,
                REG_WRITE_SOURCE_STEP,
                prev_sp,
                prev_tp,
                prev_s11,
                &x,
            );
            crate::harness_hooks::record_zero_reg_transition(
                vm.tid, instr_pc, raw, prev_sp, prev_s11, &x,
            );
        }

        vm.x = x;
        vm.f = f;
        vm.pc = pc;
        vm.fcsr = fcsr;
        // Advance monotonic clock by instructions executed
        let executed = (budget - remaining) as u64;
        crate::syscall::time::advance_monotonic(executed);
        remaining
    }
}

/// Get RAM base address. Always 0 because each thread-worker WASM instance
/// imports the per-process shared Memory as memory index 0. The base of
/// guest memory is the base of WASM linear memory.
#[inline(always)]
fn ram_base(vm: &ThreadState) -> u32 {
    vm.guest_base
}

#[cfg(test)]
mod tests;
