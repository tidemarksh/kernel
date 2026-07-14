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

use self::block_cache::{BLOCK_LOOP_SIMPLE_LOAD_SCAN, BlockCache};
use self::block_exec::{BlockOutcome, exec_block, exec_simple_load_scan_loop};
use self::dispatch::{StepOutcome, exec_decoded};
use self::fault::{AccessPermitCache, deliver_sync_sigsegv, guest_range_in_bounds};
use self::trace::{HotCounts, JitBitmap, TraceBuffer};
use crate::abi;
use crate::guest_mem;
use crate::types::ThreadState;

const REG_WRITE_SOURCE_STEP: u32 = 1;
const REG_WRITE_SOURCE_VM_RESTORE: u32 = 2;

#[inline(always)]
pub(super) fn normalize_x0(x: &mut [u64; 32]) {
    x[0] = 0;
}

struct ExecLoopCtx<'a> {
    vm: &'a mut ThreadState,
    base: u32,
    pc: &'a mut u64,
    x: &'a mut [u64; 32],
    f: &'a mut [u64; 32],
    fcsr: &'a mut u32,
    remaining: &'a mut i32,
    cache: Option<&'a mut BlockCache>,
    hot_counts: Option<&'a mut HotCounts>,
    jit_bitmap: Option<&'a JitBitmap>,
    trace_buf: Option<&'a mut TraceBuffer>,
}

#[inline(always)]
fn cached_exec_fetch_permitted(
    vm: &ThreadState,
    base: u32,
    pc: u64,
    width: u64,
    cache_start: &mut u64,
    cache_end: &mut u64,
    cache_generation: &mut u32,
) -> bool {
    let Some(end) = pc.checked_add(width) else {
        *cache_generation = 0;
        return false;
    };
    let generation = crate::syscall::memory::permit_cache_generation();
    if *cache_generation == generation && pc >= *cache_start && end <= *cache_end {
        return true;
    }
    let Some((cover_start, cover_end, cover_generation)) =
        crate::syscall::memory::guest_range_permitted_cover(vm, base, pc, width, abi::PROT_EXEC)
    else {
        *cache_generation = 0;
        return false;
    };
    *cache_start = cover_start;
    *cache_end = cover_end;
    *cache_generation = cover_generation;
    true
}

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
            guest_base(vm),
            cache,
            hot_counts,
            jit_bitmap,
            trace_buf,
        )
    }
}

/// Execute up to `budget` guest instructions from a caller-specified guest base.
///
/// The production runtime always uses guest base 0. Tests may place guest memory at
/// a non-zero offset to avoid overlapping the host WASI runtime's own memory.
///
/// # Safety
/// `vm` must point to a valid ThreadState. Guest memory at `base..` must be
/// accessible for the guest address space referenced by the thread.
#[inline(never)]
pub unsafe fn exec_at_base(
    vm: &mut ThreadState,
    budget: i32,
    base: u32,
    cache: Option<&mut BlockCache>,
    hot_counts: Option<&mut HotCounts>,
    jit_bitmap: Option<&JitBitmap>,
    trace_buf: Option<&mut TraceBuffer>,
) -> i32 {
    unsafe { exec_at_base_impl(vm, budget, base, cache, hot_counts, jit_bitmap, trace_buf) }
}

#[inline(never)]
unsafe fn exec_at_base_impl(
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
        normalize_x0(&mut x);
        let mut f = vm.f;
        let mut fcsr = vm.fcsr;
        let mut remaining = budget;
        let mut ctx = ExecLoopCtx {
            vm,
            base,
            pc: &mut pc,
            x: &mut x,
            f: &mut f,
            fcsr: &mut fcsr,
            remaining: &mut remaining,
            cache: cache.as_deref_mut(),
            hot_counts: hot_counts.as_deref_mut(),
            jit_bitmap,
            trace_buf: trace_buf.as_deref_mut(),
        };
        remaining = exec_at_base_loop(&mut ctx);
        vm.x = x;
        vm.f = f;
        vm.pc = pc;
        vm.fcsr = fcsr;
        let executed = (budget - remaining) as u64;
        crate::syscall::time::advance_monotonic(executed);
        remaining
    }
}

#[inline(never)]
unsafe fn exec_at_base_loop(ctx: &mut ExecLoopCtx<'_>) -> i32 {
    let vm = &mut *ctx.vm;
    let base = ctx.base;
    let pc = &mut *ctx.pc;
    let x = &mut *ctx.x;
    let f = &mut *ctx.f;
    let fcsr = &mut *ctx.fcsr;
    let remaining = &mut *ctx.remaining;
    let mut cache = ctx.cache.take();
    let mut hot_counts = ctx.hot_counts.take();
    let jit_bitmap = ctx.jit_bitmap;
    let mut trace_buf = ctx.trace_buf.take();
    let mut exec_permit_start = 0u64;
    let mut exec_permit_end = 0u64;
    let mut exec_permit_generation = 0u32;
    let mut access_permit_cache = AccessPermitCache::new();
    let memory_is_multi_threaded = unsafe { guest_mem::memory_is_multi_threaded() };
    loop {
        if *remaining <= 0 {
            let prev_sp = x[2];
            let prev_tp = x[4];
            let prev_s11 = x[27];
            vm.x = *x;
            vm.f = *f;
            vm.pc = *pc;
            vm.fcsr = *fcsr;
            if crate::syscall::signal::check_pending_at_boundary(
                vm,
                base,
                crate::supervisor::SUPERVISOR_SIGNAL_BOUNDARY_STEP,
            ) {
                *x = vm.x;
                normalize_x0(x);
                *f = vm.f;
                *pc = vm.pc;
                *fcsr = vm.fcsr;
                crate::tracepoints::record_special_reg_transitions(
                    vm as *const ThreadState as u32,
                    vm.tid,
                    *pc,
                    0,
                    REG_WRITE_SOURCE_VM_RESTORE,
                    prev_sp,
                    prev_tp,
                    prev_s11,
                    x,
                );
                if vm.status != abi::STATUS_OK {
                    return *remaining;
                }
            }
            break;
        }
        *remaining -= 1;
        let prev_sp = x[2];
        let prev_tp = x[4];
        let prev_s11 = x[27];
        let instr_pc = *pc;

        crate::syscall::signal::note_pc(vm, *pc);
        if crate::syscall::signal::is_current_sigreturn_trampoline(x[2], *pc) {
            vm.x = *x;
            vm.f = *f;
            vm.pc = *pc;
            vm.fcsr = *fcsr;
            crate::syscall::signal::sys_rt_sigreturn(vm, base);
            *x = vm.x;
            normalize_x0(x);
            *f = vm.f;
            *pc = vm.pc;
            *fcsr = vm.fcsr;
            crate::tracepoints::record_special_reg_transitions(
                vm as *const ThreadState as u32,
                vm.tid,
                instr_pc,
                0,
                REG_WRITE_SOURCE_VM_RESTORE,
                prev_sp,
                prev_tp,
                prev_s11,
                x,
            );
            x[0] = 0;
            crate::tracepoints::record_zero_reg_transition(
                vm as *const ThreadState as u32,
                vm.tid,
                instr_pc,
                0,
                prev_sp,
                prev_s11,
                x,
            );
            continue;
        }
        if !cached_exec_fetch_permitted(
            vm,
            base,
            *pc,
            2,
            &mut exec_permit_start,
            &mut exec_permit_end,
            &mut exec_permit_generation,
        ) {
            let fault_addr = *pc;
            let accerr = guest_range_in_bounds(base, *pc, 2);
            if !unsafe { deliver_sync_sigsegv(vm, x, f, fcsr, pc, base, fault_addr, accerr) } {
                return *remaining;
            }
            continue;
        }
        if trace_buf.is_none()
            && hot_counts.is_none()
            && jit_bitmap.is_none()
            && let Some(ref mut bc) = cache
            && let Some(blk) = unsafe { bc.get_or_build_checked(vm, *pc, base) }
        {
            let cost = blk.total_budget as i32;
            if cost > 0 && remaining.saturating_add(1) >= cost {
                let outcome = if blk.loop_flags & BLOCK_LOOP_SIMPLE_LOAD_SCAN != 0 {
                    unsafe {
                        exec_simple_load_scan_loop::<true>(
                            blk,
                            vm,
                            x,
                            f,
                            fcsr,
                            pc,
                            base,
                            remaining,
                            &mut access_permit_cache,
                            memory_is_multi_threaded,
                        )
                    }
                } else {
                    unsafe {
                        exec_block::<true>(
                            blk,
                            vm,
                            x,
                            f,
                            fcsr,
                            pc,
                            base,
                            remaining,
                            &mut access_permit_cache,
                            memory_is_multi_threaded,
                        )
                    }
                };
                match outcome {
                    BlockOutcome::Restart => {
                        x[0] = 0;
                        continue;
                    }
                    BlockOutcome::Return => return *remaining,
                    BlockOutcome::Unsupported => {}
                }
            } else {
                crate::tracepoints::record_block_cache_budget_skip();
            }
        }
        let raw16 = unsafe { guest_mem::read_u16_seqlock(base, *pc) };
        let (raw, step): (u32, u64) = if (raw16 & 3) != 3 {
            let expanded = decode::expand_compressed(raw16);
            if expanded == 0 {
                vm.x = *x;
                vm.f = *f;
                vm.pc = *pc;
                vm.fcsr = *fcsr;
                crate::syscall::signal::queue_sigill(vm, *pc, raw16 as u32);
                crate::syscall::signal::check_pending_at_boundary(
                    vm,
                    base,
                    crate::supervisor::SUPERVISOR_SIGNAL_BOUNDARY_FAULT,
                );
                *x = vm.x;
                normalize_x0(x);
                *f = vm.f;
                *pc = vm.pc;
                *fcsr = vm.fcsr;
                crate::tracepoints::record_special_reg_transitions(
                    vm as *const ThreadState as u32,
                    vm.tid,
                    instr_pc,
                    raw16 as u32,
                    REG_WRITE_SOURCE_VM_RESTORE,
                    prev_sp,
                    prev_tp,
                    prev_s11,
                    x,
                );
                if vm.status != abi::STATUS_OK {
                    return *remaining;
                }
                continue;
            }
            (expanded, 2)
        } else {
            if !cached_exec_fetch_permitted(
                vm,
                base,
                *pc,
                4,
                &mut exec_permit_start,
                &mut exec_permit_end,
                &mut exec_permit_generation,
            ) {
                let fault_addr = *pc;
                let accerr = guest_range_in_bounds(base, *pc, 4);
                if !unsafe { deliver_sync_sigsegv(vm, x, f, fcsr, pc, base, fault_addr, accerr) } {
                    return *remaining;
                }
                continue;
            }
            (unsafe { guest_mem::read_u32_seqlock(base, *pc) }, 4)
        };
        if let Some(ref mut tb) = trace_buf
            && tb.recording != 0
            && tb.record(*pc, raw, step as u32)
        {
            tb.stop();
            vm.x = *x;
            vm.f = *f;
            vm.pc = *pc;
            vm.status = abi::STATUS_JIT_READY;
            return *remaining;
        }
        crate::tracepoints::record_exec_trace(
            vm as *const ThreadState as u32,
            vm.tid,
            instr_pc,
            raw,
            step,
            x,
        );
        crate::tracepoints::record_interpreter_op(block_cache::op_id_for_raw(raw) as u32);
        if x[17] == crate::abi::SYS_EXECVE {
            crate::tracepoints::record_execve_approach(
                vm as *const ThreadState as u32,
                instr_pc,
                raw,
            );
        }
        if raw == 0x0000_0073 && x[17] == crate::abi::SYS_EXECVE {
            crate::tracepoints::record_execve_pre_dispatch(
                instr_pc,
                raw,
                vm.process_ptr as u64
                    + core::mem::offset_of!(crate::types::ProcessState, pid) as u64,
                x[11],
            );
        }
        match unsafe {
            exec_decoded(
                vm,
                raw,
                step,
                instr_pc,
                base,
                x,
                f,
                fcsr,
                pc,
                remaining,
                cache.as_deref_mut(),
                hot_counts.as_deref_mut(),
                jit_bitmap,
                trace_buf.as_deref_mut(),
                prev_sp,
                prev_tp,
                prev_s11,
                &mut access_permit_cache,
                memory_is_multi_threaded,
            )
        } {
            StepOutcome::Advance => {}
            StepOutcome::Restart => continue,
            StepOutcome::Return(remaining) => return remaining,
        }
        if decode::opcode(raw) == decode::OP_SYSTEM {
            exec_permit_generation = 0;
        }
        x[0] = 0;
        crate::tracepoints::record_special_reg_transitions(
            vm as *const ThreadState as u32,
            vm.tid,
            instr_pc,
            raw,
            REG_WRITE_SOURCE_STEP,
            prev_sp,
            prev_tp,
            prev_s11,
            x,
        );
        crate::tracepoints::record_zero_reg_transition(
            vm as *const ThreadState as u32,
            vm.tid,
            instr_pc,
            raw,
            prev_sp,
            prev_s11,
            x,
        );
    }
    *remaining
}

/// Get guest base address. Always 0 because each thread-worker WASM instance
/// imports the per-process shared Memory as memory index 0. The base of
/// guest memory is the base of WASM linear memory.
#[inline(always)]
fn guest_base(vm: &ThreadState) -> u32 {
    vm.guest_base
}

#[cfg(test)]
mod tests;
