//! Decoded instruction dispatch for the interpreter loop.
//!
//! Reference: RISC-V ISA spec V20191213
//!   (https://github.com/riscv/riscv-isa-manual/releases/tag/Ratified-IMAFDQC)
//!   §2 (RV32I), §5 (RV64I), §8 (A), §9 (Zicsr), §11 (F), §12 (D)
//!
//! This module executes one already-fetched instruction and reports how the
//! main exec loop should proceed.

use super::atomic::exec_amo;
use super::block_cache::BlockCache;
use super::block_exec::exec_block;
use super::decode;
use super::fault::{AccessOutcome, ensure_guest_access};
use super::fp::{exec_fma, exec_load_fp, exec_op_fp, exec_store_fp};
use super::integer::{
    exec_branch, exec_load, exec_op, exec_op_32, exec_op_imm, exec_op_imm_32, exec_store,
};
use super::system::{exec_system, handle_illegal_instruction};
use super::trace::{HotCounts, JitBitmap, TraceBuffer};
use crate::abi;
use crate::types::ThreadState;

// =============================================================================
// Dispatch result
// =============================================================================

/// Control flow result of executing one decoded instruction.
pub(super) enum StepOutcome {
    /// Continue with the normal post-step epilogue in `cpu/mod.rs`.
    Advance,
    /// Skip the normal epilogue and restart the interpreter loop immediately.
    Restart,
    /// Stop execution and return the remaining budget to the caller.
    Return(i32),
}

// =============================================================================
// Decoded instruction dispatch
// =============================================================================

/// Execute one already-decoded instruction.
#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn exec_decoded(
    vm: &mut ThreadState,
    raw: u32,
    step: u64,
    instr_pc: u64,
    base: u32,
    x: &mut [u64; 32],
    f: &mut [u64; 32],
    fcsr: &mut u32,
    pc: &mut u64,
    remaining: &mut i32,
    cache: Option<&mut BlockCache>,
    hot_counts: Option<&mut HotCounts>,
    jit_bitmap: Option<&JitBitmap>,
    trace_buf: Option<&mut TraceBuffer>,
    prev_sp: u64,
    prev_tp: u64,
    prev_s11: u64,
) -> StepOutcome {
    let opcode = decode::opcode(raw);

    unsafe {
        match opcode {
            decode::OP_OP_IMM => exec_op_imm(x, raw, pc, step),
            decode::OP_OP_IMM_32 => exec_op_imm_32(x, raw, pc, step),
            decode::OP_OP => exec_op(x, raw, pc, step),
            decode::OP_OP_32 => exec_op_32(x, raw, pc, step),
            decode::OP_LOAD => {
                let addr = (x[decode::rs1(raw)] as i64 + decode::imm_i(raw)) as u64;
                let width = match decode::funct3(raw) {
                    0 | 4 => 1,
                    1 | 5 => 2,
                    2 | 6 => 4,
                    3 => 8,
                    _ => 0,
                };
                match ensure_guest_access(vm, x, f, fcsr, pc, base, addr, width) {
                    AccessOutcome::Ok => {}
                    AccessOutcome::Restart => return StepOutcome::Restart,
                    AccessOutcome::Return => return StepOutcome::Return(*remaining),
                }
                exec_load(x, raw, base, pc, step);
            }
            decode::OP_STORE => {
                let addr = (x[decode::rs1(raw)] as i64 + decode::imm_s(raw)) as u64;
                let width = match decode::funct3(raw) {
                    0 => 1,
                    1 => 2,
                    2 => 4,
                    3 => 8,
                    _ => 0,
                };
                match ensure_guest_access(vm, x, f, fcsr, pc, base, addr, width) {
                    AccessOutcome::Ok => {}
                    AccessOutcome::Restart => return StepOutcome::Restart,
                    AccessOutcome::Return => return StepOutcome::Return(*remaining),
                }
                exec_store(x, raw, base, pc, step);
            }
            decode::OP_LUI => {
                let rd = decode::rd(raw);
                if rd != 0 {
                    x[rd] = decode::imm_u(raw) as u64;
                }
                *pc += step;
            }
            decode::OP_AUIPC => {
                let rd = decode::rd(raw);
                if rd != 0 {
                    x[rd] = (*pc as i64 + decode::imm_u(raw)) as u64;
                }
                *pc += step;
            }
            decode::OP_BRANCH => {
                if exec_branch(x, raw) {
                    let target = (*pc as i64 + decode::imm_b(raw)) as u64;
                    let imm = decode::imm_b(raw);
                    *pc = target;

                    if imm < 0 {
                        if let Some(bm) = jit_bitmap
                            && bm.is_ready(target)
                        {
                            vm.x = *x;
                            vm.f = *f;
                            vm.pc = target;
                            vm.status = abi::STATUS_JIT_READY;
                            return StepOutcome::Return(*remaining);
                        }
                        if let Some(hc) = hot_counts
                            && hc.increment(target)
                            && let Some(tb) = trace_buf
                            && tb.recording == 0
                        {
                            tb.start(target);
                        }
                    }
                } else {
                    *pc += step;
                }
            }
            decode::OP_JAL => {
                let rd = decode::rd(raw);
                if rd != 0 {
                    x[rd] = *pc + step;
                }
                *pc = (*pc as i64 + decode::imm_j(raw)) as u64;
            }
            decode::OP_JALR => {
                let rd = decode::rd(raw);
                let rs1v = decode::rs1(raw);
                let target = ((x[rs1v] as i64 + decode::imm_i(raw)) as u64) & !1;
                crate::harness_debug::record_jalr(*pc, rd, rs1v, x[rs1v], target);
                if rd != 0 {
                    x[rd] = *pc + step;
                }
                *pc = target;

                if rs1v == 1
                    && let Some(bc) = cache
                    && let Some(blk) = bc.get(target)
                {
                    let cost = blk.total_budget as i32;
                    if *remaining >= cost {
                        let executed = exec_block(blk, x, pc, base, vm.tid);
                        if executed > 0 {
                            *remaining -= executed;
                            x[0] = 0;
                            return StepOutcome::Restart;
                        }
                    }
                }
            }
            decode::OP_SYSTEM => {
                return exec_system(
                    vm, raw, step, instr_pc, base, x, f, fcsr, pc, *remaining, prev_sp, prev_tp,
                    prev_s11,
                );
            }
            decode::OP_MISC_MEM => {
                *pc += step;
            }
            decode::OP_AMO => {
                let addr = x[decode::rs1(raw)];
                let width = match decode::funct3(raw) {
                    2 => 4,
                    3 => 8,
                    _ => 0,
                };
                match ensure_guest_access(vm, x, f, fcsr, pc, base, addr, width) {
                    AccessOutcome::Ok => {}
                    AccessOutcome::Restart => return StepOutcome::Restart,
                    AccessOutcome::Return => return StepOutcome::Return(*remaining),
                }
                exec_amo(vm, x, raw, base, pc, step);
            }
            decode::OP_LOAD_FP => {
                let addr = (x[decode::rs1(raw)] as i64 + decode::imm_i(raw)) as u64;
                let width = match decode::funct3(raw) {
                    2 => 4,
                    3 => 8,
                    _ => 0,
                };
                match ensure_guest_access(vm, x, f, fcsr, pc, base, addr, width) {
                    AccessOutcome::Ok => {}
                    AccessOutcome::Restart => return StepOutcome::Restart,
                    AccessOutcome::Return => return StepOutcome::Return(*remaining),
                }
                exec_load_fp(f, x, raw, base, pc, step);
            }
            decode::OP_STORE_FP => {
                let addr = (x[decode::rs1(raw)] as i64 + decode::imm_s(raw)) as u64;
                let width = match decode::funct3(raw) {
                    2 => 4,
                    3 => 8,
                    _ => 0,
                };
                match ensure_guest_access(vm, x, f, fcsr, pc, base, addr, width) {
                    AccessOutcome::Ok => {}
                    AccessOutcome::Restart => return StepOutcome::Restart,
                    AccessOutcome::Return => return StepOutcome::Return(*remaining),
                }
                exec_store_fp(f, x, raw, base, pc, step);
            }
            decode::OP_OP_FP => exec_op_fp(x, f, raw, pc, step, fcsr),
            decode::OP_FMADD | decode::OP_FMSUB | decode::OP_FNMSUB | decode::OP_FNMADD => {
                exec_fma(f, raw, opcode, pc, step, fcsr);
            }
            _ => {
                return handle_illegal_instruction(
                    vm, raw, step, instr_pc, base, x, f, fcsr, pc, *remaining, prev_sp, prev_tp,
                    prev_s11,
                );
            }
        }
    }

    StepOutcome::Advance
}
