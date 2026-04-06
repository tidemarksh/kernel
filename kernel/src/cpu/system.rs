//! System instruction and illegal-instruction handling helpers.
//!
//! Reference: RISC-V ISA spec V20191213
//!   (https://github.com/riscv/riscv-isa-manual/releases/tag/Ratified-IMAFDQC)
//!   §2 (RV32I), §9 (Zicsr)
//!
//! These helpers keep ECALL/EBREAK/CSR handling and SIGILL recovery out of the
//! main decoded-instruction dispatch table.

use super::csr::exec_csr;
use super::decode;
use super::dispatch::StepOutcome;
use crate::abi;
use crate::types::ThreadState;

const REG_WRITE_SOURCE_VM_RESTORE: u32 = 2;

// =============================================================================
// System instruction execution
// =============================================================================

/// Execute an OP_SYSTEM instruction and report how the interpreter should proceed.
#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn exec_system(
    vm: &mut ThreadState,
    raw: u32,
    step: u64,
    instr_pc: u64,
    base: u32,
    x: &mut [u64; 32],
    f: &mut [u64; 32],
    fcsr: &mut u32,
    pc: &mut u64,
    remaining: i32,
    prev_sp: u64,
    prev_tp: u64,
    prev_s11: u64,
) -> StepOutcome {
    let funct3 = decode::funct3(raw);
    if funct3 == 0 {
        let funct12 = raw >> 20;
        match funct12 {
            0 => {
                vm.x = *x;
                vm.f = *f;
                vm.pc = *pc + step;
                vm.fcsr = *fcsr;
                let status = crate::syscall::dispatch(vm, base);
                *x = vm.x;
                *f = vm.f;
                *pc = vm.pc;
                *fcsr = vm.fcsr;
                crate::harness_debug::record_special_reg_transitions(
                    vm.tid,
                    instr_pc,
                    raw,
                    REG_WRITE_SOURCE_VM_RESTORE,
                    prev_sp,
                    prev_tp,
                    prev_s11,
                    x,
                );
                if status != abi::STATUS_OK {
                    vm.status = status;
                    return StepOutcome::Return(remaining);
                }
                x[0] = 0;
                crate::harness_debug::record_zero_reg_transition(
                    vm.tid, instr_pc, raw, prev_sp, prev_s11, x,
                );
                StepOutcome::Restart
            }
            1 => {
                vm.status = abi::STATUS_FAULT;
                vm.fault_pc = *pc;
                vm.x = *x;
                vm.pc = *pc;
                StepOutcome::Return(remaining)
            }
            _ => {
                *pc += step;
                StepOutcome::Advance
            }
        }
    } else {
        exec_csr(x, raw, pc, step, fcsr);
        StepOutcome::Advance
    }
}

// =============================================================================
// Illegal instruction handling
// =============================================================================

/// Queue SIGILL for an unknown opcode and reload thread state from `vm`.
#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn handle_illegal_instruction(
    vm: &mut ThreadState,
    raw: u32,
    step: u64,
    instr_pc: u64,
    base: u32,
    x: &mut [u64; 32],
    f: &mut [u64; 32],
    fcsr: &mut u32,
    pc: &mut u64,
    remaining: i32,
    prev_sp: u64,
    prev_tp: u64,
    prev_s11: u64,
) -> StepOutcome {
    vm.x = *x;
    vm.f = *f;
    vm.pc = *pc;
    vm.fcsr = *fcsr;
    crate::syscall::signal::queue_sigill(vm, *pc);
    crate::syscall::signal::check_pending(vm, base);
    *x = vm.x;
    *f = vm.f;
    *pc = vm.pc;
    *fcsr = vm.fcsr;
    crate::harness_debug::record_special_reg_transitions(
        vm.tid,
        instr_pc,
        raw,
        REG_WRITE_SOURCE_VM_RESTORE,
        prev_sp,
        prev_tp,
        prev_s11,
        x,
    );
    if vm.status != abi::STATUS_OK {
        return StepOutcome::Return(remaining);
    }
    *pc += step;
    StepOutcome::Restart
}
