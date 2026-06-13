//! System instruction and illegal-instruction handling helpers.
//!
//! Reference: RISC-V ISA spec V20191213
//!   (https://github.com/riscv/riscv-isa-manual/releases/tag/Ratified-IMAFDQC)
//!   §2 (RV32I), §9 (Zicsr)
//!
//! These helpers keep ECALL/EBREAK/CSR handling and SIGILL recovery out of the
//! main decoded-instruction dispatch table.

use super::csr::{CsrOutcome, exec_csr};
use super::decode;
use super::dispatch::StepOutcome;
use crate::abi;
use crate::types::ThreadState;

const REG_WRITE_SOURCE_VM_RESTORE: u32 = 2;

fn syscall_needs_runtime_sync_boundary(nr: u64) -> bool {
    matches!(
        nr,
        abi::SYS_OPENAT
            | abi::SYS_READ
            | abi::SYS_READV
            | abi::SYS_WRITE
            | abi::SYS_WRITEV
            | abi::SYS_CLOSE
            | abi::SYS_CLOSE_RANGE
            | abi::SYS_PIPE2
            | abi::SYS_DUP
            | abi::SYS_DUP3
            | abi::SYS_FCNTL
            | abi::SYS_IOCTL
            | abi::SYS_SOCKET
            | abi::SYS_SOCKETPAIR
            | abi::SYS_ACCEPT4
            | abi::SYS_EVENTFD2
            | abi::SYS_EPOLL_CREATE1
            | abi::SYS_EPOLL_CTL
            | abi::SYS_EXECVE
            | abi::SYS_EXECVEAT
            | abi::SYS_SETPGID
            | abi::SYS_SETSID
            | abi::SYS_KILL
            | abi::SYS_TKILL
            | abi::SYS_TGKILL
    )
}

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
                let syscall_nr = x[17];
                if syscall_nr == crate::abi::SYS_EXECVE {
                    crate::tracepoints::record_execve_ecall(
                        vm.process_ptr as u64
                            + core::mem::offset_of!(crate::types::ProcessState, pid) as u64,
                        x[11],
                    );
                }
                vm.x = *x;
                vm.f = *f;
                vm.pc = *pc + step;
                vm.fcsr = *fcsr;
                let status = crate::syscall::dispatch(vm, base);
                *x = vm.x;
                super::normalize_x0(x);
                *f = vm.f;
                *pc = vm.pc;
                *fcsr = vm.fcsr;
                crate::tracepoints::record_special_reg_transitions(
                    vm as *const ThreadState as u32,
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
                crate::tracepoints::record_zero_reg_transition(
                    vm as *const ThreadState as u32,
                    vm.tid,
                    instr_pc,
                    raw,
                    prev_sp,
                    prev_s11,
                    x,
                );
                if syscall_needs_runtime_sync_boundary(syscall_nr) {
                    return StepOutcome::Return(remaining);
                }
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
        match exec_csr(x, raw, pc, step, fcsr) {
            CsrOutcome::Advance => StepOutcome::Advance,
            CsrOutcome::Illegal => unsafe {
                handle_illegal_instruction(
                    vm, raw, step, instr_pc, base, x, f, fcsr, pc, remaining, prev_sp, prev_tp,
                    prev_s11,
                )
            },
        }
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
    _step: u64,
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
    crate::syscall::signal::queue_sigill(vm, *pc, raw);
    crate::syscall::signal::check_pending(vm, base);
    *x = vm.x;
    super::normalize_x0(x);
    *f = vm.f;
    *pc = vm.pc;
    *fcsr = vm.fcsr;
    crate::tracepoints::record_special_reg_transitions(
        vm as *const ThreadState as u32,
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
    StepOutcome::Restart
}
