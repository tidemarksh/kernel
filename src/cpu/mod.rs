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

pub mod block_cache;
pub mod decode;
pub mod trace;

use crate::abi;
use crate::guest_mem;
use crate::types::ThreadState;
use self::block_cache::BlockCache;
use self::trace::{HotCounts, JitBitmap, TraceBuffer};

// LR/SC reservation state (per-hart, single-threaded).
static mut RESV_ADDR: u64 = 0;
static mut RESV_VALID: bool = false;

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
    let base = ram_base(vm);
    let mut remaining = budget;

    loop {
        if remaining <= 0 {
            // Budget boundary: check pending signals (RISC-V ISA spec + Linux semantics)
            // WASM has no async interrupts, so check at budget boundaries in addition
            // to syscall return boundaries.
            vm.x = x; vm.f = f; vm.pc = pc; vm.fcsr = fcsr;
            if crate::syscall::signal::check_pending(vm, base) {
                x = vm.x; f = vm.f; pc = vm.pc; fcsr = vm.fcsr;
                if vm.status != abi::STATUS_OK { return remaining; }
            }
            break;
        }
        remaining -= 1;

        // Fetch instruction
        let raw16 = guest_mem::read_u16(base, pc);
        let (raw, step): (u32, u64) = if (raw16 & 3) != 3 {
            // Compressed (RVC)
            let expanded = decode::expand_compressed(raw16);
            if expanded == 0 {
                vm.status = abi::STATUS_FAULT;
                vm.fault_pc = pc;
                break;
            }
            (expanded, 2)
        } else {
            (guest_mem::read_u32(base, pc), 4)
        };

        // --- Trace recording (JIT the JIT compiler hook) ---
        if let Some(ref mut tb) = trace_buf {
            if tb.recording != 0 {
                if tb.record(pc, raw, step as u32) {
                    // Buffer full → stop recording, signal trace ready
                    tb.stop();
                    vm.x = x; vm.f = f; vm.pc = pc;
                    vm.status = abi::STATUS_JIT_READY;
                    return remaining;
                }
            }
        }

        let opcode = decode::opcode(raw);

        match opcode {
            decode::OP_OP_IMM => exec_op_imm(&mut x, raw, &mut pc, step),
            decode::OP_OP_IMM_32 => exec_op_imm_32(&mut x, raw, &mut pc, step),
            decode::OP_OP => exec_op(&mut x, raw, &mut pc, step),
            decode::OP_OP_32 => exec_op_32(&mut x, raw, &mut pc, step),
            decode::OP_LOAD => {
                if crate::syscall::memory::has_prot_none() {
                    let addr = (x[decode::rs1(raw)] as i64 + decode::imm_i(raw)) as u64;
                    if crate::syscall::memory::is_prot_none(addr) {
                        crate::syscall::signal::send_signal(vm, crate::abi::SIGSEGV);
                        vm.status = abi::STATUS_FAULT;
                        vm.fault_pc = pc;
                        vm.fault_addr = addr;
                        break;
                    }
                }
                exec_load(&mut x, raw, base, &mut pc, step);
            }
            decode::OP_STORE => {
                if crate::syscall::memory::has_prot_none() {
                    let addr = (x[decode::rs1(raw)] as i64 + decode::imm_s(raw)) as u64;
                    if crate::syscall::memory::is_prot_none(addr) {
                        crate::syscall::signal::send_signal(vm, crate::abi::SIGSEGV);
                        vm.status = abi::STATUS_FAULT;
                        vm.fault_pc = pc;
                        vm.fault_addr = addr;
                        break;
                    }
                }
                exec_store(&x, raw, base, &mut pc, step);
            }
            decode::OP_LUI => {
                let rd = decode::rd(raw);
                if rd != 0 { x[rd] = decode::imm_u(raw) as u64; }
                pc += step;
            }
            decode::OP_AUIPC => {
                let rd = decode::rd(raw);
                if rd != 0 { x[rd] = (pc as i64 + decode::imm_u(raw)) as u64; }
                pc += step;
            }
            decode::OP_BRANCH => {
                if exec_branch(&x, raw) {
                    let target = (pc as i64 + decode::imm_b(raw)) as u64;
                    let imm = decode::imm_b(raw);
                    pc = target;

                    // Backward branch → hot count check + JIT hook
                    if imm < 0 {
                        // Check JIT bitmap
                        if let Some(ref bm) = jit_bitmap {
                            if bm.is_ready(target) {
                                vm.x = x; vm.f = f; vm.pc = target;
                                vm.status = abi::STATUS_JIT_READY;
                                return remaining;
                            }
                        }
                        // Hot count → start trace recording
                        if let Some(ref mut hc) = hot_counts {
                            if hc.increment(target) {
                                if let Some(ref mut tb) = trace_buf {
                                    if tb.recording == 0 {
                                        tb.start(target);
                                    }
                                }
                            }
                        }
                    }
                } else {
                    pc += step;
                }
            }
            decode::OP_JAL => {
                let rd = decode::rd(raw);
                if rd != 0 { x[rd] = pc + step; }
                pc = (pc as i64 + decode::imm_j(raw)) as u64;
            }
            decode::OP_JALR => {
                let rd = decode::rd(raw);
                let rs1v = decode::rs1(raw);
                let target = ((x[rs1v] as i64 + decode::imm_i(raw)) as u64) & !1;
                if rd != 0 { x[rd] = pc + step; }
                pc = target;

                // JALR return prediction (): rs1==ra (x1) → execute cached block
                if rs1v == 1 {
                    if let Some(ref mut bc) = cache {
                        if let Some(blk) = bc.get(target) {
                            let cost = blk.total_budget as i32;
                            if remaining >= cost {
                                let executed = exec_block(blk, &mut x, &mut pc, base);
                                if executed > 0 {
                                    remaining -= executed;
                                    x[0] = 0;
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
            decode::OP_SYSTEM => {
                let funct3 = decode::funct3(raw);
                if funct3 == 0 {
                    let funct12 = raw >> 20;
                    match funct12 {
                        0 => {
                            // ECALL — syscall dispatch
                            vm.x = x;
                            vm.f = f;
                            vm.pc = pc + step;
                            vm.fcsr = fcsr;
                            let status = crate::syscall::dispatch(vm, base);
                            // Reload registers (syscall may modify them)
                            x = vm.x;
                            f = vm.f;
                            pc = vm.pc;
                            fcsr = vm.fcsr;
                            if status != abi::STATUS_OK {
                                vm.status = status;
                                return remaining;
                            }
                            x[0] = 0;
                            continue;
                        }
                        1 => {
                            // EBREAK
                            vm.status = abi::STATUS_FAULT;
                            vm.fault_pc = pc;
                            vm.x = x;
                            vm.pc = pc;
                            return remaining;
                        }
                        _ => { pc += step; } // other system: ignore
                    }
                } else {
                    // CSR instructions
                    exec_csr(&mut x, raw, &mut pc, step, &mut fcsr);
                }
            }
            decode::OP_MISC_MEM => {
                // FENCE — no-op in single-threaded userland emulation
                pc += step;
            }
            decode::OP_AMO => {
                exec_amo(&mut x, raw, base, &mut pc, step);
            }
            decode::OP_LOAD_FP => exec_load_fp(&mut f, &x, raw, base, &mut pc, step),
            decode::OP_STORE_FP => exec_store_fp(&f, &x, raw, base, &mut pc, step),
            decode::OP_OP_FP => exec_op_fp(&mut x, &mut f, raw, &mut pc, step, &mut fcsr),
            decode::OP_FMADD | decode::OP_FMSUB | decode::OP_FNMSUB | decode::OP_FNMADD => {
                exec_fma(&mut f, raw, opcode, &mut pc, step, &mut fcsr);
            }
            _ => {
                // Unknown opcode → fault
                vm.status = abi::STATUS_FAULT;
                vm.fault_pc = pc;
                break;
            }
        }

        // Enforce x0 = 0
        x[0] = 0;
    }

    vm.x = x;
    vm.f = f;
    vm.pc = pc;
    vm.fcsr = fcsr;
    remaining
    }
}

/// Get RAM base address. Always 0 because each thread-worker WASM instance
/// imports the per-process shared Memory as memory index 0. The base of
/// guest memory is the base of WASM linear memory.
#[inline(always)]
fn ram_base(_vm: &ThreadState) -> u32 {
    0
}

// =============================================================================
// Block cache execution ( JALR return prediction)
// =============================================================================

/// Execute a cached basic block. Returns ops executed (for budget), or 0 if
/// the block contains unsupported ops (FP, AMO, SYSTEM) at position 0.
/// Sets `pc` to the next address after the block (or after the bail-out point).
unsafe fn exec_block(
    blk: &block_cache::BlockEntry,
    x: &mut [u64; 32],
    pc: &mut u64,
    base: u32,
) -> i32 {
    unsafe {
    let len = blk.len as usize;
    let mut cur_pc = blk.start_pc;

    for i in 0..len {
        let op = blk.ops[i];
        let rd = op.rd();
        let r1 = op.rs1();
        let r2 = op.rs2();
        let f3 = op.f3();
        let step = op.step();
        let imm = op.imm() as i64;

        match op.op_id() {
            1 => { // OP_IMM
                let v = x[r1] as i64;
                let r = match f3 {
                    0 => v.wrapping_add(imm),
                    1 => (x[r1] << (imm & 0x3F)) as i64,
                    2 => if v < imm { 1 } else { 0 },
                    3 => if x[r1] < imm as u64 { 1 } else { 0 },
                    4 => v ^ imm,
                    5 => { let sh = imm & 0x3F;
                           if op.f7b5() { v >> sh } else { (x[r1] >> sh) as i64 } }
                    6 => v | imm,
                    7 => v & imm,
                    _ => 0,
                };
                if rd != 0 { x[rd] = r as u64; }
            }
            2 => { // OP_IMM_32
                let v = x[r1] as i32;
                let r: i32 = match f3 {
                    0 => v.wrapping_add(imm as i32),
                    1 => v << (imm & 0x1F),
                    5 => { let sh = (imm & 0x1F) as u32;
                           if op.f7b5() { v >> sh } else { ((v as u32) >> sh) as i32 } }
                    _ => 0,
                };
                if rd != 0 { x[rd] = r as i64 as u64; }
            }
            3 => { // OP (base: ADD/SUB/SLL/SLT/SLTU/XOR/SRL/SRA/OR/AND)
                let v1 = x[r1]; let v2 = x[r2];
                let r: u64 = match f3 {
                    0 => if op.f7b5() { (v1 as i64).wrapping_sub(v2 as i64) as u64 }
                         else { v1.wrapping_add(v2) },
                    1 => v1 << (v2 & 0x3F),
                    2 => if (v1 as i64) < (v2 as i64) { 1 } else { 0 },
                    3 => if v1 < v2 { 1 } else { 0 },
                    4 => v1 ^ v2,
                    5 => if op.f7b5() { ((v1 as i64) >> (v2 & 0x3F)) as u64 }
                         else { v1 >> (v2 & 0x3F) },
                    6 => v1 | v2,
                    7 => v1 & v2,
                    _ => 0,
                };
                if rd != 0 { x[rd] = r; }
            }
            22 => { // OP M extension (MUL/DIV/REM)
                let v1 = x[r1]; let v2 = x[r2];
                let r: u64 = match f3 {
                    0 => (v1 as i64).wrapping_mul(v2 as i64) as u64,
                    1 => mulh(v1 as i64, v2 as i64) as u64,
                    2 => mulhsu(v1 as i64, v2) as u64,
                    3 => mulhu(v1, v2),
                    4 => div_i64(v1 as i64, v2 as i64) as u64,
                    5 => divu_64(v1, v2),
                    6 => rem_i64(v1 as i64, v2 as i64) as u64,
                    7 => remu_64(v1, v2),
                    _ => 0,
                };
                if rd != 0 { x[rd] = r; }
            }
            4 => { // OP_32 (base)
                let v1 = x[r1] as i32; let v2 = x[r2] as i32;
                let r: i32 = match f3 {
                    0 => if op.f7b5() { v1.wrapping_sub(v2) } else { v1.wrapping_add(v2) },
                    1 => v1 << (v2 & 0x1F),
                    5 => if op.f7b5() { v1 >> (v2 & 0x1F) }
                         else { ((v1 as u32) >> (v2 as u32 & 0x1F)) as i32 },
                    _ => 0,
                };
                if rd != 0 { x[rd] = r as i64 as u64; }
            }
            23 => { // OP_32 M extension
                let v1 = x[r1] as i32; let v2 = x[r2] as i32;
                let r: i32 = match f3 {
                    0 => v1.wrapping_mul(v2),
                    4 => if v2 == 0 { -1 } else if v1 == i32::MIN && v2 == -1 { v1 } else { v1 / v2 },
                    5 => { let (u1, u2) = (v1 as u32, v2 as u32);
                           if u2 == 0 { u32::MAX as i32 } else { (u1 / u2) as i32 } }
                    6 => if v2 == 0 { v1 } else if v1 == i32::MIN && v2 == -1 { 0 } else { v1 % v2 },
                    7 => { let (u1, u2) = (v1 as u32, v2 as u32);
                           if u2 == 0 { v1 } else { (u1 % u2) as i32 } }
                    _ => 0,
                };
                if rd != 0 { x[rd] = r as i64 as u64; }
            }
            5 => { // LOAD
                let addr = (x[r1] as i64 + imm) as u64;
                let val: u64 = match f3 {
                    0 => guest_mem::read_i8(base, addr) as u64,
                    1 => guest_mem::read_i16(base, addr) as u64,
                    2 => guest_mem::read_i32(base, addr) as u64,
                    3 => guest_mem::read_u64(base, addr),
                    4 => guest_mem::read_u8(base, addr) as u64,
                    5 => guest_mem::read_u16(base, addr) as u64,
                    6 => guest_mem::read_u32(base, addr) as u64,
                    _ => 0,
                };
                if rd != 0 { x[rd] = val; }
            }
            6 => { // STORE
                let addr = (x[r1] as i64 + imm) as u64;
                match f3 {
                    0 => guest_mem::write_u8(base, addr, x[r2] as u8),
                    1 => guest_mem::write_u16(base, addr, x[r2] as u16),
                    2 => guest_mem::write_u32(base, addr, x[r2] as u32),
                    3 => guest_mem::write_u64(base, addr, x[r2]),
                    _ => {}
                }
            }
            7 => { if rd != 0 { x[rd] = imm as u64; } }  // LUI
            8 => { if rd != 0 { x[rd] = (cur_pc as i64 + imm) as u64; } }  // AUIPC
            9 => { // BRANCH (terminator)
                let taken = match f3 {
                    0 => x[r1] == x[r2],
                    1 => x[r1] != x[r2],
                    4 => (x[r1] as i64) < (x[r2] as i64),
                    5 => (x[r1] as i64) >= (x[r2] as i64),
                    6 => x[r1] < x[r2],
                    7 => x[r1] >= x[r2],
                    _ => false,
                };
                *pc = if taken { (cur_pc as i64 + imm) as u64 } else { cur_pc + step };
                x[0] = 0;
                return blk.total_budget as i32;
            }
            10 => { // JAL (terminator)
                if rd != 0 { x[rd] = cur_pc + step; }
                *pc = (cur_pc as i64 + imm) as u64;
                x[0] = 0;
                return blk.total_budget as i32;
            }
            11 => { // JALR (terminator)
                if rd != 0 { x[rd] = cur_pc + step; }
                *pc = ((x[r1] as i64 + imm) as u64) & !1;
                x[0] = 0;
                return blk.total_budget as i32;
            }
            13 => {} // FENCE — no-op
            _ => {
                // Unsupported (FP, AMO, SYSTEM) — bail to interpreter
                *pc = cur_pc;
                x[0] = 0;
                return i as i32;
            }
        }
        x[0] = 0;
        cur_pc += step;
    }

    *pc = cur_pc;
    blk.total_budget as i32
    }
}

// =============================================================================
// Instruction executors
// =============================================================================

#[inline(always)]
unsafe fn exec_op_imm(x: &mut [u64; 32], raw: u32, pc: &mut u64, step: u64) {
    unsafe {
    let rd = decode::rd(raw);
    let rs1 = decode::rs1(raw);
    let imm = decode::imm_i(raw);
    let v1 = x[rs1] as i64;
    let result = match decode::funct3(raw) {
        0 => v1.wrapping_add(imm),                       // ADDI
        1 => (x[rs1] << (imm & 0x3F)) as i64,            // SLLI
        2 => if v1 < imm { 1 } else { 0 },               // SLTI
        3 => if (x[rs1]) < (imm as u64) { 1 } else { 0 },// SLTIU
        4 => v1 ^ imm,                                    // XORI
        5 => {
            let shamt = imm & 0x3F;
            if (raw >> 30) & 1 != 0 {
                v1 >> shamt                                // SRAI
            } else {
                (x[rs1] >> shamt) as i64                   // SRLI
            }
        }
        6 => v1 | imm,                                    // ORI
        7 => v1 & imm,                                    // ANDI
        _ => 0,
    };
    if rd != 0 { x[rd] = result as u64; }
    *pc += step;
    }
}

#[inline(always)]
unsafe fn exec_op_imm_32(x: &mut [u64; 32], raw: u32, pc: &mut u64, step: u64) {
    unsafe {
    let rd = decode::rd(raw);
    let rs1 = decode::rs1(raw);
    let imm = decode::imm_i(raw);
    let v1 = x[rs1] as i32;
    let result: i32 = match decode::funct3(raw) {
        0 => v1.wrapping_add(imm as i32),                 // ADDIW
        1 => v1 << (imm & 0x1F),                          // SLLIW
        5 => {
            let shamt = (imm & 0x1F) as u32;
            if (raw >> 30) & 1 != 0 {
                v1 >> shamt                                // SRAIW
            } else {
                ((v1 as u32) >> shamt) as i32              // SRLIW
            }
        }
        _ => 0,
    };
    if rd != 0 { x[rd] = result as i64 as u64; }
    *pc += step;
    }
}

#[inline(always)]
unsafe fn exec_op(x: &mut [u64; 32], raw: u32, pc: &mut u64, step: u64) {
    unsafe {
    let rd = decode::rd(raw);
    let rs1 = decode::rs1(raw);
    let rs2 = decode::rs2(raw);
    let f7 = decode::funct7(raw);
    let v1 = x[rs1];
    let v2 = x[rs2];

    let result: u64 = if f7 == 1 {
        // M extension
        match decode::funct3(raw) {
            0 => (v1 as i64).wrapping_mul(v2 as i64) as u64,  // MUL
            1 => mulh(v1 as i64, v2 as i64) as u64,           // MULH
            2 => mulhsu(v1 as i64, v2) as u64,                // MULHSU
            3 => mulhu(v1, v2),                                // MULHU
            4 => div_i64(v1 as i64, v2 as i64) as u64,        // DIV
            5 => divu_64(v1, v2),                              // DIVU
            6 => rem_i64(v1 as i64, v2 as i64) as u64,        // REM
            7 => remu_64(v1, v2),                              // REMU
            _ => 0,
        }
    } else {
        match decode::funct3(raw) {
            0 => if f7 == 0x20 { (v1 as i64).wrapping_sub(v2 as i64) as u64 }
                 else { v1.wrapping_add(v2) },                 // ADD/SUB
            1 => v1 << (v2 & 0x3F),                            // SLL
            2 => if (v1 as i64) < (v2 as i64) { 1 } else { 0 }, // SLT
            3 => if v1 < v2 { 1 } else { 0 },                 // SLTU
            4 => v1 ^ v2,                                      // XOR
            5 => if f7 == 0x20 { ((v1 as i64) >> (v2 & 0x3F)) as u64 }
                 else { v1 >> (v2 & 0x3F) },                   // SRA/SRL
            6 => v1 | v2,                                      // OR
            7 => v1 & v2,                                      // AND
            _ => 0,
        }
    };
    if rd != 0 { x[rd] = result; }
    *pc += step;
    }
}

#[inline(always)]
unsafe fn exec_op_32(x: &mut [u64; 32], raw: u32, pc: &mut u64, step: u64) {
    unsafe {
    let rd = decode::rd(raw);
    let rs1 = decode::rs1(raw);
    let rs2 = decode::rs2(raw);
    let f7 = decode::funct7(raw);
    let v1 = x[rs1] as i32;
    let v2 = x[rs2] as i32;

    let result: i32 = if f7 == 1 {
        match decode::funct3(raw) {
            0 => v1.wrapping_mul(v2),                          // MULW
            4 => if v2 == 0 { -1 } else if v1 == i32::MIN && v2 == -1 { v1 } else { v1 / v2 }, // DIVW
            5 => { let u1 = v1 as u32; let u2 = v2 as u32;
                   if u2 == 0 { u32::MAX as i32 } else { (u1 / u2) as i32 } }, // DIVUW
            6 => if v2 == 0 { v1 } else if v1 == i32::MIN && v2 == -1 { 0 } else { v1 % v2 }, // REMW
            7 => { let u1 = v1 as u32; let u2 = v2 as u32;
                   if u2 == 0 { v1 } else { (u1 % u2) as i32 } }, // REMUW
            _ => 0,
        }
    } else {
        match decode::funct3(raw) {
            0 => if f7 == 0x20 { v1.wrapping_sub(v2) } else { v1.wrapping_add(v2) },
            1 => v1 << (v2 & 0x1F),                            // SLLW
            5 => if f7 == 0x20 { v1 >> (v2 & 0x1F) }           // SRAW
                 else { ((v1 as u32) >> (v2 as u32 & 0x1F)) as i32 }, // SRLW
            _ => 0,
        }
    };
    if rd != 0 { x[rd] = result as i64 as u64; }
    *pc += step;
    }
}

#[inline(always)]
unsafe fn exec_load(x: &mut [u64; 32], raw: u32, base: u32, pc: &mut u64, step: u64) {
    unsafe {
    let rd = decode::rd(raw);
    let rs1 = decode::rs1(raw);
    let addr = (x[rs1] as i64 + decode::imm_i(raw)) as u64;
    let val: u64 = match decode::funct3(raw) {
        0 => guest_mem::read_i8(base, addr) as u64,   // LB
        1 => guest_mem::read_i16(base, addr) as u64,  // LH
        2 => guest_mem::read_i32(base, addr) as u64,  // LW
        3 => guest_mem::read_u64(base, addr),          // LD
        4 => guest_mem::read_u8(base, addr) as u64,    // LBU
        5 => guest_mem::read_u16(base, addr) as u64,   // LHU
        6 => guest_mem::read_u32(base, addr) as u64,   // LWU
        _ => 0,
    };
    if rd != 0 { x[rd] = val; }
    *pc += step;
    }
}

#[inline(always)]
unsafe fn exec_store(x: &[u64; 32], raw: u32, base: u32, pc: &mut u64, step: u64) {
    unsafe {
    let rs1 = decode::rs1(raw);
    let rs2 = decode::rs2(raw);
    let addr = (x[rs1] as i64 + decode::imm_s(raw)) as u64;
    let val = x[rs2];
    match decode::funct3(raw) {
        0 => guest_mem::write_u8(base, addr, val as u8),   // SB
        1 => guest_mem::write_u16(base, addr, val as u16), // SH
        2 => guest_mem::write_u32(base, addr, val as u32), // SW
        3 => guest_mem::write_u64(base, addr, val),        // SD
        _ => {}
    }
    *pc += step;
    }
}

#[inline(always)]
fn exec_branch(x: &[u64; 32], raw: u32) -> bool {
    let rs1 = decode::rs1(raw);
    let rs2 = decode::rs2(raw);
    let v1 = x[rs1];
    let v2 = x[rs2];
    match decode::funct3(raw) {
        0 => v1 == v2,                                     // BEQ
        1 => v1 != v2,                                     // BNE
        4 => (v1 as i64) < (v2 as i64),                   // BLT
        5 => (v1 as i64) >= (v2 as i64),                  // BGE
        6 => v1 < v2,                                      // BLTU
        7 => v1 >= v2,                                     // BGEU
        _ => false,
    }
}

// =============================================================================
// FP helpers: fflags, NaN-boxing, FMIN/FMAX, FCLASS, FCVT
// =============================================================================

// fcsr.fflags exception bits (RISC-V ISA spec §11.2)
const NV: u32 = 1 << 4; // Invalid Operation
const DZ: u32 = 1 << 3; // Divide by Zero
const OF: u32 = 1 << 2; // Overflow
const UF: u32 = 1 << 1; // Underflow
const NX: u32 = 1 << 0; // Inexact

#[inline(always)]
fn set_flags(fcsr: &mut u32, flags: u32) { *fcsr |= flags; }

/// Detect signaling NaN for f64 (exponent all-1, fraction nonzero, quiet bit clear)
#[inline(always)]
fn is_snan_f64(v: f64) -> bool {
    let b = v.to_bits();
    let exp = (b >> 52) & 0x7FF;
    let frac = b & 0x000F_FFFF_FFFF_FFFF;
    exp == 0x7FF && frac != 0 && (frac & (1 << 51)) == 0
}

/// Detect signaling NaN for f32 (exponent all-1, fraction nonzero, quiet bit clear)
#[inline(always)]
fn is_snan_f32(v: f32) -> bool {
    let b = v.to_bits();
    let exp = (b >> 23) & 0xFF;
    let frac = b & 0x007F_FFFF;
    exp == 0xFF && frac != 0 && (frac & (1 << 22)) == 0
}

/// Classify fflags for f64: sNaN→NV, overflow→OF|NX, subnormal result→UF|NX
#[inline(always)]
fn classify_flags_f64(a: f64, b: f64, result: f64) -> u32 {
    let mut flags = 0u32;
    if is_snan_f64(a) || is_snan_f64(b) { flags |= NV; }
    if result.is_nan() { if a.is_nan() || b.is_nan() { return flags | NV; } return flags | NV; }
    if result.is_infinite() && !a.is_infinite() && !b.is_infinite() { flags |= OF | NX; }
    let rb = result.to_bits();
    let exp = (rb >> 52) & 0x7FF;
    if exp == 0 && (rb & 0x000F_FFFF_FFFF_FFFF) != 0 { flags |= UF | NX; }
    flags
}

/// Classify fflags for f32
#[inline(always)]
fn classify_flags_f32(a: f32, b: f32, result: f32) -> u32 {
    let mut flags = 0u32;
    if is_snan_f32(a) || is_snan_f32(b) { flags |= NV; }
    if result.is_nan() { if a.is_nan() || b.is_nan() { return flags | NV; } return flags | NV; }
    if result.is_infinite() && !a.is_infinite() && !b.is_infinite() { flags |= OF | NX; }
    let rb = result.to_bits();
    let exp = (rb >> 23) & 0xFF;
    if exp == 0 && (rb & 0x007F_FFFF) != 0 { flags |= UF | NX; }
    flags
}

/// Check if f64 addition was inexact: (a+b) is inexact iff (result - a) != b
#[inline(always)]
fn add_flags_f64(a: f64, b: f64, result: f64) -> u32 {
    let mut flags = classify_flags_f64(a, b, result);
    if !result.is_nan() && !result.is_infinite() && (result - a != b || result - b != a) { flags |= NX; }
    flags
}
#[inline(always)]
fn add_flags_f32(a: f32, b: f32, result: f32) -> u32 {
    let mut flags = classify_flags_f32(a, b, result);
    if !result.is_nan() && !result.is_infinite() {
        let wide = (a as f64) + (b as f64);
        if wide != result as f64 { flags |= NX; }
    }
    flags
}

/// Check if f64 multiplication was inexact: a*b is inexact iff fma(a,b,-result) != 0
#[inline(always)]
fn mul_flags_f64(a: f64, b: f64, result: f64) -> u32 {
    let mut flags = classify_flags_f64(a, b, result);
    if !result.is_nan() && !result.is_infinite() && libm::fma(a, b, -result) != 0.0 { flags |= NX; }
    // ∞ × 0 = NV
    if (a.is_infinite() && b == 0.0) || (a == 0.0 && b.is_infinite()) { flags |= NV; }
    flags
}
#[inline(always)]
fn mul_flags_f32(a: f32, b: f32, result: f32) -> u32 {
    let mut flags = classify_flags_f32(a, b, result);
    if !result.is_nan() && !result.is_infinite() {
        let wide = (a as f64) * (b as f64);
        if wide != result as f64 { flags |= NX; }
    }
    if (a.is_infinite() && b == 0.0) || (a == 0.0 && b.is_infinite()) { flags |= NV; }
    flags
}

/// Check if f64 division was inexact: a/b is inexact iff result*b != a
#[inline(always)]
fn div_flags_f64(a: f64, b: f64, result: f64) -> u32 {
    let mut flags = classify_flags_f64(a, b, result);
    if !a.is_nan() && !b.is_nan() && b == 0.0 && a != 0.0 { flags |= DZ; }
    if !a.is_nan() && !b.is_nan() && b == 0.0 && a == 0.0 { flags |= NV; }
    if !result.is_nan() && !result.is_infinite() && b != 0.0 && libm::fma(result, b, -a) != 0.0 { flags |= NX; }
    flags
}
#[inline(always)]
fn div_flags_f32(a: f32, b: f32, result: f32) -> u32 {
    let mut flags = classify_flags_f32(a, b, result);
    if !a.is_nan() && !b.is_nan() && b == 0.0 && a != 0.0 { flags |= DZ; }
    if !a.is_nan() && !b.is_nan() && b == 0.0 && a == 0.0 { flags |= NV; }
    if !result.is_nan() && !result.is_infinite() && b != 0.0 {
        let wide = (a as f64) / (b as f64);
        if wide != result as f64 { flags |= NX; }
    }
    flags
}

/// fflags for sqrt: NV if negative, NX if inexact (result*result != a)
#[inline(always)]
fn sqrt_flags_f64(a: f64, result: f64) -> u32 {
    let mut flags = 0u32;
    if is_snan_f64(a) { flags |= NV; }
    if a < 0.0 { flags |= NV; }
    if !result.is_nan() && !result.is_infinite() && libm::fma(result, result, -a) != 0.0 { flags |= NX; }
    flags
}
#[inline(always)]
fn sqrt_flags_f32(a: f32, result: f32) -> u32 {
    let mut flags = 0u32;
    if is_snan_f32(a) { flags |= NV; }
    if a < 0.0 { flags |= NV; }
    if !result.is_nan() && !result.is_infinite() {
        let wide = libm::sqrt(a as f64);
        if wide != result as f64 { flags |= NX; }
    }
    flags
}

/// Canonical NaN constants (RISC-V ISA spec §11.3)
const CANONICAL_NAN_F64: u64 = 0x7FF8_0000_0000_0000;
const CANONICAL_NAN_F32: u32 = 0x7FC0_0000;

/// Canonicalize f64 NaN result (RISC-V ISA spec §11.3)
#[inline(always)]
fn canon_f64(v: f64) -> f64 {
    if v.is_nan() { f64::from_bits(CANONICAL_NAN_F64) } else { v }
}

/// Canonicalize f32 NaN result
#[inline(always)]
fn canon_f32(v: f32) -> f32 {
    if v.is_nan() { f32::from_bits(CANONICAL_NAN_F32) } else { v }
}

/// NaN-box a single-precision value for storage in f register (FLEN=64, ).
#[inline(always)]
fn box_f32(val: f32) -> u64 {
    0xFFFF_FFFF_0000_0000 | (val.to_bits() as u64)
}

/// Unbox a single-precision value from f register.
/// If not correctly NaN-boxed, return canonical NaN ().
#[inline(always)]
fn unbox_f32(bits: u64) -> f32 {
    if (bits & 0xFFFF_FFFF_0000_0000) == 0xFFFF_FFFF_0000_0000 {
        f32::from_bits(bits as u32)
    } else {
        f32::from_bits(0x7FC0_0000) // canonical NaN
    }
}

/// FMIN.D: IEEE 754-201x minimumNumber ()
#[inline(always)]
fn fmin_f64(a: f64, b: f64) -> f64 {
    if a.is_nan() && b.is_nan() { return f64::from_bits(0x7FF8_0000_0000_0000); }
    if a.is_nan() { return b; }
    if b.is_nan() { return a; }
    if a.to_bits() == 0x8000_0000_0000_0000 && b.to_bits() == 0 { return a; }
    if b.to_bits() == 0x8000_0000_0000_0000 && a.to_bits() == 0 { return b; }
    if a < b { a } else { b }
}

/// FMAX.D: IEEE 754-201x maximumNumber ()
#[inline(always)]
fn fmax_f64(a: f64, b: f64) -> f64 {
    if a.is_nan() && b.is_nan() { return f64::from_bits(0x7FF8_0000_0000_0000); }
    if a.is_nan() { return b; }
    if b.is_nan() { return a; }
    if a.to_bits() == 0x8000_0000_0000_0000 && b.to_bits() == 0 { return b; }
    if b.to_bits() == 0x8000_0000_0000_0000 && a.to_bits() == 0 { return a; }
    if a > b { a } else { b }
}

/// FMIN.S: IEEE 754-201x minimumNumber ()
#[inline(always)]
fn fmin_f32(a: f32, b: f32) -> f32 {
    if a.is_nan() && b.is_nan() { return f32::from_bits(0x7FC0_0000); }
    if a.is_nan() { return b; }
    if b.is_nan() { return a; }
    if a.to_bits() == 0x8000_0000 && b.to_bits() == 0 { return a; }
    if b.to_bits() == 0x8000_0000 && a.to_bits() == 0 { return b; }
    if a < b { a } else { b }
}

/// FMAX.S: IEEE 754-201x maximumNumber ()
#[inline(always)]
fn fmax_f32(a: f32, b: f32) -> f32 {
    if a.is_nan() && b.is_nan() { return f32::from_bits(0x7FC0_0000); }
    if a.is_nan() { return b; }
    if b.is_nan() { return a; }
    if a.to_bits() == 0x8000_0000 && b.to_bits() == 0 { return b; }
    if b.to_bits() == 0x8000_0000 && a.to_bits() == 0 { return a; }
    if a > b { a } else { b }
}

/// FCLASS.D (): classify double-precision value → 10-bit mask
fn fclass_f64(bits: u64) -> u64 {
    let sign = (bits >> 63) & 1;
    let exp = (bits >> 52) & 0x7FF;
    let frac = bits & 0x000F_FFFF_FFFF_FFFF;
    if exp == 0x7FF {
        if frac == 0 {
            if sign != 0 { 1 << 0 } else { 1 << 7 } // ±∞
        } else if frac & (1 << 51) != 0 {
            1 << 9 // quiet NaN
        } else {
            1 << 8 // signaling NaN
        }
    } else if exp == 0 {
        if frac == 0 {
            if sign != 0 { 1 << 3 } else { 1 << 4 } // ±0
        } else {
            if sign != 0 { 1 << 2 } else { 1 << 5 } // ±subnormal
        }
    } else {
        if sign != 0 { 1 << 1 } else { 1 << 6 } // ±normal
    }
}

/// FCLASS.S (): classify single-precision value → 10-bit mask
fn fclass_f32(bits: u32) -> u64 {
    let sign = (bits >> 31) & 1;
    let exp = (bits >> 23) & 0xFF;
    let frac = bits & 0x007F_FFFF;
    if exp == 0xFF {
        if frac == 0 {
            if sign != 0 { 1 << 0 } else { 1 << 7 }
        } else if frac & (1 << 22) != 0 {
            1 << 9
        } else {
            1 << 8
        }
    } else if exp == 0 {
        if frac == 0 {
            if sign != 0 { 1 << 3 } else { 1 << 4 }
        } else {
            if sign != 0 { 1 << 2 } else { 1 << 5 }
        }
    } else {
        if sign != 0 { 1 << 1 } else { 1 << 6 }
    }
}

// FCVT: float→int with RISC-V NaN semantics (NaN → MAX, Table 11.4).
// Rust's `as` saturates for out-of-range (matching RISC-V) but returns 0 for NaN.
#[inline(always)] fn fcvt_w_f64(v: f64) -> i32 { if v.is_nan() { i32::MAX } else { v as i32 } }
#[inline(always)] fn fcvt_wu_f64(v: f64) -> u32 { if v.is_nan() { u32::MAX } else { v as u32 } }
#[inline(always)] fn fcvt_l_f64(v: f64) -> i64 { if v.is_nan() { i64::MAX } else { v as i64 } }
#[inline(always)] fn fcvt_lu_f64(v: f64) -> u64 { if v.is_nan() { u64::MAX } else { v as u64 } }
#[inline(always)] fn fcvt_w_f32(v: f32) -> i32 { if v.is_nan() { i32::MAX } else { v as i32 } }
#[inline(always)] fn fcvt_wu_f32(v: f32) -> u32 { if v.is_nan() { u32::MAX } else { v as u32 } }
#[inline(always)] fn fcvt_l_f32(v: f32) -> i64 { if v.is_nan() { i64::MAX } else { v as i64 } }
#[inline(always)] fn fcvt_lu_f32(v: f32) -> u64 { if v.is_nan() { u64::MAX } else { v as u64 } }

// =============================================================================
// FP instruction executors
// =============================================================================

#[inline(always)]
unsafe fn exec_load_fp(f: &mut [u64; 32], x: &[u64; 32], raw: u32, base: u32, pc: &mut u64, step: u64) {
    unsafe {
    let rd = decode::rd(raw);
    let rs1 = decode::rs1(raw);
    let addr = (x[rs1] as i64 + decode::imm_i(raw)) as u64;
    match decode::funct3(raw) {
        2 => f[rd] = 0xFFFF_FFFF_0000_0000 | (guest_mem::read_u32(base, addr) as u64), // FLW: NaN-box ()
        3 => f[rd] = guest_mem::read_u64(base, addr), // FLD
        _ => {}
    }
    *pc += step;
    }
}

#[inline(always)]
unsafe fn exec_store_fp(f: &[u64; 32], x: &[u64; 32], raw: u32, base: u32, pc: &mut u64, step: u64) {
    unsafe {
    let rs1 = decode::rs1(raw);
    let rs2 = decode::rs2(raw);
    let addr = (x[rs1] as i64 + decode::imm_s(raw)) as u64;
    match decode::funct3(raw) {
        2 => guest_mem::write_u32(base, addr, f[rs2] as u32), // FSW: lower 32 bits
        3 => guest_mem::write_u64(base, addr, f[rs2]),        // FSD
        _ => {}
    }
    *pc += step;
    }
}

/// RV64F + RV64D: all OP-FP instructions.
/// Dispatch on funct5 (bits 31:27) and fmt (bits 26:25, 0=S, 1=D).
#[inline(always)]
unsafe fn exec_op_fp(x: &mut [u64; 32], f: &mut [u64; 32], raw: u32, pc: &mut u64, step: u64, fcsr: &mut u32) {
    unsafe {
    let rd = decode::rd(raw);
    let rs1 = decode::rs1(raw);
    let rs2 = decode::rs2(raw);
    let f7 = decode::funct7(raw);
    let funct5 = f7 >> 2;
    let fmt = f7 & 3;
    let f3 = decode::funct3(raw);

    match (funct5, fmt) {
        // ========================= Double-precision (fmt=1) =========================
        (0x00, 1) => { // FADD.D
            let a = f64::from_bits(f[rs1]); let b = f64::from_bits(f[rs2]);
            let r = canon_f64(a + b); f[rd] = r.to_bits();
            set_flags(fcsr, add_flags_f64(a, b, r));
        }
        (0x01, 1) => { // FSUB.D
            let a = f64::from_bits(f[rs1]); let b = f64::from_bits(f[rs2]);
            let r = canon_f64(a - b); f[rd] = r.to_bits();
            set_flags(fcsr, add_flags_f64(a, -b, r));
        }
        (0x02, 1) => { // FMUL.D
            let a = f64::from_bits(f[rs1]); let b = f64::from_bits(f[rs2]);
            let r = canon_f64(a * b); f[rd] = r.to_bits();
            set_flags(fcsr, mul_flags_f64(a, b, r));
        }
        (0x03, 1) => { // FDIV.D
            let a = f64::from_bits(f[rs1]); let b = f64::from_bits(f[rs2]);
            let r = canon_f64(a / b); f[rd] = r.to_bits();
            set_flags(fcsr, div_flags_f64(a, b, r));
        }
        (0x0B, 1) => { // FSQRT.D
            let a = f64::from_bits(f[rs1]);
            let r = canon_f64(libm::sqrt(a)); f[rd] = r.to_bits();
            set_flags(fcsr, sqrt_flags_f64(a, r));
        }
        (0x04, 1) => { // FSGNJ.D / FSGNJN.D / FSGNJX.D
            let a = f[rs1]; let b = f[rs2];
            f[rd] = match f3 {
                0 => (a & 0x7FFF_FFFF_FFFF_FFFF) | (b & 0x8000_0000_0000_0000),
                1 => (a & 0x7FFF_FFFF_FFFF_FFFF) | (!b & 0x8000_0000_0000_0000),
                2 | _ => a ^ (b & 0x8000_0000_0000_0000),
            };
        }
        (0x05, 1) => { // FMIN.D / FMAX.D
            let a = f64::from_bits(f[rs1]); let b = f64::from_bits(f[rs2]);
            f[rd] = match f3 {
                0 => fmin_f64(a, b).to_bits(),
                1 | _ => fmax_f64(a, b).to_bits(),
            };
            // RISC-V ISA spec §11.6: signaling NaN inputs set NV, even when result is not NaN
            if is_snan_f64(a) || is_snan_f64(b) { set_flags(fcsr, NV); }
        }
        (0x14, 1) => { // FEQ.D / FLT.D / FLE.D → x[rd]
            let a = f64::from_bits(f[rs1]); let b = f64::from_bits(f[rs2]);
            let r = match f3 { 2 => a == b, 1 => a < b, 0 => a <= b, _ => false };
            if rd != 0 { x[rd] = r as u64; }
            // RISC-V ISA spec §11.8: FLT/FLE set NV if either is NaN; FEQ sets NV only for sNaN
            match f3 {
                1 | 0 => { if a.is_nan() || b.is_nan() { set_flags(fcsr, NV); } }
                2 => { if is_snan_f64(a) || is_snan_f64(b) { set_flags(fcsr, NV); } }
                _ => {}
            }
        }
        (0x18, 1) => { // FCVT.W[U].D / FCVT.L[U].D → x[rd]
            let v = f64::from_bits(f[rs1]);
            let r = match rs2 {
                0 => fcvt_w_f64(v) as i64 as u64,
                1 => (fcvt_wu_f64(v) as i32 as i64) as u64,
                2 => fcvt_l_f64(v) as u64,
                3 => fcvt_lu_f64(v),
                _ => 0,
            };
            if rd != 0 { x[rd] = r; }
            // RISC-V ISA spec §11.7 Table 11.4: NV if NaN/Inf/out-of-range after rounding.
            // Use truncated value for range check to handle cases like -0.9 → 0 (in range for unsigned).
            let trunc = if v.is_nan() || v.is_infinite() { None } else { Some(v as i64) };
            let out_of_range = trunc.is_none() || match rs2 {
                0 => trunc.unwrap() < (i32::MIN as i64) || trunc.unwrap() > (i32::MAX as i64),
                1 => v < -1.0 + f64::EPSILON || v > (u32::MAX as f64) + 1.0 - f64::EPSILON,
                2 => v <= (i64::MIN as f64) - 1.0 || v >= (i64::MAX as f64) + 1.0,
                3 => v < -1.0 + f64::EPSILON || v > (u64::MAX as f64),
                _ => false,
            };
            if out_of_range { set_flags(fcsr, NV); }
            else {
                let exact = match rs2 {
                    0 => v == (r as i32 as f64),
                    1 => v == (r as u32 as f64),
                    2 => v == (r as i64 as f64),
                    3 => v == (r as u64 as f64),
                    _ => true,
                };
                if !exact { set_flags(fcsr, NX); }
            }
        }
        (0x1A, 1) => { // FCVT.D.W[U] / FCVT.D.L[U] → f[rd]
            f[rd] = match rs2 {
                0 => ((x[rs1] as i32) as f64).to_bits(),           // FCVT.D.W
                1 => ((x[rs1] as u32) as f64).to_bits(),           // FCVT.D.WU
                2 => ((x[rs1] as i64) as f64).to_bits(),           // FCVT.D.L
                3 => ((x[rs1] as u64) as f64).to_bits(),           // FCVT.D.LU
                _ => 0,
            };
        }
        (0x1C, 1) => match f3 { // FMV.X.D / FCLASS.D → x[rd]
            0 => { if rd != 0 { x[rd] = f[rs1]; } }              // FMV.X.D
            1 => { if rd != 0 { x[rd] = fclass_f64(f[rs1]); } }  // FCLASS.D
            _ => {}
        }
        (0x1E, 1) => f[rd] = x[rs1], // FMV.D.X

        // ========================= Single-precision (fmt=0) =========================
        (0x00, 0) => { let a = unbox_f32(f[rs1]); let b = unbox_f32(f[rs2]);
            let r = canon_f32(a + b); f[rd] = box_f32(r); set_flags(fcsr, add_flags_f32(a, b, r)); }
        (0x01, 0) => { let a = unbox_f32(f[rs1]); let b = unbox_f32(f[rs2]);
            let r = canon_f32(a - b); f[rd] = box_f32(r); set_flags(fcsr, add_flags_f32(a, -b, r)); }
        (0x02, 0) => { let a = unbox_f32(f[rs1]); let b = unbox_f32(f[rs2]);
            let r = canon_f32(a * b); f[rd] = box_f32(r); set_flags(fcsr, mul_flags_f32(a, b, r)); }
        (0x03, 0) => { let a = unbox_f32(f[rs1]); let b = unbox_f32(f[rs2]);
            let r = canon_f32(a / b); f[rd] = box_f32(r); set_flags(fcsr, div_flags_f32(a, b, r)); }
        (0x0B, 0) => { let a = unbox_f32(f[rs1]);
            let r = canon_f32(libm::sqrtf(a)); f[rd] = box_f32(r); set_flags(fcsr, sqrt_flags_f32(a, r)); }
        (0x04, 0) => { // FSGNJ.S / FSGNJN.S / FSGNJX.S
            let a = unbox_f32(f[rs1]).to_bits();
            let b = unbox_f32(f[rs2]).to_bits();
            let r = match f3 {
                0 => (a & 0x7FFF_FFFF) | (b & 0x8000_0000),
                1 => (a & 0x7FFF_FFFF) | (!b & 0x8000_0000),
                2 | _ => a ^ (b & 0x8000_0000),
            };
            f[rd] = box_f32(f32::from_bits(r));
        }
        (0x05, 0) => { // FMIN.S / FMAX.S
            let a = unbox_f32(f[rs1]); let b = unbox_f32(f[rs2]);
            f[rd] = match f3 {
                0 => box_f32(fmin_f32(a, b)),
                1 | _ => box_f32(fmax_f32(a, b)),
            };
            if is_snan_f32(a) || is_snan_f32(b) { set_flags(fcsr, NV); }
        }
        (0x14, 0) => { // FEQ.S / FLT.S / FLE.S → x[rd]
            let a = unbox_f32(f[rs1]); let b = unbox_f32(f[rs2]);
            let r = match f3 { 2 => a == b, 1 => a < b, 0 => a <= b, _ => false };
            if rd != 0 { x[rd] = r as u64; }
            match f3 {
                1 | 0 => { if a.is_nan() || b.is_nan() { set_flags(fcsr, NV); } }
                2 => { if is_snan_f32(a) || is_snan_f32(b) { set_flags(fcsr, NV); } }
                _ => {}
            }
        }
        (0x18, 0) => { // FCVT.W[U].S / FCVT.L[U].S → x[rd]
            let v = unbox_f32(f[rs1]);
            let vd = v as f64;
            let r = match rs2 {
                0 => fcvt_w_f32(v) as i64 as u64,
                1 => (fcvt_wu_f32(v) as i32 as i64) as u64,
                2 => fcvt_l_f32(v) as u64,
                3 => fcvt_lu_f32(v),
                _ => 0,
            };
            if rd != 0 { x[rd] = r; }
            // RISC-V ISA spec §11.7 Table 11.4: NV if NaN/Inf/out-of-range after rounding.
            let trunc = if v.is_nan() || v.is_infinite() { None } else { Some(vd as i64) };
            let out_of_range = trunc.is_none() || match rs2 {
                0 => trunc.unwrap() < (i32::MIN as i64) || trunc.unwrap() > (i32::MAX as i64),
                1 => trunc.unwrap() < 0 || trunc.unwrap() > (u32::MAX as i64),
                2 => vd <= (i64::MIN as f64) - 1.0 || vd >= (i64::MAX as f64) + 1.0,
                3 => vd < 0.0 && trunc.unwrap() < 0 || vd > (u64::MAX as f64),
                _ => false,
            };
            if out_of_range { set_flags(fcsr, NV); }
            else {
                let exact = match rs2 {
                    0 => vd == (r as i32 as f64),
                    1 => vd == (r as u32 as f64),
                    2 => vd == (r as i64 as f64),
                    3 => vd == (r as u64 as f64),
                    _ => true,
                };
                if !exact { set_flags(fcsr, NX); }
            }
        }
        (0x1A, 0) => { // FCVT.S.W[U] / FCVT.S.L[U] → f[rd]
            f[rd] = match rs2 {
                0 => box_f32((x[rs1] as i32) as f32),
                1 => box_f32((x[rs1] as u32) as f32),
                2 => box_f32((x[rs1] as i64) as f32),
                3 => box_f32((x[rs1] as u64) as f32),
                _ => 0,
            };
        }
        (0x1C, 0) => match f3 { // FMV.X.W / FCLASS.S → x[rd]
            0 => { // FMV.X.W: lower 32 bits, sign-extended to 64
                if rd != 0 { x[rd] = (f[rs1] as u32 as i32 as i64) as u64; }
            }
            1 => { // FCLASS.S
                if rd != 0 { x[rd] = fclass_f32(unbox_f32(f[rs1]).to_bits()); }
            }
            _ => {}
        }
        (0x1E, 0) => { // FMV.W.X: NaN-box lower 32 bits of x[rs1]
            f[rd] = 0xFFFF_FFFF_0000_0000 | (x[rs1] as u32 as u64);
        }

        // ========================= S↔D conversion (funct5=0x08) =========================
        (0x08, 0) => { // FCVT.S.D: double → single
            let a = f64::from_bits(f[rs1]);
            let r = canon_f32(a as f32);
            f[rd] = box_f32(r);
            // NX if precision lost, NV if sNaN input
            if is_snan_f64(a) { set_flags(fcsr, NV); }
            else if !a.is_nan() && !a.is_infinite() && (r as f64).to_bits() != a.to_bits() { set_flags(fcsr, NX); }
        }
        (0x08, 1) => { // FCVT.D.S: single → double (always exact, but canonicalize NaN)
            let a = unbox_f32(f[rs1]);
            let r = if a.is_nan() { f64::from_bits(CANONICAL_NAN_F64) } else { a as f64 };
            f[rd] = r.to_bits();
            if is_snan_f32(a) { set_flags(fcsr, NV); }
        }

        _ => {} // Q/H not supported
    }
    *pc += step;
    }
}

/// RV64F + RV64D: fused multiply-add (FMADD, FMSUB, FNMSUB, FNMADD).
/// fmt (bits 26:25) selects S (0) or D (1).
/// Uses libm::fma/fmaf for correct fused operation (single rounding).
#[inline(always)]
unsafe fn exec_fma(f: &mut [u64; 32], raw: u32, opcode: u32, pc: &mut u64, step: u64, fcsr: &mut u32) {
    unsafe {
    let rd = decode::rd(raw);
    let rs1 = decode::rs1(raw);
    let rs2 = decode::rs2(raw);
    let rs3 = decode::rs3(raw);
    let fmt = (raw >> 25) & 3;

    match fmt {
        0 => { // Single-precision
            let a = unbox_f32(f[rs1]);
            let b = unbox_f32(f[rs2]);
            let c = unbox_f32(f[rs3]);
            let r = canon_f32(match opcode {
                decode::OP_FMADD  => libm::fmaf(a, b, c),
                decode::OP_FMSUB  => libm::fmaf(a, b, -c),
                decode::OP_FNMSUB => libm::fmaf(-a, b, c),
                decode::OP_FNMADD => libm::fmaf(-a, b, -c),
                _ => 0.0,
            });
            f[rd] = box_f32(r);
            let mut fl = 0u32;
            if (a.is_infinite() && b == 0.0) || (a == 0.0 && b.is_infinite()) { fl |= NV; }
            if is_snan_f32(a) || is_snan_f32(b) || is_snan_f32(c) { fl |= NV; }
            if r.is_nan() && (a.is_nan() || b.is_nan() || c.is_nan()) { fl |= NV; }
            if r.is_infinite() && !a.is_infinite() && !b.is_infinite() && !c.is_infinite() { fl |= OF | NX; }
            if !r.is_nan() && !r.is_infinite() {
                // Compute same operation in f64 and compare to detect inexact
                let wide = match opcode {
                    decode::OP_FMADD  => libm::fma(a as f64, b as f64, c as f64),
                    decode::OP_FMSUB  => libm::fma(a as f64, b as f64, -(c as f64)),
                    decode::OP_FNMSUB => -libm::fma(a as f64, b as f64, -(c as f64)),
                    decode::OP_FNMADD => -libm::fma(a as f64, b as f64, c as f64),
                    _ => r as f64,
                };
                if wide != r as f64 { fl |= NX; }
            }
            set_flags(fcsr, fl);
        }
        1 => { // Double-precision
            let a = f64::from_bits(f[rs1]);
            let b = f64::from_bits(f[rs2]);
            let c = f64::from_bits(f[rs3]);
            let r = canon_f64(match opcode {
                decode::OP_FMADD  => libm::fma(a, b, c),
                decode::OP_FMSUB  => libm::fma(a, b, -c),
                decode::OP_FNMSUB => libm::fma(-a, b, c),
                decode::OP_FNMADD => libm::fma(-a, b, -c),
                _ => 0.0,
            });
            f[rd] = r.to_bits();
            let mut fl = 0u32;
            if (a.is_infinite() && b == 0.0) || (a == 0.0 && b.is_infinite()) { fl |= NV; }
            if is_snan_f64(a) || is_snan_f64(b) || is_snan_f64(c) { fl |= NV; }
            if r.is_nan() && (a.is_nan() || b.is_nan() || c.is_nan()) { fl |= NV; }
            if r.is_infinite() && !a.is_infinite() && !b.is_infinite() && !c.is_infinite() { fl |= OF | NX; }
            if !r.is_nan() && !r.is_infinite() {
                // fma(a,b,c) = r is the correctly-rounded result from libm::fma.
                // Inexact iff the mathematical result a*b+c differs from r.
                // Use error-free transformation: prod = a*b, prod_err = fma(a,b,-prod)
                // Then mathematical a*b = prod + prod_err exactly.
                // mathematical a*b+c_eff = prod + c_eff + prod_err
                // The sum (prod + c_eff) may round, giving sum + sum_err = prod + c_eff exactly.
                // Total error = sum_err + prod_err. If nonzero, result is inexact.
                let c_eff = match opcode {
                    decode::OP_FMSUB | decode::OP_FNMADD => -c, _ => c,
                };
                let prod = a * b;
                let prod_err = libm::fma(a, b, -prod);
                // Two-sum: sum + sum_err = prod + c_eff exactly
                let sum = prod + c_eff;
                let sum_err = if prod.abs() >= c_eff.abs() {
                    (prod - sum) + c_eff
                } else {
                    (c_eff - sum) + prod
                };
                let total_err = sum_err + prod_err;
                // Apply negation for FNMSUB/FNMADD (doesn't change whether it's inexact)
                if total_err != 0.0 { fl |= NX; }
            }
            set_flags(fcsr, fl);
        }
        _ => {} // Q/H not supported
    }
    *pc += step;
    }
}

#[inline(always)]
unsafe fn exec_amo(x: &mut [u64; 32], raw: u32, base: u32, pc: &mut u64, step: u64) {
    unsafe {
    let rd = decode::rd(raw);
    let rs1 = decode::rs1(raw);
    let rs2 = decode::rs2(raw);
    let funct5 = decode::funct5(raw);
    let f3 = decode::funct3(raw);
    let is_word = f3 == 2;
    let addr = x[rs1];

    match funct5 {
        0x02 => { // LR — load reserved, set reservation
            let old = if is_word { guest_mem::read_i32(base, addr) as i64 as u64 }
                      else { guest_mem::read_u64(base, addr) };
            if rd != 0 { x[rd] = old; }
            // Set reservation: addr and size
            RESV_ADDR = addr;
            RESV_VALID = true;
        }
        0x03 => { // SC — store conditional, check reservation
            if RESV_VALID && RESV_ADDR == addr {
                if is_word { guest_mem::write_u32(base, addr, x[rs2] as u32); }
                else { guest_mem::write_u64(base, addr, x[rs2]); }
                if rd != 0 { x[rd] = 0; } // success
            } else {
                if rd != 0 { x[rd] = 1; } // failure
            }
            RESV_VALID = false;
        }
        _ => {
            // AMO: read-modify-write
            // For .W: read 32-bit sign-extended, operate on 32-bit values,
            // write back 32-bit, return sign-extended old value (RISC-V ISA spec §8.4).
            let old = if is_word { guest_mem::read_i32(base, addr) as i64 as u64 }
                      else { guest_mem::read_u64(base, addr) };
            let src = if is_word { x[rs2] as i32 as i64 as u64 } else { x[rs2] };
            let new_val = match funct5 {
                0x01 => src,                                               // AMOSWAP
                0x00 => old.wrapping_add(src),                             // AMOADD
                0x04 => old ^ src,                                         // AMOXOR
                0x0C => old & src,                                         // AMOAND
                0x08 => old | src,                                         // AMOOR
                0x10 => core::cmp::min(old as i64, src as i64) as u64,    // AMOMIN
                0x14 => core::cmp::max(old as i64, src as i64) as u64,    // AMOMAX
                0x18 => if is_word {                                       // AMOMINU
                    core::cmp::min(old as u32, src as u32) as i32 as i64 as u64
                } else { core::cmp::min(old, src) },
                0x1C => if is_word {                                       // AMOMAXU
                    core::cmp::max(old as u32, src as u32) as i32 as i64 as u64
                } else { core::cmp::max(old, src) },
                _ => old,
            };
            if is_word { guest_mem::write_u32(base, addr, new_val as u32); }
            else { guest_mem::write_u64(base, addr, new_val); }
            if rd != 0 { x[rd] = old; }
            // AMO store invalidates any reservation (RISC-V ISA spec §8.4)
            RESV_VALID = false;
        }
    }
    *pc += step;
    }
}

/// CSR instructions: handle fcsr (0x003), fflags (0x001), frm (0x002).
/// Other CSRs (cycle, time, instret) return 0.
#[inline(always)]
fn exec_csr(x: &mut [u64; 32], raw: u32, pc: &mut u64, step: u64, fcsr: &mut u32) {
    let rd = decode::rd(raw);
    let rs1 = decode::rs1(raw);
    let f3 = decode::funct3(raw);
    let csr = (raw >> 20) & 0xFFF;

    let old_val: u64 = match csr {
        0x001 => (*fcsr & 0x1F) as u64,         // fflags
        0x002 => ((*fcsr >> 5) & 0x7) as u64,   // frm
        0x003 => (*fcsr & 0xFF) as u64,          // fcsr
        _ => 0,                                   // cycle/time/instret/others: stub
    };

    let src = if f3 >= 5 { rs1 as u64 } else { x[rs1] };
    let new_val = match f3 {
        1 | 5 => src,                // CSRRW / CSRRWI
        2 | 6 => old_val | src,      // CSRRS / CSRRSI
        3 | 7 => old_val & !src,     // CSRRC / CSRRCI
        _ => old_val,
    };

    let do_write = match f3 {
        1 | 5 => true,               // CSRRW/CSRRWI always write
        2 | 3 | 6 | 7 => rs1 != 0,  // CSRRS/CSRRC: write only if rs1/uimm != 0
        _ => false,
    };

    if do_write {
        match csr {
            0x001 => *fcsr = (*fcsr & !0x1F) | (new_val as u32 & 0x1F),
            0x002 => *fcsr = (*fcsr & !0xE0) | ((new_val as u32 & 0x7) << 5),
            0x003 => *fcsr = new_val as u32 & 0xFF,
            _ => {}
        }
    }

    if rd != 0 { x[rd] = old_val; }
    *pc += step;
}

// =============================================================================
// M extension helpers (DIV/REM with RISC-V spec semantics)
// =============================================================================

#[inline(always)]
fn div_i64(a: i64, b: i64) -> i64 {
    if b == 0 { return -1; } // division by zero → all bits set
    if a == i64::MIN && b == -1 { return a; } // overflow → dividend
    a / b
}

#[inline(always)]
fn divu_64(a: u64, b: u64) -> u64 {
    if b == 0 { return u64::MAX; } // all bits set
    a / b
}

#[inline(always)]
fn rem_i64(a: i64, b: i64) -> i64 {
    if b == 0 { return a; } // remainder = dividend
    if a == i64::MIN && b == -1 { return 0; } // overflow → 0
    a % b
}

#[inline(always)]
fn remu_64(a: u64, b: u64) -> u64 {
    if b == 0 { return a; }
    a % b
}

#[inline(always)]
fn mulh(a: i64, b: i64) -> i64 {
    ((a as i128 * b as i128) >> 64) as i64
}

#[inline(always)]
fn mulhsu(a: i64, b: u64) -> i64 {
    ((a as i128 * b as i128) >> 64) as i64
}

#[inline(always)]
fn mulhu(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) >> 64) as u64
}

#[cfg(test)]
mod tests {
    use crate::abi::STATUS_FAULT;
    use crate::test_helpers::TestVm;

    /// Test that executing an invalid instruction (all zeros) causes STATUS_FAULT.
    ///
    /// Currently the interpreter sets STATUS_FAULT for unknown opcodes.
    /// TODO: Once SIGILL delivery is implemented, this test should verify
    /// that SIGILL (signal 4) is queued and delivered to the guest handler.
    /// For now we just check the current behavior: status == STATUS_FAULT.
    #[test]
    fn sigill_on_invalid_instruction() {
        let mut t = TestVm::new();
        let code_addr: u64 = t.scratch;

        // Write an invalid 32-bit instruction: 0x00000000 has opcode bits [6:0] = 0b0000000.
        // The two low bits are not 0b11, so the interpreter first tries compressed decode.
        // The compressed halfword 0x0000 expands to 0 → STATUS_FAULT.
        unsafe {
            crate::guest_mem::write_u32(t.base, code_addr, 0x0000_0000);
        }

        t.vm.pc = code_addr;
        t.vm.status = crate::abi::STATUS_OK;

        unsafe {
            crate::cpu::exec(&mut t.vm, 10, None, None, None, None);
        }

        assert_eq!(
            t.vm.status, STATUS_FAULT,
            "executing an invalid instruction should set STATUS_FAULT"
        );
    }
}
