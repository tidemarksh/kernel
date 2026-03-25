//! CPU execution engine: interpreter + block cache + JIT integration.
//!
//! exec() is the main interpreter loop. It runs `budget` instructions,
//! then returns to JS. Block cache amortizes decode cost.
//! JIT hooks (trace recording, JIT_READY handoff) are integrated
//! but disabled until Phase 7.

pub mod block_cache;
pub mod decode;
pub mod trace;

use crate::abi;
use crate::guest_mem;
use crate::types::ThreadState;
use self::block_cache::BlockCache;
use self::trace::{HotCounts, JitBitmap, TraceBuffer};

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
    let mut pc = vm.pc;
    let mut x = vm.x;
    let mut f = vm.f;
    let fcsr = vm.fcsr;
    let base = ram_base(vm);
    let mut remaining = budget;

    loop {
        if remaining <= 0 { break; }
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

        // --- Trace recording (JIT Phase 7 hook) ---
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
            decode::OP_LOAD => exec_load(&mut x, raw, base, &mut pc, step),
            decode::OP_STORE => exec_store(&x, raw, base, &mut pc, step),
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

                // JALR return prediction: rs1==ra (x1) → try block cache
                if rs1v == 1 {
                    if let Some(ref mut bc) = cache {
                        if let Some(blk) = bc.get(target) {
                            // Execute the cached block directly
                            let block_budget = blk.total_budget as i32;
                            if remaining >= block_budget {
                                remaining -= block_budget;
                                // Skip: actual exec_block integration deferred
                                // (block cache dispatch requires exec_block which
                                //  duplicates the match arms — implemented in Phase 7
                                //  when JIT region compilation subsumes block cache)
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
                            // ECALL — syscall
                            vm.x = x;
                            vm.f = f;
                            vm.pc = pc + step;
                            vm.status = abi::STATUS_FAULT;
                            return remaining;
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
                    exec_csr(&mut x, raw, &mut pc, step, fcsr);
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
            decode::OP_OP_FP => exec_op_fp(&mut x, &mut f, raw, &mut pc, step),
            decode::OP_FMADD | decode::OP_FMSUB | decode::OP_FNMSUB | decode::OP_FNMADD => {
                exec_fma(&mut f, raw, opcode, &mut pc, step);
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
    remaining
}

/// Get RAM base address from ThreadState's ProcessState pointer.
#[inline(always)]
unsafe fn ram_base(_vm: &ThreadState) -> u32 {
    // TODO: read from ProcessState when process model is implemented
    // For now, return 0 (guest memory starts at WASM linear memory base)
    0
}

// =============================================================================
// Instruction executors
// =============================================================================

#[inline(always)]
unsafe fn exec_op_imm(x: &mut [u64; 32], raw: u32, pc: &mut u64, step: u64) {
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

#[inline(always)]
unsafe fn exec_op_imm_32(x: &mut [u64; 32], raw: u32, pc: &mut u64, step: u64) {
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

#[inline(always)]
unsafe fn exec_op(x: &mut [u64; 32], raw: u32, pc: &mut u64, step: u64) {
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

#[inline(always)]
unsafe fn exec_op_32(x: &mut [u64; 32], raw: u32, pc: &mut u64, step: u64) {
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

#[inline(always)]
unsafe fn exec_load(x: &mut [u64; 32], raw: u32, base: u32, pc: &mut u64, step: u64) {
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

#[inline(always)]
unsafe fn exec_store(x: &[u64; 32], raw: u32, base: u32, pc: &mut u64, step: u64) {
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

// Placeholder implementations for FP, AMO, CSR
#[inline(always)]
unsafe fn exec_load_fp(f: &mut [u64; 32], x: &[u64; 32], raw: u32, base: u32, pc: &mut u64, step: u64) {
    let rd = decode::rd(raw);
    let rs1 = decode::rs1(raw);
    let addr = (x[rs1] as i64 + decode::imm_i(raw)) as u64;
    match decode::funct3(raw) {
        2 => f[rd] = guest_mem::read_u32(base, addr) as u64, // FLW (NaN-boxed)
        3 => f[rd] = guest_mem::read_u64(base, addr),        // FLD
        _ => {}
    }
    *pc += step;
}

#[inline(always)]
unsafe fn exec_store_fp(f: &[u64; 32], x: &[u64; 32], raw: u32, base: u32, pc: &mut u64, step: u64) {
    let rs1 = decode::rs1(raw);
    let rs2 = decode::rs2(raw);
    let addr = (x[rs1] as i64 + decode::imm_s(raw)) as u64;
    match decode::funct3(raw) {
        2 => guest_mem::write_u32(base, addr, f[rs2] as u32), // FSW
        3 => guest_mem::write_u64(base, addr, f[rs2]),        // FSD
        _ => {}
    }
    *pc += step;
}

#[inline(always)]
unsafe fn exec_op_fp(_x: &mut [u64; 32], f: &mut [u64; 32], raw: u32, pc: &mut u64, step: u64) {
    let rd = decode::rd(raw);
    let rs1 = decode::rs1(raw);
    let rs2 = decode::rs2(raw);
    let f7 = decode::funct7(raw);
    let v1 = f64::from_bits(f[rs1]);
    let v2 = f64::from_bits(f[rs2]);

    // Double-precision FP operations (funct7 upper bits determine operation)
    let funct5 = f7 >> 2;
    match funct5 {
        0x00 => f[rd] = (v1 + v2).to_bits(),     // FADD.D
        0x01 => f[rd] = (v1 - v2).to_bits(),     // FSUB.D
        0x02 => f[rd] = (v1 * v2).to_bits(),     // FMUL.D
        0x03 => f[rd] = (v1 / v2).to_bits(),     // FDIV.D
        0x0B => f[rd] = libm::sqrt(v1).to_bits(),   // FSQRT.D
        _ => {} // TODO: FMIN, FMAX, FCVT, FMV, FCLASS, comparisons
    }
    *pc += step;
}

#[inline(always)]
unsafe fn exec_fma(f: &mut [u64; 32], raw: u32, opcode: u32, pc: &mut u64, step: u64) {
    let rd = decode::rd(raw);
    let rs1 = decode::rs1(raw);
    let rs2 = decode::rs2(raw);
    let rs3 = decode::rs3(raw);
    let v1 = f64::from_bits(f[rs1]);
    let v2 = f64::from_bits(f[rs2]);
    let v3 = f64::from_bits(f[rs3]);
    let result = match opcode {
        decode::OP_FMADD  => v1 * v2 + v3,   // FMADD
        decode::OP_FMSUB  => v1 * v2 - v3,   // FMSUB
        decode::OP_FNMSUB => -(v1 * v2) + v3, // FNMSUB
        decode::OP_FNMADD => -(v1 * v2) - v3, // FNMADD
        _ => 0.0,
    };
    f[rd] = result.to_bits();
    *pc += step;
}

#[inline(always)]
unsafe fn exec_amo(x: &mut [u64; 32], raw: u32, base: u32, pc: &mut u64, step: u64) {
    let rd = decode::rd(raw);
    let rs1 = decode::rs1(raw);
    let rs2 = decode::rs2(raw);
    let funct5 = decode::funct5(raw);
    let f3 = decode::funct3(raw);
    let is_word = f3 == 2;
    let addr = x[rs1];

    match funct5 {
        0x02 => { // LR
            let old = if is_word { guest_mem::read_i32(base, addr) as u64 }
                      else { guest_mem::read_u64(base, addr) };
            if rd != 0 { x[rd] = old; }
        }
        0x03 => { // SC — always succeeds in single-threaded
            if is_word { guest_mem::write_u32(base, addr, x[rs2] as u32); }
            else { guest_mem::write_u64(base, addr, x[rs2]); }
            if rd != 0 { x[rd] = 0; } // success
        }
        _ => {
            // AMO: read-modify-write
            let old = if is_word { guest_mem::read_i32(base, addr) as i64 as u64 }
                      else { guest_mem::read_u64(base, addr) };
            let new_val = match funct5 {
                0x01 => x[rs2],                                  // AMOSWAP
                0x00 => old.wrapping_add(x[rs2]),                // AMOADD
                0x04 => old ^ x[rs2],                            // AMOXOR
                0x0C => old & x[rs2],                            // AMOAND
                0x08 => old | x[rs2],                            // AMOOR
                0x10 => core::cmp::min(old as i64, x[rs2] as i64) as u64, // AMOMIN
                0x14 => core::cmp::max(old as i64, x[rs2] as i64) as u64, // AMOMAX
                0x18 => core::cmp::min(old, x[rs2]),             // AMOMINU
                0x1C => core::cmp::max(old, x[rs2]),             // AMOMAXU
                _ => old,
            };
            if is_word { guest_mem::write_u32(base, addr, new_val as u32); }
            else { guest_mem::write_u64(base, addr, new_val); }
            if rd != 0 { x[rd] = old; }
        }
    }
    *pc += step;
}

#[inline(always)]
fn exec_csr(x: &mut [u64; 32], raw: u32, pc: &mut u64, step: u64, _fcsr: u32) {
    let rd = decode::rd(raw);
    let _csr = (raw >> 20) & 0xFFF;
    // Stub: return 0 for all CSR reads
    if rd != 0 { x[rd] = 0; }
    *pc += step;
}

// =============================================================================
// M extension helpers (DIV/REM with RISC-V spec §7.2 Table 7.1 semantics)
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
