//! Integer, branch, and scalar memory instruction executors.
//!
//! Reference: RISC-V ISA spec V20191213
//!   (https://github.com/riscv/riscv-isa-manual/releases/tag/Ratified-IMAFDQC)
//!   §2 (RV32I), §5 (RV64I), §7 (M)
//!
//! This module holds the instruction-local helpers used by the main exec loop.

use super::decode;
use crate::guest_mem;

// =============================================================================
// Integer ALU executors
// =============================================================================

/// Execute OP-IMM instructions (ADDI, SLLI, SLTI, SLTIU, XORI, SRLI/SRAI, ORI, ANDI).
#[inline(always)]
pub(super) unsafe fn exec_op_imm(x: &mut [u64; 32], raw: u32, pc: &mut u64, step: u64) {
    let rd = decode::rd(raw);
    let rs1 = decode::rs1(raw);
    let imm = decode::imm_i(raw);
    let v1 = x[rs1] as i64;
    let result = match decode::funct3(raw) {
        0 => v1.wrapping_add(imm),            // ADDI
        1 => (x[rs1] << (imm & 0x3F)) as i64, // SLLI
        2 if v1 < imm => 1,                   // SLTI
        3 if x[rs1] < imm as u64 => 1,        // SLTIU
        4 => v1 ^ imm,                        // XORI
        5 => {
            let shamt = imm & 0x3F;
            if (raw >> 30) & 1 != 0 {
                v1 >> shamt // SRAI
            } else {
                (x[rs1] >> shamt) as i64 // SRLI
            }
        }
        6 => v1 | imm, // ORI
        7 => v1 & imm, // ANDI
        _ => 0,
    };
    if rd != 0 {
        x[rd] = result as u64;
    }
    *pc += step;
}

/// Execute OP-IMM-32 instructions (ADDIW, SLLIW, SRLIW, SRAIW).
#[inline(always)]
pub(super) unsafe fn exec_op_imm_32(x: &mut [u64; 32], raw: u32, pc: &mut u64, step: u64) {
    let rd = decode::rd(raw);
    let rs1 = decode::rs1(raw);
    let imm = decode::imm_i(raw);
    let v1 = x[rs1] as i32;
    let result: i32 = match decode::funct3(raw) {
        0 => v1.wrapping_add(imm as i32), // ADDIW
        1 => v1 << (imm & 0x1F),          // SLLIW
        5 => {
            let shamt = (imm & 0x1F) as u32;
            if (raw >> 30) & 1 != 0 {
                v1 >> shamt // SRAIW
            } else {
                ((v1 as u32) >> shamt) as i32 // SRLIW
            }
        }
        _ => 0,
    };
    if rd != 0 {
        x[rd] = result as i64 as u64;
    }
    *pc += step;
}

/// Execute OP instructions from RV64I and RV64M.
#[inline(always)]
pub(super) unsafe fn exec_op(x: &mut [u64; 32], raw: u32, pc: &mut u64, step: u64) {
    let rd = decode::rd(raw);
    let rs1 = decode::rs1(raw);
    let rs2 = decode::rs2(raw);
    let f7 = decode::funct7(raw);
    let v1 = x[rs1];
    let v2 = x[rs2];

    let result: u64 = if f7 == 1 {
        match decode::funct3(raw) {
            0 => (v1 as i64).wrapping_mul(v2 as i64) as u64, // MUL
            1 => mulh(v1 as i64, v2 as i64) as u64,          // MULH
            2 => mulhsu(v1 as i64, v2) as u64,               // MULHSU
            3 => mulhu(v1, v2),                              // MULHU
            4 => div_i64(v1 as i64, v2 as i64) as u64,       // DIV
            5 => divu_64(v1, v2),                            // DIVU
            6 => rem_i64(v1 as i64, v2 as i64) as u64,       // REM
            7 => remu_64(v1, v2),                            // REMU
            _ => 0,
        }
    } else {
        match decode::funct3(raw) {
            0 => {
                if f7 == 0x20 {
                    (v1 as i64).wrapping_sub(v2 as i64) as u64
                } else {
                    v1.wrapping_add(v2)
                }
            }
            1 => v1 << (v2 & 0x3F),              // SLL
            2 if (v1 as i64) < (v2 as i64) => 1, // SLT
            3 if v1 < v2 => 1,                   // SLTU
            4 => v1 ^ v2,                        // XOR
            5 => {
                if f7 == 0x20 {
                    ((v1 as i64) >> (v2 & 0x3F)) as u64
                } else {
                    v1 >> (v2 & 0x3F)
                }
            }
            6 => v1 | v2, // OR
            7 => v1 & v2, // AND
            _ => 0,
        }
    };
    if rd != 0 {
        x[rd] = result;
    }
    *pc += step;
}

/// Execute OP-32 instructions from RV64I and RV64M.
#[inline(always)]
pub(super) unsafe fn exec_op_32(x: &mut [u64; 32], raw: u32, pc: &mut u64, step: u64) {
    let rd = decode::rd(raw);
    let rs1 = decode::rs1(raw);
    let rs2 = decode::rs2(raw);
    let f7 = decode::funct7(raw);
    let v1 = x[rs1] as i32;
    let v2 = x[rs2] as i32;

    let result: i32 = if f7 == 1 {
        match decode::funct3(raw) {
            0 => v1.wrapping_mul(v2), // MULW
            4 => {
                if v2 == 0 {
                    -1
                } else if v1 == i32::MIN && v2 == -1 {
                    v1
                } else {
                    v1 / v2
                }
            }
            5 => {
                let u1 = v1 as u32;
                let u2 = v2 as u32;
                u1.checked_div(u2).map_or(u32::MAX as i32, |q| q as i32)
            }
            6 => {
                if v2 == 0 {
                    v1
                } else if v1 == i32::MIN && v2 == -1 {
                    0
                } else {
                    v1 % v2
                }
            }
            7 => {
                let u1 = v1 as u32;
                let u2 = v2 as u32;
                if u2 == 0 { v1 } else { (u1 % u2) as i32 }
            }
            _ => 0,
        }
    } else {
        match decode::funct3(raw) {
            0 => {
                if f7 == 0x20 {
                    v1.wrapping_sub(v2)
                } else {
                    v1.wrapping_add(v2)
                }
            }
            1 => v1 << (v2 & 0x1F), // SLLW
            5 => {
                if f7 == 0x20 {
                    v1 >> (v2 & 0x1F)
                } else {
                    ((v1 as u32) >> (v2 as u32 & 0x1F)) as i32
                }
            }
            _ => 0,
        }
    };
    if rd != 0 {
        x[rd] = result as i64 as u64;
    }
    *pc += step;
}

// =============================================================================
// Scalar load/store and branch helpers
// =============================================================================

/// Execute LOAD instructions (LB/LH/LW/LD/LBU/LHU/LWU).
#[inline(always)]
pub(super) unsafe fn exec_load(x: &mut [u64; 32], raw: u32, base: u32, pc: &mut u64, step: u64) {
    let rd = decode::rd(raw);
    let rs1 = decode::rs1(raw);
    let addr = (x[rs1] as i64 + decode::imm_i(raw)) as u64;
    let val: u64 = unsafe {
        match decode::funct3(raw) {
            0 => guest_mem::read_i8(base, addr) as u64,  // LB
            1 => guest_mem::read_i16(base, addr) as u64, // LH
            2 => guest_mem::read_i32(base, addr) as u64, // LW
            3 => guest_mem::read_u64(base, addr),        // LD
            4 => guest_mem::read_u8(base, addr) as u64,  // LBU
            5 => guest_mem::read_u16(base, addr) as u64, // LHU
            6 => guest_mem::read_u32(base, addr) as u64, // LWU
            _ => 0,
        }
    };
    if rd != 0 {
        x[rd] = val;
    }
    *pc += step;
}

/// Execute STORE instructions (SB/SH/SW/SD).
#[inline(always)]
pub(super) unsafe fn exec_store(x: &[u64; 32], raw: u32, base: u32, pc: &mut u64, step: u64) {
    let rs1 = decode::rs1(raw);
    let rs2 = decode::rs2(raw);
    let addr = (x[rs1] as i64 + decode::imm_s(raw)) as u64;
    let val = x[rs2];
    unsafe {
        match decode::funct3(raw) {
            0 => guest_mem::write_u8(base, addr, val as u8),
            1 => guest_mem::write_u16(base, addr, val as u16),
            2 => guest_mem::write_u32(base, addr, val as u32),
            3 => guest_mem::write_u64(base, addr, val),
            _ => {}
        }
    }
    *pc += step;
}

/// Evaluate BRANCH conditions (BEQ/BNE/BLT/BGE/BLTU/BGEU).
#[inline(always)]
pub(super) fn exec_branch(x: &[u64; 32], raw: u32) -> bool {
    let rs1 = decode::rs1(raw);
    let rs2 = decode::rs2(raw);
    let v1 = x[rs1];
    let v2 = x[rs2];
    match decode::funct3(raw) {
        0 => v1 == v2,                   // BEQ
        1 => v1 != v2,                   // BNE
        4 => (v1 as i64) < (v2 as i64),  // BLT
        5 => (v1 as i64) >= (v2 as i64), // BGE
        6 => v1 < v2,                    // BLTU
        7 => v1 >= v2,                   // BGEU
        _ => false,
    }
}

// =============================================================================
// M extension helpers (DIV/REM with RISC-V spec semantics)
// =============================================================================

/// Signed division with RV64M overflow and divide-by-zero semantics.
#[inline(always)]
pub(super) fn div_i64(a: i64, b: i64) -> i64 {
    if b == 0 {
        return -1;
    }
    if a == i64::MIN && b == -1 {
        return a;
    }
    a / b
}

/// Unsigned division with RV64M divide-by-zero semantics.
#[inline(always)]
pub(super) fn divu_64(a: u64, b: u64) -> u64 {
    if b == 0 {
        return u64::MAX;
    }
    a / b
}

/// Signed remainder with RV64M overflow and divide-by-zero semantics.
#[inline(always)]
pub(super) fn rem_i64(a: i64, b: i64) -> i64 {
    if b == 0 {
        return a;
    }
    if a == i64::MIN && b == -1 {
        return 0;
    }
    a % b
}

/// Unsigned remainder with RV64M divide-by-zero semantics.
#[inline(always)]
pub(super) fn remu_64(a: u64, b: u64) -> u64 {
    if b == 0 {
        return a;
    }
    a % b
}

/// High 64 bits of signed 64x64 multiplication.
#[inline(always)]
pub(super) fn mulh(a: i64, b: i64) -> i64 {
    ((a as i128 * b as i128) >> 64) as i64
}

/// High 64 bits of signed x unsigned 64x64 multiplication.
#[inline(always)]
pub(super) fn mulhsu(a: i64, b: u64) -> i64 {
    ((a as i128 * b as i128) >> 64) as i64
}

/// High 64 bits of unsigned 64x64 multiplication.
#[inline(always)]
pub(super) fn mulhu(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) >> 64) as u64
}
