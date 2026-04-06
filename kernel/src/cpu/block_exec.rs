//! Cached basic block execution helpers.
//!
//! Reference: RISC-V ISA spec V20191213
//!   (https://github.com/riscv/riscv-isa-manual/releases/tag/Ratified-IMAFDQC)
//!   §2 (RV32I), §5 (RV64I), §7 (M)
//!
//! This module executes pre-decoded `BlockEntry` values produced by the
//! direct-mapped block cache.

use super::block_cache::BlockEntry;
use super::integer::{div_i64, divu_64, mulh, mulhsu, mulhu, rem_i64, remu_64};
use crate::guest_mem;

const REG_WRITE_SOURCE_BLOCK: u32 = 3;

// =============================================================================
// Cached block execution
// =============================================================================

/// Execute a cached basic block.
///
/// Returns the number of operations consumed from the budget. If the block
/// encounters an unsupported cached op, execution bails out to the interpreter
/// at the current PC.
pub(super) unsafe fn exec_block(
    blk: &BlockEntry,
    x: &mut [u64; 32],
    pc: &mut u64,
    base: u32,
    tid: i32,
) -> i32 {
    let len = blk.len as usize;
    let mut cur_pc = blk.start_pc;

    for i in 0..len {
        let op = blk.ops[i];
        let prev_sp = x[2];
        let prev_tp = x[4];
        let prev_s11 = x[27];
        let op_pc = cur_pc;
        let rd = op.rd();
        let r1 = op.rs1();
        let r2 = op.rs2();
        let f3 = op.f3();
        let step = op.step();
        let imm = op.imm() as i64;

        match op.op_id() {
            1 => {
                let v = x[r1] as i64;
                let r = match f3 {
                    0 => v.wrapping_add(imm),
                    1 => (x[r1] << (imm & 0x3F)) as i64,
                    2 if v < imm => 1,
                    3 if x[r1] < imm as u64 => 1,
                    4 => v ^ imm,
                    5 => {
                        let sh = imm & 0x3F;
                        if op.f7b5() {
                            v >> sh
                        } else {
                            (x[r1] >> sh) as i64
                        }
                    }
                    6 => v | imm,
                    7 => v & imm,
                    _ => 0,
                };
                if rd != 0 {
                    x[rd] = r as u64;
                }
            }
            2 => {
                let v = x[r1] as i32;
                let r: i32 = match f3 {
                    0 => v.wrapping_add(imm as i32),
                    1 => v << (imm & 0x1F),
                    5 => {
                        let sh = (imm & 0x1F) as u32;
                        if op.f7b5() {
                            v >> sh
                        } else {
                            ((v as u32) >> sh) as i32
                        }
                    }
                    _ => 0,
                };
                if rd != 0 {
                    x[rd] = r as i64 as u64;
                }
            }
            3 => {
                let v1 = x[r1];
                let v2 = x[r2];
                let r: u64 = match f3 {
                    0 => {
                        if op.f7b5() {
                            (v1 as i64).wrapping_sub(v2 as i64) as u64
                        } else {
                            v1.wrapping_add(v2)
                        }
                    }
                    1 => v1 << (v2 & 0x3F),
                    2 if (v1 as i64) < (v2 as i64) => 1,
                    3 if v1 < v2 => 1,
                    4 => v1 ^ v2,
                    5 => {
                        if op.f7b5() {
                            ((v1 as i64) >> (v2 & 0x3F)) as u64
                        } else {
                            v1 >> (v2 & 0x3F)
                        }
                    }
                    6 => v1 | v2,
                    7 => v1 & v2,
                    _ => 0,
                };
                if rd != 0 {
                    x[rd] = r;
                }
            }
            22 => {
                let v1 = x[r1];
                let v2 = x[r2];
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
                if rd != 0 {
                    x[rd] = r;
                }
            }
            4 => {
                let v1 = x[r1] as i32;
                let v2 = x[r2] as i32;
                let r: i32 = match f3 {
                    0 => {
                        if op.f7b5() {
                            v1.wrapping_sub(v2)
                        } else {
                            v1.wrapping_add(v2)
                        }
                    }
                    1 => v1 << (v2 & 0x1F),
                    5 => {
                        if op.f7b5() {
                            v1 >> (v2 & 0x1F)
                        } else {
                            ((v1 as u32) >> (v2 as u32 & 0x1F)) as i32
                        }
                    }
                    _ => 0,
                };
                if rd != 0 {
                    x[rd] = r as i64 as u64;
                }
            }
            23 => {
                let v1 = x[r1] as i32;
                let v2 = x[r2] as i32;
                let r: i32 = match f3 {
                    0 => v1.wrapping_mul(v2),
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
                        let (u1, u2) = (v1 as u32, v2 as u32);
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
                        let (u1, u2) = (v1 as u32, v2 as u32);
                        if u2 == 0 { v1 } else { (u1 % u2) as i32 }
                    }
                    _ => 0,
                };
                if rd != 0 {
                    x[rd] = r as i64 as u64;
                }
            }
            5 => {
                let addr = (x[r1] as i64 + imm) as u64;
                let val: u64 = unsafe {
                    match f3 {
                        0 => guest_mem::read_i8(base, addr) as u64,
                        1 => guest_mem::read_i16(base, addr) as u64,
                        2 => guest_mem::read_i32(base, addr) as u64,
                        3 => guest_mem::read_u64(base, addr),
                        4 => guest_mem::read_u8(base, addr) as u64,
                        5 => guest_mem::read_u16(base, addr) as u64,
                        6 => guest_mem::read_u32(base, addr) as u64,
                        _ => 0,
                    }
                };
                if rd != 0 {
                    x[rd] = val;
                }
            }
            6 => {
                let addr = (x[r1] as i64 + imm) as u64;
                unsafe {
                    match f3 {
                        0 => guest_mem::write_u8(base, addr, x[r2] as u8),
                        1 => guest_mem::write_u16(base, addr, x[r2] as u16),
                        2 => guest_mem::write_u32(base, addr, x[r2] as u32),
                        3 => guest_mem::write_u64(base, addr, x[r2]),
                        _ => {}
                    }
                }
            }
            7 => {
                if rd != 0 {
                    x[rd] = imm as u64;
                }
            }
            8 => {
                if rd != 0 {
                    x[rd] = (cur_pc as i64 + imm) as u64;
                }
            }
            9 => {
                let taken = match f3 {
                    0 => x[r1] == x[r2],
                    1 => x[r1] != x[r2],
                    4 => (x[r1] as i64) < (x[r2] as i64),
                    5 => (x[r1] as i64) >= (x[r2] as i64),
                    6 => x[r1] < x[r2],
                    7 => x[r1] >= x[r2],
                    _ => false,
                };
                *pc = if taken {
                    (cur_pc as i64 + imm) as u64
                } else {
                    cur_pc + step
                };
                x[0] = 0;
                crate::harness_hooks::record_special_reg_transitions(
                    tid,
                    op_pc,
                    0,
                    REG_WRITE_SOURCE_BLOCK,
                    prev_sp,
                    prev_tp,
                    prev_s11,
                    x,
                );
                return blk.total_budget as i32;
            }
            10 => {
                if rd != 0 {
                    x[rd] = cur_pc + step;
                }
                *pc = (cur_pc as i64 + imm) as u64;
                x[0] = 0;
                crate::harness_hooks::record_special_reg_transitions(
                    tid,
                    op_pc,
                    0,
                    REG_WRITE_SOURCE_BLOCK,
                    prev_sp,
                    prev_tp,
                    prev_s11,
                    x,
                );
                return blk.total_budget as i32;
            }
            11 => {
                let target = ((x[r1] as i64 + imm) as u64) & !1;
                crate::harness_hooks::record_jalr(cur_pc, rd, r1, x[r1], target);
                if rd != 0 {
                    x[rd] = cur_pc + step;
                }
                *pc = target;
                x[0] = 0;
                crate::harness_hooks::record_special_reg_transitions(
                    tid,
                    op_pc,
                    0,
                    REG_WRITE_SOURCE_BLOCK,
                    prev_sp,
                    prev_tp,
                    prev_s11,
                    x,
                );
                return blk.total_budget as i32;
            }
            13 => {}
            _ => {
                *pc = cur_pc;
                x[0] = 0;
                crate::harness_hooks::record_special_reg_transitions(
                    tid,
                    op_pc,
                    0,
                    REG_WRITE_SOURCE_BLOCK,
                    prev_sp,
                    prev_tp,
                    prev_s11,
                    x,
                );
                return i as i32;
            }
        }

        x[0] = 0;
        crate::harness_hooks::record_special_reg_transitions(
            tid,
            op_pc,
            0,
            REG_WRITE_SOURCE_BLOCK,
            prev_sp,
            prev_tp,
            prev_s11,
            x,
        );
        cur_pc += step;
    }

    *pc = cur_pc;
    blk.total_budget as i32
}
