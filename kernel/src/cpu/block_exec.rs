//! Cached basic block execution helpers.
//!
//! Reference: RISC-V ISA spec V20191213
//!   (https://github.com/riscv/riscv-isa-manual/releases/tag/Ratified-IMAFDQC)
//!   §2 (RV32I), §5 (RV64I), §7 (M)
//!
//! This module executes pre-decoded `BlockEntry` values produced by the
//! direct-mapped block cache.

use super::atomic::exec_amo;
use super::block_cache::BlockEntry;
use super::decode;
use super::fault::{AccessOutcome, AccessPermitCache, ensure_guest_access};
use super::fp::{exec_fma, exec_op_fp};
use super::integer::{div_i64, divu_64, mulh, mulhsu, mulhu, rem_i64, remu_64};
use super::trace::{HotCounts, JitBitmap, TraceBuffer};
use crate::abi;
use crate::guest_mem;
use crate::types::ThreadState;

fn sampled_block_signature(blk: &BlockEntry) -> u64 {
    let mut signature = 0xcbf2_9ce4_8422_2325u64;
    for op in blk.ops.iter().take(blk.len as usize) {
        signature ^= op.op_id() as u64;
        signature = signature.wrapping_mul(0x100_0000_01b3);
    }
    signature
}

fn record_sampled_block(blk: &BlockEntry, sampled: bool) {
    if sampled {
        crate::tracepoints::record_block_exec_sampled_block(
            blk.start_pc,
            blk.len as u32,
            blk.loop_flags as u32,
            sampled_block_signature(blk),
        );
    }
}

pub(super) enum BlockOutcome {
    Restart,
    Return,
    Unsupported,
}

enum JitBackedgeOutcome {
    None,
    StartTrace,
    Compiled,
}

fn observe_jit_backedge(
    vm: &mut ThreadState,
    x: &[u64; 32],
    f: &[u64; 32],
    pc: u64,
    target: u64,
    hot_counts: Option<&mut HotCounts>,
    jit_bitmap: Option<&JitBitmap>,
    trace_buf: Option<&mut TraceBuffer>,
) -> JitBackedgeOutcome {
    if target >= pc {
        return JitBackedgeOutcome::None;
    }
    if jit_bitmap.is_some_and(|bitmap| bitmap.is_ready(target)) {
        vm.x = *x;
        vm.f = *f;
        vm.pc = target;
        vm.status = abi::STATUS_JIT_READY;
        return JitBackedgeOutcome::Compiled;
    }
    if hot_counts.is_some_and(|counts| counts.increment(target))
        && let Some(trace) = trace_buf
        && trace.recording == 0
    {
        trace.start(target);
        return JitBackedgeOutcome::StartTrace;
    }
    JitBackedgeOutcome::None
}

#[inline(always)]
fn block_budget_charge<const FIRST_CONSUMED: bool>(len: usize) -> i32 {
    if FIRST_CONSUMED {
        len.saturating_sub(1) as i32
    } else {
        len as i32
    }
}

#[inline(always)]
fn block_budget_refund_after(len: usize, index: usize) -> i32 {
    len.saturating_sub(index + 1) as i32
}

#[inline(always)]
fn block_budget_refund_from<const FIRST_CONSUMED: bool>(len: usize, index: usize) -> i32 {
    let first_charged = if FIRST_CONSUMED { 1 } else { 0 };
    if index < first_charged {
        len.saturating_sub(first_charged) as i32
    } else {
        len.saturating_sub(index) as i32
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn exec_simple_load_scan_loop<const FIRST_CONSUMED: bool>(
    blk: &BlockEntry,
    vm: &mut ThreadState,
    x: &mut [u64; 32],
    f: &mut [u64; 32],
    fcsr: &mut u32,
    pc: &mut u64,
    base: u32,
    remaining: &mut i32,
    access_cache: &mut AccessPermitCache,
    memory_is_multi_threaded: bool,
    hot_counts: Option<&mut HotCounts>,
    jit_bitmap: Option<&JitBitmap>,
    trace_buf: Option<&mut TraceBuffer>,
) -> BlockOutcome {
    // Select the memory synchronization mode once, outside the cached loop.
    if memory_is_multi_threaded {
        unsafe {
            exec_simple_load_scan_loop_for_mode::<FIRST_CONSUMED, true>(
                blk,
                vm,
                x,
                f,
                fcsr,
                pc,
                base,
                remaining,
                access_cache,
                hot_counts,
                jit_bitmap,
                trace_buf,
            )
        }
    } else {
        unsafe {
            exec_simple_load_scan_loop_for_mode::<FIRST_CONSUMED, false>(
                blk,
                vm,
                x,
                f,
                fcsr,
                pc,
                base,
                remaining,
                access_cache,
                hot_counts,
                jit_bitmap,
                trace_buf,
            )
        }
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn exec_simple_load_scan_loop_for_mode<
    const FIRST_CONSUMED: bool,
    const MULTI_THREADED: bool,
>(
    blk: &BlockEntry,
    vm: &mut ThreadState,
    x: &mut [u64; 32],
    f: &mut [u64; 32],
    fcsr: &mut u32,
    pc: &mut u64,
    base: u32,
    remaining: &mut i32,
    access_cache: &mut AccessPermitCache,
    mut hot_counts: Option<&mut HotCounts>,
    jit_bitmap: Option<&JitBitmap>,
    mut trace_buf: Option<&mut TraceBuffer>,
) -> BlockOutcome {
    let len = blk.len as usize;
    let mut cur_pc = blk.start_pc;
    let mut charged_ops = 0u32;
    let sample_ops = crate::tracepoints::record_block_exec_sample_start();
    record_sampled_block(blk, sample_ops);
    *remaining -= block_budget_charge::<FIRST_CONSUMED>(len);
    charged_ops = charged_ops.saturating_add(len as u32);

    'block_loop: loop {
        for index in 0..len {
            let op = blk.ops[index];
            let rd = op.rd();
            let r1 = op.rs1();
            let r2 = op.rs2();
            let f3 = op.f3();
            let step = op.step();
            let imm = op.imm() as i64;
            let op_id = op.op_id();
            if sample_ops {
                crate::tracepoints::record_block_exec_sampled_op(op_id as u32);
            }

            match op_id {
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
                5 => {
                    let addr = (x[r1] as i64 + imm) as u64;
                    let width = match f3 {
                        0 | 4 => 1,
                        1 | 5 => 2,
                        2 | 6 => 4,
                        3 => 8,
                        _ => 0,
                    };
                    *pc = cur_pc;
                    match unsafe {
                        ensure_guest_access(
                            vm,
                            x,
                            f,
                            fcsr,
                            pc,
                            base,
                            addr,
                            width,
                            abi::PROT_READ,
                            access_cache,
                        )
                    } {
                        AccessOutcome::Ok => {}
                        AccessOutcome::Restart => {
                            *remaining += block_budget_refund_after(len, index);
                            crate::tracepoints::record_block_exec_ops(charged_ops);
                            return BlockOutcome::Restart;
                        }
                        AccessOutcome::Return => {
                            *remaining += block_budget_refund_after(len, index);
                            crate::tracepoints::record_block_exec_ops(charged_ops);
                            return BlockOutcome::Return;
                        }
                    }
                    let val: u64 = match f3 {
                        0 => unsafe { guest_mem::read_u8_unchecked(base, addr) as i8 as u64 },
                        1 => unsafe {
                            (if MULTI_THREADED {
                                guest_mem::read_u16_seqlock(base, addr)
                            } else {
                                guest_mem::read_u16(base, addr)
                            }) as i16 as u64
                        },
                        2 => unsafe {
                            (if MULTI_THREADED {
                                guest_mem::read_u32_seqlock(base, addr)
                            } else {
                                guest_mem::read_u32(base, addr)
                            }) as i32 as u64
                        },
                        3 => unsafe {
                            if MULTI_THREADED {
                                guest_mem::read_u64_seqlock(base, addr)
                            } else {
                                guest_mem::read_u64(base, addr)
                            }
                        },
                        4 => unsafe { guest_mem::read_u8_unchecked(base, addr) as u64 },
                        5 => unsafe {
                            (if MULTI_THREADED {
                                guest_mem::read_u16_seqlock(base, addr)
                            } else {
                                guest_mem::read_u16(base, addr)
                            }) as u64
                        },
                        6 => unsafe {
                            (if MULTI_THREADED {
                                guest_mem::read_u32_seqlock(base, addr)
                            } else {
                                guest_mem::read_u32(base, addr)
                            }) as u64
                        },
                        _ => 0,
                    };
                    if rd != 0 {
                        x[rd] = val;
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
                    if taken {
                        let target = (cur_pc as i64 + imm) as u64;
                        match observe_jit_backedge(
                            vm,
                            x,
                            f,
                            cur_pc,
                            target,
                            hot_counts.as_deref_mut(),
                            jit_bitmap,
                            trace_buf.as_deref_mut(),
                        ) {
                            JitBackedgeOutcome::Compiled => {
                                *pc = target;
                                return BlockOutcome::Return;
                            }
                            JitBackedgeOutcome::StartTrace => {
                                *pc = target;
                                crate::tracepoints::record_block_exec_ops(charged_ops);
                                return BlockOutcome::Restart;
                            }
                            JitBackedgeOutcome::None => {}
                        }
                        if target == blk.start_pc && index + 1 == len && *remaining >= len as i32 {
                            *remaining -= len as i32;
                            charged_ops = charged_ops.saturating_add(len as u32);
                            cur_pc = blk.start_pc;
                            x[0] = 0;
                            continue 'block_loop;
                        }
                        *pc = target;
                    } else {
                        *pc = cur_pc + step;
                    }
                    x[0] = 0;
                    crate::tracepoints::record_block_exec_ops(charged_ops);
                    return BlockOutcome::Restart;
                }
                _ => {
                    *remaining += block_budget_refund_from::<FIRST_CONSUMED>(len, index);
                    crate::tracepoints::record_block_exec_unsupported_op(op_id as u32);
                    *pc = cur_pc;
                    crate::tracepoints::record_block_exec_ops(charged_ops);
                    return BlockOutcome::Unsupported;
                }
            }

            x[0] = 0;
            cur_pc += step;
        }

        *pc = cur_pc;
        crate::tracepoints::record_block_exec_ops(charged_ops);
        return BlockOutcome::Restart;
    }
}

// =============================================================================
// Cached block execution
// =============================================================================

/// Execute a cached basic block.
///
/// The caller owns instruction-budget accounting for the instruction that
/// dispatched into this helper when `first_consumed` is true. Data accesses are
/// still validated through the same fault path used by the interpreter.
#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn exec_block<const FIRST_CONSUMED: bool>(
    blk: &BlockEntry,
    vm: &mut ThreadState,
    x: &mut [u64; 32],
    f: &mut [u64; 32],
    fcsr: &mut u32,
    pc: &mut u64,
    base: u32,
    remaining: &mut i32,
    access_cache: &mut AccessPermitCache,
    memory_is_multi_threaded: bool,
    hot_counts: Option<&mut HotCounts>,
    jit_bitmap: Option<&JitBitmap>,
    trace_buf: Option<&mut TraceBuffer>,
) -> BlockOutcome {
    // Const specialization removes a per-load/store mode branch from hot blocks.
    if memory_is_multi_threaded {
        unsafe {
            exec_block_for_mode::<FIRST_CONSUMED, true>(
                blk,
                vm,
                x,
                f,
                fcsr,
                pc,
                base,
                remaining,
                access_cache,
                hot_counts,
                jit_bitmap,
                trace_buf,
            )
        }
    } else {
        unsafe {
            exec_block_for_mode::<FIRST_CONSUMED, false>(
                blk,
                vm,
                x,
                f,
                fcsr,
                pc,
                base,
                remaining,
                access_cache,
                hot_counts,
                jit_bitmap,
                trace_buf,
            )
        }
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn exec_block_for_mode<const FIRST_CONSUMED: bool, const MULTI_THREADED: bool>(
    blk: &BlockEntry,
    vm: &mut ThreadState,
    x: &mut [u64; 32],
    f: &mut [u64; 32],
    fcsr: &mut u32,
    pc: &mut u64,
    base: u32,
    remaining: &mut i32,
    access_cache: &mut AccessPermitCache,
    mut hot_counts: Option<&mut HotCounts>,
    jit_bitmap: Option<&JitBitmap>,
    mut trace_buf: Option<&mut TraceBuffer>,
) -> BlockOutcome {
    let len = blk.len as usize;
    let mut cur_pc = blk.start_pc;
    let vm_ptr = vm as *const ThreadState as u32;
    crate::tracepoints::record_block_exec_ops(len as u32);
    let sample_ops = crate::tracepoints::record_block_exec_sample_start();
    record_sampled_block(blk, sample_ops);
    *remaining -= block_budget_charge::<FIRST_CONSUMED>(len);

    'block_loop: loop {
        for index in 0..len {
            let op = blk.ops[index];
            let rd = op.rd();
            let r1 = op.rs1();
            let r2 = op.rs2();
            let f3 = op.f3();
            let step = op.step();
            let imm = op.imm() as i64;
            let op_id = op.op_id();
            if sample_ops {
                crate::tracepoints::record_block_exec_sampled_op(op_id as u32);
            }

            match op_id {
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
                    let width = match f3 {
                        0 | 4 => 1,
                        1 | 5 => 2,
                        2 | 6 => 4,
                        3 => 8,
                        _ => 0,
                    };
                    *pc = cur_pc;
                    match unsafe {
                        ensure_guest_access(
                            vm,
                            x,
                            f,
                            fcsr,
                            pc,
                            base,
                            addr,
                            width,
                            abi::PROT_READ,
                            access_cache,
                        )
                    } {
                        AccessOutcome::Ok => {}
                        AccessOutcome::Restart => {
                            *remaining += block_budget_refund_after(len, index);
                            return BlockOutcome::Restart;
                        }
                        AccessOutcome::Return => {
                            *remaining += block_budget_refund_after(len, index);
                            return BlockOutcome::Return;
                        }
                    }
                    let val: u64 = match f3 {
                        0 => unsafe { guest_mem::read_u8_unchecked(base, addr) as i8 as u64 },
                        1 => unsafe {
                            (if MULTI_THREADED {
                                guest_mem::read_u16_seqlock(base, addr)
                            } else {
                                guest_mem::read_u16(base, addr)
                            }) as i16 as u64
                        },
                        2 => unsafe {
                            (if MULTI_THREADED {
                                guest_mem::read_u32_seqlock(base, addr)
                            } else {
                                guest_mem::read_u32(base, addr)
                            }) as i32 as u64
                        },
                        3 => unsafe {
                            if MULTI_THREADED {
                                guest_mem::read_u64_seqlock(base, addr)
                            } else {
                                guest_mem::read_u64(base, addr)
                            }
                        },
                        4 => unsafe { guest_mem::read_u8_unchecked(base, addr) as u64 },
                        5 => unsafe {
                            (if MULTI_THREADED {
                                guest_mem::read_u16_seqlock(base, addr)
                            } else {
                                guest_mem::read_u16(base, addr)
                            }) as u64
                        },
                        6 => unsafe {
                            (if MULTI_THREADED {
                                guest_mem::read_u32_seqlock(base, addr)
                            } else {
                                guest_mem::read_u32(base, addr)
                            }) as u64
                        },
                        _ => 0,
                    };
                    if rd != 0 {
                        x[rd] = val;
                    }
                }
                6 => {
                    let addr = (x[r1] as i64 + imm) as u64;
                    let width = match f3 {
                        0 => 1,
                        1 => 2,
                        2 => 4,
                        3 => 8,
                        _ => 0,
                    };
                    *pc = cur_pc;
                    match unsafe {
                        ensure_guest_access(
                            vm,
                            x,
                            f,
                            fcsr,
                            pc,
                            base,
                            addr,
                            width,
                            abi::PROT_WRITE,
                            access_cache,
                        )
                    } {
                        AccessOutcome::Ok => {}
                        AccessOutcome::Restart => {
                            *remaining += block_budget_refund_after(len, index);
                            return BlockOutcome::Restart;
                        }
                        AccessOutcome::Return => {
                            *remaining += block_budget_refund_after(len, index);
                            return BlockOutcome::Return;
                        }
                    }
                    crate::tracepoints::set_guest_write_context(cur_pc, vm.tid);
                    match f3 {
                        0 => unsafe {
                            guest_mem::write_u8_unchecked_for_mode(
                                base,
                                addr,
                                x[r2] as u8,
                                MULTI_THREADED,
                            )
                        },
                        1 => unsafe {
                            guest_mem::write_u16_unchecked_for_mode(
                                base,
                                addr,
                                x[r2] as u16,
                                MULTI_THREADED,
                            )
                        },
                        2 => unsafe {
                            guest_mem::write_u32_unchecked_for_mode(
                                base,
                                addr,
                                x[r2] as u32,
                                MULTI_THREADED,
                            )
                        },
                        3 => unsafe {
                            guest_mem::write_u64_unchecked_for_mode(
                                base,
                                addr,
                                x[r2],
                                MULTI_THREADED,
                            )
                        },
                        _ => {}
                    }
                    crate::tracepoints::clear_guest_write_context();
                }
                14 => {
                    let addr = x[r1];
                    let width = match f3 {
                        2 => 4,
                        3 => 8,
                        _ => 0,
                    };
                    *pc = cur_pc;
                    match unsafe {
                        ensure_guest_access(
                            vm,
                            x,
                            f,
                            fcsr,
                            pc,
                            base,
                            addr,
                            width,
                            abi::PROT_READ | abi::PROT_WRITE,
                            access_cache,
                        )
                    } {
                        AccessOutcome::Ok => {}
                        AccessOutcome::Restart => {
                            *remaining += block_budget_refund_after(len, index);
                            return BlockOutcome::Restart;
                        }
                        AccessOutcome::Return => {
                            *remaining += block_budget_refund_after(len, index);
                            return BlockOutcome::Return;
                        }
                    }
                    unsafe { exec_amo(vm, x, op.raw(), base, pc, step) };
                }
                15 => {
                    let addr = (x[r1] as i64 + imm) as u64;
                    let width = match f3 {
                        2 => 4,
                        3 => 8,
                        _ => 0,
                    };
                    *pc = cur_pc;
                    match unsafe {
                        ensure_guest_access(
                            vm,
                            x,
                            f,
                            fcsr,
                            pc,
                            base,
                            addr,
                            width,
                            abi::PROT_READ,
                            access_cache,
                        )
                    } {
                        AccessOutcome::Ok => {}
                        AccessOutcome::Restart => {
                            *remaining += block_budget_refund_after(len, index);
                            return BlockOutcome::Restart;
                        }
                        AccessOutcome::Return => {
                            *remaining += block_budget_refund_after(len, index);
                            return BlockOutcome::Return;
                        }
                    }
                    match f3 {
                        2 => {
                            let value = unsafe {
                                if MULTI_THREADED {
                                    guest_mem::read_u32_seqlock(base, addr)
                                } else {
                                    guest_mem::read_u32(base, addr)
                                }
                            };
                            f[rd] = 0xFFFF_FFFF_0000_0000 | value as u64;
                        }
                        3 => {
                            f[rd] = unsafe {
                                if MULTI_THREADED {
                                    guest_mem::read_u64_seqlock(base, addr)
                                } else {
                                    guest_mem::read_u64(base, addr)
                                }
                            };
                        }
                        _ => {}
                    }
                }
                16 => {
                    let addr = (x[r1] as i64 + imm) as u64;
                    let width = match f3 {
                        2 => 4,
                        3 => 8,
                        _ => 0,
                    };
                    *pc = cur_pc;
                    match unsafe {
                        ensure_guest_access(
                            vm,
                            x,
                            f,
                            fcsr,
                            pc,
                            base,
                            addr,
                            width,
                            abi::PROT_WRITE,
                            access_cache,
                        )
                    } {
                        AccessOutcome::Ok => {}
                        AccessOutcome::Restart => {
                            *remaining += block_budget_refund_after(len, index);
                            return BlockOutcome::Restart;
                        }
                        AccessOutcome::Return => {
                            *remaining += block_budget_refund_after(len, index);
                            return BlockOutcome::Return;
                        }
                    }
                    crate::tracepoints::set_guest_write_context(cur_pc, vm.tid);
                    match f3 {
                        2 => unsafe {
                            guest_mem::write_u32_unchecked_for_mode(
                                base,
                                addr,
                                f[r2] as u32,
                                MULTI_THREADED,
                            )
                        },
                        3 => unsafe {
                            guest_mem::write_u64_unchecked_for_mode(
                                base,
                                addr,
                                f[r2],
                                MULTI_THREADED,
                            )
                        },
                        _ => {}
                    }
                    crate::tracepoints::clear_guest_write_context();
                }
                17 => {
                    let mut op_pc = cur_pc;
                    unsafe { exec_op_fp(x, f, op.raw(), &mut op_pc, step, fcsr) };
                }
                18..=21 => {
                    let opcode = match op_id {
                        18 => decode::OP_FMADD,
                        19 => decode::OP_FMSUB,
                        20 => decode::OP_FNMSUB,
                        _ => decode::OP_FNMADD,
                    };
                    let mut op_pc = cur_pc;
                    unsafe { exec_fma(f, op.raw(), opcode, &mut op_pc, step, fcsr) };
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
                    let target = if taken {
                        (cur_pc as i64 + imm) as u64
                    } else {
                        cur_pc + step
                    };
                    if taken {
                        match observe_jit_backedge(
                            vm,
                            x,
                            f,
                            cur_pc,
                            target,
                            hot_counts.as_deref_mut(),
                            jit_bitmap,
                            trace_buf.as_deref_mut(),
                        ) {
                            JitBackedgeOutcome::Compiled => {
                                *pc = target;
                                return BlockOutcome::Return;
                            }
                            JitBackedgeOutcome::StartTrace => {
                                *pc = target;
                                return BlockOutcome::Restart;
                            }
                            JitBackedgeOutcome::None => {}
                        }
                    }
                    if target == blk.start_pc && index + 1 == len && *remaining >= len as i32 {
                        *remaining -= len as i32;
                        crate::tracepoints::record_block_exec_ops(len as u32);
                        cur_pc = blk.start_pc;
                        x[0] = 0;
                        continue 'block_loop;
                    }
                    if taken || index + 1 == len {
                        *pc = target;
                        x[0] = 0;
                        return BlockOutcome::Restart;
                    }
                }
                10 => {
                    if rd != 0 {
                        x[rd] = cur_pc + step;
                    }
                    *pc = (cur_pc as i64 + imm) as u64;
                    x[0] = 0;
                    return BlockOutcome::Restart;
                }
                11 => {
                    let target = ((x[r1] as i64 + imm) as u64) & !1;
                    crate::tracepoints::record_jalr(vm_ptr, cur_pc, rd, r1, x[r1], target);
                    if rd != 0 {
                        x[rd] = cur_pc + step;
                    }
                    *pc = target;
                    x[0] = 0;
                    return BlockOutcome::Restart;
                }
                13 => {}
                _ => {
                    *remaining += block_budget_refund_from::<FIRST_CONSUMED>(len, index);
                    crate::tracepoints::record_block_exec_unsupported_op(op_id as u32);
                    *pc = cur_pc;
                    return BlockOutcome::Unsupported;
                }
            }

            x[0] = 0;
            cur_pc += step;
        }

        *pc = cur_pc;
        return BlockOutcome::Restart;
    }
}
