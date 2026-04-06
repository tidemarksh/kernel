//! Atomic memory operation executors for the RISC-V A extension.
//!
//! Reference: RISC-V ISA spec V20191213
//!   (https://github.com/riscv/riscv-isa-manual/releases/tag/Ratified-IMAFDQC)
//!   §8 (A)
//!
//! LR/SC reservation state is tracked in `ProcessState`, so helpers here
//! operate on both thread-local registers and process-shared reservation slots.

use super::decode;
use crate::types::{ProcessState, ThreadState};
use core::sync::atomic::{AtomicI32, AtomicI64, Ordering};

// =============================================================================
// Reservation state access
// =============================================================================

/// Resolve the process-shared reservation state for LR/SC and AMO execution.
#[inline(always)]
unsafe fn process_reservation_state(process_ptr: u32, base: u32) -> &'static ProcessState {
    unsafe { &*(((base as u64) + process_ptr as u64) as *const ProcessState) }
}

// =============================================================================
// AMO dispatch
// =============================================================================

/// Execute AMO instructions and dispatch to width/alignment-specific helpers.
#[inline(always)]
pub(super) unsafe fn exec_amo(
    vm: &mut ThreadState,
    x: &mut [u64; 32],
    raw: u32,
    base: u32,
    pc: &mut u64,
    step: u64,
) {
    let rd = decode::rd(raw);
    let rs1 = decode::rs1(raw);
    let rs2 = decode::rs2(raw);
    let amo_op = decode::funct5(raw);
    let funct3 = decode::funct3(raw);
    let addr = x[rs1];
    let host_ptr = (base + addr as u32) as usize;

    match funct3 {
        2 => {
            if (host_ptr & 3) == 0 {
                unsafe { exec_amo32_atomic(vm, host_ptr, x, rd, rs2, amo_op, addr, base) };
            } else {
                unsafe { exec_amo32_nonatomic(vm, base, x, rd, rs2, amo_op, addr) };
            }
        }
        3 => {
            if (host_ptr & 7) == 0 {
                unsafe { exec_amo64_atomic(vm, host_ptr, x, rd, rs2, amo_op, addr, base) };
            } else {
                unsafe { exec_amo64_nonatomic(vm, base, x, rd, rs2, amo_op, addr) };
            }
        }
        _ => {}
    }
    *pc += step;
}

// =============================================================================
// 32-bit atomic-width helpers
// =============================================================================

/// Execute aligned 32-bit AMO/LR/SC operations using native atomics.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
unsafe fn exec_amo32_atomic(
    vm: &mut ThreadState,
    host_ptr: usize,
    x: &mut [u64; 32],
    rd: usize,
    rs2: usize,
    amo_op: u32,
    addr: u64,
    base: u32,
) {
    let a = unsafe { &*(host_ptr as *const AtomicI32) };
    match amo_op {
        0x02 => {
            let gen_idx = ((addr >> 3) % 64) as usize;
            let ps = unsafe { process_reservation_state(vm.process_ptr, base) };
            while ps.reservation_lock[gen_idx]
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            loop {
                let g = ps.reservation_gen[gen_idx].load(Ordering::SeqCst);
                if g & 1 == 0 {
                    break;
                }
                core::hint::spin_loop();
            }
            let val = a.load(Ordering::SeqCst);
            vm.lr_addr = addr;
            vm.lr_val = val as u32 as u64;
            vm.lr_gen = ps.reservation_gen[gen_idx].load(Ordering::SeqCst);
            vm.lr_gen_end = 0;
            ps.reservation_lock[gen_idx].store(0, Ordering::Release);
            if rd != 0 {
                x[rd] = val as i64 as u64;
            }
        }
        0x03 => {
            if vm.lr_addr == addr {
                let gen_idx = ((addr >> 3) % 64) as usize;
                let ps = unsafe { process_reservation_state(vm.process_ptr, base) };
                while ps.reservation_lock[gen_idx]
                    .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_err()
                {
                    core::hint::spin_loop();
                }
                let generation = ps.reservation_gen[gen_idx].load(Ordering::SeqCst);
                if generation != vm.lr_gen {
                    vm.lr_addr = u64::MAX;
                    if rd != 0 {
                        x[rd] = 1;
                    }
                } else {
                    a.store(x[rs2] as i32, Ordering::SeqCst);
                    ps.reservation_gen[gen_idx].fetch_add(2, Ordering::SeqCst);
                    vm.lr_addr = u64::MAX;
                    if rd != 0 {
                        x[rd] = 0;
                    }
                }
                ps.reservation_lock[gen_idx].store(0, Ordering::Release);
            } else {
                vm.lr_addr = u64::MAX;
                if rd != 0 {
                    x[rd] = 1;
                }
            }
        }
        0x01 => {
            let gen_idx = ((addr >> 3) % 64) as usize;
            let ps = unsafe { process_reservation_state(vm.process_ptr, base) };
            while ps.reservation_lock[gen_idx]
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            let old = a.swap(x[rs2] as i32, Ordering::SeqCst);
            ps.reservation_gen[gen_idx].fetch_add(2, Ordering::SeqCst);
            ps.reservation_lock[gen_idx].store(0, Ordering::Release);
            if rd != 0 {
                x[rd] = old as i64 as u64;
            }
        }
        0x00 => {
            let gen_idx = ((addr >> 3) % 64) as usize;
            let ps = unsafe { process_reservation_state(vm.process_ptr, base) };
            while ps.reservation_lock[gen_idx]
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            let old = a.fetch_add(x[rs2] as i32, Ordering::SeqCst);
            ps.reservation_gen[gen_idx].fetch_add(2, Ordering::SeqCst);
            ps.reservation_lock[gen_idx].store(0, Ordering::Release);
            if rd != 0 {
                x[rd] = old as i64 as u64;
            }
        }
        0x04 => {
            let gen_idx = ((addr >> 3) % 64) as usize;
            let ps = unsafe { process_reservation_state(vm.process_ptr, base) };
            while ps.reservation_lock[gen_idx]
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            let old = a.fetch_xor(x[rs2] as i32, Ordering::SeqCst);
            ps.reservation_gen[gen_idx].fetch_add(2, Ordering::SeqCst);
            ps.reservation_lock[gen_idx].store(0, Ordering::Release);
            if rd != 0 {
                x[rd] = old as i64 as u64;
            }
        }
        0x0C => {
            let gen_idx = ((addr >> 3) % 64) as usize;
            let ps = unsafe { process_reservation_state(vm.process_ptr, base) };
            while ps.reservation_lock[gen_idx]
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            let old = a.fetch_and(x[rs2] as i32, Ordering::SeqCst);
            ps.reservation_gen[gen_idx].fetch_add(2, Ordering::SeqCst);
            ps.reservation_lock[gen_idx].store(0, Ordering::Release);
            if rd != 0 {
                x[rd] = old as i64 as u64;
            }
        }
        0x08 => {
            let gen_idx = ((addr >> 3) % 64) as usize;
            let ps = unsafe { process_reservation_state(vm.process_ptr, base) };
            while ps.reservation_lock[gen_idx]
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            let old = a.fetch_or(x[rs2] as i32, Ordering::SeqCst);
            ps.reservation_gen[gen_idx].fetch_add(2, Ordering::SeqCst);
            ps.reservation_lock[gen_idx].store(0, Ordering::Release);
            if rd != 0 {
                x[rd] = old as i64 as u64;
            }
        }
        0x10 => {
            let gen_idx = ((addr >> 3) % 64) as usize;
            let ps = unsafe { process_reservation_state(vm.process_ptr, base) };
            while ps.reservation_lock[gen_idx]
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            let old = a.fetch_min(x[rs2] as i32, Ordering::SeqCst);
            ps.reservation_gen[gen_idx].fetch_add(2, Ordering::SeqCst);
            ps.reservation_lock[gen_idx].store(0, Ordering::Release);
            if rd != 0 {
                x[rd] = old as i64 as u64;
            }
        }
        0x14 => {
            let gen_idx = ((addr >> 3) % 64) as usize;
            let ps = unsafe { process_reservation_state(vm.process_ptr, base) };
            while ps.reservation_lock[gen_idx]
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            let old = a.fetch_max(x[rs2] as i32, Ordering::SeqCst);
            ps.reservation_gen[gen_idx].fetch_add(2, Ordering::SeqCst);
            ps.reservation_lock[gen_idx].store(0, Ordering::Release);
            if rd != 0 {
                x[rd] = old as i64 as u64;
            }
        }
        0x18 => {
            let gen_idx = ((addr >> 3) % 64) as usize;
            let ps = unsafe { process_reservation_state(vm.process_ptr, base) };
            while ps.reservation_lock[gen_idx]
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            let au = unsafe { &*(host_ptr as *const core::sync::atomic::AtomicU32) };
            let old = au.fetch_min(x[rs2] as u32, Ordering::SeqCst);
            ps.reservation_gen[gen_idx].fetch_add(2, Ordering::SeqCst);
            ps.reservation_lock[gen_idx].store(0, Ordering::Release);
            if rd != 0 {
                x[rd] = old as i32 as i64 as u64;
            }
        }
        0x1C => {
            let gen_idx = ((addr >> 3) % 64) as usize;
            let ps = unsafe { process_reservation_state(vm.process_ptr, base) };
            while ps.reservation_lock[gen_idx]
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            let au = unsafe { &*(host_ptr as *const core::sync::atomic::AtomicU32) };
            let old = au.fetch_max(x[rs2] as u32, Ordering::SeqCst);
            ps.reservation_gen[gen_idx].fetch_add(2, Ordering::SeqCst);
            ps.reservation_lock[gen_idx].store(0, Ordering::Release);
            if rd != 0 {
                x[rd] = old as i32 as i64 as u64;
            }
        }
        _ => {}
    }
}

/// Execute unaligned 32-bit AMO/LR/SC operations with explicit locking.
#[inline(always)]
unsafe fn exec_amo32_nonatomic(
    vm: &mut ThreadState,
    base: u32,
    x: &mut [u64; 32],
    rd: usize,
    rs2: usize,
    amo_op: u32,
    addr: u64,
) {
    match amo_op {
        0x02 => {
            let gen_idx = ((addr >> 3) % 64) as usize;
            let end_idx = (((addr + 3) >> 3) % 64) as usize;
            let (first, second) = if gen_idx <= end_idx {
                (gen_idx, end_idx)
            } else {
                (end_idx, gen_idx)
            };
            let ps = unsafe { process_reservation_state(vm.process_ptr, base) };
            while ps.reservation_lock[first]
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            if first != second {
                while ps.reservation_lock[second]
                    .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_err()
                {
                    core::hint::spin_loop();
                }
            }
            let ptr = (base + addr as u32) as *const u32;
            let val = unsafe { ptr.read_unaligned() as i32 };
            vm.lr_addr = addr;
            vm.lr_val = val as u32 as u64;
            vm.lr_gen = ps.reservation_gen[gen_idx].load(Ordering::SeqCst);
            vm.lr_gen_end = if end_idx != gen_idx {
                ps.reservation_gen[end_idx].load(Ordering::SeqCst)
            } else {
                0
            };
            if first != second {
                ps.reservation_lock[second].store(0, Ordering::Release);
            }
            ps.reservation_lock[first].store(0, Ordering::Release);
            if rd != 0 {
                x[rd] = val as i64 as u64;
            }
        }
        0x03 => {
            if vm.lr_addr == addr {
                let gen_idx = ((addr >> 3) % 64) as usize;
                let end_idx = (((addr + 3) >> 3) % 64) as usize;
                let (first, second) = if gen_idx <= end_idx {
                    (gen_idx, end_idx)
                } else {
                    (end_idx, gen_idx)
                };
                let ps = unsafe { process_reservation_state(vm.process_ptr, base) };
                while ps.reservation_lock[first]
                    .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_err()
                {
                    core::hint::spin_loop();
                }
                if first != second {
                    while ps.reservation_lock[second]
                        .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                        .is_err()
                    {
                        core::hint::spin_loop();
                    }
                }
                let generation = ps.reservation_gen[gen_idx].load(Ordering::SeqCst);
                let end_gen = if end_idx != gen_idx {
                    ps.reservation_gen[end_idx].load(Ordering::SeqCst)
                } else {
                    0
                };
                if generation != vm.lr_gen || (end_idx != gen_idx && end_gen != vm.lr_gen_end) {
                    vm.lr_addr = u64::MAX;
                    if rd != 0 {
                        x[rd] = 1;
                    }
                } else {
                    let ptr = (base + addr as u32) as *mut u32;
                    unsafe { ptr.write_unaligned(x[rs2] as u32) };
                    ps.reservation_gen[gen_idx].fetch_add(2, Ordering::SeqCst);
                    if end_idx != gen_idx {
                        ps.reservation_gen[end_idx].fetch_add(2, Ordering::SeqCst);
                    }
                    vm.lr_addr = u64::MAX;
                    if rd != 0 {
                        x[rd] = 0;
                    }
                }
                if first != second {
                    ps.reservation_lock[second].store(0, Ordering::Release);
                }
                ps.reservation_lock[first].store(0, Ordering::Release);
            } else {
                vm.lr_addr = u64::MAX;
                if rd != 0 {
                    x[rd] = 1;
                }
            }
        }
        _ => {
            let gen_idx = ((addr >> 3) % 64) as usize;
            let end_idx = (((addr + 3) >> 3) % 64) as usize;
            let (first, second) = if gen_idx <= end_idx {
                (gen_idx, end_idx)
            } else {
                (end_idx, gen_idx)
            };
            let ps = unsafe { process_reservation_state(vm.process_ptr, base) };
            while ps.reservation_lock[first]
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            if first != second {
                while ps.reservation_lock[second]
                    .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_err()
                {
                    core::hint::spin_loop();
                }
            }
            let rptr = (base + addr as u32) as *const u32;
            let old = unsafe { rptr.read_unaligned() as i32 };
            let src = x[rs2] as i32;
            let new_val = match amo_op {
                0x01 => src,
                0x00 => old.wrapping_add(src),
                0x04 => old ^ src,
                0x0C => old & src,
                0x08 => old | src,
                0x10 => {
                    if old < src {
                        old
                    } else {
                        src
                    }
                }
                0x14 => {
                    if old > src {
                        old
                    } else {
                        src
                    }
                }
                0x18 => {
                    if (old as u32) < (src as u32) {
                        old
                    } else {
                        src
                    }
                }
                0x1C => {
                    if (old as u32) > (src as u32) {
                        old
                    } else {
                        src
                    }
                }
                _ => old,
            };
            let wptr = (base + addr as u32) as *mut u32;
            unsafe { wptr.write_unaligned(new_val as u32) };
            ps.reservation_gen[gen_idx].fetch_add(2, Ordering::SeqCst);
            if end_idx != gen_idx {
                ps.reservation_gen[end_idx].fetch_add(2, Ordering::SeqCst);
            }
            if first != second {
                ps.reservation_lock[second].store(0, Ordering::Release);
            }
            ps.reservation_lock[first].store(0, Ordering::Release);
            if rd != 0 {
                x[rd] = old as i64 as u64;
            }
        }
    }
}

// =============================================================================
// 64-bit atomic-width helpers
// =============================================================================

/// Execute aligned 64-bit AMO/LR/SC operations using native atomics.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
unsafe fn exec_amo64_atomic(
    vm: &mut ThreadState,
    host_ptr: usize,
    x: &mut [u64; 32],
    rd: usize,
    rs2: usize,
    amo_op: u32,
    addr: u64,
    base: u32,
) {
    let a = unsafe { &*(host_ptr as *const AtomicI64) };
    match amo_op {
        0x02 => {
            let gen_idx = ((addr >> 3) % 64) as usize;
            let ps = unsafe { process_reservation_state(vm.process_ptr, base) };
            while ps.reservation_lock[gen_idx]
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            loop {
                let g = ps.reservation_gen[gen_idx].load(Ordering::SeqCst);
                if g & 1 == 0 {
                    break;
                }
                core::hint::spin_loop();
            }
            let val = a.load(Ordering::SeqCst);
            vm.lr_addr = addr;
            vm.lr_val = val as u64;
            vm.lr_gen = ps.reservation_gen[gen_idx].load(Ordering::SeqCst);
            vm.lr_gen_end = 0;
            ps.reservation_lock[gen_idx].store(0, Ordering::Release);
            if rd != 0 {
                x[rd] = val as u64;
            }
        }
        0x03 => {
            if vm.lr_addr == addr {
                let gen_idx = ((addr >> 3) % 64) as usize;
                let ps = unsafe { process_reservation_state(vm.process_ptr, base) };
                while ps.reservation_lock[gen_idx]
                    .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_err()
                {
                    core::hint::spin_loop();
                }
                let generation = ps.reservation_gen[gen_idx].load(Ordering::SeqCst);
                if generation != vm.lr_gen {
                    vm.lr_addr = u64::MAX;
                    if rd != 0 {
                        x[rd] = 1;
                    }
                } else {
                    a.store(x[rs2] as i64, Ordering::SeqCst);
                    ps.reservation_gen[gen_idx].fetch_add(2, Ordering::SeqCst);
                    vm.lr_addr = u64::MAX;
                    if rd != 0 {
                        x[rd] = 0;
                    }
                }
                ps.reservation_lock[gen_idx].store(0, Ordering::Release);
            } else {
                vm.lr_addr = u64::MAX;
                if rd != 0 {
                    x[rd] = 1;
                }
            }
        }
        0x01 => {
            let gen_idx = ((addr >> 3) % 64) as usize;
            let ps = unsafe { process_reservation_state(vm.process_ptr, base) };
            while ps.reservation_lock[gen_idx]
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            let old = a.swap(x[rs2] as i64, Ordering::SeqCst);
            ps.reservation_gen[gen_idx].fetch_add(2, Ordering::SeqCst);
            ps.reservation_lock[gen_idx].store(0, Ordering::Release);
            if rd != 0 {
                x[rd] = old as u64;
            }
        }
        0x00 => {
            let gen_idx = ((addr >> 3) % 64) as usize;
            let ps = unsafe { process_reservation_state(vm.process_ptr, base) };
            while ps.reservation_lock[gen_idx]
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            let old = a.fetch_add(x[rs2] as i64, Ordering::SeqCst);
            ps.reservation_gen[gen_idx].fetch_add(2, Ordering::SeqCst);
            ps.reservation_lock[gen_idx].store(0, Ordering::Release);
            if rd != 0 {
                x[rd] = old as u64;
            }
        }
        0x04 => {
            let gen_idx = ((addr >> 3) % 64) as usize;
            let ps = unsafe { process_reservation_state(vm.process_ptr, base) };
            while ps.reservation_lock[gen_idx]
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            let old = a.fetch_xor(x[rs2] as i64, Ordering::SeqCst);
            ps.reservation_gen[gen_idx].fetch_add(2, Ordering::SeqCst);
            ps.reservation_lock[gen_idx].store(0, Ordering::Release);
            if rd != 0 {
                x[rd] = old as u64;
            }
        }
        0x0C => {
            let gen_idx = ((addr >> 3) % 64) as usize;
            let ps = unsafe { process_reservation_state(vm.process_ptr, base) };
            while ps.reservation_lock[gen_idx]
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            let old = a.fetch_and(x[rs2] as i64, Ordering::SeqCst);
            ps.reservation_gen[gen_idx].fetch_add(2, Ordering::SeqCst);
            ps.reservation_lock[gen_idx].store(0, Ordering::Release);
            if rd != 0 {
                x[rd] = old as u64;
            }
        }
        0x08 => {
            let gen_idx = ((addr >> 3) % 64) as usize;
            let ps = unsafe { process_reservation_state(vm.process_ptr, base) };
            while ps.reservation_lock[gen_idx]
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            let old = a.fetch_or(x[rs2] as i64, Ordering::SeqCst);
            ps.reservation_gen[gen_idx].fetch_add(2, Ordering::SeqCst);
            ps.reservation_lock[gen_idx].store(0, Ordering::Release);
            if rd != 0 {
                x[rd] = old as u64;
            }
        }
        0x10 => {
            let gen_idx = ((addr >> 3) % 64) as usize;
            let ps = unsafe { process_reservation_state(vm.process_ptr, base) };
            while ps.reservation_lock[gen_idx]
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            let old = a.fetch_min(x[rs2] as i64, Ordering::SeqCst);
            ps.reservation_gen[gen_idx].fetch_add(2, Ordering::SeqCst);
            ps.reservation_lock[gen_idx].store(0, Ordering::Release);
            if rd != 0 {
                x[rd] = old as u64;
            }
        }
        0x14 => {
            let gen_idx = ((addr >> 3) % 64) as usize;
            let ps = unsafe { process_reservation_state(vm.process_ptr, base) };
            while ps.reservation_lock[gen_idx]
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            let old = a.fetch_max(x[rs2] as i64, Ordering::SeqCst);
            ps.reservation_gen[gen_idx].fetch_add(2, Ordering::SeqCst);
            ps.reservation_lock[gen_idx].store(0, Ordering::Release);
            if rd != 0 {
                x[rd] = old as u64;
            }
        }
        0x18 => {
            let gen_idx = ((addr >> 3) % 64) as usize;
            let ps = unsafe { process_reservation_state(vm.process_ptr, base) };
            while ps.reservation_lock[gen_idx]
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            let au = unsafe { &*(host_ptr as *const core::sync::atomic::AtomicU64) };
            let old = au.fetch_min(x[rs2], Ordering::SeqCst);
            ps.reservation_gen[gen_idx].fetch_add(2, Ordering::SeqCst);
            ps.reservation_lock[gen_idx].store(0, Ordering::Release);
            if rd != 0 {
                x[rd] = old;
            }
        }
        0x1C => {
            let gen_idx = ((addr >> 3) % 64) as usize;
            let ps = unsafe { process_reservation_state(vm.process_ptr, base) };
            while ps.reservation_lock[gen_idx]
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            let au = unsafe { &*(host_ptr as *const core::sync::atomic::AtomicU64) };
            let old = au.fetch_max(x[rs2], Ordering::SeqCst);
            ps.reservation_gen[gen_idx].fetch_add(2, Ordering::SeqCst);
            ps.reservation_lock[gen_idx].store(0, Ordering::Release);
            if rd != 0 {
                x[rd] = old;
            }
        }
        _ => {}
    }
}

/// Execute unaligned 64-bit AMO/LR/SC operations with explicit locking.
#[inline(always)]
unsafe fn exec_amo64_nonatomic(
    vm: &mut ThreadState,
    base: u32,
    x: &mut [u64; 32],
    rd: usize,
    rs2: usize,
    amo_op: u32,
    addr: u64,
) {
    match amo_op {
        0x02 => {
            let gen_idx = ((addr >> 3) % 64) as usize;
            let end_idx = (((addr + 7) >> 3) % 64) as usize;
            let (first, second) = if gen_idx <= end_idx {
                (gen_idx, end_idx)
            } else {
                (end_idx, gen_idx)
            };
            let ps = unsafe { process_reservation_state(vm.process_ptr, base) };
            while ps.reservation_lock[first]
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            if first != second {
                while ps.reservation_lock[second]
                    .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_err()
                {
                    core::hint::spin_loop();
                }
            }
            let ptr = (base + addr as u32) as *const u64;
            let val = unsafe { ptr.read_unaligned() };
            vm.lr_addr = addr;
            vm.lr_val = val;
            vm.lr_gen = ps.reservation_gen[gen_idx].load(Ordering::SeqCst);
            vm.lr_gen_end = if end_idx != gen_idx {
                ps.reservation_gen[end_idx].load(Ordering::SeqCst)
            } else {
                0
            };
            if first != second {
                ps.reservation_lock[second].store(0, Ordering::Release);
            }
            ps.reservation_lock[first].store(0, Ordering::Release);
            if rd != 0 {
                x[rd] = val;
            }
        }
        0x03 => {
            if vm.lr_addr == addr {
                let gen_idx = ((addr >> 3) % 64) as usize;
                let end_idx = (((addr + 7) >> 3) % 64) as usize;
                let (first, second) = if gen_idx <= end_idx {
                    (gen_idx, end_idx)
                } else {
                    (end_idx, gen_idx)
                };
                let ps = unsafe { process_reservation_state(vm.process_ptr, base) };
                while ps.reservation_lock[first]
                    .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_err()
                {
                    core::hint::spin_loop();
                }
                if first != second {
                    while ps.reservation_lock[second]
                        .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                        .is_err()
                    {
                        core::hint::spin_loop();
                    }
                }
                let generation = ps.reservation_gen[gen_idx].load(Ordering::SeqCst);
                let end_gen = if end_idx != gen_idx {
                    ps.reservation_gen[end_idx].load(Ordering::SeqCst)
                } else {
                    0
                };
                if generation != vm.lr_gen || (end_idx != gen_idx && end_gen != vm.lr_gen_end) {
                    vm.lr_addr = u64::MAX;
                    if rd != 0 {
                        x[rd] = 1;
                    }
                } else {
                    let ptr = (base + addr as u32) as *mut u64;
                    unsafe { ptr.write_unaligned(x[rs2]) };
                    ps.reservation_gen[gen_idx].fetch_add(2, Ordering::SeqCst);
                    if end_idx != gen_idx {
                        ps.reservation_gen[end_idx].fetch_add(2, Ordering::SeqCst);
                    }
                    vm.lr_addr = u64::MAX;
                    if rd != 0 {
                        x[rd] = 0;
                    }
                }
                if first != second {
                    ps.reservation_lock[second].store(0, Ordering::Release);
                }
                ps.reservation_lock[first].store(0, Ordering::Release);
            } else {
                vm.lr_addr = u64::MAX;
                if rd != 0 {
                    x[rd] = 1;
                }
            }
        }
        _ => {
            let gen_idx = ((addr >> 3) % 64) as usize;
            let end_idx = (((addr + 7) >> 3) % 64) as usize;
            let (first, second) = if gen_idx <= end_idx {
                (gen_idx, end_idx)
            } else {
                (end_idx, gen_idx)
            };
            let ps = unsafe { process_reservation_state(vm.process_ptr, base) };
            while ps.reservation_lock[first]
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            if first != second {
                while ps.reservation_lock[second]
                    .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_err()
                {
                    core::hint::spin_loop();
                }
            }
            let rptr = (base + addr as u32) as *const u64;
            let old = unsafe { rptr.read_unaligned() };
            let src = x[rs2];
            let new_val = match amo_op {
                0x01 => src,
                0x00 => old.wrapping_add(src),
                0x04 => old ^ src,
                0x0C => old & src,
                0x08 => old | src,
                0x10 => {
                    if (old as i64) < (src as i64) {
                        old
                    } else {
                        src
                    }
                }
                0x14 => {
                    if (old as i64) > (src as i64) {
                        old
                    } else {
                        src
                    }
                }
                0x18 => {
                    if old < src {
                        old
                    } else {
                        src
                    }
                }
                0x1C => {
                    if old > src {
                        old
                    } else {
                        src
                    }
                }
                _ => old,
            };
            let wptr = (base + addr as u32) as *mut u64;
            unsafe { wptr.write_unaligned(new_val) };
            ps.reservation_gen[gen_idx].fetch_add(2, Ordering::SeqCst);
            if end_idx != gen_idx {
                ps.reservation_gen[end_idx].fetch_add(2, Ordering::SeqCst);
            }
            if first != second {
                ps.reservation_lock[second].store(0, Ordering::Release);
            }
            ps.reservation_lock[first].store(0, Ordering::Release);
            if rd != 0 {
                x[rd] = old;
            }
        }
    }
}
