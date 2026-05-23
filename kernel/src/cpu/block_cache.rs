//! Pre-decoded basic block cache.
//!
//! Direct-mapped, 32768 entries. Each entry holds a pre-decoded basic block
//! (up to MAX_BLOCK_OPS instructions) with packed fields for fast dispatch.
//!
//! JALR rs1==ra triggers a cache lookup for return prediction.

use crate::cpu::decode;
use crate::guest_mem;
use crate::types::ThreadState;

pub const CACHE_SIZE: usize = 32768;
pub const MAX_BLOCK_OPS: usize = 32;
pub const BLOCK_LOOP_SIMPLE_LOAD_SCAN: u16 = 1 << 0;

#[inline(always)]
fn block_fetch_permitted(vm: Option<&ThreadState>, ram_base: u32, pc: u64, width: u64) -> bool {
    let Some(thread) = vm else {
        return true;
    };
    crate::syscall::memory::guest_range_permitted(
        thread,
        ram_base,
        pc,
        width,
        crate::abi::PROT_EXEC,
    )
}

#[inline(always)]
const fn block_exec_supports(op_id: u8) -> bool {
    matches!(op_id, 1..=11 | 13 | 22 | 23)
}

pub(crate) fn op_id_for_raw(raw: u32) -> u8 {
    let opc = decode::opcode(raw);
    let f7 = decode::funct7(raw);
    match opc {
        decode::OP_OP_IMM => 1,
        decode::OP_OP_IMM_32 => 2,
        decode::OP_OP => {
            if f7 == 1 {
                22
            } else {
                3
            }
        }
        decode::OP_OP_32 => {
            if f7 == 1 {
                23
            } else {
                4
            }
        }
        decode::OP_LOAD => 5,
        decode::OP_STORE => 6,
        decode::OP_LUI => 7,
        decode::OP_AUIPC => 8,
        decode::OP_BRANCH => 9,
        decode::OP_JAL => 10,
        decode::OP_JALR => 11,
        decode::OP_SYSTEM => 12,
        decode::OP_MISC_MEM => 13,
        decode::OP_AMO => 14,
        decode::OP_LOAD_FP => 15,
        decode::OP_STORE_FP => 16,
        decode::OP_OP_FP => 17,
        decode::OP_FMADD => 18,
        decode::OP_FMSUB => 19,
        decode::OP_FNMSUB => 20,
        decode::OP_FNMADD => 21,
        _ => 0,
    }
}

/// Pre-decoded operation. Packed into a single u64 for cache-friendly access.
///
/// Layout (upper 32 bits):
///   op_id:8 | rd:5 | rs1:5 | rs2:5 | f3:3 | f7b5:1 | step4:1 | _:4
/// Lower 32 bits:
///   pre-extracted immediate (i32)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PackedOp {
    pub packed: u64,
}

impl PackedOp {
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        op_id: u8,
        rd: u8,
        rs1: u8,
        rs2: u8,
        f3: u8,
        f7b5: bool,
        step: u64,
        imm: i32,
    ) -> Self {
        let step4 = if step == 4 { 1u32 } else { 0 };
        let upper = (op_id as u32) << 24
            | (rd as u32 & 0x1F) << 19
            | (rs1 as u32 & 0x1F) << 14
            | (rs2 as u32 & 0x1F) << 9
            | (f3 as u32 & 0x7) << 6
            | if f7b5 { 1u32 << 5 } else { 0 }
            | step4 << 4;
        Self {
            packed: ((upper as u64) << 32) | (imm as u32 as u64),
        }
    }

    #[inline(always)]
    pub fn op_id(self) -> u8 {
        (self.packed >> 56) as u8
    }
    #[inline(always)]
    pub fn rd(self) -> usize {
        ((self.packed >> 51) & 0x1F) as usize
    }
    #[inline(always)]
    pub fn rs1(self) -> usize {
        ((self.packed >> 46) & 0x1F) as usize
    }
    #[inline(always)]
    pub fn rs2(self) -> usize {
        ((self.packed >> 41) & 0x1F) as usize
    }
    #[inline(always)]
    pub fn f3(self) -> u32 {
        ((self.packed >> 38) & 0x7) as u32
    }
    #[inline(always)]
    pub fn f7b5(self) -> bool {
        (self.packed >> 37) & 1 != 0
    }
    #[inline(always)]
    pub fn step(self) -> u64 {
        if (self.packed >> 36) & 1 != 0 { 4 } else { 2 }
    }
    #[inline(always)]
    pub fn imm(self) -> i32 {
        self.packed as i32
    }
}

/// A cached basic block.
#[repr(C)]
pub struct BlockEntry {
    /// Start PC (0 = empty slot)
    pub start_pc: u64,
    /// Pre-decoded operations
    pub ops: [PackedOp; MAX_BLOCK_OPS],
    /// Number of valid operations
    pub len: u16,
    /// Total instruction count (for budget)
    pub total_budget: u16,
    /// Precomputed block-shape flags used by optional executor fast paths.
    pub loop_flags: u16,
}

fn classify_loop_flags(ops: &[PackedOp; MAX_BLOCK_OPS], len: u16, start_pc: u64) -> u16 {
    if len == 0 {
        return 0;
    }
    let last = ops[len as usize - 1];
    if last.op_id() != 9 {
        return 0;
    }

    if len == 5
        && ops[0].op_id() == 5
        && ops[1].op_id() == 1
        && ops[2].op_id() == 1
        && ops[3].op_id() == 3
        && (start_pc as i64
            + ops[0].step() as i64
            + ops[1].step() as i64
            + ops[2].step() as i64
            + ops[3].step() as i64
            + ops[4].imm() as i64) as u64
            == start_pc
    {
        BLOCK_LOOP_SIMPLE_LOAD_SCAN
    } else {
        0
    }
}

/// The block cache (direct-mapped, indexed by PC).
/// Heap-allocated due to large size (~1.3MB for 4096 entries).
pub struct BlockCache {
    entries: *mut BlockEntry,
}

impl BlockCache {
    /// Create a new block cache. `base_ptr` is a pre-allocated zeroed region
    /// of at least `CACHE_SIZE * size_of::<BlockEntry>()` bytes.
    ///
    /// # Safety
    /// `base_ptr` must be valid and zeroed.
    pub unsafe fn from_ptr(base_ptr: *mut BlockEntry) -> Self {
        Self { entries: base_ptr }
    }

    /// Size in bytes needed for the cache allocation.
    pub const fn allocation_size() -> usize {
        CACHE_SIZE * core::mem::size_of::<BlockEntry>()
    }

    /// Look up a block by PC. Returns None if not cached or tag mismatch.
    #[inline(always)]
    pub fn get(&self, pc: u64) -> Option<&BlockEntry> {
        let idx = ((pc >> 1) as usize) & (CACHE_SIZE - 1);
        let entry = unsafe { &*self.entries.add(idx) };
        if entry.start_pc == pc && entry.len > 0 {
            Some(entry)
        } else {
            None
        }
    }

    /// Build a block starting at `pc` by decoding instructions from guest memory.
    /// Returns the block entry, or None if the first instruction is unsupported.
    ///
    /// # Safety
    /// `ram_base` must point at readable guest RAM containing instructions for
    /// every byte touched while decoding the block rooted at `pc`.
    pub unsafe fn build_block(&mut self, pc: u64, ram_base: u32) -> Option<&BlockEntry> {
        unsafe { self.build_block_inner(None, pc, ram_base) }
    }

    /// Look up a block or build it after verifying each fetched instruction has
    /// guest execute permission. This is the production path used by the CPU
    /// loop; plain `build_block` remains for tests with synthetic memory.
    pub unsafe fn get_or_build_checked(
        &mut self,
        vm: &ThreadState,
        pc: u64,
        ram_base: u32,
    ) -> Option<&BlockEntry> {
        let idx = ((pc >> 1) as usize) & (CACHE_SIZE - 1);
        let entry = unsafe { &*self.entries.add(idx) };
        if entry.start_pc == pc && entry.len > 0 {
            crate::tracepoints::record_block_cache_hit();
            return Some(entry);
        }
        crate::tracepoints::record_block_cache_miss(pc, idx as u32, entry.start_pc);
        let built = unsafe { self.build_block_inner(Some(vm), pc, ram_base) };
        if let Some(entry) = built {
            crate::tracepoints::record_block_cache_build(
                entry.len as u32,
                entry.total_budget as u32,
            );
        } else {
            crate::tracepoints::record_block_cache_build_failure();
        }
        built
    }

    unsafe fn build_block_inner(
        &mut self,
        vm: Option<&ThreadState>,
        pc: u64,
        ram_base: u32,
    ) -> Option<&BlockEntry> {
        unsafe {
            let idx = ((pc >> 1) as usize) & (CACHE_SIZE - 1);
            let entry = &mut *self.entries.add(idx);
            entry.start_pc = pc;
            entry.len = 0;
            entry.total_budget = 0;
            entry.loop_flags = 0;

            let mut cur_pc = pc;
            let mut count = 0u16;

            while (count as usize) < MAX_BLOCK_OPS {
                if !block_fetch_permitted(vm, ram_base, cur_pc, 2) {
                    break;
                }
                let raw16 = guest_mem::read_u16(ram_base, cur_pc);
                let (raw, step) = if decode::is_compressed(raw16) {
                    let expanded = decode::expand_compressed(raw16);
                    if expanded == 0 {
                        break;
                    } // unknown compressed
                    (expanded, 2u64)
                } else {
                    if !block_fetch_permitted(vm, ram_base, cur_pc, 4) {
                        break;
                    }
                    (guest_mem::read_u32(ram_base, cur_pc), 4u64)
                };

                let opc = decode::opcode(raw);
                let rd = decode::rd(raw) as u8;
                let rs1 = decode::rs1(raw) as u8;
                let rs2 = decode::rs2(raw) as u8;
                let f3 = decode::funct3(raw) as u8;
                let f7 = decode::funct7(raw);
                let f7b5 = (f7 >> 5) & 1 != 0;

                let op_id = op_id_for_raw(raw);

                if op_id == 0 {
                    break;
                }
                if vm.is_some() && !block_exec_supports(op_id) {
                    crate::tracepoints::record_block_cache_unsupported_op(op_id as u32);
                    break;
                }
                crate::tracepoints::record_block_cache_build_op(op_id as u32);

                // Extract immediate based on instruction type
                let imm = match opc {
                    decode::OP_OP_IMM
                    | decode::OP_OP_IMM_32
                    | decode::OP_LOAD
                    | decode::OP_LOAD_FP
                    | decode::OP_JALR => decode::imm_i(raw) as i32,
                    decode::OP_STORE | decode::OP_STORE_FP => decode::imm_s(raw) as i32,
                    decode::OP_BRANCH => decode::imm_b(raw) as i32,
                    decode::OP_LUI | decode::OP_AUIPC => decode::imm_u(raw) as i32,
                    decode::OP_JAL => decode::imm_j(raw) as i32,
                    _ => 0,
                };

                entry.ops[count as usize] = PackedOp::new(op_id, rd, rs1, rs2, f3, f7b5, step, imm);
                count += 1;
                cur_pc += step;

                // Terminators: branch, JAL, JALR, ECALL, FENCE stop the block
                match opc {
                    decode::OP_BRANCH
                    | decode::OP_JAL
                    | decode::OP_JALR
                    | decode::OP_SYSTEM
                    | decode::OP_MISC_MEM => break,
                    _ => {}
                }
            }

            if count == 0 {
                entry.start_pc = 0; // mark empty
                return None;
            }

            entry.len = count;
            entry.total_budget = count;
            entry.loop_flags = classify_loop_flags(&entry.ops, count, pc);
            Some(&*self.entries.add(idx))
        }
    }

    /// Invalidate all entries (e.g., after execve).
    pub fn clear(&mut self) {
        for i in 0..CACHE_SIZE {
            let entry = unsafe { &mut *self.entries.add(i) };
            entry.start_pc = 0;
            entry.len = 0;
        }
    }

    /// Invalidate entries whose PC range overlaps [start, end).
    pub fn invalidate_range(&mut self, start: u64, end: u64) {
        for i in 0..CACHE_SIZE {
            let entry = unsafe { &mut *self.entries.add(i) };
            if entry.start_pc != 0 && entry.start_pc >= start && entry.start_pc < end {
                entry.start_pc = 0;
                entry.len = 0;
                entry.loop_flags = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_ops() -> [PackedOp; MAX_BLOCK_OPS] {
        [PackedOp { packed: 0 }; MAX_BLOCK_OPS]
    }

    #[test]
    fn classifies_simple_load_scan_backedge() {
        let mut ops = empty_ops();
        ops[0] = PackedOp::new(5, 13, 14, 0, 4, false, 4, 0);
        ops[1] = PackedOp::new(1, 15, 15, 0, 0, false, 2, 1);
        ops[2] = PackedOp::new(1, 14, 14, 0, 0, false, 2, 1);
        ops[3] = PackedOp::new(3, 8, 8, 13, 0, false, 2, 0);
        ops[4] = PackedOp::new(9, 0, 15, 10, 4, false, 4, -10);

        assert_eq!(
            classify_loop_flags(&ops, 5, 0x104de),
            BLOCK_LOOP_SIMPLE_LOAD_SCAN
        );
    }

    #[test]
    fn does_not_classify_non_backedge_load_scan_shape() {
        let mut ops = empty_ops();
        ops[0] = PackedOp::new(5, 13, 14, 0, 4, false, 4, 0);
        ops[1] = PackedOp::new(1, 15, 15, 0, 0, false, 2, 1);
        ops[2] = PackedOp::new(1, 14, 14, 0, 0, false, 2, 1);
        ops[3] = PackedOp::new(3, 8, 8, 13, 0, false, 2, 0);
        ops[4] = PackedOp::new(9, 0, 15, 10, 4, false, 4, 4);

        assert_eq!(classify_loop_flags(&ops, 5, 0x104de), 0);
    }
}
