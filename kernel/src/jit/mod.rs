//! JIT compiler: RISC-V → WASM translation.

use alloc_crate::vec::Vec;

use crate::cpu::{
    decode,
    trace::{HotCounts, JitBitmap, TraceBuffer, TraceEntry},
};
use cache::{AddressRange, CompiledRegion, RegionCache};
use wasm_gen::{
    JitCompileError, JitModuleConfig, Region, RegionBlock, RegionInstruction, compile_region,
};

pub mod cache;
pub mod wasm_gen;

struct PendingRegion {
    bytes: Vec<u8>,
    entry_pc: u64,
    permit_generation: u32,
    code_ranges: Vec<AddressRange>,
}

pub struct JitState {
    pub(crate) hot_counts: HotCounts,
    pub(crate) ready: JitBitmap,
    pub(crate) trace: TraceBuffer,
    cache: RegionCache,
    pending: Option<PendingRegion>,
}

impl JitState {
    pub const fn new() -> Self {
        Self {
            hot_counts: HotCounts::new(),
            ready: JitBitmap::new(),
            trace: TraceBuffer::new(),
            cache: RegionCache::new(),
            pending: None,
        }
    }

    pub fn compile_completed_trace(
        &mut self,
        max_instructions: u32,
        memory_max_pages: u64,
    ) -> Result<(), TraceCompileError> {
        let count = self.trace.count as usize;
        let region = region_from_trace(&self.trace.entries[..count], max_instructions)
            .map_err(TraceCompileError::Trace)?;
        let snapshot = crate::syscall::memory::jit_memory_snapshot();
        let bytes = compile_region(
            &region,
            JitModuleConfig {
                memory_max_pages,
                permit_generation_address: snapshot.generation_address,
                permit_generation: snapshot.generation,
                memory_permits: &snapshot.permits,
            },
        )
        .map_err(TraceCompileError::Compile)?;
        let code_ranges = region
            .blocks
            .iter()
            .filter_map(|block| {
                let end = block
                    .instructions
                    .last()
                    .map(|instruction| instruction.pc + instruction.step as u64)?;
                AddressRange::new(block.start_pc, end)
            })
            .collect();
        self.pending = Some(PendingRegion {
            bytes,
            entry_pc: region.entry_pc,
            permit_generation: snapshot.generation,
            code_ranges,
        });
        self.trace.count = 0;
        Ok(())
    }

    pub fn pending_bytes(&self) -> Option<&[u8]> {
        self.pending
            .as_ref()
            .map(|pending| pending.bytes.as_slice())
    }

    pub fn pending_entry_pc(&self) -> Option<u64> {
        self.pending.as_ref().map(|pending| pending.entry_pc)
    }

    pub fn pending_matches_generation(&self, permit_generation: u32) -> bool {
        self.pending
            .as_ref()
            .is_some_and(|pending| pending.permit_generation == permit_generation)
    }

    pub fn clear_pending(&mut self) {
        self.pending = None;
        self.trace.count = 0;
    }

    pub fn install_pending(&mut self, id: u32) -> bool {
        if id == 0 {
            return false;
        }
        let Some(pending) = self.pending.take() else {
            return false;
        };
        let entry_pc = pending.entry_pc;
        self.cache.insert(CompiledRegion {
            id,
            entry_pc,
            permit_generation: pending.permit_generation,
            code_ranges: pending.code_ranges,
        });
        self.ready.mark_ready(entry_pc);
        true
    }

    pub fn compiled_id(&mut self, pc: u64, permit_generation: u32) -> Option<u32> {
        let region = self.cache.get(pc)?;
        if region.permit_generation == permit_generation {
            return Some(region.id);
        }
        self.cache.clear();
        self.ready.clear();
        None
    }

    pub fn invalidate_range(&mut self, range: AddressRange) {
        for region in self.cache.invalidate_range(range) {
            self.ready.unmark_ready(region.entry_pc);
            self.hot_counts.reset(region.entry_pc);
        }
        if self.pending.as_ref().is_some_and(|pending| {
            pending
                .code_ranges
                .iter()
                .any(|code_range| code_range.overlaps(range))
        }) {
            self.pending = None;
        }
    }

    pub fn clear(&mut self) {
        self.hot_counts.clear();
        self.ready.clear();
        self.trace = TraceBuffer::new();
        self.cache.clear();
        self.pending = None;
    }
}

pub(crate) fn invalidate_thread_code(vm: &mut crate::types::ThreadState, start: u64, end: u64) {
    let Some(range) = AddressRange::new(start, end) else {
        return;
    };
    if vm.jit_state_ptr != 0 {
        let jit = unsafe { &mut *(vm.jit_state_ptr as *mut JitState) };
        jit.invalidate_range(range);
    }
}

impl Default for JitState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceRegionError {
    Empty,
    InvalidStep(u64),
    DuplicatePc(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceCompileError {
    Trace(TraceRegionError),
    Compile(JitCompileError),
}

pub fn compile_trace_for_current_address_space(
    entries: &[TraceEntry],
    max_instructions: u32,
    memory_max_pages: u64,
) -> Result<Vec<u8>, TraceCompileError> {
    let region = region_from_trace(entries, max_instructions).map_err(TraceCompileError::Trace)?;
    let snapshot = crate::syscall::memory::jit_memory_snapshot();
    compile_region(
        &region,
        JitModuleConfig {
            memory_max_pages,
            permit_generation_address: snapshot.generation_address,
            permit_generation: snapshot.generation,
            memory_permits: &snapshot.permits,
        },
    )
    .map_err(TraceCompileError::Compile)
}

/// Convert one completed dynamic loop trace into linked basic blocks.
pub fn region_from_trace(
    entries: &[TraceEntry],
    max_instructions: u32,
) -> Result<Region, TraceRegionError> {
    let Some(first) = entries.first() else {
        return Err(TraceRegionError::Empty);
    };
    let mut seen = Vec::with_capacity(entries.len());
    for entry in entries {
        if entry.step != 2 && entry.step != 4 {
            return Err(TraceRegionError::InvalidStep(entry.pc));
        }
        if seen.contains(&entry.pc) {
            return Err(TraceRegionError::DuplicatePc(entry.pc));
        }
        seen.push(entry.pc);
    }

    let mut blocks = Vec::new();
    let mut current = RegionBlock {
        start_pc: first.pc,
        instructions: Vec::new(),
    };
    for (index, entry) in entries.iter().copied().enumerate() {
        current.instructions.push(RegionInstruction {
            pc: entry.pc,
            raw: entry.raw_insn,
            step: entry.step,
        });
        let next = entries.get(index + 1);
        let control = is_control(entry.raw_insn);
        let discontinuity =
            next.is_some_and(|next| next.pc != entry.pc.wrapping_add(entry.step as u64));
        if control || discontinuity || next.is_none() {
            if let Some(next) = next {
                let completed = core::mem::replace(
                    &mut current,
                    RegionBlock {
                        start_pc: next.pc,
                        instructions: Vec::new(),
                    },
                );
                blocks.push(completed);
            } else {
                blocks.push(current);
                break;
            }
        }
    }

    Ok(Region {
        entry_pc: first.pc,
        max_instructions,
        blocks,
    })
}

fn is_control(raw: u32) -> bool {
    matches!(
        decode::opcode(raw),
        decode::OP_BRANCH | decode::OP_JAL | decode::OP_JALR | decode::OP_SYSTEM
    )
}
