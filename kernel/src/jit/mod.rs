//! JIT compiler: RISC-V → WASM translation.

use alloc_crate::vec::Vec;

use crate::cpu::{decode, trace::TraceEntry};
use wasm_gen::{
    JitCompileError, JitModuleConfig, Region, RegionBlock, RegionInstruction, compile_region,
};

pub mod cache;
pub mod wasm_gen;

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
