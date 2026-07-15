use tidemark_kernel::cpu::trace::TraceEntry;
use tidemark_kernel::jit::cache::{AddressRange, CompiledRegion, RegionCache};
use tidemark_kernel::jit::wasm_gen::{
    JitCompileError, JitModuleConfig, Region, RegionBlock, RegionInstruction, compile_region,
};
use tidemark_kernel::jit::{TraceRegionError, region_from_trace};
use wasmparser::{Imports, Operator, Parser, Payload, Validator, WasmFeatures};

fn instruction(pc: u64, raw: u32) -> RegionInstruction {
    RegionInstruction { pc, raw, step: 4 }
}

fn addi(rd: u32, rs1: u32, imm: i32) -> u32 {
    ((imm as u32 & 0xfff) << 20) | (rs1 << 15) | (rd << 7) | 0x13
}

fn op_imm(rd: u32, rs1: u32, imm: u32, funct3: u32) -> u32 {
    ((imm & 0xfff) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | 0x13
}

fn op(rd: u32, rs1: u32, rs2: u32, funct3: u32, funct7: u32) -> u32 {
    (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | 0x33
}

fn branch(pc: u64, target: u64, rs1: u32, rs2: u32, funct3: u32) -> u32 {
    let imm = target.wrapping_sub(pc) as u32;
    ((imm >> 12 & 1) << 31)
        | ((imm >> 5 & 0x3f) << 25)
        | (rs2 << 20)
        | (rs1 << 15)
        | (funct3 << 12)
        | ((imm >> 1 & 0xf) << 8)
        | ((imm >> 11 & 1) << 7)
        | 0x63
}

fn jal(pc: u64, target: u64, rd: u32) -> u32 {
    let imm = target.wrapping_sub(pc) as u32;
    ((imm >> 20 & 1) << 31)
        | ((imm >> 1 & 0x3ff) << 21)
        | ((imm >> 11 & 1) << 20)
        | ((imm >> 12 & 0xff) << 12)
        | (rd << 7)
        | 0x6f
}

fn diamond_region() -> Region {
    Region {
        entry_pc: 0x1000,
        max_instructions: 32,
        blocks: vec![
            RegionBlock {
                start_pc: 0x1000,
                instructions: vec![instruction(0x1000, branch(0x1000, 0x1010, 1, 2, 0))],
            },
            RegionBlock {
                start_pc: 0x1004,
                instructions: vec![
                    instruction(0x1004, addi(3, 3, 1)),
                    instruction(0x1008, jal(0x1008, 0x1020, 0)),
                ],
            },
            RegionBlock {
                start_pc: 0x1010,
                instructions: vec![
                    instruction(0x1010, addi(3, 3, 2)),
                    instruction(0x1014, jal(0x1014, 0x1020, 0)),
                ],
            },
            RegionBlock {
                start_pc: 0x1020,
                instructions: vec![instruction(0x1020, jal(0x1020, 0x1000, 0))],
            },
        ],
    }
}

fn compile(region: &Region) -> Result<Vec<u8>, JitCompileError> {
    compile_region(
        region,
        JitModuleConfig {
            memory_max_pages: 32_768,
        },
    )
}

#[test]
fn region_module_validates_and_uses_shared_memory64_abi() {
    let bytes = compile(&diamond_region()).expect("region compiles");
    Validator::new_with_features(WasmFeatures::default() | WasmFeatures::THREADS)
        .validate_all(&bytes)
        .expect("generated module validates");

    let mut memory_import = None;
    let mut run_export = false;
    for payload in Parser::new(0).parse_all(&bytes) {
        match payload.expect("module parses") {
            Payload::ImportSection(section) => {
                for import in section {
                    let import = import.expect("import parses");
                    if let Imports::Single(_, import) = import
                        && import.module == "env"
                        && import.name == "memory"
                    {
                        if let wasmparser::TypeRef::Memory(memory) = import.ty {
                            memory_import = Some(memory);
                        }
                    }
                }
            }
            Payload::ExportSection(section) => {
                run_export = section
                    .into_iter()
                    .map(|export| export.expect("export parses"))
                    .any(|export| export.name == "run");
            }
            _ => {}
        }
    }
    let memory = memory_import.expect("env.memory import");
    assert!(memory.memory64);
    assert!(memory.shared);
    assert_eq!(memory.maximum, Some(32_768));
    assert!(run_export);
}

#[test]
fn multi_block_region_uses_br_table_dispatch() {
    let bytes = compile(&diamond_region()).expect("region compiles");
    let mut table_targets = None;
    for payload in Parser::new(0).parse_all(&bytes) {
        if let Payload::CodeSectionEntry(body) = payload.expect("module parses") {
            let mut operators = body.get_operators_reader().expect("operators parse");
            while !operators.eof() {
                if let Operator::BrTable { targets } = operators.read().expect("operator parses") {
                    table_targets = Some(targets.targets().collect::<Result<Vec<_>, _>>().unwrap());
                }
            }
        }
    }
    assert_eq!(table_targets, Some(vec![3, 2, 1, 0]));
}

#[test]
fn rejects_duplicate_pc_missing_entry_and_unsupported_instruction() {
    let mut region = diamond_region();
    region.blocks.push(region.blocks[0].clone());
    assert_eq!(compile(&region), Err(JitCompileError::DuplicatePc(0x1000)));

    let mut region = diamond_region();
    region.entry_pc = 0x2000;
    assert_eq!(compile(&region), Err(JitCompileError::MissingEntry));

    let mut region = diamond_region();
    region.blocks[0].instructions[0].raw = 0x0000_0073;
    assert_eq!(
        compile(&region),
        Err(JitCompileError::UnsupportedInstruction(0x1000, 0x0000_0073))
    );
}

#[test]
fn rejects_an_unusable_memory_import_maximum() {
    assert_eq!(
        compile_region(
            &diamond_region(),
            JitModuleConfig {
                memory_max_pages: 0,
            },
        ),
        Err(JitCompileError::InvalidMemoryMaximum(0))
    );
}

#[test]
fn emits_rv64_integer_alu_and_word_operators() {
    let mut region = diamond_region();
    region.blocks[1].instructions = vec![
        instruction(0x1004, op_imm(3, 4, 7, 6)),
        instruction(0x1008, op_imm(5, 6, 3, 1)),
        instruction(0x100c, op(7, 8, 9, 5, 0x20)),
        instruction(0x1010, 0x0010_019b), // addiw x3, x0, 1
        instruction(0x1014, 0x0042_11bb), // sllw x3, x4, x4
        instruction(0x1018, jal(0x1018, 0x1020, 0)),
    ];
    region.blocks.remove(2);

    let bytes = compile(&region).expect("integer region compiles");
    Validator::new_with_features(WasmFeatures::default() | WasmFeatures::THREADS)
        .validate_all(&bytes)
        .expect("integer region module validates");
    let mut saw_or = false;
    let mut saw_shl = false;
    let mut saw_sar = false;
    let mut saw_i32_add = false;
    let mut saw_i32_shl = false;
    for payload in Parser::new(0).parse_all(&bytes) {
        if let Payload::CodeSectionEntry(body) = payload.expect("module parses") {
            let mut operators = body.get_operators_reader().expect("operators parse");
            while !operators.eof() {
                match operators.read().expect("operator parses") {
                    Operator::I64Or => saw_or = true,
                    Operator::I64Shl => saw_shl = true,
                    Operator::I64ShrS => saw_sar = true,
                    Operator::I32Add => saw_i32_add = true,
                    Operator::I32Shl => saw_i32_shl = true,
                    _ => {}
                }
            }
        }
    }
    assert!(saw_or && saw_shl && saw_sar && saw_i32_add && saw_i32_shl);
}

fn cached_region(id: u32, entry_pc: u64, ranges: &[(u64, u64)]) -> CompiledRegion {
    CompiledRegion {
        id,
        entry_pc,
        code_ranges: ranges
            .iter()
            .map(|&(start, end)| AddressRange::new(start, end).unwrap())
            .collect(),
    }
}

#[test]
fn region_cache_maps_entry_pc_and_replaces_existing_module() {
    let mut cache = RegionCache::new();
    assert!(
        cache
            .insert(cached_region(7, 0x1000, &[(0x1000, 0x1024)]))
            .is_none()
    );
    assert_eq!(cache.get(0x1000).map(|region| region.id), Some(7));
    assert!(cache.get(0x1004).is_none());

    let replaced = cache
        .insert(cached_region(8, 0x1000, &[(0x1000, 0x1030)]))
        .expect("same entry replaces old module");
    assert_eq!(replaced.id, 7);
    assert_eq!(cache.get(0x1000).map(|region| region.id), Some(8));
    assert_eq!(cache.len(), 1);
}

#[test]
fn range_invalidation_removes_only_overlapping_regions() {
    let mut cache = RegionCache::new();
    cache.insert(cached_region(
        1,
        0x1000,
        &[(0x1000, 0x1010), (0x1020, 0x1030)],
    ));
    cache.insert(cached_region(2, 0x2000, &[(0x2000, 0x2010)]));

    assert!(
        cache
            .invalidate_range(AddressRange::new(0x1010, 0x1020).unwrap())
            .is_empty()
    );
    let invalidated = cache.invalidate_range(AddressRange::new(0x102f, 0x1031).unwrap());
    assert_eq!(
        invalidated
            .iter()
            .map(|region| region.id)
            .collect::<Vec<_>>(),
        vec![1]
    );
    assert_eq!(cache.get(0x2000).map(|region| region.id), Some(2));
}

#[test]
fn exec_replacement_clears_all_region_metadata() {
    let mut cache = RegionCache::new();
    cache.insert(cached_region(1, 0x1000, &[(0x1000, 0x1010)]));
    cache.insert(cached_region(2, 0x2000, &[(0x2000, 0x2010)]));

    let cleared = cache.clear();
    assert_eq!(cleared.len(), 2);
    assert!(cache.is_empty());
}

#[test]
fn completed_loop_trace_becomes_multiple_linked_blocks() {
    let entries = [
        TraceEntry {
            pc: 0x1000,
            raw_insn: addi(3, 3, 1),
            step: 4,
        },
        TraceEntry {
            pc: 0x1004,
            raw_insn: branch(0x1004, 0x1010, 1, 2, 0),
            step: 4,
        },
        TraceEntry {
            pc: 0x1008,
            raw_insn: addi(4, 4, 1),
            step: 4,
        },
        TraceEntry {
            pc: 0x100c,
            raw_insn: jal(0x100c, 0x1000, 0),
            step: 4,
        },
    ];
    let region = region_from_trace(&entries, 64).expect("trace becomes a region");
    assert_eq!(region.entry_pc, 0x1000);
    assert_eq!(
        region
            .blocks
            .iter()
            .map(|block| block.start_pc)
            .collect::<Vec<_>>(),
        vec![0x1000, 0x1008]
    );
    compile(&region).expect("trace-derived region compiles");
}

#[test]
fn trace_region_rejects_repeated_inner_loop_pc() {
    let entries = [
        TraceEntry {
            pc: 0x1000,
            raw_insn: addi(3, 3, 1),
            step: 4,
        },
        TraceEntry {
            pc: 0x1000,
            raw_insn: addi(3, 3, 1),
            step: 4,
        },
    ];
    assert_eq!(
        region_from_trace(&entries, 64),
        Err(TraceRegionError::DuplicatePc(0x1000))
    );
}
