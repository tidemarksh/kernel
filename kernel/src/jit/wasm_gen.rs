//! RISC-V region to WebAssembly code generation.

use alloc_crate::{borrow::Cow, vec::Vec};
use wasm_encoder::{
    BlockType, CodeSection, EntityType, ExportKind, ExportSection, Function, FunctionSection,
    ImportSection, Instruction, MemArg, MemoryType, Module, TypeSection, ValType,
};

use crate::cpu::decode;
use crate::types::{ProcessState, ThreadState};

const REGISTER_COUNT: u32 = 32;
const LOCAL_DISPATCH: u32 = 33;
const LOCAL_COUNT: u32 = 34;
const LOCAL_PROCESS_PTR: u32 = 35;
const LOCAL_PC: u32 = 36;
const LOCAL_GUEST_BASE: u32 = 37;
const LOCAL_ADDRESS: u32 = 38;
const MAX_MEMORY64_PAGES: u64 = 1 << 48;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JitMemoryPermit {
    pub start: u64,
    pub end: u64,
    pub prot: i32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JitMemorySnapshot {
    pub generation_address: u64,
    pub generation: u32,
    pub permits: Vec<JitMemoryPermit>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JitModuleConfig<'a> {
    /// Maximum pages declared by the process shared WebAssembly.Memory.
    pub memory_max_pages: u64,
    /// Absolute shared-memory address of Kernel's VMA permit generation.
    pub permit_generation_address: u64,
    pub permit_generation: u32,
    pub memory_permits: &'a [JitMemoryPermit],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegionInstruction {
    pub pc: u64,
    pub raw: u32,
    pub step: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegionBlock {
    pub start_pc: u64,
    pub instructions: Vec<RegionInstruction>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Region {
    pub entry_pc: u64,
    pub max_instructions: u32,
    pub blocks: Vec<RegionBlock>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JitCompileError {
    EmptyRegion,
    MissingEntry,
    EmptyBlock(u64),
    BlockStartMismatch(u64),
    NonContiguousInstruction(u64),
    DuplicatePc(u64),
    InvalidInstructionStep(u64),
    ControlBeforeBlockEnd(u64),
    UnsupportedInstruction(u64, u32),
    InvalidMemoryMaximum(u64),
    MissingPermitGeneration,
    InvalidMemoryPermit(u64, u64),
}

#[derive(Clone, Copy)]
enum Decoded {
    OpImm {
        rd: usize,
        rs1: usize,
        kind: u32,
        imm: i64,
        alternate: bool,
    },
    OpImm32 {
        rd: usize,
        rs1: usize,
        kind: u32,
        imm: i64,
        alternate: bool,
    },
    Op {
        rd: usize,
        rs1: usize,
        rs2: usize,
        kind: u32,
        alternate: bool,
    },
    Op32 {
        rd: usize,
        rs1: usize,
        rs2: usize,
        kind: u32,
        alternate: bool,
    },
    Lui {
        rd: usize,
        imm: i64,
    },
    Auipc {
        rd: usize,
        value: u64,
    },
    Load {
        rd: usize,
        rs1: usize,
        kind: u32,
        imm: i64,
    },
    Store {
        rs1: usize,
        rs2: usize,
        kind: u32,
        imm: i64,
    },
    Branch {
        kind: u32,
        rs1: usize,
        rs2: usize,
        target: u64,
        fallthrough: u64,
    },
    Jal {
        rd: usize,
        target: u64,
        fallthrough: u64,
    },
}

impl Decoded {
    fn is_control(self) -> bool {
        matches!(self, Self::Branch { .. } | Self::Jal { .. })
    }
}

pub fn compile_region(
    region: &Region,
    config: JitModuleConfig<'_>,
) -> Result<Vec<u8>, JitCompileError> {
    if config.memory_max_pages == 0 || config.memory_max_pages > MAX_MEMORY64_PAGES {
        return Err(JitCompileError::InvalidMemoryMaximum(
            config.memory_max_pages,
        ));
    }
    let decoded = validate_region(region)?;
    let has_memory = decoded
        .iter()
        .flatten()
        .any(|instruction| matches!(instruction, Decoded::Load { .. } | Decoded::Store { .. }));
    if has_memory && config.permit_generation_address == 0 {
        return Err(JitCompileError::MissingPermitGeneration);
    }
    for permit in config.memory_permits {
        if permit.start >= permit.end {
            return Err(JitCompileError::InvalidMemoryPermit(
                permit.start,
                permit.end,
            ));
        }
    }
    let mut module = Module::new();

    let mut types = TypeSection::new();
    types.ty().function([ValType::I32], [ValType::I32]);
    module.section(&types);

    let mut imports = ImportSection::new();
    imports.import(
        "env",
        "memory",
        EntityType::Memory(MemoryType {
            minimum: 0,
            maximum: Some(config.memory_max_pages),
            memory64: true,
            shared: true,
            page_size_log2: None,
        }),
    );
    module.section(&imports);

    let mut functions = FunctionSection::new();
    functions.function(0);
    module.section(&functions);

    let mut exports = ExportSection::new();
    exports.export("run", ExportKind::Func, 0);
    module.section(&exports);

    let mut function = Function::new([
        (REGISTER_COUNT, ValType::I64),
        (3, ValType::I32),
        (3, ValType::I64),
    ]);
    emit_preamble(&mut function);
    function.instruction(&Instruction::I32Const(
        block_index(region, region.entry_pc).unwrap() as i32,
    ));
    function.instruction(&Instruction::LocalSet(LOCAL_DISPATCH));
    function.instruction(&Instruction::I32Const(0));
    function.instruction(&Instruction::LocalSet(LOCAL_COUNT));

    function.instruction(&Instruction::Block(BlockType::Empty));
    function.instruction(&Instruction::Loop(BlockType::Empty));
    for _ in &region.blocks {
        function.instruction(&Instruction::Block(BlockType::Empty));
    }
    let targets: Vec<u32> = (0..region.blocks.len() as u32).rev().collect();
    function.instruction(&Instruction::LocalGet(LOCAL_DISPATCH));
    function.instruction(&Instruction::BrTable(
        Cow::Owned(targets),
        region.blocks.len() as u32 + 1,
    ));

    for block_index in (0..region.blocks.len()).rev() {
        function.instruction(&Instruction::End);
        emit_block(
            &mut function,
            region,
            &region.blocks[block_index],
            &decoded[block_index],
            block_index as u32,
            config,
        );
    }
    function.instruction(&Instruction::End);
    function.instruction(&Instruction::End);
    emit_epilogue(&mut function);
    function.instruction(&Instruction::LocalGet(LOCAL_COUNT));
    function.instruction(&Instruction::End);

    let mut code = CodeSection::new();
    code.function(&function);
    module.section(&code);
    Ok(module.finish())
}

fn validate_region(region: &Region) -> Result<Vec<Vec<Decoded>>, JitCompileError> {
    if region.blocks.is_empty() || region.max_instructions == 0 {
        return Err(JitCompileError::EmptyRegion);
    }
    if block_index(region, region.entry_pc).is_none() {
        return Err(JitCompileError::MissingEntry);
    }

    let mut decoded_blocks = Vec::with_capacity(region.blocks.len());
    let mut seen = Vec::new();
    for block in &region.blocks {
        if block.instructions.is_empty() {
            return Err(JitCompileError::EmptyBlock(block.start_pc));
        }
        if block.instructions[0].pc != block.start_pc {
            return Err(JitCompileError::BlockStartMismatch(block.start_pc));
        }
        let mut next_pc = block.start_pc;
        let mut decoded = Vec::with_capacity(block.instructions.len());
        for (index, instruction) in block.instructions.iter().enumerate() {
            if instruction.step != 2 && instruction.step != 4 {
                return Err(JitCompileError::InvalidInstructionStep(instruction.pc));
            }
            if instruction.pc != next_pc {
                return Err(JitCompileError::NonContiguousInstruction(instruction.pc));
            }
            if seen.contains(&instruction.pc) {
                return Err(JitCompileError::DuplicatePc(instruction.pc));
            }
            seen.push(instruction.pc);
            let decoded_instruction = decode_instruction(*instruction)?;
            if decoded_instruction.is_control() && index + 1 != block.instructions.len() {
                return Err(JitCompileError::ControlBeforeBlockEnd(instruction.pc));
            }
            decoded.push(decoded_instruction);
            next_pc = instruction.pc.wrapping_add(instruction.step as u64);
        }
        decoded_blocks.push(decoded);
    }
    Ok(decoded_blocks)
}

fn decode_instruction(instruction: RegionInstruction) -> Result<Decoded, JitCompileError> {
    let raw = instruction.raw;
    let fallthrough = instruction.pc.wrapping_add(instruction.step as u64);
    match decode::opcode(raw) {
        decode::OP_OP_IMM if valid_immediate_alu(raw, false) => Ok(Decoded::OpImm {
            rd: decode::rd(raw),
            rs1: decode::rs1(raw),
            kind: decode::funct3(raw),
            imm: decode::imm_i(raw),
            alternate: decode::funct3(raw) == 5 && (raw >> 30) & 1 != 0,
        }),
        decode::OP_OP_IMM_32 if valid_immediate_alu(raw, true) => Ok(Decoded::OpImm32 {
            rd: decode::rd(raw),
            rs1: decode::rs1(raw),
            kind: decode::funct3(raw),
            imm: decode::imm_i(raw),
            alternate: decode::funct3(raw) == 5 && (raw >> 30) & 1 != 0,
        }),
        decode::OP_OP if valid_register_alu(raw, false) => Ok(Decoded::Op {
            rd: decode::rd(raw),
            rs1: decode::rs1(raw),
            rs2: decode::rs2(raw),
            kind: decode::funct3(raw),
            alternate: decode::funct7(raw) == 0x20,
        }),
        decode::OP_OP_32 if valid_register_alu(raw, true) => Ok(Decoded::Op32 {
            rd: decode::rd(raw),
            rs1: decode::rs1(raw),
            rs2: decode::rs2(raw),
            kind: decode::funct3(raw),
            alternate: decode::funct7(raw) == 0x20,
        }),
        decode::OP_LUI => Ok(Decoded::Lui {
            rd: decode::rd(raw),
            imm: decode::imm_u(raw),
        }),
        decode::OP_AUIPC => Ok(Decoded::Auipc {
            rd: decode::rd(raw),
            value: instruction.pc.wrapping_add_signed(decode::imm_u(raw)),
        }),
        decode::OP_LOAD if decode::funct3(raw) <= 6 => Ok(Decoded::Load {
            rd: decode::rd(raw),
            rs1: decode::rs1(raw),
            kind: decode::funct3(raw),
            imm: decode::imm_i(raw),
        }),
        decode::OP_STORE if decode::funct3(raw) <= 3 => Ok(Decoded::Store {
            rs1: decode::rs1(raw),
            rs2: decode::rs2(raw),
            kind: decode::funct3(raw),
            imm: decode::imm_s(raw),
        }),
        decode::OP_BRANCH if !matches!(decode::funct3(raw), 2 | 3) => Ok(Decoded::Branch {
            kind: decode::funct3(raw),
            rs1: decode::rs1(raw),
            rs2: decode::rs2(raw),
            target: instruction.pc.wrapping_add_signed(decode::imm_b(raw)),
            fallthrough,
        }),
        decode::OP_JAL => Ok(Decoded::Jal {
            rd: decode::rd(raw),
            target: instruction.pc.wrapping_add_signed(decode::imm_j(raw)),
            fallthrough,
        }),
        _ => Err(JitCompileError::UnsupportedInstruction(instruction.pc, raw)),
    }
}

fn valid_immediate_alu(raw: u32, word: bool) -> bool {
    match decode::funct3(raw) {
        0 => true,
        1 => {
            if word {
                decode::funct7(raw) == 0
            } else {
                raw >> 26 == 0
            }
        }
        5 => {
            if word {
                matches!(decode::funct7(raw), 0 | 0x20)
            } else {
                matches!(raw >> 26, 0 | 0x10)
            }
        }
        2..=4 | 6..=7 => !word,
        _ => false,
    }
}

fn valid_register_alu(raw: u32, word: bool) -> bool {
    match (decode::funct3(raw), decode::funct7(raw)) {
        (0 | 5, 0 | 0x20) => true,
        (1, 0) => true,
        (2..=4 | 6..=7, 0) => !word,
        _ => false,
    }
}

fn emit_preamble(function: &mut Function) {
    for register in 0..REGISTER_COUNT {
        function.instruction(&Instruction::LocalGet(0));
        function.instruction(&Instruction::I64ExtendI32U);
        function.instruction(&Instruction::I64Load(memarg((register * 8) as u64)));
        function.instruction(&Instruction::LocalSet(register + 1));
    }
    function.instruction(&Instruction::I64Const(0));
    function.instruction(&Instruction::LocalSet(1));
    function.instruction(&Instruction::LocalGet(0));
    function.instruction(&Instruction::I64ExtendI32U);
    function.instruction(&Instruction::I64Load(memarg(REGISTER_COUNT as u64 * 8)));
    function.instruction(&Instruction::LocalSet(LOCAL_PC));
    function.instruction(&Instruction::LocalGet(0));
    function.instruction(&Instruction::I64ExtendI32U);
    function.instruction(&Instruction::I32Load(memarg_with_align(
        core::mem::offset_of!(ThreadState, guest_base) as u64,
        2,
    )));
    function.instruction(&Instruction::I64ExtendI32U);
    function.instruction(&Instruction::LocalSet(LOCAL_GUEST_BASE));
    function.instruction(&Instruction::LocalGet(0));
    function.instruction(&Instruction::I64ExtendI32U);
    function.instruction(&Instruction::I32Load(memarg_with_align(
        core::mem::offset_of!(ThreadState, process_ptr) as u64,
        2,
    )));
    function.instruction(&Instruction::LocalSet(LOCAL_PROCESS_PTR));
}

fn emit_epilogue(function: &mut Function) {
    for register in 1..REGISTER_COUNT {
        function.instruction(&Instruction::LocalGet(0));
        function.instruction(&Instruction::I64ExtendI32U);
        function.instruction(&Instruction::LocalGet(register + 1));
        function.instruction(&Instruction::I64Store(memarg((register * 8) as u64)));
    }
    function.instruction(&Instruction::LocalGet(0));
    function.instruction(&Instruction::I64ExtendI32U);
    function.instruction(&Instruction::LocalGet(LOCAL_PC));
    function.instruction(&Instruction::I64Store(memarg(REGISTER_COUNT as u64 * 8)));
}

fn emit_block(
    function: &mut Function,
    region: &Region,
    block: &RegionBlock,
    decoded: &[Decoded],
    outer_block_count: u32,
    config: JitModuleConfig<'_>,
) {
    for (instruction, decoded) in block.instructions.iter().zip(decoded.iter().copied()) {
        emit_budget_guard(
            function,
            region.max_instructions,
            instruction.pc,
            outer_block_count,
        );
        if matches!(decoded, Decoded::Load { .. } | Decoded::Store { .. }) {
            emit_memory_guards(function, decoded, instruction.pc, outer_block_count, config);
        }
        emit_instruction(function, decoded);
        function.instruction(&Instruction::LocalGet(LOCAL_COUNT));
        function.instruction(&Instruction::I32Const(1));
        function.instruction(&Instruction::I32Add);
        function.instruction(&Instruction::LocalSet(LOCAL_COUNT));
        function.instruction(&Instruction::I64Const(
            instruction.pc.wrapping_add(instruction.step as u64) as i64,
        ));
        function.instruction(&Instruction::LocalSet(LOCAL_PC));
    }

    match decoded.last().copied().unwrap() {
        Decoded::Branch {
            kind,
            rs1,
            rs2,
            target,
            fallthrough,
        } => {
            emit_branch_condition(function, kind, rs1, rs2);
            function.instruction(&Instruction::If(BlockType::Empty));
            emit_transition(function, region, target, outer_block_count + 1);
            function.instruction(&Instruction::Else);
            emit_transition(function, region, fallthrough, outer_block_count + 1);
            function.instruction(&Instruction::End);
        }
        Decoded::Jal {
            rd,
            target,
            fallthrough,
        } => {
            if rd != 0 {
                function.instruction(&Instruction::I64Const(fallthrough as i64));
                function.instruction(&Instruction::LocalSet(rd as u32 + 1));
            }
            emit_transition(function, region, target, outer_block_count);
        }
        _ => {
            let next_pc = block.instructions.last().unwrap().pc
                + block.instructions.last().unwrap().step as u64;
            emit_transition(function, region, next_pc, outer_block_count);
        }
    }
}

fn emit_instruction(function: &mut Function, decoded: Decoded) {
    match decoded {
        Decoded::OpImm {
            rd,
            rs1,
            kind,
            imm,
            alternate,
        } => {
            function.instruction(&Instruction::LocalGet(rs1 as u32 + 1));
            function.instruction(&Instruction::I64Const(imm));
            emit_i64_alu(function, kind, alternate);
            set_register(function, rd);
        }
        Decoded::OpImm32 {
            rd,
            rs1,
            kind,
            imm,
            alternate,
        } => {
            function.instruction(&Instruction::LocalGet(rs1 as u32 + 1));
            function.instruction(&Instruction::I32WrapI64);
            function.instruction(&Instruction::I32Const(imm as i32));
            emit_i32_word_alu(function, kind, alternate);
            function.instruction(&Instruction::I64ExtendI32S);
            set_register(function, rd);
        }
        Decoded::Op {
            rd,
            rs1,
            rs2,
            kind,
            alternate,
        } => {
            function.instruction(&Instruction::LocalGet(rs1 as u32 + 1));
            function.instruction(&Instruction::LocalGet(rs2 as u32 + 1));
            emit_i64_alu(function, kind, alternate);
            set_register(function, rd);
        }
        Decoded::Op32 {
            rd,
            rs1,
            rs2,
            kind,
            alternate,
        } => {
            function.instruction(&Instruction::LocalGet(rs1 as u32 + 1));
            function.instruction(&Instruction::I32WrapI64);
            function.instruction(&Instruction::LocalGet(rs2 as u32 + 1));
            function.instruction(&Instruction::I32WrapI64);
            emit_i32_word_alu(function, kind, alternate);
            function.instruction(&Instruction::I64ExtendI32S);
            set_register(function, rd);
        }
        Decoded::Lui { rd, imm } => {
            function.instruction(&Instruction::I64Const(imm));
            set_register(function, rd);
        }
        Decoded::Auipc { rd, value } => {
            function.instruction(&Instruction::I64Const(value as i64));
            set_register(function, rd);
        }
        Decoded::Load { rd, kind, .. } => {
            emit_guest_memory_address(function);
            function.instruction(&match kind {
                0 => Instruction::I64Load8S(memarg_with_align(0, 0)),
                1 => Instruction::I64Load16S(memarg_with_align(0, 1)),
                2 => Instruction::I64Load32S(memarg_with_align(0, 2)),
                3 => Instruction::I64Load(memarg_with_align(0, 3)),
                4 => Instruction::I64Load8U(memarg_with_align(0, 0)),
                5 => Instruction::I64Load16U(memarg_with_align(0, 1)),
                6 => Instruction::I64Load32U(memarg_with_align(0, 2)),
                _ => unreachable!(),
            });
            set_register(function, rd);
        }
        Decoded::Store { rs2, kind, .. } => {
            emit_guest_memory_address(function);
            function.instruction(&Instruction::LocalGet(rs2 as u32 + 1));
            function.instruction(&match kind {
                0 => Instruction::I64Store8(memarg_with_align(0, 0)),
                1 => Instruction::I64Store16(memarg_with_align(0, 1)),
                2 => Instruction::I64Store32(memarg_with_align(0, 2)),
                3 => Instruction::I64Store(memarg_with_align(0, 3)),
                _ => unreachable!(),
            });
        }
        Decoded::Branch { .. } | Decoded::Jal { .. } => {}
    }
}

fn emit_memory_guards(
    function: &mut Function,
    decoded: Decoded,
    pc: u64,
    outer_block_count: u32,
    config: JitModuleConfig<'_>,
) {
    let (rs1, imm, width, prot) = match decoded {
        Decoded::Load { rs1, imm, kind, .. } => {
            (rs1, imm, memory_width(kind), crate::abi::PROT_READ)
        }
        Decoded::Store { rs1, imm, kind, .. } => {
            (rs1, imm, memory_width(kind), crate::abi::PROT_WRITE)
        }
        _ => unreachable!(),
    };
    function.instruction(&Instruction::LocalGet(rs1 as u32 + 1));
    function.instruction(&Instruction::I64Const(imm));
    function.instruction(&Instruction::I64Add);
    function.instruction(&Instruction::LocalSet(LOCAL_ADDRESS));

    emit_generation_guard(function, pc, outer_block_count, config);
    emit_single_thread_guard(function, pc, outer_block_count);
    emit_permit_guard(
        function,
        pc,
        outer_block_count,
        width,
        prot,
        config.memory_permits,
    );
}

fn emit_generation_guard(
    function: &mut Function,
    pc: u64,
    outer_block_count: u32,
    config: JitModuleConfig<'_>,
) {
    function.instruction(&Instruction::I64Const(
        config.permit_generation_address as i64,
    ));
    function.instruction(&Instruction::I32AtomicLoad(memarg_with_align(0, 2)));
    function.instruction(&Instruction::I32Const(config.permit_generation as i32));
    function.instruction(&Instruction::I32Ne);
    emit_side_exit_if(function, pc, outer_block_count);
}

fn emit_single_thread_guard(function: &mut Function, pc: u64, outer_block_count: u32) {
    function.instruction(&Instruction::LocalGet(LOCAL_PROCESS_PTR));
    function.instruction(&Instruction::I32Eqz);
    emit_side_exit_if(function, pc, outer_block_count);

    function.instruction(&Instruction::LocalGet(LOCAL_GUEST_BASE));
    function.instruction(&Instruction::LocalGet(LOCAL_PROCESS_PTR));
    function.instruction(&Instruction::I64ExtendI32U);
    function.instruction(&Instruction::I64Add);
    function.instruction(&Instruction::I32AtomicLoad(memarg_with_align(
        core::mem::offset_of!(ProcessState, thread_count) as u64,
        2,
    )));
    function.instruction(&Instruction::I32Const(1));
    function.instruction(&Instruction::I32Ne);
    emit_side_exit_if(function, pc, outer_block_count);
}

fn emit_permit_guard(
    function: &mut Function,
    pc: u64,
    outer_block_count: u32,
    width: u64,
    prot: i32,
    permits: &[JitMemoryPermit],
) {
    let mut emitted = false;
    for permit in permits {
        if permit.prot & prot != prot || permit.end - permit.start < width {
            continue;
        }
        function.instruction(&Instruction::LocalGet(LOCAL_ADDRESS));
        function.instruction(&Instruction::I64Const(permit.start as i64));
        function.instruction(&Instruction::I64GeU);
        function.instruction(&Instruction::LocalGet(LOCAL_ADDRESS));
        function.instruction(&Instruction::I64Const((permit.end - width) as i64));
        function.instruction(&Instruction::I64LeU);
        function.instruction(&Instruction::I32And);
        if emitted {
            function.instruction(&Instruction::I32Or);
        }
        emitted = true;
    }
    if !emitted {
        function.instruction(&Instruction::I32Const(0));
    }
    function.instruction(&Instruction::I32Eqz);
    emit_side_exit_if(function, pc, outer_block_count);
}

fn emit_side_exit_if(function: &mut Function, pc: u64, outer_block_count: u32) {
    function.instruction(&Instruction::If(BlockType::Empty));
    function.instruction(&Instruction::I64Const(pc as i64));
    function.instruction(&Instruction::LocalSet(LOCAL_PC));
    function.instruction(&Instruction::Br(outer_block_count + 2));
    function.instruction(&Instruction::End);
}

fn emit_guest_memory_address(function: &mut Function) {
    function.instruction(&Instruction::LocalGet(LOCAL_GUEST_BASE));
    function.instruction(&Instruction::LocalGet(LOCAL_ADDRESS));
    function.instruction(&Instruction::I64Add);
}

fn memory_width(kind: u32) -> u64 {
    match kind {
        0 | 4 => 1,
        1 | 5 => 2,
        2 | 6 => 4,
        3 => 8,
        _ => unreachable!(),
    }
}

fn emit_i64_alu(function: &mut Function, kind: u32, alternate: bool) {
    function.instruction(&match (kind, alternate) {
        (0, false) => Instruction::I64Add,
        (0, true) => Instruction::I64Sub,
        (1, false) => Instruction::I64Shl,
        (2, false) => Instruction::I64LtS,
        (3, false) => Instruction::I64LtU,
        (4, false) => Instruction::I64Xor,
        (5, false) => Instruction::I64ShrU,
        (5, true) => Instruction::I64ShrS,
        (6, false) => Instruction::I64Or,
        (7, false) => Instruction::I64And,
        _ => unreachable!(),
    });
    if matches!(kind, 2 | 3) {
        function.instruction(&Instruction::I64ExtendI32U);
    }
}

fn emit_i32_word_alu(function: &mut Function, kind: u32, alternate: bool) {
    function.instruction(&match (kind, alternate) {
        (0, false) => Instruction::I32Add,
        (0, true) => Instruction::I32Sub,
        (1, false) => Instruction::I32Shl,
        (5, false) => Instruction::I32ShrU,
        (5, true) => Instruction::I32ShrS,
        _ => unreachable!(),
    });
}

fn emit_branch_condition(function: &mut Function, kind: u32, rs1: usize, rs2: usize) {
    function.instruction(&Instruction::LocalGet(rs1 as u32 + 1));
    function.instruction(&Instruction::LocalGet(rs2 as u32 + 1));
    function.instruction(&match kind {
        0 => Instruction::I64Eq,
        1 => Instruction::I64Ne,
        4 => Instruction::I64LtS,
        5 => Instruction::I64GeS,
        6 => Instruction::I64LtU,
        7 => Instruction::I64GeU,
        _ => unreachable!(),
    });
}

fn emit_transition(function: &mut Function, region: &Region, pc: u64, outer_block_count: u32) {
    function.instruction(&Instruction::I64Const(pc as i64));
    function.instruction(&Instruction::LocalSet(LOCAL_PC));
    if let Some(index) = block_index(region, pc) {
        function.instruction(&Instruction::I32Const(index as i32));
        function.instruction(&Instruction::LocalSet(LOCAL_DISPATCH));
        function.instruction(&Instruction::Br(outer_block_count));
    } else {
        function.instruction(&Instruction::Br(outer_block_count + 1));
    }
}

fn emit_budget_guard(function: &mut Function, max: u32, pc: u64, outer_block_count: u32) {
    function.instruction(&Instruction::LocalGet(LOCAL_COUNT));
    function.instruction(&Instruction::I32Const(max as i32));
    function.instruction(&Instruction::I32GeU);
    function.instruction(&Instruction::If(BlockType::Empty));
    function.instruction(&Instruction::I64Const(pc as i64));
    function.instruction(&Instruction::LocalSet(LOCAL_PC));
    function.instruction(&Instruction::Br(outer_block_count + 2));
    function.instruction(&Instruction::End);
}

fn set_register(function: &mut Function, rd: usize) {
    if rd == 0 {
        function.instruction(&Instruction::Drop);
    } else {
        function.instruction(&Instruction::LocalSet(rd as u32 + 1));
    }
}

fn block_index(region: &Region, pc: u64) -> Option<usize> {
    region.blocks.iter().position(|block| block.start_pc == pc)
}

fn memarg(offset: u64) -> MemArg {
    memarg_with_align(offset, 3)
}

fn memarg_with_align(offset: u64, align: u32) -> MemArg {
    MemArg {
        offset,
        align,
        memory_index: 0,
    }
}
