//! RISC-V region to WebAssembly code generation.

use alloc_crate::{borrow::Cow, vec::Vec};
use wasm_encoder::{
    BlockType, CodeSection, EntityType, ExportKind, ExportSection, Function, FunctionSection,
    ImportSection, Instruction, MemArg, MemoryType, Module, TypeSection, ValType,
};

use crate::cpu::decode;

const REGISTER_COUNT: u32 = 32;
const LOCAL_DISPATCH: u32 = 33;
const LOCAL_COUNT: u32 = 34;
const LOCAL_PC: u32 = 35;
const MAX_MEMORY64_PAGES: u64 = 1 << 48;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JitModuleConfig {
    /// Maximum pages declared by the process shared WebAssembly.Memory.
    pub memory_max_pages: u64,
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
}

#[derive(Clone, Copy)]
enum Decoded {
    Addi {
        rd: usize,
        rs1: usize,
        imm: i64,
    },
    Add {
        rd: usize,
        rs1: usize,
        rs2: usize,
    },
    Sub {
        rd: usize,
        rs1: usize,
        rs2: usize,
    },
    Lui {
        rd: usize,
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
    config: JitModuleConfig,
) -> Result<Vec<u8>, JitCompileError> {
    if config.memory_max_pages == 0 || config.memory_max_pages > MAX_MEMORY64_PAGES {
        return Err(JitCompileError::InvalidMemoryMaximum(
            config.memory_max_pages,
        ));
    }
    let decoded = validate_region(region)?;
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
        (2, ValType::I32),
        (1, ValType::I64),
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
        decode::OP_OP_IMM if decode::funct3(raw) == 0 => Ok(Decoded::Addi {
            rd: decode::rd(raw),
            rs1: decode::rs1(raw),
            imm: decode::imm_i(raw),
        }),
        decode::OP_OP if decode::funct3(raw) == 0 && decode::funct7(raw) == 0 => Ok(Decoded::Add {
            rd: decode::rd(raw),
            rs1: decode::rs1(raw),
            rs2: decode::rs2(raw),
        }),
        decode::OP_OP if decode::funct3(raw) == 0 && decode::funct7(raw) == 0x20 => {
            Ok(Decoded::Sub {
                rd: decode::rd(raw),
                rs1: decode::rs1(raw),
                rs2: decode::rs2(raw),
            })
        }
        decode::OP_LUI => Ok(Decoded::Lui {
            rd: decode::rd(raw),
            imm: decode::imm_u(raw),
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
) {
    for (instruction, decoded) in block.instructions.iter().zip(decoded.iter().copied()) {
        emit_budget_guard(
            function,
            region.max_instructions,
            instruction.pc,
            outer_block_count,
        );
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
        Decoded::Addi { rd, rs1, imm } => {
            function.instruction(&Instruction::LocalGet(rs1 as u32 + 1));
            function.instruction(&Instruction::I64Const(imm));
            function.instruction(&Instruction::I64Add);
            set_register(function, rd);
        }
        Decoded::Add { rd, rs1, rs2 } | Decoded::Sub { rd, rs1, rs2 } => {
            function.instruction(&Instruction::LocalGet(rs1 as u32 + 1));
            function.instruction(&Instruction::LocalGet(rs2 as u32 + 1));
            function.instruction(&if matches!(decoded, Decoded::Add { .. }) {
                Instruction::I64Add
            } else {
                Instruction::I64Sub
            });
            set_register(function, rd);
        }
        Decoded::Lui { rd, imm } => {
            function.instruction(&Instruction::I64Const(imm));
            set_register(function, rd);
        }
        Decoded::Branch { .. } | Decoded::Jal { .. } => {}
    }
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
    MemArg {
        offset,
        align: 3,
        memory_index: 0,
    }
}
