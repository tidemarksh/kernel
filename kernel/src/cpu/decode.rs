//! RISC-V RV64GC instruction decoder.
//!
//! Reference: RISC-V ISA spec V20191213
//!   (https://github.com/riscv/riscv-isa-manual/releases/tag/Ratified-IMAFDQC)
//!   §2 (RV32I), §5 (RV64I), §7 (M), §8 (A), §16 (C)
//!
//! All immediate extraction follows the spec's bit numbering exactly.

// =============================================================================
// 32-bit instruction field extraction
// =============================================================================

/// Extract opcode (bits 6:0)
#[inline(always)]
pub fn opcode(insn: u32) -> u32 {
    insn & 0x7F
}

/// Extract rd (bits 11:7)
#[inline(always)]
pub fn rd(insn: u32) -> usize {
    ((insn >> 7) & 0x1F) as usize
}

/// Extract funct3 (bits 14:12)
#[inline(always)]
pub fn funct3(insn: u32) -> u32 {
    (insn >> 12) & 0x7
}

/// Extract rs1 (bits 19:15)
#[inline(always)]
pub fn rs1(insn: u32) -> usize {
    ((insn >> 15) & 0x1F) as usize
}

/// Extract rs2 (bits 24:20)
#[inline(always)]
pub fn rs2(insn: u32) -> usize {
    ((insn >> 20) & 0x1F) as usize
}

/// Extract funct7 (bits 31:25)
#[inline(always)]
pub fn funct7(insn: u32) -> u32 {
    insn >> 25
}

/// Extract funct5 for AMO (bits 31:27)
#[inline(always)]
pub fn funct5(insn: u32) -> u32 {
    insn >> 27
}

/// Extract rs3 for FMA (bits 31:27)
#[inline(always)]
pub fn rs3(insn: u32) -> usize {
    (insn >> 27) as usize & 0x1F
}

// =============================================================================
// Immediate extraction (sign-extended to i64)
// =============================================================================

/// I-type immediate: insn[31:20], sign-extended
#[inline(always)]
pub fn imm_i(insn: u32) -> i64 {
    ((insn as i32) >> 20) as i64
}

/// S-type immediate: insn[31:25|11:7], sign-extended
#[inline(always)]
pub fn imm_s(insn: u32) -> i64 {
    let hi = ((insn as i32) >> 20) & !0x1F;
    let lo = ((insn >> 7) & 0x1F) as i32;
    (hi | lo) as i64
}

/// B-type immediate: insn[31|7|30:25|11:8] << 1, sign-extended
#[inline(always)]
pub fn imm_b(insn: u32) -> i64 {
    let v = (((insn as i32) >> 31) << 12)       // bit 12 (sign)
        | ((((insn >> 7) & 1) as i32) << 11)    // bit 11
        | ((((insn >> 25) & 0x3F) as i32) << 5) // bits 10:5
        | ((((insn >> 8) & 0xF) as i32) << 1); // bits 4:1
    v as i64
}

/// U-type immediate: insn[31:12] << 12, sign-extended to 64 bits
#[inline(always)]
pub fn imm_u(insn: u32) -> i64 {
    // (insn & 0xFFFFF000) as i32 gives sign extension from bit 31
    (insn & 0xFFFFF000) as i32 as i64
}

/// J-type immediate: insn[31|19:12|20|30:21] << 1, sign-extended
#[inline(always)]
pub fn imm_j(insn: u32) -> i64 {
    let v = (((insn as i32) >> 31) << 20)           // bit 20 (sign)
        | ((insn & 0x000FF000) as i32)               // bits 19:12
        | ((((insn >> 20) & 1) as i32) << 11)        // bit 11
        | ((((insn >> 21) & 0x3FF) as i32) << 1); // bits 10:1
    v as i64
}

// =============================================================================
// Opcode constants (bits 6:2 of opcode field, RISC-V ISA spec §2.2 Table 24.1)
// =============================================================================

pub const OP_LOAD: u32 = 0x03;
pub const OP_LOAD_FP: u32 = 0x07;
pub const OP_MISC_MEM: u32 = 0x0F; // FENCE
pub const OP_OP_IMM: u32 = 0x13;
pub const OP_AUIPC: u32 = 0x17;
pub const OP_OP_IMM_32: u32 = 0x1B;
pub const OP_STORE: u32 = 0x23;
pub const OP_STORE_FP: u32 = 0x27;
pub const OP_AMO: u32 = 0x2F;
pub const OP_OP: u32 = 0x33;
pub const OP_LUI: u32 = 0x37;
pub const OP_OP_32: u32 = 0x3B;
pub const OP_FMADD: u32 = 0x43;
pub const OP_FMSUB: u32 = 0x47;
pub const OP_FNMSUB: u32 = 0x4B;
pub const OP_FNMADD: u32 = 0x4F;
pub const OP_OP_FP: u32 = 0x53;
pub const OP_BRANCH: u32 = 0x63;
pub const OP_JALR: u32 = 0x67;
pub const OP_JAL: u32 = 0x6F;
pub const OP_SYSTEM: u32 = 0x73;

// =============================================================================
// RVC (Compressed) instruction expansion — RISC-V ISA spec §16 (C extension)
// =============================================================================

/// Check if a 16-bit halfword is a compressed instruction (bits 1:0 != 0b11).
#[inline(always)]
pub fn is_compressed(halfword: u16) -> bool {
    (halfword & 3) != 3
}

/// Expand a 16-bit compressed instruction to its 32-bit equivalent.
/// Returns 0 if the instruction is not recognized or not expandable.
///
/// Reference: RISC-V ISA spec §16 (C extension), Table 16.1-16.6
pub fn expand_compressed(insn: u16) -> u32 {
    let op = insn & 0x03;
    let f3 = (insn >> 13) & 0x07;

    match (op, f3) {
        // === Quadrant 0 (op = 0b00) ===
        (0, 0) => expand_c_addi4spn(insn),
        (0, 1) => expand_c_fld(insn),
        (0, 2) => expand_c_lw(insn),
        (0, 3) => expand_c_ld(insn),
        (0, 5) => expand_c_fsd(insn),
        (0, 6) => expand_c_sw(insn),
        (0, 7) => expand_c_sd(insn),

        // === Quadrant 1 (op = 0b01) ===
        (1, 0) => expand_c_addi(insn),
        (1, 1) => expand_c_addiw(insn),
        (1, 2) => expand_c_li(insn),
        (1, 3) => expand_c_lui_addi16sp(insn),
        (1, 4) => expand_c_alu(insn),
        (1, 5) => expand_c_j(insn),
        (1, 6) => expand_c_beqz(insn),
        (1, 7) => expand_c_bnez(insn),

        // === Quadrant 2 (op = 0b10) ===
        (2, 0) => expand_c_slli(insn),
        (2, 1) => expand_c_fldsp(insn),
        (2, 2) => expand_c_lwsp(insn),
        (2, 3) => expand_c_ldsp(insn),
        (2, 4) => expand_c_jr_mv_jalr_add(insn),
        (2, 5) => expand_c_fsdsp(insn),
        (2, 6) => expand_c_swsp(insn),
        (2, 7) => expand_c_sdsp(insn),

        _ => 0,
    }
}

// --- RVC helper: compressed register (3 bits → x8..x15) ---
#[inline(always)]
fn creg(bits: u16) -> u32 {
    (bits as u32 & 7) + 8
}

// --- Quadrant 0 expansions ---

fn expand_c_addi4spn(insn: u16) -> u32 {
    // C.ADDI4SPN: addi rd', x2, nzuimm
    let nzuimm = (((insn >> 5) & 1) << 3)
        | (((insn >> 6) & 1) << 2)
        | (((insn >> 7) & 0x0F) << 6)
        | (((insn >> 11) & 0x03) << 4);
    if nzuimm == 0 {
        return 0;
    } // reserved
    let rd = creg((insn >> 2) & 7);
    encode_i(OP_OP_IMM, rd, 0, 2, nzuimm as u32) // addi rd', x2, nzuimm
}

fn expand_c_fld(insn: u16) -> u32 {
    // C.FLD: fld rd', offset(rs1')
    let off = (((insn >> 5) & 3) << 6) | (((insn >> 10) & 7) << 3);
    let rs1 = creg((insn >> 7) & 7);
    let rd = creg((insn >> 2) & 7);
    encode_i(OP_LOAD_FP, rd, 3, rs1, off as u32) // fld, funct3=3 (D)
}

fn expand_c_lw(insn: u16) -> u32 {
    // C.LW: lw rd', offset(rs1')
    let off = (((insn >> 5) & 1) << 6) | (((insn >> 6) & 1) << 2) | (((insn >> 10) & 7) << 3);
    let rs1 = creg((insn >> 7) & 7);
    let rd = creg((insn >> 2) & 7);
    encode_i(OP_LOAD, rd, 2, rs1, off as u32) // lw
}

fn expand_c_ld(insn: u16) -> u32 {
    // C.LD: ld rd', offset(rs1')
    let off = (((insn >> 5) & 3) << 6) | (((insn >> 10) & 7) << 3);
    let rs1 = creg((insn >> 7) & 7);
    let rd = creg((insn >> 2) & 7);
    encode_i(OP_LOAD, rd, 3, rs1, off as u32) // ld
}

fn expand_c_fsd(insn: u16) -> u32 {
    let off = (((insn >> 5) & 3) << 6) | (((insn >> 10) & 7) << 3);
    let rs1 = creg((insn >> 7) & 7);
    let rs2 = creg((insn >> 2) & 7);
    encode_s(OP_STORE_FP, 3, rs1, rs2, off as u32)
}

fn expand_c_sw(insn: u16) -> u32 {
    let off = (((insn >> 5) & 1) << 6) | (((insn >> 6) & 1) << 2) | (((insn >> 10) & 7) << 3);
    let rs1 = creg((insn >> 7) & 7);
    let rs2 = creg((insn >> 2) & 7);
    encode_s(OP_STORE, 2, rs1, rs2, off as u32)
}

fn expand_c_sd(insn: u16) -> u32 {
    let off = (((insn >> 5) & 3) << 6) | (((insn >> 10) & 7) << 3);
    let rs1 = creg((insn >> 7) & 7);
    let rs2 = creg((insn >> 2) & 7);
    encode_s(OP_STORE, 3, rs1, rs2, off as u32)
}

// --- Quadrant 1 expansions ---

fn expand_c_addi(insn: u16) -> u32 {
    // C.ADDI / C.NOP: addi rd, rd, nzimm
    let rd = ((insn >> 7) & 0x1F) as u32;
    let imm = c_imm6(insn);
    encode_i(OP_OP_IMM, rd, 0, rd, imm)
}

fn expand_c_addiw(insn: u16) -> u32 {
    // C.ADDIW: addiw rd, rd, imm
    let rd = ((insn >> 7) & 0x1F) as u32;
    if rd == 0 {
        return 0;
    } // reserved
    let imm = c_imm6(insn);
    encode_i(OP_OP_IMM_32, rd, 0, rd, imm)
}

fn expand_c_li(insn: u16) -> u32 {
    // C.LI: addi rd, x0, imm
    let rd = ((insn >> 7) & 0x1F) as u32;
    let imm = c_imm6(insn);
    encode_i(OP_OP_IMM, rd, 0, 0, imm)
}

fn expand_c_lui_addi16sp(insn: u16) -> u32 {
    let rd = ((insn >> 7) & 0x1F) as u32;
    if rd == 2 {
        // C.ADDI16SP: addi x2, x2, nzimm
        let nzimm = (((insn >> 2) & 1) << 5)
            | (((insn >> 3) & 3) << 7)
            | (((insn >> 5) & 1) << 6)
            | (((insn >> 6) & 1) << 4)
            | (((insn >> 12) & 1) << 9);
        let nzimm = sign_extend(nzimm as u32, 10) as u32;
        if nzimm == 0 {
            return 0;
        }
        encode_i(OP_OP_IMM, 2, 0, 2, nzimm)
    } else {
        // C.LUI: lui rd, nzimm
        let nzimm = (((insn >> 2) & 0x1F) as u32) | ((((insn >> 12) & 1) as u32) << 5);
        let nzimm = sign_extend(nzimm, 6);
        if nzimm == 0 {
            return 0;
        }
        // LUI encodes imm[31:12], so shift left 12
        ((nzimm as u32) << 12) | (rd << 7) | OP_LUI
    }
}

fn expand_c_alu(insn: u16) -> u32 {
    let f2 = (insn >> 10) & 3;
    let rd = creg((insn >> 7) & 7);
    match f2 {
        0 => {
            // C.SRLI
            let shamt = c_shamt(insn);
            encode_i(OP_OP_IMM, rd, 5, rd, shamt)
        }
        1 => {
            // C.SRAI
            let shamt = c_shamt(insn) | (1 << 10); // funct7 bit
            encode_i(OP_OP_IMM, rd, 5, rd, shamt)
        }
        2 => {
            // C.ANDI
            let imm = c_imm6(insn);
            encode_i(OP_OP_IMM, rd, 7, rd, imm)
        }
        3 => {
            let rs2 = creg((insn >> 2) & 7);
            let f1 = (insn >> 12) & 1;
            let f2b = (insn >> 5) & 3;
            match (f1, f2b) {
                (0, 0) => encode_r(OP_OP, rd, 0, rd, rs2, 0x20), // C.SUB
                (0, 1) => encode_r(OP_OP, rd, 4, rd, rs2, 0),    // C.XOR
                (0, 2) => encode_r(OP_OP, rd, 6, rd, rs2, 0),    // C.OR
                (0, 3) => encode_r(OP_OP, rd, 7, rd, rs2, 0),    // C.AND
                (1, 0) => encode_r(OP_OP_32, rd, 0, rd, rs2, 0x20), // C.SUBW
                (1, 1) => encode_r(OP_OP_32, rd, 0, rd, rs2, 0), // C.ADDW
                _ => 0,
            }
        }
        _ => 0,
    }
}

fn expand_c_j(insn: u16) -> u32 {
    // C.J: jal x0, offset
    let off = c_j_offset(insn);
    encode_j(OP_JAL, 0, off)
}

fn expand_c_beqz(insn: u16) -> u32 {
    let rs1 = creg((insn >> 7) & 7);
    let off = c_b_offset(insn);
    encode_b(OP_BRANCH, 0, rs1, 0, off)
}

fn expand_c_bnez(insn: u16) -> u32 {
    let rs1 = creg((insn >> 7) & 7);
    let off = c_b_offset(insn);
    encode_b(OP_BRANCH, 1, rs1, 0, off)
}

// --- Quadrant 2 expansions ---

fn expand_c_slli(insn: u16) -> u32 {
    let rd = ((insn >> 7) & 0x1F) as u32;
    let shamt = c_shamt(insn);
    encode_i(OP_OP_IMM, rd, 1, rd, shamt)
}

fn expand_c_fldsp(insn: u16) -> u32 {
    let rd = ((insn >> 7) & 0x1F) as u32;
    let off = (((insn >> 2) & 7) << 6) | (((insn >> 5) & 3) << 3) | (((insn >> 12) & 1) << 5);
    encode_i(OP_LOAD_FP, rd, 3, 2, off as u32) // fld rd, off(x2)
}

fn expand_c_lwsp(insn: u16) -> u32 {
    let rd = ((insn >> 7) & 0x1F) as u32;
    if rd == 0 {
        return 0;
    } // reserved
    // CI format: bit12=offset[5], bits6:4=offset[4:2], bits3:2=offset[7:6]
    let off = (((insn >> 4) & 7) << 2) | (((insn >> 2) & 3) << 6) | (((insn >> 12) & 1) << 5);
    encode_i(OP_LOAD, rd, 2, 2, off as u32) // lw rd, off(x2)
}

fn expand_c_ldsp(insn: u16) -> u32 {
    let rd = ((insn >> 7) & 0x1F) as u32;
    if rd == 0 {
        return 0;
    }
    let off = (((insn >> 2) & 7) << 6) | (((insn >> 5) & 3) << 3) | (((insn >> 12) & 1) << 5);
    encode_i(OP_LOAD, rd, 3, 2, off as u32) // ld rd, off(x2)
}

fn expand_c_jr_mv_jalr_add(insn: u16) -> u32 {
    let rd = ((insn >> 7) & 0x1F) as u32;
    let rs2 = ((insn >> 2) & 0x1F) as u32;
    let bit12 = (insn >> 12) & 1;
    if bit12 == 0 {
        if rs2 == 0 {
            // C.JR: jalr x0, 0(rs1)
            if rd == 0 {
                return 0;
            }
            encode_i(OP_JALR, 0, 0, rd, 0)
        } else {
            // C.MV: add rd, x0, rs2
            encode_r(OP_OP, rd, 0, 0, rs2, 0)
        }
    } else {
        if rs2 == 0 {
            if rd == 0 {
                // C.EBREAK: ebreak
                0x00100073
            } else {
                // C.JALR: jalr x1, 0(rs1)
                encode_i(OP_JALR, 1, 0, rd, 0)
            }
        } else {
            // C.ADD: add rd, rd, rs2
            encode_r(OP_OP, rd, 0, rd, rs2, 0)
        }
    }
}

fn expand_c_fsdsp(insn: u16) -> u32 {
    let rs2 = ((insn >> 2) & 0x1F) as u32;
    // CSS format: bits12:10=offset[5:3], bits9:7=offset[8:6]
    let off = (((insn >> 10) & 7) << 3) | (((insn >> 7) & 7) << 6);
    encode_s(OP_STORE_FP, 3, 2, rs2, off as u32)
}

fn expand_c_swsp(insn: u16) -> u32 {
    let rs2 = ((insn >> 2) & 0x1F) as u32;
    // CSS format: bits12:9=offset[5:2], bits8:7=offset[7:6]
    let off = (((insn >> 9) & 0xF) << 2) | (((insn >> 7) & 3) << 6);
    encode_s(OP_STORE, 2, 2, rs2, off as u32)
}

fn expand_c_sdsp(insn: u16) -> u32 {
    let rs2 = ((insn >> 2) & 0x1F) as u32;
    // CSS format: bits12:10=offset[5:3], bits9:7=offset[8:6]
    let off = (((insn >> 10) & 7) << 3) | (((insn >> 7) & 7) << 6);
    encode_s(OP_STORE, 3, 2, rs2, off as u32)
}

// =============================================================================
// RVC immediate helpers
// =============================================================================

/// 6-bit sign-extended immediate (C.ADDI, C.LI, C.ANDI)
fn c_imm6(insn: u16) -> u32 {
    let v = ((insn >> 2) & 0x1F) | (((insn >> 12) & 1) << 5);
    sign_extend(v as u32, 6) as u32
}

/// 6-bit shift amount (C.SLLI, C.SRLI, C.SRAI)
fn c_shamt(insn: u16) -> u32 {
    (((insn >> 2) & 0x1F) | (((insn >> 12) & 1) << 5)) as u32
}

/// C.J offset (11-bit sign-extended)
fn c_j_offset(insn: u16) -> u32 {
    let v = (((insn >> 2) & 1) << 5)
        | (((insn >> 3) & 7) << 1)
        | (((insn >> 6) & 1) << 7)
        | (((insn >> 7) & 1) << 6)
        | (((insn >> 8) & 1) << 10)
        | (((insn >> 9) & 3) << 8)
        | (((insn >> 11) & 1) << 4)
        | (((insn >> 12) & 1) << 11);
    sign_extend(v as u32, 12) as u32
}

/// C.BEQZ/C.BNEZ offset (8-bit sign-extended)
fn c_b_offset(insn: u16) -> u32 {
    let v = (((insn >> 2) & 1) << 5)
        | (((insn >> 3) & 3) << 1)
        | (((insn >> 5) & 3) << 6)
        | (((insn >> 10) & 3) << 3)
        | (((insn >> 12) & 1) << 8);
    sign_extend(v as u32, 9) as u32
}

fn sign_extend(val: u32, bits: u32) -> i32 {
    let shift = 32 - bits;
    ((val << shift) as i32) >> shift
}

// =============================================================================
// 32-bit instruction encoding helpers (for RVC expansion)
// =============================================================================

fn encode_i(opcode: u32, rd: u32, funct3: u32, rs1: u32, imm: u32) -> u32 {
    (imm << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
}

fn encode_s(opcode: u32, funct3: u32, rs1: u32, rs2: u32, imm: u32) -> u32 {
    let imm11_5 = (imm >> 5) & 0x7F;
    let imm4_0 = imm & 0x1F;
    (imm11_5 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (imm4_0 << 7) | opcode
}

fn encode_r(opcode: u32, rd: u32, funct3: u32, rs1: u32, rs2: u32, funct7: u32) -> u32 {
    (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
}

fn encode_b(opcode: u32, funct3: u32, rs1: u32, rs2: u32, imm: u32) -> u32 {
    let bit12 = (imm >> 12) & 1;
    let bit11 = (imm >> 11) & 1;
    let bits10_5 = (imm >> 5) & 0x3F;
    let bits4_1 = (imm >> 1) & 0xF;
    (bit12 << 31)
        | (bits10_5 << 25)
        | (rs2 << 20)
        | (rs1 << 15)
        | (funct3 << 12)
        | (bits4_1 << 8)
        | (bit11 << 7)
        | opcode
}

fn encode_j(opcode: u32, rd: u32, imm: u32) -> u32 {
    let bit20 = (imm >> 20) & 1;
    let bits10_1 = (imm >> 1) & 0x3FF;
    let bit11 = (imm >> 11) & 1;
    let bits19_12 = (imm >> 12) & 0xFF;
    (bit20 << 31) | (bits10_1 << 21) | (bit11 << 20) | (bits19_12 << 12) | (rd << 7) | opcode
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn i_type_immediate() {
        // addi x1, x0, 42 → imm=42, rs1=0, rd=1, funct3=0, opcode=0x13
        let insn = encode_i(OP_OP_IMM, 1, 0, 0, 42);
        assert_eq!(imm_i(insn), 42);
        assert_eq!(rd(insn), 1);
        assert_eq!(rs1(insn), 0);
        assert_eq!(funct3(insn), 0);
        assert_eq!(opcode(insn), OP_OP_IMM);
    }

    #[test]
    fn i_type_negative() {
        // addi x1, x0, -1
        let insn = encode_i(OP_OP_IMM, 1, 0, 0, -1i32 as u32);
        assert_eq!(imm_i(insn), -1);
    }

    #[test]
    fn s_type_immediate() {
        // sw x2, 8(x1) → imm=8, rs1=1, rs2=2
        let insn = encode_s(OP_STORE, 2, 1, 2, 8);
        assert_eq!(imm_s(insn), 8);
        assert_eq!(rs1(insn), 1);
        assert_eq!(rs2(insn), 2);
    }

    #[test]
    fn b_type_immediate() {
        // beq x1, x2, +16
        let insn = encode_b(OP_BRANCH, 0, 1, 2, 16);
        assert_eq!(imm_b(insn), 16);
    }

    #[test]
    fn b_type_negative() {
        // beq x1, x2, -8
        let insn = encode_b(OP_BRANCH, 0, 1, 2, -8i32 as u32);
        assert_eq!(imm_b(insn), -8);
    }

    #[test]
    fn u_type_immediate() {
        // lui x1, 0x12345 → imm = 0x12345000
        let insn = 0x1234_50B7; // lui x1, 0x12345
        assert_eq!(imm_u(insn), 0x12345000);
    }

    #[test]
    fn j_type_round_trip() {
        let insn = encode_j(OP_JAL, 1, 100);
        assert_eq!(imm_j(insn), 100);
        assert_eq!(rd(insn), 1);
    }

    #[test]
    fn compressed_detection() {
        assert!(is_compressed(0x0001)); // bits 1:0 = 01
        assert!(is_compressed(0x0002)); // bits 1:0 = 10
        assert!(!is_compressed(0x0003)); // bits 1:0 = 11 → 32-bit
        assert!(!is_compressed(0xFFFF)); // bits 1:0 = 11
    }

    #[test]
    fn c_addi_expansion() {
        // C.ADDI x15, 1 → addi x15, x15, 1
        // op=01, funct3=000, rd=x15 (01111), imm=1
        let c_insn: u16 = 0x0785; // C.ADDI x15, 1
        let expanded = expand_compressed(c_insn);
        assert_ne!(expanded, 0);
        assert_eq!(opcode(expanded), OP_OP_IMM);
        assert_eq!(funct3(expanded), 0);
        assert_eq!(rd(expanded), 15);
        assert_eq!(rs1(expanded), 15);
    }

    #[test]
    fn c_li_expansion() {
        // C.LI x10, 5 → addi x10, x0, 5
        let c_insn: u16 = 0x4515; // C.LI x10, 5
        let expanded = expand_compressed(c_insn);
        assert_ne!(expanded, 0);
        assert_eq!(opcode(expanded), OP_OP_IMM);
        assert_eq!(rd(expanded), 10);
        assert_eq!(rs1(expanded), 0);
        assert_eq!(imm_i(expanded), 5);
    }

    #[test]
    fn c_mv_expansion() {
        // C.MV x10, x11 → add x10, x0, x11
        let c_insn: u16 = 0x852E; // C.MV x10, x11
        let expanded = expand_compressed(c_insn);
        assert_ne!(expanded, 0);
        assert_eq!(opcode(expanded), OP_OP);
        assert_eq!(rd(expanded), 10);
    }
}
