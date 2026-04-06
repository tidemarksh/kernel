//! Control and status register helpers used by the main exec loop.
//!
//! Reference: RISC-V ISA spec V20191213
//!   (https://github.com/riscv/riscv-isa-manual/releases/tag/Ratified-IMAFDQC)
//!   §9 (Zicsr), §11.2 (fcsr/fflags/frm)
//!
//! The emulator only exposes the CSR subset needed by current userland.

use super::decode;

// =============================================================================
// CSR execution
// =============================================================================

/// Execute CSR instructions for fcsr (0x003), fflags (0x001), and frm (0x002).
/// Other CSRs currently read as zero and ignore writes.
#[inline(always)]
pub(super) fn exec_csr(x: &mut [u64; 32], raw: u32, pc: &mut u64, step: u64, fcsr: &mut u32) {
    let rd = decode::rd(raw);
    let rs1 = decode::rs1(raw);
    let f3 = decode::funct3(raw);
    let csr = (raw >> 20) & 0xFFF;

    let old_val: u64 = match csr {
        0x001 => (*fcsr & 0x1F) as u64,
        0x002 => ((*fcsr >> 5) & 0x7) as u64,
        0x003 => (*fcsr & 0xFF) as u64,
        _ => 0,
    };

    let src = if f3 >= 5 { rs1 as u64 } else { x[rs1] };
    let new_val = match f3 {
        1 | 5 => src,
        2 | 6 => old_val | src,
        3 | 7 => old_val & !src,
        _ => old_val,
    };

    let do_write = match f3 {
        1 | 5 => true,
        2 | 3 | 6 | 7 => rs1 != 0,
        _ => false,
    };

    if do_write {
        match csr {
            0x001 => *fcsr = (*fcsr & !0x1F) | (new_val as u32 & 0x1F),
            0x002 => *fcsr = (*fcsr & !0xE0) | ((new_val as u32 & 0x7) << 5),
            0x003 => *fcsr = new_val as u32 & 0xFF,
            _ => {}
        }
    }

    if rd != 0 {
        x[rd] = old_val;
    }
    *pc += step;
}
