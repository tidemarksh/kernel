//! Floating-point helpers and instruction executors for RV64F/RV64D.
//!
//! Reference: RISC-V ISA spec V20191213
//!   (https://github.com/riscv/riscv-isa-manual/releases/tag/Ratified-IMAFDQC)
//!   §11 (F), §12 (D)
//!
//! This module centralizes fflags updates, NaN-boxing rules, conversions,
//! and the floating-point instruction helpers used by the main exec loop.

use super::decode;
use crate::guest_mem;

// =============================================================================
// fflags helpers and NaN handling
// =============================================================================

// fcsr.fflags exception bits (RISC-V ISA spec §11.2)
const NV: u32 = 1 << 4; // Invalid Operation
const DZ: u32 = 1 << 3; // Divide by Zero
const OF: u32 = 1 << 2; // Overflow
const UF: u32 = 1 << 1; // Underflow
const NX: u32 = 1 << 0; // Inexact

#[inline(always)]
fn set_flags(fcsr: &mut u32, flags: u32) {
    *fcsr |= flags;
}

/// Detect signaling NaN for f64 (exponent all-1, fraction nonzero, quiet bit clear).
#[inline(always)]
fn is_snan_f64(v: f64) -> bool {
    let b = v.to_bits();
    let exp = (b >> 52) & 0x7FF;
    let frac = b & 0x000F_FFFF_FFFF_FFFF;
    exp == 0x7FF && frac != 0 && (frac & (1 << 51)) == 0
}

/// Detect signaling NaN for f32 (exponent all-1, fraction nonzero, quiet bit clear).
#[inline(always)]
fn is_snan_f32(v: f32) -> bool {
    let b = v.to_bits();
    let exp = (b >> 23) & 0xFF;
    let frac = b & 0x007F_FFFF;
    exp == 0xFF && frac != 0 && (frac & (1 << 22)) == 0
}

/// Classify fflags for f64: sNaN→NV, overflow→OF|NX, subnormal result→UF|NX.
#[inline(always)]
fn classify_flags_f64(a: f64, b: f64, result: f64) -> u32 {
    let mut flags = 0u32;
    if is_snan_f64(a) || is_snan_f64(b) {
        flags |= NV;
    }
    if result.is_nan() {
        if a.is_nan() || b.is_nan() {
            return flags | NV;
        }
        return flags | NV;
    }
    if result.is_infinite() && !a.is_infinite() && !b.is_infinite() {
        flags |= OF | NX;
    }
    let rb = result.to_bits();
    let exp = (rb >> 52) & 0x7FF;
    if exp == 0 && (rb & 0x000F_FFFF_FFFF_FFFF) != 0 {
        flags |= UF | NX;
    }
    flags
}

/// Classify fflags for f32: sNaN→NV, overflow→OF|NX, subnormal result→UF|NX.
#[inline(always)]
fn classify_flags_f32(a: f32, b: f32, result: f32) -> u32 {
    let mut flags = 0u32;
    if is_snan_f32(a) || is_snan_f32(b) {
        flags |= NV;
    }
    if result.is_nan() {
        if a.is_nan() || b.is_nan() {
            return flags | NV;
        }
        return flags | NV;
    }
    if result.is_infinite() && !a.is_infinite() && !b.is_infinite() {
        flags |= OF | NX;
    }
    let rb = result.to_bits();
    let exp = (rb >> 23) & 0xFF;
    if exp == 0 && (rb & 0x007F_FFFF) != 0 {
        flags |= UF | NX;
    }
    flags
}

/// Check whether f64 addition was inexact.
#[inline(always)]
fn add_flags_f64(a: f64, b: f64, result: f64) -> u32 {
    let mut flags = classify_flags_f64(a, b, result);
    if !result.is_nan() && !result.is_infinite() && (result - a != b || result - b != a) {
        flags |= NX;
    }
    flags
}

/// Check whether f32 addition was inexact.
#[inline(always)]
fn add_flags_f32(a: f32, b: f32, result: f32) -> u32 {
    let mut flags = classify_flags_f32(a, b, result);
    if !result.is_nan() && !result.is_infinite() {
        let wide = (a as f64) + (b as f64);
        if wide != result as f64 {
            flags |= NX;
        }
    }
    flags
}

/// Check whether f64 multiplication was inexact.
#[inline(always)]
fn mul_flags_f64(a: f64, b: f64, result: f64) -> u32 {
    let mut flags = classify_flags_f64(a, b, result);
    if !result.is_nan() && !result.is_infinite() && libm::fma(a, b, -result) != 0.0 {
        flags |= NX;
    }
    if (a.is_infinite() && b == 0.0) || (a == 0.0 && b.is_infinite()) {
        flags |= NV;
    }
    flags
}

/// Check whether f32 multiplication was inexact.
#[inline(always)]
fn mul_flags_f32(a: f32, b: f32, result: f32) -> u32 {
    let mut flags = classify_flags_f32(a, b, result);
    if !result.is_nan() && !result.is_infinite() {
        let wide = (a as f64) * (b as f64);
        if wide != result as f64 {
            flags |= NX;
        }
    }
    if (a.is_infinite() && b == 0.0) || (a == 0.0 && b.is_infinite()) {
        flags |= NV;
    }
    flags
}

/// Check whether f64 division was inexact.
#[inline(always)]
fn div_flags_f64(a: f64, b: f64, result: f64) -> u32 {
    let mut flags = classify_flags_f64(a, b, result);
    if !a.is_nan() && !b.is_nan() && b == 0.0 && a != 0.0 {
        flags |= DZ;
    }
    if !a.is_nan() && !b.is_nan() && b == 0.0 && a == 0.0 {
        flags |= NV;
    }
    if !result.is_nan() && !result.is_infinite() && b != 0.0 && libm::fma(result, b, -a) != 0.0 {
        flags |= NX;
    }
    flags
}

/// Check whether f32 division was inexact.
#[inline(always)]
fn div_flags_f32(a: f32, b: f32, result: f32) -> u32 {
    let mut flags = classify_flags_f32(a, b, result);
    if !a.is_nan() && !b.is_nan() && b == 0.0 && a != 0.0 {
        flags |= DZ;
    }
    if !a.is_nan() && !b.is_nan() && b == 0.0 && a == 0.0 {
        flags |= NV;
    }
    if !result.is_nan() && !result.is_infinite() && b != 0.0 {
        let wide = (a as f64) / (b as f64);
        if wide != result as f64 {
            flags |= NX;
        }
    }
    flags
}

/// Compute fflags for f64 sqrt.
#[inline(always)]
fn sqrt_flags_f64(a: f64, result: f64) -> u32 {
    let mut flags = 0u32;
    if is_snan_f64(a) {
        flags |= NV;
    }
    if a < 0.0 {
        flags |= NV;
    }
    if !result.is_nan() && !result.is_infinite() && libm::fma(result, result, -a) != 0.0 {
        flags |= NX;
    }
    flags
}

/// Compute fflags for f32 sqrt.
#[inline(always)]
fn sqrt_flags_f32(a: f32, result: f32) -> u32 {
    let mut flags = 0u32;
    if is_snan_f32(a) {
        flags |= NV;
    }
    if a < 0.0 {
        flags |= NV;
    }
    if !result.is_nan() && !result.is_infinite() {
        let wide = libm::sqrt(a as f64);
        if wide != result as f64 {
            flags |= NX;
        }
    }
    flags
}

/// Canonical NaN constants (RISC-V ISA spec §11.3).
const CANONICAL_NAN_F64: u64 = 0x7FF8_0000_0000_0000;
const CANONICAL_NAN_F32: u32 = 0x7FC0_0000;

/// Canonicalize f64 NaN results.
#[inline(always)]
fn canon_f64(v: f64) -> f64 {
    if v.is_nan() {
        f64::from_bits(CANONICAL_NAN_F64)
    } else {
        v
    }
}

/// Canonicalize f32 NaN results.
#[inline(always)]
fn canon_f32(v: f32) -> f32 {
    if v.is_nan() {
        f32::from_bits(CANONICAL_NAN_F32)
    } else {
        v
    }
}

/// NaN-box a single-precision value for storage in an f register (FLEN=64).
#[inline(always)]
fn box_f32(val: f32) -> u64 {
    0xFFFF_FFFF_0000_0000 | (val.to_bits() as u64)
}

/// Unbox a single-precision value from an f register, returning canonical NaN on invalid boxing.
#[inline(always)]
fn unbox_f32(bits: u64) -> f32 {
    if (bits & 0xFFFF_FFFF_0000_0000) == 0xFFFF_FFFF_0000_0000 {
        f32::from_bits(bits as u32)
    } else {
        f32::from_bits(0x7FC0_0000)
    }
}

// =============================================================================
// FMIN/FMAX, FCLASS, and FCVT helpers
// =============================================================================

/// IEEE 754-201x minimumNumber for f64.
#[inline(always)]
fn fmin_f64(a: f64, b: f64) -> f64 {
    if a.is_nan() && b.is_nan() {
        return f64::from_bits(0x7FF8_0000_0000_0000);
    }
    if a.is_nan() {
        return b;
    }
    if b.is_nan() {
        return a;
    }
    if a.to_bits() == 0x8000_0000_0000_0000 && b.to_bits() == 0 {
        return a;
    }
    if b.to_bits() == 0x8000_0000_0000_0000 && a.to_bits() == 0 {
        return b;
    }
    if a < b { a } else { b }
}

/// IEEE 754-201x maximumNumber for f64.
#[inline(always)]
fn fmax_f64(a: f64, b: f64) -> f64 {
    if a.is_nan() && b.is_nan() {
        return f64::from_bits(0x7FF8_0000_0000_0000);
    }
    if a.is_nan() {
        return b;
    }
    if b.is_nan() {
        return a;
    }
    if a.to_bits() == 0x8000_0000_0000_0000 && b.to_bits() == 0 {
        return b;
    }
    if b.to_bits() == 0x8000_0000_0000_0000 && a.to_bits() == 0 {
        return a;
    }
    if a > b { a } else { b }
}

/// IEEE 754-201x minimumNumber for f32.
#[inline(always)]
fn fmin_f32(a: f32, b: f32) -> f32 {
    if a.is_nan() && b.is_nan() {
        return f32::from_bits(0x7FC0_0000);
    }
    if a.is_nan() {
        return b;
    }
    if b.is_nan() {
        return a;
    }
    if a.to_bits() == 0x8000_0000 && b.to_bits() == 0 {
        return a;
    }
    if b.to_bits() == 0x8000_0000 && a.to_bits() == 0 {
        return b;
    }
    if a < b { a } else { b }
}

/// IEEE 754-201x maximumNumber for f32.
#[inline(always)]
fn fmax_f32(a: f32, b: f32) -> f32 {
    if a.is_nan() && b.is_nan() {
        return f32::from_bits(0x7FC0_0000);
    }
    if a.is_nan() {
        return b;
    }
    if b.is_nan() {
        return a;
    }
    if a.to_bits() == 0x8000_0000 && b.to_bits() == 0 {
        return b;
    }
    if b.to_bits() == 0x8000_0000 && a.to_bits() == 0 {
        return a;
    }
    if a > b { a } else { b }
}

/// Classify a double-precision value into the RISC-V 10-bit FCLASS mask.
fn fclass_f64(bits: u64) -> u64 {
    let sign = (bits >> 63) & 1;
    let exp = (bits >> 52) & 0x7FF;
    let frac = bits & 0x000F_FFFF_FFFF_FFFF;
    if exp == 0x7FF {
        if frac == 0 {
            if sign != 0 { 1 << 0 } else { 1 << 7 }
        } else if frac & (1 << 51) != 0 {
            1 << 9
        } else {
            1 << 8
        }
    } else if exp == 0 {
        if frac == 0 {
            if sign != 0 { 1 << 3 } else { 1 << 4 }
        } else if sign != 0 {
            1 << 2
        } else {
            1 << 5
        }
    } else if sign != 0 {
        1 << 1
    } else {
        1 << 6
    }
}

/// Classify a single-precision value into the RISC-V 10-bit FCLASS mask.
fn fclass_f32(bits: u32) -> u64 {
    let sign = (bits >> 31) & 1;
    let exp = (bits >> 23) & 0xFF;
    let frac = bits & 0x007F_FFFF;
    if exp == 0xFF {
        if frac == 0 {
            if sign != 0 { 1 << 0 } else { 1 << 7 }
        } else if frac & (1 << 22) != 0 {
            1 << 9
        } else {
            1 << 8
        }
    } else if exp == 0 {
        if frac == 0 {
            if sign != 0 { 1 << 3 } else { 1 << 4 }
        } else if sign != 0 {
            1 << 2
        } else {
            1 << 5
        }
    } else if sign != 0 {
        1 << 1
    } else {
        1 << 6
    }
}

/// Convert f64 to i32 with RISC-V NaN semantics (NaN → INT_MAX).
#[inline(always)]
fn fcvt_w_f64(v: f64) -> i32 {
    if v.is_nan() { i32::MAX } else { v as i32 }
}

/// Convert f64 to u32 with RISC-V NaN semantics (NaN → UINT_MAX).
#[inline(always)]
fn fcvt_wu_f64(v: f64) -> u32 {
    if v.is_nan() { u32::MAX } else { v as u32 }
}

/// Convert f64 to i64 with RISC-V NaN semantics (NaN → INT_MAX).
#[inline(always)]
fn fcvt_l_f64(v: f64) -> i64 {
    if v.is_nan() { i64::MAX } else { v as i64 }
}

/// Convert f64 to u64 with RISC-V NaN semantics (NaN → UINT_MAX).
#[inline(always)]
fn fcvt_lu_f64(v: f64) -> u64 {
    if v.is_nan() { u64::MAX } else { v as u64 }
}

/// Convert f32 to i32 with RISC-V NaN semantics (NaN → INT_MAX).
#[inline(always)]
fn fcvt_w_f32(v: f32) -> i32 {
    if v.is_nan() { i32::MAX } else { v as i32 }
}

/// Convert f32 to u32 with RISC-V NaN semantics (NaN → UINT_MAX).
#[inline(always)]
fn fcvt_wu_f32(v: f32) -> u32 {
    if v.is_nan() { u32::MAX } else { v as u32 }
}

/// Convert f32 to i64 with RISC-V NaN semantics (NaN → INT_MAX).
#[inline(always)]
fn fcvt_l_f32(v: f32) -> i64 {
    if v.is_nan() { i64::MAX } else { v as i64 }
}

/// Convert f32 to u64 with RISC-V NaN semantics (NaN → UINT_MAX).
#[inline(always)]
fn fcvt_lu_f32(v: f32) -> u64 {
    if v.is_nan() { u64::MAX } else { v as u64 }
}

// =============================================================================
// FP load/store and arithmetic executors
// =============================================================================

/// Execute LOAD-FP instructions (FLW/FLD).
#[inline(always)]
pub(super) unsafe fn exec_load_fp(
    f: &mut [u64; 32],
    x: &[u64; 32],
    raw: u32,
    base: u32,
    pc: &mut u64,
    step: u64,
) {
    let rd = decode::rd(raw);
    let rs1 = decode::rs1(raw);
    let addr = (x[rs1] as i64 + decode::imm_i(raw)) as u64;
    unsafe {
        match decode::funct3(raw) {
            2 => f[rd] = 0xFFFF_FFFF_0000_0000 | (guest_mem::read_u32_seqlock(base, addr) as u64),
            3 => f[rd] = guest_mem::read_u64_seqlock(base, addr),
            _ => {}
        }
    }
    *pc += step;
}

/// Execute STORE-FP instructions (FSW/FSD).
#[inline(always)]
pub(super) unsafe fn exec_store_fp(
    f: &[u64; 32],
    x: &[u64; 32],
    raw: u32,
    base: u32,
    pc: &mut u64,
    step: u64,
) {
    let rs1 = decode::rs1(raw);
    let rs2 = decode::rs2(raw);
    let addr = (x[rs1] as i64 + decode::imm_s(raw)) as u64;
    unsafe {
        match decode::funct3(raw) {
            2 => guest_mem::write_u32(base, addr, f[rs2] as u32),
            3 => guest_mem::write_u64(base, addr, f[rs2]),
            _ => {}
        }
    }
    *pc += step;
}

/// Execute OP-FP instructions for RV64F and RV64D.
#[inline(always)]
pub(super) unsafe fn exec_op_fp(
    x: &mut [u64; 32],
    f: &mut [u64; 32],
    raw: u32,
    pc: &mut u64,
    step: u64,
    fcsr: &mut u32,
) {
    let rd = decode::rd(raw);
    let rs1 = decode::rs1(raw);
    let rs2 = decode::rs2(raw);
    let f7 = decode::funct7(raw);
    let funct5 = f7 >> 2;
    let fmt = f7 & 3;
    let f3 = decode::funct3(raw);

    match (funct5, fmt) {
        (0x00, 1) => {
            let a = f64::from_bits(f[rs1]);
            let b = f64::from_bits(f[rs2]);
            let r = canon_f64(a + b);
            f[rd] = r.to_bits();
            set_flags(fcsr, add_flags_f64(a, b, r));
        }
        (0x01, 1) => {
            let a = f64::from_bits(f[rs1]);
            let b = f64::from_bits(f[rs2]);
            let r = canon_f64(a - b);
            f[rd] = r.to_bits();
            set_flags(fcsr, add_flags_f64(a, -b, r));
        }
        (0x02, 1) => {
            let a = f64::from_bits(f[rs1]);
            let b = f64::from_bits(f[rs2]);
            let r = canon_f64(a * b);
            f[rd] = r.to_bits();
            set_flags(fcsr, mul_flags_f64(a, b, r));
        }
        (0x03, 1) => {
            let a = f64::from_bits(f[rs1]);
            let b = f64::from_bits(f[rs2]);
            let r = canon_f64(a / b);
            f[rd] = r.to_bits();
            set_flags(fcsr, div_flags_f64(a, b, r));
        }
        (0x0B, 1) => {
            let a = f64::from_bits(f[rs1]);
            let r = canon_f64(libm::sqrt(a));
            f[rd] = r.to_bits();
            set_flags(fcsr, sqrt_flags_f64(a, r));
        }
        (0x04, 1) => {
            let a = f[rs1];
            let b = f[rs2];
            f[rd] = match f3 {
                0 => (a & 0x7FFF_FFFF_FFFF_FFFF) | (b & 0x8000_0000_0000_0000),
                1 => (a & 0x7FFF_FFFF_FFFF_FFFF) | (!b & 0x8000_0000_0000_0000),
                _ => a ^ (b & 0x8000_0000_0000_0000),
            };
        }
        (0x05, 1) => {
            let a = f64::from_bits(f[rs1]);
            let b = f64::from_bits(f[rs2]);
            f[rd] = match f3 {
                0 => fmin_f64(a, b).to_bits(),
                _ => fmax_f64(a, b).to_bits(),
            };
            if is_snan_f64(a) || is_snan_f64(b) {
                set_flags(fcsr, NV);
            }
        }
        (0x14, 1) => {
            let a = f64::from_bits(f[rs1]);
            let b = f64::from_bits(f[rs2]);
            let r = match f3 {
                2 => a == b,
                1 => a < b,
                0 => a <= b,
                _ => false,
            };
            if rd != 0 {
                x[rd] = r as u64;
            }
            match f3 {
                1 | 0 if a.is_nan() || b.is_nan() => set_flags(fcsr, NV),
                2 if is_snan_f64(a) || is_snan_f64(b) => set_flags(fcsr, NV),
                _ => {}
            }
        }
        (0x18, 1) => {
            let v = f64::from_bits(f[rs1]);
            let r = match rs2 {
                0 => fcvt_w_f64(v) as i64 as u64,
                1 => (fcvt_wu_f64(v) as i32 as i64) as u64,
                2 => fcvt_l_f64(v) as u64,
                3 => fcvt_lu_f64(v),
                _ => 0,
            };
            if rd != 0 {
                x[rd] = r;
            }
            let trunc = if v.is_nan() || v.is_infinite() {
                None
            } else {
                Some(v as i64)
            };
            let out_of_range = trunc.is_none()
                || match rs2 {
                    0 => trunc.unwrap() < i32::MIN as i64 || trunc.unwrap() > i32::MAX as i64,
                    1 => v < -1.0 + f64::EPSILON || v > u32::MAX as f64 + 1.0 - f64::EPSILON,
                    2 => v <= i64::MIN as f64 - 1.0 || v >= i64::MAX as f64 + 1.0,
                    3 => v < -1.0 + f64::EPSILON || v > u64::MAX as f64,
                    _ => false,
                };
            if out_of_range {
                set_flags(fcsr, NV);
            } else {
                let exact = match rs2 {
                    0 => v == r as i32 as f64,
                    1 => v == r as u32 as f64,
                    2 => v == r as i64 as f64,
                    3 => v == r as f64,
                    _ => true,
                };
                if !exact {
                    set_flags(fcsr, NX);
                }
            }
        }
        (0x1A, 1) => {
            f[rd] = match rs2 {
                0 => (x[rs1] as i32 as f64).to_bits(),
                1 => (x[rs1] as u32 as f64).to_bits(),
                2 => (x[rs1] as i64 as f64).to_bits(),
                3 => (x[rs1] as f64).to_bits(),
                _ => 0,
            };
        }
        (0x1C, 1) => match f3 {
            0 if rd != 0 => x[rd] = f[rs1],
            1 if rd != 0 => x[rd] = fclass_f64(f[rs1]),
            _ => {}
        },
        (0x1E, 1) => f[rd] = x[rs1],

        (0x00, 0) => {
            let a = unbox_f32(f[rs1]);
            let b = unbox_f32(f[rs2]);
            let r = canon_f32(a + b);
            f[rd] = box_f32(r);
            set_flags(fcsr, add_flags_f32(a, b, r));
        }
        (0x01, 0) => {
            let a = unbox_f32(f[rs1]);
            let b = unbox_f32(f[rs2]);
            let r = canon_f32(a - b);
            f[rd] = box_f32(r);
            set_flags(fcsr, add_flags_f32(a, -b, r));
        }
        (0x02, 0) => {
            let a = unbox_f32(f[rs1]);
            let b = unbox_f32(f[rs2]);
            let r = canon_f32(a * b);
            f[rd] = box_f32(r);
            set_flags(fcsr, mul_flags_f32(a, b, r));
        }
        (0x03, 0) => {
            let a = unbox_f32(f[rs1]);
            let b = unbox_f32(f[rs2]);
            let r = canon_f32(a / b);
            f[rd] = box_f32(r);
            set_flags(fcsr, div_flags_f32(a, b, r));
        }
        (0x0B, 0) => {
            let a = unbox_f32(f[rs1]);
            let r = canon_f32(libm::sqrtf(a));
            f[rd] = box_f32(r);
            set_flags(fcsr, sqrt_flags_f32(a, r));
        }
        (0x04, 0) => {
            let a = unbox_f32(f[rs1]).to_bits();
            let b = unbox_f32(f[rs2]).to_bits();
            let r = match f3 {
                0 => (a & 0x7FFF_FFFF) | (b & 0x8000_0000),
                1 => (a & 0x7FFF_FFFF) | (!b & 0x8000_0000),
                _ => a ^ (b & 0x8000_0000),
            };
            f[rd] = box_f32(f32::from_bits(r));
        }
        (0x05, 0) => {
            let a = unbox_f32(f[rs1]);
            let b = unbox_f32(f[rs2]);
            f[rd] = match f3 {
                0 => box_f32(fmin_f32(a, b)),
                _ => box_f32(fmax_f32(a, b)),
            };
            if is_snan_f32(a) || is_snan_f32(b) {
                set_flags(fcsr, NV);
            }
        }
        (0x14, 0) => {
            let a = unbox_f32(f[rs1]);
            let b = unbox_f32(f[rs2]);
            let r = match f3 {
                2 => a == b,
                1 => a < b,
                0 => a <= b,
                _ => false,
            };
            if rd != 0 {
                x[rd] = r as u64;
            }
            match f3 {
                1 | 0 if a.is_nan() || b.is_nan() => set_flags(fcsr, NV),
                2 if is_snan_f32(a) || is_snan_f32(b) => set_flags(fcsr, NV),
                _ => {}
            }
        }
        (0x18, 0) => {
            let v = unbox_f32(f[rs1]);
            let vd = v as f64;
            let r = match rs2 {
                0 => fcvt_w_f32(v) as i64 as u64,
                1 => (fcvt_wu_f32(v) as i32 as i64) as u64,
                2 => fcvt_l_f32(v) as u64,
                3 => fcvt_lu_f32(v),
                _ => 0,
            };
            if rd != 0 {
                x[rd] = r;
            }
            let trunc = if v.is_nan() || v.is_infinite() {
                None
            } else {
                Some(vd as i64)
            };
            let out_of_range = trunc.is_none()
                || match rs2 {
                    0 => trunc.unwrap() < i32::MIN as i64 || trunc.unwrap() > i32::MAX as i64,
                    1 => trunc.unwrap() < 0 || trunc.unwrap() > u32::MAX as i64,
                    2 => vd <= i64::MIN as f64 - 1.0 || vd >= i64::MAX as f64 + 1.0,
                    3 => vd < 0.0 && trunc.unwrap() < 0 || vd > u64::MAX as f64,
                    _ => false,
                };
            if out_of_range {
                set_flags(fcsr, NV);
            } else {
                let exact = match rs2 {
                    0 => vd == r as i32 as f64,
                    1 => vd == r as u32 as f64,
                    2 => vd == r as i64 as f64,
                    3 => vd == r as f64,
                    _ => true,
                };
                if !exact {
                    set_flags(fcsr, NX);
                }
            }
        }
        (0x1A, 0) => {
            f[rd] = match rs2 {
                0 => box_f32(x[rs1] as i32 as f32),
                1 => box_f32(x[rs1] as u32 as f32),
                2 => box_f32(x[rs1] as i64 as f32),
                3 => box_f32(x[rs1] as f32),
                _ => 0,
            };
        }
        (0x1C, 0) => match f3 {
            0 if rd != 0 => x[rd] = (f[rs1] as u32 as i32 as i64) as u64,
            1 if rd != 0 => x[rd] = fclass_f32(unbox_f32(f[rs1]).to_bits()),
            _ => {}
        },
        (0x1E, 0) => f[rd] = 0xFFFF_FFFF_0000_0000 | (x[rs1] as u32 as u64),

        (0x08, 0) => {
            let a = f64::from_bits(f[rs1]);
            let r = canon_f32(a as f32);
            f[rd] = box_f32(r);
            if is_snan_f64(a) {
                set_flags(fcsr, NV);
            } else if !a.is_nan() && !a.is_infinite() && (r as f64).to_bits() != a.to_bits() {
                set_flags(fcsr, NX);
            }
        }
        (0x08, 1) => {
            let a = unbox_f32(f[rs1]);
            let r = if a.is_nan() {
                f64::from_bits(CANONICAL_NAN_F64)
            } else {
                a as f64
            };
            f[rd] = r.to_bits();
            if is_snan_f32(a) {
                set_flags(fcsr, NV);
            }
        }

        _ => {}
    }
    *pc += step;
}

/// Execute fused multiply-add instructions (FMADD/FMSUB/FNMSUB/FNMADD).
#[inline(always)]
pub(super) unsafe fn exec_fma(
    f: &mut [u64; 32],
    raw: u32,
    opcode: u32,
    pc: &mut u64,
    step: u64,
    fcsr: &mut u32,
) {
    let rd = decode::rd(raw);
    let rs1 = decode::rs1(raw);
    let rs2 = decode::rs2(raw);
    let rs3 = decode::rs3(raw);
    let fmt = (raw >> 25) & 3;

    match fmt {
        0 => {
            let a = unbox_f32(f[rs1]);
            let b = unbox_f32(f[rs2]);
            let c = unbox_f32(f[rs3]);
            let r = canon_f32(match opcode {
                decode::OP_FMADD => libm::fmaf(a, b, c),
                decode::OP_FMSUB => libm::fmaf(a, b, -c),
                decode::OP_FNMSUB => libm::fmaf(-a, b, c),
                decode::OP_FNMADD => libm::fmaf(-a, b, -c),
                _ => 0.0,
            });
            f[rd] = box_f32(r);
            let mut fl = 0u32;
            if (a.is_infinite() && b == 0.0) || (a == 0.0 && b.is_infinite()) {
                fl |= NV;
            }
            if is_snan_f32(a) || is_snan_f32(b) || is_snan_f32(c) {
                fl |= NV;
            }
            if r.is_nan() && (a.is_nan() || b.is_nan() || c.is_nan()) {
                fl |= NV;
            }
            if r.is_infinite() && !a.is_infinite() && !b.is_infinite() && !c.is_infinite() {
                fl |= OF | NX;
            }
            if !r.is_nan() && !r.is_infinite() {
                let wide = match opcode {
                    decode::OP_FMADD => libm::fma(a as f64, b as f64, c as f64),
                    decode::OP_FMSUB => libm::fma(a as f64, b as f64, -(c as f64)),
                    decode::OP_FNMSUB => -libm::fma(a as f64, b as f64, -(c as f64)),
                    decode::OP_FNMADD => -libm::fma(a as f64, b as f64, c as f64),
                    _ => r as f64,
                };
                if wide != r as f64 {
                    fl |= NX;
                }
            }
            set_flags(fcsr, fl);
        }
        1 => {
            let a = f64::from_bits(f[rs1]);
            let b = f64::from_bits(f[rs2]);
            let c = f64::from_bits(f[rs3]);
            let r = canon_f64(match opcode {
                decode::OP_FMADD => libm::fma(a, b, c),
                decode::OP_FMSUB => libm::fma(a, b, -c),
                decode::OP_FNMSUB => libm::fma(-a, b, c),
                decode::OP_FNMADD => libm::fma(-a, b, -c),
                _ => 0.0,
            });
            f[rd] = r.to_bits();
            let mut fl = 0u32;
            if (a.is_infinite() && b == 0.0) || (a == 0.0 && b.is_infinite()) {
                fl |= NV;
            }
            if is_snan_f64(a) || is_snan_f64(b) || is_snan_f64(c) {
                fl |= NV;
            }
            if r.is_nan() && (a.is_nan() || b.is_nan() || c.is_nan()) {
                fl |= NV;
            }
            if r.is_infinite() && !a.is_infinite() && !b.is_infinite() && !c.is_infinite() {
                fl |= OF | NX;
            }
            if !r.is_nan() && !r.is_infinite() {
                let c_eff = match opcode {
                    decode::OP_FMSUB | decode::OP_FNMADD => -c,
                    _ => c,
                };
                let prod = a * b;
                let prod_err = libm::fma(a, b, -prod);
                let sum = prod + c_eff;
                let sum_err = if prod.abs() >= c_eff.abs() {
                    (prod - sum) + c_eff
                } else {
                    (c_eff - sum) + prod
                };
                let total_err = sum_err + prod_err;
                if total_err != 0.0 {
                    fl |= NX;
                }
            }
            set_flags(fcsr, fl);
        }
        _ => {}
    }
    *pc += step;
}
