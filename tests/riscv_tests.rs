//! RISC-V ISA test suite — integration tests in a separate wasm instance.
//!
//! Two sets: baseline (no block cache) and block-cache-enabled.
//! Each filtered invocation runs in its own wasmtime process, so the fixed
//! guest RAM layout in tests/support is safe.

mod support;

use support::{assert_elf_pass, assert_elf_pass_no_cache};

macro_rules! riscv_test {
    ($name:ident, $suite:expr, $test:expr) => {
        #[test]
        fn $name() -> Result<(), String> {
            let path = concat!(env!("OUT_DIR"), "/", $suite, "/", $test, ".elf");
            let bytes = std::fs::read(path).map_err(|e| format!("{} not built: {}", path, e))?;
            assert_elf_pass(stringify!($name), &bytes)
        }
    };
}

macro_rules! riscv_test_no_cache {
    ($name:ident, $suite:expr, $test:expr) => {
        #[test]
        fn $name() -> Result<(), String> {
            let path = concat!(env!("OUT_DIR"), "/", $suite, "/", $test, ".elf");
            let bytes = std::fs::read(path).map_err(|e| format!("{} not built: {}", path, e))?;
            assert_elf_pass_no_cache(stringify!($name), &bytes)
        }
    };
}

// Baseline verification (interpreter without block cache — full 104 tests)
riscv_test_no_cache!(baseline_rv64ui_add, "rv64ui", "add");
riscv_test_no_cache!(baseline_rv64ui_addi, "rv64ui", "addi");
riscv_test_no_cache!(baseline_rv64ui_addiw, "rv64ui", "addiw");
riscv_test_no_cache!(baseline_rv64ui_addw, "rv64ui", "addw");
riscv_test_no_cache!(baseline_rv64ui_and, "rv64ui", "and");
riscv_test_no_cache!(baseline_rv64ui_andi, "rv64ui", "andi");
riscv_test_no_cache!(baseline_rv64ui_auipc, "rv64ui", "auipc");
riscv_test_no_cache!(baseline_rv64ui_beq, "rv64ui", "beq");
riscv_test_no_cache!(baseline_rv64ui_bge, "rv64ui", "bge");
riscv_test_no_cache!(baseline_rv64ui_bgeu, "rv64ui", "bgeu");
riscv_test_no_cache!(baseline_rv64ui_blt, "rv64ui", "blt");
riscv_test_no_cache!(baseline_rv64ui_bltu, "rv64ui", "bltu");
riscv_test_no_cache!(baseline_rv64ui_bne, "rv64ui", "bne");
riscv_test_no_cache!(baseline_rv64ui_jal, "rv64ui", "jal");
riscv_test_no_cache!(baseline_rv64ui_jalr, "rv64ui", "jalr");
riscv_test_no_cache!(baseline_rv64ui_lb, "rv64ui", "lb");
riscv_test_no_cache!(baseline_rv64ui_lbu, "rv64ui", "lbu");
riscv_test_no_cache!(baseline_rv64ui_ld, "rv64ui", "ld");
riscv_test_no_cache!(baseline_rv64ui_lh, "rv64ui", "lh");
riscv_test_no_cache!(baseline_rv64ui_lhu, "rv64ui", "lhu");
riscv_test_no_cache!(baseline_rv64ui_lui, "rv64ui", "lui");
riscv_test_no_cache!(baseline_rv64ui_lw, "rv64ui", "lw");
riscv_test_no_cache!(baseline_rv64ui_lwu, "rv64ui", "lwu");
riscv_test_no_cache!(baseline_rv64ui_or, "rv64ui", "or");
riscv_test_no_cache!(baseline_rv64ui_ori, "rv64ui", "ori");
riscv_test_no_cache!(baseline_rv64ui_sb, "rv64ui", "sb");
riscv_test_no_cache!(baseline_rv64ui_sd, "rv64ui", "sd");
riscv_test_no_cache!(baseline_rv64ui_sh, "rv64ui", "sh");
riscv_test_no_cache!(baseline_rv64ui_sll, "rv64ui", "sll");
riscv_test_no_cache!(baseline_rv64ui_slli, "rv64ui", "slli");
riscv_test_no_cache!(baseline_rv64ui_slliw, "rv64ui", "slliw");
riscv_test_no_cache!(baseline_rv64ui_sllw, "rv64ui", "sllw");
riscv_test_no_cache!(baseline_rv64ui_slt, "rv64ui", "slt");
riscv_test_no_cache!(baseline_rv64ui_slti, "rv64ui", "slti");
riscv_test_no_cache!(baseline_rv64ui_sltiu, "rv64ui", "sltiu");
riscv_test_no_cache!(baseline_rv64ui_sltu, "rv64ui", "sltu");
riscv_test_no_cache!(baseline_rv64ui_sra, "rv64ui", "sra");
riscv_test_no_cache!(baseline_rv64ui_srai, "rv64ui", "srai");
riscv_test_no_cache!(baseline_rv64ui_sraiw, "rv64ui", "sraiw");
riscv_test_no_cache!(baseline_rv64ui_sraw, "rv64ui", "sraw");
riscv_test_no_cache!(baseline_rv64ui_srl, "rv64ui", "srl");
riscv_test_no_cache!(baseline_rv64ui_srli, "rv64ui", "srli");
riscv_test_no_cache!(baseline_rv64ui_srliw, "rv64ui", "srliw");
riscv_test_no_cache!(baseline_rv64ui_srlw, "rv64ui", "srlw");
riscv_test_no_cache!(baseline_rv64ui_sub, "rv64ui", "sub");
riscv_test_no_cache!(baseline_rv64ui_subw, "rv64ui", "subw");
riscv_test_no_cache!(baseline_rv64ui_sw, "rv64ui", "sw");
riscv_test_no_cache!(baseline_rv64ui_xor, "rv64ui", "xor");
riscv_test_no_cache!(baseline_rv64ui_xori, "rv64ui", "xori");
riscv_test_no_cache!(baseline_rv64um_mul, "rv64um", "mul");
riscv_test_no_cache!(baseline_rv64um_mulh, "rv64um", "mulh");
riscv_test_no_cache!(baseline_rv64um_mulhsu, "rv64um", "mulhsu");
riscv_test_no_cache!(baseline_rv64um_mulhu, "rv64um", "mulhu");
riscv_test_no_cache!(baseline_rv64um_mulw, "rv64um", "mulw");
riscv_test_no_cache!(baseline_rv64um_div, "rv64um", "div");
riscv_test_no_cache!(baseline_rv64um_divu, "rv64um", "divu");
riscv_test_no_cache!(baseline_rv64um_divuw, "rv64um", "divuw");
riscv_test_no_cache!(baseline_rv64um_divw, "rv64um", "divw");
riscv_test_no_cache!(baseline_rv64um_rem, "rv64um", "rem");
riscv_test_no_cache!(baseline_rv64um_remu, "rv64um", "remu");
riscv_test_no_cache!(baseline_rv64um_remuw, "rv64um", "remuw");
riscv_test_no_cache!(baseline_rv64um_remw, "rv64um", "remw");
riscv_test_no_cache!(baseline_rv64ua_amoadd_d, "rv64ua", "amoadd_d");
riscv_test_no_cache!(baseline_rv64ua_amoadd_w, "rv64ua", "amoadd_w");
riscv_test_no_cache!(baseline_rv64ua_amoand_d, "rv64ua", "amoand_d");
riscv_test_no_cache!(baseline_rv64ua_amoand_w, "rv64ua", "amoand_w");
riscv_test_no_cache!(baseline_rv64ua_amomax_d, "rv64ua", "amomax_d");
riscv_test_no_cache!(baseline_rv64ua_amomax_w, "rv64ua", "amomax_w");
riscv_test_no_cache!(baseline_rv64ua_amomaxu_d, "rv64ua", "amomaxu_d");
riscv_test_no_cache!(baseline_rv64ua_amomaxu_w, "rv64ua", "amomaxu_w");
riscv_test_no_cache!(baseline_rv64ua_amomin_d, "rv64ua", "amomin_d");
riscv_test_no_cache!(baseline_rv64ua_amomin_w, "rv64ua", "amomin_w");
riscv_test_no_cache!(baseline_rv64ua_amominu_d, "rv64ua", "amominu_d");
riscv_test_no_cache!(baseline_rv64ua_amominu_w, "rv64ua", "amominu_w");
riscv_test_no_cache!(baseline_rv64ua_amoor_d, "rv64ua", "amoor_d");
riscv_test_no_cache!(baseline_rv64ua_amoor_w, "rv64ua", "amoor_w");
riscv_test_no_cache!(baseline_rv64ua_amoswap_d, "rv64ua", "amoswap_d");
riscv_test_no_cache!(baseline_rv64ua_amoswap_w, "rv64ua", "amoswap_w");
riscv_test_no_cache!(baseline_rv64ua_amoxor_d, "rv64ua", "amoxor_d");
riscv_test_no_cache!(baseline_rv64ua_amoxor_w, "rv64ua", "amoxor_w");
riscv_test_no_cache!(baseline_rv64ua_lrsc, "rv64ua", "lrsc");
riscv_test_no_cache!(baseline_rv64uf_fadd, "rv64uf", "fadd");
riscv_test_no_cache!(baseline_rv64uf_fclass, "rv64uf", "fclass");
riscv_test_no_cache!(baseline_rv64uf_fcmp, "rv64uf", "fcmp");
riscv_test_no_cache!(baseline_rv64uf_fcvt, "rv64uf", "fcvt");
riscv_test_no_cache!(baseline_rv64uf_fcvt_w, "rv64uf", "fcvt_w");
riscv_test_no_cache!(baseline_rv64uf_fdiv, "rv64uf", "fdiv");
riscv_test_no_cache!(baseline_rv64uf_fmadd, "rv64uf", "fmadd");
riscv_test_no_cache!(baseline_rv64uf_fmin, "rv64uf", "fmin");
riscv_test_no_cache!(baseline_rv64uf_ldst, "rv64uf", "ldst");
riscv_test_no_cache!(baseline_rv64uf_move, "rv64uf", "move");
riscv_test_no_cache!(baseline_rv64uf_recoding, "rv64uf", "recoding");
riscv_test_no_cache!(baseline_rv64ud_fadd, "rv64ud", "fadd");
riscv_test_no_cache!(baseline_rv64ud_fclass, "rv64ud", "fclass");
riscv_test_no_cache!(baseline_rv64ud_fcmp, "rv64ud", "fcmp");
riscv_test_no_cache!(baseline_rv64ud_fcvt, "rv64ud", "fcvt");
riscv_test_no_cache!(baseline_rv64ud_fcvt_w, "rv64ud", "fcvt_w");
riscv_test_no_cache!(baseline_rv64ud_fdiv, "rv64ud", "fdiv");
riscv_test_no_cache!(baseline_rv64ud_fmadd, "rv64ud", "fmadd");
riscv_test_no_cache!(baseline_rv64ud_fmin, "rv64ud", "fmin");
riscv_test_no_cache!(baseline_rv64ud_ldst, "rv64ud", "ldst");
riscv_test_no_cache!(baseline_rv64ud_move, "rv64ud", "move");
riscv_test_no_cache!(baseline_rv64ud_recoding, "rv64ud", "recoding");
riscv_test_no_cache!(baseline_rv64ud_structural, "rv64ud", "structural");

// rv64ui (with block cache)
riscv_test!(rv64ui_add, "rv64ui", "add");
riscv_test!(rv64ui_addi, "rv64ui", "addi");
riscv_test!(rv64ui_addiw, "rv64ui", "addiw");
riscv_test!(rv64ui_addw, "rv64ui", "addw");
riscv_test!(rv64ui_and, "rv64ui", "and");
riscv_test!(rv64ui_andi, "rv64ui", "andi");
riscv_test!(rv64ui_auipc, "rv64ui", "auipc");
riscv_test!(rv64ui_beq, "rv64ui", "beq");
riscv_test!(rv64ui_bge, "rv64ui", "bge");
riscv_test!(rv64ui_bgeu, "rv64ui", "bgeu");
riscv_test!(rv64ui_blt, "rv64ui", "blt");
riscv_test!(rv64ui_bltu, "rv64ui", "bltu");
riscv_test!(rv64ui_bne, "rv64ui", "bne");
riscv_test!(rv64ui_jal, "rv64ui", "jal");
riscv_test!(rv64ui_jalr, "rv64ui", "jalr");
riscv_test!(rv64ui_lb, "rv64ui", "lb");
riscv_test!(rv64ui_lbu, "rv64ui", "lbu");
riscv_test!(rv64ui_ld, "rv64ui", "ld");
riscv_test!(rv64ui_lh, "rv64ui", "lh");
riscv_test!(rv64ui_lhu, "rv64ui", "lhu");
riscv_test!(rv64ui_lui, "rv64ui", "lui");
riscv_test!(rv64ui_lw, "rv64ui", "lw");
riscv_test!(rv64ui_lwu, "rv64ui", "lwu");
riscv_test!(rv64ui_or, "rv64ui", "or");
riscv_test!(rv64ui_ori, "rv64ui", "ori");
riscv_test!(rv64ui_sb, "rv64ui", "sb");
riscv_test!(rv64ui_sd, "rv64ui", "sd");
riscv_test!(rv64ui_sh, "rv64ui", "sh");
riscv_test!(rv64ui_sll, "rv64ui", "sll");
riscv_test!(rv64ui_slli, "rv64ui", "slli");
riscv_test!(rv64ui_slliw, "rv64ui", "slliw");
riscv_test!(rv64ui_sllw, "rv64ui", "sllw");
riscv_test!(rv64ui_slt, "rv64ui", "slt");
riscv_test!(rv64ui_slti, "rv64ui", "slti");
riscv_test!(rv64ui_sltiu, "rv64ui", "sltiu");
riscv_test!(rv64ui_sltu, "rv64ui", "sltu");
riscv_test!(rv64ui_sra, "rv64ui", "sra");
riscv_test!(rv64ui_srai, "rv64ui", "srai");
riscv_test!(rv64ui_sraiw, "rv64ui", "sraiw");
riscv_test!(rv64ui_sraw, "rv64ui", "sraw");
riscv_test!(rv64ui_srl, "rv64ui", "srl");
riscv_test!(rv64ui_srli, "rv64ui", "srli");
riscv_test!(rv64ui_srliw, "rv64ui", "srliw");
riscv_test!(rv64ui_srlw, "rv64ui", "srlw");
riscv_test!(rv64ui_sub, "rv64ui", "sub");
riscv_test!(rv64ui_subw, "rv64ui", "subw");
riscv_test!(rv64ui_sw, "rv64ui", "sw");
riscv_test!(rv64ui_xor, "rv64ui", "xor");
riscv_test!(rv64ui_xori, "rv64ui", "xori");

// rv64um
riscv_test!(rv64um_mul, "rv64um", "mul");
riscv_test!(rv64um_mulh, "rv64um", "mulh");
riscv_test!(rv64um_mulhsu, "rv64um", "mulhsu");
riscv_test!(rv64um_mulhu, "rv64um", "mulhu");
riscv_test!(rv64um_mulw, "rv64um", "mulw");
riscv_test!(rv64um_div, "rv64um", "div");
riscv_test!(rv64um_divu, "rv64um", "divu");
riscv_test!(rv64um_divuw, "rv64um", "divuw");
riscv_test!(rv64um_divw, "rv64um", "divw");
riscv_test!(rv64um_rem, "rv64um", "rem");
riscv_test!(rv64um_remu, "rv64um", "remu");
riscv_test!(rv64um_remuw, "rv64um", "remuw");
riscv_test!(rv64um_remw, "rv64um", "remw");

// rv64ua
riscv_test!(rv64ua_amoadd_d, "rv64ua", "amoadd_d");
riscv_test!(rv64ua_amoadd_w, "rv64ua", "amoadd_w");
riscv_test!(rv64ua_amoand_d, "rv64ua", "amoand_d");
riscv_test!(rv64ua_amoand_w, "rv64ua", "amoand_w");
riscv_test!(rv64ua_amomax_d, "rv64ua", "amomax_d");
riscv_test!(rv64ua_amomax_w, "rv64ua", "amomax_w");
riscv_test!(rv64ua_amomaxu_d, "rv64ua", "amomaxu_d");
riscv_test!(rv64ua_amomaxu_w, "rv64ua", "amomaxu_w");
riscv_test!(rv64ua_amomin_d, "rv64ua", "amomin_d");
riscv_test!(rv64ua_amomin_w, "rv64ua", "amomin_w");
riscv_test!(rv64ua_amominu_d, "rv64ua", "amominu_d");
riscv_test!(rv64ua_amominu_w, "rv64ua", "amominu_w");
riscv_test!(rv64ua_amoor_d, "rv64ua", "amoor_d");
riscv_test!(rv64ua_amoor_w, "rv64ua", "amoor_w");
riscv_test!(rv64ua_amoswap_d, "rv64ua", "amoswap_d");
riscv_test!(rv64ua_amoswap_w, "rv64ua", "amoswap_w");
riscv_test!(rv64ua_amoxor_d, "rv64ua", "amoxor_d");
riscv_test!(rv64ua_amoxor_w, "rv64ua", "amoxor_w");
riscv_test!(rv64ua_lrsc, "rv64ua", "lrsc");

// rv64uf
riscv_test!(rv64uf_fadd, "rv64uf", "fadd");
riscv_test!(rv64uf_fclass, "rv64uf", "fclass");
riscv_test!(rv64uf_fcmp, "rv64uf", "fcmp");
riscv_test!(rv64uf_fcvt, "rv64uf", "fcvt");
riscv_test!(rv64uf_fcvt_w, "rv64uf", "fcvt_w");
riscv_test!(rv64uf_fdiv, "rv64uf", "fdiv");
riscv_test!(rv64uf_fmadd, "rv64uf", "fmadd");
riscv_test!(rv64uf_fmin, "rv64uf", "fmin");
riscv_test!(rv64uf_ldst, "rv64uf", "ldst");
riscv_test!(rv64uf_move, "rv64uf", "move");
riscv_test!(rv64uf_recoding, "rv64uf", "recoding");

// rv64ud
riscv_test!(rv64ud_fadd, "rv64ud", "fadd");
riscv_test!(rv64ud_fclass, "rv64ud", "fclass");
riscv_test!(rv64ud_fcmp, "rv64ud", "fcmp");
riscv_test!(rv64ud_fcvt, "rv64ud", "fcvt");
riscv_test!(rv64ud_fcvt_w, "rv64ud", "fcvt_w");
riscv_test!(rv64ud_fdiv, "rv64ud", "fdiv");
riscv_test!(rv64ud_fmadd, "rv64ud", "fmadd");
riscv_test!(rv64ud_fmin, "rv64ud", "fmin");
riscv_test!(rv64ud_ldst, "rv64ud", "ldst");
riscv_test!(rv64ud_move, "rv64ud", "move");
riscv_test!(rv64ud_recoding, "rv64ud", "recoding");
riscv_test!(rv64ud_structural, "rv64ud", "structural");
