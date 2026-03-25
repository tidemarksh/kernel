#![cfg_attr(not(test), no_std)]

#[cfg(all(not(test), target_arch = "wasm32"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

pub mod abi;
pub mod alloc;
pub mod cpu;
pub mod elf;
pub mod fs;
pub mod guest_mem;
pub mod jit;
pub mod net;
pub mod syscall;
pub mod types;

#[cfg(test)]
mod tests {
    use super::abi::*;
    use super::guest_mem;
    use super::types::*;

    #[test]
    fn status_codes_are_distinct() {
        let codes = [
            STATUS_OK, STATUS_FAULT, STATUS_FS, STATUS_FUTEX_WAIT,
            STATUS_PIPE_WAIT, STATUS_EPOLL_WAIT, STATUS_VFORK_WAIT,
            STATUS_EXECVE_SPAWN, STATUS_CLONE_SPAWN, STATUS_SLEEP, STATUS_JIT_READY,
        ];
        for i in 0..codes.len() {
            for j in (i + 1)..codes.len() {
                assert_ne!(codes[i], codes[j]);
            }
        }
    }

    #[test]
    fn fd_types_are_distinct() {
        let types = [
            FD_TYPE_NONE, FD_TYPE_STDOUT, FD_TYPE_STDERR, FD_TYPE_FILE,
            FD_TYPE_DIR, FD_TYPE_DEVNULL, FD_TYPE_PIPE, FD_TYPE_EPOLL,
            FD_TYPE_SOCKET, FD_TYPE_EVENTFD, FD_TYPE_TIMERFD,
            FD_TYPE_PTY_MASTER, FD_TYPE_PTY_SLAVE, FD_TYPE_INOTIFY,
        ];
        for i in 0..types.len() {
            for j in (i + 1)..types.len() {
                assert_ne!(types[i], types[j]);
            }
        }
    }

    #[test]
    fn thread_state_layout() {
        let size = core::mem::size_of::<ThreadState>();
        assert!(size > 0);
        assert_eq!(size % 8, 0, "ThreadState should be 8-byte aligned");
    }

    #[test]
    fn process_state_has_fd_table() {
        let size = core::mem::size_of::<ProcessState>();
        assert!(size >= MAX_FDS * core::mem::size_of::<FdEntry>());
    }

    #[test]
    fn vma_is_copy() {
        let v = Vma {
            start: 0x1000, end: 0x2000, prot: PROT_READ | PROT_WRITE,
            flags: 0, fd: -1, _pad: 0, offset: 0,
        };
        let v2 = v;
        assert_eq!(v2.start, 0x1000);
    }

    #[test]
    fn error_codes_are_negative() {
        assert!(ENOENT < 0);
        assert!(EBADF < 0);
        assert!(EINVAL < 0);
        assert!(ENOMEM < 0);
        assert!(ENOSYS < 0);
    }

    #[test]
    fn clone_flags_no_overlap() {
        assert_eq!(CLONE_VM & CLONE_THREAD, 0);
        assert_eq!(CLONE_VM & CLONE_VFORK, 0);
        assert_eq!(CLONE_THREAD & CLONE_VFORK, 0);
    }

    // =========================================================================
    // ELF integration tests
    // =========================================================================

    /// Load an ELF, run the interpreter, return the exit code.
    /// Capture stdout writes from the guest for debugging.
    /// Uses raw pointer to avoid Rust 2024 mutable static reference issues.
    static mut STDOUT_BUF: [u8; 4096] = [0; 4096];
    static mut STDOUT_LEN: usize = 0;
    static mut WRITE_COUNT: usize = 0;

    fn captured_stdout() -> &'static [u8] {
        unsafe {
            let len = core::ptr::read(core::ptr::addr_of!(STDOUT_LEN));
            let base = core::ptr::addr_of!(STDOUT_BUF) as *const u8;
            core::slice::from_raw_parts(base, len)
        }
    }

    fn capture_write(base: u32, buf: u64, len: usize) {
        unsafe {
            let wc = core::ptr::addr_of_mut!(WRITE_COUNT);
            core::ptr::write(wc, core::ptr::read(wc) + 1);
            let cur = core::ptr::read(core::ptr::addr_of!(STDOUT_LEN));
            let avail = 4096 - cur;
            let n = if len < avail { len } else { avail };
            if n > 0 {
                let dst = (core::ptr::addr_of_mut!(STDOUT_BUF) as *mut u8).add(cur);
                let src = (base as u64 + buf) as *const u8;
                core::ptr::copy_nonoverlapping(src, dst, n);
                core::ptr::write(core::ptr::addr_of_mut!(STDOUT_LEN), cur + n);
            }
        }
    }

    fn run_elf(elf_bytes: &[u8]) -> (i32, u64) {
        unsafe {
            core::ptr::write(core::ptr::addr_of_mut!(STDOUT_LEN), 0);
            core::ptr::write(core::ptr::addr_of_mut!(WRITE_COUNT), 0);
        }
        super::syscall::fs::set_write_capture(Some(capture_write));
        unsafe {
            let base: u32 = 0;

            super::guest_mem::init(core::ptr::null(), core::ptr::null());
            super::syscall::memory::init(0);

            // Grow WASM memory to 16 MB
            let current_pages = core::arch::wasm32::memory_size(0);
            let target_pages = 256; // 256 * 64KB = 16 MB
            if current_pages < target_pages {
                core::arch::wasm32::memory_grow(0, target_pages - current_pages);
            }

            // Copy ELF to a high address to avoid overlap with load segments
            let elf_load_addr: u64 = 0xC0_0000; // 12 MB
            super::guest_mem::write_bytes(base, elf_load_addr, elf_bytes);

            let elf_result = super::elf::load_elf(
                base, 0x100_0000, // 16 MB RAM
                (base as u64 + elf_load_addr) as u32,
                elf_bytes.len() as u32,
            ).expect("ELF load failed");

            super::syscall::memory::init(elf_result.brk_start);

            // AT_RANDOM: 16 bytes
            let random_addr = 0xBF_FF00u64;
            super::guest_mem::write_bytes(base, random_addr, &[0x42u8; 16]);

            // argv[0] string
            let argv0_addr = 0xBF_FE00u64;
            super::guest_mem::write_bytes(base, argv0_addr, b"test\0");

            let sp = super::elf::setup_stack(
                base, 0xBF_FD00, &[argv0_addr], &[], &elf_result, random_addr,
            );

            let mut vm: ThreadState = core::mem::zeroed();
            vm.pc = elf_result.entry;
            vm.x[2] = sp;
            vm.status = STATUS_OK;
            vm.tid = 1;

            // ProcessState in guest memory
            let ps_addr = (elf_result.brk_start + 0x1000) & !0xF;
            super::guest_mem::zero_mem(base, ps_addr, core::mem::size_of::<ProcessState>());
            vm.process_ptr = ps_addr as u32;

            // Write pid = 1
            let pid_off = core::mem::offset_of!(ProcessState, pid) as u64;
            super::guest_mem::write_u32(base, ps_addr + pid_off, 1);

            // Set up FD 0/1/2 (ofd_id != 0 so close doesn't fail)
            let fd_off = 0u64; // fd_table is first field
            super::guest_mem::write_u32(base, ps_addr + fd_off + 0, 1);  // fd 0 ofd_id=1
            super::guest_mem::write_u32(base, ps_addr + fd_off + 8, 2);  // fd 1 ofd_id=2
            super::guest_mem::write_u32(base, ps_addr + fd_off + 16, 3); // fd 2 ofd_id=3

            let mut total = 0i64;
            loop {
                let budget = 500_000i32;
                vm.status = STATUS_OK;
                let rem = super::cpu::exec(&mut vm, budget, None, None, None, None);
                total += (budget - rem) as i64;

                match vm.status {
                    STATUS_OK => {
                        if total > 50_000_000 { return (-999, vm.pc); }
                    }
                    STATUS_FAULT => return (vm.exit_code, vm.pc),
                    STATUS_SLEEP => {}
                    _ => return (-vm.status, vm.pc),
                }
            }
        }
    }

    fn assert_elf_pass(name: &str, elf_bytes: &[u8]) {
        let (code, pc) = run_elf(elf_bytes);
        let output = core::str::from_utf8(captured_stdout()).unwrap_or("<invalid utf8>");
        let writes = unsafe { core::ptr::read(core::ptr::addr_of!(WRITE_COUNT)) };
        assert_eq!(code, 0,
            "{} failed: exit_code={}, last_pc=0x{:x}, writes={}, output=[{}]",
            name, code, pc, writes, output);
    }

    #[test] fn elf_hello()        { assert_elf_pass("hello.elf",        include_bytes!("../tests/fixtures/hello.elf")); }
    #[test] fn elf_test_suite()    { assert_elf_pass("test_suite.elf",   include_bytes!("../tests/fixtures/test_suite.elf")); }
    #[test] fn elf_test_float()    { assert_elf_pass("test_float.elf",   include_bytes!("../tests/fixtures/test_float.elf")); }
    #[test] fn elf_test_rvc()      { assert_elf_pass("test_rvc.elf",     include_bytes!("../tests/fixtures/test_rvc.elf")); }
    #[test] fn elf_test_memory()   { assert_elf_pass("test_memory.elf",  include_bytes!("../tests/fixtures/test_memory.elf")); }
    #[test] fn elf_test_syscalls() { assert_elf_pass("test_syscalls.elf", include_bytes!("../tests/fixtures/test_syscalls.elf")); }

    // =========================================================================
    // riscv-tests ISA test suite
    // =========================================================================

    macro_rules! riscv_test {
        ($name:ident, $suite:expr, $test:expr) => {
            #[test]
            fn $name() {
                let path = concat!(env!("OUT_DIR"), "/", $suite, "/", $test, ".elf");
                let bytes = match std::fs::read(path) {
                    Ok(b) => b,
                    Err(_) => { eprintln!("skip: {} not built", path); return; }
                };
                assert_elf_pass(stringify!($name), &bytes);
            }
        };
    }

    // rv64ui
    riscv_test!(rv64ui_add,    "rv64ui", "add");
    riscv_test!(rv64ui_addi,   "rv64ui", "addi");
    riscv_test!(rv64ui_addiw,  "rv64ui", "addiw");
    riscv_test!(rv64ui_addw,   "rv64ui", "addw");
    riscv_test!(rv64ui_and,    "rv64ui", "and");
    riscv_test!(rv64ui_andi,   "rv64ui", "andi");
    riscv_test!(rv64ui_auipc,  "rv64ui", "auipc");
    riscv_test!(rv64ui_beq,    "rv64ui", "beq");
    riscv_test!(rv64ui_bge,    "rv64ui", "bge");
    riscv_test!(rv64ui_bgeu,   "rv64ui", "bgeu");
    riscv_test!(rv64ui_blt,    "rv64ui", "blt");
    riscv_test!(rv64ui_bltu,   "rv64ui", "bltu");
    riscv_test!(rv64ui_bne,    "rv64ui", "bne");
    riscv_test!(rv64ui_jal,    "rv64ui", "jal");
    riscv_test!(rv64ui_jalr,   "rv64ui", "jalr");
    riscv_test!(rv64ui_lb,     "rv64ui", "lb");
    riscv_test!(rv64ui_lbu,    "rv64ui", "lbu");
    riscv_test!(rv64ui_ld,     "rv64ui", "ld");
    riscv_test!(rv64ui_lh,     "rv64ui", "lh");
    riscv_test!(rv64ui_lhu,    "rv64ui", "lhu");
    riscv_test!(rv64ui_lui,    "rv64ui", "lui");
    riscv_test!(rv64ui_lw,     "rv64ui", "lw");
    riscv_test!(rv64ui_lwu,    "rv64ui", "lwu");
    riscv_test!(rv64ui_or,     "rv64ui", "or");
    riscv_test!(rv64ui_ori,    "rv64ui", "ori");
    riscv_test!(rv64ui_sb,     "rv64ui", "sb");
    riscv_test!(rv64ui_sd,     "rv64ui", "sd");
    riscv_test!(rv64ui_sh,     "rv64ui", "sh");
    riscv_test!(rv64ui_sll,    "rv64ui", "sll");
    riscv_test!(rv64ui_slli,   "rv64ui", "slli");
    riscv_test!(rv64ui_slliw,  "rv64ui", "slliw");
    riscv_test!(rv64ui_sllw,   "rv64ui", "sllw");
    riscv_test!(rv64ui_slt,    "rv64ui", "slt");
    riscv_test!(rv64ui_slti,   "rv64ui", "slti");
    riscv_test!(rv64ui_sltiu,  "rv64ui", "sltiu");
    riscv_test!(rv64ui_sltu,   "rv64ui", "sltu");
    riscv_test!(rv64ui_sra,    "rv64ui", "sra");
    riscv_test!(rv64ui_srai,   "rv64ui", "srai");
    riscv_test!(rv64ui_sraiw,  "rv64ui", "sraiw");
    riscv_test!(rv64ui_sraw,   "rv64ui", "sraw");
    riscv_test!(rv64ui_srl,    "rv64ui", "srl");
    riscv_test!(rv64ui_srli,   "rv64ui", "srli");
    riscv_test!(rv64ui_srliw,  "rv64ui", "srliw");
    riscv_test!(rv64ui_srlw,   "rv64ui", "srlw");
    riscv_test!(rv64ui_sub,    "rv64ui", "sub");
    riscv_test!(rv64ui_subw,   "rv64ui", "subw");
    riscv_test!(rv64ui_sw,     "rv64ui", "sw");
    riscv_test!(rv64ui_xor,    "rv64ui", "xor");
    riscv_test!(rv64ui_xori,   "rv64ui", "xori");

    // rv64um
    riscv_test!(rv64um_mul,    "rv64um", "mul");
    riscv_test!(rv64um_mulh,   "rv64um", "mulh");
    riscv_test!(rv64um_mulhsu, "rv64um", "mulhsu");
    riscv_test!(rv64um_mulhu,  "rv64um", "mulhu");
    riscv_test!(rv64um_mulw,   "rv64um", "mulw");
    riscv_test!(rv64um_div,    "rv64um", "div");
    riscv_test!(rv64um_divu,   "rv64um", "divu");
    riscv_test!(rv64um_divuw,  "rv64um", "divuw");
    riscv_test!(rv64um_divw,   "rv64um", "divw");
    riscv_test!(rv64um_rem,    "rv64um", "rem");
    riscv_test!(rv64um_remu,   "rv64um", "remu");
    riscv_test!(rv64um_remuw,  "rv64um", "remuw");
    riscv_test!(rv64um_remw,   "rv64um", "remw");

    // rv64ua
    riscv_test!(rv64ua_amoadd_d,  "rv64ua", "amoadd_d");
    riscv_test!(rv64ua_amoadd_w,  "rv64ua", "amoadd_w");
    riscv_test!(rv64ua_amoand_d,  "rv64ua", "amoand_d");
    riscv_test!(rv64ua_amoand_w,  "rv64ua", "amoand_w");
    riscv_test!(rv64ua_amomax_d,  "rv64ua", "amomax_d");
    riscv_test!(rv64ua_amomax_w,  "rv64ua", "amomax_w");
    riscv_test!(rv64ua_amomaxu_d, "rv64ua", "amomaxu_d");
    riscv_test!(rv64ua_amomaxu_w, "rv64ua", "amomaxu_w");
    riscv_test!(rv64ua_amomin_d,  "rv64ua", "amomin_d");
    riscv_test!(rv64ua_amomin_w,  "rv64ua", "amomin_w");
    riscv_test!(rv64ua_amominu_d, "rv64ua", "amominu_d");
    riscv_test!(rv64ua_amominu_w, "rv64ua", "amominu_w");
    riscv_test!(rv64ua_amoor_d,   "rv64ua", "amoor_d");
    riscv_test!(rv64ua_amoor_w,   "rv64ua", "amoor_w");
    riscv_test!(rv64ua_amoswap_d, "rv64ua", "amoswap_d");
    riscv_test!(rv64ua_amoswap_w, "rv64ua", "amoswap_w");
    riscv_test!(rv64ua_amoxor_d,  "rv64ua", "amoxor_d");
    riscv_test!(rv64ua_amoxor_w,  "rv64ua", "amoxor_w");
    riscv_test!(rv64ua_lrsc,      "rv64ua", "lrsc");

    // rv64uf
    riscv_test!(rv64uf_fadd,    "rv64uf", "fadd");
    riscv_test!(rv64uf_fclass,  "rv64uf", "fclass");
    riscv_test!(rv64uf_fcmp,    "rv64uf", "fcmp");
    riscv_test!(rv64uf_fcvt,    "rv64uf", "fcvt");
    riscv_test!(rv64uf_fcvt_w,  "rv64uf", "fcvt_w");
    riscv_test!(rv64uf_fdiv,    "rv64uf", "fdiv");
    riscv_test!(rv64uf_fmadd,   "rv64uf", "fmadd");
    riscv_test!(rv64uf_fmin,    "rv64uf", "fmin");
    riscv_test!(rv64uf_ldst,    "rv64uf", "ldst");
    riscv_test!(rv64uf_move,    "rv64uf", "move");
    riscv_test!(rv64uf_recoding,"rv64uf", "recoding");

    // rv64ud
    riscv_test!(rv64ud_fadd,      "rv64ud", "fadd");
    riscv_test!(rv64ud_fclass,    "rv64ud", "fclass");
    riscv_test!(rv64ud_fcmp,      "rv64ud", "fcmp");
    riscv_test!(rv64ud_fcvt,      "rv64ud", "fcvt");
    riscv_test!(rv64ud_fcvt_w,    "rv64ud", "fcvt_w");
    riscv_test!(rv64ud_fdiv,      "rv64ud", "fdiv");
    riscv_test!(rv64ud_fmadd,     "rv64ud", "fmadd");
    riscv_test!(rv64ud_fmin,      "rv64ud", "fmin");
    riscv_test!(rv64ud_ldst,      "rv64ud", "ldst");
    riscv_test!(rv64ud_move,      "rv64ud", "move");
    riscv_test!(rv64ud_recoding,  "rv64ud", "recoding");
    riscv_test!(rv64ud_structural,"rv64ud", "structural");
}
