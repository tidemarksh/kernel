use core::sync::atomic::Ordering;
use tidemark_kernel::cpu::block_cache::{BlockCache, BlockEntry, CACHE_SIZE, PackedOp};
use tidemark_kernel::harness::TestVm;
use tidemark_kernel::{abi, guest_mem};

fn alloc_block_cache_ptr() -> u32 {
    let alloc_size = BlockCache::allocation_size();
    let cache_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(alloc_size as u32, 8) };
    assert!(cache_ptr != 0);
    cache_ptr
}

fn alloc_block_cache() -> BlockCache {
    unsafe { BlockCache::from_ptr(alloc_block_cache_ptr() as *mut BlockEntry) }
}

fn mmap_exec(t: &mut TestVm, len: u64) -> u64 {
    let addr = t.sys_mmap(
        0,
        len,
        abi::PROT_READ | abi::PROT_WRITE | abi::PROT_EXEC,
        abi::MAP_ANONYMOUS | abi::MAP_PRIVATE,
        -1,
        0,
    );
    assert!(addr > 0, "mmap failed: {addr}");
    addr as u64
}

fn encode_fp_load(rd: u32, rs1: u32, imm: i32, funct3: u32) -> u32 {
    ((imm as u32 & 0x0fff) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | 0x07
}

fn encode_fp_store(rs2: u32, rs1: u32, imm: i32, funct3: u32) -> u32 {
    let imm = imm as u32 & 0x0fff;
    ((imm >> 5) << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | ((imm & 0x1f) << 7) | 0x27
}

fn encode_amo(funct5: u32, rd: u32, rs1: u32, rs2: u32, funct3: u32) -> u32 {
    (funct5 << 27) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | 0x2f
}

fn encode_op_fp(funct7: u32, rd: u32, rs1: u32, rs2: u32, funct3: u32) -> u32 {
    (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | 0x53
}

fn encode_fma(opcode: u32, rd: u32, rs1: u32, rs2: u32, rs3: u32, fmt: u32, rm: u32) -> u32 {
    (rs3 << 27) | (fmt << 25) | (rs2 << 20) | (rs1 << 15) | (rm << 12) | (rd << 7) | opcode
}

fn encode_branch(rs1: u32, rs2: u32, imm: i32, funct3: u32) -> u32 {
    let imm = imm as u32;
    ((imm >> 12) & 1) << 31
        | ((imm >> 5) & 0x3f) << 25
        | (rs2 << 20)
        | (rs1 << 15)
        | (funct3 << 12)
        | ((imm >> 1) & 0x0f) << 8
        | ((imm >> 11) & 1) << 7
        | 0x63
}

fn encode_store(rs2: u32, rs1: u32, imm: i32, funct3: u32) -> u32 {
    let imm = imm as u32 & 0x0fff;
    ((imm >> 5) << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | ((imm & 0x1f) << 7) | 0x23
}

#[test]
fn packed_op_round_trip() {
    let op = PackedOp::new(5, 10, 15, 20, 3, true, 4, -42);
    assert_eq!(op.op_id(), 5);
    assert_eq!(op.rd(), 10);
    assert_eq!(op.rs1(), 15);
    assert_eq!(op.rs2(), 20);
    assert_eq!(op.f3(), 3);
    assert!(op.f7b5());
    assert_eq!(op.step(), 4);
    assert_eq!(op.imm(), -42);
}

#[test]
fn packed_op_step2() {
    let op = PackedOp::new(1, 0, 0, 0, 0, false, 2, 0);
    assert_eq!(op.step(), 2);
}

#[test]
fn block_entry_size() {
    let size = BlockCache::allocation_size();
    assert!(size > 0);
    assert!(size < 4 * 1024 * 1024);
}

#[test]
fn block_cache_populate_and_get() {
    let t = TestVm::new();
    let code_addr: u64 = t.scratch;
    let addi_x1_x0_42: u32 = 0x02A00093;
    let ecall: u32 = 0x00000073;

    unsafe {
        guest_mem::write_u32(t.base, code_addr, addi_x1_x0_42);
        guest_mem::write_u32(t.base, code_addr + 4, ecall);
    }

    let mut cache = alloc_block_cache();
    assert!(cache.get(code_addr).is_none());

    let block = unsafe { cache.build_block(code_addr, t.base) };
    assert!(block.is_some());

    let blk = block.unwrap();
    assert_eq!(blk.start_pc, code_addr);
    assert_eq!(blk.len, 2);

    let op0 = blk.ops[0];
    assert_eq!(op0.op_id(), 1);
    assert_eq!(op0.rd(), 1);
    assert_eq!(op0.rs1(), 0);
    assert_eq!(op0.imm(), 42);

    let cached = cache.get(code_addr);
    assert!(cached.is_some());
    assert_eq!(cached.unwrap().start_pc, code_addr);
    assert_eq!(cached.unwrap().len, 2);
}

#[test]
fn block_cache_retains_two_blocks_that_map_to_the_same_set() {
    let t = TestVm::new();
    let first = t.scratch;
    let second = first + (CACHE_SIZE as u64 * 2);
    let ecall: u32 = 0x00000073;

    unsafe {
        guest_mem::write_u32(t.base, first, 0x00100093);
        guest_mem::write_u32(t.base, first + 4, ecall);
        guest_mem::write_u32(t.base, second, 0x00200093);
        guest_mem::write_u32(t.base, second + 4, ecall);
    }

    let mut cache = alloc_block_cache();
    assert!(unsafe { cache.build_block(first, t.base) }.is_some());
    assert!(unsafe { cache.build_block(second, t.base) }.is_some());
    assert_eq!(cache.get(first).map(|block| block.ops[0].imm()), Some(1));
    assert_eq!(cache.get(second).map(|block| block.ops[0].imm()), Some(2));
}

#[test]
fn checked_block_cache_executes_fp_load_store_block() {
    fn run(use_cache: bool) -> (i32, u64, u64, u64) {
        let mut t = TestVm::new();
        let code_addr = mmap_exec(&mut t, 4096);
        let data_addr = code_addr + 0x200;
        let source = 0x4018_0000_0000_0000u64; // 6.0f64

        unsafe {
            guest_mem::write_u32(t.base, code_addr, encode_fp_load(10, 10, 0, 3)); // fld fa0,0(a0)
            guest_mem::write_u32(t.base, code_addr + 4, encode_fp_store(10, 10, 8, 3)); // fsd fa0,8(a0)
            guest_mem::write_u64(t.base, data_addr, source);
            guest_mem::write_u64(t.base, data_addr + 8, 0);
        }

        t.vm.pc = code_addr;
        t.vm.x[10] = data_addr;
        t.vm.status = abi::STATUS_OK;

        if use_cache {
            let mut cache = alloc_block_cache();
            {
                let blk = unsafe { cache.get_or_build_checked(&t.vm, code_addr, t.base) }
                    .expect("checked block cache should build an FP load/store block");
                assert_eq!(blk.len, 2);
                assert_eq!(blk.ops[0].op_id(), 15);
                assert_eq!(blk.ops[1].op_id(), 16);
            }
            unsafe {
                tidemark_kernel::cpu::exec_at_base(
                    &mut t.vm,
                    2,
                    t.base,
                    Some(&mut cache),
                    None,
                    None,
                    None,
                );
            }
        } else {
            unsafe {
                tidemark_kernel::cpu::exec_at_base(&mut t.vm, 2, t.base, None, None, None, None);
            }
        }

        (t.vm.status, t.vm.pc - code_addr, t.vm.f[10], unsafe {
            guest_mem::read_u64(t.base, data_addr + 8)
        })
    }

    let no_cache = run(false);
    let with_cache = run(true);
    assert_eq!(with_cache, no_cache);
    assert_eq!(with_cache.0, abi::STATUS_OK);
    assert_eq!(with_cache.1, 8);
    assert_eq!(with_cache.2, 0x4018_0000_0000_0000);
    assert_eq!(with_cache.3, 0x4018_0000_0000_0000);
}

#[test]
fn checked_block_cache_executes_amo_block() {
    fn run(use_cache: bool) -> (i32, u64, u64, u64, u64, u32) {
        let mut t = TestVm::new();
        let code_addr = mmap_exec(&mut t, 4096);
        let data_addr = code_addr + 0x200;
        let word_addr = data_addr + 0x10;

        unsafe {
            guest_mem::write_u32(t.base, code_addr, encode_amo(0x00, 6, 10, 7, 3)); // amoadd.d x6,x7,(x10)
            guest_mem::write_u32(t.base, code_addr + 4, encode_amo(0x01, 8, 11, 9, 2)); // amoswap.w x8,x9,(x11)
            guest_mem::write_u64(t.base, data_addr, 10);
            guest_mem::write_u32(t.base, word_addr, 0x8000_0001);
        }

        t.vm.pc = code_addr;
        t.vm.x[7] = 5;
        t.vm.x[9] = 0x1234_5678;
        t.vm.x[10] = data_addr;
        t.vm.x[11] = word_addr;
        t.vm.status = abi::STATUS_OK;

        if use_cache {
            let mut cache = alloc_block_cache();
            {
                let blk = unsafe { cache.get_or_build_checked(&t.vm, code_addr, t.base) }
                    .expect("checked block cache should build an AMO block");
                assert_eq!(blk.len, 2);
                assert_eq!(blk.ops[0].op_id(), 14);
                assert_eq!(blk.ops[1].op_id(), 14);
            }
            unsafe {
                tidemark_kernel::cpu::exec_at_base(
                    &mut t.vm,
                    2,
                    t.base,
                    Some(&mut cache),
                    None,
                    None,
                    None,
                );
            }
        } else {
            unsafe {
                tidemark_kernel::cpu::exec_at_base(&mut t.vm, 2, t.base, None, None, None, None);
            }
        }

        (
            t.vm.status,
            t.vm.pc - code_addr,
            t.vm.x[6],
            t.vm.x[8],
            unsafe { guest_mem::read_u64(t.base, data_addr) },
            unsafe { guest_mem::read_u32(t.base, word_addr) },
        )
    }

    let no_cache = run(false);
    let with_cache = run(true);
    assert_eq!(with_cache, no_cache);
    assert_eq!(with_cache.0, abi::STATUS_OK);
    assert_eq!(with_cache.1, 8);
    assert_eq!(with_cache.2, 10);
    assert_eq!(with_cache.3, 0xffff_ffff_8000_0001);
    assert_eq!(with_cache.4, 15);
    assert_eq!(with_cache.5, 0x1234_5678);
}

#[test]
fn checked_block_cache_executes_self_backedge_with_exact_budget() {
    fn run(use_cache: bool) -> (i32, u64, u64) {
        let mut t = TestVm::new();
        let code_addr = mmap_exec(&mut t, 4096);

        unsafe {
            guest_mem::write_u32(t.base, code_addr, 0x0012_8293); // addi t0,t0,1
            guest_mem::write_u32(
                t.base,
                code_addr + 4,
                encode_branch(5, 6, -4, 4), // blt t0,t1,loop
            );
        }

        t.vm.pc = code_addr;
        t.vm.x[5] = 0;
        t.vm.x[6] = 5;
        t.vm.status = abi::STATUS_OK;

        let remaining = if use_cache {
            let mut cache = alloc_block_cache();
            unsafe {
                tidemark_kernel::cpu::exec_at_base(
                    &mut t.vm,
                    10,
                    t.base,
                    Some(&mut cache),
                    None,
                    None,
                    None,
                )
            }
        } else {
            unsafe {
                tidemark_kernel::cpu::exec_at_base(&mut t.vm, 10, t.base, None, None, None, None)
            }
        };

        (remaining, t.vm.pc - code_addr, t.vm.x[5])
    }

    let no_cache = run(false);
    let with_cache = run(true);
    assert_eq!(with_cache, no_cache);
    assert_eq!(with_cache, (0, 8, 5));
}

#[test]
fn checked_block_cache_preserves_multithreaded_seqlock_loads() {
    let mut t = TestVm::new();
    let code_addr = mmap_exec(&mut t, 4096);
    let data_addr = code_addr + 512;
    let process = unsafe {
        &*((t.base as u64 + t.vm.process_ptr as u64) as *const tidemark_kernel::types::ProcessState)
    };

    unsafe {
        guest_mem::write_u32(t.base, code_addr, 0x0005_3283); // ld t0,0(a0)
        guest_mem::write_u64(t.base, data_addr, 0x1122_3344_5566_7788);
    }
    process.thread_count.store(2, Ordering::Release);
    unsafe {
        guest_mem::init(
            core::ptr::addr_of!(process.reservation_gen) as *const _,
            core::ptr::addr_of!(process.reservation_lock) as *const _,
            core::ptr::addr_of!(process.thread_count),
        );
    }

    t.vm.pc = code_addr;
    t.vm.x[10] = data_addr;
    t.vm.status = abi::STATUS_OK;
    let mut cache = alloc_block_cache();
    let remaining = unsafe {
        tidemark_kernel::cpu::exec_at_base(&mut t.vm, 1, t.base, Some(&mut cache), None, None, None)
    };

    assert_eq!(remaining, 0);
    assert_eq!(t.vm.pc, code_addr + 4);
    assert_eq!(t.vm.x[5], 0x1122_3344_5566_7788);
}

#[test]
fn checked_block_cache_preserves_multithreaded_seqlock_stores() {
    let mut t = TestVm::new();
    let code_addr = mmap_exec(&mut t, 4096);
    let data_addr = code_addr + 512;
    let process = unsafe {
        &*((t.base as u64 + t.vm.process_ptr as u64) as *const tidemark_kernel::types::ProcessState)
    };

    unsafe {
        guest_mem::write_u32(t.base, code_addr, encode_store(6, 10, 0, 3)); // sd t1,0(a0)
        guest_mem::write_u64(t.base, data_addr, 0);
    }
    process.thread_count.store(2, Ordering::Release);
    unsafe {
        guest_mem::init(
            core::ptr::addr_of!(process.reservation_gen) as *const _,
            core::ptr::addr_of!(process.reservation_lock) as *const _,
            core::ptr::addr_of!(process.thread_count),
        );
    }

    let slot = ((data_addr >> 3) & 63) as usize;
    let generation_before = process.reservation_gen[slot].load(Ordering::Acquire);
    t.vm.pc = code_addr;
    t.vm.x[6] = 0x1122_3344_5566_7788;
    t.vm.x[10] = data_addr;
    t.vm.status = abi::STATUS_OK;
    let mut cache = alloc_block_cache();
    let remaining = unsafe {
        tidemark_kernel::cpu::exec_at_base(&mut t.vm, 1, t.base, Some(&mut cache), None, None, None)
    };

    assert_eq!(remaining, 0);
    assert_eq!(t.vm.pc, code_addr + 4);
    assert_eq!(
        unsafe { guest_mem::read_u64(t.base, data_addr) },
        0x1122_3344_5566_7788
    );
    assert_eq!(
        process.reservation_gen[slot].load(Ordering::Acquire),
        generation_before.wrapping_add(2),
    );
    assert_eq!(process.reservation_lock[slot].load(Ordering::Acquire), 0);
}

#[test]
fn checked_block_cache_executes_fp_arithmetic_block() {
    fn run(use_cache: bool) -> (i32, u64, u64, u64, u64, u32) {
        let mut t = TestVm::new();
        let code_addr = mmap_exec(&mut t, 4096);

        unsafe {
            guest_mem::write_u32(t.base, code_addr, encode_op_fp(0x01, 12, 10, 11, 0)); // fadd.d fa2,fa0,fa1
            guest_mem::write_u32(t.base, code_addr + 4, encode_op_fp(0x09, 13, 10, 11, 0)); // fmul.d fa3,fa0,fa1
            guest_mem::write_u32(t.base, code_addr + 8, encode_op_fp(0x51, 6, 12, 13, 2)); // feq.d t1,fa2,fa3
        }

        t.vm.pc = code_addr;
        t.vm.f[10] = 1.5f64.to_bits();
        t.vm.f[11] = 2.5f64.to_bits();
        t.vm.fcsr = 0;
        t.vm.status = abi::STATUS_OK;

        if use_cache {
            let mut cache = alloc_block_cache();
            {
                let blk = unsafe { cache.get_or_build_checked(&t.vm, code_addr, t.base) }
                    .expect("checked block cache should build an FP arithmetic block");
                assert_eq!(blk.len, 3);
                assert_eq!(blk.ops[0].op_id(), 17);
                assert_eq!(blk.ops[1].op_id(), 17);
                assert_eq!(blk.ops[2].op_id(), 17);
            }
            unsafe {
                tidemark_kernel::cpu::exec_at_base(
                    &mut t.vm,
                    3,
                    t.base,
                    Some(&mut cache),
                    None,
                    None,
                    None,
                );
            }
        } else {
            unsafe {
                tidemark_kernel::cpu::exec_at_base(&mut t.vm, 3, t.base, None, None, None, None);
            }
        }

        (
            t.vm.status,
            t.vm.pc - code_addr,
            t.vm.f[12],
            t.vm.f[13],
            t.vm.x[6],
            t.vm.fcsr,
        )
    }

    let no_cache = run(false);
    let with_cache = run(true);
    assert_eq!(with_cache, no_cache);
    assert_eq!(with_cache.0, abi::STATUS_OK);
    assert_eq!(with_cache.1, 12);
    assert_eq!(f64::from_bits(with_cache.2), 4.0);
    assert_eq!(f64::from_bits(with_cache.3), 3.75);
    assert_eq!(with_cache.4, 0);
    assert_eq!(with_cache.5, 0);
}

#[test]
fn checked_block_cache_executes_fma_block() {
    fn run(use_cache: bool) -> (i32, u64, u64, u32) {
        let mut t = TestVm::new();
        let code_addr = mmap_exec(&mut t, 4096);

        unsafe {
            guest_mem::write_u32(t.base, code_addr, encode_fma(0x43, 13, 10, 11, 12, 1, 0)); // fmadd.d fa3,fa0,fa1,fa2
        }

        t.vm.pc = code_addr;
        t.vm.f[10] = 2.0f64.to_bits();
        t.vm.f[11] = 3.0f64.to_bits();
        t.vm.f[12] = 4.0f64.to_bits();
        t.vm.fcsr = 0;
        t.vm.status = abi::STATUS_OK;

        if use_cache {
            let mut cache = alloc_block_cache();
            {
                let blk = unsafe { cache.get_or_build_checked(&t.vm, code_addr, t.base) }
                    .expect("checked block cache should build an FMA block");
                assert_eq!(blk.len, 1);
                assert_eq!(blk.ops[0].op_id(), 18);
            }
            unsafe {
                tidemark_kernel::cpu::exec_at_base(
                    &mut t.vm,
                    1,
                    t.base,
                    Some(&mut cache),
                    None,
                    None,
                    None,
                );
            }
        } else {
            unsafe {
                tidemark_kernel::cpu::exec_at_base(&mut t.vm, 1, t.base, None, None, None, None);
            }
        }

        (t.vm.status, t.vm.pc - code_addr, t.vm.f[13], t.vm.fcsr)
    }

    let no_cache = run(false);
    let with_cache = run(true);
    assert_eq!(with_cache, no_cache);
    assert_eq!(with_cache.0, abi::STATUS_OK);
    assert_eq!(with_cache.1, 4);
    assert_eq!(f64::from_bits(with_cache.2), 10.0);
    assert_eq!(with_cache.3, 0);
}

#[test]
fn reserved_c_lui_zero_immediate_queues_sigill_trace() {
    let mut t = TestVm::new();
    let code_addr = mmap_exec(&mut t, 4096);

    // C.LUI with nzimm=0 is reserved.
    unsafe {
        guest_mem::write_u16(t.base, code_addr, 0x6281);
    }
    tidemark_kernel::harness::signal::clear_debug_trace();

    t.vm.pc = code_addr;
    t.vm.status = abi::STATUS_OK;
    t.vm.sig_mask = 0;
    t.vm.sig_pending = 0;

    unsafe {
        tidemark_kernel::cpu::exec_at_base(&mut t.vm, 10, t.base, None, None, None, None);
    }

    assert_eq!(
        t.vm.status,
        abi::STATUS_FAULT,
        "reserved C.LUI zero-immediate encoding should fault via SIGILL"
    );
    assert_eq!(
        t.vm.exit_code,
        128 + abi::SIGILL,
        "exit_code should be 128 + SIGILL"
    );
    let (vm_ptr, pc, raw) = tidemark_kernel::harness::signal::last_illegal_instruction();
    assert_ne!(vm_ptr, 0, "SIGILL trace should record the trapping VM");
    assert_eq!(pc, code_addr);
    assert_eq!(raw, 0x6281);
}

#[test]
fn cached_exec_falls_back_to_sigill_for_reserved_c_lui_zero_immediate() {
    let mut t = TestVm::new();
    let code_addr = mmap_exec(&mut t, 4096);
    let mut cache = alloc_block_cache();

    unsafe {
        guest_mem::write_u16(t.base, code_addr, 0x6281);
    }
    tidemark_kernel::harness::signal::clear_debug_trace();

    t.vm.pc = code_addr;
    t.vm.status = abi::STATUS_OK;
    t.vm.sig_mask = 0;
    t.vm.sig_pending = 0;

    unsafe {
        tidemark_kernel::cpu::exec_at_base(
            &mut t.vm,
            10,
            t.base,
            Some(&mut cache),
            None,
            None,
            None,
        );
    }

    assert_eq!(
        t.vm.status,
        abi::STATUS_FAULT,
        "cached entry path should fall back and fault via SIGILL"
    );
    assert_eq!(
        t.vm.exit_code,
        128 + abi::SIGILL,
        "exit_code should be 128 + SIGILL"
    );
    let (vm_ptr, pc, raw) = tidemark_kernel::harness::signal::last_illegal_instruction();
    assert_ne!(vm_ptr, 0, "SIGILL trace should record the trapping VM");
    assert_eq!(pc, code_addr);
    assert_eq!(raw, 0x6281);
}

#[test]
fn cached_exec_preserves_same_block_compressed_sd_ld_dependency() {
    let mut t = TestVm::new();
    let code_addr = mmap_exec(&mut t, 4096);
    let mut cache = alloc_block_cache();
    let scope = code_addr + 0x100;
    let list = code_addr + 0x200;
    let sentinel = 0x1122_3344_5566_7788;

    unsafe {
        guest_mem::write_u16(t.base, code_addr, 0xf09c); // c.sd a5,32(s1)
        guest_mem::write_u16(t.base, code_addr + 2, 0x709c); // c.ld a5,32(s1)
        guest_mem::write_u32(t.base, code_addr + 4, 0x0187_8793); // addi a5,a5,24
        guest_mem::write_u32(t.base, code_addr + 8, 0x0007_b023); // sd zero,0(a5)
        guest_mem::write_u64(t.base, scope + 32, 0);
        guest_mem::write_u64(t.base, list + 24, sentinel);
    }

    t.vm.pc = code_addr;
    t.vm.x[9] = scope; // s1
    t.vm.x[15] = list; // a5
    t.vm.status = abi::STATUS_OK;

    unsafe {
        tidemark_kernel::cpu::exec_at_base(
            &mut t.vm,
            4,
            t.base,
            Some(&mut cache),
            None,
            None,
            None,
        );
    }

    assert_eq!(t.vm.status, abi::STATUS_OK);
    assert_eq!(t.vm.pc, code_addr + 12);
    assert_eq!(unsafe { guest_mem::read_u64(t.base, scope + 32) }, list);
    assert_eq!(unsafe { guest_mem::read_u64(t.base, list + 24) }, 0);
}

#[test]
fn read_only_csr_write_queues_sigill_trace() {
    let mut t = TestVm::new();
    let code_addr = mmap_exec(&mut t, 4096);

    // HotSpot RISC-V stop instruction: csrrw x0, time, x0.
    unsafe {
        guest_mem::write_u32(t.base, code_addr, 0xc010_1073);
    }
    tidemark_kernel::harness::signal::clear_debug_trace();

    t.vm.pc = code_addr;
    t.vm.status = abi::STATUS_OK;
    t.vm.sig_mask = 0;
    t.vm.sig_pending = 0;

    unsafe {
        tidemark_kernel::cpu::exec_at_base(&mut t.vm, 10, t.base, None, None, None, None);
    }

    assert_eq!(
        t.vm.status,
        abi::STATUS_FAULT,
        "read-only CSR write should fault via SIGILL"
    );
    assert_eq!(
        t.vm.exit_code,
        128 + abi::SIGILL,
        "exit_code should be 128 + SIGILL"
    );
    let (vm_ptr, pc, raw) = tidemark_kernel::harness::signal::last_illegal_instruction();
    assert_ne!(vm_ptr, 0, "SIGILL trace should record the trapping VM");
    assert_eq!(pc, code_addr);
    assert_eq!(raw, 0xc010_1073);
}

#[test]
fn read_only_csr_read_advances_without_sigill() {
    let mut t = TestVm::new();
    let code_addr = mmap_exec(&mut t, 4096);

    // csrrs t0, time, x0 reads the read-only CSR without requesting a write.
    unsafe {
        guest_mem::write_u32(t.base, code_addr, 0xc010_22f3);
    }

    t.vm.pc = code_addr;
    t.vm.x[5] = 0xffff;
    t.vm.status = abi::STATUS_OK;

    unsafe {
        tidemark_kernel::cpu::exec_at_base(&mut t.vm, 1, t.base, None, None, None, None);
    }

    assert_eq!(t.vm.status, abi::STATUS_OK);
    assert_eq!(t.vm.pc, code_addr + 4);
    assert_eq!(t.vm.x[5], 0);
}

#[test]
fn cached_exec_falls_back_to_sigill_for_read_only_csr_write() {
    let mut t = TestVm::new();
    let code_addr = mmap_exec(&mut t, 4096);
    let mut cache = alloc_block_cache();

    unsafe {
        guest_mem::write_u32(t.base, code_addr, 0xc010_1073);
    }
    tidemark_kernel::harness::signal::clear_debug_trace();

    t.vm.pc = code_addr;
    t.vm.status = abi::STATUS_OK;
    t.vm.sig_mask = 0;
    t.vm.sig_pending = 0;

    unsafe {
        tidemark_kernel::cpu::exec_at_base(
            &mut t.vm,
            10,
            t.base,
            Some(&mut cache),
            None,
            None,
            None,
        );
    }

    assert_eq!(
        t.vm.status,
        abi::STATUS_FAULT,
        "cached entry path should fall back and fault via SIGILL"
    );
    assert_eq!(
        t.vm.exit_code,
        128 + abi::SIGILL,
        "exit_code should be 128 + SIGILL"
    );
    let (vm_ptr, pc, raw) = tidemark_kernel::harness::signal::last_illegal_instruction();
    assert_ne!(vm_ptr, 0, "SIGILL trace should record the trapping VM");
    assert_eq!(pc, code_addr);
    assert_eq!(raw, 0xc010_1073);
}

#[test]
fn cached_exec_matches_interpreter_for_ialign2_jalr_target() {
    fn run(use_cache: bool) -> (i32, u64, u64, u64) {
        let mut t = TestVm::new();
        if use_cache {
            t.vm.block_cache_ptr = alloc_block_cache_ptr();
        }
        let code = mmap_exec(&mut t, 4096);
        let start = code + 2;
        let target = code + 0x20;
        unsafe {
            // addi t2, zero, 3; jalr ra, t0, 1.
            // RVC relaxes IALIGN to 2 bytes, and JALR must clear the low target bit.
            guest_mem::write_u16(t.base, code, 0x0001);
            guest_mem::write_u32(t.base, start, 0x0030_0393);
            guest_mem::write_u32(t.base, start + 4, 0x0012_80e7);
            // addi t1, zero, 7
            guest_mem::write_u32(t.base, target, 0x0070_0313);
        }
        t.vm.pc = start;
        t.vm.x[5] = target;
        t.vm.status = abi::STATUS_OK;

        let remaining = if use_cache {
            tidemark_kernel::abi::thread_step(&mut t.vm as *mut _ as u32, 3)
        } else {
            unsafe {
                tidemark_kernel::cpu::exec_at_base(&mut t.vm, 3, t.base, None, None, None, None)
            }
        };
        assert_eq!(
            remaining, 0,
            "use_cache={use_cache} status={} pc=0x{:x} fault_addr=0x{:x}",
            t.vm.status, t.vm.pc, t.vm.fault_addr
        );
        (t.vm.status, t.vm.pc - code, t.vm.x[1] - code, t.vm.x[6])
    }

    let no_cache = run(false);
    let with_cache = run(true);
    assert_eq!(with_cache, no_cache);
    assert_eq!(with_cache.0, abi::STATUS_OK);
    assert_eq!(with_cache.1, 0x24);
    assert_eq!(with_cache.2, 10);
    assert_eq!(with_cache.3, 7);
}

#[test]
fn cached_exec_matches_interpreter_for_ialign2_32bit_branch_fallthrough() {
    fn run(use_cache: bool) -> (i32, u64, u64) {
        let mut t = TestVm::new();
        if use_cache {
            t.vm.block_cache_ptr = alloc_block_cache_ptr();
        }
        let code = mmap_exec(&mut t, 4096);
        let start = code + 2;

        unsafe {
            guest_mem::write_u16(t.base, code, 0x0001);
            // bge a3,a4,+152. At an IALIGN=2 PC, non-taken fallthrough must
            // still advance by the 32-bit instruction length.
            guest_mem::write_u32(t.base, start, 0x08e6_dc63);
            guest_mem::write_u32(t.base, start + 4, 0x00b0_0313); // addi t1,zero,11
        }

        t.vm.pc = start;
        t.vm.x[13] = 1;
        t.vm.x[14] = 2;
        t.vm.status = abi::STATUS_OK;

        let remaining = if use_cache {
            tidemark_kernel::abi::thread_step(&mut t.vm as *mut _ as u32, 2)
        } else {
            unsafe {
                tidemark_kernel::cpu::exec_at_base(&mut t.vm, 2, t.base, None, None, None, None)
            }
        };
        assert_eq!(
            remaining, 0,
            "use_cache={use_cache} status={} pc=0x{:x} fault_pc=0x{:x}",
            t.vm.status, t.vm.pc, t.vm.fault_pc
        );
        (t.vm.status, t.vm.pc - code, t.vm.x[6])
    }

    let no_cache = run(false);
    let with_cache = run(true);
    assert_eq!(with_cache, no_cache);
    assert_eq!(with_cache.0, abi::STATUS_OK);
    assert_eq!(with_cache.1, 10);
    assert_eq!(with_cache.2, 11);
}

#[test]
fn cached_exec_treats_x0_as_zero_for_ialign2_bnez_and_preserves_s11() {
    fn run(use_cache: bool) -> (i32, u64, u64, u64) {
        let mut t = TestVm::new();
        if use_cache {
            t.vm.block_cache_ptr = alloc_block_cache_ptr();
        }
        let code = mmap_exec(&mut t, 4096);
        let start = code + 2;

        unsafe {
            guest_mem::write_u16(t.base, code, 0x0001);
            // bnez a5,+0x4de at a halfword-aligned PC.
            guest_mem::write_u32(t.base, start, 0x4c07_9f63);
            guest_mem::write_u32(t.base, start + 4, 0x02a0_0313); // addi t1,zero,42
            guest_mem::write_u32(t.base, start + 0x4de, 0x0630_0313); // addi t1,zero,99
        }

        t.vm.pc = start;
        t.vm.x[0] = 0x1256;
        t.vm.x[15] = 0;
        t.vm.x[27] = 0x0a46_67e8;
        t.vm.status = abi::STATUS_OK;

        let remaining = if use_cache {
            tidemark_kernel::abi::thread_step(&mut t.vm as *mut _ as u32, 1)
        } else {
            unsafe {
                tidemark_kernel::cpu::exec_at_base(&mut t.vm, 1, t.base, None, None, None, None)
            }
        };
        assert_eq!(
            remaining, 0,
            "use_cache={use_cache} status={} pc=0x{:x}",
            t.vm.status, t.vm.pc
        );
        (t.vm.status, t.vm.pc - code, t.vm.x[0], t.vm.x[27])
    }

    let no_cache = run(false);
    let with_cache = run(true);
    assert_eq!(with_cache, no_cache);
    assert_eq!(with_cache.0, abi::STATUS_OK);
    assert_eq!(with_cache.1, 6);
    assert_eq!(with_cache.2, 0);
    assert_eq!(with_cache.3, 0x0a46_67e8);
}

#[test]
fn cached_data_fault_reports_faulting_op_pc() {
    let mut t = TestVm::new();
    let code_addr = mmap_exec(&mut t, 4096);
    let mut cache = alloc_block_cache();
    let bad_addr = code_addr + 0x2000;

    unsafe {
        guest_mem::write_u32(t.base, code_addr, 0x0010_0313); // addi x6, x0, 1
        guest_mem::write_u32(t.base, code_addr + 4, 0x0002_b383); // ld x7, 0(x5)
    }

    t.vm.pc = code_addr;
    t.vm.x[5] = bad_addr;
    t.vm.status = abi::STATUS_OK;
    t.vm.sig_mask = 0;
    t.vm.sig_pending = 0;

    unsafe {
        tidemark_kernel::cpu::exec_at_base(
            &mut t.vm,
            10,
            t.base,
            Some(&mut cache),
            None,
            None,
            None,
        );
    }

    assert_eq!(t.vm.status, abi::STATUS_FAULT);
    assert_eq!(t.vm.exit_code, 128 + abi::SIGSEGV);
    assert_eq!(t.vm.term_signal, abi::SIGSEGV);
    assert_eq!(t.vm.fault_pc, code_addr + 4);
    assert_eq!(t.vm.fault_addr, bad_addr);
    assert_eq!(t.vm.fault_kind, abi::FAULT_KIND_GUEST_MAPERR);
}

#[test]
fn cached_exec_matches_interpreter_for_nested_clone_return_epilogues() {
    fn run(use_cache: bool) -> (i32, u64, u64, u64, u64, u64) {
        let mut t = TestVm::new();
        if use_cache {
            t.vm.block_cache_ptr = alloc_block_cache_ptr();
        }
        let code = mmap_exec(&mut t, 4096);
        let clone_ret = code + 0x100;
        let inner_epilogue = code + 0x140;
        let outer_after_call = code + 0x1a8;
        let outer_epilogue = code + 0x1bc;
        let caller_after_clone = code + 0x2f4;
        let inner_sp = t.scratch + 0x4000;
        let outer_sp = inner_sp + 16;
        let final_sp = outer_sp + 48;

        unsafe {
            // Raw clone parent return: ret to the inner wrapper.
            guest_mem::write_u32(t.base, clone_ret, 0x0000_8067); // ret

            // Inner wrapper epilogue: restore ra/s0, pop 16, ret.
            guest_mem::write_u32(t.base, inner_epilogue, 0x0081_3083); // ld ra,8(sp)
            guest_mem::write_u32(t.base, inner_epilogue + 4, 0x0001_3403); // ld s0,0(sp)
            guest_mem::write_u32(t.base, inner_epilogue + 8, 0x0101_0113); // addi sp,sp,16
            guest_mem::write_u32(t.base, inner_epilogue + 12, 0x0000_8067); // ret

            // Outer wrapper resumes after its inner call, then restores caller state.
            guest_mem::write_u32(t.base, outer_after_call, 0xfff0_0793); // addi a5,zero,-1
            guest_mem::write_u32(t.base, outer_after_call + 4, 0x00f5_1863); // bne a0,a5,+16
            guest_mem::write_u32(t.base, outer_epilogue, 0x0281_3083); // ld ra,40(sp)
            guest_mem::write_u32(t.base, outer_epilogue + 4, 0x0201_3403); // ld s0,32(sp)
            guest_mem::write_u32(t.base, outer_epilogue + 8, 0x0181_3483); // ld s1,24(sp)
            guest_mem::write_u32(t.base, outer_epilogue + 12, 0x0101_3903); // ld s2,16(sp)
            guest_mem::write_u32(t.base, outer_epilogue + 16, 0x0081_3983); // ld s3,8(sp)
            guest_mem::write_u32(t.base, outer_epilogue + 20, 0x0001_3a03); // ld s4,0(sp)
            guest_mem::write_u32(t.base, outer_epilogue + 24, 0x0301_0113); // addi sp,sp,48
            guest_mem::write_u32(t.base, outer_epilogue + 28, 0x0000_8067); // ret

            // Caller continuation after the clone wrapper returns.
            guest_mem::write_u32(t.base, caller_after_clone, 0x0550_0313); // addi t1,zero,85

            guest_mem::write_u64(t.base, inner_sp, 0x1111);
            guest_mem::write_u64(t.base, inner_sp + 8, outer_after_call);
            guest_mem::write_u64(t.base, outer_sp, 0x2222);
            guest_mem::write_u64(t.base, outer_sp + 8, 0x3333);
            guest_mem::write_u64(t.base, outer_sp + 16, 0x4444);
            guest_mem::write_u64(t.base, outer_sp + 24, 0x5555);
            guest_mem::write_u64(t.base, outer_sp + 32, 0x6666);
            guest_mem::write_u64(t.base, outer_sp + 40, caller_after_clone);
        }

        t.vm.pc = clone_ret;
        t.vm.x[1] = inner_epilogue;
        t.vm.x[2] = inner_sp;
        t.vm.x[10] = 3;
        t.vm.status = abi::STATUS_OK;

        let remaining = if use_cache {
            tidemark_kernel::abi::thread_step(&mut t.vm as *mut _ as u32, 16)
        } else {
            unsafe {
                tidemark_kernel::cpu::exec_at_base(&mut t.vm, 16, t.base, None, None, None, None)
            }
        };
        assert_eq!(
            remaining, 0,
            "use_cache={use_cache} status={} pc=0x{:x} ra=0x{:x} sp=0x{:x}",
            t.vm.status, t.vm.pc, t.vm.x[1], t.vm.x[2]
        );
        (
            t.vm.status,
            t.vm.pc - code,
            t.vm.x[1] - code,
            t.vm.x[2] - final_sp,
            t.vm.x[6],
            t.vm.x[10],
        )
    }

    let no_cache = run(false);
    let with_cache = run(true);
    assert_eq!(with_cache, no_cache);
    assert_eq!(with_cache.0, abi::STATUS_OK);
    assert_eq!(with_cache.1, 0x2f8);
    assert_eq!(with_cache.2, 0x2f4);
    assert_eq!(with_cache.3, 0);
    assert_eq!(with_cache.4, 85);
    assert_eq!(with_cache.5, 3);
}

#[test]
fn cached_exec_matches_interpreter_for_compressed_clone_return_epilogues() {
    fn run(use_cache: bool) -> (i32, u64, u64, u64, u64, u64) {
        let mut t = TestVm::new();
        if use_cache {
            t.vm.block_cache_ptr = alloc_block_cache_ptr();
        }
        let code = mmap_exec(&mut t, 4096);
        let clone_ret = code + 0x100;
        let inner_after_call = code + 0x140;
        let inner_epilogue = inner_after_call + 0x6;
        let outer_after_call = code + 0x1a8;
        let outer_epilogue = code + 0x1bc;
        let caller_after_clone = code + 0x2f4;
        let inner_sp = t.scratch + 0x4000;
        let outer_sp = inner_sp + 16;
        let final_sp = outer_sp + 48;

        unsafe {
            // Raw clone parent return: compressed ret to the inner helper.
            guest_mem::write_u16(t.base, clone_ret, 0x8082); // ret

            // Inner helper after-call and compressed epilogue.
            guest_mem::write_u16(t.base, inner_after_call, 0x57fd); // li a5,-1
            guest_mem::write_u32(t.base, inner_after_call + 2, 0x00f5_0663); // beq a0,a5,+12
            guest_mem::write_u16(t.base, inner_epilogue, 0x60a2); // c.ldsp ra,8(sp)
            guest_mem::write_u16(t.base, inner_epilogue + 2, 0x6402); // c.ldsp s0,0(sp)
            guest_mem::write_u16(t.base, inner_epilogue + 4, 0x0141); // c.addi sp,16
            guest_mem::write_u16(t.base, inner_epilogue + 6, 0x8082); // ret

            // Outer wrapper after-call and compressed epilogue.
            guest_mem::write_u16(t.base, outer_after_call, 0x57fd); // li a5,-1
            guest_mem::write_u32(t.base, outer_after_call + 2, 0x00f5_1963); // bne a0,a5,+18
            guest_mem::write_u16(t.base, outer_epilogue, 0x70a2); // c.ldsp ra,40(sp)
            guest_mem::write_u16(t.base, outer_epilogue + 2, 0x7402); // c.ldsp s0,32(sp)
            guest_mem::write_u16(t.base, outer_epilogue + 4, 0x64e2); // c.ldsp s1,24(sp)
            guest_mem::write_u16(t.base, outer_epilogue + 6, 0x6942); // c.ldsp s2,16(sp)
            guest_mem::write_u16(t.base, outer_epilogue + 8, 0x69a2); // c.ldsp s3,8(sp)
            guest_mem::write_u16(t.base, outer_epilogue + 10, 0x6a02); // c.ldsp s4,0(sp)
            guest_mem::write_u16(t.base, outer_epilogue + 12, 0x6145); // c.addi sp,48
            guest_mem::write_u16(t.base, outer_epilogue + 14, 0x8082); // ret

            // Caller continuation after the clone wrapper returns.
            guest_mem::write_u32(t.base, caller_after_clone, 0x0550_0313); // addi t1,zero,85

            guest_mem::write_u64(t.base, inner_sp, 0x1111);
            guest_mem::write_u64(t.base, inner_sp + 8, outer_after_call);
            guest_mem::write_u64(t.base, outer_sp, 0x2222);
            guest_mem::write_u64(t.base, outer_sp + 8, 0x3333);
            guest_mem::write_u64(t.base, outer_sp + 16, 0x4444);
            guest_mem::write_u64(t.base, outer_sp + 24, 0x5555);
            guest_mem::write_u64(t.base, outer_sp + 32, 0x6666);
            guest_mem::write_u64(t.base, outer_sp + 40, caller_after_clone);
        }

        t.vm.pc = clone_ret;
        t.vm.x[1] = inner_after_call;
        t.vm.x[2] = inner_sp;
        t.vm.x[10] = 3;
        t.vm.status = abi::STATUS_OK;

        let remaining = if use_cache {
            tidemark_kernel::abi::thread_step(&mut t.vm as *mut _ as u32, 18)
        } else {
            unsafe {
                tidemark_kernel::cpu::exec_at_base(&mut t.vm, 18, t.base, None, None, None, None)
            }
        };
        assert_eq!(
            remaining, 0,
            "use_cache={use_cache} status={} pc=0x{:x} ra=0x{:x} sp=0x{:x}",
            t.vm.status, t.vm.pc, t.vm.x[1], t.vm.x[2]
        );
        (
            t.vm.status,
            t.vm.pc - code,
            t.vm.x[1] - code,
            t.vm.x[2] - final_sp,
            t.vm.x[6],
            t.vm.x[10],
        )
    }

    let no_cache = run(false);
    let with_cache = run(true);
    assert_eq!(with_cache, no_cache);
    assert_eq!(with_cache.0, abi::STATUS_OK);
    assert_eq!(with_cache.1, 0x2f8);
    assert_eq!(with_cache.2, 0x2f4);
    assert_eq!(with_cache.3, 0);
    assert_eq!(with_cache.4, 85);
    assert_eq!(with_cache.5, 3);
}

#[test]
fn cached_exec_revalidates_pc_tags_after_index_collision() {
    let mut t = TestVm::new();
    let mut cache = alloc_block_cache();
    let collision_stride = tidemark_kernel::cpu::block_cache::CACHE_SIZE as u64 * 2;
    let code = mmap_exec(&mut t, collision_stride + 4096);
    let pc_a = code;
    let pc_b = code + collision_stride;

    unsafe {
        // addi a0, zero, 11
        guest_mem::write_u32(t.base, pc_a, 0x00b0_0513);
        // addi a0, zero, 22
        guest_mem::write_u32(t.base, pc_b, 0x0160_0513);
    }

    for (pc, expected) in [(pc_a, 11), (pc_b, 22), (pc_a, 11)] {
        t.vm.pc = pc;
        t.vm.x[10] = 0;
        t.vm.status = abi::STATUS_OK;

        let remaining = unsafe {
            tidemark_kernel::cpu::exec_at_base(
                &mut t.vm,
                1,
                t.base,
                Some(&mut cache),
                None,
                None,
                None,
            )
        };
        assert_eq!(remaining, 0);
        assert_eq!(t.vm.status, abi::STATUS_OK);
        assert_eq!(t.vm.pc, pc + 4);
        assert_eq!(t.vm.x[10], expected);
    }
}
