use tidemark_kernel::cpu::block_cache::{BlockCache, BlockEntry, PackedOp};
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
