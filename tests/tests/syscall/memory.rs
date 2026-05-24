use tidemark_kernel::abi::*;
use tidemark_kernel::fs::memfs;
use tidemark_kernel::harness::TestVm;
use tidemark_kernel::syscall::memory;
use tidemark_kernel::types::ProcessState;

fn encode_i(opcode: u32, rd: u32, funct3: u32, rs1: u32, imm: i32) -> u32 {
    (((imm as u32) & 0x0fff) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
}

fn encode_s(opcode: u32, funct3: u32, rs1: u32, rs2: u32, imm: i32) -> u32 {
    let imm = imm as u32;
    ((imm & 0x0fe0) << 20)
        | (rs2 << 20)
        | (rs1 << 15)
        | (funct3 << 12)
        | ((imm & 0x001f) << 7)
        | opcode
}

fn encode_u(opcode: u32, rd: u32, imm20: u32) -> u32 {
    (imm20 << 12) | (rd << 7) | opcode
}

fn encode_li(rd: u32, value: u32) -> [u32; 2] {
    let upper = (value.wrapping_add(0x800)) >> 12;
    let lower = value.wrapping_sub(upper << 12) as i32;
    [encode_u(0x37, rd, upper), encode_i(0x13, rd, 0, rd, lower)]
}

#[test]
fn memory_syscalls() {
    let mut t = TestVm::new();

    let cur = t.sys_brk(0);
    assert!(cur > 0);

    let new_brk = cur as u64 + 4096;
    assert_eq!(t.sys_brk(new_brk), new_brk as i64);

    let addr = t.sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0,
    );
    assert!(
        addr > 0,
        "mmap should return positive address, got {}",
        addr
    );

    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, addr as u64, 0xDEADBEEF);
        assert_eq!(
            tidemark_kernel::guest_mem::read_u64(t.base, addr as u64),
            0xDEADBEEF
        );
    }

    assert_eq!(t.sys_munmap(addr as u64, 4096), 0);

    let addr2 = t.sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0,
    );
    assert!(addr2 > 0);
    assert_eq!(t.sys_mprotect(addr2 as u64, 4096, PROT_READ), 0);
    assert_eq!(t.sys_mprotect(addr2 as u64, 4096, PROT_NONE), 0);
    assert!(memory::has_prot_none());
    t.sys_munmap(addr2 as u64, 4096);
}

#[test]
fn vmas_are_sorted_after_multiple_mmaps() {
    let mut t = TestVm::new();
    let a1 = t.sys_mmap(0, 4096, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    let a2 = t.sys_mmap(0, 4096, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    let a3 = t.sys_mmap(0, 4096, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    assert!(a1 > 0 && a2 > 0 && a3 > 0);
    assert!((a1 as u64) + PAGE_SIZE <= a2 as u64);
    assert!((a2 as u64) + PAGE_SIZE <= a3 as u64);
    t.sys_munmap(a1 as u64, 4096);
    t.sys_munmap(a2 as u64, 4096);
    t.sys_munmap(a3 as u64, 4096);
}

#[test]
fn map_fixed_replaces_existing_vma() {
    let mut t = TestVm::new();
    let a = t.sys_mmap(
        0,
        8192,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0,
    );
    assert!(a > 0);

    let a2 = t.sys_mmap(
        a as u64,
        4096,
        PROT_READ,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
        -1,
        0,
    );
    assert_eq!(a2, a);
    t.sys_munmap(a as u64, 8192);
}

#[test]
fn map_fixed_noreplace_maps_exact_addr_without_clobbering_existing_vma() {
    let mut t = TestVm::new();
    let addr = 0x40_0000u64;
    let first = t.sys_mmap(
        addr,
        PAGE_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE,
        -1,
        0,
    );
    assert_eq!(first as u64, addr);

    let second = t.sys_mmap(
        addr,
        PAGE_SIZE,
        PROT_READ,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE,
        -1,
        0,
    );
    assert_eq!(second, EEXIST as i64);

    let elsewhere = t.sys_mmap(0, PAGE_SIZE, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    assert!(elsewhere > 0);
    assert_ne!(elsewhere as u64, addr);

    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, addr, 0x1122_3344);
        assert_eq!(
            tidemark_kernel::guest_mem::read_u32(t.base, addr),
            0x1122_3344
        );
    }
}

#[test]
fn syscall_dispatch_discards_private_anonymous_pages_for_madvise_dontneed() {
    let mut t = TestVm::new();
    let mapped = t.sys_mmap(
        0,
        PAGE_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0,
    );
    assert!(mapped > 0);

    t.write_mem(mapped as u64, b"madvise-keeps-mapping");
    t.vm.x[10] = mapped as u64;
    t.vm.x[11] = PAGE_SIZE;
    t.vm.x[12] = MADV_DONTNEED as u64;
    t.vm.x[17] = SYS_MADVISE;
    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
        STATUS_OK
    );
    assert_eq!(t.vm.x[10] as i64, 0);
    assert!(t.guest_mem(mapped as u64, 32).iter().all(|byte| *byte == 0));
}

#[test]
fn madvise_dontneed_reloads_file_backed_mapping_from_memfs() {
    let mut t = TestVm::new();
    let data = b"0123456789abcdef";
    t.memfs.create_file(b"madvise.bin", data);
    let fd = t.sys_openat(b"/madvise.bin", O_RDONLY);
    assert!(fd >= 3);

    let mapped = t.sys_mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    assert!(mapped > 0);
    t.write_mem(mapped as u64, b"XXXXXXXXXXXXXXXX");

    assert_eq!(t.sys_madvise(mapped as u64, PAGE_SIZE, MADV_DONTNEED), 0);
    assert_eq!(&t.guest_mem(mapped as u64, data.len())[..], data);
}

#[test]
fn madvise_free_rejects_file_backed_ranges() {
    let mut t = TestVm::new();
    t.memfs.create_file(b"madvise-free.bin", b"payload");
    let fd = t.sys_openat(b"/madvise-free.bin", O_RDONLY);
    assert!(fd >= 3);

    let mapped = t.sys_mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    assert!(mapped > 0);
    assert_eq!(
        t.sys_madvise(mapped as u64, PAGE_SIZE, MADV_FREE),
        EINVAL as i64
    );
}

#[test]
fn madvise_dontfork_and_dofork_are_accepted_as_advisory_noops() {
    let mut t = TestVm::new();
    let mapped = t.sys_mmap(
        0,
        PAGE_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0,
    );
    assert!(mapped > 0);

    t.write_mem(mapped as u64, b"fork-advice");
    assert_eq!(t.sys_madvise(mapped as u64, PAGE_SIZE, MADV_DONTFORK), 0);
    assert_eq!(t.sys_madvise(mapped as u64, PAGE_SIZE, MADV_DOFORK), 0);
    assert_eq!(&t.guest_mem(mapped as u64, 11)[..], b"fork-advice");
}

#[test]
fn fixed_high_commit_within_sparse_prot_none_reservation_can_skip_linear_materialization() {
    let mut t = TestVm::new();
    let fake_base = 0x23e0_0000u32;
    t.vm.guest_ram_limit = 0xd820_0000u32;

    let reserve_addr = 0xf820_0000u64;
    let reserve_len = 0x07e0_0000u64;
    let reserve = memory::sys_mmap(
        &mut t.vm,
        fake_base,
        reserve_addr,
        reserve_len,
        PROT_NONE as u64,
        (MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE | MAP_NORESERVE) as u64,
        -1,
        0,
    );
    assert_eq!(reserve as u64, reserve_addr);

    let before = core::arch::wasm32::memory_size(0);
    let commit_len = 0x002a_0000u64;
    let commit = memory::sys_mmap(
        &mut t.vm,
        fake_base,
        reserve_addr,
        commit_len,
        (PROT_READ | PROT_WRITE) as u64,
        (MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED) as u64,
        -1,
        0,
    );
    let after = core::arch::wasm32::memory_size(0);

    assert_eq!(commit as u64, reserve_addr);
    assert_eq!(before, after);

    let maps = String::from_utf8(memory::proc_self_maps_snapshot()).expect("utf8 maps");
    assert!(maps.contains("f8200000-f84a0000 rw-p"));
    assert!(maps.contains("f84a0000-100000000 ---p"));
}

#[test]
fn map_fixed_noreplace_above_guest_limit_fails_instead_of_falling_back() {
    let mut t = TestVm::new();
    t.vm.guest_ram_limit = 0x7fff_ffff;

    let ret = t.sys_mmap(
        0x1_0000_0000,
        0x7e0_0000,
        PROT_NONE,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE | MAP_FIXED_NOREPLACE,
        -1,
        0,
    );

    assert_eq!(ret, ENOMEM as i64);

    let fallback = t.sys_mmap(0, PAGE_SIZE, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    assert!(fallback > 0);
    assert!((fallback as u64) < 0x1000_0000);
}

#[test]
fn map_fixed_noreplace_above_2gb_succeeds_when_guest_window_allows_it() {
    let mut t = TestVm::new();
    t.vm.guest_ram_limit = tidemark_kernel::abi::max_guest_window_for_base(t.base) as u32;
    let addr = 0x8900_0000u64;
    let len = 0x1000u64;

    let mapped = t.sys_mmap(
        addr,
        len,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE,
        -1,
        0,
    );

    assert_eq!(mapped as u64, addr);
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, addr, 0x5566_7788);
        assert_eq!(
            tidemark_kernel::guest_mem::read_u32(t.base, addr),
            0x5566_7788
        );
    }
}

#[test]
fn map_fixed_noreplace_prot_none_noreserve_can_reserve_up_to_u32_ceiling() {
    let mut t = TestVm::new();
    t.vm.guest_ram_limit = 0xd820_0000;
    let addr = 0xf820_0000u64;
    let len = 0x07e0_0000u64;
    let before_pages = core::arch::wasm32::memory_size(0);

    let mapped = t.sys_mmap(
        addr,
        len,
        PROT_NONE,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE | MAP_FIXED_NOREPLACE,
        -1,
        0,
    );

    assert_eq!(mapped as u64, addr);
    assert_eq!(core::arch::wasm32::memory_size(0), before_pages);
    assert!(memory::is_prot_none(addr));
    assert!(memory::is_prot_none(addr + len - PAGE_SIZE));
}

#[test]
fn munmap_partial_splits_vma() {
    let mut t = TestVm::new();
    let a = t.sys_mmap(
        0,
        0x3000,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0,
    );
    assert!(a > 0);
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, a as u64, 0x1111_1111);
        tidemark_kernel::guest_mem::write_u32(t.base, a as u64 + 0x2000, 0x3333_3333);
    }
    let ret = t.sys_munmap(a as u64 + 0x1000, 0x1000);
    assert_eq!(ret, 0);
    let middle = t.sys_mmap(
        a as u64 + 0x1000,
        0x1000,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
        -1,
        0,
    );
    assert_eq!(middle, a + 0x1000);
    unsafe {
        assert_eq!(
            tidemark_kernel::guest_mem::read_u32(t.base, a as u64),
            0x1111_1111
        );
        assert_eq!(
            tidemark_kernel::guest_mem::read_u32(t.base, a as u64 + 0x2000),
            0x3333_3333
        );
        tidemark_kernel::guest_mem::write_u32(t.base, middle as u64, 0x2222_2222);
        assert_eq!(
            tidemark_kernel::guest_mem::read_u32(t.base, middle as u64),
            0x2222_2222
        );
    }
    t.sys_munmap(a as u64, 0x1000);
    t.sys_munmap(middle as u64, 0x1000);
    t.sys_munmap(a as u64 + 0x2000, 0x1000);
}

#[test]
fn mprotect_split_on_boundary_mismatch() {
    let mut t = TestVm::new();
    let a = t.sys_mmap(
        0,
        0x2000,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0,
    );
    assert!(a > 0);
    assert_eq!(t.sys_mprotect(a as u64, 0x1000, PROT_READ), 0);
    t.sys_munmap(a as u64, 0x2000);
}

#[test]
fn mprotect_rejects_ranges_that_are_not_fully_mapped() {
    let mut t = TestVm::new();
    let a = t.sys_mmap(
        0,
        PAGE_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0,
    );
    assert!(a > 0);

    assert_eq!(
        t.sys_mprotect(a as u64, PAGE_SIZE * 2, PROT_READ),
        ENOMEM,
    );
    assert!(memory::guest_range_permitted(
        &t.vm,
        t.base,
        a as u64,
        8,
        PROT_WRITE,
    ));

    assert_eq!(
        t.sys_mprotect((a as u64) + PAGE_SIZE, PAGE_SIZE, PROT_READ),
        ENOMEM,
    );
    assert_eq!(t.sys_munmap(a as u64, PAGE_SIZE), 0);
}

#[test]
fn permission_cache_is_invalidated_by_address_space_changes() {
    let mut t = TestVm::new();
    let a = t.sys_mmap(
        0,
        PAGE_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0,
    );
    assert!(a > 0);
    assert!(memory::guest_range_permitted(
        &t.vm, t.base, a as u64, 8, PROT_WRITE,
    ));
    assert_eq!(t.sys_mprotect(a as u64, PAGE_SIZE, PROT_READ), 0);
    assert!(!memory::guest_range_permitted(
        &t.vm, t.base, a as u64, 8, PROT_WRITE,
    ));
    assert!(memory::guest_range_permitted(
        &t.vm, t.base, a as u64, 8, PROT_READ,
    ));
    assert_eq!(t.sys_munmap(a as u64, PAGE_SIZE), 0);
    assert!(!memory::guest_range_permitted(
        &t.vm, t.base, a as u64, 8, PROT_READ,
    ));

    let cur = t.sys_brk(0) as u64;
    assert_eq!(t.sys_brk(cur + PAGE_SIZE), (cur + PAGE_SIZE) as i64);
    assert!(memory::guest_range_permitted(
        &t.vm, t.base, cur, 8, PROT_WRITE,
    ));
    assert_eq!(t.sys_brk(cur), cur as i64);
    assert!(!memory::guest_range_permitted(
        &t.vm, t.base, cur, 8, PROT_WRITE,
    ));
}

#[test]
fn brk_refuses_above_current_guest_window() {
    let mut t = TestVm::new();
    let cur = t.sys_brk(0);
    let guest_limit = tidemark_kernel::abi::max_guest_window_for_base(t.base);
    let ret = t.sys_brk(guest_limit + 1);
    assert_eq!(
        ret, cur,
        "brk should refuse addresses above the guest window"
    );
}

#[test]
fn brk_refuses_growth_into_existing_vma() {
    let mut t = TestVm::new();
    let cur = t.sys_brk(0) as u64;
    let map_start = (cur + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let mapped = t.sys_mmap(
        map_start,
        PAGE_SIZE,
        PROT_READ | PROT_EXEC,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
        -1,
        0,
    );
    assert_eq!(mapped, map_start as i64);

    let ret = t.sys_brk(map_start + PAGE_SIZE);
    assert_eq!(ret, cur as i64, "brk should refuse growth into mapped VMA");
    assert_eq!(t.sys_brk(0), cur as i64);
}

#[test]
fn instruction_fetch_from_brk_heap_requires_prot_exec() {
    let mut t = TestVm::new();
    let heap_pc = t.sys_brk(0) as u64;
    assert_eq!(t.sys_brk(heap_pc + 4), (heap_pc + 4) as i64);

    // addi a0, zero, 42
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, heap_pc, 0x02a0_0513);
    }

    t.vm.pc = heap_pc;
    t.vm.status = STATUS_OK;
    t.vm.sig_mask = 0;
    t.vm.sig_pending = 0;

    unsafe {
        tidemark_kernel::cpu::exec(&mut t.vm, 1, None, None, None, None);
    }

    assert_eq!(t.vm.status, STATUS_FAULT);
    assert_eq!(t.vm.exit_code, 128 + SIGSEGV);
    assert_eq!(t.vm.term_signal, SIGSEGV);
    assert_eq!(t.vm.fault_pc, heap_pc);
    assert_eq!(t.vm.fault_addr, heap_pc);
}

#[test]
fn anonymous_exec_mapping_supports_write_protect_execute_and_repatch() {
    let mut t = TestVm::new();
    let code = t.sys_mmap(
        0,
        PAGE_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0,
    );
    assert!(code > 0, "code={code}");
    let code = code as u64;

    unsafe {
        // addi a0, zero, 1
        tidemark_kernel::guest_mem::write_u32(t.base, code, 0x0010_0513);
        // jalr zero, ra, 0
        tidemark_kernel::guest_mem::write_u32(t.base, code + 4, 0x0000_8067);
        // c.nop
        tidemark_kernel::guest_mem::write_u16(t.base, code + 8, 0x0001);
    }

    assert_eq!(t.sys_mprotect(code, PAGE_SIZE, PROT_READ | PROT_EXEC), 0);

    t.vm.pc = code;
    t.vm.x[1] = code + 8;
    t.vm.x[10] = 0;
    t.vm.status = STATUS_OK;
    t.vm.sig_mask = 0;
    t.vm.sig_pending = 0;

    let remaining = tidemark_kernel::abi::thread_step(&mut t.vm as *mut _ as u32, 2);
    assert_eq!(remaining, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, code + 8);
    assert_eq!(t.vm.x[10], 1);

    assert_eq!(t.sys_mprotect(code, PAGE_SIZE, PROT_READ | PROT_WRITE), 0);
    unsafe {
        // addi a0, zero, 42
        tidemark_kernel::guest_mem::write_u32(t.base, code, 0x02a0_0513);
    }
    assert_eq!(
        tidemark_kernel::syscall::identity::sys_riscv_flush_icache(
            &mut t.vm,
            t.base,
            code,
            code + 8,
            0
        ),
        0
    );
    assert_eq!(t.sys_mprotect(code, PAGE_SIZE, PROT_READ | PROT_EXEC), 0);

    t.vm.pc = code;
    t.vm.x[1] = code + 8;
    t.vm.x[10] = 0;
    t.vm.status = STATUS_OK;
    t.vm.sig_mask = 0;
    t.vm.sig_pending = 0;

    let remaining = tidemark_kernel::abi::thread_step(&mut t.vm as *mut _ as u32, 2);
    assert_eq!(remaining, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, code + 8);
    assert_eq!(t.vm.x[10], 42);
}

#[test]
fn mmap_rejects_invalid_fd_for_file_backed() {
    let mut t = TestVm::new();
    let ret = t.sys_mmap(0, 4096, PROT_READ, MAP_PRIVATE, -1, 0);
    assert_eq!(ret, EBADF as i64);
}

#[test]
fn file_backed_mmap_preserves_bytes_for_offset_executable_mapping() {
    let mut t = TestVm::new();
    let data: Vec<u8> = (0..0x5000).map(|idx| ((idx * 17) % 251) as u8).collect();
    let ino = memfs::create_file(1, b"mapped-exec.bin", 0o755);
    assert!(ino > 0);
    assert_eq!(memfs::write_file(ino, 0, &data), data.len() as i64);

    let fd = t.sys_openat(b"/mapped-exec.bin", O_RDONLY);
    assert!(fd >= 3);

    let offset = 0x1000u64;
    let len = 0x2000u64;
    let mapped = t.sys_mmap(0, len, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, offset);
    assert!(mapped > 0, "mapped={mapped}");
    assert_eq!(
        &t.guest_mem(mapped as u64, len as usize),
        &data[offset as usize..(offset + len) as usize],
    );
}

#[test]
fn file_backed_mmap_zero_fills_tail_after_eof_with_offset() {
    let mut t = TestVm::new();
    let data: Vec<u8> = (0..5000).map(|idx| ((idx * 29) % 251) as u8).collect();
    let ino = memfs::create_file(1, b"mapped-tail.bin", 0o644);
    assert!(ino > 0);
    assert_eq!(memfs::write_file(ino, 0, &data), data.len() as i64);

    let fd = t.sys_openat(b"/mapped-tail.bin", O_RDONLY);
    assert!(fd >= 3);

    let offset = 4096u64;
    let len = 4096u64;
    let mapped = t.sys_mmap(0, len, PROT_READ, MAP_PRIVATE, fd, offset);
    assert!(mapped > 0, "mapped={mapped}");

    const FILE_REMAINDER: usize = 5000 - 4096;
    let mapped_bytes = t.guest_mem(mapped as u64, len as usize);
    assert_eq!(&mapped_bytes[..FILE_REMAINDER], &data[4096..]);
    assert!(mapped_bytes[FILE_REMAINDER..].iter().all(|byte| *byte == 0));
}

#[test]
fn prot_none_reservation_does_not_grow_linear_memory() {
    let mut t = TestVm::new();
    let before = core::arch::wasm32::memory_size(0);
    let addr = t.sys_mmap(
        0,
        128 * 1024 * 1024,
        PROT_NONE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0,
    );
    let after = core::arch::wasm32::memory_size(0);

    assert!(addr > 0);
    assert_eq!(before, after);
    assert!(memory::has_prot_none());
}

#[test]
fn guest_ram_limit_caps_high_prot_none_reservations() {
    let mut t = TestVm::new();
    let guest_limit = 0x6000_0000u64;
    t.vm.guest_ram_limit = guest_limit as u32;
    let len = 128 * 1024 * 1024;

    let addr = t.sys_mmap(0, len, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    assert!(addr > 0, "addr={addr}");
    assert!(
        (addr as u64) + len <= guest_limit,
        "addr=0x{:x} len=0x{:x} guest_limit=0x{:x}",
        addr,
        len,
        guest_limit,
    );
}

#[test]
fn prot_none_reservations_stay_within_linux_shaped_topdown_window() {
    let mut t = TestVm::new();
    t.vm.guest_ram_limit = 0xd820_0000u32;
    let len = 128 * 1024 * 1024;

    let addr = t.sys_mmap(0, len, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    assert!(addr > 0, "addr={addr}");
    assert!(
        (addr as u64) + len <= 0x8000_0000,
        "addr=0x{:x} len=0x{:x}",
        addr,
        len,
    );
}

#[test]
fn guest_ram_limit_caps_brk_growth() {
    let mut t = TestVm::new();
    let cur = t.sys_brk(0) as u64;
    let guest_limit = cur + 2 * PAGE_SIZE;
    t.vm.guest_ram_limit = guest_limit as u32;

    assert_eq!(t.sys_brk(cur + PAGE_SIZE), (cur + PAGE_SIZE) as i64);
    assert_eq!(t.sys_brk(guest_limit + PAGE_SIZE), (cur + PAGE_SIZE) as i64);
}

#[test]
fn prot_none_reservation_keeps_rw_mmaps_low() {
    let mut t = TestVm::new();
    t.vm.guest_ram_limit = 0x6000_0000;

    let reserve = t.sys_mmap(
        0,
        512 * 1024 * 1024,
        PROT_NONE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0,
    );
    assert!(reserve > 0);

    let mapped = t.sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0,
    );
    assert!(mapped > 0);
    assert!((mapped as u64) < reserve as u64);
}

#[test]
fn mprotect_materializes_high_prot_none_reservation_without_clobbering_current_thread_state() {
    let mut t = TestVm::new();
    let addr = 0x5c00_0000u64;
    let len = 0x21_000u64;
    t.vm.guest_ram_limit = 0x6000_0000;
    t.vm.pc = 0x1234_5678;
    t.vm.x[2] = 0x2345_6780;
    t.vm.x[27] = 0x3456_7890;

    let reserved = t.sys_mmap(
        addr,
        len,
        PROT_NONE,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
        -1,
        0,
    );
    assert_eq!(reserved as u64, addr);

    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.thread_count
        .store(2, core::sync::atomic::Ordering::Release);

    assert_eq!(t.sys_mprotect(addr, len, PROT_READ | PROT_WRITE), 0);
    assert_eq!(t.vm.pc, 0x1234_5678);
    assert_eq!(t.vm.x[2], 0x2345_6780);
    assert_eq!(t.vm.x[27], 0x3456_7890);

    let materialized = t.guest_mem(addr, len as usize);
    assert!(
        materialized.iter().all(|byte| *byte == 0),
        "materialized mapping should be zero-filled",
    );
}

#[test]
fn thread_step_mprotect_materialization_preserves_parent_context_in_multithreaded_process() {
    let mut t = TestVm::new();
    let code = t.sys_mmap(
        0x10000,
        0x1000,
        PROT_READ | PROT_EXEC,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert_eq!(code, 0x10000);

    let reserve_addr = 0x5c00_0000u64;
    let reserve_len = 0x21_000u64;
    t.vm.guest_ram_limit = 0x6000_0000;
    let reserved = t.sys_mmap(
        reserve_addr,
        reserve_len,
        PROT_NONE,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
        -1,
        0,
    );
    assert_eq!(reserved as u64, reserve_addr);

    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, 0x10000, 0x0000_0073);
        tidemark_kernel::guest_mem::write_u32(t.base, 0x10004, 0x0000_8067);
        tidemark_kernel::guest_mem::write_u16(t.base, 0x10008, 0x0001);
    }

    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.thread_count
        .store(2, core::sync::atomic::Ordering::Release);

    t.vm.pc = 0x10000;
    t.vm.x[1] = 0x10008;
    t.vm.x[2] = 0x2345_6780;
    t.vm.x[10] = reserve_addr;
    t.vm.x[11] = reserve_len;
    t.vm.x[12] = (PROT_READ | PROT_WRITE) as u64;
    t.vm.x[17] = SYS_MPROTECT;
    t.vm.x[27] = 0x3456_7890;

    let remaining = tidemark_kernel::abi::thread_step(&mut t.vm as *mut _ as u32, 2);
    assert_eq!(remaining, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, 0x10008);
    assert_eq!(t.vm.x[10], 0);
    assert_eq!(t.vm.x[2], 0x2345_6780);
    assert_eq!(t.vm.x[27], 0x3456_7890);

    let materialized = t.guest_mem(reserve_addr, reserve_len as usize);
    assert!(
        materialized.iter().all(|byte| *byte == 0),
        "materialized mapping should be zero-filled after syscall path",
    );
}

#[test]
fn multithreaded_flush_icache_reexec_preserves_parent_context() {
    let mut t = TestVm::new();
    let code = t.sys_mmap(
        0,
        PAGE_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0,
    );
    assert!(code > 0, "code={code}");
    let code = code as u64;

    unsafe {
        // addi a0, zero, 1
        tidemark_kernel::guest_mem::write_u32(t.base, code, 0x0010_0513);
        // jalr zero, ra, 0
        tidemark_kernel::guest_mem::write_u32(t.base, code + 4, 0x0000_8067);
        // c.nop
        tidemark_kernel::guest_mem::write_u16(t.base, code + 8, 0x0001);
    }

    assert_eq!(t.sys_mprotect(code, PAGE_SIZE, PROT_READ | PROT_EXEC), 0);

    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.thread_count
        .store(2, core::sync::atomic::Ordering::Release);

    t.vm.pc = code;
    t.vm.x[1] = code + 8;
    t.vm.x[2] = 0x2345_6780;
    t.vm.x[10] = 0;
    t.vm.x[27] = 0x3456_7890;
    t.vm.status = STATUS_OK;
    t.vm.sig_mask = 0;
    t.vm.sig_pending = 0;

    let remaining = tidemark_kernel::abi::thread_step(&mut t.vm as *mut _ as u32, 2);
    assert_eq!(remaining, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, code + 8);
    assert_eq!(t.vm.x[10], 1);
    assert_eq!(t.vm.x[2], 0x2345_6780);
    assert_eq!(t.vm.x[27], 0x3456_7890);

    assert_eq!(t.sys_mprotect(code, PAGE_SIZE, PROT_READ | PROT_WRITE), 0);
    unsafe {
        // addi a0, zero, 42
        tidemark_kernel::guest_mem::write_u32(t.base, code, 0x02a0_0513);
    }
    assert_eq!(
        tidemark_kernel::syscall::identity::sys_riscv_flush_icache(
            &mut t.vm,
            t.base,
            code,
            code + 8,
            0
        ),
        0
    );
    assert_eq!(t.sys_mprotect(code, PAGE_SIZE, PROT_READ | PROT_EXEC), 0);

    t.vm.pc = code;
    t.vm.x[1] = code + 8;
    t.vm.x[2] = 0x2345_6780;
    t.vm.x[10] = 0;
    t.vm.x[27] = 0x3456_7890;
    t.vm.status = STATUS_OK;
    t.vm.sig_mask = 0;
    t.vm.sig_pending = 0;

    let remaining = tidemark_kernel::abi::thread_step(&mut t.vm as *mut _ as u32, 2);
    assert_eq!(remaining, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, code + 8);
    assert_eq!(t.vm.x[10], 42);
    assert_eq!(t.vm.x[2], 0x2345_6780);
    assert_eq!(t.vm.x[27], 0x3456_7890);
}

#[test]
fn guest_generated_high_code_cache_flush_icache_executes_in_multithreaded_process() {
    let mut t = TestVm::new();
    t.vm.guest_ram_limit = 0x7fff_ffff;

    let reserve_base = 0x7053_0000u64;
    let reserve_len = 0x90_000u64;
    let code_page = 0x7053_8000u64;
    let code_addr = code_page + 0x80;
    let entry = 0x10000u64;

    let reserved = t.sys_mmap(
        reserve_base,
        reserve_len,
        PROT_NONE,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
        -1,
        0,
    );
    assert_eq!(reserved as u64, reserve_base);

    let mapped = t.sys_mmap(
        code_page,
        PAGE_SIZE,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
        -1,
        0,
    );
    assert_eq!(mapped as u64, code_page);

    let entry_map = t.sys_mmap(
        entry,
        PAGE_SIZE,
        PROT_READ | PROT_EXEC,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
        -1,
        0,
    );
    assert_eq!(entry_map as u64, entry);

    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.thread_count
        .store(2, core::sync::atomic::Ordering::Release);

    let li_t0_addr = encode_li(5, code_addr as u32);
    let li_t1_addi42 = encode_li(6, 0x02a0_0513);
    let li_t1_ret = encode_li(6, 0x0000_8067);

    unsafe {
        let mut pc = entry;
        for insn in li_t0_addr {
            tidemark_kernel::guest_mem::write_u32(t.base, pc, insn);
            pc += 4;
        }
        for insn in li_t1_addi42 {
            tidemark_kernel::guest_mem::write_u32(t.base, pc, insn);
            pc += 4;
        }
        tidemark_kernel::guest_mem::write_u32(t.base, pc, encode_s(0x23, 0b010, 5, 6, 0));
        pc += 4;
        for insn in li_t1_ret {
            tidemark_kernel::guest_mem::write_u32(t.base, pc, insn);
            pc += 4;
        }
        tidemark_kernel::guest_mem::write_u32(t.base, pc, encode_s(0x23, 0b010, 5, 6, 4));
        pc += 4;
        tidemark_kernel::guest_mem::write_u32(t.base, pc, encode_i(0x13, 10, 0, 5, 0));
        pc += 4;
        tidemark_kernel::guest_mem::write_u32(t.base, pc, encode_i(0x13, 11, 0, 5, 8));
        pc += 4;
        tidemark_kernel::guest_mem::write_u32(t.base, pc, encode_i(0x13, 12, 0, 0, 0));
        pc += 4;
        tidemark_kernel::guest_mem::write_u32(
            t.base,
            pc,
            encode_i(0x13, 17, 0, 0, SYS_RISCV_FLUSH_ICACHE as i32),
        );
        pc += 4;
        tidemark_kernel::guest_mem::write_u32(t.base, pc, 0x0000_0073);
        pc += 4;
        tidemark_kernel::guest_mem::write_u32(t.base, pc, encode_i(0x67, 1, 0, 5, 0));
        pc += 4;
        tidemark_kernel::guest_mem::write_u16(t.base, pc, 0x0001);
    }

    let return_pc = entry + 14 * 4;
    t.vm.pc = entry;
    t.vm.x[1] = 0;
    t.vm.x[2] = 0x2345_6780;
    t.vm.x[10] = 0;
    t.vm.x[27] = 0x3456_7890;
    t.vm.status = STATUS_OK;
    t.vm.sig_mask = 0;
    t.vm.sig_pending = 0;

    let remaining = tidemark_kernel::abi::thread_step(&mut t.vm as *mut _ as u32, 16);
    assert_eq!(remaining, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, return_pc);
    assert_eq!(t.vm.x[1], return_pc);
    assert_eq!(t.vm.x[10], 42);
    assert_eq!(t.vm.x[2], 0x2345_6780);
    assert_eq!(t.vm.x[27], 0x3456_7890);

    unsafe {
        assert_eq!(
            tidemark_kernel::guest_mem::read_u32(t.base, code_addr),
            0x02a0_0513
        );
        assert_eq!(
            tidemark_kernel::guest_mem::read_u32(t.base, code_addr + 4),
            0x0000_8067
        );
    }
}

#[test]
fn failed_hint_probe_reuses_low_hole_after_munmap() {
    let mut t = TestVm::new();
    let bad_hint = 0x9000_0000;
    let len = 64 * 1024 * 1024;

    let first = t.sys_mmap(bad_hint, len, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    assert!(first > 0);
    assert_eq!(t.sys_munmap(first as u64, len), 0);

    let second = t.sys_mmap(bad_hint, len, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    assert_eq!(second, first);
}

#[test]
fn mmap_stays_above_expanded_brk_region() {
    let mut t = TestVm::new();
    let grown = t.sys_brk(0x40_0000);
    assert_eq!(grown, 0x40_0000);

    let mapped = t.sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0,
    );
    assert!(mapped > 0);

    let floor = (((grown as u64) + 8 * 1024 * 1024 + 0xF_FFFF) & !0xF_FFFF).max(0x20_0000);
    assert!((mapped as u64) >= floor);
}

#[test]
fn nonfixed_mmap_leaves_room_for_later_brk_growth() {
    let mut t = TestVm::new();
    let mapped = t.sys_mmap(
        0,
        1024 * 1024,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0,
    );
    assert!(mapped > 0);

    let grown = t.sys_brk(0x80_0000);
    assert_eq!(grown, 0x80_0000);
    assert!((mapped as u64) >= 0x80_0000);
}

#[test]
fn initial_stack_maps_guard_and_writable_stack() {
    let t = TestVm::new();
    let guest_limit = 0x80_0000;
    let stack_top = memory::map_initial_stack(t.base, guest_limit, 1024 * 1024);
    assert_eq!(stack_top, (guest_limit - PAGE_SIZE) as i64);

    let guard_addr = guest_limit - 1024 * 1024 - PAGE_SIZE / 2;
    let stack_addr = guest_limit - PAGE_SIZE - 64;
    assert!(memory::is_prot_none(guard_addr));
    assert!(!memory::is_prot_none(stack_addr));

    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, stack_addr, 0xDEAD_BEEF_CAFE_BABEu64);
        assert_eq!(
            tidemark_kernel::guest_mem::read_u64(t.base, stack_addr),
            0xDEAD_BEEF_CAFE_BABEu64
        );
    }
}

#[test]
fn initial_stack_aligns_unaligned_guest_limit_down() {
    let t = TestVm::new();
    let guest_limit = 0x80_0010;
    let aligned_limit = guest_limit & !(PAGE_SIZE - 1);
    let stack_top = memory::map_initial_stack(t.base, guest_limit, 1024 * 1024);
    assert_eq!(stack_top, (aligned_limit - PAGE_SIZE) as i64);

    let guard_addr = aligned_limit - 1024 * 1024 - PAGE_SIZE / 2;
    let stack_addr = aligned_limit - PAGE_SIZE - 64;
    assert!(memory::is_prot_none(guard_addr));
    assert!(!memory::is_prot_none(stack_addr));
}
