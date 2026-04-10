use tidemark_kernel::abi::*;
use tidemark_kernel::harness::TestVm;
use tidemark_kernel::syscall::memory;

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
fn brk_refuses_above_2gb() {
    let mut t = TestVm::new();
    let cur = t.sys_brk(0);
    let ret = t.sys_brk(0x8000_0001);
    assert_eq!(ret, cur, "brk should refuse addresses above 2GB");
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
fn mmap_rejects_invalid_fd_for_file_backed() {
    let mut t = TestVm::new();
    let ret = t.sys_mmap(0, 4096, PROT_READ, MAP_PRIVATE, -1, 0);
    assert_eq!(ret, EBADF as i64);
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
fn prot_none_reservation_keeps_rw_mmaps_low() {
    let mut t = TestVm::new();

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

    let floor = (((grown as u64) + 0x1F_FFFF) & !0x1F_FFFF).max(0x20_0000);
    assert!((mapped as u64) >= floor);
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
