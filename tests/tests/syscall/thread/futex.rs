use super::*;

#[test]
fn contract_runtime_notesleep_futex_return_path_preserves_go_worker_context() {
    let mut t = TestVm::new();
    let notesleep_page = t.sys_mmap(
        0x2a000,
        0x1000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert_eq!(notesleep_page, 0x2a000);
    let futexsleep_page = t.sys_mmap(
        0x4d000,
        0x1000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert_eq!(futexsleep_page, 0x4d000);
    let futex_page = t.sys_mmap(
        0x83000,
        0x1000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert_eq!(futex_page, 0x83000);
    let cgo_yield_page = t.sys_mmap(
        0xbdc000,
        0x1000,
        PROT_READ | PROT_WRITE,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert_eq!(cgo_yield_page, 0xbdc000);
    tidemark_kernel::syscall::memory::register_elf_load_segment(
        0x2a000,
        0x2b000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
    );
    tidemark_kernel::syscall::memory::register_elf_load_segment(
        0x4d000,
        0x4e000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
    );
    tidemark_kernel::syscall::memory::register_elf_load_segment(
        0x83000,
        0x84000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
    );

    unsafe {
        // runtime.notesleep tail around the futexsleep call and loop.
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a482, 0x72a2); // ld t0,40(sp)
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a484, 0x0302_b383); // ld t2,48(t0)
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a488, 0x1003_8aa3); // sb zero,277(t2)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a48c, 0x7302); // ld t1,32(sp)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a48e, 0x7562); // ld a0,56(sp)
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a490, 0x1405_23af); // lr.w.aq t2,(a0)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a494, 0x1382); // slli t2,t2,0x20
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a496, 0x0203_d393); // srli t2,t2,0x20
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a49a, 0x0203_9963); // bnez t2,2a4cc
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a49e, 0x0302_b283); // ld t0,48(t0)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4a2, 0x4385); // li t2,1
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a4a4, 0x1072_8aa3); // sb t2,277(t0)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4a8, 0x4581); // li a1,0
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4aa, 0x861a); // mv a2,t1
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a4ac, 0x18c2_30ef); // jal runtime.futexsleep
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a4b0, 0x00bb_2297); // auipc t0,...
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a4b4, 0x6282_b283); // ld t0,1576(t0)
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a4b8, 0x0002_b283); // ld t0,0(t0)
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a4bc, 0xfc02_83e3); // beqz t0,2a482
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4c0, 0x0001); // c.nop
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4c2, 0x0001); // c.nop
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4c4, 0x0001); // c.nop
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4c6, 0x0001); // c.nop
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4c8, 0x0001); // c.nop
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4ca, 0x0001); // c.nop
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4cc, 0x6082); // ld ra,0(sp)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4ce, 0x6145); // addi sp,sp,48
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a4d0, 0x0000_8067); // ret

        // runtime.futexsleep fast path.
        tidemark_kernel::guest_mem::write_u32(t.base, 0x4d638, 0xfc11_3023); // sd ra,-64(sp)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d63c, 0x7139); // addi sp,sp,-64
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d63e, 0xe006); // sd ra,0(sp)
        tidemark_kernel::guest_mem::write_u32(t.base, 0x4d640, 0x0006_5e63); // bgez a2,4d65c
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d644, 0x862e); // mv a2,a1
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d646, 0x4681); // li a3,0
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d648, 0x4701); // li a4,0
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d64a, 0x4781); // li a5,0
        tidemark_kernel::guest_mem::write_u32(t.base, 0x4d64c, 0x0800_0593); // li a1,128
        tidemark_kernel::guest_mem::write_u32(t.base, 0x4d650, 0x4b13_50ef); // jal runtime.futex
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d654, 0x6082); // ld ra,0(sp)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d656, 0x6121); // addi sp,sp,64
        tidemark_kernel::guest_mem::write_u32(t.base, 0x4d658, 0x0000_8067); // ret

        // runtime.futex
        tidemark_kernel::guest_mem::write_u32(t.base, 0x83300, 0x0620_0893); // li a7,98
        tidemark_kernel::guest_mem::write_u32(t.base, 0x83304, 0x0000_0073); // ecall
        tidemark_kernel::guest_mem::write_u32(t.base, 0x83308, 0x0000_8067); // ret

        // cgo_yield points at a null function pointer so notesleep loops back.
        tidemark_kernel::guest_mem::write_u64(t.base, 0xbdcad8, 0xbdcb00);
        tidemark_kernel::guest_mem::write_u64(t.base, 0xbdcb00, 0);
    }
    assert_eq!(
        tidemark_kernel::syscall::identity::sys_riscv_flush_icache(
            &mut t.vm, t.base, 0x2a000, 0x84000, 0,
        ),
        0
    );

    let futexsleep_sp = t.scratch + 0x7000;
    let notesleep_sp = futexsleep_sp + 64;
    let note_addr = t.scratch + 0x7200;
    let note_state = t.scratch + 0x7300;
    let g = t.scratch + 0x7800;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, note_addr, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, note_state + 48, g);
        tidemark_kernel::guest_mem::write_u64(t.base, notesleep_sp + 32, u64::MAX);
        tidemark_kernel::guest_mem::write_u64(t.base, notesleep_sp + 40, note_state);
        tidemark_kernel::guest_mem::write_u64(t.base, notesleep_sp + 56, note_addr);
        tidemark_kernel::guest_mem::write_u64(t.base, futexsleep_sp, 0x2a4b0);
    }

    t.vm.tid = 3;
    t.vm.status = STATUS_OK;
    t.vm.guest_base = t.base;
    t.vm.pc = 0x83308;
    t.vm.x[1] = 0x4d654;
    t.vm.x[2] = futexsleep_sp;
    t.vm.x[27] = g;
    install_current_thread_record(&mut t);
    unsafe {
        let ps = &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState);
        ps.thread_count
            .store(2, std::sync::atomic::Ordering::Release);
    }
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, 0x83308, 0x0000_8067);
    }
    assert!(
        tidemark_kernel::syscall::memory::guest_range_permitted(
            &t.vm, t.base, 0x83308, 4, PROT_EXEC,
        ),
        "synthetic futex return page must be executable"
    );

    let remaining = tidemark_kernel::abi::thread_step(&mut t.vm as *mut ThreadState as u32, 64);
    assert!(remaining >= 0);
    assert_eq!(
        t.vm.status, STATUS_FUTEX_WAIT,
        "status={} pc=0x{:x} ra=0x{:x} sp=0x{:x} exit={} fault_pc=0x{:x} fault_addr=0x{:x}",
        t.vm.status, t.vm.pc, t.vm.x[1], t.vm.x[2], t.vm.exit_code, t.vm.fault_pc, t.vm.fault_addr,
    );
    assert_eq!(
        t.vm.pc, 0x83308,
        "status={} pc=0x{:x} ra=0x{:x} sp=0x{:x} exit={} fault_pc=0x{:x} fault_addr=0x{:x}",
        t.vm.status, t.vm.pc, t.vm.x[1], t.vm.x[2], t.vm.exit_code, t.vm.fault_pc, t.vm.fault_addr,
    );
    assert_eq!(t.vm.x[27], g);
    assert_eq!(t.vm.x[2], futexsleep_sp);
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, futexsleep_sp) },
        0x2a4b0
    );
}

#[test]
fn contract_runtime_notesleep_futex_wake_return_path_preserves_go_worker_context() {
    let mut t = TestVm::new();
    let notesleep_page = t.sys_mmap(
        0x2a000,
        0x1000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert_eq!(notesleep_page, 0x2a000);
    let futexsleep_page = t.sys_mmap(
        0x4d000,
        0x1000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert_eq!(futexsleep_page, 0x4d000);
    let futex_page = t.sys_mmap(
        0x83000,
        0x1000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert_eq!(futex_page, 0x83000);
    let cgo_yield_page = t.sys_mmap(
        0xbdc000,
        0x1000,
        PROT_READ | PROT_WRITE,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert_eq!(cgo_yield_page, 0xbdc000);
    let caller_page = t.sys_mmap(
        0x2b000,
        0x1000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert_eq!(caller_page, 0x2b000);
    tidemark_kernel::syscall::memory::register_elf_load_segment(
        0x2a000,
        0x2c000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
    );
    tidemark_kernel::syscall::memory::register_elf_load_segment(
        0x4d000,
        0x4e000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
    );
    tidemark_kernel::syscall::memory::register_elf_load_segment(
        0x83000,
        0x84000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
    );

    unsafe {
        // runtime.notesleep tail around the futexsleep call and wake check.
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a482, 0x72a2); // ld t0,40(sp)
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a484, 0x0302_b383); // ld t2,48(t0)
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a488, 0x1003_8aa3); // sb zero,277(t2)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a48c, 0x7302); // ld t1,32(sp)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a48e, 0x7562); // ld a0,56(sp)
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a490, 0x1405_23af); // lr.w.aq t2,(a0)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a494, 0x1382); // slli t2,t2,0x20
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a496, 0x0203_d393); // srli t2,t2,0x20
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a49a, 0x0203_9963); // bnez t2,2a4cc
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a49e, 0x0302_b283); // ld t0,48(t0)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4a2, 0x4385); // li t2,1
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a4a4, 0x1072_8aa3); // sb t2,277(t0)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4a8, 0x4581); // li a1,0
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4aa, 0x861a); // mv a2,t1
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a4ac, 0x18c2_30ef); // jal runtime.futexsleep
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a4b0, 0x00bb_2297); // auipc t0,...
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a4b4, 0x6282_b283); // ld t0,1576(t0)
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a4b8, 0x0002_b283); // ld t0,0(t0)
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a4bc, 0xfc02_83e3); // beqz t0,2a482
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4c0, 0x0001); // c.nop
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4c2, 0x0001); // c.nop
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4c4, 0x0001); // c.nop
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4c6, 0x0001); // c.nop
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4c8, 0x0001); // c.nop
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4ca, 0x0001); // c.nop
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4cc, 0x6082); // ld ra,0(sp)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4ce, 0x6145); // addi sp,sp,48
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a4d0, 0x0000_8067); // ret

        // runtime.futexsleep fast path.
        tidemark_kernel::guest_mem::write_u32(t.base, 0x4d638, 0xfc11_3023); // sd ra,-64(sp)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d63c, 0x7139); // addi sp,sp,-64
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d63e, 0xe006); // sd ra,0(sp)
        tidemark_kernel::guest_mem::write_u32(t.base, 0x4d640, 0x0006_5e63); // bgez a2,4d65c
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d644, 0x862e); // mv a2,a1
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d646, 0x4681); // li a3,0
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d648, 0x4701); // li a4,0
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d64a, 0x4781); // li a5,0
        tidemark_kernel::guest_mem::write_u32(t.base, 0x4d64c, 0x0800_0593); // li a1,128
        tidemark_kernel::guest_mem::write_u32(t.base, 0x4d650, 0x4b13_50ef); // jal runtime.futex
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d654, 0x6082); // ld ra,0(sp)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d656, 0x6121); // addi sp,sp,64
        tidemark_kernel::guest_mem::write_u32(t.base, 0x4d658, 0x0000_8067); // ret

        // runtime.futex
        tidemark_kernel::guest_mem::write_u32(t.base, 0x83300, 0x0620_0893); // li a7,98
        tidemark_kernel::guest_mem::write_u32(t.base, 0x83304, 0x0000_0073); // ecall
        tidemark_kernel::guest_mem::write_u32(t.base, 0x83308, 0x0000_8067); // ret

        // cgo_yield points at a non-zero function pointer so notesleep exits after wake.
        tidemark_kernel::guest_mem::write_u64(t.base, 0xbdcad8, 0xbdcb00);
        tidemark_kernel::guest_mem::write_u64(t.base, 0xbdcb00, 1);

        // Caller target after notesleep returns.
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2b000, 0x0010_0513); // li a0,1
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2b004, 0x0000_8067); // ret
    }
    assert_eq!(
        tidemark_kernel::syscall::identity::sys_riscv_flush_icache(
            &mut t.vm, t.base, 0x2a000, 0x84000, 0,
        ),
        0
    );

    let futexsleep_sp = t.scratch + 0x7000;
    let notesleep_sp = futexsleep_sp + 64;
    let note_addr = t.scratch + 0x7200;
    let note_state = t.scratch + 0x7300;
    let g = t.scratch + 0x7800;
    unsafe {
        // Wake condition already satisfied.
        tidemark_kernel::guest_mem::write_u32(t.base, note_addr, 1);
        tidemark_kernel::guest_mem::write_u64(t.base, note_state + 48, g);
        tidemark_kernel::guest_mem::write_u64(t.base, notesleep_sp + 32, u64::MAX);
        tidemark_kernel::guest_mem::write_u64(t.base, notesleep_sp + 40, note_state);
        tidemark_kernel::guest_mem::write_u64(t.base, notesleep_sp + 56, note_addr);
        tidemark_kernel::guest_mem::write_u64(t.base, futexsleep_sp, 0x2a4b0);
        tidemark_kernel::guest_mem::write_u64(t.base, notesleep_sp, 0x2b000);
    }

    t.vm.tid = 3;
    t.vm.status = STATUS_OK;
    t.vm.guest_base = t.base;
    t.vm.pc = 0x83308;
    t.vm.x[1] = 0x4d654;
    t.vm.x[2] = futexsleep_sp;
    t.vm.x[27] = g;
    install_current_thread_record(&mut t);
    unsafe {
        let ps = &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState);
        ps.thread_count
            .store(2, std::sync::atomic::Ordering::Release);
        tidemark_kernel::guest_mem::write_u32(t.base, 0x83308, 0x0000_8067);
    }

    let remaining = tidemark_kernel::abi::thread_step(&mut t.vm as *mut ThreadState as u32, 64);
    assert!(remaining >= 0);
    assert_eq!(
        t.vm.status, STATUS_OK,
        "status={} pc=0x{:x} ra=0x{:x} sp=0x{:x} exit={} fault_pc=0x{:x} fault_addr=0x{:x}",
        t.vm.status, t.vm.pc, t.vm.x[1], t.vm.x[2], t.vm.exit_code, t.vm.fault_pc, t.vm.fault_addr,
    );
    assert_eq!(
        t.vm.pc, 0x2b004,
        "status={} pc=0x{:x} ra=0x{:x} sp=0x{:x} exit={} fault_pc=0x{:x} fault_addr=0x{:x}",
        t.vm.status, t.vm.pc, t.vm.x[1], t.vm.x[2], t.vm.exit_code, t.vm.fault_pc, t.vm.fault_addr,
    );
    assert_eq!(t.vm.x[2], notesleep_sp + 48);
    assert_eq!(t.vm.x[27], g);
}

#[test]
fn contract_futex_wake_unblocks_waiting_thread_record() {
    let mut t = TestVm::new();
    let addr = t.scratch + 0x500;
    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.threads[1] = ThreadRecord::new(2, THREAD_BLOCKED_FUTEX, 0xDEAD_BEEFu32, 0, addr as u32);
    ps.thread_count
        .store(2, core::sync::atomic::Ordering::Release);

    let ret = thread_impl::sys_futex(&mut t.vm, t.base, addr, FUTEX_WAKE as u64, 1, 0, 0, 0);
    assert_eq!(ret, 1);
    assert_eq!(ps.threads[1].state, THREAD_RUNNING);
    assert_eq!(ps.threads[1].blocked_addr, 0);
}

#[test]
fn contract_futex_wake_bitset_only_wakes_matching_waiters() {
    let mut t = TestVm::new();
    let addr = t.scratch + 0x510;
    let waiter_ptr = unsafe {
        tidemark_kernel::alloc::alloc_zeroed(
            core::mem::size_of::<ThreadState>() as u32,
            core::mem::align_of::<ThreadState>() as u32,
        )
    };
    assert_ne!(waiter_ptr, 0);
    let waiter = unsafe { &mut *(waiter_ptr as *mut ThreadState) };
    waiter.process_ptr = t.vm.process_ptr;
    waiter.futex_wait_bitset = 0x2;
    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.thread_count
        .store(2, core::sync::atomic::Ordering::Release);
    ps.threads[1] = ThreadRecord::new(2, THREAD_BLOCKED_FUTEX, waiter_ptr, 0, addr as u32);

    let mismatch = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        addr,
        FUTEX_WAKE_BITSET as u64,
        1,
        0,
        0,
        0x1,
    );
    assert_eq!(mismatch, 0);
    assert_eq!(ps.threads[1].state, THREAD_BLOCKED_FUTEX);
    assert_eq!(ps.threads[1].blocked_addr, addr as u32);

    let matched = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        addr,
        FUTEX_WAKE_BITSET as u64,
        1,
        0,
        0,
        0x2,
    );
    assert_eq!(matched, 1);
    assert_eq!(ps.threads[1].state, THREAD_RUNNING);
    assert_eq!(ps.threads[1].blocked_addr, 0);
}

#[test]
fn contract_futex_bitset_rejects_zero_mask() {
    let mut t = TestVm::new();
    let addr = t.scratch + 0x514;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, addr, 3);
    }

    let wait_ret = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        addr,
        FUTEX_WAIT_BITSET as u64,
        3,
        0,
        0,
        0,
    );
    assert_eq!(wait_ret, EINVAL);

    let wake_ret = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        addr,
        FUTEX_WAKE_BITSET as u64,
        1,
        0,
        0,
        0,
    );
    assert_eq!(wake_ret, EINVAL);
}

#[test]
fn contract_futex_wait_bitset_captures_realtime_flag_and_clears_on_resume() {
    let mut t = TestVm::new();
    let addr = t.scratch + 0x518;
    let timeout = t.scratch + 0x540;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, addr, 3);
        tidemark_kernel::guest_mem::write_u64(t.base, timeout, 1);
        tidemark_kernel::guest_mem::write_u64(t.base, timeout + 8, 0);
    }

    let wait_ret = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        addr,
        (FUTEX_WAIT_BITSET | FUTEX_CLOCK_REALTIME) as u64,
        3,
        timeout,
        0,
        FUTEX_BITSET_MATCH_ANY as u64,
    );
    assert_eq!(wait_ret, 0);
    assert_eq!(t.vm.status, STATUS_FUTEX_WAIT);
    assert_eq!(t.vm.futex_wait_timeout, timeout);
    assert_eq!(t.vm.futex_wait_absolute, 1);
    assert_eq!(t.vm.futex_wait_flags, FUTEX_CLOCK_REALTIME);

    thread_impl::resume_futex_wait_result(&mut t.vm, t.base, ETIMEDOUT);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.futex_wait_timeout, 0);
    assert_eq!(t.vm.futex_wait_absolute, 0);
    assert_eq!(t.vm.futex_wait_flags, 0);
    assert_eq!(t.vm.x[10] as i64, ETIMEDOUT);
}

#[test]
fn contract_resume_timed_futex_wait_without_pending_signal_preserves_context() {
    let mut t = TestVm::new();
    let addr = t.scratch + 0x580;
    let timeout = t.scratch + 0x5a0;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, addr, 7);
        tidemark_kernel::guest_mem::write_u64(t.base, timeout, 1);
        tidemark_kernel::guest_mem::write_u64(t.base, timeout + 8, 0);
    }

    let wait_ret =
        thread_impl::sys_futex(&mut t.vm, t.base, addr, FUTEX_WAIT as u64, 7, timeout, 0, 0);
    assert_eq!(wait_ret, 0);
    assert_eq!(t.vm.status, STATUS_FUTEX_WAIT);

    t.vm.pc = 0x4455_6677;
    t.vm.x[1] = 0x5566_7788;
    t.vm.x[2] = t.scratch + 0x1800;
    t.vm.x[27] = 0x7788_9900;
    t.vm.sig_pending = 0;
    t.vm.sig_info_code = 0;

    let record = unsafe {
        &mut (*((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState)).threads
            [(t.vm.tid - 1) as usize]
    };
    record.state = THREAD_BLOCKED_FUTEX;
    record.blocked_addr = addr as u32;

    thread_impl::resume_futex_wait_result(&mut t.vm, t.base, ETIMEDOUT);

    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.futex_wait_addr, 0);
    assert_eq!(t.vm.futex_wait_timeout, 0);
    assert_eq!(t.vm.futex_wait_expected, 0);
    assert_eq!(t.vm.futex_wait_bitset, 0);
    assert_eq!(t.vm.futex_wait_absolute, 0);
    assert_eq!(t.vm.futex_wait_flags, 0);
    assert_eq!(t.vm.x[10] as i64, ETIMEDOUT);
    assert_eq!(t.vm.pc, 0x4455_6677);
    assert_eq!(t.vm.x[1], 0x5566_7788);
    assert_eq!(t.vm.x[2], t.scratch + 0x1800);
    assert_eq!(t.vm.x[27], 0x7788_9900);
    assert_eq!(t.vm.sig_pending, 0);
    assert_eq!(t.vm.sig_info_code, 0);
    assert_eq!(record.state, THREAD_RUNNING);
    assert_eq!(record.blocked_addr, 0);
}

#[test]
fn contract_resume_timed_futex_wait_delivers_pending_signal_and_restores_timeout_result() {
    let mut t = TestVm::new();
    let addr = t.scratch + 0x5c0;
    let timeout = t.scratch + 0x5e0;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, addr, 9);
        tidemark_kernel::guest_mem::write_u64(t.base, timeout, 1);
        tidemark_kernel::guest_mem::write_u64(t.base, timeout + 8, 0);
    }

    let wait_ret =
        thread_impl::sys_futex(&mut t.vm, t.base, addr, FUTEX_WAIT as u64, 9, timeout, 0, 0);
    assert_eq!(wait_ret, 0);
    assert_eq!(t.vm.status, STATUS_FUTEX_WAIT);

    let handler = 0x12345;
    let act_addr = t.scratch + 0x640;
    write_sigaction(t.base, act_addr, handler, 0, 0);
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, SIGURG as u64, act_addr, 0, 8),
        0
    );

    t.vm.pc = 0x4455_6677;
    t.vm.x[1] = 0x5566_7788;
    t.vm.x[2] = t.scratch + 0x2000;
    t.vm.x[27] = 0x7788_9900;
    t.vm.sig_mask = 0;
    t.vm.sig_pending = 1u64 << (SIGURG - 1);
    t.vm.sig_info_code = 0;

    let orig_pc = t.vm.pc;
    let orig_ra = t.vm.x[1];
    let orig_sp = t.vm.x[2];
    let orig_s11 = t.vm.x[27];

    let record = unsafe {
        &mut (*((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState)).threads
            [(t.vm.tid - 1) as usize]
    };
    record.state = THREAD_BLOCKED_FUTEX;
    record.blocked_addr = addr as u32;

    thread_impl::resume_futex_wait_result(&mut t.vm, t.base, ETIMEDOUT);

    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, handler);
    assert_eq!(t.vm.x[10], SIGURG as u64);
    assert_eq!(t.vm.x[1], t.vm.x[2] + SIGFRAME_OFF_TRAMPOLINE);
    assert_eq!(t.vm.x[27], orig_s11);
    assert_eq!(t.vm.sig_pending & (1u64 << (SIGURG - 1)), 0);
    assert_eq!(record.state, THREAD_RUNNING);
    assert_eq!(record.blocked_addr, 0);

    signal::sys_rt_sigreturn(&mut t.vm, t.base);
    assert_eq!(t.vm.pc, orig_pc);
    assert_eq!(t.vm.x[1], orig_ra);
    assert_eq!(t.vm.x[2], orig_sp);
    assert_eq!(t.vm.x[10] as i64, ETIMEDOUT);
    assert_eq!(t.vm.x[27], orig_s11);
}

#[test]
fn contract_futex_cmp_requeue_moves_remaining_waiters() {
    let mut t = TestVm::new();
    let from_addr = t.scratch + 0x520;
    let to_addr = t.scratch + 0x524;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, from_addr, 7);
    }
    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.thread_count
        .store(3, core::sync::atomic::Ordering::Release);
    ps.threads[1] = ThreadRecord::new(2, THREAD_BLOCKED_FUTEX, 0, 0, from_addr as u32);
    ps.threads[2] = ThreadRecord::new(3, THREAD_BLOCKED_FUTEX, 0, 0, from_addr as u32);

    let ret = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        from_addr,
        FUTEX_CMP_REQUEUE as u64,
        1,
        1,
        to_addr,
        7,
    );

    assert_eq!(ret, 2);
    assert_eq!(ps.threads[1].state, THREAD_RUNNING);
    assert_eq!(ps.threads[1].blocked_addr, 0);
    assert_eq!(ps.threads[2].state, THREAD_BLOCKED_FUTEX);
    assert_eq!(ps.threads[2].blocked_addr, to_addr as u32);
}

#[test]
fn contract_futex_cmp_requeue_validates_counts_and_compare_value() {
    let mut t = TestVm::new();
    let from_addr = t.scratch + 0x600;
    let to_addr = t.scratch + 0x604;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, from_addr, 11);
    }

    let invalid_wake = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        from_addr,
        FUTEX_CMP_REQUEUE as u64,
        u64::MAX,
        1,
        to_addr,
        11,
    );
    assert_eq!(invalid_wake, EINVAL);

    let invalid_requeue = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        from_addr,
        FUTEX_CMP_REQUEUE as u64,
        1,
        u64::MAX,
        to_addr,
        11,
    );
    assert_eq!(invalid_requeue, EINVAL);

    let mismatched = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        from_addr,
        FUTEX_CMP_REQUEUE as u64,
        1,
        1,
        to_addr,
        12,
    );
    assert_eq!(mismatched, EAGAIN);
}
