use tidemark_kernel::abi::*;
use tidemark_kernel::harness::TestVm;
use tidemark_kernel::syscall::signal;
use tidemark_kernel::syscall::thread as thread_impl;
use tidemark_kernel::types::{
    ProcessState, THREAD_BLOCKED_FUTEX, THREAD_NONE, THREAD_RUNNING, ThreadRecord, ThreadState,
};

const FUTEX_WAITERS: u32 = 0x8000_0000;
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
const SIGFRAME_SIZE: u64 = 1136;
const SIGFRAME_OFF_TRAMPOLINE: u64 = SIGFRAME_SIZE - 8;

fn write_sigaction(base: u32, addr: u64, handler: u64, flags: u64, mask: u64) {
    unsafe {
        tidemark_kernel::guest_mem::write_u64(base, addr, handler);
        tidemark_kernel::guest_mem::write_u64(base, addr + 8, flags);
        tidemark_kernel::guest_mem::write_u64(base, addr + 16, mask);
    }
}

#[test]
fn contract_exit_decrements_thread_count() {
    let mut t = TestVm::new();
    let ps_ptr = t.vm.process_ptr as u64;
    let tc_off = core::mem::offset_of!(ProcessState, thread_count) as u64;
    unsafe { tidemark_kernel::guest_mem::write_u32(t.base, ps_ptr + tc_off, 2) };

    let status = thread_impl::sys_exit(&mut t.vm, t.base, 42);
    assert_eq!(status, STATUS_FAULT);
    assert_eq!(t.vm.exit_code, 42);

    let tc = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, ps_ptr + tc_off) };
    assert_eq!(tc, 1);
}

#[test]
fn contract_clone_thread_returns_status_clone_spawn() {
    let mut t = TestVm::new();
    t.vm.tid = 1;
    let ps_ptr = t.vm.process_ptr as u64;
    let tc_off = core::mem::offset_of!(ProcessState, thread_count) as u64;

    let flags = (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS) as u64;
    let child_stack = 0x80000u64;
    let ret = thread_impl::sys_clone(&mut t.vm, t.base, flags, child_stack, 0, 0, 0);

    assert!(ret > 0);
    assert_eq!(t.vm.status, STATUS_CLONE_SPAWN);

    let tc = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, ps_ptr + tc_off) };
    assert_eq!(tc, 2);
}

#[test]
fn contract_spawn_from_clone_initializes_child_thread_state() {
    let mut t = TestVm::new();
    t.vm.tid = 1;
    t.vm.sig_mask = 0x55;
    t.vm.sig_pending = 0xAA;
    t.vm.sigaltstack_sp = 0x9000;
    t.vm.sigaltstack_size = 4096;
    t.vm.sigaltstack_flags = 1;
    t.vm.x[1] = 0x1234_5678;
    t.vm.x[3] = 0x2345_6789;
    t.vm.x[27] = 0x3456_789a;
    t.vm.pc = 0x4567_89ab;

    let ps_ptr = t.vm.process_ptr as u64;

    let child_tidptr = t.scratch + 0x280;
    let flags = (CLONE_VM
        | CLONE_THREAD
        | CLONE_SIGHAND
        | CLONE_FS
        | CLONE_SETTLS
        | CLONE_CHILD_SETTID
        | CLONE_CHILD_CLEARTID) as u64;
    let child_stack = 0x88000u64;
    let tls = 0x1234_5000u64;

    let ret = thread_impl::sys_clone(&mut t.vm, t.base, flags, child_stack, 0, tls, child_tidptr);
    assert!(ret > 0);
    assert_eq!(t.vm.clone_pending, 1);
    assert_eq!(t.vm.clone_child_tid, ret as i32);
    assert_eq!(t.vm.clone_child_stack, child_stack);
    assert_eq!(t.vm.clone_tls, tls);
    assert_eq!(t.vm.clone_child_tidptr, child_tidptr);

    let child_ptr = thread_impl::spawn_from_clone(&t.vm as *const ThreadState as u32, t.base);
    assert_ne!(child_ptr, 0);

    let child = unsafe { &*(child_ptr as *const ThreadState) };
    assert_eq!(child.tid, ret as i32);
    assert_eq!(child.pc, 0x4567_89ab);
    assert_eq!(child.x[1], 0x1234_5678);
    assert_eq!(child.x[3], 0x2345_6789);
    assert_eq!(child.x[27], 0x3456_789a);
    assert_eq!(child.x[10], 0);
    assert_eq!(child.x[2], child_stack);
    assert_eq!(child.x[4], tls);
    assert_eq!(child.tls_base, tls);
    assert_eq!(child.clear_child_tid, child_tidptr);
    assert_eq!(child.sig_mask, 0x55);
    assert_eq!(child.sig_pending, 0);
    assert_eq!(child.sigaltstack_sp, 0);
    assert_eq!(child.sigaltstack_size, 0);
    assert_eq!(child.sigaltstack_flags, 0);

    let written_tid = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, child_tidptr) };
    assert_eq!(written_tid, ret as u32);

    let threads_off = core::mem::offset_of!(ProcessState, threads) as u64;
    let record_size = core::mem::size_of::<ThreadRecord>() as u64;
    let record_off = ps_ptr + threads_off + ((ret as u64) - 1) * record_size;
    let state = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, record_off) };
    let thread_ptr = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, record_off + 8) };
    assert_eq!(state as i32, THREAD_RUNNING);
    assert_eq!(thread_ptr, child_ptr);

    assert_eq!(t.vm.clone_pending, 0);
    assert_eq!(t.vm.clone_child_tid, 0);
    assert_eq!(t.vm.clone_child_stack, 0);
    assert_eq!(t.vm.clone_tls, 0);
    assert_eq!(t.vm.clone_child_tidptr, 0);
}

#[test]
fn contract_spawn_from_clone_preserves_go_clone_child_entry_contract() {
    let mut t = TestVm::new();
    t.vm.tid = 1;
    t.vm.pc = 0x83336;
    t.vm.x[1] = 0x4d9b4;
    t.vm.x[27] = 0x00bf_dc80;

    let child_stack = t.scratch + 0x4000;
    let mp = 0x37d4_c808u64;
    let gp = 0x37d0_8e00u64;
    let fn_ptr = 0x80f30u64;
    let sentinel = 1234u64;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, child_stack - 8, mp);
        tidemark_kernel::guest_mem::write_u64(t.base, child_stack - 16, gp);
        tidemark_kernel::guest_mem::write_u64(t.base, child_stack - 24, fn_ptr);
        tidemark_kernel::guest_mem::write_u64(t.base, child_stack - 32, sentinel);
    }

    let flags = (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS) as u64;
    let ret = thread_impl::sys_clone(&mut t.vm, t.base, flags, child_stack, 0, 0, 0);
    assert!(ret > 0);

    let child_ptr = thread_impl::spawn_from_clone(&t.vm as *const ThreadState as u32, t.base);
    assert_ne!(child_ptr, 0);

    let child = unsafe { &*(child_ptr as *const ThreadState) };
    assert_eq!(child.tid, ret as i32);
    assert_eq!(child.pc, 0x83336);
    assert_eq!(child.x[1], 0x4d9b4);
    assert_eq!(child.x[2], child_stack);
    assert_eq!(child.x[10], 0);
    assert_eq!(child.x[27], 0x00bf_dc80);
    assert_eq!(unsafe { tidemark_kernel::guest_mem::read_u64(t.base, child_stack - 8) }, mp);
    assert_eq!(unsafe { tidemark_kernel::guest_mem::read_u64(t.base, child_stack - 16) }, gp);
    assert_eq!(unsafe { tidemark_kernel::guest_mem::read_u64(t.base, child_stack - 24) }, fn_ptr);
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, child_stack - 32) },
        sentinel
    );
}

#[test]
fn contract_spawn_from_clone_first_thread_step_preserves_go_child_gettid_path() {
    let mut t = TestVm::new();
    let entry_pc = 0x10002u64;
    t.vm.tid = 1;
    t.vm.pc = entry_pc;
    t.vm.x[1] = 0x4d9b4;
    t.vm.x[27] = 0x00bf_dc80;

    let mapped = t.sys_mmap(
        0x10000,
        0x1000,
        PROT_READ | PROT_EXEC,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert_eq!(mapped, 0x10000);

    // Primary source:
    // /usr/lib/go/src/runtime/sys_linux_riscv64.s
    // runtime.clone.abi0 child continuation:
    //   beq zero,a0, ...
    //   sentinel check at -32(sp)
    //   gettid (A7=178)
    //   load fn/g/mp from stack
    //   sd tid -> 64(mp)
    //   sd mp -> 48(g)
    //   mv s11,g
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, entry_pc, 0x00a0_0563);
        tidemark_kernel::guest_mem::write_u32(t.base, entry_pc + 0x0a, 0xfe01_3283);
        tidemark_kernel::guest_mem::write_u32(t.base, entry_pc + 0x0e, 0x4d20_0513);
        tidemark_kernel::guest_mem::write_u32(t.base, entry_pc + 0x12, 0x0055_0463);
        tidemark_kernel::guest_mem::write_u32(t.base, entry_pc + 0x1a, 0x0b20_0893);
        tidemark_kernel::guest_mem::write_u32(t.base, entry_pc + 0x1e, 0x0000_0073);
        tidemark_kernel::guest_mem::write_u32(t.base, entry_pc + 0x22, 0xfe81_3383);
        tidemark_kernel::guest_mem::write_u32(t.base, entry_pc + 0x26, 0xff01_3303);
        tidemark_kernel::guest_mem::write_u32(t.base, entry_pc + 0x2a, 0xff81_3283);
        tidemark_kernel::guest_mem::write_u32(t.base, entry_pc + 0x2e, 0x0050_0963);
        tidemark_kernel::guest_mem::write_u32(t.base, entry_pc + 0x32, 0x0060_0763);
        tidemark_kernel::guest_mem::write_u32(t.base, entry_pc + 0x36, 0x04a2_b023);
        tidemark_kernel::guest_mem::write_u32(t.base, entry_pc + 0x3a, 0x0253_3823);
        tidemark_kernel::guest_mem::write_u16(t.base, entry_pc + 0x3e, 0x8d9a);
    }

    let child_stack = t.scratch + 0x5000;
    let mp = t.scratch + 0x5400;
    let g = t.scratch + 0x5800;
    let fn_ptr = 0x80f30u64;
    let sentinel = 1234u64;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, child_stack - 8, mp);
        tidemark_kernel::guest_mem::write_u64(t.base, child_stack - 16, g);
        tidemark_kernel::guest_mem::write_u64(t.base, child_stack - 24, fn_ptr);
        tidemark_kernel::guest_mem::write_u64(t.base, child_stack - 32, sentinel);
        tidemark_kernel::guest_mem::write_u64(t.base, mp + 64, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, g + 48, 0);
    }

    let flags = (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS) as u64;
    let ret = thread_impl::sys_clone(&mut t.vm, t.base, flags, child_stack, 0, 0, 0);
    assert!(ret > 0);

    let child_ptr = thread_impl::spawn_from_clone(&t.vm as *const ThreadState as u32, t.base);
    assert_ne!(child_ptr, 0);

    let remaining = tidemark_kernel::abi::thread_step(child_ptr, 14);
    assert_eq!(remaining, 0);

    let child = unsafe { &*(child_ptr as *const ThreadState) };
    assert_eq!(child.status, STATUS_OK);
    assert_eq!(child.pc, entry_pc + 0x40);
    assert_eq!(child.x[10], ret as u64);
    assert_eq!(child.x[27], g);
    assert_eq!(unsafe { tidemark_kernel::guest_mem::read_u64(t.base, child_stack - 8) }, mp);
    assert_eq!(unsafe { tidemark_kernel::guest_mem::read_u64(t.base, child_stack - 16) }, g);
    assert_eq!(unsafe { tidemark_kernel::guest_mem::read_u64(t.base, child_stack - 24) }, fn_ptr);
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, child_stack - 32) },
        sentinel
    );
    assert_eq!(unsafe { tidemark_kernel::guest_mem::read_u64(t.base, mp + 64) }, ret as u64);
    assert_eq!(unsafe { tidemark_kernel::guest_mem::read_u64(t.base, g + 48) }, mp);
}

#[test]
fn contract_runtime_notesleep_futex_return_path_preserves_go_worker_context() {
    let mut t = TestVm::new();
    let notesleep_page = t.sys_mmap(
        0x2a000,
        0x1000,
        PROT_READ | PROT_EXEC,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert_eq!(notesleep_page, 0x2a000);
    let futexsleep_page = t.sys_mmap(
        0x4d000,
        0x1000,
        PROT_READ | PROT_EXEC,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert_eq!(futexsleep_page, 0x4d000);
    let futex_page = t.sys_mmap(
        0x83000,
        0x1000,
        PROT_READ | PROT_EXEC,
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

        // cgo_yield pointer slot is null so notesleep loops back.
        tidemark_kernel::guest_mem::write_u64(t.base, 0xbdcad8, 0);
    }

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
    t.vm.pc = 0x83308;
    t.vm.x[1] = 0x4d654;
    t.vm.x[2] = futexsleep_sp;
    t.vm.x[27] = g;

    let remaining = tidemark_kernel::abi::thread_step(&mut t.vm as *mut ThreadState as u32, 64);
    assert!(remaining >= 0);
    assert_eq!(t.vm.status, STATUS_FUTEX_WAIT);
    assert_eq!(t.vm.pc, 0x83308);
    assert_eq!(t.vm.x[27], g);
    assert_eq!(t.vm.x[2], futexsleep_sp);
    assert_eq!(unsafe { tidemark_kernel::guest_mem::read_u64(t.base, futexsleep_sp) }, 0x2a4b0);
}

#[test]
fn contract_runtime_notesleep_futex_wake_return_path_preserves_go_worker_context() {
    let mut t = TestVm::new();
    let notesleep_page = t.sys_mmap(
        0x2a000,
        0x1000,
        PROT_READ | PROT_EXEC,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert_eq!(notesleep_page, 0x2a000);
    let futexsleep_page = t.sys_mmap(
        0x4d000,
        0x1000,
        PROT_READ | PROT_EXEC,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert_eq!(futexsleep_page, 0x4d000);
    let futex_page = t.sys_mmap(
        0x83000,
        0x1000,
        PROT_READ | PROT_EXEC,
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
        PROT_READ | PROT_EXEC,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert_eq!(caller_page, 0x2b000);

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

        // cgo_yield pointer slot is non-zero so notesleep exits after wake.
        tidemark_kernel::guest_mem::write_u64(t.base, 0xbdcad8, 1);

        // Caller target after notesleep returns.
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2b000, 0x0010_0513); // li a0,1
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2b004, 0x0000_8067); // ret
    }

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
    t.vm.pc = 0x83308;
    t.vm.x[1] = 0x4d654;
    t.vm.x[2] = futexsleep_sp;
    t.vm.x[27] = g;

    let remaining = tidemark_kernel::abi::thread_step(&mut t.vm as *mut ThreadState as u32, 64);
    assert!(remaining >= 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, 0x2b000);
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

    let wait_ret = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        addr,
        FUTEX_WAIT as u64,
        7,
        timeout,
        0,
        0,
    );
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

    let wait_ret = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        addr,
        FUTEX_WAIT as u64,
        9,
        timeout,
        0,
        0,
    );
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

#[test]
fn contract_clone_thread_subset_returns_enomem_once_max_threads_slots_are_consumed() {
    let mut t = TestVm::new();
    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.thread_count
        .store(MAX_THREADS as u32, core::sync::atomic::Ordering::Release);
    for (idx, record) in ps.threads.iter_mut().enumerate() {
        *record = ThreadRecord::new((idx + 1) as i32, THREAD_RUNNING, 0x1000 + idx as u32, 0, 0);
    }

    let flags = (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS) as u64;
    let ret = thread_impl::sys_clone(&mut t.vm, t.base, flags, 0, 0, 0, 0);

    assert_eq!(ret, ENOMEM);
    assert_eq!(t.vm.status, STATUS_OK);
}

#[test]
fn contract_clone_thread_tid_starts_above_existing_leader_tid() {
    let mut t = TestVm::new();
    t.vm.tid = 3;
    thread_impl::init_main_thread(&mut t.vm as *mut ThreadState as u32, t.base);

    let flags = (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS) as u64;
    let ret = thread_impl::sys_clone(&mut t.vm, t.base, flags, 0, 0, 0, 0);

    assert_eq!(ret, 4);
    assert_eq!(t.vm.clone_child_tid, 4);
}

#[test]
fn contract_clone_thread_tid_does_not_immediately_reuse_exited_tid() {
    let mut t = TestVm::new();
    t.vm.tid = 3;
    thread_impl::init_main_thread(&mut t.vm as *mut ThreadState as u32, t.base);

    let flags = (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS) as u64;
    let first = thread_impl::sys_clone(&mut t.vm, t.base, flags, 0, 0, 0, 0);
    assert_eq!(first, 4);
    let child_ptr = thread_impl::spawn_from_clone(&mut t.vm as *mut ThreadState as u32, t.base);
    assert_ne!(child_ptr, 0);

    let child_vm = unsafe { &mut *(child_ptr as *mut ThreadState) };
    assert_eq!(child_vm.tid, 4);
    assert_eq!(thread_impl::sys_exit(child_vm, t.base, 0), STATUS_FAULT);

    let second = thread_impl::sys_clone(&mut t.vm, t.base, flags, 0, 0, 0, 0);
    assert_eq!(second, 5);
    assert_eq!(t.vm.clone_child_tid, 5);
}

#[test]
fn contract_clone3_thread_subset_maps_clone_args_to_clone_handoff() {
    let mut t = TestVm::new();
    thread_impl::init_main_thread(&mut t.vm as *mut ThreadState as u32, t.base);

    let args = t.scratch + 0x700;
    let parent_tidptr = t.scratch + 0x760;
    let child_tidptr = t.scratch + 0x768;
    let stack_base = 0x88000u64;
    let stack_size = 0x4000u64;
    let tls = 0x1234_5000u64;
    let flags = CLONE_VM
        | CLONE_THREAD
        | CLONE_SIGHAND
        | CLONE_FS
        | CLONE_SETTLS
        | CLONE_PARENT_SETTID
        | CLONE_CHILD_SETTID
        | CLONE_CHILD_CLEARTID;

    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, args, flags);
        tidemark_kernel::guest_mem::write_u64(t.base, args + 8, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, args + 16, child_tidptr);
        tidemark_kernel::guest_mem::write_u64(t.base, args + 24, parent_tidptr);
        tidemark_kernel::guest_mem::write_u64(t.base, args + 32, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, args + 40, stack_base);
        tidemark_kernel::guest_mem::write_u64(t.base, args + 48, stack_size);
        tidemark_kernel::guest_mem::write_u64(t.base, args + 56, tls);
    }

    let ret = thread_impl::sys_clone3(&mut t.vm, t.base, args, 64);
    assert!(ret > 0);
    assert_eq!(t.vm.status, STATUS_CLONE_SPAWN);
    assert_eq!(t.vm.clone_child_tid, ret as i32);
    assert_eq!(t.vm.clone_child_stack, stack_base + stack_size);
    assert_eq!(t.vm.clone_tls, tls);
    assert_eq!(t.vm.clone_child_tidptr, child_tidptr);
    let written_parent_tid =
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, parent_tidptr) };
    assert_eq!(written_parent_tid, ret as u32);
}

#[test]
fn contract_exit_marks_owned_robust_futex_owner_died_and_wakes_waiters() {
    let mut t = TestVm::new();
    let head = t.scratch + 0x600;
    let node = head + 0x40;
    let futex_addr = node + 8;

    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, head, node);
        tidemark_kernel::guest_mem::write_u64(t.base, head + 8, 8);
        tidemark_kernel::guest_mem::write_u64(t.base, head + 16, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, node, head);
        tidemark_kernel::guest_mem::write_u32(t.base, futex_addr, FUTEX_WAITERS | t.vm.tid as u32);
    }
    t.vm.robust_list_head = head;
    t.vm.robust_list_len = 24;

    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.threads[1] = ThreadRecord::new(
        2,
        THREAD_BLOCKED_FUTEX,
        0xDEAD_BEEFu32,
        0,
        futex_addr as u32,
    );
    ps.thread_count
        .store(2, core::sync::atomic::Ordering::Release);

    let status = thread_impl::sys_exit(&mut t.vm, t.base, 7);
    assert_eq!(status, STATUS_FAULT);
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, futex_addr) },
        FUTEX_WAITERS | FUTEX_OWNER_DIED
    );
    assert_eq!(ps.threads[1].state, THREAD_RUNNING);
    assert_eq!(ps.threads[1].blocked_addr, 0);
}

#[test]
fn contract_exit_group_cleans_up_other_thread_robust_futexes() {
    let mut t = TestVm::new();
    let head = t.scratch + 0x700;
    let node = head + 0x40;
    let futex_addr = node + 8;

    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, head, node);
        tidemark_kernel::guest_mem::write_u64(t.base, head + 8, 8);
        tidemark_kernel::guest_mem::write_u64(t.base, head + 16, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, node, head);
        tidemark_kernel::guest_mem::write_u32(t.base, futex_addr, FUTEX_WAITERS | 2);
    }

    let child_ptr = unsafe {
        tidemark_kernel::alloc::alloc_zeroed(
            core::mem::size_of::<ThreadState>() as u32,
            core::mem::align_of::<ThreadState>() as u32,
        )
    };
    assert_ne!(child_ptr, 0);
    let child = unsafe { &mut *(child_ptr as *mut ThreadState) };
    child.tid = 2;
    child.process_ptr = t.vm.process_ptr;
    child.robust_list_head = head;
    child.robust_list_len = 24;

    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.threads[1] = ThreadRecord::new(2, THREAD_RUNNING, child_ptr, 0, 0);
    ps.thread_count
        .store(2, core::sync::atomic::Ordering::Release);

    let status = thread_impl::sys_exit_group(&mut t.vm, t.base, 9);
    assert_eq!(status, STATUS_FAULT);
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, futex_addr) },
        FUTEX_WAITERS | FUTEX_OWNER_DIED
    );
    assert_eq!(
        ps.thread_count.load(core::sync::atomic::Ordering::Acquire),
        0
    );
    assert_eq!(ps.threads[0].state, THREAD_NONE);
    assert_eq!(ps.threads[1].state, THREAD_NONE);
}

#[test]
fn contract_exit_group_marks_process_dead() {
    let mut t = TestVm::new();
    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.thread_count
        .store(2, core::sync::atomic::Ordering::Release);
    ps.threads[1] = ThreadRecord::new(2, THREAD_RUNNING, 0xCAFE_BABEu32, 0, 0);

    let status = thread_impl::sys_exit_group(&mut t.vm, t.base, 9);
    assert_eq!(status, STATUS_FAULT);
    assert_eq!(t.vm.exit_code, 9);
    assert_eq!(
        ps.thread_count.load(core::sync::atomic::Ordering::Acquire),
        0
    );
    assert_eq!(ps.threads[0].state, THREAD_NONE);
    assert_eq!(ps.threads[1].state, THREAD_NONE);
}

#[test]
fn contract_init_main_thread_records_running_slot() {
    let mut t = TestVm::new();
    let vm_ptr = &mut t.vm as *mut ThreadState as u32;
    thread_impl::init_main_thread(vm_ptr, t.base);

    let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    assert_eq!(
        ps.thread_count.load(core::sync::atomic::Ordering::Acquire),
        1
    );
    assert_eq!(ps.threads[0].tid, 1);
    assert_eq!(ps.threads[0].state, THREAD_RUNNING);
    assert_eq!(ps.threads[0].thread_ptr, vm_ptr);
}

#[test]
fn contract_discard_exec_ignores_invalid_stale_slots() {
    let t = TestVm::new();
    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.thread_count
        .store(2, core::sync::atomic::Ordering::Release);
    ps.threads[1] = ThreadRecord::new(0, THREAD_RUNNING, 0, 0x6e69_622f, 0);

    let discarded = thread_impl::discard_other_threads_for_exec(&t.vm, t.base);
    assert_eq!(discarded, 1);
    assert_eq!(
        ps.thread_count.load(core::sync::atomic::Ordering::Acquire),
        1
    );
    assert_eq!(ps.threads[1].state, THREAD_NONE);
}
