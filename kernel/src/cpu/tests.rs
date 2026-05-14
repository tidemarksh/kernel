use super::atomic::exec_amo;
use crate::abi::{MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE, STATUS_FAULT};
use crate::harness::TestVm;
use core::sync::atomic::Ordering;

/// Test that executing an invalid instruction (all zeros) causes STATUS_FAULT.
///
/// Currently the interpreter sets STATUS_FAULT for unknown opcodes.
/// TODO: Once SIGILL delivery is implemented, this test should verify
/// that SIGILL (signal 4) is queued and delivered to the guest handler.
/// For now we just check the current behavior: status == STATUS_FAULT.
#[test]
fn sigill_on_invalid_instruction() {
    let mut t = TestVm::new();
    let code_addr = t.sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0,
    ) as u64;
    assert!(code_addr > 0);

    // Write an invalid 32-bit instruction: 0x00000000 has opcode bits [6:0] = 0b0000000.
    // The two low bits are not 0b11, so the interpreter first tries compressed decode.
    // The compressed halfword 0x0000 expands to 0 → SIGILL queued → STATUS_FAULT (SIG_DFL).
    // https://man7.org/linux/man-pages/man7/signal.7.html
    unsafe {
        crate::guest_mem::write_u32(t.base, code_addr, 0x0000_0000);
    }

    t.vm.pc = code_addr;
    t.vm.status = crate::abi::STATUS_OK;
    t.vm.sig_mask = 0;
    t.vm.sig_pending = 0;

    unsafe {
        crate::cpu::exec(&mut t.vm, 10, None, None, None, None);
    }

    assert_eq!(
        t.vm.status, STATUS_FAULT,
        "invalid instruction should set STATUS_FAULT via SIGILL"
    );
    assert_eq!(
        t.vm.exit_code,
        128 + crate::abi::SIGILL,
        "exit_code should be 128 + SIGILL"
    );
}

fn encode_amo(funct5: u32, rd: u32, rs1: u32, rs2: u32, funct3: u32) -> u32 {
    (funct5 << 27) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | 0x2f
}

#[test]
fn lr_sc_reservation_is_invalidated_by_intervening_store() {
    let mut t = TestVm::new();
    let ps = unsafe {
        &*((t.base as u64 + t.vm.process_ptr as u64) as *const crate::types::ProcessState)
    };
    ps.thread_count.store(2, Ordering::Release);
    unsafe {
        crate::guest_mem::init(
            core::ptr::addr_of!(ps.reservation_gen) as *const core::sync::atomic::AtomicU32,
            core::ptr::addr_of!(ps.reservation_lock) as *const core::sync::atomic::AtomicU32,
            core::ptr::addr_of!(ps.thread_count),
        );
    }

    let addr = t.scratch + 0x200;
    unsafe { crate::guest_mem::write_u32(t.base, addr, 1) };

    let mut x = [0u64; 32];
    x[10] = addr;
    x[11] = 9;
    x[27] = 0xdead_beef;
    let mut pc = 0u64;

    unsafe {
        exec_amo(
            &mut t.vm,
            &mut x,
            encode_amo(0x02, 5, 10, 0, 2),
            t.base,
            &mut pc,
            4,
        );
    }
    unsafe { crate::guest_mem::write_u32(t.base, addr, 2) };
    unsafe {
        exec_amo(
            &mut t.vm,
            &mut x,
            encode_amo(0x03, 6, 10, 11, 2),
            t.base,
            &mut pc,
            4,
        );
    }

    assert_eq!(x[5], 1, "lr should read the original word");
    assert_eq!(x[6], 1, "sc should fail after an intervening store");
    assert_eq!(unsafe { crate::guest_mem::read_u32(t.base, addr) }, 2);
    assert_eq!(
        x[27], 0xdead_beef,
        "lr/sc must not clobber unrelated registers"
    );
}

#[test]
fn c_addi16sp_does_not_clobber_tp() {
    let mut t = TestVm::new();
    let code_addr = t.sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0,
    ) as u64;
    assert!(code_addr > 0);

    unsafe {
        crate::guest_mem::write_u16(t.base, code_addr, 0x7101);
    }

    t.vm.pc = code_addr;
    t.vm.status = crate::abi::STATUS_OK;
    t.vm.x[2] = 0x8000;
    t.vm.x[4] = 0x1234_5678_9abc_def0;

    unsafe {
        crate::cpu::exec(&mut t.vm, 1, None, None, None, None);
    }

    assert_eq!(t.vm.x[2], 0x7e00, "c.addi16sp must update sp");
    assert_eq!(
        t.vm.x[4], 0x1234_5678_9abc_def0,
        "c.addi16sp must not clobber tp"
    );
}
