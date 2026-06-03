use super::support::*;

#[test]
fn process_create_initializes_tp_from_pt_tls() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let elf = build_test_elf_with_tls(&[0x13, 0x05, 0x70, 0x00], &[0x41, 0x42, 0x43, 0x44], 0x20);

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64 + 0x400, b"/bin/test\0");
    }

    process_clear_args();
    process_push_arg(elf_ptr + 0x400);

    let vm_ptr = test_process_create(elf_ptr, elf.len() as u32, ram_size as u64, 1024 * 1024);
    assert_ne!(vm_ptr, 0);

    let vm = unsafe { &*(vm_ptr as *const tidemark_kernel::types::ThreadState) };
    assert_eq!(vm.tls_base, 0x3000);
    assert_eq!(vm.x[4], 0x3000);
}
