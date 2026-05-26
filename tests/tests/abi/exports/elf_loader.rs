use super::support::*;

#[test]
fn process_inspect_elf_brk_accepts_et_dyn() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let elf = build_test_elf_dyn(&[0x13, 0x05, 0x70, 0x00]);

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
    }

    assert_eq!(
        process_inspect_elf_brk(elf_ptr, elf.len() as u32, ram_size),
        0x2000
    );
}
