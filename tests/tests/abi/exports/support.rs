pub(super) use tidemark_kernel::abi::*;
pub(super) use tidemark_kernel::fs::memfs;
pub(super) use tidemark_kernel::harness::TestVm;
pub(super) use tidemark_kernel_tests::support::{
    build_test_elf, build_test_elf_dyn, build_test_elf_dyn_low, build_test_elf_dyn_two_loads,
    build_test_elf_dyn_with_interp, build_test_elf_dyn_with_interp_and_tls,
    build_test_elf_dyn_with_interp_dynamic, build_test_elf_dyn_with_interp_two_loads,
    build_test_elf_with_interp, build_test_elf_with_interp_and_tls, build_test_elf_with_tls,
    find_auxv_value, install_memfs_file_at as install_file_at,
};

pub(super) fn test_process_guest_base() -> u32 {
    let base = process_guest_base_for_address_profile(abi_guest_address_profile_target());
    assert_ne!(base, 0);
    assert!(base <= u32::MAX as u64);
    base as u32
}

pub(super) fn test_process_inspect_elf_brk(
    elf_ptr: u32,
    elf_len: u32,
    guest_memory_policy_limit: u64,
) -> u64 {
    process_inspect_elf_brk_with_memory_policy(
        elf_ptr,
        elf_len,
        abi_guest_address_profile_target(),
        guest_memory_policy_limit,
    )
}

pub(super) fn test_process_create(
    elf_ptr: u32,
    elf_len: u32,
    guest_memory_policy_limit: u64,
    stack_size: u32,
) -> u32 {
    process_create_with_memory_policy(
        elf_ptr,
        elf_len,
        abi_guest_address_profile_target(),
        guest_memory_policy_limit,
        0,
        stack_size,
    )
}
