pub(super) use std::vec;
pub(super) use tidemark_kernel::abi::*;
pub(super) use tidemark_kernel::fs::memfs;
pub(super) use tidemark_kernel::harness::TestVm;
pub(super) use tidemark_kernel_tests::support::{
    build_test_elf, build_test_elf_dyn, build_test_elf_dyn_low, build_test_elf_dyn_two_loads,
    build_test_elf_dyn_with_interp, build_test_elf_dyn_with_interp_and_tls,
    build_test_elf_dyn_with_interp_dynamic, build_test_elf_dyn_with_interp_two_loads,
    build_test_elf_with_interp, build_test_elf_with_interp_and_tls, build_test_elf_with_tls,
};

pub(super) fn ensure_dir(parent: u32, name: &[u8]) -> u32 {
    let ino = memfs::lookup(parent, name);
    if ino != 0 {
        ino
    } else {
        memfs::create_dir(parent, name, 0o755)
    }
}

pub(super) fn install_file_at(path: &[u8], bytes: &[u8], mode: u32) -> u32 {
    let trimmed = path.strip_prefix(b"/").unwrap_or(path);
    let mut parts = trimmed.split(|b| *b == b'/').peekable();
    let mut parent = 1u32;
    let mut final_name = b"".as_slice();
    while let Some(part) = parts.next() {
        if parts.peek().is_some() {
            parent = ensure_dir(parent, part);
        } else {
            final_name = part;
        }
    }
    let ino = match memfs::lookup(parent, final_name) {
        0 => memfs::create_file(parent, final_name, mode),
        ino => ino,
    };
    assert_ne!(ino, 0);
    assert_eq!(memfs::truncate(ino, 0), 0);
    assert_eq!(memfs::write_file(ino, 0, bytes), bytes.len() as i64);
    ino
}
pub(super) fn find_auxv_value(base: u32, sp: u64, tag: u64) -> Option<u64> {
    let argc = unsafe { tidemark_kernel::guest_mem::read_u64(base, sp) };
    let mut cursor = sp + 8;
    cursor += argc * 8 + 8;
    while unsafe { tidemark_kernel::guest_mem::read_u64(base, cursor) } != 0 {
        cursor += 8;
    }
    cursor += 8;
    for _ in 0..32 {
        let aux_tag = unsafe { tidemark_kernel::guest_mem::read_u64(base, cursor) };
        let aux_val = unsafe { tidemark_kernel::guest_mem::read_u64(base, cursor + 8) };
        if aux_tag == tidemark_kernel::elf::AT_NULL {
            return None;
        }
        if aux_tag == tag {
            return Some(aux_val);
        }
        cursor += 16;
    }
    None
}
