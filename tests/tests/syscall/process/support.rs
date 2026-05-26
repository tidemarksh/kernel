pub(super) use std::sync::atomic::Ordering;
pub(super) use std::vec;
pub(super) use std::vec::Vec;
pub(super) use tidemark_kernel::abi::*;
pub(super) use tidemark_kernel::elf::AT_NULL;
pub(super) use tidemark_kernel::fs::memfs;
pub(super) use tidemark_kernel::guest_mem;
pub(super) use tidemark_kernel::harness::TestVm;
pub(super) use tidemark_kernel::syscall::process as process_impl;
pub(super) use tidemark_kernel::syscall::signal;
pub(super) use tidemark_kernel::syscall::thread as thread_impl;
pub(super) use tidemark_kernel::types::{
    FdEntry, ProcessState, THREAD_NONE, THREAD_RUNNING, ThreadRecord,
};
pub(super) use tidemark_kernel_tests::support::{
    build_test_elf, build_test_elf_dyn, build_test_elf_dyn_low, build_test_elf_dyn_two_loads,
    build_test_elf_dyn_with_interp, build_test_elf_dyn_with_interp_and_tls,
    build_test_elf_dyn_with_interp_dynamic, build_test_elf_dyn_with_interp_two_loads,
    build_test_elf_with_interp, build_test_elf_with_interp_and_tls, build_test_elf_with_tls,
};

pub(super) const EPOLL_CTL_ADD: u64 = 1;
pub(super) const EPOLL_CTL_DEL: u64 = 2;
pub(super) const EPOLLIN: u32 = 0x001;
pub(super) const WNOHANG: u64 = 1;
pub(super) const WUNTRACED: u64 = 2;
pub(super) const WCONTINUED: u64 = 8;
pub(super) const WNOWAIT: u64 = 0x01000000;
pub(super) const WEXITED: u64 = 4;
pub(super) const P_PID: u32 = 1;
pub(super) const ECHILD: i64 = -10;
pub(super) const SS_DISABLE: i32 = 2;

pub(super) fn write_process_ids(t: &TestVm, pid: i32, ppid: i32) {
    let ps_ptr = t.vm.process_ptr as u64;
    let pid_off = core::mem::offset_of!(ProcessState, pid) as u64;
    let ppid_off = core::mem::offset_of!(ProcessState, ppid) as u64;
    unsafe {
        guest_mem::write_u32(t.base, ps_ptr + pid_off, pid as u32);
        guest_mem::write_u32(t.base, ps_ptr + ppid_off, ppid as u32);
    }
}

pub(super) fn ensure_dir(parent: u32, name: &[u8]) -> u32 {
    let ino = memfs::lookup(parent, name);
    if ino != 0 {
        ino
    } else {
        memfs::create_dir(parent, name, 0o755)
    }
}

pub(super) fn read_file_bytes(path: &[u8]) -> Vec<u8> {
    let ino = memfs::resolve_path(path);
    assert_ne!(ino, 0, "missing memfs path: {:?}", path);
    let size = memfs::stat(ino).unwrap().size as usize;
    let mut buf = vec![0u8; size];
    let n = memfs::read_file(ino, 0, &mut buf);
    assert_eq!(n as usize, size);
    buf
}

pub(super) fn read_link_bytes(path: &[u8]) -> Vec<u8> {
    let ino = memfs::resolve_path(path);
    assert_ne!(ino, 0, "missing symlink path: {:?}", path);
    let mut buf = vec![0u8; 512];
    let n = memfs::read_link(ino, &mut buf);
    buf.truncate(n);
    buf
}
pub(super) fn install_exec_file(t: &TestVm, name: &[u8], elf_bytes: &[u8]) -> u64 {
    let bin = ensure_dir(1, b"bin");
    let ino = match memfs::lookup(bin, name) {
        0 => memfs::create_file(bin, name, 0o755),
        ino => ino,
    };
    assert!(ino != 0);
    assert_eq!(memfs::truncate(ino, 0), 0);
    assert_eq!(memfs::write_file(ino, 0, elf_bytes), elf_bytes.len() as i64);

    let mut path = Vec::from(&b"/bin/"[..]);
    path.extend_from_slice(name);
    path.push(0);
    let path_addr = t.scratch;
    t.write_mem(path_addr, &path);
    path_addr
}

pub(super) fn install_exec_file_at(t: &TestVm, path: &[u8], elf_bytes: &[u8]) -> u64 {
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
        0 => memfs::create_file(parent, final_name, 0o755),
        ino => ino,
    };
    assert!(ino != 0);
    assert_eq!(memfs::truncate(ino, 0), 0);
    assert_eq!(memfs::write_file(ino, 0, elf_bytes), elf_bytes.len() as i64);
    let mut c_path = Vec::from(path);
    c_path.push(0);
    let path_addr = t.scratch;
    t.write_mem(path_addr, &c_path);
    path_addr
}

pub(super) fn find_auxv_value(t: &TestVm, tag: u64) -> Option<u64> {
    let argc = unsafe { guest_mem::read_u64(t.base, t.vm.x[2]) };
    let mut cursor = t.vm.x[2] + 8;
    cursor += argc * 8 + 8;
    while unsafe { guest_mem::read_u64(t.base, cursor) } != 0 {
        cursor += 8;
    }
    cursor += 8;
    for _ in 0..32 {
        let aux_tag = unsafe { guest_mem::read_u64(t.base, cursor) };
        let aux_val = unsafe { guest_mem::read_u64(t.base, cursor + 8) };
        if aux_tag == AT_NULL {
            return None;
        }
        if aux_tag == tag {
            return Some(aux_val);
        }
        cursor += 16;
    }
    None
}

pub(super) fn write_strvec(t: &TestVm, offset: u64, values: &[&[u8]]) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let vec_addr = t.scratch + offset;
    let mut data_cursor = vec_addr + ((values.len() + 1) as u64) * 8;
    for (idx, value) in values.iter().enumerate() {
        unsafe {
            guest_mem::write_u64(t.base, vec_addr + (idx as u64) * 8, data_cursor);
            guest_mem::write_bytes(t.base, data_cursor, value);
            guest_mem::write_u8(t.base, data_cursor + value.len() as u64, 0);
        }
        data_cursor += value.len() as u64 + 1;
    }
    unsafe {
        guest_mem::write_u64(t.base, vec_addr + (values.len() as u64) * 8, 0);
    }
    vec_addr
}

pub(super) const SIGINFO_OFF_SI_PID: u64 = 16;
pub(super) const SIGINFO_OFF_SI_STATUS: u64 = 24;
