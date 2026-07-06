pub(super) use std::sync::atomic::Ordering;
pub(super) use std::vec::Vec;
pub(super) use tidemark_kernel::abi::*;
pub(super) use tidemark_kernel::fs::memfs;
pub(super) use tidemark_kernel::guest_mem;
pub(super) use tidemark_kernel::harness::TestVm;
pub(super) use tidemark_kernel::syscall::process as process_impl;
pub(super) use tidemark_kernel::syscall::signal;
pub(super) use tidemark_kernel::syscall::thread as thread_impl;
pub(super) use tidemark_kernel::types::{
    FdEntry, ProcessState, THREAD_NONE, THREAD_RUNNING, ThreadRecord, ThreadState,
};
pub(super) use tidemark_kernel_tests::support::{
    build_test_elf, build_test_elf_dyn, build_test_elf_dyn_low, build_test_elf_dyn_two_loads,
    build_test_elf_dyn_with_interp, build_test_elf_dyn_with_interp_and_tls,
    build_test_elf_dyn_with_interp_dynamic, build_test_elf_dyn_with_interp_two_loads,
    build_test_elf_with_interp, build_test_elf_with_interp_and_tls, build_test_elf_with_tls,
    ensure_memfs_dir as ensure_dir, find_vm_auxv_value as find_auxv_value, install_exec_file,
    install_exec_file_at, write_process_ids, write_strvec,
};

pub(super) const EPOLL_CTL_ADD: u64 = 1;
pub(super) const EPOLL_CTL_DEL: u64 = 2;
pub(super) const EPOLLIN: u32 = 0x001;
pub(super) const WNOHANG: u64 = 1;
pub(super) const WUNTRACED: u64 = 2;
pub(super) const WCONTINUED: u64 = 8;
pub(super) const WNOWAIT: u64 = 0x01000000;
pub(super) const WEXITED: u64 = 4;
pub(super) const P_ALL: u32 = 0;
pub(super) const P_PID: u32 = 1;
pub(super) const ECHILD: i64 = -10;
pub(super) const CLD_KILLED: u32 = 2;
pub(super) const SS_DISABLE: i32 = 2;

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

pub(super) const SIGINFO_OFF_SI_PID: u64 = 16;
pub(super) const SIGINFO_OFF_SI_CODE: u64 = 8;
pub(super) const SIGINFO_OFF_SI_SIGNO: u64 = 0;
pub(super) const SIGINFO_OFF_SI_STATUS: u64 = 24;
