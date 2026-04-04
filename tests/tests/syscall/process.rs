use std::vec;
use std::vec::Vec;
use tidemark_kernel::abi::*;
use tidemark_kernel::fs::memfs;
use tidemark_kernel::guest_mem;
use tidemark_kernel::harness::TestVm;
use tidemark_kernel::syscall::process as process_impl;
use tidemark_kernel::syscall::thread as thread_impl;
use tidemark_kernel::types::{FdEntry, ProcessState, THREAD_NONE, THREAD_RUNNING, ThreadRecord};

const EPOLL_CTL_ADD: u64 = 1;
const EPOLL_CTL_DEL: u64 = 2;
const EPOLLIN: u32 = 0x001;
const WNOHANG: u64 = 1;
const WNOWAIT: u64 = 0x01000000;
const WEXITED: u64 = 4;
const P_PID: u32 = 1;
const ECHILD: i64 = -10;

fn write_process_ids(t: &TestVm, pid: i32, ppid: i32) {
    let ps_ptr = t.vm.process_ptr as u64;
    let pid_off = core::mem::offset_of!(ProcessState, pid) as u64;
    let ppid_off = core::mem::offset_of!(ProcessState, ppid) as u64;
    unsafe {
        guest_mem::write_u32(t.base, ps_ptr + pid_off, pid as u32);
        guest_mem::write_u32(t.base, ps_ptr + ppid_off, ppid as u32);
    }
}

fn ensure_dir(parent: u32, name: &[u8]) -> u32 {
    let ino = memfs::lookup(parent, name);
    if ino != 0 {
        ino
    } else {
        memfs::create_dir(parent, name, 0o755)
    }
}

fn build_test_elf(code: &[u8]) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let mut elf = vec![0u8; 0x100 + code.len()];
    elf[0] = 0x7f;
    elf[1] = b'E';
    elf[2] = b'L';
    elf[3] = b'F';
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    put_u16(&mut elf, 16, 2);
    put_u16(&mut elf, 18, 243);
    put_u32(&mut elf, 20, 1);
    put_u64(&mut elf, 24, 0x1000);
    put_u64(&mut elf, 32, 64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, 1);

    put_u32(&mut elf, 64, 1);
    put_u32(&mut elf, 68, 5);
    put_u64(&mut elf, 72, 0x100);
    put_u64(&mut elf, 80, 0x1000);
    put_u64(&mut elf, 96, code.len() as u64);
    put_u64(&mut elf, 104, code.len() as u64);
    put_u64(&mut elf, 112, 0x1000);
    elf[0x100..0x100 + code.len()].copy_from_slice(code);
    elf
}

fn build_test_elf_with_tls(code: &[u8], tls_init: &[u8], tls_memsz: u64) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let code_off = 0x100usize;
    let data_off = 0x200usize;
    let entry = 0x1000u64 + code_off as u64;
    let code_filesz = (code_off + code.len()) as u64;
    let data_vaddr = 0x3000u64;
    let data_filesz = tls_init.len() as u64;
    let data_memsz = tls_memsz.max(data_filesz);
    let total_len = data_off + tls_init.len();
    let mut elf = vec![0u8; total_len];
    elf[0] = 0x7f;
    elf[1] = b'E';
    elf[2] = b'L';
    elf[3] = b'F';
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    put_u16(&mut elf, 16, 2);
    put_u16(&mut elf, 18, 243);
    put_u32(&mut elf, 20, 1);
    put_u64(&mut elf, 24, entry);
    put_u64(&mut elf, 32, 64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, 3);

    put_u32(&mut elf, 64, 1);
    put_u32(&mut elf, 68, 5);
    put_u64(&mut elf, 72, 0);
    put_u64(&mut elf, 80, 0x1000);
    put_u64(&mut elf, 96, code_filesz);
    put_u64(&mut elf, 104, code_filesz);
    put_u64(&mut elf, 112, 0x1000);

    put_u32(&mut elf, 120, 1);
    put_u32(&mut elf, 124, 6);
    put_u64(&mut elf, 128, data_off as u64);
    put_u64(&mut elf, 136, data_vaddr);
    put_u64(&mut elf, 152, data_filesz);
    put_u64(&mut elf, 160, data_memsz);
    put_u64(&mut elf, 168, 0x1000);

    put_u32(&mut elf, 176, 7);
    put_u32(&mut elf, 180, 4);
    put_u64(&mut elf, 184, data_off as u64);
    put_u64(&mut elf, 192, data_vaddr);
    put_u64(&mut elf, 208, data_filesz);
    put_u64(&mut elf, 216, tls_memsz);
    put_u64(&mut elf, 224, 8);

    elf[code_off..code_off + code.len()].copy_from_slice(code);
    elf[data_off..data_off + tls_init.len()].copy_from_slice(tls_init);
    elf
}

fn build_test_elf_dyn(code: &[u8]) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let mut elf = vec![0u8; 0x100 + code.len()];
    elf[0] = 0x7f;
    elf[1] = b'E';
    elf[2] = b'L';
    elf[3] = b'F';
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    put_u16(&mut elf, 16, 3);
    put_u16(&mut elf, 18, 243);
    put_u32(&mut elf, 20, 1);
    put_u64(&mut elf, 24, 0x1000);
    put_u64(&mut elf, 32, 64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, 1);

    put_u32(&mut elf, 64, 1);
    put_u32(&mut elf, 68, 5);
    put_u64(&mut elf, 72, 0x100);
    put_u64(&mut elf, 80, 0x1000);
    put_u64(&mut elf, 96, code.len() as u64);
    put_u64(&mut elf, 104, code.len() as u64);
    put_u64(&mut elf, 112, 0x1000);
    elf[0x100..0x100 + code.len()].copy_from_slice(code);
    elf
}

fn build_test_elf_dyn_with_interp(code: &[u8], interp: &[u8]) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let code_off = 0x100usize;
    let interp_off = 0x200usize;
    let entry = 0x1000u64;
    let total_len = interp_off + interp.len();
    let mut elf = vec![0u8; total_len];
    elf[0] = 0x7f;
    elf[1] = b'E';
    elf[2] = b'L';
    elf[3] = b'F';
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    put_u16(&mut elf, 16, 3);
    put_u16(&mut elf, 18, 243);
    put_u32(&mut elf, 20, 1);
    put_u64(&mut elf, 24, entry);
    put_u64(&mut elf, 32, 64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, 2);

    put_u32(&mut elf, 64, 1);
    put_u32(&mut elf, 68, 5);
    put_u64(&mut elf, 72, code_off as u64);
    put_u64(&mut elf, 80, entry);
    put_u64(&mut elf, 96, code.len() as u64);
    put_u64(&mut elf, 104, code.len() as u64);
    put_u64(&mut elf, 112, 0x1000);

    put_u32(&mut elf, 120, 3);
    put_u32(&mut elf, 124, 4);
    put_u64(&mut elf, 128, interp_off as u64);
    put_u64(&mut elf, 136, 0);
    put_u64(&mut elf, 152, interp.len() as u64);
    put_u64(&mut elf, 160, interp.len() as u64);
    put_u64(&mut elf, 168, 1);

    elf[code_off..code_off + code.len()].copy_from_slice(code);
    elf[interp_off..interp_off + interp.len()].copy_from_slice(interp);
    elf
}

fn install_exec_file(t: &TestVm, name: &[u8], elf_bytes: &[u8]) -> u64 {
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

fn write_strvec(t: &TestVm, offset: u64, values: &[&[u8]]) -> u64 {
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

const SIGINFO_OFF_SI_PID: u64 = 16;
const SIGINFO_OFF_SI_STATUS: u64 = 24;

#[test]
fn contract_vfork_snapshots_and_suspends_parent() {
    let mut t = TestVm::new();
    t.vm.x[1] = 0xDEAD;
    t.vm.pc = 0x1000;

    let status = process_impl::sys_vfork(&mut t.vm, t.base);
    assert_eq!(status, STATUS_VFORK_WAIT);
    assert_eq!(t.vm.x[10], 0);
    assert_eq!(t.vm.status, STATUS_VFORK_WAIT);
    assert!(process_impl::vfork_child_pid() > 0);
}

#[test]
fn contract_vfork_parent_resume_restores_state() {
    let mut t = TestVm::new();
    t.vm.x[1] = 0xBEEF;
    t.vm.pc = 0x2000;
    t.vm.sig_pending = 1 << (SIGTERM - 1);
    t.vm.fault_pc = 0x4444;
    t.vm.fault_addr = 0x5555;
    t.vm.blocked_fd = 17;
    t.vm.blocked_ofd_id = 23;
    t.vm.epoll_timeout_ms = 99;
    t.vm.clone_pending = 1;
    t.vm.clone_child_tid = 77;

    process_impl::sys_vfork(&mut t.vm, t.base);
    assert_eq!(t.vm.sig_pending, 0);

    t.vm.x[1] = 0xFFFF;
    t.vm.pc = 0x9999;
    t.vm.fault_pc = 0xAAAA;
    t.vm.fault_addr = 0xBBBB;
    t.vm.blocked_fd = 0;
    t.vm.blocked_ofd_id = 0;
    t.vm.epoll_timeout_ms = -1;
    t.vm.clone_pending = 0;
    t.vm.clone_child_tid = 0;

    process_impl::vfork_parent_resume(&mut t.vm, 42);
    assert_eq!(t.vm.x[1], 0xBEEF);
    assert_eq!(t.vm.pc, 0x2000);
    assert_eq!(t.vm.x[10], 42);
    assert_eq!(t.vm.sig_pending, 1 << (SIGTERM - 1));
    assert_eq!(t.vm.fault_pc, 0x4444);
    assert_eq!(t.vm.fault_addr, 0x5555);
    assert_eq!(t.vm.blocked_fd, 17);
    assert_eq!(t.vm.blocked_ofd_id, 23);
    assert_eq!(t.vm.epoll_timeout_ms, 99);
    assert_eq!(t.vm.clone_pending, 1);
    assert_eq!(t.vm.clone_child_tid, 77);
    assert_eq!(t.vm.status, STATUS_OK);
}

#[test]
fn contract_vfork_exit_preserves_parent_thread_state() {
    let mut t = TestVm::new();
    let thread_count_off = core::mem::offset_of!(ProcessState, thread_count) as u64;

    process_impl::sys_vfork(&mut t.vm, t.base);
    let child_pid = process_impl::vfork_child_pid();
    assert!(child_pid > 0);

    let status = thread_impl::sys_exit(&mut t.vm, t.base, 7);
    assert_eq!(status, STATUS_FAULT);

    let thread_count = unsafe { guest_mem::read_u32(t.base, t.vm.process_ptr as u64 + thread_count_off) };
    assert_eq!(thread_count, 1);

    process_impl::record_child_exit(child_pid, ((t.vm.exit_code as u32) << 8) as i32);
    process_impl::vfork_parent_resume(&mut t.vm, child_pid);
    assert_eq!(t.vm.x[10], child_pid as u64);
    assert_eq!(t.vm.status, STATUS_OK);
}

#[test]
fn contract_execve_completes_in_place_without_spawn() {
    let mut t = TestVm::new();
    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let path_addr = install_exec_file(&t, b"test", &elf);

    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(ret, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.spawn_kind, SPAWN_KIND_NONE);
    assert_eq!(t.vm.spawn_child_pid, 0);
    assert_eq!(t.vm.pc, 0x1000);
}

#[test]
fn contract_execve_initializes_tp_from_pt_tls() {
    let mut t = TestVm::new();
    let elf = build_test_elf_with_tls(&[0x13, 0x05, 0x70, 0x00], &[0x41, 0x42, 0x43, 0x44], 0x20);
    let path_addr = install_exec_file(&t, b"test_tls", &elf);

    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(ret, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.tls_base, 0x3000);
    assert_eq!(t.vm.x[4], 0x3000);
}

#[test]
fn contract_execve_accepts_et_dyn_without_pt_interp() {
    let mut t = TestVm::new();
    let elf = build_test_elf_dyn(&[0x13, 0x05, 0x70, 0x00]);
    let path_addr = install_exec_file(&t, b"test_dyn", &elf);

    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(ret, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.spawn_kind, SPAWN_KIND_NONE);
    assert_eq!(t.vm.pc, 0x1000);
}

#[test]
#[ignore = "requires ET_DYN + PT_INTERP execve loader support"]
fn contract_execve_accepts_et_dyn_with_pt_interp() {
    let mut t = TestVm::new();
    let elf = build_test_elf_dyn_with_interp(
        &[0x13, 0x05, 0x70, 0x00],
        b"/lib/ld-linux-riscv64-lp64d.so.1\0",
    );
    let path_addr = install_exec_file(&t, b"test_dyn", &elf);

    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(ret, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.spawn_kind, SPAWN_KIND_NONE);
}

#[test]
fn contract_execve_preserves_host_stdio_slots() {
    let mut t = TestVm::new();
    let ps_addr = t.vm.process_ptr as u64;
    let stdin_pipe_off = core::mem::offset_of!(ProcessState, stdin_pipe_slot) as u64;
    let stdout_pipe_off = core::mem::offset_of!(ProcessState, stdout_pipe_slot) as u64;
    let stderr_pipe_off = core::mem::offset_of!(ProcessState, stderr_pipe_slot) as u64;
    let old_stdin = unsafe { guest_mem::read_u32(t.base, ps_addr + stdin_pipe_off) };
    let old_stdout = unsafe { guest_mem::read_u32(t.base, ps_addr + stdout_pipe_off) };
    let old_stderr = unsafe { guest_mem::read_u32(t.base, ps_addr + stderr_pipe_off) };
    assert!(old_stdin != 0 && old_stdout != 0 && old_stderr != 0);

    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let path_addr = install_exec_file(&t, b"test", &elf);
    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(ret, 0);

    let new_ps_addr = t.vm.process_ptr as u64;
    let new_stdin = unsafe { guest_mem::read_u32(t.base, new_ps_addr + stdin_pipe_off) };
    let new_stdout = unsafe { guest_mem::read_u32(t.base, new_ps_addr + stdout_pipe_off) };
    let new_stderr = unsafe { guest_mem::read_u32(t.base, new_ps_addr + stderr_pipe_off) };
    assert_eq!(new_stdin, old_stdin);
    assert_eq!(new_stdout, old_stdout);
    assert_eq!(new_stderr, old_stderr);
}

#[test]
fn contract_fork_returns_status_execve_spawn() {
    let mut t = TestVm::new();
    let ret = process_impl::sys_fork(&mut t.vm, t.base, 0, 0, 0, 0, 0);
    assert!(ret > 0);
    assert_eq!(t.vm.status, STATUS_EXECVE_SPAWN);
    assert_eq!(t.vm.spawn_kind, SPAWN_KIND_FORK);
    assert_eq!(t.vm.spawn_child_pid, ret as i32);
    assert_eq!(t.vm.spawn_path, 0);
}

#[test]
fn contract_vfork_parent_resume_clears_spawn_handoff() {
    let mut t = TestVm::new();
    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let path_addr = install_exec_file(&t, b"test", &elf);

    process_impl::sys_vfork(&mut t.vm, t.base);
    let child_pid = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(t.vm.status, STATUS_EXECVE_SPAWN);
    assert_eq!(t.vm.spawn_kind, SPAWN_KIND_EXECVE);

    process_impl::vfork_parent_resume(&mut t.vm, child_pid as i32);
    assert_eq!(t.vm.spawn_kind, SPAWN_KIND_NONE);
    assert_eq!(t.vm.spawn_child_pid, 0);
    assert_eq!(t.vm.x[10], child_pid as u64);
}

#[test]
fn contract_vfork_execve_failure_does_not_publish_spawn_handoff() {
    let mut t = TestVm::new();
    let path_addr = install_exec_file(&t, b"bad", b"not-an-elf");

    process_impl::sys_vfork(&mut t.vm, t.base);
    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(ret, ENOEXEC);
    assert_eq!(t.vm.status, STATUS_VFORK_WAIT);
    assert_eq!(t.vm.spawn_kind, SPAWN_KIND_NONE);
    assert_eq!(t.vm.spawn_child_pid, 0);
}

#[test]
fn semantics_execve_discards_other_threads_on_success() {
    let mut t = TestVm::new();
    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.thread_count.store(2, core::sync::atomic::Ordering::Release);
    ps.threads[1] = ThreadRecord::new(2, THREAD_RUNNING, 0xFEED_BEEFu32, 0, 0);
    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let path_addr = install_exec_file(&t, b"test", &elf);
    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(ret, 0);
    let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    assert_eq!(ps.thread_count.load(core::sync::atomic::Ordering::Acquire), 1);
    assert_eq!(ps.threads[0].state, THREAD_RUNNING);
    assert_eq!(ps.threads[1].state, THREAD_NONE);
}

#[test]
fn semantics_execve_clears_alt_stack() {
    let mut t = TestVm::new();
    t.vm.sigaltstack_sp = 0x5000;
    t.vm.sigaltstack_size = 8192;

    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let path_addr = install_exec_file(&t, b"test", &elf);
    process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);

    assert_eq!(t.vm.sigaltstack_sp, 0);
    assert_eq!(t.vm.sigaltstack_size, 0);
}

#[test]
fn semantics_execve_preserves_signal_mask_and_pending() {
    let mut t = TestVm::new();
    t.vm.sig_mask = (1u64 << (SIGALRM - 1)) | (1u64 << (SIGTERM - 1));
    t.vm.sig_pending = 1u64 << (SIGCHLD - 1);

    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let path_addr = install_exec_file(&t, b"test", &elf);
    process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);

    assert_eq!(t.vm.sig_mask, (1u64 << (SIGALRM - 1)) | (1u64 << (SIGTERM - 1)));
    assert_eq!(t.vm.sig_pending, 1u64 << (SIGCHLD - 1));
}

#[test]
fn semantics_execve_in_place_reload_rebuilds_process_state() {
    let mut t = TestVm::new();
    let mapped = tidemark_kernel::syscall::memory::sys_mmap(
        &mut t.vm,
        t.base,
        0,
        PAGE_SIZE,
        PROT_NONE as u64,
        (MAP_PRIVATE | MAP_ANONYMOUS) as u64,
        -1,
        0,
    );
    assert!(mapped >= 0);
    assert!(tidemark_kernel::syscall::memory::has_prot_none());

    t.memfs.create_file(b"keep.txt", b"payload");
    let kept_fd = t.sys_openat(b"/keep.txt", O_RDONLY);
    assert_eq!(kept_fd, 3);
    let cloexec_fd = t.sys_dup(kept_fd as u64);
    assert_eq!(cloexec_fd, 4);
    assert_eq!(t.sys_fcntl(cloexec_fd as u64, 2, 1), 0);

    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let path_addr = install_exec_file(&t, b"test", &elf);
    let argv_addr = write_strvec(&t, 0x400, &[b"/bin/test", b"arg1"]);
    let envp_addr = write_strvec(&t, 0x800, &[b"KEY=VALUE"]);

    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, argv_addr, envp_addr);
    assert_eq!(ret, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, 0x1000);
    assert_eq!(t.vm.tid, 1);
    assert!(!tidemark_kernel::syscall::memory::range_has_prot_none(mapped as u64, PAGE_SIZE));

    let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    assert_eq!(ps.pid, 42);
    let kept_entry = unsafe {
        guest_mem::read_u32(
            t.base,
            t.vm.process_ptr as u64 + 3 * core::mem::size_of::<FdEntry>() as u64,
        )
    };
    let cloexec_entry = unsafe {
        guest_mem::read_u32(
            t.base,
            t.vm.process_ptr as u64 + 4 * core::mem::size_of::<FdEntry>() as u64,
        )
    };
    assert_ne!(kept_entry, 0);
    assert_eq!(cloexec_entry, 0);

    let argc = unsafe { guest_mem::read_u64(t.base, t.vm.x[2]) };
    assert_eq!(argc, 2);
    let argv0 = unsafe { guest_mem::read_u64(t.base, t.vm.x[2] + 8) };
    let argv1 = unsafe { guest_mem::read_u64(t.base, t.vm.x[2] + 16) };
    let env0 = unsafe { guest_mem::read_u64(t.base, t.vm.x[2] + 32) };
    let mut buf = [0u8; 32];
    let len0 = unsafe { guest_mem::read_cstr(t.base, argv0, &mut buf) };
    assert_eq!(&buf[..len0], b"/bin/test");
    let len1 = unsafe { guest_mem::read_cstr(t.base, argv1, &mut buf) };
    assert_eq!(&buf[..len1], b"arg1");
    let env_len = unsafe { guest_mem::read_cstr(t.base, env0, &mut buf) };
    assert_eq!(&buf[..env_len], b"KEY=VALUE");
    assert!(argv0 > t.vm.x[2]);
    assert!(argv1 > t.vm.x[2]);
    assert!(env0 > t.vm.x[2]);
}

#[test]
fn semantics_execve_clears_blocked_resume_scratch() {
    let mut t = TestVm::new();
    let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    let stdout_ofd = ps.fd_table[1].ofd_id;
    assert!(stdout_ofd > 0);

    tidemark_kernel::fs::fd_table::retain_ofd_id(stdout_ofd);
    t.vm.blocked_fd = 1;
    t.vm.blocked_ofd_id = stdout_ofd;
    t.vm.futex_wait_addr = 0x1234;
    t.vm.futex_wait_timeout = 0x5678;
    t.vm.futex_wait_expected = 0x9abc;
    t.vm.epoll_timeout_ms = 99;

    let before = tidemark_kernel::fs::fd_table::get_ofd_by_id(stdout_ofd).expect("stdout OFD should exist");
    assert_eq!(before.refcount, 2);

    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let path_addr = install_exec_file(&t, b"test", &elf);

    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(ret, 0);
    assert_eq!(t.vm.blocked_fd, 0);
    assert_eq!(t.vm.blocked_ofd_id, 0);
    assert_eq!(t.vm.futex_wait_addr, 0);
    assert_eq!(t.vm.futex_wait_timeout, 0);
    assert_eq!(t.vm.futex_wait_expected, 0);
    assert_eq!(t.vm.epoll_timeout_ms, 0);

    let after = tidemark_kernel::fs::fd_table::get_ofd_by_id(stdout_ofd).expect("stdout OFD should survive execve");
    assert_eq!(after.refcount, 1);
}

#[test]
fn semantics_vfork_execve_preserves_stdio_fds() {
    let mut t = TestVm::new();
    let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    let old_fd0 = ps.fd_table[0].ofd_id;
    let old_fd1 = ps.fd_table[1].ofd_id;
    let old_fd2 = ps.fd_table[2].ofd_id;
    assert!(old_fd0 != 0 && old_fd1 != 0 && old_fd2 != 0);

    let status = process_impl::sys_vfork(&mut t.vm, t.base);
    assert_eq!(status, STATUS_VFORK_WAIT);

    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let path_addr = install_exec_file(&t, b"test", &elf);
    let child_pid = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert!(child_pid > 0);
    assert_eq!(t.vm.status, STATUS_EXECVE_SPAWN);

    process_impl::clear_vfork_runtime_state();
    let ret = process_impl::complete_execve_in_place_from_handoff(
        &mut t.vm,
        t.base,
        process_impl::EXECVE_RAM_LIMIT,
    );
    assert_eq!(ret, 0);

    let new_ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    assert_eq!(new_ps.fd_table[0].ofd_id, old_fd0);
    assert_eq!(new_ps.fd_table[1].ofd_id, old_fd1);
    assert_eq!(new_ps.fd_table[2].ofd_id, old_fd2);
}

#[test]
fn semantics_vfork_execve_preserves_distinct_capture_pipe_ofds() {
    let mut t = TestVm::new();
    let stdout_pipefd_addr = t.scratch + 0x1800;
    let stderr_pipefd_addr = t.scratch + 0x1810;
    assert_eq!(tidemark_kernel::syscall::pipe::sys_pipe2(&mut t.vm, t.base, stdout_pipefd_addr, 0), 0);
    assert_eq!(tidemark_kernel::syscall::pipe::sys_pipe2(&mut t.vm, t.base, stderr_pipefd_addr, 0), 0);

    let stdout_read_fd = unsafe { guest_mem::read_u32(t.base, stdout_pipefd_addr) };
    let stdout_write_fd = unsafe { guest_mem::read_u32(t.base, stdout_pipefd_addr + 4) };
    let stderr_read_fd = unsafe { guest_mem::read_u32(t.base, stderr_pipefd_addr) };
    let stderr_write_fd = unsafe { guest_mem::read_u32(t.base, stderr_pipefd_addr + 4) };

    assert_eq!(t.sys_dup3(stdout_write_fd as u64, 1, 0), 1);
    assert_eq!(t.sys_dup3(stderr_write_fd as u64, 2, 0), 2);
    assert_eq!(t.sys_close(stdout_write_fd as i64), 0);
    assert_eq!(t.sys_close(stderr_write_fd as i64), 0);
    assert_eq!(t.sys_close(stdout_read_fd as i64), 0);
    assert_eq!(t.sys_close(stderr_read_fd as i64), 0);

    let ps_before = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    let stdout_ofd_before = ps_before.fd_table[1].ofd_id;
    let stderr_ofd_before = ps_before.fd_table[2].ofd_id;
    assert_ne!(stdout_ofd_before, 0);
    assert_ne!(stderr_ofd_before, 0);
    assert_ne!(stdout_ofd_before, stderr_ofd_before);

    let stdout_pipe_before = tidemark_kernel::fs::fd_table::get_ofd_by_id(stdout_ofd_before)
        .expect("stdout pipe OFD should exist before vfork+execve");
    let stderr_pipe_before = tidemark_kernel::fs::fd_table::get_ofd_by_id(stderr_ofd_before)
        .expect("stderr pipe OFD should exist before vfork+execve");
    assert_ne!(stdout_pipe_before.ino, stderr_pipe_before.ino);

    let status = process_impl::sys_vfork(&mut t.vm, t.base);
    assert_eq!(status, STATUS_VFORK_WAIT);

    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let path_addr = install_exec_file(&t, b"test", &elf);
    let child_pid = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert!(child_pid > 0);
    assert_eq!(t.vm.status, STATUS_EXECVE_SPAWN);

    process_impl::clear_vfork_runtime_state();
    let ret = process_impl::complete_execve_in_place_from_handoff(
        &mut t.vm,
        t.base,
        process_impl::EXECVE_RAM_LIMIT,
    );
    assert_eq!(ret, 0);

    let ps_after = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    let stdout_ofd_after = ps_after.fd_table[1].ofd_id;
    let stderr_ofd_after = ps_after.fd_table[2].ofd_id;
    assert_eq!(stdout_ofd_after, stdout_ofd_before);
    assert_eq!(stderr_ofd_after, stderr_ofd_before);

    let stdout_pipe_after = tidemark_kernel::fs::fd_table::get_ofd_by_id(stdout_ofd_after)
        .expect("stdout pipe OFD should survive execve");
    let stderr_pipe_after = tidemark_kernel::fs::fd_table::get_ofd_by_id(stderr_ofd_after)
        .expect("stderr pipe OFD should survive execve");
    assert_ne!(stdout_pipe_after.ino, stderr_pipe_after.ino);
}

#[test]
fn semantics_vfork_parent_restore_without_cleanup_preserves_parent_epoll() {
    let mut t = TestVm::new();
    t.memfs.create_file(b"stdin.txt", b"");

    let output_pipefd_addr = t.scratch + 0x1820;
    let status_pipefd_addr = t.scratch + 0x1830;
    assert_eq!(
        tidemark_kernel::syscall::pipe::sys_pipe2(&mut t.vm, t.base, output_pipefd_addr, O_CLOEXEC as u64),
        0
    );
    assert_eq!(
        tidemark_kernel::syscall::pipe::sys_pipe2(&mut t.vm, t.base, status_pipefd_addr, O_CLOEXEC as u64),
        0
    );

    let output_read_fd = unsafe { guest_mem::read_u32(t.base, output_pipefd_addr) } as u64;
    let output_write_fd = unsafe { guest_mem::read_u32(t.base, output_pipefd_addr + 4) } as u64;
    let status_read_fd = unsafe { guest_mem::read_u32(t.base, status_pipefd_addr) } as u64;
    let status_write_fd = unsafe { guest_mem::read_u32(t.base, status_pipefd_addr + 4) } as u64;
    let stdin_fd = t.sys_openat(b"/stdin.txt", O_RDONLY | O_CLOEXEC);
    assert!(stdin_fd >= 3);

    let epfd = tidemark_kernel::syscall::epoll::sys_epoll_create1(&mut t.vm, t.base, O_CLOEXEC as u64);
    assert!(epfd >= 3);

    let event_addr = t.scratch + 0x2000;
    let out_addr = t.scratch + 0x2100;
    unsafe {
        guest_mem::write_u32(t.base, event_addr, EPOLLIN);
        guest_mem::write_u64(t.base, event_addr + 8, 0x1111);
    }
    assert_eq!(
        tidemark_kernel::syscall::epoll::sys_epoll_ctl(&mut t.vm, t.base, epfd as u64, EPOLL_CTL_ADD, output_read_fd, event_addr),
        0
    );
    unsafe {
        guest_mem::write_u32(t.base, event_addr, EPOLLIN);
        guest_mem::write_u64(t.base, event_addr + 8, 0x2222);
    }
    assert_eq!(
        tidemark_kernel::syscall::epoll::sys_epoll_ctl(&mut t.vm, t.base, epfd as u64, EPOLL_CTL_ADD, status_read_fd, event_addr),
        0
    );

    let epoll_ofd_id = unsafe {
        let ps = &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState);
        ps.fd_table[epfd as usize].ofd_id
    };
    let epoll_idx = tidemark_kernel::fs::fd_table::get_ofd_by_id(epoll_ofd_id)
        .expect("epoll OFD should exist before vfork")
        .ino;
    assert_eq!(
        tidemark_kernel::fs::fd_table::get_ofd_by_id(epoll_ofd_id)
            .expect("epoll OFD should be readable before vfork")
            .refcount,
        1
    );

    let status = process_impl::sys_vfork(&mut t.vm, t.base);
    assert_eq!(status, STATUS_VFORK_WAIT);
    assert_eq!(
        tidemark_kernel::fs::fd_table::get_ofd_by_id(epoll_ofd_id)
            .expect("epoll OFD should be retained for the vfork child")
            .refcount,
        2
    );

    assert_eq!(t.sys_dup3(stdin_fd as u64, 0, 0), 0);
    assert_eq!(t.sys_dup3(output_write_fd, 1, 0), 1);
    assert_eq!(t.sys_dup3(output_write_fd, 2, 0), 2);
    assert_eq!(t.sys_close(output_read_fd as i64), 0);
    assert_eq!(t.sys_close(status_read_fd as i64), 0);
    assert!(tidemark_kernel::syscall::epoll::epoll_slot_allocated(epoll_idx));
    assert_eq!(
        tidemark_kernel::fs::fd_table::get_ofd_by_id(epoll_ofd_id)
            .expect("epoll OFD should survive child pipe setup")
            .refcount,
        2
    );

    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let path_addr = install_exec_file(&t, b"test", &elf);
    let child_pid = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert!(child_pid > 0);
    assert_eq!(t.vm.status, STATUS_EXECVE_SPAWN);

    process_impl::vfork_parent_restore_without_cleanup(&mut t.vm, child_pid as i32);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.x[10], child_pid as u64);
    assert!(tidemark_kernel::syscall::epoll::epoll_slot_allocated(epoll_idx));
    assert_eq!(
        tidemark_kernel::fs::fd_table::get_ofd_by_id(epoll_ofd_id)
            .expect("epoll OFD should survive parent restore")
            .refcount,
        1
    );

    assert_eq!(t.sys_close(stdin_fd), 0);
    assert_eq!(t.sys_close(output_write_fd as i64), 0);
    assert_eq!(t.sys_close(status_write_fd as i64), 0);
    assert!(tidemark_kernel::syscall::epoll::epoll_slot_allocated(epoll_idx));

    assert_eq!(
        tidemark_kernel::syscall::epoll::sys_epoll_ctl(&mut t.vm, t.base, epfd as u64, EPOLL_CTL_DEL, output_read_fd, event_addr),
        0
    );
    assert_eq!(
        tidemark_kernel::syscall::epoll::sys_epoll_ctl(&mut t.vm, t.base, epfd as u64, EPOLL_CTL_DEL, status_read_fd, event_addr),
        0
    );
    assert_eq!(
        tidemark_kernel::syscall::epoll::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, 0, 0),
        0
    );
}

#[test]
fn semantics_vfork_parent_restore_without_cleanup_preserves_distinct_capture_pipe_ofds() {
    let mut t = TestVm::new();

    let stdout_pipefd_addr = t.scratch + 0x1800;
    let stderr_pipefd_addr = t.scratch + 0x1810;
    assert_eq!(tidemark_kernel::syscall::pipe::sys_pipe2(&mut t.vm, t.base, stdout_pipefd_addr, 0), 0);
    assert_eq!(tidemark_kernel::syscall::pipe::sys_pipe2(&mut t.vm, t.base, stderr_pipefd_addr, 0), 0);

    let stdout_read_fd = unsafe { guest_mem::read_u32(t.base, stdout_pipefd_addr) };
    let stdout_write_fd = unsafe { guest_mem::read_u32(t.base, stdout_pipefd_addr + 4) };
    let stderr_read_fd = unsafe { guest_mem::read_u32(t.base, stderr_pipefd_addr) };
    let stderr_write_fd = unsafe { guest_mem::read_u32(t.base, stderr_pipefd_addr + 4) };

    assert_eq!(t.sys_dup3(stdout_write_fd as u64, 1, 0), 1);
    assert_eq!(t.sys_dup3(stderr_write_fd as u64, 2, 0), 2);
    assert_eq!(t.sys_close(stdout_write_fd as i64), 0);
    assert_eq!(t.sys_close(stderr_write_fd as i64), 0);
    assert_eq!(t.sys_close(stdout_read_fd as i64), 0);
    assert_eq!(t.sys_close(stderr_read_fd as i64), 0);

    let ps_before = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    let stdout_ofd_before = ps_before.fd_table[1].ofd_id;
    let stderr_ofd_before = ps_before.fd_table[2].ofd_id;
    assert_ne!(stdout_ofd_before, 0);
    assert_ne!(stderr_ofd_before, 0);
    assert_ne!(stdout_ofd_before, stderr_ofd_before);

    let status = process_impl::sys_vfork(&mut t.vm, t.base);
    assert_eq!(status, STATUS_VFORK_WAIT);

    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let path_addr = install_exec_file(&t, b"test", &elf);
    let child_pid = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert!(child_pid > 0);
    assert_eq!(t.vm.status, STATUS_EXECVE_SPAWN);

    process_impl::vfork_parent_restore_without_cleanup(&mut t.vm, child_pid as i32);
    assert_eq!(t.vm.status, STATUS_OK);

    let ps_after = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    assert_eq!(ps_after.fd_table[1].ofd_id, stdout_ofd_before);
    assert_eq!(ps_after.fd_table[2].ofd_id, stderr_ofd_before);

    let eventfd = tidemark_kernel::syscall::pipe::sys_eventfd2(&mut t.vm, t.base, 0, 0);
    assert!(eventfd >= 3);

    let ps_after_eventfd =
        unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    assert_eq!(ps_after_eventfd.fd_table[1].ofd_id, stdout_ofd_before);
    assert_eq!(ps_after_eventfd.fd_table[2].ofd_id, stderr_ofd_before);

    let stdout_pipe_after = tidemark_kernel::fs::fd_table::get_ofd_by_id(stdout_ofd_before)
        .expect("stdout pipe OFD should survive restore_without_cleanup");
    let stderr_pipe_after = tidemark_kernel::fs::fd_table::get_ofd_by_id(stderr_ofd_before)
        .expect("stderr pipe OFD should survive restore_without_cleanup");
    assert_eq!(stdout_pipe_after.fd_type, FD_TYPE_PIPE);
    assert_eq!(stderr_pipe_after.fd_type, FD_TYPE_PIPE);
    assert_ne!(stdout_pipe_after.ino, stderr_pipe_after.ino);
}

#[test]
fn semantics_execve_failure_preserves_thread_group_and_altstack() {
    let mut t = TestVm::new();
    let ps_before = t.vm.process_ptr;
    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.thread_count.store(2, core::sync::atomic::Ordering::Release);
    ps.threads[1] = ThreadRecord::new(2, THREAD_RUNNING, 0xFEED_BEEFu32, 0, 0);
    t.vm.sigaltstack_sp = 0x7000;
    t.vm.sigaltstack_size = 4096;

    let path_addr = install_exec_file(&t, b"bad", b"not-an-elf");
    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(ret, ENOEXEC);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.process_ptr, ps_before);
    assert_eq!(t.vm.sigaltstack_sp, 0x7000);
    assert_eq!(t.vm.sigaltstack_size, 4096);

    let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    assert_eq!(ps.thread_count.load(core::sync::atomic::Ordering::Acquire), 2);
    assert_eq!(ps.threads[1].state, THREAD_RUNNING);
}

#[test]
fn contract_reset_process_lifecycle_reinitializes_thread_registry() {
    let mut t = TestVm::new();
    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.thread_count.store(3, core::sync::atomic::Ordering::Release);
    ps.threads[1] = ThreadRecord::new(2, THREAD_RUNNING, 0xFEED_BEEFu32, 0, 0);
    ps.threads[2] = ThreadRecord::new(3, THREAD_RUNNING, 0xCAFE_BABEu32, 0, 0);

    process_impl::reset_process_lifecycle(&mut t.vm, t.base, 7, 1, 8, 7, 7, true);

    let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    assert_eq!(ps.pid, 7);
    assert_eq!(ps.ppid, 1);
    assert_eq!(ps.thread_count.load(core::sync::atomic::Ordering::Acquire), 1);
    assert_eq!(ps.threads[0].tid, t.vm.tid);
    assert_eq!(ps.threads[0].state, THREAD_RUNNING);
    assert_eq!(ps.threads[0].thread_ptr, &t.vm as *const _ as u32);
    assert_eq!(ps.threads[1].state, THREAD_NONE);
    assert_eq!(ps.threads[2].state, THREAD_NONE);
}

#[test]
fn semantics_nested_child_can_join_existing_parent_group() {
    let t = TestVm::new();

    write_process_ids(&t, 2, 1);
    assert_eq!(process_impl::sys_getpgid(&t.vm, t.base, 0), 1);

    write_process_ids(&t, 3, 2);
    assert_eq!(process_impl::sys_setpgid(&t.vm, t.base, 0, 0), 0);
    assert_eq!(process_impl::sys_getpgid(&t.vm, t.base, 0), 3);

    write_process_ids(&t, 4, 3);
    assert_eq!(process_impl::sys_setpgid(&t.vm, t.base, 0, 0), 0);
    assert_eq!(process_impl::sys_getpgid(&t.vm, t.base, 0), 4);

    assert_eq!(process_impl::sys_setpgid(&t.vm, t.base, 0, 3), 0);
    assert_eq!(process_impl::sys_getpgid(&t.vm, t.base, 0), 3);
}

#[test]
fn semantics_fork_inherited_session_allows_nested_group_join() {
    let mut t = TestVm::new();

    let child1 = process_impl::sys_fork(&mut t.vm, t.base, 0, 0, 0, 0, 0) as i32;
    assert!(child1 > 0);
    t.vm.status = STATUS_OK;

    write_process_ids(&t, child1, 42);
    let child2 = process_impl::sys_fork(&mut t.vm, t.base, 0, 0, 0, 0, 0) as i32;
    assert!(child2 > 0);
    t.vm.status = STATUS_OK;

    assert_eq!(process_impl::sys_setpgid(&t.vm, t.base, 0, 0), 0);
    assert_eq!(process_impl::sys_getpgid(&t.vm, t.base, 0), child1 as i64);

    write_process_ids(&t, child2, child1);
    assert_eq!(process_impl::sys_setpgid(&t.vm, t.base, 0, 0), 0);
    assert_eq!(process_impl::sys_setpgid(&t.vm, t.base, 0, child1 as i64), 0);
    assert_eq!(process_impl::sys_getpgid(&t.vm, t.base, 0), child1 as i64);
}

#[test]
fn semantics_setsid_creates_new_session_for_non_group_leader() {
    let t = TestVm::new();

    write_process_ids(&t, 1, 0);
    assert_eq!(process_impl::sys_getpgid(&t.vm, t.base, 0), 1);

    write_process_ids(&t, 42, 1);
    assert_eq!(process_impl::sys_getpgid(&t.vm, t.base, 0), 1);

    assert_eq!(process_impl::sys_setsid(&t.vm, t.base), 42);
    assert_eq!(process_impl::sys_getpgid(&t.vm, t.base, 0), 42);
}

#[test]
fn semantics_waitid_wnowait_reports_without_reaping() {
    let mut t = TestVm::new();
    let info_addr = t.scratch + 0x1000;

    let child = process_impl::sys_fork(&mut t.vm, t.base, 0, 0, 0, 0, 0) as i32;
    assert!(child > 0);
    t.vm.status = STATUS_OK;
    process_impl::record_child_exit(child, 9 << 8);

    let ret = process_impl::sys_waitid(&mut t.vm, t.base, P_PID, child as i64, info_addr, WEXITED | WNOWAIT, 0);
    assert_eq!(ret, 0);
    assert_eq!(unsafe { guest_mem::read_u32(t.base, info_addr + SIGINFO_OFF_SI_PID) }, child as u32);
    assert_eq!(unsafe { guest_mem::read_u32(t.base, info_addr + SIGINFO_OFF_SI_STATUS) }, 9);

    let ret = process_impl::sys_waitid(&mut t.vm, t.base, P_PID, child as i64, info_addr, WEXITED, 0);
    assert_eq!(ret, 0);

    let ret =
        process_impl::sys_waitid(&mut t.vm, t.base, P_PID, child as i64, info_addr, WEXITED | WNOHANG, 0);
    assert_eq!(ret, ECHILD);
}
