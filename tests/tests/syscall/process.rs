use std::sync::atomic::Ordering;
use std::vec;
use std::vec::Vec;
use tidemark_kernel::abi::*;
use tidemark_kernel::elf::AT_NULL;
use tidemark_kernel::fs::memfs;
use tidemark_kernel::guest_mem;
use tidemark_kernel::harness::TestVm;
use tidemark_kernel::syscall::process as process_impl;
use tidemark_kernel::syscall::signal;
use tidemark_kernel::syscall::thread as thread_impl;
use tidemark_kernel::types::{FdEntry, ProcessState, THREAD_NONE, THREAD_RUNNING, ThreadRecord};

const EPOLL_CTL_ADD: u64 = 1;
const EPOLL_CTL_DEL: u64 = 2;
const EPOLLIN: u32 = 0x001;
const WNOHANG: u64 = 1;
const WUNTRACED: u64 = 2;
const WCONTINUED: u64 = 8;
const WNOWAIT: u64 = 0x01000000;
const WEXITED: u64 = 4;
const P_PID: u32 = 1;
const ECHILD: i64 = -10;
const SS_DISABLE: i32 = 2;

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

fn read_file_bytes(path: &[u8]) -> Vec<u8> {
    let ino = memfs::resolve_path(path);
    assert_ne!(ino, 0, "missing memfs path: {:?}", path);
    let size = memfs::stat(ino).unwrap().size as usize;
    let mut buf = vec![0u8; size];
    let n = memfs::read_file(ino, 0, &mut buf);
    assert_eq!(n as usize, size);
    buf
}

fn read_link_bytes(path: &[u8]) -> Vec<u8> {
    let ino = memfs::resolve_path(path);
    assert_ne!(ino, 0, "missing symlink path: {:?}", path);
    let mut buf = vec![0u8; 512];
    let n = memfs::read_link(ino, &mut buf);
    buf.truncate(n);
    buf
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

fn build_test_elf_with_interp(code: &[u8], interp_path: &[u8]) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let ph_off = 64usize;
    let ph_num = 2usize;
    let interp_off = 0x100usize;
    let code_off = 0x200usize;
    let entry = 0x1000u64 + code_off as u64;
    let code_end = code_off + code.len();
    let total_len = code_end.max(interp_off + interp_path.len() + 1);
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
    put_u64(&mut elf, 32, ph_off as u64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, ph_num as u16);

    put_u32(&mut elf, ph_off, 3);
    put_u32(&mut elf, ph_off + 4, 4);
    put_u64(&mut elf, ph_off + 8, interp_off as u64);
    put_u64(&mut elf, ph_off + 16, 0x1100);
    put_u64(&mut elf, ph_off + 32, (interp_path.len() + 1) as u64);
    put_u64(&mut elf, ph_off + 40, (interp_path.len() + 1) as u64);
    put_u64(&mut elf, ph_off + 48, 1);

    let load_off = ph_off + 56;
    put_u32(&mut elf, load_off, 1);
    put_u32(&mut elf, load_off + 4, 5);
    put_u64(&mut elf, load_off + 8, 0);
    put_u64(&mut elf, load_off + 16, 0x1000);
    put_u64(&mut elf, load_off + 32, code_end as u64);
    put_u64(&mut elf, load_off + 40, code_end as u64);
    put_u64(&mut elf, load_off + 48, 0x1000);

    elf[interp_off..interp_off + interp_path.len()].copy_from_slice(interp_path);
    elf[interp_off + interp_path.len()] = 0;
    elf[code_off..code_off + code.len()].copy_from_slice(code);
    elf
}

fn build_test_elf_with_interp_and_tls(
    code: &[u8],
    interp_path: &[u8],
    tls_init: &[u8],
    tls_memsz: u64,
) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let ph_off = 64usize;
    let interp_off = 0x200usize;
    let code_off = 0x300usize;
    let data_off = 0x400usize;
    let entry = 0x1000u64 + code_off as u64;
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
    put_u64(&mut elf, 32, ph_off as u64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, 4);

    put_u32(&mut elf, ph_off, 3);
    put_u32(&mut elf, ph_off + 4, 4);
    put_u64(&mut elf, ph_off + 8, interp_off as u64);
    put_u64(&mut elf, ph_off + 16, 0x1100);
    put_u64(&mut elf, ph_off + 32, (interp_path.len() + 1) as u64);
    put_u64(&mut elf, ph_off + 40, (interp_path.len() + 1) as u64);
    put_u64(&mut elf, ph_off + 48, 1);

    let code_ph = ph_off + 56;
    put_u32(&mut elf, code_ph, 1);
    put_u32(&mut elf, code_ph + 4, 5);
    put_u64(&mut elf, code_ph + 8, 0);
    put_u64(&mut elf, code_ph + 16, 0x1000);
    put_u64(&mut elf, code_ph + 32, data_off as u64);
    put_u64(&mut elf, code_ph + 40, data_off as u64);
    put_u64(&mut elf, code_ph + 48, 0x1000);

    let data_ph = ph_off + 112;
    put_u32(&mut elf, data_ph, 1);
    put_u32(&mut elf, data_ph + 4, 6);
    put_u64(&mut elf, data_ph + 8, data_off as u64);
    put_u64(&mut elf, data_ph + 16, 0x3000);
    put_u64(&mut elf, data_ph + 32, tls_init.len() as u64);
    put_u64(&mut elf, data_ph + 40, tls_memsz);
    put_u64(&mut elf, data_ph + 48, 0x1000);

    let tls_ph = ph_off + 168;
    put_u32(&mut elf, tls_ph, 7);
    put_u32(&mut elf, tls_ph + 4, 4);
    put_u64(&mut elf, tls_ph + 8, data_off as u64);
    put_u64(&mut elf, tls_ph + 16, 0x3000);
    put_u64(&mut elf, tls_ph + 32, tls_init.len() as u64);
    put_u64(&mut elf, tls_ph + 40, tls_memsz);
    put_u64(&mut elf, tls_ph + 48, 8);

    elf[interp_off..interp_off + interp_path.len()].copy_from_slice(interp_path);
    elf[interp_off + interp_path.len()] = 0;
    elf[code_off..code_off + code.len()].copy_from_slice(code);
    elf[data_off..data_off + tls_init.len()].copy_from_slice(tls_init);
    elf
}

fn build_test_elf_dyn_with_interp(code: &[u8], interp_path: &[u8]) -> Vec<u8> {
    let mut elf = build_test_elf_with_interp(code, interp_path);
    elf[16..18].copy_from_slice(&3u16.to_le_bytes());
    elf
}

fn build_test_elf_dyn_with_interp_and_tls(
    code: &[u8],
    interp_path: &[u8],
    tls_init: &[u8],
    tls_memsz: u64,
) -> Vec<u8> {
    let mut elf = build_test_elf_with_interp_and_tls(code, interp_path, tls_init, tls_memsz);
    elf[16..18].copy_from_slice(&3u16.to_le_bytes());
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

fn build_test_elf_dyn_low(code: &[u8]) -> Vec<u8> {
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
    let mut elf = vec![0u8; code_off + code.len()];
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
    put_u64(&mut elf, 24, 0x40);
    put_u64(&mut elf, 32, 64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, 1);

    put_u32(&mut elf, 64, 1);
    put_u32(&mut elf, 68, 5);
    put_u64(&mut elf, 72, code_off as u64);
    put_u64(&mut elf, 80, 0);
    put_u64(&mut elf, 96, code.len() as u64);
    put_u64(&mut elf, 104, code.len() as u64);
    put_u64(&mut elf, 112, 0x1000);
    elf[code_off..code_off + code.len()].copy_from_slice(code);
    elf
}

fn build_test_elf_dyn_two_loads(code: &[u8], data: &[u8]) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let ph_off = 64usize;
    let code_off = 0x100usize;
    let data_off = 0x300usize;
    let entry = 0x1000u64;
    let total_len = data_off + data.len();
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
    put_u64(&mut elf, 32, ph_off as u64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, 2);

    put_u32(&mut elf, ph_off, 1);
    put_u32(&mut elf, ph_off + 4, 5);
    put_u64(&mut elf, ph_off + 8, code_off as u64);
    put_u64(&mut elf, ph_off + 16, 0x1000);
    put_u64(&mut elf, ph_off + 32, code.len() as u64);
    put_u64(&mut elf, ph_off + 40, code.len() as u64);
    put_u64(&mut elf, ph_off + 48, 0x1000);

    let data_ph = ph_off + 56;
    put_u32(&mut elf, data_ph, 1);
    put_u32(&mut elf, data_ph + 4, 6);
    put_u64(&mut elf, data_ph + 8, data_off as u64);
    put_u64(&mut elf, data_ph + 16, 0x3000);
    put_u64(&mut elf, data_ph + 32, data.len() as u64);
    put_u64(&mut elf, data_ph + 40, data.len() as u64 + 0x100);
    put_u64(&mut elf, data_ph + 48, 0x1000);

    elf[code_off..code_off + code.len()].copy_from_slice(code);
    elf[data_off..data_off + data.len()].copy_from_slice(data);
    elf
}

fn build_test_elf_dyn_with_interp_two_loads(
    code: &[u8],
    data: &[u8],
    interp_path: &[u8],
) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let ph_off = 64usize;
    let interp_off = 0x100usize;
    let code_off = 0x200usize;
    let data_off = 0x300usize;
    let entry = 0x1000u64 + code_off as u64;
    let total_len = data_off + data.len();
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
    put_u64(&mut elf, 32, ph_off as u64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, 3);

    put_u32(&mut elf, ph_off, 3);
    put_u32(&mut elf, ph_off + 4, 4);
    put_u64(&mut elf, ph_off + 8, interp_off as u64);
    put_u64(&mut elf, ph_off + 16, 0x1100);
    put_u64(&mut elf, ph_off + 32, (interp_path.len() + 1) as u64);
    put_u64(&mut elf, ph_off + 40, (interp_path.len() + 1) as u64);
    put_u64(&mut elf, ph_off + 48, 1);

    let code_ph = ph_off + 56;
    put_u32(&mut elf, code_ph, 1);
    put_u32(&mut elf, code_ph + 4, 5);
    put_u64(&mut elf, code_ph + 8, 0);
    put_u64(&mut elf, code_ph + 16, 0x1000);
    put_u64(&mut elf, code_ph + 32, data_off as u64);
    put_u64(&mut elf, code_ph + 40, data_off as u64);
    put_u64(&mut elf, code_ph + 48, 0x1000);

    let data_ph = ph_off + 112;
    put_u32(&mut elf, data_ph, 1);
    put_u32(&mut elf, data_ph + 4, 6);
    put_u64(&mut elf, data_ph + 8, data_off as u64);
    put_u64(&mut elf, data_ph + 16, 0x3000);
    put_u64(&mut elf, data_ph + 32, data.len() as u64);
    put_u64(&mut elf, data_ph + 40, data.len() as u64 + 0x100);
    put_u64(&mut elf, data_ph + 48, 0x1000);

    elf[interp_off..interp_off + interp_path.len()].copy_from_slice(interp_path);
    elf[interp_off + interp_path.len()] = 0;
    elf[code_off..code_off + code.len()].copy_from_slice(code);
    elf[data_off..data_off + data.len()].copy_from_slice(data);
    elf
}

fn build_test_elf_dyn_with_interp_dynamic(code: &[u8], data: &[u8], interp_path: &[u8]) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let ph_off = 64usize;
    let interp_off = 0x100usize;
    let code_off = 0x200usize;
    let data_off = 0x300usize;
    let dynamic_off = 0x320usize;
    let dynamic_vaddr = 0x3020u64;
    let entry = 0x1000u64 + code_off as u64;
    let second_filesz = (dynamic_off + 64 - data_off).max(data.len());
    let total_len = data_off + second_filesz;
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
    put_u64(&mut elf, 32, ph_off as u64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, 4);

    put_u32(&mut elf, ph_off, 3);
    put_u32(&mut elf, ph_off + 4, 4);
    put_u64(&mut elf, ph_off + 8, interp_off as u64);
    put_u64(&mut elf, ph_off + 16, 0x1100);
    put_u64(&mut elf, ph_off + 32, (interp_path.len() + 1) as u64);
    put_u64(&mut elf, ph_off + 40, (interp_path.len() + 1) as u64);
    put_u64(&mut elf, ph_off + 48, 1);

    let code_ph = ph_off + 56;
    put_u32(&mut elf, code_ph, 1);
    put_u32(&mut elf, code_ph + 4, 5);
    put_u64(&mut elf, code_ph + 8, 0);
    put_u64(&mut elf, code_ph + 16, 0x1000);
    put_u64(&mut elf, code_ph + 32, data_off as u64);
    put_u64(&mut elf, code_ph + 40, data_off as u64);
    put_u64(&mut elf, code_ph + 48, 0x1000);

    let data_ph = ph_off + 112;
    put_u32(&mut elf, data_ph, 1);
    put_u32(&mut elf, data_ph + 4, 6);
    put_u64(&mut elf, data_ph + 8, data_off as u64);
    put_u64(&mut elf, data_ph + 16, 0x3000);
    put_u64(&mut elf, data_ph + 32, second_filesz as u64);
    put_u64(&mut elf, data_ph + 40, second_filesz as u64 + 0x100);
    put_u64(&mut elf, data_ph + 48, 0x1000);

    let dynamic_ph = ph_off + 168;
    put_u32(&mut elf, dynamic_ph, 2);
    put_u32(&mut elf, dynamic_ph + 4, 6);
    put_u64(&mut elf, dynamic_ph + 8, dynamic_off as u64);
    put_u64(&mut elf, dynamic_ph + 16, dynamic_vaddr);
    put_u64(&mut elf, dynamic_ph + 32, 4 * 16);
    put_u64(&mut elf, dynamic_ph + 40, 4 * 16);
    put_u64(&mut elf, dynamic_ph + 48, 8);

    elf[interp_off..interp_off + interp_path.len()].copy_from_slice(interp_path);
    elf[interp_off + interp_path.len()] = 0;
    elf[code_off..code_off + code.len()].copy_from_slice(code);
    elf[data_off..data_off + data.len()].copy_from_slice(data);
    put_u64(&mut elf, dynamic_off, 7);
    put_u64(&mut elf, dynamic_off + 8, 0x3300);
    put_u64(&mut elf, dynamic_off + 16, 8);
    put_u64(&mut elf, dynamic_off + 24, 24);
    put_u64(&mut elf, dynamic_off + 32, 0x6fff_ffff);
    put_u64(&mut elf, dynamic_off + 40, 5);
    put_u64(&mut elf, dynamic_off + 48, 0);
    put_u64(&mut elf, dynamic_off + 56, 0);
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

fn install_exec_file_at(t: &TestVm, path: &[u8], elf_bytes: &[u8]) -> u64 {
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

fn find_auxv_value(t: &TestVm, tag: u64) -> Option<u64> {
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

#[path = "process/exec.rs"]
mod exec;
#[path = "process/fork.rs"]
mod fork;
#[path = "process/lifecycle.rs"]
mod lifecycle;
#[path = "process/vfork.rs"]
mod vfork;
#[path = "process/wait.rs"]
mod wait;
