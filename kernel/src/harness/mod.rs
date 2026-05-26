pub(crate) mod debug;
mod exports;
pub mod memory;
pub mod pipe;
pub mod process;
pub mod resource;
pub mod signal;
pub mod support;
pub(crate) mod trace;

use crate::abi::*;
use crate::fs;
use crate::net;
use crate::syscall;
use crate::types::{ProcessState, ThreadState};

pub const DEFAULT_BRK_START: u64 = 0x12_0000;
pub const DEFAULT_MEMORY_PAGES: usize = 256;
pub const DEFAULT_GUEST_RAM_SIZE: u32 = 0x100_0000;
pub const DEFAULT_GUEST_RAM_ALIGN: u32 = 0x20_0000;
pub const DEFAULT_GUEST_BASE_PADDING: u32 = 0x200_00000;
pub const DEFAULT_HOST_HEAP_PADDING: u32 = 0x040_00000;

static mut TEST_GUEST_BASE: u32 = 0;

pub struct MemfsHelper;

impl MemfsHelper {
    pub fn create_file(&self, path: &[u8], data: &[u8]) -> u32 {
        let parent_ino = fs::memfs::resolve_path(b"/");
        let ino = fs::memfs::create_file(parent_ino, path, 0o644);
        if ino > 0 && !data.is_empty() {
            fs::memfs::write_file(ino, 0, data);
        }
        ino
    }
}

pub struct TestVm {
    pub vm: ThreadState,
    pub base: u32,
    pub scratch: u64,
    pub memfs: MemfsHelper,
}

/// Reset all kernel-owned state for a fresh harness instance.
///
/// # Safety
/// The caller must ensure any previous guest/kernel state in the current WASM
/// instance is no longer in use before resetting allocator, memory, and kernel
/// subsystems in place.
pub unsafe fn reset_state(heap_base: u32, brk_start: u64) {
    unsafe {
        crate::guest_mem::init(core::ptr::null(), core::ptr::null(), core::ptr::null());
    }

    let current_pages = core::arch::wasm32::memory_size(0);
    if current_pages < DEFAULT_MEMORY_PAGES {
        let _ = core::arch::wasm32::memory_grow(0, DEFAULT_MEMORY_PAGES - current_pages);
    }

    unsafe {
        crate::alloc::reset(heap_base);
    }
    syscall::time::init();
    syscall::memory::init(brk_start);
    syscall::process::reset_for_tests();
    syscall::thread::init();
    syscall::signal::init();
    syscall::resource::init();
    syscall::epoll::init();
    syscall::pipe::init();
    syscall::pty::init();
    syscall::socket::init();
    net::ring_buffer::init();
    fs::fd_table::init();
    fs::memfs::init();
}

/// Reset kernel-owned state using the default harness memory layout.
///
/// # Safety
/// Equivalent to [`reset_state`] and inherits the same requirement that no
/// live state from a previous harness instance is still being used.
pub unsafe fn reset_default_state() {
    let heap_base = DEFAULT_GUEST_BASE_PADDING
        .saturating_add(DEFAULT_GUEST_RAM_SIZE)
        .saturating_add(DEFAULT_HOST_HEAP_PADDING);
    unsafe {
        reset_state(heap_base, DEFAULT_BRK_START);
    }
}

impl TestVm {
    pub fn new() -> Self {
        unsafe {
            let current_pages = core::arch::wasm32::memory_size(0);
            let aligned = (DEFAULT_GUEST_BASE_PADDING as u64)
                .saturating_add((DEFAULT_GUEST_RAM_ALIGN - 1) as u64)
                & !((DEFAULT_GUEST_RAM_ALIGN - 1) as u64);
            let candidate_base = aligned.min(u32::MAX as u64) as u32;
            let base = candidate_base;
            TEST_GUEST_BASE = base;
            let target_bytes = (base as u64).saturating_add(DEFAULT_GUEST_RAM_SIZE as u64);
            let target_pages = target_bytes.div_ceil(65536) as usize;
            let target_pages = target_pages.max(DEFAULT_MEMORY_PAGES);
            if current_pages < target_pages {
                let grown = core::arch::wasm32::memory_grow(0, target_pages - current_pages);
                if grown == usize::MAX {
                    core::arch::wasm32::unreachable();
                }
            }
            let host_heap_base = base
                .saturating_add(DEFAULT_GUEST_RAM_SIZE)
                .saturating_add(DEFAULT_HOST_HEAP_PADDING);
            reset_state(host_heap_base, DEFAULT_BRK_START);

            let mut vm: ThreadState = core::mem::zeroed();
            vm.tid = 1;
            vm.status = STATUS_OK;
            vm.lr_addr = u64::MAX;
            vm.guest_base = base;

            let ps_size = core::mem::size_of::<ProcessState>() as u64;
            let ps_align = core::mem::align_of::<ProcessState>() as u64;
            let brk = syscall::memory::current_brk();
            let ps_addr = (brk + ps_align - 1) & !(ps_align - 1);
            let scratch = (ps_addr + ps_size + 15) & !15;
            syscall::memory::grow_brk(base, scratch + 0x10000);
            crate::guest_mem::zero_mem(base, ps_addr, ps_size as usize);
            vm.process_ptr = ps_addr as u32;

            let pid_off = core::mem::offset_of!(ProcessState, pid) as u64;
            crate::guest_mem::write_u32(base, ps_addr + pid_off, 42);
            let ppid_off = core::mem::offset_of!(ProcessState, ppid) as u64;
            crate::guest_mem::write_u32(base, ps_addr + ppid_off, 1);
            let cwd_off = core::mem::offset_of!(ProcessState, cwd_ino) as u64;
            crate::guest_mem::write_u32(base, ps_addr + cwd_off, 1);
            let fs_ring_off = core::mem::offset_of!(ProcessState, fs_ring_base) as u64;
            let fs_ring_base =
                crate::alloc::alloc_zeroed(crate::fs::ring_buffer::RING_BUFFER_SIZE as u32, 16);
            crate::guest_mem::write_u32(base, ps_addr + fs_ring_off, fs_ring_base);
            let umask_off = core::mem::offset_of!(ProcessState, umask) as u64;
            crate::guest_mem::write_u32(base, ps_addr + umask_off, 0o022);

            syscall::signal::init_for_process(42);
            syscall::resource::init_for_process(42);
            fs::fd_table::init_stdio(base, &mut vm);

            let ps = &*((base as u64 + vm.process_ptr as u64) as *const ProcessState);
            let gen_ptr =
                core::ptr::addr_of!(ps.reservation_gen) as *const core::sync::atomic::AtomicU32;
            let lock_ptr =
                core::ptr::addr_of!(ps.reservation_lock) as *const core::sync::atomic::AtomicU32;
            let tc_ptr = core::ptr::addr_of!(ps.thread_count);
            crate::guest_mem::init(gen_ptr, lock_ptr, tc_ptr);

            crate::guest_mem::zero_mem(base, scratch, 0x10000);

            let mut test_vm = Self {
                vm,
                base,
                scratch,
                memfs: MemfsHelper,
            };
            let vm_ptr = &mut test_vm.vm as *mut ThreadState as u32;
            syscall::thread::init_main_thread(vm_ptr, base);
            test_vm
        }
    }

    pub fn guest_mem(&self, addr: u64, n: usize) -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec![0u8; n];
        unsafe {
            crate::guest_mem::read_bytes(self.base, addr, &mut buf);
        }
        buf
    }

    pub fn write_mem(&self, addr: u64, data: &[u8]) {
        unsafe {
            crate::guest_mem::write_bytes(self.base, addr, data);
        }
    }

    pub fn write_path(&self, offset: u64, path: &[u8]) -> u64 {
        let addr = self.scratch + offset;
        unsafe {
            crate::guest_mem::write_bytes(self.base, addr, path);
            crate::guest_mem::write_u8(self.base, addr + path.len() as u64, 0);
        }
        addr
    }

    pub fn sys_openat(&mut self, path: &[u8], flags: i32) -> i64 {
        let path_addr = self.write_path(0xF000, path);
        syscall::fs::sys_openat(
            &mut self.vm,
            self.base,
            (-100i64) as u64,
            path_addr,
            flags as u64,
            0o644,
        )
    }

    pub fn sys_read(&mut self, fd: i64, buf: &mut [u8]) -> i64 {
        let addr = self.scratch + 0xE000;
        let n = syscall::fs::sys_read(&mut self.vm, self.base, fd as u64, addr, buf.len() as u64);
        if n > 0 {
            unsafe {
                crate::guest_mem::read_bytes(self.base, addr, &mut buf[..n as usize]);
            }
        }
        n
    }

    pub fn sys_write_data(&mut self, fd: i64, data: &[u8]) -> i64 {
        let addr = self.scratch + 0xD000;
        unsafe {
            crate::guest_mem::write_bytes(self.base, addr, data);
        }
        syscall::fs::sys_write(
            &mut self.vm,
            self.base,
            fd as u64,
            addr,
            data.len() as u64,
            SYS_WRITE,
        )
    }

    pub fn sys_close(&mut self, fd: i64) -> i64 {
        fs::fd_table::sys_close(&mut self.vm, self.base, fd as u64)
    }

    pub fn sys_fstat(&mut self, fd: i64, stat_buf: u64) -> i64 {
        syscall::fs::sys_fstat(&mut self.vm, self.base, fd as u64, stat_buf)
    }

    pub fn sys_lseek(&mut self, fd: i64, offset: i64, whence: u64) -> i64 {
        syscall::fs::sys_lseek(&mut self.vm, self.base, fd as u64, offset, whence)
    }

    pub fn sys_mkdirat(&mut self, path: &[u8]) -> i64 {
        let path_addr = self.write_path(0xF000, path);
        syscall::fs::sys_mkdirat(&mut self.vm, self.base, (-100i64) as u64, path_addr, 0o755)
    }

    pub fn sys_getdents64(&mut self, fd: i64, buf_addr: u64, buf_size: u64) -> i64 {
        syscall::fs::sys_getdents64(&mut self.vm, self.base, fd as u64, buf_addr, buf_size)
    }

    pub fn sys_brk(&mut self, addr: u64) -> i64 {
        syscall::memory::sys_brk(&mut self.vm, self.base, addr)
    }

    pub fn sys_mmap(
        &mut self,
        addr: u64,
        len: u64,
        prot: i32,
        flags: u64,
        fd: i64,
        offset: u64,
    ) -> i64 {
        syscall::memory::sys_mmap(
            &mut self.vm,
            self.base,
            addr,
            len,
            prot as u64,
            flags,
            fd,
            offset,
        )
    }

    pub fn sys_munmap(&mut self, addr: u64, len: u64) -> i64 {
        syscall::memory::sys_munmap(&mut self.vm, self.base, addr, len)
    }

    pub fn sys_mprotect(&mut self, addr: u64, len: u64, prot: i32) -> i64 {
        syscall::memory::sys_mprotect(&mut self.vm, self.base, addr, len, prot as u64)
    }

    pub fn sys_madvise(&mut self, addr: u64, len: u64, advice: i32) -> i64 {
        syscall::memory::sys_madvise(&mut self.vm, self.base, addr, len, advice as u64)
    }

    pub fn sys_dup(&mut self, fd: u64) -> i64 {
        fs::fd_table::sys_dup(&mut self.vm, self.base, fd)
    }

    pub fn sys_dup3(&mut self, oldfd: u64, newfd: u64, flags: u64) -> i64 {
        fs::fd_table::sys_dup3(&mut self.vm, self.base, oldfd, newfd, flags)
    }

    pub fn sys_fcntl(&mut self, fd: u64, cmd: u64, arg: u64) -> i64 {
        fs::fd_table::sys_fcntl(&mut self.vm, self.base, fd, cmd, arg)
    }

    pub fn sys_flock(&mut self, fd: u64, operation: u64) -> i64 {
        fs::fd_table::sys_flock(&mut self.vm, self.base, fd, operation)
    }
}

impl Default for TestVm {
    fn default() -> Self {
        Self::new()
    }
}

extern crate alloc;
