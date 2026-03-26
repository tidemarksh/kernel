//! Shared test helpers: VM setup, ELF runner.

use crate::abi::*;
use crate::types::*;

/// MemFS helper accessible as `vm.memfs`.
pub struct MemfsHelper;

impl MemfsHelper {
    pub fn create_file(&self, path: &[u8], data: &[u8]) -> u32 {
        let parent_ino = crate::fs::memfs::resolve_path(b"/");
        let ino = crate::fs::memfs::create_file(parent_ino, path, 0o644);
        if ino > 0 && !data.is_empty() {
            crate::fs::memfs::write_file(ino, 0, data);
        }
        ino
    }
}

/// Minimal VM state for syscall and integration tests.
///
/// Usage:
/// ```ignore
/// let mut vm = TestVm::new();
/// vm.memfs.create_file(b"a.txt", b"hello");
/// let fd = vm.sys_openat(b"/a.txt", O_RDONLY);
/// let addr = vm.sys_mmap(0, 4096, PROT_READ, MAP_PRIVATE, fd as i64, 0);
/// assert_eq!(&vm.guest_mem(addr as u64, 5), b"hello");
/// ```
pub struct TestVm {
    pub vm: ThreadState,
    pub base: u32,
    /// Guest scratch area (above shadow stack).
    pub scratch: u64,
    /// MemFS helper for file creation.
    pub memfs: MemfsHelper,
}

impl TestVm {
    /// Set up minimal VM state for syscall tests.
    pub fn new() -> Self {
        unsafe {
            let base: u32 = 0;
            crate::guest_mem::init(core::ptr::null(), core::ptr::null());

            let current_pages = core::arch::wasm32::memory_size(0);
            let target_pages = 256;
            if current_pages < target_pages {
                core::arch::wasm32::memory_grow(0, target_pages - current_pages);
            }

            // Initialize alloc.rs and kernel state.
            // Heap starts at 2MB to leave room for guest data below.
            // Heap and brk must be above WASM static data (~0x11D000 for wasip1 test binary).
            // __stack_pointer = 0x100000, static data = 0x100000..0x11D000.
            crate::alloc::reset(0x20_0000);
            crate::syscall::memory::init(0x12_0000); // brk above static data
            crate::syscall::signal::init();
            crate::syscall::epoll::init();
            crate::syscall::pipe::init();
            crate::syscall::socket::init();
            crate::fs::fd_table::init();
            crate::fs::memfs::init();

            let mut vm: ThreadState = core::mem::zeroed();
            vm.tid = 1;
            vm.status = STATUS_OK;

            // Allocate ProcessState in guest Memory via brk (not alloc.rs which is
            // kernel Worker private memory). Guest Memory is the shared address space
            // that thread-workers access directly.
            let ps_size = core::mem::size_of::<ProcessState>() as u64;
            let ps_align = core::mem::align_of::<ProcessState>() as u64;
            let brk = crate::syscall::memory::current_brk();
            let ps_addr = (brk + ps_align - 1) & !(ps_align - 1);
            crate::syscall::memory::grow_brk(base, ps_addr + ps_size);
            crate::guest_mem::zero_mem(base, ps_addr, ps_size as usize);
            vm.process_ptr = ps_addr as u32;

            let pid_off = core::mem::offset_of!(ProcessState, pid) as u64;
            crate::guest_mem::write_u32(base, ps_addr + pid_off, 42);
            let ppid_off = core::mem::offset_of!(ProcessState, ppid) as u64;
            crate::guest_mem::write_u32(base, ps_addr + ppid_off, 1);

            // FD 0/1/2
            crate::guest_mem::write_u32(base, ps_addr + 0, 1);
            crate::guest_mem::write_u32(base, ps_addr + 8, 2);
            crate::guest_mem::write_u32(base, ps_addr + 16, 3);

            // Scratch area for test data (64KB, above shadow stack)
            let scratch = crate::alloc::alloc_zeroed(0x10000, 16) as u64;

            TestVm { vm, base, scratch, memfs: MemfsHelper }
        }
    }

    // --- Guest memory access ---

    /// Read n bytes from guest memory at addr.
    pub fn guest_mem(&self, addr: u64, n: usize) -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec![0u8; n];
        unsafe { crate::guest_mem::read_bytes(self.base, addr, &mut buf); }
        buf
    }

    /// Write bytes to guest memory at addr.
    pub fn write_mem(&self, addr: u64, data: &[u8]) {
        unsafe { crate::guest_mem::write_bytes(self.base, addr, data); }
    }

    /// Write a null-terminated path string to scratch + offset, return the address.
    pub fn write_path(&self, offset: u64, path: &[u8]) -> u64 {
        let addr = self.scratch + offset;
        unsafe {
            crate::guest_mem::write_bytes(self.base, addr, path);
            crate::guest_mem::write_u8(self.base, addr + path.len() as u64, 0);
        }
        addr
    }

    // --- Syscall wrappers ---

    pub fn sys_openat(&mut self, path: &[u8], flags: i32) -> i64 {
        let path_addr = self.write_path(0xF000, path);
        crate::syscall::fs::sys_openat(
            &mut self.vm, self.base, (-100i64) as u64, path_addr, flags as u64, 0o644,
        )
    }

    pub fn sys_read(&mut self, fd: i64, buf: &mut [u8]) -> i64 {
        let addr = self.scratch + 0xE000;
        let n = crate::syscall::fs::sys_read(
            &mut self.vm, self.base, fd as u64, addr, buf.len() as u64,
        );
        if n > 0 {
            unsafe { crate::guest_mem::read_bytes(self.base, addr, &mut buf[..n as usize]); }
        }
        n
    }

    pub fn sys_write_data(&mut self, fd: i64, data: &[u8]) -> i64 {
        let addr = self.scratch + 0xD000;
        unsafe { crate::guest_mem::write_bytes(self.base, addr, data); }
        crate::syscall::fs::sys_write(
            &mut self.vm, self.base, fd as u64, addr, data.len() as u64, SYS_WRITE,
        )
    }

    pub fn sys_close(&mut self, fd: i64) -> i64 {
        crate::fs::fd_table::sys_close(&mut self.vm, self.base, fd as u64)
    }

    pub fn sys_fstat(&mut self, fd: i64, stat_buf: u64) -> i64 {
        crate::syscall::fs::sys_fstat(&mut self.vm, self.base, fd as u64, stat_buf)
    }

    pub fn sys_lseek(&mut self, fd: i64, offset: i64, whence: u64) -> i64 {
        crate::syscall::fs::sys_lseek(&mut self.vm, self.base, fd as u64, offset, whence)
    }

    pub fn sys_mkdirat(&mut self, path: &[u8]) -> i64 {
        let path_addr = self.write_path(0xF000, path);
        crate::syscall::fs::sys_mkdirat(
            &mut self.vm, self.base, (-100i64) as u64, path_addr, 0o755,
        )
    }

    pub fn sys_getdents64(&mut self, fd: i64, buf_addr: u64, buf_size: u64) -> i64 {
        crate::syscall::fs::sys_getdents64(
            &mut self.vm, self.base, fd as u64, buf_addr, buf_size,
        )
    }

    pub fn sys_brk(&mut self, addr: u64) -> i64 {
        crate::syscall::memory::sys_brk(&mut self.vm, self.base, addr)
    }

    pub fn sys_mmap(&mut self, addr: u64, len: u64, prot: i32, flags: u64, fd: i64, offset: u64) -> i64 {
        crate::syscall::memory::sys_mmap(
            &mut self.vm, self.base, addr, len, prot as u64, flags, fd, offset,
        )
    }

    pub fn sys_munmap(&mut self, addr: u64, len: u64) -> i64 {
        crate::syscall::memory::sys_munmap(&mut self.vm, self.base, addr, len)
    }

    pub fn sys_mprotect(&mut self, addr: u64, len: u64, prot: i32) -> i64 {
        crate::syscall::memory::sys_mprotect(&mut self.vm, self.base, addr, len, prot as u64)
    }

    pub fn sys_dup(&mut self, fd: u64) -> i64 {
        crate::fs::fd_table::sys_dup(&mut self.vm, self.base, fd)
    }

    pub fn sys_dup3(&mut self, oldfd: u64, newfd: u64, flags: u64) -> i64 {
        crate::fs::fd_table::sys_dup3(&mut self.vm, self.base, oldfd, newfd, flags)
    }

    pub fn sys_fcntl(&mut self, fd: u64, cmd: u64, arg: u64) -> i64 {
        crate::fs::fd_table::sys_fcntl(&mut self.vm, self.base, fd, cmd, arg)
    }
}

extern crate alloc;
