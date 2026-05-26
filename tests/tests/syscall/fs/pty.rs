use super::support::*;

#[test]
fn stdio_pty_ends_enforce_read_write_direction() {
    let mut t = TestVm::new();
    let mut buf = [0u8; 8];
    assert_eq!(t.sys_write_data(0, b"stdin"), EBADF);
    assert_eq!(t.sys_read(1, &mut buf), EBADF);
    assert_eq!(t.sys_read(2, &mut buf), EBADF);
}

#[test]
fn stdio_fds_report_tty_termios_and_winsize() {
    let mut t = TestVm::new();
    let termios_addr = t.scratch + 0x3700;
    let winsize_addr = t.scratch + 0x3800;
    let stat_addr = t.scratch + 0x3900;

    assert_eq!(
        tidemark_kernel::syscall::pty::sys_ioctl(&mut t.vm, t.base, 0, TCGETS, termios_addr),
        0
    );
    assert_eq!(
        tidemark_kernel::syscall::pty::sys_ioctl(&mut t.vm, t.base, 1, TIOCGWINSZ, winsize_addr),
        0
    );
    assert_eq!(t.sys_fstat(0, stat_addr), 0);

    let iflag = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, termios_addr) };
    let ws_row = unsafe { tidemark_kernel::guest_mem::read_u16(t.base, winsize_addr) };
    let ws_col = unsafe { tidemark_kernel::guest_mem::read_u16(t.base, winsize_addr + 2) };
    let mode = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, stat_addr + 16) };
    assert_ne!(iflag, 0);
    assert_eq!(ws_row, 24);
    assert_eq!(ws_col, 80);
    assert_eq!(mode & memfs::S_IFMT, memfs::S_IFCHR);
}

#[test]
fn dev_tty_opens_controlling_pty_slave() {
    let mut t = TestVm::new();
    let fd = t.sys_openat(b"/dev/tty", O_RDWR);
    assert!(fd >= 3);

    let winsize_addr = t.scratch + 0x3a00;
    assert_eq!(
        tidemark_kernel::syscall::pty::sys_ioctl(
            &mut t.vm,
            t.base,
            fd as u64,
            TIOCGWINSZ,
            winsize_addr
        ),
        0
    );
    let ws_col = unsafe { tidemark_kernel::guest_mem::read_u16(t.base, winsize_addr + 2) };
    assert_eq!(ws_col, 80);
}

#[test]
fn stdio_pty_slave_writev_reaches_master_output() {
    let mut t = TestVm::new();
    let buf_a = t.scratch + 0x7000;
    let buf_b = t.scratch + 0x7100;
    let iov_addr = t.scratch + 0x7200;

    t.write_mem(buf_a, b"pw");
    t.write_mem(buf_b, b"d\n");
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, iov_addr, buf_a);
        tidemark_kernel::guest_mem::write_u64(t.base, iov_addr + 8, 2);
        tidemark_kernel::guest_mem::write_u64(t.base, iov_addr + 16, buf_b);
        tidemark_kernel::guest_mem::write_u64(t.base, iov_addr + 24, 2);
    }

    let written = fs::sys_write(&mut t.vm, t.base, 1, iov_addr, 2, SYS_WRITEV);
    assert_eq!(written, 4);

    let pty_idx = fd_table::get_ofd(t.base, &t.vm, 1)
        .map(|ofd| ofd.ino)
        .unwrap_or(0);
    assert!(pty_idx > 0);

    let mut out = [0u8; 8];
    let n = tidemark_kernel::syscall::pty::master_read(pty_idx, &mut out);
    assert_eq!(n, 5);
    assert_eq!(&out[..5], b"pwd\r\n");
}

#[test]
fn stdio_pty_master_canonical_mode_commits_input_only_after_newline() {
    let t = TestVm::new();
    let pty_idx = fd_table::get_ofd(t.base, &t.vm, 1)
        .map(|ofd| ofd.ino)
        .unwrap_or(0);
    assert!(pty_idx > 0);

    assert_eq!(
        tidemark_kernel::syscall::pty::master_write(pty_idx, b"l"),
        1
    );
    let mut cooked = [0u8; 16];
    assert_eq!(
        tidemark_kernel::syscall::pty::slave_read(pty_idx, &mut cooked),
        EAGAIN
    );

    assert_eq!(
        tidemark_kernel::syscall::pty::master_write(pty_idx, b"s\r"),
        2
    );
    let n = tidemark_kernel::syscall::pty::slave_read(pty_idx, &mut cooked);
    assert_eq!(n, 3);
    assert_eq!(&cooked[..3], b"ls\n");

    let mut echoed = [0u8; 16];
    let n = tidemark_kernel::syscall::pty::master_read(pty_idx, &mut echoed);
    assert_eq!(n, 4);
    assert_eq!(&echoed[..4], b"ls\r\n");
}

#[test]
fn stdio_pty_master_erase_updates_canonical_line() {
    let t = TestVm::new();
    let pty_idx = fd_table::get_ofd(t.base, &t.vm, 1)
        .map(|ofd| ofd.ino)
        .unwrap_or(0);
    assert!(pty_idx > 0);

    assert_eq!(
        tidemark_kernel::syscall::pty::master_write(pty_idx, b"lx\x7fs\r"),
        5
    );

    let mut cooked = [0u8; 16];
    let n = tidemark_kernel::syscall::pty::slave_read(pty_idx, &mut cooked);
    assert_eq!(n, 3);
    assert_eq!(&cooked[..3], b"ls\n");
}

#[test]
fn stdio_pty_blocked_read_resume_preserves_register_context() {
    let mut t = TestVm::new();
    let pty_idx = fd_table::get_ofd(t.base, &t.vm, 0)
        .map(|ofd| ofd.ino)
        .unwrap_or(0);
    assert!(pty_idx > 0);

    let buf_addr = t.scratch + 0x3b00;
    t.vm.x[17] = SYS_READ;
    t.vm.x[10] = 0;
    t.vm.x[11] = buf_addr;
    t.vm.x[12] = 8;
    let status = tidemark_kernel::syscall::dispatch(&mut t.vm, t.base);
    assert_eq!(status, STATUS_PIPE_WAIT);
    assert_eq!(t.vm.status, STATUS_PIPE_WAIT);

    t.vm.pc = 0x4455_6677;
    t.vm.x[1] = 0x5566_7788;
    t.vm.x[2] = t.scratch + 0x2800;
    t.vm.x[27] = 0x7788_9900;

    assert_eq!(
        tidemark_kernel::syscall::pty::master_write(pty_idx, b"ls\r"),
        3
    );

    let vm_ptr = &mut t.vm as *mut _ as u32;
    assert_eq!(thread_resume_blocked_syscall(vm_ptr), 3);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, 0x4455_6677);
    assert_eq!(t.vm.x[1], 0x5566_7788);
    assert_eq!(t.vm.x[2], t.scratch + 0x2800);
    assert_eq!(t.vm.x[27], 0x7788_9900);

    let mut cooked = [0u8; 8];
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(t.base, buf_addr, &mut cooked[..3]);
    }
    assert_eq!(&cooked[..3], b"ls\n");
}

#[test]
fn stdio_pty_blocked_read_resume_first_thread_step_preserves_s11() {
    let mut t = TestVm::new();
    let pty_idx = fd_table::get_ofd(t.base, &t.vm, 0)
        .map(|ofd| ofd.ino)
        .unwrap_or(0);
    assert!(pty_idx > 0);

    let mapped = t.sys_mmap(
        0,
        0x1000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert!(mapped > 0);
    let code_addr = mapped as u64;
    assert!(
        tidemark_kernel::syscall::memory::guest_range_permitted(
            &t.vm, t.base, code_addr, 2, PROT_EXEC,
        ),
        "mapped code is not executable at {:#x}",
        code_addr
    );

    unsafe {
        // ecall
        tidemark_kernel::guest_mem::write_u32(t.base, code_addr, 0x0000_0073);
        // addi s11, s11, 0
        tidemark_kernel::guest_mem::write_u32(t.base, code_addr + 4, 0x000d_8d93);
        assert_eq!(
            tidemark_kernel::guest_mem::read_u32(t.base, code_addr),
            0x0000_0073
        );
    }

    let buf_addr = t.scratch + 0x3c00;
    t.vm.pc = code_addr;
    t.vm.x[1] = 0x5566_7788;
    t.vm.x[2] = t.scratch + 0x2800;
    t.vm.x[10] = 0;
    t.vm.x[11] = buf_addr;
    t.vm.x[12] = 8;
    t.vm.x[17] = SYS_READ;
    t.vm.x[27] = 0x7788_9900;

    let ps = unsafe {
        &*((t.base as u64 + t.vm.process_ptr as u64) as *const tidemark_kernel::types::ProcessState)
    };
    ps.thread_count.store(2, Ordering::Release);
    let vm_ptr = &mut t.vm as *mut _ as u32;
    let remaining = tidemark_kernel::abi::thread_step(vm_ptr, 1);
    assert_eq!(remaining, 0);
    assert_eq!(
        t.vm.status, STATUS_PIPE_WAIT,
        "status={} pc={:#x} fault_pc={:#x} fault_addr={:#x} sig_pending={:#x}",
        t.vm.status, t.vm.pc, t.vm.fault_pc, t.vm.fault_addr, t.vm.sig_pending
    );

    assert_eq!(
        tidemark_kernel::syscall::pty::master_write(pty_idx, b"ls\r"),
        3
    );
    assert_eq!(thread_resume_blocked_syscall(vm_ptr), 3);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, code_addr + 4);
    assert_eq!(t.vm.x[1], 0x5566_7788);
    assert_eq!(t.vm.x[2], t.scratch + 0x2800);
    assert_eq!(t.vm.x[10], 3);
    assert_eq!(t.vm.x[27], 0x7788_9900);

    let remaining = tidemark_kernel::abi::thread_step(vm_ptr, 1);
    assert_eq!(remaining, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, code_addr + 8);
    assert_eq!(t.vm.x[1], 0x5566_7788);
    assert_eq!(t.vm.x[2], t.scratch + 0x2800);
    assert_eq!(t.vm.x[27], 0x7788_9900);

    let mut cooked = [0u8; 8];
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(t.base, buf_addr, &mut cooked[..3]);
    }
    assert_eq!(&cooked[..3], b"ls\n");
}
