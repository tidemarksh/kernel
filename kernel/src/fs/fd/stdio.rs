use super::alloc::{open_pipe, open_pty_slave};
use super::close::sys_close;
use super::entry::get_process_state;
use crate::abi::{O_RDONLY, O_WRONLY};
use crate::types::ThreadState;

/// Initialize stdin/stdout/stderr bridges for a new process.
///
/// Runtime owns the hidden peer ends:
/// - stdin: runtime writes, guest reads
/// - stdout/stderr: guest writes, runtime reads
///
/// # Safety
/// `base` and `vm.process_ptr` must describe a valid writable guest `ProcessState`.
pub unsafe fn init_stdio(base: u32, vm: &mut ThreadState) {
    let ps = get_process_state(base, vm);
    if ps.is_null() {
        return;
    }

    let Some(stdio_pty) = crate::syscall::pty::alloc_stdio_pty(vm, base) else {
        return;
    };

    let fd0 = open_pty_slave(vm, base, stdio_pty.pty_idx, O_RDONLY);
    let fd1 = open_pty_slave(vm, base, stdio_pty.pty_idx, O_WRONLY);
    let fd2 = open_pty_slave(vm, base, stdio_pty.pty_idx, O_WRONLY);
    if fd0 != 0 || fd1 != 1 || fd2 != 2 {
        if fd0 >= 0 {
            let _ = sys_close(vm, base, fd0 as u64);
        }
        if fd1 >= 0 {
            let _ = sys_close(vm, base, fd1 as u64);
        }
        if fd2 >= 0 {
            let _ = sys_close(vm, base, fd2 as u64);
        }
        crate::syscall::pty::release_host_attachment(vm, base);
        return;
    }

    unsafe {
        (*ps).stdin_pipe_slot = stdio_pty.stdin_pipe;
        (*ps).stdout_pipe_slot = stdio_pty.stdout_pipe;
        (*ps).stderr_pipe_slot = stdio_pty.stdout_pipe;
    }
}

/// Replace the default host-facing PTY stdio with plain pipes.
///
/// Non-interactive processes use byte streams; PTY echo/canonical handling is
/// only correct for terminal sessions. Runtime keeps the hidden peer ends:
/// - stdin: runtime writes, guest reads fd 0
/// - stdout/stderr: guest writes fd 1/2, runtime reads
pub unsafe fn use_pipe_stdio(base: u32, vm: &mut ThreadState) -> bool {
    crate::syscall::pty::release_host_attachment(vm, base);
    let _ = sys_close(vm, base, 0);
    let _ = sys_close(vm, base, 1);
    let _ = sys_close(vm, base, 2);

    let Some(stdin_pipe) = crate::syscall::pipe::alloc_pipe_slot() else {
        return false;
    };
    let Some(stdout_pipe) = crate::syscall::pipe::alloc_pipe_slot() else {
        crate::syscall::pipe::pipe_close(stdin_pipe, true);
        crate::syscall::pipe::pipe_close(stdin_pipe, false);
        return false;
    };
    let Some(stderr_pipe) = crate::syscall::pipe::alloc_pipe_slot() else {
        crate::syscall::pipe::pipe_close(stdin_pipe, true);
        crate::syscall::pipe::pipe_close(stdin_pipe, false);
        crate::syscall::pipe::pipe_close(stdout_pipe, true);
        crate::syscall::pipe::pipe_close(stdout_pipe, false);
        return false;
    };

    let fd0 = open_pipe(vm, base, stdin_pipe, true, 0);
    let fd1 = open_pipe(vm, base, stdout_pipe, false, 0);
    let fd2 = open_pipe(vm, base, stderr_pipe, false, 0);
    if fd0 != 0 || fd1 != 1 || fd2 != 2 {
        if fd0 >= 0 {
            let _ = sys_close(vm, base, fd0 as u64);
        }
        if fd1 >= 0 {
            let _ = sys_close(vm, base, fd1 as u64);
        }
        if fd2 >= 0 {
            let _ = sys_close(vm, base, fd2 as u64);
        }
        crate::syscall::pipe::pipe_close(stdin_pipe, true);
        crate::syscall::pipe::pipe_close(stdin_pipe, false);
        crate::syscall::pipe::pipe_close(stdout_pipe, true);
        crate::syscall::pipe::pipe_close(stdout_pipe, false);
        crate::syscall::pipe::pipe_close(stderr_pipe, true);
        crate::syscall::pipe::pipe_close(stderr_pipe, false);
        return false;
    }

    let ps = get_process_state(base, vm);
    if ps.is_null() {
        return false;
    }
    unsafe {
        (*ps).stdin_pipe_slot = stdin_pipe;
        (*ps).stdout_pipe_slot = stdout_pipe;
        (*ps).stderr_pipe_slot = stderr_pipe;
        (*ps).tty_pty_slot = 0;
    }
    true
}
