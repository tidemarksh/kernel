use crate::abi::*;
use crate::fs::{fd_table, memfs};
use crate::guest_mem;
use crate::syscall::sync_effects::{
    mark_fork_shared_ofd_sync_effect, mark_pipe_sync_effect, mark_process_memfs_sync_effect,
    mark_socket_sync_effect,
};
use crate::syscall::{pipe, signal, socket};
use crate::types::{OpenFileDesc, ThreadState};

const EVENTFD_COUNTER_MAX: u64 = u64::MAX - 1;
const IOVEC_SIZE: u64 = 16;
const LINUX_IOV_MAX: u64 = 1024;
pub(crate) const PIPE_READ_EOF_SYNC_RETRY_MARKER: u64 = 0x7069_7065_454f_4652;
const PIPE_EPIPE_SYNC_RETRY_MARKER: u64 = 0x7069_7065_4550_4950;
const PROC_MAPS_READ_TRACE_CAP: usize = 64;
const PROC_MAPS_READ_TRACE_ENABLED: bool = false;

#[derive(Clone, Copy)]
#[allow(dead_code)]
pub(crate) struct ProcMapsReadTraceEntry {
    pub vm_ptr: u32,
    pub fd: u64,
    pub ino: u32,
    pub buf: u64,
    pub len: u64,
    pub result: i64,
    pub file_offset: u64,
    pub writable: u32,
    pub exec_overlap: u32,
    pub vma_start: u64,
    pub vma_end: u64,
    pub vma_prot: i32,
    pub vma_fd: i32,
    pub vma_offset: u64,
}

static mut PROC_MAPS_READ_TRACE: [ProcMapsReadTraceEntry; PROC_MAPS_READ_TRACE_CAP] =
    [ProcMapsReadTraceEntry {
        vm_ptr: 0,
        fd: 0,
        ino: 0,
        buf: 0,
        len: 0,
        result: 0,
        file_offset: 0,
        writable: 0,
        exec_overlap: 0,
        vma_start: 0,
        vma_end: 0,
        vma_prot: 0,
        vma_fd: 0,
        vma_offset: 0,
    }; PROC_MAPS_READ_TRACE_CAP];
static mut PROC_MAPS_READ_TRACE_LEN: u32 = 0;
static mut PROC_MAPS_READ_TRACE_NEXT: u32 = 0;

fn guest_range_readable(vm: &ThreadState, base: u32, start: u64, len: u64) -> bool {
    crate::syscall::memory::guest_range_permitted(vm, base, start, len, PROT_READ)
}

fn guest_range_writable(vm: &ThreadState, base: u32, start: u64, len: u64) -> bool {
    crate::syscall::memory::guest_range_permitted(vm, base, start, len, PROT_WRITE)
}

fn is_proc_self_maps_inode(ino: u32) -> bool {
    let mut path = [0u8; 128];
    let len = memfs::write_path(ino, &mut path);
    &path[..len] == b"/proc/self/maps"
}

fn executable_overlap(start: u64, len: u64) -> (u32, u64, u64, i32, i32, u64) {
    let Some(end) = start.checked_add(len) else {
        return (0, 0, 0, 0, 0, 0);
    };
    let vma_len = crate::syscall::memory::address_space_vma_len();
    for index in 0..vma_len {
        let prot = crate::syscall::memory::address_space_vma_prot(index);
        if (prot & PROT_EXEC) == 0 {
            continue;
        }
        let vma_start = crate::syscall::memory::address_space_vma_start(index);
        let vma_end = crate::syscall::memory::address_space_vma_end(index);
        if start < vma_end && end > vma_start {
            return (
                1,
                vma_start,
                vma_end,
                prot,
                crate::syscall::memory::address_space_vma_fd(index),
                crate::syscall::memory::address_space_vma_offset(index),
            );
        }
    }
    (0, 0, 0, 0, 0, 0)
}

fn record_proc_maps_read(
    vm: &ThreadState,
    base: u32,
    fd: u64,
    ino: u32,
    buf: u64,
    len: u64,
    result: i64,
    file_offset: u64,
) {
    if !PROC_MAPS_READ_TRACE_ENABLED {
        let _ = (vm, base, fd, ino, buf, len, result, file_offset);
        return;
    }
    if result <= 0 || !is_proc_self_maps_inode(ino) {
        return;
    }
    let writable = guest_range_writable(vm, base, buf, len) as u32;
    let (exec_overlap, vma_start, vma_end, vma_prot, vma_fd, vma_offset) =
        executable_overlap(buf, len);
    let entry = ProcMapsReadTraceEntry {
        vm_ptr: vm as *const ThreadState as u32,
        fd,
        ino,
        buf,
        len,
        result,
        file_offset,
        writable,
        exec_overlap,
        vma_start,
        vma_end,
        vma_prot,
        vma_fd,
        vma_offset,
    };
    unsafe {
        let index = PROC_MAPS_READ_TRACE_NEXT as usize % PROC_MAPS_READ_TRACE_CAP;
        PROC_MAPS_READ_TRACE[index] = entry;
        PROC_MAPS_READ_TRACE_NEXT = PROC_MAPS_READ_TRACE_NEXT.wrapping_add(1);
        if PROC_MAPS_READ_TRACE_LEN < PROC_MAPS_READ_TRACE_CAP as u32 {
            PROC_MAPS_READ_TRACE_LEN += 1;
        }
    }
}

#[allow(dead_code)]
pub(crate) fn proc_maps_read_trace_len() -> u32 {
    unsafe { PROC_MAPS_READ_TRACE_LEN }
}

#[allow(dead_code)]
pub(crate) fn proc_maps_read_trace_entry(index: u32) -> ProcMapsReadTraceEntry {
    unsafe {
        if PROC_MAPS_READ_TRACE_LEN == 0 {
            return PROC_MAPS_READ_TRACE[0];
        }
        PROC_MAPS_READ_TRACE[index as usize % PROC_MAPS_READ_TRACE_CAP]
    }
}

// =========================================================================
// read / pread64
// =========================================================================

/// read: read from file or pipe FD. Advances OFD offset for files.
pub fn sys_read(vm: &mut ThreadState, base: u32, fd: u64, buf: u64, count: u64) -> i64 {
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };

    if ofd.fd_type == FD_TYPE_DEVNULL {
        return 0;
    }

    if ofd.fd_type == FD_TYPE_PTY_SLAVE || ofd.fd_type == FD_TYPE_PTY_MASTER {
        let access_mode = ofd.status_flags & fd_table::OPEN_ACCESS_MODE_MASK;
        if access_mode == O_WRONLY {
            return EBADF;
        }
        let mut tmp = [0u8; 4096];
        let to_read = (count as usize).min(tmp.len());
        let n = if ofd.fd_type == FD_TYPE_PTY_SLAVE {
            crate::syscall::pty::slave_read(ofd.ino, &mut tmp[..to_read])
        } else {
            crate::syscall::pty::master_read(ofd.ino, &mut tmp[..to_read])
        };
        if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.status = STATUS_PIPE_WAIT;
            return 0;
        }
        if n > 0 {
            let pipe_slot = if ofd.fd_type == FD_TYPE_PTY_SLAVE {
                crate::syscall::pty::input_pipe_slot(ofd.ino)
            } else {
                crate::syscall::pty::output_pipe_slot(ofd.ino)
            };
            mark_pipe_sync_effect(vm, pipe_slot, false);
            if !guest_range_writable(vm, base, buf, n as u64) {
                return EFAULT;
            }
            unsafe {
                guest_mem::write_bytes(base, buf, &tmp[..n as usize]);
            }
            flush_shared_guest_write(vm, base, buf, n as u64);
            vm.completed_pipe_read_guest_ptr = buf;
            vm.completed_pipe_read_len = n as u32;
        }
        return n;
    }

    if ofd.fd_type == FD_TYPE_PIPE {
        if !fd_table::is_pipe_read(&ofd) {
            return EBADF;
        }
        let mut tmp = [0u8; pipe::PIPE_BUF_SIZE];
        let to_read = (count as usize).min(tmp.len());
        let n = pipe::pipe_read(ofd.ino, &mut tmp[..to_read]);
        if n == 0 && count > 0 {
            if vm.fault_addr != PIPE_READ_EOF_SYNC_RETRY_MARKER || vm.fault_pc != fd {
                fd_table::pin_blocked_fd(base, vm, fd);
                vm.fault_addr = PIPE_READ_EOF_SYNC_RETRY_MARKER;
                vm.fault_pc = fd;
                vm.status = STATUS_PIPE_WAIT;
                return 0;
            }
            vm.fault_addr = 0;
            vm.fault_pc = 0;
        }
        if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.status = STATUS_PIPE_WAIT;
            return 0;
        }
        if n > 0 {
            mark_pipe_sync_effect(vm, ofd.ino, false);
            vm.fault_addr = 0;
            vm.fault_pc = 0;
            if !guest_range_writable(vm, base, buf, n as u64) {
                return EFAULT;
            }
            unsafe {
                guest_mem::write_bytes(base, buf, &tmp[..n as usize]);
            }
            flush_shared_guest_write(vm, base, buf, n as u64);
            vm.completed_pipe_read_guest_ptr = buf;
            vm.completed_pipe_read_len = n as u32;
        }
        return n;
    }

    if ofd.fd_type == FD_TYPE_EVENTFD {
        if count < 8 {
            return EINVAL;
        }
        let counter = fd_table::get_offset(base, vm, fd);
        if counter == 0 {
            if ofd.status_flags & O_NONBLOCK != 0 {
                return EAGAIN;
            }
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.status = STATUS_PIPE_WAIT;
            return 0;
        }

        let value = if ofd.host_fd != 0 { 1 } else { counter };
        let next = if ofd.host_fd != 0 { counter - 1 } else { 0 };
        if !guest_range_writable(vm, base, buf, 8) {
            return EFAULT;
        }
        unsafe {
            guest_mem::write_u64(base, buf, value);
        }
        flush_shared_guest_write(vm, base, buf, 8);
        fd_table::set_offset(base, vm, fd, next);
        return 8;
    }

    if ofd.fd_type == FD_TYPE_TIMERFD {
        let n = crate::syscall::time::timerfd_read(base, buf, count, ofd.ino);
        if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.status = STATUS_PIPE_WAIT;
            return 0;
        }
        return n;
    }

    if ofd.fd_type == FD_TYPE_SIGNALFD {
        let n = crate::syscall::signal::signalfd_read(vm, base, buf, count, ofd.ino);
        if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.status = STATUS_PIPE_WAIT;
            return 0;
        }
        return n;
    }

    if ofd.fd_type == FD_TYPE_SOCKET {
        let n = socket::socket_read(vm, base, fd, buf, count);
        if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.socket_timeout_ms = socket::socket_recv_timeout_ms_for_fd(base, vm, fd);
            vm.status = STATUS_SOCKET_RECV;
            return 0;
        }
        if n >= 0 {
            mark_socket_sync_effect(vm);
        }
        if n > 0 {
            flush_shared_guest_write(vm, base, buf, n as u64);
        }
        return n;
    }

    read_regular_file_to_guest(vm, base, fd, buf, count, None)
}

/// readv: scatter read into multiple guest buffers.
pub fn sys_readv(vm: &mut ThreadState, base: u32, fd: u64, iov_addr: u64, iovcnt: u64) -> i64 {
    let validation = validate_readv_iovecs(vm, base, iov_addr, iovcnt);
    if validation < 0 {
        return validation;
    }

    let mut total = 0i64;

    for i in 0..iovcnt {
        let iov_base = unsafe { guest_mem::read_u64(base, iov_addr + i * 16) };
        let iov_len = unsafe { guest_mem::read_u64(base, iov_addr + i * 16 + 8) };
        if iov_len == 0 {
            continue;
        }

        let n = sys_read(vm, base, fd, iov_base, iov_len);
        if vm.status == STATUS_PIPE_WAIT || vm.status == STATUS_SOCKET_RECV {
            if total > 0 {
                fd_table::clear_blocked_ofd_pin(vm);
                vm.socket_timeout_ms = -1;
                vm.status = STATUS_OK;
                return total;
            }
            return 0;
        }
        if n < 0 {
            return if total > 0 { total } else { n };
        }
        if n == 0 {
            break;
        }

        total += n;
        if (n as u64) < iov_len {
            break;
        }
    }

    total
}

fn validate_readv_iovecs(vm: &ThreadState, base: u32, iov_addr: u64, iovcnt: u64) -> i64 {
    if iovcnt == 0 {
        return 0;
    }
    if iovcnt > LINUX_IOV_MAX {
        return EINVAL;
    }
    let Some(iov_bytes) = iovcnt.checked_mul(IOVEC_SIZE) else {
        return EINVAL;
    };
    if !guest_range_readable(vm, base, iov_addr, iov_bytes) {
        return EFAULT;
    }

    let mut total = 0u64;
    for i in 0..iovcnt {
        let iov_base = unsafe { guest_mem::read_u64(base, iov_addr + i * IOVEC_SIZE) };
        let iov_len = unsafe { guest_mem::read_u64(base, iov_addr + i * IOVEC_SIZE + 8) };
        if iov_len > i64::MAX as u64 {
            return EINVAL;
        }
        let Some(next_total) = total.checked_add(iov_len) else {
            return EINVAL;
        };
        if next_total > i64::MAX as u64 {
            return EINVAL;
        }
        total = next_total;
        if iov_len > 0 && !guest_range_writable(vm, base, iov_base, iov_len) {
            return EFAULT;
        }
    }
    0
}

/// pread64: read at specified offset without changing OFD offset.
pub fn sys_pread64(
    vm: &mut ThreadState,
    base: u32,
    fd: u64,
    buf: u64,
    count: u64,
    offset: u64,
) -> i64 {
    if (offset as i64) < 0 {
        return EINVAL;
    }
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };

    if ofd.fd_type == FD_TYPE_DEVNULL {
        return 0;
    }
    if ofd.fd_type != FD_TYPE_FILE {
        return ESPIPE;
    }
    if ofd.status_flags & fd_table::OPEN_ACCESS_MODE_MASK == O_WRONLY {
        return EBADF;
    }

    read_regular_file_to_guest(vm, base, fd, buf, count, Some(offset))
}

fn read_regular_file_to_guest(
    vm: &mut ThreadState,
    base: u32,
    fd: u64,
    guest_buf: u64,
    count: u64,
    offset: Option<u64>,
) -> i64 {
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };
    if ofd.status_flags & fd_table::OPEN_ACCESS_MODE_MASK == O_WRONLY {
        return EBADF;
    }
    if let Some(st) = memfs::stat(ofd.ino) {
        if st.mode & memfs::S_IFMT == memfs::S_IFDIR {
            return EISDIR;
        }
    }
    if count == 0 {
        return 0;
    }
    if guest_buf == 0 {
        return EFAULT;
    }

    let start_offset = offset.unwrap_or(ofd.offset as u64);
    let mut tmp = [0u8; 4096];
    let mut total = 0u64;

    while total < count {
        let to_read = ((count - total) as usize).min(tmp.len());
        let n = memfs::read_file(ofd.ino, start_offset + total, &mut tmp[..to_read]);
        if n < 0 {
            return if total > 0 { total as i64 } else { n };
        }
        if n == 0 {
            break;
        }
        if !guest_range_writable(vm, base, guest_buf + total, n as u64) {
            record_proc_maps_read(
                vm,
                base,
                fd,
                ofd.ino,
                guest_buf + total,
                n as u64,
                EFAULT,
                start_offset + total,
            );
            return if total > 0 { total as i64 } else { EFAULT };
        }
        record_proc_maps_read(
            vm,
            base,
            fd,
            ofd.ino,
            guest_buf + total,
            n as u64,
            n,
            start_offset + total,
        );
        unsafe {
            guest_mem::write_bytes(base, guest_buf + total, &tmp[..n as usize]);
        }
        flush_shared_guest_write(vm, base, guest_buf + total, n as u64);
        total += n as u64;
        if (n as usize) < to_read {
            break;
        }
    }

    if total > 0 && offset.is_none() {
        fd_table::advance_offset(base, vm, fd, total);
        mark_fork_shared_ofd_sync_effect(vm);
    }
    total as i64
}

// =========================================================================
// pwrite64
// =========================================================================

/// pwrite64: write at specified offset without changing OFD offset.
pub fn sys_pwrite64(
    vm: &mut ThreadState,
    base: u32,
    fd: u64,
    buf: u64,
    count: u64,
    offset: u64,
) -> i64 {
    if (offset as i64) < 0 {
        return EINVAL;
    }
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };

    if !file_open_for_write(&ofd) {
        return EBADF;
    }
    if ofd.fd_type == FD_TYPE_DEVNULL {
        return count as i64;
    }
    if ofd.fd_type != FD_TYPE_FILE {
        return ESPIPE;
    }

    let start_offset = if ofd.status_flags & O_APPEND != 0 {
        memfs::stat(ofd.ino).map(|stat| stat.size).unwrap_or(0)
    } else {
        offset
    };
    let n = write_regular_file_from_guest(base, buf, count, ofd.ino, start_offset);
    if n > 0 {
        mark_process_memfs_sync_effect(vm);
    }
    n
}

fn write_regular_file_from_guest(
    base: u32,
    guest_addr: u64,
    len: u64,
    ino: u32,
    start_offset: u64,
) -> i64 {
    if len == 0 {
        return 0;
    }
    if guest_addr == 0 {
        return EFAULT;
    }
    if len <= u32::MAX as u64
        && crate::syscall::memory::guest_range_accessible(base, guest_addr, len)
    {
        let data = unsafe { guest_mem::read_slice(base, guest_addr, len as usize) };
        return memfs::write_file(ino, start_offset, data);
    }

    let mut tmp = [0u8; 4096];
    let mut total = 0u64;
    while total < len {
        let to_write = ((len - total) as usize).min(tmp.len());
        if !crate::syscall::memory::guest_range_accessible(
            base,
            guest_addr + total,
            to_write as u64,
        ) {
            return if total > 0 { total as i64 } else { EFAULT };
        }
        unsafe {
            guest_mem::read_bytes(base, guest_addr + total, &mut tmp[..to_write]);
        }
        let n = memfs::write_file(ino, start_offset + total, &tmp[..to_write]);
        if n < 0 {
            return if total > 0 { total as i64 } else { n };
        }
        if n == 0 {
            break;
        }
        total += n as u64;
        if (n as usize) < to_write {
            break;
        }
    }
    total as i64
}

// =========================================================================
// write / writev
// =========================================================================

/// write: write to file or pipe FD. Sends SIGPIPE on broken pipe.
/// Also handles writev (dispatched by nr == SYS_WRITEV).
#[allow(clippy::too_many_arguments)]
fn trace_write_attempt(
    fd: u64,
    nr: u64,
    buf_addr: u64,
    count: u64,
    result: i64,
    ofd_id: u32,
    ofd_type: i32,
    ofd_ino: u32,
    status_flags: i32,
    pipe_read_open: i32,
    pipe_write_open: i32,
    bytes: Option<&[u8]>,
) -> i64 {
    crate::tracepoints::record_write_attempt(
        fd,
        nr,
        buf_addr,
        count,
        result,
        ofd_id,
        ofd_type,
        ofd_ino,
        status_flags,
        pipe_read_open,
        pipe_write_open,
        bytes,
    );
    result
}

fn trace_pipe_open_state(ofd: &OpenFileDesc) -> (i32, i32) {
    if ofd.fd_type == FD_TYPE_PIPE {
        (
            pipe::debug_read_open(ofd.ino),
            pipe::debug_write_open(ofd.ino),
        )
    } else {
        (0, 0)
    }
}

fn flush_shared_guest_write(vm: &mut ThreadState, base: u32, guest_addr: u64, len: u64) {
    if len == 0 {
        return;
    }
    if crate::syscall::memory::flush_shared_mappings_for_guest_write(base, guest_addr, len) {
        mark_process_memfs_sync_effect(vm);
    }
}

fn file_open_for_write(ofd: &OpenFileDesc) -> bool {
    (ofd.status_flags & fd_table::OPEN_ACCESS_MODE_MASK) != O_RDONLY
}

fn regular_file_write_offset(ofd: &OpenFileDesc, ofd_id: u32) -> u64 {
    if ofd.status_flags & O_APPEND != 0 {
        return memfs::stat(ofd.ino).map(|stat| stat.size).unwrap_or(0);
    }
    fd_table::get_offset_by_id(ofd_id)
        .max(fd_table::get_offset_floor_by_id(ofd_id))
        .max(ofd.offset as u64)
}

fn validate_writev_iovecs(base: u32, iov_addr: u64, iovcnt: u64) -> i64 {
    if iovcnt == 0 {
        return 0;
    }
    if iovcnt > LINUX_IOV_MAX {
        return EINVAL;
    }
    let Some(iov_bytes) = iovcnt.checked_mul(IOVEC_SIZE) else {
        return EINVAL;
    };
    if !crate::syscall::memory::guest_range_accessible(base, iov_addr, iov_bytes) {
        return EFAULT;
    }

    let mut total = 0u64;
    for i in 0..iovcnt {
        let iov_len = unsafe { guest_mem::read_u64(base, iov_addr + i * IOVEC_SIZE + 8) };
        if iov_len > i64::MAX as u64 {
            return EINVAL;
        }
        let Some(next_total) = total.checked_add(iov_len) else {
            return EINVAL;
        };
        if next_total > i64::MAX as u64 {
            return EINVAL;
        }
        total = next_total;
    }
    0
}

pub fn sys_write(vm: &mut ThreadState, base: u32, fd: u64, buf: u64, count: u64, nr: u64) -> i64 {
    if nr == SYS_WRITEV {
        return sys_writev(vm, base, fd, buf, count);
    }

    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => {
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                EBADF,
                0,
                FD_TYPE_NONE,
                0,
                0,
                0,
                0,
                None,
            );
        }
    };
    let ofd_id = fd_table::get_ofd_id(base, vm, fd).unwrap_or(0);
    let (pipe_read_open, pipe_write_open) = trace_pipe_open_state(&ofd);

    if ofd.fd_type == FD_TYPE_DEVNULL {
        if !file_open_for_write(&ofd) {
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                EBADF,
                ofd_id,
                ofd.fd_type,
                ofd.ino,
                ofd.status_flags,
                0,
                0,
                None,
            );
        }
        return trace_write_attempt(
            fd,
            nr,
            buf,
            count,
            count as i64,
            ofd_id,
            ofd.fd_type,
            ofd.ino,
            ofd.status_flags,
            0,
            0,
            None,
        );
    }

    if ofd.fd_type == FD_TYPE_STDOUT || ofd.fd_type == FD_TYPE_STDERR {
        #[cfg(target_os = "wasi")]
        {
            let mut tmp = [0u8; 4096];
            let to_write = (count as usize).min(tmp.len());
            unsafe {
                guest_mem::read_bytes(base, buf, &mut tmp[..to_write]);
            }
            if let Ok(s) = core::str::from_utf8(&tmp[..to_write]) {
                eprint!("{s}");
            } else {
                eprintln!("guest-fd{} {:?}", fd, &tmp[..to_write]);
            }
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                to_write as i64,
                ofd_id,
                ofd.fd_type,
                ofd.ino,
                ofd.status_flags,
                0,
                0,
                Some(&tmp[..to_write]),
            );
        }
    }

    if ofd.fd_type == FD_TYPE_PTY_SLAVE || ofd.fd_type == FD_TYPE_PTY_MASTER {
        let access_mode = ofd.status_flags & fd_table::OPEN_ACCESS_MODE_MASK;
        if access_mode == O_RDONLY {
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                EBADF,
                ofd_id,
                ofd.fd_type,
                ofd.ino,
                ofd.status_flags,
                0,
                0,
                None,
            );
        }
        let mut tmp = [0u8; 4096];
        let to_write = (count as usize).min(tmp.len());
        unsafe {
            guest_mem::read_bytes(base, buf, &mut tmp[..to_write]);
        }
        let n = if ofd.fd_type == FD_TYPE_PTY_SLAVE {
            crate::syscall::pty::slave_write(ofd.ino, &tmp[..to_write])
        } else {
            crate::syscall::pty::master_write_from_thread(ofd.ino, &tmp[..to_write], vm, base)
        };
        if n == EPIPE {
            signal::send_signal(vm, SIGPIPE);
        }
        if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.status = STATUS_PIPE_WAIT;
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                0,
                ofd_id,
                ofd.fd_type,
                ofd.ino,
                ofd.status_flags,
                0,
                0,
                Some(&tmp[..to_write]),
            );
        }
        if n > 0 {
            let pipe_slot = if ofd.fd_type == FD_TYPE_PTY_SLAVE {
                crate::syscall::pty::output_pipe_slot(ofd.ino)
            } else {
                crate::syscall::pty::input_pipe_slot(ofd.ino)
            };
            mark_pipe_sync_effect(vm, pipe_slot, true);
        }
        return trace_write_attempt(
            fd,
            nr,
            buf,
            count,
            n,
            ofd_id,
            ofd.fd_type,
            ofd.ino,
            ofd.status_flags,
            0,
            0,
            Some(&tmp[..to_write]),
        );
    }

    if ofd.fd_type == FD_TYPE_PIPE {
        if !fd_table::is_pipe_write(&ofd) {
            let mut tmp = [0u8; 64];
            let to_trace = (count as usize).min(tmp.len());
            if to_trace > 0
                && crate::syscall::memory::guest_range_accessible(base, buf, to_trace as u64)
            {
                unsafe {
                    guest_mem::read_bytes(base, buf, &mut tmp[..to_trace]);
                }
                return trace_write_attempt(
                    fd,
                    nr,
                    buf,
                    count,
                    EBADF,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    pipe_read_open,
                    pipe_write_open,
                    Some(&tmp[..to_trace]),
                );
            }
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                EBADF,
                ofd_id,
                ofd.fd_type,
                ofd.ino,
                ofd.status_flags,
                pipe_read_open,
                pipe_write_open,
                None,
            );
        }
        let mut tmp = [0u8; pipe::PIPE_BUF_SIZE];
        let to_write = (count as usize).min(tmp.len());
        unsafe {
            guest_mem::read_bytes(base, buf, &mut tmp[..to_write]);
        }
        let n = pipe::pipe_write(ofd.ino, &tmp[..to_write]);
        if n == EPIPE {
            if !fd_table::pipe_epipe_synced(ofd_id)
                && (vm.fault_addr != PIPE_EPIPE_SYNC_RETRY_MARKER || vm.fault_pc != fd)
            {
                fd_table::pin_blocked_fd(base, vm, fd);
                fd_table::set_pipe_epipe_synced(ofd_id, true);
                vm.fault_addr = PIPE_EPIPE_SYNC_RETRY_MARKER;
                vm.fault_pc = fd;
                vm.status = STATUS_PIPE_WAIT;
                return trace_write_attempt(
                    fd,
                    nr,
                    buf,
                    count,
                    0,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    pipe_read_open,
                    pipe_write_open,
                    Some(&tmp[..to_write]),
                );
            }
            vm.fault_addr = 0;
            vm.fault_pc = 0;
            signal::send_signal(vm, SIGPIPE);
        }
        if n >= 0 {
            vm.fault_addr = 0;
            vm.fault_pc = 0;
            fd_table::set_pipe_epipe_synced(ofd_id, false);
        }
        if n == EAGAIN {
            fd_table::set_pipe_epipe_synced(ofd_id, false);
        }
        if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.status = STATUS_PIPE_WAIT;
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                0,
                ofd_id,
                ofd.fd_type,
                ofd.ino,
                ofd.status_flags,
                pipe_read_open,
                pipe_write_open,
                Some(&tmp[..to_write]),
            );
        }
        if n > 0 {
            mark_pipe_sync_effect(vm, ofd.ino, true);
        }
        return trace_write_attempt(
            fd,
            nr,
            buf,
            count,
            n,
            ofd_id,
            ofd.fd_type,
            ofd.ino,
            ofd.status_flags,
            pipe_read_open,
            pipe_write_open,
            Some(&tmp[..to_write]),
        );
    }

    if ofd.fd_type == FD_TYPE_EVENTFD {
        if count < 8 {
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                EINVAL,
                ofd_id,
                ofd.fd_type,
                ofd.ino,
                ofd.status_flags,
                0,
                0,
                None,
            );
        }
        let value = unsafe { guest_mem::read_u64(base, buf) };
        if value == u64::MAX {
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                EINVAL,
                ofd_id,
                ofd.fd_type,
                ofd.ino,
                ofd.status_flags,
                0,
                0,
                None,
            );
        }

        let counter = fd_table::get_offset(base, vm, fd);
        if counter > EVENTFD_COUNTER_MAX.saturating_sub(value) {
            if ofd.status_flags & O_NONBLOCK != 0 {
                return trace_write_attempt(
                    fd,
                    nr,
                    buf,
                    count,
                    EAGAIN,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.status = STATUS_PIPE_WAIT;
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                0,
                ofd_id,
                ofd.fd_type,
                ofd.ino,
                ofd.status_flags,
                0,
                0,
                None,
            );
        }

        fd_table::set_offset(base, vm, fd, counter + value);
        return trace_write_attempt(
            fd,
            nr,
            buf,
            count,
            8,
            ofd_id,
            ofd.fd_type,
            ofd.ino,
            ofd.status_flags,
            0,
            0,
            None,
        );
    }

    if ofd.fd_type == FD_TYPE_TIMERFD {
        return trace_write_attempt(
            fd,
            nr,
            buf,
            count,
            EINVAL,
            ofd_id,
            ofd.fd_type,
            ofd.ino,
            ofd.status_flags,
            0,
            0,
            None,
        );
    }

    if ofd.fd_type == FD_TYPE_SIGNALFD {
        return trace_write_attempt(
            fd,
            nr,
            buf,
            count,
            EINVAL,
            ofd_id,
            ofd.fd_type,
            ofd.ino,
            ofd.status_flags,
            0,
            0,
            None,
        );
    }

    if ofd.fd_type == FD_TYPE_SOCKET {
        let n = socket::socket_write(vm, base, fd, buf, count);
        if n == EPIPE {
            signal::send_signal(vm, SIGPIPE);
        }
        if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.socket_timeout_ms = socket::socket_send_timeout_ms_for_fd(base, vm, fd);
            vm.status = STATUS_SOCKET_SEND;
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                0,
                ofd_id,
                ofd.fd_type,
                ofd.ino,
                ofd.status_flags,
                0,
                0,
                None,
            );
        }
        if n >= 0 || n == EPIPE {
            mark_socket_sync_effect(vm);
        }
        return trace_write_attempt(
            fd,
            nr,
            buf,
            count,
            n,
            ofd_id,
            ofd.fd_type,
            ofd.ino,
            ofd.status_flags,
            0,
            0,
            None,
        );
    }

    if ofd.fd_type == FD_TYPE_FILE && !file_open_for_write(&ofd) {
        return trace_write_attempt(
            fd,
            nr,
            buf,
            count,
            EBADF,
            ofd_id,
            ofd.fd_type,
            ofd.ino,
            ofd.status_flags,
            0,
            0,
            None,
        );
    }

    let mut trace = [0u8; 64];
    let to_trace = (count as usize).min(trace.len());
    if to_trace > 0 {
        unsafe {
            guest_mem::read_bytes(base, buf, &mut trace[..to_trace]);
        }
    }
    let current_offset = regular_file_write_offset(&ofd, ofd_id);
    let n = write_regular_file_from_guest(base, buf, count, ofd.ino, current_offset);
    if n > 0 {
        let next_offset = current_offset.saturating_add(n as u64);
        fd_table::set_offset_by_id(ofd_id, next_offset.max(fd_table::get_offset_by_id(ofd_id)));
        mark_fork_shared_ofd_sync_effect(vm);
        mark_process_memfs_sync_effect(vm);
    }
    trace_write_attempt(
        fd,
        nr,
        buf,
        count,
        n,
        ofd_id,
        ofd.fd_type,
        ofd.ino,
        ofd.status_flags,
        0,
        0,
        Some(&trace[..to_trace]),
    )
}

fn sys_writev(vm: &mut ThreadState, base: u32, fd: u64, iov_addr: u64, iovcnt: u64) -> i64 {
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => {
            return trace_write_attempt(
                fd,
                SYS_WRITEV,
                iov_addr,
                iovcnt,
                EBADF,
                0,
                FD_TYPE_NONE,
                0,
                0,
                0,
                0,
                None,
            );
        }
    };
    let ofd_id = fd_table::get_ofd_id(base, vm, fd).unwrap_or(0);
    let (pipe_read_open, pipe_write_open) = trace_pipe_open_state(&ofd);
    let validation = validate_writev_iovecs(base, iov_addr, iovcnt);
    if validation < 0 {
        return trace_write_attempt(
            fd,
            SYS_WRITEV,
            iov_addr,
            iovcnt,
            validation,
            ofd_id,
            ofd.fd_type,
            ofd.ino,
            ofd.status_flags,
            pipe_read_open,
            pipe_write_open,
            None,
        );
    }

    if ofd.fd_type == FD_TYPE_DEVNULL {
        if !file_open_for_write(&ofd) {
            return trace_write_attempt(
                fd,
                SYS_WRITEV,
                iov_addr,
                iovcnt,
                EBADF,
                ofd_id,
                ofd.fd_type,
                ofd.ino,
                ofd.status_flags,
                0,
                0,
                None,
            );
        }
        let mut total = 0u64;
        for i in 0..iovcnt {
            total += unsafe { guest_mem::read_u64(base, iov_addr + i * 16 + 8) };
        }
        return trace_write_attempt(
            fd,
            SYS_WRITEV,
            iov_addr,
            iovcnt,
            total as i64,
            ofd_id,
            ofd.fd_type,
            ofd.ino,
            ofd.status_flags,
            0,
            0,
            None,
        );
    }

    if ofd.fd_type == FD_TYPE_STDOUT || ofd.fd_type == FD_TYPE_STDERR {
        let mut total = 0u64;
        for i in 0..iovcnt {
            #[cfg(target_os = "wasi")]
            {
                let iov_base = unsafe { guest_mem::read_u64(base, iov_addr + i * 16) };
                let len = unsafe { guest_mem::read_u64(base, iov_addr + i * 16 + 8) };
                let mut tmp = [0u8; 4096];
                let to_write = (len as usize).min(tmp.len());
                unsafe {
                    guest_mem::read_bytes(base, iov_base, &mut tmp[..to_write]);
                }
                if let Ok(s) = core::str::from_utf8(&tmp[..to_write]) {
                    eprint!("{s}");
                } else {
                    eprintln!("guest-fd{} {:?}", fd, &tmp[..to_write]);
                }
            }
            let len = unsafe { guest_mem::read_u64(base, iov_addr + i * 16 + 8) };
            total += len;
        }
        return trace_write_attempt(
            fd,
            SYS_WRITEV,
            iov_addr,
            iovcnt,
            total as i64,
            ofd_id,
            ofd.fd_type,
            ofd.ino,
            ofd.status_flags,
            0,
            0,
            None,
        );
    }

    let mut total = 0i64;
    for i in 0..iovcnt {
        let iov_base = unsafe { guest_mem::read_u64(base, iov_addr + i * IOVEC_SIZE) };
        let iov_len = unsafe { guest_mem::read_u64(base, iov_addr + i * IOVEC_SIZE + 8) };
        if iov_len == 0 {
            continue;
        }

        if ofd.fd_type == FD_TYPE_PTY_SLAVE || ofd.fd_type == FD_TYPE_PTY_MASTER {
            let access_mode = ofd.status_flags & fd_table::OPEN_ACCESS_MODE_MASK;
            if access_mode == O_RDONLY {
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    EBADF,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
            let mut tmp = [0u8; 4096];
            let to_write = (iov_len as usize).min(tmp.len());
            unsafe {
                guest_mem::read_bytes(base, iov_base, &mut tmp[..to_write]);
            }
            let n = if ofd.fd_type == FD_TYPE_PTY_SLAVE {
                crate::syscall::pty::slave_write(ofd.ino, &tmp[..to_write])
            } else {
                crate::syscall::pty::master_write_from_thread(ofd.ino, &tmp[..to_write], vm, base)
            };
            if n == EPIPE {
                signal::send_signal(vm, SIGPIPE);
                if total == 0 {
                    return trace_write_attempt(
                        fd,
                        SYS_WRITEV,
                        iov_addr,
                        iovcnt,
                        EPIPE,
                        ofd_id,
                        ofd.fd_type,
                        ofd.ino,
                        ofd.status_flags,
                        0,
                        0,
                        None,
                    );
                }
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    total,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
            if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
                fd_table::pin_blocked_fd(base, vm, fd);
                vm.status = STATUS_PIPE_WAIT;
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    if total > 0 { total } else { 0 },
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
            if n < 0 {
                if total > 0 {
                    return trace_write_attempt(
                        fd,
                        SYS_WRITEV,
                        iov_addr,
                        iovcnt,
                        total,
                        ofd_id,
                        ofd.fd_type,
                        ofd.ino,
                        ofd.status_flags,
                        0,
                        0,
                        None,
                    );
                }
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    n,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
            if n > 0 {
                mark_pipe_sync_effect(vm, ofd.ino, true);
            }
            total += n;
            if (n as usize) < to_write {
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    total,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
        } else if ofd.fd_type == FD_TYPE_PIPE {
            if !fd_table::is_pipe_write(&ofd) {
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    EBADF,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    pipe_read_open,
                    pipe_write_open,
                    None,
                );
            }
            let mut tmp = [0u8; pipe::PIPE_BUF_SIZE];
            let to_write = (iov_len as usize).min(tmp.len());
            unsafe {
                guest_mem::read_bytes(base, iov_base, &mut tmp[..to_write]);
            }
            let n = pipe::pipe_write(ofd.ino, &tmp[..to_write]);
            if n == EPIPE {
                signal::send_signal(vm, SIGPIPE);
                if total == 0 {
                    return trace_write_attempt(
                        fd,
                        SYS_WRITEV,
                        iov_addr,
                        iovcnt,
                        EPIPE,
                        ofd_id,
                        ofd.fd_type,
                        ofd.ino,
                        ofd.status_flags,
                        pipe_read_open,
                        pipe_write_open,
                        None,
                    );
                }
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    total,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    pipe_read_open,
                    pipe_write_open,
                    None,
                );
            }
            if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
                fd_table::pin_blocked_fd(base, vm, fd);
                vm.status = STATUS_PIPE_WAIT;
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    if total > 0 { total } else { 0 },
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    pipe_read_open,
                    pipe_write_open,
                    None,
                );
            }
            if n < 0 {
                if total > 0 {
                    return trace_write_attempt(
                        fd,
                        SYS_WRITEV,
                        iov_addr,
                        iovcnt,
                        total,
                        ofd_id,
                        ofd.fd_type,
                        ofd.ino,
                        ofd.status_flags,
                        pipe_read_open,
                        pipe_write_open,
                        None,
                    );
                }
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    n,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    pipe_read_open,
                    pipe_write_open,
                    None,
                );
            }
            if n > 0 {
                mark_pipe_sync_effect(vm, ofd.ino, true);
            }
            total += n;
            if (n as usize) < to_write {
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    total,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    pipe_read_open,
                    pipe_write_open,
                    None,
                );
            }
        } else if ofd.fd_type == FD_TYPE_SOCKET {
            let n = socket::socket_write(vm, base, fd, iov_base, iov_len);
            if n == EPIPE {
                signal::send_signal(vm, SIGPIPE);
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    if total > 0 { total } else { EPIPE },
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
            if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
                fd_table::pin_blocked_fd(base, vm, fd);
                vm.socket_timeout_ms = socket::socket_send_timeout_ms_for_fd(base, vm, fd);
                vm.status = STATUS_SOCKET_SEND;
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    if total > 0 { total } else { 0 },
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
            if n < 0 {
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    if total > 0 { total } else { n },
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
            total += n;
            if (n as u64) < iov_len {
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    total,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
        } else {
            if ofd.fd_type == FD_TYPE_FILE && !file_open_for_write(&ofd) {
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    EBADF,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
            let current_offset = regular_file_write_offset(&ofd, ofd_id);
            let n = write_regular_file_from_guest(base, iov_base, iov_len, ofd.ino, current_offset);
            if n > 0 {
                let next_offset = current_offset.saturating_add(n as u64);
                fd_table::set_offset_by_id(
                    ofd_id,
                    next_offset.max(fd_table::get_offset_by_id(ofd_id)),
                );
                mark_fork_shared_ofd_sync_effect(vm);
                mark_process_memfs_sync_effect(vm);
            }
            if n < 0 {
                if total > 0 {
                    return trace_write_attempt(
                        fd,
                        SYS_WRITEV,
                        iov_addr,
                        iovcnt,
                        total,
                        ofd_id,
                        ofd.fd_type,
                        ofd.ino,
                        ofd.status_flags,
                        0,
                        0,
                        None,
                    );
                }
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    n,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
            total += n;
        }
    }
    trace_write_attempt(
        fd,
        SYS_WRITEV,
        iov_addr,
        iovcnt,
        total,
        ofd_id,
        ofd.fd_type,
        ofd.ino,
        ofd.status_flags,
        0,
        0,
        None,
    )
}
