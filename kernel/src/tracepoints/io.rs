#[cfg(any(test, all(any(target_arch = "wasm32", target_arch = "wasm64"), feature = "harness")))]
pub(crate) use crate::harness::trace::{
    record_epoll_wait, record_fd_syscall, record_memory_syscall, record_path_syscall,
    record_pipe_close_event, record_write_attempt,
};

macro_rules! noop_tracepoint {
    ($(fn $name:ident($($arg:ident : $ty:ty),* $(,)?) $(-> $ret:ty)? $body:block)*) => {
        $(
            #[cfg(not(any(test, all(any(target_arch = "wasm32", target_arch = "wasm64"), feature = "harness"))))]
            #[inline(always)]
            pub(crate) fn $name($($arg: $ty),*) $(-> $ret)? {
                let _ = ($($arg),*);
                $body
            }
        )*
    };
}

noop_tracepoint! {
    fn record_epoll_wait(
        vm_ptr: u32,
        epfd: u64,
        ofd_id: u32,
        ofd_type: i32,
        epoll_idx: u32,
        epoll_ptr: u32,
        epoll_count: u32,
        result: i64,
        reason: u32,
    ) {}
    fn record_fd_syscall(
        vm_ptr: u32,
        nr: u64,
        arg0: u64,
        arg0_ofd_id: u32,
        arg0_ofd_type: i32,
        arg1: u64,
        arg2: u64,
        arg2_ofd_id: u32,
        arg2_ofd_type: i32,
        arg3: u64,
        result: i64,
        status: i32,
    ) {}
    fn record_memory_syscall(nr: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64, result: i64) {}
    fn record_path_syscall(vm_ptr: u32, nr: u64, dirfd: i64, path: &[u8], result: i64, status: i32) {}
    fn record_pipe_close_event(
        pipe_idx: u32,
        is_read_end: bool,
        ofd_id: u32,
        read_open: i32,
        write_open: i32,
    ) {}
    fn record_write_attempt(
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
    ) {}
}
