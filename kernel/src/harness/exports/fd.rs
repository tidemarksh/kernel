#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_len() -> u32 {
    crate::harness::debug::fd_syscall_trace_len()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_vm_ptr(index: u32) -> u32 {
    crate::harness::debug::fd_syscall_trace_entry(index).vm_ptr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_nr(index: u32) -> u64 {
    crate::harness::debug::fd_syscall_trace_entry(index).nr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_arg0(index: u32) -> u64 {
    crate::harness::debug::fd_syscall_trace_entry(index).arg0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_arg0_ofd_id(index: u32) -> u32 {
    crate::harness::debug::fd_syscall_trace_entry(index).arg0_ofd_id
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_arg0_ofd_type(index: u32) -> i32 {
    crate::harness::debug::fd_syscall_trace_entry(index).arg0_ofd_type
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_arg1(index: u32) -> u64 {
    crate::harness::debug::fd_syscall_trace_entry(index).arg1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_arg2(index: u32) -> u64 {
    crate::harness::debug::fd_syscall_trace_entry(index).arg2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_arg2_ofd_id(index: u32) -> u32 {
    crate::harness::debug::fd_syscall_trace_entry(index).arg2_ofd_id
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_arg2_ofd_type(index: u32) -> i32 {
    crate::harness::debug::fd_syscall_trace_entry(index).arg2_ofd_type
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_arg3(index: u32) -> u64 {
    crate::harness::debug::fd_syscall_trace_entry(index).arg3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_result(index: u32) -> i64 {
    crate::harness::debug::fd_syscall_trace_entry(index).result
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_status(index: u32) -> i32 {
    crate::harness::debug::fd_syscall_trace_entry(index).status
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_pid_sample0(index: u32) -> u64 {
    crate::harness::debug::fd_syscall_trace_entry(index).pid_sample0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_pid_sample1(index: u32) -> u64 {
    crate::harness::debug::fd_syscall_trace_entry(index).pid_sample1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_path_syscall_trace_len() -> u32 {
    crate::harness::debug::path_syscall_trace_len()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_path_syscall_trace_vm_ptr(index: u32) -> u32 {
    crate::harness::debug::path_syscall_trace_entry(index).vm_ptr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_path_syscall_trace_nr(index: u32) -> u64 {
    crate::harness::debug::path_syscall_trace_entry(index).nr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_path_syscall_trace_dirfd(index: u32) -> i64 {
    crate::harness::debug::path_syscall_trace_entry(index).dirfd
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_path_syscall_trace_result(index: u32) -> i64 {
    crate::harness::debug::path_syscall_trace_entry(index).result
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_path_syscall_trace_status(index: u32) -> i32 {
    crate::harness::debug::path_syscall_trace_entry(index).status
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_path_syscall_trace_path_ptr(index: u32) -> u32 {
    crate::harness::debug::path_syscall_trace_path_ptr(index)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_path_syscall_trace_path_len(index: u32) -> u32 {
    crate::harness::debug::path_syscall_trace_entry(index).path_len
}
