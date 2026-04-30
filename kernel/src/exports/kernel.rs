#[unsafe(no_mangle)]
pub extern "C" fn kernel_pty_input_pipe(pty_idx: u32) -> u32 {
    crate::syscall::pty::input_pipe_slot(pty_idx)
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_pty_output_pipe(pty_idx: u32) -> u32 {
    crate::syscall::pty::output_pipe_slot(pty_idx)
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_init(heap_base: u32) {
    unsafe {
        crate::alloc::init(heap_base);
        crate::guest_mem::init(core::ptr::null(), core::ptr::null(), core::ptr::null());
    }
    crate::syscall::memory::init(0);
    crate::syscall::process::init();
    crate::syscall::time::init();
    crate::syscall::thread::init();
    crate::syscall::signal::init();
    crate::syscall::resource::init();
    crate::syscall::epoll::init();
    crate::syscall::pipe::init();
    crate::syscall::pty::init();
    crate::syscall::socket::init();
    crate::net::ring_buffer::init();
    crate::fs::fd_table::init();
    crate::fs::memfs::init();
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_heap_base() -> u32 {
    crate::alloc::heap_base()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_heap_ptr() -> u32 {
    crate::alloc::heap_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_ofd_table_ptr() -> u32 {
    crate::fs::fd_table::ofd_table_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_ofd_table_bytes() -> u32 {
    crate::fs::fd_table::ofd_table_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_memfs_ptr() -> u32 {
    crate::fs::memfs::memfs_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_memfs_header_bytes() -> u32 {
    crate::fs::memfs::memfs_header_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_memfs_inodes_ptr() -> u32 {
    crate::fs::memfs::memfs_inodes_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_memfs_inodes_bytes() -> u32 {
    crate::fs::memfs::memfs_inodes_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_memfs_first_child_ptr() -> u32 {
    crate::fs::memfs::memfs_first_child_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_memfs_first_child_bytes() -> u32 {
    crate::fs::memfs::memfs_first_child_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_memfs_dir_entries_ptr() -> u32 {
    crate::fs::memfs::memfs_dir_entries_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_memfs_dir_entries_bytes() -> u32 {
    crate::fs::memfs::memfs_dir_entries_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_memfs_data_ptr() -> u32 {
    crate::fs::memfs::memfs_data_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_memfs_data_bytes() -> u32 {
    crate::fs::memfs::memfs_data_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_mem_state_ptr() -> u32 {
    crate::syscall::memory::mem_state_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_epoll_table_ptr() -> u32 {
    crate::syscall::epoll::epoll_table_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_epoll_table_bytes() -> u32 {
    crate::syscall::epoll::epoll_table_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_epoll_instance_bytes() -> u32 {
    crate::syscall::epoll::epoll_instance_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_socket_table_ptr() -> u32 {
    crate::syscall::socket::socket_table_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_socket_table_bytes() -> u32 {
    crate::syscall::socket::socket_table_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_socket_used() -> u32 {
    crate::syscall::socket::socket_used()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_pipe_base() -> u32 {
    crate::syscall::pipe::pipe_state().0
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_pipe_region_bytes() -> u32 {
    crate::syscall::pipe::pipe_region_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_pipe_used() -> u64 {
    crate::syscall::pipe::pipe_state().1
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_net_buf_base() -> u32 {
    crate::net::ring_buffer::net_buffer_state().0
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_net_buf_pool_bytes() -> u32 {
    crate::net::ring_buffer::net_buffer_pool_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_net_buf_used() -> u64 {
    crate::net::ring_buffer::net_buffer_state().1
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_sig_slots_ptr() -> u32 {
    crate::syscall::signal::sig_slots_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_sig_slots_bytes() -> u32 {
    crate::syscall::signal::signal_slots_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_signal_action_table_bytes() -> u32 {
    crate::syscall::signal::signal_action_table_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_process_pending_ptr() -> u32 {
    crate::syscall::signal::process_pending_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_process_pending_bytes() -> u32 {
    crate::syscall::signal::process_pending_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_process_runtime_state_ptr() -> u32 {
    crate::syscall::process::process_runtime_state_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_process_runtime_state_bytes() -> u32 {
    crate::syscall::process::process_runtime_state_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_time_state_ptr() -> u32 {
    crate::syscall::time::time_state_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_time_state_bytes() -> u32 {
    crate::syscall::time::time_state_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_syscall_trace_len() -> u32 {
    crate::syscall::memory::debug_syscall_trace_len()
}

#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_syscall_trace_entry_nr(index: u32) -> u64 {
    crate::syscall::memory::debug_syscall_trace_entry_nr(index)
}

#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_syscall_trace_entry_arg0(index: u32) -> u64 {
    crate::syscall::memory::debug_syscall_trace_entry_arg0(index)
}

#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_syscall_trace_entry_arg1(index: u32) -> u64 {
    crate::syscall::memory::debug_syscall_trace_entry_arg1(index)
}

#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_syscall_trace_entry_arg2(index: u32) -> u64 {
    crate::syscall::memory::debug_syscall_trace_entry_arg2(index)
}

#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_syscall_trace_entry_arg3(index: u32) -> u64 {
    crate::syscall::memory::debug_syscall_trace_entry_arg3(index)
}

#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_syscall_trace_entry_arg4(index: u32) -> u64 {
    crate::syscall::memory::debug_syscall_trace_entry_arg4(index)
}

#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_syscall_trace_entry_arg5(index: u32) -> u64 {
    crate::syscall::memory::debug_syscall_trace_entry_arg5(index)
}

#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_syscall_trace_entry_result(index: u32) -> i64 {
    crate::syscall::memory::debug_syscall_trace_entry_result(index)
}

#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_syscall_trace_entry_pid(index: u32) -> i32 {
    crate::syscall::memory::debug_syscall_trace_entry_pid(index)
}

#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_syscall_trace_entry_process_ptr(index: u32) -> u32 {
    crate::syscall::memory::debug_syscall_trace_entry_process_ptr(index)
}

#[cfg(not(any(test, feature = "harness")))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_brk_base() -> u64 {
    crate::syscall::memory::address_space_brk_base()
}

#[cfg(not(any(test, feature = "harness")))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_brk_current() -> u64 {
    crate::syscall::memory::current_brk()
}

#[cfg(not(any(test, feature = "harness")))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_mmap_next() -> u64 {
    crate::syscall::memory::address_space_mmap_next()
}

#[cfg(not(any(test, feature = "harness")))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_vma_len() -> u32 {
    crate::syscall::memory::address_space_vma_len()
}

#[cfg(not(any(test, feature = "harness")))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_vma_start(index: u32) -> u64 {
    crate::syscall::memory::address_space_vma_start(index)
}

#[cfg(not(any(test, feature = "harness")))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_vma_end(index: u32) -> u64 {
    crate::syscall::memory::address_space_vma_end(index)
}

#[cfg(not(any(test, feature = "harness")))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_vma_prot(index: u32) -> i32 {
    crate::syscall::memory::address_space_vma_prot(index)
}

#[cfg(not(any(test, feature = "harness")))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_vma_flags(index: u32) -> i32 {
    crate::syscall::memory::address_space_vma_flags(index)
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_reset_memfs() {
    crate::fs::memfs::reset();
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_attach_runtime_state(
    heap_base: u32,
    heap_ptr: u32,
    ofd_table_ptr: u32,
    memfs_ptr: u32,
    mem_state_ptr: u32,
    epoll_table_ptr: u32,
    socket_table_ptr: u32,
    socket_used: u32,
    pipe_base: u32,
    pipe_used: u64,
    net_buf_base: u32,
    net_buf_used: u64,
    sig_slots_ptr: u32,
    process_pending_ptr: u32,
    process_runtime_state_ptr: u32,
    time_state_ptr: u32,
) {
    crate::alloc::attach_heap_state(heap_base, heap_ptr);
    crate::fs::fd_table::attach_ofd_table_ptr(ofd_table_ptr);
    crate::fs::memfs::attach_memfs_ptr(memfs_ptr);
    crate::syscall::memory::attach_mem_state_ptr(mem_state_ptr);
    crate::syscall::epoll::attach_epoll_table_ptr(epoll_table_ptr);
    crate::syscall::socket::attach_socket_state(socket_table_ptr, socket_used);
    crate::syscall::pipe::attach_pipe_state(pipe_base, pipe_used);
    crate::net::ring_buffer::attach_net_buffer_state(net_buf_base, net_buf_used);
    crate::syscall::signal::attach_process_signal_state(sig_slots_ptr, process_pending_ptr);
    crate::syscall::process::attach_process_runtime_state_ptr(process_runtime_state_ptr);
    crate::syscall::time::attach_time_state_ptr(time_state_ptr);
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_retain_ofd(ofd_id: u32) {
    crate::fs::fd_table::retain_ofd_id(ofd_id);
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_release_ofd(ofd_id: u32) {
    crate::fs::fd_table::release_ofd_id(ofd_id);
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_reserve_ofd(ofd_id: u32) {
    crate::fs::fd_table::reserve_ofd_id(ofd_id);
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_unreserve_ofd(ofd_id: u32) {
    crate::fs::fd_table::unreserve_ofd_id(ofd_id);
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_ofd_reserved(ofd_id: u32) -> i32 {
    if crate::fs::fd_table::is_ofd_reserved(ofd_id) {
        1
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_ofd_fd_type(ofd_id: u32) -> i32 {
    crate::fs::fd_table::get_ofd_by_id(ofd_id).map_or(0, |ofd| ofd.fd_type)
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_ofd_host_fd(ofd_id: u32) -> i32 {
    crate::fs::fd_table::get_ofd_by_id(ofd_id).map_or(-1, |ofd| ofd.host_fd)
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_ofd_status_flags(ofd_id: u32) -> i32 {
    crate::fs::fd_table::get_ofd_by_id(ofd_id).map_or(0, |ofd| ofd.status_flags)
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_ofd_ino(ofd_id: u32) -> u32 {
    crate::fs::fd_table::get_ofd_by_id(ofd_id).map_or(0, |ofd| ofd.ino)
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_ofd_refcount(ofd_id: u32) -> i32 {
    crate::fs::fd_table::get_ofd_by_id(ofd_id).map_or(0, |ofd| ofd.refcount)
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_ofd_offset(ofd_id: u32) -> i64 {
    crate::fs::fd_table::get_ofd_by_id(ofd_id).map_or(0, |ofd| ofd.offset)
}
