#[allow(clippy::too_many_arguments)]
pub(crate) fn record_epoll_wait(
    vm_ptr: u32,
    epfd: u64,
    ofd_id: u32,
    ofd_type: i32,
    epoll_idx: u32,
    epoll_ptr: u32,
    epoll_count: u32,
    result: i64,
    reason: u32,
) {
    let _ = (
        vm_ptr,
        epfd,
        ofd_id,
        ofd_type,
        epoll_idx,
        epoll_ptr,
        epoll_count,
        result,
        reason,
    );
}
