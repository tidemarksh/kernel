pub(super) const WAKE_SOURCE_PIPE_SYNC: u32 = 1;
pub(super) const WAKE_SOURCE_EPOLL_SYNC: u32 = 2;
pub(super) const WAKE_SOURCE_SOCKET_SYNC: u32 = 3;
pub(super) const WAKE_SOURCE_PIPE_AND_EPOLL_SYNC: u32 = 4;

pub(super) const WAKE_TARGET_PIPE_WAIT: u32 = 1;
pub(super) const WAKE_TARGET_EPOLL_WAIT: u32 = 1 << 1;
pub(super) const WAKE_TARGET_SOCKET_RECV: u32 = 1 << 2;
pub(super) const WAKE_TARGET_SOCKET_SEND: u32 = 1 << 3;

pub(super) fn wake_source_pipe_sync() -> u32 {
    WAKE_SOURCE_PIPE_SYNC
}

pub(super) fn wake_source_epoll_sync() -> u32 {
    WAKE_SOURCE_EPOLL_SYNC
}

pub(super) fn wake_source_socket_sync() -> u32 {
    WAKE_SOURCE_SOCKET_SYNC
}

pub(super) fn wake_source_pipe_and_epoll_sync() -> u32 {
    WAKE_SOURCE_PIPE_AND_EPOLL_SYNC
}

pub(super) fn wake_target_pipe_wait() -> u32 {
    WAKE_TARGET_PIPE_WAIT
}

pub(super) fn wake_target_epoll_wait() -> u32 {
    WAKE_TARGET_EPOLL_WAIT
}

pub(super) fn wake_target_socket_recv() -> u32 {
    WAKE_TARGET_SOCKET_RECV
}

pub(super) fn wake_target_socket_send() -> u32 {
    WAKE_TARGET_SOCKET_SEND
}

pub(super) fn wake_mask_for_sync(source: u32) -> i32 {
    match source {
        WAKE_SOURCE_PIPE_SYNC => WAKE_TARGET_PIPE_WAIT as i32,
        WAKE_SOURCE_EPOLL_SYNC => WAKE_TARGET_EPOLL_WAIT as i32,
        WAKE_SOURCE_SOCKET_SYNC => {
            (WAKE_TARGET_PIPE_WAIT
                | WAKE_TARGET_EPOLL_WAIT
                | WAKE_TARGET_SOCKET_RECV
                | WAKE_TARGET_SOCKET_SEND) as i32
        }
        WAKE_SOURCE_PIPE_AND_EPOLL_SYNC => (WAKE_TARGET_PIPE_WAIT | WAKE_TARGET_EPOLL_WAIT) as i32,
        _ => -(crate::abi::EINVAL as i32),
    }
}
