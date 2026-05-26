use crate::abi::*;

pub fn is_nonseekable_fd_type(fd_type: i32) -> bool {
    matches!(
        fd_type,
        FD_TYPE_STDOUT
            | FD_TYPE_STDERR
            | FD_TYPE_PIPE
            | FD_TYPE_EPOLL
            | FD_TYPE_SOCKET
            | FD_TYPE_EVENTFD
            | FD_TYPE_TIMERFD
            | FD_TYPE_PTY_MASTER
            | FD_TYPE_PTY_SLAVE
            | FD_TYPE_INOTIFY
            | FD_TYPE_SIGNALFD
    )
}
