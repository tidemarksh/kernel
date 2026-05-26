use super::support::*;

#[test]
fn fd_types_are_distinct() {
    let types = [
        FD_TYPE_NONE,
        FD_TYPE_STDOUT,
        FD_TYPE_STDERR,
        FD_TYPE_FILE,
        FD_TYPE_DIR,
        FD_TYPE_DEVNULL,
        FD_TYPE_PIPE,
        FD_TYPE_EPOLL,
        FD_TYPE_SOCKET,
        FD_TYPE_EVENTFD,
        FD_TYPE_TIMERFD,
        FD_TYPE_PTY_MASTER,
        FD_TYPE_PTY_SLAVE,
        FD_TYPE_INOTIFY,
    ];
    for i in 0..types.len() {
        for j in (i + 1)..types.len() {
            assert_ne!(types[i], types[j]);
        }
    }
}
