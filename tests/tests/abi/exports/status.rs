use super::support::*;

#[test]
fn status_codes_are_distinct() {
    let codes = [
        STATUS_OK,
        STATUS_FAULT,
        STATUS_FS,
        STATUS_FUTEX_WAIT,
        STATUS_PIPE_WAIT,
        STATUS_EPOLL_WAIT,
        STATUS_VFORK_WAIT,
        STATUS_EXECVE_SPAWN,
        STATUS_CLONE_SPAWN,
        STATUS_SLEEP,
        STATUS_JIT_READY,
        STATUS_CONNECT,
        STATUS_SOCKET_SEND,
        STATUS_SOCKET_RECV,
        STATUS_WAIT4,
        STATUS_FLOCK_WAIT,
    ];
    for i in 0..codes.len() {
        for j in (i + 1)..codes.len() {
            assert_ne!(codes[i], codes[j]);
        }
    }
}
