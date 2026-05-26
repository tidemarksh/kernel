use crate::abi::*;
use crate::types::OpenFileDesc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendCleanup {
    Pipe {
        pipe_idx: u32,
        generation: u32,
        is_read_end: bool,
        ofd_id: u32,
    },
    Epoll {
        epoll_idx: u32,
    },
    Socket {
        socket_idx: u32,
    },
    Timerfd {
        timerfd_idx: u32,
    },
    Signalfd {
        signalfd_idx: u32,
    },
    Pty {
        pty_idx: u32,
        is_master: bool,
    },
}

pub(in crate::fs) fn for_ofd(ofd_id: u32, ofd: &OpenFileDesc) -> Option<BackendCleanup> {
    if ofd.fd_type == FD_TYPE_PIPE {
        Some(BackendCleanup::Pipe {
            pipe_idx: ofd.ino,
            generation: ofd.offset as u32,
            is_read_end: ofd.host_fd >= 0,
            ofd_id,
        })
    } else if ofd.fd_type == FD_TYPE_EPOLL {
        Some(BackendCleanup::Epoll { epoll_idx: ofd.ino })
    } else if ofd.fd_type == FD_TYPE_SOCKET {
        Some(BackendCleanup::Socket {
            socket_idx: ofd.ino,
        })
    } else if ofd.fd_type == FD_TYPE_TIMERFD {
        Some(BackendCleanup::Timerfd {
            timerfd_idx: ofd.ino,
        })
    } else if ofd.fd_type == FD_TYPE_SIGNALFD {
        Some(BackendCleanup::Signalfd {
            signalfd_idx: ofd.ino,
        })
    } else if ofd.fd_type == FD_TYPE_PTY_MASTER {
        Some(BackendCleanup::Pty {
            pty_idx: ofd.ino,
            is_master: true,
        })
    } else if ofd.fd_type == FD_TYPE_PTY_SLAVE {
        Some(BackendCleanup::Pty {
            pty_idx: ofd.ino,
            is_master: false,
        })
    } else {
        None
    }
}

pub fn run(cleanup: BackendCleanup) {
    match cleanup {
        BackendCleanup::Pipe {
            pipe_idx,
            generation,
            is_read_end,
            ofd_id,
        } => {
            if !crate::syscall::pipe::pipe_generation_matches(pipe_idx, generation) {
                return;
            }
            let outcome = crate::syscall::pipe::pipe_close_outcome(pipe_idx, is_read_end);
            crate::tracepoints::record_pipe_close_event(
                pipe_idx,
                is_read_end,
                ofd_id,
                outcome.read_open,
                outcome.write_open,
            );
        }
        BackendCleanup::Epoll { epoll_idx } => {
            crate::syscall::epoll::close_epoll(epoll_idx);
        }
        BackendCleanup::Socket { socket_idx } => {
            crate::syscall::socket::socket_close(socket_idx);
        }
        BackendCleanup::Timerfd { timerfd_idx } => {
            crate::syscall::time::close_timerfd(timerfd_idx);
        }
        BackendCleanup::Signalfd { signalfd_idx } => {
            crate::syscall::signal::close_signalfd(signalfd_idx);
        }
        BackendCleanup::Pty { pty_idx, is_master } => {
            crate::syscall::pty::pty_close(pty_idx, is_master);
        }
    }
}
