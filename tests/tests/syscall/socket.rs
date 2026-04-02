use tidemark_kernel::abi::*;
use tidemark_kernel::fs::fd_table;
use tidemark_kernel::harness::TestVm;
use tidemark_kernel::syscall::socket;

const SOL_SOCKET: u64 = 1;
const SO_REUSEADDR: u64 = 2;
const SO_TYPE: u64 = 3;
const SO_SNDBUF: u64 = 7;
const SO_KEEPALIVE: u64 = 9;
const SO_ACCEPTCONN: u64 = 30;
const IPPROTO_TCP: u64 = 6;
const TCP_NODELAY: u64 = 1;

#[test]
fn socket_create_close_and_errors() {
    let mut t = TestVm::new();

    let bad = socket::sys_socket(&mut t.vm, t.base, 16, SOCK_STREAM as u64, 0);
    assert_eq!(bad, EAFNOSUPPORT);

    let fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert!(fd >= 3, "socket fd should be >= 3, got {}", fd);

    let ofd = fd_table::get_ofd(t.base, &t.vm, fd as u64).unwrap();
    assert_eq!(ofd.fd_type, FD_TYPE_SOCKET);

    assert_eq!(t.sys_close(fd), 0);
    assert!(fd_table::get_ofd(t.base, &t.vm, fd as u64).is_none());
}

#[test]
fn socket_bind_and_getsockname() {
    let mut t = TestVm::new();
    let fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert!(fd >= 0);

    let addr_buf = t.scratch + 0x300;
    let addrlen_ptr = t.scratch + 0x380;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, addrlen_ptr, 16);
    }
    let ret = socket::sys_getsockname(&mut t.vm, t.base, fd as u64, addr_buf, addrlen_ptr);
    assert_eq!(ret, 0);
    let family = unsafe { tidemark_kernel::guest_mem::read_u16(t.base, addr_buf) };
    assert_eq!(family, AF_INET as u16);
    let actual_len = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, addrlen_ptr) };
    assert_eq!(actual_len, 2);

    let sockaddr: [u8; 16] = [2, 0, 0x50, 0x00, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    let bind_addr = t.scratch + 0x100;
    t.write_mem(bind_addr, &sockaddr);
    assert_eq!(socket::sys_bind(&mut t.vm, t.base, fd as u64, bind_addr, 16), 0);

    let out_addr = t.scratch + 0x400;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, addrlen_ptr, 16);
    }
    let ret2 = socket::sys_getsockname(&mut t.vm, t.base, fd as u64, out_addr, addrlen_ptr);
    assert_eq!(ret2, 0);
    let bound_len = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, addrlen_ptr) };
    assert_eq!(bound_len, 16);
    let returned = t.guest_mem(out_addr, 16);
    assert_eq!(&returned, &sockaddr);
}

#[test]
fn socket_sockopt_roundtrip_and_enotsock() {
    let mut t = TestVm::new();
    let fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert!(fd >= 0);

    let val_addr = t.scratch + 0x200;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, val_addr, 1);
    }
    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_REUSEADDR as u64,
            val_addr,
            4,
        ),
        0
    );
    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            IPPROTO_TCP as u64,
            TCP_NODELAY as u64,
            val_addr,
            4,
        ),
        0
    );

    let out_addr = t.scratch + 0x240;
    let out_len = t.scratch + 0x248;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, out_len, 4);
    }
    assert_eq!(
        socket::sys_getsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_REUSEADDR as u64,
            out_addr,
            out_len,
        ),
        0
    );
    assert_eq!(unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr) }, 1);

    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, out_len, 4);
    }
    assert_eq!(
        socket::sys_getsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_TYPE as u64,
            out_addr,
            out_len,
        ),
        0
    );
    assert_eq!(unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr) }, SOCK_STREAM);

    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            1,
            SOL_SOCKET as u64,
            SO_REUSEADDR as u64,
            val_addr,
            4,
        ),
        ENOTSOCK
    );
}

#[test]
fn socket_sockopt_validation_and_acceptconn() {
    let mut t = TestVm::new();
    let fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert!(fd >= 0);

    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_KEEPALIVE as u64,
            t.scratch + 0x300,
            1,
        ),
        EINVAL
    );

    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, t.scratch + 0x304, 0);
    }
    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_SNDBUF as u64,
            t.scratch + 0x304,
            4,
        ),
        EINVAL
    );

    let sockaddr: [u8; 16] = [2, 0, 0x50, 0x00, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    let bind_addr = t.scratch + 0x340;
    t.write_mem(bind_addr, &sockaddr);
    assert_eq!(socket::sys_bind(&mut t.vm, t.base, fd as u64, bind_addr, 16), 0);
    assert_eq!(socket::sys_listen(&mut t.vm, t.base, fd as u64, 8), 0);

    let out_addr = t.scratch + 0x380;
    let out_len = t.scratch + 0x388;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, out_len, 4);
    }
    assert_eq!(
        socket::sys_getsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_ACCEPTCONN as u64,
            out_addr,
            out_len,
        ),
        0
    );
    assert_eq!(unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr) }, 1);
}

#[test]
fn socket_connect_and_getpeername() {
    let mut t = TestVm::new();
    let fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert!(fd >= 0);

    let out_addr = t.scratch + 0x600;
    let addrlen_ptr = t.scratch + 0x680;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, addrlen_ptr, 16);
    }
    assert_eq!(
        socket::sys_getpeername(&mut t.vm, t.base, fd as u64, out_addr, addrlen_ptr),
        ENOTCONN
    );

    let sockaddr: [u8; 16] = [2, 0, 0x00, 0x50, 93, 184, 216, 34, 0, 0, 0, 0, 0, 0, 0, 0];
    let addr = t.scratch + 0x500;
    t.write_mem(addr, &sockaddr);
    t.vm.x[10] = fd as u64;
    assert_eq!(socket::sys_connect(&mut t.vm, t.base, fd as u64, addr, 16), 0);
    assert_eq!(t.vm.status, STATUS_CONNECT);

    socket::resume_connect_result(&mut t.vm, t.base, ECONNREFUSED);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.x[10] as i64, ECONNREFUSED);
}

#[test]
fn socket_slot_exhaustion_and_reuse() {
    let mut t = TestVm::new();
    let mut fds = [0i64; MAX_SOCKETS];
    for (i, slot) in fds.iter_mut().enumerate() {
        *slot = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
        assert!(*slot >= 0, "socket {} failed: {}", i, *slot);
    }

    let extra = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert_eq!(extra, ENOMEM);

    assert_eq!(t.sys_close(fds[0]), 0);
    let new_fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert!(new_fd >= 0);
}
