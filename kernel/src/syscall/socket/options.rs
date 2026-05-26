use super::{IPPROTO_TCP, SOCK_STATE_LISTENING, get_socket_idx, socket_table};
use crate::abi::*;
use crate::guest_mem;
use crate::types::ThreadState;

const SOL_SOCKET: u32 = 1;
const SO_REUSEADDR: u32 = 2;
const SO_TYPE: u32 = 3;
const SO_ERROR: u32 = 4;
const SO_BROADCAST: u32 = 6;
const SO_SNDBUF: u32 = 7;
const SO_RCVBUF: u32 = 8;
const SO_SNDBUFFORCE: u32 = 32;
const SO_RCVBUFFORCE: u32 = 33;
const SO_KEEPALIVE: u32 = 9;
const SO_OOBINLINE: u32 = 10;
const SO_NO_CHECK: u32 = 11;
const SO_BSDCOMPAT: u32 = 14;
const SO_REUSEPORT: u32 = 15;
const SO_RCVLOWAT: u32 = 18;
const SO_SNDLOWAT: u32 = 19;
const SO_RCVTIMEO_OLD: u32 = 20;
const SO_SNDTIMEO_OLD: u32 = 21;
const SO_ACCEPTCONN: u32 = 30;
const SO_PROTOCOL: u32 = 38;
const SO_DOMAIN: u32 = 39;
const SO_INCOMING_CPU: u32 = 49;
const SO_COOKIE: u32 = 57;
const SO_RCVTIMEO_NEW: u32 = 66;
const SO_SNDTIMEO_NEW: u32 = 67;
const TCP_NODELAY: u32 = 1;

fn read_opt_i32(base: u32, optval: u64, optlen: u64) -> Result<i32, i64> {
    if optval == 0 || optlen < 4 {
        return Err(EINVAL);
    }
    Ok(unsafe { guest_mem::read_i32(base, optval) })
}

fn read_opt_timeval(base: u32, optval: u64, optlen: u64) -> Result<(u64, u64), i64> {
    if optval == 0 || optlen < 16 {
        return Err(EINVAL);
    }
    let sec = unsafe { guest_mem::read_i64(base, optval) };
    let usec = unsafe { guest_mem::read_i64(base, optval + 8) };
    if sec < 0 || !(0..1_000_000).contains(&usec) {
        return Err(EINVAL);
    }
    Ok((sec as u64, usec as u64))
}

fn write_opt_u32(base: u32, optval: u64, optlen_ptr: u64, value: u32) -> i64 {
    if optval == 0 || optlen_ptr == 0 {
        return EFAULT;
    }

    let user_len = unsafe { guest_mem::read_u32(base, optlen_ptr) } as usize;
    let bytes = value.to_le_bytes();
    let copy_len = user_len.min(bytes.len());
    unsafe {
        guest_mem::write_bytes(base, optval, &bytes[..copy_len]);
        guest_mem::write_u32(base, optlen_ptr, bytes.len() as u32);
    }
    0
}

fn write_opt_bytes(base: u32, optval: u64, optlen_ptr: u64, bytes: &[u8]) -> i64 {
    if optval == 0 || optlen_ptr == 0 {
        return EFAULT;
    }

    let user_len = unsafe { guest_mem::read_u32(base, optlen_ptr) } as usize;
    let copy_len = user_len.min(bytes.len());
    unsafe {
        guest_mem::write_bytes(base, optval, &bytes[..copy_len]);
        guest_mem::write_u32(base, optlen_ptr, bytes.len() as u32);
    }
    0
}

fn write_opt_timeval(base: u32, optval: u64, optlen_ptr: u64, sec: u64, usec: u64) -> i64 {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&(sec as i64).to_le_bytes());
    bytes[8..].copy_from_slice(&(usec as i64).to_le_bytes());
    write_opt_bytes(base, optval, optlen_ptr, &bytes)
}

/// setsockopt(fd, level, optname, optval, optlen)
pub fn sys_setsockopt(
    vm: &mut ThreadState,
    base: u32,
    fd: u64,
    level: u64,
    optname: u64,
    optval: u64,
    optlen: u64,
) -> i64 {
    let idx = match get_socket_idx(base, vm, fd) {
        Some(idx) => idx as usize,
        None => return ENOTSOCK,
    };
    let slot = &mut socket_table()[idx];

    match (level as u32, optname as u32) {
        (SOL_SOCKET, SO_REUSEADDR) => match read_opt_i32(base, optval, optlen) {
            Ok(value) => {
                slot.so_reuseaddr = u32::from(value != 0);
                0
            }
            Err(err) => err,
        },
        (SOL_SOCKET, SO_REUSEPORT) => match read_opt_i32(base, optval, optlen) {
            Ok(value) => {
                slot.so_reuseport = u32::from(value != 0);
                0
            }
            Err(err) => err,
        },
        (SOL_SOCKET, SO_KEEPALIVE) => match read_opt_i32(base, optval, optlen) {
            Ok(value) => {
                slot.so_keepalive = u32::from(value != 0);
                0
            }
            Err(err) => err,
        },
        (SOL_SOCKET, SO_OOBINLINE) => match read_opt_i32(base, optval, optlen) {
            Ok(value) => {
                slot.so_oobinline = u32::from(value != 0);
                0
            }
            Err(err) => err,
        },
        (SOL_SOCKET, SO_NO_CHECK) => match read_opt_i32(base, optval, optlen) {
            Ok(value) => {
                slot.so_nocheck = u32::from(value != 0);
                0
            }
            Err(err) => err,
        },
        (SOL_SOCKET, SO_BSDCOMPAT) => match read_opt_i32(base, optval, optlen) {
            Ok(value) => {
                slot.so_bsdcompat = u32::from(value != 0);
                0
            }
            Err(err) => err,
        },
        (SOL_SOCKET, SO_BROADCAST) => match read_opt_i32(base, optval, optlen) {
            Ok(value) => {
                slot.so_broadcast = u32::from(value != 0);
                0
            }
            Err(err) => err,
        },
        (SOL_SOCKET, SO_RCVLOWAT) => match read_opt_i32(base, optval, optlen) {
            Ok(value) if value > 0 => {
                slot.so_rcvlowat = value as u32;
                0
            }
            Ok(_) => EINVAL,
            Err(err) => err,
        },
        (SOL_SOCKET, SO_SNDLOWAT) => ENOPROTOOPT,
        (SOL_SOCKET, SO_RCVTIMEO_OLD | SO_RCVTIMEO_NEW) => {
            match read_opt_timeval(base, optval, optlen) {
                Ok((sec, usec)) => {
                    slot.so_rcvtimeo_sec = sec;
                    slot.so_rcvtimeo_usec = usec;
                    0
                }
                Err(err) => err,
            }
        }
        (SOL_SOCKET, SO_SNDTIMEO_OLD | SO_SNDTIMEO_NEW) => {
            match read_opt_timeval(base, optval, optlen) {
                Ok((sec, usec)) => {
                    slot.so_sndtimeo_sec = sec;
                    slot.so_sndtimeo_usec = usec;
                    0
                }
                Err(err) => err,
            }
        }
        (SOL_SOCKET, SO_SNDBUF | SO_SNDBUFFORCE) => match read_opt_i32(base, optval, optlen) {
            Ok(value) if value > 0 => {
                slot.so_sndbuf = value.max(256) as u32;
                0
            }
            Ok(_) => EINVAL,
            Err(err) => err,
        },
        (SOL_SOCKET, SO_RCVBUF | SO_RCVBUFFORCE) => match read_opt_i32(base, optval, optlen) {
            Ok(value) if value > 0 => {
                slot.so_rcvbuf = value.max(256) as u32;
                0
            }
            Ok(_) => EINVAL,
            Err(err) => err,
        },
        (IPPROTO_TCP, TCP_NODELAY) => {
            if slot.sock_type != SOCK_STREAM {
                return ENOPROTOOPT;
            }
            match read_opt_i32(base, optval, optlen) {
                Ok(value) => {
                    slot.tcp_nodelay = u32::from(value != 0);
                    0
                }
                Err(err) => err,
            }
        }
        (SOL_SOCKET, SO_TYPE | SO_ERROR | SO_ACCEPTCONN | SO_PROTOCOL | SO_DOMAIN) => ENOPROTOOPT,
        _ => ENOPROTOOPT,
    }
}

/// getsockopt(fd, level, optname, optval, optlen)
pub fn sys_getsockopt(
    vm: &mut ThreadState,
    base: u32,
    fd: u64,
    level: u64,
    optname: u64,
    optval: u64,
    optlen: u64,
) -> i64 {
    let idx = match get_socket_idx(base, vm, fd) {
        Some(idx) => idx as usize,
        None => return ENOTSOCK,
    };
    let slot = &mut socket_table()[idx];

    match (level as u32, optname as u32) {
        (SOL_SOCKET, SO_TYPE) => write_opt_u32(base, optval, optlen, slot.sock_type),
        (SOL_SOCKET, SO_ERROR) => {
            let error = slot.last_error as u32;
            slot.last_error = 0;
            write_opt_u32(base, optval, optlen, error)
        }
        (SOL_SOCKET, SO_REUSEADDR) => write_opt_u32(base, optval, optlen, slot.so_reuseaddr),
        (SOL_SOCKET, SO_REUSEPORT) => write_opt_u32(base, optval, optlen, slot.so_reuseport),
        (SOL_SOCKET, SO_KEEPALIVE) => write_opt_u32(base, optval, optlen, slot.so_keepalive),
        (SOL_SOCKET, SO_OOBINLINE) => write_opt_u32(base, optval, optlen, slot.so_oobinline),
        (SOL_SOCKET, SO_NO_CHECK) => write_opt_u32(base, optval, optlen, slot.so_nocheck),
        (SOL_SOCKET, SO_BSDCOMPAT) => write_opt_u32(base, optval, optlen, slot.so_bsdcompat),
        (SOL_SOCKET, SO_BROADCAST) => write_opt_u32(base, optval, optlen, slot.so_broadcast),
        (SOL_SOCKET, SO_SNDBUF) => write_opt_u32(base, optval, optlen, slot.so_sndbuf),
        (SOL_SOCKET, SO_RCVBUF) => write_opt_u32(base, optval, optlen, slot.so_rcvbuf),
        (SOL_SOCKET, SO_INCOMING_CPU) => write_opt_u32(base, optval, optlen, 0),
        (SOL_SOCKET, SO_COOKIE) => {
            write_opt_bytes(base, optval, optlen, &slot.so_cookie.to_le_bytes())
        }
        (SOL_SOCKET, SO_RCVLOWAT) => write_opt_u32(base, optval, optlen, slot.so_rcvlowat),
        (SOL_SOCKET, SO_SNDLOWAT) => write_opt_u32(base, optval, optlen, 1),
        (SOL_SOCKET, SO_RCVTIMEO_OLD | SO_RCVTIMEO_NEW) => write_opt_timeval(
            base,
            optval,
            optlen,
            slot.so_rcvtimeo_sec,
            slot.so_rcvtimeo_usec,
        ),
        (SOL_SOCKET, SO_SNDTIMEO_OLD | SO_SNDTIMEO_NEW) => write_opt_timeval(
            base,
            optval,
            optlen,
            slot.so_sndtimeo_sec,
            slot.so_sndtimeo_usec,
        ),
        (SOL_SOCKET, SO_ACCEPTCONN) => write_opt_u32(
            base,
            optval,
            optlen,
            u32::from(slot.state == SOCK_STATE_LISTENING),
        ),
        (SOL_SOCKET, SO_PROTOCOL) => write_opt_u32(base, optval, optlen, slot.protocol),
        (SOL_SOCKET, SO_DOMAIN) => write_opt_u32(base, optval, optlen, slot.domain),
        (IPPROTO_TCP, TCP_NODELAY) => {
            if slot.sock_type != SOCK_STREAM {
                return ENOPROTOOPT;
            }
            write_opt_u32(base, optval, optlen, slot.tcp_nodelay)
        }
        _ => ENOPROTOOPT,
    }
}
