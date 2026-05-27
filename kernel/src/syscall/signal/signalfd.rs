use super::{
    pending::SI_USER, pending::peek_thread_pending_signals, pending::pid_from_vm,
    pending::process_pending, pending::take_thread_pending_signals, sanitized_signal_mask,
};
use crate::abi::*;
use crate::guest_mem;
use crate::types::ThreadState;

#[derive(Clone, Copy)]
struct SignalFdState {
    used: u32,
    _pad: u32,
    mask: u64,
}

const EMPTY_SIGNALFD_STATE: SignalFdState = SignalFdState {
    used: 0,
    _pad: 0,
    mask: 0,
};

static mut SIGNALFD_PTR: *mut [SignalFdState; MAX_SIGNALFDS + 1] = core::ptr::null_mut();

#[inline(always)]
fn signalfd_slots() -> &'static mut [SignalFdState; MAX_SIGNALFDS + 1] {
    unsafe {
        let p = core::ptr::read(core::ptr::addr_of!(SIGNALFD_PTR));
        &mut *p
    }
}

pub(super) fn init() {
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(SIGNALFD_PTR), core::ptr::null_mut());

        let signalfd_size = core::mem::size_of::<[SignalFdState; MAX_SIGNALFDS + 1]>() as u32;
        let signalfd_align = core::mem::align_of::<SignalFdState>() as u32;
        let signalfd_ptr = crate::alloc::alloc_zeroed(signalfd_size, signalfd_align);
        if signalfd_ptr == 0 {
            core::arch::wasm32::unreachable();
        }
        core::ptr::write(
            core::ptr::addr_of_mut!(SIGNALFD_PTR),
            signalfd_ptr as *mut [SignalFdState; MAX_SIGNALFDS + 1],
        );
    }
}

fn signalfd_slot(idx: u32) -> Option<&'static mut SignalFdState> {
    if idx == 0 || idx as usize > MAX_SIGNALFDS {
        return None;
    }
    Some(&mut signalfd_slots()[idx as usize])
}

fn signalfd_mask_sanitized(mask: u64) -> u64 {
    sanitized_signal_mask(mask)
}

fn alloc_signalfd_slot(mask: u64) -> Option<u32> {
    let slots = signalfd_slots();
    for idx in 1..=MAX_SIGNALFDS {
        if slots[idx].used == 0 {
            slots[idx] = SignalFdState {
                used: 1,
                _pad: 0,
                mask: signalfd_mask_sanitized(mask),
            };
            return Some(idx as u32);
        }
    }
    None
}

pub fn close_signalfd(signalfd_idx: u32) {
    if let Some(slot) = signalfd_slot(signalfd_idx) {
        *slot = EMPTY_SIGNALFD_STATE;
    }
}

fn signalfd_pending_mask(vm: &ThreadState, base: u32, mask: u64) -> u64 {
    let pid = pid_from_vm(vm, base);
    let mut pending = vm.sig_pending | peek_thread_pending_signals(vm, base);
    if pid > 0 {
        let idx = (pid - 1) as usize;
        if idx < MAX_PROCESSES {
            pending |= process_pending()[idx];
        }
    }
    pending & signalfd_mask_sanitized(mask)
}

fn consume_signalfd_signal(vm: &mut ThreadState, base: u32, mask: u64) -> Option<(usize, i32)> {
    take_thread_pending_signals(vm, base);

    let matched = signalfd_pending_mask(vm, base, mask);
    if matched == 0 {
        return None;
    }

    let sig = matched.trailing_zeros() as usize + 1;
    let bit = 1u64 << (sig - 1);
    if (vm.sig_pending & bit) != 0 {
        vm.sig_pending &= !bit;
        let code = if vm.sig_info_code != 0 {
            vm.sig_info_code
        } else {
            SI_USER
        };
        vm.sig_info_code = 0;
        return Some((sig, code));
    }

    let pid = pid_from_vm(vm, base);
    if pid > 0 {
        let idx = (pid - 1) as usize;
        if idx < MAX_PROCESSES && (process_pending()[idx] & bit) != 0 {
            process_pending()[idx] &= !bit;
            return Some((sig, SI_USER));
        }
    }

    None
}

fn write_signalfd_siginfo(vm: &ThreadState, base: u32, buf: u64, sig: usize, code: i32, pid: i32) {
    unsafe {
        guest_mem::zero_mem(base, buf, 128);
        guest_mem::write_u32(base, buf, sig as u32);
        guest_mem::write_u32(base, buf + 4, 0);
        guest_mem::write_u32(base, buf + 8, code as u32);
        guest_mem::write_u32(base, buf + 12, pid as u32);
        guest_mem::write_u32(base, buf + 16, vm.uid as u32);
        guest_mem::write_u32(base, buf + 24, vm.tid as u32);
    }
}

pub fn signalfd_is_readable(vm: &ThreadState, base: u32, signalfd_idx: u32) -> bool {
    let Some(slot) = signalfd_slot(signalfd_idx) else {
        return false;
    };
    slot.used != 0 && signalfd_pending_mask(vm, base, slot.mask) != 0
}

pub fn signalfd_read(
    vm: &mut ThreadState,
    base: u32,
    buf: u64,
    count: u64,
    signalfd_idx: u32,
) -> i64 {
    if count < 128 {
        return EINVAL;
    }
    if !crate::syscall::memory::guest_range_accessible(base, buf, 128) {
        return EFAULT;
    }
    let Some(slot) = signalfd_slot(signalfd_idx) else {
        return EINVAL;
    };
    let Some((sig, code)) = consume_signalfd_signal(vm, base, slot.mask) else {
        return EAGAIN;
    };
    write_signalfd_siginfo(vm, base, buf, sig, code, pid_from_vm(vm, base));
    128
}

pub fn sys_signalfd4(
    vm: &mut ThreadState,
    base: u32,
    fd: i64,
    mask_addr: u64,
    sigsetsize: u64,
    flags: u64,
) -> i64 {
    if sigsetsize != 8 {
        return EINVAL;
    }
    let allowed_flags = (O_CLOEXEC | O_NONBLOCK) as u64;
    if flags & !allowed_flags != 0 {
        return EINVAL;
    }
    if mask_addr == 0 || !crate::syscall::memory::guest_range_accessible(base, mask_addr, 8) {
        return EFAULT;
    }
    let mask = unsafe { guest_mem::read_u64(base, mask_addr) };

    if fd == -1 {
        let Some(signalfd_idx) = alloc_signalfd_slot(mask) else {
            return EMFILE;
        };
        let new_fd = crate::fs::fd_table::open_signalfd(vm, base, signalfd_idx, flags as i32);
        if new_fd < 0 {
            close_signalfd(signalfd_idx);
        }
        return new_fd;
    }

    let Some(ofd) = crate::fs::fd_table::get_ofd(base, vm, fd as u64) else {
        return EBADF;
    };
    if ofd.fd_type != FD_TYPE_SIGNALFD {
        return EINVAL;
    }
    let Some(slot) = signalfd_slot(ofd.ino) else {
        return EINVAL;
    };
    slot.mask = signalfd_mask_sanitized(mask);
    fd
}
