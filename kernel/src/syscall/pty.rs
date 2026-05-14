//! Pseudo-terminal control plane.
//!
//! Primary sources:
//! - https://man7.org/linux/man-pages/man2/ioctl.2.html
//! - https://codebrowser.dev/linux/linux/include/uapi/asm-generic/ioctls.h.html
//! - https://codebrowser.dev/linux/linux/include/uapi/asm-generic/termbits.h.html
//! - https://codebrowser.dev/linux/linux/include/uapi/asm-generic/termios.h.html

use crate::abi::*;
use crate::alloc;
use crate::fs::fd_table;
use crate::guest_mem;
use crate::types::{ProcessState, ThreadState};

const MAX_PTYS: usize = 64;
const NCCS: usize = 19;
const PTY_CANON_BUF_SIZE: usize = 4096;

const TCGETS: u64 = 0x5401;
const TCSETS: u64 = 0x5402;
const TCSETSW: u64 = 0x5403;
const TCSETSF: u64 = 0x5404;
const TIOCSCTTY: u64 = 0x540E;
const TIOCGPGRP: u64 = 0x540F;
const TIOCSPGRP: u64 = 0x5410;
const TIOCGWINSZ: u64 = 0x5413;
const TIOCSWINSZ: u64 = 0x5414;
const FIONREAD: u64 = 0x541B;
const FIONBIO: u64 = 0x5421;
const TIOCNOTTY: u64 = 0x5422;
const TIOCGPTN: u64 = 0x80045430;
const TIOCSPTLCK: u64 = 0x40045431;

const BRKINT: u32 = 0x002;
const ICRNL: u32 = 0x100;
const OPOST: u32 = 0x01;
const ONLCR: u32 = 0x00004;
const B38400: u32 = 0x0000000f;
const CS8: u32 = 0x00000030;
const CREAD: u32 = 0x00000080;
const HUPCL: u32 = 0x00000400;
const ISIG: u32 = 0x00001;
const ICANON: u32 = 0x00002;
const ECHO: u32 = 0x00008;
const ECHOE: u32 = 0x00010;
const ECHOK: u32 = 0x00020;
const ECHOCTL: u32 = 0x00200;
const ECHOKE: u32 = 0x00800;
const IEXTEN: u32 = 0x08000;
const EXTPROC: u32 = 0x10000;
const IXON: u32 = 0x0400;
const IUTF8: u32 = 0x4000;
const ECHONL: u32 = 0x00040;

const VINTR: usize = 0;
const VQUIT: usize = 1;
const VERASE: usize = 2;
const VKILL: usize = 3;
const VEOF: usize = 4;
const VSTART: usize = 8;
const VSTOP: usize = 9;
const VEOL: usize = 11;
const VEOL2: usize = 16;

#[repr(C)]
#[derive(Clone, Copy)]
struct PtySlot {
    used: u32,
    input_pipe: u32,
    output_pipe: u32,
    host_open: i32,
    master_open: i32,
    slave_open: i32,
    locked: i32,
    session_sid: i32,
    fg_pgrp: i32,
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
    c_iflag: u32,
    c_oflag: u32,
    c_cflag: u32,
    c_lflag: u32,
    c_line: u8,
    c_cc: [u8; NCCS],
    canon_line_len: u16,
    canon_ready_len: u16,
    canon_ready_pos: u16,
    _pad0: u16,
    canon_buf: [u8; PTY_CANON_BUF_SIZE],
}

impl PtySlot {
    const fn empty() -> Self {
        Self {
            used: 0,
            input_pipe: 0,
            output_pipe: 0,
            host_open: 0,
            master_open: 0,
            slave_open: 0,
            locked: 0,
            session_sid: 0,
            fg_pgrp: 0,
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
            c_iflag: 0,
            c_oflag: 0,
            c_cflag: 0,
            c_lflag: 0,
            c_line: 0,
            c_cc: [0; NCCS],
            canon_line_len: 0,
            canon_ready_len: 0,
            canon_ready_pos: 0,
            _pad0: 0,
            canon_buf: [0; PTY_CANON_BUF_SIZE],
        }
    }
}

pub struct StdioPty {
    pub pty_idx: u32,
    pub stdin_pipe: u32,
    pub stdout_pipe: u32,
}

static mut PTY_TABLE_PTR: *mut [PtySlot; MAX_PTYS] = core::ptr::null_mut();

fn pty_table() -> &'static mut [PtySlot; MAX_PTYS] {
    unsafe {
        let ptr = core::ptr::read(core::ptr::addr_of!(PTY_TABLE_PTR));
        &mut *ptr
    }
}

fn process_state(base: u32, vm: &ThreadState) -> Option<&'static mut ProcessState> {
    let ptr = (base as u64 + vm.process_ptr as u64) as *mut ProcessState;
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &mut *ptr })
    }
}

fn default_termios(slot: &mut PtySlot) {
    slot.c_iflag = BRKINT | ICRNL | IXON | IUTF8;
    slot.c_oflag = OPOST | ONLCR;
    slot.c_cflag = B38400 | CS8 | CREAD | HUPCL;
    slot.c_lflag = ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN;
    slot.c_line = 0;
    slot.c_cc = [0; NCCS];
    slot.c_cc[0] = 3;
    slot.c_cc[1] = 28;
    slot.c_cc[2] = 127;
    slot.c_cc[3] = 21;
    slot.c_cc[4] = 4;
    slot.c_cc[8] = 17;
    slot.c_cc[9] = 19;
    slot.c_cc[10] = 26;
    slot.c_cc[11] = 0;
    slot.c_cc[12] = 18;
    slot.c_cc[13] = 15;
    slot.c_cc[14] = 23;
    slot.c_cc[15] = 22;
    slot.c_cc[16] = 0;
}

fn current_sid_and_pgrp(vm: &ThreadState, base: u32) -> (i32, i32) {
    let sid = crate::syscall::process::current_process_sid(vm, base);
    let pgid = crate::syscall::process::current_process_pgid(vm, base);
    let pid = process_state(base, vm).map(|ps| ps.pid).unwrap_or(1);
    (
        if sid > 0 { sid } else { pid },
        if pgid > 0 { pgid } else { pid },
    )
}

fn alloc_pty_slot(input_pipe: u32, output_pipe: u32) -> Option<u32> {
    for index in 1..MAX_PTYS {
        let slot = &mut pty_table()[index];
        if slot.used != 0 {
            continue;
        }
        *slot = PtySlot::empty();
        slot.used = 1;
        slot.input_pipe = input_pipe;
        slot.output_pipe = output_pipe;
        slot.ws_row = 24;
        slot.ws_col = 80;
        default_termios(slot);
        return Some(index as u32);
    }
    None
}

fn maybe_free_pty(pty_idx: u32) {
    let slot = &mut pty_table()[pty_idx as usize];
    if slot.used == 0 || slot.host_open > 0 || slot.master_open > 0 || slot.slave_open > 0 {
        return;
    }
    if slot.input_pipe != 0 {
        crate::syscall::pipe::pipe_close(slot.input_pipe, true);
        crate::syscall::pipe::pipe_close(slot.input_pipe, false);
    }
    if slot.output_pipe != 0 {
        crate::syscall::pipe::pipe_close(slot.output_pipe, true);
        crate::syscall::pipe::pipe_close(slot.output_pipe, false);
    }
    *slot = PtySlot::empty();
}

pub fn init() {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(PTY_TABLE_PTR),
            core::ptr::null_mut(),
        );
        let size = core::mem::size_of::<[PtySlot; MAX_PTYS]>() as u32;
        let align = core::mem::align_of::<PtySlot>() as u32;
        let ptr = alloc::alloc_zeroed(size, align);
        if ptr == 0 {
            core::arch::wasm32::unreachable();
        }
        core::ptr::write(
            core::ptr::addr_of_mut!(PTY_TABLE_PTR),
            ptr as *mut [PtySlot; MAX_PTYS],
        );
    }
}

pub fn alloc_stdio_pty(vm: &ThreadState, base: u32) -> Option<StdioPty> {
    let input_pipe = crate::syscall::pipe::alloc_pipe_slot()?;
    let output_pipe = match crate::syscall::pipe::alloc_pipe_slot() {
        Some(slot) => slot,
        None => {
            crate::syscall::pipe::pipe_close(input_pipe, true);
            crate::syscall::pipe::pipe_close(input_pipe, false);
            return None;
        }
    };
    let Some(pty_idx) = alloc_pty_slot(input_pipe, output_pipe) else {
        crate::syscall::pipe::pipe_close(input_pipe, true);
        crate::syscall::pipe::pipe_close(input_pipe, false);
        crate::syscall::pipe::pipe_close(output_pipe, true);
        crate::syscall::pipe::pipe_close(output_pipe, false);
        return None;
    };
    let (sid, pgid) = current_sid_and_pgrp(vm, base);
    let slot = &mut pty_table()[pty_idx as usize];
    slot.host_open = 1;
    slot.session_sid = sid;
    slot.fg_pgrp = pgid;
    if let Some(ps) = process_state(base, vm) {
        ps.tty_pty_slot = pty_idx;
    }
    Some(StdioPty {
        pty_idx,
        stdin_pipe: input_pipe,
        stdout_pipe: output_pipe,
    })
}

pub fn open_controlling_tty(vm: &mut ThreadState, base: u32, flags: i32) -> i64 {
    let Some(ps) = process_state(base, vm) else {
        return ENXIO;
    };
    if ps.tty_pty_slot == 0 {
        return ENXIO;
    }
    fd_table::open_pty_slave(vm, base, ps.tty_pty_slot, flags)
}

pub fn has_controlling_tty(vm: &ThreadState, base: u32) -> bool {
    process_state(base, vm)
        .map(|ps| {
            let pty_idx = ps.tty_pty_slot;
            pty_idx != 0 && (pty_idx as usize) < MAX_PTYS && pty_table()[pty_idx as usize].used != 0
        })
        .unwrap_or(false)
}

pub fn pty_close(pty_idx: u32, is_master: bool) {
    if pty_idx == 0 || pty_idx as usize >= MAX_PTYS {
        return;
    }
    let slot = &mut pty_table()[pty_idx as usize];
    if slot.used == 0 {
        return;
    }
    if is_master {
        slot.master_open -= 1;
    } else {
        slot.slave_open -= 1;
    }
    maybe_free_pty(pty_idx);
}

pub fn release_host_attachment(vm: &ThreadState, base: u32) {
    let Some(ps) = process_state(base, vm) else {
        return;
    };
    let pty_idx = ps.tty_pty_slot;
    if pty_idx == 0 || pty_idx as usize >= MAX_PTYS {
        ps.tty_pty_slot = 0;
        return;
    }
    let slot = &mut pty_table()[pty_idx as usize];
    if slot.used != 0 && slot.host_open > 0 {
        slot.host_open -= 1;
    }
    ps.tty_pty_slot = 0;
    maybe_free_pty(pty_idx);
}

pub fn refresh_controlling_tty_foreground(vm: &ThreadState, base: u32) {
    let Some(ps) = process_state(base, vm) else {
        return;
    };
    let pty_idx = ps.tty_pty_slot;
    if pty_idx == 0 || pty_idx as usize >= MAX_PTYS {
        return;
    }
    let slot = &mut pty_table()[pty_idx as usize];
    if slot.used == 0 {
        return;
    }
    let (sid, pgid) = current_sid_and_pgrp(vm, base);
    slot.session_sid = sid;
    slot.fg_pgrp = pgid;
}

pub fn retain_slave(pty_idx: u32) {
    let slot = &mut pty_table()[pty_idx as usize];
    slot.slave_open += 1;
}

pub fn retain_master(pty_idx: u32) {
    let slot = &mut pty_table()[pty_idx as usize];
    slot.master_open += 1;
}

fn write_output_bytes(slot: &PtySlot, data: &[u8]) -> i64 {
    if data.is_empty() {
        return 0;
    }
    if slot.c_oflag & OPOST == 0 || slot.c_oflag & ONLCR == 0 {
        return crate::syscall::pipe::pipe_write(slot.output_pipe, data);
    }
    let mut translated = [0u8; 512];
    let mut write_start = 0usize;
    for &byte in data {
        if write_start + 2 > translated.len() {
            let n = crate::syscall::pipe::pipe_write(slot.output_pipe, &translated[..write_start]);
            if n < 0 {
                return n;
            }
            write_start = 0;
        }
        if byte == b'\n' {
            translated[write_start] = b'\r';
            translated[write_start + 1] = b'\n';
            write_start += 2;
        } else {
            translated[write_start] = byte;
            write_start += 1;
        }
    }
    crate::syscall::pipe::pipe_write(slot.output_pipe, &translated[..write_start])
}

fn translated_input_progress(slot: &PtySlot, data: &[u8], written_out: usize) -> usize {
    if slot.c_oflag & OPOST == 0 || slot.c_oflag & ONLCR == 0 {
        return written_out.min(data.len());
    }
    let mut consumed_in = 0usize;
    let mut consumed_out = 0usize;
    for &byte in data {
        let step_out = if byte == b'\n' { 2 } else { 1 };
        if consumed_out + step_out > written_out {
            break;
        }
        consumed_out += step_out;
        consumed_in += 1;
    }
    consumed_in
}

fn echo_visual_width(slot: &PtySlot, byte: u8) -> usize {
    if byte == b'\t' || byte == b'\n' {
        return 1;
    }
    if (byte < 0x20 || byte == 0x7f) && slot.c_lflag & ECHOCTL != 0 {
        return 2;
    }
    1
}

fn echo_erase(slot: &PtySlot, width: usize) {
    if slot.c_lflag & ECHOE == 0 {
        return;
    }
    const ERASE_SEQ: &[u8] = b"\x08 \x08";
    for _ in 0..width {
        let _ = write_output_bytes(slot, ERASE_SEQ);
    }
}

fn echo_input_byte(slot: &PtySlot, byte: u8) {
    if byte == b'\n' {
        if slot.c_lflag & (ECHO | ECHONL) != 0 {
            let _ = write_output_bytes(slot, b"\n");
        }
        return;
    }
    if slot.c_lflag & ECHO == 0 {
        return;
    }
    if (byte < 0x20 || byte == 0x7f) && byte != b'\t' {
        if slot.c_lflag & ECHOCTL != 0 {
            let rendered = [b'^', if byte == 0x7f { b'?' } else { byte ^ 0x40 }];
            let _ = write_output_bytes(slot, &rendered);
            return;
        }
    }
    let _ = write_output_bytes(slot, core::slice::from_ref(&byte));
}

fn flush_ready_input(slot: &mut PtySlot) -> i64 {
    if slot.canon_ready_pos as usize >= slot.canon_ready_len as usize || slot.canon_ready_len == 0 {
        slot.canon_ready_len = 0;
        slot.canon_ready_pos = 0;
        return 0;
    }
    let start = slot.canon_ready_pos as usize;
    let end = slot.canon_ready_len as usize;
    let written = crate::syscall::pipe::pipe_write(slot.input_pipe, &slot.canon_buf[start..end]);
    if written > 0 {
        slot.canon_ready_pos = slot.canon_ready_pos.saturating_add(written as u16);
        if slot.canon_ready_pos >= slot.canon_ready_len {
            slot.canon_ready_len = 0;
            slot.canon_ready_pos = 0;
        }
    }
    written
}

fn queue_canonical_line(slot: &mut PtySlot, include_byte: Option<u8>) -> i64 {
    if let Some(byte) = include_byte {
        let line_len = slot.canon_line_len as usize;
        if line_len >= slot.canon_buf.len() {
            return EAGAIN;
        }
        slot.canon_buf[line_len] = byte;
        slot.canon_line_len += 1;
    }
    if slot.canon_line_len == 0 {
        return 0;
    }
    slot.canon_ready_len = slot.canon_line_len;
    slot.canon_ready_pos = 0;
    slot.canon_line_len = 0;
    flush_ready_input(slot)
}

fn process_signal_char(vm: &mut ThreadState, base: u32, slot: &PtySlot, byte: u8) -> bool {
    if slot.c_lflag & ISIG == 0 || slot.c_lflag & EXTPROC != 0 {
        return false;
    }
    let sig = if byte == slot.c_cc[VINTR] {
        SIGINT
    } else if byte == slot.c_cc[VQUIT] {
        SIGQUIT
    } else {
        return false;
    };
    let target_pgid = slot.fg_pgrp;
    if target_pgid > 0 {
        for pid in 1..MAX_PROCESSES as i32 {
            if crate::syscall::process::process_pgid(pid) == target_pgid {
                let _ = crate::syscall::signal::send_signal_to_pid(vm, base, pid, sig);
            }
        }
    } else {
        crate::syscall::signal::send_signal(vm, sig);
    }
    true
}

fn canonicalize_input_byte(slot: &PtySlot, byte: u8) -> u8 {
    if byte == b'\r' && slot.c_iflag & ICRNL != 0 {
        b'\n'
    } else {
        byte
    }
}

pub fn slave_read(pty_idx: u32, buf: &mut [u8]) -> i64 {
    let slot = &mut pty_table()[pty_idx as usize];
    let _ = flush_ready_input(slot);
    crate::syscall::pipe::pipe_read(slot.input_pipe, buf)
}

pub fn slave_write(pty_idx: u32, data: &[u8]) -> i64 {
    let slot = &pty_table()[pty_idx as usize];
    let written = write_output_bytes(slot, data);
    if written < 0 {
        return written;
    }
    translated_input_progress(slot, data, written as usize) as i64
}

pub fn master_read(pty_idx: u32, buf: &mut [u8]) -> i64 {
    let slot = &pty_table()[pty_idx as usize];
    crate::syscall::pipe::pipe_read(slot.output_pipe, buf)
}

pub fn master_write(pty_idx: u32, data: &[u8]) -> i64 {
    master_write_with_context(pty_idx, data, None)
}

pub fn master_write_from_thread(pty_idx: u32, data: &[u8], vm: &mut ThreadState, base: u32) -> i64 {
    master_write_with_context(pty_idx, data, Some((vm, base)))
}

fn master_write_with_context(
    pty_idx: u32,
    data: &[u8],
    context: Option<(&mut ThreadState, u32)>,
) -> i64 {
    let slot = &mut pty_table()[pty_idx as usize];
    let mut signal_context = context;
    let mut consumed = 0usize;
    if slot.used == 0 {
        return EIO;
    }
    let pending = flush_ready_input(slot);
    if pending == EAGAIN && slot.canon_ready_len != 0 {
        return EAGAIN;
    }
    for &raw_byte in data {
        if slot.c_lflag & ICANON == 0 {
            let n =
                crate::syscall::pipe::pipe_write(slot.input_pipe, core::slice::from_ref(&raw_byte));
            if n <= 0 {
                return if consumed > 0 { consumed as i64 } else { n };
            }
            echo_input_byte(slot, raw_byte);
            consumed += 1;
            continue;
        }

        if slot.canon_ready_len != 0 {
            let flushed = flush_ready_input(slot);
            if flushed == EAGAIN && slot.canon_ready_len != 0 {
                return if consumed > 0 {
                    consumed as i64
                } else {
                    EAGAIN
                };
            }
        }

        let byte = canonicalize_input_byte(slot, raw_byte);
        if let Some((vm, base)) = signal_context.as_mut()
            && process_signal_char(vm, *base, slot, byte)
        {
            slot.canon_line_len = 0;
            if slot.c_lflag & ECHO != 0 {
                echo_input_byte(slot, byte);
                let _ = write_output_bytes(slot, b"\n");
            }
            consumed += 1;
            continue;
        }

        if byte == slot.c_cc[VERASE] {
            if slot.canon_line_len > 0 {
                let removed = slot.canon_buf[slot.canon_line_len as usize - 1];
                slot.canon_line_len -= 1;
                echo_erase(slot, echo_visual_width(slot, removed));
            }
            consumed += 1;
            continue;
        }

        if byte == slot.c_cc[VKILL] {
            while slot.canon_line_len > 0 {
                let removed = slot.canon_buf[slot.canon_line_len as usize - 1];
                slot.canon_line_len -= 1;
                if slot.c_lflag & ECHOKE != 0 {
                    echo_erase(slot, echo_visual_width(slot, removed));
                }
            }
            if slot.c_lflag & ECHOK != 0 {
                let _ = write_output_bytes(slot, b"\n");
            }
            consumed += 1;
            continue;
        }

        if byte == slot.c_cc[VSTART] || byte == slot.c_cc[VSTOP] {
            consumed += 1;
            continue;
        }

        if byte == slot.c_cc[VEOF] {
            let committed = queue_canonical_line(slot, None);
            if committed == EAGAIN {
                return if consumed > 0 {
                    consumed as i64
                } else {
                    EAGAIN
                };
            }
            consumed += 1;
            continue;
        }

        let line_terminator = byte == b'\n'
            || (slot.c_cc[VEOL] != 0 && byte == slot.c_cc[VEOL])
            || (slot.c_cc[VEOL2] != 0 && byte == slot.c_cc[VEOL2]);
        if line_terminator {
            echo_input_byte(slot, byte);
            let committed = queue_canonical_line(slot, Some(byte));
            if committed == EAGAIN {
                return if consumed > 0 {
                    consumed as i64
                } else {
                    EAGAIN
                };
            }
            consumed += 1;
            continue;
        }

        let line_len = slot.canon_line_len as usize;
        if line_len >= slot.canon_buf.len() {
            return if consumed > 0 {
                consumed as i64
            } else {
                EAGAIN
            };
        }
        slot.canon_buf[line_len] = byte;
        slot.canon_line_len += 1;
        echo_input_byte(slot, byte);
        consumed += 1;
    }
    consumed as i64
}

pub fn input_pipe_slot(pty_idx: u32) -> u32 {
    if pty_idx == 0 || pty_idx as usize >= MAX_PTYS {
        return 0;
    }
    let slot = &pty_table()[pty_idx as usize];
    if slot.used == 0 { 0 } else { slot.input_pipe }
}

pub fn host_write_from_process(vm: &mut ThreadState, base: u32, data: &[u8]) -> i64 {
    let Some(ps) = process_state(base, vm) else {
        return EIO;
    };
    let pty_idx = ps.tty_pty_slot;
    if pty_idx == 0 || pty_idx as usize >= MAX_PTYS {
        return EIO;
    }
    master_write_from_thread(pty_idx, data, vm, base)
}

pub fn output_pipe_slot(pty_idx: u32) -> u32 {
    if pty_idx == 0 || pty_idx as usize >= MAX_PTYS {
        return 0;
    }
    let slot = &pty_table()[pty_idx as usize];
    if slot.used == 0 { 0 } else { slot.output_pipe }
}

pub fn is_locked(pty_idx: u32) -> bool {
    pty_table()[pty_idx as usize].locked != 0
}

fn write_termios(base: u32, addr: u64, slot: &PtySlot) {
    unsafe {
        guest_mem::write_u32(base, addr, slot.c_iflag);
        guest_mem::write_u32(base, addr + 4, slot.c_oflag);
        guest_mem::write_u32(base, addr + 8, slot.c_cflag);
        guest_mem::write_u32(base, addr + 12, slot.c_lflag);
        guest_mem::write_u8(base, addr + 16, slot.c_line);
        guest_mem::write_bytes(base, addr + 17, &slot.c_cc);
    }
}

fn read_termios(base: u32, addr: u64, slot: &mut PtySlot) {
    unsafe {
        slot.c_iflag = guest_mem::read_u32(base, addr);
        slot.c_oflag = guest_mem::read_u32(base, addr + 4);
        slot.c_cflag = guest_mem::read_u32(base, addr + 8);
        slot.c_lflag = guest_mem::read_u32(base, addr + 12);
        slot.c_line = guest_mem::read_u8(base, addr + 16);
        guest_mem::read_bytes(base, addr + 17, &mut slot.c_cc);
    }
}

fn write_winsize(base: u32, addr: u64, slot: &PtySlot) {
    unsafe {
        guest_mem::write_u16(base, addr, slot.ws_row);
        guest_mem::write_u16(base, addr + 2, slot.ws_col);
        guest_mem::write_u16(base, addr + 4, slot.ws_xpixel);
        guest_mem::write_u16(base, addr + 6, slot.ws_ypixel);
    }
}

fn read_winsize(base: u32, addr: u64, slot: &mut PtySlot) {
    unsafe {
        slot.ws_row = guest_mem::read_u16(base, addr);
        slot.ws_col = guest_mem::read_u16(base, addr + 2);
        slot.ws_xpixel = guest_mem::read_u16(base, addr + 4);
        slot.ws_ypixel = guest_mem::read_u16(base, addr + 6);
    }
}

fn ioctl_pty_slave(vm: &mut ThreadState, base: u32, pty_idx: u32, request: u64, arg: u64) -> i64 {
    let slot = &mut pty_table()[pty_idx as usize];
    match request {
        TCGETS => {
            write_termios(base, arg, slot);
            0
        }
        TCSETS | TCSETSW | TCSETSF => {
            read_termios(base, arg, slot);
            if request == TCSETSF {
                slot.canon_line_len = 0;
                slot.canon_ready_len = 0;
                slot.canon_ready_pos = 0;
            }
            0
        }
        TIOCGWINSZ => {
            write_winsize(base, arg, slot);
            0
        }
        TIOCSWINSZ => {
            read_winsize(base, arg, slot);
            0
        }
        TIOCGPGRP => {
            unsafe { guest_mem::write_u32(base, arg, slot.fg_pgrp as u32) };
            0
        }
        TIOCSPGRP => {
            let pgid = unsafe { guest_mem::read_u32(base, arg) as i32 };
            if pgid <= 0 {
                EINVAL
            } else {
                slot.fg_pgrp = pgid;
                0
            }
        }
        TIOCSCTTY => {
            let (sid, pgid) = current_sid_and_pgrp(vm, base);
            slot.session_sid = sid;
            slot.fg_pgrp = pgid;
            if let Some(ps) = process_state(base, vm) {
                ps.tty_pty_slot = pty_idx;
            }
            0
        }
        TIOCNOTTY => {
            if let Some(ps) = process_state(base, vm)
                && ps.tty_pty_slot == pty_idx
            {
                ps.tty_pty_slot = 0;
            }
            0
        }
        FIONREAD => {
            let available = crate::syscall::pipe::pipe_peek(slot.input_pipe);
            let pending = slot.canon_ready_len.saturating_sub(slot.canon_ready_pos) as u32;
            let value = if available < 0 {
                pending
            } else {
                available as u32 + pending
            };
            unsafe { guest_mem::write_u32(base, arg, value) };
            0
        }
        _ => ENOTTY,
    }
}

fn ioctl_pty_master(base: u32, pty_idx: u32, request: u64, arg: u64) -> i64 {
    let slot = &mut pty_table()[pty_idx as usize];
    match request {
        TIOCGPTN => {
            unsafe { guest_mem::write_u32(base, arg, pty_idx - 1) };
            0
        }
        TIOCSPTLCK => {
            slot.locked = unsafe { guest_mem::read_u32(base, arg) as i32 };
            0
        }
        TIOCGWINSZ => {
            write_winsize(base, arg, slot);
            0
        }
        TIOCSWINSZ => {
            read_winsize(base, arg, slot);
            0
        }
        FIONREAD => {
            let available = crate::syscall::pipe::pipe_peek(slot.output_pipe);
            let value = if available < 0 { 0 } else { available as u32 };
            unsafe { guest_mem::write_u32(base, arg, value) };
            0
        }
        _ => ENOTTY,
    }
}

pub fn sys_ioctl(vm: &mut ThreadState, base: u32, fd: u64, request: u64, arg: u64) -> i64 {
    let Some(ofd) = fd_table::get_ofd(base, vm, fd) else {
        return EBADF;
    };
    if request == FIONBIO {
        if !crate::syscall::memory::guest_range_accessible(base, arg, 4) {
            return EFAULT;
        }
        // Linux defines FIONBIO as a generic ioctl for toggling O_NONBLOCK;
        // see https://codebrowser.dev/linux/linux/include/uapi/asm-generic/ioctls.h.html
        let enabled = unsafe { guest_mem::read_u32(base, arg) != 0 };
        return fd_table::set_fd_nonblock(base, vm, fd, enabled);
    }
    match ofd.fd_type {
        FD_TYPE_PTY_SLAVE => ioctl_pty_slave(vm, base, ofd.ino, request, arg),
        FD_TYPE_PTY_MASTER => ioctl_pty_master(base, ofd.ino, request, arg),
        FD_TYPE_PIPE => {
            if request != FIONREAD {
                return ENOTTY;
            }
            let available = crate::syscall::pipe::pipe_peek(ofd.ino);
            let value = if available < 0 { 0 } else { available as u32 };
            unsafe { guest_mem::write_u32(base, arg, value) };
            0
        }
        _ => ENOTTY,
    }
}
