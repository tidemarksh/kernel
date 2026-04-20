pub fn debug_read_open(slot: u32) -> i32 {
    crate::syscall::pipe::debug_read_open(slot)
}

pub fn debug_write_open(slot: u32) -> i32 {
    crate::syscall::pipe::debug_write_open(slot)
}
