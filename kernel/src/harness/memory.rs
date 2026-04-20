use crate::types::Vma;

#[derive(Clone)]
pub(crate) struct AddressSpaceSnapshot {
    state: crate::syscall::memory::AddressSpaceStateImage,
}

impl AddressSpaceSnapshot {
    pub(crate) fn empty() -> Self {
        Self {
            state: crate::syscall::memory::AddressSpaceStateImage::empty(),
        }
    }

    pub(crate) fn vmas(&self) -> &[Vma] {
        self.state.vmas()
    }

    pub(crate) fn debug_vma_vec_meta(&self) -> (usize, usize, usize) {
        self.state.debug_vma_vec_meta()
    }
}

pub(crate) fn snapshot_process_context_into(snapshot: &mut AddressSpaceSnapshot) {
    crate::syscall::memory::capture_state_image_into(&mut snapshot.state);
}

pub(crate) fn restore_process_context(snapshot: &AddressSpaceSnapshot) {
    crate::syscall::memory::restore_state_from_image(&snapshot.state);
}

pub fn current_brk() -> u64 {
    crate::syscall::memory::current_brk()
}

pub fn flush_shared_mappings(base: u32) {
    crate::syscall::memory::flush_shared_mappings(base);
}

pub fn refresh_shared_file_mappings(base: u32, guest_limit: u64) {
    crate::syscall::memory::refresh_shared_file_mappings(base, guest_limit);
}

pub fn debug_brk_base() -> u64 {
    crate::syscall::memory::address_space_brk_base()
}

pub fn debug_mmap_next() -> u64 {
    crate::syscall::memory::address_space_mmap_next()
}

pub fn debug_vma_len() -> u32 {
    crate::syscall::memory::address_space_vma_len()
}

pub fn debug_vma_start(index: u32) -> u64 {
    crate::syscall::memory::address_space_vma_start(index)
}

pub fn debug_vma_end(index: u32) -> u64 {
    crate::syscall::memory::address_space_vma_end(index)
}

pub fn debug_vma_prot(index: u32) -> i32 {
    crate::syscall::memory::address_space_vma_prot(index)
}

pub fn debug_vma_flags(index: u32) -> i32 {
    crate::syscall::memory::address_space_vma_flags(index)
}
