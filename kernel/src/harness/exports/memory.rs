#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_permit_checks() -> u64 {
    crate::harness::debug::memory_permit_checks()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_permit_cache_hits() -> u64 {
    crate::harness::debug::memory_permit_cache_hits()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_permit_cover_hits() -> u64 {
    crate::harness::debug::memory_permit_cover_hits()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_permit_denied() -> u64 {
    crate::harness::debug::memory_permit_denied()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_permit_checks_by_prot(prot: u32) -> u64 {
    crate::harness::debug::memory_permit_checks_by_prot(prot)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_permit_cache_hits_by_prot(prot: u32) -> u64 {
    crate::harness::debug::memory_permit_cache_hits_by_prot(prot)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_permit_cover_hits_by_prot(prot: u32) -> u64 {
    crate::harness::debug::memory_permit_cover_hits_by_prot(prot)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_permit_denied_by_prot(prot: u32) -> u64 {
    crate::harness::debug::memory_permit_denied_by_prot(prot)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clear_guest_write_watch_trace() {
    crate::harness::trace::clear_guest_write_watch_trace();
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_configure_guest_write_watch(slot: u32, start: u64, end: u64) {
    crate::harness::trace::configure_guest_write_watch(slot, start, end);
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_write_overlap_trace_len() -> u32 {
    crate::harness::debug::guest_write_overlap_trace_len()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_write_overlap_trace_entry_slot(index: u32) -> u32 {
    crate::harness::debug::guest_write_overlap_trace_entry(index).slot
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_write_overlap_trace_entry_op(index: u32) -> u32 {
    crate::harness::debug::guest_write_overlap_trace_entry(index).op
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_write_overlap_trace_entry_tid(index: u32) -> i32 {
    crate::harness::debug::guest_write_overlap_trace_entry(index).tid
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_write_overlap_trace_entry_pc(index: u32) -> u64 {
    crate::harness::debug::guest_write_overlap_trace_entry(index).pc
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_write_overlap_trace_entry_addr(index: u32) -> u64 {
    crate::harness::debug::guest_write_overlap_trace_entry(index).addr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_write_overlap_trace_entry_len(index: u32) -> u32 {
    crate::harness::debug::guest_write_overlap_trace_entry(index).len
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_write_overlap_trace_entry_sample_len(index: u32) -> u32 {
    crate::harness::debug::guest_write_overlap_trace_entry(index).sample_len
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_write_overlap_trace_entry_sample(index: u32) -> u64 {
    crate::harness::debug::guest_write_overlap_trace_entry(index).sample
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_write_overlap_trace_entry_execve_stage(index: u32) -> u32 {
    crate::harness::debug::guest_write_overlap_trace_entry(index).execve_stage
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_range_permit_denied_trace_len() -> u32 {
    crate::harness::debug::guest_range_permit_denied_trace_len()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_range_permit_denied_trace_entry_vm_ptr(index: u32) -> u32 {
    crate::harness::debug::guest_range_permit_denied_trace_entry(index).vm_ptr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_range_permit_denied_trace_entry_tid(index: u32) -> i32 {
    crate::harness::debug::guest_range_permit_denied_trace_entry(index).tid
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_range_permit_denied_trace_entry_pc(index: u32) -> u64 {
    crate::harness::debug::guest_range_permit_denied_trace_entry(index).pc
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_range_permit_denied_trace_entry_a0(index: u32) -> u64 {
    crate::harness::debug::guest_range_permit_denied_trace_entry(index).a0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_range_permit_denied_trace_entry_a1(index: u32) -> u64 {
    crate::harness::debug::guest_range_permit_denied_trace_entry(index).a1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_range_permit_denied_trace_entry_a2(index: u32) -> u64 {
    crate::harness::debug::guest_range_permit_denied_trace_entry(index).a2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_range_permit_denied_trace_entry_a3(index: u32) -> u64 {
    crate::harness::debug::guest_range_permit_denied_trace_entry(index).a3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_range_permit_denied_trace_entry_a4(index: u32) -> u64 {
    crate::harness::debug::guest_range_permit_denied_trace_entry(index).a4
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_range_permit_denied_trace_entry_a5(index: u32) -> u64 {
    crate::harness::debug::guest_range_permit_denied_trace_entry(index).a5
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_range_permit_denied_trace_entry_s1(index: u32) -> u64 {
    crate::harness::debug::guest_range_permit_denied_trace_entry(index).s1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_range_permit_denied_trace_entry_s2(index: u32) -> u64 {
    crate::harness::debug::guest_range_permit_denied_trace_entry(index).s2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_range_permit_denied_trace_entry_s3(index: u32) -> u64 {
    crate::harness::debug::guest_range_permit_denied_trace_entry(index).s3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_range_permit_denied_trace_entry_s11(index: u32) -> u64 {
    crate::harness::debug::guest_range_permit_denied_trace_entry(index).s11
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_range_permit_denied_trace_entry_start(index: u32) -> u64 {
    crate::harness::debug::guest_range_permit_denied_trace_entry(index).start
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_range_permit_denied_trace_entry_len(index: u32) -> u64 {
    crate::harness::debug::guest_range_permit_denied_trace_entry(index).len
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_range_permit_denied_trace_entry_end(index: u32) -> u64 {
    crate::harness::debug::guest_range_permit_denied_trace_entry(index).end
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_range_permit_denied_trace_entry_guest_limit(index: u32) -> u64 {
    crate::harness::debug::guest_range_permit_denied_trace_entry(index).guest_limit
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_range_permit_denied_trace_entry_prot(index: u32) -> i32 {
    crate::harness::debug::guest_range_permit_denied_trace_entry(index).prot
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_range_permit_denied_trace_entry_cover_start(index: u32) -> u64 {
    crate::harness::debug::guest_range_permit_denied_trace_entry(index).cover_start
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_range_permit_denied_trace_entry_cover_end(index: u32) -> u64 {
    crate::harness::debug::guest_range_permit_denied_trace_entry(index).cover_end
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_range_permit_denied_trace_entry_cover_prot(index: u32) -> i32 {
    crate::harness::debug::guest_range_permit_denied_trace_entry(index).cover_prot
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_range_permit_denied_trace_entry_reason(index: u32) -> u32 {
    crate::harness::debug::guest_range_permit_denied_trace_entry(index).reason
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_nr() -> u64 {
    crate::harness::debug::memory_trace_summary().nr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_arg0() -> u64 {
    crate::harness::debug::memory_trace_summary().arg0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_arg1() -> u64 {
    crate::harness::debug::memory_trace_summary().arg1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_arg2() -> u64 {
    crate::harness::debug::memory_trace_summary().arg2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_arg3() -> u64 {
    crate::harness::debug::memory_trace_summary().arg3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_result() -> i64 {
    crate::harness::debug::memory_trace_summary().result
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_len() -> u32 {
    crate::harness::debug::memory_trace_len()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_entry_nr(index: u32) -> u64 {
    crate::harness::debug::memory_trace_entry(index).nr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_entry_arg0(index: u32) -> u64 {
    crate::harness::debug::memory_trace_entry(index).arg0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_entry_arg1(index: u32) -> u64 {
    crate::harness::debug::memory_trace_entry(index).arg1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_entry_arg2(index: u32) -> u64 {
    crate::harness::debug::memory_trace_entry(index).arg2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_entry_arg3(index: u32) -> u64 {
    crate::harness::debug::memory_trace_entry(index).arg3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_entry_result(index: u32) -> i64 {
    crate::harness::debug::memory_trace_entry(index).result
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_brk_base() -> u64 {
    crate::harness::memory::debug_brk_base()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_brk_current() -> u64 {
    crate::harness::memory::current_brk()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_mmap_next() -> u64 {
    crate::harness::memory::debug_mmap_next()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_vma_len() -> u32 {
    crate::harness::memory::debug_vma_len()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_vma_start(index: u32) -> u64 {
    crate::harness::memory::debug_vma_start(index)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_vma_end(index: u32) -> u64 {
    crate::harness::memory::debug_vma_end(index)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_vma_prot(index: u32) -> i32 {
    crate::harness::memory::debug_vma_prot(index)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_vma_flags(index: u32) -> i32 {
    crate::harness::memory::debug_vma_flags(index)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_vma_fd(index: u32) -> i32 {
    crate::harness::memory::debug_vma_fd(index)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_vma_offset(index: u32) -> u64 {
    crate::harness::memory::debug_vma_offset(index)
}
