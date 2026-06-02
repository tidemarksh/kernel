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

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_vma_path_len(index: u32) -> u32 {
    crate::harness::memory::debug_vma_path_len(index)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_vma_path_byte(index: u32, offset: u32) -> u32 {
    crate::harness::memory::debug_vma_path_byte(index, offset)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_vma_file_sample(index: u32, addr: u64) -> u64 {
    crate::harness::memory::debug_vma_file_sample(index, addr)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_vma_file_sample_len(index: u32, addr: u64) -> u32 {
    crate::harness::memory::debug_vma_file_sample_len(index, addr)
}
