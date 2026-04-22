//! ELF loader for RISC-V 64-bit executables.
//!
//! Reference: ELF spec (https://refspecs.linuxfoundation.org/elf/elf.pdf)
//!            RISC-V ELF psABI (https://github.com/riscv-non-isa/riscv-elf-psabi-doc)
//!
//! Supports: ET_EXEC and ET_DYN inspection/loading, RV64, little-endian.
//! Does not support: dynamic linking semantics, relocations, shared objects.

use crate::guest_mem;
use alloc_crate::vec::Vec;

// =============================================================================
// ELF constants (ELF spec v1.2, Chapter 1 — see module doc for URL)
// =============================================================================

const EI_MAG0: u8 = 0x7F;
const EI_MAG1: u8 = b'E';
const EI_MAG2: u8 = b'L';
const EI_MAG3: u8 = b'F';
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_RISCV: u16 = 243;
const PT_INTERP: u32 = 3;
const PT_LOAD: u32 = 1;
const PT_TLS: u32 = 7;
const PF_X: u32 = 0x1;
const PF_W: u32 = 0x2;
const PF_R: u32 = 0x4;

// ELF64 header offsets
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const E_TYPE: usize = 16;
const E_MACHINE: usize = 18;
const E_ENTRY: usize = 24;
const E_PHOFF: usize = 32;
const E_PHENTSIZE: usize = 54;
const E_PHNUM: usize = 56;

// ELF64 program header offsets
const P_TYPE: usize = 0;
const P_FLAGS: usize = 4;
const P_OFFSET: usize = 8;
const P_VADDR: usize = 16;
const P_FILESZ: usize = 32;
const P_MEMSZ: usize = 40;

// Auxiliary vector types (for initial stack setup)
pub const AT_NULL: u64 = 0;
pub const AT_PHDR: u64 = 3;
pub const AT_PHENT: u64 = 4;
pub const AT_PHNUM: u64 = 5;
pub const AT_PAGESZ: u64 = 6;
pub const AT_BASE: u64 = 7;
pub const AT_ENTRY: u64 = 9;
pub const AT_HWCAP: u64 = 16;
pub const AT_CLKTCK: u64 = 17;
pub const AT_RANDOM: u64 = 25;
pub const AT_EXECFN: u64 = 31;

/// Result of loading an ELF binary.
#[derive(Clone, Copy)]
pub struct ElfLoadResult {
    /// Whether the inspected ELF image is ET_DYN.
    pub is_dyn: bool,
    /// Entry point address (e_entry)
    pub entry: u64,
    /// Highest loaded address before page-aligning the initial brk.
    pub load_end: u64,
    /// Highest loaded address + 1 (for brk initialization)
    pub brk_start: u64,
    /// Initial TLS image base from PT_TLS, or 0 when absent.
    pub tls_base: u64,
    /// Program header table address in guest memory (for AT_PHDR)
    pub phdr_addr: u64,
    /// Size of one program header entry
    pub phent: u16,
    /// Number of program header entries
    pub phnum: u16,
    /// AT_ENTRY value exposed to the new process image.
    pub aux_entry: u64,
    /// AT_PHDR value exposed to the new process image.
    pub aux_phdr_addr: u64,
    /// AT_PHENT value exposed to the new process image.
    pub aux_phent: u16,
    /// AT_PHNUM value exposed to the new process image.
    pub aux_phnum: u16,
    /// AT_BASE value exposed to the new process image.
    pub aux_base: u64,
}

#[derive(Clone, Copy)]
pub struct ElfLoadSegment {
    pub start: u64,
    pub end: u64,
    pub prot: i32,
}

/// Validate an ELF image and compute the metadata needed for loading it
/// without mutating guest memory.
///
/// # Safety
/// `elf_ptr..elf_ptr+elf_len` must reference readable bytes in the current
/// WASM linear memory for the duration of the call.
pub unsafe fn inspect_elf(elf_ptr: u32, elf_len: u32, ram_size: u64) -> Result<ElfLoadResult, i32> {
    unsafe {
        if elf_len < 64 {
            return Err(-1); // too small for ELF header
        }

        let e = elf_ptr as *const u8;

        if *e.add(0) != EI_MAG0
            || *e.add(1) != EI_MAG1
            || *e.add(2) != EI_MAG2
            || *e.add(3) != EI_MAG3
        {
            return Err(-1);
        }

        if *e.add(EI_CLASS) != ELFCLASS64 {
            return Err(-2);
        }

        if *e.add(EI_DATA) != ELFDATA2LSB {
            return Err(-3);
        }

        let e_type = read_u16(e, E_TYPE);
        if e_type != ET_EXEC && e_type != ET_DYN {
            return Err(-4);
        }

        let e_machine = read_u16(e, E_MACHINE);
        if e_machine != EM_RISCV {
            return Err(-5);
        }

        let entry = read_u64(e, E_ENTRY);
        let ph_off = read_u64(e, E_PHOFF) as usize;
        let ph_entsize = read_u16(e, E_PHENTSIZE) as usize;
        let ph_num = read_u16(e, E_PHNUM) as usize;

        if ph_entsize < 56 || ph_off + ph_num * ph_entsize > elf_len as usize {
            return Err(-6);
        }

        let mut load_end: u64 = 0;
        let mut phdr_addr: u64 = 0;
        let mut tls_base: u64 = 0;

        for i in 0..ph_num {
            let ph = e.add(ph_off + i * ph_entsize);
            let p_type = read_u32(ph, P_TYPE);

            match p_type {
                PT_LOAD => {
                    let p_offset = read_u64(ph, P_OFFSET);
                    let p_vaddr = read_u64(ph, P_VADDR);
                    let p_filesz = read_u64(ph, P_FILESZ);
                    let p_memsz = read_u64(ph, P_MEMSZ);

                    if p_vaddr + p_memsz > ram_size {
                        return Err(-7);
                    }
                    if p_offset + p_filesz > elf_len as u64 {
                        return Err(-8);
                    }

                    let seg_end = p_vaddr + p_memsz;
                    if seg_end > load_end {
                        load_end = seg_end;
                    }

                    if phdr_addr == 0 && p_offset == 0 {
                        phdr_addr = p_vaddr + ph_off as u64;
                    }
                }
                PT_TLS => {
                    let p_offset = read_u64(ph, P_OFFSET);
                    let p_vaddr = read_u64(ph, P_VADDR);
                    let p_filesz = read_u64(ph, P_FILESZ);
                    let p_memsz = read_u64(ph, P_MEMSZ);
                    if p_vaddr + p_memsz > ram_size {
                        return Err(-7);
                    }
                    if p_offset + p_filesz > elf_len as u64 {
                        return Err(-8);
                    }
                    tls_base = p_vaddr;
                }
                _ => {}
            }
        }

        let brk_end = (load_end + 4095) & !4095;

        Ok(ElfLoadResult {
            is_dyn: e_type == ET_DYN,
            entry,
            load_end,
            brk_start: brk_end,
            tls_base,
            phdr_addr,
            phent: ph_entsize as u16,
            phnum: ph_num as u16,
            aux_entry: entry,
            aux_phdr_addr: phdr_addr,
            aux_phent: ph_entsize as u16,
            aux_phnum: ph_num as u16,
            aux_base: 0,
        })
    }
}

/// Load an ELF binary from `elf_data` (byte slice in WASM memory at `elf_ptr`)
/// into guest RAM at `ram_base`.
///
/// Returns entry point and metadata, or -1 on error.
///
/// # Safety
/// `ram_base` must point to valid guest memory. `elf_ptr` must contain a valid ELF.
fn apply_load_bias(mut result: ElfLoadResult, load_bias: u64) -> ElfLoadResult {
    result.entry = result.entry.saturating_add(load_bias);
    result.load_end = result.load_end.saturating_add(load_bias);
    result.brk_start = result.brk_start.saturating_add(load_bias);
    if result.tls_base != 0 {
        result.tls_base = result.tls_base.saturating_add(load_bias);
    }
    if result.phdr_addr != 0 {
        result.phdr_addr = result.phdr_addr.saturating_add(load_bias);
    }
    result.aux_entry = result.aux_entry.saturating_add(load_bias);
    if result.aux_phdr_addr != 0 {
        result.aux_phdr_addr = result.aux_phdr_addr.saturating_add(load_bias);
    }
    result.aux_base = load_bias;
    result
}

pub fn bias_load_result(result: ElfLoadResult, load_bias: u64) -> ElfLoadResult {
    apply_load_bias(result, load_bias)
}

pub fn main_executable_load_bias(main_elf: &ElfLoadResult, has_interp: bool) -> u64 {
    if has_interp && main_elf.is_dyn {
        0x1000
    } else {
        0
    }
}

pub fn interpreter_load_bias(main_brk_start: u64) -> u64 {
    align_up(main_brk_start, 0x1000)
}

pub fn preserve_main_executable_auxv(load_result: &mut ElfLoadResult, main_result: &ElfLoadResult) {
    load_result.aux_entry = main_result.entry;
    load_result.aux_phdr_addr = main_result.phdr_addr;
    load_result.aux_phent = main_result.phent;
    load_result.aux_phnum = main_result.phnum;
}

/// Keep process-image metadata sourced from the main executable even when
/// execution enters a PT_INTERP loader image first.
pub fn preserve_main_executable_process_image(
    load_result: &mut ElfLoadResult,
    main_result: &ElfLoadResult,
) {
    preserve_main_executable_auxv(load_result, main_result);
    if main_result.tls_base != 0 {
        load_result.tls_base = main_result.tls_base;
    }
}

pub fn zero_fill_load_padding(ram_base: u32, load_end: u64, brk_start: u64) {
    if brk_start <= load_end {
        return;
    }
    unsafe {
        guest_mem::zero_mem(ram_base, load_end, (brk_start - load_end) as usize);
    }
}

pub unsafe fn collect_load_segments(
    elf_ptr: u32,
    elf_len: u32,
    load_bias: u64,
) -> Result<Vec<ElfLoadSegment>, i32> {
    unsafe {
        let elf = core::slice::from_raw_parts(elf_ptr as *const u8, elf_len as usize);
        if elf.len() < 64 {
            return Err(-1);
        }
        if elf[0] != EI_MAG0 || elf[1] != EI_MAG1 || elf[2] != EI_MAG2 || elf[3] != EI_MAG3 {
            return Err(-1);
        }
        let ph_off = read_u64_le(elf, E_PHOFF).ok_or(-6)? as usize;
        let ph_entsize = read_u16_le(elf, E_PHENTSIZE).ok_or(-6)? as usize;
        let ph_num = read_u16_le(elf, E_PHNUM).ok_or(-6)? as usize;
        if ph_entsize < 56 {
            return Err(-6);
        }
        let ph_size = ph_num.checked_mul(ph_entsize).ok_or(-6)?;
        let ph_end = ph_off.checked_add(ph_size).ok_or(-6)?;
        if ph_end > elf.len() {
            return Err(-6);
        }

        let mut segments = Vec::new();
        for index in 0..ph_num {
            let start = ph_off + index * ph_entsize;
            let ph = &elf[start..start + ph_entsize];
            if read_u32_le(ph, P_TYPE) != Some(PT_LOAD) {
                continue;
            }
            let p_vaddr = read_u64_le(ph, P_VADDR).ok_or(-6)?;
            let p_memsz = read_u64_le(ph, P_MEMSZ).ok_or(-6)?;
            if p_memsz == 0 {
                continue;
            }
            let seg_start = p_vaddr.checked_add(load_bias).ok_or(-6)?;
            let seg_end = seg_start.checked_add(p_memsz).ok_or(-6)?;
            let flags = read_u32_le(ph, P_FLAGS).ok_or(-6)?;
            let mut prot = crate::abi::PROT_NONE;
            if (flags & PF_R) != 0 {
                prot |= crate::abi::PROT_READ;
            }
            if (flags & PF_W) != 0 {
                prot |= crate::abi::PROT_WRITE;
            }
            if (flags & PF_X) != 0 {
                prot |= crate::abi::PROT_EXEC;
            }
            segments.push(ElfLoadSegment {
                start: seg_start,
                end: seg_end,
                prot,
            });
        }
        Ok(segments)
    }
}

pub fn read_interp_path_bytes(elf: &[u8]) -> Result<Option<Vec<u8>>, i32> {
    if elf.len() < 64 {
        return Err(-1);
    }
    if elf[0] != EI_MAG0 || elf[1] != EI_MAG1 || elf[2] != EI_MAG2 || elf[3] != EI_MAG3 {
        return Err(-1);
    }
    if elf[EI_CLASS] != ELFCLASS64 {
        return Err(-2);
    }
    if elf[EI_DATA] != ELFDATA2LSB {
        return Err(-3);
    }

    let ph_off = read_u64_le(elf, E_PHOFF).ok_or(-6)? as usize;
    let ph_entsize = read_u16_le(elf, E_PHENTSIZE).ok_or(-6)? as usize;
    let ph_num = read_u16_le(elf, E_PHNUM).ok_or(-6)? as usize;
    if ph_entsize < 56 {
        return Err(-6);
    }
    let ph_size = ph_num.checked_mul(ph_entsize).ok_or(-6)?;
    let ph_end = ph_off.checked_add(ph_size).ok_or(-6)?;
    if ph_end > elf.len() {
        return Err(-6);
    }

    for index in 0..ph_num {
        let start = ph_off + index * ph_entsize;
        let ph = &elf[start..start + ph_entsize];
        if read_u32_le(ph, P_TYPE) != Some(PT_INTERP) {
            continue;
        }
        let p_offset = read_u64_le(ph, P_OFFSET).ok_or(-8)? as usize;
        let p_filesz = read_u64_le(ph, P_FILESZ).ok_or(-8)? as usize;
        let p_end = p_offset.checked_add(p_filesz).ok_or(-8)?;
        if p_filesz == 0 || p_end > elf.len() {
            return Err(-8);
        }
        let mut interp = elf[p_offset..p_end].to_vec();
        if let Some(nul) = interp.iter().position(|b| *b == 0) {
            interp.truncate(nul);
        }
        if interp.is_empty() {
            return Err(-8);
        }
        return Ok(Some(interp));
    }

    Ok(None)
}

/// Read the `PT_INTERP` path from an ELF image when present.
///
/// # Safety
/// `elf_ptr..elf_ptr+elf_len` must reference readable bytes in the current
/// WASM linear memory for the duration of the call.
pub unsafe fn read_interp_path(elf_ptr: u32, elf_len: u32) -> Result<Option<Vec<u8>>, i32> {
    let elf = unsafe { core::slice::from_raw_parts(elf_ptr as *const u8, elf_len as usize) };
    read_interp_path_bytes(elf)
}

/// Load an ELF image at the given guest RAM base using the provided load bias.
///
/// # Safety
/// `elf_ptr..elf_ptr+elf_len` must be readable, and `ram_base..ram_base+ram_size`
/// must be valid writable guest memory for every PT_LOAD segment selected.
pub unsafe fn load_elf_at(
    ram_base: u32,
    ram_size: u64,
    elf_ptr: u32,
    elf_len: u32,
    load_bias: u64,
) -> Result<ElfLoadResult, i32> {
    unsafe {
        crate::tracepoints::record_execve_stage(340, elf_ptr as u64, elf_len as u64);
        let inspected = inspect_elf(elf_ptr, elf_len, ram_size)?;
        let e = elf_ptr as *const u8;
        let ph_off = read_u64(e, E_PHOFF) as usize;
        let ph_entsize = read_u16(e, E_PHENTSIZE) as usize;
        let ph_num = read_u16(e, E_PHNUM) as usize;

        for i in 0..ph_num {
            let ph = e.add(ph_off + i * ph_entsize);
            let p_type = read_u32(ph, P_TYPE);

            if p_type != PT_LOAD {
                continue;
            }

            let p_offset = read_u64(ph, P_OFFSET);
            let p_vaddr = read_u64(ph, P_VADDR).saturating_add(load_bias);
            let p_filesz = read_u64(ph, P_FILESZ);
            let p_memsz = read_u64(ph, P_MEMSZ);
            crate::tracepoints::record_execve_stage(341, i as u64, p_vaddr);
            crate::tracepoints::record_execve_stage(342, p_offset, p_filesz);
            crate::tracepoints::record_execve_stage(343, p_memsz, load_bias);
            crate::tracepoints::record_execve_stage(347, i as u64, p_offset);

            // Copy file data to guest memory
            if p_filesz > 0 {
                let src = e.add(p_offset as usize);
                let dst = (ram_base as u64 + p_vaddr) as *mut u8;
                core::ptr::copy_nonoverlapping(src, dst, p_filesz as usize);
            }
            crate::tracepoints::record_execve_stage(344, i as u64, p_filesz);
            crate::tracepoints::record_execve_stage(348, i as u64, p_vaddr + p_filesz);

            // ELF PT_LOAD mappings expose zero-filled bytes from the end of the
            // file-backed data through the end of the mapped segment pages.
            // Fresh process memory masked this before, but execve reuses guest
            // memory, so we must actively clear the tail to avoid stale bytes
            // corrupting post-exec runtime metadata.
            let zero_start = p_vaddr.saturating_add(p_filesz);
            let zero_end = align_up(p_vaddr.saturating_add(p_memsz), 4096).min(ram_size);
            if zero_end > zero_start {
                guest_mem::zero_mem(ram_base, zero_start, (zero_end - zero_start) as usize);
            }
            crate::tracepoints::record_execve_stage(345, i as u64, p_memsz);
            crate::tracepoints::record_execve_stage(349, i as u64, p_vaddr + p_memsz);
        }

        crate::tracepoints::record_execve_stage(346, inspected.entry, inspected.brk_start);
        Ok(apply_load_bias(inspected, load_bias))
    }
}

/// Load an ELF image at load bias 0.
///
/// # Safety
/// Inherits the safety requirements of [`load_elf_at`].
pub unsafe fn load_elf(
    ram_base: u32,
    ram_size: u64,
    elf_ptr: u32,
    elf_len: u32,
) -> Result<ElfLoadResult, i32> {
    unsafe { load_elf_at(ram_base, ram_size, elf_ptr, elf_len, 0) }
}

fn align_up(value: u64, align: u64) -> u64 {
    if align == 0 {
        return value;
    }
    (value + align - 1) & !(align - 1)
}

/// Set up the initial stack for the loaded ELF.
/// Writes argc, argv pointers, envp pointers, auxv to the stack.
///
/// Returns the initial stack pointer (pointing to argc).
///
/// # Safety
/// `stack_top` must be a valid guest address with enough space below.
pub unsafe fn setup_stack(
    ram_base: u32,
    stack_top: u64,
    argv: &[u64], // pointers to arg strings in guest memory
    envp: &[u64], // pointers to env strings in guest memory
    elf_result: &ElfLoadResult,
    random_addr: u64, // 16 bytes of random data address
    execfn_addr: u64,
) -> u64 {
    unsafe {
        // Stack layout (grows downward):
        //   auxv entries (AT_NULL terminated)
        //   NULL (end of envp)
        //   envp[n-1] ... envp[0]
        //   NULL (end of argv)
        //   argv[argc-1] ... argv[0]
        //   argc

        let argc = argv.len();
        let envc = envp.len();

        // Auxiliary vector entries required by the current rv64gc userland
        // startup path.
        let auxv: [(u64, u64); 10] = [
            (AT_PAGESZ, 4096),
            (AT_PHDR, elf_result.aux_phdr_addr),
            (AT_PHENT, elf_result.aux_phent as u64),
            (AT_PHNUM, elf_result.aux_phnum as u64),
            (AT_BASE, elf_result.aux_base),
            (AT_ENTRY, elf_result.aux_entry),
            (AT_HWCAP, 0x112D),
            (AT_CLKTCK, 100),
            (AT_RANDOM, random_addr),
            (AT_EXECFN, execfn_addr),
        ];

        // Calculate total size needed
        let auxv_size = (auxv.len() + 1) * 16; // +1 for AT_NULL
        let total_entries = 1 + argc + 1 + envc + 1; // argc + argv + NULL + envp + NULL
        let total_size = total_entries * 8 + auxv_size;

        // Align stack to 16 bytes
        let sp = (stack_top - total_size as u64) & !15;
        let mut pos = sp;

        // argc
        guest_mem::write_u64(ram_base, pos, argc as u64);
        pos += 8;

        // argv pointers
        for &arg in argv {
            guest_mem::write_u64(ram_base, pos, arg);
            pos += 8;
        }
        guest_mem::write_u64(ram_base, pos, 0); // NULL terminator
        pos += 8;

        // envp pointers
        for &env in envp {
            guest_mem::write_u64(ram_base, pos, env);
            pos += 8;
        }
        guest_mem::write_u64(ram_base, pos, 0); // NULL terminator
        pos += 8;

        // auxv
        for &(a_type, a_val) in &auxv {
            guest_mem::write_u64(ram_base, pos, a_type);
            guest_mem::write_u64(ram_base, pos + 8, a_val);
            pos += 16;
        }
        // AT_NULL
        guest_mem::write_u64(ram_base, pos, AT_NULL);
        guest_mem::write_u64(ram_base, pos + 8, 0);

        sp
    }
}

// =============================================================================
// ELF reading helpers (little-endian)
// =============================================================================

#[inline(always)]
unsafe fn read_u16(base: *const u8, off: usize) -> u16 {
    unsafe { (base.add(off) as *const u16).read_unaligned() }
}

#[inline(always)]
unsafe fn read_u32(base: *const u8, off: usize) -> u32 {
    unsafe { (base.add(off) as *const u32).read_unaligned() }
}

#[inline(always)]
unsafe fn read_u64(base: *const u8, off: usize) -> u64 {
    unsafe { (base.add(off) as *const u64).read_unaligned() }
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset + 2)
        .and_then(|slice| <[u8; 2]>::try_from(slice).ok())
        .map(u16::from_le_bytes)
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)
        .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
        .map(u32::from_le_bytes)
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes
        .get(offset..offset + 8)
        .and_then(|slice| <[u8; 8]>::try_from(slice).ok())
        .map(u64::from_le_bytes)
}
