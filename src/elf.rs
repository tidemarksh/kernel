//! ELF loader for statically-linked RISC-V 64-bit executables.
//!
//! Reference: ELF spec (https://refspecs.linuxfoundation.org/elf/elf.pdf)
//!            RISC-V ELF psABI (https://github.com/riscv-non-isa/riscv-elf-psabi-doc)
//!
//! Supports: ET_EXEC (static), RV64, little-endian.
//! Does not support: dynamic linking, relocations, shared objects.

use crate::guest_mem;

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
const EM_RISCV: u16 = 243;
const PT_LOAD: u32 = 1;

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
pub const AT_ENTRY: u64 = 9;
pub const AT_RANDOM: u64 = 25;

/// Result of loading an ELF binary.
pub struct ElfLoadResult {
    /// Entry point address (e_entry)
    pub entry: u64,
    /// Highest loaded address + 1 (for brk initialization)
    pub brk_start: u64,
    /// Program header table address in guest memory (for AT_PHDR)
    pub phdr_addr: u64,
    /// Size of one program header entry
    pub phent: u16,
    /// Number of program header entries
    pub phnum: u16,
}

/// Load an ELF binary from `elf_data` (byte slice in WASM memory at `elf_ptr`)
/// into guest RAM at `ram_base`.
///
/// Returns entry point and metadata, or -1 on error.
///
/// # Safety
/// `ram_base` must point to valid guest memory. `elf_ptr` must contain a valid ELF.
pub unsafe fn load_elf(
    ram_base: u32,
    ram_size: u64,
    elf_ptr: u32,
    elf_len: u32,
) -> Result<ElfLoadResult, i32> {
    unsafe {
        if elf_len < 64 {
            return Err(-1); // too small for ELF header
        }

        // --- Validate ELF header ---
        let e = elf_ptr as *const u8;

        // Magic number
        if *e.add(0) != EI_MAG0 || *e.add(1) != EI_MAG1
            || *e.add(2) != EI_MAG2 || *e.add(3) != EI_MAG3 {
            return Err(-1);
        }

        // Class: 64-bit
        if *e.add(EI_CLASS) != ELFCLASS64 {
            return Err(-2);
        }

        // Endianness: little-endian
        if *e.add(EI_DATA) != ELFDATA2LSB {
            return Err(-3);
        }

        // Type: executable
        let e_type = read_u16(e, E_TYPE);
        if e_type != ET_EXEC {
            return Err(-4);
        }

        // Machine: RISC-V
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

        // --- Load PT_LOAD segments ---
        let mut brk_end: u64 = 0;
        let mut phdr_addr: u64 = 0;

        for i in 0..ph_num {
            let ph = e.add(ph_off + i * ph_entsize);
            let p_type = read_u32(ph, P_TYPE);

            if p_type != PT_LOAD {
                continue;
            }

            let p_offset = read_u64(ph, P_OFFSET);
            let p_vaddr = read_u64(ph, P_VADDR);
            let p_filesz = read_u64(ph, P_FILESZ);
            let p_memsz = read_u64(ph, P_MEMSZ);

            // Bounds check
            if p_vaddr + p_memsz > ram_size {
                return Err(-7); // segment out of bounds
            }
            if p_offset + p_filesz > elf_len as u64 {
                return Err(-8); // file data out of bounds
            }

            // Copy file data to guest memory
            if p_filesz > 0 {
                let src = e.add(p_offset as usize);
                let dst = (ram_base as u64 + p_vaddr) as *mut u8;
                core::ptr::copy_nonoverlapping(src, dst, p_filesz as usize);
            }

            // Zero BSS (memsz > filesz)
            if p_memsz > p_filesz {
                let bss_start = p_vaddr + p_filesz;
                let bss_len = (p_memsz - p_filesz) as usize;
                guest_mem::zero_mem(ram_base, bss_start, bss_len);
            }

            // Track highest address for brk
            let seg_end = p_vaddr + p_memsz;
            if seg_end > brk_end {
                brk_end = seg_end;
            }

            // Record first LOAD segment for phdr (heuristic: usually first segment contains phdrs)
            if i == 0 {
                phdr_addr = p_vaddr + ph_off as u64;
            }
        }

        // Align brk to page boundary
        brk_end = (brk_end + 4095) & !4095;

        Ok(ElfLoadResult {
            entry,
            brk_start: brk_end,
            phdr_addr,
            phent: ph_entsize as u16,
            phnum: ph_num as u16,
        })
    }
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
    argv: &[u64],     // pointers to arg strings in guest memory
    envp: &[u64],     // pointers to env strings in guest memory
    elf_result: &ElfLoadResult,
    random_addr: u64,  // 16 bytes of random data address
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

        // Auxiliary vector entries
        let auxv: [(u64, u64); 6] = [
            (AT_PAGESZ, 4096),
            (AT_PHDR, elf_result.phdr_addr),
            (AT_PHENT, elf_result.phent as u64),
            (AT_PHNUM, elf_result.phnum as u64),
            (AT_ENTRY, elf_result.entry),
            (AT_RANDOM, random_addr),
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
