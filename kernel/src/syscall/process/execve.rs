use super::common::{ECHILD, ESRCH};
use super::handoff::{clear_spawn_handoff, set_spawn_handoff};
use super::lifecycle::{clear_wait4_state, ensure_current_process, ensure_process};
use super::runtime::prs;
use crate::abi::*;
use crate::fs::{fd_table, memfs};
use crate::guest_mem;
use crate::types::{FdEntry, ProcessState, THREAD_RUNNING, ThreadRecord, ThreadState};
use alloc_crate::{format, vec, vec::Vec};

pub const EXECVE_GUEST_MEMORY_LIMIT: u64 = 0x8000_0000;
const EXECVE_PATH_MAX: usize = 4096;
const EXECVE_NAME_MAX: usize = 255;
const EXECVE_PREFLIGHT_ELF_PREFIX_MAX: usize = 64 * 1024;
const EXECVE_BACKING_FILL_CHUNK: usize = 4 * 1024 * 1024;
const EXECVE_SCRIPT_RECURSION_LIMIT: usize = 4;
pub(crate) const PROC_SELF_EXE_SNAPSHOT_MAX: usize = 512;

struct ExecveFileReadCache {
    vm_ptr: u32,
    ino: u32,
    read_len: u32,
    expected_size: u32,
    filled: u32,
    bytes: Vec<u8>,
}

struct ExecveImage {
    path_bytes: Vec<u8>,
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
    main_bytes: ExecveFileBytes,
    main_bias: u64,
    main_elf: crate::elf::ElfLoadResult,
    interp_bytes: Option<ExecveFileBytes>,
    interp_bias: u64,
    interp_elf: Option<crate::elf::ElfLoadResult>,
}

struct ExecveFileBytes {
    owned: Vec<u8>,
}

static mut EXECVE_PREFIX_READ_CACHE: Option<ExecveFileReadCache> = None;
static mut EXECVE_FILE_READ_CACHE: Option<ExecveFileReadCache> = None;
static mut EXECVE_INTERP_FILE_READ_CACHE: Option<ExecveFileReadCache> = None;

impl ExecveFileBytes {
    fn from_owned(bytes: Vec<u8>) -> Self {
        Self { owned: bytes }
    }

    fn as_slice(&self) -> &[u8] {
        self.owned.as_slice()
    }
}

fn set_execve_backing_miss(vm_ptr: u32, ino: u32, offset: u64, len: u32, expected_size: u32) {
    unsafe {
        let vm = &mut *(vm_ptr as *mut ThreadState);
        vm.execve_backing_miss_ino = ino;
        vm.execve_backing_miss_offset = offset;
        vm.execve_backing_miss_len = len;
        vm.execve_backing_miss_expected_size = expected_size;
    }
}

pub fn clear_execve_backing_miss(vm_ptr: u32) {
    unsafe {
        let vm = &mut *(vm_ptr as *mut ThreadState);
        vm.execve_backing_miss_ino = 0;
        vm.execve_backing_miss_offset = 0;
        vm.execve_backing_miss_len = 0;
        vm.execve_backing_miss_expected_size = 0;
    }
}

fn clear_execve_file_cache(cache_slot: *mut Option<ExecveFileReadCache>, vm_ptr: u32) {
    unsafe {
        if (*cache_slot)
            .as_ref()
            .is_some_and(|cache| cache.vm_ptr == vm_ptr)
        {
            *cache_slot = None;
        }
    }
}

pub fn clear_execve_backing_state(vm_ptr: u32) {
    clear_execve_backing_miss(vm_ptr);
    clear_execve_file_cache(core::ptr::addr_of_mut!(EXECVE_PREFIX_READ_CACHE), vm_ptr);
    clear_execve_file_cache(core::ptr::addr_of_mut!(EXECVE_FILE_READ_CACHE), vm_ptr);
    clear_execve_file_cache(
        core::ptr::addr_of_mut!(EXECVE_INTERP_FILE_READ_CACHE),
        vm_ptr,
    );
}

pub fn execve_backing_miss_ino(vm_ptr: u32) -> u32 {
    unsafe { (*(vm_ptr as *const ThreadState)).execve_backing_miss_ino }
}

pub fn execve_backing_miss_offset(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const ThreadState)).execve_backing_miss_offset }
}

pub fn execve_backing_miss_len(vm_ptr: u32) -> u32 {
    unsafe { (*(vm_ptr as *const ThreadState)).execve_backing_miss_len }
}

pub fn execve_backing_miss_expected_size(vm_ptr: u32) -> u32 {
    unsafe { (*(vm_ptr as *const ThreadState)).execve_backing_miss_expected_size }
}

fn read_execve_file_bytes_cached(
    cache_slot: *mut Option<ExecveFileReadCache>,
    vm_ptr: u32,
    ino: u32,
    read_len: u32,
    expected_size: u32,
) -> Result<Vec<u8>, i64> {
    unsafe {
        let reset_cache = !(*cache_slot).as_ref().is_some_and(|cache| {
            cache.vm_ptr == vm_ptr
                && cache.ino == ino
                && cache.read_len == read_len
                && cache.expected_size == expected_size
        });
        if reset_cache {
            *cache_slot = Some(ExecveFileReadCache {
                vm_ptr,
                ino,
                read_len,
                expected_size,
                filled: 0,
                bytes: vec![0u8; read_len as usize],
            });
        }

        let cache = (*cache_slot).as_mut().ok_or(ENOMEM)?;
        while cache.filled < cache.read_len {
            let offset = cache.filled;
            let chunk_len = (cache.read_len - offset).min(EXECVE_BACKING_FILL_CHUNK as u32);
            let start = offset as usize;
            let end = start + chunk_len as usize;
            let read = memfs::read_file(ino, offset as u64, &mut cache.bytes[start..end]);
            if read == chunk_len as i64 {
                cache.filled += chunk_len;
                continue;
            }
            set_execve_backing_miss(vm_ptr, ino, offset as u64, chunk_len, expected_size);
            return Err(EAGAIN);
        }

        Ok(cache.bytes.clone())
    }
}

fn current_cwd_ino(vm: &ThreadState, base: u32) -> u32 {
    let cwd_off = core::mem::offset_of!(ProcessState, cwd_ino) as u64;
    let cwd = unsafe { guest_mem::read_u32(base, vm.process_ptr as u64 + cwd_off) };
    if cwd == 0 { 1 } else { cwd }
}

fn current_effective_uid(vm: &ThreadState) -> u32 {
    vm.euid
}

fn current_effective_gid(vm: &ThreadState) -> u32 {
    vm.egid
}

fn stat_execve_regular_executable(vm: &ThreadState, ino: u32) -> Result<memfs::InodeStat, i64> {
    let st = match memfs::stat(ino) {
        Some(st) => st,
        None => return Err(ENOENT),
    };
    if st.mode & memfs::S_IFMT != memfs::S_IFREG {
        return Err(EACCES);
    }
    let exec_mask = if current_effective_uid(vm) == 0 {
        st.mode & 0o111
    } else if current_effective_uid(vm) == st.uid {
        st.mode & 0o100
    } else if current_effective_gid(vm) == st.gid {
        st.mode & 0o010
    } else {
        st.mode & 0o001
    };
    if exec_mask == 0 {
        return Err(EACCES);
    }
    if fd_table::inode_has_write_open(ino) {
        return Err(ETXTBSY);
    }
    Ok(st)
}

fn read_guest_cstr_bytes(base: u32, addr: u64) -> Result<Vec<u8>, i64> {
    if addr == 0 {
        return Err(EFAULT);
    }

    let guest_limit = crate::wasm::memory_size_bytes().saturating_sub(base as u64);
    if addr >= guest_limit {
        return Err(EFAULT);
    }

    let mut out = Vec::new();
    let mut offset = 0u64;
    loop {
        let Some(cur) = addr.checked_add(offset) else {
            return Err(EFAULT);
        };
        if cur >= guest_limit {
            return Err(EFAULT);
        }
        if crate::syscall::memory::range_has_prot_none(cur, 1) {
            return Err(EFAULT);
        }

        let byte = unsafe { guest_mem::read_u8(base, cur) };
        if byte == 0 {
            break;
        }
        out.push(byte);
        if out.len() > EXECVE_PATH_MAX {
            return Err(ENAMETOOLONG);
        }
        offset += 1;
    }

    Ok(out)
}

fn read_guest_nonempty_cstr_bytes(base: u32, addr: u64) -> Result<Vec<u8>, i64> {
    let out = read_guest_cstr_bytes(base, addr)?;
    if out.is_empty() {
        return Err(ENOENT);
    }
    Ok(out)
}

fn resolve_execve_inode(
    vm: &ThreadState,
    base: u32,
    path_addr: u64,
) -> Result<(u32, Vec<u8>), i64> {
    let path = read_guest_nonempty_cstr_bytes(base, path_addr)?;
    let mut ino = if path.first() == Some(&b'/') {
        1
    } else {
        current_cwd_ino(vm, base)
    };

    let components = if path.first() == Some(&b'/') {
        &path[1..]
    } else {
        &path[..]
    };
    for component in components.split(|&b| b == b'/') {
        if component.is_empty() || component == b"." {
            continue;
        }
        if component.len() > EXECVE_NAME_MAX {
            return Err(ENAMETOOLONG);
        }
        let parent = match memfs::stat(ino) {
            Some(parent) => parent,
            None => return Err(ENOENT),
        };
        if parent.mode & memfs::S_IFMT != memfs::S_IFDIR {
            return Err(ENOTDIR);
        }
        ino = memfs::lookup(ino, component);
        if ino == 0 {
            return Err(ENOENT);
        }
    }

    let mut absolute = [0u8; 1024];
    let absolute_len = memfs::write_path(ino, &mut absolute);
    if absolute_len != 0 {
        Ok((ino, absolute[..absolute_len].to_vec()))
    } else {
        Ok((ino, path))
    }
}

fn read_guest_strvec(base: u32, vec_addr: u64) -> Result<Vec<Vec<u8>>, i64> {
    let mut out = Vec::new();
    if vec_addr == 0 {
        return Ok(out);
    }

    let mut idx = 0u64;
    loop {
        let Some(slot_offset) = idx.checked_mul(8) else {
            return Err(EFAULT);
        };
        let Some(slot_addr) = vec_addr.checked_add(slot_offset) else {
            return Err(EFAULT);
        };
        if !crate::syscall::memory::guest_range_accessible(base, slot_addr, 8) {
            return Err(EFAULT);
        }
        let ptr = unsafe { guest_mem::read_u64(base, slot_addr) };
        if ptr == 0 {
            break;
        }
        let mut bytes = read_guest_cstr_bytes(base, ptr)?;
        bytes.push(0);
        out.push(bytes);
        idx += 1;
    }
    Ok(out)
}

fn read_execve_elf_image_bytes_with_cache(
    cache_slot: *mut Option<ExecveFileReadCache>,
    vm_ptr: u32,
    ino: u32,
    elf_len: u32,
) -> Result<ExecveFileBytes, i64> {
    crate::tracepoints::record_execve_stage(
        105,
        crate::alloc::heap_base() as u64,
        crate::alloc::heap_ptr() as u64,
    );
    crate::tracepoints::record_execve_dispatch(vm_ptr, 1244);
    let prefix = read_execve_elf_prefix(vm_ptr, ino, elf_len)?;
    if prefix.starts_with(b"#!") {
        crate::tracepoints::record_execve_stage(110, prefix.len() as u64, elf_len as u64);
        return Ok(ExecveFileBytes::from_owned(prefix));
    }
    let required_len = match crate::elf::required_exec_image_file_len_bytes(&prefix, elf_len as u64)
    {
        Ok(required_len) => required_len,
        Err(_) => {
            crate::tracepoints::record_execve_stage(110, prefix.len() as u64, elf_len as u64);
            return Ok(ExecveFileBytes::from_owned(prefix));
        }
    };
    crate::tracepoints::record_execve_stage(110, required_len, elf_len as u64);
    if required_len <= prefix.len() as u64 {
        return Ok(ExecveFileBytes::from_owned(prefix));
    }
    let required_len = u32::try_from(required_len).map_err(|_| ENOEXEC)?;
    let elf_bytes = read_execve_file_bytes_cached(cache_slot, vm_ptr, ino, required_len, elf_len)?;
    crate::tracepoints::record_execve_stage(
        106,
        elf_bytes.as_ptr() as u64,
        crate::alloc::heap_ptr() as u64,
    );
    crate::tracepoints::record_execve_dispatch(vm_ptr, 1245);
    crate::tracepoints::record_execve_stage(109, ino as u64, memfs::debug_file_data_layout(ino));
    crate::tracepoints::record_execve_dispatch(vm_ptr, 1246);
    Ok(ExecveFileBytes::from_owned(elf_bytes))
}

fn read_execve_elf_image_bytes(
    vm_ptr: u32,
    ino: u32,
    elf_len: u32,
) -> Result<ExecveFileBytes, i64> {
    read_execve_elf_image_bytes_with_cache(
        core::ptr::addr_of_mut!(EXECVE_FILE_READ_CACHE),
        vm_ptr,
        ino,
        elf_len,
    )
}

fn read_execve_interp_elf_image_bytes(
    vm_ptr: u32,
    ino: u32,
    elf_len: u32,
) -> Result<ExecveFileBytes, i64> {
    read_execve_elf_image_bytes_with_cache(
        core::ptr::addr_of_mut!(EXECVE_INTERP_FILE_READ_CACHE),
        vm_ptr,
        ino,
        elf_len,
    )
}

fn read_execve_elf_metadata_or_image_bytes(
    vm_ptr: u32,
    ino: u32,
    elf_len: u32,
) -> Result<ExecveFileBytes, i64> {
    let prefix = read_execve_elf_prefix(vm_ptr, ino, elf_len)?;
    if prefix.starts_with(b"#!") {
        crate::tracepoints::record_execve_stage(110, prefix.len() as u64, elf_len as u64);
        return Ok(ExecveFileBytes::from_owned(prefix));
    }
    if crate::elf::required_exec_image_file_len_bytes(&prefix, elf_len as u64).is_err() {
        crate::tracepoints::record_execve_stage(110, prefix.len() as u64, elf_len as u64);
        return Ok(ExecveFileBytes::from_owned(prefix));
    }
    if matches!(crate::elf::read_interp_path_bytes(&prefix), Ok(Some(_))) {
        crate::tracepoints::record_execve_stage(111, prefix.len() as u64, elf_len as u64);
        return Ok(ExecveFileBytes::from_owned(prefix));
    }
    read_execve_elf_image_bytes(vm_ptr, ino, elf_len)
}

fn read_execve_elf_prefix(vm_ptr: u32, ino: u32, elf_len: u32) -> Result<Vec<u8>, i64> {
    let prefix_len = (elf_len as usize).min(EXECVE_PREFLIGHT_ELF_PREFIX_MAX) as u32;
    read_execve_file_bytes_cached(
        core::ptr::addr_of_mut!(EXECVE_PREFIX_READ_CACHE),
        vm_ptr,
        ino,
        prefix_len,
        elf_len,
    )
}

fn parse_interpreter_script_header(
    file_bytes: &[u8],
) -> Result<Option<(Vec<u8>, Option<Vec<u8>>)>, i64> {
    if !file_bytes.starts_with(b"#!") {
        return Ok(None);
    }

    let line_end = file_bytes
        .iter()
        .position(|b| *b == b'\n')
        .unwrap_or(file_bytes.len());
    let mut line = &file_bytes[2..line_end];
    if let Some(stripped) = line.strip_suffix(b"\r") {
        line = stripped;
    }
    line = line.trim_ascii_start();
    if line.is_empty() {
        return Err(ENOEXEC);
    }

    let interp_end = line
        .iter()
        .position(|b| *b == b' ' || *b == b'\t')
        .unwrap_or(line.len());
    if interp_end == 0 {
        return Err(ENOEXEC);
    }
    let interp_path = line[..interp_end].to_vec();
    let optional_arg = line[interp_end..].trim_ascii();
    if optional_arg.is_empty() {
        Ok(Some((interp_path, None)))
    } else {
        Ok(Some((interp_path, Some(optional_arg.to_vec()))))
    }
}

fn validate_execve_file_for_preflight(
    vm: &ThreadState,
    base: u32,
    ino: u32,
    guest_limit: u64,
) -> Result<(), i64> {
    validate_execve_file_for_preflight_inner(vm, base, ino, guest_limit, 0)
}

fn validate_execve_file_for_preflight_inner(
    vm: &ThreadState,
    base: u32,
    ino: u32,
    guest_limit: u64,
    script_depth: usize,
) -> Result<(), i64> {
    let st = stat_execve_regular_executable(vm, ino)?;
    let elf_len = match u32::try_from(st.size) {
        Ok(len) if len > 0 => len,
        _ => return Err(ENOEXEC),
    };
    let vm_ptr = vm as *const ThreadState as u32;
    let prefix = read_execve_elf_prefix(vm_ptr, ino, elf_len)?;
    if let Some((interp_path, _optional_arg)) = parse_interpreter_script_header(&prefix)? {
        if script_depth >= EXECVE_SCRIPT_RECURSION_LIMIT {
            return Err(ELOOP);
        }
        let interp_ino = memfs::resolve_path_following_symlinks_with_errno(&interp_path)?;
        validate_execve_file_for_preflight_inner(
            vm,
            base,
            interp_ino,
            guest_limit,
            script_depth + 1,
        )
    } else {
        crate::elf::inspect_elf_metadata_bytes(&prefix, st.size, guest_limit)
            .map(|_| ())
            .map_err(|_| {
                crate::tracepoints::record_execve_stage(183, ino as u64, prefix.len() as u64);
                ENOEXEC
            })
    }
}

fn validate_vfork_execve_preflight(
    vm: &ThreadState,
    base: u32,
    path_addr: u64,
    argv_addr: u64,
    envp_addr: u64,
    guest_limit: u64,
) -> Result<(), i64> {
    let (ino, _path_bytes) = resolve_execve_inode(vm, base, path_addr)?;
    let _argv = read_guest_strvec(base, argv_addr)?;
    let _envp = read_guest_strvec(base, envp_addr)?;
    validate_execve_file_for_preflight(vm, base, ino, guest_limit)
}

fn inspect_execve_elf_bytes(
    elf_bytes: &[u8],
    guest_limit: u64,
) -> Result<crate::elf::ElfLoadResult, i64> {
    let file_head0 = elf_bytes
        .iter()
        .take(8)
        .enumerate()
        .fold(0u64, |acc, (idx, byte)| acc | ((*byte as u64) << (idx * 8)));
    let file_head1 = elf_bytes
        .iter()
        .skip(8)
        .take(8)
        .enumerate()
        .fold(0u64, |acc, (idx, byte)| acc | ((*byte as u64) << (idx * 8)));
    match crate::elf::inspect_elf_bytes(elf_bytes, guest_limit) {
        Ok(result) => Ok(result),
        Err(error) => {
            crate::tracepoints::record_execve_stage(
                180,
                error as i64 as u64,
                elf_bytes.len() as u64,
            );
            crate::tracepoints::record_execve_stage(181, file_head0, file_head1);
            Err(ENOEXEC)
        }
    }
}

fn inspect_execve_elf_metadata_bytes(
    elf_bytes: &[u8],
    file_len: u64,
    guest_limit: u64,
) -> Result<crate::elf::ElfLoadResult, i64> {
    let file_head0 = elf_bytes
        .iter()
        .take(8)
        .enumerate()
        .fold(0u64, |acc, (idx, byte)| acc | ((*byte as u64) << (idx * 8)));
    let file_head1 = elf_bytes
        .iter()
        .skip(8)
        .take(8)
        .enumerate()
        .fold(0u64, |acc, (idx, byte)| acc | ((*byte as u64) << (idx * 8)));
    match crate::elf::inspect_elf_metadata_bytes(elf_bytes, file_len, guest_limit) {
        Ok(result) => Ok(result),
        Err(error) => {
            crate::tracepoints::record_execve_stage(
                180,
                error as i64 as u64,
                elf_bytes.len() as u64,
            );
            crate::tracepoints::record_execve_stage(181, file_head0, file_head1);
            Err(ENOEXEC)
        }
    }
}

fn load_execve_elf_bytes_at(
    base: u32,
    guest_limit: u64,
    elf_bytes: &ExecveFileBytes,
    load_bias: u64,
) -> Result<crate::elf::ElfLoadResult, i64> {
    let bytes = elf_bytes.as_slice();
    crate::tracepoints::record_execve_stage(330, bytes.as_ptr() as u64, bytes.len() as u64);
    unsafe {
        crate::elf::load_elf_bytes_at(base, guest_limit, bytes, load_bias).map_err(|_| ENOEXEC)
    }
}

fn load_execve_image(
    vm: &ThreadState,
    base: u32,
    path_addr: u64,
    argv_addr: u64,
    envp_addr: u64,
    guest_limit: u64,
) -> Result<ExecveImage, i64> {
    let vm_ptr = vm as *const ThreadState as u32;
    crate::tracepoints::record_execve_dispatch(vm_ptr, 123);
    let (ino, path_bytes) = resolve_execve_inode(vm, base, path_addr)?;
    crate::tracepoints::record_execve_dispatch(vm_ptr, 124);
    let st = stat_execve_regular_executable(vm, ino)?;
    let elf_len = match u32::try_from(st.size) {
        Ok(len) if len > 0 => len,
        _ => return Err(ENOEXEC),
    };
    crate::tracepoints::record_execve_stage(101, argv_addr, envp_addr);
    crate::tracepoints::record_execve_stage(
        104,
        vm.process_ptr as u64 + core::mem::offset_of!(ProcessState, pid) as u64,
        argv_addr,
    );
    let argv = read_guest_strvec(base, argv_addr)?;
    crate::tracepoints::record_execve_dispatch(vm_ptr, 126);
    crate::tracepoints::record_execve_stage(102, argv.len() as u64, argv_addr);
    let envp = read_guest_strvec(base, envp_addr)?;
    crate::tracepoints::record_execve_dispatch(vm_ptr, 127);
    crate::tracepoints::record_execve_stage(103, envp.len() as u64, envp_addr);
    crate::tracepoints::record_execve_stage(107, st.size, elf_len as u64);
    let file_bytes = read_execve_elf_metadata_or_image_bytes(vm_ptr, ino, elf_len)?;
    crate::tracepoints::record_execve_dispatch(vm_ptr, 125);
    let file_head0 = file_bytes
        .as_slice()
        .iter()
        .take(8)
        .enumerate()
        .fold(0u64, |acc, (idx, byte)| acc | ((*byte as u64) << (idx * 8)));
    let file_head1 = file_bytes
        .as_slice()
        .iter()
        .skip(8)
        .take(8)
        .enumerate()
        .fold(0u64, |acc, (idx, byte)| acc | ((*byte as u64) << (idx * 8)));
    crate::tracepoints::record_execve_stage(108, file_head0, file_head1);
    let mut path_bytes = path_bytes;
    let mut main_bytes = file_bytes;
    let mut main_ino = ino;
    let mut main_len = elf_len;
    let mut argv = argv;
    for script_depth in 0..=EXECVE_SCRIPT_RECURSION_LIMIT {
        let Some((interp_path, optional_arg)) =
            parse_interpreter_script_header(main_bytes.as_slice())?
        else {
            break;
        };
        if script_depth >= EXECVE_SCRIPT_RECURSION_LIMIT {
            return Err(ELOOP);
        }
        let interp_ino = memfs::resolve_path_following_symlinks_with_errno(&interp_path)?;
        let interp_st = stat_execve_regular_executable(vm, interp_ino)?;
        let interp_len = u32::try_from(interp_st.size).map_err(|_| ENOEXEC)?;
        if interp_len == 0 {
            return Err(ENOEXEC);
        }
        let interp_bytes = read_execve_elf_metadata_or_image_bytes(vm_ptr, interp_ino, interp_len)?;
        let mut rewritten_argv = Vec::new();
        let mut interp_argv0 = interp_path.clone();
        interp_argv0.push(0);
        rewritten_argv.push(interp_argv0);
        if let Some(mut arg) = optional_arg {
            arg.push(0);
            rewritten_argv.push(arg);
        }
        let mut script_argv = path_bytes.clone();
        script_argv.push(0);
        rewritten_argv.push(script_argv);
        for arg in argv.into_iter().skip(1) {
            rewritten_argv.push(arg);
        }
        path_bytes = interp_path;
        main_bytes = interp_bytes;
        main_ino = interp_ino;
        main_len = interp_len;
        argv = rewritten_argv;
    }
    crate::tracepoints::record_execve_dispatch(vm_ptr, 128);
    let mut elf =
        inspect_execve_elf_metadata_bytes(main_bytes.as_slice(), main_len as u64, guest_limit)?;
    let interp_path = match crate::elf::read_interp_path_bytes(main_bytes.as_slice()) {
        Ok(path) => path,
        Err(error) => {
            crate::tracepoints::record_execve_stage(
                182,
                error as i64 as u64,
                main_bytes.as_slice().len() as u64,
            );
            return Err(ENOEXEC);
        }
    };
    let main_bias = crate::elf::main_executable_load_bias(&elf, interp_path.is_some());
    if main_bias != 0 {
        elf = crate::elf::bias_load_result(elf, main_bias);
    }
    crate::tracepoints::record_execve_dispatch(vm_ptr, 129);
    let (interp_bytes, interp_bias, interp_elf) = match interp_path {
        Some(interp_path) => {
            let interp_ino = memfs::resolve_path_following_symlinks_with_errno(&interp_path)?;
            let interp_st = memfs::stat(interp_ino).ok_or(ENOENT)?;
            if interp_st.mode & memfs::S_IFMT != memfs::S_IFREG {
                return Err(EACCES);
            }
            let interp_len = u32::try_from(interp_st.size).map_err(|_| ENOEXEC)?;
            if interp_len == 0 {
                return Err(ENOEXEC);
            }
            let interp_bytes = read_execve_interp_elf_image_bytes(vm_ptr, interp_ino, interp_len)?;
            let mut interp_elf = inspect_execve_elf_bytes(interp_bytes.as_slice(), guest_limit)?;
            let interp_bias = crate::elf::interpreter_load_bias(elf.brk_start);
            interp_elf = crate::elf::bias_load_result(interp_elf, interp_bias);
            crate::elf::preserve_main_executable_process_image(&mut interp_elf, &elf);
            (Some(interp_bytes), interp_bias, Some(interp_elf))
        }
        None => (None, 0, None),
    };
    if interp_bytes.is_some() {
        main_bytes = read_execve_elf_image_bytes(vm_ptr, main_ino, main_len)?;
    }
    crate::tracepoints::record_execve_dispatch(vm_ptr, 130);
    if argv.is_empty() {
        // Linux fills in a dummy argv[0] when execve() is called with an
        // empty argument vector, so post-exec user space never sees argc == 0.
        argv.push(vec![0]);
    }

    Ok(ExecveImage {
        path_bytes,
        argv,
        envp,
        main_bytes,
        main_bias,
        main_elf: elf,
        interp_bytes,
        interp_bias,
        interp_elf,
    })
}

fn proc_self_dir_ino(create_missing: bool) -> u32 {
    let proc_ino = memfs::resolve_path(b"/proc");
    let proc_ino = if proc_ino == 0 && create_missing {
        memfs::create_dir(1, b"proc", 0o555)
    } else {
        proc_ino
    };
    crate::tracepoints::record_execve_stage(712, proc_ino as u64, 0);
    if proc_ino == 0 {
        return 0;
    }

    let self_ino = memfs::resolve_path(b"/proc/self");
    let self_ino = if self_ino == 0 && create_missing {
        memfs::create_dir(proc_ino, b"self", 0o555)
    } else {
        self_ino
    };
    crate::tracepoints::record_execve_stage(713, self_ino as u64, 0);
    self_ino
}

fn replace_proc_self_exe(target: Option<&[u8]>) {
    crate::tracepoints::record_execve_stage(711, target.map_or(0, |bytes| bytes.len()) as u64, 0);
    let self_ino = proc_self_dir_ino(target.is_some());
    if self_ino == 0 {
        return;
    }

    let existing_exe = memfs::lookup(self_ino, b"exe");
    crate::tracepoints::record_execve_stage(714, existing_exe as u64, self_ino as u64);
    if existing_exe != 0 {
        if let Some(target) = target {
            if memfs::replace_symlink_target(existing_exe, target) == 0 {
                return;
            }
        }
        let _ = memfs::unlink(self_ino, b"exe");
    }

    if let Some(target) = target {
        crate::tracepoints::record_execve_stage(715, self_ino as u64, target.len() as u64);
        let exe_ino = memfs::create_symlink(self_ino, b"exe", target);
        crate::tracepoints::record_execve_stage(716, exe_ino as u64, 0);
    }
}

fn ensure_proc_self_fd_dir(self_ino: u32) {
    if self_ino == 0 || memfs::lookup(self_ino, b"fd") != 0 {
        return;
    }
    let _ = memfs::create_dir(self_ino, b"fd", 0o555);
}

fn install_proc_self_exe(target: &[u8]) {
    replace_proc_self_exe(Some(target));
}

pub(crate) fn snapshot_proc_self_exe_target(out: &mut [u8; PROC_SELF_EXE_SNAPSHOT_MAX]) -> usize {
    let ino = memfs::resolve_path(b"/proc/self/exe");
    if ino == 0 {
        return 0;
    }
    memfs::read_link(ino, out).min(PROC_SELF_EXE_SNAPSHOT_MAX)
}

pub(crate) fn restore_proc_self_exe_target(target: Option<&[u8]>) {
    replace_proc_self_exe(target);
}

const PROC_STAT_BYTES: &[u8] = b"cpu  1 1 1 1 0 0 0 0 0 0\ncpu0 1 1 1 1 0 0 0 0 0 0\n";
const PROC_CPUINFO_BYTES: &[u8] =
    b"processor\t: 0\nmodel name\t: tidemark-riscv64\nmmu\t\t: sv48\n\n";
const PROC_SYS_KERNEL_NGROUPS_MAX_BYTES: &[u8] = b"65536\n";

fn proc_meminfo_snapshot(guest_memory_policy_limit: u64) -> Vec<u8> {
    let total_bytes =
        crate::syscall::identity::sysinfo_totalram_bytes_for_policy(guest_memory_policy_limit);
    let free_bytes = crate::syscall::identity::sysinfo_freeram_bytes(total_bytes);
    let total_kib = total_bytes / 1024;
    let free_kib = free_bytes / 1024;
    format!(
        "MemTotal: {total_kib} kB\nMemFree: {free_kib} kB\nMemAvailable: {free_kib} kB\nCached: 0 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n"
    )
    .into_bytes()
}

fn ensure_proc_child_dir(parent_ino: u32, name: &[u8], mode: u32) -> u32 {
    if parent_ino == 0 {
        return 0;
    }
    let existing = memfs::lookup(parent_ino, name);
    if existing != 0 {
        return existing;
    }
    memfs::create_dir(parent_ino, name, mode)
}

fn replace_proc_file(proc_ino: u32, name: &[u8], data: &[u8]) {
    let existing = memfs::lookup(proc_ino, name);
    if existing != 0 {
        if memfs::truncate(existing, 0) == 0
            && memfs::write_file(existing, 0, data) == data.len() as i64
        {
            return;
        }
        let _ = memfs::unlink(proc_ino, name);
    }
    let _ = memfs::create_file_with_data(proc_ino, name, data);
}

pub fn install_procfs_snapshot(exe_target: &[u8], guest_memory_policy_limit: u64) {
    install_proc_self_exe(exe_target);

    let proc_ino = memfs::resolve_path(b"/proc");
    if proc_ino == 0 {
        return;
    }
    let self_ino = memfs::resolve_path(b"/proc/self");
    if self_ino == 0 {
        return;
    }
    ensure_proc_self_fd_dir(self_ino);
    replace_proc_file(proc_ino, b"stat", PROC_STAT_BYTES);
    replace_proc_file(proc_ino, b"cpuinfo", PROC_CPUINFO_BYTES);
    replace_proc_file(
        proc_ino,
        b"meminfo",
        &proc_meminfo_snapshot(guest_memory_policy_limit),
    );
    let sys_ino = ensure_proc_child_dir(proc_ino, b"sys", 0o555);
    let kernel_ino = ensure_proc_child_dir(sys_ino, b"kernel", 0o555);
    replace_proc_file(
        kernel_ino,
        b"ngroups_max",
        PROC_SYS_KERNEL_NGROUPS_MAX_BYTES,
    );
    replace_proc_file(
        self_ino,
        b"maps",
        &crate::syscall::memory::proc_self_maps_snapshot(),
    );
}

fn write_stack_strings(base: u32, start: u64, strings: &[Vec<u8>], addrs: &mut [u64]) {
    let mut cursor = start;
    for (idx, bytes) in strings.iter().enumerate() {
        unsafe {
            guest_mem::write_bytes(base, cursor, bytes);
        }
        addrs[idx] = cursor;
        cursor += bytes.len() as u64;
    }
}

fn stack_string_bytes_total(strings: &[Vec<u8>]) -> u64 {
    strings.iter().map(|bytes| bytes.len() as u64).sum()
}

fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

fn validate_execve_initial_stack(
    base: u32,
    sp: u64,
    argv: &[Vec<u8>],
    envp: &[Vec<u8>],
) -> Result<(), i64> {
    let argc = unsafe { guest_mem::read_u64(base, sp) };
    if argc != argv.len() as u64 {
        crate::tracepoints::record_execve_stage(901, argc, argv.len() as u64);
        return Err(EINVAL);
    }

    for (index, expected) in argv.iter().enumerate() {
        let ptr = unsafe { guest_mem::read_u64(base, sp + 8 + index as u64 * 8) };
        if ptr == 0 {
            crate::tracepoints::record_execve_stage(902, index as u64, 0);
            return Err(EINVAL);
        }
        let mut actual = read_guest_cstr_bytes(base, ptr)?;
        actual.push(0);
        if actual != *expected {
            crate::tracepoints::record_execve_stage(903, index as u64, ptr);
            crate::tracepoints::record_execve_stage(
                904,
                expected.len() as u64,
                actual.len() as u64,
            );
            return Err(EINVAL);
        }
    }

    let argv_null = unsafe { guest_mem::read_u64(base, sp + 8 + argv.len() as u64 * 8) };
    if argv_null != 0 {
        crate::tracepoints::record_execve_stage(905, argv.len() as u64, argv_null);
        return Err(EINVAL);
    }

    let env_base = sp + 8 + (argv.len() as u64 + 1) * 8;
    for (index, expected) in envp.iter().enumerate() {
        let ptr = unsafe { guest_mem::read_u64(base, env_base + index as u64 * 8) };
        if ptr == 0 {
            crate::tracepoints::record_execve_stage(906, index as u64, 0);
            return Err(EINVAL);
        }
        let mut actual = read_guest_cstr_bytes(base, ptr)?;
        actual.push(0);
        if actual != *expected {
            crate::tracepoints::record_execve_stage(907, index as u64, ptr);
            crate::tracepoints::record_execve_stage(
                908,
                expected.len() as u64,
                actual.len() as u64,
            );
            return Err(EINVAL);
        }
    }

    let env_null = unsafe { guest_mem::read_u64(base, env_base + envp.len() as u64 * 8) };
    if env_null != 0 {
        crate::tracepoints::record_execve_stage(909, envp.len() as u64, env_null);
        return Err(EINVAL);
    }

    Ok(())
}

fn current_guest_memory_limit(base: u32) -> u64 {
    let heap_base = crate::alloc::heap_base() as u64;
    let limit = if heap_base > base as u64 {
        heap_base - base as u64
    } else {
        crate::wasm::memory_size_bytes().saturating_sub(base as u64)
    };
    limit.min(max_execve_guest_memory_limit(base))
}

fn execve_guest_limit(base: u32, brk_start: u64, stack_size: u64, guest_limit: u64) -> u64 {
    const EXECVE_STACK_HEADROOM: u64 = 64 * 1024 * 1024;
    let max_limit = if guest_limit != 0 {
        guest_limit.min(max_execve_guest_memory_limit(base))
    } else {
        max_execve_guest_memory_limit(base)
    };
    let current_limit = current_guest_memory_limit(base);
    let usable_stack = ((stack_size.max(64 * 1024) + 4095) & !4095).saturating_add(4096);
    let required_limit = brk_start
        .saturating_add(usable_stack)
        .saturating_add(EXECVE_STACK_HEADROOM);
    let rounded_limit = (required_limit + 0xF_FFFF) & !0xF_FFFF;
    current_limit.max(rounded_limit).min(max_limit)
}

#[allow(clippy::too_many_arguments)]
fn install_execve_process_state(
    vm: &mut ThreadState,
    vm_ptr: u32,
    base: u32,
    ps_addr: u64,
    pid: i32,
    ppid: i32,
    cwd_ino: u32,
    stdin_pipe_slot: u32,
    stdout_pipe_slot: u32,
    stderr_pipe_slot: u32,
    tty_pty_slot: u32,
    fs_ring_base: u32,
    umask: u32,
    fd_table: &[FdEntry; MAX_FDS],
) {
    let ps_size = core::mem::size_of::<ProcessState>() as u64;
    unsafe {
        guest_mem::zero_mem(base, ps_addr, ps_size as usize);
    }
    let ps = unsafe { &mut *((base as u64 + ps_addr) as *mut ProcessState) };
    let gen_ptr = core::ptr::addr_of!(ps.reservation_gen) as *const core::sync::atomic::AtomicU32;
    let lock_ptr = core::ptr::addr_of!(ps.reservation_lock) as *const core::sync::atomic::AtomicU32;
    let tc_ptr = core::ptr::addr_of!(ps.thread_count);
    unsafe {
        guest_mem::init(gen_ptr, lock_ptr, tc_ptr);
    }
    ps.pid = pid;
    ps.ppid = ppid;
    ps.cwd_ino = cwd_ino;
    ps.stdin_pipe_slot = stdin_pipe_slot;
    ps.stdout_pipe_slot = stdout_pipe_slot;
    ps.stderr_pipe_slot = stderr_pipe_slot;
    ps.tty_pty_slot = tty_pty_slot;
    ps.fs_ring_base = fs_ring_base;
    ps.umask = umask;
    ps.fd_table.copy_from_slice(fd_table);
    ps.thread_count
        .store(1, core::sync::atomic::Ordering::Release);
    ps.threads[0] = ThreadRecord::new(1, THREAD_RUNNING, vm_ptr, vm.clear_child_tid, 0);
    vm.process_ptr = ps_addr as u32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::TestVm;

    #[test]
    fn repeated_procfs_snapshot_updates_preserve_inode_identity() {
        let _t = TestVm::new();

        install_procfs_snapshot(b"/bin/first", 64 * 1024 * 1024);
        let initial_count = memfs::memfs_inode_count();
        let initial_exe = memfs::resolve_path(b"/proc/self/exe");
        let initial_stat = memfs::resolve_path(b"/proc/stat");
        let initial_meminfo = memfs::resolve_path(b"/proc/meminfo");

        install_procfs_snapshot(b"/bin/second-longer", 128 * 1024 * 1024);

        assert_eq!(memfs::memfs_inode_count(), initial_count);
        assert_eq!(memfs::resolve_path(b"/proc/self/exe"), initial_exe);
        assert_eq!(memfs::resolve_path(b"/proc/stat"), initial_stat);
        assert_eq!(memfs::resolve_path(b"/proc/meminfo"), initial_meminfo);
        let mut target = [0u8; 64];
        let target_len = memfs::read_link(initial_exe, &mut target);
        assert_eq!(&target[..target_len], b"/bin/second-longer");
    }

    #[test]
    fn execve_guest_limit_respects_explicit_guest_policy_limit() {
        let limit = execve_guest_limit(
            0,
            0x83000,
            crate::syscall::memory::DEFAULT_STACK_SIZE,
            16 * 1024 * 1024,
        );

        assert_eq!(limit, 16 * 1024 * 1024);
    }

    #[test]
    fn execve_guest_limit_treats_large_guest_limit_as_cap_not_allocation_target() {
        let limit = execve_guest_limit(
            0,
            0x83000,
            crate::syscall::memory::DEFAULT_STACK_SIZE,
            896 * 1024 * 1024,
        );

        assert!(limit < 896 * 1024 * 1024);
        assert!(limit >= 72 * 1024 * 1024);
    }
}

fn complete_execve_in_place_inner(
    vm: &mut ThreadState,
    base: u32,
    guest_limit: u64,
    flush_shared_mappings: bool,
    reset_fs_ring: bool,
) -> i64 {
    let vm_ptr = vm as *mut ThreadState as u32;
    if vm.spawn_kind != SPAWN_KIND_EXECVE {
        return EINVAL;
    }
    crate::tracepoints::record_execve_stage(1, base as u64, guest_limit);
    crate::tracepoints::record_execve_stage(
        100,
        vm.process_ptr as u64 + core::mem::offset_of!(ProcessState, pid) as u64,
        vm.spawn_argv,
    );
    crate::tracepoints::record_execve_dispatch(vm_ptr, 121);

    let ps_addr = vm.process_ptr as u64;
    let old_pid = unsafe {
        guest_mem::read_i32(
            base,
            ps_addr + core::mem::offset_of!(ProcessState, pid) as u64,
        )
    };
    let old_ppid = unsafe {
        guest_mem::read_i32(
            base,
            ps_addr + core::mem::offset_of!(ProcessState, ppid) as u64,
        )
    };
    let old_cwd = unsafe {
        guest_mem::read_u32(
            base,
            ps_addr + core::mem::offset_of!(ProcessState, cwd_ino) as u64,
        )
    };
    let old_stdin_pipe_slot = unsafe {
        guest_mem::read_u32(
            base,
            ps_addr + core::mem::offset_of!(ProcessState, stdin_pipe_slot) as u64,
        )
    };
    let old_stdout_pipe_slot = unsafe {
        guest_mem::read_u32(
            base,
            ps_addr + core::mem::offset_of!(ProcessState, stdout_pipe_slot) as u64,
        )
    };
    let old_stderr_pipe_slot = unsafe {
        guest_mem::read_u32(
            base,
            ps_addr + core::mem::offset_of!(ProcessState, stderr_pipe_slot) as u64,
        )
    };
    let old_tty_pty_slot = unsafe {
        guest_mem::read_u32(
            base,
            ps_addr + core::mem::offset_of!(ProcessState, tty_pty_slot) as u64,
        )
    };
    let old_fs_ring_base = unsafe {
        guest_mem::read_u32(
            base,
            ps_addr + core::mem::offset_of!(ProcessState, fs_ring_base) as u64,
        )
    };
    let old_umask = unsafe {
        guest_mem::read_u32(
            base,
            ps_addr + core::mem::offset_of!(ProcessState, umask) as u64,
        )
    };
    let mut old_fd_table = [FdEntry {
        ofd_id: 0,
        fd_flags: 0,
    }; MAX_FDS];
    for (idx, entry) in old_fd_table.iter_mut().enumerate() {
        *entry = fd_table::load_process_fd_entry(base, ps_addr as u32, idx);
    }
    let target_pid = if vm.spawn_child_pid != 0 {
        vm.spawn_child_pid
    } else {
        old_pid
    };
    if target_pid <= 0 {
        return EINVAL;
    }
    let target_ppid = if target_pid != old_pid {
        old_pid
    } else {
        old_ppid
    };
    crate::tracepoints::record_execve_dispatch(vm_ptr, 1221);

    let mut inherited_fds = [FdEntry {
        ofd_id: 0,
        fd_flags: 0,
    }; MAX_FDS];
    for (idx, entry) in old_fd_table.iter().copied().enumerate() {
        if entry.ofd_id == 0 {
            continue;
        }
        if entry.fd_flags & fd_table::FD_CLOEXEC != 0 {
            continue;
        }
        inherited_fds[idx] = entry;
    }

    let ExecveImage {
        path_bytes,
        argv,
        envp,
        main_bytes,
        main_bias,
        main_elf,
        interp_bytes,
        interp_bias,
        interp_elf,
    } = match load_execve_image(
        vm,
        base,
        vm.spawn_path,
        vm.spawn_argv,
        vm.spawn_envp,
        guest_limit,
    ) {
        Ok(image) => image,
        Err(errno) => return errno,
    };
    crate::tracepoints::record_execve_dispatch(vm_ptr, 122);
    let load_brk_start = main_elf
        .brk_start
        .max(interp_elf.as_ref().map(|elf| elf.brk_start).unwrap_or(0));
    let active_elf = interp_elf.as_ref().copied().unwrap_or(main_elf);
    crate::tracepoints::record_execve_stage(2, load_brk_start, active_elf.entry);

    fd_table::clear_blocked_ofd_pin(vm);

    let mut argv_ptrs = vec![0u64; argv.len()];
    let mut envp_ptrs = vec![0u64; envp.len()];
    crate::tracepoints::record_execve_dispatch(vm_ptr, 1222);
    let guest_limit = execve_guest_limit(
        base,
        load_brk_start,
        crate::syscall::memory::DEFAULT_STACK_SIZE,
        guest_limit,
    );

    let ps_size = core::mem::size_of::<ProcessState>() as u64;
    let ps_align = core::mem::align_of::<ProcessState>() as u64;
    let new_ps_addr = (load_brk_start + ps_align - 1) & !(ps_align - 1);
    let hidden_end = new_ps_addr + ps_size;
    let public_brk = crate::syscall::memory::user_brk_start_after_hidden_prefix(hidden_end);
    crate::tracepoints::record_execve_stage(3, guest_limit, new_ps_addr + ps_size);
    if !crate::syscall::memory::ensure_guest_memory_capacity(base, hidden_end) {
        crate::tracepoints::record_execve_stage(11, guest_limit, new_ps_addr + ps_size);
        return ENOMEM;
    }
    crate::tracepoints::record_execve_dispatch(vm_ptr, 1223);
    crate::tracepoints::record_execve_stage(31, guest_limit, new_ps_addr + ps_size);

    crate::syscall::thread::discard_other_threads_for_exec(vm, base);
    guest_mem::init_single_threaded();
    crate::tracepoints::record_execve_stage(32, target_pid as u64, target_ppid as u64);
    crate::syscall::memory::reset_for_execve_with_flush(
        base,
        load_brk_start,
        flush_shared_mappings,
    );
    if crate::syscall::memory::grow_brk(base, public_brk) < public_brk as i64 {
        crate::tracepoints::record_execve_stage(13, load_brk_start, hidden_end);
        return ENOMEM;
    }
    crate::syscall::memory::rebase_brk_after_hidden_prefix(hidden_end);
    install_execve_process_state(
        vm,
        vm_ptr,
        base,
        new_ps_addr,
        target_pid,
        target_ppid,
        old_cwd,
        old_stdin_pipe_slot,
        old_stdout_pipe_slot,
        old_stderr_pipe_slot,
        old_tty_pty_slot,
        old_fs_ring_base,
        old_umask,
        &old_fd_table,
    );
    crate::tracepoints::record_execve_dispatch(vm_ptr, 1224);
    crate::tracepoints::record_execve_stage(33, load_brk_start, flush_shared_mappings as u64);
    let main_result = match load_execve_elf_bytes_at(base, guest_limit, &main_bytes, main_bias) {
        Ok(result) => result,
        Err(errno) => return errno,
    };
    crate::tracepoints::record_execve_dispatch(vm_ptr, 1225);
    crate::tracepoints::record_execve_stage(34, main_result.entry, main_result.brk_start);
    let mut elf_result = match interp_bytes.as_ref() {
        Some(interp_bytes) => {
            match load_execve_elf_bytes_at(base, guest_limit, interp_bytes, interp_bias) {
                Ok(result) => result,
                Err(errno) => return errno,
            }
        }
        None => main_result,
    };
    crate::tracepoints::record_execve_dispatch(vm_ptr, 1226);
    crate::tracepoints::record_execve_stage(35, elf_result.entry, elf_result.brk_start);
    if interp_bytes.is_some() {
        crate::elf::preserve_main_executable_process_image(&mut elf_result, &main_result);
    }
    let loaded_end = main_result
        .load_end
        .max(interp_elf.map(|elf| elf.load_end).unwrap_or(0));
    crate::elf::zero_fill_load_padding(base, loaded_end, load_brk_start);
    elf_result.brk_start = load_brk_start;
    let main_bytes_slice = main_bytes.as_slice();
    let main_segments = crate::elf::collect_load_segments_bytes(main_bytes_slice, main_bias);
    let Ok(main_segments) = main_segments else {
        crate::tracepoints::record_execve_stage(
            184,
            main_bytes_slice.as_ptr() as u64,
            main_bytes_slice.len() as u64,
        );
        return ENOEXEC;
    };
    for segment in main_segments {
        crate::syscall::memory::register_elf_load_segment(segment.start, segment.end, segment.prot);
    }
    if let Some(interp_bytes) = interp_bytes.as_ref() {
        let interp_bytes_slice = interp_bytes.as_slice();
        let interp_segments =
            crate::elf::collect_load_segments_bytes(interp_bytes_slice, interp_bias);
        let Ok(interp_segments) = interp_segments else {
            crate::tracepoints::record_execve_stage(
                185,
                interp_bytes_slice.as_ptr() as u64,
                interp_bytes_slice.len() as u64,
            );
            return ENOEXEC;
        };
        for segment in interp_segments {
            crate::syscall::memory::register_elf_load_segment(
                segment.start,
                segment.end,
                segment.prot,
            );
        }
    }
    crate::tracepoints::record_execve_stage(4, elf_result.brk_start, elf_result.entry);
    let stack_top = crate::syscall::memory::map_initial_stack(
        base,
        guest_limit,
        crate::syscall::memory::DEFAULT_STACK_SIZE,
    );
    if stack_top < 0 {
        crate::tracepoints::record_execve_stage(12, guest_limit, stack_top as u64);
        return ENOMEM;
    }
    let stack_top = stack_top as u64;
    crate::tracepoints::record_execve_dispatch(vm_ptr, 1227);
    crate::tracepoints::record_execve_stage(5, guest_limit, stack_top);

    let brk = crate::syscall::memory::current_brk();
    if crate::syscall::memory::grow_brk(base, public_brk) < public_brk as i64 {
        crate::tracepoints::record_execve_stage(13, brk, hidden_end);
        return ENOMEM;
    }
    crate::tracepoints::record_execve_dispatch(vm_ptr, 1228);
    crate::tracepoints::record_execve_stage(6, brk, hidden_end);
    crate::tracepoints::record_execve_stage(61, new_ps_addr, ps_size);
    crate::tracepoints::record_execve_dispatch(vm_ptr, 1229);
    crate::syscall::memory::rebase_brk_after_hidden_prefix(hidden_end);
    crate::tracepoints::record_execve_stage(62, new_ps_addr, ps_size);

    for entry in old_fd_table.iter().copied() {
        if entry.ofd_id == 0
            || entry.ofd_id as usize >= MAX_FDS
            || entry.fd_flags & fd_table::FD_CLOEXEC == 0
        {
            continue;
        }
        // https://man7.org/linux/man-pages/man2/execve.2.html closes
        // FD_CLOEXEC descriptors as part of a successful exec. The backend
        // endpoint must be released too so pipes observe EOF/EPIPE correctly.
        fd_table::release_ofd_id(entry.ofd_id);
    }

    let vm = unsafe { &mut *(vm_ptr as *mut ThreadState) };
    crate::tracepoints::record_execve_dispatch(vm_ptr, 131);
    install_execve_process_state(
        vm,
        vm_ptr,
        base,
        new_ps_addr,
        target_pid,
        target_ppid,
        old_cwd,
        old_stdin_pipe_slot,
        old_stdout_pipe_slot,
        old_stderr_pipe_slot,
        old_tty_pty_slot,
        old_fs_ring_base,
        old_umask,
        &inherited_fds,
    );
    crate::tracepoints::record_execve_dispatch(vm_ptr, 132);
    crate::tracepoints::record_execve_stage(63, new_ps_addr, inherited_fds.len() as u64);
    let pid_off = core::mem::offset_of!(ProcessState, pid) as u64;
    let fs_ring_off = core::mem::offset_of!(ProcessState, fs_ring_base) as u64;
    crate::tracepoints::record_execve_dispatch(vm_ptr, 133);
    crate::tracepoints::record_execve_stage(64, new_ps_addr + pid_off, new_ps_addr + fs_ring_off);

    let random_addr = stack_top.saturating_sub(16);
    crate::tracepoints::record_execve_stage(65, stack_top, random_addr);
    unsafe {
        guest_mem::write_bytes(base, random_addr, &[0x42u8; 16]);
    }
    let string_bytes = stack_string_bytes_total(&argv) + stack_string_bytes_total(&envp);
    let strings_end = stack_top.saturating_sub(128);
    let strings_start = align_down(strings_end.saturating_sub(string_bytes), 16);
    let stack_setup_top = strings_start.saturating_sub(128);
    let cursor = {
        write_stack_strings(base, strings_start, &argv, &mut argv_ptrs);
        crate::tracepoints::record_execve_stage(66, strings_start, argv.len() as u64);
        let argv_bytes_end = strings_start.saturating_add(stack_string_bytes_total(&argv));
        write_stack_strings(base, argv_bytes_end, &envp, &mut envp_ptrs);
        argv_bytes_end
    };
    crate::tracepoints::record_execve_stage(67, cursor, envp.len() as u64);
    let mut stack_elf = active_elf;
    stack_elf.entry = elf_result.entry;
    stack_elf.brk_start = elf_result.brk_start;
    stack_elf.tls_base = elf_result.tls_base;
    stack_elf.phdr_addr = elf_result.phdr_addr;
    stack_elf.phent = elf_result.phent;
    stack_elf.phnum = elf_result.phnum;
    stack_elf.aux_entry = elf_result.aux_entry;
    stack_elf.aux_phdr_addr = elf_result.aux_phdr_addr;
    stack_elf.aux_phent = elf_result.aux_phent;
    stack_elf.aux_phnum = elf_result.aux_phnum;
    stack_elf.aux_base = elf_result.aux_base;
    let sp = unsafe {
        crate::elf::setup_stack(
            base,
            stack_setup_top,
            &argv_ptrs,
            &envp_ptrs,
            &stack_elf,
            random_addr,
            argv_ptrs[0],
        )
    };
    crate::tracepoints::record_execve_stage(68, sp, stack_setup_top);
    if let Err(errno) = validate_execve_initial_stack(base, sp, &argv, &envp) {
        return errno;
    }

    vm.x = [0; 32];
    vm.pc = elf_result.entry;
    vm.x[2] = sp;
    vm.x[4] = elf_result.tls_base;
    vm.f = [0; 32];
    vm.fcsr = 0;
    vm.status = STATUS_OK;
    vm.exit_code = 0;
    // ThreadState::tid is process-local; ProcessState::pid carries getpid().
    vm.tid = 1;
    vm.tls_base = elf_result.tls_base;
    vm.sigaltstack_sp = 0;
    vm.sigaltstack_size = 0;
    vm.sigaltstack_flags = crate::syscall::signal::SS_DISABLE;
    vm.clear_child_tid = 0;
    vm.robust_list_head = 0;
    vm.robust_list_len = 0;
    vm.sig_info_code = 0;
    vm.term_signal = 0;
    vm.lr_addr = u64::MAX;
    vm.lr_val = 0;
    vm.lr_gen = 0;
    vm.lr_gen_end = 0;
    vm.insn_budget = 0;
    vm.fault_pc = 0;
    vm.fault_addr = 0;
    vm.clone_flags = 0;
    vm.clone_child_stack = 0;
    vm.clone_tls = 0;
    vm.clone_child_tidptr = 0;
    vm.clone_child_tid = 0;
    vm.clone_pending = 0;
    vm.futex_wait_addr = 0;
    vm.futex_wait_timeout = 0;
    vm.futex_wait_expected = 0;
    vm.futex_wait_bitset = 0;
    vm.futex_wait_absolute = 0;
    vm.futex_wait_flags = 0;
    vm.epoll_timeout_ms = 0;
    vm.socket_timeout_ms = -1;
    vm.epoll_maxevents = 0;
    vm.blocked_fd = 0;
    vm.blocked_ofd_id = 0;
    vm.blocked_syscall_nr = 0;
    vm.blocked_syscall_args = [0; 6];
    vm.completed_sync_effects = 0;
    vm.completed_pipe_sync_slots = 0;
    vm.completed_pipe_sync_read_slots = 0;
    vm.completed_pipe_sync_write_slots = 0;
    vm.completed_pipe_sync_control_slots = 0;
    vm.completed_pipe_fresh_slots = 0;
    vm.completed_pipe_read_guest_ptr = 0;
    vm.completed_pipe_read_len = 0;
    vm.block_cache_ptr = 0;
    vm.jit_state_ptr = 0;
    vm.execve_backing_miss_ino = 0;
    vm.execve_backing_miss_len = 0;
    vm.execve_backing_miss_offset = 0;
    vm.execve_backing_miss_expected_size = 0;
    clear_wait4_state(vm);
    clear_spawn_handoff(vm);
    crate::tracepoints::record_execve_stage(69, vm.pc, vm.x[2]);

    crate::syscall::thread::init_main_thread(vm as *mut ThreadState as u32, base);
    crate::tracepoints::record_execve_dispatch(vm_ptr, 134);
    crate::tracepoints::record_execve_stage(70, vm.pc, vm.x[2]);
    crate::syscall::signal::reset_on_execve(target_pid);
    crate::tracepoints::record_execve_dispatch(vm_ptr, 135);
    crate::tracepoints::record_execve_stage(71, target_pid as u64, 0);
    if flush_shared_mappings {
        install_procfs_snapshot(&path_bytes, vm.guest_memory_policy_limit);
        crate::tracepoints::record_execve_stage(72, path_bytes.len() as u64, 0);
    }
    if let Some(slot) = ensure_process(target_pid, target_ppid) {
        slot.did_exec = true;
    }
    if reset_fs_ring {
        crate::fs::ring_buffer::reset(old_fs_ring_base);
    }
    crate::tracepoints::record_execve_stage(73, target_pid as u64, target_ppid as u64);

    crate::tracepoints::record_execve_dispatch(vm_ptr, 136);
    crate::tracepoints::record_execve_stage(7, vm.pc, vm.x[2]);
    0
}

fn effective_execve_guest_memory_limit(vm: &ThreadState, base: u32) -> u64 {
    if vm.guest_memory_policy_limit != 0 {
        return vm
            .guest_memory_policy_limit
            .min(max_execve_guest_memory_limit(base));
    }
    current_guest_memory_limit(base)
}

pub fn complete_execve_in_place(vm: &mut ThreadState, base: u32, guest_limit: u64) -> i64 {
    complete_execve_in_place_inner(vm, base, guest_limit, true, false)
}

pub fn complete_execve_in_place_from_handoff(
    vm: &mut ThreadState,
    base: u32,
    guest_limit: u64,
) -> i64 {
    complete_execve_in_place_inner(vm, base, guest_limit, true, true)
}

/// execve: replace process image.
/// Normal execve completes in place inside the current ThreadState.
/// vfork+execve exports `STATUS_EXECVE_SPAWN` so TS can create the post-exec child Worker.
/// https://man7.org/linux/man-pages/man2/execve.2.html
pub fn sys_execve(
    vm: &mut ThreadState,
    base: u32,
    path_addr: u64,
    argv_addr: u64,
    envp_addr: u64,
) -> i64 {
    let mut trace_path_buf = [0u8; EXECVE_NAME_MAX + 1];
    let trace_path_len = unsafe { guest_mem::read_cstr(base, path_addr, &mut trace_path_buf) };
    let trace_path = &trace_path_buf[..trace_path_len];
    crate::tracepoints::record_execve_stage(0, 0, 0);
    crate::tracepoints::record_execve_stage(
        99,
        vm.process_ptr as u64 + core::mem::offset_of!(ProcessState, pid) as u64,
        argv_addr,
    );
    let current_pid = match ensure_current_process(vm, base) {
        Some(slot) => slot.pid,
        None => {
            crate::tracepoints::record_path_syscall(
                vm as *mut ThreadState as u32,
                SYS_EXECVE,
                -100,
                trace_path,
                ESRCH,
                STATUS_OK,
            );
            return ESRCH;
        }
    };
    crate::tracepoints::record_execve_dispatch(vm as *const ThreadState as u32, 11);
    let is_vfork_exec = prs().vfork_active != 0;
    let execve_guest_limit = effective_execve_guest_memory_limit(vm, base);

    if is_vfork_exec {
        if let Err(errno) = validate_vfork_execve_preflight(
            vm,
            base,
            path_addr,
            argv_addr,
            envp_addr,
            execve_guest_limit,
        ) {
            crate::tracepoints::record_execve_error(errno);
            crate::tracepoints::record_path_syscall(
                vm as *mut ThreadState as u32,
                SYS_EXECVE,
                -100,
                trace_path,
                errno,
                STATUS_OK,
            );
            return errno;
        }
        let child_pid = prs().vfork_snapshot.child_pid;
        if child_pid <= 0 {
            crate::tracepoints::record_path_syscall(
                vm as *mut ThreadState as u32,
                SYS_EXECVE,
                -100,
                trace_path,
                ECHILD,
                STATUS_OK,
            );
            return ECHILD;
        }
        install_procfs_snapshot(trace_path, vm.guest_memory_policy_limit);
        crate::syscall::signal::reset_on_execve(child_pid);
        set_spawn_handoff(
            vm,
            SPAWN_KIND_EXECVE,
            child_pid,
            path_addr,
            argv_addr,
            envp_addr,
        );

        vm.x[10] = path_addr;
        vm.x[11] = argv_addr;
        vm.x[12] = envp_addr;
        vm.x[13] = child_pid as u64;
        vm.status = STATUS_EXECVE_SPAWN;
        crate::tracepoints::record_path_syscall(
            vm as *mut ThreadState as u32,
            SYS_EXECVE,
            -100,
            trace_path,
            child_pid as i64,
            STATUS_EXECVE_SPAWN,
        );
        return child_pid as i64;
    }

    crate::tracepoints::record_execve_dispatch(vm as *const ThreadState as u32, 12);
    set_spawn_handoff(
        vm,
        SPAWN_KIND_EXECVE,
        current_pid,
        path_addr,
        argv_addr,
        envp_addr,
    );
    crate::tracepoints::record_execve_dispatch(vm as *const ThreadState as u32, 13);
    let ret = complete_execve_in_place(vm, base, execve_guest_limit);
    crate::tracepoints::record_execve_dispatch(vm as *const ThreadState as u32, 14);
    if ret < 0 {
        crate::tracepoints::record_execve_error(ret);
        clear_spawn_handoff(vm);
    }
    crate::tracepoints::record_path_syscall(
        vm as *mut ThreadState as u32,
        SYS_EXECVE,
        -100,
        trace_path,
        ret,
        vm.status,
    );
    ret
}

/// execveat: execute a pathname relative to a directory file descriptor.
/// This supports the Linux-compatible case used by libc execv wrappers:
/// AT_FDCWD with no flags is identical to execve.
pub fn sys_execveat(
    vm: &mut ThreadState,
    base: u32,
    dirfd: u64,
    path_addr: u64,
    argv_addr: u64,
    envp_addr: u64,
    flags: u64,
) -> i64 {
    const AT_FDCWD_I64: i64 = -100;
    const AT_FDCWD_U32: u64 = (-100i32 as u32) as u64;

    let trace_path = read_guest_cstr_bytes(base, path_addr).unwrap_or_default();
    let record_failure = |vm: &mut ThreadState, result: i64| {
        crate::tracepoints::record_path_syscall(
            vm as *mut ThreadState as u32,
            SYS_EXECVEAT,
            dirfd as i64,
            &trace_path,
            result,
            STATUS_OK,
        );
        result
    };

    if flags != 0 {
        return record_failure(vm, EINVAL);
    }
    let is_at_fdcwd = dirfd as i64 == AT_FDCWD_I64 || dirfd == AT_FDCWD_U32;
    let is_absolute = trace_path.first() == Some(&b'/');
    if !is_at_fdcwd && !is_absolute {
        return record_failure(vm, ENOSYS);
    }

    sys_execve(vm, base, path_addr, argv_addr, envp_addr)
}

pub fn max_execve_guest_memory_limit(base: u32) -> u64 {
    crate::abi::max_guest_window_for_base(base)
}
