use tidemark_kernel_tests::{ltp_gate, support};

unsafe extern "C" {
    fn debug_clear_syscall_trace();
    fn debug_syscall_trace_len() -> u32;
    fn debug_syscall_trace_entry_vm_ptr(index: u32) -> u32;
    fn debug_syscall_trace_entry_nr(index: u32) -> u64;
    fn debug_syscall_trace_entry_result(index: u32) -> i64;
    fn debug_syscall_trace_entry_status(index: u32) -> i32;
    fn debug_path_syscall_trace_len() -> u32;
    fn debug_path_syscall_trace_vm_ptr(index: u32) -> u32;
    fn debug_path_syscall_trace_nr(index: u32) -> u64;
    fn debug_path_syscall_trace_dirfd(index: u32) -> i64;
    fn debug_path_syscall_trace_result(index: u32) -> i64;
    fn debug_path_syscall_trace_status(index: u32) -> i32;
    fn debug_path_syscall_trace_path_ptr(index: u32) -> u32;
    fn debug_path_syscall_trace_path_len(index: u32) -> u32;
    fn debug_thread_count_trace_len() -> u32;
    fn debug_thread_count_trace_kind(index: u32) -> u32;
    fn debug_thread_count_trace_vm_ptr(index: u32) -> u32;
    fn debug_thread_count_trace_tid(index: u32) -> i32;
    fn debug_thread_count_trace_process_ptr(index: u32) -> u32;
    fn debug_thread_count_trace_before(index: u32) -> u32;
    fn debug_thread_count_trace_after(index: u32) -> u32;
}

fn syscall_trace_dump() -> String {
    let len = unsafe { debug_syscall_trace_len() };
    if len == 0 {
        return "syscall_trace=<empty>".to_string();
    }
    let start = 0;
    let mut parts = Vec::new();
    for idx in start..len {
        let vm_ptr = unsafe { debug_syscall_trace_entry_vm_ptr(idx) };
        let nr = unsafe { debug_syscall_trace_entry_nr(idx) };
        let result = unsafe { debug_syscall_trace_entry_result(idx) };
        let status = unsafe { debug_syscall_trace_entry_status(idx) };
        parts.push(format!(
            "#{idx}:vm=0x{vm_ptr:x} nr={nr} result={result} status={status}"
        ));
    }
    format!("syscall_trace_len={len} {}", parts.join(" | "))
}

fn path_syscall_trace_dump() -> String {
    let len = unsafe { debug_path_syscall_trace_len() };
    if len == 0 {
        return "path_syscall_trace=<empty>".to_string();
    }
    let mut parts = Vec::new();
    for idx in 0..len {
        let vm_ptr = unsafe { debug_path_syscall_trace_vm_ptr(idx) };
        let nr = unsafe { debug_path_syscall_trace_nr(idx) };
        let dirfd = unsafe { debug_path_syscall_trace_dirfd(idx) };
        let result = unsafe { debug_path_syscall_trace_result(idx) };
        let status = unsafe { debug_path_syscall_trace_status(idx) };
        let path_ptr = unsafe { debug_path_syscall_trace_path_ptr(idx) };
        let path_len = unsafe { debug_path_syscall_trace_path_len(idx) } as usize;
        let path = if path_ptr == 0 || path_len == 0 {
            String::new()
        } else {
            let bytes = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, path_len) };
            String::from_utf8_lossy(bytes).to_string()
        };
        parts.push(format!(
            "#{idx}:vm=0x{vm_ptr:x} nr={nr} dirfd={dirfd} result={result} status={status} path={path:?}"
        ));
    }
    format!("path_syscall_trace_len={len} {}", parts.join(" | "))
}

fn thread_count_trace_dump() -> String {
    let len = unsafe { debug_thread_count_trace_len() };
    if len == 0 {
        return "thread_count_trace=<empty>".to_string();
    }
    let mut parts = Vec::new();
    for idx in 0..len {
        let kind = unsafe { debug_thread_count_trace_kind(idx) };
        let vm_ptr = unsafe { debug_thread_count_trace_vm_ptr(idx) };
        let tid = unsafe { debug_thread_count_trace_tid(idx) };
        let process_ptr = unsafe { debug_thread_count_trace_process_ptr(idx) };
        let before = unsafe { debug_thread_count_trace_before(idx) };
        let after = unsafe { debug_thread_count_trace_after(idx) };
        parts.push(format!(
            "#{idx}:kind={kind} vm=0x{vm_ptr:x} tid={tid} process_ptr=0x{process_ptr:x} {before}->{after}"
        ));
    }
    format!("thread_count_trace_len={len} {}", parts.join(" | "))
}

fn run_ltp(binary: &str) -> Result<(), String> {
    let kernel_root = ltp_gate::resolve_kernel_root(None)?;
    ltp_gate::guard_case(&kernel_root, binary)?;
    let path = format!("{}/ltp/{}", env!("OUT_DIR"), binary);
    let bytes = std::fs::read(&path).map_err(|e| format!("{} not built: {}", path, e))?;
    unsafe {
        debug_clear_syscall_trace();
    }
    let (code, pc, output) = support::run_elf_with_output(&bytes).map_err(|err| {
        format!(
            "{err}\n{}\n{}\n{}",
            syscall_trace_dump(),
            path_syscall_trace_dump(),
            thread_count_trace_dump()
        )
    })?;
    let output_text = String::from_utf8_lossy(&output);
    if output_text.contains("TBROK") || output_text.contains("TFAIL") {
        return Err(format!(
            "{binary} reported failure:\n{output_text}\n{}\n{}\n{}",
            syscall_trace_dump(),
            path_syscall_trace_dump(),
            thread_count_trace_dump()
        ));
    }
    if output_text.contains("TCONF") || code == 32 {
        return Err(format!(
            "{binary} TCONF\n{}\n{}\n{}",
            syscall_trace_dump(),
            path_syscall_trace_dump(),
            thread_count_trace_dump()
        ));
    }
    if code == 0 {
        Ok(())
    } else {
        Err(format!(
            "{} exit_code={}, last_pc=0x{:x}\n{}\n{}\n{}\n{}",
            binary,
            code,
            pc,
            output_text,
            syscall_trace_dump(),
            path_syscall_trace_dump(),
            thread_count_trace_dump()
        ))
    }
}

macro_rules! ltp_case {
    ($name:ident) => {
        #[test]
        fn $name() -> Result<(), String> {
            run_ltp(
                stringify!($name)
                    .strip_prefix("ltp_")
                    .expect("LTP test name must start with ltp_"),
            )
        }
    };
}

ltp_case!(ltp_clone08);
ltp_case!(ltp_close01);
ltp_case!(ltp_close02);
ltp_case!(ltp_epoll_create1_01);
ltp_case!(ltp_epoll_create1_02);
ltp_case!(ltp_epoll_ctl01);
ltp_case!(ltp_epoll_wait07);
ltp_case!(ltp_eventfd2_01);
ltp_case!(ltp_eventfd2_02);
ltp_case!(ltp_eventfd2_03);
ltp_case!(ltp_exit01);
ltp_case!(ltp_exit02);
ltp_case!(ltp_exit_group01);
ltp_case!(ltp_faccessat01);
ltp_case!(ltp_faccessat02);
ltp_case!(ltp_fstatat01);
ltp_case!(ltp_ftruncate01);
ltp_case!(ltp_futex_cmp_requeue02);
ltp_case!(ltp_futex_wait01);
ltp_case!(ltp_futex_wait02);
ltp_case!(ltp_futex_wait03);
ltp_case!(ltp_futex_wait05);
ltp_case!(ltp_futex_wait04);
ltp_case!(ltp_futex_wait_bitset01);
ltp_case!(ltp_futex_cmp_requeue01);
ltp_case!(ltp_futex_wake01);
ltp_case!(ltp_futex_wake02);
ltp_case!(ltp_futex_wake03);
ltp_case!(ltp_geteuid01);
ltp_case!(ltp_getpgid01);
ltp_case!(ltp_getpgid02);
ltp_case!(ltp_getuid01);
ltp_case!(ltp_lseek01);
ltp_case!(ltp_mkdirat01);
ltp_case!(ltp_openat01);
ltp_case!(ltp_pread01);
ltp_case!(ltp_pwrite01);
ltp_case!(ltp_read01);
ltp_case!(ltp_read04);
ltp_case!(ltp_sched_getaffinity01);
ltp_case!(ltp_sched_yield01);
ltp_case!(ltp_set_robust_list01);
ltp_case!(ltp_set_tid_address01);
ltp_case!(ltp_setpgid01);
ltp_case!(ltp_setpgid02);
ltp_case!(ltp_setpgid03);
ltp_case!(ltp_setsid01);
ltp_case!(ltp_sigaltstack02);
ltp_case!(ltp_tgkill03);
ltp_case!(ltp_sysinfo01);
ltp_case!(ltp_sysinfo02);
ltp_case!(ltp_truncate02);
ltp_case!(ltp_uname01);
ltp_case!(ltp_uname02);
ltp_case!(ltp_unlinkat01);
ltp_case!(ltp_vfork01);
ltp_case!(ltp_vfork02);
ltp_case!(ltp_wait401);
ltp_case!(ltp_wait402);
ltp_case!(ltp_wait403);
ltp_case!(ltp_waitid06);
ltp_case!(ltp_waitid09);
ltp_case!(ltp_waitpid04);
ltp_case!(ltp_waitpid09);
ltp_case!(ltp_write02);
