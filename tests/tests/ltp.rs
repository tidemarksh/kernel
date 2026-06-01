use tidemark_kernel_tests::{ltp_gate, ltp_runner, support};

fn run_ltp(binary: &str) -> Result<(), String> {
    let kernel_root = ltp_gate::resolve_kernel_root(None)?;
    ltp_gate::guard_case(&kernel_root, binary)?;
    let path = format!("{}/ltp/{}", env!("OUT_DIR"), binary);
    let bytes = std::fs::read(&path).map_err(|e| format!("{} not built: {}", path, e))?;
    let (code, pc, output) = ltp_runner::run_named_elf_with_output(binary, &bytes)?;
    let output_text = String::from_utf8_lossy(&output);
    if output_text.contains("TBROK") || output_text.contains("TFAIL") {
        let (sig, code, pc, ra, sp, gp, tp, s11, fault_pc, fault_addr) =
            tidemark_kernel::harness::signal::last_default_signal();
        let arg_regs = tidemark_kernel::harness::signal::last_default_signal_arg_regs();
        let default_vm_ptr = tidemark_kernel::harness::signal::last_default_signal_vm_ptr();
        return Err(format!(
            "{} reported failure:\n{}\ndefault_signal(vm_ptr=0x{:x} sig={} code={} pc=0x{:x} ra=0x{:x} sp=0x{:x} gp=0x{:x} tp=0x{:x} s11=0x{:x} fault_pc=0x{:x} fault_addr=0x{:x} a0=0x{:x} a1=0x{:x} a2=0x{:x} a3=0x{:x} a4=0x{:x} a5=0x{:x} a6=0x{:x} a7=0x{:x})\ndefault_vm_identity={}\nltp_memory_probe={}\nprint_result_jump_table={}\nfault_exec_trace={}\ndefault_vm_exec_trace={}\nexec_trace_tail={}\nlast_jalr={}\nexternal_waits={}\nexternal_trace={}",
            binary,
            output_text,
            default_vm_ptr,
            sig,
            code,
            pc,
            ra,
            sp,
            gp,
            tp,
            s11,
            fault_pc,
            fault_addr,
            arg_regs[0],
            arg_regs[1],
            arg_regs[2],
            arg_regs[3],
            arg_regs[4],
            arg_regs[5],
            arg_regs[6],
            arg_regs[7],
            support::describe_ltp_vm_identity(default_vm_ptr),
            support::describe_ltp_memory_probe(),
            support::describe_current_guest_u32_words(0xa36e0, 16),
            tidemark_kernel::harness::support::describe_fault_exec_trace_for_vm(default_vm_ptr),
            tidemark_kernel::harness::support::describe_exec_trace_for_vm(default_vm_ptr),
            tidemark_kernel::harness::support::describe_exec_trace_tail(),
            tidemark_kernel::harness::support::describe_last_jalr_trace(),
            tidemark_kernel::harness::support::describe_external_futex_waits(),
            tidemark_kernel::harness::support::describe_external_futex_trace(),
        ));
    }
    if output_text.contains("TCONF") || code == 32 {
        return Err(format!("{binary} TCONF\n{output_text}"));
    }
    if code == 0 {
        Ok(())
    } else {
        Err(format!(
            "{} exit_code={}, last_pc=0x{:x}\n{}",
            binary, code, pc, output_text
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
ltp_case!(ltp_futex_cmp_requeue01);
ltp_case!(ltp_futex_cmp_requeue02);
ltp_case!(ltp_futex_wait01);
ltp_case!(ltp_futex_wait02);
ltp_case!(ltp_futex_wait03);
ltp_case!(ltp_futex_wait04);
ltp_case!(ltp_futex_wait05);
ltp_case!(ltp_futex_wait_bitset01);
ltp_case!(ltp_futex_wake01);
ltp_case!(ltp_futex_wake02);
ltp_case!(ltp_futex_wake03);
ltp_case!(ltp_getcpu02);
ltp_case!(ltp_getegid02);
ltp_case!(ltp_geteuid01);
ltp_case!(ltp_getgid01);
ltp_case!(ltp_getgid03);
ltp_case!(ltp_getpgid01);
ltp_case!(ltp_getpgid02);
ltp_case!(ltp_getpid01);
ltp_case!(ltp_getpid02);
ltp_case!(ltp_getppid01);
ltp_case!(ltp_getppid02);
ltp_case!(ltp_getresgid01);
ltp_case!(ltp_getresgid02);
ltp_case!(ltp_getresuid01);
ltp_case!(ltp_getresuid02);
ltp_case!(ltp_gettid02);
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
ltp_case!(ltp_setgid01);
ltp_case!(ltp_setgid02);
ltp_case!(ltp_setgid03);
ltp_case!(ltp_setgroups01);
ltp_case!(ltp_setregid01);
ltp_case!(ltp_setregid02);
ltp_case!(ltp_setregid04);
ltp_case!(ltp_setuid01);
ltp_case!(ltp_setuid03);
ltp_case!(ltp_setreuid01);
ltp_case!(ltp_setreuid04);
ltp_case!(ltp_setreuid06);
ltp_case!(ltp_setsid01);
ltp_case!(ltp_sigaltstack02);
ltp_case!(ltp_sysinfo01);
ltp_case!(ltp_sysinfo02);
ltp_case!(ltp_tgkill03);
ltp_case!(ltp_timerfd02);
ltp_case!(ltp_timerfd_create01);
ltp_case!(ltp_timerfd_gettime01);
ltp_case!(ltp_timerfd_settime01);
ltp_case!(ltp_truncate02);
ltp_case!(ltp_umask01);
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
ltp_case!(ltp_write01);
ltp_case!(ltp_write02);
ltp_case!(ltp_write03);
ltp_case!(ltp_write05);
ltp_case!(ltp_write06);
ltp_case!(ltp_writev01);
ltp_case!(ltp_writev02);
ltp_case!(ltp_writev05);
ltp_case!(ltp_writev06);
ltp_case!(ltp_writev07);
