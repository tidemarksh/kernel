use tidemark_kernel_tests::support;

fn run_ltp(binary: &str) -> Result<(), String> {
    let path = format!("{}/ltp/{}", env!("OUT_DIR"), binary);
    let bytes = std::fs::read(&path).map_err(|e| format!("{} not built: {}", path, e))?;
    let (code, pc, output) = support::run_elf_with_output(&bytes)?;
    let output_text = String::from_utf8_lossy(&output);
    if output_text.contains("TBROK") || output_text.contains("TFAIL") {
        return Err(format!("{binary} reported failure:\n{output_text}"));
    }
    if output_text.contains("TCONF") || code == 32 {
        return Err(format!("{binary} TCONF"));
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
ltp_case!(ltp_exit01);
ltp_case!(ltp_exit02);
ltp_case!(ltp_exit_group01);
ltp_case!(ltp_faccessat01);
ltp_case!(ltp_faccessat02);
ltp_case!(ltp_fstatat01);
ltp_case!(ltp_ftruncate01);
ltp_case!(ltp_futex_wait01);
ltp_case!(ltp_futex_wait02);
ltp_case!(ltp_futex_wake01);
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
