use super::support::*;

#[test]
fn install_procfs_snapshot_writes_linux_like_maps() {
    let mut t = TestVm::new();
    let grown = t.sys_brk(0x126000);
    assert_eq!(grown, 0x126000);

    let bin = ensure_dir(1, b"bin");
    let exe_ino = memfs::create_file(bin, b"maps-target", 0o755);
    assert!(exe_ino > 0);
    assert_eq!(memfs::write_file(exe_ino, 0, b"ELF"), 3);

    let exe_fd = t.sys_openat(b"/bin/maps-target", O_RDONLY);
    assert!(exe_fd >= 3);
    let file_map = t.sys_mmap(0, PAGE_SIZE, PROT_READ | PROT_EXEC, MAP_PRIVATE, exe_fd, 0);
    assert!(file_map > 0);
    let anon_map = t.sys_mmap(
        0,
        PAGE_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert!(anon_map > 0);
    let stack_top = tidemark_kernel::syscall::memory::map_initial_stack(t.base, 0x80_0000, 0x20000);
    assert!(stack_top > 0);

    process_impl::install_procfs_snapshot(b"/bin/maps-target", 2 * 1024 * 1024 * 1024);

    let maps = String::from_utf8(read_file_bytes(b"/proc/self/maps")).unwrap();
    assert!(maps.contains("/bin/maps-target"));
    assert!(maps.contains("r-xp"));
    assert!(maps.contains("[heap]"));
    assert!(maps.contains("[stack]"));
    assert!(maps.contains("rw-p 00000000 00:00 0 [heap]"));

    let ngroups_max = String::from_utf8(read_file_bytes(b"/proc/sys/kernel/ngroups_max")).unwrap();
    assert_eq!(ngroups_max, "65536\n");

    let cpuinfo = String::from_utf8(read_file_bytes(b"/proc/cpuinfo")).unwrap();
    assert!(cpuinfo.contains("mmu\t\t: sv48\n"));

    let meminfo = String::from_utf8(read_file_bytes(b"/proc/meminfo")).unwrap();
    assert!(meminfo.contains("MemTotal: 2097152 kB\n"));
    assert!(meminfo.contains("MemFree: 1048576 kB\n"));
    assert!(meminfo.contains("MemAvailable: 1048576 kB\n"));
    assert!(meminfo.contains("SwapTotal: 0 kB\n"));
}

#[test]
fn semantics_vfork_parent_resume_restores_proc_self_exe_target() {
    let mut t = TestVm::new();
    let parent_path_addr = install_exec_file(&t, b"parent", &build_test_elf(&[0x13]));

    let ret = process_impl::sys_execve(&mut t.vm, t.base, parent_path_addr, 0, 0);
    assert_eq!(ret, 0);
    assert_eq!(read_link_bytes(b"/proc/self/exe"), b"/bin/parent");

    let status = process_impl::sys_vfork(&mut t.vm, t.base);
    assert_eq!(status, STATUS_VFORK_WAIT);

    let child_path_addr = install_exec_file(&t, b"child", &build_test_elf(&[0x13]));
    let child_pid = process_impl::sys_execve(&mut t.vm, t.base, child_path_addr, 0, 0);
    assert_eq!(t.vm.status, STATUS_EXECVE_SPAWN);
    assert_eq!(read_link_bytes(b"/proc/self/exe"), b"/bin/child");

    process_impl::vfork_parent_resume(&mut t.vm, child_pid as i32);
    assert_eq!(read_link_bytes(b"/proc/self/exe"), b"/bin/parent");
}

#[test]
fn semantics_vfork_preserves_proc_self_exe_and_memfs_paths_before_execve() {
    let mut t = TestVm::new();
    let parent_elf = build_test_elf(&[0x13]);
    let parent_path_addr = install_exec_file(&t, b"parent", &parent_elf);

    let ret = process_impl::sys_execve(&mut t.vm, t.base, parent_path_addr, 0, 0);
    assert_eq!(ret, 0);
    assert_eq!(read_link_bytes(b"/proc/self/exe"), b"/bin/parent");

    let tool_path = b"/usr/local/bin/tool";
    let tool_elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let tool_path_addr = install_exec_file_at(&t, tool_path, &tool_elf);
    assert_eq!(read_file_bytes(tool_path), tool_elf);

    let status = process_impl::sys_vfork(&mut t.vm, t.base);
    assert_eq!(status, STATUS_VFORK_WAIT);

    assert_eq!(read_link_bytes(b"/proc/self/exe"), b"/bin/parent");
    assert_eq!(read_file_bytes(tool_path), tool_elf);
    assert_ne!(
        memfs::resolve_path(tool_path),
        0,
        "tool path should remain resolvable during vfork child view"
    );
    assert_ne!(process_impl::vfork_child_pid(), 0);

    let child_ret = process_impl::sys_execve(&mut t.vm, t.base, tool_path_addr, 0, 0);
    assert!(child_ret > 0);
    assert_eq!(t.vm.status, STATUS_EXECVE_SPAWN);
}
