use crate::abi::SPAWN_KIND_NONE;
use crate::types::ThreadState;

pub(crate) fn set_spawn_handoff(
    vm: &mut ThreadState,
    kind: u32,
    child_pid: i32,
    path_addr: u64,
    argv_addr: u64,
    envp_addr: u64,
) {
    vm.spawn_kind = kind;
    vm.spawn_ram_size = 0;
    vm.spawn_child_pid = child_pid;
    vm.spawn_path = path_addr;
    vm.spawn_argv = argv_addr;
    vm.spawn_envp = envp_addr;
}

pub(crate) fn clear_spawn_handoff(vm: &mut ThreadState) {
    vm.spawn_kind = SPAWN_KIND_NONE;
    vm.spawn_ram_size = 0;
    vm.spawn_child_pid = 0;
    vm.spawn_path = 0;
    vm.spawn_argv = 0;
    vm.spawn_envp = 0;
}
