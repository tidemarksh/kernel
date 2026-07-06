use crate::abi::{FD_TYPE_FILE, FD_TYPE_PIPE, FD_TYPE_SOCKET, MAX_FDS};
use crate::fs::fd_table;

const FORK_SHARED_PEER_FLAG_COMPATIBLE: u32 = 1;
const FORK_SHARED_PEER_FLAG_INCOMPATIBLE: u32 = 1 << 1;
const FORK_SHARED_PEER_FLAG_PIPE_PEER: u32 = 1 << 2;
const FORK_SHARED_HELD_OFD_TRACK_FLAG_SHARED: u32 = 1;
const FORK_SHARED_HELD_OFD_TRACK_FLAG_HOST_STDIO_PIPE: u32 = 1 << 1;
const FORK_SHARED_HELD_OFD_TRACK_FLAG_STDIO_FD: u32 = 1 << 2;
const FORK_SHARED_HELD_OFD_TRACK_FLAG_FD_ENTRY_SOURCE: u32 = 1 << 3;
const FORK_SHARED_SYNC_TARGET_REJECT: i32 = 0;
const FORK_SHARED_SYNC_TARGET_DEFER: i32 = 1;
const FORK_SHARED_SYNC_TARGET_USE: i32 = 2;
const FORK_SHARED_OFD_ACTION_INCLUDE: i32 = 1;
const FORK_SHARED_OFD_ACTION_ADD_SHARED: i32 = 1 << 1;
const FORK_SHARED_OFD_ACTION_REHYDRATE: i32 = 1 << 2;
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

pub fn peer_flag_compatible() -> u32 {
    FORK_SHARED_PEER_FLAG_COMPATIBLE
}

pub fn peer_flag_incompatible() -> u32 {
    FORK_SHARED_PEER_FLAG_INCOMPATIBLE
}

pub fn peer_flag_pipe_peer() -> u32 {
    FORK_SHARED_PEER_FLAG_PIPE_PEER
}

pub fn held_ofd_track_flag_shared() -> u32 {
    FORK_SHARED_HELD_OFD_TRACK_FLAG_SHARED
}

pub fn held_ofd_track_flag_host_stdio_pipe() -> u32 {
    FORK_SHARED_HELD_OFD_TRACK_FLAG_HOST_STDIO_PIPE
}

pub fn held_ofd_track_flag_stdio_fd() -> u32 {
    FORK_SHARED_HELD_OFD_TRACK_FLAG_STDIO_FD
}

pub fn held_ofd_track_flag_fd_entry_source() -> u32 {
    FORK_SHARED_HELD_OFD_TRACK_FLAG_FD_ENTRY_SOURCE
}

pub fn sync_target_action_reject() -> i32 {
    FORK_SHARED_SYNC_TARGET_REJECT
}

pub fn sync_target_action_defer() -> i32 {
    FORK_SHARED_SYNC_TARGET_DEFER
}

pub fn sync_target_action_use() -> i32 {
    FORK_SHARED_SYNC_TARGET_USE
}

pub fn ofd_action_include() -> i32 {
    FORK_SHARED_OFD_ACTION_INCLUDE
}

pub fn ofd_action_add_shared() -> i32 {
    FORK_SHARED_OFD_ACTION_ADD_SHARED
}

pub fn ofd_action_rehydrate() -> i32 {
    FORK_SHARED_OFD_ACTION_REHYDRATE
}

pub fn held_ofd_track_action(ofd_id: u32, flags: u32) -> i32 {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return 0;
    }
    if (flags & FORK_SHARED_HELD_OFD_TRACK_FLAG_HOST_STDIO_PIPE) != 0 {
        return 0;
    }
    let Some(ofd) = fd_table::get_ofd_by_id(ofd_id) else {
        return 0;
    };
    if (flags
        & (FORK_SHARED_HELD_OFD_TRACK_FLAG_SHARED
            | FORK_SHARED_HELD_OFD_TRACK_FLAG_STDIO_FD
            | FORK_SHARED_HELD_OFD_TRACK_FLAG_FD_ENTRY_SOURCE))
        != 0
    {
        return 1;
    }
    if ofd.fd_type == FD_TYPE_FILE {
        return 0;
    }
    1
}

fn fold_identity_part(hash: u64, value: u64) -> u64 {
    let mut next = hash ^ value;
    next = next.wrapping_mul(FNV_PRIME);
    next
}

pub fn ofd_identity_key(ofd_id: u32) -> u64 {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return 0;
    }
    let Some(ofd) = fd_table::get_ofd_by_id(ofd_id) else {
        return 0;
    };
    if ofd.fd_type <= 0 {
        return 0;
    }
    let endpoint_or_host_fd = match ofd.fd_type {
        FD_TYPE_PIPE => {
            if ofd.host_fd >= 0 {
                1
            } else {
                2
            }
        }
        FD_TYPE_SOCKET => ofd.host_fd as u64,
        _ => 0,
    };
    let hash = fold_identity_part(FNV_OFFSET, ofd.fd_type as u64);
    let hash = fold_identity_part(hash, ofd.ino as u64);
    let hash = fold_identity_part(hash, endpoint_or_host_fd);
    if hash == 0 { FNV_OFFSET } else { hash }
}

pub fn ofd_publish_action(ofd_id: u32, peer_flags: u32) -> i32 {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return 0;
    }
    let Some(ofd) = fd_table::get_ofd_by_id(ofd_id) else {
        return 0;
    };
    if ofd.fd_type <= 0 {
        return 0;
    }
    if (peer_flags & FORK_SHARED_PEER_FLAG_INCOMPATIBLE) != 0 {
        return 0;
    }
    let compatible_peer = (peer_flags & FORK_SHARED_PEER_FLAG_COMPATIBLE) != 0;
    let pipe_peer = (peer_flags & FORK_SHARED_PEER_FLAG_PIPE_PEER) != 0;
    match ofd.fd_type {
        FD_TYPE_FILE => i32::from(compatible_peer),
        FD_TYPE_PIPE => i32::from(compatible_peer || pipe_peer),
        _ => 1,
    }
}

pub fn effect_sync_action(
    has_effect: i32,
    has_tracked_state: i32,
    source_holds_regular_file: i32,
    regular_file_has_peer: i32,
) -> i32 {
    if has_effect == 0 || has_tracked_state == 0 {
        return 0;
    }
    if source_holds_regular_file != 0 && regular_file_has_peer == 0 {
        return 0;
    }
    1
}

pub fn sync_target_action(
    invalid_pid: i32,
    running_worker: i32,
    vfork_ready_worker: i32,
    has_host_blocked_worker: i32,
    rpc_pending: i32,
    process_exit: i32,
    registered_process_exit: i32,
    registered_mismatch: i32,
    incompatible_ofd: i32,
    require_host_blocked: i32,
    include_memfs: i32,
    runtime_network_state: i32,
) -> i32 {
    if invalid_pid != 0
        || process_exit != 0
        || registered_process_exit != 0
        || registered_mismatch != 0
        || incompatible_ofd != 0
    {
        return FORK_SHARED_SYNC_TARGET_REJECT;
    }
    if include_memfs != 0 && runtime_network_state != 0 {
        return FORK_SHARED_SYNC_TARGET_REJECT;
    }
    if running_worker != 0 || vfork_ready_worker != 0 || rpc_pending != 0 {
        return FORK_SHARED_SYNC_TARGET_DEFER;
    }
    if require_host_blocked != 0 && has_host_blocked_worker == 0 {
        return FORK_SHARED_SYNC_TARGET_DEFER;
    }
    FORK_SHARED_SYNC_TARGET_USE
}

pub fn syncable_ofd_action(
    syncable: i32,
    source_conflicting: i32,
    allowed: i32,
    regular_file: i32,
    source_published: i32,
    runtime_network_socket: i32,
) -> i32 {
    if syncable == 0 || source_conflicting != 0 || allowed == 0 || runtime_network_socket != 0 {
        return 0;
    }
    if regular_file != 0 && source_published == 0 {
        return 0;
    }
    FORK_SHARED_OFD_ACTION_INCLUDE
}

pub fn delta_source_ofd_action(
    allowed: i32,
    source_published: i32,
    source_held: i32,
    pipe_peer: i32,
) -> i32 {
    if allowed == 0 {
        return 0;
    }
    if source_published != 0 {
        return FORK_SHARED_OFD_ACTION_INCLUDE;
    }
    if source_held != 0 && pipe_peer != 0 {
        return FORK_SHARED_OFD_ACTION_INCLUDE | FORK_SHARED_OFD_ACTION_ADD_SHARED;
    }
    0
}

pub fn tracked_source_ofd_action(
    kernel_shared: i32,
    source_fd_entry: i32,
    syncable: i32,
    type_none: i32,
    incompatible_peer: i32,
) -> i32 {
    if syncable == 0 || type_none != 0 {
        return 0;
    }
    if kernel_shared == 0 && source_fd_entry == 0 {
        return 0;
    }
    if source_fd_entry == 0 && incompatible_peer != 0 {
        return 0;
    }
    FORK_SHARED_OFD_ACTION_INCLUDE
}

pub fn pipe_peer_ofd_action(stale: i32, syncable: i32) -> i32 {
    if stale != 0 || syncable == 0 {
        return 0;
    }
    FORK_SHARED_OFD_ACTION_INCLUDE | FORK_SHARED_OFD_ACTION_ADD_SHARED
}

pub fn rehydrate_ofd_action(active: i32, source_held: i32, allowed: i32) -> i32 {
    if active != 0 && source_held == 0 && allowed != 0 {
        return FORK_SHARED_OFD_ACTION_REHYDRATE;
    }
    0
}
