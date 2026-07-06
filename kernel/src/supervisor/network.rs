use core::sync::atomic::{AtomicU32, Ordering};

const NETWORK_PUMP_BACKOFF_CAP: usize = 256;

pub(super) const NETWORK_PUMP_ACTION_SKIP: u32 = 0;
pub(super) const NETWORK_PUMP_ACTION_PUMP: u32 = 1;

#[derive(Clone, Copy)]
struct NetworkPumpBackoff {
    vm_ptr: u32,
    skip_next_pump: u32,
}

impl NetworkPumpBackoff {
    const fn empty() -> Self {
        Self {
            vm_ptr: 0,
            skip_next_pump: 0,
        }
    }

    fn matches(&self, vm_ptr: u32) -> bool {
        self.vm_ptr == vm_ptr
    }
}

static NETWORK_PUMP_BACKOFF_LOCK: AtomicU32 = AtomicU32::new(0);
static NETWORK_PUMP_BACKOFF_CURSOR: AtomicU32 = AtomicU32::new(0);
static mut NETWORK_PUMP_BACKOFFS: [NetworkPumpBackoff; NETWORK_PUMP_BACKOFF_CAP] =
    [NetworkPumpBackoff::empty(); NETWORK_PUMP_BACKOFF_CAP];

fn with_network_pump_backoffs<T>(
    f: impl FnOnce(&mut [NetworkPumpBackoff; NETWORK_PUMP_BACKOFF_CAP]) -> T,
) -> T {
    super::lock::with_spin_lock(&NETWORK_PUMP_BACKOFF_LOCK, || {
        let backoffs_ptr = core::ptr::addr_of_mut!(NETWORK_PUMP_BACKOFFS);
        unsafe { f(&mut *backoffs_ptr) }
    })
}

pub(super) fn init() {
    with_network_pump_backoffs(|backoffs| {
        NETWORK_PUMP_BACKOFF_CURSOR.store(0, Ordering::Relaxed);
        for backoff in backoffs.iter_mut() {
            *backoff = NetworkPumpBackoff::empty();
        }
    });
}

pub(super) fn pump_action_skip() -> u32 {
    NETWORK_PUMP_ACTION_SKIP
}

pub(super) fn pump_action_pump() -> u32 {
    NETWORK_PUMP_ACTION_PUMP
}

fn validate_vm_ptr(vm_ptr: u32) -> Result<(), i32> {
    if vm_ptr == 0 {
        return Err(-(crate::abi::EFAULT as i32));
    }
    Ok(())
}

fn find_backoff_slot(
    backoffs: &mut [NetworkPumpBackoff; NETWORK_PUMP_BACKOFF_CAP],
    vm_ptr: u32,
) -> Option<usize> {
    backoffs
        .iter()
        .enumerate()
        .find_map(|(idx, backoff)| backoff.matches(vm_ptr).then_some(idx))
}

fn backoff_slot(
    backoffs: &mut [NetworkPumpBackoff; NETWORK_PUMP_BACKOFF_CAP],
    vm_ptr: u32,
) -> usize {
    if let Some(idx) = find_backoff_slot(backoffs, vm_ptr) {
        return idx;
    }
    for (idx, backoff) in backoffs.iter_mut().enumerate() {
        if backoff.vm_ptr == 0 {
            *backoff = NetworkPumpBackoff {
                vm_ptr,
                skip_next_pump: 0,
            };
            return idx;
        }
    }
    let idx = NETWORK_PUMP_BACKOFF_CURSOR.fetch_add(1, Ordering::Relaxed) as usize
        % NETWORK_PUMP_BACKOFF_CAP;
    backoffs[idx] = NetworkPumpBackoff {
        vm_ptr,
        skip_next_pump: 0,
    };
    idx
}

pub(super) fn blocked_wait_pump_action(vm_ptr: u32) -> i32 {
    if let Err(errno) = validate_vm_ptr(vm_ptr) {
        return errno;
    }
    with_network_pump_backoffs(|backoffs| {
        let Some(idx) = find_backoff_slot(backoffs, vm_ptr) else {
            return NETWORK_PUMP_ACTION_PUMP as i32;
        };
        if backoffs[idx].skip_next_pump == 0 {
            return NETWORK_PUMP_ACTION_PUMP as i32;
        }
        backoffs[idx] = NetworkPumpBackoff::empty();
        NETWORK_PUMP_ACTION_SKIP as i32
    })
}

pub(super) fn complete_blocked_wait_pump(vm_ptr: u32, changed: u32) -> i32 {
    if let Err(errno) = validate_vm_ptr(vm_ptr) {
        return errno;
    }
    with_network_pump_backoffs(|backoffs| {
        if changed != 0 {
            clear_backoff(backoffs, vm_ptr);
            return 0;
        }
        let idx = backoff_slot(backoffs, vm_ptr);
        backoffs[idx].skip_next_pump = 1;
        0
    })
}

pub(super) fn clear_blocked_wait_pump(vm_ptr: u32) -> i32 {
    if let Err(errno) = validate_vm_ptr(vm_ptr) {
        return errno;
    }
    with_network_pump_backoffs(|backoffs| {
        clear_backoff(backoffs, vm_ptr);
    });
    0
}

fn clear_backoff(backoffs: &mut [NetworkPumpBackoff; NETWORK_PUMP_BACKOFF_CAP], vm_ptr: u32) {
    for backoff in backoffs.iter_mut() {
        if backoff.matches(vm_ptr) {
            *backoff = NetworkPumpBackoff::empty();
        }
    }
}
