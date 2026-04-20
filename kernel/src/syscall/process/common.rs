pub(crate) const ECHILD: i64 = -10;
pub(crate) const ESRCH: i64 = -3;

pub(crate) const P_ALL: u32 = 0;
pub(crate) const P_PID: u32 = 1;
pub(crate) const P_PGID: u32 = 2;
pub(crate) const CLD_EXITED: i32 = 1;
pub(crate) const CLD_KILLED: i32 = 2;

pub(crate) const SIGINFO_OFF_SI_SIGNO: u64 = 0;
pub(crate) const SIGINFO_OFF_SI_ERRNO: u64 = 4;
pub(crate) const SIGINFO_OFF_SI_CODE: u64 = 8;
pub(crate) const SIGINFO_OFF_SI_PID: u64 = 16;
pub(crate) const SIGINFO_OFF_SI_UID: u64 = 20;
pub(crate) const SIGINFO_OFF_SI_STATUS: u64 = 24;
