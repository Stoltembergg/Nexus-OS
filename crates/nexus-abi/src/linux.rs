//! Linux Pico Subsystem System Call Dispatcher.

use crate::context::RegisterContext;
use nexus_types::errno::Errno;

pub const SYS_READ: u64 = 0;
pub const SYS_WRITE: u64 = 1;
pub const SYS_OPEN: u64 = 2;
pub const SYS_CLOSE: u64 = 3;
pub const SYS_MMAP: u64 = 9;
pub const SYS_BRK: u64 = 12;
pub const SYS_SCHED_YIELD: u64 = 24;
pub const SYS_EXIT: u64 = 60;
pub const SYS_ARCH_PRCTL: u64 = 158;
pub const SYS_EXIT_GROUP: u64 = 231;

/// Host routing inspection only. Real services require a live kernel address space.
pub fn dispatch_linux_syscall(ctx: &mut RegisterContext) -> i64 {
    let error = Errno::ENOSYS.as_ret_val();
    ctx.rax = error as u64;
    error
}
