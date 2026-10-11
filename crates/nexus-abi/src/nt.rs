//! Windows NT Executive System Service Dispatcher (SSDT).

use crate::context::RegisterContext;
use nexus_types::status::NtStatus;

pub const NT_CLOSE: u32 = 0x000F;
pub const NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 0x0018;
pub const NT_FREE_VIRTUAL_MEMORY: u32 = 0x001E;
pub const NT_WRITE_FILE: u32 = 0x0008;
pub const NT_QUERY_SYSTEM_INFORMATION: u32 = 0x0036;
pub const NT_TERMINATE_PROCESS: u32 = 0x002C;
pub const NT_YIELD_EXECUTION: u32 = 0x0050;

/// Host routing inspection only. No handles, memory or I/O are fabricated.
pub fn dispatch_nt_syscall(ctx: &mut RegisterContext) -> NtStatus {
    ctx.rax = NtStatus::STATUS_NOT_IMPLEMENTED.0 as u64;
    NtStatus::STATUS_NOT_IMPLEMENTED
}
