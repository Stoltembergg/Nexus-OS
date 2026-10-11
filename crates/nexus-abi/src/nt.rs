//! Windows NT Executive System Service Dispatcher (SSDT).

use crate::context::RegisterContext;
use nexus_types::status::NtStatus;

pub const NT_CLOSE: u32 = 0x000F;
pub const NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 0x0018;
pub const NT_FREE_VIRTUAL_MEMORY: u32 = 0x001E;
pub const NT_WRITE_FILE: u32 = 0x0008;
pub const NT_QUERY_SYSTEM_INFORMATION: u32 = 0x0036;
pub const NT_TERMINATE_PROCESS: u32 = 0x002C;

/// Dispatches an NT system service call from a Windows thread context.
pub fn dispatch_nt_syscall(ctx: &mut RegisterContext) -> NtStatus {
    let service_id = ctx.rax as u32;

    let status = match service_id {
        NT_ALLOCATE_VIRTUAL_MEMORY => {
            // Args: ProcessHandle (RCX), BaseAddress (RDX), ZeroBits (R8), CommitSize (R9)
            // Simulated memory allocation
            log::info!("[NT-SSDT] NtAllocateVirtualMemory(handle={:#X}, size={:#X})", ctx.rcx, ctx.r9);
            NtStatus::STATUS_SUCCESS
        }
        NT_FREE_VIRTUAL_MEMORY => {
            log::info!("[NT-SSDT] NtFreeVirtualMemory(handle={:#X}, addr={:#X})", ctx.rcx, ctx.rdx);
            NtStatus::STATUS_SUCCESS
        }
        NT_WRITE_FILE => {
            // Args: FileHandle (RCX), Event (RDX), ApcRoutine (R8), ApcContext (R9)
            log::info!("[NT-SSDT] NtWriteFile(handle={:#X})", ctx.rcx);
            NtStatus::STATUS_SUCCESS
        }
        NT_CLOSE => {
            // Args: Handle (RCX)
            log::info!("[NT-SSDT] NtClose(handle={:#X})", ctx.rcx);
            NtStatus::STATUS_SUCCESS
        }
        NT_TERMINATE_PROCESS => {
            log::info!("[NT-SSDT] NtTerminateProcess(handle={:#X}, exit_code={})", ctx.rcx, ctx.rdx);
            NtStatus::STATUS_SUCCESS
        }
        NT_QUERY_SYSTEM_INFORMATION => {
            log::info!("[NT-SSDT] NtQuerySystemInformation(info_class={})", ctx.rcx);
            NtStatus::STATUS_SUCCESS
        }
        _ => {
            log::warn!("[NT-SSDT] Unhandled NT service ID: {:#06X}", service_id);
            NtStatus::STATUS_NOT_IMPLEMENTED
        }
    };

    ctx.rax = status.0 as u64;
    status
}
