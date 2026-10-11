//! Nexus OS Dual ABI Multiplexer (NT Executive SSDT + Linux Pico Subsystem).

pub mod context;
pub mod linux;
pub mod nt;
pub mod router;

pub use context::RegisterContext;
pub use linux::dispatch_linux_syscall;
pub use nt::dispatch_nt_syscall;
pub use router::SyscallRouter;

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_types::address::VirtualAddress;
    use nexus_types::process::ProcessPersonality;

    #[test]
    fn standalone_router_never_claims_unimplemented_os_operations_succeeded() {
        for nr in [
            linux::SYS_READ,
            linux::SYS_WRITE,
            linux::SYS_OPEN,
            linux::SYS_CLOSE,
            linux::SYS_BRK,
            linux::SYS_MMAP,
            linux::SYS_ARCH_PRCTL,
            linux::SYS_EXIT,
            linux::SYS_SCHED_YIELD,
        ] {
            let mut ctx = RegisterContext {
                rax: nr,
                rdx: 32,
                ..Default::default()
            };
            assert_eq!(
                dispatch_linux_syscall(&mut ctx),
                nexus_types::Errno::ENOSYS.as_ret_val()
            );
        }
        for nr in [
            nt::NT_ALLOCATE_VIRTUAL_MEMORY,
            nt::NT_FREE_VIRTUAL_MEMORY,
            nt::NT_WRITE_FILE,
            nt::NT_TERMINATE_PROCESS,
            nt::NT_YIELD_EXECUTION,
            nt::NT_CLOSE,
            nt::NT_QUERY_SYSTEM_INFORMATION,
        ] {
            let mut ctx = RegisterContext {
                rax: nr as u64,
                ..Default::default()
            };
            assert_eq!(
                dispatch_nt_syscall(&mut ctx),
                nexus_types::NtStatus::STATUS_NOT_IMPLEMENTED
            );
        }
    }

    #[test]
    fn test_dual_router_dispatch() {
        let mut router = SyscallRouter::new();

        // 1. Dispatch NT syscall
        let win_pers = ProcessPersonality::Windows {
            image_base: VirtualAddress::new(0x140000000),
            entry_point: VirtualAddress::new(0x140001000),
            subsystem: 3,
            teb_address: VirtualAddress::new(0),
            peb_address: VirtualAddress::new(0),
        };

        let mut win_ctx = RegisterContext::new();
        win_ctx.rax = nt::NT_ALLOCATE_VIRTUAL_MEMORY as u64;
        win_ctx.rcx = 0xFFFFFFFF; // Current process pseudo-handle
        win_ctx.r9 = 0x1000; // 4KB commit

        router.dispatch(&win_pers, &mut win_ctx);
        assert_eq!(
            win_ctx.rax,
            nexus_types::NtStatus::STATUS_NOT_IMPLEMENTED.0 as u64
        );
        assert_eq!(router.nt_call_count, 1);

        // 2. Dispatch Linux syscall
        let lin_pers = ProcessPersonality::Linux {
            image_base: VirtualAddress::new(0x400000),
            entry_point: VirtualAddress::new(0x400100),
            brk_point: VirtualAddress::new(0x405000),
        };

        let mut lin_ctx = RegisterContext::new();
        lin_ctx.rax = linux::SYS_WRITE;
        lin_ctx.rdi = 1; // stdout
        lin_ctx.rsi = 0x402000;
        lin_ctx.rdx = 14; // "Hello, World!\n"

        router.dispatch(&lin_pers, &mut lin_ctx);
        assert_eq!(lin_ctx.rax as i64, nexus_types::Errno::ENOSYS.as_ret_val());
        assert_eq!(router.linux_call_count, 1);
    }
}
