//! x86_64 SYSCALL / SYSRET MSR Configuration and Syscall Router Binding.

use nexus_abi::SyscallRouter;
use spin::Mutex;

pub const IA32_EFER_MSR: u32 = 0xC000_0080;
pub const IA32_STAR_MSR: u32 = 0xC000_0081;
pub const IA32_LSTAR_MSR: u32 = 0xC000_0082;
pub const IA32_SFMASK_MSR: u32 = 0xC000_0084;

pub const EFER_SCE_BIT: u64 = 1 << 0; // System Call Extensions enable
pub const SFMASK_FLAGS: u64 = 0x200; // Mask IF (Interrupt Flag) on syscall entry

pub static KERNEL_SYSCALL_ROUTER: Mutex<Option<SyscallRouter>> = Mutex::new(None);

/// Initializes IA32 MSRs for the SYSCALL / SYSRET instructions.
///
/// - `IA32_STAR[63:48]`: User 32/64-bit CS and SS base selectors.
/// - `IA32_STAR[47:32]`: Kernel CS and SS selectors.
/// - `IA32_LSTAR`: Target RIP for 64-bit mode SYSCALL.
/// - `IA32_SFMASK`: Low 32 bits of RFLAGS masked during SYSCALL entry.
/// - `IA32_EFER.SCE`: Must be set to 1 to enable SYSCALL opcode.
pub fn init_syscall_msrs(syscall_entry_rip: u64) {
    #[cfg(all(target_arch = "x86_64", not(test)))]
    unsafe {
        // Enable SCE in EFER
        let efer = rdmsr(IA32_EFER_MSR);
        wrmsr(IA32_EFER_MSR, efer | EFER_SCE_BIT);

        // STAR: Kernel CS=0x08, Kernel SS=0x10; User CS32=0x18, User SS=0x20, User CS64=0x28
        let star: u64 = (0x0023_0008_u64) << 32;
        wrmsr(IA32_STAR_MSR, star);

        // LSTAR: 64-bit Syscall Entry Point
        wrmsr(IA32_LSTAR_MSR, syscall_entry_rip);

        // SFMASK: Clear IF (0x200) during kernel entry to prevent premature interrupts
        wrmsr(IA32_SFMASK_MSR, SFMASK_FLAGS);
    }

    #[cfg(test)]
    let _ = syscall_entry_rip;

    let mut router = KERNEL_SYSCALL_ROUTER.lock();
    *router = Some(SyscallRouter::new());
}

/// Reads a 64-bit Model Specific Register (MSR).
///
/// # Safety
/// Caller must ensure that the target CPU supports the specified MSR index,
/// and that reading this MSR does not violate hardware privileges or trigger a general protection fault (#GP).
pub unsafe fn rdmsr(msr: u32) -> u64 {
    #[cfg(all(target_arch = "x86_64", not(test)))]
    {
        let low: u32;
        let high: u32;
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags)
        );
        ((high as u64) << 32) | (low as u64)
    }
    #[cfg(any(not(target_arch = "x86_64"), test))]
    {
        let _ = msr;
        0
    }
}

/// Writes a 64-bit value to a Model Specific Register (MSR).
///
/// # Safety
/// Caller must ensure that the target CPU supports the specified MSR index,
/// and that the value written is valid and does not cause undefined hardware behavior or #GP.
pub unsafe fn wrmsr(msr: u32, val: u64) {
    #[cfg(all(target_arch = "x86_64", not(test)))]
    {
        let low = val as u32;
        let high = (val >> 32) as u32;
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") low,
            in("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
    #[cfg(any(not(target_arch = "x86_64"), test))]
    {
        let _ = msr;
        let _ = val;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_integration() {
        init_syscall_msrs(0xFFFF_8000_0000_1000);
        let guard = KERNEL_SYSCALL_ROUTER.lock();
        assert!(guard.is_some());
    }
}
