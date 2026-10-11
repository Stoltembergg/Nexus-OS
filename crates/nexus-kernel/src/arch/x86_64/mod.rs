//! x86_64 architecture-specific hardware initialization.

#[macro_use]
pub mod serial;
pub mod gdt;
pub mod idt;

use gdt::{GdtTable, TaskStateSegment};
use idt::IdtTable;
use spin::Mutex;

#[repr(align(16))]
pub struct KernelStack(pub [u8; 16384]); // 16 KB stack

pub static mut KERNEL_STACK: KernelStack = KernelStack([0; 16384]);
pub static mut DOUBLE_FAULT_STACK: KernelStack = KernelStack([0; 16384]);

static mut TSS: TaskStateSegment = TaskStateSegment::zeroed();
static mut GDT: Option<GdtTable> = None;
static IDT: Mutex<IdtTable> = Mutex::new(IdtTable::new());

/// Updates the Ring 0 kernel stack in the Task State Segment (TSS).
pub fn set_kernel_stack(rsp0: u64) {
    unsafe {
        TSS.rsp0 = rsp0;
    }
}

/// Sets the user FS base address in IA32_FS_BASE (0xC0000100).
///
/// # Safety
///
/// The caller must ensure that `addr` is a canonical virtual address and that
/// writing to IA32_FS_BASE is supported by the CPU.
pub unsafe fn set_user_fs_base(addr: u64) {
    #[cfg(all(target_arch = "x86_64", any(target_os = "uefi", target_os = "none")))]
    {
        let low = addr as u32;
        let high = (addr >> 32) as u32;
        core::arch::asm!(
            "wrmsr",
            in("ecx") 0xC000_0100u32,
            in("eax") low,
            in("edx") high,
            options(nostack, preserves_flags)
        );
    }
    #[cfg(not(all(target_arch = "x86_64", any(target_os = "uefi", target_os = "none"))))]
    let _ = addr;
}

/// Sets the user GS base address in IA32_GS_BASE (0xC0000101).
///
/// # Safety
///
/// The caller must ensure that `addr` is a canonical virtual address and that
/// writing to IA32_GS_BASE is supported by the CPU.
pub unsafe fn set_user_gs_base(addr: u64) {
    #[cfg(all(target_arch = "x86_64", any(target_os = "uefi", target_os = "none")))]
    {
        let low = addr as u32;
        let high = (addr >> 32) as u32;
        core::arch::asm!(
            "wrmsr",
            in("ecx") 0xC000_0101u32,
            in("eax") low,
            in("edx") high,
            options(nostack, preserves_flags)
        );
    }
    #[cfg(not(all(target_arch = "x86_64", any(target_os = "uefi", target_os = "none"))))]
    let _ = addr;
}

/// Initializes core x86_64 CPU structures: GDT, TSS, IDT, SSE, and COM1 serial.
pub fn init_arch() {
    // 1. Initialize serial logging immediately
    serial::SERIAL1.lock().init();

    // 2. Enable SSE / FXSR in CR0 and CR4 to allow compiler vector instructions
    #[cfg(all(target_arch = "x86_64", any(target_os = "uefi", target_os = "none")))]
    unsafe {
        let mut cr0: u64;
        core::arch::asm!("cli", options(nomem, nostack));
        let mut cr4: u64;
        core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        cr0 &= !(1 << 2); // Clear CR0.EM (Emulation)
        cr0 |= (1 << 1) | (1 << 16); // MP and supervisor write protection (WP)
        core::arch::asm!("mov cr0, {}", in(reg) cr0, options(nomem, nostack, preserves_flags));

        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        cr4 |= (1 << 9) | (1 << 10); // Set CR4.OSFXSR and CR4.OSXMMEXCPT
                                     // FXSAVE context covers x87/SSE. Do not advertise user AVX or FSGSBASE.
                                     // Clear PGE to flush inherited firmware global translations.
        cr4 &= !((1 << 18) | (1 << 16) | (1 << 7));
        let features = core::arch::x86_64::__cpuid_count(7, 0).ebx;
        if features & (1 << 7) != 0 {
            cr4 |= 1 << 20;
        } // SMEP
        if features & (1 << 20) != 0 {
            cr4 |= 1 << 21;
        } // SMAP (copies use supervisor aliases)
        core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack, preserves_flags));
        let efer = crate::syscall::rdmsr(crate::syscall::IA32_EFER_MSR);
        assert!(
            core::arch::x86_64::__cpuid(0x80000001).edx & (1 << 20) != 0,
            "CPU NX required"
        );
        crate::syscall::wrmsr(crate::syscall::IA32_EFER_MSR, efer | (1 << 11)); // NXE
    }

    // 3. Setup GDT and TSS
    unsafe {
        let kstack_top = (&raw const KERNEL_STACK as u64) + 16384;
        let df_stack_top = (&raw const DOUBLE_FAULT_STACK as u64) + 16384;
        TSS.rsp0 = kstack_top;
        TSS.ist1 = df_stack_top;

        GDT = Some(GdtTable::from_tss_ptr(&raw const TSS));
        if let Some(ref gdt) = GDT {
            let ptr = gdt.pointer();
            #[cfg(all(target_arch = "x86_64", any(target_os = "uefi", target_os = "none")))]
            {
                core::arch::asm!(
                    "lgdt [{}]",
                    in(reg) &ptr,
                    options(readonly, nostack, preserves_flags)
                );

                // Reload CS via far return and load Task Register (TR)
                core::arch::asm!(
                    "push 0x08",
                    "lea {tmp}, [2f + rip]",
                    "push {tmp}",
                    "retfq",
                    "2:",
                    "mov ax, 0x10",
                    "mov ds, ax",
                    "mov es, ax",
                    "mov ss, ax",
                    "mov ax, 0x28",
                    "ltr ax",
                    tmp = out(reg) _,
                    options(preserves_flags)
                );
            }
            #[cfg(not(any(target_os = "uefi", target_os = "none")))]
            {
                let _ = ptr;
            }
        }
    }

    // 4. Setup IDT and Arm Exception Gates
    {
        let mut idt = IDT.lock();
        idt::arm_exception_gates(&mut idt);

        let ptr = idt.pointer();
        #[cfg(all(target_arch = "x86_64", any(target_os = "uefi", target_os = "none")))]
        unsafe {
            core::arch::asm!(
                "lidt [{}]",
                in(reg) &ptr,
                options(readonly, nostack, preserves_flags)
            );
        }
        #[cfg(not(any(target_os = "uefi", target_os = "none")))]
        {
            let _ = ptr;
        }
    }
}
