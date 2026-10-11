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

/// Initializes core x86_64 CPU structures: GDT, TSS, IDT, SSE, and COM1 serial.
pub fn init_arch() {
    // 1. Initialize serial logging immediately
    serial::SERIAL1.lock().init();

    // 2. Enable SSE / FXSR in CR0 and CR4 to allow compiler vector instructions
    #[cfg(all(target_arch = "x86_64", not(test)))]
    unsafe {
        let mut cr0: u64;
        let mut cr4: u64;
        core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        cr0 &= !(1 << 2); // Clear CR0.EM (Emulation)
        cr0 |= 1 << 1; // Set CR0.MP (Monitor Coprocessor)
        core::arch::asm!("mov cr0, {}", in(reg) cr0, options(nomem, nostack, preserves_flags));

        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        cr4 |= (1 << 9) | (1 << 10); // Set CR4.OSFXSR and CR4.OSXMMEXCPT
        core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack, preserves_flags));
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
            #[cfg(all(target_arch = "x86_64", not(test)))]
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
            #[cfg(test)]
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
        #[cfg(all(target_arch = "x86_64", not(test)))]
        unsafe {
            core::arch::asm!(
                "lidt [{}]",
                in(reg) &ptr,
                options(readonly, nostack, preserves_flags)
            );
        }
        #[cfg(test)]
        {
            let _ = ptr;
        }
    }
}
