//! x86_64 architecture-specific hardware initialization.

#[macro_use]
pub mod serial;
pub mod gdt;
pub mod idt;

use gdt::{GdtTable, TaskStateSegment};
use idt::IdtTable;
use spin::Mutex;

static mut TSS: TaskStateSegment = TaskStateSegment::zeroed();
static mut GDT: Option<GdtTable> = None;
static IDT: Mutex<IdtTable> = Mutex::new(IdtTable::new());

/// Initializes core x86_64 CPU structures: GDT, TSS, IDT, and COM1 serial.
pub fn init_arch() {
    // 1. Initialize serial logging immediately
    serial::SERIAL1.lock().init();

    // 2. Setup GDT and TSS
    unsafe {
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
            }
            #[cfg(test)]
            {
                let _ = ptr;
            }
        }
    }

    // 3. Setup IDT
    {
        let idt = IDT.lock();
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
