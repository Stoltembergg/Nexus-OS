//! Physical and Virtual Memory Management Subsystem.

pub mod heap;
pub mod pmm;
pub mod vmm;

use nexus_types::{BootHandoverInfo, PhysicalAddress};
use spin::Mutex;

pub static KERNEL_ADDRESS_SPACE: Mutex<Option<vmm::AddressSpace>> = Mutex::new(None);

/// Initializes physical frame allocator using UEFI memory map descriptors,
/// builds the kernel's dedicated 4-level page directory, and switches CR3.
pub fn init_memory(boot_info: &BootHandoverInfo) {
    let mut pmm = pmm::PMM.lock();
    pmm.init_from_memory_map(boot_info.memory_map());

    // 1. Explicitly reserve Framebuffer MMIO range
    if let Some(ref fb) = boot_info.framebuffer {
        pmm.reserve_region(fb.base_address, fb.size);
    }

    // Determine the highest physical RAM address from all descriptors (excluding MMIO above 4GB)
    let mut max_phys_ram = 64 * 1024 * 1024_u64; // at least 64MB
    for desc in boot_info.memory_map() {
        let end = desc.phys_start.as_u64() + desc.number_of_pages * 4096;
        if end > max_phys_ram && end <= 0x1_0000_0000 {
            // Keep below 4GB (standard RAM boundary)
            max_phys_ram = end;
        }
    }
    serial_println!(
        "[*] Maximum Physical RAM Address detected: {:#018X} ({} MB)",
        max_phys_ram,
        max_phys_ram / (1024 * 1024)
    );

    // 2. Construct Kernel Dedicated AddressSpace (PML4)
    let mut kernel_as = vmm::AddressSpace::new(&mut pmm).expect("Failed to allocate Kernel PML4");
    serial_println!(
        "[+] Allocated Kernel PML4 at {:#018X}",
        kernel_as.pml4_frame().as_u64()
    );

    // 3. Identity-map physical memory up to max_phys_ram for kernel text, data, and hardware IO
    // Crucial: Flags are PRESENT | WRITABLE (Supervisor-only: USER bit is NOT set!)
    let kflags = vmm::PageTableFlags::PRESENT | vmm::PageTableFlags::WRITABLE;
    kernel_as
        .map_identity(
            PhysicalAddress::new(0),
            max_phys_ram as usize,
            kflags,
            &mut pmm,
        )
        .expect("Failed to identity-map kernel physical memory");
    serial_println!(
        "[+] Identity mapped physical memory up to {:#018X}",
        max_phys_ram
    );

    // 4. Identity-map Framebuffer MMIO memory (Supervisor-only)
    if let Some(ref fb) = boot_info.framebuffer {
        let _ = kernel_as.map_identity(fb.base_address, fb.size, kflags, &mut pmm);
        serial_println!(
            "[+] Identity mapped Framebuffer at {:#018X} ({} bytes)",
            fb.base_address.as_u64(),
            fb.size
        );
    }

    // 5. Read current CR3 before switch
    #[cfg(all(target_arch = "x86_64", not(test)))]
    unsafe {
        let old_cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) old_cr3, options(nomem, nostack, preserves_flags));
        serial_println!(
            "[*] Switching CR3 from UEFI {:#018X} to Kernel {:#018X}...",
            old_cr3,
            kernel_as.pml4_frame().as_u64()
        );
    }

    // 6. Switch CPU CR3 to Kernel Address Space
    kernel_as.switch_to();
    serial_println!("[+] Successfully switched to Kernel CR3!");

    let mut kas_guard = KERNEL_ADDRESS_SPACE.lock();
    *kas_guard = Some(kernel_as);
}
