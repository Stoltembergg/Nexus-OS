//! Nexus OS Bare-Metal Kernel Core.
//!
//! Provides bare-metal x86_64 architecture initialization (GDT, IDT, exceptions),
//! Physical Memory Management (PMM), GOP Framebuffer Terminal, and MSR Syscall Routing.

#[macro_use]
pub mod arch;
pub mod framebuffer;
pub mod mem;
pub mod syscall;

use nexus_types::BootHandoverInfo;

/// Main kernel entry point invoked immediately following UEFI ExitBootServices.
pub fn nexus_kernel_init(boot_info: &BootHandoverInfo) {
    // 1. Hardware Architecture Initialization (COM1 Serial, GDT, TSS, IDT)
    arch::init_arch();

    serial_println!("============================================================");
    serial_println!("        Nexus OS - Bare-Metal Kernel Boot (Phase 1)         ");
    serial_println!("============================================================");
    serial_println!("[*] CPU Architecture: x86_64 Long Mode (64-bit)");
    serial_println!("[+] Serial COM1 (115200 8N1) Initialized.");
    serial_println!("[+] GDT and TSS Configured (Ring 0 & Ring 3 Selectors Ready).");
    serial_println!("[+] IDT Initialized (Architectural Exception Gates Armed).");

    // 2. GOP Linear Framebuffer Console Initialization
    framebuffer::CONSOLE.lock().init(boot_info.framebuffer);
    if let Some(ref fb) = boot_info.framebuffer {
        serial_println!(
            "[+] GOP Framebuffer Detected: {}x{} (Pitch: {}, Base: {:#018X})",
            fb.width,
            fb.height,
            fb.pixels_per_scan_line,
            fb.base_address.as_u64()
        );
    } else {
        serial_println!(
            "[!] Warning: No GOP Framebuffer provided, falling back to pure serial console."
        );
    }

    // 3. Physical Memory Manager (PMM)
    mem::init_memory(boot_info);
    let (_total_frames, free_frames) = {
        let pmm = mem::pmm::PMM.lock();
        (pmm.total_frames(), pmm.free_frames())
    };
    let usable_mb = (free_frames * 4096) / (1024 * 1024);
    serial_println!(
        "[+] PMM Initialized: {} usable frames ({} MB free conventional RAM).",
        free_frames,
        usable_mb
    );

    // 4. SYSCALL / SYSRET MSR Configuration
    syscall::init_syscall_msrs(0xFFFF_8000_0000_1000);
    serial_println!("[+] IA32_EFER.SCE & IA32_LSTAR Configured for Dual-Personality Syscalls.");

    serial_println!("============================================================");
    serial_println!("  NEXUS_BOOT_SUCCESS: Kernel Core Initialized and Stable    ");
    serial_println!("============================================================");
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_types::{
        FramebufferInfo, MemoryDescriptor, PhysicalAddress, UefiMemoryType, VirtualAddress,
    };

    #[test]
    fn test_kernel_init_flow() {
        let mut boot_info = BootHandoverInfo::new();
        boot_info.push_descriptor(MemoryDescriptor {
            mem_type: UefiMemoryType::ConventionalMemory,
            phys_start: PhysicalAddress::new(0x200_0000), // 32MB
            virt_start: VirtualAddress::new(0),
            number_of_pages: 1024, // 4MB
            attribute: 0,
        });

        boot_info.framebuffer = Some(FramebufferInfo {
            base_address: PhysicalAddress::new(0xE000_0000),
            size: 1920 * 1080 * 4,
            width: 1920,
            height: 1080,
            pixels_per_scan_line: 1920,
            red_mask: 0x00FF0000,
            green_mask: 0x0000FF00,
            blue_mask: 0x000000FF,
        });

        nexus_kernel_init(&boot_info);

        let pmm = mem::pmm::PMM.lock();
        assert!(pmm.free_frames() > 0);
    }
}
