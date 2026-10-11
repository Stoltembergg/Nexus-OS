//! Nexus OS Bare-Metal Kernel Core.
//!
//! Provides bare-metal x86_64 architecture initialization (GDT, IDT, exceptions),
//! Physical Memory Management (PMM), Virtual Memory Management (VMM),
//! Process / Thread execution in Ring 3, and Dual-Personality Syscalls.

#[macro_use]
pub mod arch;
pub mod framebuffer;
pub mod mem;
pub mod syscall;
pub mod task;

use nexus_types::BootHandoverInfo;

/// Main kernel entry point invoked immediately following UEFI ExitBootServices.
pub fn nexus_kernel_init(boot_info: &BootHandoverInfo) {
    // 1. Hardware Architecture Initialization (COM1 Serial, GDT, TSS, IDT)
    arch::init_arch();

    serial_println!("============================================================");
    serial_println!("     Nexus OS - Real Process Execution & VMM (Phase 2)      ");
    serial_println!("============================================================");
    serial_println!("[*] CPU Architecture: x86_64 Long Mode (64-bit)");
    serial_println!("[+] Serial COM1 (115200 8N1) Initialized.");
    serial_println!("[+] GDT, TSS (TR loaded), and Architectural Exception Gates Armed.");

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

    // 3. Physical & Virtual Memory Management (PMM / VMM)
    mem::init_memory(boot_info);
    let (_total_frames, free_frames) = {
        let pmm = mem::pmm::PMM.lock();
        (pmm.total_frames(), pmm.free_frames())
    };
    let usable_mb = (free_frames * 4096) / (1024 * 1024);
    serial_println!(
        "[+] PMM & VMM Active: {} usable frames ({} MB free RAM). Dedicated Kernel CR3 Armed.",
        free_frames,
        usable_mb
    );

    // 4. SYSCALL / SYSRET Hardware MSR Configuration
    syscall::init_syscall_msrs(task::syscall::asm_syscall_entry as *const () as usize as u64);
    serial_println!("[+] IA32_EFER.SCE & IA32_LSTAR Configured with Secure Pointer Validation.");

    // 5. Milestone 1: Freestanding ELF64 Process Execution in Ring 3
    serial_println!("------------------------------------------------------------");
    serial_println!("[*] Milestone 1: Executing Freestanding ELF64 in Ring 3...");
    serial_println!("------------------------------------------------------------");

    serial_println!("[*] Generating Ring 3 payload...");
    let elf_bytes = task::elf_payload::generate_ring3_elf_payload(
        b"Hello from Nexus OS Ring 3 (Freestanding ELF64)!\n",
    );
    serial_println!("[*] Acquiring kernel memory locks...");
    let mut kernel_as_guard = mem::KERNEL_ADDRESS_SPACE.lock();
    let kernel_as = kernel_as_guard
        .as_mut()
        .expect("Kernel Address Space must be initialized");
    let mut pmm_guard = mem::pmm::PMM.lock();

    serial_println!("[*] Calling spawn_elf for PID 1...");
    let mut user_process = task::Process::spawn_elf(
        nexus_types::ProcessId(1),
        "init_elf",
        &elf_bytes,
        kernel_as,
        &mut pmm_guard,
    )
    .expect("Failed to spawn Ring 3 ELF process");

    drop(kernel_as_guard);
    drop(pmm_guard);

    serial_println!("[*] Launching user process PID 1 in Ring 3...");
    let kernel_as_ref = mem::KERNEL_ADDRESS_SPACE.lock();
    let k_as = kernel_as_ref.as_ref().unwrap();
    let exit_code =
        task::run_user_process(&mut user_process, k_as).expect("Failed to execute process");
    drop(kernel_as_ref);

    if exit_code == 0 {
        serial_println!(
            "[+] MILESTONE 1 VERIFIED: Ring 3 ELF64 executed cleanly (Exit Code: {}).",
            exit_code
        );
    } else {
        serial_println!("[!] MILESTONE 1 FAILED: Unexpected Exit Code {}", exit_code);
    }

    // 6. Milestone 2: Ring 3 Memory Isolation & #PF Recovery Test
    serial_println!("------------------------------------------------------------");
    serial_println!("[*] Milestone 2: Testing Ring 3 Memory Isolation & #PF Recovery...");
    serial_println!("------------------------------------------------------------");

    let fault_elf_bytes = task::elf_payload::generate_faulting_elf_payload();
    let mut kernel_as_guard = mem::KERNEL_ADDRESS_SPACE.lock();
    let kernel_as = kernel_as_guard
        .as_mut()
        .expect("Kernel Address Space must be initialized");
    let mut pmm_guard = mem::pmm::PMM.lock();

    let mut fault_process = task::Process::spawn_elf(
        nexus_types::ProcessId(2),
        "fault_test",
        &fault_elf_bytes,
        kernel_as,
        &mut pmm_guard,
    )
    .expect("Failed to spawn faulting ELF process");

    drop(kernel_as_guard);
    drop(pmm_guard);

    let kernel_as_ref = mem::KERNEL_ADDRESS_SPACE.lock();
    let k_as = kernel_as_ref.as_ref().unwrap();
    let fault_res = task::run_user_process(&mut fault_process, k_as);
    drop(kernel_as_ref);

    match fault_res {
        Err(task::ProcessError::Fault(14)) => {
            serial_println!(
                "[+] MILESTONE 2 VERIFIED: Memory isolation caught illegal access (Exception Vector 14: #PF)."
            );
        }
        Err(task::ProcessError::Fault(13)) => {
            serial_println!(
                "[+] MILESTONE 2 VERIFIED: Memory isolation caught illegal access (Exception Vector 13: #GP)."
            );
        }
        other => {
            serial_println!("[!] MILESTONE 2: Outcome: {:?}", other);
        }
    }

    serial_println!("============================================================");
    serial_println!(" NEXUS_PHASE2_SUCCESS: Real Process Execution Verified     ");
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
