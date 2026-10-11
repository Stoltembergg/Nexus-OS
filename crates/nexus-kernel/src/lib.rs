//! Nexus OS Bare-Metal Kernel Core.
//!
//! Provides bare-metal x86_64 architecture initialization (GDT, IDT, exceptions),
//! Physical Memory Management (PMM), Virtual Memory Management (VMM),
//! Process / Thread execution in Ring 3, and Dual-Personality Syscalls (NT & Linux).

#[macro_use]
pub mod arch;
pub mod driver_host;
pub mod framebuffer;
pub mod mem;
pub mod syscall;
pub mod task;

use nexus_types::BootHandoverInfo;

/// Main kernel entry point invoked immediately following UEFI ExitBootServices.
#[cfg(any(target_os = "uefi", target_os = "none"))]
pub fn nexus_kernel_init(boot_info: &BootHandoverInfo) {
    // 1. Hardware Architecture Initialization (COM1 Serial, GDT, TSS, IDT)
    arch::init_arch();
    #[cfg(feature = "hardening-tests")]
    hardening::install_panic_exit_hook();

    serial_println!("============================================================");
    serial_println!("  Nexus OS - Unified PE32+ / ELF64 Process Executive (Phase 3) ");
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

    #[cfg(feature = "hardening-tests")]
    hardening::run();

    // 5. Milestone 1: Spawning Windows PE32+ and Linux ELF64 Processes
    serial_println!("------------------------------------------------------------");
    serial_println!("[*] Milestone 1: Spawning Windows PE32+ & Linux ELF64 Processes...");
    serial_println!("------------------------------------------------------------");

    let pe_bytes = task::pe_payload::generate_ring3_pe_payload();
    let elf_bytes = task::elf_payload::generate_ring3_elf_payload(
        b"Hello from Nexus OS Ring 3 (Linux ELF64)!\n",
    );

    let mut kernel_as_guard = mem::KERNEL_ADDRESS_SPACE.lock();
    let kernel_as = kernel_as_guard
        .as_mut()
        .expect("Kernel Address Space must be initialized");
    let mut pmm_guard = mem::pmm::PMM.lock();

    serial_println!("[*] Spawning Windows PE32+ Process (PID 1, 'win_app.exe')...");
    let win_proc = task::Process::spawn_pe(
        nexus_types::ProcessId(1),
        "win_app.exe",
        &pe_bytes,
        kernel_as,
        &mut pmm_guard,
    )
    .expect("Failed to spawn Windows PE32+ process");

    serial_println!("[*] Spawning Linux ELF64 Process (PID 2, 'linux_app.elf')...");
    let linux_proc = task::Process::spawn_elf(
        nexus_types::ProcessId(2),
        "linux_app.elf",
        &elf_bytes,
        kernel_as,
        &mut pmm_guard,
    )
    .expect("Failed to spawn Linux ELF64 process");

    drop(kernel_as_guard);
    drop(pmm_guard);

    // 6. Milestone 2: Cooperative Multi-Process Scheduling & Personality Alternation
    serial_println!("------------------------------------------------------------");
    serial_println!("[*] Milestone 2: Interleaved Multi-Personality Scheduling...");
    serial_println!("------------------------------------------------------------");

    let mut scheduler = task::Scheduler::new();
    scheduler.add_process(win_proc);
    scheduler.add_process(linux_proc);

    let kernel_as_ref = mem::KERNEL_ADDRESS_SPACE.lock();
    let k_as = kernel_as_ref.as_ref().unwrap();
    scheduler.run_all(k_as).expect("Scheduler execution failed");
    assert!(scheduler
        .processes
        .iter()
        .all(|p| p.outcome == Some(task::RunOutcome::Exit(0))));
    drop(kernel_as_ref);

    serial_println!(
        "[+] MILESTONE 1 & 2 VERIFIED: Dual PE32+ & ELF64 execution and cooperative scheduling completed!"
    );

    // 7. Milestone 3: Memory Isolation & Protection Fault Recovery
    serial_println!("------------------------------------------------------------");
    serial_println!(
        "[*] Milestone 3: Testing Address Space Isolation & Hardware Fault Recovery..."
    );
    serial_println!("------------------------------------------------------------");

    let fault_elf_bytes = task::elf_payload::generate_faulting_elf_payload();
    let mut kernel_as_guard = mem::KERNEL_ADDRESS_SPACE.lock();
    let kernel_as = kernel_as_guard
        .as_mut()
        .expect("Kernel Address Space must be initialized");
    let mut pmm_guard = mem::pmm::PMM.lock();

    let mut fault_process = task::Process::spawn_elf(
        nexus_types::ProcessId(3),
        "fault_test",
        &fault_elf_bytes,
        kernel_as,
        &mut pmm_guard,
    )
    .expect("Failed to spawn faulting process");

    drop(kernel_as_guard);
    drop(pmm_guard);

    let kernel_as_ref = mem::KERNEL_ADDRESS_SPACE.lock();
    let k_as = kernel_as_ref.as_ref().unwrap();
    let fault_res = task::run_user_process(&mut fault_process, k_as);
    drop(kernel_as_ref);

    match fault_res {
        Err(task::ProcessError::Fault(14)) => {
            let fault = unsafe { core::ptr::read(&raw const arch::x86_64::idt::LAST_FAULT_INFO) };
            assert_eq!(fault, Some((14, 0x100000, 5)));
            serial_println!(
                "[+] MILESTONE 3 VERIFIED: Memory isolation caught illegal access (Exception Vector 14: #PF)."
            );
        }
        other => panic!("Unexpected isolation result: {:?}", other),
    }
    fault_process
        .release(&mut mem::pmm::PMM.lock())
        .expect("fault reaping");

    serial_println!("============================================================");
    serial_println!(" NEXUS_PHASE3_SUCCESS: Unified PE32+/ELF64 Execution Verified");
    serial_println!("============================================================");

    // 8. Milestone 4: Windows NT Driver Compatibility Validation (Phase 3.6)
    serial_println!("------------------------------------------------------------");
    serial_println!("[*] Milestone 4: Windows NT Driver Compatibility Validation (Ring 0)...");
    serial_println!("------------------------------------------------------------");

    let report = driver_host::validate_nt_driver_subsystem();

    // Markers are derived from the evidence counters, not printed unconditionally (FP1).
    // 3 drivers: reloc_driver, nexus_driver, standard_wdm.
    assert_eq!(
        report.lifecycles_verified, 3,
        "driver lifecycle evidence missing"
    );
    assert_eq!(
        report.wx_pages_verified, report.wx_pages_expected,
        "driver PTE W^X evidence must cover exactly every page of the 3 fixtures"
    );
    serial_println!("NEXUS_CHECK:driver-wx:PASS");
    serial_println!(
        "NEXUS_DRIVER_WX:pages_verified={}:expected={}",
        report.wx_pages_verified,
        report.wx_pages_expected
    );
    assert_eq!(
        report.nt_semantics_checks, 14,
        "NT semantics self-test incomplete"
    );
    serial_println!("NEXUS_CHECK:nt-semantics:PASS");
    serial_println!("NEXUS_NT_SEMANTICS:checks={}", report.nt_semantics_checks);
    serial_println!("NEXUS_CHECK:driver-lifecycle:PASS");
    serial_println!(
        "NEXUS_DRIVER_LIFECYCLE:drivers={}:heap_balanced=true:pool_balanced=true:devices_deleted=true",
        report.lifecycles_verified
    );

    serial_println!("============================================================");
    serial_println!(" NEXUS_PHASE3_6_SUCCESS: Native NT Driver Execution Verified in Ring 0");
    serial_println!("============================================================");
    serial_println!(
        " NEXUS_PHASE3_7_SUCCESS: NT Driver Runtime Hardening & W^X Verified in Ring 0"
    );
    serial_println!("============================================================");

    #[cfg(feature = "hardening-tests")]
    hardening::exit_success();
}

#[cfg(not(any(target_os = "uefi", target_os = "none")))]
pub fn nexus_kernel_init(_boot_info: &BootHandoverInfo) {
    panic!("Kernel initialization requires real UEFI/bare-metal execution");
}

#[cfg(all(
    feature = "hardening-tests",
    any(target_os = "uefi", target_os = "none")
))]
mod hardening;
