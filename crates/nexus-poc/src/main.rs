//! Nexus OS - Phase 0 Proof of Concept (PoC) Runner
//!
//! Validates:
//! 1. PE32+ (x86_64) parsing and segment mapping
//! 2. ELF64 (x86_64) parsing and segment mapping
//! 3. Dual Address Space coexistence without collisions
//! 4. Dual-personality Syscall Multiplexer (NT Executive vs Linux Pico)

pub mod fixtures;

use fixtures::{create_minimal_elf64, create_minimal_pe64};
use nexus_abi::{linux, nt, RegisterContext, SyscallRouter};
use nexus_loader::{detect_format, load_binary, BinaryFormat};
use nexus_types::process::{HybridProcessDescriptor, ProcessId};

fn main() {
    // Initialize logging
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
    env_logger::init();

    println!("============================================================");
    println!("       Nexus OS - Phase 0 Hybrid Architecture PoC           ");
    println!("  Executing Windows PE32+ and Linux ELF64 Dual-Personality  ");
    println!("============================================================\n");

    // -----------------------------------------------------------------
    // Step 1: Windows PE32+ Binary Processing
    // -----------------------------------------------------------------
    println!("[1/4] Processing Windows PE32+ (AMD64) Binary...");
    let pe_bytes = create_minimal_pe64();
    let pe_format = detect_format(&pe_bytes);
    println!("  [*] Detected Format: {:?}", pe_format);
    assert_eq!(pe_format, BinaryFormat::Pe32Plus);

    let loaded_pe = match load_binary(&pe_bytes) {
        Ok(img) => img,
        Err(e) => {
            eprintln!("  [!] Failed to load PE binary: {}", e);
            std::process::exit(1);
        }
    };
    println!("  [+] Successfully parsed PE32+ image:");
    println!("      Personality: {}", loaded_pe.personality.name());
    println!("      Entry Point: {}", loaded_pe.entry_point);
    println!("      Mapped Segments: {}", loaded_pe.segments.len());
    for (i, seg) in loaded_pe.segments.iter().enumerate() {
        println!(
            "        - Segment #{}: tag='{}', base={}, size={:#X} bytes, flags={:?}",
            i, seg.tag, seg.base_va, seg.size, seg.flags
        );
    }
    println!();

    // -----------------------------------------------------------------
    // Step 2: Linux ELF64 Binary Processing
    // -----------------------------------------------------------------
    println!("[2/4] Processing Linux ELF64 (x86_64) Binary...");
    let elf_bytes = create_minimal_elf64();
    let elf_format = detect_format(&elf_bytes);
    println!("  [*] Detected Format: {:?}", elf_format);
    assert_eq!(elf_format, BinaryFormat::Elf64);

    let loaded_elf = match load_binary(&elf_bytes) {
        Ok(img) => img,
        Err(e) => {
            eprintln!("  [!] Failed to load ELF binary: {}", e);
            std::process::exit(1);
        }
    };
    println!("  [+] Successfully parsed ELF64 image:");
    println!("      Personality: {}", loaded_elf.personality.name());
    println!("      Entry Point: {}", loaded_elf.entry_point);
    println!("      Mapped Segments: {}", loaded_elf.segments.len());
    for (i, seg) in loaded_elf.segments.iter().enumerate() {
        println!(
            "        - Segment #{}: tag='{}', base={}, size={:#X} bytes, flags={:?}",
            i, seg.tag, seg.base_va, seg.size, seg.flags
        );
    }
    println!();

    // -----------------------------------------------------------------
    // Step 3: Dual Address Space Coexistence Verification
    // -----------------------------------------------------------------
    println!("[3/4] Verifying Memory Coexistence in Unified 64-bit Address Space...");
    let mut collision_detected = false;
    for pe_seg in &loaded_pe.segments {
        for elf_seg in &loaded_elf.segments {
            if pe_seg.overlaps_with(elf_seg) {
                eprintln!(
                    "  [!] Collision detected between PE segment '{}' and ELF segment '{}'!",
                    pe_seg.tag, elf_seg.tag
                );
                collision_detected = true;
            }
        }
    }

    if !collision_detected {
        println!("  [+] Verified: Windows PE base (0x140000000) and Linux ELF base (0x400000)");
        println!("      occupy disjoint canonical virtual memory ranges without collision.");
    } else {
        panic!("Fatal: Memory overlap detected in dual personality space!");
    }
    println!();

    // -----------------------------------------------------------------
    // Step 4: Dual-Personality Syscall Multiplexer Simulation
    // -----------------------------------------------------------------
    println!("[4/4] Demonstrating Dual-Personality Syscall Routing...");
    let mut router = SyscallRouter::new();

    // Hybrid process registration
    let win_proc = HybridProcessDescriptor::new(
        ProcessId(100),
        "cmd.exe".to_string(),
        loaded_pe.personality.clone(),
    );
    let lin_proc = HybridProcessDescriptor::new(
        ProcessId(101),
        "busybox".to_string(),
        loaded_elf.personality.clone(),
    );

    // Simulated Windows thread issues NtAllocateVirtualMemory
    println!("  [*] Simulating Windows thread syscall: NtAllocateVirtualMemory (ID 0x0018)");
    let mut win_ctx = RegisterContext::new();
    win_ctx.rax = nt::NT_ALLOCATE_VIRTUAL_MEMORY as u64;
    win_ctx.rcx = 0xFFFFFFFF; // Process handle
    win_ctx.rdx = 0x0000_0001_4005_0000; // Desired base
    win_ctx.r9 = 0x2000; // Commit 8KB
    router.dispatch(&win_proc.personality, &mut win_ctx);
    println!("      -> Result: NTSTATUS = {:#010X}", win_ctx.rax);
    assert_eq!(win_ctx.rax, 0); // STATUS_SUCCESS

    // Simulated Linux thread issues sys_write
    println!("  [*] Simulating Linux thread syscall: sys_write (ID 1)");
    let mut lin_ctx = RegisterContext::new();
    lin_ctx.rax = linux::SYS_WRITE;
    lin_ctx.rdi = 1; // stdout fd
    lin_ctx.rsi = 0x0040_1000; // buffer pointer
    lin_ctx.rdx = 24; // length
    router.dispatch(&lin_proc.personality, &mut lin_ctx);
    println!("      -> Result: Written bytes = {}", lin_ctx.rax);
    assert_eq!(lin_ctx.rax, 24);

    // Simulated Linux thread issues sys_brk
    println!("  [*] Simulating Linux thread syscall: sys_brk (ID 12)");
    let mut brk_ctx = RegisterContext::new();
    brk_ctx.rax = linux::SYS_BRK;
    brk_ctx.rdi = 0x0041_0000; // Expand heap break
    router.dispatch(&lin_proc.personality, &mut brk_ctx);
    println!("      -> Result: New heap break = {:#X}", brk_ctx.rax);
    assert_eq!(brk_ctx.rax, 0x0041_0000);

    println!("\n============================================================");
    println!("  Phase 0 PoC Verification Summary:                         ");
    println!("  - Total NT System Service Calls Handled: {}", router.nt_call_count);
    println!("  - Total Linux Pico Syscalls Handled:     {}", router.linux_call_count);
    println!("  - Hybrid Binary Execution Status: PASS                    ");
    println!("============================================================");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phase0_end_to_end_verification() {
        let pe_bytes = create_minimal_pe64();
        let elf_bytes = create_minimal_elf64();

        let loaded_pe = load_binary(&pe_bytes).expect("Failed to load PE");
        let loaded_elf = load_binary(&elf_bytes).expect("Failed to load ELF");

        // Verify non-collision
        for pe_seg in &loaded_pe.segments {
            for elf_seg in &loaded_elf.segments {
                assert!(!pe_seg.overlaps_with(elf_seg));
            }
        }

        // Verify dual syscall routing
        let mut router = SyscallRouter::new();

        let mut win_ctx = RegisterContext::new();
        win_ctx.rax = nt::NT_ALLOCATE_VIRTUAL_MEMORY as u64;
        router.dispatch(&loaded_pe.personality, &mut win_ctx);
        assert_eq!(win_ctx.rax, 0);

        let mut lin_ctx = RegisterContext::new();
        lin_ctx.rax = linux::SYS_WRITE;
        lin_ctx.rdx = 10;
        router.dispatch(&loaded_elf.personality, &mut lin_ctx);
        assert_eq!(lin_ctx.rax, 10);
    }
}
