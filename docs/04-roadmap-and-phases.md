# Nexus OS Roadmap & Implementation Phases

The development of Nexus OS is structured into incremental, verifiable phases. Each phase establishes a functional, reproducible milestone on real hardware/QEMU before advancing.

---

> Phase 3.5 is now the active gate before Phase 4. Earlier "Done" milestones refer to their original limited demonstrations; [the hardening report](09-phase3.5-kernel-hardening.md) supersedes broad validation claims and records remaining blockers.

## Phase Overview

```
+--------------------------------------------------------------------------+
| Phase 0: Specifications, Architecture & Minimal Dual Loader PoC (Done)   |
+--------------------------------------------------------------------------+
                                    |
                                    v
+--------------------------------------------------------------------------+
| Phase 1: Bare-Metal UEFI Bootloader & Microkernel Initialization (Done)  |
+--------------------------------------------------------------------------+
                                    |
                                    v
+--------------------------------------------------------------------------+
| Phase 2: Real Process Execution, VMM Isolation & Ring 3 Syscalls (Done)  |
+--------------------------------------------------------------------------+
                                    |
                                    v
+--------------------------------------------------------------------------+
| Phase 3: Unified PE32+ / ELF64 Execution & Cooperative Scheduling (Done) |
+--------------------------------------------------------------------------+
                                    |
                                    v
+--------------------------------------------------------------------------+
| Phase 3.5: Kernel Hardening & Architecture Validation (In progress)    |
+--------------------------------------------------------------------------+
                                    |
                                    v
+--------------------------------------------------------------------------+
| Phase 4: Multi-Threaded Executive, In-Memory VFS & Dynamic Runtimes      |
+--------------------------------------------------------------------------+
                                    |
                                    v
+--------------------------------------------------------------------------+
| Phase 5: NT Subsystem, Object Handles & Win32 Userland Integration       |
+--------------------------------------------------------------------------+
                                    |
                                    v
+--------------------------------------------------------------------------+
| Phase 6: Hardware Acceleration (Vulkan/DRM) & Anti-Cheat Research Lab   |
+--------------------------------------------------------------------------+
```

---

## Detailed Phase Breakdown

### Phase 0: Specifications, Architecture & Minimal Dual Loader PoC (Completed)
- **Objective**: Establish the repository foundation, deep technical specifications, and a fully functional, verifiable Proof of Concept (PoC) capable of parsing, validating, memory-mapping, and simulating syscall execution for both Windows PE32+ and Linux ELF64 binaries.
- **Deliverables**:
  - Modular Rust workspace (`nexus-types`, `nexus-loader`, `nexus-abi`, `nexus-poc`, `nexus-boot`).
  - PE32+ parser (DOS header, PE header, Optional header, Section headers, Relocations).
  - ELF64 parser (ELF header, Program headers, Section headers, Entry point validation).
  - Dual syscall dispatcher with simulated NT SSDT and Linux POSIX call routing.
  - Test suites with synthetic and real PE/ELF binary fixtures.
  - Multi-platform CI pipeline (GitHub Actions).

### Phase 1: Bare-Metal UEFI Bootloader & Microkernel Initialization (Completed)
- **Objective**: Boot directly on real x86_64 UEFI hardware or QEMU/OVMF without a host operating system.
- **Architectural Revision**: Completed full feasibility study of DRM/KMS in an independent microkernel (`docs/06-drm-kms-feasibility-revision.md`). Adopted a 3-stage graphical architecture: Stage 1 = UEFI GOP linear framebuffer console; Stage 2 = VirtIO-GPU paravirtualized accelerator; Stage 3 = user-space Vulkan driver split (eliminating monolithic Linux DRM in-kernel bloat).
- **Deliverables & Verified Milestones**:
  - Freestanding UEFI 2.x bootloader (`crates/nexus-boot` -> `target/x86_64-unknown-uefi/debug/bootx64.efi`).
  - UEFI GOP (Graphics Output Protocol) linear framebuffer acquisition and early console driver (`crates/nexus-kernel/src/framebuffer.rs`).
  - Memory map acquisition via `GetMemoryMap` and handoff via `ExitBootServices` (`BootHandoverInfo`).
  - Microkernel core (`crates/nexus-kernel`):
    - 16550 UART driver for COM1 (0x3F8) at 115200 8N1 with `serial_println!` macro.
    - 64-bit GDT with Ring 0 & Ring 3 code/data selectors, 16-byte TSS descriptor, and Double Fault IST1 stack.
    - 256-vector IDT armed for CPU architectural exceptions (#DE, #DB, #BP, #UD, #DF, #GP, #PF).
    - Physical Memory Manager (PMM) 4KB bitmap allocator tracking up to 4GB of physical RAM.
    - 4-level x86_64 paging definitions (PML4, PDPT, PD, PT) and PTE bitflag encoding.
    - Hardware MSR setup (`IA32_EFER.SCE`, `IA32_STAR`, `IA32_LSTAR`, `IA32_SFMASK`) with `SyscallRouter` integration.
  - **Automated Verification**:
    - Automated tests in QEMU 11.1.0 with EDK2 OVMF firmware (`scripts/test-boot.ps1` and `scripts/test-boot.sh`).
    - Verified serial output: `GDT and TSS Configured`, `IDT Initialized`, `GOP Framebuffer Detected: 1280x800`, `PMM Initialized: 20075 usable frames (78 MB free RAM)`, `NEXUS_BOOT_SUCCESS`.
    - 100% unit tests pass across all workspace crates (`cargo test --workspace`).
    - 100% clean formatting and linting (`cargo fmt --check`, `cargo clippy -D warnings`).

### Phase 2: Real Process Execution, VMM Isolation & Ring 3 Syscalls (Completed)
- **Objective**: Implement a functional Virtual Memory Manager (VMM), dual address space isolation, hardware Ring 3 transitions, safe syscall dispatcher with user-pointer boundary checks, freestanding ELF64 execution, and hardware exception recovery.
- **Deliverables & Verified Milestones**:
  - **Audit & Architecture**:
    - Audited Phase 1 bootloader/kernel boundary, memory map handoff, and paging isolation (`docs/07-phase2-process-execution.md`).
    - Fixed low-memory identity mapping collision: relocated user binary execution space to `0x4000_0000` (1GB) and user stack to `0x0000_7FFF_FFFF_0000`.
  - **Functional VMM & Memory Isolation**:
    - Dedicated Kernel AddressSpace (PML4) constructed at physical frame `0x0010_0000`.
    - Low physical RAM and GOP framebuffer identity-mapped with supervisor-only flags (`USER = 0`).
    - CPU CR3 switched cleanly from UEFI page tables (`0x07801000`) to Kernel PML4 (`0x00100000`).
    - `AddressSpace::new_user`: creates isolated address space per process, sharing upper-half kernel mappings and mapping lower half with hardware-enforced protection.
  - **Ring 0 / Ring 3 Transitions & Task Context**:
    - TSS initialized with 16KB dedicated kernel stack (`TSS.rsp0`) and double-fault stack (`TSS.ist1`). Task Register loaded via `ltr 0x28`.
    - Hardware Ring 3 transition implemented via `iretq` in standalone assembly routine `nexus_enter_user`.
    - Safe exception and syscall unrolling via `trigger_user_abort_asm`.
  - **Hardware SYSCALL / SYSRET Dispatcher & User Pointer Security**:
    - Hardware `SYSCALL` entry stub (`asm_syscall_entry`) wired to `IA32_LSTAR`.
    - Secure pointer validation (`validate_user_buffer`): checks for 64-bit integer overflow, enforces canonical user ceiling (`< 0x0000_8000_0000_0000`), and verifies page presence in the active address space before dereferencing.
    - Implemented Linux `SYS_WRITE` (1) and `SYS_EXIT` (60) dispatchers.

### Phase 3: Unified PE32+ / ELF64 Execution & Cooperative Scheduling (Completed)
- **Objective**: Execute real Windows PE32+ and Linux ELF64 binaries in Ring 3 on the same kernel executive with personality-aware syscall dispatching, TEB/PEB setup, base relocations, and interleaved scheduling.
- **Deliverables & Verified Milestones**:
  - **PE32+ Loader & Base Relocations**:
    - Full section mapping with granular page flags (R/W/X).
    - Base Relocations engine (`PeRelocationBlock`, `IMAGE_REL_BASED_DIR64`).
    - Import table and Data Directories parsing up to 16 entries.
  - **Windows NT Personality**:
    - Aligned 4KB TEB (`0x0000_7FFF_FFF1_0000`) and PEB (`0x0000_7FFF_FFF0_0000`).
    - MSR `IA32_GS_BASE` (`0xC000_0101`) setup after segment reloading for seamless `gs:[0x30]` and `gs:[0x60]` userland access.
    - Syscall dispatching: `NtWriteFile` (0x0008), `NtYieldExecution` (0x0050), and `NtTerminateProcess` (0x002C).
  - **Linux Personality & Independent PML4 per Process**:
    - Maintained `SYS_WRITE` (1) and `SYS_EXIT` (60); added `SYS_SCHED_YIELD` (24) and `SYS_EXIT_GROUP` (231).
    - Dedicated PML4 address space allocated per process.
  - **Interleaved Cooperative Scheduler (`Scheduler`)**:
    - Round-robin multi-tasking across distinct binary personalities.
    - Context switches update `CR3`, TSS `RSP0`, and `IA32_GS_BASE`/`IA32_FS_BASE` MSRs.
    - Preserves user RIP and RSP across cooperative yields.
  - **Automated Bare-Metal QEMU Validation**:
    - Serial logs confirmed interleaved execution of `win_app.exe` (PID 1) and `linux_app.elf` (PID 2).
    - Verified hardware protection (#PF Vector 14) and safe error recovery (`NEXUS_PHASE3_SUCCESS`).

### Phase 4: Multi-Threaded Executive, In-Memory VFS & Dynamic Runtimes
- **Objective**: Advance the executive with preemptive timer-driven scheduling (APIC/HPET), in-memory VFS (initramfs), dynamic libraries (ELF shared objects, PE DLL imports), and userland libc/runtimes.
- **Deliverables**:
  - Local APIC timer interrupts and preemptive thread context switching.
  - In-memory Root VFS providing `/dev`, `/proc`, `/sys`, `/bin`, and FAT32 disk reading.
  - Dynamic linking support: Musl libc dynamic loader (`ld-musl-x86_64.so.1`) and initial Windows DLL loading (`ntdll.dll`).
  - Extended POSIX syscall set (`mmap`, `munmap`, `brk`, `fork`/`clone`, `execve`).

### Phase 5: NT Subsystem, Object Handles & Win32 Userland Integration
- **Objective**: Execute real Windows console and windowed PE applications natively using kernel object tables and system service dispatching.
- **Deliverables**:
  - Handle table (`HANDLE`) implementation with reference-counted kernel objects (Process, Thread, Event, Section, File).
  - NT System Service Dispatcher (`NtAllocateVirtualMemory`, `NtCreateSection`, `NtMapViewOfSection`, `NtCreateThreadEx`).
  - Win32 subsystem initialization (CSRSS / Win32k userland abstraction).
  - Native Windows executable support for standard C runtime applications.

### Phase 6: Hardware Acceleration (Vulkan/DRM) & Anti-Cheat Research Lab
- **Objective**: Direct GPU hardware acceleration for modern games and systematic reverse engineering of anti-cheat drivers.
- **Deliverables**:
  - Direct Rendering Manager (DRM) / KMS user-space split or VirtIO-GPU / DMA-BUF subsystem.
  - Native Vulkan 1.3 driver support.
  - DirectX 11/12 translation via DXVK / VKD3D running directly on native Vulkan.
  - Isolated Anti-Cheat Research Sandbox: Ring-0 driver monitoring environment to inspect calls made by `vgk.sys` and `EasyAntiCheat.sys`.
