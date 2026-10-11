# Nexus OS Roadmap & Implementation Phases

The development of Nexus OS is structured into six strictly incremental phases. Each phase establishes a functional, verifiable milestone with concrete deliverables before advancing.

---

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
| Phase 2: Dual Address Space & Hybrid Process Scheduler                  |
+--------------------------------------------------------------------------+
                                    |
                                    v
+--------------------------------------------------------------------------+
| Phase 3: Linux Pico Subsystem & Musl/Glibc Runtime Execution             |
+--------------------------------------------------------------------------+
                                    |
                                    v
+--------------------------------------------------------------------------+
| Phase 4: NT Executive Subsystem & Win32 Userland (PE Execution)          |
+--------------------------------------------------------------------------+
                                    |
                                    v
+--------------------------------------------------------------------------+
| Phase 5: Hardware Acceleration (Vulkan/DRM) & Anti-Cheat Research Lab   |
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

### Phase 2: Dual Address Space & Hybrid Process Scheduler
- **Objective**: Implement physical and virtual memory managers and preemptive task scheduling for hybrid processes.
- **Deliverables**:
  - PMM frame allocator integration with dynamic page table mapping (VMM).
  - Virtual Address Space (`VAddressSpace`) capable of mapping both PE base (`0x140000000`) and ELF base (`0x400000`).
  - Context switching mechanism saving and restoring user registers, `FS_BASE`, `GS_BASE`, and SSE/AVX state.
  - Preemptive timer interrupt (APIC Timer) and round-robin scheduler.

### Phase 3: Linux Pico Subsystem & Musl/Glibc Runtime Execution
- **Objective**: Execute real Linux command-line binaries (e.g., BusyBox, Dash, GCC-compiled static/dynamic ELF) natively on bare metal.
- **Deliverables**:
  - MSR `LSTAR` syscall handler intercepting System V AMD64 syscalls.
  - Core POSIX syscalls: `sys_read`, `sys_write`, `sys_open`, `sys_close`, `sys_mmap`, `sys_munmap`, `sys_brk`, `sys_clone`, `sys_exit_group`, `sys_arch_prctl`.
  - VFS (Virtual File System) providing rootfs, `/dev/null`, `/dev/zero`, `/dev/console`.
  - Musl libc ELF runtime execution test.

### Phase 4: NT Executive Subsystem & Win32 Userland (PE Execution)
- **Objective**: Execute real Windows console and windowed PE executables natively.
- **Deliverables**:
  - NT System Service Dispatcher (`NtAllocateVirtualMemory`, `NtCreateSection`, `NtMapViewOfSection`, `NtWriteFile`, `NtCreateThreadEx`).
  - `ntdll.dll` bootstrap loader: mapping and initializing PE import tables (IAT), base relocations, and Thread Local Storage (TLS).
  - Handle table (`HANDLE`) implementation with reference-counted kernel objects (Events, Mutexes, Sections, Files).
  - Integration with Wine-based Win32 userland libraries.

### Phase 5: Hardware Acceleration (Vulkan/DRM) & Anti-Cheat Research Lab
- **Objective**: Direct GPU hardware acceleration for modern games and systematic reverse engineering of anti-cheat drivers.
- **Deliverables**:
  - Direct Rendering Manager (DRM) / KMS user-space split or VirtIO-GPU / DMA-BUF subsystem.
  - Native Vulkan 1.3 driver support.
  - DirectX 11/12 translation via DXVK / VKD3D running directly on native Vulkan.
  - Isolated Anti-Cheat Research Sandbox: Ring-0 driver monitoring environment to inspect calls made by `vgk.sys` and `EasyAntiCheat.sys`.
