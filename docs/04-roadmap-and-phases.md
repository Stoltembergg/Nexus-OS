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
| Phase 2: Real Process Execution, VMM Isolation & Ring 3 Syscalls (Done)  |
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

### Phase 2: Real Process Execution, VMM Isolation & Ring 3 Syscalls (Completed)
- **Objective**: Implement a functional Virtual Memory Manager (VMM), dual address space isolation, hardware Ring 3 transitions, safe syscall dispatcher with user-pointer boundary checks, freestanding ELF64 execution, and hardware exception recovery.
- **Deliverables & Verified Milestones**:
  - **Audit & Architecture**:
    - Audited Phase 1 bootloader/kernel boundary, memory map handoff, and paging isolation (`docs/07-phase2-process-execution.md`).
    - Fixed low-memory identity mapping collision: relocated user binary execution space to `0x4000_0000` (1GB) and user stack to `0x0000_7FFF_FFFF_0000`.
  - **Functional VMM & Memory Isolation**:
    - Dynamic physical memory discovery up to detected RAM ceiling (128 MB in test VM).
    - Dedicated Kernel AddressSpace (PML4) constructed at physical frame `0x0010_0000`.
    - Low physical RAM and GOP framebuffer identity-mapped with supervisor-only flags (`USER = 0`).
    - CPU CR3 switched cleanly from UEFI page tables (`0x07801000`) to Kernel PML4 (`0x00100000`).
    - `AddressSpace::new_user`: creates isolated address space per process, sharing upper-half kernel mappings and mapping lower half with hardware-enforced protection.
  - **Ring 0 / Ring 3 Transitions & Task Context**:
    - Segment selectors: Ring 3 Code (`0x23`), Ring 3 Data (`0x1B`).
    - TSS initialized with 16KB dedicated kernel stack (`TSS.rsp0`) and double-fault stack (`TSS.ist1`). Task Register loaded via `ltr 0x28`.
    - Hardware Ring 3 transition implemented via `iretq` in standalone assembly routine `nexus_enter_user`.
    - Safe exception and syscall unrolling via `trigger_user_abort_asm`.
  - **Hardware SYSCALL / SYSRET Dispatcher & User Pointer Security**:
    - Hardware `SYSCALL` entry stub (`asm_syscall_entry`) wired to `IA32_LSTAR`.
    - Scratch RSP swapping between user RSP and thread-specific kernel RSP.
    - Secure pointer validation (`validate_user_buffer`): checks for 64-bit integer overflow, enforces canonical user ceiling (`< 0x0000_8000_0000_0000`), and verifies page presence in the active address space before dereferencing.
    - Implemented Linux `SYS_WRITE` (1) and `SYS_EXIT` (60) dispatchers.
  - **Milestone 1 Verified (Bare-Metal QEMU Execution)**:
    - Generated and executed freestanding ELF64 executable in Ring 3.
    - Executed `SYS_WRITE` printing `"Hello from Nexus OS Ring 3 (Freestanding ELF64)!\n"` to COM1 serial.
    - Executed `SYS_EXIT` with exit code 0, unrolling back to kernel cleanly.
  - **Milestone 2 Verified (Hardware Memory Isolation & #PF Recovery)**:
    - Spawned isolated faulting process in Ring 3 attempting to dereference supervisor kernel page (`0x0010_0000`).
    - CPU MMU raised hardware `#PF` (Vector 14, Error Code `0x5`: Protection Violation in User Mode).
    - Kernel IDT exception gate intercepted `#PF`, safely logged violation, unrolled execution back to kernel, and terminated process without panicking or halting the OS.
  - **Automated Verification**:
    - `scripts/test-boot.ps1` runs QEMU/OVMF headless and asserts `NEXUS_PHASE2_SUCCESS`, `MILESTONE 1 VERIFIED`, and `MILESTONE 2 VERIFIED`.
    - 22 workspace unit tests pass (`cargo test --workspace`).
    - 0 warnings in Clippy (`cargo clippy --workspace --all-targets -- -D warnings`).

### Phase 3: Linux Pico Subsystem & Musl/Glibc Runtime Execution
- **Objective**: Execute real Linux command-line binaries (e.g., BusyBox, Dash, GCC-compiled static/dynamic ELF) natively on bare metal.
- **Deliverables**:
  - Extended POSIX syscall set: `sys_read`, `sys_open`, `sys_close`, `sys_mmap`, `sys_munmap`, `sys_brk`, `sys_clone`, `sys_exit_group`, `sys_arch_prctl`.
  - In-memory Root VFS providing `/dev/null`, `/dev/zero`, `/dev/console`, and initramfs binary loading.
  - Musl libc dynamic loader (`ld-musl-x86_64.so.1`) bootstrap on bare metal.

### Phase 4: NT Executive Subsystem & Win32 Userland (PE Execution)
- **Objective**: Execute real Windows console and windowed PE executables natively using the unified process infrastructure.
- **Deliverables**:
  - NT System Service Dispatcher (`NtAllocateVirtualMemory`, `NtCreateSection`, `NtMapViewOfSection`, `NtWriteFile`, `NtCreateThreadEx`).
  - PE32+ loader integration into `Process::spawn_pe`: mapping sections, applying base relocations, allocating TEB/PEB, and setting up SEH.
  - Handle table (`HANDLE`) implementation with reference-counted kernel objects.
  - Wine-based Win32 userland integration.

### Phase 5: Hardware Acceleration (Vulkan/DRM) & Anti-Cheat Research Lab
- **Objective**: Direct GPU hardware acceleration for modern games and systematic reverse engineering of anti-cheat drivers.
- **Deliverables**:
  - Direct Rendering Manager (DRM) / KMS user-space split or VirtIO-GPU / DMA-BUF subsystem.
  - Native Vulkan 1.3 driver support.
  - DirectX 11/12 translation via DXVK / VKD3D running directly on native Vulkan.
  - Isolated Anti-Cheat Research Sandbox: Ring-0 driver monitoring environment to inspect calls made by `vgk.sys` and `EasyAntiCheat.sys`.
