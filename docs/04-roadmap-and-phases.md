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
| Phase 1: Bare-Metal UEFI Bootloader & Microkernel Initialization         |
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

### Phase 0: Specifications, Architecture & Minimal Dual Loader PoC
- **Objective**: Establish the repository foundation, deep technical specifications, and a fully functional, verifiable Proof of Concept (PoC) capable of parsing, validating, memory-mapping, and simulating syscall execution for both Windows PE32+ and Linux ELF64 binaries.
- **Deliverables**:
  - Modular Rust workspace (`nexus-types`, `nexus-loader`, `nexus-abi`, `nexus-poc`, `nexus-boot`).
  - PE32+ parser (DOS header, PE header, Optional header, Section headers, Relocations).
  - ELF64 parser (ELF header, Program headers, Section headers, Entry point validation).
  - Dual syscall dispatcher with simulated NT SSDT and Linux POSIX call routing.
  - Test suites with synthetic and real PE/ELF binary fixtures.
  - Multi-platform CI pipeline (GitHub Actions).

### Phase 1: Bare-Metal UEFI Bootloader & Microkernel Initialization
- **Objective**: Boot directly on real x86_64 UEFI hardware or QEMU without an operating system host.
- **Deliverables**:
  - UEFI Application (`bootx64.efi`) using UEFI Boot Services.
  - GOP (Graphics Output Protocol) framebuffer detection and linear framebuffer setup.
  - Memory map acquisition and handoff to the kernel.
  - ExitBootServices handover protocol.
  - Kernel core entry: 4-level paging setup, GDT (Global Descriptor Table), IDT (Interrupt Descriptor Table), APIC initialization, serial debug logging (`COM1`).

### Phase 2: Dual Address Space & Hybrid Process Scheduler
- **Objective**: Implement physical and virtual memory managers and preemptive task scheduling for hybrid processes.
- **Deliverables**:
  - PMM (Bitmap / Buddy allocator) and VMM (PML4 page table manager with 4KB, 2MB, 1GB page support).
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
  - Direct Rendering Manager (DRM) / KMS kernel driver for AMDGPU and Intel GPUs.
  - Native Vulkan 1.3 userland driver support.
  - DirectX 11/12 translation via DXVK / VKD3D running directly on native Vulkan.
  - Isolated Anti-Cheat Research Sandbox: Virtualized Ring-0 driver monitoring environment to inspect calls made by `vgk.sys` and `EasyAntiCheat.sys`.
