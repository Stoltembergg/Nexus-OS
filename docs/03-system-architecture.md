# Nexus OS: System Architecture Specification

This document details the internal architecture of **Nexus OS**, specifying the memory manager, object and handle manager, dual-personality process model, system call dispatcher, and binary loaders.

---

## 1. High-Level Architectural Diagram

```
+-------------------------------------------------------------------------+
|                              USER SPACE                                 |
|                                                                         |
|     +-------------------------+         +-------------------------+     |
|     |  Windows Application    |         |    Linux Application    |     |
|     |    (PE32+ / x86_64)     |         |     (ELF64 / x86_64)    |     |
|     +------------+------------+         +------------+------------+     |
|                  |                                   |                  |
|     +------------v------------+         +------------v------------+     |
|     |   ntdll.dll / kernel32  |         |   glibc / musl libc     |     |
|     +------------+------------+         +------------+------------+     |
+------------------|-----------------------------------|------------------+
|                  |             SYSCALL               |                  |
+------------------v-----------------------------------v------------------+
|                             KERNEL SPACE                                |
|                                                                         |
|                +---------------------------------------+                |
|                |    MSR LSTAR System Call Dispatcher   |                |
|                +-------------------+-------------------+                |
|                                    |                                    |
|               [Check Current Thread Personality]                        |
|                                    |                                    |
|                 +------------------+------------------+                 |
|                 |                                     |                 |
|                 v                                     v                 |
|    +--------------------------+         +--------------------------+    |
|    |   NT Executive Service   |         |   Linux Pico Subsystem   |    |
|    |   Table (SSDT Dispatch)  |         |   (POSIX Syscall Table)  |    |
|    +------------+-------------+         +-------------+------------+    |
|                 |                                     |                 |
|                 +------------------+------------------+                 |
|                                    |                                    |
|                                    v                                    |
|                +---------------------------------------+                |
|                |         Unified Executive Core        |                |
|                |  - Process & Thread Manager           |                |
|                |  - Object & Handle Manager (Ob)       |                |
|                |  - Virtual Memory Manager (Mm / VMM)  |                |
|                |  - Asynchronous I/O Manager (Io / IRP)|                |
|                +-------------------+-------------------+                |
|                                    |                                    |
|                                    v                                    |
|                +---------------------------------------+                |
|                |       Hardware Abstraction Layer      |                |
|                |   - x86_64 APIC / LAPIC / IOAPIC      |                |
|                |   - 4-Level Paging (PML4)             |                |
|                |   - UEFI GOP / ACPI / PCI Express     |                |
|                +---------------------------------------+                |
+-------------------------------------------------------------------------+
```

---

## 2. Process & Thread Dual-Personality Model

A central design innovation of Nexus OS is that every process is an instance of `HybridProcess`. The kernel core does not discriminate between an "NT process" or a "Linux task"; rather, it assigns a **Personality Descriptor** to the process:

```rust
pub enum ProcessPersonality {
    /// Native Windows PE32+ executable environment
    Windows {
        subsystem: WindowsSubsystem, // GUI (2) or CUI (3)
        peb_address: VirtualAddress, // Address of Process Environment Block
        image_base: VirtualAddress,  // Default e.g. 0x0000000140000000
    },
    /// Native Linux ELF64 executable environment
    Linux {
        abi_version: LinuxAbiVersion,
        brk_point: VirtualAddress,   // Current heap break pointer
        aux_vectors: Vec<AuxVector>, // ELF auxiliary vectors for ld.so / glibc
    },
}
```

### Thread Execution State
- Each thread (`HybridThread`) has its own kernel stack, user stack pointer (`RSP`), instruction pointer (`RIP`), and CPU register context.
- When scheduled onto a CPU core, the processor's `GS_BASE` register points to the thread's control block (`KPCR` / `ThreadControlBlock`), allowing immediate $O(1)$ identification of the active personality during a `syscall` trap.

---

## 3. Virtual Memory & Address Space Layout

x86_64 hardware provides a 48-bit (or 57-bit with 5-level paging) virtual address space per process.

### Userland vs. Kernel Split
- **User Space**: `0x00000000_00000000` to `0x00007FFF_FFFFFFFF` (128 TiB canonical lower half).
- **Non-Canonical Hole**: `0x00008000_00000000` to `0xFFFF7FFF_FFFFFFFF`.
- **Kernel Space**: `0xFFFF8000_00000000` to `0xFFFFFFFF_FFFFFFFF` (128 TiB canonical upper half).

### Binary Mapping Regions

| Binary Format | Typical Preferred Base | Nexus OS Virtual Memory Strategy |
| :--- | :--- | :--- |
| **PE32+ (Windows)** | `0x00000001_40000000` | Mapped exactly at image base if available, or relocated using `.reloc` table if ASLR is enforced. |
| **ELF64 (Linux)** | `0x00000000_00400000` (ET_EXEC) or `0x00005555_xxxx` (ET_DYN / PIE) | Mapped according to ELF `p_vaddr`. PIE executables loaded with randomized base in user space. |
| **Shared Libraries** | Dynamic Allocation | Dynamic loader (`ntdll.dll` or `ld-linux.so`) mapped into high canonical user addresses (`0x00007FFF_xxxx`). |

Because Windows PE images and traditional Linux ELF executables use non-overlapping default base addresses (`0x140000000` vs `0x400000`), a single address space can theoretically host both a PE module and an ELF module simultaneously (crucial for hybrid interoperability and shared memory IPC).

---

## 4. System Call Dispatching Mechanics

In 64-bit Long Mode on x86_64, userland issues the `syscall` instruction. The CPU performs:
1. Loads `RIP` from `MSR_LSTAR` (Long System Target Address Register).
2. Clears flags according to `MSR_SFMASK`.
3. Loads `CS` and `SS` selectors from `MSR_STAR`.
4. Saves user `RIP` into `RCX` and user `RFLAGS` into `R11`.

```rust
#[no_mangle]
pub extern "C" fn sys_call_handler(context: &mut TrapFrame) {
    let current_thread = get_current_thread();
    
    match current_thread.personality {
        ProcessPersonality::Windows { .. } => {
            // Syscall number is in EAX
            // Arguments in RCX, RDX, R8, R9 + stack (Microsoft x64 ABI)
            nt_executive_dispatch(context);
        }
        ProcessPersonality::Linux { .. } => {
            // Syscall number is in RAX
            // Arguments in RDI, RSI, RDX, R10, R8, R9 (System V AMD64 ABI)
            linux_pico_dispatch(context);
        }
    }
}
```

This single hardware entry point ensures zero overhead for personality switching. There is no VM exit, no hypervisor interception, and no userland context switch overhead.

---

## 5. Reusable Open-Source Components

To avoid reinventing solved engineering domains, Nexus OS reuses proven open-source implementations:

1. **UEFI Boot Services**: Standard UEFI x86_64 protocols for memory map collection, ACPI RSDP discovery, and GOP framebuffer configuration.
2. **Wine Userland Components**: User-space libraries (`kernel32`, `user32`, `gdi32`, `advapi32`) under LGPLv2.1 to provide the Win32 application surface.
3. **Mesa Graphics Stack**: Open-source Vulkan drivers (RADV, ANV, NVK) ported to communicate with the Nexus OS DRM driver layer.
4. **Musl libc**: Clean, standards-compliant, lightweight C library for native Linux ELF binaries.
