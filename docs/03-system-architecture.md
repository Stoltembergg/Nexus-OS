# Nexus OS: System Architecture Specification

> **2026-10-11 status notice:** Sections 1–5 are the original architectural target and contain illustrative pseudocode, not a list of implemented APIs. The decisions and implementation boundaries in **Section 6** and the [updated roadmap](04-roadmap-and-phases.md) supersede earlier claims of completed portability, graphics, drivers or runtimes.


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

This is the intended direct system-call entry design. Performance and security of full personality switching are **not measured or proven** here. No hypervisor is planned as an application runtime; QEMU/OVMF may be used for kernel development.

---

## 5. Reusable Open-Source Components

To avoid reinventing solved engineering domains, Nexus OS reuses proven open-source implementations:

1. **UEFI Boot Services**: Standard UEFI x86_64 protocols for memory map collection, ACPI RSDP discovery, and GOP framebuffer configuration.
2. **Wine Userland Components**: User-space libraries (`kernel32`, `user32`, `gdi32`, `advapi32`) under LGPLv2.1 to provide the Win32 application surface.
3. **Mesa Graphics Stack**: Open-source Vulkan drivers (RADV, ANV, NVK) ported to communicate with the Nexus OS DRM driver layer.
4. **Musl libc**: Clean, standards-compliant, lightweight C library for native Linux ELF binaries.

---

## 6. Current binding decisions and integration contracts (2026-10-11)

### 6.1 Exactly one kernel, two execution personalities

Nexus uses one custom hybrid executive (Rust/C) for CPU, virtual memory, scheduling, interrupts, I/O, security and device ownership. NT PE32+ and Linux ELF64 are **ABI and process personalities**, not a Windows guest and not a second Linux kernel. Only minimal freestanding PE32+/ELF64 guest execution has been demonstrated; normal Win32, glibc/musl and Linux applications require major missing runtime and kernel work.

### 6.2 NT driver boundary

A specific MSVC-compiled WDM `.sys` fixture ran in QEMU Ring 0 with `DriverEntry`, IRP dispatch and unload ([Phase 3.6 report](11-phase3.6-nt-driver-validation.md)). It is **not** proof of general modern WDM/KMDF or `vgk.sys` support. Security debt includes current RWX driver pages, a limited IRQL model, and incomplete independent-driver conformance. The [kernel hardening report](09-phase3.5-kernel-hardening.md) remains an open gate; Phase 3.7 addresses driver runtime hardening.

### 6.3 Graphics and Nexus Shell

The official **Nexus Shell** choice is:
- **Niri** — Wayland compositor/layout/window behavior, adapted to Nexus platform APIs.
- **iNiR Shell** — desktop UX on **Quickshell / Qt / QML**, adapted to Nexus IPC, settings, notification, input, display and runtime facilities.
- **Nexus display/graphics interface** — buffer allocation/sharing, synchronization, display modes, hardware input, window transport and later GPU command submission.

Niri/iNiR must remain clearly sourced with upstream-compatible licensing obligations; an existing Linux Niri/Smithay/Qt binary cannot be assumed to run unchanged on the Nexus kernel. Windows GUI apps require a separate USER32/GDI/Win32 integration layer.

The already demonstrated fallback is UEFI GOP framebuffer and text console. Proposed QEMU **virtio-gpu** is a development milestone, **not** the physical GPU strategy. Real AMD/Intel/NVIDIA support depends on explicit investigation and implementations of modesetting, PCIe, MMIO, VRAM, DMA, IOMMU, firmware, queues and security. Mesa Vulkan ICDs are generally userspace but depend on kernel device interfaces. Do not promise a simple drop-in DRM/KMS port or userspace-only GPU solution; see [DRM feasibility review](06-drm-kms-feasibility-revision.md).

### 6.4 Update and boot reliability contract

[Nexus Update](12-nexus-update-architecture.md) is a required planned service, **not implemented**. The kernel and boot manager must expose versioned, tested interfaces:
- a durable block-device/GPT/VFS API with flush/readback and bounded writes;
- an authenticated, versioned UEFI boot-control structure representing A/B slots, boot attempts and last-known-good;
- an offline recovery path that operates before the shell;
- a Ring 3 update agent with permission-limited service APIs and a separate health confirmation process;
- no write to the currently running system slot, no accidental loss of user data, no confirmation based only on a printed serial marker.

GitHub Releases provides delivery, **not trust**. Independent signed metadata and a pinned Nexus trust root are required. U0 specification begins now; a signed offline A/B update (U1–U3) must pass before any sustained physical SSD installation. GitHub transport (U4) waits on real TLS/network; iNiR integration (U5) waits on the shell.

### 6.5 Acceptance and verification

All proposed contracts must have independent tests and failure-injection cases. Host unit tests != guest Ring 0 tests != physical hardware tests. Project completion ultimately requires **legitimate League of Legends and VALORANT games with accepted Vanguard** on Nexus OS without a Windows installation/VM/bypass. Riot approval and the proprietary anti-cheat trust policy remain external unproven factors. Do not claim a reliable release before those gates are satisfied.
