# Architectural Review & Revision: DRM/KMS in an Independent Kernel

## Status update: Nexus Shell and graphics constraints (2026-10-11)

The early document uses absolute terms such as “technically impossible” for a direct DRM/KMS port, and implies that a userspace split solves graphics support. **Interpret these as assessments of large engineering cost, not mathematical impossibility or an implemented design.** GPU initialization, display modes, DMA, command queues, firmware and synchronization all need a real kernel/device contract. Mesa RADV/ANV/NVK userspace components are not standalone GPU drivers on Nexus.

**Official desktop decision:** Nexus Shell will be based on the **Niri Wayland compositor** and **iNiR Shell (Quickshell/Qt/QML)**, preserved as closely as practical to upstream. Port Smithay/Niri platform backends and Quickshell services to Nexus-specific display, input and IPC interfaces. GPL and dependent licensing must be reviewed before redistribution.

**Staged validation:** (1) existing UEFI GOP 2D console, (2) minimal compositor and virtio-gpu in QEMU as a development target, (3) carefully scoped real-hardware GPU driver/API prototype for specific vendor/device, (4) Vulkan acceleration with verified Mesa/kernel interface compatibility, (5) UI integration and fullscreen performance. Do not claim a functional Nexus Shell or Vulkan GPU stack today. See [architecture](03-system-architecture.md) and [roadmap](04-roadmap-and-phases.md).


This document provides a critical review of the graphical stack assumptions made in early architectural drafts, specifically identifying the technical impossibility of embedding the monolithic Linux **DRM/KMS (Direct Rendering Manager / Kernel Mode Setting)** subsystem directly into an independent hybrid kernel without importing the entirety of the Linux kernel source tree.

---

## 1. The Fallacy of "Simple DRM/KMS Re-use"

In early system designs, it is tempting to propose:
> *"We will simply use Linux's open-source DRM/KMS drivers (AMDGPU, Intel i915/Xe, Nouveau) for bare-metal graphics in our custom kernel."*

Upon deeper structural analysis, this proposition is **technically flawed and mirrors the exact failure mode of Project Longene**:

### 1.1 Monolithic Coupling of Linux DRM/KMS
Linux DRM/KMS is not a modular, freestanding graphics library. It is deeply entangled with hundreds of internal, rapidly evolving Linux kernel subsystems:

```
               [Linux DRM/KMS Subsystem (amdgpu / i915 / xe)]
                                      |
     +-----------------+--------------+---------------+------------------+
     |                 |                              |                  |
     v                 v                              v                  v
[DMA-BUF / TTM / GEM] [Linux Waitqueues / Workqueues] [RCU & Spinlocks] [struct page / VMA]
     |                 |                              |                  |
     v                 v                              v                  v
[Memory Allocator]    [Linux Preemption Model]        [Linux Scheduler]  [Linux VFS / Sysfs]
```

To compile `amdgpu.ko` or `i915.ko`, the host kernel must supply:
1. **Linux Memory Management Invariants**: `struct page`, `vm_area_struct`, `shmem_file_setup`, TTM (Translation Table Manager), GEM objects, and dma-buf scatter-gather tables.
2. **Concurrency Primitives**: RCU (Read-Copy-Update), `kthread_worker`, Linux workqueues, completions, wait queues, mutexes, and ww-mutexes (wound-wait mutexes for GPU buffer reservations).
3. **Bus & Power Management**: Linux PCI driver core (`pci_register_driver`), runtime PM (`pm_runtime_get_sync`), ACPI video extensions.
4. **Firmware Loader**: Linux `request_firmware()` expecting standard `/lib/firmware/` root filesystem integration.

### 1.2 The FreeBSD Precedent: `linuxkpi`
FreeBSD achieved DRM/KMS driver re-use only by constructing **`linuxkpi`**—a dedicated, multi-decade compatibility layer consisting of over **150,000 lines of glue code** designed solely to trick Linux DRM drivers into believing they are running inside Linux. Even with FreeBSD's massive engineering resources, updates consistently lag months behind upstream Linux, and subtle synchronization bugs abound.

For a new independent hybrid operating system, attempting to graft Linux DRM/KMS in early phases is an **anti-pattern that guarantees architectural paralysis**.

---

## 2. Realistic, Staged Graphics Architecture for Nexus OS

To achieve high performance, bare-metal stability, and verifiable milestones without impossible dependencies, Nexus OS adopts a **3-stage graphics architecture**:

```
+--------------------------------------------------------------------------+
| Stage 1: UEFI GOP (Graphics Output Protocol) - [Phase 1 Standard]        |
| - Standard 32-bit linear framebuffer configured during boot              |
| - Guaranteed on 100% of modern x86_64 UEFI hardware (Intel, AMD, Nvidia) |
| - Zero hardware-specific driver dependencies                             |
| - Provides double-buffered terminal, text console, and 2D blitting       |
+--------------------------------------------------------------------------+
                                    |
                                    v
+--------------------------------------------------------------------------+
| Stage 2: Hardware-Independent Framebuffer + VirtIO-GPU / RamFB           |
| - SimpleFB / EFI Framebuffer standard handoff                            |
| - VirtIO-GPU 2D/3D driver for accelerated development                    |
| - Linear scanout with page-flipping support                              |
+--------------------------------------------------------------------------+
                                    |
                                    v
+--------------------------------------------------------------------------+
| Stage 3: Modular User-Space / Micro-Driver Architecture (Magma-style)    |
| - Kernel role: Pure MMIO mapping, IOMMU page tables, and MSI-X interrupts|
| - Driver role: GPU command submission, firmware loading, and memory      |
|   eviction run in isolated user-space driver services (like Fuchsia/Redox)|
| - Vulkan-first: Expose standard Vulkan 1.3 ICD without Linux DRM coupling|
+--------------------------------------------------------------------------+
```

### Stage 1: UEFI GOP (Target for Phase 1)
- The UEFI firmware initializes the GPU's display engine into a native high-resolution mode (e.g. 1920x1080 @ 32bpp) via GOP before transferring control to the kernel.
- The bootloader captures `framebuffer_base`, `framebuffer_size`, `width`, `height`, `stride`, and color masks.
- The kernel maps this physical memory region into higher-half virtual space.
- A built-in terminal engine with an embedded font provides real-time logging, diagnostic screens, and graphical output without needing any vendor-specific driver.

---

## 3. Revised Feasibility Conclusions

| Graphical Approach | Feasibility for Independent Kernel | Verdict |
| :--- | :--- | :--- |
| **Direct Linux DRM/KMS in Kernel** | Virtually Impossible without porting 150k+ LoC of Linux kernel internals | **REJECTED** |
| **WDDM 3.x Display Miniport Driver** | Impossible (Closed-source Microsoft WHQL architecture) | **REJECTED** |
| **UEFI GOP Linear Framebuffer** | 100% Feasible, universal across all modern UEFI hardware | **ACCEPTED (Phase 1 Baseline)** |
| **VirtIO-GPU & Microkernel Driver Split** | Fully Feasible, clean modular engineering | **ACCEPTED (Roadmap for Phase 5)** |
