# Nexus OS: Hybrid NT + Linux Operating System

[![CI Status](https://github.com/hybrid-os/nexus-os/actions/workflows/ci.yml/badge.svg)](https://github.com/hybrid-os/nexus-os/actions)
[![License](https://img.shields.io/badge/License-Apache_2.0_OR_MIT-blue.svg)](LICENSE)
[![Target](https://img.shields.io/badge/Target-x86__64_UEFI-orange.svg)](#architecture)
[![Phase](https://img.shields.io/badge/Phase-3.5_Hardening_in_progress-orange.svg)](docs/09-phase3.5-kernel-hardening.md)

> Current status: Phase 3.5 hardening is in progress. QEMU validates a bounded freestanding PE32+/ELF64 execution profile; general Windows/Linux application compatibility, preemption and SMP remain unvalidated. See [the hardening report](docs/09-phase3.5-kernel-hardening.md) for evidence and limitations.

**Nexus OS** is an open-source, research-driven hybrid operating system designed to execute Windows (PE/PE32+) and Linux (ELF64) binaries natively on x86_64 bare-metal hardware without relying on virtual machines or emulation layers.

---

## 1. Project Overview & Motivation

Modern systems are fractured into two dominant user-facing paradigms:
1. **Windows NT Architecture**: The gold standard for commercial desktop games, enterprise software, Win32 API richness, and kernel-mode anti-cheat systems.
2. **Linux / POSIX Architecture**: The industry standard for open driver stacks (AMDGPU, Mesa, Intel, DRM/KMS), high-performance memory management, server computing, and developer toolchains.

Existing solutions either:
- Run full virtual machines (WSL 2, KVM, Hyper-V) with severe hardware virtualization overhead, latency, and anti-cheat incompatibility;
- Rely purely on user-space translation (Wine/Proton), which cannot run kernel drivers (`.sys`), anti-cheats, or native NT kernel services;
- Attempt to patch ancient monolithic kernels (Longene/LUK), suffering insurmountable architectural rot.

**Nexus OS** implements a clean-slate, dual-personality hybrid executive kernel inspired by:
- **Windows NT Executive & ReactOS**: Object manager, handle table, asynchronous I/O packets (IRP), and PE image loading.
- **WSL 1 (Pico Process Architecture)**: High-speed, in-kernel translation of POSIX syscalls into native executive primitives.
- **Modern Linux Driver Stack**: Clean driver model abstractions for bare-metal graphics (Vulkan/DRM) and modern NVMe/UEFI platforms.

---

## 2. Architectural Pillars

```
+---------------------------------------------------------------+
|                      User Applications                         |
|     Windows Binaries (PE/EXE)         Linux Binaries (ELF)    |
|       (Win32, DirectX/Vulkan)           (POSIX, glibc/musl)   |
+-----------------------------------+---------------------------+
| Userland Runtimes (ntdll.dll)     | Userland Runtimes (libc)  |
+-----------------------------------+---------------------------+
|                          Ring 3 / Ring 0                      |
|=================== SYSCALL / SYSENTER (MSR LSTAR) ============|
|                                                               |
|        +---------------------------------------------+        |
|        |           Dual-Personality Dispatcher       |        |
|        +----------------------+----------------------+        |
|                               |                               |
|        v                      v                               |
|   +-------------------+  +--------------------+               |
|   | NT Executive Subsys|  | Linux Pico Subsystem|              |
|   | (Zw*, Ob*, Io*, Ps*)| | (POSIX 64-bit ABI) |              |
|   +---------+---------+  +---------+----------+               |
|             |                      |                          |
|             +----------+-----------+                          |
|                        |                                      |
|                        v                                      |
|             +---------------------+                           |
|             | Unified Kernel Core |                           |
|             | - 4-Level Paging    |                           |
|             | - Object & Handles  |                           |
|             | - Hybrid Scheduler  |                           |
|             +----------+----------+                           |
|                        |                                      |
|                        v                                      |
|             +---------------------+                           |
|             | Hardware Abstraction| (HAL / UEFI / ACPI)       |
+-------------+---------------------+---------------------------+
```

1. **Bare Metal Execution**: Boots directly on UEFI x86_64 machines.
2. **Dual-Personality Dispatch**: Fast system call routing distinguishing NT syscalls from Linux syscalls with zero hypervisor overhead.
3. **Unified Memory & Address Space**: PE images (default 0x140000000) and ELF binaries (default 0x400000 or ASLR base) mapped seamlessly using standard 4-level x86_64 page tables.
4. **Anti-Cheat Research Framework**: Rigorous reverse engineering and analysis of kernel-level anti-cheat drivers (Vanguard, EAC, BattlEye) to map out ring-0 dependencies, PatchGuard integrity checks, and TPM 2.0 attestation constraints.

---

## 3. Repository Structure

```
├── .github/
│   └── workflows/
│       └── ci.yml               # Automated CI pipeline (lint, test, build)
├── docs/                        # Deep technical specifications & research
│   ├── 01-reference-projects-analysis.md
│   ├── 02-kernel-feasibility-study.md
│   ├── 03-system-architecture.md
│   ├── 04-roadmap-and-phases.md
│   └── 05-anticheat-technical-analysis.md
├── crates/                      # Core Rust modular codebase
│   ├── nexus-types/             # Core OS types (Status, Errno, Process, Memory)
│   ├── nexus-loader/            # Native PE32+ and ELF64 parser & mapper
│   ├── nexus-abi/               # Dual ABI system call dispatcher (NT + Linux)
│   ├── nexus-poc/               # Phase 0 verified Proof-of-Concept runner
│   └── nexus-boot/              # UEFI bootloader stub (x86_64)
├── fixtures/                    # Test PE and ELF binary payloads
├── scripts/                     # Cross-platform build & test helpers
│   ├── build.ps1
│   ├── build.sh
│   └── test.ps1
├── Cargo.toml                   # Workspace manifest
└── CONTRIBUTING.md              # Engineering guidelines & conventions
```

---

## 4. Quickstart & Phase 0 Verification

### Prerequisites
- **Rust Toolchain**: `stable` (1.88+ recommended, x86_64 target)
- **CMake**: 3.20+
- **Git**

### Running the Proof of Concept
The Phase 0 PoC demonstrates parsing, validation, virtual memory mapping, and dual ABI routing inspection (unimplemented services return errors) for both a native Windows PE32+ binary and an ELF64 Linux binary:

```bash
# Clone the repository
git clone https://github.com/hybrid-os/nexus-os.git
cd nexus-os

# Run all unit and integration tests
cargo test --workspace

# Run the Phase 0 interactive loader demonstration
cargo run -p nexus-poc
```

---

## 5. Development Phases

- [x] **Phase 0: Specifications, Architecture & Minimal Dual Loader PoC** (host parsing/routing only)
- [x] **Phase 1: Bare-Metal UEFI Bootloader & Microkernel Initialization** (Paging, GDT, IDT, Serial)
- [x] **Phase 2: Hybrid Process Scheduler & Memory Subsystem** (VAD / mm_struct unified core)
- [x] **Phase 3: Unified Freestanding PE32+/ELF64 Execution & Cooperative Scheduling** (see validation limits)
- [ ] **Phase 3.5: Kernel Hardening & Architecture Validation** ([in progress](docs/09-phase3.5-kernel-hardening.md))
- [ ] **Phase 4: NT Executive Subsystem & Win32 Userland** (Relocations, IAT, DirectX/Vulkan bridge)
- [ ] **Phase 5: Native GPU Acceleration (DRM/KMS) & Anti-Cheat Research Lab**

---

## 6. License & Legal Disclaimer

- This project is licensed under dual [Apache-2.0](LICENSE) or [MIT](LICENSE).
- All reverse engineering and architecture analyses follow strict clean-room principles.
- Trademarks (Windows, ReactOS, Wine, Riot Games, Vanguard, League of Legends) belong to their respective holders and are referenced for interoperability and technical research purposes under fair use.
