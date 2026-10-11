# Nexus OS: Hybrid NT + Linux Operating System

[![CI Status](https://github.com/Stoltembergg/Nexus-OS/actions/workflows/ci.yml/badge.svg)](https://github.com/Stoltembergg/Nexus-OS/actions)
[![License](https://img.shields.io/badge/License-Apache_2.0_OR_MIT-blue.svg)](LICENSE)
[![Target](https://img.shields.io/badge/Target-x86__64_UEFI-orange.svg)](#architecture)
[![Phase](https://img.shields.io/badge/Phase-3.5_Closed_%7C_3.7_Closed-brightgreen.svg)](docs/04-roadmap-and-phases.md)

> **Current status (2026-10-11; Phase 3.7 evidence: [PR #10, CI run 38163656509](https://github.com/Stoltembergg/Nexus-OS/actions/runs/38163656509), tested code revision `40f985e`):** evidence below comes from an **emulated QEMU/OVMF guest**, a hosted Windows runner and host tests in CI. **Nothing has been validated on physical hardware.** This is **not** Windows, Linux, third-party driver or Vanguard compatibility.
>
> - [Phase 3.5 kernel hardening](docs/09-phase3.5-kernel-hardening.md) is **closed**: audited defects have regression tests; its five-job closure run was green (PRs #3–#6).
> - [Phase 3.7 NT driver hardening](docs/12-phase3.7-nt-driver-hardening.md) is **closed within its revised scope**. CI run 38163656509 passed all six jobs: 62/62 official WDK ABI entries match; three MSVC-built test drivers compile, link, load and run; layout/import negative controls reject injected faults; MSVC outputs pass the guest QEMU suite; and committed fixtures reproduce with clang-cl 19.1.7.
> - **IRQL is routed to CR8 but masks no interrupts**: interrupts stay disabled and there is no APIC yet. Hardware-aware IRQL, real waits/timers/threads, object references and full IRP completion remain Phase 4 work.
> - Physical installation, Vulkan acceleration, Nexus Shell and OTA are not implemented; Phase 4 has not been implemented by this work.

**Nexus OS** is an open-source, research-driven hybrid operating system designed to execute Windows (PE/PE32+) and Linux (ELF64) binaries natively on x86_64 bare-metal hardware without relying on virtual machines or emulation layers.

---

## 1. Project Overview & Motivation

Modern systems are fractured into two dominant user-facing paradigms:
1. **Windows NT Architecture**: The gold standard for commercial desktop games, enterprise software, Win32 API richness, and kernel-mode anti-cheat systems.
2. **Linux / POSIX Architecture**: The industry standard for open driver stacks (AMDGPU, Mesa, Intel, DRM/KMS), high-performance memory management, server computing, and developer toolchains.

Existing solutions either:
- Run full virtual machines (WSL 2, KVM, Hyper-V) with incompatible product assumptions for Nexus' no-VM requirement;
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

1. **Bare Metal Execution (goal)**: boot directly on UEFI x86_64 machines. Today this is demonstrated **only in an emulated QEMU/OVMF guest**; no physical machine has been tested.
2. **Dual-Personality Dispatch**: Fast system call routing distinguishing NT syscalls from Linux syscalls with zero hypervisor overhead.
3. **Unified Memory & Address Space**: PE images (default 0x140000000) and ELF binaries (default 0x400000 or ASLR base) mapped seamlessly using standard 4-level x86_64 page tables.
4. **Anti-Cheat research:** standard NT drivers can be validated independently; Vanguard compatibility and vendor acceptance remain unproven and may need cooperation with Riot. No bypass, spoofing or hidden hypervisor strategy.

---

## 3. Repository structure (selected components)

```text
.github/workflows/ci.yml       # host checks, QEMU/OVMF integration
crates/nexus-boot/             # UEFI entry
crates/nexus-kernel/           # x86_64 kernel, VMM, Ring 3, driver host
crates/nexus-loader/           # PE/ELF and NT driver image processing
crates/nexus-abi/              # personality-aware syscall interfaces
crates/nexus-types/            # ABI structs and core types
crates/nexus-poc/              # host-side exploratory PoC
docs/                          # architecture, feasibility, historical evidence and roadmap
scripts/                       # build, test, hardening and fixture helpers
tests/fixtures/nt_driver/      # test WDM driver code and fixture
```

---

## 4. Quickstart & Phase 0 Verification

### Prerequisites
- **Rust Toolchain**: pinned to **1.98.0** by `rust-toolchain.toml` (installed automatically by `rustup`; includes the `x86_64-unknown-uefi` target). Rust 1.99.0 fails to link the UEFI kernel ([issue #2](https://github.com/Stoltembergg/Nexus-OS/issues/2)).
- **QEMU + OVMF** and **Python 3** for the guest test suite
- **CMake**: 3.20+
- **Git**

### Running the Proof of Concept
The Phase 0 host PoC inspects PE/ELF parsing and routing; it does not boot the kernel or prove full Windows/Linux compatibility. QEMU integration and security tests are separate:

```bash
# Clone the repository
git clone https://github.com/Stoltembergg/Nexus-OS.git
cd nexus-os

# Run all unit and integration tests
cargo test --workspace

# Run the Phase 0 interactive loader demonstration
cargo run -p nexus-poc

# Negative tests for the QEMU runner itself
python3 scripts/test-hardening-runner.py

# On a configured QEMU/OVMF development machine (emulated guest, not hardware)
cargo build --locked -p nexus-boot --target x86_64-unknown-uefi
python3 scripts/test-hardening.py --ram 256 --cpu max --timeout 120
```

---

## 5. Development phases, shell and updates

See the [authoritative roadmap](docs/04-roadmap-and-phases.md) for dependency gates, phase acceptance criteria and evidentiary limits.

- [x] **Phase 0** — PE32+/ELF64 loader and routing prototype (host tests)
- [x] **Phase 1** — UEFI/GOP boot demonstration (QEMU/OVMF)
- [x] **Phase 2** — Minimal freestanding ELF64 Ring 3 and syscall demonstration (QEMU)
- [x] **Phase 3** — Freestanding dual PE32+/ELF64 cooperative execution (QEMU)
- [x] **Phase 3.5** — kernel hardening and architecture validation (**closed 2026-10-11**; QEMU + CI evidence, [criteria](docs/09-phase3.5-kernel-hardening.md))
- [x] **Phase 3.6** — targeted MSVC-compiled WDM driver Ring 0 PoC (not general driver support)
- [x] **Phase 3.7** — NT driver runtime hardening (**closed within revised scope**, PR #10): official WDK/MSVC ABI and driver checks, negative controls, compiler-specific fixture reproducibility and guest execution passed in CI run 38163656509. Interrupt-aware IRQL remains Phase 4 work.
- [ ] **Phase 4+** — planned, not implemented here: ACPI/APIC and real IRQL, preemption, threads/timers and blocking waits, Object Manager, IRP Manager, storage, runtimes, graphics, hardware and real applications.

**Graphical interface decision:** **Nexus Shell** uses the **Niri compositor + iNiR Shell**, ported/adapted to Nexus APIs (Wayland, Qt/QML/Quickshell integration); **not running yet**. See the [architecture](docs/03-system-architecture.md) and [graphics feasibility review](docs/06-drm-kms-feasibility-revision.md).

**Update strategy:** **Nexus Update** uses signed A/B system images, independent boot fallback, offline USB updates before sustained physical installation, and eventually GitHub Releases OTA with Nightly/Beta/Stable channels. See the [detailed OTA plan](docs/12-nexus-update-architecture.md). **No updater is implemented yet.**

**Project success criterion:** legitimate online **League of Legends and VALORANT** gameplay on Nexus OS with Riot Vanguard accepted, on real hardware and with no Windows installation, VM or evasion. This is **not yet demonstrated** and is subject to Riot acceptance beyond binary compatibility.

---

## 6. License & Legal Disclaimer

- This project is licensed under dual [Apache-2.0](LICENSE) or [MIT](LICENSE).
- All reverse engineering and architecture analyses follow strict clean-room principles.
- Trademarks (Windows, ReactOS, Wine, Riot Games, Vanguard, League of Legends) belong to their respective holders and are referenced for interoperability and technical research purposes under fair use.
