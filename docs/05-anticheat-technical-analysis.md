# Anti-Cheat Systems: Technical Analysis & Research Strategy

## Status and evidence correction (2026-10-11)

**Historical research document; not a verified internal specification of Vanguard.** References to exact ELAM behavior, server-side TPM quotes, PCR validation rules, PatchGuard inspection, callback lists, compatibility outcomes for individual third-party games, and vendor signature requirements may include hypotheses from public material. The proprietary Vanguard implementation and acceptance policy are not fully documented. The [updated Vanguard study](10-vanguard-feasibility-study.md) must also distinguish public facts from hypotheses; do not interpret a quoted procedure as demonstrated fact.

The project-level acceptance gate remains **legitimate League of Legends and VALORANT on a physical Nexus installation with vendor-approved anti-cheat behavior**. Existing Phase 3.6 WDM driver execution is an experimental building block, **not** Vanguard compatibility, and success with one vendor's anti-cheat would not automatically establish others' acceptance. There must be no spoofing, fake attestation or evasion.

Research into Riot support/approval should run in parallel with engineering; it must not be deferred until all GPU/UI work is complete. Relevant priorities and ongoing risks are tracked in the [roadmap](04-roadmap-and-phases.md).


This document provides a comprehensive technical breakdown of modern kernel-level anti-cheat solutions (specifically **Riot Vanguard** used in *Valorant* and *League of Legends*, and **Easy Anti-Cheat / BattlEye**), analyzing their kernel interactions, cryptographic attestation mechanisms, and the realistic engineering hurdles for third-party operating systems.

---

## 1. The Anti-Cheat Threat Model

Historically, game cheats operated in user space by injecting DLLs, reading process memory (`ReadProcessMemory`), or modifying game assembly instructions. Anti-cheats responded by deploying userland hooks.

Cheats then escalated into kernel space:
- Cheaters loaded unsigned or vulnerable signed third-party drivers (BYOVD - Bring Your Own Vulnerable Driver) to directly alter game memory from Ring 0, bypassing userland security hooks.
- Cheaters used DMA (Direct Memory Access) PCIe cards to read physical RAM over hardware buses without the host CPU executing cheat instructions.

In response, game publishers deployed **Ring 0 / Early-Boot Anti-Cheat Drivers**.

---

## 2. Riot Vanguard (`vgk.sys`) Deep Dive

Riot Vanguard represents the most sophisticated consumer anti-cheat stack.

### 2.1 Boot Chain & Driver Loading (ELAM)
- Vanguard consists of two primary components:
  1. `vgk.sys`: Ring 0 kernel-mode driver.
  2. `vgc.exe`: Userland Windows service running under `SYSTEM` privileges.
- `vgk.sys` registers as an **Early Launch Anti-Malware (ELAM)** driver. Windows initializes ELAM drivers before any regular third-party drivers are allowed to start.
- This allows Vanguard to build a whitelist of loaded drivers and verify that no hypervisor, debugger, or unapproved driver is present in memory.

### 2.2 Kernel Integrity Checks & PatchGuard
- On genuine Windows x86_64, Microsoft implements **Kernel Patch Protection (PatchGuard / KPP)**. KPP uses randomized, obfuscated timers to check the integrity of:
  - System Service Descriptor Table (SSDT).
  - Interrupt Descriptor Table (IDT) and Global Descriptor Table (GDT).
  - Kernel control registers (`CR0`, `CR3`, `CR4`, MSR `LSTAR`).
  - Kernel code pages (`ntoskrnl.exe`, `hal.dll`).
- Vanguard runs independent watchdogs that replicate and extend these checks. If a kernel does not implement exact Windows memory paging tables or if syscall routing is hooked in an unfamiliar manner, Vanguard triggers an immediate crash or server kick.

### 2.3 Hardware Attestation: TPM 2.0 & Secure Boot
On Windows 11, Vanguard mandates:
1. **UEFI Secure Boot**: Ensures all boot components (`bootx64.efi`, Windows boot manager `bootmgfw.efi`, `winload.efi`, `ntoskrnl.exe`) are signed by Microsoft's Production Root CA.
2. **TPM 2.0 Cryptographic Attestation**:
   - The TPM measures hashes of the firmware, bootloader, kernel, and driver configuration into Platform Configuration Registers (PCRs 0 through 7).
   - Vanguard's backend server requests a **TPM quote** (a cryptographic signature generated using the TPM's non-extractable Endorsement Key).
   - If the quote fails to match a genuine Windows PCR signature, the server rejects the client with error code `VAN9001` or `VAN1067`.

```
+--------------------------------------------------------------------------+
| Game Client (Valorant)                                                   |
+--------------------------------------------------------------------------+
                                    |
                                    v
+--------------------------------------------------------------------------+
| Vanguard Ring-0 Driver (vgk.sys)                                         |
| - Inspects KPCR, SSDT, Page Tables                                       |
| - Requests TPM Quote for PCR 7 (Secure Boot State)                       |
+--------------------------------------------------------------------------+
                                    |
                                    v
+--------------------------------------------------------------------------+
| TPM 2.0 Hardware Chip                                                    |
| - Signs measurement with Endorsement Key (EK)                            |
+--------------------------------------------------------------------------+
                                    |
                                    v
+--------------------------------------------------------------------------+
| Riot Remote Attestation Server                                           |
| - Validates EK certificate against AMD / Intel / Infineon Root CA        |
| - Verifies PCR 7 matches verified Windows 11 Secure Boot Chain           |
| - Decision: ALLOW or DISCONNECT                                          |
+--------------------------------------------------------------------------+
```

---

## 3. Easy Anti-Cheat (EAC) & BattlEye

Unlike Vanguard, EAC and BattlEye support a dual-tier deployment model:
1. **Windows Native**: Ring-0 driver (`EasyAntiCheat.sys` / `BEDaisy.sys`).
2. **Linux / SteamOS / Proton**: Userland bridge (`easyanticheat_x64.so` / `battleye_x64.so`).
   - Developed in partnership with Valve for Steam Deck.
   - Relies on Linux kernel namespaces, seccomp, and userland integrity monitoring rather than ring-0 driver loading.
   - Games like *Apex Legends* and *Arma 3* run on Linux using this native userland bridge.

---

## 4. Nexus OS Research Roadmap for Anti-Cheat Compatibility

To maintain absolute technical honesty: **No independent operating system can claim full Valorant Vanguard compatibility without either Microsoft's proprietary cryptographic boot signatures or an official Riot port.**

However, Nexus OS establishes an **Anti-Cheat Compatibility Research Lab** with actionable technical milestones:

### Milestone 1: Windows NT Kernel Driver Environment
- Provide complete `ntoskrnl.exe` and `hal.dll` export coverage for standard anti-cheat dependencies:
  - Memory scanning: `MmCopyVirtualMemory`, `MmIsAddressValid`, `MmMapLockedPagesSpecifyCache`.
  - Process notification routines: `PsSetCreateProcessNotifyRoutineEx`, `PsSetCreateThreadNotifyRoutine`.
  - Object callbacks: `ObRegisterCallbacks` (to protect game handles).
  - Registry & File I/O: `ZwQueryValueKey`, `ZwCreateFile`.

### Milestone 2: Kernel Driver Sandbox
- Build an isolated kernel driver test harness within Nexus OS to load and execute real `.sys` binaries in a controlled Ring-0 environment, tracing every accessed memory structure and unhandled export.

### Milestone 3: Userland Anti-Cheat Bridge (Proton/SteamOS Parity)
- Fully support the Linux-native userland bridges for EAC and BattlEye through our Linux Pico subsystem, enabling competitive games with native Linux anti-cheat configurations.
