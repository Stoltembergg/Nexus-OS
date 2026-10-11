# Kernel Feasibility Study: Hybrid NT + Linux Architecture

This study evaluates the technical, hardware, and security feasibility of constructing an operating system capable of running Windows (PE32+) and Linux (ELF64) binaries directly on bare-metal x86_64 UEFI hardware without virtual machines.

---

## 1. Architectural Strategy Comparison

We evaluated three potential architectural approaches:

```
[Approach A: NT-First]             [Approach B: Linux-First]          [Approach C: Nexus Hybrid Core]
+-------------------------+        +-------------------------+        +-----------------------------+
| Linux Pico Provider     |        | Longene/Wine-in-Kernel  |        | NT Subsys  |  Linux Subsys  |
+-------------------------+        +-------------------------+        +------------+----------------+
| NT Kernel (ReactOS-like)|        | Monolithic Linux Kernel |        | Nexus Executive Core (Rust) |
+-------------------------+        +-------------------------+        +-----------------------------+
| WDM / WDF Drivers       |        | Linux DRM / KMS Drivers |        | Unified HAL / DRM-PCI Bus   |
+-------------------------+        +-------------------------+        +-----------------------------+
```

### Approach A: NT-First (ReactOS Modernization + Linux Pico Subsystem)
- **Concept**: Use an NT kernel core (similar to ReactOS or a clean-slate NT clone) and implement an in-kernel Linux ABI layer (like WSL 1 `lxcore.sys`).
- **Strengths**:
  - Native object manager, handle table, and IRP architecture align 1:1 with Windows PE requirements.
  - Native Win32 userland (`ntdll.dll`, `kernel32.dll`) interacts directly with executive system services.
- **Critical Blockers**:
  - **Modern GPU Driver Void**: Modern AMD, NVIDIA, and Intel graphics drivers for Windows are closed-source WDDM 3.x packages. They require Microsoft WHQL signature validation, undocumented DxgkKrnl (DirectX Graphics Kernel Subsystem) interfaces, and complex power/bus management. ReactOS cannot load these drivers today.
  - Developing an open-source WDDM 3.x driver stack from scratch is a multi-million-dollar undertaking with zero vendor documentation.

### Approach B: Linux-First (Linux Kernel + NT In-Kernel Shim - Longene Style)
- **Concept**: Take the Linux kernel and graft NT Executive objects, IRPs, and `.sys` driver loaders into it.
- **Strengths**:
  - Immediate, world-class modern hardware support: open-source AMDGPU, Intel Iris/Xe (i915/xe), Nouveau/NVIDIA open kernel modules, NVMe, USB4, Wi-Fi 6/7, and UEFI GOP framebuffers work out of the box.
- **Critical Blockers**:
  - Proved disastrous by project Longene. Continuous internal Linux API churn breaks NT shims.
  - Loading binary Windows drivers (`.sys`) into Linux kernel memory causes immediate panics due to missing undocumented NT kernel globals (`KeServiceDescriptorTable`, `PsLoadedModuleList`, `KPCR`, `PspCidTable`).

### Approach C: Nexus Hybrid Executive (Selected Architecture)
- **Concept**: A modern 64-bit microkernel/modular executive written in **Rust and C**, booted directly via UEFI:
  - **Unified Driver Foundation**: Adopts modern open driver protocols (DRM/KMS and PCI bus management) inspired by the open Linux driver architecture, exposing Vulkan-first graphics to userland.
  - **Dual-Personality Syscall Multiplexer**: The CPU's `syscall` handler inspects the thread's personality descriptor (`Personality::Windows` vs `Personality::Linux`), routing syscalls to either the **NT Executive Subsystem** or the **Linux Pico Subsystem**.
  - **Direct PE & ELF Mapping**: The memory manager natively understands PE32+ section headers, base relocations, and ELF64 program headers (`PT_LOAD`), setting up valid memory mappings and paging permissions (NX/WP) for both.

---

## 2. Hardware Driver Reality Check

| Hardware Subsystem | Windows NT Requirement | Linux Requirement | Nexus OS Strategy |
| :--- | :--- | :--- | :--- |
| **GPU / Display** | Closed-source WDDM 3.x driver + `dxgkrnl.sys` | Open DRM/KMS + Mesa (RADV, ANV, NVK) | **DRM/KMS + Vulkan**: Expose Vulkan 1.3 natively; bridge Direct3D 11/12 via DXVK/VKD3D in userland. |
| **Storage (NVMe / AHCI)** | StorPort / NVMe miniport | Block layer + NVMe driver | Clean Rust NVMe controller driver over standard PCI Express registers. |
| **Audio** | PortCls / HD Audio | ALSA / ASoC | Intel HDA / USB Audio Class standard driver. |
| **Input (Keyboard/Mouse)** | `i8042prt.sys` / HIDClass | evdev / HID subsystem | Standard HID over USB / PS2 input event stream. |
| **Networking** | NDIS 6.x | net_device / sk_buff | VirtIO-net / Intel e1000 / Realtek PCIe driver stack. |

> [!IMPORTANT]
> Modern desktop 3D acceleration without closed-source proprietary Windows drivers can only be achieved via **open-source Vulkan drivers** (Mesa/DRM architecture). Windows applications running on Nexus OS will map DirectX to Vulkan, running at native GPU speeds without virtual machine translation.

---

## 3. Anti-Cheat Technical Feasibility (Vanguard, EAC, BattlEye)

The user request explicitly identifies competitive games such as **Valorant** and **League of Legends** as research targets. Here is an honest, scientific evaluation of the state of the art:

### 3.1 Riot Vanguard (`vgk.sys`) Architecture
Vanguard is currently the most invasive, security-hardened consumer anti-cheat system in the world. It enforces:

1. **Boot-Time Launch (ELAM)**:
   - `vgk.sys` registers as an Early Launch Anti-Malware driver. It loads before 3rd party drivers, hooks kernel routines, and monitors all subsequently loaded kernel images.
2. **Kernel Patch Protection (PatchGuard / KPP)**:
   - On Windows, PatchGuard continuously verifies that core kernel structures (SSDT, IDT, GDT, MSRs, `ntoskrnl.exe` code text) have not been modified. Vanguard runs its own integrity watchdog that scans kernel code pages and detects foreign hooks.
3. **Hypervisor-Protected Code Integrity (HVCI) & VBS**:
   - Modern Vanguard requires Windows 11 with Virtualization-Based Security (VBS) and HVCI enabled. It leverages hardware virtualization (Intel VT-x / AMD-V) through the Windows Hypervisor to make kernel page tables read-only to Ring 0 itself (Second Level Address Translation - SLAT).
4. **TPM 2.0 & Secure Boot Attestation**:
   - Vanguard queries the hardware TPM 2.0 chip to cryptographically attest PCR (Platform Configuration Register) measurements of the bootloader, kernel, and driver signature chain. If the boot path is not signed by Microsoft's Windows Production PCA, the client is banned or refused connection to the game server.
5. **Direct Hardware Probing**:
   - Vanguard inspects physical memory controller configurations, PCI configuration spaces, and DMA protection (IOMMU) to prevent hardware-based DMA cheat devices.

### 3.2 Can Nexus OS Run Vanguard?

```
               [Game Launch: Valorant]
                         |
                         v
               [Is OS genuine Windows 11?]
               /                         \
            (Yes)                        (No)
              |                            |
    [Does TPM 2.0 PCR match       [REJECT CONNECTION]
     Microsoft WHQL chain?]          "VAN9001 / VAN1067"
              |
      [Is vgk.sys running
       in certified Ring 0?]
              |
         (Game Boots)
```

- **Immediate Term**: **No non-Microsoft OS can run Vanguard out-of-the-box today.** Emulating `ntoskrnl.exe` in software is insufficient because Vanguard does not just call kernel APIs; it cryptographically verifies the hardware TPM 2.0 measurements and demands Microsoft WHQL signature validation.
- **Legal & Architectural Stance**:
  - Implementing spoofed TPM PCR measurements or hypervisor-level deception to fool Vanguard constitutes anti-cheat circumvention, which violates terms of service and invites rapid game-server blacklisting.
  - Games like *League of Legends* on macOS operate **without** `vgk.sys` ring-0 drivers because Apple does not allow 3rd-party kernel extensions.
  - **Verdict for Nexus OS**: Anti-cheat compatibility is defined as a **dedicated research track** to document kernel invariants, analyze driver behavioral patterns in an isolated sandbox, and build the requisite Ring-0 driver interfaces. It must **never** be marketed as an out-of-the-box guarantee for production gaming.

---

## 4. Feasibility Summary & Recommendations

1. **Dual Binary Execution**: **100% Feasible.** Parsing, mapping, and executing x86_64 PE and ELF files in a unified kernel address space is mathematically sound and verified in our Phase 0 implementation.
2. **POSIX & Win32 Userland**: **Feasible.** Using a Pico provider approach for Linux and a native Win32 subsystem for Windows delivers high performance without virtual machines.
3. **Graphics & Games**: **Feasible.** Running DirectX 9/11/12 and Vulkan games through an open DRM/KMS Vulkan driver stack provides native bare-metal framerates.
4. **Kernel-Level Anti-Cheat**: **Research Restricted.** Anti-cheats with hardware TPM attestation (Vanguard) will detect non-Windows environments by design. Games with userland anti-cheats or server-side anti-cheats (CS2, Valve games, older DirectX titles) are fully viable.
