# Nexus OS — Roadmap and Implementation Gates

**Updated:** 2026-10-11  
**Scope:** experimental hybrid NT/Linux kernel, Nexus Shell, hardware enablement, and secure OTA updates.  
**Status rule:** a passing host test is not evidence of guest Ring 0 execution; a QEMU result is not proof of real-hardware compatibility; a laboratory driver is not general NT driver support.

This is the **current planning source of truth**. Detailed implementation reports (Phases 0–3.6) remain historical evidence, including known limits, and are not retroactively reclassified as production ready.

## Product contract

- **One independent Nexus kernel**, with NT PE32+ and Linux ELF64 personalities sharing a core executive. No second Linux kernel, Windows guest, or VM-based application execution in the product.
- **Nexus Shell = Niri compositor + iNiR Shell**, adapted through explicit Nexus graphics/input/IPC APIs. Qt/QML/Quickshell and Wayland ports are research and implementation tasks, not functional dependencies today.
- **Nexus Update** will distribute signed A/B system images, initially offline and eventually from GitHub Releases. The updater is mandatory **before** sustained SSD installation; see [OTA architecture](12-nexus-update-architecture.md).
- **League of Legends and VALORANT with legitimate Riot Vanguard support** is the mandatory **project-success criterion**, not a feature promised by current engineering demos. Vendor acceptance is an independent external gate. Never bypass, falsify, or camouflage anti-cheat integrity checks.
- Hardware drivers cannot be assumed to load unchanged from Linux. Evaluate ports, stable driver classes, and vendor-device ownership explicitly. GPU acceleration is an unresolved research track; see [DRM/KMS review](06-drm-kms-feasibility-revision.md).

## Demonstrated progress versus maturity

| Milestone | Recorded evidence | Actual maturity / open gates |
| --- | --- | --- |
| **0 — Research + PE/ELF parser PoC** | Host parsing, loader and syscall routing tests | Prototype; no general application ABI compatibility |
| **1 — UEFI boot** | QEMU/OVMF startup and basic PMM/IDT/GDT | Experimental; not tested as broadly installable physical hardware |
| **2 — Ring 3 ELF execution** | Guest syscall, exit and supervisor memory-fault tests | Minimal freestanding ELF support; not a complete Linux ABI |
| **3 — Dual PE32+/ELF64** | Interleaved guest processes and cooperative yields | Test binaries only; preemption, SMP, runtimes and real-world apps missing |
| **3.5 — Kernel hardening** | [Closure criteria and evidence](09-phase3.5-kernel-hardening.md); [audit](13-auditoria-fases-3.5-3.7.md) | **Closed (2026-10-11)** in QEMU/OVMF + CI: audited defects fixed with regression tests, CI green on 5 jobs after PRs #3–#6. No physical-hardware evidence; toolchain pinned to 1.98.0 (issue #2) |
| **3.6 — NT WDM driver PoC** | [MSVC-built .sys](11-phase3.6-nt-driver-validation.md) executed in QEMU Ring 0; I/O and unload | **PoC achieved** with Nexus-defined NT structs, not arbitrary .sys support. RWX mapping and silent leaks were fixed in 3.7 work (PRs #4–#6) |
| **3.7 — NT runtime hardening** | [Revised scope](12-phase3.7-nt-driver-hardening.md): PTE-verified W^X (exact page count), fail-closed loader + DIR64 fixture, leak-checked lifecycles, 14 Ring 0 NT-semantics checks with bugchecks (PRs #4–#6) | **Open.** Remaining: official-WDK rebuild + `sizeof`/`offsetof` table (PR-5, blocked on CI workflow permission) and struct alignment to the real `wdm.h` (PR-6). IRQL = software-validated value routed to CR8 **without interrupt masking**; interrupt-aware IRQL moved to Phase 4 |

3.5 was closed on explicit criteria, not because 3.6 reported success. Do not mark 3.7 complete until PR-5 and PR-6 land with green CI. See the [Vanguard study](10-vanguard-feasibility-study.md) for claims requiring explicit evidence.

## Critical path: kernel to first physical installation

### Gate K — Stabilization (3.5 + 3.7, blocking)

1. Fix documented user pointer access permissions, kernel/user isolation, page ownership, memory cleanup, context saving, trapping and test-harness false positives.
2. Transition driver mapping to **W^X** (temporary staging followed by executable read-only code and writable non-executable data); reject incompatible sections instead of defaulting to RWX.
3. ~~Model NT IRQL with true interrupt masking~~ **Moved to Phase 4 (Gate E).** 3.7 enforces IRQL direction/limits with bugchecks and routes IRQL to CR8, without interrupt sources.
4. Rebuild the test drivers with the official WDK headers in CI, generate a `sizeof`/`offsetof` table for key NT structs, and align `nexus-types` and fixtures to it (PR-5, PR-6); then run a WDK-built driver in the guest, including unload/reload, failures and malformed requests.
5. Differentiate guest evidence, host tests, hardware tests, and unverified statements; maintain strict negative tests.

**Exit:** reproducible QEMU guest tests plus a written limitations and security audit ([doc 13](13-auditoria-fases-3.5-3.7.md)). No assertion of compatibility with Vanguard. Status: 3.5 closed; 3.7 open pending items 4 above.

### Gate E — Core executive & device foundations (Phase 4)

- Preemptive single-core scheduling before SMP; per-thread context, FPU/SIMD, locks, interrupt routing, timers, cancellation, object lifetimes and handles.
- **Transferred from 3.7:** real IRQL with LAPIC/IOAPIC, PIC masking, IRQ vectors and IF=1, with a test that a pending interrupt is held while TPR ≥ its class and delivered when TPR is lowered (plus the CR8 check in `run_user_process`); the NT pool-registry spin lock must raise to `DISPATCH_LEVEL` or disable interrupts once ISRs/DPCs can allocate; blocking `KeWaitForSingleObject` with waiter lists, wake-ups and real timeouts; device-object reference counting so a reused device address cannot be mistaken for a stale pointer (`ObReferenceObject`-style deferred deletion).
- Hardware discovery (ACPI/PCIe), block-device interfaces, DMA/IOMMU and IRQ APIs. VFS, initial FAT32/GPT support, durable flush and mount semantics.
- Production-style process lifecycle, IPC and basic user services needed by the update agent and display stack.
- **Exit:** crash-resistant multi-process test suite and persistent read/write on a QEMU block device with power-loss fault injection.

### Gate R — Linux and Windows runtimes (Phase 5)

- Expand Linux syscalls, ELF dynamic linking, signals, threads, futex, filesystem and musl bootstrap incrementally.
- Expand NT object/I/O/process APIs, file handles, NTDLL, DLL linking and Win32 userland incrementally.
- Integrate WDM/KMDF capabilities without assuming a simple driver fixture generalizes to third-party drivers.
- **Exit:** independent externally built console programs on both personalities, with documented ABI coverage.

### Gate G — Graphics/display/input research and implementation (Phase 6)

- Stage G0: existing UEFI GOP framebuffer and software rendering; establish display surface and input APIs.
- Stage G1: virtio-gpu in QEMU and a minimal 2D compositor demonstration; display/input drivers and buffer sharing.
- Stage G2: **separate** real GPU feasibility efforts for AMD/Intel/NVIDIA; design kernel DRM-equivalent capabilities, MMIO, DMA, synchronization, firmware, display modes and security boundaries.
- Stage G3: validated Vulkan/Mesa adapter and performance tests only after a real kernel-device implementation exists; **do not** assume Linux DRM/KMS or userspace Mesa works unchanged.
- **Exit:** real device(s) selected and tested; no blanket GPU compatibility claim.

### Gate S — Nexus Shell (Phase 7)

- Maintain Niri and iNiR upstream lineage and license compliance; audit Smithay, DRM/GBM, libinput, Wayland, Qt, QML and Quickshell portability.
- Implement adapter backends for Nexus display, input, IPC and app lifecycle. Stage compositor functionality before porting the full shell.
- Windows window integration is a distinct Win32/USER32/GDI compatibility task; Niri alone does not run Windows GUI applications.
- **Exit:** functional desktop on a supported hardware profile; launcher, windows, input, and updater status interface.

### Gate I — First practical bare-metal installation (Phase 8; may be brought forward)

- Select a **dedicated test SSD** and a narrow supported hardware profile. Implement storage/USB/console, recovery boot, installer and durable boot metadata.
- Do not offer an in-place install over a user's main OS at this maturity.
- **Exit:** install once, boot from SSD, restore/recover, and perform **signed offline A/B update with rollback** without loss of the data partition. That is the minimum requirement for sustained physical testing.

### Gate W — Network and OTA delivery (Phase 9; may proceed independently)

- DNS, TCP/TLS, clock validation, restartable downloads, quota/backoff and authenticated signed channel metadata.
- Download artifacts from GitHub Releases, then verify using Nexus-owned trust roots; CI-generated hashes alone are not sufficient.
- Integrate update notifications in iNiR; install agent remains privileged and separate from the desktop.
- **Exit:** signed nightly/beta/stable update from remote release, interrupted network/disk tests and boot rollback.

### Gate V — Games and Vanguard legitimacy (permanent parallel track; mandatory for 1.0)

- Driver ABI conformance and WDM/KMDF breadth, TPM2/Secure Boot attestation **as publicly documented**, NT security and modern graphics performance.
- Riot Client, game rendering, network services and anti-cheat compatibility must be demonstrated separately.
- Seek explicit vendor support/approval. Unpublished details of Vanguard remote attestation remain hypotheses, not established facts.
- **Nexus OS 1.0 acceptance:** legitimate League of Legends **and** VALORANT online gameplay, complete matches without anti-cheat rejection, on supported real hardware, and no VM, bypass or Windows installation. Current feasibility is **unproven and may depend on Riot**.

## Independent Nexus Update workstream (U0–U7)

| Stage | Dependency | Exit test |
| --- | --- | --- |
| **U0 — Contracts / threat model** | Now | A/B layout, metadata, signature policy, downgrade prevention, signed release format, rollback invariants reviewed |
| **U1 — Boot-control prototype** | U0, EFI boot manager | QEMU chooses signed candidate with bounded attempts and autonomous fallback to last-good |
| **U2 — Storage/installer integration** | Gate E block/VFS | GPT + system A/B + persistent data + recovery disk, power-cut safe |
| **U3 — Offline signed update** | U1/U2 | v0.1 to v0.2 via USB and rollback on failure, no reinstall |
| **U4 — GitHub Releases transport** | Network/TLS/clock | Verified signed metadata and payload, retry/resume/error handling |
| **U5 — Shell UI** | Gate S | iNiR shows channel, progress, status, reboot/rollback without raw disk access |
| **U6 — Release security hardening** | U0–U5 | Key rotation/revocation, TUF-style metadata or equivalent reviewed design, independent adversarial audit |
| **U7 — Delta/component updates** | Stable A/B base | Small signed incremental updates with measured safety and bandwidth wins |

**Order constraint:** U0 begins now. U1 can proceed in QEMU. **U2 and U3 are required before the first sustained SSD installation**, even if U4 and U5 are not ready. Details and acceptance tests: [Nexus Update architecture](12-nexus-update-architecture.md).

## Evidence, release and security policy

- Use QEMU/OVMF for repeatable engineering; never call QEMU a real physical hardware acceptance test.
- Unit tests, lint and serial markers do not by themselves prove safety. Retain raw logs, QEMU exit status, negative checks, image hashes and test fixture provenance.
- CI artifacts are not implicitly trusted software updates. Signing authority must be independent of ordinary CI jobs; keys never committed to the repository or built into images.
- No boot-control/partition destructive changes without recovery media, data backups, and a proof of power-loss correctness.
- Nightly, Beta and Stable are distinct signed release channels with explicit opt-in and anti-rollback policy.
- Any GPL/LGPL components from ReactOS, Niri/iNiR, Wine, Linux or other sources require per-component license provenance and compatibility review.
- All userspace/driver feature claims require runtime evidence on supported configurations.

## Decisions and references

- [System architecture](03-system-architecture.md)
- [Kernel feasibility](02-kernel-feasibility-study.md)
- [GPU dependency analysis](06-drm-kms-feasibility-revision.md)
- [Fase 3.5 hardening (closed)](09-phase3.5-kernel-hardening.md)
- [Fase 3.7 NT driver hardening (open, revised scope)](12-phase3.7-nt-driver-hardening.md)
- [Fases 3.5/3.7 closure audit](13-auditoria-fases-3.5-3.7.md)
- [Vanguard feasibility](10-vanguard-feasibility-study.md)
- [Phase 3.6 driver demonstration](11-phase3.6-nt-driver-validation.md)
- [Nexus Update detailed design](12-nexus-update-architecture.md)
