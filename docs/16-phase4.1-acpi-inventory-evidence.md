# Phase 4.1 — ACPI Inventory Evidence

**Status:** **Closed 2026-10-11 within inventory-only scope**, after local validation / CI-equivalent gates and independent review. The local branch `feat/phase4.1-acpi-inventory` was not published; no remote GitHub Actions run for Phase 4.1 was performed. This status is **not** “GitHub CI green.”

## Goal and scope

Discover the firmware RSDP through `EFI_SYSTEM_TABLE.ConfigurationTable`, hand its physical pointer to the kernel, and validate the ACPI root and MADT before reporting bounded processor, Local APIC, I/O APIC, and interrupt-override metadata. The UEFI-provided RSDP pointer has no 16-byte alignment requirement; that alignment rule applies to legacy IA-PC memory scanning, which is not used here.

ACPI descriptors, physical bounds, table lengths/checksums, and supported MADT records are validated fail-closed. Invalid advertised tables/ranges are rejected rather than treated as absent. The implementation is an inventory only: APIC MMIO is never read or programmed; interrupts remain disabled and IF stays clear. No timer/IRQ handlers, preemption, SMP, or Phase 4.2 behavior is included.

## Local validation summary

All checks below were run locally on the Phase 4.1 branch. The repository and QEMU gates passed; the independent final Oracle review found no material issues and confirmed the three coverage findings had been corrected.

| Command / check | Outcome |
| --- | --- |
| `python scripts/build-acpi-fixtures.py --check` | Passed: `ACPI fixtures reproducible: 32 files`. |
| `python scripts/test-hardening-runner.py` | Passed: 6 tests. |
| `cargo fmt --all -- --check` | Passed. |
| `cargo check --locked --workspace --all-targets` | Passed. |
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | Passed. |
| `cargo test --locked --workspace` and `cargo test --locked --workspace --release` | Both passed. |
| `cargo build --locked -p nexus-boot --target x86_64-unknown-uefi` | Passed. |
| `cargo clippy --locked -p nexus-boot --target x86_64-unknown-uefi --features hardening-tests -- -D warnings` | Passed. |
| `python scripts/test-wdk-abi.py` | Passed: 16 tests. |
| `python scripts/test-hardening.py --ram 128 --cpu qemu64 --timeout 60`; `python scripts/test-hardening.py --ram 256 --cpu max --timeout 60`; `python scripts/test-hardening.py --ram 512 --cpu max --timeout 60 --release` | All three passed with `passed=true` and QEMU exit 33. Each reported ACPI revision 2, LAPIC `0xfee00000`, 1 processor, 1 IOAPIC, 5 overrides, and `if_clear=true`. MADT addresses: `0x7778000`, `0xfb78000`, and `0x1fb78000`, respectively. |
| `scripts/test-wdk-ci.ps1 -WdkRoot build/wdk-packages/wdk -SdkRoot build/wdk-packages/sdk` | Full local WDK CI-equivalent script exited 0 (`FULL WDK CI GATE PASSED`); details below. This is not a GitHub Actions run. |

The normal 256 MiB profile was run successfully before its evidence was overwritten by the WDK run using MSVC fixtures. The WDK guest run validated 256 MiB / `max` again with those MSVC fixtures.

## WDK evidence and environment

The local WDK script reported 62/62 MSVC ABI entries; three drivers compiled, linked reproducibly, loaded, and executed; `negative-layout` and `negative-import` controls were rejected with expected results; the clang fixture report had no issues and all three fixtures were identical; 32 PE/ELF images were compiled; and the 256 MiB / `max` QEMU/OVMF guest with MSVC fixtures passed. Three temporarily replaced `.sys` files were restored byte-for-byte to their backup hashes.

Environment: Windows 11 build 26300; PowerShell `pwsh` 7.6.6; Rust 1.98.0; MSVC `cl` 19.44.35229; WDK NuGet 10.0.26100.6584; SDK 10.0.26100.7705; `clang-cl` / `lld-link` 19.1.7; Python 3.13.15; QEMU/OVMF 11.1.0 using TCG. Local MSVC is localized (Spanish) and emits non-UTF-8 subprocess output. To reproduce locally, `PYTHONUTF8=0` and `PYTHONIOENCODING=utf-8` were used. These overrides are not claimed to be part of the GitHub workflow, which currently sets `PYTHONUTF8=1`; the hosted Windows runner has a different locale.

## Source and transient evidence

- Final sources SHA-256, computed with the same algorithm as the harness: `42911fafabeaa89e1a4fdeec3d6cd490eb65ee025623507ff1c21e3dcbd16315`.
- Earlier documentation/spec commits on this branch: `72c2003` and `f6e10bc`.
- The QEMU and WDK outputs/logs were under local `build/hardening-*/` and `build/wdk-ci/`. These are local/ignored outputs, not durable versioned or checked-in evidence.

## Exit criteria

- [x] UEFI firmware RSDP → root SDT → exactly one valid MADT discovered and reported from QEMU/OVMF, including LAPIC identity/base, at least one processor and IOAPIC, and available overrides.
- [x] Independent generated ACPI fixtures reproduce; malformed checksums, lengths, entries, reserved fields, duplicate records, and invalid/unreadable ranges are rejected.
- [x] Existing workspace, UEFI, WDK, runner, and three guest-profile gates passed locally.
- [x] IF remains clear; APIC is not accessed/programmed; no timers, preemption, SMP, or Phase 4.2 behavior is implemented.
- [x] Evidence is explicitly limited to QEMU/OVMF TCG; no physical hardware was tested.

## Limitations

QEMU/OVMF under TCG does not prove behavior on physical hardware or general firmware compatibility. No physical system was tested. Local validation / CI-equivalent results are distinct from GitHub Actions CI; the Phase 4.1 branch was not published and no remote Actions run was executed. Phase 4.1 validates ACPI inventory only and does not deliver APIC hardware support, interrupt handling, hardware-aware IRQL, or any Phase 4.2+ feature.
