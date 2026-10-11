# Contributing to Nexus OS

Thank you for your interest in contributing to **Nexus OS**! This document outlines the engineering guidelines, clean-room standards, versioning conventions, and testing requirements for the project.

---

## 1. Clean-Room Reverse Engineering & Legal Compliance

Because Nexus OS targets binary compatibility with both Windows NT (PE32+) and Linux (ELF64), all contributors **must strictly adhere to clean-room engineering guidelines**:

1. **No Leaked Code**: Never read, decompile, or reference leaked Microsoft Windows source code (e.g., Windows Research Kernel, leaked 2000/XP/NT source code) or proprietary anti-cheat driver source code.
2. **Acceptable References**:
   - Official public documentation (Microsoft Learn, Win32 API docs, POSIX.1-2017 standard, Linux man-pages).
   - Clean-room open-source projects with permissive or compatible licenses (ReactOS under GPLv2/LGPL, Wine under LGPLv2.1, FreeBSD, Musl libc).
   - Black-box behavioral testing and public ABI specifications (System V AMD64 ABI, Microsoft x64 Calling Convention).
3. **Intellectual Property**: All new code written directly in the Nexus OS repository is licensed under MIT / Apache-2.0. Any external modules imported must clearly declare their license and upstream origin in a `THIRD_PARTY_LICENSES.md` file.

---

## 2. Code Conventions

- **Primary Languages**: Rust (kernel core, loader, memory management, safe subsystems) and C/Assembly (UEFI entry stub, low-level context switching, IDT/GDT initialization).
- **Rust Style**:
  - Code must be formatted with `rustfmt` (`cargo fmt`).
  - Code must pass `cargo clippy --workspace --all-targets -- -D warnings`.
  - Panic in kernel space is strictly prohibited outside early fatal abort handlers; use `Result<T, OSStatus>` or `Result<T, Errno>`.
  - Unsafe code must include a `// SAFETY:` explanatory comment detailing why the invariants hold.
- **Naming Conventions**:
  - NT types and status codes follow NT convention: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, `UNICODE_STRING`, `OBJECT_ATTRIBUTES`.
  - Linux types and errors follow POSIX convention: `ENOENT`, `EFAULT`, `EINVAL`, `SYS_READ`.
  - Internal abstractions follow Rust idiomatic naming: `HybridProcess`, `VirtualAddressSpace`, `PicoThread`.

---

## 3. Git Workflow & Commit Guidelines

- **Branching**:
  - `main`: Production-ready, passing CI, tested codebase.
  - `feature/<name>`: New subsystems, features, loaders.
  - `research/<topic>`: Anti-cheat investigations, driver compatibility experiments.
- **Commit Messages**: Follow Conventional Commits:
  - `feat(loader): add PE32+ base relocation table parser`
  - `fix(abi): correct 64-bit Linux syscall argument mapping for sys_clone`
  - `docs(anticheat): add technical analysis of Vanguard vgk.sys requirements`
  - `test(poc): add integration test for simultaneous PE and ELF mapping`

---

## 4. Testing & Verification

Every functional modification must include automated tests:
```bash
# Run unit tests across all crates
cargo test --workspace

# Verify code formatting and linting
cargo fmt --all -- --check
cargo clippy --workspace --all-targets
```
No PR will be merged if it declares theoretical compatibility without functional unit tests or measurable reproduction criteria.
