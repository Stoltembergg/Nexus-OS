//! Core shared types for the Nexus OS hybrid kernel.
//!
//! Provides type-safe representations of:
//! - NT status codes (`NTSTATUS`)
//! - Linux POSIX error numbers (`Errno`)
//! - Canonical virtual and physical memory addresses
//! - Process personalities and hybrid descriptors

pub mod address;
pub mod errno;
pub mod process;
pub mod status;

pub use address::{MemoryFlags, PhysicalAddress, VirtualAddress, PAGE_SIZE_4KB};
pub use errno::Errno;
pub use process::{HybridProcessDescriptor, ProcessId, ProcessPersonality, ThreadId};
pub use status::NtStatus;
