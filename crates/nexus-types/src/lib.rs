//! Nexus OS Core Architecture Types.
//!
//! Provides fundamental types for:
//! - Physical and Virtual memory addresses
//! - NTSTATUS (Windows NT Native API return codes)
//! - Errno (POSIX / Linux system call error numbers)
//! - Process personalities and address space layouts
//! - UEFI Boot Handoff protocol structures

pub mod address;
pub mod boot;
pub mod errno;
pub mod process;
pub mod status;

pub use address::{MemoryFlags, PhysicalAddress, VirtualAddress, PAGE_SIZE_2MB, PAGE_SIZE_4KB};
pub use boot::{BootHandoverInfo, FramebufferInfo, MemoryDescriptor, UefiMemoryType};
pub use errno::Errno;
pub use process::{HybridProcessDescriptor, ProcessPersonality};
pub use status::NtStatus;
