//! Nexus OS UEFI Boot Services Handoff Protocol & Memory Map Descriptors.

use nexus_types::{PhysicalAddress, VirtualAddress};

/// Framebuffer configuration obtained via UEFI GOP (Graphics Output Protocol).
#[derive(Debug, Clone, Copy)]
pub struct FramebufferInfo {
    pub base_address: PhysicalAddress,
    pub size: usize,
    pub width: u32,
    pub height: u32,
    pub pixels_per_scan_line: u32,
    pub red_mask: u32,
    pub green_mask: u32,
    pub blue_mask: u32,
}

/// UEFI memory type descriptor passed to the kernel at handoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UefiMemoryType {
    Reserved,
    LoaderCode,
    LoaderData,
    BootServicesCode,
    BootServicesData,
    RuntimeServicesCode,
    RuntimeServicesData,
    ConventionalMemory, // Free RAM available for kernel physical allocator
    UnusableMemory,
    AcpiReclaimMemory,
    AcpiMemoryNvs,
    MemoryMappedIo,
    MemoryMappedIoPortSpace,
    PalCode,
    PersistentMemory,
}

/// A contiguous physical memory region described by UEFI.
#[derive(Debug, Clone, Copy)]
pub struct MemoryDescriptor {
    pub mem_type: UefiMemoryType,
    pub phys_start: PhysicalAddress,
    pub virt_start: VirtualAddress,
    pub number_of_pages: u64,
    pub attribute: u64,
}

/// Boot handover information structure passed from the UEFI loader to the kernel entry point.
#[derive(Debug, Clone)]
pub struct BootHandoverInfo {
    pub rsdp_address: Option<PhysicalAddress>,
    pub framebuffer: Option<FramebufferInfo>,
    pub memory_map: Vec<MemoryDescriptor>,
}
