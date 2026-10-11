//! Nexus OS UEFI Boot Services Handoff Protocol & Memory Map Descriptors.

use crate::{PhysicalAddress, VirtualAddress};

pub const MAX_BOOT_MEMORY_DESCRIPTORS: usize = 256;

/// Framebuffer configuration obtained via UEFI GOP (Graphics Output Protocol).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    Unknown(u32),
}

impl From<u32> for UefiMemoryType {
    fn from(val: u32) -> Self {
        match val {
            0 => Self::Reserved,
            1 => Self::LoaderCode,
            2 => Self::LoaderData,
            3 => Self::BootServicesCode,
            4 => Self::BootServicesData,
            5 => Self::RuntimeServicesCode,
            6 => Self::RuntimeServicesData,
            7 => Self::ConventionalMemory,
            8 => Self::UnusableMemory,
            9 => Self::AcpiReclaimMemory,
            10 => Self::AcpiMemoryNvs,
            11 => Self::MemoryMappedIo,
            12 => Self::MemoryMappedIoPortSpace,
            13 => Self::PalCode,
            14 => Self::PersistentMemory,
            other => Self::Unknown(other),
        }
    }
}

/// A contiguous physical memory region described by UEFI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryDescriptor {
    pub mem_type: UefiMemoryType,
    pub phys_start: PhysicalAddress,
    pub virt_start: VirtualAddress,
    pub number_of_pages: u64,
    pub attribute: u64,
}

impl Default for MemoryDescriptor {
    fn default() -> Self {
        Self {
            mem_type: UefiMemoryType::Reserved,
            phys_start: PhysicalAddress::new(0),
            virt_start: VirtualAddress::new(0),
            number_of_pages: 0,
            attribute: 0,
        }
    }
}

/// Boot handover information structure passed from the UEFI loader to the kernel entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootHandoverInfo {
    pub kernel_code: [(u64, u64); 16], // actual loaded VA / page-rounded length
    pub kernel_code_len: usize,
    pub rsdp_address: Option<PhysicalAddress>,
    pub framebuffer: Option<FramebufferInfo>,
    pub memory_map_len: usize,
    pub memory_map: [MemoryDescriptor; MAX_BOOT_MEMORY_DESCRIPTORS],
}

impl BootHandoverInfo {
    pub const fn new() -> Self {
        Self {
            kernel_code: [(0, 0); 16],
            kernel_code_len: 0,
            rsdp_address: None,
            framebuffer: None,
            memory_map_len: 0,
            memory_map: [MemoryDescriptor {
                mem_type: UefiMemoryType::Reserved,
                phys_start: PhysicalAddress::new(0),
                virt_start: VirtualAddress::new(0),
                number_of_pages: 0,
                attribute: 0,
            }; MAX_BOOT_MEMORY_DESCRIPTORS],
        }
    }

    /// Appends a memory descriptor if capacity allows.
    pub fn push_descriptor(&mut self, desc: MemoryDescriptor) -> bool {
        if self.memory_map_len < MAX_BOOT_MEMORY_DESCRIPTORS {
            self.memory_map[self.memory_map_len] = desc;
            self.memory_map_len += 1;
            true
        } else {
            false
        }
    }

    /// Returns a slice of active memory descriptors.
    pub fn memory_map(&self) -> &[MemoryDescriptor] {
        &self.memory_map[..self.memory_map_len]
    }

    /// Computes total usable conventional physical memory in bytes.
    pub fn total_conventional_memory(&self) -> u64 {
        let mut sum = 0u64;
        let mut i = 0;
        while i < self.memory_map_len {
            if self.memory_map[i].mem_type == UefiMemoryType::ConventionalMemory {
                sum += self.memory_map[i].number_of_pages * 4096;
            }
            i += 1;
        }
        sum
    }
}

impl Default for BootHandoverInfo {
    fn default() -> Self {
        Self::new()
    }
}
