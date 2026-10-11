//! Nexus OS UEFI Boot Services Handoff Protocol & Memory Map Descriptors.

pub mod proto;

pub use nexus_types::{
    BootHandoverInfo, FramebufferInfo, MemoryDescriptor, PhysicalAddress, UefiMemoryType,
    VirtualAddress,
};
use proto::EfiMemoryDescriptorRaw;

impl From<EfiMemoryDescriptorRaw> for MemoryDescriptor {
    fn from(raw: EfiMemoryDescriptorRaw) -> Self {
        Self {
            mem_type: UefiMemoryType::from(raw.mem_type),
            phys_start: PhysicalAddress::new(raw.physical_start),
            virt_start: VirtualAddress::new(raw.virtual_start),
            number_of_pages: raw.number_of_pages,
            attribute: raw.attribute,
        }
    }
}
