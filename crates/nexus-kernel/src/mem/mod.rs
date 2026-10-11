//! Physical and Virtual Memory Management Subsystem.

pub mod pmm;
pub mod vmm;

use nexus_types::BootHandoverInfo;

/// Initializes physical frame allocator using the UEFI memory map descriptors.
pub fn init_memory(boot_info: &BootHandoverInfo) {
    let mut pmm = pmm::PMM.lock();
    pmm.init_from_memory_map(boot_info.memory_map());
}
