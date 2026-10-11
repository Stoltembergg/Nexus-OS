//! Virtual Memory Manager (VMM) - 4-Level x86_64 Paging Structures.

use bitflags::bitflags;
use nexus_types::{PhysicalAddress, VirtualAddress};

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PageTableFlags: u64 {
        const PRESENT       = 1 << 0;
        const WRITABLE      = 1 << 1;
        const USER          = 1 << 2;
        const WRITE_THROUGH = 1 << 3;
        const NO_CACHE      = 1 << 4;
        const ACCESSED      = 1 << 5;
        const DIRTY         = 1 << 6;
        const HUGE_PAGE     = 1 << 7;
        const GLOBAL        = 1 << 8;
        const NO_EXECUTE    = 1 << 63;
    }
}

/// A 64-bit Page Table Entry (PTE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct PageTableEntry(pub u64);

impl PageTableEntry {
    pub const ZERO: Self = Self(0);

    pub fn new(frame: PhysicalAddress, flags: PageTableFlags) -> Self {
        Self((frame.as_u64() & 0x000F_FFFF_FFFF_F000) | flags.bits())
    }

    pub fn is_present(&self) -> bool {
        (self.0 & PageTableFlags::PRESENT.bits()) != 0
    }

    pub fn is_writable(&self) -> bool {
        (self.0 & PageTableFlags::WRITABLE.bits()) != 0
    }

    pub fn is_user(&self) -> bool {
        (self.0 & PageTableFlags::USER.bits()) != 0
    }

    pub fn physical_address(&self) -> PhysicalAddress {
        PhysicalAddress::new(self.0 & 0x000F_FFFF_FFFF_F000)
    }

    pub fn flags(&self) -> PageTableFlags {
        PageTableFlags::from_bits_truncate(self.0)
    }
}

/// A 512-entry x86_64 Page Table (PML4, PDPT, PD, or PT).
#[derive(Clone, Copy)]
#[repr(C, align(4096))]
pub struct PageTable {
    pub entries: [PageTableEntry; 512],
}

impl PageTable {
    pub const fn empty() -> Self {
        Self {
            entries: [PageTableEntry::ZERO; 512],
        }
    }

    pub fn clear(&mut self) {
        for entry in self.entries.iter_mut() {
            *entry = PageTableEntry::ZERO;
        }
    }
}

/// Extracts the 4-level page table indices for a given virtual address.
#[inline]
pub fn page_indices(vaddr: VirtualAddress) -> (usize, usize, usize, usize) {
    let raw = vaddr.as_u64();
    let pml4 = ((raw >> 39) & 0x1FF) as usize;
    let pdpt = ((raw >> 30) & 0x1FF) as usize;
    let pd = ((raw >> 21) & 0x1FF) as usize;
    let pt = ((raw >> 12) & 0x1FF) as usize;
    (pml4, pdpt, pd, pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_page_table_entry_encoding() {
        let phys = PhysicalAddress::new(0x200_0000);
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER;
        let entry = PageTableEntry::new(phys, flags);

        assert!(entry.is_present());
        assert!(entry.is_writable());
        assert!(entry.is_user());
        assert_eq!(entry.physical_address(), phys);
    }

    #[test]
    fn test_page_indices_extraction() {
        // Canonical address: 0xFFFF_8000_1234_5000
        let vaddr = VirtualAddress::new(0xFFFF_8000_1234_5000);
        let (pml4, pdpt, pd, pt) = page_indices(vaddr);

        assert_eq!(pml4, 0x100);
        assert_eq!(pdpt, 0x000);
        assert_eq!(pd, 0x091);
        assert_eq!(pt, 0x145);
    }
}
