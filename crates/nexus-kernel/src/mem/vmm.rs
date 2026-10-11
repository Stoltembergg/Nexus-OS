//! Virtual Memory Manager (VMM) - 4-Level x86_64 Paging Structures & AddressSpace.

use super::pmm::PhysicalMemoryManager;
use bitflags::bitflags;
use nexus_types::{PhysicalAddress, VirtualAddress, PAGE_SIZE_4KB};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmmError {
    FrameAllocationFailed,
    AlreadyMapped,
    NotMapped,
    InvalidAddress,
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

    pub fn set(&mut self, frame: PhysicalAddress, flags: PageTableFlags) {
        self.0 = (frame.as_u64() & 0x000F_FFFF_FFFF_F000) | flags.bits();
    }

    pub fn clear(&mut self) {
        self.0 = 0;
    }
}

/// A 512-entry x86_64 Page Table (PML4, PDPT, PD, or PT).
#[derive(Clone, Copy)]
#[repr(C, align(4096))]
pub struct PageTable {
    pub entries: [PageTableEntry; 512],
}

impl Default for PageTable {
    fn default() -> Self {
        Self::empty()
    }
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

/// An isolated Virtual Address Space backed by a 4-level PML4 page table hierarchy.
#[derive(Debug, Clone, Copy)]
pub struct AddressSpace {
    pml4_frame: PhysicalAddress,
}

impl AddressSpace {
    /// Creates a new address space by allocating a root PML4 table.
    pub fn new(pmm: &mut PhysicalMemoryManager) -> Result<Self, VmmError> {
        let pml4_frame = pmm
            .allocate_zeroed_frame()
            .ok_or(VmmError::FrameAllocationFailed)?;
        Ok(Self { pml4_frame })
    }

    /// Creates an AddressSpace wrapper around an existing root PML4 frame.
    pub const fn from_pml4(pml4_frame: PhysicalAddress) -> Self {
        Self { pml4_frame }
    }

    pub fn pml4_frame(&self) -> PhysicalAddress {
        self.pml4_frame
    }

    /// Creates an isolated user address space that preserves supervisor kernel mapping
    /// but restricts Ring 3 permissions exclusively to user-allocated pages.
    pub fn new_user(
        kernel_as: &AddressSpace,
        pmm: &mut PhysicalMemoryManager,
    ) -> Result<Self, VmmError> {
        let user_as = Self::new(pmm)?;

        #[cfg(all(target_arch = "x86_64", not(test)))]
        unsafe {
            let kernel_pml4 = &*(kernel_as.pml4_frame.as_u64() as *const PageTable);
            let user_pml4 = &mut *(user_as.pml4_frame.as_u64() as *mut PageTable);

            // 1. Share upper-half kernel mappings (indices 256..512)
            for i in 256..512 {
                if kernel_pml4.entries[i].is_present() {
                    user_pml4.entries[i] = kernel_pml4.entries[i];
                }
            }

            // 2. Clone PML4 entry 0 (lower half) using a dedicated PDPT to protect kernel tables
            if kernel_pml4.entries[0].is_present() {
                let kernel_pdpt =
                    &*(kernel_pml4.entries[0].physical_address().as_u64() as *const PageTable);
                let user_pdpt_frame = pmm
                    .allocate_zeroed_frame()
                    .ok_or(VmmError::FrameAllocationFailed)?;
                let user_pdpt = &mut *(user_pdpt_frame.as_u64() as *mut PageTable);

                // Copy kernel PD entries into user PDPT (Supervisor-only: USER = 0)
                for j in 0..512 {
                    user_pdpt.entries[j] = kernel_pdpt.entries[j];
                }

                user_pml4.entries[0] = PageTableEntry::new(
                    user_pdpt_frame,
                    PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER,
                );
            }
        }

        #[cfg(any(not(target_arch = "x86_64"), test))]
        {
            let _ = (kernel_as, pmm);
        }

        Ok(user_as)
    }

    /// Maps a 4KB virtual page to a physical frame with specified flags.
    /// Allocates intermediate page tables (PDPT, PD, PT) as needed.
    pub fn map_page(
        &mut self,
        vaddr: VirtualAddress,
        paddr: PhysicalAddress,
        flags: PageTableFlags,
        pmm: &mut PhysicalMemoryManager,
    ) -> Result<(), VmmError> {
        let (pml4_idx, pdpt_idx, pd_idx, pt_idx) = page_indices(vaddr);

        #[cfg(all(target_arch = "x86_64", not(test)))]
        unsafe {
            let pml4 = &mut *(self.pml4_frame.as_u64() as *mut PageTable);

            // Level 4 -> Level 3 (PDPT)
            let pdpt_frame = Self::get_or_create_subtable(&mut pml4.entries[pml4_idx], flags, pmm)?;
            let pdpt = &mut *(pdpt_frame.as_u64() as *mut PageTable);

            // Level 3 -> Level 2 (PD)
            let pd_frame = Self::get_or_create_subtable(&mut pdpt.entries[pdpt_idx], flags, pmm)?;
            let pd = &mut *(pd_frame.as_u64() as *mut PageTable);

            // Level 2 -> Level 1 (PT)
            let pt_frame = Self::get_or_create_subtable(&mut pd.entries[pd_idx], flags, pmm)?;
            let pt = &mut *(pt_frame.as_u64() as *mut PageTable);

            let pte = &mut pt.entries[pt_idx];
            if pte.is_present() {
                return Err(VmmError::AlreadyMapped);
            }

            pte.set(paddr, flags | PageTableFlags::PRESENT);
            Self::invalidate_tlb(vaddr);
            Ok(())
        }

        #[cfg(any(not(target_arch = "x86_64"), test))]
        {
            let _ = (pml4_idx, pdpt_idx, pd_idx, pt_idx, paddr, flags, pmm);
            Ok(())
        }
    }

    /// Maps a contiguous range of physical memory to identical virtual addresses (identity mapping).
    pub fn map_identity(
        &mut self,
        start: PhysicalAddress,
        length: usize,
        flags: PageTableFlags,
        pmm: &mut PhysicalMemoryManager,
    ) -> Result<(), VmmError> {
        let pages = (length as u64).div_ceil(PAGE_SIZE_4KB);
        let base = start.as_u64();

        for i in 0..pages {
            let addr = base + i * PAGE_SIZE_4KB;
            let vaddr = VirtualAddress::new(addr);
            let paddr = PhysicalAddress::new(addr);
            self.map_page(vaddr, paddr, flags, pmm)?;
        }
        Ok(())
    }

    /// Translates a virtual address to physical address in this address space.
    pub fn translate(&self, vaddr: VirtualAddress) -> Option<PhysicalAddress> {
        let (pml4_idx, pdpt_idx, pd_idx, pt_idx) = page_indices(vaddr);
        let offset = vaddr.as_u64() & (PAGE_SIZE_4KB - 1);

        #[cfg(all(target_arch = "x86_64", not(test)))]
        unsafe {
            let pml4 = &*(self.pml4_frame.as_u64() as *const PageTable);
            let pml4e = &pml4.entries[pml4_idx];
            if !pml4e.is_present() {
                return None;
            }

            let pdpt = &*(pml4e.physical_address().as_u64() as *const PageTable);
            let pdpte = &pdpt.entries[pdpt_idx];
            if !pdpte.is_present() {
                return None;
            }

            let pd = &*(pdpte.physical_address().as_u64() as *const PageTable);
            let pde = &pd.entries[pd_idx];
            if !pde.is_present() {
                return None;
            }

            let pt = &*(pde.physical_address().as_u64() as *const PageTable);
            let pte = &pt.entries[pt_idx];
            if !pte.is_present() {
                return None;
            }

            Some(PhysicalAddress::new(
                pte.physical_address().as_u64() + offset,
            ))
        }

        #[cfg(any(not(target_arch = "x86_64"), test))]
        {
            let _ = (pml4_idx, pdpt_idx, pd_idx, pt_idx);
            Some(PhysicalAddress::new(vaddr.as_u64() + offset))
        }
    }

    /// Switches the CPU's CR3 register to this address space.
    pub fn switch_to(&self) {
        #[cfg(all(target_arch = "x86_64", not(test)))]
        unsafe {
            let cr3 = self.pml4_frame.as_u64();
            core::arch::asm!(
                "mov cr3, {}",
                in(reg) cr3,
                options(nostack, preserves_flags)
            );
        }
    }

    /// Invalidates TLB entry for the given virtual address via INVLPG.
    #[inline]
    pub fn invalidate_tlb(vaddr: VirtualAddress) {
        #[cfg(all(target_arch = "x86_64", not(test)))]
        unsafe {
            let addr = vaddr.as_u64();
            core::arch::asm!(
                "invlpg [{}]",
                in(reg) addr,
                options(nostack, preserves_flags)
            );
        }
        #[cfg(test)]
        let _ = vaddr;
    }

    #[cfg(all(target_arch = "x86_64", not(test)))]
    fn get_or_create_subtable(
        entry: &mut PageTableEntry,
        flags: PageTableFlags,
        pmm: &mut PhysicalMemoryManager,
    ) -> Result<PhysicalAddress, VmmError> {
        if entry.is_present() {
            // If the new mapping requires USER or WRITABLE, propagate it to parent entries
            let mut parent_flags = entry.flags();
            if flags.contains(PageTableFlags::USER) {
                parent_flags |= PageTableFlags::USER;
            }
            if flags.contains(PageTableFlags::WRITABLE) {
                parent_flags |= PageTableFlags::WRITABLE;
            }
            entry.set(entry.physical_address(), parent_flags);
            Ok(entry.physical_address())
        } else {
            let frame = pmm
                .allocate_zeroed_frame()
                .ok_or(VmmError::FrameAllocationFailed)?;
            let mut parent_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
            if flags.contains(PageTableFlags::USER) {
                parent_flags |= PageTableFlags::USER;
            }
            entry.set(frame, parent_flags);
            Ok(frame)
        }
    }
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
        let vaddr = VirtualAddress::new(0xFFFF_8000_1234_5000);
        let (pml4, pdpt, pd, pt) = page_indices(vaddr);

        assert_eq!(pml4, 0x100);
        assert_eq!(pdpt, 0x000);
        assert_eq!(pd, 0x091);
        assert_eq!(pt, 0x145);
    }

    #[test]
    fn test_user_flag_isolation() {
        let k_entry = PageTableEntry::new(
            PhysicalAddress::new(0x1000),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        );
        let u_entry = PageTableEntry::new(
            PhysicalAddress::new(0x2000),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER,
        );

        assert!(
            !k_entry.is_user(),
            "Kernel entry must NOT have USER bit set"
        );
        assert!(u_entry.is_user(), "User entry MUST have USER bit set");
    }
}
