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
    UnsupportedPlatform,
    HugePageUnsupported,
    ActiveAddressSpace,
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

pub const fn is_canonical(addr: u64) -> bool {
    addr < 0x0000_8000_0000_0000 || addr >= 0xFFFF_8000_0000_0000
}

#[derive(Debug, Clone, Copy)]
pub struct PageMapping {
    pub physical_address: PhysicalAddress,
    pub flags: PageTableFlags,
}

/// Owns its page tables. Borrowed kernel branches are copied before modification.
#[derive(Debug)]
pub struct AddressSpace {
    pml4_frame: PhysicalAddress,
    tables: Vec<PhysicalAddress>,
}

impl AddressSpace {
    pub fn new(pmm: &mut PhysicalMemoryManager) -> Result<Self, VmmError> {
        #[cfg(not(any(target_os = "uefi", target_os = "none")))]
        {
            let _ = pmm;
            Err(VmmError::UnsupportedPlatform)
        }
        #[cfg(any(target_os = "uefi", target_os = "none"))]
        {
            let mut tables = Vec::new();
            tables
                .try_reserve(1)
                .map_err(|_| VmmError::FrameAllocationFailed)?;
            let frame = pmm
                .allocate_zeroed_frame()
                .ok_or(VmmError::FrameAllocationFailed)?;
            tables.push(frame);
            Ok(Self {
                pml4_frame: frame,
                tables,
            })
        }
    }
    /// Non-owning view of a live, identity-mapped root.
    pub const fn from_pml4(pml4_frame: PhysicalAddress) -> Self {
        Self {
            pml4_frame,
            tables: Vec::new(),
        }
    }
    pub fn pml4_frame(&self) -> PhysicalAddress {
        self.pml4_frame
    }

    pub fn new_user(kernel: &Self, pmm: &mut PhysicalMemoryManager) -> Result<Self, VmmError> {
        let space = Self::new(pmm)?;
        #[cfg(any(target_os = "uefi", target_os = "none"))]
        unsafe {
            let source = &*(kernel.pml4_frame.as_u64() as *const PageTable);
            let dest = &mut *(space.pml4_frame.as_u64() as *mut PageTable);
            for (dst, src) in dest.entries.iter_mut().zip(source.entries.iter()) {
                *dst = PageTableEntry::new(
                    src.physical_address(),
                    src.flags() & !PageTableFlags::USER,
                );
            }
        }
        #[cfg(not(any(target_os = "uefi", target_os = "none")))]
        let _ = kernel;
        Ok(space)
    }

    pub fn map_page(
        &mut self,
        va: VirtualAddress,
        pa: PhysicalAddress,
        flags: PageTableFlags,
        pmm: &mut PhysicalMemoryManager,
    ) -> Result<(), VmmError> {
        if !va.is_page_aligned()
            || pa.as_u64() & 4095 != 0
            || !is_canonical(va.as_u64())
            || pa.as_u64() >= (1 << 52)
            || flags.contains(PageTableFlags::HUGE_PAGE)
            || (flags.contains(PageTableFlags::USER)
                && (va.as_u64() == 0
                    || va.as_u64() >= 0x0000_8000_0000_0000
                    || flags.contains(PageTableFlags::GLOBAL)
                    || (flags.contains(PageTableFlags::WRITABLE)
                        && !flags.contains(PageTableFlags::NO_EXECUTE))))
        {
            return Err(VmmError::InvalidAddress);
        }
        #[cfg(not(any(target_os = "uefi", target_os = "none")))]
        {
            let _ = pmm;
            Err(VmmError::UnsupportedPlatform)
        }
        #[cfg(any(target_os = "uefi", target_os = "none"))]
        unsafe {
            // Shadowing a live kernel identity mapping is forbidden.
            if self.mapping(va).is_some() {
                return Err(VmmError::AlreadyMapped);
            }
            let indices = page_indices(va);
            let mut table_frame = self.pml4_frame;
            let owned_before = self.tables.len();
            let mut changed = [(
                core::ptr::null_mut::<PageTableEntry>(),
                PageTableEntry::ZERO,
            ); 3];
            let mut count = 0;
            for idx in [indices.0, indices.1, indices.2] {
                let table = &mut *(table_frame.as_u64() as *mut PageTable);
                let entry = &mut table.entries[idx];
                let old = *entry;
                match self.private_subtable(entry, flags, pmm) {
                    Ok(frame) => {
                        changed[count] = (entry as *mut _, old);
                        count += 1;
                        table_frame = frame;
                    }
                    Err(err) => {
                        for (ptr, old) in changed[..count].iter().rev() {
                            **ptr = *old;
                        }
                        for frame in self.tables.drain(owned_before..) {
                            pmm.free_frame(frame);
                        }
                        return Err(err);
                    }
                }
            }
            let table = &mut *(table_frame.as_u64() as *mut PageTable);
            table.entries[indices.3].set(pa, flags | PageTableFlags::PRESENT);
            Self::invalidate_tlb(va);
            Ok(())
        }
    }

    #[cfg(any(target_os = "uefi", target_os = "none"))]
    unsafe fn private_subtable(
        &mut self,
        entry: &mut PageTableEntry,
        flags: PageTableFlags,
        pmm: &mut PhysicalMemoryManager,
    ) -> Result<PhysicalAddress, VmmError> {
        if entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            return Err(VmmError::HugePageUnsupported);
        }
        if !entry.is_present() || !self.tables.contains(&entry.physical_address()) {
            self.tables
                .try_reserve(1)
                .map_err(|_| VmmError::FrameAllocationFailed)?;
            let frame = pmm
                .allocate_zeroed_frame()
                .ok_or(VmmError::FrameAllocationFailed)?;
            if entry.is_present() {
                core::ptr::copy_nonoverlapping(
                    entry.physical_address().as_u64() as *const PageTable,
                    frame.as_u64() as *mut PageTable,
                    1,
                );
            }
            self.tables.push(frame);
            entry.set(frame, PageTableFlags::PRESENT | PageTableFlags::WRITABLE);
        }
        let mut parent_flags = entry.flags();
        if flags.contains(PageTableFlags::USER) {
            parent_flags |= PageTableFlags::USER;
        }
        entry.set(entry.physical_address(), parent_flags);
        Ok(entry.physical_address())
    }

    pub fn map_identity(
        &mut self,
        start: PhysicalAddress,
        length: usize,
        flags: PageTableFlags,
        pmm: &mut PhysicalMemoryManager,
    ) -> Result<(), VmmError> {
        if length == 0 {
            return Ok(());
        }
        let base = start.as_u64() & !4095;
        let end = start
            .as_u64()
            .checked_add(length as u64)
            .and_then(|v| v.checked_add(4095))
            .ok_or(VmmError::InvalidAddress)?
            & !4095;
        for addr in (base..end).step_by(PAGE_SIZE_4KB as usize) {
            self.map_page(
                VirtualAddress::new(addr),
                PhysicalAddress::new(addr),
                flags,
                pmm,
            )?;
        }
        Ok(())
    }

    /// Reports effective USER/WRITE/NX permission across all four paging levels.
    pub fn mapping(&self, va: VirtualAddress) -> Option<PageMapping> {
        if !is_canonical(va.as_u64()) || self.pml4_frame.as_u64() == 0 {
            return None;
        }
        #[cfg(not(any(target_os = "uefi", target_os = "none")))]
        {
            None
        }
        #[cfg(any(target_os = "uefi", target_os = "none"))]
        unsafe {
            let idx = page_indices(va);
            let mut frame = self.pml4_frame;
            let mut effective =
                PageTableFlags::PRESENT | PageTableFlags::USER | PageTableFlags::WRITABLE;
            for i in [idx.0, idx.1, idx.2, idx.3] {
                let table = &*(frame.as_u64() as *const PageTable);
                let entry = table.entries[i];
                if !entry.is_present() || entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                    return None;
                }
                if !entry.is_user() {
                    effective.remove(PageTableFlags::USER);
                }
                if !entry.is_writable() {
                    effective.remove(PageTableFlags::WRITABLE);
                }
                if entry.flags().contains(PageTableFlags::NO_EXECUTE) {
                    effective.insert(PageTableFlags::NO_EXECUTE);
                }
                frame = entry.physical_address();
            }
            Some(PageMapping {
                physical_address: PhysicalAddress::new(frame.as_u64() + (va.as_u64() & 4095)),
                flags: effective,
            })
        }
    }
    pub fn translate(&self, va: VirtualAddress) -> Option<PhysicalAddress> {
        self.mapping(va).map(|m| m.physical_address)
    }
    /// Only for owned kernel tables, before user address spaces borrow branches.
    pub fn protect_kernel_code(&mut self, va: VirtualAddress) -> Result<(), VmmError> {
        self.protect_kernel_page(va, PageTableFlags::PRESENT)
    }

    /// Set supervisor page permissions (e.g. PRESENT | WRITABLE for RW or PRESENT for RX).
    pub fn protect_kernel_page(
        &mut self,
        va: VirtualAddress,
        flags: PageTableFlags,
    ) -> Result<(), VmmError> {
        #[cfg(not(any(target_os = "uefi", target_os = "none")))]
        {
            let _ = (va, flags);
            Err(VmmError::UnsupportedPlatform)
        }
        #[cfg(any(target_os = "uefi", target_os = "none"))]
        unsafe {
            if !va.is_page_aligned() {
                return Err(VmmError::InvalidAddress);
            }
            let idx = page_indices(va);
            let mut frame = self.pml4_frame;
            for i in [idx.0, idx.1, idx.2] {
                if !self.tables.contains(&frame) {
                    return Err(VmmError::InvalidAddress);
                }
                let entry = (&*(frame.as_u64() as *const PageTable)).entries[i];
                if !entry.is_present() || entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                    return Err(VmmError::NotMapped);
                }
                frame = entry.physical_address();
            }
            if !self.tables.contains(&frame) {
                return Err(VmmError::InvalidAddress);
            }
            let entry = &mut (&mut *(frame.as_u64() as *mut PageTable)).entries[idx.3];
            if !entry.is_present() || entry.is_user() {
                return Err(VmmError::NotMapped);
            }
            entry.set(entry.physical_address(), flags | PageTableFlags::PRESENT);
            Self::invalidate_tlb(va);
            Ok(())
        }
    }
    pub fn switch_to(&self) {
        #[cfg(any(target_os = "uefi", target_os = "none"))]
        unsafe {
            core::arch::asm!("mov cr3, {}", in(reg) self.pml4_frame.as_u64(), options(nostack, preserves_flags));
        }
    }
    pub fn is_active(&self) -> bool {
        #[cfg(any(target_os = "uefi", target_os = "none"))]
        unsafe {
            let root: u64;
            core::arch::asm!("mov {}, cr3", out(reg) root, options(nomem, nostack, preserves_flags));
            root & !4095 == self.pml4_frame.as_u64()
        }
        #[cfg(not(any(target_os = "uefi", target_os = "none")))]
        {
            false
        }
    }
    /// The caller must switch away first. Process owns leaf frames separately.
    pub fn destroy(&mut self, pmm: &mut PhysicalMemoryManager) -> Result<(), VmmError> {
        if self.is_active() {
            return Err(VmmError::ActiveAddressSpace);
        }
        for frame in self.tables.drain(..).rev() {
            pmm.free_frame(frame);
        }
        self.pml4_frame = PhysicalAddress::new(0);
        Ok(())
    }
    pub fn invalidate_tlb(va: VirtualAddress) {
        #[cfg(any(target_os = "uefi", target_os = "none"))]
        unsafe {
            core::arch::asm!("invlpg [{}]", in(reg) va.as_u64(), options(nostack, preserves_flags));
        }
        #[cfg(not(any(target_os = "uefi", target_os = "none")))]
        let _ = va;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_does_not_invent_mappings_or_success() {
        let mut pmm = PhysicalMemoryManager::new();
        let mut space = AddressSpace::from_pml4(PhysicalAddress::new(0x1000));
        assert_eq!(space.translate(VirtualAddress::new(0x400123)), None);
        assert!(space
            .map_page(
                VirtualAddress::new(0x400000),
                PhysicalAddress::new(0x2000),
                PageTableFlags::USER,
                &mut pmm
            )
            .is_err());
    }

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
