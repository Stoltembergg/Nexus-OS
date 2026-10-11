//! Memory address and permission flags for virtual memory management.

use bitflags::bitflags;

pub const PAGE_SIZE_4KB: u64 = 4096;
pub const PAGE_MASK_4KB: u64 = !(PAGE_SIZE_4KB - 1);
pub const PAGE_SIZE_2MB: u64 = 2 * 1024 * 1024;
pub const PAGE_MASK_2MB: u64 = !(PAGE_SIZE_2MB - 1);

/// A canonical 64-bit virtual memory address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct VirtualAddress(pub u64);

impl VirtualAddress {
    #[inline]
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    #[inline]
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    #[inline]
    pub const fn is_null(&self) -> bool {
        self.0 == 0
    }

    #[inline]
    pub const fn is_page_aligned(&self) -> bool {
        (self.0 & (PAGE_SIZE_4KB - 1)) == 0
    }

    #[inline]
    pub const fn align_down(&self) -> Self {
        Self(self.0 & PAGE_MASK_4KB)
    }

    #[inline]
    pub const fn align_up(&self) -> Self {
        Self((self.0 + PAGE_SIZE_4KB - 1) & PAGE_MASK_4KB)
    }

    #[inline]
    pub const fn offset(&self, bytes: u64) -> Self {
        Self(self.0 + bytes)
    }
}

impl core::fmt::Display for VirtualAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:#018X}", self.0)
    }
}

/// A 64-bit physical memory address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct PhysicalAddress(pub u64);

impl PhysicalAddress {
    #[inline]
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    #[inline]
    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

impl core::fmt::Display for PhysicalAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:#018X} (phys)", self.0)
    }
}

bitflags! {
    /// Memory protection flags compatible with both NT (PAGE_*) and POSIX (PROT_*).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct MemoryFlags: u32 {
        const NONE    = 0x00;
        const READ    = 0x01;
        const WRITE   = 0x02;
        const EXECUTE = 0x04;
        const USER    = 0x08;
    }
}

impl MemoryFlags {
    pub const READ_WRITE: Self = Self::READ.union(Self::WRITE);
    pub const READ_EXECUTE: Self = Self::READ.union(Self::EXECUTE);
    pub const READ_WRITE_EXECUTE: Self = Self::READ.union(Self::WRITE).union(Self::EXECUTE);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_alignment() {
        let addr = VirtualAddress::new(0x400123);
        assert!(!addr.is_page_aligned());
        assert_eq!(addr.align_down().as_u64(), 0x400000);
        assert_eq!(addr.align_up().as_u64(), 0x401000);
    }
}
