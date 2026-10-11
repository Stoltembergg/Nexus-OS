//! Physical Memory Manager (PMM) - Frame Allocation via Bitmap.

use nexus_types::{MemoryDescriptor, PhysicalAddress, UefiMemoryType, PAGE_SIZE_4KB};
use spin::Mutex;

pub const MAX_SUPPORTED_MEMORY_BYTES: u64 = 4 * 1024 * 1024 * 1024; // 4 GB
pub const BITMAP_FRAMES: usize = (MAX_SUPPORTED_MEMORY_BYTES / PAGE_SIZE_4KB) as usize; // 1,048,576 frames
pub const BITMAP_WORDS: usize = BITMAP_FRAMES / 64; // 16,384 u64 words (128 KB bitmap)

/// Reserve the first 1MB of physical memory (frames 0..255) for architectural structures (IVT, BDA, EBDA).
pub const RESERVED_LOW_FRAMES: usize = 256;

pub static PMM: Mutex<PhysicalMemoryManager> = Mutex::new(PhysicalMemoryManager::new());

pub struct PhysicalMemoryManager {
    bitmap: [u64; BITMAP_WORDS],
    allocated: [u64; BITMAP_WORDS],
    total_frames: usize,
    free_frames: usize,
    last_alloc_idx: usize,
}

impl Default for PhysicalMemoryManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PhysicalMemoryManager {
    pub const fn new() -> Self {
        Self {
            bitmap: [!0u64; BITMAP_WORDS], // default all allocated (1 = used/reserved)
            allocated: [0; BITMAP_WORDS],
            total_frames: 0,
            free_frames: 0,
            last_alloc_idx: 0,
        }
    }

    /// Initializes usable frames from the UEFI memory map descriptors.
    pub fn init_from_memory_map<'a, I>(&mut self, descriptors: I)
    where
        I: IntoIterator<Item = &'a MemoryDescriptor>,
    {
        self.bitmap.fill(u64::MAX);
        self.allocated.fill(0);
        self.total_frames = 0;
        self.free_frames = 0;
        self.last_alloc_idx = 0;
        let descriptors: Vec<_> = descriptors.into_iter().collect();
        for desc in &descriptors {
            if desc.mem_type == UefiMemoryType::ConventionalMemory {
                let base = desc.phys_start.as_u64();
                if base % PAGE_SIZE_4KB != 0 || base >= MAX_SUPPORTED_MEMORY_BYTES {
                    continue;
                }
                let start_frame = (base / PAGE_SIZE_4KB) as usize;
                let end_frame = start_frame
                    .saturating_add(desc.number_of_pages.min(BITMAP_FRAMES as u64) as usize)
                    .min(BITMAP_FRAMES);
                for frame in start_frame.max(RESERVED_LOW_FRAMES)..end_frame {
                    // Architecture requirement: Never allocate within low 1MB (frames 0..255)
                    if self.is_used(frame) {
                        self.mark_free(frame);
                        self.total_frames += 1;
                        self.free_frames += 1;
                    }
                }
            }
        }
        // Firmware reservation wins independent of descriptor ordering.
        for desc in descriptors {
            if desc.mem_type != UefiMemoryType::ConventionalMemory {
                let size = desc
                    .number_of_pages
                    .saturating_mul(PAGE_SIZE_4KB)
                    .min(MAX_SUPPORTED_MEMORY_BYTES) as usize;
                self.reserve_region(desc.phys_start, size);
            }
        }
        self.total_frames = self.free_frames;
    }

    /// Explicitly reserves a contiguous range of physical memory (marking it used).
    pub fn reserve_region(&mut self, start: PhysicalAddress, size: usize) {
        if size == 0 || start.as_u64() >= MAX_SUPPORTED_MEMORY_BYTES {
            return;
        }
        let start_frame = (start.as_u64() / PAGE_SIZE_4KB) as usize;
        let end = start
            .as_u64()
            .saturating_add(size as u64)
            .min(MAX_SUPPORTED_MEMORY_BYTES);
        let end_frame = end.div_ceil(PAGE_SIZE_4KB) as usize;
        for frame in start_frame..end_frame {
            self.allocated[frame / 64] &= !(1 << (frame % 64));
            if frame < BITMAP_FRAMES && !self.is_used(frame) {
                self.mark_used(frame);
                if self.free_frames > 0 {
                    self.free_frames -= 1;
                }
            }
        }
    }

    /// Allocates a single 4KB physical frame zeroed out.
    pub fn allocate_zeroed_frame(&mut self) -> Option<PhysicalAddress> {
        #[cfg(all(target_arch = "x86_64", any(target_os = "uefi", target_os = "none")))]
        {
            let frame = self.allocate_frame()?;
            unsafe {
                core::ptr::write_bytes(frame.as_u64() as *mut u8, 0, PAGE_SIZE_4KB as usize);
            }
            Some(frame)
        }
        #[cfg(not(any(target_os = "uefi", target_os = "none")))]
        {
            None
        }
    }

    /// Allocates a single 4KB physical frame using first-fit with next-fit pointer.
    pub fn allocate_frame(&mut self) -> Option<PhysicalAddress> {
        if self.free_frames == 0 {
            return None;
        }

        let start = self.last_alloc_idx;
        for i in 0..BITMAP_WORDS {
            let word_idx = (start + i) % BITMAP_WORDS;
            let word = self.bitmap[word_idx];
            if word != !0u64 {
                let bit_idx = (!word).trailing_zeros() as usize;
                let frame = word_idx * 64 + bit_idx;
                if (RESERVED_LOW_FRAMES..BITMAP_FRAMES).contains(&frame) {
                    self.bitmap[word_idx] |= 1 << bit_idx;
                    self.allocated[word_idx] |= 1 << bit_idx;
                    self.free_frames -= 1;
                    self.last_alloc_idx = word_idx;
                    return Some(PhysicalAddress::new((frame as u64) * PAGE_SIZE_4KB));
                }
            }
        }
        None
    }

    /// Frees a single 4KB physical frame.
    pub fn free_frame(&mut self, addr: PhysicalAddress) {
        if !addr.as_u64().is_multiple_of(PAGE_SIZE_4KB) {
            return;
        }
        let frame = (addr.as_u64() / PAGE_SIZE_4KB) as usize;
        if (RESERVED_LOW_FRAMES..BITMAP_FRAMES).contains(&frame)
            && (self.allocated[frame / 64] & (1 << (frame % 64))) != 0
        {
            self.allocated[frame / 64] &= !(1 << (frame % 64));
            self.mark_free(frame);
            self.free_frames += 1;
        }
    }

    #[inline]
    fn is_used(&self, frame: usize) -> bool {
        (self.bitmap[frame / 64] & (1 << (frame % 64))) != 0
    }

    #[inline]
    fn mark_used(&mut self, frame: usize) {
        self.bitmap[frame / 64] |= 1 << (frame % 64);
    }

    #[inline]
    fn mark_free(&mut self, frame: usize) {
        self.bitmap[frame / 64] &= !(1 << (frame % 64));
    }

    pub fn total_frames(&self) -> usize {
        self.total_frames
    }

    pub fn free_frames(&self) -> usize {
        self.free_frames
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(start: u64, pages: u64) -> MemoryDescriptor {
        MemoryDescriptor {
            mem_type: UefiMemoryType::ConventionalMemory,
            phys_start: PhysicalAddress::new(start),
            virt_start: nexus_types::VirtualAddress::new(0),
            number_of_pages: pages,
            attribute: 0,
        }
    }

    #[test]
    fn cannot_free_reserved_unallocated_or_unaligned_frames() {
        let mut pmm = PhysicalMemoryManager::new();
        pmm.init_from_memory_map(&[descriptor(0x100000, 4)]);
        pmm.free_frame(PhysicalAddress::new(0));
        pmm.free_frame(PhysicalAddress::new(0x900000));
        assert_eq!(pmm.free_frames(), 4);
        let frame = pmm.allocate_frame().unwrap();
        pmm.free_frame(PhysicalAddress::new(frame.as_u64() + 1));
        assert_eq!(pmm.free_frames(), 3);
        pmm.reserve_region(frame, 4096);
        pmm.free_frame(frame);
        assert_eq!(pmm.free_frames(), 3);
    }

    #[test]
    fn overlapping_descriptors_and_reinitialization_do_not_inflate_counts() {
        let mut pmm = PhysicalMemoryManager::new();
        pmm.init_from_memory_map(&[descriptor(0x100000, 4), descriptor(0x102000, 4)]);
        assert_eq!(pmm.free_frames(), 6);
        pmm.init_from_memory_map(&[descriptor(0x100000, 4)]);
        assert_eq!(pmm.free_frames(), 4);
        assert_eq!(pmm.total_frames(), 4);
    }

    #[test]
    fn unaligned_reservation_covers_both_pages_and_zero_covers_none() {
        let mut pmm = PhysicalMemoryManager::new();
        pmm.init_from_memory_map(&[descriptor(0x100000, 4)]);
        pmm.reserve_region(PhysicalAddress::new(0x100001), 4096);
        assert_eq!(pmm.free_frames(), 2);
        pmm.reserve_region(PhysicalAddress::new(0x102001), 0);
        assert_eq!(pmm.free_frames(), 2);
    }

    #[test]
    fn reserved_descriptor_overrides_overlapping_conventional_memory() {
        let mut pmm = PhysicalMemoryManager::new();
        let mut reserved = descriptor(0x101000, 1);
        reserved.mem_type = UefiMemoryType::MemoryMappedIo;
        pmm.init_from_memory_map(&[reserved, descriptor(0x100000, 4)]);
        assert_eq!(pmm.free_frames(), 3);
        assert_eq!(pmm.total_frames(), 3);
        assert_eq!(pmm.allocate_frame().unwrap().as_u64(), 0x100000);
        assert_eq!(pmm.allocate_frame().unwrap().as_u64(), 0x102000);
    }

    #[test]
    fn test_pmm_frame_alloc_and_free() {
        let mut pmm = PhysicalMemoryManager::new();
        let desc = MemoryDescriptor {
            mem_type: UefiMemoryType::ConventionalMemory,
            phys_start: PhysicalAddress::new(0x100_0000), // 16MB
            virt_start: nexus_types::VirtualAddress::new(0),
            number_of_pages: 10,
            attribute: 0,
        };

        pmm.init_from_memory_map(&[desc]);
        assert_eq!(pmm.free_frames(), 10);

        let frame1 = pmm.allocate_frame().expect("Frame 1 allocation");
        assert_eq!(frame1.as_u64(), 0x100_0000);
        assert_eq!(pmm.free_frames(), 9);

        pmm.free_frame(frame1);
        assert_eq!(pmm.free_frames(), 10);
    }

    #[test]
    fn test_pmm_reserve_region() {
        let mut pmm = PhysicalMemoryManager::new();
        let desc = MemoryDescriptor {
            mem_type: UefiMemoryType::ConventionalMemory,
            phys_start: PhysicalAddress::new(0x100_0000), // 16MB
            virt_start: nexus_types::VirtualAddress::new(0),
            number_of_pages: 10,
            attribute: 0,
        };

        pmm.init_from_memory_map(&[desc]);
        assert_eq!(pmm.free_frames(), 10);

        // Reserve 2 pages starting at 0x100_0000
        pmm.reserve_region(PhysicalAddress::new(0x100_0000), 8192);
        assert_eq!(pmm.free_frames(), 8);

        // First allocation should now be at page 2 (0x100_2000)
        let frame = pmm.allocate_frame().expect("Frame allocation");
        assert_eq!(frame.as_u64(), 0x100_2000);
    }
}
