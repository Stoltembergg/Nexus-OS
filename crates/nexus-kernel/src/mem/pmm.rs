//! Physical Memory Manager (PMM) using a bitmap frame allocator.

use nexus_types::{MemoryDescriptor, PhysicalAddress, UefiMemoryType, PAGE_SIZE_4KB};
use spin::Mutex;

pub const MAX_PHYSICAL_FRAMES: usize = 1024 * 1024; // Tracks up to 4GB of physical RAM
pub const BITMAP_SIZE_BYTES: usize = MAX_PHYSICAL_FRAMES / 8; // 128 KB bitmap

pub static PMM: Mutex<PhysicalMemoryManager> = Mutex::new(PhysicalMemoryManager::new());

pub struct PhysicalMemoryManager {
    bitmap: [u8; BITMAP_SIZE_BYTES],
    total_frames: usize,
    free_frames: usize,
}

impl Default for PhysicalMemoryManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PhysicalMemoryManager {
    pub const fn new() -> Self {
        Self {
            bitmap: [0xFF; BITMAP_SIZE_BYTES], // Initially all marked as used/reserved (1)
            total_frames: 0,
            free_frames: 0,
        }
    }

    /// Initializes allocator by marking `ConventionalMemory` regions from UEFI as free (0).
    pub fn init_from_memory_map(&mut self, map: &[MemoryDescriptor]) {
        self.bitmap.fill(0xFF);
        self.total_frames = 0;
        self.free_frames = 0;

        for desc in map {
            let start_frame = (desc.phys_start.as_u64() / PAGE_SIZE_4KB) as usize;
            let count = desc.number_of_pages as usize;

            if desc.mem_type == UefiMemoryType::ConventionalMemory {
                for i in 0..count {
                    let frame = start_frame + i;
                    if frame < MAX_PHYSICAL_FRAMES {
                        self.clear_bit(frame);
                        self.free_frames += 1;
                    }
                }
            }
            self.total_frames += count;
        }
    }

    /// Allocates a single 4KB physical frame.
    pub fn allocate_frame(&mut self) -> Option<PhysicalAddress> {
        for byte_idx in 0..BITMAP_SIZE_BYTES {
            if self.bitmap[byte_idx] != 0xFF {
                for bit_idx in 0..8 {
                    if (self.bitmap[byte_idx] & (1 << bit_idx)) == 0 {
                        let frame_idx = byte_idx * 8 + bit_idx;
                        self.set_bit(frame_idx);
                        self.free_frames -= 1;
                        return Some(PhysicalAddress::new((frame_idx as u64) * PAGE_SIZE_4KB));
                    }
                }
            }
        }
        None
    }

    /// Frees a previously allocated 4KB frame.
    pub fn free_frame(&mut self, frame: PhysicalAddress) {
        let frame_idx = (frame.as_u64() / PAGE_SIZE_4KB) as usize;
        if frame_idx < MAX_PHYSICAL_FRAMES && self.is_bit_set(frame_idx) {
            self.clear_bit(frame_idx);
            self.free_frames += 1;
        }
    }

    #[inline]
    fn set_bit(&mut self, bit: usize) {
        self.bitmap[bit / 8] |= 1 << (bit % 8);
    }

    #[inline]
    fn clear_bit(&mut self, bit: usize) {
        self.bitmap[bit / 8] &= !(1 << (bit % 8));
    }

    #[inline]
    fn is_bit_set(&self, bit: usize) -> bool {
        (self.bitmap[bit / 8] & (1 << (bit % 8))) != 0
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
    use nexus_types::VirtualAddress;

    #[test]
    fn test_pmm_frame_alloc_and_free() {
        let mut pmm = PhysicalMemoryManager::new();
        let desc = MemoryDescriptor {
            mem_type: UefiMemoryType::ConventionalMemory,
            phys_start: PhysicalAddress::new(0x10_0000), // 1MB
            virt_start: VirtualAddress::new(0),
            number_of_pages: 10,
            attribute: 0,
        };

        pmm.init_from_memory_map(&[desc]);
        assert_eq!(pmm.free_frames(), 10);

        let frame1 = pmm.allocate_frame().expect("failed to allocate frame");
        assert_eq!(frame1.as_u64(), 0x10_0000);
        assert_eq!(pmm.free_frames(), 9);

        let frame2 = pmm.allocate_frame().expect("failed to allocate frame");
        assert_eq!(frame2.as_u64(), 0x10_1000);
        assert_eq!(pmm.free_frames(), 8);

        pmm.free_frame(frame1);
        assert_eq!(pmm.free_frames(), 9);
    }
}
