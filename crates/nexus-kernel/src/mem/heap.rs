//! Kernel Bump Allocator providing standard `alloc` support in freestanding Ring 0.

use core::alloc::{GlobalAlloc, Layout};
use spin::Mutex;

const HEAP_SIZE: usize = 1024 * 1024; // 1 MB heap

#[repr(align(16))]
struct HeapMemory([u8; HEAP_SIZE]);

static mut HEAP_STORAGE: HeapMemory = HeapMemory([0; HEAP_SIZE]);

pub struct BumpAllocator {
    offset: usize,
}

pub struct LockedHeap(Mutex<BumpAllocator>);

unsafe impl Sync for LockedHeap {}

unsafe impl GlobalAlloc for LockedHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut heap = self.0.lock();
        let align = layout.align();
        let size = layout.size();
        let current = heap.offset;
        let aligned = (current + align - 1) & !(align - 1);
        if aligned + size <= HEAP_SIZE {
            heap.offset = aligned + size;
            let base = &raw mut HEAP_STORAGE.0;
            (base as *mut u8).add(aligned)
        } else {
            core::ptr::null_mut()
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Bump allocator does not reclaim individual allocations
    }
}

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap(Mutex::new(BumpAllocator { offset: 0 }));
