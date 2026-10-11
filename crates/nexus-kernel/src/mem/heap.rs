//! Reclaiming kernel heap. Coalescing free list; absolute address alignment.
use core::alloc::{GlobalAlloc, Layout};
use linked_list_allocator::Heap;
use spin::Mutex;
const HEAP_SIZE: usize = 1024 * 1024;
#[repr(align(4096))]
struct HeapMemory([u8; HEAP_SIZE]);
static mut HEAP_STORAGE: HeapMemory = HeapMemory([0; HEAP_SIZE]);
pub struct LockedHeap(Mutex<Heap>);
unsafe impl GlobalAlloc for LockedHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut heap = self.0.lock();
        if heap.size() == 0 {
            heap.init((&raw mut HEAP_STORAGE.0).cast::<u8>(), HEAP_SIZE);
        }
        match heap.allocate_first_fit(layout) {
            Ok(pointer) => pointer.as_ptr(),
            Err(_) => {
                crate::serial_println!(
                    "[HEAP_OOM] bytes={} alignment={} used={} free={}",
                    layout.size(),
                    layout.align(),
                    heap.used(),
                    heap.free()
                );
                core::ptr::null_mut()
            }
        }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if let Some(ptr) = core::ptr::NonNull::new(ptr) {
            self.0.lock().deallocate(ptr, layout);
        }
    }
}
#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap(Mutex::new(Heap::empty()));
pub fn used_bytes() -> usize {
    ALLOCATOR.0.lock().used()
}
