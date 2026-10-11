//! Heap accounting for `IoDeleteDevice` (PR-4 review): a double delete or a delete of a
//! pointer that never was a device must bugcheck and must not free anything, so the
//! process heap returns exactly to its baseline.
//!
//! This file holds a single test and its own counting global allocator, so no other test
//! in the binary allocates concurrently.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, AtomicUsize, Ordering};

use nexus_loader::driver::{
    bugcheck_count, last_bugcheck, last_bugcheck_params, live_device_objects,
    lock_nt_host_state_for_tests, stub_io_create_device, stub_io_delete_device, BUGCHECK_HANDLER,
    BUGCHECK_NEXUS_INVALID_DEVICE_DELETE, DEVICE_DELETE_NOT_LIVE,
};
use nexus_types::driver::{DeviceObject, DriverObject, STATUS_SUCCESS};

struct Counting;
static LIVE_BYTES: AtomicIsize = AtomicIsize::new(0);
static FREES: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE_BYTES.fetch_add(layout.size() as isize, Ordering::SeqCst);
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE_BYTES.fetch_sub(layout.size() as isize, Ordering::SeqCst);
        FREES.fetch_add(1, Ordering::SeqCst);
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn record_only(_code: u32, _params: [usize; 4]) {}

#[test]
fn invalid_device_deletes_bugcheck_and_keep_heap_balanced() {
    let _host_state = lock_nt_host_state_for_tests();
    BUGCHECK_HANDLER.store(record_only as *mut (), Ordering::SeqCst);
    let mut drv = DriverObject::default();
    let mut fake = [0x3Cu8; 256];
    let fake_dev = unsafe { fake.as_mut_ptr().add(64) } as *mut DeviceObject;

    let heap0 = LIVE_BYTES.load(Ordering::SeqCst);
    let devices0 = live_device_objects();
    let bugchecks0 = bugcheck_count();
    let mut dev = std::ptr::null_mut();
    unsafe {
        assert_eq!(
            stub_io_create_device(&mut drv, 128, std::ptr::null_mut(), 0x22, 0, 0, &mut dev),
            STATUS_SUCCESS
        );
        stub_io_delete_device(dev);
        let frees_after_valid_delete = FREES.load(Ordering::SeqCst);
        let heap_after_valid_delete = LIVE_BYTES.load(Ordering::SeqCst);

        stub_io_delete_device(dev); // double delete
        let double = (last_bugcheck(), last_bugcheck_params());
        stub_io_delete_device(fake_dev); // never a device
        let foreign = (last_bugcheck(), last_bugcheck_params());

        assert_eq!(
            heap_after_valid_delete, heap0,
            "valid delete frees the device"
        );
        assert_eq!(
            FREES.load(Ordering::SeqCst),
            frees_after_valid_delete,
            "invalid deletes must not free anything"
        );
        assert_eq!(LIVE_BYTES.load(Ordering::SeqCst), heap0, "heap balanced");
        assert_eq!(bugcheck_count(), bugchecks0 + 2);
        assert_eq!(double.0, BUGCHECK_NEXUS_INVALID_DEVICE_DELETE);
        assert_eq!(double.1[..2], [DEVICE_DELETE_NOT_LIVE, dev as usize]);
        assert_eq!(foreign.0, BUGCHECK_NEXUS_INVALID_DEVICE_DELETE);
        assert_eq!(foreign.1[..2], [DEVICE_DELETE_NOT_LIVE, fake_dev as usize]);
    }
    assert!(fake.iter().all(|&b| b == 0x3C), "foreign memory untouched");
    assert_eq!(live_device_objects(), devices0);
    assert!(drv.device_object.is_null());
}
