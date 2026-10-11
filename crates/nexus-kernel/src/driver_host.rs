//! Windows NT Driver Host Subsystem & Ring 0 WDM Execution Validation.

use core::ffi::c_void;
use core::sync::atomic::Ordering;
use nexus_loader::driver::{
    stub_ke_get_current_irql, stub_ke_lower_irql, stub_ke_raise_irql, NtDriverHost,
    BUGCHECK_HANDLER, DIAGNOSTIC_SINK, HARDWARE_IRQL_GETTER, HARDWARE_IRQL_SETTER,
};
use nexus_types::driver::{
    IoStackLocation, Irp, ParametersDeviceIoControl, UnicodeString, DISPATCH_LEVEL,
    IOCTL_NEXUS_GET_VERSION, IOCTL_NEXUS_RAISE_IRQL_TEST, IOCTL_WDM_SAMPLE_EVENT_TEST,
    IOCTL_WDM_SAMPLE_MEM_TEST, IOCTL_WDM_SAMPLE_SPINLOCK_IRQL, IRP_MJ_CREATE,
    IRP_MJ_DEVICE_CONTROL, IRP_MJ_READ, PASSIVE_LEVEL,
};
#[cfg(any(target_os = "uefi", target_os = "none"))]
use nexus_types::VirtualAddress;

const REAL_DRIVER_BYTES: &[u8] =
    include_bytes!("../../../tests/fixtures/nt_driver/nexus_driver.sys");
const STANDARD_WDM_BYTES: &[u8] =
    include_bytes!("../../../tests/fixtures/nt_driver/standard_wdm.sys");
/// Fixture with an absolute-pointer table (3 `IMAGE_REL_BASED_DIR64` fixups); its
/// `DriverEntry` returns STATUS_SUCCESS only if every relocated pointer is correct.
const RELOC_DRIVER_BYTES: &[u8] =
    include_bytes!("../../../tests/fixtures/nt_driver/reloc/reloc_driver.sys");
/// Preferred `ImageBase` of the fixtures; the host always maps elsewhere.
const FIXTURE_PREFERRED_BASE: u64 = 0x1_4000_0000;

/// Evidence gathered by [`validate_nt_driver_subsystem`].
#[derive(Debug, Default, Clone, Copy)]
pub struct DriverValidationReport {
    /// Driver image pages whose PTEs were read back and matched the section's W^X policy.
    pub wx_pages_verified: usize,
    /// Pages the 3 fixtures must have, derived independently from their PE section tables.
    pub wx_pages_expected: usize,
    /// Checks passed by `nexus_loader::driver::nt_semantics_self_test` in Ring 0.
    pub nt_semantics_checks: usize,
    /// Driver lifecycles (load -> DriverEntry -> unload -> drop) with balanced heap and pool.
    pub lifecycles_verified: usize,
}

/// Applies the driver's W^X section permissions to the kernel page tables and then reads
/// every image page's effective PTE flags back, asserting the policy (audit M5/FP1):
/// headers and read-only sections R/NX, code R/X, data RW/NX, never W+X, never USER.
/// Returns the number of pages verified. W^X is mandatory: without a kernel address
/// space this panics instead of silently skipping. Code becomes executable only here,
/// because the UEFI heap backing the image is NX by default.
#[cfg(any(target_os = "uefi", target_os = "none"))]
fn protect_driver_pages(driver: &nexus_loader::LoadedDriver) -> usize {
    use crate::mem::vmm::PageTableFlags as F;
    let mut guard = crate::mem::KERNEL_ADDRESS_SPACE.lock();
    let kas = guard
        .as_mut()
        .expect("W^X for NT drivers requires the kernel address space");
    driver
        .enforce_wx_protection(|va, writable, executable| {
            let mut flags = F::empty();
            if writable {
                flags |= F::WRITABLE;
            }
            if !executable {
                flags |= F::NO_EXECUTE;
            }
            kas.protect_kernel_page(VirtualAddress::new(va), flags)
                .map_err(|_| ())
        })
        .expect("Failed to apply W^X protection to driver sections");

    let base = driver.image_base;
    let header_end = driver.sections.first().map_or(4096, |s| s.rva as u64);
    let mut verified = 0;
    let mut check = |va: u64, writable: bool, executable: bool| {
        let m = kas
            .mapping(VirtualAddress::new(va))
            .expect("driver page must be mapped");
        let w = m.flags.contains(F::WRITABLE);
        let x = !m.flags.contains(F::NO_EXECUTE);
        assert!(!(w && x), "W+X driver page at {va:#x}");
        assert!(
            !m.flags.contains(F::USER),
            "driver page at {va:#x} is user-accessible"
        );
        assert_eq!(
            (w, x),
            (writable, executable),
            "PTE policy mismatch at {va:#x}"
        );
        verified += 1;
    };
    for off in (0..header_end.div_ceil(4096) * 4096).step_by(4096) {
        check(base + off, false, false);
    }
    for sec in &driver.sections {
        let start = (base + sec.rva as u64) & !4095;
        let end = (base + sec.rva as u64 + sec.size as u64).div_ceil(4096) * 4096;
        for va in (start..end).step_by(4096) {
            check(va, sec.is_writable, sec.is_executable);
        }
    }
    assert!(verified > 0, "no driver page verified");
    verified
}

#[cfg(not(any(target_os = "uefi", target_os = "none")))]
fn protect_driver_pages(_driver: &nexus_loader::LoadedDriver) -> usize {
    0
}

/// Returns the image pages to RW+NX before the heap buffer is freed.
#[cfg(any(target_os = "uefi", target_os = "none"))]
fn release_driver_pages(driver: &nexus_loader::LoadedDriver) {
    let mut guard = crate::mem::KERNEL_ADDRESS_SPACE.lock();
    let kas = guard
        .as_mut()
        .expect("releasing NT driver pages requires the kernel address space");
    let start = (driver.buffer.as_ptr() as u64) & !4095;
    let end = (driver.buffer.as_ptr() as u64 + driver.buffer.len() as u64 + 4095) & !4095;
    for addr in (start..end).step_by(4096) {
        kas.protect_kernel_page(
            VirtualAddress::new(addr),
            crate::mem::vmm::PageTableFlags::WRITABLE | crate::mem::vmm::PageTableFlags::NO_EXECUTE,
        )
        .expect("Failed to restore RW+NX on released driver pages");
    }
}

#[cfg(not(any(target_os = "uefi", target_os = "none")))]
fn release_driver_pages(_driver: &nexus_loader::LoadedDriver) {}

#[cfg(any(target_os = "uefi", target_os = "none"))]
fn heap_used_bytes() -> usize {
    crate::mem::heap::used_bytes()
}

/// Host builds use the system allocator; heap balance is only measured in the guest.
#[cfg(not(any(target_os = "uefi", target_os = "none")))]
fn heap_used_bytes() -> usize {
    0
}

/// Asserts that a driver lifecycle returned every kernel heap byte (audit M6). Together
/// with `LoadedDriver::unload` (device and pool accounting) this makes leaks fail the run.
fn expect_heap_balanced(before: usize, driver: &str) {
    let after = heap_used_bytes();
    assert_eq!(
        after, before,
        "{driver}: kernel heap not balanced after unload/drop ({before} -> {after} bytes)"
    );
}

/// Exercises base relocation and fail-closed loading in guest Ring 0.
///
/// Panics (and therefore fails the QEMU run) unless the relocation-bearing driver is
/// rebased, all 3 DIR64 fixups are applied, its `DriverEntry` verifies them, and images
/// with corrupted import/relocation directories are refused.
fn validate_loader_relocations_and_fail_closed(host: &NtDriverHost) -> usize {
    let mut driver = host
        .load_driver(
            RELOC_DRIVER_BYTES,
            "\\Driver\\NexusReloc",
            "\\Registry\\Test",
        )
        .expect("relocation fixture must load");
    assert_ne!(driver.image_base, FIXTURE_PREFERRED_BASE);
    assert_eq!(driver.relocations_applied, 3);
    let wx_pages = protect_driver_pages(&driver);
    let (reg, _reg_backing) = UnicodeString::from_str_vec("\\Registry\\Test");
    let status = unsafe { driver.init(&reg) };
    assert_eq!(
        status, 0,
        "reloc_driver DriverEntry rejected its relocated pointers"
    );
    crate::serial_println!(
        "NEXUS_DRIVER_RELOC:applied={}:rebased=true:entry_status={:#x}",
        driver.relocations_applied,
        status
    );
    release_driver_pages(&driver);
    drop(driver);

    let pe_off = u32::from_le_bytes(RELOC_DRIVER_BYTES[60..64].try_into().unwrap()) as usize;
    let data_dir = |index: usize| pe_off + 24 + 112 + index * 8;
    for (name, index) in [("imports", 1usize), ("relocs", 5usize)] {
        let mut corrupted = RELOC_DRIVER_BYTES.to_vec();
        let at = data_dir(index);
        corrupted[at..at + 4].copy_from_slice(&0x7FFF_0000u32.to_le_bytes());
        assert!(
            host.load_driver(&corrupted, "\\Driver\\Corrupt", "\\Registry\\Test")
                .is_err(),
            "corrupted {name} directory was loaded"
        );
    }
    crate::serial_println!("NEXUS_DRIVER_FAIL_CLOSED:imports=rejected:relocs=rejected");
    wx_pages
}

/// Number of image pages W^X must cover for a fixture, computed from the raw PE file
/// (headers up to the first section, then every section's page span). Used to require an
/// exact `wx_pages_verified` instead of a lower bound.
fn expected_wx_pages(image: &[u8]) -> usize {
    let pe = nexus_loader::PeImage::parse(image).expect("fixture must parse");
    let header_end = pe
        .sections
        .first()
        .map_or(4096, |s| s.virtual_address as usize);
    let mut pages = header_end.div_ceil(4096);
    for sec in &pe.sections {
        let size = if sec.virtual_size != 0 {
            sec.virtual_size
        } else {
            sec.size_of_raw_data
        } as usize;
        let start = sec.virtual_address as usize;
        pages += (start + size).div_ceil(4096) - start / 4096;
    }
    pages
}

/// Bugcheck handler for the guest: report the stop code and stop. Under the QEMU
/// hardening suite it exits with a dedicated failure status (39).
fn kernel_bugcheck_handler(code: u32, params: [usize; 4]) {
    crate::serial_println!(
        "NEXUS_BUGCHECK: code={:#x} params={:#x} {:#x} {:#x} {:#x}",
        code,
        params[0],
        params[1],
        params[2],
        params[3]
    );
    #[cfg(all(
        feature = "hardening-tests",
        any(target_os = "uefi", target_os = "none")
    ))]
    crate::hardening::exit_failure(crate::hardening::EXIT_CODE_NT_BUGCHECK);
    #[cfg(not(all(
        feature = "hardening-tests",
        any(target_os = "uefi", target_os = "none")
    )))]
    loop {
        core::hint::spin_loop();
    }
}

fn serial_diagnostic(line: &str) {
    crate::serial_println!("{}", line);
}

fn hardware_cr8_getter() -> u8 {
    crate::arch::x86_64::read_cr8_irql()
}

unsafe fn hardware_cr8_setter(irql: u8) {
    crate::arch::x86_64::write_cr8_irql(irql);
}

/// Validates native Windows NT `.sys` driver loading, relocation, import resolution,
/// hardware CR8 IRQL management, strict W^X memory protection, IRP dispatching,
/// synchronization primitives, non-paged memory pools, and clean unloading in Ring 0.
///
/// Every check panics on failure (which, under `hardening-tests`, exits QEMU with a failure
/// code). The returned report carries the evidence counters printed by the caller.
pub fn validate_nt_driver_subsystem() -> DriverValidationReport {
    crate::serial_println!("[*] Initializing NT Driver Host Subsystem...");

    // Hook hardware CR8 IRQL getter and setter callbacks
    HARDWARE_IRQL_GETTER.store(hardware_cr8_getter as *mut (), Ordering::Release);
    HARDWARE_IRQL_SETTER.store(hardware_cr8_setter as *mut (), Ordering::Release);
    crate::serial_println!("[+] Hardware CR8 / TPR IRQL hooks installed into NT Driver Host");

    BUGCHECK_HANDLER.store(kernel_bugcheck_handler as *mut (), Ordering::Release);
    DIAGNOSTIC_SINK.store(serial_diagnostic as *mut (), Ordering::Release);

    let host = NtDriverHost::new();
    let mut report = DriverValidationReport {
        wx_pages_expected: [RELOC_DRIVER_BYTES, REAL_DRIVER_BYTES, STANDARD_WDM_BYTES]
            .iter()
            .map(|image| expected_wx_pages(image))
            .sum(),
        ..Default::default()
    };

    // Minimal NT semantics (IRQL direction, events/waits, pool tags, device extensions and
    // deletion, pool registry exhaustion), before any driver is loaded. The self-test
    // swaps in a recording bugcheck handler and restores kernel_bugcheck_handler after.
    report.nt_semantics_checks = nexus_loader::driver::nt_semantics_self_test()
        .unwrap_or_else(|failed| panic!("NT semantics self-test failed: {failed}"));
    assert_eq!(
        BUGCHECK_HANDLER.load(Ordering::SeqCst),
        kernel_bugcheck_handler as *mut ()
    );
    let heap_before_reloc = heap_used_bytes();
    report.wx_pages_verified += validate_loader_relocations_and_fail_closed(&host);
    expect_heap_balanced(heap_before_reloc, "reloc_driver.sys");
    report.lifecycles_verified += 1;

    let heap_before_nexus = heap_used_bytes();
    {
        // =========================================================================
        // Part 1: MSVC-Compiled Driver Validation (nexus_driver.sys)
        // =========================================================================
        crate::serial_println!("[*] Loading MSVC-compiled WDM Driver (nexus_driver.sys)...");
        let mut driver = host
            .load_driver(
                REAL_DRIVER_BYTES,
                "\\Driver\\NexusDrv0",
                "\\Registry\\Machine\\System",
            )
            .expect("Failed to load WDM driver into Ring 0 host");

        crate::serial_println!(
            "[+] Driver Image Mapped: Base {:#018X}, EntryPoint {:#018X}, Size {} bytes",
            driver.image_base,
            driver.entry_point,
            driver.buffer.len()
        );

        // Apply strict W^X page protection (RX code, RW data, RO headers/rdata)
        report.wx_pages_verified += protect_driver_pages(&driver);

        // 1. Execute DriverEntry in Ring 0
        let (reg_ustr, _reg_backing) = UnicodeString::from_str_vec(
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\NexusDrv0",
        );
        let init_status = unsafe { driver.init(&reg_ustr) };
        assert_eq!(
            init_status, 0,
            "DriverEntry must succeed and return STATUS_SUCCESS (0)"
        );
        crate::serial_println!("[+] DriverEntry executed successfully in Ring 0 (STATUS_SUCCESS)");

        // 2. Validate DeviceObject creation
        let dev_ptr = driver.driver_object.device_object;
        assert!(
            !dev_ptr.is_null(),
            "DeviceObject must have been created by driver"
        );
        crate::serial_println!(
            "[+] DeviceObject dynamically created and registered at {:p}",
            dev_ptr
        );

        // 3. Dispatch IRP_MJ_CREATE
        let mut create_irp = Irp::default();
        let create_status = unsafe { driver.dispatch(IRP_MJ_CREATE, dev_ptr, &mut create_irp) };
        assert_eq!(create_status, 0, "IRP_MJ_CREATE dispatch failed");
        crate::serial_println!("[+] IRP_MJ_CREATE dispatched and completed successfully");

        // 4. Dispatch IRP_MJ_DEVICE_CONTROL: IOCTL_NEXUS_GET_VERSION
        let mut ver_output: u32 = 0;
        let mut stack_ver = IoStackLocation {
            major_function: IRP_MJ_DEVICE_CONTROL as u8,
            parameters: ParametersDeviceIoControl {
                output_buffer_length: 4,
                input_buffer_length: 0,
                io_control_code: IOCTL_NEXUS_GET_VERSION,
                _padding: 0,
                type3_input_buffer: core::ptr::null_mut(),
            },
            ..Default::default()
        };

        let mut ioctl_irp_ver = Irp {
            user_buffer: &mut ver_output as *mut u32 as *mut c_void,
            current_stack_location: &mut stack_ver,
            ..Default::default()
        };

        let ver_status =
            unsafe { driver.dispatch(IRP_MJ_DEVICE_CONTROL, dev_ptr, &mut ioctl_irp_ver) };
        assert_eq!(ver_status, 0, "IOCTL_NEXUS_GET_VERSION failed");
        assert_eq!(
            ver_output, 0x0003_0600,
            "Invalid version returned by driver"
        );
        crate::serial_println!(
            "[+] IOCTL_NEXUS_GET_VERSION verified: Driver Version {:#010X}",
            ver_output
        );

        // 5. Dispatch IRP_MJ_DEVICE_CONTROL: IOCTL_NEXUS_RAISE_IRQL_TEST
        let mut irql_test_result: u32 = 0;
        let mut stack_irql = IoStackLocation {
            major_function: IRP_MJ_DEVICE_CONTROL as u8,
            parameters: ParametersDeviceIoControl {
                output_buffer_length: 4,
                input_buffer_length: 0,
                io_control_code: IOCTL_NEXUS_RAISE_IRQL_TEST,
                _padding: 0,
                type3_input_buffer: core::ptr::null_mut(),
            },
            ..Default::default()
        };

        let mut ioctl_irp_irql = Irp {
            user_buffer: &mut irql_test_result as *mut u32 as *mut c_void,
            current_stack_location: &mut stack_irql,
            ..Default::default()
        };

        let irql_status =
            unsafe { driver.dispatch(IRP_MJ_DEVICE_CONTROL, dev_ptr, &mut ioctl_irp_irql) };
        assert_eq!(irql_status, 0, "IOCTL_NEXUS_RAISE_IRQL_TEST failed");
        assert_eq!(
            irql_test_result, 0x1337_C0DE,
            "IRQL raise/lower test failed inside driver"
        );
        crate::serial_println!(
        "[+] IOCTL_NEXUS_RAISE_IRQL_TEST verified: IRQL hardware elevation/restoration ({:#010X})",
        irql_test_result
    );

        // 6. Dispatch IRP_MJ_READ
        let mut read_buf = [0u8; 32];
        let mut read_irp = Irp {
            user_buffer: read_buf.as_mut_ptr() as *mut c_void,
            ..Default::default()
        };

        let read_status = unsafe { driver.dispatch(IRP_MJ_READ, dev_ptr, &mut read_irp) };
        assert_eq!(read_status, 0, "IRP_MJ_READ failed");
        assert_eq!(read_irp.io_status.information, 25);
        let read_str = core::str::from_utf8(&read_buf[..25]).unwrap_or("<invalid utf8>");
        crate::serial_println!("[+] IRP_MJ_READ verified: Driver payload '{}'", read_str);

        // 7. Safe Driver Unload
        unsafe {
            driver.unload().expect("Driver unload failed");
        }
        assert!(
            driver.driver_object.device_object.is_null(),
            "DeviceObject must be destroyed on unload"
        );
        release_driver_pages(&driver);
        crate::serial_println!("[+] DriverUnload executed cleanly: DeviceObject freed");
    }
    expect_heap_balanced(heap_before_nexus, "nexus_driver.sys");
    report.lifecycles_verified += 1;

    let heap_before_std = heap_used_bytes();
    {
        // =========================================================================
        // Part 2: Authentic Standard WDM Driver (standard_wdm.sys)
        // Pools, SpinLocks, Events, and Hardware CR8 IRQL Verification
        // =========================================================================
        crate::serial_println!("[*] Loading Authentic Standard WDM Driver (standard_wdm.sys)...");
        let mut std_driver = host
            .load_driver(
                STANDARD_WDM_BYTES,
                "\\Driver\\StandardWdm0",
                "\\Registry\\Machine\\System",
            )
            .expect("Failed to load standard WDM driver into Ring 0 host");

        // Apply strict W^X protection to standard WDM driver
        report.wx_pages_verified += protect_driver_pages(&std_driver);

        // 1. Initialize Standard WDM Driver
        let (std_reg_ustr, _std_reg_backing) = UnicodeString::from_str_vec(
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\StandardWdm0",
        );
        let std_init_status = unsafe { std_driver.init(&std_reg_ustr) };
        assert_eq!(
            std_init_status, 0,
            "Standard WDM DriverEntry must return STATUS_SUCCESS"
        );
        let std_dev_ptr = std_driver.driver_object.device_object;
        assert!(!std_dev_ptr.is_null(), "DeviceObject creation failed");
        crate::serial_println!(
            "[+] Standard WDM DriverEntry initialized successfully: DeviceObject at {:p}",
            std_dev_ptr
        );

        // 2. Test Non-Paged Memory Pool Allocation & Verification IOCTL
        let mut pool_result: u32 = 0;
        let mut stack_mem = IoStackLocation {
            major_function: IRP_MJ_DEVICE_CONTROL as u8,
            parameters: ParametersDeviceIoControl {
                output_buffer_length: 4,
                input_buffer_length: 0,
                io_control_code: IOCTL_WDM_SAMPLE_MEM_TEST,
                _padding: 0,
                type3_input_buffer: core::ptr::null_mut(),
            },
            ..Default::default()
        };
        let mut ioctl_irp_mem = Irp {
            user_buffer: &mut pool_result as *mut u32 as *mut c_void,
            current_stack_location: &mut stack_mem,
            ..Default::default()
        };
        let pool_status =
            unsafe { std_driver.dispatch(IRP_MJ_DEVICE_CONTROL, std_dev_ptr, &mut ioctl_irp_mem) };
        assert_eq!(pool_status, 0, "Pool test IOCTL failed");
        assert_eq!(
            pool_result, 0x504F4F4C,
            "Pool test result must match 'POOL' (0x504F4F4C)"
        );
        crate::serial_println!(
            "[+] Non-Paged Pool allocation and memory verification verified (0x{:08X})",
            pool_result
        );

        // 3. Test SpinLock and Hardware CR8 IRQL IOCTL
        let mut spinlock_counter: u32 = 0;
        let mut stack_spin = IoStackLocation {
            major_function: IRP_MJ_DEVICE_CONTROL as u8,
            parameters: ParametersDeviceIoControl {
                output_buffer_length: 4,
                input_buffer_length: 0,
                io_control_code: IOCTL_WDM_SAMPLE_SPINLOCK_IRQL,
                _padding: 0,
                type3_input_buffer: core::ptr::null_mut(),
            },
            ..Default::default()
        };
        let mut ioctl_irp_spin = Irp {
            user_buffer: &mut spinlock_counter as *mut u32 as *mut c_void,
            current_stack_location: &mut stack_spin,
            ..Default::default()
        };
        let spin_status =
            unsafe { std_driver.dispatch(IRP_MJ_DEVICE_CONTROL, std_dev_ptr, &mut ioctl_irp_spin) };
        assert_eq!(spin_status, 0, "SpinLock test IOCTL failed");
        assert_eq!(spinlock_counter, 101, "SpinLock counter mismatch");
        assert_eq!(
            crate::arch::x86_64::read_cr8_irql(),
            PASSIVE_LEVEL,
            "IRQL must return to PASSIVE_LEVEL after spinlock release"
        );
        crate::serial_println!(
            "[+] SpinLock synchronization and hardware CR8 IRQL elevation verified (counter = {})",
            spinlock_counter
        );

        // 4. Test Event Synchronization IOCTL
        let mut event_res: u32 = 0;
        let mut stack_evt = IoStackLocation {
            major_function: IRP_MJ_DEVICE_CONTROL as u8,
            parameters: ParametersDeviceIoControl {
                output_buffer_length: 4,
                input_buffer_length: 0,
                io_control_code: IOCTL_WDM_SAMPLE_EVENT_TEST,
                _padding: 0,
                type3_input_buffer: core::ptr::null_mut(),
            },
            ..Default::default()
        };
        let mut ioctl_irp_evt = Irp {
            user_buffer: &mut event_res as *mut u32 as *mut c_void,
            current_stack_location: &mut stack_evt,
            ..Default::default()
        };
        let evt_status =
            unsafe { std_driver.dispatch(IRP_MJ_DEVICE_CONTROL, std_dev_ptr, &mut ioctl_irp_evt) };
        assert_eq!(evt_status, 0, "Event test IOCTL failed");
        assert_eq!(
            event_res, 0xCAFE_FEED,
            "Event test result must match 0xCAFEFEED"
        );
        crate::serial_println!(
        "[+] KeSetEvent/KeWaitForSingleObject call path on a signaled event (0x{:08X}); blocking/wake-up semantics NOT verified (no waiters yet)",
        event_res
    );

        // 5. Test Standard WDM Payload Read
        let mut std_read_buf = [0u8; 32];
        let mut std_read_stack = IoStackLocation {
            major_function: IRP_MJ_READ as u8,
            device_object: std_dev_ptr,
            parameters: ParametersDeviceIoControl {
                output_buffer_length: 32,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut std_read_irp = Irp {
            user_buffer: std_read_buf.as_mut_ptr() as *mut c_void,
            current_stack_location: &mut std_read_stack,
            ..Default::default()
        };
        let std_read_status =
            unsafe { std_driver.dispatch(IRP_MJ_READ, std_dev_ptr, &mut std_read_irp) };
        assert_eq!(std_read_status, 0, "Standard WDM IRP_MJ_READ failed");
        assert_eq!(std_read_irp.io_status.information, 27);
        let std_read_str = core::str::from_utf8(&std_read_buf[..27]).unwrap_or("<invalid utf8>");
        crate::serial_println!("[+] Standard WDM IRP_MJ_READ verified: '{}'", std_read_str);

        // 6. Test Unload of Standard WDM Driver (pool freeing, symbolic link/device destruction)
        unsafe {
            std_driver.unload().expect("Standard WDM unload failed");
        }
        assert!(
            std_driver.driver_object.device_object.is_null(),
            "DeviceObject must be destroyed on unload"
        );
        release_driver_pages(&std_driver);
        crate::serial_println!(
        "[+] Standard WDM DriverUnload executed cleanly: DeviceObject destroyed and pools freed"
    );
    }
    expect_heap_balanced(heap_before_std, "standard_wdm.sys");
    report.lifecycles_verified += 1;

    // =========================================================================
    // Part 3: IRQL plumbing in Ring 0 (CR8 round-trip and stub routing)
    // =========================================================================
    // What this proves: CR8 accepts and returns the written value, and the NT IRQL stubs
    // reach CR8 through the installed hooks. What it does NOT prove: interrupt masking.
    // Interrupts stay disabled and there is no APIC/timer yet (moved to Phase 4), so the
    // IRQL has no effect on preemption today (audit FP4/FP6).
    crate::arch::x86_64::write_cr8_irql(DISPATCH_LEVEL);
    assert_eq!(crate::arch::x86_64::read_cr8_irql(), DISPATCH_LEVEL);
    crate::arch::x86_64::write_cr8_irql(PASSIVE_LEVEL);
    assert_eq!(crate::arch::x86_64::read_cr8_irql(), PASSIVE_LEVEL);
    let mut old_irql = 0xFF;
    unsafe { stub_ke_raise_irql(DISPATCH_LEVEL, &mut old_irql) };
    assert_eq!(
        old_irql, PASSIVE_LEVEL,
        "KeRaiseIrql must report the previous CR8 IRQL"
    );
    assert_eq!(
        crate::arch::x86_64::read_cr8_irql(),
        DISPATCH_LEVEL,
        "KeRaiseIrql must write CR8 through the hardware hook"
    );
    assert_eq!(unsafe { stub_ke_get_current_irql() }, DISPATCH_LEVEL);
    unsafe { stub_ke_lower_irql(PASSIVE_LEVEL) };
    assert_eq!(crate::arch::x86_64::read_cr8_irql(), PASSIVE_LEVEL);
    crate::serial_println!(
        "[+] CR8 (TPR) read/write round-trip and KeRaise/LowerIrql -> CR8 routing verified (no interrupt masking: interrupts are disabled until Phase 4)"
    );

    report
}
