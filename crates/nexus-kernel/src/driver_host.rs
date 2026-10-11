//! Windows NT Driver Host Subsystem & Ring 0 WDM Execution Validation.

use core::ffi::c_void;
use nexus_loader::driver::NtDriverHost;
use nexus_types::driver::{
    IoStackLocation, Irp, ParametersDeviceIoControl, UnicodeString, IOCTL_NEXUS_GET_VERSION,
    IOCTL_NEXUS_RAISE_IRQL_TEST, IRP_MJ_CREATE, IRP_MJ_DEVICE_CONTROL, IRP_MJ_READ,
};
#[cfg(any(target_os = "uefi", target_os = "none"))]
use nexus_types::VirtualAddress;

const REAL_DRIVER_BYTES: &[u8] =
    include_bytes!("../../../tests/fixtures/nt_driver/nexus_driver.sys");

/// Validates native Windows NT `.sys` driver loading, relocation, import resolution,
/// `DriverEntry` execution in Ring 0, IRP dispatching (Create, DeviceControl, Read),
/// and clean driver unloading.
pub fn validate_nt_driver_subsystem() {
    crate::serial_println!("[*] Initializing NT Driver Host Subsystem...");
    let host = NtDriverHost::new();

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

    // If running with paging enabled, set WRITABLE and clear NO_EXECUTE on driver's memory pages
    #[cfg(any(target_os = "uefi", target_os = "none"))]
    {
        if let Some(ref mut kas) = *crate::mem::KERNEL_ADDRESS_SPACE.lock() {
            let start = (driver.buffer.as_ptr() as u64) & !4095;
            let end = (driver.buffer.as_ptr() as u64 + driver.buffer.len() as u64 + 4095) & !4095;
            for addr in (start..end).step_by(4096) {
                let _ = kas.protect_kernel_page(
                    VirtualAddress::new(addr),
                    crate::mem::vmm::PageTableFlags::WRITABLE,
                );
            }
            crate::serial_println!("[+] Driver pages protected with Supervisor RWX permissions");
        }
    }

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

    let ver_status = unsafe { driver.dispatch(IRP_MJ_DEVICE_CONTROL, dev_ptr, &mut ioctl_irp_ver) };
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
        "[+] IOCTL_NEXUS_RAISE_IRQL_TEST verified: IRQL hardware elevation/restoration verified ({:#010X})",
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
    crate::serial_println!("[+] DriverUnload executed cleanly: DeviceObject freed");
}
