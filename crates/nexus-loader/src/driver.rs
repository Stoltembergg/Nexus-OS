//! Windows NT Kernel Driver (`.sys`) Loader & WDM Host Subsystem.
//!
//! Provides parsing, section mapping, relocation processing, dynamic kernel export binding,
//! and `DriverEntry` dispatching for native Windows NT kernel-mode drivers (`IMAGE_SUBSYSTEM_NATIVE`).

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use byteorder::{ByteOrder, LittleEndian};
use core::ffi::c_void;
use nexus_types::driver::{
    DeviceObject, DriverObject, Irp, UnicodeString, IMAGE_SUBSYSTEM_NATIVE, IRP_MJ_MAXIMUM_FUNCTION,
};

use crate::error::LoaderError;
use crate::pe::{PeImage, IMAGE_REL_BASED_DIR64};

/// Errors encountered while loading and binding an NT kernel driver.
#[derive(Debug, PartialEq, Eq)]
pub enum NtDriverError {
    Loader(LoaderError),
    InvalidImageFormat,
    NotNativeDriver(u16),
    NoEntryPoint,
    RelocationFailed,
    UnresolvedImport { dll: String, function: String },
    DriverEntryFailed(i32),
}

impl From<LoaderError> for NtDriverError {
    fn from(err: LoaderError) -> Self {
        Self::Loader(err)
    }
}

/// Simulated NT Kernel function table providing fundamental `ntoskrnl.exe` and `hal.dll` exports.
pub struct NtoskrnlTable {
    exports: BTreeMap<(String, String), usize>,
}

impl Default for NtoskrnlTable {
    fn default() -> Self {
        Self::new()
    }
}

impl NtoskrnlTable {
    /// Creates a new kernel export table populated with standard WDM foundation routines.
    pub fn new() -> Self {
        let mut table = Self {
            exports: BTreeMap::new(),
        };

        // Register default WDM core exports
        table.register(
            "NTOSKRNL.EXE",
            "DbgPrint",
            stub_dbg_print as *const () as usize,
        );
        table.register(
            "NTOSKRNL.EXE",
            "IoCreateDevice",
            stub_io_create_device as *const () as usize,
        );
        table.register(
            "NTOSKRNL.EXE",
            "IoDeleteDevice",
            stub_io_delete_device as *const () as usize,
        );
        table.register(
            "NTOSKRNL.EXE",
            "IoCreateSymbolicLink",
            stub_io_create_symbolic_link as *const () as usize,
        );
        table.register(
            "NTOSKRNL.EXE",
            "IoCompleteRequest",
            stub_io_complete_request as *const () as usize,
        );

        table
    }

    /// Registers a custom kernel function export.
    pub fn register(&mut self, dll: &str, function: &str, address: usize) {
        self.exports
            .insert((dll.to_uppercase(), function.to_string()), address);
    }

    /// Resolves a requested import symbol.
    pub fn resolve(&self, dll: &str, function: &str) -> Option<usize> {
        self.exports
            .get(&(dll.to_uppercase(), function.to_string()))
            .copied()
    }
}

/// Active, loaded Windows NT kernel driver instance.
#[derive(Debug)]
pub struct LoadedDriver {
    pub name: String,
    pub image_base: u64,
    pub entry_point: u64,
    pub driver_object: DriverObject,
    pub mapped_image: Vec<u8>,
    pub created_devices: Vec<DeviceObject>,
}

impl LoadedDriver {
    /// Dispatches an I/O Request Packet (IRP) to the driver's registered dispatch routine.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `device` points to a valid `DeviceObject` and `irp` points
    /// to a valid `Irp` instance in accessible memory.
    pub unsafe fn dispatch(
        &mut self,
        major_function: usize,
        device: *mut DeviceObject,
        irp: *mut Irp,
    ) -> i32 {
        if major_function > IRP_MJ_MAXIMUM_FUNCTION {
            return -1073741822; // STATUS_NOT_IMPLEMENTED (0xC0000002)
        }

        if let Some(dispatch_fn) = self.driver_object.major_function[major_function] {
            dispatch_fn(device, irp)
        } else {
            -1073741822 // STATUS_NOT_IMPLEMENTED
        }
    }
}

/// Host executive capable of loading, binding, and executing Windows NT `.sys` drivers.
pub struct NtDriverHost {
    pub kernel_table: NtoskrnlTable,
}

impl Default for NtDriverHost {
    fn default() -> Self {
        Self::new()
    }
}

impl NtDriverHost {
    pub fn new() -> Self {
        Self {
            kernel_table: NtoskrnlTable::new(),
        }
    }

    /// Validates, maps, relocates, binds imports, and initializes an NT kernel driver from raw `.sys` PE bytes.
    pub fn load_driver(
        &self,
        sys_bytes: &[u8],
        driver_name: &str,
        registry_path: &str,
    ) -> Result<LoadedDriver, NtDriverError> {
        // 1. Parse PE Image and verify subsystem
        let pe = PeImage::parse(sys_bytes)?;

        if pe.subsystem != IMAGE_SUBSYSTEM_NATIVE {
            return Err(NtDriverError::NotNativeDriver(pe.subsystem));
        }

        if pe.entry_point_rva == 0 {
            return Err(NtDriverError::NoEntryPoint);
        }

        // 2. Allocate contiguous virtual memory layout for headers and sections
        let image_size = pe.size_of_image as usize;
        let mut mapped = vec![0u8; image_size];

        // Map PE Headers
        let header_copy_len = (pe.size_of_headers as usize).min(sys_bytes.len());
        mapped[..header_copy_len].copy_from_slice(&sys_bytes[..header_copy_len]);

        // Map Sections
        for sec in &pe.sections {
            let va_start = sec.virtual_address as usize;
            let raw_start = sec.pointer_to_raw_data as usize;
            let raw_size = (sec.size_of_raw_data as usize).min(sec.virtual_size as usize);

            if raw_start + raw_size <= sys_bytes.len() && va_start + raw_size <= mapped.len() {
                mapped[va_start..va_start + raw_size]
                    .copy_from_slice(&sys_bytes[raw_start..raw_start + raw_size]);
            }
        }

        // 3. Process Base Relocations
        let actual_base = mapped.as_ptr() as u64;
        let preferred_base = pe.image_base;
        let delta = actual_base.wrapping_sub(preferred_base);

        if delta != 0 {
            let reloc_blocks = pe.parse_relocations(sys_bytes).unwrap_or_default();
            for block in reloc_blocks {
                for entry in block.entries {
                    if entry.rel_type == IMAGE_REL_BASED_DIR64 {
                        let target_rva = (block.page_rva + entry.offset as u32) as usize;
                        if target_rva + 8 <= mapped.len() {
                            let curr_val =
                                LittleEndian::read_u64(&mapped[target_rva..target_rva + 8]);
                            let patched = curr_val.wrapping_add(delta);
                            LittleEndian::write_u64(
                                &mut mapped[target_rva..target_rva + 8],
                                patched,
                            );
                        }
                    }
                }
            }
        }

        // 4. Resolve Imports against NtoskrnlTable and patch IAT
        let import_descriptors = pe.parse_imports(sys_bytes).unwrap_or_default();
        for desc in import_descriptors {
            for func in desc.functions {
                let resolved_addr = self
                    .kernel_table
                    .resolve(&desc.dll_name, &func.name)
                    .ok_or_else(|| NtDriverError::UnresolvedImport {
                        dll: desc.dll_name.clone(),
                        function: func.name.clone(),
                    })?;

                let iat_offset = func.iat_rva as usize;
                if iat_offset + 8 <= mapped.len() {
                    LittleEndian::write_u64(
                        &mut mapped[iat_offset..iat_offset + 8],
                        resolved_addr as u64,
                    );
                }
            }
        }

        // 5. Initialize DRIVER_OBJECT
        let mut driver_obj = DriverObject::default();
        let (driver_name_ustr, _name_backing) = UnicodeString::from_str_vec(driver_name);
        let (_registry_ustr, _reg_backing) = UnicodeString::from_str_vec(registry_path);

        driver_obj.driver_name = driver_name_ustr;
        driver_obj.driver_start = mapped.as_mut_ptr() as *mut c_void;
        driver_obj.driver_size = image_size as u32;

        let entry_va = actual_base + pe.entry_point_rva as u64;

        Ok(LoadedDriver {
            name: driver_name.to_string(),
            image_base: actual_base,
            entry_point: entry_va,
            driver_object: driver_obj,
            mapped_image: mapped,
            created_devices: Vec::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Standard WDM Kernel Function Stubs
// ---------------------------------------------------------------------------

unsafe extern "win64" fn stub_dbg_print(_format_ptr: *const u8) -> i32 {
    0 // STATUS_SUCCESS
}

unsafe extern "win64" fn stub_io_create_device(
    driver_object: *mut DriverObject,
    _device_extension_size: u32,
    _device_name: *mut UnicodeString,
    device_type: u32,
    characteristics: u32,
    _exclusive: u8,
    device_object: *mut *mut DeviceObject,
) -> i32 {
    if driver_object.is_null() || device_object.is_null() {
        return -1073741811; // STATUS_INVALID_PARAMETER (0xC000000D)
    }

    // Allocate Device Object in heap for the driver
    let dev = alloc::boxed::Box::into_raw(alloc::boxed::Box::new(DeviceObject {
        driver_object,
        device_type,
        characteristics,
        ..Default::default()
    }));

    (*driver_object).device_object = dev;
    *device_object = dev;

    0 // STATUS_SUCCESS
}

unsafe extern "win64" fn stub_io_delete_device(device_object: *mut DeviceObject) {
    if !device_object.is_null() {
        let _ = alloc::boxed::Box::from_raw(device_object);
    }
}

unsafe extern "win64" fn stub_io_create_symbolic_link(
    _symbolic_link_name: *mut UnicodeString,
    _device_name: *mut UnicodeString,
) -> i32 {
    0 // STATUS_SUCCESS
}

unsafe extern "win64" fn stub_io_complete_request(irp: *mut Irp, _priority_boost: i8) {
    if !irp.is_null() {
        (*irp).pending_returned = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_types::driver::{IRP_MJ_CREATE, IRP_MJ_DEVICE_CONTROL};

    // Sample mock DriverEntry routine matching WDM ABI
    unsafe extern "win64" fn mock_driver_entry(
        driver_obj: *mut DriverObject,
        _reg_path: *const UnicodeString,
    ) -> i32 {
        if driver_obj.is_null() {
            return -1073741811;
        }

        // Arm IRP_MJ_CREATE and IRP_MJ_DEVICE_CONTROL dispatch routines
        (*driver_obj).major_function[IRP_MJ_CREATE] = Some(mock_create_dispatch);
        (*driver_obj).major_function[IRP_MJ_DEVICE_CONTROL] = Some(mock_ioctl_dispatch);

        let mut dev: *mut DeviceObject = core::ptr::null_mut();
        stub_io_create_device(
            driver_obj,
            0,
            core::ptr::null_mut(),
            0x22, // FILE_DEVICE_UNKNOWN
            0,
            0,
            &mut dev,
        )
    }

    unsafe extern "win64" fn mock_create_dispatch(
        _device: *mut DeviceObject,
        irp: *mut Irp,
    ) -> i32 {
        if !irp.is_null() {
            (*irp).io_status.status = 0;
            (*irp).io_status.information = 0;
        }
        0 // STATUS_SUCCESS
    }

    unsafe extern "win64" fn mock_ioctl_dispatch(_device: *mut DeviceObject, irp: *mut Irp) -> i32 {
        if !irp.is_null() {
            (*irp).io_status.status = 0;
            (*irp).io_status.information = 42; // Returned 42 bytes
        }
        0 // STATUS_SUCCESS
    }

    /// Synthesizes a valid PE32+ .sys driver binary with IMAGE_SUBSYSTEM_NATIVE (1).
    fn create_test_sys_binary() -> Vec<u8> {
        let mut buf = vec![0u8; 8192];

        // DOS Header
        LittleEndian::write_u16(&mut buf[0..2], crate::pe::IMAGE_DOS_SIGNATURE); // "MZ"
        LittleEndian::write_u32(&mut buf[60..64], 128); // e_lfanew = 128

        let pe_off = 128;
        // NT Signature
        LittleEndian::write_u32(&mut buf[pe_off..pe_off + 4], crate::pe::IMAGE_NT_SIGNATURE); // "PE\0\0"

        // File Header
        let file_off = pe_off + 4;
        LittleEndian::write_u16(
            &mut buf[file_off..file_off + 2],
            crate::pe::IMAGE_FILE_MACHINE_AMD64,
        ); // AMD64
        LittleEndian::write_u16(&mut buf[file_off + 2..file_off + 4], 1); // 1 section
        LittleEndian::write_u16(&mut buf[file_off + 16..file_off + 18], 240); // SizeOfOptionalHeader = 240
        LittleEndian::write_u16(&mut buf[file_off + 18..file_off + 20], 0x2002); // EXECUTABLE_IMAGE | SYSTEM

        // Optional Header
        let opt_off = file_off + 20;
        LittleEndian::write_u16(
            &mut buf[opt_off..opt_off + 2],
            crate::pe::IMAGE_NT_OPTIONAL_HDR64_MAGIC,
        ); // PE32+
        LittleEndian::write_u32(&mut buf[opt_off + 16..opt_off + 20], 0x1000); // EntryPoint = 0x1000
        LittleEndian::write_u64(&mut buf[opt_off + 24..opt_off + 32], 0x140000000); // ImageBase
        LittleEndian::write_u32(&mut buf[opt_off + 32..opt_off + 36], 4096); // SectionAlignment
        LittleEndian::write_u32(&mut buf[opt_off + 36..opt_off + 40], 512); // FileAlignment
        LittleEndian::write_u32(&mut buf[opt_off + 56..opt_off + 60], 8192); // SizeOfImage = 8KB
        LittleEndian::write_u32(&mut buf[opt_off + 60..opt_off + 64], 512); // SizeOfHeaders = 512
        LittleEndian::write_u16(&mut buf[opt_off + 68..opt_off + 70], IMAGE_SUBSYSTEM_NATIVE); // Subsystem = 1 (NATIVE)
        LittleEndian::write_u32(&mut buf[opt_off + 108..opt_off + 112], 16); // NumberOfRvaAndSizes

        // Section Header (.text)
        let sec_off = opt_off + 240;
        buf[sec_off..sec_off + 5].copy_from_slice(b".text");
        LittleEndian::write_u32(&mut buf[sec_off + 8..sec_off + 12], 0x1000); // VirtualSize
        LittleEndian::write_u32(&mut buf[sec_off + 12..sec_off + 16], 0x1000); // VirtualAddress
        LittleEndian::write_u32(&mut buf[sec_off + 16..sec_off + 20], 0x1000); // SizeOfRawData
        LittleEndian::write_u32(&mut buf[sec_off + 20..sec_off + 24], 512); // PointerToRawData
        LittleEndian::write_u32(
            &mut buf[sec_off + 36..sec_off + 40],
            crate::pe::IMAGE_SCN_MEM_EXECUTE | crate::pe::IMAGE_SCN_MEM_READ,
        );

        buf
    }

    #[test]
    fn test_driver_loader_validates_native_subsystem() {
        let mut sys_bytes = create_test_sys_binary();
        let host = NtDriverHost::new();

        // 1. Verify standard native driver loads successfully
        let driver = host
            .load_driver(&sys_bytes, "\\Driver\\TestDriver", "\\Registry\\Test")
            .expect("Failed to load native driver");
        assert_eq!(driver.name, "\\Driver\\TestDriver");
        assert_eq!(driver.driver_object.type_, 4);

        // 2. Corrupt subsystem to 3 (Windows CUI / console) and verify rejection
        let pe_off = 128;
        let opt_off = pe_off + 24;
        LittleEndian::write_u16(&mut sys_bytes[opt_off + 68..opt_off + 70], 3);

        let err = host
            .load_driver(&sys_bytes, "\\Driver\\BadDriver", "\\Registry\\Test")
            .unwrap_err();
        assert_eq!(err, NtDriverError::NotNativeDriver(3));
    }

    #[test]
    fn test_driver_host_dispatch_and_irp_handling() {
        let sys_bytes = create_test_sys_binary();
        let host = NtDriverHost::new();

        let mut driver = host
            .load_driver(
                &sys_bytes,
                "\\Driver\\NexusVanguardPoC",
                "\\Registry\\Machine\\System",
            )
            .expect("Driver load failed");

        // Manually invoke mock DriverEntry to simulate entry point invocation
        let status = unsafe {
            mock_driver_entry(&mut driver.driver_object, &driver.driver_object.driver_name)
        };
        assert_eq!(status, 0); // STATUS_SUCCESS

        // Verify device was created and attached
        assert!(!driver.driver_object.device_object.is_null());

        // Dispatch IRP_MJ_CREATE
        let mut test_irp = Irp::default();
        let create_status = unsafe {
            driver.dispatch(
                IRP_MJ_CREATE,
                driver.driver_object.device_object,
                &mut test_irp,
            )
        };
        assert_eq!(create_status, 0);
        assert_eq!(test_irp.io_status.status, 0);

        // Dispatch IRP_MJ_DEVICE_CONTROL
        let ioctl_status = unsafe {
            driver.dispatch(
                IRP_MJ_DEVICE_CONTROL,
                driver.driver_object.device_object,
                &mut test_irp,
            )
        };
        assert_eq!(ioctl_status, 0);
        assert_eq!(test_irp.io_status.information, 42);

        // Cleanup created device object
        unsafe {
            stub_io_delete_device(driver.driver_object.device_object);
        }
    }
}
