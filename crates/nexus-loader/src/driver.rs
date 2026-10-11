//! Windows NT Kernel Driver (`.sys`) Loader & WDM Host Subsystem.
//!
//! Provides parsing, section mapping, relocation processing, dynamic kernel export binding,
//! native `DriverEntry` execution, IRP dispatching, and safe driver unloading for
//! Windows NT kernel-mode drivers (`IMAGE_SUBSYSTEM_NATIVE`).

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use byteorder::{ByteOrder, LittleEndian};
use core::ffi::c_void;
use core::sync::atomic::{AtomicU8, Ordering};
use nexus_types::driver::{
    DeviceObject, DriverEntryFn, DriverObject, Irp, Kirql, UnicodeString, IMAGE_SUBSYSTEM_NATIVE,
    IRP_MJ_MAXIMUM_FUNCTION, PASSIVE_LEVEL, STATUS_INVALID_PARAMETER, STATUS_NOT_IMPLEMENTED,
    STATUS_SUCCESS,
};

use crate::error::LoaderError;
use crate::pe::{PeImage, IMAGE_REL_BASED_DIR64};

/// Global IRQL tracking register for the NT host executive.
pub static CURRENT_IRQL: AtomicU8 = AtomicU8::new(PASSIVE_LEVEL);

/// Errors encountered while loading, binding, and executing an NT kernel driver.
#[derive(Debug, PartialEq, Eq)]
pub enum NtDriverError {
    Loader(LoaderError),
    InvalidImageFormat,
    NotNativeDriver(u16),
    NoEntryPoint,
    RelocationFailed,
    UnresolvedImport { dll: String, function: String },
    MemoryAllocationFailed,
    DriverEntryFailed(i32),
    NoUnloadRoutine,
}

impl From<LoaderError> for NtDriverError {
    fn from(err: LoaderError) -> Self {
        Self::Loader(err)
    }
}

/// Buffer for executable kernel driver memory.
pub struct ExecutableBuffer {
    ptr: *mut u8,
    size: usize,
}

unsafe impl Send for ExecutableBuffer {}
unsafe impl Sync for ExecutableBuffer {}

impl core::fmt::Debug for ExecutableBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExecutableBuffer")
            .field("ptr", &self.ptr)
            .field("size", &self.size)
            .finish()
    }
}

#[cfg(windows)]
impl ExecutableBuffer {
    pub fn allocate(size: usize) -> Result<Self, NtDriverError> {
        #[link(name = "kernel32")]
        extern "system" {
            fn VirtualAlloc(
                lpAddress: *mut c_void,
                dwSize: usize,
                flAllocationType: u32,
                flProtect: u32,
            ) -> *mut c_void;
        }

        const MEM_COMMIT: u32 = 0x1000;
        const MEM_RESERVE: u32 = 0x2000;
        const PAGE_EXECUTE_READWRITE: u32 = 0x40;

        let ptr = unsafe {
            VirtualAlloc(
                core::ptr::null_mut(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };

        if ptr.is_null() {
            return Err(NtDriverError::MemoryAllocationFailed);
        }

        Ok(Self {
            ptr: ptr as *mut u8,
            size,
        })
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.size) }
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.ptr
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

#[cfg(windows)]
impl Drop for ExecutableBuffer {
    fn drop(&mut self) {
        #[link(name = "kernel32")]
        extern "system" {
            fn VirtualFree(lpAddress: *mut c_void, dwSize: usize, dwFreeType: u32) -> i32;
        }
        const MEM_RELEASE: u32 = 0x8000;
        if !self.ptr.is_null() {
            unsafe {
                VirtualFree(self.ptr as *mut c_void, 0, MEM_RELEASE);
            }
        }
    }
}

#[cfg(unix)]
impl ExecutableBuffer {
    pub fn allocate(size: usize) -> Result<Self, NtDriverError> {
        extern "C" {
            fn mmap(
                addr: *mut c_void,
                len: usize,
                prot: i32,
                flags: i32,
                fd: i32,
                offset: i64,
            ) -> *mut c_void;
        }

        const PROT_READ: i32 = 1;
        const PROT_WRITE: i32 = 2;
        const PROT_EXEC: i32 = 4;
        const MAP_PRIVATE: i32 = 2;
        const MAP_ANONYMOUS: i32 = 0x20;

        let ptr = unsafe {
            mmap(
                core::ptr::null_mut(),
                size,
                PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if ptr == (usize::MAX as *mut c_void) || ptr.is_null() {
            return Err(NtDriverError::MemoryAllocationFailed);
        }

        Ok(Self {
            ptr: ptr as *mut u8,
            size,
        })
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.size) }
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.ptr
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

#[cfg(unix)]
impl Drop for ExecutableBuffer {
    fn drop(&mut self) {
        extern "C" {
            fn munmap(addr: *mut c_void, len: usize) -> i32;
        }
        if !self.ptr.is_null() {
            unsafe {
                munmap(self.ptr as *mut c_void, self.size);
            }
        }
    }
}

#[cfg(not(any(windows, unix)))]
impl ExecutableBuffer {
    pub fn allocate(size: usize) -> Result<Self, NtDriverError> {
        let layout = alloc::alloc::Layout::from_size_align(size, 4096)
            .map_err(|_| NtDriverError::MemoryAllocationFailed)?;
        let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
        if ptr.is_null() {
            return Err(NtDriverError::MemoryAllocationFailed);
        }
        Ok(Self { ptr, size })
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.size) }
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.ptr
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

#[cfg(not(any(windows, unix)))]
impl Drop for ExecutableBuffer {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            let layout = alloc::alloc::Layout::from_size_align(self.size, 4096).unwrap();
            unsafe { alloc::alloc::dealloc(self.ptr, layout) };
        }
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
            "IoDeleteSymbolicLink",
            stub_io_delete_symbolic_link as *const () as usize,
        );
        table.register(
            "NTOSKRNL.EXE",
            "IoCompleteRequest",
            stub_io_complete_request as *const () as usize,
        );
        table.register(
            "NTOSKRNL.EXE",
            "KeGetCurrentIrql",
            stub_ke_get_current_irql as *const () as usize,
        );
        table.register(
            "NTOSKRNL.EXE",
            "KeRaiseIrql",
            stub_ke_raise_irql as *const () as usize,
        );
        table.register(
            "NTOSKRNL.EXE",
            "KeLowerIrql",
            stub_ke_lower_irql as *const () as usize,
        );
        table.register(
            "NTOSKRNL.EXE",
            "RtlInitUnicodeString",
            stub_rtl_init_unicode_string as *const () as usize,
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
    pub buffer: ExecutableBuffer,
}

impl LoadedDriver {
    /// Calls the driver's native `DriverEntry` routine.
    ///
    /// # Safety
    ///
    /// Executes native kernel-mode code at the driver's entry point.
    pub unsafe fn init(&mut self, registry_path: *const UnicodeString) -> i32 {
        let entry_fn: DriverEntryFn = core::mem::transmute(self.entry_point as *const ());
        entry_fn(&mut self.driver_object, registry_path)
    }

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
            return STATUS_NOT_IMPLEMENTED;
        }

        if let Some(dispatch_fn) = self.driver_object.major_function[major_function] {
            dispatch_fn(device, irp)
        } else {
            STATUS_NOT_IMPLEMENTED
        }
    }

    /// Calls the driver's registered `DriverUnload` routine.
    ///
    /// # Safety
    ///
    /// Executes the driver's unload routine and frees associated devices.
    pub unsafe fn unload(&mut self) -> Result<(), NtDriverError> {
        if let Some(unload_fn) = self.driver_object.driver_unload {
            unload_fn(&mut self.driver_object);
            Ok(())
        } else {
            Err(NtDriverError::NoUnloadRoutine)
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
        _registry_path: &str,
    ) -> Result<LoadedDriver, NtDriverError> {
        // 1. Parse PE Image and verify subsystem
        let pe = PeImage::parse(sys_bytes)?;

        if pe.subsystem != IMAGE_SUBSYSTEM_NATIVE {
            return Err(NtDriverError::NotNativeDriver(pe.subsystem));
        }

        if pe.entry_point_rva == 0 {
            return Err(NtDriverError::NoEntryPoint);
        }

        // 2. Allocate executable memory buffer for headers and sections
        let image_size = pe.size_of_image as usize;
        let mut buffer = ExecutableBuffer::allocate(image_size)?;

        // Map PE Headers
        let header_copy_len = (pe.size_of_headers as usize).min(sys_bytes.len());
        buffer.as_mut_slice()[..header_copy_len].copy_from_slice(&sys_bytes[..header_copy_len]);

        // Map Sections
        for sec in &pe.sections {
            let va_start = sec.virtual_address as usize;
            let raw_start = sec.pointer_to_raw_data as usize;
            let raw_size = (sec.size_of_raw_data as usize).min(sec.virtual_size as usize);

            if raw_start + raw_size <= sys_bytes.len() && va_start + raw_size <= buffer.len() {
                buffer.as_mut_slice()[va_start..va_start + raw_size]
                    .copy_from_slice(&sys_bytes[raw_start..raw_start + raw_size]);
            }
        }

        // 3. Process Base Relocations
        let actual_base = buffer.as_ptr() as u64;
        let preferred_base = pe.image_base;
        let delta = actual_base.wrapping_sub(preferred_base);

        if delta != 0 {
            let reloc_blocks = pe.parse_relocations(sys_bytes).unwrap_or_default();
            for block in reloc_blocks {
                for entry in block.entries {
                    if entry.rel_type == IMAGE_REL_BASED_DIR64 {
                        let target_rva = (block.page_rva + entry.offset as u32) as usize;
                        if target_rva + 8 <= buffer.len() {
                            let curr_val = LittleEndian::read_u64(
                                &buffer.as_mut_slice()[target_rva..target_rva + 8],
                            );
                            let patched = curr_val.wrapping_add(delta);
                            LittleEndian::write_u64(
                                &mut buffer.as_mut_slice()[target_rva..target_rva + 8],
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
                if iat_offset + 8 <= buffer.len() {
                    LittleEndian::write_u64(
                        &mut buffer.as_mut_slice()[iat_offset..iat_offset + 8],
                        resolved_addr as u64,
                    );
                }
            }
        }

        // 5. Initialize DRIVER_OBJECT
        let mut driver_obj = DriverObject::default();
        let (driver_name_ustr, _name_backing) = UnicodeString::from_str_vec(driver_name);

        driver_obj.driver_name = driver_name_ustr;
        driver_obj.driver_start = buffer.as_mut_ptr() as *mut c_void;
        driver_obj.driver_size = image_size as u32;

        let entry_va = actual_base + pe.entry_point_rva as u64;

        Ok(LoadedDriver {
            name: driver_name.to_string(),
            image_base: actual_base,
            entry_point: entry_va,
            driver_object: driver_obj,
            buffer,
        })
    }
}

// ---------------------------------------------------------------------------
// Standard WDM Kernel Function Stubs
// ---------------------------------------------------------------------------

/// WDM DbgPrint export stub.
///
/// # Safety
///
/// `format_ptr` must point to a valid null-terminated ASCII/UTF-8 format string if non-null.
pub unsafe extern "win64" fn stub_dbg_print(_format_ptr: *const u8) -> i32 {
    STATUS_SUCCESS
}

/// WDM KeGetCurrentIrql export stub.
///
/// # Safety
///
/// Safe to call in any context; reads atomic IRQL status.
pub unsafe extern "win64" fn stub_ke_get_current_irql() -> Kirql {
    CURRENT_IRQL.load(Ordering::SeqCst)
}

/// WDM KeRaiseIrql export stub.
///
/// # Safety
///
/// If `old_irql` is non-null, it must be writable for a single byte.
pub unsafe extern "win64" fn stub_ke_raise_irql(new_irql: Kirql, old_irql: *mut Kirql) {
    let prev = CURRENT_IRQL.swap(new_irql, Ordering::SeqCst);
    if !old_irql.is_null() {
        *old_irql = prev;
    }
}

/// WDM KeLowerIrql export stub.
///
/// # Safety
///
/// Restores previously recorded hardware or software IRQL.
pub unsafe extern "win64" fn stub_ke_lower_irql(new_irql: Kirql) {
    CURRENT_IRQL.store(new_irql, Ordering::SeqCst);
}

/// WDM RtlInitUnicodeString export stub.
///
/// # Safety
///
/// `dest` must point to valid writable `UnicodeString` memory. `source` if non-null
/// must point to a valid null-terminated UTF-16 buffer.
pub unsafe extern "win64" fn stub_rtl_init_unicode_string(
    dest: *mut UnicodeString,
    source: *const u16,
) {
    if dest.is_null() {
        return;
    }
    if source.is_null() {
        (*dest).length = 0;
        (*dest).maximum_length = 0;
        (*dest).buffer = core::ptr::null_mut();
        return;
    }
    let mut len = 0usize;
    while *source.add(len) != 0 {
        len += 1;
    }
    (*dest).length = (len * 2) as u16;
    (*dest).maximum_length = ((len + 1) * 2) as u16;
    (*dest).buffer = source as *mut u16;
}

/// WDM IoCreateDevice export stub.
///
/// # Safety
///
/// `driver_object` must point to a valid `DriverObject`. `device_object` must point
/// to writable pointer storage.
pub unsafe extern "win64" fn stub_io_create_device(
    driver_object: *mut DriverObject,
    _device_extension_size: u32,
    _device_name: *mut UnicodeString,
    device_type: u32,
    characteristics: u32,
    _exclusive: u8,
    device_object: *mut *mut DeviceObject,
) -> i32 {
    if driver_object.is_null() || device_object.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let dev = alloc::boxed::Box::into_raw(alloc::boxed::Box::new(DeviceObject {
        driver_object,
        device_type,
        characteristics,
        ..Default::default()
    }));

    if (*driver_object).device_object.is_null() {
        (*driver_object).device_object = dev;
    } else {
        let mut cur = (*driver_object).device_object;
        while !(*cur).next_device.is_null() {
            cur = (*cur).next_device;
        }
        (*cur).next_device = dev;
    }

    *device_object = dev;
    STATUS_SUCCESS
}

/// WDM IoDeleteDevice export stub.
///
/// # Safety
///
/// `device_object` must point to an active `DeviceObject` allocated via `IoCreateDevice`.
pub unsafe extern "win64" fn stub_io_delete_device(device_object: *mut DeviceObject) {
    if !device_object.is_null() {
        let drv = (*device_object).driver_object;
        if !drv.is_null() && (*drv).device_object == device_object {
            (*drv).device_object = (*device_object).next_device;
        }
        let _ = alloc::boxed::Box::from_raw(device_object);
    }
}

/// WDM IoCreateSymbolicLink export stub.
///
/// # Safety
///
/// Parameters must point to valid UnicodeString structures.
pub unsafe extern "win64" fn stub_io_create_symbolic_link(
    _symbolic_link_name: *mut UnicodeString,
    _device_name: *mut UnicodeString,
) -> i32 {
    STATUS_SUCCESS
}

/// WDM IoDeleteSymbolicLink export stub.
///
/// # Safety
///
/// Parameter must point to valid UnicodeString structure.
pub unsafe extern "win64" fn stub_io_delete_symbolic_link(
    _symbolic_link_name: *mut UnicodeString,
) -> i32 {
    STATUS_SUCCESS
}

/// WDM IoCompleteRequest export stub.
///
/// # Safety
///
/// `irp` must point to an active `Irp` instance being processed by a driver.
pub unsafe extern "win64" fn stub_io_complete_request(irp: *mut Irp, _priority_boost: i8) {
    if !irp.is_null() {
        (*irp).pending_returned = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_types::driver::{
        IoStackLocation, ParametersDeviceIoControl, IOCTL_NEXUS_ECHO, IOCTL_NEXUS_GET_VERSION,
        IOCTL_NEXUS_RAISE_IRQL_TEST, IRP_MJ_CREATE, IRP_MJ_DEVICE_CONTROL, IRP_MJ_READ,
    };

    const REAL_DRIVER_BYTES: &[u8] =
        include_bytes!("../../../tests/fixtures/nt_driver/nexus_driver.sys");

    #[test]
    fn test_driver_loader_validates_native_subsystem() {
        let host = NtDriverHost::new();

        // 1. Verify real native driver loads successfully
        let driver = host
            .load_driver(REAL_DRIVER_BYTES, "\\Driver\\NexusTest", "\\Registry\\Test")
            .expect("Failed to load native driver");
        assert_eq!(driver.name, "\\Driver\\NexusTest");
        assert_eq!(driver.driver_object.type_, 4);

        // 2. Corrupt subsystem to 3 (Windows CUI / console) and verify rejection
        let mut bad_bytes = REAL_DRIVER_BYTES.to_vec();
        let pe_off = LittleEndian::read_u32(&bad_bytes[60..64]) as usize;
        let opt_off = pe_off + 24;
        LittleEndian::write_u16(&mut bad_bytes[opt_off + 68..opt_off + 70], 3);

        let err = host
            .load_driver(&bad_bytes, "\\Driver\\BadDriver", "\\Registry\\Test")
            .unwrap_err();
        assert_eq!(err, NtDriverError::NotNativeDriver(3));
    }

    #[test]
    fn test_real_nt_driver_execution_ring0_lifecycle() {
        let host = NtDriverHost::new();

        // Reset IRQL state
        CURRENT_IRQL.store(PASSIVE_LEVEL, Ordering::SeqCst);

        // 1. Load real MSVC-compiled WDM driver
        let mut driver = host
            .load_driver(
                REAL_DRIVER_BYTES,
                "\\Driver\\NexusRealDriver",
                "\\Registry\\Machine\\System",
            )
            .expect("Real driver load failed");

        // 2. Call native DriverEntry in executable memory
        let (reg_ustr, _reg_backing) = UnicodeString::from_str_vec(
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\NexusDrv0",
        );
        let init_status = unsafe { driver.init(&reg_ustr) };
        assert_eq!(
            init_status, STATUS_SUCCESS,
            "DriverEntry must succeed with 0"
        );

        // 3. Verify device object was dynamically created by DriverEntry
        let dev_ptr = driver.driver_object.device_object;
        assert!(
            !dev_ptr.is_null(),
            "DriverEntry must have created DeviceObject"
        );

        // 4. Test IRP_MJ_CREATE dispatching
        let mut create_irp = Irp::default();
        let create_status = unsafe { driver.dispatch(IRP_MJ_CREATE, dev_ptr, &mut create_irp) };
        assert_eq!(create_status, STATUS_SUCCESS);
        assert_eq!(create_irp.io_status.status, STATUS_SUCCESS);

        // 5. Test IRP_MJ_DEVICE_CONTROL: IOCTL_NEXUS_GET_VERSION
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

        let status = unsafe { driver.dispatch(IRP_MJ_DEVICE_CONTROL, dev_ptr, &mut ioctl_irp_ver) };
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(ioctl_irp_ver.io_status.status, STATUS_SUCCESS);
        assert_eq!(ioctl_irp_ver.io_status.information, 4);
        assert_eq!(ver_output, 0x00030600, "Must return Phase 3.6 version tag");

        // 6. Test IRP_MJ_DEVICE_CONTROL: IOCTL_NEXUS_ECHO (Case Transformation)
        let mut text_buf = *b"Hello Nexus OS Kernel!\0";
        let mut stack_echo = IoStackLocation {
            major_function: IRP_MJ_DEVICE_CONTROL as u8,
            parameters: ParametersDeviceIoControl {
                output_buffer_length: 22,
                input_buffer_length: 22,
                io_control_code: IOCTL_NEXUS_ECHO,
                _padding: 0,
                type3_input_buffer: core::ptr::null_mut(),
            },
            ..Default::default()
        };

        let mut ioctl_irp_echo = Irp {
            user_buffer: text_buf.as_mut_ptr() as *mut c_void,
            current_stack_location: &mut stack_echo,
            ..Default::default()
        };

        let status =
            unsafe { driver.dispatch(IRP_MJ_DEVICE_CONTROL, dev_ptr, &mut ioctl_irp_echo) };
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(ioctl_irp_echo.io_status.information, 22);
        assert_eq!(&text_buf[..22], b"hELLO nEXUS os kERNEL!");

        // 7. Test IRP_MJ_DEVICE_CONTROL: IOCTL_NEXUS_RAISE_IRQL_TEST
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

        let status =
            unsafe { driver.dispatch(IRP_MJ_DEVICE_CONTROL, dev_ptr, &mut ioctl_irp_irql) };
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(ioctl_irp_irql.io_status.status, STATUS_SUCCESS);
        assert_eq!(
            irql_test_result, 0x1337C0DE,
            "IRQL raise/lower test must succeed"
        );
        assert_eq!(CURRENT_IRQL.load(Ordering::SeqCst), PASSIVE_LEVEL);

        // 8. Test IRP_MJ_READ
        let mut read_buf = [0u8; 32];
        let mut read_irp = Irp {
            user_buffer: read_buf.as_mut_ptr() as *mut c_void,
            ..Default::default()
        };

        let read_status = unsafe { driver.dispatch(IRP_MJ_READ, dev_ptr, &mut read_irp) };
        assert_eq!(read_status, STATUS_SUCCESS);
        assert_eq!(read_irp.io_status.information, 25);
        assert_eq!(&read_buf[..25], b"NEXUS_OS_WDM_READ_SUCCESS");

        // 9. Test safe driver unload
        unsafe {
            driver.unload().expect("Driver unload must succeed");
        }
        assert!(
            driver.driver_object.device_object.is_null(),
            "Device object must be destroyed on unload"
        );
    }
}
