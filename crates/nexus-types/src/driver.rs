//! Windows Driver Model (WDM / NT Kernel) Architecture Types.
//!
//! Provides fundamental data structures for loading, initializing, and dispatching
//! Windows NT kernel-mode drivers (`.sys` files) on bare-metal or simulated environments.

extern crate alloc;
use alloc::vec::Vec;
use core::ffi::c_void;

/// Major function dispatch indices in Windows NT (`IRP_MJ_*`).
pub const IRP_MJ_CREATE: usize = 0x00;
pub const IRP_MJ_CREATE_NAMED_PIPE: usize = 0x01;
pub const IRP_MJ_CLOSE: usize = 0x02;
pub const IRP_MJ_READ: usize = 0x03;
pub const IRP_MJ_WRITE: usize = 0x04;
pub const IRP_MJ_QUERY_INFORMATION: usize = 0x05;
pub const IRP_MJ_SET_INFORMATION: usize = 0x06;
pub const IRP_MJ_FLUSH_BUFFERS: usize = 0x09;
pub const IRP_MJ_QUERY_VOLUME_INFORMATION: usize = 0x0A;
pub const IRP_MJ_DIRECTORY_CONTROL: usize = 0x0C;
pub const IRP_MJ_DEVICE_CONTROL: usize = 0x0E;
pub const IRP_MJ_INTERNAL_DEVICE_CONTROL: usize = 0x0F;
pub const IRP_MJ_SHUTDOWN: usize = 0x10;
pub const IRP_MJ_CLEANUP: usize = 0x12;
pub const IRP_MJ_POWER: usize = 0x16;
pub const IRP_MJ_SYSTEM_CONTROL: usize = 0x17;
pub const IRP_MJ_DEVICE_CHANGE: usize = 0x18;
pub const IRP_MJ_PNP: usize = 0x1B;
pub const IRP_MJ_MAXIMUM_FUNCTION: usize = 0x1B;

/// Standard NT Driver Subsystem identifier in PE headers (`IMAGE_SUBSYSTEM_NATIVE`).
pub const IMAGE_SUBSYSTEM_NATIVE: u16 = 1;

/// Unicode String structure used across the Windows NT Kernel (`UNICODE_STRING`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnicodeString {
    /// Length of the string in bytes (not characters), excluding null terminator.
    pub length: u16,
    /// Maximum allocated length in bytes.
    pub maximum_length: u16,
    pub _padding: u32,
    /// Pointer to UTF-16 code units.
    pub buffer: *mut u16,
}

impl Default for UnicodeString {
    fn default() -> Self {
        Self {
            length: 0,
            maximum_length: 0,
            _padding: 0,
            buffer: core::ptr::null_mut(),
        }
    }
}

impl UnicodeString {
    pub const fn empty() -> Self {
        Self {
            length: 0,
            maximum_length: 0,
            _padding: 0,
            buffer: core::ptr::null_mut(),
        }
    }

    /// Converts a Rust string slice into a standalone heap-allocated `UnicodeString` and vector backing.
    pub fn from_str_vec(s: &str) -> (Self, Vec<u16>) {
        let mut u16_chars: Vec<u16> = s.encode_utf16().collect();
        u16_chars.push(0); // Null terminator
        let byte_len = ((u16_chars.len() - 1) * 2) as u16;
        let max_len = (u16_chars.len() * 2) as u16;
        let ptr = u16_chars.as_mut_ptr();

        let ustr = Self {
            length: byte_len,
            maximum_length: max_len,
            _padding: 0,
            buffer: ptr,
        };

        (ustr, u16_chars)
    }
}

/// NT Driver Dispatch routine function pointer signature.
pub type DriverDispatchFn =
    unsafe extern "win64" fn(device: *mut DeviceObject, irp: *mut Irp) -> i32;

/// NT Driver Unload routine function pointer signature.
pub type DriverUnloadFn = unsafe extern "win64" fn(driver: *mut DriverObject);

/// NT Driver Entry point function pointer signature (`DriverEntry`).
pub type DriverEntryFn =
    unsafe extern "win64" fn(driver: *mut DriverObject, registry_path: *const UnicodeString) -> i32;

/// Windows NT Kernel Driver Object (`DRIVER_OBJECT`).
#[repr(C)]
#[derive(Debug)]
pub struct DriverObject {
    pub type_: i16,
    pub size: i16,
    pub _padding0: u32,
    pub device_object: *mut DeviceObject,
    pub flags: u32,
    pub _padding1: u32,
    pub driver_start: *mut c_void,
    pub driver_size: u32,
    pub _padding2: u32,
    pub driver_section: *mut c_void,
    pub driver_extension: *mut c_void,
    pub driver_name: UnicodeString,
    pub hardware_database: *mut UnicodeString,
    pub fast_io_dispatch: *mut c_void,
    pub driver_init: *mut c_void,
    pub driver_start_io: *mut c_void,
    pub driver_unload: Option<DriverUnloadFn>,
    /// Array of major function dispatch routines (`IRP_MJ_CREATE` .. `IRP_MJ_PNP`).
    pub major_function: [Option<DriverDispatchFn>; IRP_MJ_MAXIMUM_FUNCTION + 1],
}

impl Default for DriverObject {
    fn default() -> Self {
        Self {
            type_: 4, // IO_TYPE_DRIVER
            size: core::mem::size_of::<Self>() as i16,
            _padding0: 0,
            device_object: core::ptr::null_mut(),
            flags: 0,
            _padding1: 0,
            driver_start: core::ptr::null_mut(),
            driver_size: 0,
            _padding2: 0,
            driver_section: core::ptr::null_mut(),
            driver_extension: core::ptr::null_mut(),
            driver_name: UnicodeString::empty(),
            hardware_database: core::ptr::null_mut(),
            fast_io_dispatch: core::ptr::null_mut(),
            driver_init: core::ptr::null_mut(),
            driver_start_io: core::ptr::null_mut(),
            driver_unload: None,
            major_function: [None; IRP_MJ_MAXIMUM_FUNCTION + 1],
        }
    }
}

/// Windows NT Kernel Device Object (`DEVICE_OBJECT`).
#[repr(C)]
#[derive(Debug)]
pub struct DeviceObject {
    pub type_: i16,
    pub size: u16,
    pub reference_count: i32,
    pub driver_object: *mut DriverObject,
    pub next_device: *mut DeviceObject,
    pub attached_device: *mut DeviceObject,
    pub current_irp: *mut Irp,
    pub flags: u32,
    pub characteristics: u32,
    pub device_extension: *mut c_void,
    pub device_type: u32,
    pub stack_size: i8,
    pub _padding: [u8; 7],
}

impl Default for DeviceObject {
    fn default() -> Self {
        Self {
            type_: 3, // IO_TYPE_DEVICE
            size: core::mem::size_of::<Self>() as u16,
            reference_count: 1,
            driver_object: core::ptr::null_mut(),
            next_device: core::ptr::null_mut(),
            attached_device: core::ptr::null_mut(),
            current_irp: core::ptr::null_mut(),
            flags: 0,
            characteristics: 0,
            device_extension: core::ptr::null_mut(),
            device_type: 0,
            stack_size: 1,
            _padding: [0; 7],
        }
    }
}

/// I/O Status Block (`IO_STATUS_BLOCK`).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IoStatusBlock {
    pub status: i32,
    pub _padding: u32,
    pub information: usize,
}

/// Windows NT I/O Stack Location (`IO_STACK_LOCATION`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IoStackLocation {
    pub major_function: u8,
    pub minor_function: u8,
    pub flags: u8,
    pub control: u8,
    pub _padding: u32,
    pub parameters: [u64; 4],
    pub device_object: *mut DeviceObject,
    pub file_object: *mut c_void,
    pub completion_routine: *mut c_void,
    pub context: *mut c_void,
}

impl Default for IoStackLocation {
    fn default() -> Self {
        Self {
            major_function: 0,
            minor_function: 0,
            flags: 0,
            control: 0,
            _padding: 0,
            parameters: [0; 4],
            device_object: core::ptr::null_mut(),
            file_object: core::ptr::null_mut(),
            completion_routine: core::ptr::null_mut(),
            context: core::ptr::null_mut(),
        }
    }
}

/// Windows NT I/O Request Packet (`IRP`).
#[repr(C)]
#[derive(Debug)]
pub struct Irp {
    pub type_: i16,
    pub size: u16,
    pub _padding0: u32,
    pub mdl_address: *mut c_void,
    pub flags: u32,
    pub _padding1: u32,
    pub associated_irp: *mut c_void,
    pub io_status: IoStatusBlock,
    pub requestor_mode: i8,
    pub pending_returned: u8,
    pub stack_count: i8,
    pub current_location: i8,
    pub _padding2: u32,
    pub user_buffer: *mut c_void,
    pub current_stack_location: *mut IoStackLocation,
}

impl Default for Irp {
    fn default() -> Self {
        Self {
            type_: 6, // IO_TYPE_IRP
            size: core::mem::size_of::<Self>() as u16,
            _padding0: 0,
            mdl_address: core::ptr::null_mut(),
            flags: 0,
            _padding1: 0,
            associated_irp: core::ptr::null_mut(),
            io_status: IoStatusBlock::default(),
            requestor_mode: 0, // KernelMode = 0
            pending_returned: 0,
            stack_count: 1,
            current_location: 1,
            _padding2: 0,
            user_buffer: core::ptr::null_mut(),
            current_stack_location: core::ptr::null_mut(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_driver_object_sizes_and_alignments() {
        assert_eq!(core::mem::size_of::<UnicodeString>(), 16);
        assert_eq!(core::mem::size_of::<IoStatusBlock>(), 16);
        let drv = DriverObject::default();
        assert_eq!(drv.type_, 4);
        assert_eq!(drv.major_function.len(), 28);
    }

    #[test]
    fn test_unicode_string_conversion() {
        let (ustr, _backing) = UnicodeString::from_str_vec("\\Driver\\NexusTest");
        assert_eq!(ustr.length, 34); // 17 UTF-16 code units * 2 bytes
        assert_eq!(ustr.maximum_length, 36); // Including null terminator
        assert!(!ustr.buffer.is_null());
    }
}
