//! Windows NT Kernel Driver Model (WDM / KMDF) Architectural Structures.
//!
//! Provides fundamental data structures, function pointer signatures, and constants
//! matching the 64-bit Windows NT Kernel driver binary interface.

extern crate alloc;
use alloc::vec::Vec;
use core::ffi::c_void;

/// Standard NT Driver Subsystem identifier in PE headers (`IMAGE_SUBSYSTEM_NATIVE`).
pub const IMAGE_SUBSYSTEM_NATIVE: u16 = 1;

/// NT IRQL Constants
pub type Kirql = u8;
pub const PASSIVE_LEVEL: Kirql = 0;
pub const APC_LEVEL: Kirql = 1;
pub const DISPATCH_LEVEL: Kirql = 2;
/// Highest IRQL on x64 (`wdm.h` defines `HIGH_LEVEL` as 15 on AMD64; 31 is the x86 value).
pub const HIGH_LEVEL: Kirql = 15;

/// Standard NT Status Codes
pub const STATUS_SUCCESS: i32 = 0x0000_0000;
pub const STATUS_INVALID_PARAMETER: i32 = -1073741811; // 0xC000000D
pub const STATUS_NOT_IMPLEMENTED: i32 = -1073741822; // 0xC0000002
pub const STATUS_BUFFER_TOO_SMALL: i32 = -1073741789; // 0xC0000023
pub const STATUS_INSUFFICIENT_RESOURCES: i32 = -1073741801; // 0xC0000017
pub const STATUS_UNSUCCESSFUL: i32 = -1073741823; // 0xC0000001
pub const STATUS_TIMEOUT: i32 = 0x0000_0102;
pub const STATUS_POSSIBLE_DEADLOCK: i32 = 0xC000_0194_u32 as i32;

/// Standard Windows NT Device Control Definition Macro (`CTL_CODE`).
pub const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

pub const FILE_DEVICE_UNKNOWN: u32 = 0x0000_0022;
pub const METHOD_BUFFERED: u32 = 0;
pub const FILE_ANY_ACCESS: u32 = 0;

/// Generic WDM Sample IOCTLs (independent of OS vendor naming).
pub const IOCTL_WDM_SAMPLE_MEM_TEST: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const IOCTL_WDM_SAMPLE_SPINLOCK_IRQL: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const IOCTL_WDM_SAMPLE_EVENT_TEST: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS);

/// Test IOCTL Codes for Nexus Verification
pub const IOCTL_NEXUS_GET_VERSION: u32 = 0x8000_2000;
pub const IOCTL_NEXUS_ECHO: u32 = 0x8000_2004;
pub const IOCTL_NEXUS_RAISE_IRQL_TEST: u32 = 0x8000_2008;

/// NT Memory Pool Types (`POOL_TYPE`).
pub const POOL_TYPE_NON_PAGED: u32 = 0;
pub const POOL_TYPE_PAGED: u32 = 1;
pub const POOL_TYPE_NON_PAGED_NX: u32 = 512;

/// NT Spinlock Type (`KSPIN_LOCK`).
pub type KSpinLock = usize;

/// `DEVICE_OBJECT.Flags`: `DO_EXCLUSIVE`.
pub const DO_EXCLUSIVE: u32 = 0x0000_0008;
/// `DEVICE_OBJECT.Flags`: `DO_BUFFERED_IO`.
pub const DO_BUFFERED_IO: u32 = 0x0000_0004;
/// `DEVICE_OBJECT.Flags`: `DO_DEVICE_INITIALIZING` (set by `IoCreateDevice`).
pub const DO_DEVICE_INITIALIZING: u32 = 0x0000_0080;

/// NT Event Synchronization Object (`KEVENT`).
///
/// x64 layout matches the WDK `KEVENT` / `DISPATCHER_HEADER`: the header
/// bytes (`Type`, `Signalling`, `Size`, `Reserved1`) and `SignalState` come
/// first, followed by `WaitListHead` as a `LIST_ENTRY` (`Flink` at 0x08,
/// `Blink` at 0x10). Verified against the official headers by
/// `scripts/wdk-abi.py`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KEvent {
    pub header_type: u8,
    pub header_signaled: u8,
    pub header_size: u8,
    pub header_reserved: u8,
    pub signal_state: i32,
    pub wait_list_flink: *mut c_void,
    pub wait_list_blink: *mut c_void,
}

impl Default for KEvent {
    fn default() -> Self {
        Self {
            header_type: 0,
            header_signaled: 0,
            // DISPATCHER_HEADER.Size is in LONG (4-byte) units.
            header_size: (core::mem::size_of::<Self>() / 4) as u8,
            header_reserved: 0,
            signal_state: 0,
            wait_list_flink: core::ptr::null_mut(),
            wait_list_blink: core::ptr::null_mut(),
        }
    }
}

/// Driver Section Mapping details for W^X enforcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverSectionMapping {
    pub name: [u8; 8],
    pub rva: u32,
    pub size: u32,
    pub is_executable: bool,
    pub is_writable: bool,
}

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

pub const IRP_MJ_CREATE: usize = 0x00;
pub const IRP_MJ_CREATE_NAMED_PIPE: usize = 0x01;
pub const IRP_MJ_CLOSE: usize = 0x02;
pub const IRP_MJ_READ: usize = 0x03;
pub const IRP_MJ_WRITE: usize = 0x04;
pub const IRP_MJ_QUERY_INFORMATION: usize = 0x05;
pub const IRP_MJ_SET_INFORMATION: usize = 0x06;
pub const IRP_MJ_QUERY_EA: usize = 0x07;
pub const IRP_MJ_SET_EA: usize = 0x08;
pub const IRP_MJ_FLUSH_BUFFERS: usize = 0x09;
pub const IRP_MJ_QUERY_VOLUME_INFORMATION: usize = 0x0a;
pub const IRP_MJ_SET_VOLUME_INFORMATION: usize = 0x0b;
pub const IRP_MJ_DIRECTORY_CONTROL: usize = 0x0c;
pub const IRP_MJ_FILE_SYSTEM_CONTROL: usize = 0x0d;
pub const IRP_MJ_DEVICE_CONTROL: usize = 0x0e;
pub const IRP_MJ_INTERNAL_DEVICE_CONTROL: usize = 0x0f;
pub const IRP_MJ_SHUTDOWN: usize = 0x10;
pub const IRP_MJ_LOCK_CONTROL: usize = 0x11;
pub const IRP_MJ_CLEANUP: usize = 0x12;
pub const IRP_MJ_CREATE_MAILSLOT: usize = 0x13;
pub const IRP_MJ_QUERY_SECURITY: usize = 0x14;
pub const IRP_MJ_SET_SECURITY: usize = 0x15;
pub const IRP_MJ_POWER: usize = 0x16;
pub const IRP_MJ_SYSTEM_CONTROL: usize = 0x17;
pub const IRP_MJ_DEVICE_CHANGE: usize = 0x18;
pub const IRP_MJ_QUERY_QUOTA: usize = 0x19;
pub const IRP_MJ_SET_QUOTA: usize = 0x1a;
pub const IRP_MJ_PNP: usize = 0x1b;
pub const IRP_MJ_MAXIMUM_FUNCTION: usize = 0x1b;

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
///
/// Full x64 WDK layout (`sizeof == 0x150`, 16-byte aligned via
/// `DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT)`). Members Nexus does not
/// implement yet (`Queue`, `DeviceQueue`, `Dpc`, ...) are kept as opaque,
/// zero-initialised byte blocks of the official size so that every offset a
/// driver can touch is the real one.
#[repr(C, align(16))]
#[derive(Debug)]
pub struct DeviceObject {
    pub type_: i16,
    pub size: u16,
    pub reference_count: i32,
    pub driver_object: *mut DriverObject,
    pub next_device: *mut DeviceObject,
    pub attached_device: *mut DeviceObject,
    pub current_irp: *mut Irp,
    pub timer: *mut c_void,
    pub flags: u32,
    pub characteristics: u32,
    pub vpb: *mut c_void,
    pub device_extension: *mut c_void,
    pub device_type: u32,
    pub stack_size: i8,
    pub _pad_stack_size: [u8; 3],
    /// `union { LIST_ENTRY ListEntry; WAIT_CONTEXT_BLOCK Wcb; } Queue`.
    pub queue: [u8; 0x48],
    pub alignment_requirement: u32,
    pub _pad_alignment: u32,
    /// `KDEVICE_QUEUE DeviceQueue`.
    pub device_queue: [u8; 0x28],
    /// `KDPC Dpc`.
    pub dpc: [u8; 0x40],
    pub active_thread_count: u32,
    pub _pad_active_threads: u32,
    pub security_descriptor: *mut c_void,
    pub device_lock: KEvent,
    pub sector_size: u16,
    pub spare1: u16,
    pub _pad_sector: u32,
    pub device_object_extension: *mut c_void,
    pub reserved: *mut c_void,
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
            timer: core::ptr::null_mut(),
            flags: 0,
            characteristics: 0,
            vpb: core::ptr::null_mut(),
            device_extension: core::ptr::null_mut(),
            device_type: 0,
            stack_size: 1,
            _pad_stack_size: [0; 3],
            queue: [0; 0x48],
            alignment_requirement: 0,
            _pad_alignment: 0,
            device_queue: [0; 0x28],
            dpc: [0; 0x40],
            active_thread_count: 0,
            _pad_active_threads: 0,
            security_descriptor: core::ptr::null_mut(),
            device_lock: KEvent::default(),
            sector_size: 0,
            spare1: 0,
            _pad_sector: 0,
            device_object_extension: core::ptr::null_mut(),
            reserved: core::ptr::null_mut(),
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

/// `IO_STACK_LOCATION.Parameters.DeviceIoControl` (x64).
///
/// Every `ULONG` in the WDK parameter structs is `POINTER_ALIGNMENT`, so each
/// occupies a full 8-byte slot. The first slot doubles as
/// `Parameters.Read.Length` / `Parameters.Write.Length` (offset 0x08 of the
/// stack location), exactly as in the official union.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ParametersDeviceIoControl {
    pub output_buffer_length: u32,
    pub _pad0: u32,
    pub input_buffer_length: u32,
    pub _pad1: u32,
    pub io_control_code: u32,
    pub _pad2: u32,
    pub type3_input_buffer: *mut c_void,
}

impl ParametersDeviceIoControl {
    /// `Parameters.DeviceIoControl` for an IOCTL.
    pub fn ioctl(io_control_code: u32, input_len: u32, output_len: u32) -> Self {
        Self {
            output_buffer_length: output_len,
            input_buffer_length: input_len,
            io_control_code,
            ..Self::default()
        }
    }

    /// `Parameters.Read` / `Parameters.Write`: `Length` lives in the first slot.
    pub fn transfer(length: u32) -> Self {
        Self {
            output_buffer_length: length,
            ..Self::default()
        }
    }

    /// `Parameters.Read.Length` / `Parameters.Write.Length`.
    pub fn length(&self) -> u32 {
        self.output_buffer_length
    }
}

impl Default for ParametersDeviceIoControl {
    fn default() -> Self {
        Self {
            output_buffer_length: 0,
            _pad0: 0,
            input_buffer_length: 0,
            _pad1: 0,
            io_control_code: 0,
            _pad2: 0,
            type3_input_buffer: core::ptr::null_mut(),
        }
    }
}

/// Windows NT I/O Stack Location (`IO_STACK_LOCATION`), x64 size 0x48.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoStackLocation {
    pub major_function: u8,
    pub minor_function: u8,
    pub flags: u8,
    pub control: u8,
    pub _padding: u32,
    pub parameters: ParametersDeviceIoControl,
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
            parameters: ParametersDeviceIoControl::default(),
            device_object: core::ptr::null_mut(),
            file_object: core::ptr::null_mut(),
            completion_routine: core::ptr::null_mut(),
            context: core::ptr::null_mut(),
        }
    }
}

/// Windows NT I/O Request Packet (`IRP`), full x64 WDK layout
/// (`sizeof == 0xD0`, 16-byte aligned).
///
/// `associated_irp` is the `AssociatedIrp` union (`SystemBuffer` for
/// `METHOD_BUFFERED` / `DO_BUFFERED_IO`). `current_stack_location` is
/// `Tail.Overlay.CurrentStackLocation` (0xB8), which the WDK inline
/// `IoGetCurrentIrpStackLocation` reads directly.
#[repr(C, align(16))]
#[derive(Debug)]
pub struct Irp {
    pub type_: i16,
    pub size: u16,
    pub _padding0: u32,
    pub mdl_address: *mut c_void,
    pub flags: u32,
    pub _padding1: u32,
    pub associated_irp: *mut c_void,
    pub thread_list_entry: [*mut c_void; 2],
    pub io_status: IoStatusBlock,
    pub requestor_mode: i8,
    pub pending_returned: u8,
    pub stack_count: i8,
    pub current_location: i8,
    pub cancel: u8,
    pub cancel_irql: u8,
    pub apc_environment: i8,
    pub allocation_flags: u8,
    pub user_iosb: *mut IoStatusBlock,
    pub user_event: *mut KEvent,
    /// `Overlay` union (`AsynchronousParameters` / `AllocationSize`).
    pub overlay: [usize; 2],
    pub cancel_routine: *mut c_void,
    pub user_buffer: *mut c_void,
    /// `Tail.Overlay.DriverContext[4]` (aliases `DeviceQueueEntry`).
    pub driver_context: [*mut c_void; 4],
    pub thread: *mut c_void,
    pub auxiliary_buffer: *mut c_void,
    pub list_entry: [*mut c_void; 2],
    pub current_stack_location: *mut IoStackLocation,
    pub original_file_object: *mut c_void,
    /// Remainder of the `Tail` union (sized by `KAPC Apc`, 0x58 bytes).
    pub _tail_pad: [u8; 8],
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
            thread_list_entry: [core::ptr::null_mut(); 2],
            io_status: IoStatusBlock::default(),
            requestor_mode: 0,
            pending_returned: 0,
            stack_count: 1,
            current_location: 1,
            cancel: 0,
            cancel_irql: 0,
            apc_environment: 0,
            allocation_flags: 0,
            user_iosb: core::ptr::null_mut(),
            user_event: core::ptr::null_mut(),
            overlay: [0; 2],
            cancel_routine: core::ptr::null_mut(),
            user_buffer: core::ptr::null_mut(),
            driver_context: [core::ptr::null_mut(); 4],
            thread: core::ptr::null_mut(),
            auxiliary_buffer: core::ptr::null_mut(),
            list_entry: [core::ptr::null_mut(); 2],
            current_stack_location: core::ptr::null_mut(),
            original_file_object: core::ptr::null_mut(),
            _tail_pad: [0; 8],
        }
    }
}

// Compile-time pins of the x64 WDK layout (values from the official
// headers, see docs/14). `scripts/wdk-abi.py --enforce` is the authoritative
// check; these asserts make a drift fail the build on every target.
#[cfg(target_pointer_width = "64")]
const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<KEvent>() == 0x18);
    assert!(offset_of!(KEvent, signal_state) == 0x04);
    assert!(offset_of!(KEvent, wait_list_flink) == 0x08);
    assert!(offset_of!(KEvent, wait_list_blink) == 0x10);
    assert!(size_of::<DeviceObject>() == 0x150);
    assert!(offset_of!(DeviceObject, timer) == 0x28);
    assert!(offset_of!(DeviceObject, flags) == 0x30);
    assert!(offset_of!(DeviceObject, vpb) == 0x38);
    assert!(offset_of!(DeviceObject, device_extension) == 0x40);
    assert!(offset_of!(DeviceObject, device_type) == 0x48);
    assert!(offset_of!(DeviceObject, stack_size) == 0x4c);
    assert!(offset_of!(DeviceObject, alignment_requirement) == 0x98);
    assert!(offset_of!(DeviceObject, device_lock) == 0x118);
    assert!(offset_of!(DeviceObject, device_object_extension) == 0x138);
    assert!(size_of::<IoStackLocation>() == 0x48);
    assert!(offset_of!(IoStackLocation, parameters) == 0x08);
    assert!(offset_of!(IoStackLocation, device_object) == 0x28);
    assert!(offset_of!(IoStackLocation, context) == 0x40);
    assert!(size_of::<Irp>() == 0xd0);
    assert!(offset_of!(Irp, associated_irp) == 0x18);
    assert!(offset_of!(Irp, io_status) == 0x30);
    assert!(offset_of!(Irp, cancel) == 0x44);
    assert!(offset_of!(Irp, user_buffer) == 0x70);
    assert!(offset_of!(Irp, current_stack_location) == 0xb8);
    assert!(offset_of!(Irp, original_file_object) == 0xc0);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_driver_object_sizes_and_alignments() {
        assert_eq!(core::mem::size_of::<UnicodeString>(), 16);
        assert_eq!(core::mem::size_of::<IoStatusBlock>(), 16);
        assert_eq!(core::mem::size_of::<KEvent>(), 24);
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

    #[test]
    fn test_ctl_code_calculation() {
        let code = ctl_code(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);
        assert_eq!(code, 0x00222004);
        assert_eq!(IOCTL_WDM_SAMPLE_MEM_TEST, code);
    }
}
