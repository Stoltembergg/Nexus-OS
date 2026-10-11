//! Minimal freestanding UEFI 2.x protocol structures and definitions.

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EfiStatus(pub usize);

impl EfiStatus {
    pub const SUCCESS: Self = Self(0);
    pub const BUFFER_TOO_SMALL: Self = Self(0x8000000000000005);
    pub const NOT_FOUND: Self = Self(0x800000000000000E);
    pub const INVALID_PARAMETER: Self = Self(0x8000000000000002);

    pub fn is_success(&self) -> bool {
        self.0 == 0
    }
}

pub type EfiHandle = *mut core::ffi::c_void;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EfiGuid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl EfiGuid {
    pub const ACPI_10_GUID: Self = Self::new(
        0xeb9d2d30,
        0x2d88,
        0x11d3,
        [0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d],
    );
    pub const ACPI_20_GUID: Self = Self::new(
        0x8868e871,
        0xe4f1,
        0x11d3,
        [0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81],
    );
    pub const LOADED_IMAGE_GUID: Self = Self::new(
        0x5b1b31a1,
        0x9562,
        0x11d2,
        [0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
    );
    pub const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        Self {
            data1,
            data2,
            data3,
            data4,
        }
    }

    /// EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID
    /// 9042a9de-23dc-4a38-96fb-7aded080516a
    pub const GOP_GUID: Self = Self::new(
        0x9042a9de,
        0x23dc,
        0x4a38,
        [0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a],
    );
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EfiConfigurationTable {
    pub vendor_guid: EfiGuid,
    pub vendor_table: *const core::ffi::c_void,
}

#[repr(C)]
pub struct EfiTableHeader {
    pub signature: u64,
    pub revision: u32,
    pub header_size: u32,
    pub crc32: u32,
    pub reserved: u32,
}

#[repr(C)]
pub struct EfiSimpleTextOutputProtocol {
    pub reset: usize,
    pub output_string:
        unsafe extern "win64" fn(*mut EfiSimpleTextOutputProtocol, *const u16) -> EfiStatus,
    pub test_string: usize,
    pub query_mode: usize,
    pub set_mode: usize,
    pub set_attribute: usize,
    pub clear_screen: unsafe extern "win64" fn(*mut EfiSimpleTextOutputProtocol) -> EfiStatus,
    pub set_cursor_position: usize,
    pub enable_cursor: usize,
    pub mode: usize,
}

#[repr(C)]
pub struct EfiSystemTable {
    pub hdr: EfiTableHeader,
    pub firmware_vendor: *const u16,
    pub firmware_revision: u32,
    pub console_in_handle: EfiHandle,
    pub con_in: usize,
    pub console_out_handle: EfiHandle,
    pub con_out: *mut EfiSimpleTextOutputProtocol,
    pub standard_error_handle: EfiHandle,
    pub std_err: *mut EfiSimpleTextOutputProtocol,
    pub runtime_services: usize,
    pub boot_services: *mut EfiBootServices,
    pub number_of_table_entries: usize,
    pub configuration_table: usize,
}

#[repr(C)]
pub struct EfiBootServices {
    pub hdr: EfiTableHeader,
    pub raise_tpl: usize,
    pub restore_tpl: usize,
    pub allocate_pages: usize,
    pub free_pages: usize,
    pub get_memory_map: unsafe extern "win64" fn(
        memory_map_size: *mut usize,
        memory_map: *mut EfiMemoryDescriptorRaw,
        map_key: *mut usize,
        descriptor_size: *mut usize,
        descriptor_version: *mut u32,
    ) -> EfiStatus,
    pub allocate_pool: usize,
    pub free_pool: usize,
    pub create_event: usize,
    pub set_timer: usize,
    pub wait_for_event: usize,
    pub signal_event: usize,
    pub close_event: usize,
    pub check_event: usize,
    pub install_protocol_interface: usize,
    pub reinstall_protocol_interface: usize,
    pub uninstall_protocol_interface: usize,
    pub handle_protocol: unsafe extern "win64" fn(
        EfiHandle,
        *const EfiGuid,
        *mut *mut core::ffi::c_void,
    ) -> EfiStatus,
    pub void_reserved: usize,
    pub register_protocol_notify: usize,
    pub locate_handle: usize,
    pub locate_device_path: usize,
    pub install_configuration_table: usize,
    pub load_image: usize,
    pub start_image: usize,
    pub exit: usize,
    pub unload_image: usize,
    pub exit_boot_services:
        unsafe extern "win64" fn(image_handle: EfiHandle, map_key: usize) -> EfiStatus,
    pub get_next_monotonic_count: usize,
    pub stall: unsafe extern "win64" fn(microseconds: usize) -> EfiStatus,
    pub set_watchdog_timer: usize,
    pub connect_controller: usize,
    pub disconnect_controller: usize,
    pub open_protocol: usize,
    pub close_protocol: usize,
    pub open_protocol_information: usize,
    pub protocols_per_handle: usize,
    pub locate_handle_buffer: usize,
    pub locate_protocol: unsafe extern "win64" fn(
        protocol: *const EfiGuid,
        registration: *const core::ffi::c_void,
        interface: *mut *mut core::ffi::c_void,
    ) -> EfiStatus,
}

#[repr(C)]
pub struct EfiLoadedImageProtocol {
    pub revision: u32,
    pub parent_handle: EfiHandle,
    pub system_table: *mut EfiSystemTable,
    pub device_handle: EfiHandle,
    pub file_path: *mut core::ffi::c_void,
    pub reserved: *mut core::ffi::c_void,
    pub load_options_size: u32,
    pub load_options: *mut core::ffi::c_void,
    pub image_base: *mut core::ffi::c_void,
    pub image_size: u64,
    pub image_code_type: u32,
    pub image_data_type: u32,
    pub unload: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EfiMemoryDescriptorRaw {
    pub mem_type: u32,
    pub pad: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub number_of_pages: u64,
    pub attribute: u64,
}

#[repr(C)]
pub struct EfiPixelBitmask {
    pub red_mask: u32,
    pub green_mask: u32,
    pub blue_mask: u32,
    pub reserved_mask: u32,
}

#[repr(C)]
pub struct EfiGraphicsOutputModeInformation {
    pub version: u32,
    pub horizontal_resolution: u32,
    pub vertical_resolution: u32,
    pub pixel_format: u32,
    pub pixel_information: EfiPixelBitmask,
    pub pixels_per_scan_line: u32,
}

#[repr(C)]
pub struct EfiGraphicsOutputProtocolMode {
    pub max_mode: u32,
    pub mode: u32,
    pub info: *const EfiGraphicsOutputModeInformation,
    pub size_of_info: usize,
    pub frame_buffer_base: u64,
    pub frame_buffer_size: usize,
}

#[repr(C)]
pub struct EfiGraphicsOutputProtocol {
    pub query_mode: usize,
    pub set_mode: usize,
    pub blt: usize,
    pub mode: *const EfiGraphicsOutputProtocolMode,
}
