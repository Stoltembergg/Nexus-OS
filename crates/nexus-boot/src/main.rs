#![no_main]

#[cfg(target_os = "uefi")]
use nexus_boot::proto::*;
#[cfg(target_os = "uefi")]
use nexus_types::{BootHandoverInfo, FramebufferInfo, PhysicalAddress};

#[cfg(target_os = "uefi")]
#[no_mangle]
/// # Safety
/// Firmware must pass valid live UEFI system-table and image handles.
pub unsafe extern "win64" fn efi_main(
    image_handle: EfiHandle,
    system_table: *mut EfiSystemTable,
) -> EfiStatus {
    unsafe {
        if system_table.is_null() {
            return EfiStatus::NOT_FOUND;
        }

        let st = &*system_table;
        if st.boot_services.is_null() {
            return EfiStatus::NOT_FOUND;
        }
        let bs = &*st.boot_services;

        // 1. Clear screen & print greeting
        if !st.con_out.is_null() {
            let con_out = &*st.con_out;
            (con_out.clear_screen)(st.con_out);

            // UTF-16 "Nexus OS UEFI Bootloader v0.1.0\r\n\0"
            let msg: [u16; 34] = [
                b'N' as u16,
                b'e' as u16,
                b'x' as u16,
                b'u' as u16,
                b's' as u16,
                b' ' as u16,
                b'O' as u16,
                b'S' as u16,
                b' ' as u16,
                b'U' as u16,
                b'E' as u16,
                b'F' as u16,
                b'I' as u16,
                b' ' as u16,
                b'B' as u16,
                b'o' as u16,
                b'o' as u16,
                b't' as u16,
                b'l' as u16,
                b'o' as u16,
                b'a' as u16,
                b'd' as u16,
                b'e' as u16,
                b'r' as u16,
                b' ' as u16,
                b'v' as u16,
                b'0' as u16,
                b'.' as u16,
                b'1' as u16,
                b'.' as u16,
                b'0' as u16,
                b'\r' as u16,
                b'\n' as u16,
                0,
            ];
            (con_out.output_string)(st.con_out, msg.as_ptr());
        }

        // 2. Query GOP (Graphics Output Protocol)
        let mut gop_ptr: *mut core::ffi::c_void = core::ptr::null_mut();
        let status = (bs.locate_protocol)(&EfiGuid::GOP_GUID, core::ptr::null(), &mut gop_ptr);

        let fb_info = if status.is_success() && !gop_ptr.is_null() {
            let gop = &*(gop_ptr as *mut EfiGraphicsOutputProtocol);
            if !gop.mode.is_null()
                && !(*gop.mode).info.is_null()
                && (*gop.mode).size_of_info
                    >= core::mem::size_of::<EfiGraphicsOutputModeInformation>()
            {
                let mode = &*gop.mode;
                let info = &*mode.info;
                Some(FramebufferInfo {
                    base_address: PhysicalAddress::new(mode.frame_buffer_base),
                    size: mode.frame_buffer_size,
                    width: info.horizontal_resolution,
                    height: info.vertical_resolution,
                    pixels_per_scan_line: info.pixels_per_scan_line,
                    red_mask: info.pixel_information.red_mask,
                    green_mask: info.pixel_information.green_mask,
                    blue_mask: info.pixel_information.blue_mask,
                })
            } else {
                None
            }
        } else {
            None
        };

        // 3. Prepare Boot Handover Structure
        let mut boot_info = BootHandoverInfo::new();
        boot_info.framebuffer = fb_info;

        let mut loaded: *mut core::ffi::c_void = core::ptr::null_mut();
        let status = (bs.handle_protocol)(image_handle, &EfiGuid::LOADED_IMAGE_GUID, &mut loaded);
        if !status.is_success() || loaded.is_null() {
            return EfiStatus::NOT_FOUND;
        }
        let loaded = &*(loaded as *const EfiLoadedImageProtocol);
        if loaded.image_base.is_null()
            || loaded.image_size == 0
            || loaded.image_size > 64 * 1024 * 1024
        {
            return EfiStatus::INVALID_PARAMETER;
        }
        let image =
            core::slice::from_raw_parts(loaded.image_base.cast::<u8>(), loaded.image_size as usize);
        if let Err(status) =
            nexus_boot::decode_kernel_code(loaded.image_base as u64, image, &mut boot_info)
        {
            return status;
        }

        // Fixed-capacity map: fail closed if firmware exceeds it. No truncation.
        let mut memory_buffer = [0u8; 16384];
        for _ in 0..3 {
            let mut map_size = memory_buffer.len();
            let mut map_key = 0usize;
            let mut desc_size = 0usize;
            let mut desc_version = 0u32;
            let status = (bs.get_memory_map)(
                &mut map_size,
                memory_buffer.as_mut_ptr().cast::<EfiMemoryDescriptorRaw>(),
                &mut map_key,
                &mut desc_size,
                &mut desc_version,
            );
            if !status.is_success() {
                return status;
            }
            let bytes = match memory_buffer.get(..map_size) {
                Some(bytes) => bytes,
                None => return EfiStatus::BUFFER_TOO_SMALL,
            };
            if let Err(status) =
                nexus_boot::decode_memory_map(bytes, desc_size, desc_version, &mut boot_info)
            {
                return status;
            }
            // No allocating firmware call between GetMemoryMap and ExitBootServices.
            let status = (bs.exit_boot_services)(image_handle, map_key);
            if status.is_success() {
                core::arch::asm!("cli", options(nomem, nostack));
                nexus_kernel::nexus_kernel_init(&boot_info);
                loop {
                    core::hint::spin_loop();
                }
            }
            if status != EfiStatus::INVALID_PARAMETER {
                return status;
            }
        }
        EfiStatus::INVALID_PARAMETER
    }
}

#[cfg(not(target_os = "uefi"))]
#[no_mangle]
pub extern "C" fn main() -> i32 {
    println!("Nexus OS UEFI Bootloader (compiled for host inspection/tests).");
    0
}
