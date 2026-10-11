#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
use core::panic::PanicInfo;
#[cfg(target_os = "none")]
use nexus_boot::BootHandoverInfo;

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(target_os = "none")]
#[no_mangle]
pub extern "C" fn _start(boot_info: *const BootHandoverInfo) -> ! {
    if !boot_info.is_null() {
        let info = unsafe { &*boot_info };
        nexus_kernel::nexus_kernel_init(info);
    }

    loop {
        core::hint::spin_loop();
    }
}

#[cfg(not(target_os = "none"))]
fn main() {
    println!("Nexus OS Kernel Binary (compiled for host test/inspection).");
    println!(
        "To build for bare-metal target: cargo build -p nexus-kernel --target x86_64-unknown-none"
    );
}
