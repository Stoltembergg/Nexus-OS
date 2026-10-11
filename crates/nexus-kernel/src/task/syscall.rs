//! Real hardware syscall path; user access checks effective permissions at every level.
use crate::mem::vmm::{AddressSpace, PageTableFlags};
use core::sync::atomic::{AtomicU64, Ordering};
use nexus_types::{errno::Errno, VirtualAddress};
pub static LAST_SYSCALL_EXIT_CODE: AtomicU64 = AtomicU64::new(u64::MAX);

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyscallFrame {
    pub rax: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbx: u64,
    pub rbp: u64,
    pub rcx: u64,
    pub r11: u64,
    pub rsp: u64,
    pub fs_base: u64,
    pub gs_base: u64,
}
#[no_mangle]
pub static mut KERNEL_RSP_SCRATCH: u64 = 0;
#[no_mangle]
pub static mut USER_RSP_SCRATCH: u64 = 0;
pub const USER_CEILING: u64 = 0x0000_8000_0000_0000;

pub fn validate_user_buffer(
    ptr: u64,
    len: usize,
    writable: bool,
    space: &AddressSpace,
) -> Result<(), Errno> {
    if len == 0 {
        return Ok(());
    }
    let end = ptr.checked_add(len as u64).ok_or(Errno::EFAULT)?;
    if ptr == 0 || ptr >= USER_CEILING || end > USER_CEILING {
        return Err(Errno::EFAULT);
    }
    for page in ((ptr & !4095)..end).step_by(4096) {
        let mapping = space
            .mapping(VirtualAddress::new(page))
            .ok_or(Errno::EFAULT)?;
        if !mapping.flags.contains(PageTableFlags::USER)
            || (writable && !mapping.flags.contains(PageTableFlags::WRITABLE))
        {
            return Err(Errno::EFAULT);
        }
    }
    Ok(())
}
pub fn validate_return_context(frame: &SyscallFrame, space: &AddressSpace) -> Result<(), Errno> {
    validate_user_buffer(frame.rcx, 1, false, space)?;
    validate_user_buffer(
        frame.rsp.checked_sub(1).ok_or(Errno::EFAULT)?,
        1,
        true,
        space,
    )?;
    let code = space
        .mapping(VirtualAddress::new(frame.rcx))
        .ok_or(Errno::EFAULT)?;
    if code.flags.contains(PageTableFlags::NO_EXECUTE)
        || frame.fs_base >= USER_CEILING
        || frame.gs_base >= USER_CEILING
    {
        return Err(Errno::EFAULT);
    }
    Ok(())
}

/// Copy through supervisor physical aliases, independent of the current CR3.
pub fn safe_copy_from_user(
    dest: &mut [u8],
    src: u64,
    len: usize,
    space: &AddressSpace,
) -> Result<usize, Errno> {
    let count = dest.len().min(len);
    validate_user_buffer(src, count, false, space)?;
    #[cfg(any(target_os = "uefi", target_os = "none"))]
    for (offset, byte) in dest.iter_mut().enumerate().take(count) {
        let pa = space
            .translate(VirtualAddress::new(src + offset as u64))
            .ok_or(Errno::EFAULT)?;
        unsafe {
            *byte = core::ptr::read(pa.as_u64() as *const u8);
        }
    }
    Ok(count)
}
pub fn safe_copy_to_user(dest: u64, src: &[u8], space: &AddressSpace) -> Result<(), Errno> {
    validate_user_buffer(dest, src.len(), true, space)?;
    #[cfg(any(target_os = "uefi", target_os = "none"))]
    for (offset, value) in src.iter().enumerate() {
        let pa = space
            .translate(VirtualAddress::new(dest + offset as u64))
            .ok_or(Errno::EFAULT)?;
        unsafe {
            core::ptr::write(pa.as_u64() as *mut u8, *value);
        }
    }
    Ok(())
}
fn user_u64(ptr: u64, space: &AddressSpace) -> Result<u64, Errno> {
    let mut bytes = [0; 8];
    safe_copy_from_user(&mut bytes, ptr, 8, space)?;
    Ok(u64::from_le_bytes(bytes))
}
fn write_serial(bytes: &[u8]) {
    let port = crate::arch::x86_64::serial::SERIAL1.lock();
    for byte in bytes {
        port.write_byte(*byte);
    }
}

#[no_mangle]
pub extern "win64" fn raw_syscall_dispatcher(frame: &mut SyscallFrame) {
    #[cfg(all(
        feature = "hardening-tests",
        any(target_os = "uefi", target_os = "none")
    ))]
    crate::hardening::assert_kernel_fx();
    #[cfg(any(target_os = "uefi", target_os = "none"))]
    unsafe {
        frame.fs_base = crate::syscall::rdmsr(0xc0000100);
        frame.gs_base = crate::syscall::rdmsr(0xc0000101);
    }
    // Cooperative kernel keeps IF disabled. User may retain arithmetic flags and DF only.
    frame.r11 = (frame.r11 & 0xcd5) | 2;
    let space = crate::task::get_active_address_space();
    if validate_return_context(frame, &space).is_err() {
        crate::task::trigger_user_abort(13);
        return;
    }
    if crate::task::get_active_personality().is_windows() {
        dispatch_nt_syscall(frame);
    } else {
        dispatch_linux_syscall(frame);
    }
}
fn dispatch_nt_syscall(frame: &mut SyscallFrame) {
    if frame.rax > u32::MAX as u64 {
        frame.rax = 0xc0000002;
        return;
    }
    match frame.rax as u32 {
        0x0008 => {
            let space = crate::task::get_active_address_space();
            // NT x64: first argument in R10, fifth onward on user stack.
            let args = (|| -> Result<(u64, u64, usize), Errno> {
                let iosb = user_u64(frame.rsp.checked_add(0x28).ok_or(Errno::EFAULT)?, &space)?;
                let buffer = user_u64(frame.rsp.checked_add(0x30).ok_or(Errno::EFAULT)?, &space)?;
                let len =
                    user_u64(frame.rsp.checked_add(0x38).ok_or(Errno::EFAULT)?, &space)? as usize;
                validate_user_buffer(iosb, 16, true, &space)?;
                Ok((iosb, buffer, len))
            })();
            let (iosb, ptr, len) = match args {
                Ok(args) => args,
                Err(_) => {
                    frame.rax = 0xc0000005;
                    return;
                }
            };
            if !matches!(frame.r10, 1 | 2) {
                frame.rax = 0xc0000008;
                return;
            }
            if frame.rdx != 0 || frame.r8 != 0 || frame.r9 != 0 || len > 256 {
                frame.rax = 0xc000000d;
                return;
            }
            let mut bytes = [0; 256];
            match safe_copy_from_user(&mut bytes, ptr, len, &space) {
                Ok(count) => {
                    write_serial(&bytes[..count]);
                    let mut status = [0; 16];
                    status[8..16].copy_from_slice(&(count as u64).to_le_bytes());
                    frame.rax = if safe_copy_to_user(iosb, &status, &space).is_ok() {
                        0
                    } else {
                        0xc0000005
                    };
                }
                Err(_) => frame.rax = 0xc0000005,
            }
        }
        0x0050 => {
            frame.rax = 0;
            crate::task::save_active_thread_registers(frame);
            crate::task::trigger_user_yield();
        }
        0x002c => {
            if frame.r10 != u64::MAX {
                frame.rax = 0xc0000008;
                return;
            }
            let code = frame.rdx as i32;
            LAST_SYSCALL_EXIT_CODE.store(code as u64, Ordering::Relaxed);
            crate::task::finish_user(crate::task::RunOutcome::Exit(code));
        }
        _ => frame.rax = 0xc0000002,
    }
}
fn dispatch_linux_syscall(frame: &mut SyscallFrame) {
    match frame.rax {
        1 => {
            if !matches!(frame.rdi, 1 | 2) {
                frame.rax = Errno::EBADF.as_ret_val() as u64;
                return;
            }
            let space = crate::task::get_active_address_space();
            let mut bytes = [0; 256];
            match safe_copy_from_user(&mut bytes, frame.rsi, frame.rdx as usize, &space) {
                Ok(count) => {
                    write_serial(&bytes[..count]);
                    frame.rax = count as u64;
                }
                Err(error) => frame.rax = error.as_ret_val() as u64,
            }
        }
        24 => {
            frame.rax = 0;
            crate::task::save_active_thread_registers(frame);
            crate::task::trigger_user_yield();
        }
        60 | 231 => {
            let code = frame.rdi as i32;
            LAST_SYSCALL_EXIT_CODE.store(code as u64, Ordering::Relaxed);
            crate::task::finish_user(crate::task::RunOutcome::Exit(code));
        }
        _ => frame.rax = Errno::ENOSYS.as_ret_val() as u64,
    }
}

#[cfg(any(target_os = "uefi", target_os = "none"))]
core::arch::global_asm!(
    r#"
    .global asm_syscall_entry
    asm_syscall_entry:
        mov [rip + USER_RSP_SCRATCH], rsp
        mov rsp, [rip + KERNEL_RSP_SCRATCH]
        sub rsp, 16 // FS/GS slots filled by dispatcher
        push qword ptr [rip + USER_RSP_SCRATCH]
        push r11
        push rcx
        push rbp
        push rbx
        push r12
        push r13
        push r14
        push r15
        push rdx
        push rsi
        push rdi
        push r8
        push r9
        push r10
        push rax
        fxsave64 [rip + USER_FX]
        // User floating-point controls must not affect Rust kernel code.
        fxrstor64 [rip + KERNEL_SAVED_CTX + 0x60]
        cld
        mov rcx, rsp
        sub rsp, 32 // Win64 shadow space; pre-CALL RSP aligned to 16
        call raw_syscall_dispatcher
        add rsp, 32
        fxrstor64 [rip + USER_FX]
    .global asm_restore_user_frame
    asm_restore_user_frame:
        pop rax
        pop r10
        pop r9
        pop r8
        pop rdi
        pop rsi
        pop rdx
        pop r15
        pop r14
        pop r13
        pop r12
        pop rbx
        pop rbp
        pop rcx
        pop r11
        // IRET avoids non-canonical SYSRET faults in Ring 0, and never loads user RSP in Ring 0.
        push 0x1b
        push qword ptr [rsp + 8]
        push r11
        push 0x23
        push rcx
        iretq
"#
);
#[cfg(any(target_os = "uefi", target_os = "none"))]
extern "C" {
    pub fn asm_syscall_entry();
}
#[cfg(not(any(target_os = "uefi", target_os = "none")))]
pub extern "C" fn asm_syscall_entry() {}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_types::PhysicalAddress;
    #[test]
    fn test_user_buffer_bounds_check() {
        let space = AddressSpace::from_pml4(PhysicalAddress::new(0x1000));
        for (ptr, len) in [
            (0x400000, 32),
            (0xffff800000000000, 32),
            (0x7ffffffffff0, 256),
            (u64::MAX - 10, 20),
            (0, 16),
        ] {
            assert_eq!(
                validate_user_buffer(ptr, len, false, &space),
                Err(Errno::EFAULT)
            );
        }
        assert_eq!(validate_user_buffer(0, 0, false, &space), Ok(()));
    }
    #[test]
    fn frame_layout_matches_hardware_entry() {
        assert_eq!(core::mem::offset_of!(SyscallFrame, rsp), 0x78);
        assert_eq!(core::mem::offset_of!(SyscallFrame, fs_base), 0x80);
        assert_eq!(core::mem::offset_of!(SyscallFrame, gs_base), 0x88);
        assert_eq!(core::mem::size_of::<SyscallFrame>(), 144);
    }
}
