//! Hardware Syscall Dispatcher with Dual Personality (NT SSDT / Linux Pico).
//!
//! Handles transitions initiated by the `syscall` CPU instruction in Ring 3.
//! Implements strict user pointer validation, boundary checks, and routing based on
//! the active thread's `ProcessPersonality`.

use crate::mem::vmm::AddressSpace;
use core::sync::atomic::{AtomicU64, Ordering};
use nexus_types::errno::Errno;
use nexus_types::VirtualAddress;

pub static LAST_SYSCALL_EXIT_CODE: AtomicU64 = AtomicU64::new(u64::MAX);

#[repr(C)]
#[derive(Debug, Clone, Copy)]
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
    pub rcx: u64, // Saved user RIP (from RCX)
    pub r11: u64, // Saved user RFLAGS (from R11)
    pub rsp: u64, // Saved user RSP
}

#[no_mangle]
pub static mut KERNEL_RSP_SCRATCH: u64 = 0;

#[no_mangle]
pub static mut USER_RSP_SCRATCH: u64 = 0;

pub const USER_CEILING: u64 = 0x0000_8000_0000_0000;

/// Validates that a user-provided buffer is safely within user memory bounds.
pub fn validate_user_buffer(
    user_ptr: u64,
    len: usize,
    _require_writable: bool,
    address_space: &AddressSpace,
) -> Result<(), Errno> {
    if len == 0 {
        return Ok(());
    }

    let end_ptr = user_ptr.checked_add(len as u64).ok_or(Errno::EFAULT)?;

    if end_ptr > USER_CEILING || user_ptr >= USER_CEILING || user_ptr == 0 {
        return Err(Errno::EFAULT);
    }

    // Verify all pages spanned by buffer are mapped and present in user address space
    let start_page = user_ptr & !0xFFF;
    let end_page = (end_ptr + 0xFFF) & !0xFFF;

    let mut curr = start_page;
    while curr < end_page {
        let vaddr = VirtualAddress::new(curr);
        if address_space.translate(vaddr).is_none() {
            return Err(Errno::EFAULT);
        }
        curr += 4096;
    }

    Ok(())
}

/// Safely copies bytes from Ring 3 memory into a kernel buffer after validation.
pub fn safe_copy_from_user(
    dest: &mut [u8],
    user_src: u64,
    len: usize,
    address_space: &AddressSpace,
) -> Result<usize, Errno> {
    let to_copy = dest.len().min(len);
    validate_user_buffer(user_src, to_copy, false, address_space)?;

    #[cfg(all(target_arch = "x86_64", not(test)))]
    unsafe {
        let src_ptr = user_src as *const u8;
        core::ptr::copy_nonoverlapping(src_ptr, dest.as_mut_ptr(), to_copy);
    }

    #[cfg(any(not(target_arch = "x86_64"), test))]
    {
        let _ = (dest, user_src, to_copy);
    }

    Ok(to_copy)
}

#[no_mangle]
pub extern "C" fn raw_syscall_dispatcher(frame: &mut SyscallFrame) {
    let personality = crate::task::get_active_personality();

    if personality.is_windows() {
        dispatch_nt_syscall(frame);
    } else {
        dispatch_linux_syscall(frame);
    }
}

fn dispatch_nt_syscall(frame: &mut SyscallFrame) {
    let service_id = frame.rax as u32;

    match service_id {
        // NtWriteFile (0x0008)
        0x0008 => {
            let active_as = crate::task::get_active_address_space();
            let mut buf_ptr = frame.rdx;
            let mut count = frame.r8 as usize;

            // Check if buffer pointer and length were passed on stack (Win64 NT convention)
            let stack_buf_slot = frame.rsp.wrapping_add(0x30);
            if validate_user_buffer(stack_buf_slot, 8, false, &active_as).is_ok() {
                let stack_val = unsafe { *(stack_buf_slot as *const u64) };
                if (0x4000_0000..USER_CEILING).contains(&stack_val) {
                    buf_ptr = stack_val;
                    let stack_len_slot = frame.rsp.wrapping_add(0x38);
                    if validate_user_buffer(stack_len_slot, 8, false, &active_as).is_ok() {
                        let l = unsafe { *(stack_len_slot as *const u64) } as usize;
                        if l > 0 && l < 1024 {
                            count = l;
                        }
                    }
                }
            }

            let mut local_buf = [0u8; 256];
            let to_read = count.min(local_buf.len());

            if let Err(e) = validate_user_buffer(buf_ptr, to_read, false, &active_as) {
                serial_println!(
                    "[Kernel Syscall] NtWriteFile rejected invalid pointer {:#018X} ({:?})",
                    buf_ptr,
                    e
                );
                frame.rax = 0xC000_0005; // STATUS_ACCESS_VIOLATION
                return;
            }

            if let Ok(copied) = safe_copy_from_user(&mut local_buf, buf_ptr, to_read, &active_as) {
                if let Ok(s) = core::str::from_utf8(&local_buf[..copied]) {
                    serial_print!("[Ring 3 WinPE]: {}", s);
                }
                frame.rax = 0; // STATUS_SUCCESS
                return;
            }

            frame.rax = 0;
        }

        // NtYieldExecution (0x0050)
        0x0050 => {
            serial_println!("[Kernel Syscall] NtYieldExecution invoked by Windows PE32+ task.");
            crate::task::save_active_thread_registers(frame);
            crate::task::trigger_user_yield();
        }

        // NtTerminateProcess (0x002C)
        0x002C => {
            let exit_code = frame.rdx as i32;
            serial_println!(
                "[Kernel Syscall] NtTerminateProcess invoked (status={})",
                exit_code
            );
            LAST_SYSCALL_EXIT_CODE.store(exit_code as u64, Ordering::SeqCst);
            crate::task::trigger_user_abort(exit_code);
        }

        _ => {
            serial_println!(
                "[Kernel Syscall] Unhandled NT service ID: {:#06X}",
                service_id
            );
            frame.rax = 0xC000_0002; // STATUS_NOT_IMPLEMENTED
        }
    }
}

fn dispatch_linux_syscall(frame: &mut SyscallFrame) {
    let syscall_nr = frame.rax;

    match syscall_nr {
        // Linux SYS_WRITE (1): fd = rdi, buf = rsi, count = rdx
        1 => {
            let fd = frame.rdi;
            let user_buf = frame.rsi;
            let count = frame.rdx as usize;

            if fd == 1 || fd == 2 {
                let mut local_buf = [0u8; 256];
                let to_read = count.min(local_buf.len());

                let active_as = crate::task::get_active_address_space();
                if let Err(e) = validate_user_buffer(user_buf, to_read, false, &active_as) {
                    serial_println!(
                        "[Kernel Syscall] SYS_WRITE rejected: Invalid user pointer {:#018X} ({:?})",
                        user_buf,
                        e
                    );
                    frame.rax = e.as_ret_val() as u64;
                    return;
                }

                if let Ok(copied) =
                    safe_copy_from_user(&mut local_buf, user_buf, to_read, &active_as)
                {
                    if let Ok(s) = core::str::from_utf8(&local_buf[..copied]) {
                        serial_print!("[Ring 3 Linux]: {}", s);
                    }
                    frame.rax = copied as u64;
                    return;
                }
            }
            frame.rax = count as u64;
        }

        // Linux SYS_SCHED_YIELD (24)
        24 => {
            serial_println!("[Kernel Syscall] SYS_SCHED_YIELD invoked by Linux ELF64 task.");
            crate::task::save_active_thread_registers(frame);
            crate::task::trigger_user_yield();
        }

        // Linux SYS_EXIT (60) or SYS_EXIT_GROUP (231): status = rdi
        60 | 231 => {
            let exit_code = frame.rdi as i32;
            serial_println!(
                "[Kernel Syscall] Linux sys_exit invoked (status={})",
                exit_code
            );
            LAST_SYSCALL_EXIT_CODE.store(exit_code as u64, Ordering::SeqCst);
            crate::task::trigger_user_abort(exit_code);
        }

        _ => {
            serial_println!("[Kernel Syscall] Unknown Linux syscall nr: {}", syscall_nr);
            frame.rax = Errno::ENOSYS.as_ret_val() as u64;
        }
    }
}

#[cfg(all(target_arch = "x86_64", not(test)))]
core::arch::global_asm!(
    r#"
    .global asm_syscall_entry
    asm_syscall_entry:
        // 1. Save user RSP to scratch variable
        mov [rip + USER_RSP_SCRATCH], rsp

        // 2. Load dedicated kernel stack
        mov rsp, [rip + KERNEL_RSP_SCRATCH]

        // 3. Push saved user context
        push qword ptr [rip + USER_RSP_SCRATCH] // Saved User RSP
        push r11                                // Saved User RFLAGS
        push rcx                                // Saved User RIP
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

        // 4. Pass pointer to SyscallFrame
        mov rcx, rsp
        mov rdi, rsp
        sub rsp, 40 // Shadow space
        call raw_syscall_dispatcher
        add rsp, 40

        // 5. Restore user context
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
        pop rcx // Restore user RIP into RCX
        pop r11 // Restore user RFLAGS into R11
        pop rsp // Restore user RSP directly

        sysretq
    "#
);

#[cfg(all(target_arch = "x86_64", not(test)))]
extern "C" {
    pub fn asm_syscall_entry();
}

#[cfg(any(not(target_arch = "x86_64"), test))]
pub extern "C" fn asm_syscall_entry() {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::vmm::AddressSpace;
    use nexus_types::PhysicalAddress;

    #[test]
    fn test_user_buffer_bounds_check() {
        let dummy_as = AddressSpace::from_pml4(PhysicalAddress::new(0x1000));

        // Canonical user addresses: 0x400000
        assert!(validate_user_buffer(0x0040_0000, 32, false, &dummy_as).is_ok());

        // Kernel higher addresses: 0xFFFF_8000_0000_0000 -> Must return EFAULT
        assert_eq!(
            validate_user_buffer(0xFFFF_8000_0000_0000, 32, false, &dummy_as),
            Err(Errno::EFAULT)
        );

        // Address overflowing past canonical ceiling: 0x0000_7FFF_FFFF_FFF0 with len 0x100 -> EFAULT
        assert_eq!(
            validate_user_buffer(0x0000_7FFF_FFFF_FFF0, 0x100, false, &dummy_as),
            Err(Errno::EFAULT)
        );

        // Integer overflow -> EFAULT
        assert_eq!(
            validate_user_buffer(u64::MAX - 10, 20, false, &dummy_as),
            Err(Errno::EFAULT)
        );

        // Null pointer -> EFAULT
        assert_eq!(
            validate_user_buffer(0, 16, false, &dummy_as),
            Err(Errno::EFAULT)
        );
    }
}
