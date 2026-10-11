//! Linux Pico Subsystem System Call Dispatcher.

use crate::context::RegisterContext;
use nexus_types::errno::Errno;

pub const SYS_READ: u64 = 0;
pub const SYS_WRITE: u64 = 1;
pub const SYS_OPEN: u64 = 2;
pub const SYS_CLOSE: u64 = 3;
pub const SYS_MMAP: u64 = 9;
pub const SYS_BRK: u64 = 12;
pub const SYS_SCHED_YIELD: u64 = 24;
pub const SYS_EXIT: u64 = 60;
pub const SYS_ARCH_PRCTL: u64 = 158;
pub const SYS_EXIT_GROUP: u64 = 231;

/// Dispatches a Linux POSIX system call from an ELF thread context.
pub fn dispatch_linux_syscall(ctx: &mut RegisterContext) -> i64 {
    let syscall_nr = ctx.rax;

    let ret_val: i64 = match syscall_nr {
        SYS_READ => {
            // fd: rdi, buf: rsi, count: rdx
            log::info!(
                "[Linux-Pico] sys_read(fd={}, buf={:#X}, count={})",
                ctx.rdi,
                ctx.rsi,
                ctx.rdx
            );
            0 // 0 bytes read (EOF simulation)
        }
        SYS_WRITE => {
            // fd: rdi, buf: rsi, count: rdx
            log::info!(
                "[Linux-Pico] sys_write(fd={}, buf={:#X}, count={})",
                ctx.rdi,
                ctx.rsi,
                ctx.rdx
            );
            ctx.rdx as i64 // successfully wrote count bytes
        }
        SYS_OPEN => {
            log::info!(
                "[Linux-Pico] sys_open(path={:#X}, flags={:#X})",
                ctx.rdi,
                ctx.rsi
            );
            3 // return dummy fd 3
        }
        SYS_CLOSE => {
            log::info!("[Linux-Pico] sys_close(fd={})", ctx.rdi);
            0
        }
        SYS_BRK => {
            log::info!("[Linux-Pico] sys_brk(new_brk={:#X})", ctx.rdi);
            if ctx.rdi == 0 {
                0x0040_0000 + 0x10000 // Return default simulated break
            } else {
                ctx.rdi as i64
            }
        }
        SYS_MMAP => {
            log::info!(
                "[Linux-Pico] sys_mmap(addr={:#X}, len={}, prot={:#X})",
                ctx.rdi,
                ctx.rsi,
                ctx.rdx
            );
            0x0000_7FFF_0000_0000 // Return simulated mmap allocation base
        }
        SYS_SCHED_YIELD => {
            log::info!("[Linux-Pico] sys_sched_yield()");
            0
        }
        SYS_ARCH_PRCTL => {
            // code: rdi, addr: rsi (ARCH_SET_FS = 0x1002)
            log::info!(
                "[Linux-Pico] sys_arch_prctl(code={:#X}, addr={:#X})",
                ctx.rdi,
                ctx.rsi
            );
            0
        }
        SYS_EXIT | SYS_EXIT_GROUP => {
            log::info!("[Linux-Pico] sys_exit(status={})", ctx.rdi);
            ctx.rdi as i64
        }
        _ => {
            log::warn!("[Linux-Pico] Unhandled Linux syscall nr: {}", syscall_nr);
            Errno::ENOSYS.as_ret_val()
        }
    };

    ctx.rax = ret_val as u64;
    ret_val
}
