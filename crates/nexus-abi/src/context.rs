//! Low-level CPU register context captured during a SYSCALL or interrupt trap.

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(C)]
pub struct RegisterContext {
    pub rax: u64, // Syscall number (Linux) or NT return value / syscall ID
    pub rbx: u64,
    pub rcx: u64, // 1st arg (Windows x64) / user RIP saved by SYSCALL
    pub rdx: u64, // 2nd arg (Windows x64) / 3rd arg (Linux)
    pub rsi: u64, // 2nd arg (Linux)
    pub rdi: u64, // 1st arg (Linux)
    pub rbp: u64,
    pub rsp: u64, // User stack pointer
    pub r8: u64,  // 3rd arg (Windows) / 5th arg (Linux)
    pub r9: u64,  // 4th arg (Windows) / 6th arg (Linux)
    pub r10: u64, // 4th arg (Linux)
    pub r11: u64, // User RFLAGS saved by SYSCALL
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64, // Target or return instruction pointer
    pub rflags: u64,
}

impl RegisterContext {
    pub fn new() -> Self {
        Self::default()
    }
}
