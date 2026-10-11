//! x86_64 Interrupt Descriptor Table (IDT) and Architectural Exception Gates.

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    zero: u32,
}

impl IdtEntry {
    pub const NULL: Self = Self {
        offset_low: 0,
        selector: 0,
        ist: 0,
        type_attr: 0,
        offset_mid: 0,
        offset_high: 0,
        zero: 0,
    };

    /// Sets the gate handler virtual address, segment selector, and flags.
    pub fn set_handler(&mut self, handler_addr: u64, selector: u16, ist: u8, type_attr: u8) {
        self.offset_low = handler_addr as u16;
        self.selector = selector;
        self.ist = ist & 0x07;
        self.type_attr = type_attr;
        self.offset_mid = (handler_addr >> 16) as u16;
        self.offset_high = (handler_addr >> 32) as u32;
        self.zero = 0;
    }

    /// Reconstructs the 64-bit target address for verification.
    pub fn address(&self) -> u64 {
        let low = self.offset_low as u64;
        let mid = (self.offset_mid as u64) << 16;
        let high = (self.offset_high as u64) << 32;
        low | mid | high
    }

    #[inline]
    pub fn selector(&self) -> u16 {
        self.selector
    }

    #[inline]
    pub fn ist(&self) -> u8 {
        self.ist
    }

    #[inline]
    pub fn type_attr(&self) -> u8 {
        self.type_attr
    }
}

#[repr(C, packed)]
pub struct IdtPointer {
    pub limit: u16,
    pub base: u64,
}

#[repr(C, align(16))]
pub struct IdtTable {
    pub entries: [IdtEntry; 256],
}

impl Default for IdtTable {
    fn default() -> Self {
        Self::new()
    }
}

impl IdtTable {
    pub const fn new() -> Self {
        Self {
            entries: [IdtEntry::NULL; 256],
        }
    }

    pub fn pointer(&self) -> IdtPointer {
        IdtPointer {
            limit: (core::mem::size_of::<Self>() - 1) as u16,
            base: self as *const _ as u64,
        }
    }

    pub fn set_gate(&mut self, vector: usize, handler: u64, selector: u16, ist: u8, flags: u8) {
        if vector < 256 {
            self.entries[vector].set_handler(handler, selector, ist, flags);
        }
    }
}

/// Hardware exception stack frame passed to exception_dispatch_handler.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExceptionFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    pub vector: u64,
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

/// Reads the CR2 register containing the linear address that caused a Page Fault.
#[inline]
pub fn read_cr2() -> u64 {
    let cr2: u64;
    #[cfg(all(target_arch = "x86_64", any(target_os = "uefi", target_os = "none")))]
    unsafe {
        core::arch::asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack, preserves_flags));
    }
    #[cfg(not(all(target_arch = "x86_64", any(target_os = "uefi", target_os = "none"))))]
    {
        cr2 = 0;
    }
    cr2
}

pub static mut LAST_FAULT_INFO: Option<(u64, u64, u64)> = None; // (vector, cr2, error_code)

#[no_mangle]
pub extern "win64" fn exception_dispatch_handler(frame: &mut ExceptionFrame) {
    let is_user = (frame.cs & 3) == 3;
    #[cfg(all(
        feature = "hardening-tests",
        any(target_os = "uefi", target_os = "none")
    ))]
    if is_user {
        crate::hardening::assert_kernel_fx();
    }
    let cr2 = if frame.vector == 14 { read_cr2() } else { 0 };
    unsafe {
        LAST_FAULT_INFO = Some((frame.vector, cr2, frame.error_code));
    }
    // Never dereference untrusted RIP merely for #UD diagnostics.
    serial_println!(
        "[TRAP] vector={} cr2={:#x} error={:#x} rip={:#x} ring={}",
        frame.vector,
        cr2,
        frame.error_code,
        frame.rip,
        if is_user { 3 } else { 0 }
    );
    if is_user && !matches!(frame.vector, 2 | 8 | 18) {
        crate::task::trigger_user_abort(frame.vector as i32);
    }
    // A Ring 0 trap is unrecoverable. Under the QEMU hardening suite, report it as a
    // failure exit code instead of halting until the runner times out (M8).
    #[cfg(all(
        feature = "hardening-tests",
        any(target_os = "uefi", target_os = "none")
    ))]
    if !is_user {
        serial_println!("NEXUS_RING0_TRAP: vector={}", frame.vector);
        crate::hardening::exit_failure(crate::hardening::EXIT_CODE_RING0_TRAP);
    }
    #[cfg(any(target_os = "uefi", target_os = "none"))]
    unsafe {
        core::arch::asm!("cli; 2: hlt; jmp 2b", options(noreturn));
    }
}
pub fn arm_exception_gates(idt: &mut IdtTable) {
    #[cfg(any(target_os = "uefi", target_os = "none"))]
    {
        extern "C" {
            fn asm_stub_de();
            fn asm_stub_db();
            fn asm_stub_nmi();
            fn asm_stub_bp();
            fn asm_stub_of();
            fn asm_stub_br();
            fn asm_stub_ud();
            fn asm_stub_nm();
            fn asm_stub_df();
            fn asm_stub_r9();
            fn asm_stub_ts();
            fn asm_stub_np();
            fn asm_stub_ss();
            fn asm_stub_gp();
            fn asm_stub_pf();
            fn asm_stub_r15();
            fn asm_stub_mf();
            fn asm_stub_ac();
            fn asm_stub_mc();
            fn asm_stub_xm();
            fn asm_stub_ve();
            fn asm_stub_cp();
            fn asm_stub_r22();
            fn asm_stub_r23();
            fn asm_stub_r24();
            fn asm_stub_r25();
            fn asm_stub_r26();
            fn asm_stub_r27();
            fn asm_stub_hv();
            fn asm_stub_vc();
            fn asm_stub_sx();
            fn asm_stub_r31();
        }
        let handlers = [
            asm_stub_de as *const () as u64,
            asm_stub_db as *const () as u64,
            asm_stub_nmi as *const () as u64,
            asm_stub_bp as *const () as u64,
            asm_stub_of as *const () as u64,
            asm_stub_br as *const () as u64,
            asm_stub_ud as *const () as u64,
            asm_stub_nm as *const () as u64,
            asm_stub_df as *const () as u64,
            asm_stub_r9 as *const () as u64,
            asm_stub_ts as *const () as u64,
            asm_stub_np as *const () as u64,
            asm_stub_ss as *const () as u64,
            asm_stub_gp as *const () as u64,
            asm_stub_pf as *const () as u64,
            asm_stub_r15 as *const () as u64,
            asm_stub_mf as *const () as u64,
            asm_stub_ac as *const () as u64,
            asm_stub_mc as *const () as u64,
            asm_stub_xm as *const () as u64,
            asm_stub_ve as *const () as u64,
            asm_stub_cp as *const () as u64,
            asm_stub_r22 as *const () as u64,
            asm_stub_r23 as *const () as u64,
            asm_stub_r24 as *const () as u64,
            asm_stub_r25 as *const () as u64,
            asm_stub_r26 as *const () as u64,
            asm_stub_r27 as *const () as u64,
            asm_stub_hv as *const () as u64,
            asm_stub_vc as *const () as u64,
            asm_stub_sx as *const () as u64,
            asm_stub_r31 as *const () as u64,
        ];
        for (vector, handler) in handlers.into_iter().enumerate() {
            idt.set_gate(vector, handler, 0x08, if vector == 8 { 1 } else { 0 }, 0x8e);
        }
    }
    #[cfg(not(any(target_os = "uefi", target_os = "none")))]
    let _ = idt;
}
#[cfg(any(target_os = "uefi", target_os = "none"))]
core::arch::global_asm!(
    r#"
    .global asm_stub_de
    asm_stub_de:
        push 0
        push 0
        jmp asm_common_exception
    .global asm_stub_db
    asm_stub_db:
        push 0
        push 1
        jmp asm_common_exception
    .global asm_stub_nmi
    asm_stub_nmi:
        push 0
        push 2
        jmp asm_common_exception
    .global asm_stub_bp
    asm_stub_bp:
        push 0
        push 3
        jmp asm_common_exception
    .global asm_stub_of
    asm_stub_of:
        push 0
        push 4
        jmp asm_common_exception
    .global asm_stub_br
    asm_stub_br:
        push 0
        push 5
        jmp asm_common_exception
    .global asm_stub_ud
    asm_stub_ud:
        push 0
        push 6
        jmp asm_common_exception
    .global asm_stub_nm
    asm_stub_nm:
        push 0
        push 7
        jmp asm_common_exception
    .global asm_stub_df
    asm_stub_df:
        push 8
        jmp asm_common_exception
    .global asm_stub_r9
    asm_stub_r9:
        push 0
        push 9
        jmp asm_common_exception
    .global asm_stub_ts
    asm_stub_ts:
        push 10
        jmp asm_common_exception
    .global asm_stub_np
    asm_stub_np:
        push 11
        jmp asm_common_exception
    .global asm_stub_ss
    asm_stub_ss:
        push 12
        jmp asm_common_exception
    .global asm_stub_gp
    asm_stub_gp:
        push 13
        jmp asm_common_exception
    .global asm_stub_pf
    asm_stub_pf:
        push 14
        jmp asm_common_exception
    .global asm_stub_r15
    asm_stub_r15:
        push 0
        push 15
        jmp asm_common_exception
    .global asm_stub_mf
    asm_stub_mf:
        push 0
        push 16
        jmp asm_common_exception
    .global asm_stub_ac
    asm_stub_ac:
        push 17
        jmp asm_common_exception
    .global asm_stub_mc
    asm_stub_mc:
        push 0
        push 18
        jmp asm_common_exception
    .global asm_stub_xm
    asm_stub_xm:
        push 0
        push 19
        jmp asm_common_exception
    .global asm_stub_ve
    asm_stub_ve:
        push 0
        push 20
        jmp asm_common_exception
    .global asm_stub_cp
    asm_stub_cp:
        push 21
        jmp asm_common_exception
    .global asm_stub_r22
    asm_stub_r22:
        push 0
        push 22
        jmp asm_common_exception
    .global asm_stub_r23
    asm_stub_r23:
        push 0
        push 23
        jmp asm_common_exception
    .global asm_stub_r24
    asm_stub_r24:
        push 0
        push 24
        jmp asm_common_exception
    .global asm_stub_r25
    asm_stub_r25:
        push 0
        push 25
        jmp asm_common_exception
    .global asm_stub_r26
    asm_stub_r26:
        push 0
        push 26
        jmp asm_common_exception
    .global asm_stub_r27
    asm_stub_r27:
        push 0
        push 27
        jmp asm_common_exception
    .global asm_stub_hv
    asm_stub_hv:
        push 0
        push 28
        jmp asm_common_exception
    .global asm_stub_vc
    asm_stub_vc:
        push 29
        jmp asm_common_exception
    .global asm_stub_sx
    asm_stub_sx:
        push 30
        jmp asm_common_exception
    .global asm_stub_r31
    asm_stub_r31:
        push 0
        push 31
        jmp asm_common_exception
    asm_common_exception:
        push rax
        push rbx
        push rcx
        push rdx
        push rbp
        push rsi
        push rdi
        push r8
        push r9
        push r10
        push r11
        push r12
        push r13
        push r14
        push r15
        cld
        test byte ptr [rsp + 144], 3 // saved CS: only Ring 3 has a saved kernel context
        jz .Lkernel_exception_fx
        fxrstor64 [rip + KERNEL_SAVED_CTX + 0x60]
    .Lkernel_exception_fx:
        mov rcx, rsp
        mov r12, rsp
        and rsp, -16
        sub rsp, 32
        call exception_dispatch_handler
        mov rsp, r12
        pop r15
        pop r14
        pop r13
        pop r12
        pop r11
        pop r10
        pop r9
        pop r8
        pop rdi
        pop rsi
        pop rbp
        pop rdx
        pop rcx
        pop rbx
        pop rax
        add rsp, 16
        iretq
"#
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_idt_entry_address_reconstruction() {
        let mut entry = IdtEntry::NULL;
        let target_rip = 0xFFFF_8000_1234_5678_u64;
        entry.set_handler(target_rip, 0x08, 1, 0x8E);

        assert_eq!(entry.address(), target_rip);
        assert_eq!(entry.selector(), 0x08);
        assert_eq!(entry.ist(), 1);
        assert_eq!(entry.type_attr(), 0x8E);
    }

    #[test]
    fn test_idt_table_initialization() {
        let mut table = IdtTable::new();
        table.set_gate(0x0E, 0xFFFF_8000_DEAD_BEEF, 0x08, 0, 0x8E); // #PF
        assert_eq!(table.entries[0x0E].address(), 0xFFFF_8000_DEAD_BEEF);
        assert_eq!(table.entries[0x00].address(), 0);
    }
}
