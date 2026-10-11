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
    #[cfg(all(target_arch = "x86_64", not(test)))]
    unsafe {
        core::arch::asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack, preserves_flags));
    }
    #[cfg(any(not(target_arch = "x86_64"), test))]
    {
        cr2 = 0;
    }
    cr2
}

pub static mut LAST_FAULT_INFO: Option<(u64, u64, u64)> = None; // (vector, cr2, error_code)

#[no_mangle]
pub extern "C" fn exception_dispatch_handler(frame: &mut ExceptionFrame) {
    let vector = frame.vector;
    let is_user = (frame.cs & 3) == 3;

    match vector {
        14 => {
            // #PF (Page Fault)
            let cr2 = read_cr2();
            unsafe {
                LAST_FAULT_INFO = Some((14, cr2, frame.error_code));
            }
            serial_println!(
                "[#PF] Page Fault at Linear Address {:#018X} (RIP={:#018X}, Code={:#X}, Ring={})",
                cr2,
                frame.rip,
                frame.error_code,
                if is_user { 3 } else { 0 }
            );

            if is_user {
                serial_println!(
                    "[#PF] Enforcing memory isolation: safely terminating Ring 3 process."
                );
                crate::task::trigger_user_abort(14);
            } else {
                serial_println!("[#PF] FATAL: Kernel Page Fault in Ring 0! Halting.");
                #[cfg(all(target_arch = "x86_64", not(test)))]
                unsafe {
                    core::arch::asm!("cli; 2: hlt; jmp 2b", options(noreturn));
                }
            }
        }
        13 => {
            // #GP (General Protection Fault)
            unsafe {
                LAST_FAULT_INFO = Some((13, 0, frame.error_code));
            }
            serial_println!(
                "[#GP] General Protection Fault at RIP={:#018X} (Code={:#X}, Ring={})",
                frame.rip,
                frame.error_code,
                if is_user { 3 } else { 0 }
            );
            if is_user {
                serial_println!("[#GP] Terminating Ring 3 process after privilege violation.");
                crate::task::trigger_user_abort(13);
            } else {
                serial_println!("[#GP] FATAL: Kernel GP Fault in Ring 0! Halting.");
                #[cfg(all(target_arch = "x86_64", not(test)))]
                unsafe {
                    core::arch::asm!("cli; 2: hlt; jmp 2b", options(noreturn));
                }
            }
        }
        6 => {
            // #UD (Invalid Opcode)
            let rip_ptr = frame.rip as *const u8;
            let (b0, b1, b2, b3) =
                unsafe { (*rip_ptr, *rip_ptr.add(1), *rip_ptr.add(2), *rip_ptr.add(3)) };
            serial_println!(
                "[#UD] Invalid Opcode at RIP={:#018X} (Ring={}) Bytes: {:02X} {:02X} {:02X} {:02X}",
                frame.rip,
                if is_user { 3 } else { 0 },
                b0,
                b1,
                b2,
                b3
            );
            if is_user {
                crate::task::trigger_user_abort(6);
            } else {
                serial_println!("[#UD] FATAL: Kernel Invalid Opcode in Ring 0! Halting.");
                #[cfg(all(target_arch = "x86_64", not(test)))]
                unsafe {
                    core::arch::asm!("cli; 2: hlt; jmp 2b", options(noreturn));
                }
            }
        }
        8 => {
            // #DF (Double Fault)
            serial_println!("[#DF] FATAL: Double Fault at RIP={:#018X}", frame.rip);
            #[cfg(all(target_arch = "x86_64", not(test)))]
            unsafe {
                core::arch::asm!("cli; 2: hlt; jmp 2b", options(noreturn));
            }
        }
        _ => {
            serial_println!(
                "[!] Unhandled Exception Vector {} at RIP={:#018X}",
                vector,
                frame.rip
            );
        }
    }
}

pub fn arm_exception_gates(idt: &mut IdtTable) {
    #[cfg(all(target_arch = "x86_64", not(test)))]
    {
        extern "C" {
            fn asm_stub_ud();
            fn asm_stub_df();
            fn asm_stub_gp();
            fn asm_stub_pf();
        }
        idt.set_gate(6, asm_stub_ud as *const () as u64, 0x08, 0, 0x8E); // #UD
        idt.set_gate(8, asm_stub_df as *const () as u64, 0x08, 1, 0x8E); // #DF (uses IST1)
        idt.set_gate(13, asm_stub_gp as *const () as u64, 0x08, 0, 0x8E); // #GP
        idt.set_gate(14, asm_stub_pf as *const () as u64, 0x08, 0, 0x8E); // #PF
    }
    #[cfg(any(not(target_arch = "x86_64"), test))]
    {
        let _ = idt;
    }
}

#[cfg(all(target_arch = "x86_64", not(test)))]
core::arch::global_asm!(
    r#"
    .global asm_stub_ud
    asm_stub_ud:
        push 0 // Dummy error code
        push 6 // Vector
        jmp asm_common_exception

    .global asm_stub_df
    asm_stub_df:
        // Hardware pushes error code
        push 8 // Vector
        jmp asm_common_exception

    .global asm_stub_gp
    asm_stub_gp:
        // Hardware pushes error code
        push 13 // Vector
        jmp asm_common_exception

    .global asm_stub_pf
    asm_stub_pf:
        // Hardware pushes error code
        push 14 // Vector
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

        mov rcx, rsp
        mov rdi, rsp
        sub rsp, 40
        call exception_dispatch_handler
        add rsp, 40

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

        add rsp, 16 // Pop vector and error_code
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
