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
