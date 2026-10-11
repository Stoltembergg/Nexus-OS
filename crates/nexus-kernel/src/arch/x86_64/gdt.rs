//! 64-bit Global Descriptor Table (GDT) and Task State Segment (TSS) for Nexus OS.

use core::mem::size_of;

/// GDT Segment Selectors.
pub const KERNEL_CS: u16 = 0x08; // Ring 0 64-bit Code
pub const KERNEL_DS: u16 = 0x10; // Ring 0 Data
pub const USER_DS: u16 = 0x18 | 3; // Ring 3 Data (RPL=3)
pub const USER_CS: u16 = 0x20 | 3; // Ring 3 64-bit Code (RPL=3)
pub const TSS_SELECTOR: u16 = 0x28; // Task State Segment

/// 64-bit GDT Entry Descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C, packed)]
pub struct GdtEntry {
    pub limit_low: u16,
    pub base_low: u16,
    pub base_mid: u8,
    pub access: u8,
    pub flags_limit_high: u8,
    pub base_high: u8,
}

impl GdtEntry {
    pub const NULL: Self = Self {
        limit_low: 0,
        base_low: 0,
        base_mid: 0,
        access: 0,
        flags_limit_high: 0,
        base_high: 0,
    };

    /// Creates a 64-bit code segment descriptor (L=1, D=0).
    pub const fn new_code64(dpl: u8) -> Self {
        let access = 0x9A | ((dpl & 0x03) << 5); // Present | Type (Code/Exec/Read)
        let flags = 0x20; // 64-bit code flag (Long mode L bit set)
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access,
            flags_limit_high: flags | 0x0F,
            base_high: 0,
        }
    }

    /// Creates a 64-bit data segment descriptor.
    pub const fn new_data(dpl: u8) -> Self {
        let access = 0x92 | ((dpl & 0x03) << 5); // Present | Type (Data/Read/Write)
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access,
            flags_limit_high: 0xCF, // 4KB granularity | 32-bit limit
            base_high: 0,
        }
    }

    pub fn access(&self) -> u8 {
        self.access
    }

    pub fn flags_limit_high(&self) -> u8 {
        self.flags_limit_high
    }
}

/// 16-byte TSS descriptor for x86_64 Long Mode.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct TssDescriptor {
    pub limit_low: u16,
    pub base_low: u16,
    pub base_mid: u8,
    pub access: u8,
    pub flags_limit_high: u8,
    pub base_high: u8,
    pub base_upper: u32,
    pub reserved: u32,
}

impl TssDescriptor {
    pub fn new(tss_addr: u64, size: u32) -> Self {
        let limit = size - 1;
        Self {
            limit_low: (limit & 0xFFFF) as u16,
            base_low: (tss_addr & 0xFFFF) as u16,
            base_mid: ((tss_addr >> 16) & 0xFF) as u8,
            access: 0x89, // Present | Available 64-bit TSS (Type 9)
            flags_limit_high: (((limit >> 16) & 0x0F) as u8),
            base_high: ((tss_addr >> 24) & 0xFF) as u8,
            base_upper: (tss_addr >> 32) as u32,
            reserved: 0,
        }
    }

    pub fn access(&self) -> u8 {
        self.access
    }
}

/// x86_64 Task State Segment (TSS).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct TaskStateSegment {
    pub reserved0: u32,
    pub rsp0: u64, // Stack pointer for Ring 0 transitions
    pub rsp1: u64,
    pub rsp2: u64,
    pub reserved1: u64,
    pub ist1: u64, // Dedicated Double Fault IST stack
    pub ist2: u64,
    pub ist3: u64,
    pub ist4: u64,
    pub ist5: u64,
    pub ist6: u64,
    pub ist7: u64,
    pub reserved2: u64,
    pub reserved3: u16,
    pub iomap_base: u16,
}

impl TaskStateSegment {
    pub const fn zeroed() -> Self {
        Self {
            reserved0: 0,
            rsp0: 0,
            rsp1: 0,
            rsp2: 0,
            reserved1: 0,
            ist1: 0,
            ist2: 0,
            ist3: 0,
            ist4: 0,
            ist5: 0,
            ist6: 0,
            ist7: 0,
            reserved2: 0,
            reserved3: 0,
            iomap_base: size_of::<Self>() as u16,
        }
    }
}

/// GDTR register pointer loaded into the CPU via LGDT.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct GdtPointer {
    pub limit: u16,
    pub base: u64,
}

/// Complete Nexus OS GDT table layout.
#[repr(C, align(16))]
pub struct GdtTable {
    pub entries: [GdtEntry; 5],
    pub tss: TssDescriptor,
}

impl GdtTable {
    pub fn new(tss: &TaskStateSegment) -> Self {
        Self::from_tss_ptr(tss as *const _)
    }

    pub fn from_tss_ptr(tss_ptr: *const TaskStateSegment) -> Self {
        let tss_addr = tss_ptr as u64;
        let tss_size = size_of::<TaskStateSegment>() as u32;

        Self {
            entries: [
                GdtEntry::NULL,          // 0x00
                GdtEntry::new_code64(0), // 0x08: Kernel Code
                GdtEntry::new_data(0),   // 0x10: Kernel Data
                GdtEntry::new_data(3),   // 0x18: User Data
                GdtEntry::new_code64(3), // 0x20: User Code
            ],
            tss: TssDescriptor::new(tss_addr, tss_size), // 0x28: TSS (16 bytes)
        }
    }

    pub fn pointer(&self) -> GdtPointer {
        GdtPointer {
            limit: (size_of::<[GdtEntry; 5]>() + size_of::<TssDescriptor>() - 1) as u16,
            base: self as *const _ as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gdtr_limit_excludes_alignment_padding() {
        let tss = TaskStateSegment::zeroed();
        let gdt = GdtTable::new(&tss);
        let limit = gdt.pointer().limit;
        assert_eq!(limit, 55); // five segment slots plus two TSS slots
    }

    #[test]
    fn test_gdt_selectors() {
        let tss = TaskStateSegment::zeroed();
        let gdt = GdtTable::new(&tss);

        // Verify kernel code descriptor (DPL 0, Executable, 64-bit)
        let k_code = gdt.entries[1];
        assert_eq!(k_code.access() & 0x9A, 0x9A); // Present, Code, Exec, Read
        assert_eq!(k_code.flags_limit_high() & 0x20, 0x20); // Long mode bit

        // Verify user code descriptor (DPL 3)
        let u_code = gdt.entries[4];
        assert_eq!((u_code.access() >> 5) & 0x03, 3); // DPL = 3

        // Verify TSS access byte (Type 9: 64-bit available TSS, Present)
        assert_eq!(gdt.tss.access(), 0x89);
    }
}
