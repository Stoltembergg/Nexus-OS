//! Linux ELF64 (x86_64) Parser and Loader.

use crate::error::LoaderError;
use byteorder::{ByteOrder, LittleEndian};
use nexus_types::{MemoryFlags, VirtualAddress};

pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
pub const ELF_CLASS_64: u8 = 2;
pub const ELF_DATA_2LSB: u8 = 1; // Little-endian
pub const EM_X86_64: u16 = 62; // 0x3E

// Segment Types
pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_SHLIB: u32 = 5;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;

// Segment Flags
pub const PF_X: u32 = 0x1;
pub const PF_W: u32 = 0x2;
pub const PF_R: u32 = 0x4;

#[derive(Debug, Clone)]
pub struct ElfProgramHeader {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

impl ElfProgramHeader {
    pub fn memory_flags(&self) -> MemoryFlags {
        let mut flags = MemoryFlags::USER;
        if (self.p_flags & PF_R) != 0 {
            flags |= MemoryFlags::READ;
        }
        if (self.p_flags & PF_W) != 0 {
            flags |= MemoryFlags::WRITE;
        }
        if (self.p_flags & PF_X) != 0 {
            flags |= MemoryFlags::EXECUTE;
        }
        flags
    }
}

#[derive(Debug, Clone)]
pub struct ElfImage {
    pub entry_point: u64,
    pub elf_type: u16,
    pub program_headers: Vec<ElfProgramHeader>,
}

impl ElfImage {
    /// Parses a raw ELF64 byte buffer.
    pub fn parse(bytes: &[u8]) -> Result<Self, LoaderError> {
        if bytes.len() < 64 {
            return Err(LoaderError::BufferTooSmall {
                expected: 64,
                actual: bytes.len(),
            });
        }

        // 1. Verify Magic
        if bytes[0..4] != ELF_MAGIC {
            let mut magic = [0u8; 4];
            magic.copy_from_slice(&bytes[0..4]);
            return Err(LoaderError::InvalidElfMagic(magic));
        }

        // 2. Class and Endianness
        if bytes[4] != ELF_CLASS_64 {
            return Err(LoaderError::UnsupportedElfClass(bytes[4]));
        }
        if bytes[5] != ELF_DATA_2LSB {
            return Err(LoaderError::UnsupportedElfEndian(bytes[5]));
        }

        // 3. Header fields
        let elf_type = LittleEndian::read_u16(&bytes[16..18]);
        let machine = LittleEndian::read_u16(&bytes[18..20]);
        if machine != EM_X86_64 {
            return Err(LoaderError::UnsupportedElfMachine(machine));
        }

        let entry_point = LittleEndian::read_u64(&bytes[24..32]);
        let phoff = LittleEndian::read_u64(&bytes[32..40]) as usize;
        let phentsize = LittleEndian::read_u16(&bytes[54..56]) as usize;
        let phnum = LittleEndian::read_u16(&bytes[56..58]) as usize;

        // 4. Parse Program Headers
        let mut program_headers = Vec::with_capacity(phnum);
        for i in 0..phnum {
            let offset = phoff + (i * phentsize);
            if bytes.len() < offset + 56 {
                return Err(LoaderError::BufferTooSmall {
                    expected: offset + 56,
                    actual: bytes.len(),
                });
            }

            let p_type = LittleEndian::read_u32(&bytes[offset..offset + 4]);
            let p_flags = LittleEndian::read_u32(&bytes[offset + 4..offset + 8]);
            let p_offset = LittleEndian::read_u64(&bytes[offset + 8..offset + 16]);
            let p_vaddr = LittleEndian::read_u64(&bytes[offset + 16..offset + 24]);
            let p_paddr = LittleEndian::read_u64(&bytes[offset + 24..offset + 32]);
            let p_filesz = LittleEndian::read_u64(&bytes[offset + 32..offset + 40]);
            let p_memsz = LittleEndian::read_u64(&bytes[offset + 40..offset + 48]);
            let p_align = LittleEndian::read_u64(&bytes[offset + 48..offset + 56]);

            program_headers.push(ElfProgramHeader {
                p_type,
                p_flags,
                p_offset,
                p_vaddr,
                p_paddr,
                p_filesz,
                p_memsz,
                p_align,
            });
        }

        Ok(Self {
            entry_point,
            elf_type,
            program_headers,
        })
    }

    pub fn entry_point_va(&self) -> VirtualAddress {
        VirtualAddress::new(self.entry_point)
    }

    pub fn loadable_segments(&self) -> impl Iterator<Item = &ElfProgramHeader> {
        self.program_headers
            .iter()
            .filter(|ph| ph.p_type == PT_LOAD)
    }
}
